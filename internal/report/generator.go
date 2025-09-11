package report

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/schema"
)

//go:embed templates/report.html.tmpl
var reportHTMLTemplate string

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// LoadScanResult reads results.json into a ScanResult
func LoadScanResult(fromDir string) (schema.ScanResult, error) {
	var res schema.ScanResult
	data, err := os.ReadFile(filepath.Join(fromDir, "results.json"))
	if err != nil {
		return res, fmt.Errorf("read results.json: %w", err)
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return res, fmt.Errorf("parse results.json: %w", err)
	}
	return res, nil
}

// GenerateHTML renders an HTML report and saves it to <outDir>/report.html
func GenerateHTML(res schema.ScanResult, outDir string) (string, error) {
	vm := buildViewModel(res)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("create out dir: %w", err)
	}

	tmpl, err := template.New("report").Parse(reportHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vm); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	htmlPath := filepath.Join(outDir, "report.html")
	if err := os.WriteFile(htmlPath, buf.Bytes(), 0o644); err != nil {
		return "", fmt.Errorf("write report.html: %w", err)
	}
	return htmlPath, nil
}

// GeneratePDF converts HTML report into PDF using headless Chrome (Chromedp)
func GeneratePDF(htmlPath string) (string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate("file://"+htmlPath),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			buf, _, err = page.PrintToPDF().
				WithPrintBackground(true).
				Do(ctx)
			return err
		}),
	)
	if err != nil {
		return "", fmt.Errorf("chromedp PDF generation failed: %w", err)
	}

	pdfPath := strings.TrimSuffix(htmlPath, ".html") + ".pdf"
	if err := os.WriteFile(pdfPath, buf, 0644); err != nil {
		return "", fmt.Errorf("write pdf: %w", err)
	}
	return pdfPath, nil
}

// ---------------------------------------------------------------------------
// View Model
// ---------------------------------------------------------------------------

type viewModel struct {
	Target         string
	ScanTime       string
	TotalFindings  int
	Counts         map[string]int
	Score          int
	Grade          string
	Findings       []findingRow
	Generator      string
	GeneratedAt    string
	LegendSeverity []string
	Year           int
}

type findingRow struct {
	Severity    string
	ID          string
	Template    string
	Description string
	Evidence    string
	Scanner     string
}

func buildViewModel(res schema.ScanResult) viewModel {
	now := time.Now().UTC()
	sevOrder := []string{"critical", "high", "medium", "low", "info"}
	sevWeight := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

	counts := map[string]int{}
	var rows []findingRow

	for _, f := range res.Findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		counts[sev]++
		rows = append(rows, findingRow{
			Severity:    strings.ToUpper(sev),
			ID:          fallback(f.ID, "N/A"),
			Template:    fallback(f.Template, "-"),
			Description: truncate(f.Description, 500),
			Evidence:    truncate(f.Evidence, 200),
			Scanner:     f.Scanner,
		})
	}

	// Sort by severity, then by ID
	sort.SliceStable(rows, func(i, j int) bool {
		ai := indexOf(sevOrder, strings.ToLower(rows[i].Severity))
		bi := indexOf(sevOrder, strings.ToLower(rows[j].Severity))
		if ai != bi {
			return ai < bi
		}
		return rows[i].ID < rows[j].ID
	})

	// Simple score heuristic based on weighted severity counts
	total := 0
	weighted := 0
	for sev, c := range counts {
		total += c
		weighted += sevWeight[sev] * c
	}
	score := 100
	if total > 0 {
		penalty := min(100, (weighted*100)/(total*4)) // normalize
		score = 100 - penalty
	}
	grade := scoreToGrade(score)

	return viewModel{
		Target:         res.Target,
		ScanTime:       res.Timestamp.UTC().Format(time.RFC3339),
		TotalFindings:  total,
		Counts:         normalizeCounts(counts, sevOrder),
		Score:          score,
		Grade:          grade,
		Findings:       rows,
		Generator:      "yorosec-agent",
		GeneratedAt:    now.Format(time.RFC3339),
		LegendSeverity: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
		Year:           now.Year(),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func indexOf(arr []string, v string) int {
	for i, x := range arr {
		if x == v {
			return i
		}
	}
	return len(arr)
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func normalizeCounts(in map[string]int, order []string) map[string]int {
	out := make(map[string]int, len(order))
	for _, k := range order {
		out[strings.ToUpper(k)] = in[k]
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fallback(s, fb string) string {
	if strings.TrimSpace(s) == "" {
		return fb
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
