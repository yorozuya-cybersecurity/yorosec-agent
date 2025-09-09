package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/schema"
)

var reportHTMLTemplate string

// ---------- Public API ----------

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

func GenerateHTML(res schema.ScanResult, outDir string) (string, error) {
	vm := buildViewModel(res)

	if err := os.MkdirAll(outDir, 0755); err != nil {
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
	if err := os.WriteFile(htmlPath, buf.Bytes(), 0644); err != nil {
		return "", fmt.Errorf("write report.html: %w", err)
	}

	return htmlPath, nil
}

var ErrWKHTMLNotFound = errors.New("wkhtmltopdf not found")

func GeneratePDF(htmlPath string) (string, error) {
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		return "", ErrWKHTMLNotFound
	}
	pdfPath := strings.TrimSuffix(htmlPath, ".html") + ".pdf"
	cmd := exec.Command("wkhtmltopdf", "--enable-local-file-access", htmlPath, pdfPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wkhtmltopdf: %w", err)
	}
	return pdfPath, nil
}

// ---------- View Model & helpers ----------

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
		sev := strings.ToLower(f.Severity)
		if sev == "" {
			sev = "info"
		}
		counts[sev]++
		rows = append(rows, findingRow{
			Severity:    strings.ToUpper(sev),
			ID:          emptyFallback(f.ID, "N/A"),
			Template:    emptyFallback(f.Template, "-"),
			Description: trimTo(f.Description, 500),
			Evidence:    trimTo(f.Evidence, 200),
			Scanner:     f.Scanner,
		})
	}

	// Sort findings: severity -> ID
	sort.SliceStable(rows, func(i, j int) bool {
		a := strings.ToLower(rows[i].Severity)
		b := strings.ToLower(rows[j].Severity)
		ai := indexOf(sevOrder, a)
		bi := indexOf(sevOrder, b)
		if ai != bi {
			return ai < bi
		}
		return rows[i].ID < rows[j].ID
	})

	total := 0
	weighted := 0
	for sev, c := range counts {
		total += c
		weighted += sevWeight[strings.ToLower(sev)] * c
	}
	score := 100
	if total > 0 {
		// A simple heuristic: more high/critical lowers score
		penalty := min(100, (weighted*100)/(total*4)) // normalize to 0..100
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

func indexOf(arr []string, s string) int {
	for i, v := range arr {
		if v == s {
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
	out := make(map[string]int)
	for _, k := range order {
		if v, ok := in[k]; ok {
			out[strings.ToUpper(k)] = v
		} else {
			out[strings.ToUpper(k)] = 0
		}
	}
	return out
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func emptyFallback(s, fb string) string {
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
