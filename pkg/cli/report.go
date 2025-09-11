package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	reportpkg "github.com/yorozuya-cybersecurity/yorosec-agent/internal/report"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "report",
		Short:   "Generate HTML/PDF report from a scan result directory",
		Example: "yoro report --from ./reports/example.com_20250911_131722 --format html,pdf",
		RunE:    runReport,
	}

	cmd.Flags().String("from", "", "Scan result directory (must contain results.json)")
	cmd.Flags().String("format", "html,pdf", "Output formats: html,pdf,json (json just points to results.json)")

	_ = viper.BindPFlag("report.from", cmd.Flags().Lookup("from"))
	_ = viper.BindPFlag("report.format", cmd.Flags().Lookup("format"))
	return cmd
}

func runReport(cmd *cobra.Command, _ []string) error {
	from := viper.GetString("report.from")
	if from == "" {
		return errors.New("please provide --from pointing to the scan directory (with results.json)")
	}

	formats := strings.Split(viper.GetString("report.format"), ",")
	for i := range formats {
		formats[i] = strings.TrimSpace(strings.ToLower(formats[i]))
	}

	// Load scan results and render HTML
	res, err := reportpkg.LoadScanResult(from)
	if err != nil {
		return err
	}
	htmlPath, err := reportpkg.GenerateHTML(res, from)
	if err != nil {
		return err
	}
	fmt.Printf("📝 HTML report: %s\n", htmlPath)

	// Optional PDF (Chromedp-based)
	if contains(formats, "pdf") {
		pdfPath, err := reportpkg.GeneratePDF(htmlPath)
		if err != nil {
			fmt.Printf("⚠️  PDF generation failed: %v\n", err)
		} else {
			fmt.Printf("📄 PDF report:  %s\n", pdfPath)
		}
	}

	// Optional JSON passthrough
	if contains(formats, "json") {
		fmt.Printf("📦 JSON already exists at: %s\n", filepath.Join(from, "results.json"))
	}

	return nil
}

func contains(arr []string, v string) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}
