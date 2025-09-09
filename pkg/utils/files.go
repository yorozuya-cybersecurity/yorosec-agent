package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/schema"
)

// SaveResult writes findings into a JSON file inside ./reports/<target_timestamp>/
func SaveResult(res schema.ScanResult, outputDir string) (string, error) {
	dir := filepath.Join(outputDir, safeName(res.Target)+"_"+res.Timestamp.Format("20060102_150405"))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir: %w", err)
	}

	file := filepath.Join(dir, "results.json")
	fh, err := os.Create(file)
	if err != nil {
		return "", fmt.Errorf("failed to create results.json: %w", err)
	}
	defer fh.Close()

	enc := json.NewEncoder(fh)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return "", fmt.Errorf("failed to encode results: %w", err)
	}

	return file, nil
}

// safeName replaces characters not safe for file paths
func safeName(s string) string {
	invalid := []rune{'/', '\\', ':', '*', '?', '"', '<', '>', '|'}
	rs := []rune(s)
	for i, r := range rs {
		for _, bad := range invalid {
			if r == bad {
				rs[i] = '_'
			}
		}
	}
	return string(rs)
}
