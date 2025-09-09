package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/yorozuya-cybersecurity/yorosec-agent/internal/schema"
)

// RunNuclei executes nuclei with JSON export and returns normalized findings
func RunNuclei(target string) ([]schema.Finding, error) {
	// Prepare temp output file
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei_%d.json", time.Now().UnixNano()))

	cmd := exec.Command("nuclei",
		"-target", target,
		"-json-export", tmpFile,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei failed: %w", err)
	}

	// Read back JSON
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	// Nuclei exports an array of objects
	var raw []map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse nuclei JSON: %w", err)
	}

	var findings []schema.Finding
	for _, r := range raw {
		f := schema.Finding{
			Target:  target,
			Scanner: "nuclei",
		}
		if id, ok := r["template-id"].(string); ok {
			f.ID = id
			f.Template = id
		}
		if sev, ok := r["info"].(map[string]interface{})["severity"].(string); ok {
			f.Severity = sev
		}
		if desc, ok := r["info"].(map[string]interface{})["description"].(string); ok {
			f.Description = desc
		}
		if matched, ok := r["matched-at"].(string); ok {
			f.Evidence = matched
		}
		findings = append(findings, f)
	}

	return findings, nil
}
