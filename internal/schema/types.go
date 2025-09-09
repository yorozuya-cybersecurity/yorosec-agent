package schema

import "time"

// Finding is a normalized vulnerability finding
type Finding struct {
	ID             string   `json:"id"`
	Target         string   `json:"target"`
	Scanner        string   `json:"scanner"`
	Template       string   `json:"template"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss,omitempty"`
	Description    string   `json:"description,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Tags           []string `json:"tags,omitempty"`
}

// ScanResult groups all findings for one run
type ScanResult struct {
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Findings  []Finding `json:"findings"`
}
