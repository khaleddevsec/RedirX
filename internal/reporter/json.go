package reporter

import (
	"encoding/json"
	"io"
	"time"

	"redirx/internal/models"
	"redirx/pkg/version"
)

// JSONReportSchema defines the structured JSON export document.
type JSONReportSchema struct {
	Engine    string             `json:"engine"`
	Version   string             `json:"version"`
	Timestamp string             `json:"timestamp"`
	Summary   models.ScanSummary `json:"summary"`
	Findings  []models.Finding   `json:"findings"`
}

// WriteJSONReport serializes findings and scan metrics to formatted JSON.
func WriteJSONReport(w io.Writer, summary models.ScanSummary, findings []models.Finding) error {
	doc := JSONReportSchema{
		Engine:    "RedirX",
		Version:   version.Version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary:   summary,
		Findings:  findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(doc)
}

