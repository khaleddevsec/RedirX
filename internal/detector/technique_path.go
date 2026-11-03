package detector

import (
	"context"

	"redirx/internal/models"
)

// PathCanonicalizationTechnique implements the path-segment stripping detection
// heuristic preserved and enhanced from No-Redirect.py.
type PathCanonicalizationTechnique struct{}

// NewPathCanonicalizationTechnique constructs a new PathCanonicalizationTechnique.
func NewPathCanonicalizationTechnique() *PathCanonicalizationTechnique {
	return &PathCanonicalizationTechnique{}
}

// ID returns the unique identifier for this technique.
func (t *PathCanonicalizationTechnique) ID() string {
	return "path_canonicalization"
}

// Name returns the descriptive name.
func (t *PathCanonicalizationTechnique) Name() string {
	return "Path Canonicalization Anomaly"
}

// Description describes the mechanism.
func (t *PathCanonicalizationTechnique) Description() string {
	return "Removes the trailing path segment to detect abnormal bounce-back redirects and routing anomalies"
}

// IsEnabled checks if path testing is toggled on in the scan configuration.
func (t *PathCanonicalizationTechnique) IsEnabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.PathTest
}

// Execute performs the path anomaly analysis using the decoupled RequestExecutor.
func (t *PathCanonicalizationTechnique) Execute(ctx context.Context, targetURL string, exec RequestExecutor, cfg *models.ScanConfig) ([]models.Finding, error) {
	finding, err := AnalyzePathAnomaly(ctx, targetURL, exec.Execute)
	if err != nil {
		return nil, err
	}

	if finding != nil {
		exec.RecordFinding(finding.Classification)
		return []models.Finding{*finding}, nil
	}

	return nil, nil
}
