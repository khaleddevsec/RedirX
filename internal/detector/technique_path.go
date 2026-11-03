package detector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

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
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	cleanPath := strings.Trim(parsed.Path, "/")
	if cleanPath == "" {
		return nil, nil // Insufficient path depth
	}

	segments := strings.Split(cleanPath, "/")
	if len(segments) < 2 {
		return nil, nil // Not enough path segments to test
	}

	// Create test path by removing the last segment
	testPath := "/" + strings.Join(segments[:len(segments)-1], "/") + "/"
	testURLObj := *parsed
	testURLObj.Path = testPath
	testURL := testURLObj.String()

	// 1. Request original URL
	resOrig, err := exec.Execute(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	// 2. Request test URL
	resTest, err := exec.Execute(ctx, testURL)
	if err != nil {
		return nil, err
	}

	// Parse final URLs
	parsedFinalOrig, err := url.Parse(resOrig.FinalURL)
	if err != nil {
		return nil, nil
	}
	parsedFinalTest, err := url.Parse(resTest.FinalURL)
	if err != nil {
		return nil, nil
	}

	sameNetloc := strings.EqualFold(parsedFinalOrig.Host, parsedFinalTest.Host)
	normOrigPath := strings.ToLower(strings.TrimRight(parsedFinalOrig.Path, "/"))
	normTestPath := strings.ToLower(strings.TrimRight(parsedFinalTest.Path, "/"))
	samePath := normOrigPath == normTestPath
	hadRedirects := resTest.HadRedirects

	if sameNetloc && samePath && hadRedirects {
		// Filter out benign changes
		origNoSlash := strings.TrimRight(parsed.Path, "/")
		testNoSlash := strings.TrimRight(testPath, "/")
		isJustSlashChange := (origNoSlash == testNoSlash+"/" || origNoSlash+"/" == testNoSlash)

		expectedNormalized := strings.ToLower(strings.TrimRight(testPath, "/"))
		isNormalization := (normTestPath == expectedNormalized || normTestPath == expectedNormalized+"/")

		meaningfulRedirect := !isJustSlashChange && !isNormalization

		if meaningfulRedirect {
			locHeader := ""
			initialStatus := resTest.FinalStatus
			if len(resTest.RedirectChain) > 0 {
				locHeader = resTest.RedirectChain[0].LocationHeader
				initialStatus = resTest.RedirectChain[0].StatusCode
			}

			finding := models.Finding{
				ID:                fmt.Sprintf("path-%d", time.Now().UnixNano()),
				VulnerableURL:     testURL,
				OriginalURL:       targetURL,
				TargetHost:        parsed.Host,
				Parameter:         "[path-segment]",
				Payload:           testPath,
				VulnerabilityType: models.VulnPathCanonical,
				Classification:    models.ClassificationPotential,
				Confidence:        models.ConfidenceMedium,
				InitialStatus:     initialStatus,
				FinalStatus:       resTest.FinalStatus,
				FinalDestination:  resTest.FinalURL,
				RedirectChain:     resTest.RedirectChain,
				Evidence: models.Evidence{
					LocationHeader:       locHeader,
					InjectedPayload:      testPath,
					BaselineDestination:  resOrig.FinalURL,
					BaselineStatus:       resOrig.FinalStatus,
					InjectedDestination:  resTest.FinalURL,
					DestinationHostMatch: true,
				},
				ValidationNotes: []string{
					"Stripping the last path segment triggered a redirection back to the full original path.",
					"Verified that the redirection is not standard trailing slash addition or path normalization.",
					"Note: This is an internal path canonicalization anomaly, not an external open redirect.",
				},
				Timestamp: time.Now(),
			}

			exec.RecordFinding(finding.Classification)
			return []models.Finding{finding}, nil
		}
	}

	return nil, nil
}

