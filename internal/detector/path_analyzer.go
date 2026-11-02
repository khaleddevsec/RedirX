package detector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"redirx/internal/models"
	"redirx/internal/redirect"
)

// CheckPathCanonicalizationAnomaly executes the legacy path-segment stripping heuristic
// migrated and enhanced from the original Python No-Redirect implementation.
// It removes the last path segment and checks whether an unexpected redirection occurs
// back to the original resource or an anomalous location, while filtering out benign trailing slash
// adjustments and standard path normalizations.
func CheckPathCanonicalizationAnomaly(ctx context.Context, client *redirect.Client, rawURL string) (*models.Finding, error) {
	parsed, err := url.Parse(rawURL)
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
	resOrig, err := client.ExecuteHopByHop(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	// 2. Request test URL
	resTest, err := client.ExecuteHopByHop(ctx, testURL)
	if err != nil {
		return nil, err
	}

	// Parse finals
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
		// Filter out benign changes:
		// Check 1: Trailing slash addition/removal
		origNoSlash := strings.TrimRight(parsed.Path, "/")
		testNoSlash := strings.TrimRight(testPath, "/")
		isJustSlashChange := (origNoSlash == testNoSlash+"/" || origNoSlash+"/" == testNoSlash)

		// Check 2: Standard normalization to the expected tested path
		expectedNormalized := strings.ToLower(strings.TrimRight(testPath, "/"))
		isNormalization := (normTestPath == expectedNormalized || normTestPath == expectedNormalized+"/")

		meaningfulRedirect := !isJustSlashChange && !isNormalization

		if meaningfulRedirect {
			locHeader := ""
			if len(resTest.RedirectChain) > 0 {
				locHeader = resTest.RedirectChain[0].LocationHeader
			}

			finding := &models.Finding{
				ID:                fmt.Sprintf("path-%d", time.Now().UnixNano()),
				VulnerableURL:     testURL,
				OriginalURL:       rawURL,
				TargetHost:        parsed.Host,
				Parameter:         "[path-segment]",
				Payload:           testPath,
				VulnerabilityType: models.VulnPathCanonical,
				Classification:    models.ClassificationPotential,
				Confidence:        models.ConfidenceMedium,
				InitialStatus:     resTest.RedirectChain[0].StatusCode,
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

			return finding, nil
		}
	}

	return nil, nil
}

