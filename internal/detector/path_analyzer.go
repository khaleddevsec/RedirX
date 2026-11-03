package detector

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"redirx/internal/models"
	"redirx/internal/redirect"
)

// PathFetcher abstracts HTTP hop-by-hop execution for path anomaly detection.
type PathFetcher func(ctx context.Context, targetURL string) (*redirect.ExecutionResult, error)

// CheckPathCanonicalizationAnomaly executes the legacy path-segment stripping heuristic
// migrated and enhanced from the original Python No-Redirect implementation.
// It removes the last path segment and checks whether an unexpected redirection occurs
// back to the original resource or an anomalous location, while filtering out benign trailing slash
// adjustments, standard path normalizations, and generic catch-all root redirects.
func CheckPathCanonicalizationAnomaly(ctx context.Context, client *redirect.Client, rawURL string) (*models.Finding, error) {
	if client == nil {
		return nil, fmt.Errorf("redirect client cannot be nil")
	}
	return AnalyzePathAnomaly(ctx, rawURL, client.ExecuteHopByHop)
}

// AnalyzePathAnomaly executes the 11-step No-Redirect detection methodology ported
// from No-Redirect.py and enhanced to eliminate false positives, handle edge cases,
// preserve query parameters, and perform Execution After Redirect (EAR) verification.
func AnalyzePathAnomaly(ctx context.Context, rawURL string, fetcher PathFetcher) (*models.Finding, error) {
	trimmedURL := strings.TrimSpace(rawURL)
	if trimmedURL == "" {
		return nil, nil
	}

	// Step 1 & 2: Parse and validate candidate URL
	parsed, err := url.Parse(trimmedURL)
	if err != nil || parsed.Host == "" {
		return nil, nil // Invalid URL structure
	}

	// Scheme check: Ensure HTTP/HTTPS
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, nil
	}

	// Step 3: Check path depth (require at least 2 non-empty path segments)
	cleanPath := strings.Trim(parsed.Path, "/")
	if cleanPath == "" {
		return nil, nil // Insufficient path depth (root or empty)
	}

	rawSegments := strings.Split(cleanPath, "/")
	var segments []string
	for _, seg := range rawSegments {
		seg = strings.TrimSpace(seg)
		if seg != "" {
			segments = append(segments, seg)
		}
	}

	if len(segments) < 2 {
		return nil, nil // Not enough path segments to test
	}

	// Step 4: Remove final path segment
	parentSegments := segments[:len(segments)-1]
	testPath := "/" + strings.Join(parentSegments, "/") + "/"

	// Step 5: Construct modified test URL with query parameter & fragment preservation
	testURLObj := *parsed
	testURLObj.Path = testPath
	testURLObj.RawPath = "" // Prevent stale RawPath serialization in Go net/url
	testURL := testURLObj.String()

	if testURL == trimmedURL {
		return nil, nil // Redundant URL
	}

	// Step 6 & 7: Request original URL and modified test URL concurrently (follow redirects)
	var (
		resOrig *redirect.ExecutionResult
		errOrig error
		resTest *redirect.ExecutionResult
		errTest error
		fetchWg sync.WaitGroup
	)

	fetchWg.Add(2)
	go func() {
		defer fetchWg.Done()
		resOrig, errOrig = fetcher(ctx, trimmedURL)
	}()
	go func() {
		defer fetchWg.Done()
		resTest, errTest = fetcher(ctx, testURL)
	}()
	fetchWg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errOrig != nil || errTest != nil || resOrig == nil || resTest == nil {
		return nil, nil
	}

	// Discard broken/dead endpoints
	if resTest.FinalStatus >= 400 {
		return nil, nil
	}

	// Step 8 & 9: Parse finals, compare hosts and normalized paths
	parsedFinalOrig, err := url.Parse(resOrig.FinalURL)
	if err != nil {
		return nil, nil
	}
	parsedFinalTest, err := url.Parse(resTest.FinalURL)
	if err != nil {
		return nil, nil
	}

	sameNetloc := isSameHost(parsedFinalOrig, parsedFinalTest)

	normOrigPath := normalizePathForComparison(parsedFinalOrig.Path)
	normTestPath := normalizePathForComparison(parsedFinalTest.Path)
	samePath := normOrigPath == normTestPath

	// Step 10: Check redirect history
	hadRedirects := resTest.HadRedirects && len(resTest.RedirectChain) > 0

	// Check if any redirect hop actually changed the path
	hasPathChangingRedirect := false
	for _, hop := range resTest.RedirectChain {
		if hop.DestinationURL != "" {
			if hopParsed, parseErr := url.Parse(hop.DestinationURL); parseErr == nil {
				if normalizePathForComparison(hopParsed.Path) != normalizePathForComparison(testPath) {
					hasPathChangingRedirect = true
					break
				}
			}
		}
	}

	// Step 11: Apply detection conditions ported from No-Redirect.py + enhancements
	if sameNetloc && samePath && hadRedirects && hasPathChangingRedirect {
		// Filter 1: Trailing slash addition/removal
		origNoSlash := strings.TrimRight(parsed.Path, "/")
		testNoSlash := strings.TrimRight(testPath, "/")
		isJustSlashChange := (origNoSlash == testNoSlash+"/" || origNoSlash+"/" == testNoSlash || origNoSlash == testNoSlash)

		// Filter 2: Standard normalization to the expected tested path
		expectedNormalized := normalizePathForComparison(testPath)
		isNormalization := (normTestPath == expectedNormalized)

		// Filter 3: Catch-all homepage redirect (false-positive elimination)
		// If both ended up at root ("" or "/"), but original target was deeper,
		// this represents a generic homepage redirect rather than a resource bounce-back.
		isCatchAllRoot := (normTestPath == "" || normTestPath == "/") && len(segments) >= 2

		meaningfulRedirect := !isJustSlashChange && !isNormalization && !isCatchAllRoot

		if meaningfulRedirect {
			locHeader := ""
			initialStatus := resTest.FinalStatus
			if len(resTest.RedirectChain) > 0 {
				locHeader = resTest.RedirectChain[0].LocationHeader
				initialStatus = resTest.RedirectChain[0].StatusCode
			}

			// Targeted Verification: Execution After Redirect (EAR) and session cookie leakage
			isEARConfirmed, earSnippet, hasCookieLeak := checkExecutionAfterRedirect(resTest.RedirectChain)

			classification := models.ClassificationPotential
			confidence := models.ConfidenceMedium
			var validationNotes []string

			validationNotes = append(validationNotes,
				"Stripping the last path segment triggered a redirection back to the full original path.",
				"Verified that the redirection is not standard trailing slash addition, path normalization, or catch-all root redirect.",
			)

			if isEARConfirmed || hasCookieLeak {
				classification = models.ClassificationConfirmed
				confidence = models.ConfidenceHigh
				if isEARConfirmed {
					validationNotes = append(validationNotes, fmt.Sprintf("Execution After Redirect (EAR) verified: HTTP 3xx response indicates unauthenticated body leakage: %s", earSnippet))
				}
				if hasCookieLeak {
					validationNotes = append(validationNotes, "Session cookie leakage verified: HTTP 3xx response sets unauthenticated cookies during redirection.")
				}
			} else {
				validationNotes = append(validationNotes, "Note: Path canonicalization anomaly detected; no unauthenticated body leakage detected in initial 3xx response.")
			}

			finding := &models.Finding{
				ID:                fmt.Sprintf("path-%d", time.Now().UnixNano()),
				VulnerableURL:     testURL,
				OriginalURL:       trimmedURL,
				TargetHost:        parsed.Host,
				Parameter:         "[path-segment]",
				Payload:           testPath,
				VulnerabilityType: models.VulnPathCanonical,
				Classification:    classification,
				Confidence:        confidence,
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
				ValidationNotes: validationNotes,
				Timestamp:       time.Now(),
			}

			return finding, nil
		}
	}

	return nil, nil
}

// isSameHost compares two URLs for netloc equality, normalizing hostname casing and default ports.
func isSameHost(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	h1 := strings.ToLower(u1.Hostname())
	h2 := strings.ToLower(u2.Hostname())
	if h1 != h2 {
		return false
	}
	p1 := u1.Port()
	p2 := u2.Port()
	if (u1.Scheme == "http" && p1 == "80") || (u1.Scheme == "https" && p1 == "443") {
		p1 = ""
	}
	if (u2.Scheme == "http" && p2 == "80") || (u2.Scheme == "https" && p2 == "443") {
		p2 = ""
	}
	return p1 == p2
}

// normalizePathForComparison converts path to lowercase, strips trailing slashes, and collapses duplicates.
func normalizePathForComparison(p string) string {
	clean := strings.TrimRight(strings.ToLower(p), "/")
	for strings.Contains(clean, "//") {
		clean = strings.ReplaceAll(clean, "//", "/")
	}
	return clean
}

// checkExecutionAfterRedirect inspects intermediate 3xx redirect hops for Execution After Redirect (EAR)
// symptoms such as sensitive response body leakage or unauthenticated session cookies.
func checkExecutionAfterRedirect(chain []models.RedirectHop) (hasEAR bool, snippet string, hasCookie bool) {
	earKeywords := []string{
		"<form",
		"<input",
		"type=\"password\"",
		"type='password'",
		"dashboard",
		"admin panel",
		"welcome, admin",
		"logout",
		"session_id",
		"sql syntax",
		"database error",
	}

	for _, hop := range chain {
		if hop.StatusCode >= 300 && hop.StatusCode < 400 {
			// Check for Set-Cookie header
			if hop.Headers != nil {
				for k, v := range hop.Headers {
					if strings.EqualFold(k, "Set-Cookie") && v != "" {
						hasCookie = true
					}
				}
			}

			// Check body snippet length and content
			bodyLower := strings.ToLower(hop.BodySnippet)
			for _, kw := range earKeywords {
				if strings.Contains(bodyLower, kw) {
					hasEAR = true
					snip := strings.TrimSpace(hop.BodySnippet)
					if len(snip) > 100 {
						snip = snip[:100] + "..."
					}
					snippet = snip
					break
				}
			}

			// Check Content-Length header for large response body on 302
			if hop.Headers != nil {
				for k, v := range hop.Headers {
					if strings.EqualFold(k, "Content-Length") && v != "" {
						var cl int
						if _, err := fmt.Sscanf(v, "%d", &cl); err == nil && cl > 500 {
							hasEAR = true
							if snippet == "" {
								snippet = fmt.Sprintf("HTTP %d response contains %d bytes body", hop.StatusCode, cl)
							}
						}
					}
				}
			}
		}
	}
	return hasEAR, snippet, hasCookie
}
