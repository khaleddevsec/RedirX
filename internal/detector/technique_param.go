package detector

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/validator"
)

// QueryParameterTechnique encapsulates candidate parameter extraction,
// two-stage canary probing (Fast Mode), and contextual payload evasion (Deep Mode).
type QueryParameterTechnique struct{}

// NewQueryParameterTechnique constructs a new QueryParameterTechnique.
func NewQueryParameterTechnique() *QueryParameterTechnique {
	return &QueryParameterTechnique{}
}

// ID returns the unique identifier for this technique.
func (t *QueryParameterTechnique) ID() string {
	return "query_parameter"
}

// Name returns the descriptive title.
func (t *QueryParameterTechnique) Name() string {
	return "Query Parameter Injection"
}

// Description explains the testing methodology.
func (t *QueryParameterTechnique) Description() string {
	return "Discovers candidate redirect query parameters and injects contextual evasion payloads"
}

// IsEnabled indicates whether parameter injection is active.
func (t *QueryParameterTechnique) IsEnabled(cfg *models.ScanConfig) bool {
	return true
}

// Execute performs baseline establishment, parameter discovery, and two-stage payload testing.
func (t *QueryParameterTechnique) Execute(ctx context.Context, targetURL string, exec RequestExecutor, cfg *models.ScanConfig) ([]models.Finding, error) {
	var findings []models.Finding

	targetHost := ExtractHost(targetURL)

	// 1. Establish Baseline Response
	resBaseline, err := exec.Execute(ctx, targetURL)
	if err != nil {
		exec.RecordError(fmt.Sprintf("Baseline %s: %v", targetURL, err))
		return nil, err
	}

	normPath := ""
	if parsed, pErr := url.Parse(resBaseline.FinalURL); pErr == nil {
		normPath = strings.ToLower(strings.TrimRight(parsed.Path, "/"))
	}

	locHeader := ""
	if len(resBaseline.RedirectChain) > 0 {
		locHeader = resBaseline.RedirectChain[0].LocationHeader
	}

	baseline := &models.BaselineResult{
		URL:              targetURL,
		StatusCode:       resBaseline.FinalStatus,
		FinalURL:         resBaseline.FinalURL,
		LocationHeader:   locHeader,
		RedirectChain:    resBaseline.RedirectChain,
		HadRedirects:     resBaseline.HadRedirects,
		NormalizedPath:   normPath,
		IsStaticRedirect: resBaseline.HadRedirects,
	}

	// 2. Extract Candidate Parameters
	var includeParams, excludeParams []string
	if cfg != nil {
		includeParams = cfg.IncludeParams
		excludeParams = cfg.ExcludeParams
	}

	params, _, err := ExtractCandidateParams(targetURL, includeParams, excludeParams)
	if err != nil || len(params) == 0 {
		return nil, nil
	}

	// 3. Generate Payloads
	testDomain := "example.com"
	payloadFile := ""
	retries := 0
	verbose := false
	isDeepMode := false

	if cfg != nil {
		if cfg.TestDomain != "" {
			testDomain = cfg.TestDomain
		}
		payloadFile = cfg.PayloadFile
		retries = cfg.Retries
		verbose = cfg.Verbose
		isDeepMode = strings.EqualFold(cfg.Mode, models.ScanModeDeep)
	}

	payloads, err := GeneratePayloads(targetHost, testDomain, payloadFile)
	if err != nil {
		exec.RecordError(fmt.Sprintf("Payload error %s: %v", targetURL, err))
		return nil, err
	}
	if len(payloads) == 0 {
		return nil, nil
	}

	// Determine if target URL explicitly carried query parameters in input
	origParsed, _ := url.Parse(targetURL)
	hasExplicitParams := origParsed != nil && len(origParsed.Query()) > 0

	// 4. Test Parameters with Two-Stage Execution
	for _, param := range params {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		exec.IncrementParameters()

		// STAGE 1: Canary Probing for Parameterless URLs in Fast Mode
		// If URL has no query parameters and we are in Fast Mode, first test 1 canary probe.
		// If the parameter is completely inert, skip firing the remaining 18 evasion payloads!
		if !isDeepMode && !hasExplicitParams {
			canary := payloads[0] // Standard HTTPS payload (e.g. https://example.com)

			injected, injectErr := InjectQueryParameter(targetURL, param, canary.Value, canary.Category)
			if injectErr != nil {
				continue
			}

			execResult, execErr := exec.Execute(ctx, injected.URL)
			if execErr != nil {
				for r := 0; r < retries; r++ {
					execResult, execErr = exec.Execute(ctx, injected.URL)
					if execErr == nil {
						break
					}
				}
				if execErr != nil {
					continue
				}
			}

			// Check client-side navigation (Meta Refresh / JS)
			clientSide := AnalyzeClientSideRedirects(execResult.FinalBody, testDomain, canary.Value)

			// Validate finding against baseline and heuristics
			finding := validator.ValidateFinding(targetURL, injected, baseline, execResult, clientSide, testDomain)
			if finding != nil {
				if finding.Classification == models.ClassificationConfirmed ||
					finding.Classification == models.ClassificationPotential {
					exec.RecordFinding(finding.Classification)
					findings = append(findings, *finding)
					// Vulnerability confirmed on first probe; no further payloads needed on this parameter
					continue
				}
				if verbose {
					findings = append(findings, *finding)
				}
			}

			// Check if parameter is receptive / responsive to input
			if !isParameterResponsive(baseline, execResult, canary.Value, testDomain) {
				// Parameter ignored by backend logic; skip Stage 2 evasion matrix
				continue
			}

			// Parameter demonstrated responsiveness; proceed to Stage 2 Evasion Matrix
			for _, p := range payloads[1:] {
				select {
				case <-ctx.Done():
					return findings, ctx.Err()
				default:
				}

				injected, injectErr := InjectQueryParameter(targetURL, param, p.Value, p.Category)
				if injectErr != nil {
					continue
				}

				execResult, execErr := exec.Execute(ctx, injected.URL)
				if execErr != nil {
					for r := 0; r < retries; r++ {
						execResult, execErr = exec.Execute(ctx, injected.URL)
						if execErr == nil {
							break
						}
					}
					if execErr != nil {
						continue
					}
				}

				clientSide := AnalyzeClientSideRedirects(execResult.FinalBody, testDomain, p.Value)
				finding := validator.ValidateFinding(targetURL, injected, baseline, execResult, clientSide, testDomain)
				if finding == nil {
					continue
				}

				exec.RecordFinding(finding.Classification)

				if finding.Classification == models.ClassificationConfirmed ||
					finding.Classification == models.ClassificationPotential ||
					verbose {
					findings = append(findings, *finding)
				}

				if finding.Classification == models.ClassificationConfirmed {
					break
				}
			}
			continue
		}

		// STAGE 2 / DEEP MODE: Exhaustive Testing (or testing explicit URL query parameters)
		for _, p := range payloads {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			injected, injectErr := InjectQueryParameter(targetURL, param, p.Value, p.Category)
			if injectErr != nil {
				continue
			}

			execResult, execErr := exec.Execute(ctx, injected.URL)
			if execErr != nil {
				for r := 0; r < retries; r++ {
					execResult, execErr = exec.Execute(ctx, injected.URL)
					if execErr == nil {
						break
					}
				}
				if execErr != nil {
					continue
				}
			}

			clientSide := AnalyzeClientSideRedirects(execResult.FinalBody, testDomain, p.Value)
			finding := validator.ValidateFinding(targetURL, injected, baseline, execResult, clientSide, testDomain)
			if finding == nil {
				continue
			}

			exec.RecordFinding(finding.Classification)

			if finding.Classification == models.ClassificationConfirmed ||
				finding.Classification == models.ClassificationPotential ||
				verbose {
				findings = append(findings, *finding)
			}

			if finding.Classification == models.ClassificationConfirmed {
				break
			}
		}
	}

	return findings, nil
}

// isParameterResponsive evaluates whether the candidate parameter altered backend execution behavior
// compared to the baseline response (e.g. status code shift, location header alteration, or body reflection).
func isParameterResponsive(baseline *models.BaselineResult, execResult *redirect.ExecutionResult, canaryValue, testDomain string) bool {
	if execResult == nil {
		return false
	}

	// 1. Status Code Variation (e.g. baseline 200 vs probe 302, 400, or 403)
	if baseline != nil && execResult.FinalStatus != baseline.StatusCode {
		return true
	}

	// 2. Redirect Activity Difference
	if baseline != nil && execResult.HadRedirects != baseline.HadRedirects {
		return true
	}

	// 3. Location Header Variation
	locHeader := ""
	if len(execResult.RedirectChain) > 0 {
		locHeader = execResult.RedirectChain[0].LocationHeader
	}
	if locHeader != "" {
		if baseline == nil || locHeader != baseline.LocationHeader {
			return true
		}
	}

	// 4. Destination Shift when Redirection Occurs
	if execResult.HadRedirects {
		if baseline == nil || !strings.EqualFold(execResult.FinalURL, baseline.FinalURL) {
			return true
		}
	}

	// 5. Canary Reflection in Response Body
	cleanCanary := strings.ToLower(canaryValue)
	cleanDomain := strings.ToLower(testDomain)
	bodyLower := strings.ToLower(execResult.FinalBody)

	if strings.Contains(bodyLower, cleanDomain) || strings.Contains(bodyLower, cleanCanary) {
		return true
	}

	return false
}
