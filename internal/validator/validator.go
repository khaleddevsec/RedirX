package validator

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"redirx/internal/detector"
	"redirx/internal/models"
	"redirx/internal/redirect"
)

// ValidateFinding evaluates execution results against baseline and policy rules
// to produce a rigorously verified, evidence-backed Finding.
func ValidateFinding(
	originalURL string,
	injected *detector.InjectedTarget,
	baseline *models.BaselineResult,
	execResult *redirect.ExecutionResult,
	clientSide *detector.ClientSideResult,
	testDomain string,
) *models.Finding {
	if injected == nil || execResult == nil {
		return nil
	}

	cleanDomain := strings.ToLower(testDomain)
	origParsed, _ := url.Parse(originalURL)
	targetHost := ""
	if origParsed != nil {
		targetHost = origParsed.Hostname()
	}

	finding := &models.Finding{
		ID:                fmt.Sprintf("rx-%d", time.Now().UnixNano()),
		VulnerableURL:     injected.URL,
		OriginalURL:       originalURL,
		TargetHost:        targetHost,
		Parameter:         injected.Parameter,
		Payload:           injected.Payload,
		VulnerabilityType: models.VulnServerSideDirect,
		Classification:    models.ClassificationFalsePositive,
		Confidence:        models.ConfidenceLow,
		InitialStatus:     execResult.FinalStatus,
		FinalStatus:       execResult.FinalStatus,
		FinalDestination:  execResult.FinalURL,
		RedirectChain:     execResult.RedirectChain,
		Evidence: models.Evidence{
			InjectedPayload: injected.Payload,
			TargetParameter: injected.Parameter,
		},
		Timestamp: time.Now(),
	}

	if len(execResult.RedirectChain) > 0 {
		finding.InitialStatus = execResult.RedirectChain[0].StatusCode
		finding.Evidence.LocationHeader = execResult.RedirectChain[0].LocationHeader
	}

	if baseline != nil {
		finding.Evidence.BaselineDestination = baseline.FinalURL
		finding.Evidence.BaselineStatus = baseline.StatusCode
		finding.Evidence.BaselineRedirects = baseline.HadRedirects
	}

	// -------------------------------------------------------------
	// 1. Check for Server-Side HTTP 3xx Redirects
	// -------------------------------------------------------------
	if execResult.HadRedirects && len(execResult.RedirectChain) > 0 {
		var matchedHop *models.RedirectHop
		var destHost string

		for i := range execResult.RedirectChain {
			hop := &execResult.RedirectChain[i]
			destParsed, _ := url.Parse(hop.DestinationURL)
			h := ""
			if destParsed != nil {
				h = strings.ToLower(destParsed.Hostname())
			}
			if strings.Contains(h, cleanDomain) {
				matchedHop = hop
				destHost = h
				break
			}
			// Also check if Location header is an absolute or protocol-relative URI with matching host
			if locParsed, err := url.Parse(hop.LocationHeader); err == nil && locParsed.Host != "" {
				locHost := strings.ToLower(locParsed.Hostname())
				if strings.Contains(locHost, cleanDomain) {
					matchedHop = hop
					destHost = locHost
					break
				}
			}
		}

		if matchedHop == nil {
			finalParsed, _ := url.Parse(execResult.FinalURL)
			if finalParsed != nil && strings.Contains(strings.ToLower(finalParsed.Hostname()), cleanDomain) {
				matchedHop = &execResult.RedirectChain[len(execResult.RedirectChain)-1]
				destHost = strings.ToLower(finalParsed.Hostname())
			}
		}

		if matchedHop != nil {
			// Check against Baseline: Did the baseline already redirect to this exact location?
			if baseline != nil && baseline.HadRedirects && strings.EqualFold(baseline.FinalURL, execResult.FinalURL) {
				finding.Classification = models.ClassificationFalsePositive
				finding.Confidence = models.ConfidenceHigh
				finding.ValidationNotes = append(finding.ValidationNotes,
					"Baseline comparison: Target naturally redirects to this destination regardless of parameter input (Fixed Redirect).")
				return finding
			}

			// Check for same-host normalization vs genuine external redirect
			if isSameOrigin(targetHost, destHost) {
				// Benign internal redirect or trailing slash
				finding.Classification = models.ClassificationFalsePositive
				finding.Confidence = models.ConfidenceHigh
				finding.ValidationNotes = append(finding.ValidationNotes,
					fmt.Sprintf("Redirect remained on the same host (%s). Not an external Open Redirect.", destHost))
				return finding
			}

			// Genuine External Open Redirect confirmed!
			finding.Classification = models.ClassificationConfirmed
			finding.Confidence = models.ConfidenceHigh
			finding.Evidence.DestinationHostMatch = true
			finding.Evidence.InjectedDestination = execResult.FinalURL
			finding.Evidence.LocationHeader = matchedHop.LocationHeader

			if len(execResult.RedirectChain) > 1 {
				finding.VulnerabilityType = models.VulnServerSideChained
				finding.ValidationNotes = append(finding.ValidationNotes,
					fmt.Sprintf("Confirmed multi-hop redirect chain culminating in external domain %q.", destHost))
			} else {
				finding.VulnerabilityType = models.VulnServerSideDirect
				finding.ValidationNotes = append(finding.ValidationNotes,
					fmt.Sprintf("Confirmed immediate HTTP %d redirect to external domain %q via Location header.", matchedHop.StatusCode, destHost))
			}

			finding.ValidationNotes = append(finding.ValidationNotes,
				fmt.Sprintf("Attacker-supplied input via parameter %q successfully dictated the redirect destination.", injected.Parameter),
				fmt.Sprintf("Payload category: %s", injected.PayloadCategory))

			return finding
		}
	}

	// -------------------------------------------------------------
	// 2. Check for Client-Side Redirects (Meta Refresh or JavaScript)
	// -------------------------------------------------------------
	if clientSide != nil && clientSide.Detected {
		finding.VulnerabilityType = clientSide.Type
		finding.Classification = models.ClassificationPotential
		finding.Confidence = models.ConfidenceMedium
		finding.FinalDestination = clientSide.TargetDestination
		finding.Evidence.ScriptSnippet = clientSide.Snippet
		finding.Evidence.InjectedDestination = clientSide.TargetDestination

		if clientSide.Type == models.VulnClientSideMeta {
			finding.ValidationNotes = append(finding.ValidationNotes,
				fmt.Sprintf("Detected HTML <meta http-equiv=\"refresh\"> directive pointing to %q.", clientSide.TargetDestination),
				"Requires browser environment to trigger execution.",
			)
		} else {
			finding.ValidationNotes = append(finding.ValidationNotes,
				fmt.Sprintf("Detected client-side JavaScript navigation pattern targeting %q.", clientSide.TargetDestination),
				fmt.Sprintf("Code snippet: %s", clientSide.Snippet),
				"Requires browser environment or DOM execution to trigger navigation.",
			)
		}

		return finding
	}

	// -------------------------------------------------------------
	// 3. Check for Reflection without Navigation
	// -------------------------------------------------------------
	if strings.Contains(execResult.FinalBody, injected.Payload) {
		finding.Evidence.ReflectedInBody = true
		finding.Classification = models.ClassificationFalsePositive
		finding.Confidence = models.ConfidenceHigh
		finding.ValidationNotes = append(finding.ValidationNotes,
			"Payload is reflected in the HTTP response body but does not trigger an HTTP redirect or client-side navigation.",
			"Classified as False Positive (Reflection != Open Redirect).",
		)
		return finding
	}

	// Default fallback: No redirect occurred
	finding.Classification = models.ClassificationFalsePositive
	finding.Confidence = models.ConfidenceHigh
	finding.ValidationNotes = append(finding.ValidationNotes, "No redirect response or navigation behavior observed.")
	return finding
}

func isSameOrigin(hostA, hostB string) bool {
	cleanA := strings.ToLower(strings.TrimSpace(hostA))
	cleanB := strings.ToLower(strings.TrimSpace(hostB))

	if cleanA == "" || cleanB == "" {
		return false
	}

	if cleanA == cleanB {
		return true
	}

	return false
}
