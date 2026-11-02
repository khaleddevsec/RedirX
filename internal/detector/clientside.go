package detector

import (
	"regexp"
	"strings"

	"redirx/internal/models"
)

// Regex patterns for client-side redirection detection
var (
	// Meta refresh: <meta http-equiv="refresh" content="0; url=https://example.com">
	metaRefreshRegex = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?[0-9]*\s*;\s*url=([^"'>\s]+)["']?`)
	// Alternative meta attribute order: <meta content="0; url=https://..." http-equiv="refresh">
	metaRefreshAltRegex = regexp.MustCompile(`(?i)<meta[^>]+content=["']?[0-9]*\s*;\s*url=([^"'>\s]+)["']?[^>]+http-equiv=["']?refresh["']?`)

	// JavaScript window.location or document.location assignments
	jsLocationAssignRegex = regexp.MustCompile(`(?i)(?:window\.|document\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)
	// JavaScript location.replace(...)
	jsLocationReplaceRegex = regexp.MustCompile(`(?i)(?:window\.|document\.)?location\.replace\s*\(\s*["']([^"']+)["']\s*\)`)
	// JavaScript location.assign(...)
	jsLocationAssignFuncRegex = regexp.MustCompile(`(?i)(?:window\.|document\.)?location\.assign\s*\(\s*["']([^"']+)["']\s*\)`)
)

// ClientSideResult contains any detected client-side navigation patterns.
type ClientSideResult struct {
	Detected         bool
	Type             models.VulnerabilityType
	TargetDestination string
	Snippet          string
}

// AnalyzeClientSideRedirects inspects an HTML response body for meta-refresh or JS redirects.
func AnalyzeClientSideRedirects(body string, testDomain, payload string) *ClientSideResult {
	if body == "" {
		return &ClientSideResult{Detected: false}
	}

	cleanDomain := strings.ToLower(testDomain)
	cleanPayload := strings.ToLower(payload)

	// 1. Check for Meta Refresh
	if matches := metaRefreshRegex.FindStringSubmatch(body); len(matches) > 1 {
		target := strings.TrimSpace(matches[1])
		if targetMatches(target, cleanDomain, cleanPayload) {
			return &ClientSideResult{
				Detected:          true,
				Type:              models.VulnClientSideMeta,
				TargetDestination: target,
				Snippet:           truncateSnippet(matches[0], 200),
			}
		}
	}

	if matches := metaRefreshAltRegex.FindStringSubmatch(body); len(matches) > 1 {
		target := strings.TrimSpace(matches[1])
		if targetMatches(target, cleanDomain, cleanPayload) {
			return &ClientSideResult{
				Detected:          true,
				Type:              models.VulnClientSideMeta,
				TargetDestination: target,
				Snippet:           truncateSnippet(matches[0], 200),
			}
		}
	}

	// 2. Check for JavaScript location.replace(...)
	if matches := jsLocationReplaceRegex.FindStringSubmatch(body); len(matches) > 1 {
		target := strings.TrimSpace(matches[1])
		if targetMatches(target, cleanDomain, cleanPayload) {
			return &ClientSideResult{
				Detected:          true,
				Type:              models.VulnClientSideJS,
				TargetDestination: target,
				Snippet:           truncateSnippet(matches[0], 200),
			}
		}
	}

	// 3. Check for JavaScript location.assign(...)
	if matches := jsLocationAssignFuncRegex.FindStringSubmatch(body); len(matches) > 1 {
		target := strings.TrimSpace(matches[1])
		if targetMatches(target, cleanDomain, cleanPayload) {
			return &ClientSideResult{
				Detected:          true,
				Type:              models.VulnClientSideJS,
				TargetDestination: target,
				Snippet:           truncateSnippet(matches[0], 200),
			}
		}
	}

	// 4. Check for JavaScript location = ... / location.href = ...
	if matches := jsLocationAssignRegex.FindStringSubmatch(body); len(matches) > 1 {
		target := strings.TrimSpace(matches[1])
		if targetMatches(target, cleanDomain, cleanPayload) {
			return &ClientSideResult{
				Detected:          true,
				Type:              models.VulnClientSideJS,
				TargetDestination: target,
				Snippet:           truncateSnippet(matches[0], 200),
			}
		}
	}

	return &ClientSideResult{Detected: false}
}

func targetMatches(destination, cleanDomain, cleanPayload string) bool {
	lowerDest := strings.ToLower(destination)
	if cleanDomain != "" && strings.Contains(lowerDest, cleanDomain) {
		return true
	}
	if cleanPayload != "" && strings.Contains(lowerDest, cleanPayload) {
		return true
	}
	return false
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

