package detector

import (
	"net/url"
	"regexp"
	"strings"

	"redirx/internal/models"
	"redirx/internal/validator"
)

// Regex patterns for client-side redirection detection supporting modern JS, SPA routers, and template literals
var (
	// Meta refresh: <meta http-equiv="refresh" content="0; url=https://example.com">
	metaRefreshRegex = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?[0-9]*\s*;\s*url=([^"'>\s]+)["']?`)
	// Alternative meta attribute order: <meta content="0; url=https://..." http-equiv="refresh">
	metaRefreshAltRegex = regexp.MustCompile(`(?i)<meta[^>]+content=["']?[0-9]*\s*;\s*url=([^"'>\s]+)["']?[^>]+http-equiv=["']?refresh["']?`)

	// JavaScript window.location / document.location / self.location / top.location assignments (supports quotes and backticks)
	jsLocationAssignRegex = regexp.MustCompile(`(?i)(?:window\.|document\.|self\.|top\.|parent\.)?location(?:\.href)?\s*=\s*["'\x60]?([^"'\x60>\s;]+)["'\x60]?`)
	// JavaScript location.replace(...)
	jsLocationReplaceRegex = regexp.MustCompile(`(?i)(?:window\.|document\.|self\.|top\.|parent\.)?location\.replace\s*\(\s*["'\x60]?([^"'\x60\s\)]+)["'\x60]?\s*\)`)
	// JavaScript location.assign(...)
	jsLocationAssignFuncRegex = regexp.MustCompile(`(?i)(?:window\.|document\.|self\.|top\.|parent\.)?location\.assign\s*\(\s*["'\x60]?([^"'\x60\s\)]+)["'\x60]?\s*\)`)
	// JavaScript window.navigate(...)
	jsWindowNavigateRegex = regexp.MustCompile(`(?i)(?:window\.)?navigate\s*\(\s*["'\x60]?([^"'\x60\s\)]+)["'\x60]?\s*\)`)
)

// ClientSideResult contains any detected client-side navigation patterns.
type ClientSideResult = models.ClientSideResult

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

	// 4. Check for JavaScript window.navigate(...)
	if matches := jsWindowNavigateRegex.FindStringSubmatch(body); len(matches) > 1 {
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

	// 5. Check for JavaScript location = ... / location.href = ...
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
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return false
	}

	// Direct literal payload match
	if cleanPayload != "" && strings.EqualFold(destination, cleanPayload) {
		return true
	}

	// Extract hostname if destination is a valid absolute or scheme-relative URL
	destForParse := destination
	if strings.HasPrefix(destForParse, "//") {
		destForParse = "https:" + destForParse
	}

	if parsed, err := url.Parse(destForParse); err == nil && parsed.Hostname() != "" {
		return validator.MatchesTestDomain(parsed.Hostname(), cleanDomain)
	}

	return validator.MatchesTestDomain(destination, cleanDomain)
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
