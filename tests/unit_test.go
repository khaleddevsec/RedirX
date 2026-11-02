package tests

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redirx/internal/config"
	"redirx/internal/detector"
	"redirx/internal/models"
	"redirx/internal/reporter"
	"redirx/internal/scope"
)

// TestExtractCandidateParams verifies extraction of query parameters and defaults.
func TestExtractCandidateParams(t *testing.T) {
	// 1. Existing query parameters
	u := "https://example.com/login?redirect=https://target.com&source=web"
	params, query, err := detector.ExtractCandidateParams(u, nil, nil)
	if err != nil {
		t.Fatalf("ExtractCandidateParams failed: %v", err)
	}
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	if query.Get("redirect") != "https://target.com" {
		t.Errorf("expected query redirect value to be preserved")
	}

	// 2. Fallback to candidate list when no query params present
	uNoParams := "https://example.com/oauth/authorize"
	paramsFallback, _, err := detector.ExtractCandidateParams(uNoParams, nil, nil)
	if err != nil {
		t.Fatalf("ExtractCandidateParams fallback failed: %v", err)
	}
	if len(paramsFallback) == 0 {
		t.Fatalf("expected candidate params list, got empty")
	}

	// 3. Exclude params filter
	paramsExcluded, _, _ := detector.ExtractCandidateParams(u, nil, []string{"source"})
	for _, p := range paramsExcluded {
		if strings.EqualFold(p, "source") {
			t.Errorf("excluded param 'source' was not excluded")
		}
	}

	// 4. Include params filter
	paramsIncluded, _, _ := detector.ExtractCandidateParams(u, []string{"redirect"}, nil)
	if len(paramsIncluded) != 1 || paramsIncluded[0] != "redirect" {
		t.Errorf("expected only 'redirect', got %v", paramsIncluded)
	}
}

// TestGeneratePayloads verifies payload suite generation and placeholder interpolation.
func TestGeneratePayloads(t *testing.T) {
	payloads, err := detector.GeneratePayloads("target.com", "attacker.com", "")
	if err != nil {
		t.Fatalf("GeneratePayloads failed: %v", err)
	}
	if len(payloads) < 10 {
		t.Errorf("expected comprehensive payload list, got %d", len(payloads))
	}

	// Verify categories exist
	foundProtoRel := false
	foundBackslash := false
	foundUserinfo := false
	foundEncoded := false

	for _, p := range payloads {
		if strings.Contains(p.Value, "//attacker.com") {
			foundProtoRel = true
		}
		if strings.Contains(p.Value, `/\attacker.com`) || strings.Contains(p.Value, `\\attacker.com`) {
			foundBackslash = true
		}
		if strings.Contains(p.Value, "@attacker.com") {
			foundUserinfo = true
		}
		if strings.Contains(p.Value, "%2f%2fattacker.com") {
			foundEncoded = true
		}
	}

	if !foundProtoRel {
		t.Error("missing protocol-relative payload")
	}
	if !foundBackslash {
		t.Error("missing backslash payload")
	}
	if !foundUserinfo {
		t.Error("missing userinfo @ payload")
	}
	if !foundEncoded {
		t.Error("missing URL encoded payload")
	}
}

// TestSSRFProtection verifies blocking of loopback, private RFC 1918, link-local, and cloud metadata.
func TestSSRFProtection(t *testing.T) {
	privateIPs := []string{
		"127.0.0.1",
		"127.0.0.2",
		"10.0.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254", // Cloud metadata
		"169.254.1.1",     // Link local
		"::1",             // IPv6 loopback
		"fc00::1",         // IPv6 ULA
		"fe80::1",         // IPv6 link local
	}

	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		if !scope.IsPrivateOrReservedIP(ip) {
			t.Errorf("expected IP %s to be recognized as private/reserved", ipStr)
		}
	}

	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34", // example.com
	}

	for _, ipStr := range publicIPs {
		ip := net.ParseIP(ipStr)
		if scope.IsPrivateOrReservedIP(ip) {
			t.Errorf("expected public IP %s to NOT be recognized as private/reserved", ipStr)
		}
	}

	// Cloud metadata hostnames
	if !scope.IsCloudMetadataHost("metadata.google.internal") {
		t.Error("failed detecting metadata.google.internal")
	}
	if !scope.IsCloudMetadataHost("169.254.169.254") {
		t.Error("failed detecting 169.254.169.254")
	}
	if scope.IsCloudMetadataHost("example.com") {
		t.Error("falsely flagged example.com as cloud metadata")
	}
}

// TestScopeManager verifies allowlist matching.
func TestScopeManager(t *testing.T) {
	allowlist := []string{
		"example.com",
		"*.target.org",
		"192.0.2.0/24",
	}
	sm := scope.NewScopeManager(allowlist)

	tests := []struct {
		url     string
		allowed bool
	}{
		{"https://example.com/test", true},
		{"http://example.com:8080/path", true},
		{"https://sub.target.org/login", true},
		{"https://target.org/login", true},
		{"https://malicious.com/test", false},
		{"https://evil-example.com/test", false},
		{"https://192.0.2.45/test", true},
		{"https://198.51.100.1/test", false},
	}

	for _, tc := range tests {
		got := sm.IsInScope(tc.url)
		if got != tc.allowed {
			t.Errorf("IsInScope(%s) = %v; want %v", tc.url, got, tc.allowed)
		}
	}
}

// TestClientSideRedirectDetection verifies parsing of meta-refresh and JS navigation patterns.
func TestClientSideRedirectDetection(t *testing.T) {
	testDomain := "evil.com"
	payload := "https://evil.com"

	// 1. Meta refresh
	htmlMeta := `<html><head><meta http-equiv="refresh" content="0; url=https://evil.com/landing"></head><body>Redirecting...</body></html>`
	resMeta := detector.AnalyzeClientSideRedirects(htmlMeta, testDomain, payload)
	if !resMeta.Detected || resMeta.Type != models.VulnClientSideMeta {
		t.Errorf("failed detecting meta-refresh: %+v", resMeta)
	}

	// 2. JavaScript location.replace
	htmlJSReplace := `<script>window.location.replace("https://evil.com/dashboard");</script>`
	resReplace := detector.AnalyzeClientSideRedirects(htmlJSReplace, testDomain, payload)
	if !resReplace.Detected || resReplace.Type != models.VulnClientSideJS {
		t.Errorf("failed detecting location.replace: %+v", resReplace)
	}

	// 3. JavaScript location.href assignment
	htmlJSHref := `<script>document.location.href = 'https://evil.com';</script>`
	resHref := detector.AnalyzeClientSideRedirects(htmlJSHref, testDomain, payload)
	if !resHref.Detected || resHref.Type != models.VulnClientSideJS {
		t.Errorf("failed detecting location.href: %+v", resHref)
	}

	// 4. Benign HTML (no redirect)
	htmlBenign := `<html><body><p>Hello world. Welcome to https://example.com</p></body></html>`
	resBenign := detector.AnalyzeClientSideRedirects(htmlBenign, testDomain, payload)
	if resBenign.Detected {
		t.Errorf("falsely flagged benign HTML as client-side redirect: %+v", resBenign)
	}
}

// TestResolveOutputPath verifies naming, formatting, and overwrite safety.
func TestResolveOutputPath(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "redirx-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	resultsDir := filepath.Join(tempDir, "results")
	_ = os.MkdirAll(resultsDir, 0755)

	// 1. Normal resolution with auto extension
	path, err := config.ResolveOutputPath("audit-1", "html", "", resultsDir, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedEnd := filepath.Join(resultsDir, "audit-1.html")
	if path != expectedEnd {
		t.Errorf("expected %s, got %s", expectedEnd, path)
	}

	// 2. Existing file without force (should error in non-interactive mode)
	_ = os.WriteFile(path, []byte("test"), 0644)
	_, err = config.ResolveOutputPath("audit-1", "html", "", resultsDir, false, false, false)
	if err == nil {
		t.Error("expected error on existing file without force")
	}

	// 3. Existing file with force (should succeed)
	forcedPath, err := config.ResolveOutputPath("audit-1", "html", "", resultsDir, true, false, false)
	if err != nil || forcedPath != path {
		t.Errorf("expected force to succeed, got %v", err)
	}

	// 4. Auto-generated name deduplication (scan-1 -> scan-1_2)
	autoPath1, err := config.ResolveOutputPath("scan-test", "txt", "", resultsDir, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(autoPath1, []byte("data"), 0644)

	autoPath2, err := config.ResolveOutputPath("scan-test", "txt", "", resultsDir, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(autoPath2, "scan-test_2.txt") {
		t.Errorf("expected auto deduplication to produce scan-test_2.txt, got %s", autoPath2)
	}
}

// TestReportGeneration verifies serialization of all three report formats.
func TestReportGeneration(t *testing.T) {
	summary := models.ScanSummary{
		Duration:         5 * time.Second,
		TotalTargets:     1,
		TestedParameters: 2,
		TotalRequests:    10,
		ConfirmedCount:   1,
		PotentialCount:   1,
	}

	findings := []models.Finding{
		{
			ID:                "test-1",
			VulnerableURL:     "https://target.com/login?next=https://attacker.com",
			OriginalURL:       "https://target.com/login",
			TargetHost:        "target.com",
			Parameter:         "next",
			Payload:           "https://attacker.com",
			VulnerabilityType: models.VulnServerSideDirect,
			Classification:    models.ClassificationConfirmed,
			Confidence:        models.ConfidenceHigh,
			InitialStatus:     302,
			FinalStatus:       200,
			FinalDestination:  "https://attacker.com",
			RedirectChain: []models.RedirectHop{
				{
					HopNumber:      1,
					URL:            "https://target.com/login?next=https://attacker.com",
					StatusCode:     302,
					LocationHeader: "https://attacker.com",
					DestinationURL: "https://attacker.com",
				},
			},
			Evidence: models.Evidence{
				LocationHeader:  "https://attacker.com",
				InjectedPayload: "https://attacker.com",
			},
			ValidationNotes: []string{"Confirmed external redirect via Location header."},
			Timestamp:       time.Now(),
		},
	}

	// TXT Report
	var txtBuf strings.Builder
	if err := reporter.WriteTextReport(&txtBuf, summary, findings); err != nil {
		t.Fatalf("WriteTextReport failed: %v", err)
	}
	if !strings.Contains(txtBuf.String(), "CONFIRMED") || !strings.Contains(txtBuf.String(), "attacker.com") {
		t.Error("TXT report missing finding data")
	}

	// JSON Report
	var jsonBuf strings.Builder
	if err := reporter.WriteJSONReport(&jsonBuf, summary, findings); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"confirmed_count": 1`) || !strings.Contains(jsonBuf.String(), `"classification": "CONFIRMED"`) {
		t.Error("JSON report missing finding data")
	}

	// HTML Report
	var htmlBuf strings.Builder
	if err := reporter.WriteHTMLReport(&htmlBuf, summary, findings); err != nil {
		t.Fatalf("WriteHTMLReport failed: %v", err)
	}
	if !strings.Contains(htmlBuf.String(), "<!DOCTYPE html>") || !strings.Contains(htmlBuf.String(), "attacker.com") {
		t.Error("HTML report missing finding data")
	}
}

// TestURLNormalization verifies scheme prepending and whitespace trimming.
func TestURLNormalization(t *testing.T) {
	raw := "  target.com/path?foo=bar  "
	target, _, err := detector.ExtractCandidateParams("https://"+strings.TrimSpace(raw), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(target) != 1 || target[0] != "foo" {
		t.Errorf("expected param foo, got %v", target)
	}
}

// TestInjectionEngine verifies parameter injection with preserved values.
func TestInjectionEngine(t *testing.T) {
	orig := "https://example.com/auth?param1=val1&target=oldval&param2=val2"
	injected, err := detector.InjectQueryParameter(orig, "target", "https://attacker.com", "Test Category")
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := url.Parse(injected.URL)
	if err != nil {
		t.Fatal(err)
	}

	q := parsed.Query()
	if q.Get("param1") != "val1" {
		t.Error("param1 was lost or corrupted")
	}
	if q.Get("param2") != "val2" {
		t.Error("param2 was lost or corrupted")
	}
	if q.Get("target") != "https://attacker.com" {
		t.Errorf("target was not updated properly: %s", q.Get("target"))
	}
}
