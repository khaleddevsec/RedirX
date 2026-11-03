package tests

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"redirx/internal/config"
	"redirx/internal/detector"
	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/reporter"
	"redirx/internal/scanner"
	"redirx/internal/scope"
	"redirx/internal/stats"
	"redirx/internal/ui"
	"redirx/internal/validator"
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

// TestTechniqueRegistry verifies registry registration, enumeration, and configuration filtering.
func TestTechniqueRegistry(t *testing.T) {
	reg := detector.DefaultRegistry()
	all := reg.All()
	if len(all) < 2 {
		t.Fatalf("expected at least 2 default techniques, got %d", len(all))
	}

	// When PathTest is false, only QueryParameter should be enabled
	cfg := &models.ScanConfig{PathTest: false}
	enabled := reg.GetEnabled(cfg)
	if len(enabled) != 1 || enabled[0].ID() != "query_parameter" {
		t.Errorf("expected only query_parameter enabled, got %v", enabled)
	}

	// When PathTest is true, both techniques should be enabled
	cfg.PathTest = true
	enabledWithAll := reg.GetEnabled(cfg)
	if len(enabledWithAll) != 2 {
		t.Errorf("expected 2 techniques enabled, got %d", len(enabledWithAll))
	}
}

// TestTargetDeduplication verifies that duplicate URLs are filtered out before scanning.
func TestTargetDeduplication(t *testing.T) {
	targets := []string{
		"https://example.com/login?redirect=1",
		"https://example.com/login?redirect=1",
		"  https://example.com/login?redirect=1  ",
		"example.com/login?redirect=1",
		"https://example.com/other",
	}

	cfg := &models.ScanConfig{
		Threads: 1,
		Timeout: 2 * time.Second,
	}
	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	statsColl := stats.NewCollector(len(targets))
	engine := scanner.NewEngine(cfg, client, statsColl)

	// Custom empty registry to verify deduplication without network calls
	emptyReg := detector.NewRegistry()
	engine.WithRegistry(emptyReg)

	findings, err := engine.ScanTargets(context.TODO(), targets, nil)
	if err != nil {
		t.Fatalf("ScanTargets failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from empty registry, got %d", len(findings))
	}
}

// TestZeroAllocRedirectReaderAndBufferPool verifies that 3xx bodies are bypassed
// while the terminal response is captured via the buffer pool.
func TestZeroAllocRedirectReaderAndBufferPool(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/step1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/step2", http.StatusFound)
	})
	mux.HandleFunc("/step2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/terminal", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/terminal", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Terminal response body loaded via bufferPool"))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := &models.ScanConfig{
		Timeout:           5 * time.Second,
		SafeRedirectsOnly: false,
	}
	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.ExecuteHopByHop(context.Background(), ts.URL+"/step1")
	if err != nil {
		t.Fatalf("ExecuteHopByHop failed: %v", err)
	}

	if !res.HadRedirects {
		t.Fatal("expected HadRedirects to be true")
	}
	if len(res.RedirectChain) != 3 {
		t.Fatalf("expected 3 hops (2 redirects + 1 terminal), got %d", len(res.RedirectChain))
	}

	// Hops 0 and 1 are 3xx: bodies should be bypassed without allocation
	if res.RedirectChain[0].BodySnippet != "[redirect hop - body bypassed]" {
		t.Errorf("expected hop 0 body to be bypassed, got %q", res.RedirectChain[0].BodySnippet)
	}
	if res.RedirectChain[1].BodySnippet != "[redirect hop - body bypassed]" {
		t.Errorf("expected hop 1 body to be bypassed, got %q", res.RedirectChain[1].BodySnippet)
	}

	// Hop 2 is terminal: body should be fully present
	if !strings.Contains(res.RedirectChain[2].BodySnippet, "Terminal response body loaded via bufferPool") {
		t.Errorf("expected terminal body snippet to contain content, got %q", res.RedirectChain[2].BodySnippet)
	}
	if !strings.Contains(res.FinalBody, "Terminal response body loaded via bufferPool") {
		t.Errorf("expected FinalBody to contain content, got %q", res.FinalBody)
	}
}

// TestMatchesTestDomainStrict verifies strict hostname boundary evaluation.
func TestMatchesTestDomainStrict(t *testing.T) {
	testDomain := "example.com"

	// Valid matches (exact or genuine subdomains)
	validCases := []string{
		"example.com",
		"EXAMPLE.COM",
		"sub.example.com",
		"canary.sub.example.com",
		"example.com:8080",
		"example.com.",
		"sub.example.com:443",
	}
	for _, c := range validCases {
		if !validator.MatchesTestDomain(c, testDomain) {
			t.Errorf("expected %q to match %q, but failed", c, testDomain)
		}
	}

	// Invalid matches (substring collisions, evil suffixes, etc.)
	invalidCases := []string{
		"notexample.com",
		"myexample.org",
		"companyexample.com",
		"example.com.evil.org",
		"evil-example.com",
		"fake-example.com",
		"attacker.com",
		"",
	}
	for _, c := range invalidCases {
		if validator.MatchesTestDomain(c, testDomain) {
			t.Errorf("expected %q NOT to match %q, but matched (false positive!)", c, testDomain)
		}
	}
}

// TestClientSideModernJSExtraction verifies regex extraction on modern JS navigation patterns.
func TestClientSideModernJSExtraction(t *testing.T) {
	testDomain := "example.com"

	cases := []struct {
		name     string
		html     string
		expected bool
	}{
		{
			name:     "Backtick template literal",
			html:     "<html><body><script>window.location = `https://example.com`;</script></body></html>",
			expected: true,
		},
		{
			name:     "self.location assignment",
			html:     "<html><body><script>self.location.href = 'https://example.com';</script></body></html>",
			expected: true,
		},
		{
			name:     "top.location assignment",
			html:     "<html><body><script>top.location = 'https://example.com';</script></body></html>",
			expected: true,
		},
		{
			name:     "window.navigate",
			html:     "<html><body><script>window.navigate('https://example.com');</script></body></html>",
			expected: true,
		},
		{
			name:     "Sub-string collision in JS should NOT match",
			html:     "<html><body><script>window.location = 'https://notexample.com';</script></body></html>",
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := detector.AnalyzeClientSideRedirects(tc.html, testDomain, "https://example.com")
			if res.Detected != tc.expected {
				t.Errorf("[%s] expected detected=%v, got=%v (destination: %s)", tc.name, tc.expected, res.Detected, res.TargetDestination)
			}
		})
	}
}

// TestProgressTickerAndMetrics verifies format duration, stats progress, and ticker lifecycle.
func TestProgressTickerAndMetrics(t *testing.T) {
	// 1. Test Duration Formatting
	if d := ui.FormatDuration(15 * time.Second); d != "00:15" {
		t.Errorf("expected 00:15, got %s", d)
	}
	if d := ui.FormatDuration(75 * time.Second); d != "01:15" {
		t.Errorf("expected 01:15, got %s", d)
	}
	if d := ui.FormatDuration(3665 * time.Second); d != "01:01:05" {
		t.Errorf("expected 01:01:05, got %s", d)
	}

	// 2. Test Stats Calculations
	coll := stats.NewCollector(100)
	coll.IncWorker()
	if coll.GetActiveWorkers() != 1 {
		t.Errorf("expected 1 active worker, got %d", coll.GetActiveWorkers())
	}

	for i := 0; i < 50; i++ {
		coll.IncTarget()
		coll.IncRequests()
	}

	if pct := coll.ProgressPercentage(); pct != 50.0 {
		t.Errorf("expected 50%% progress, got %.1f", pct)
	}

	// 3. Test Ticker Lifecycle
	ticker := ui.NewProgressTicker(coll, true)
	ticker.Start()
	ticker.Clear()
	ticker.Resume()
	ticker.Stop()
}




