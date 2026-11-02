package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"redirx/internal/detector"
	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/scanner"
	"redirx/internal/stats"
)

// setupMockVulnerableServer starts an httptest.Server simulating various redirect behaviors.
func setupMockVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	// 1. Genuine Open Redirect: redirects directly to whatever is in the 'next' parameter
	mux.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to login page"))
	})

	// 2. Normal internal redirect (same-origin trailing slash normalization)
	mux.HandleFunc("/folder", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/folder/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/folder/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Inside folder"))
	})

	// 3. Fixed redirect (always redirects to fixed landing, ignores parameter)
	mux.HandleFunc("/oauth-fixed", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fixed-landing", http.StatusFound)
	})
	mux.HandleFunc("/fixed-landing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Fixed destination"))
	})

	// 4. URL reflection without redirect (200 OK with reflected parameter)
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("<html><body>Search query was: %s</body></html>", q)))
	})

	// 5. Multi-hop chained redirect
	mux.HandleFunc("/chain-start", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("to")
		http.Redirect(w, r, "/chain-step2?to="+url.QueryEscape(dest), http.StatusFound)
	})
	mux.HandleFunc("/chain-step2", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("to")
		http.Redirect(w, r, dest, http.StatusFound)
	})

	// 6. Client-Side JavaScript redirect
	mux.HandleFunc("/client-js", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("redirect")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<html><body><script>window.location.replace("%s");</script></body></html>`, dest)))
	})

	// 7. Client-Side Meta Refresh redirect
	mux.HandleFunc("/client-meta", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("redirect")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0; url=%s"></head><body>Redirecting...</body></html>`, dest)))
	})

	// 8. Redirect Loop
	mux.HandleFunc("/loop1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop2", http.StatusFound)
	})
	mux.HandleFunc("/loop2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop1", http.StatusFound)
	})

	// 9. Legacy Python path segment stripping anomaly:
	// If path is /app/v1/profile, stripping to /app/v1/ redirects back to /app/v1/profile!
	mux.HandleFunc("/app/v1/profile", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User Profile"))
	})
	mux.HandleFunc("/app/v1/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/v1/profile", http.StatusMovedPermanently)
	})

	// 10. SSRF attempt: redirects to private IP (127.0.0.1)
	mux.HandleFunc("/ssrf-hazard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:8080/admin", http.StatusFound)
	})

	return httptest.NewServer(mux)
}

// TestIntegrationGenuineOpenRedirect verifies detection of server-side open redirect.
func TestIntegrationGenuineOpenRedirect(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	testDomain := "example.com"
	targetURL := ts.URL + "/vulnerable?next=default"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        testDomain,
		SafeRedirectsOnly: false, // Local httptest uses 127.0.0.1
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	foundConfirmed := false
	for _, f := range findings {
		if f.Classification == models.ClassificationConfirmed && strings.Contains(f.FinalDestination, testDomain) {
			foundConfirmed = true
			if f.Parameter != "next" {
				t.Errorf("expected parameter 'next', got %s", f.Parameter)
			}
			break
		}
	}

	if !foundConfirmed {
		t.Fatalf("expected genuine Open Redirect to be CONFIRMED, got: %+v", findings)
	}
}

// TestIntegrationInternalRedirectFalsePositive verifies that normal same-origin redirects are not flagged.
func TestIntegrationInternalRedirectFalsePositive(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	targetURL := ts.URL + "/folder"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        "example.com",
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	for _, f := range findings {
		if f.Classification == models.ClassificationConfirmed {
			t.Errorf("same-origin internal redirect was falsely CONFIRMED: %+v", f)
		}
	}
}

// TestIntegrationFixedRedirectBaselineElimination verifies baseline comparison eliminates false positives.
func TestIntegrationFixedRedirectBaselineElimination(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	targetURL := ts.URL + "/oauth-fixed?redirect=default"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        "example.com",
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	for _, f := range findings {
		if f.Classification == models.ClassificationConfirmed {
			t.Errorf("fixed external redirect was falsely CONFIRMED as open redirect: %+v", f)
		}
	}
}

// TestIntegrationReflectionWithoutRedirect verifies reflection does not trigger open redirect finding.
func TestIntegrationReflectionWithoutRedirect(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	targetURL := ts.URL + "/search?q=hello"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        "example.com",
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	for _, f := range findings {
		if f.Classification == models.ClassificationConfirmed {
			t.Errorf("reflection was falsely CONFIRMED as open redirect: %+v", f)
		}
	}
}

// TestIntegrationChainedRedirect verifies tracking of multi-hop redirect chains.
func TestIntegrationChainedRedirect(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	testDomain := "example.com"
	targetURL := ts.URL + "/chain-start?to=/local-home"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        testDomain,
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}

	foundChained := false
	for _, f := range findings {
		if f.Classification == models.ClassificationConfirmed && len(f.RedirectChain) >= 2 {
			foundChained = true
			if f.VulnerabilityType != models.VulnServerSideChained {
				t.Errorf("expected chained vulnerability type, got %s", f.VulnerabilityType)
			}
			break
		}
	}

	if !foundChained {
		t.Fatalf("expected multi-hop chained redirect to be detected: %+v", findings)
	}
}

// TestIntegrationClientSideJS verifies detection of JavaScript navigation.
func TestIntegrationClientSideJS(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	testDomain := "example.com"
	targetURL := ts.URL + "/client-js?redirect=default"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        testDomain,
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	foundJS := false
	for _, f := range findings {
		if f.Classification == models.ClassificationPotential && f.VulnerabilityType == models.VulnClientSideJS {
			foundJS = true
			break
		}
	}

	if !foundJS {
		t.Fatalf("expected client-side JavaScript redirect to be flagged as POTENTIAL: %+v", findings)
	}
}

// TestIntegrationClientSideMetaRefresh verifies detection of HTML meta-refresh.
func TestIntegrationClientSideMetaRefresh(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	testDomain := "example.com"
	targetURL := ts.URL + "/client-meta?redirect=default"

	cfg := &models.ScanConfig{
		TargetURL:         targetURL,
		Threads:           1,
		Timeout:           5 * time.Second,
		TestDomain:        testDomain,
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	statsColl := stats.NewCollector(1)
	engine := scanner.NewEngine(cfg, client, statsColl)

	findings, err := engine.ScanTargets(context.Background(), []string{targetURL}, nil)
	if err != nil {
		t.Fatal(err)
	}


	foundMeta := false
	for _, f := range findings {
		if f.Classification == models.ClassificationPotential && f.VulnerabilityType == models.VulnClientSideMeta {
			foundMeta = true
			break
		}
	}

	if !foundMeta {
		t.Fatalf("expected client-side Meta Refresh redirect to be flagged as POTENTIAL: %+v", findings)
	}
}

// TestIntegrationRedirectLoop verifies loop detection.
func TestIntegrationRedirectLoop(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	cfg := &models.ScanConfig{
		TargetURL:         ts.URL + "/loop1",
		Timeout:           5 * time.Second,
		MaxRedirects:      10,
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.ExecuteHopByHop(context.Background(), ts.URL+"/loop1")
	if err != nil {
		t.Fatal(err)
	}

	if res.Error != redirect.ErrCircularRedirect {
		t.Errorf("expected circular redirect error, got: %v", res.Error)
	}
}

// TestIntegrationSSRFBlocked verifies that redirects targeting private IPs are blocked when SafeRedirectsOnly is true.
func TestIntegrationSSRFBlocked(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	cfg := &models.ScanConfig{
		TargetURL:         ts.URL + "/ssrf-hazard",
		Timeout:           5 * time.Second,
		SafeRedirectsOnly: true, // SSRF protection enabled
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.ExecuteHopByHop(context.Background(), ts.URL+"/ssrf-hazard")
	if err != nil && res == nil {
		t.Fatal(err)
	}

	if res != nil && res.Error == nil {
		t.Error("expected SSRF redirect to 127.0.0.1 to be blocked, but succeeded")
	}
}

// TestIntegrationLegacyPathSegmentAnomaly verifies the migrated Python path-segment heuristic.
func TestIntegrationLegacyPathSegmentAnomaly(t *testing.T) {
	ts := setupMockVulnerableServer()
	defer ts.Close()

	cfg := &models.ScanConfig{
		TargetURL:         ts.URL + "/app/v1/profile",
		Timeout:           5 * time.Second,
		PathTest:          true,
		SafeRedirectsOnly: false,
	}

	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/app/v1/profile")
	if err != nil {
		t.Fatal(err)
	}

	if finding == nil {
		t.Fatal("expected path canonicalization anomaly finding, got nil")
	}

	if finding.VulnerabilityType != models.VulnPathCanonical {
		t.Errorf("expected VulnPathCanonical, got %s", finding.VulnerabilityType)
	}
}
