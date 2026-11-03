package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/detector"
)

// TestPathDetectionSuite implements the full behavior comparison and validation suite
// between No-Redirect.py and the improved Go detection engine.
func TestPathDetectionSuite(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Genuine Path Bounce-Back (Original Python Positive Case)
	mux.HandleFunc("/admin/login.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Admin Login Page"))
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/login.php", http.StatusFound)
	})

	// 2. Safe Endpoint (No Redirect)
	mux.HandleFunc("/portal/view", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Portal View"))
	})
	mux.HandleFunc("/portal/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Portal Index Clean"))
	})

	// 3. Catch-All Homepage Redirect (Python False Positive Case)
	// Server redirects all unknown or stripped directories to root /
	mux.HandleFunc("/catchall/sub/item", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/catchall/sub/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Home Root"))
	})

	// 4. Trailing Slash Normalization (Benign Redirect)
	mux.HandleFunc("/blog/tech", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Tech Blog"))
	})
	mux.HandleFunc("/blog/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/blog", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/blog", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Blog Index"))
	})

	// 5. Execution After Redirect (EAR) with Unauthenticated Session Cookie Leak
	mux.HandleFunc("/secure/login.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Secure Login"))
	})
	mux.HandleFunc("/secure/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "PHPSESSID=unauthenticated_leaked_session; path=/")
		w.Header().Set("Content-Length", "1250")
		http.Redirect(w, r, "/secure/login.php", http.StatusFound)
	})

	// 6. Query Parameter Preservation
	var receivedQuery string
	mux.HandleFunc("/querytest/action.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Query Test Page"))
	})
	mux.HandleFunc("/querytest/", func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		http.Redirect(w, r, "/querytest/action.php?"+receivedQuery, http.StatusFound)
	})

	// 7. Relative Redirect
	mux.HandleFunc("/reltest/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Relative Target"))
	})
	mux.HandleFunc("/reltest/", func(w http.ResponseWriter, r *http.Request) {
		// Relative Location header
		w.Header().Set("Location", "login")
		w.WriteHeader(http.StatusFound)
	})

	// 8. Multi-Hop Redirect Chain
	mux.HandleFunc("/chain/auth.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Chain Auth"))
	})
	mux.HandleFunc("/chain/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chain/step2", http.StatusFound)
	})
	mux.HandleFunc("/chain/step2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chain/auth.php", http.StatusFound)
	})

	// 9. Case Normalization
	mux.HandleFunc("/case/profile.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Profile Page"))
	})
	mux.HandleFunc("/case/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/CASE/PROFILE.PHP", http.StatusFound)
	})
	mux.HandleFunc("/CASE/PROFILE.PHP", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Profile Page Uppercase"))
	})

	// 10. HTTP 404 Error Status on Test Path
	mux.HandleFunc("/errortest/view.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("View Page"))
	})
	mux.HandleFunc("/errortest/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// 11. Timeout Simulation
	mux.HandleFunc("/timeout/slow.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Slow Page"))
	})
	mux.HandleFunc("/timeout/", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := &models.ScanConfig{
		Timeout:           2 * time.Second,
		SafeRedirectsOnly: false,
	}
	client, err := redirect.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Run("1_CorrectlyDetected_GenuinePathBounceBack", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/admin/login.php")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected genuine path bounce-back finding, got nil")
		}
		if finding.VulnerabilityType != models.VulnPathCanonical {
			t.Errorf("expected VulnPathCanonical, got %s", finding.VulnerabilityType)
		}
		if finding.Classification != models.ClassificationPotential {
			t.Errorf("expected Potential without EAR body, got %s", finding.Classification)
		}
	})

	t.Run("2_SafeEndpoint_NoRedirect", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/portal/view")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding != nil {
			t.Fatalf("expected nil finding for safe endpoint, got: %+v", finding)
		}
	})

	t.Run("3_FalsePositiveEliminated_CatchAllRoot", func(t *testing.T) {
		// Python logic flagged catch-all redirects to / as vulnerable.
		// Go engine must filter this out!
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/catchall/sub/item")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding != nil {
			t.Fatalf("expected nil finding for catch-all root redirect, got: %+v", finding)
		}
	})

	t.Run("4_FalsePositiveEliminated_TrailingSlashNormalization", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/blog/tech")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding != nil {
			t.Fatalf("expected nil finding for trailing slash normalization, got: %+v", finding)
		}
	})

	t.Run("5_ExecutionAfterRedirect_SessionCookieLeakage", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/secure/login.php")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected finding for EAR endpoint, got nil")
		}
		if finding.Classification != models.ClassificationConfirmed {
			t.Errorf("expected CONFIRMED classification for session cookie leak, got %s", finding.Classification)
		}
		if finding.Confidence != models.ConfidenceHigh {
			t.Errorf("expected HIGH confidence, got %s", finding.Confidence)
		}
	})

	t.Run("6_QueryParameterPreservation", func(t *testing.T) {
		receivedQuery = ""
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/querytest/action.php?lang=bn&role=admin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected finding, got nil")
		}
		if receivedQuery != "lang=bn&role=admin" {
			t.Errorf("expected query parameters preserved on test request, got %q", receivedQuery)
		}
	})

	t.Run("7_RelativeRedirectResolution", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/reltest/login")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected finding for relative redirect, got nil")
		}
	})

	t.Run("8_MultiHopChainedRedirect", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/chain/auth.php")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected finding for chained redirect, got nil")
		}
		if len(finding.RedirectChain) < 2 {
			t.Errorf("expected at least 2 redirect hops, got %d", len(finding.RedirectChain))
		}
	})

	t.Run("9_CaseInsensitivePathNormalization", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/case/profile.php")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("expected finding despite uppercase destination, got nil")
		}
	})

	t.Run("10_HTTP404Discarded", func(t *testing.T) {
		finding, err := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/errortest/view.php")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if finding != nil {
			t.Fatalf("expected nil finding for 404 test path, got: %+v", finding)
		}
	})

	t.Run("11_InsufficientPathDepth", func(t *testing.T) {
		// Depth 0
		f0, _ := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/")
		if f0 != nil {
			t.Error("expected nil for root path")
		}
		// Depth 1
		f1, _ := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, ts.URL+"/admin")
		if f1 != nil {
			t.Error("expected nil for 1-segment path")
		}
	})

	t.Run("12_MalformedAndInvalidURLs", func(t *testing.T) {
		// Empty string
		fEmpty, _ := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, "")
		if fEmpty != nil {
			t.Error("expected nil for empty URL")
		}
		// Non-HTTP scheme
		fFTP, _ := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, "ftp://example.com/admin/login")
		if fFTP != nil {
			t.Error("expected nil for non-HTTP URL")
		}
		// Malformed URL
		fBad, _ := detector.CheckPathCanonicalizationAnomaly(context.Background(), client, "http://[invalid:host:80/admin/login")
		if fBad != nil {
			t.Error("expected nil for malformed URL")
		}
	})

	t.Run("13_TimeoutGracefulHandling", func(t *testing.T) {
		fastCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		finding, err := detector.CheckPathCanonicalizationAnomaly(fastCtx, client, ts.URL+"/timeout/slow.php")
		if finding != nil {
			t.Errorf("expected nil finding on timeout, got %+v", finding)
		}
		// err can be context.DeadlineExceeded or nil, but no panic
		_ = err
	})
}
