package redirect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"redirx/internal/models"
	"redirx/internal/scope"
)

var (
	ErrMaxRedirectsExceeded = errors.New("maximum redirect depth exceeded")
	ErrCircularRedirect     = errors.New("circular redirect loop detected")
)

// Client wraps an HTTP client and provides hop-by-hop inspection.
type Client struct {
	httpClient         *http.Client
	transport          *http.Transport
	maxRedirects       int
	maxResponseSize    int64
	headers            map[string]string
	cookies            string
	userAgent          string
	enforceSSRF        bool
	insecureSkipVerify bool
}

// NewClient creates an HTTP client configured with SSRF protection and custom options.
func NewClient(cfg *models.ScanConfig) (*Client, error) {
	maxRedirects := cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	maxResponseSize := cfg.MaxResponseSize
	if maxResponseSize <= 0 {
		maxResponseSize = 2 * 1024 * 1024 // 2MB default
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		DialContext:           scope.NewSafeDialContext(timeout, cfg.SafeRedirectsOnly),
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     false,
	}

	if cfg.ProxyURL != "" {
		proxy, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", cfg.ProxyURL, err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	// Disable automatic redirect following in the underlying client
	// so that ExecuteHopByHop can manually inspect every hop.
	rawHTTPClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	headerMap := make(map[string]string)
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = "RedirX/1.0 (+https://github.com/khaleddevsec/RedirX)"
	}

	return &Client{
		httpClient:         rawHTTPClient,
		transport:          transport,
		maxRedirects:       maxRedirects,
		maxResponseSize:    maxResponseSize,
		headers:            headerMap,
		cookies:            cfg.Cookies,
		userAgent:          ua,
		enforceSSRF:        cfg.SafeRedirectsOnly,
		insecureSkipVerify: cfg.InsecureSkipVerify,
	}, nil
}

// ExecutionResult holds all details of a completed hop-by-hop HTTP request.
type ExecutionResult struct {
	InitialURL     string
	FinalURL       string
	FinalStatus    int
	FinalBody      string
	FinalHeaders   http.Header
	RedirectChain  []models.RedirectHop
	HadRedirects   bool
	Error          error
}

// ExecuteHopByHop performs a request and traces each redirect hop manually.
func (c *Client) ExecuteHopByHop(ctx context.Context, targetURL string) (*ExecutionResult, error) {
	currentURL := targetURL
	visited := make(map[string]struct{})
	var chain []models.RedirectHop

	result := &ExecutionResult{
		InitialURL: targetURL,
		FinalURL:   targetURL,
	}

	for hopCount := 1; hopCount <= c.maxRedirects; hopCount++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Loop detection
		if _, seen := visited[currentURL]; seen {
			hop := models.RedirectHop{
				HopNumber: hopCount,
				URL:       currentURL,
				Error:     ErrCircularRedirect.Error(),
			}
			chain = append(chain, hop)
			result.RedirectChain = chain
			result.Error = ErrCircularRedirect
			return result, nil
		}
		visited[currentURL] = struct{}{}

		// Validate SSRF for current hop target
		if c.enforceSSRF {
			if err := scope.ValidateURLForSSRF(ctx, currentURL); err != nil {
				hop := models.RedirectHop{
					HopNumber: hopCount,
					URL:       currentURL,
					Error:     err.Error(),
				}
				chain = append(chain, hop)
				result.RedirectChain = chain
				result.Error = err
				return result, nil
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request for %s: %w", currentURL, err)
		}

		// Set headers
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		for k, v := range c.headers {
			req.Header.Set(k, v)
		}

		if c.cookies != "" {
			req.Header.Set("Cookie", c.cookies)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			hop := models.RedirectHop{
				HopNumber: hopCount,
				URL:       currentURL,
				Error:     err.Error(),
			}
			chain = append(chain, hop)
			result.RedirectChain = chain
			result.Error = err
			return result, nil
		}

		// Read response body safely with size limit
		limitedReader := io.LimitReader(resp.Body, c.maxResponseSize)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		_ = resp.Body.Close()

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			hop := models.RedirectHop{
				HopNumber:  hopCount,
				URL:        currentURL,
				StatusCode: resp.StatusCode,
				Error:      readErr.Error(),
			}
			chain = append(chain, hop)
			result.RedirectChain = chain
			result.Error = readErr
			return result, nil
		}

		bodyStr := string(bodyBytes)
		locHeader := resp.Header.Get("Location")

		hopHeaderMap := make(map[string]string)
		for k, v := range resp.Header {
			if len(v) > 0 {
				hopHeaderMap[k] = v[0]
			}
		}

		snippet := bodyStr
		if len(snippet) > 500 {
			snippet = snippet[:500] + "... [truncated]"
		}

		hop := models.RedirectHop{
			HopNumber:      hopCount,
			URL:            currentURL,
			StatusCode:     resp.StatusCode,
			LocationHeader: locHeader,
			Headers:        hopHeaderMap,
			BodySnippet:    snippet,
		}

		result.FinalStatus = resp.StatusCode
		result.FinalURL = currentURL
		result.FinalBody = bodyStr
		result.FinalHeaders = resp.Header

		// Determine if this is a redirect status (301, 302, 303, 307, 308)
		isRedirectStatus := resp.StatusCode >= 300 && resp.StatusCode < 400

		if isRedirectStatus && locHeader != "" {
			result.HadRedirects = true

			// Resolve relative redirect against current URL
			baseParsed, parseErr := url.Parse(currentURL)
			if parseErr != nil {
				hop.Error = fmt.Sprintf("invalid base URL %q: %v", currentURL, parseErr)
				chain = append(chain, hop)
				result.RedirectChain = chain
				return result, nil
			}

			resolvedDest, resolveErr := baseParsed.Parse(locHeader)
			if resolveErr != nil {
				hop.Error = fmt.Sprintf("failed to parse Location %q: %v", locHeader, resolveErr)
				chain = append(chain, hop)
				result.RedirectChain = chain
				return result, nil
			}

			destinationStr := resolvedDest.String()
			hop.DestinationURL = destinationStr
			chain = append(chain, hop)

			// Next hop
			currentURL = destinationStr
			result.FinalURL = currentURL
		} else {
			// Terminal response (200, 404, 500, etc.)
			chain = append(chain, hop)
			result.RedirectChain = chain
			return result, nil
		}
	}

	result.RedirectChain = chain
	result.Error = ErrMaxRedirectsExceeded
	return result, nil
}

