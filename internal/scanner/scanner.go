package scanner

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"redirx/internal/detector"
	"redirx/internal/logger"
	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/scope"
	"redirx/internal/stats"
)

// Engine coordinates the multi-threaded scanning process across pluggable detection techniques.
type Engine struct {
	cfg         *models.ScanConfig
	client      *redirect.Client
	scope       *scope.ScopeManager
	rateLimiter *HostRateLimiter
	stats       *stats.Collector
	registry    *detector.Registry
}

// NewEngine constructs a new scanning engine instance with the default technique registry.
func NewEngine(cfg *models.ScanConfig, client *redirect.Client, statsColl *stats.Collector) *Engine {
	return &Engine{
		cfg:         cfg,
		client:      client,
		scope:       scope.NewScopeManager(cfg.Allowlist),
		rateLimiter: NewHostRateLimiter(cfg.Delay),
		stats:       statsColl,
		registry:    detector.DefaultRegistry(),
	}
}

// WithRegistry sets a custom technique registry on the engine.
func (e *Engine) WithRegistry(r *detector.Registry) *Engine {
	if r != nil {
		e.registry = r
	}
	return e
}

// Execute implements detector.RequestExecutor.
func (e *Engine) Execute(ctx context.Context, targetURL string) (*redirect.ExecutionResult, error) {
	e.rateLimiter.Wait(targetURL)
	e.stats.IncRequests()
	return e.client.ExecuteHopByHop(ctx, targetURL)
}

// Wait implements detector.RequestExecutor.
func (e *Engine) Wait(targetURL string) {
	e.rateLimiter.Wait(targetURL)
}

// RecordRequest implements detector.RequestExecutor.
func (e *Engine) RecordRequest() {
	e.stats.IncRequests()
}

// RecordFinding implements detector.RequestExecutor.
func (e *Engine) RecordFinding(classification models.Classification) {
	e.stats.AddFinding(classification)
}

// RecordError implements detector.RequestExecutor.
func (e *Engine) RecordError(err string) {
	e.stats.AddError(err)
}

// IncrementParameters implements detector.RequestExecutor.
func (e *Engine) IncrementParameters() {
	e.stats.IncParameters()
}

// FindingHandler is invoked whenever a relevant finding is generated.
type FindingHandler func(finding *models.Finding)

// ScanTargets executes scanning concurrently across target URLs using a worker pool.
// Automatically deduplicates input URLs to avoid redundant requests.
func (e *Engine) ScanTargets(ctx context.Context, targets []string, handler FindingHandler) ([]models.Finding, error) {
	var (
		findings   []models.Finding
		findingsMu sync.Mutex
	)

	// Deduplicate and normalize input targets
	seen := make(map[string]struct{})
	var uniqueTargets []string
	for _, t := range targets {
		normalized := normalizeTargetURL(t)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		uniqueTargets = append(uniqueTargets, normalized)
	}

	if len(uniqueTargets) == 0 {
		return nil, nil
	}

	e.stats.SetTotalTargets(len(uniqueTargets))

	threads := e.cfg.Threads
	if threads <= 0 {
		threads = 10
	}
	if threads > len(uniqueTargets) {
		threads = len(uniqueTargets)
	}

	targetChan := make(chan string, len(uniqueTargets))
	for _, t := range uniqueTargets {
		targetChan <- t
	}
	close(targetChan)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.stats.IncWorker()
			defer e.stats.DecWorker()

			for {
				select {
				case <-ctx.Done():
					return
				case targetURL, ok := <-targetChan:
					if !ok {
						return
					}

					targetFindings := e.scanSingleTarget(ctx, targetURL)
					e.stats.IncTarget()

					if len(targetFindings) > 0 {
						findingsMu.Lock()
						for _, f := range targetFindings {
							findings = append(findings, f)
							if handler != nil {
								handler(&f)
							}
						}
						findingsMu.Unlock()
					}
				}
			}
		}(i)
	}

	wg.Wait()
	return findings, nil
}

// scanSingleTarget executes the decoupled detection pipeline across all enabled techniques.
func (e *Engine) scanSingleTarget(ctx context.Context, targetURL string) []models.Finding {
	// 1. Verify Scope
	if !e.scope.IsInScope(targetURL) {
		if e.cfg.Verbose {
			logger.PrintWarn("Skipping out-of-scope target: %s", targetURL)
		}
		return nil
	}

	// 2. Strict per-target timeout prevents hanging servers from causing worker depletion
	targetTimeout := e.cfg.Timeout
	if targetTimeout <= 0 {
		targetTimeout = 6 * time.Second
	}
	targetCtx, cancel := context.WithTimeout(ctx, targetTimeout)
	defer cancel()

	var targetFindings []models.Finding
	techniques := e.registry.GetEnabled(e.cfg)

	for _, tech := range techniques {
		select {
		case <-targetCtx.Done():
			return targetFindings
		default:
		}

		findings, err := tech.Execute(targetCtx, targetURL, e, e.cfg)
		if err != nil {
			if e.cfg.Verbose {
				logger.PrintError("[%s] error on %s: %v", tech.Name(), targetURL, err)
			}
			continue
		}

		targetFindings = append(targetFindings, findings...)
	}

	return targetFindings
}

// normalizeTargetURL ensures scheme is present and clean.
func normalizeTargetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return ""
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}

	return parsed.String()
}
