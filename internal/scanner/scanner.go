package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"redirx/internal/detector"
	"redirx/internal/logger"
	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/scope"
	"redirx/internal/stats"
	"redirx/internal/validator"
)

// Engine coordinates the multi-threaded scanning process.
type Engine struct {
	cfg         *models.ScanConfig
	client      *redirect.Client
	scope       *scope.ScopeManager
	rateLimiter *HostRateLimiter
	stats       *stats.Collector
}

// NewEngine constructs a new scanning engine instance.
func NewEngine(cfg *models.ScanConfig, client *redirect.Client, statsColl *stats.Collector) *Engine {
	return &Engine{
		cfg:         cfg,
		client:      client,
		scope:       scope.NewScopeManager(cfg.Allowlist),
		rateLimiter: NewHostRateLimiter(cfg.Delay),
		stats:       statsColl,
	}
}

// FindingHandler is invoked whenever a relevant finding is generated.
type FindingHandler func(finding *models.Finding)

// ScanTargets executes scanning concurrently across target URLs using a worker pool.
func (e *Engine) ScanTargets(ctx context.Context, targets []string, handler FindingHandler) ([]models.Finding, error) {
	var (
		findings   []models.Finding
		findingsMu sync.Mutex
	)

	threads := e.cfg.Threads
	if threads <= 0 {
		threads = 10
	}
	if threads > len(targets) && len(targets) > 0 {
		threads = len(targets)
	}

	targetChan := make(chan string, len(targets))
	for _, t := range targets {
		normalized := normalizeTargetURL(t)
		if normalized != "" {
			targetChan <- normalized
		}
	}
	close(targetChan)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case targetURL, ok := <-targetChan:
					if !ok {
						return
					}

					targetFindings := e.scanSingleTarget(ctx, targetURL)

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

// scanSingleTarget executes the full detection pipeline on a single URL.
func (e *Engine) scanSingleTarget(ctx context.Context, targetURL string) []models.Finding {
	var targetFindings []models.Finding

	// 1. Verify Scope
	if !e.scope.IsInScope(targetURL) {
		if e.cfg.Verbose {
			logger.PrintWarn("Skipping out-of-scope target: %s", targetURL)
		}
		return nil
	}

	targetHost := detector.ExtractHost(targetURL)

	// 2. Optional: Legacy Path Canonicalization Anomaly check
	if e.cfg.PathTest {
		e.rateLimiter.Wait(targetURL)
		e.stats.IncRequests()
		pathFinding, err := detector.CheckPathCanonicalizationAnomaly(ctx, e.client, targetURL)
		if err == nil && pathFinding != nil {
			e.stats.AddFinding(pathFinding.Classification)
			targetFindings = append(targetFindings, *pathFinding)
		}
	}

	// 3. Establish Baseline Response
	e.rateLimiter.Wait(targetURL)
	e.stats.IncRequests()
	baseline, err := detector.CollectBaseline(ctx, e.client, targetURL)
	if err != nil {
		if e.cfg.Verbose {
			logger.PrintError("Baseline failed for %s: %v", targetURL, err)
		}
		e.stats.AddError(fmt.Sprintf("Baseline %s: %v", targetURL, err))
		return targetFindings
	}

	// 4. Extract Candidate Parameters
	params, _, err := detector.ExtractCandidateParams(targetURL, e.cfg.IncludeParams, e.cfg.ExcludeParams)
	if err != nil || len(params) == 0 {
		return targetFindings
	}

	// 5. Generate Payloads
	testDomain := e.cfg.TestDomain
	if testDomain == "" {
		testDomain = "example.com"
	}

	payloads, err := detector.GeneratePayloads(targetHost, testDomain, e.cfg.PayloadFile)
	if err != nil {
		e.stats.AddError(fmt.Sprintf("Payload error %s: %v", targetURL, err))
		return targetFindings
	}

	// 6. Test Parameters with Payloads
	for _, param := range params {
		select {
		case <-ctx.Done():
			return targetFindings
		default:
		}

		e.stats.IncParameters()

		for _, p := range payloads {
			select {
			case <-ctx.Done():
				return targetFindings
			default:
			}

			injected, injectErr := detector.InjectQueryParameter(targetURL, param, p.Value, p.Category)
			if injectErr != nil {
				continue
			}

			// Apply rate limit delay before request
			e.rateLimiter.Wait(injected.URL)
			e.stats.IncRequests()

			execResult, execErr := e.client.ExecuteHopByHop(ctx, injected.URL)
			if execErr != nil {
				// Retries if configured
				for r := 0; r < e.cfg.Retries; r++ {
					e.rateLimiter.Wait(injected.URL)
					e.stats.IncRequests()
					execResult, execErr = e.client.ExecuteHopByHop(ctx, injected.URL)
					if execErr == nil {
						break
					}
				}
				if execErr != nil {
					continue
				}
			}

			// Check client-side navigation (Meta Refresh / JS)
			clientSide := detector.AnalyzeClientSideRedirects(execResult.FinalBody, testDomain, p.Value)

			// Validate finding
			finding := validator.ValidateFinding(targetURL, injected, baseline, execResult, clientSide, testDomain)
			if finding == nil {
				continue
			}

			e.stats.AddFinding(finding.Classification)

			// Record Confirmed and Potential findings, and record all if Verbose
			if finding.Classification == models.ClassificationConfirmed ||
				finding.Classification == models.ClassificationPotential ||
				e.cfg.Verbose {
				targetFindings = append(targetFindings, *finding)
			}

			// If Confirmed, no need to bombard this parameter with more payloads of the same category
			if finding.Classification == models.ClassificationConfirmed {
				break
			}
		}
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

