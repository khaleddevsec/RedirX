package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"redirx/internal/models"
)

// Collector safely aggregates statistics across concurrent scanning routines.
type Collector struct {
	mu                 sync.RWMutex
	startTime          time.Time
	endTime            time.Time
	totalTargets       int
	processedTargets   int64
	activeWorkers      int64
	testedParameters   int64
	totalRequests      int64
	confirmedCount     int64
	potentialCount     int64
	unconfirmedCount   int64
	falsePositiveCount int64
	errors             []string
}

// NewCollector initializes a statistics collector.
func NewCollector(targetCount int) *Collector {
	return &Collector{
		startTime:    time.Now(),
		totalTargets: targetCount,
	}
}

// SetTotalTargets updates the total target count (e.g. after deduplication).
func (c *Collector) SetTotalTargets(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.totalTargets = count
}

// IncTarget increments the count of fully processed target URLs.
func (c *Collector) IncTarget() {
	atomic.AddInt64(&c.processedTargets, 1)
}

// GetProcessedTargets returns the number of targets processed so far.
func (c *Collector) GetProcessedTargets() int64 {
	return atomic.LoadInt64(&c.processedTargets)
}

// GetTotalTargets returns the total number of targets.
func (c *Collector) GetTotalTargets() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalTargets
}

// IncWorker increments the active worker count.
func (c *Collector) IncWorker() {
	atomic.AddInt64(&c.activeWorkers, 1)
}

// DecWorker decrements the active worker count.
func (c *Collector) DecWorker() {
	atomic.AddInt64(&c.activeWorkers, -1)
}

// GetActiveWorkers returns the current number of active scanning workers.
func (c *Collector) GetActiveWorkers() int64 {
	workers := atomic.LoadInt64(&c.activeWorkers)
	if workers < 0 {
		return 0
	}
	return workers
}

// IncRequests increments total HTTP requests.
func (c *Collector) IncRequests() {
	atomic.AddInt64(&c.totalRequests, 1)
}

// GetTotalRequests returns the atomic total requests count.
func (c *Collector) GetTotalRequests() int64 {
	return atomic.LoadInt64(&c.totalRequests)
}

// IncParameters increments count of tested parameter instances.
func (c *Collector) IncParameters() {
	atomic.AddInt64(&c.testedParameters, 1)
}

// GetTestedParameters returns the atomic count of tested parameters.
func (c *Collector) GetTestedParameters() int64 {
	return atomic.LoadInt64(&c.testedParameters)
}

// AddFinding updates finding counters based on classification.
func (c *Collector) AddFinding(classification models.Classification) {
	switch classification {
	case models.ClassificationConfirmed:
		atomic.AddInt64(&c.confirmedCount, 1)
	case models.ClassificationPotential:
		atomic.AddInt64(&c.potentialCount, 1)
	case models.ClassificationUnconfirmed:
		atomic.AddInt64(&c.unconfirmedCount, 1)
	case models.ClassificationFalsePositive:
		atomic.AddInt64(&c.falsePositiveCount, 1)
	}
}

// GetConfirmedCount returns the atomic confirmed findings count.
func (c *Collector) GetConfirmedCount() int64 {
	return atomic.LoadInt64(&c.confirmedCount)
}

// GetPotentialCount returns the atomic potential findings count.
func (c *Collector) GetPotentialCount() int64 {
	return atomic.LoadInt64(&c.potentialCount)
}

// Throughput returns current requests processed per second.
func (c *Collector) Throughput() float64 {
	elapsed := time.Since(c.startTime).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&c.totalRequests)) / elapsed
}

// ProgressPercentage calculates the completion percentage (0.0 to 100.0).
func (c *Collector) ProgressPercentage() float64 {
	c.mu.RLock()
	total := c.totalTargets
	c.mu.RUnlock()

	if total <= 0 {
		return 0
	}
	pct := (float64(atomic.LoadInt64(&c.processedTargets)) / float64(total)) * 100.0
	if pct > 100.0 {
		pct = 100.0
	}
	return pct
}

// ETA calculates the estimated duration until all targets are processed.
func (c *Collector) ETA() time.Duration {
	c.mu.RLock()
	total := c.totalTargets
	c.mu.RUnlock()

	processed := atomic.LoadInt64(&c.processedTargets)
	if processed <= 0 || total <= 0 {
		return 0
	}
	remaining := int64(total) - processed
	if remaining <= 0 {
		return 0
	}

	elapsed := time.Since(c.startTime)
	avgPerTarget := elapsed / time.Duration(processed)
	return avgPerTarget * time.Duration(remaining)
}

// Elapsed returns the duration since scanning started.
func (c *Collector) Elapsed() time.Duration {
	return time.Since(c.startTime)
}

// AddError records an error string.
func (c *Collector) AddError(errStr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, errStr)
}

// Stop finalizes timings.
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endTime = time.Now()
}

// Summary exports a finalized models.ScanSummary snapshot.
func (c *Collector) Summary() models.ScanSummary {
	c.mu.RLock()
	defer c.mu.RUnlock()

	endTime := c.endTime
	if endTime.IsZero() {
		endTime = time.Now()
	}

	return models.ScanSummary{
		StartTime:          c.startTime,
		EndTime:            endTime,
		Duration:           endTime.Sub(c.startTime),
		TotalTargets:       c.totalTargets,
		TestedParameters:   int(atomic.LoadInt64(&c.testedParameters)),
		TotalRequests:      atomic.LoadInt64(&c.totalRequests),
		ConfirmedCount:     int(atomic.LoadInt64(&c.confirmedCount)),
		PotentialCount:     int(atomic.LoadInt64(&c.potentialCount)),
		UnconfirmedCount:   int(atomic.LoadInt64(&c.unconfirmedCount)),
		FalsePositiveCount: int(atomic.LoadInt64(&c.falsePositiveCount)),
		Errors:             c.errors,
	}
}
