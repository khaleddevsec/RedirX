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

// IncRequests increments total HTTP requests.
func (c *Collector) IncRequests() {
	atomic.AddInt64(&c.totalRequests, 1)
}

// IncParameters increments count of tested parameter instances.
func (c *Collector) IncParameters() {
	atomic.AddInt64(&c.testedParameters, 1)
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

