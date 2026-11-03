package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	"redirx/internal/logger"
	"redirx/internal/stats"
)

// ProgressTicker manages a live, non-scrolling status line in the terminal.
type ProgressTicker struct {
	stats    *stats.Collector
	interval time.Duration
	stopChan chan struct{}
	wg       sync.WaitGroup
	enabled  bool
	mu       sync.Mutex
	active   bool
}

// NewProgressTicker constructs a ProgressTicker instance.
func NewProgressTicker(statsColl *stats.Collector, enabled bool) *ProgressTicker {
	return &ProgressTicker{
		stats:    statsColl,
		interval: 200 * time.Millisecond,
		stopChan: make(chan struct{}),
		enabled:  enabled,
	}
}

// Start initiates background ticker rendering.
func (pt *ProgressTicker) Start() {
	if !pt.enabled || pt.stats == nil {
		return
	}

	pt.mu.Lock()
	if pt.active {
		pt.mu.Unlock()
		return
	}
	pt.active = true
	pt.mu.Unlock()

	pt.wg.Add(1)
	go func() {
		defer pt.wg.Done()
		ticker := time.NewTicker(pt.interval)
		defer ticker.Stop()

		for {
			select {
			case <-pt.stopChan:
				pt.clearLine()
				return
			case <-ticker.C:
				pt.render()
			}
		}
	}()
}

// Clear removes the ticker line from the terminal so that log/finding messages print cleanly.
func (pt *ProgressTicker) Clear() {
	if !pt.enabled {
		return
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.clearLine()
}

// Resume immediately redraws the ticker line after a log/finding has printed.
func (pt *ProgressTicker) Resume() {
	if !pt.enabled {
		return
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.renderUnsafe()
}

// Stop cleanly stops the background ticker and clears the line.
func (pt *ProgressTicker) Stop() {
	if !pt.enabled {
		return
	}

	pt.mu.Lock()
	if !pt.active {
		pt.mu.Unlock()
		return
	}
	pt.active = false
	close(pt.stopChan)
	pt.mu.Unlock()

	pt.wg.Wait()
	pt.clearLine()
}

func (pt *ProgressTicker) clearLine() {
	fmt.Fprint(os.Stderr, "\r\033[2K\r")
}

func (pt *ProgressTicker) render() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if !pt.active {
		return
	}
	pt.renderUnsafe()
}

func (pt *ProgressTicker) renderUnsafe() {
	processed := pt.stats.GetProcessedTargets()
	total := pt.stats.GetTotalTargets()
	pct := pt.stats.ProgressPercentage()
	speed := pt.stats.Throughput()
	workers := pt.stats.GetActiveWorkers()
	confirmed := pt.stats.GetConfirmedCount()
	potential := pt.stats.GetPotentialCount()
	elapsed := pt.stats.Elapsed().Truncate(time.Second)
	eta := pt.stats.ETA().Truncate(time.Second)

	fmt.Fprintf(os.Stderr,
		"\r\033[2K\r%s[%d/%d]%s %s(%.1f%%)%s | %s%.1f req/s%s | %sWorkers: %d%s | %sFindings: %d%s | %s%s%s | %sETA: %s%s",
		logger.ColorCyan+logger.ColorBold, processed, total, logger.ColorReset,
		logger.ColorGray, pct, logger.ColorReset,
		logger.ColorGreen, speed, logger.ColorReset,
		logger.ColorYellow, workers, logger.ColorReset,
		logger.ColorMagenta+logger.ColorBold, confirmed+potential, logger.ColorReset,
		logger.ColorGray, FormatDuration(elapsed), logger.ColorReset,
		logger.ColorCyan, FormatDuration(eta), logger.ColorReset,
	)
}

// FormatDuration formats duration as HH:MM:SS or MM:SS.
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

