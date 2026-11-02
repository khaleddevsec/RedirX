package scanner

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// HostRateLimiter manages delays between requests to the same host.
type HostRateLimiter struct {
	mu       sync.Mutex
	lastSeen map[string]time.Time
	delay    time.Duration
}

// NewHostRateLimiter creates a per-host rate limiter.
func NewHostRateLimiter(delay time.Duration) *HostRateLimiter {
	return &HostRateLimiter{
		lastSeen: make(map[string]time.Time),
		delay:    delay,
	}
}

// Wait blocks if necessary until the required delay has elapsed for the given host.
func (rl *HostRateLimiter) Wait(targetURL string) {
	if rl.delay <= 0 {
		return
	}

	host := targetURL
	if parsed, err := url.Parse(targetURL); err == nil && parsed.Host != "" {
		host = strings.ToLower(parsed.Host)
	}

	rl.mu.Lock()
	last, exists := rl.lastSeen[host]
	now := time.Now()

	var sleepDuration time.Duration
	if exists {
		elapsed := now.Sub(last)
		if elapsed < rl.delay {
			sleepDuration = rl.delay - elapsed
		}
	}

	rl.lastSeen[host] = now.Add(sleepDuration)
	rl.mu.Unlock()

	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}

