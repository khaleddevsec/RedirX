package scope

import (
	"net"
	"net/url"
	"strings"
)

// ScopeManager checks targets against configured allowlists.
type ScopeManager struct {
	allowedHosts map[string]struct{}
	wildcards    []string
	allowedCIDRs []*net.IPNet
	active       bool
}

// NewScopeManager initializes a scope manager from a list of allowed rules.
func NewScopeManager(allowlist []string) *ScopeManager {
	sm := &ScopeManager{
		allowedHosts: make(map[string]struct{}),
		active:       len(allowlist) > 0,
	}

	for _, item := range allowlist {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}

		// Check if CIDR
		if _, ipNet, err := net.ParseCIDR(item); err == nil {
			sm.allowedCIDRs = append(sm.allowedCIDRs, ipNet)
			continue
		}

		// Check if wildcard domain (e.g. *.example.com)
		if strings.HasPrefix(item, "*.") {
			sm.wildcards = append(sm.wildcards, strings.TrimPrefix(item, "*."))
			continue
		}

		sm.allowedHosts[item] = struct{}{}
	}

	return sm
}

// IsInScope checks whether the specified raw URL or hostname is within the allowed scope.
func (sm *ScopeManager) IsInScope(rawURL string) bool {
	if !sm.active {
		return true // If no allowlist is configured, all targets are in scope
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		host = strings.ToLower(rawURL)
	}

	// Exact host match
	if _, ok := sm.allowedHosts[host]; ok {
		return true
	}

	// Wildcard domain match
	for _, domain := range sm.wildcards {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	// Check IP matches
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range sm.allowedCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

