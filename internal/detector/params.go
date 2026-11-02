package detector

import (
	"net/url"
	"strings"
)

// DefaultRedirectParams contains industry-standard parameter names commonly
// associated with redirection functionality across web applications.
var DefaultRedirectParams = []string{
	"url",
	"next",
	"redirect",
	"redirect_url",
	"redirect_uri",
	"return",
	"return_url",
	"returnUrl",
	"continue",
	"destination",
	"dest",
	"target",
	"callback",
	"goto",
	"forward",
	"out",
	"view",
	"to",
	"success_url",
	"failure_url",
	"checkout_url",
	"redirect_to",
	"r",
	"u",
	"link",
	"ref",
	"relayState",
	"site",
	"domain",
	"feed",
	"host",
	"to_url",
	"from_url",
	"back",
	"nav",
	"go",
	"uri",
	"path",
}

// ExtractCandidateParams extracts existing parameters from the URL and adds
// candidate discovery parameters, respecting include/exclude filters.
func ExtractCandidateParams(targetURL string, includeParams []string, excludeParams []string) ([]string, url.Values, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}

	query := parsed.Query()
	excluded := make(map[string]struct{})
	for _, p := range excludeParams {
		excluded[strings.ToLower(strings.TrimSpace(p))] = struct{}{}
	}

	includedOnly := make(map[string]struct{})
	for _, p := range includeParams {
		includedOnly[strings.ToLower(strings.TrimSpace(p))] = struct{}{}
	}

	var candidateList []string
	seen := make(map[string]struct{})

	// 1. Existing query parameters have first priority
	for param := range query {
		lower := strings.ToLower(param)
		if _, skip := excluded[lower]; skip {
			continue
		}
		if len(includedOnly) > 0 {
			if _, keep := includedOnly[lower]; !keep {
				continue
			}
		}
		if _, exists := seen[lower]; !exists {
			candidateList = append(candidateList, param)
			seen[lower] = struct{}{}
		}
	}

	// 2. If no existing parameters found, or if specific parameters requested,
	// supplement with common candidate redirect parameters
	if len(candidateList) == 0 {
		for _, param := range DefaultRedirectParams {
			lower := strings.ToLower(param)
			if _, skip := excluded[lower]; skip {
				continue
			}
			if len(includedOnly) > 0 {
				if _, keep := includedOnly[lower]; !keep {
					continue
				}
			}
			if _, exists := seen[lower]; !exists {
				candidateList = append(candidateList, param)
				seen[lower] = struct{}{}
			}
		}
	}

	return candidateList, query, nil
}

