package detector

import (
	"fmt"
	"net/url"
	"strings"
)

// InjectedTarget holds the constructed URL alongside metadata about the injection.
type InjectedTarget struct {
	URL             string
	Parameter       string
	Payload         string
	PayloadCategory string
}

// InjectQueryParameter replaces or adds a parameter value in the target URL.
// It preserves all existing query parameters without corrupting values.
func InjectQueryParameter(rawURL, param, payload, category string) (*InjectedTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", rawURL, err)
	}

	query := parsed.Query()
	query.Set(param, payload)

	// Construct encoded query string
	parsed.RawQuery = query.Encode()

	return &InjectedTarget{
		URL:             parsed.String(),
		Parameter:       param,
		Payload:         payload,
		PayloadCategory: category,
	}, nil
}

// InjectRawQueryParameter constructs a URL with literal payload injection,
// avoiding standard url.QueryEscape when testing raw bypasses (like //, /\, etc.).
func InjectRawQueryParameter(rawURL, param, payload, category string) (*InjectedTarget, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", rawURL, err)
	}

	query := parsed.Query()
	var queryParts []string

	// Maintain existing parameters
	paramUpdated := false
	for k, vals := range query {
		if strings.EqualFold(k, param) {
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", k, payload))
			paramUpdated = true
		} else {
			for _, v := range vals {
				queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
			}
		}
	}

	if !paramUpdated {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", param, payload))
	}

	parsed.RawQuery = strings.Join(queryParts, "&")

	return &InjectedTarget{
		URL:             parsed.String(),
		Parameter:       param,
		Payload:         payload,
		PayloadCategory: category,
	}, nil
}

