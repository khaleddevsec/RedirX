package detector

import (
	"context"
	"net/url"
	"strings"

	"redirx/internal/models"
	"redirx/internal/redirect"
)

// CollectBaseline sends a baseline request to the unmodified URL to establish normal behavior.
func CollectBaseline(ctx context.Context, client *redirect.Client, targetURL string) (*models.BaselineResult, error) {
	execResult, err := client.ExecuteHopByHop(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	normPath := ""
	if parsed, pErr := url.Parse(execResult.FinalURL); pErr == nil {
		normPath = strings.ToLower(strings.TrimRight(parsed.Path, "/"))
	}

	locHeader := ""
	if len(execResult.RedirectChain) > 0 {
		locHeader = execResult.RedirectChain[0].LocationHeader
	}

	return &models.BaselineResult{
		URL:              targetURL,
		StatusCode:       execResult.FinalStatus,
		FinalURL:         execResult.FinalURL,
		LocationHeader:   locHeader,
		RedirectChain:    execResult.RedirectChain,
		HadRedirects:     execResult.HadRedirects,
		NormalizedPath:   normPath,
		IsStaticRedirect: execResult.HadRedirects,
	}, nil
}

