package reporter

import (
	"fmt"
	"io"
	"strings"
	"time"

	"redirx/internal/models"
	"redirx/pkg/version"
)

// WriteTextReport writes a structured, human-readable text report.
func WriteTextReport(w io.Writer, summary models.ScanSummary, findings []models.Finding) error {
	divider := strings.Repeat("=", 78)
	subdivider := strings.Repeat("-", 78)

	fmt.Fprintln(w, divider)
	fmt.Fprintf(w, "  RedirX Open Redirect Vulnerability Report\n")
	fmt.Fprintf(w, "  Engine: %s\n", version.Info())
	fmt.Fprintf(w, "  Generated: %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "[*] SCAN SUMMARY")
	fmt.Fprintln(w, subdivider)
	fmt.Fprintf(w, "  Duration:           %s\n", summary.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "  Total Targets:      %d\n", summary.TotalTargets)
	fmt.Fprintf(w, "  Tested Parameters:  %d\n", summary.TestedParameters)
	fmt.Fprintf(w, "  Total HTTP Requests:%d\n", summary.TotalRequests)
	fmt.Fprintf(w, "  Confirmed Vulns:    %d\n", summary.ConfirmedCount)
	fmt.Fprintf(w, "  Potential Findings: %d\n", summary.PotentialCount)
	fmt.Fprintf(w, "  False Positives:    %d\n", summary.FalsePositiveCount)
	fmt.Fprintln(w, subdivider)
	fmt.Fprintln(w, "")

	if len(findings) == 0 {
		fmt.Fprintln(w, "[+] No confirmed or potential Open Redirect vulnerabilities detected.")
		fmt.Fprintln(w, divider)
		return nil
	}

	fmt.Fprintf(w, "[*] FINDINGS DETAILS (%d items)\n", len(findings))
	fmt.Fprintln(w, divider)

	for i, f := range findings {
		fmt.Fprintf(w, "\n[%d] [%s] - %s (Confidence: %s)\n", i+1, f.Classification, f.VulnerabilityType, f.Confidence)
		fmt.Fprintln(w, subdivider)
		fmt.Fprintf(w, "  Target URL:       %s\n", f.OriginalURL)
		fmt.Fprintf(w, "  Tested URL:       %s\n", f.VulnerableURL)
		fmt.Fprintf(w, "  Parameter:        %s\n", f.Parameter)
		fmt.Fprintf(w, "  Injected Payload: %s\n", f.Payload)
		fmt.Fprintf(w, "  Initial Status:   %d\n", f.InitialStatus)
		fmt.Fprintf(w, "  Final Status:     %d\n", f.FinalStatus)
		fmt.Fprintf(w, "  Final Destination:%s\n", f.FinalDestination)

		// Redirect Chain
		if len(f.RedirectChain) > 0 {
			fmt.Fprintln(w, "\n  Redirect Chain:")
			for _, hop := range f.RedirectChain {
				fmt.Fprintf(w, "    Hop #%d: [%d] %s\n", hop.HopNumber, hop.StatusCode, hop.URL)
				if hop.LocationHeader != "" {
					fmt.Fprintf(w, "            -> Location: %s\n", hop.LocationHeader)
				}
				if hop.DestinationURL != "" {
					fmt.Fprintf(w, "            -> Resolved: %s\n", hop.DestinationURL)
				}
				if hop.Error != "" {
					fmt.Fprintf(w, "            -> Error:    %s\n", hop.Error)
				}
			}
		}

		// Evidence
		fmt.Fprintln(w, "\n  Evidence:")
		if f.Evidence.LocationHeader != "" {
			fmt.Fprintf(w, "    Location Header:       %s\n", f.Evidence.LocationHeader)
		}
		if f.Evidence.ScriptSnippet != "" {
			fmt.Fprintf(w, "    Client Script Snippet: %s\n", f.Evidence.ScriptSnippet)
		}
		if f.Evidence.BaselineDestination != "" {
			fmt.Fprintf(w, "    Baseline Destination:  %s (Status: %d, Redirects: %v)\n",
				f.Evidence.BaselineDestination, f.Evidence.BaselineStatus, f.Evidence.BaselineRedirects)
		}
		fmt.Fprintf(w, "    Reflected in Body:     %v\n", f.Evidence.ReflectedInBody)
		fmt.Fprintf(w, "    Host Match Verified:   %v\n", f.Evidence.DestinationHostMatch)

		// Validation Notes
		if len(f.ValidationNotes) > 0 {
			fmt.Fprintln(w, "\n  Validation Notes:")
			for _, note := range f.ValidationNotes {
				fmt.Fprintf(w, "    * %s\n", note)
			}
		}
		fmt.Fprintln(w, subdivider)
	}

	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintln(w, "End of RedirX Report")
	fmt.Fprintln(w, divider)
	return nil
}

