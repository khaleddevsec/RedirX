package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"redirx/internal/config"
	"redirx/internal/logger"
	"redirx/internal/models"
	"redirx/internal/redirect"
	"redirx/internal/reporter"
	"redirx/internal/scanner"
	"redirx/internal/stats"
	"redirx/internal/updater"
	"redirx/pkg/version"
)

var (
	// Root flags
	flagURL           string
	flagList          string
	flagStdin         bool
	flagThreads       int
	flagTimeout       time.Duration
	flagDelay         time.Duration
	flagRetry         int
	flagVerbose       bool
	flagSilent        bool
	flagName          string
	flagFormat        string
	flagOutput        string
	flagHeaders       []string
	flagCookies       string
	flagUserAgent     string
	flagProxy         string
	flagPayloadFile   string
	flagTestDomain    string
	flagMaxRedirects  int
	flagAllowlist     []string
	flagExcludeParams []string
	flagIncludeParams []string
	flagDataDir       string
	flagForce         bool
	flagPathTest      bool
	flagInsecure      bool
	flagUpdate        bool
	flagVersion       bool
)

// NewRootCmd constructs the primary RedirX command line interface.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "redirx",
		Short: "RedirX - Advanced Open Redirect Detection & Analysis Tool",
		Long: `RedirX is a high-performance, evidence-based Open Redirect detection and analysis engine
built in idiomatic Go for application security testing, bug bounty automation, and vulnerability auditing.

RedirX delivers multi-stage payload injection, deep hop-by-hop redirect tracking, baseline comparison,
SSRF defense, and comprehensive reporting (TXT, HTML, JSON).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runRoot,
	}

	// Target inputs
	rootCmd.Flags().StringVarP(&flagURL, "url", "u", "", "Single target URL to test")
	rootCmd.Flags().StringVarP(&flagList, "list", "l", "", "Path to file containing target URLs (one per line)")
	rootCmd.Flags().BoolVar(&flagStdin, "stdin", false, "Read target URLs from standard input")

	// Concurrency & network tuning
	rootCmd.Flags().IntVarP(&flagThreads, "threads", "t", 10, "Worker pool concurrency")
	rootCmd.Flags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "HTTP timeout per request")
	rootCmd.Flags().DurationVar(&flagDelay, "delay", 0, "Per-host delay between requests (e.g. 200ms, 1s)")
	rootCmd.Flags().IntVar(&flagRetry, "retry", 1, "Number of request retries on network error")
	rootCmd.Flags().IntVar(&flagMaxRedirects, "max-redirects", 10, "Maximum redirect depth per test")

	// Output & Logging
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose output with detailed debugging")
	rootCmd.Flags().BoolVarP(&flagSilent, "silent", "s", false, "Silent mode (suppress banners, only display findings)")
	rootCmd.Flags().StringVarP(&flagName, "name", "n", "", "Custom result filename (e.g. my-scan)")
	rootCmd.Flags().StringVar(&flagFormat, "format", "txt", "Output format(s), comma-separated (txt, html, json)")
	rootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Custom output destination path or directory")
	rootCmd.Flags().StringVar(&flagDataDir, "data-dir", "", "Custom RedirX application data directory")
	rootCmd.Flags().BoolVarP(&flagForce, "force", "f", false, "Force overwrite existing result files without prompting")

	// Payloads & Discovery
	rootCmd.Flags().StringVar(&flagPayloadFile, "payload-file", "", "Custom payload file path")
	rootCmd.Flags().StringVar(&flagTestDomain, "test-domain", "example.com", "Designated external test domain for redirection validation")
	rootCmd.Flags().StringSliceVar(&flagIncludeParams, "include-params", nil, "Test only specified parameter names")
	rootCmd.Flags().StringSliceVar(&flagExcludeParams, "exclude-params", nil, "Exclude specified parameters from testing")
	rootCmd.Flags().BoolVar(&flagPathTest, "path-test", false, "Enable legacy path-segment stripping heuristic check")

	// HTTP Configuration
	rootCmd.Flags().StringArrayVar(&flagHeaders, "headers", nil, "Custom HTTP header in 'Key: Value' format (repeatable)")
	rootCmd.Flags().StringVar(&flagCookies, "cookies", "", "Custom HTTP Cookie header string")
	rootCmd.Flags().StringVar(&flagUserAgent, "user-agent", "", "Custom User-Agent header")
	rootCmd.Flags().StringVar(&flagProxy, "proxy", "", "Proxy URL (HTTP/HTTPS/SOCKS5)")
	rootCmd.Flags().BoolVar(&flagInsecure, "insecure", false, "Skip TLS certificate verification (not recommended)")

	// Scope & Safety
	rootCmd.Flags().StringSliceVar(&flagAllowlist, "allowlist", nil, "Target allowlist (domains or CIDRs)")

	// Lifecycle
	rootCmd.Flags().BoolVar(&flagUpdate, "update", false, "Check and perform self-update to latest release")
	rootCmd.Flags().BoolVar(&flagVersion, "version", false, "Display version information and exit")

	// Add subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newUpdateCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newResultsCmd())

	return rootCmd
}

func runRoot(cmd *cobra.Command, args []string) error {
	// 1. Handle quick flags
	if flagVersion {
		fmt.Println(version.Info())
		return nil
	}

	// 2. Initialize application data directories (~/RedirX)
	dirs, err := config.InitAppDirs(flagDataDir)
	if err != nil {
		return fmt.Errorf("failed initializing RedirX data directories: %w", err)
	}

	// 3. Initialize structured logging
	_, err = logger.InitLogger(dirs.Logs, flagVerbose, flagSilent)
	if err != nil {
		return fmt.Errorf("failed initializing logger: %w", err)
	}
	defer logger.CloseLogger()

	// 4. Handle self-update flag if triggered via --update
	if flagUpdate {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return updater.CheckAndApplyUpdate(ctx, dirs.Backups)
	}

	// 5. Collect target URLs
	targets, err := collectTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return cmd.Help()
	}

	// 6. Print banner unless in silent mode
	if !flagSilent {
		printBanner(dirs.Root, len(targets))
	}

	// 7. Parse output formats
	var formats []string
	for _, f := range strings.Split(flagFormat, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			formats = append(formats, f)
		}
	}
	if len(formats) == 0 {
		formats = []string{"txt"}
	}

	// 8. Assemble Scan Configuration
	scanConfig := &models.ScanConfig{
		TargetURL:          flagURL,
		TargetList:         flagList,
		UseStdin:           flagStdin,
		Threads:            flagThreads,
		Timeout:            flagTimeout,
		Delay:              flagDelay,
		Retries:            flagRetry,
		MaxRedirects:       flagMaxRedirects,
		MaxResponseSize:    2 * 1024 * 1024,
		Headers:            flagHeaders,
		Cookies:            flagCookies,
		UserAgent:          flagUserAgent,
		ProxyURL:           flagProxy,
		PayloadFile:        flagPayloadFile,
		TestDomain:         flagTestDomain,
		ExcludeParams:      flagExcludeParams,
		IncludeParams:      flagIncludeParams,
		PathTest:           flagPathTest,
		Allowlist:          flagAllowlist,
		SafeRedirectsOnly:  true, // Enforce SSRF protection by default
		InsecureSkipVerify: flagInsecure,
		ResultName:         flagName,
		Formats:            formats,
		OutputPath:         flagOutput,
		DataDir:            dirs.Root,
		Force:              flagForce,
		Interactive:        isTerminal(),
		Verbose:            flagVerbose,
		Silent:             flagSilent,
	}

	// 9. Build HTTP Client
	client, err := redirect.NewClient(scanConfig)
	if err != nil {
		return fmt.Errorf("failed configuring HTTP engine: %w", err)
	}

	// 10. Setup Context with graceful cancellation (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !flagSilent {
			logger.PrintWarn("\nReceived interrupt signal! Gracefully concluding in-flight tasks and generating reports...")
		}
		cancel()
	}()

	// 11. Initialize Statistics and Scanner
	statsColl := stats.NewCollector(len(targets))
	engine := scanner.NewEngine(scanConfig, client, statsColl)

	// Live finding display handler (Nuclei style output formatting)
	findingHandler := func(f *models.Finding) {
		if flagSilent {
			if f.Classification == models.ClassificationConfirmed {
				fmt.Printf("[redirx] [confirmed] [open-redirect] %s -> %s [param: %s]\n", f.VulnerableURL, f.FinalDestination, f.Parameter)
			} else if f.Classification == models.ClassificationPotential {
				fmt.Printf("[redirx] [potential] [open-redirect] %s -> %s [param: %s]\n", f.VulnerableURL, f.FinalDestination, f.Parameter)
			}
			return
		}

		if f.Classification == models.ClassificationConfirmed {
			logger.PrintVuln("%s via param %q -> %s", f.VulnerableURL, f.Parameter, f.FinalDestination)
		} else if f.Classification == models.ClassificationPotential {
			logger.PrintPotential("%s (%s) -> %s", f.VulnerableURL, f.VulnerabilityType, f.FinalDestination)
		}
	}

	// 12. Execute Scan
	findings, err := engine.ScanTargets(ctx, targets, findingHandler)
	statsColl.Stop()
	summary := statsColl.Summary()

	if err != nil && err != context.Canceled {
		return fmt.Errorf("scanning error: %w", err)
	}

	// 13. Generate Reports
	generatedPaths, reportErr := reporter.GenerateReports(summary, findings, scanConfig, dirs)
	if reportErr != nil {
		logger.PrintError("Failed generating report: %v", reportErr)
	}

	// 14. Print Summary
	if !flagSilent {
		printSummary(summary, generatedPaths)
	}

	return nil
}

func collectTargets() ([]string, error) {
	var targets []string

	if flagURL != "" {
		targets = append(targets, strings.TrimSpace(flagURL))
	}

	if flagList != "" {
		file, err := os.Open(flagList)
		if err != nil {
			return nil, fmt.Errorf("failed opening target list %q: %w", flagList, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading target list: %w", err)
		}
	}

	if flagStdin {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		}
	}

	return targets, nil
}

func printBanner(dataDir string, targetCount int) {
	fmt.Println(logger.ColorCyan + logger.ColorBold + `
    ____           ___       _  __
   / __ \___  ____/ (_)____ | |/ /
  / /_/ / _ \/ __  / / ___/ |   / 
 / _, _/  __/ /_/ / / /    /   |  
/_/ |_|\___/\__,_/_/_/    /_/|_|  ` + logger.ColorReset + logger.ColorMagenta + "v" + version.Version + logger.ColorReset)
	fmt.Println(logger.ColorBold + " Advanced Open Redirect Detection & Analysis Engine" + logger.ColorReset)
	fmt.Println(logger.ColorGreen + " Developer: " + logger.ColorReset + version.Author + " | " + logger.ColorBlue + "https://github.com/khaleddevsec/RedirX" + logger.ColorReset)
	fmt.Printf(logger.ColorGray+" Data Directory: %s | Active Targets: %d\n\n"+logger.ColorReset, dataDir, targetCount)
}

func printSummary(summary models.ScanSummary, reportPaths []string) {
	fmt.Println("\n" + logger.ColorBold + strings.Repeat("=", 60) + logger.ColorReset)
	fmt.Println(logger.ColorBold + "                     SCAN COMPLETED" + logger.ColorReset)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf(" Duration:            %s\n", summary.Duration.Round(time.Millisecond))
	fmt.Printf(" Targets Audited:     %d\n", summary.TotalTargets)
	fmt.Printf(" Tested Parameters:   %d\n", summary.TestedParameters)
	fmt.Printf(" HTTP Requests:       %d\n", summary.TotalRequests)
	fmt.Printf(" Confirmed Vulns:     "+logger.ColorRed+logger.ColorBold+"%d"+logger.ColorReset+"\n", summary.ConfirmedCount)
	fmt.Printf(" Potential Findings:  "+logger.ColorYellow+logger.ColorBold+"%d"+logger.ColorReset+"\n", summary.PotentialCount)
	fmt.Printf(" False Positives:     %d\n", summary.FalsePositiveCount)

	if len(reportPaths) > 0 {
		fmt.Println("\n" + logger.ColorGreen + "[+] Saved Reports:" + logger.ColorReset)
		for _, p := range reportPaths {
			fmt.Printf("  -> %s\n", p)
		}
	}
	fmt.Println(strings.Repeat("=", 60))
}

func isTerminal() bool {
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

