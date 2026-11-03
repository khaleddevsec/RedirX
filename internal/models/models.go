package models

import (
	"time"
)

// Classification represents the validity status of a finding.
type Classification string

const (
	ClassificationConfirmed     Classification = "CONFIRMED"
	ClassificationPotential     Classification = "POTENTIAL"
	ClassificationUnconfirmed   Classification = "UNCONFIRMED"
	ClassificationFalsePositive Classification = "FALSE POSITIVE"
)

// Confidence indicates confidence in the classification.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// VulnerabilityType classifies the mechanism of the redirect finding.
type VulnerabilityType string

const (
	VulnServerSideDirect   VulnerabilityType = "Server-Side (HTTP 3xx)"
	VulnServerSideChained  VulnerabilityType = "Server-Side Chained Redirect"
	VulnClientSideMeta     VulnerabilityType = "Client-Side (Meta Refresh)"
	VulnClientSideJS       VulnerabilityType = "Client-Side (JavaScript Navigation)"
	VulnPathCanonical      VulnerabilityType = "Path Canonicalization Anomaly"
)

// RedirectHop represents an individual HTTP hop in a redirect chain.
type RedirectHop struct {
	HopNumber      int               `json:"hop_number"`
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	LocationHeader string            `json:"location_header,omitempty"`
	DestinationURL string            `json:"destination_url,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	BodySnippet    string            `json:"body_snippet,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// Evidence captures concrete proof for reproducibility.
type Evidence struct {
	LocationHeader       string `json:"location_header,omitempty"`
	InjectedPayload      string `json:"injected_payload"`
	TargetParameter      string `json:"target_parameter,omitempty"`
	ReflectedInBody      bool   `json:"reflected_in_body"`
	ScriptSnippet        string `json:"script_snippet,omitempty"`
	BaselineDestination  string `json:"baseline_destination,omitempty"`
	BaselineStatus       int    `json:"baseline_status,omitempty"`
	BaselineRedirects    bool   `json:"baseline_redirects"`
	InjectedDestination  string `json:"injected_destination,omitempty"`
	DestinationHostMatch bool   `json:"destination_host_match"`
}

// Finding represents a single discovered vulnerability or noteworthy result.
type Finding struct {
	ID                string            `json:"id"`
	VulnerableURL     string            `json:"vulnerable_url"`
	OriginalURL       string            `json:"original_url"`
	TargetHost        string            `json:"target_host"`
	Parameter         string            `json:"parameter,omitempty"`
	Payload           string            `json:"payload"`
	VulnerabilityType VulnerabilityType `json:"vulnerability_type"`
	Classification    Classification    `json:"classification"`
	Confidence        Confidence        `json:"confidence"`
	InitialStatus     int               `json:"initial_status"`
	FinalStatus       int               `json:"final_status"`
	FinalDestination  string            `json:"final_destination"`
	RedirectChain     []RedirectHop     `json:"redirect_chain,omitempty"`
	Evidence          Evidence          `json:"evidence"`
	ValidationNotes   []string          `json:"validation_notes"`
	Timestamp         time.Time         `json:"timestamp"`
}

// BaselineResult stores the pre-injection behavior of a target URL.
type BaselineResult struct {
	URL              string
	StatusCode       int
	FinalURL         string
	LocationHeader   string
	RedirectChain    []RedirectHop
	HadRedirects     bool
	NormalizedPath   string
	IsStaticRedirect bool
}

// InjectedTarget holds the constructed URL alongside metadata about the injection.
type InjectedTarget struct {
	URL             string
	Parameter       string
	Payload         string
	PayloadCategory string
}

// ClientSideResult contains any detected client-side navigation patterns.
type ClientSideResult struct {
	Detected          bool
	Type              VulnerabilityType
	TargetDestination string
	Snippet           string
}

// ScanSummary aggregates statistical data about a completed scan.
type ScanSummary struct {
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	TotalTargets      int           `json:"total_targets"`
	TestedParameters  int           `json:"tested_parameters"`
	TotalRequests     int64         `json:"total_requests"`
	ConfirmedCount    int           `json:"confirmed_count"`
	PotentialCount    int           `json:"potential_count"`
	UnconfirmedCount  int           `json:"unconfirmed_count"`
	FalsePositiveCount int          `json:"false_positive_count"`
	Errors            []string      `json:"errors,omitempty"`
}

const (
	ScanModeFast = "fast"
	ScanModeDeep = "deep"
)

// ScanConfig holds all operational settings for RedirX.
type ScanConfig struct {
	// Targets
	TargetURL  string
	TargetList string
	UseStdin   bool

	// Execution
	Mode            string // "fast" (default: two-stage canary discovery) or "deep" (exhaustive matrix)
	Threads         int
	Timeout         time.Duration
	Delay           time.Duration
	Retries         int
	MaxRedirects    int
	MaxResponseSize int64
	RateLimit       int // Requests per second per host

	// HTTP Options
	Headers   []string
	Cookies   string
	UserAgent string
	ProxyURL  string

	// Payloads and Parameters
	PayloadFile   string
	TestDomain    string
	ExcludeParams []string
	IncludeParams []string
	PathTest      bool // Enable legacy path-segment stripping check

	// Scope and Security
	Allowlist          []string
	SafeRedirectsOnly  bool // Block SSRF / private IP redirects
	InsecureSkipVerify bool // Verify TLS by default

	// Output & Reporting
	ResultName   string
	Formats      []string // txt, html, json
	OutputPath   string
	DataDir      string
	Force        bool // Overwrite existing result files
	Interactive  bool

	// Console
	Verbose bool
	Silent  bool
	NoColor bool
}

