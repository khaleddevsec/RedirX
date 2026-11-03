# RedirX
### Advanced Open Redirect Detection and Analysis Engine

[![CI](https://github.com/khaleddevsec/RedirX/actions/workflows/ci.yml/badge.svg)](https://github.com/khaleddevsec/RedirX/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/khaleddevsec/RedirX)](https://goreportcard.com/report/github.com/khaleddevsec/RedirX)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v3.1.2-emerald.svg)](https://github.com/khaleddevsec/RedirX/releases)
[![Developer](https://img.shields.io/badge/Developer-khaleddevsec-indigo.svg)](https://github.com/khaleddevsec)

**RedirX** is an advanced, high-performance, evidence-based CLI security tool developed by **Md. Khaledul Islam ([@khaleddevsec](https://github.com/khaleddevsec))** in idiomatic Go. Designed for application security research, vulnerability auditing, and bug bounty automation, RedirX serves as a specialized practical learning tool for students at **Arena Web Security** to analyze and detect Open Redirect vulnerabilities ([CWE-601](https://cwe.mitre.org/data/definitions/601.html)).

RedirX delivers two-stage injection, hop-by-hop redirect tracking, baseline comparison, SSRF defense, client-side JavaScript and Meta-refresh detection, real-time terminal metrics, and comprehensive multi-format reporting (TXT, HTML, JSON).

---

## 1. Evolution and Technical Improvements

Before architecting RedirX in Go, a technical evaluation of traditional open-redirect detection scripts and basic heuristics was conducted:

### Limitations of Basic Legacy Heuristics
1. **Vulnerability Misclassification**: Many traditional scripts only strip path segments or check if `/a/` redirects to `/a/b` on the same origin. That is an internal path canonicalization anomaly, not an Open Redirect (CWE-601). CWE-601 requires that attacker-controlled user input redirects a visitor to an untrusted external origin.
2. **Blind Redirect Following**: Standard libraries follow up to 30 redirects blindly without recording intermediate hops, status codes, or `Location` headers.
3. **Zero SSRF Protection**: Blind redirect following allows targets redirecting to internal RFC 1918 addresses, loopback (`127.0.0.1`), link-local, or cloud metadata endpoints (`169.254.169.254`) to be probed without safeguard.
4. **No Client-Side Evaluation**: Common tools miss HTML Meta Refresh (`<meta http-equiv="refresh">`) and client-side JavaScript navigation (`window.location = ...`).
5. **High Request Churn**: Testing 38 parameters with 19 payloads on unparameterized URLs causes 722 requests per URL. RedirX introduces a two-stage Canary probe to cut redundant requests by over 94%.

### Architectural Comparison Matrix

| Capability / Logic | Legacy Heuristic Scripts | RedirX (Go Implementation) | Status |
| :--- | :--- | :--- | :--- |
| **Runtime Dependency** | Python / Interpreter required | Standalone compiled Go binary (Zero external dependencies) | **Engineered in Go** |
| **Interface** | Desktop GUI / Basic scripts | POSIX CLI with Cobra, flags, and subcommands | **Production Standard** |
| **Scanning Engine** | Monolithic execution | Pluggable `DetectionTechnique` interface & `Registry` | **Modular Architecture** |
| **Two-Stage Scanning** | Unsupported | Fast Mode Canary Probing (94% traffic reduction) vs Deep Mode | **Optimized Throughput** |
| **Parameter Injection Engine** | Unsupported | Discovers and injects 38+ candidate parameters + custom lists | **Enterprise Grade** |
| **Multi-Vector Payload Suite** | Unsupported | Protocol-relative, backslash, authority `@`, dot-segment, encoding | **Enterprise Grade** |
| **Redirect Analysis** | Blind following | Hop-by-hop tracing, loop detection, status inspection | **Hardened Engine** |
| **Host Boundary Matching** | Substring checks | Strict host and subdomain verification (`MatchesTestDomain`) | **Zero False-Positive Focus** |
| **Baseline Comparison** | Unsupported | Compares unmodified baseline response with injected response | **Zero False-Positive Focus** |
| **Memory Management** | Full body buffering | Zero-allocation 3xx reader and `sync.Pool` buffer reuse | **High Concurrency** |
| **SSRF & Private IP Guard** | Unsupported | Per-hop DNS resolution & connection-time IP validation | **Built-in Security** |
| **Client-Side Redirection** | Unsupported | Regex and HTML analysis for Meta refresh & SPA `window.location` | **Built-in Security** |
| **Path Segment Analysis** | Basic stripping | Preserved and enhanced as optional heuristic (`--path-test`) | **Accurately Isolated** |
| **Live Terminal Feedback** | Basic logs | Non-interfering real-time progress ticker (req/s, ETA, findings) | **Real-Time Visibility** |
| **Output Formats** | Plaintext only | TXT, Interactive HTML (embedded styling), and JSON | **Multi-Format** |
| **Data Directory** | Unstructured | Predictable user data hierarchy (`~/RedirX/` results, reports, logs) | **Organized** |
| **Concurrency & Workers** | Single-threaded sequential | Worker pool with goroutines, channels, and per-host rate limiting | **High Throughput** |
| **Self-Update** | Unsupported | `redirx update` with GitHub Releases & SHA-256 verification | **Built-in Automation** |

---

## 2. Architecture and Design Principles

RedirX is structured into clean, modular Go packages under `internal/` and `pkg/`:

```
RedirX/
├── cmd/
│   └── redirx/            # CLI entry point (main.go)
├── internal/
│   ├── cli/               # Cobra commands: root, version, update, config, results
│   ├── config/            # Data directory paths (~/RedirX) and overwrite protection
│   ├── detector/          # Pluggable techniques: query parameter, path analyzer, client-side DOM
│   ├── logger/            # log/slog structured logging with console formatting
│   ├── models/            # Core data contracts: Finding, RedirectHop, Evidence, ScanSummary, ScanConfig
│   ├── redirect/          # Safe HTTP client, SSRF-guarded transport, 3xx zero-alloc hop-by-hop execution
│   ├── reporter/          # Multi-format report generators (TXT, HTML, JSON)
│   ├── scanner/           # Worker pool orchestrator, deduplication, and per-host rate limiting
│   ├── scope/             # Allowlist scoping and CIDR/SSRF/cloud metadata validation
│   ├── stats/             # Thread-safe atomic metrics collector
│   ├── ui/                # Real-time non-interfering terminal progress ticker
│   ├── updater/           # GitHub release checker with SHA-256 validation and atomic rollback
│   └── validator/         # Strict domain matching, evidence-based classification, and false positive filtering
├── pkg/
│   └── version/           # Version strings and build metadata
├── configs/
│   ├── payloads.txt       # Customizable payload templates
│   └── parameters.txt     # Candidate redirect parameters wordlist
├── tests/
│   ├── unit_test.go       # Unit tests for parsing, SSRF, payloads, reports, ticker
│   └── integration_test.go# Local httptest integration scenarios (28 test cases)
├── .github/
│   └── workflows/ci.yml   # GitHub Actions CI for AMD64 and ARM64
├── .goreleaser.yaml       # Cross-platform release packaging
├── Makefile               # Build, test, and release targets
├── go.mod                 # Go dependencies (Cobra only)
└── README.md
```

---

## 3. Application Data Directory (`~/RedirX/`)

RedirX maintains an isolated, predictable user data directory. It never writes to system directories or requires root privileges:

```
~/RedirX/
├── results/       # Default scan output files
├── reports/       # Archive of generated reports
├── logs/          # Structured operation logs (redirx.log)
├── config/        # User configuration templates
├── wordlists/     # Custom parameter and payload wordlists
└── backups/       # Executable backups created before self-updates
```

- Override via flag: `--data-dir /custom/path`
- Override via environment: `export REDIRX_DATA_DIR=/custom/path`
- Inspect active directories: `redirx config`

---

## 4. Detection and Validation Engine

RedirX verifies findings through a multi-stage validation pipeline:

### Finding Classifications

- **`CONFIRMED`**: Concrete proof that attacker-controlled input caused the server to emit an HTTP 3xx redirect to an external untrusted domain differing from baseline behavior.
- **`POTENTIAL`**: Client-side redirection pattern (HTML `<meta http-equiv="refresh">` or JavaScript `window.location`) targeting the test domain, requiring browser context for execution.
- **`UNCONFIRMED`**: Redirection response where destination reflected payload components but navigation did not complete or was filtered.
- **`FALSE POSITIVE`**: Fixed redirects, identical baseline redirects, or reflection in the HTML response body without navigation.

### Payload Categories

RedirX tests an array of parser and filter evasion vectors against each parameter:
1. **Standard Absolute**: `https://example.com`, `http://example.com`, `hTTps://example.com`
2. **Protocol-Relative**: `//example.com`, `///example.com`, `////example.com`, `/.//example.com`
3. **Backslash Obfuscation**: `/\example.com`, `\/example.com`, `\\example.com`, `/\\/example.com`
4. **Authority and Userinfo Bypasses**: `https://target.com@example.com`, `https://example.com#@target.com`
5. **Dot-Segment Traversal**: `/../example.com`, `/%2e%2e/example.com`, `/..//example.com`
6. **URL and Double Encoding**: `%2f%2fexample.com`, `%252f%252fexample.com`, `https:%2f%2fexample.com`
7. **CRLF Header Injection**: `/%0d%0aLocation:%20https://example.com`
8. **Termination and Whitespace**: `https://example.com%00`, `https://example.com%09`, `https://example.com.`

---

## 5. Security and SSRF Protection

By default, RedirX enforces strict SSRF protections:
- **Private IP Blocking**: Resolves destination hostnames at every hop and blocks RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and carrier-grade NAT (`100.64.0.0/10`).
- **Cloud Metadata Defense**: Intercepts requests to `169.254.169.254`, `metadata.google.internal`, and other cloud metadata endpoints.
- **Anti-DNS Rebinding**: The custom `SafeDialContext` resolves DNS and validates IP addressing at the TCP connection handshake.
- **TLS Verification**: Verified by default. Skipped only with explicit `--insecure` flag.

---

## 6. Installation and Building

### Prerequisites
- Go 1.22+ (for building from source)
- Linux (AMD64 or ARM64) or Windows (AMD64)

### Building for Linux (AMD64 and ARM64)

```bash
# Build both Linux AMD64 and ARM64 binaries
make build-all

# Or build individually:
make build-linux-amd64
make build-linux-arm64
```

Compiled binaries will be generated in `bin/`:
- `bin/redirx_linux_amd64`
- `bin/redirx_linux_arm64`

### Installation to System PATH (Linux / WSL2)

```bash
# Copy binary to system path
sudo cp bin/redirx_linux_amd64 /usr/local/bin/redirx
sudo chmod +x /usr/local/bin/redirx

# Verify installation
redirx version
```

---

## 7. CLI Usage and Examples

### Single Target Scan
```bash
redirx -u "https://example.com/login?redirect=https://target.com"
```

### Bulk Scanning from File
```bash
# Fast Mode (Default): Smart two-stage canary probing (over 94% traffic reduction on bulk lists)
redirx -l urls.txt -t 20

# Deep Mode: Exhaustive evasion fuzzing across all parameters and payloads
redirx -l urls.txt -m deep -t 20 --delay 100ms
```

### Stdin Pipeline
```bash
cat urls.txt | redirx -stdin -format txt,html,json -name bugbounty-audit
```

### Custom Test Domain and Payloads
```bash
redirx -u "https://example.com/oauth" --test-domain "my-collaborator.net" --payload-file configs/payloads.txt
```

### Enabling Legacy Path Canonicalization Heuristic
```bash
redirx -u "https://example.com/app/v1/profile" --path-test
```

### Custom Results Filename and Output Overwrite
```bash
# Generates audit.txt, audit.html, and audit.json in ~/RedirX/results/
redirx -l targets.txt -name audit -format txt,html,json

# Force overwrite existing report file
redirx -u "https://example.com/auth" -name audit -f
```

### Inspecting Previous Results and Configuration
```bash
redirx results
redirx config
```

### Self-Update
```bash
redirx update
```

---

## 8. CLI Reference

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--url` | `-u` | `""` | Single target URL |
| `--list` | `-l` | `""` | Path to file containing target URLs (one per line) |
| `--stdin` | | `false` | Read target URLs from standard input |
| `--mode` | `-m` | `fast` | Scan mode: `fast` (two-stage smart canary probe) or `deep` (exhaustive matrix) |
| `--threads` | `-t` | `10` | Worker pool concurrency |
| `--ticker` | | `true` | Display live terminal progress ticker (req/s, active workers, ETA) |
| `--timeout` | | `10s` | HTTP timeout per request |
| `--delay` | | `0s` | Delay between requests to the same host (e.g. `200ms`, `1s`) |
| `--retry` | | `1` | Request retries on network error |
| `--max-redirects`| | `10` | Maximum redirect hops before stopping |
| `--name` | `-n` | Auto | Custom result name (e.g. `audit-scan`) |
| `--format` | | `txt` | Comma-separated output formats (`txt`, `html`, `json`) |
| `--output` | `-o` | `""` | Custom destination file or directory |
| `--force` | `-f` | `false` | Force overwrite existing report files |
| `--allowlist` | | `""` | Scope allowlist (domains or CIDRs) |
| `--payload-file`| | `""` | Path to custom payload template file |
| `--test-domain` | | `example.com`| External domain for redirect verification |
| `--include-params`| | `""` | Test only specified parameters |
| `--exclude-params`| | `""` | Exclude specified parameters from testing |
| `--path-test` | | `false` | Enable legacy path-segment stripping heuristic |
| `--verbose` | `-v` | `false` | Enable verbose debugging output |
| `--silent` | | `false` | Silent mode (output only findings) |
| `--insecure` | | `false` | Skip TLS certificate verification |

---

## 9. Verification and Testing

RedirX includes an automated test suite featuring Go `httptest` mock servers covering 28 distinct test scenarios:

```bash
# Run full test suite
go test -v ./tests

# Run static analysis check
go vet ./...
```

### Test Coverage Highlights
- Genuine Open Redirect detection
- Normal internal redirect false-positive elimination
- Fixed external redirect baseline comparison
- Body reflection without redirect filtering
- Multi-hop chained redirect tracking
- Client-side JavaScript navigation detection (including ES6 template literals)
- Client-side Meta-refresh detection
- Redirect loop detection and depth limiting
- Private IP / SSRF attempt blocking
- Legacy path-segment stripping heuristic verification
- Fast Mode Canary Probing (over 94% request reduction on bulk lists)
- Stage 2 Evasion Escalation on responsive parameters
- Strict domain boundary matching (`MatchesTestDomain`) eliminating domain collision false positives
- Zero-allocation 3xx redirect reader and `sync.Pool` buffer reuse
- Live progress ticker metrics and duration formatting
- In-memory target URL deduplication
- Pluggable `DetectionTechnique` registry and decoupled `RequestExecutor`
- Parameter extraction and inclusion/exclusion filtering
- SSRF validator against loopback, private RFC 1918, link-local, and cloud metadata
- Report serialization for TXT, JSON, and responsive HTML
- File output resolution and auto-deduplication

---

## 10. Educational Context

RedirX is dedicated to the students and security researchers of **Arena Web Security** as an educational and operational reference for understanding URL parser differentials, HTTP redirect semantics, and defensible vulnerability validation.

---

## 11. License

RedirX is open-source software licensed under the [MIT License](LICENSE).
