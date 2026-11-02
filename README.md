# RedirX 🚀
### Advanced Open Redirect Detection & Analysis Engine

[![CI](https://github.com/khaleddevsec/RedirX/actions/workflows/ci.yml/badge.svg)](https://github.com/khaleddevsec/RedirX/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/khaleddevsec/RedirX)](https://goreportcard.com/report/github.com/khaleddevsec/RedirX)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.0-emerald.svg)](https://github.com/khaleddevsec/RedirX/releases)

**RedirX** is a high-performance, evidence-based CLI security tool written in idiomatic Go, engineered to detect, validate, and analyze Open Redirect vulnerabilities ([CWE-601](https://cwe.mitre.org/data/definitions/601.html)). Designed for application security engineers, penetration testers, and bug bounty researchers, RedirX moves far beyond simplistic HTTP status code checking to deliver multi-stage injection, hop-by-hop redirect tracking, baseline comparison, SSRF defense, client-side JavaScript/Meta-refresh detection, and comprehensive reporting (TXT, HTML, JSON).

---

## 1. Evolution & Technical Improvements

Before architecting RedirX in Go, a deep technical evaluation of traditional open-redirect detection scripts and basic heuristics was conducted:

### Limitations of Basic/Legacy URL Heuristics
1. **Misclassification of Vulnerability**: Many basic scripts only strip path segments or check if `/a/` redirects to `/a/b` on the same origin. That is an internal path canonicalization anomaly, **not an Open Redirect** (CWE-601). CWE-601 requires that attacker-controlled user input redirects a visitor to an untrusted external origin.
2. **Blind Redirect Following**: Standard libraries like Python `requests.get(allow_redirects=True)` follow up to 30 redirects blindly without recording intermediate hops, status codes, or `Location` headers.
3. **Zero SSRF Protection**: Blind redirect following allows targets redirecting to internal RFC 1918 addresses, loopback (`127.0.0.1`), link-local, or cloud metadata endpoints (`169.254.169.254`) to be accessed blindly.
4. **No Client-Side Evaluation**: Common tools completely miss HTML Meta Refresh (`<meta http-equiv="refresh">`) and client-side JavaScript navigation (`window.location = ...`).
5. **Rigid Output & Performance**: Lack of structured formats (JSON, HTML) and synchronous single-threaded bottlenecks.

### Architectural Improvement Matrix

| Capability / Logic | Legacy Heuristic Scripts | RedirX (Go Implementation) | Status |
| :--- | :--- | :--- | :--- |
| **Runtime Dependency** | Python / Interpreter required | Standalone compiled Go binary (Zero external dependencies) | **Engineered in Go** |
| **Interface** | Desktop GUI / Basic scripts | Modern POSIX CLI with Cobra, flags, and subcommands | **Production Standard** |
| **Parameter Injection Engine** | ❌ None | Discovers & injects 35+ candidate parameters + custom lists | **Enterprise Grade** |
| **Multi-Vector Payload Suite** | ❌ None | Protocol-relative, backslash, authority `@`, dot-segment, encoding | **Enterprise Grade** |
| **Redirect Analysis** | Blind following | Hop-by-hop tracing, loop detection, status inspection | **Hardened Engine** |
| **Baseline Comparison** | ❌ None | Compares unmodified baseline response with injected response | **Zero False-Positive Focus** |
| **SSRF & Private IP Guard** | ❌ None | Per-hop DNS resolution & connection-time IP validation (Anti-rebinding) | **Built-in Security** |
| **Client-Side Redirection** | ❌ None | Regex & HTML analysis for Meta refresh & `window.location` JS | **Built-in Security** |
| **Path Segment Analysis** | Basic stripping | Preserved and enhanced as optional heuristic (`--path-test`) | **Accurately Isolated** |
| **Output Formats** | Plaintext only | TXT, Interactive HTML (embedded styling), and JSON | **Multi-Format** |
| **Data Directory** | Unstructured | Predictable user data hierarchy (`~/RedirX/` results, reports, logs) | **Organized** |
| **Concurrency & Workers** | Single-threaded sequential | Worker pool with goroutines, channels, and per-host rate limiting | **High Throughput** |
| **Self-Update** | ❌ None | `redirx update` with GitHub Releases & SHA-256 verification | **Built-in Automation** |

---

## 2. Architecture & Design Principles

RedirX is structured into clean, modular Go packages under `internal/` and `pkg/`:

```
RedirX/
├── cmd/
│   └── redirx/            # CLI entry point (main.go)
├── internal/
│   ├── cli/               # Cobra commands: root, version, update, config, results
│   ├── config/            # Data directory paths (~/RedirX) & overwrite protection
│   ├── detector/          # URL/param parser, payload generator, injection, clientside, path analyzer
│   ├── logger/            # log/slog structured logging with console formatting
│   ├── models/            # Domain models: Finding, RedirectHop, Evidence, ScanSummary, ScanConfig
│   ├── redirect/          # Safe HTTP client, SSRF-guarded transport, hop-by-hop execution
│   ├── reporter/          # Multi-format report generators (TXT, HTML, JSON)
│   ├── scanner/           # Worker pool orchestrator & per-host rate limiting
│   ├── scope/             # Allowlist scoping & CIDR/SSRF/cloud metadata validation
│   ├── stats/             # Thread-safe atomic metrics collector
│   ├── updater/           # GitHub release checker with SHA-256 validation & atomic rollback
│   └── validator/         # Evidence-based classification & false positive filtering
├── pkg/
│   └── version/           # Version strings and build metadata
├── configs/
│   ├── payloads.txt       # Customizable payload templates
│   └── parameters.txt     # Candidate redirect parameters wordlist
├── tests/
│   ├── unit_test.go       # Unit tests for parsing, SSRF, payloads, reports
│   └── integration_test.go# Local httptest integration scenarios (10+ test cases)
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

## 4. Detection & Validation Engine

RedirX does not blindly assume that an HTTP 301 or 302 code represents a vulnerability. Findings are verified through a multi-stage validation pipeline:

### Finding Classifications

- **`CONFIRMED`**: Concrete proof that attacker-controlled input caused the server to emit an HTTP 3xx redirect to an external untrusted domain differing from baseline behavior.
- **`POTENTIAL`**: Client-side redirection pattern (HTML `<meta http-equiv="refresh">` or JavaScript `window.location`) targeting the test domain, requiring browser context for execution.
- **`UNCONFIRMED`**: Redirection response where destination reflected payload components but navigation did not complete or was filtered.
- **`FALSE POSITIVE`**: Fixed redirects, identical baseline redirects, or reflection in the HTML response body without navigation.

### Payload Categories

RedirX tests an array of parser and filter evasion vectors against each parameter:
1. **Standard Absolute**: `https://example.com`, `http://example.com`
2. **Protocol-Relative**: `//example.com`, `///example.com`, `////example.com`
3. **Backslash Obfuscation**: `/\example.com`, `\/example.com`, `\\example.com`
4. **Authority & Userinfo Bypasses**: `https://target.com@example.com`, `https://example.com#@target.com`
5. **Dot-Segment Traversal**: `/../example.com`, `/%2e%2e/example.com`
6. **URL & Double Encoding**: `%2f%2fexample.com`, `%252f%252fexample.com`
7. **Termination Bypasses**: `https://example.com%00`, `https://example.com/.`

---

## 5. Security & SSRF Protection

By default, RedirX enforces strict SSRF protections:
- **Private IP Blocking**: Resolves destination hostnames at every hop and blocks RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and carrier-grade NAT (`100.64.0.0/10`).
- **Cloud Metadata Defense**: Intercepts requests to `169.254.169.254`, `metadata.google.internal`, and other cloud metadata endpoints.
- **Anti-DNS Rebinding**: The custom `SafeDialContext` resolves DNS once, validates the IP, and connects directly to the validated IP.
- **TLS Verification**: Verified by default. Skipped only with explicit `--insecure` flag.

---

## 6. Installation & Building

### Prerequisites
- Go 1.22+ (for building from source)
- Linux (AMD64 or ARM64)

### Building for Linux (AMD64 & ARM64)

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

### Installation to System PATH

```bash
# Copy to user local bin
mkdir -p ~/.local/bin
cp bin/redirx_linux_amd64 ~/.local/bin/redirx
chmod +x ~/.local/bin/redirx

# Ensure ~/.local/bin is in your PATH:
export PATH="$HOME/.local/bin:$PATH"
```

---

## 7. CLI Usage & Examples

### Single Target Scan
```bash
redirx -u "https://example.com/login?redirect=https://target.com"
```

### Bulk Scanning from File
```bash
redirx -l urls.txt -t 20 --delay 100ms
```

### Stdin Pipeline
```bash
cat urls.txt | redirx -stdin -format txt,html,json -name bugbounty-audit
```

### Custom Test Domain & Payloads
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

### Inspecting Previous Results & Configuration
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
| `--threads` | `-t` | `10` | Worker pool concurrency |
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

## 9. Verification & Testing

RedirX includes an automated test suite featuring Go `httptest` mock servers covering 19 distinct test scenarios:

```bash
# Run full test suite
go test -v ./tests

# Run static analysis check
go vet ./...
```

### Test Coverage Highlights
- ✅ Genuine Open Redirect detection
- ✅ Normal internal redirect false-positive elimination
- ✅ Fixed external redirect baseline comparison
- ✅ Body reflection without redirect filtering
- ✅ Multi-hop chained redirect tracking
- ✅ Client-side JavaScript navigation detection
- ✅ Client-side Meta-refresh detection
- ✅ Redirect loop detection and depth limiting
- ✅ Private IP / SSRF attempt blocking
- ✅ Legacy path-segment stripping heuristic verification
- ✅ Parameter extraction and inclusion/exclusion filtering
- ✅ SSRF validator against loopback, private RFC 1918, link-local, and cloud metadata
- ✅ Report serialization for TXT, JSON, and responsive HTML
- ✅ File output resolution and auto-deduplication

---

## 10. License

RedirX is open-source software licensed under the [MIT License](LICENSE).

