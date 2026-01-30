# Architecture

**Analysis Date:** 2026-01-30

## Pattern Overview

**Overall:** Modular, scanner-plugin architecture with layered data flow and intelligent context-aware orchestration

**Key Characteristics:**
- **94+ vulnerability scanner modules** organized by vulnerability type and technology stack
- **Context-aware intelligent orchestration** replacing legacy mode-based scanning (fast/normal/thorough/insane)
- **Technology-driven routing** that detects frameworks and selects relevant scanners
- **Parameter-level risk scoring** instead of global payload intensity
- **Multi-layer analysis** combining response analysis, hypothesis engines, and attack planning
- **Async/concurrent execution** with adaptive rate limiting and circuit breaker resilience
- **Extensible plugin system** for custom scanners and findings analysis

## Layers

**CLI & Command Entry Point:**
- Purpose: Parse arguments, initialize configuration, orchestrate scan execution, output results
- Location: `src/cli/main.rs`
- Contains: Command definitions (Scan, Config, License), output format handlers, CLI state management
- Depends on: All core scanner modules, config system, licensing system
- Used by: Direct user invocation

**Configuration & Secrets Management:**
- Purpose: Load and manage application config, scan profiles, target configs, secrets from multiple backends
- Location: `src/config/` (core.rs, loader.rs, plugins.rs, profiles.rs, secrets.rs, targets.rs, validation.rs)
- Contains: Config structures, environment loading, hot-reload support, multi-backend secrets (Vault, keyring, env vars)
- Depends on: Standard library, serde, tokio, validator
- Used by: CLI, Scanner engine, HTTP client initialization

**Type System & Core Data Structures:**
- Purpose: Define scan job, vulnerability, result, and scan configuration types
- Location: `src/types.rs`, `src/vulnerability.rs`
- Contains: ScanJob, ScanConfig, ScanMode (Intelligent/Fast/Normal/Thorough/Insane), Vulnerability, ScanResults, Severity/Confidence enums
- Depends on: serde, chrono, uuid
- Used by: All scanner modules, orchestrator, reporting

**HTTP Client & Network Layer:**
- Purpose: Provide request/response abstraction with caching, rate limiting, circuit breaking, semantic analysis
- Location: `src/http_client.rs`
- Contains: HttpClient struct, request/response types, browser user-agent rotation, connection pooling, HTTP/2 support
- Depends on: reqwest, moka (caching), circuit_breaker, rate_limiter, response_analyzer
- Used by: Crawler, all scanners, discovery modules

**Crawler & Attack Surface Discovery:**
- Purpose: Discover crawlable URLs, forms, endpoints, parameters from target application
- Location: `src/crawler.rs`
- Contains: WebCrawler, URL prioritization via coverage-based heuristics, form detection, parameter extraction
- Depends on: HttpClient, scraper, URL parsing
- Used by: Intelligent orchestrator, endpoint deduplication

**Intelligent Scan Orchestrator:**
- Purpose: Context-aware scan planning replacing mode-based scanning with tech detection and risk scoring
- Location: `src/scanners/intelligent_orchestrator.rs`
- Contains: IntelligentScanOrchestrator, IntelligentScanPlan, parameter prioritization
- Depends on: ScannerRegistry, ParameterPrioritizer, AttackSurface analysis
- Used by: CLI main scan flow

**Analysis & Intelligence Engine:**
- Purpose: Multi-layered analysis to understand responses, detect vulnerabilities patterns, plan attacks
- Location: `src/analysis/`
- Contains: ResponseAnalyzer (semantic analysis of responses), AttackPlanner (orchestrate exploitation sequences), HypothesisEngine (probabilistic tech/vuln detection), CorrelationEngine (link attack chains), TechDetector (framework identification)
- Depends on: Types, HTTP client, inference
- Used by: Scanner modules, orchestrator for intelligent decisions

**Scanner Modules (94+ implementations):**
- Purpose: Implement vulnerability detection logic for specific vuln types and tech stacks
- Location: `src/scanners/` (individual .rs files for each scanner)
- Contains: Specific scanner implementations (XSS, SQLi, CSRF, BOLA, auth bypass, framework-specific vulnerabilities, etc.)
- Depends on: HttpClient, types, analysis, payloads
- Used by: ScanEngine orchestration

**Payload Management:**
- Purpose: Curate and cache vulnerability testing payloads with optimization for different contexts
- Location: `src/payloads.rs`, `src/payloads_optimized.rs`, `src/payloads_comprehensive.rs`
- Contains: Payload definitions for XSS, SQLi, SSTI, command injection, etc., with context-aware filtering
- Depends on: Standard library
- Used by: All scanner modules

**Resilience & Reliability:**
- Purpose: Prevent overload, handle failures gracefully, adapt to target behavior
- Location: `src/circuit_breaker.rs`, `src/rate_limiter.rs`, `src/adaptive_concurrency.rs`, `src/retry.rs`
- Contains: Circuit breaker (fail-fast), token-bucket rate limiting, adaptive concurrency, exponential backoff retry
- Depends on: tokio, governor
- Used by: HttpClient, crawler, all network-using modules

**Discovery Modules:**
- Purpose: Enumerate subdomains, endpoints, cloud storage, APIs
- Location: `src/discovery/` (subdomain_discovery.rs, endpoint_discovery.rs)
- Contains: Subdomain enumeration, endpoint fingerprinting
- Depends on: HttpClient, DNS resolver, DNS cache
- Used by: CLI for --subdomains flag

**License & Authorization:**
- Purpose: Validate license, check module availability, prevent unauthorized execution
- Location: `src/license/` (mod.rs, anti_tamper.rs, scan_auth.rs), `src/signing/` (quantum-safe signing)
- Contains: LicenseStatus enum, license validation, scan token signing/verification
- Depends on: Cryptographic libraries (hmac, sha2, blake3, ssh2)
- Used by: CLI before scan execution, module registry

**Reporting & Output:**
- Purpose: Format scan results in multiple output formats (JSON, HTML, PDF, SARIF, CSV, XLSX, Markdown)
- Location: `src/reporting/` (engine.rs, formats/, delivery.rs, deduplication.rs)
- Contains: Report generation, multiple format handlers, result deduplication
- Depends on: serde, rust_xlsxwriter, csv
- Used by: CLI for --output and --format flags

**Machine Learning & Inference:**
- Purpose: Federated learning for pattern recognition, false positive classification, probabilistic inference
- Location: `src/ml/` (auto_learning.rs, fp_classifier.rs, federated.rs, features.rs, privacy.rs)
- Contains: Feature extraction, model training, privacy-preserving federated learning
- Depends on: Analysis module, ML framework dependencies
- Used by: Analysis engine, response analyzer

**Database & Queue:**
- Purpose: Persistent scan state, asynchronous job queuing for distributed scanning
- Location: `src/database.rs`, `src/queue.rs`
- Contains: PostgreSQL connection pooling (deadpool-postgres), Redis queue (deadpool-redis)
- Depends on: tokio-postgres, deadpool, redis
- Used by: CLI for --database integration, job distribution

**Cloud Security:**
- Purpose: AWS, GCP, Azure-specific security scanning
- Location: `src/cloud/` (mod.rs, error_handling.rs, optimizations.rs)
- Contains: Cloud storage scanning, identity scanning, configuration assessment
- Depends on: HttpClient, analysis
- Used by: Scanner registry based on detected cloud providers

**Error Handling & Metrics:**
- Purpose: Comprehensive error types and operational metrics collection
- Location: `src/errors.rs`, `src/metrics.rs`
- Contains: ScannerError enum with variants (Network, HTTP, Database, RateLimit, etc.), metrics recording
- Depends on: thiserror, standard library
- Used by: All modules for error propagation

**Validation & Detection Helpers:**
- Purpose: Utility functions for input validation, technology detection, CDN detection
- Location: `src/validation/`, `src/detection_helpers.rs`, `src/cdn_detector.rs`, `src/framework_detector.rs`
- Contains: Regex-based and signature-based detection, validation utilities
- Depends on: regex, scraper, HTTP client
- Used by: Orchestrator, scanners, analysis

## Data Flow

**Scan Initiation Flow:**

1. User runs `lonkero scan https://target.com` with optional flags
2. CLI parses arguments, loads config from file or environment
3. License validation occurs (`src/license/mod.rs`)
4. ScannerConfig initialized with auth, rate limits, etc.
5. HttpClient created with circuit breaker, rate limiter, intelligence bus
6. WebCrawler discovers attack surface (forms, endpoints, parameters)
7. IntelligentScanOrchestrator evaluates crawl results:
   - Detects target technology stack (Django, Express, ASP.NET, etc.)
   - Deduplicates endpoints (avoid testing same login form 50 times)
   - Scores each parameter by risk (high risk → more payloads)
   - Selects relevant scanners from registry based on detected tech
8. ResponseAnalyzer wired into analysis flow for semantic understanding
9. ScanEngine executes selected scanners in parallel with adaptive concurrency
10. Results aggregated, deduplicated, formatted, output

**Vulnerability Detection Flow:**

1. Scanner module receives HttpClient, target URL, parameter, payload
2. Sends crafted request to application
3. HttpClient:
   - Applies rate limiting (adaptive to target's throttling)
   - Checks circuit breaker (skip if target failing)
   - Caches response if applicable
   - Analyzes response semantically (error type, content changes, etc.)
4. Scanner evaluates response:
   - Pattern matching (error messages, encoded payload reflection)
   - Time-based analysis (for timing-sensitive vulns)
   - Response semantic differences from baseline
5. If vulnerability confidence high, creates Vulnerability struct with evidence
6. All results streamed through IntelligenceBus to analysis module
7. Analysis performs correlation and cross-vulnerability inference

**Analysis & Intelligence Flow:**

1. ResponseAnalyzer inspects HTTP response:
   - Detects error types (SQL errors, stack traces, etc.)
   - Extracts security indicators (auth state, rate limiting headers)
   - Semantic analysis (context of response)
2. AttackPlanner receives vulnerability findings:
   - Maps prerequisites (needs auth? needs valid ID?)
   - Plans exploitation chains (if IDOR found, can we escalate to RCE?)
3. HypothesisEngine generates hypotheses about target tech:
   - Tracks evidence (e.g., "Flask detected in stack trace")
   - Suggests tests to confirm/refute hypotheses
4. CorrelationEngine links related vulnerabilities:
   - Groups related XSS findings
   - Chains auth bypasses with data exfiltration

**State Management Flow:**

1. ScanJob created with unique scan_id and configuration
2. If --database flag: scan state persisted to PostgreSQL
3. If --redis flag: scanning jobs queued for distributed execution
4. Crawl results cached (moka in-memory) to avoid re-crawling same endpoints
5. DNS results cached (dns_cache.rs) to avoid DNS resolution overhead
6. Session state tracked (session_recording.rs) for complex auth flows

**State Management:**
- Scan job state tracked via `ScanJob` struct with config and ID
- Crawler state maintained in-memory during crawl (discovered URLs, visited pages)
- HTTP response cache in HttpClient (moka) reduces duplicate requests
- DNS cache in `dns_cache.rs` persists resolution results
- Session state in `session_recording.rs` for browser-based authentication flows
- If PostgreSQL configured: persistent scan state stored with job ID

## Key Abstractions

**Vulnerability (Type):**
- Purpose: Represents detected vulnerability with all context for reporting
- Examples: `src/types.rs` defines Vulnerability struct
- Pattern: Created by scanner modules with id, type, severity, confidence, evidence, remediation

**Scanner (Module Pattern):**
- Purpose: Individual vulnerability detection implementation
- Examples: `src/scanners/xss.rs`, `src/scanners/sqli_enhanced.rs`, `src/scanners/bola.rs`
- Pattern: Each scanner module exports async function that takes (HttpClient, URL, params, config) → Vec<Vulnerability>

**ScanMode (Enum):**
- Purpose: Determine scanning intensity (legacy) or trigger intelligent mode
- Examples: ScanMode::Fast (50 payloads globally), ScanMode::Intelligent (context-aware)
- Pattern: Used in ScanConfig to control execution; Intelligent mode routes through orchestrator

**TechCategory (Detection):**
- Purpose: Group detectable technology stacks (Django, React, AWS, etc.)
- Examples: `src/scanners/registry.rs` defines TechCategory enum
- Pattern: Technologies detected by framework_detector and TechDetector, used to filter scanner selection

**PayloadIntensity (Enum):**
- Purpose: Scale payload count per parameter based on detected risk
- Examples: Low (5 payloads), Medium (20 payloads), High (100+ payloads)
- Pattern: Assigned by ParameterPrioritizer based on parameter risk score

**HttpResponse (Wrapper):**
- Purpose: Encapsulate HTTP response with semantic analysis
- Examples: `src/http_client.rs` HttpResponse struct
- Pattern: Contains body, headers, status code, timing data; used by response analyzer

**IntelligenceBus (Pub/Sub):**
- Purpose: Broadcast vulnerability findings across analysis systems
- Examples: `src/analysis/intelligence_bus.rs`
- Pattern: Channels for findings, state updates, hypothesis results; allows async consumers

**CircuitBreaker (Resilience):**
- Purpose: Fail-fast when target unresponsive (prevent timeout storms)
- Examples: `src/circuit_breaker.rs`
- Pattern: Tracks failure rate per host, opens after threshold, auto-resets after timeout

**AdaptiveRateLimiter (Resilience):**
- Purpose: Respect target rate limits while maximizing throughput
- Examples: `src/rate_limiter.rs`, `src/analysis/adaptive_rate_limiter.rs`
- Pattern: Token bucket per host, adjusts based on 429/503 responses, learns target's limits

## Entry Points

**Main CLI Binary:**
- Location: `src/cli/main.rs`
- Triggers: User runs `lonkero` command with subcommands
- Responsibilities: Parse args, initialize config, call ScanEngine, format output, handle exit codes

**Scan Subcommand:**
- Location: `src/cli/main.rs` (Commands::Scan variant)
- Triggers: `lonkero scan <targets>`
- Responsibilities: Coordinate license check, crawler, orchestrator, scanners, reporting

**Programmatic Library Entry:**
- Location: `src/lib.rs`
- Triggers: External crates import lonkero_scanner
- Responsibilities: Export public types (ScanJob, ScanResults, Vulnerability) and core structs (HttpClient, ScanEngine)

**Headless Crawler (JS-rendered apps):**
- Location: `src/headless_crawler.rs`
- Triggers: Auto-detected when initial crawl finds JavaScript content
- Responsibilities: Launch headless Chrome, execute JS, discover dynamically-rendered endpoints

**GraphQL Introspection:**
- Location: `src/graphql_introspection.rs`
- Triggers: Auto-detected when `/graphql` or schema endpoint found
- Responsibilities: Query introspection, extract available types and fields, generate test payloads

## Error Handling

**Strategy:** Hierarchical error types (ScannerError → NetworkError/HttpError/DatabaseError/ScanError) with automatic context enrichment via anyhow

**Patterns:**
- NetworkError: Connection timeouts, DNS failures, socket errors → logged with URL and timeout duration
- HttpError: 4xx/5xx responses, malformed responses → includes status code and response snippet
- ScanError: Scanner-specific errors → includes vulnerability type, target URL, parameter
- RateLimitExceeded: 429 response → includes Retry-After duration, auto-backoff
- CircuitBreakerOpen: Host failures → fail-fast, skip further requests to that host
- TimeoutError: Operation timeout → includes operation name and duration
- ValidationError: Invalid configuration → includes invalid field and expected format

Error propagation uses anyhow::Result with context() for breadcrumb trail. Errors logged at appropriate levels (debug for recoverable, warn for degradation, error for critical failures).

## Cross-Cutting Concerns

**Logging:** Structured logging via tracing crate with JSON formatter in production, human-readable in CLI output. Levels controlled by --verbose and --debug flags.

**Validation:** Input validation at config load time (ConfigValidator in `src/config/validation.rs`), URL validation in crawler, payload validation before sending.

**Authentication:** Multiple auth types supported (cookie, Bearer token, Basic auth, OAuth, SAML) via `src/auth_context.rs` and scanner-specific auth handlers (e.g., Django CSRF token handling).

**Rate Limiting:** Two-level approach - global rate limiter for overall concurrency, per-host rate limiter (AdaptiveRateLimiter) that learns target's limits from HTTP headers and responses.

**Caching:** HTTP response caching (moka), DNS resolution caching (dns_cache.rs), crawler URL caching to avoid revisits.

**Resilience:** Circuit breaker per host, exponential backoff retry (retry.rs), timeout enforcement, adaptive concurrency adjustment.

**Metrics:** Operational metrics collection (request count, error rate, latency percentiles) via metrics.rs, can be exported to external systems.

---

*Architecture analysis: 2026-01-30*
