# Codebase Structure

**Analysis Date:** 2026-01-30

## Directory Layout

```
lonkero/
├── src/                                    # Rust source code (239 .rs files)
│   ├── lib.rs                             # Library root, exports public modules
│   ├── cli/
│   │   └── main.rs                        # CLI binary entry point
│   │
│   ├── scanners/                          # 94+ vulnerability scanner modules
│   │   ├── mod.rs                         # Scanner module registry and orchestration
│   │   ├── intelligent_orchestrator.rs    # Context-aware scan planning
│   │   ├── registry.rs                    # Scanner registry and metadata
│   │   ├── parameter_prioritizer.rs       # Risk scoring for parameters
│   │   ├── parameter_filter.rs            # Filter parameters before testing
│   │   ├── attack_surface.rs              # Deduplication and attack surface analysis
│   │   │
│   │   ├── [individual scanners]
│   │   │   ├── xss.rs                     # XSS detection (multiple variants)
│   │   │   ├── hybrid_xss/                # Browser-less XSS detection
│   │   │   ├── proof_xss_scanner.rs       # Proof-based XSS (2-3 requests, no Chrome)
│   │   │   ├── reflection_xss_scanner.rs  # Reflected XSS variants
│   │   │   ├── sqli_enhanced.rs           # Advanced SQL injection with taint analysis
│   │   │   ├── bola.rs                    # Broken Object Level Authorization
│   │   │   ├── csrf.rs                    # Cross-Site Request Forgery
│   │   │   ├── auth_bypass.rs             # Authentication bypass techniques
│   │   │   ├── auth_flow_tester.rs        # OAuth/SAML/OIDC flow testing
│   │   │   ├── ssrf.rs                    # Server-Side Request Forgery
│   │   │   ├── command_injection.rs       # OS command injection
│   │   │   ├── path_traversal.rs          # Directory traversal
│   │   │   ├── jwt.rs                     # JWT token vulnerabilities
│   │   │   ├── oauth.rs                   # OAuth-specific vulns
│   │   │   ├── mfa.rs                     # MFA bypass techniques
│   │   │   ├── file_upload.rs             # File upload vulnerabilities
│   │   │   ├── race_condition.rs          # Race condition detection
│   │   │   ├── timing_attacks.rs          # Timing-based side channel attacks
│   │   │   ├── [framework-specific]
│   │   │   │   ├── django_security.rs
│   │   │   │   ├── express_security.rs
│   │   │   │   ├── laravel_security.rs
│   │   │   │   ├── react_security.rs
│   │   │   │   ├── nextjs_security.rs
│   │   │   │   ├── spring_scanner.rs
│   │   │   │   ├── aspnet_scanner.rs
│   │   │   │   └── [etc...]
│   │   │   └── [specialized scanners]
│   │   │       ├── graphql_security.rs
│   │   │       ├── api_security.rs
│   │   │       ├── cloud_security_scanner.rs
│   │   │       ├── container_scanner.rs
│   │   │       └── [etc...]
│   │   │
│   │   ├── external/                      # External tool integrations
│   │   └── internal/                      # Internal scanner helpers
│   │
│   ├── config/                            # Configuration management
│   │   ├── mod.rs                         # ConfigManager, exports
│   │   ├── core.rs                        # AppConfig, ScannerConfig, feature flags
│   │   ├── loader.rs                      # ConfigLoader, hot reload, multiple formats
│   │   ├── profiles.rs                    # Scan profiles, compliance frameworks
│   │   ├── targets.rs                     # Target config, auth, proxy, scope
│   │   ├── secrets.rs                     # SecretsManager, Vault, keyring, env vars
│   │   ├── plugins.rs                     # Plugin config and manager
│   │   └── validation.rs                  # ConfigValidator
│   │
│   ├── analysis/                          # Multi-layer analysis engine
│   │   ├── mod.rs                         # Module exports
│   │   ├── response_analyzer.rs           # Semantic response analysis, error detection
│   │   ├── attack_planner.rs              # Attack chain planning, prerequisite detection
│   │   ├── hypothesis_engine.rs           # Probabilistic inference, tech hypotheses
│   │   ├── correlation_engine.rs          # Vulnerability chain correlation
│   │   ├── intelligence_bus.rs            # Pub/sub for analysis findings
│   │   ├── tech_detection.rs              # Technology stack detection
│   │   ├── adaptive_rate_limiter.rs       # Per-domain adaptive rate limiting
│   │   └── [etc...]
│   │
│   ├── discovery/                         # Asset discovery modules
│   │   ├── mod.rs                         # Module exports
│   │   ├── subdomain_discovery.rs         # Subdomain enumeration
│   │   └── endpoint_discovery.rs          # Endpoint fingerprinting
│   │
│   ├── crawler.rs                         # Web crawler with URL prioritization
│   ├── headless_crawler.rs                # Headless Chrome for JS rendering
│   ├── http_client.rs                     # HTTP client wrapper, pooling, caching
│   ├── rate_limiter.rs                    # Token-bucket rate limiting
│   ├── circuit_breaker.rs                 # Circuit breaker for resilience
│   ├── adaptive_concurrency.rs            # Adaptive concurrency control
│   ├── retry.rs                           # Exponential backoff retry
│   │
│   ├── types.rs                           # Core types (ScanJob, ScanConfig, Vulnerability, etc.)
│   ├── errors.rs                          # Error types and propagation
│   ├── vulnerability.rs                   # VulnerabilityDetector helper
│   ├── validation/                        # Input validation utilities
│   │
│   ├── payloads.rs                        # Base payload definitions
│   ├── payloads_optimized.rs              # Optimized/filtered payload sets
│   ├── payloads_comprehensive.rs          # Comprehensive payload library
│   │
│   ├── detection_helpers.rs               # Tech detection utilities
│   ├── framework_detector.rs              # Framework-specific detection
│   ├── cdn_detector.rs                    # CDN detection
│   ├── dns_cache.rs                       # DNS resolution caching
│   ├── oob_detector.rs                    # Out-of-band channel detection
│   │
│   ├── auth_context.rs                    # Multi-auth management
│   ├── form_replay.rs                     # Form state tracking and replay
│   ├── session_recording.rs               # Session capture and replay
│   ├── state_tracker.rs                   # State-aware crawling
│   ├── multi_role.rs                      # Multi-role testing context
│   │
│   ├── engine/                            # Rule engine for decision making
│   │   ├── mod.rs                         # Module exports
│   │   └── rule_engine.rs                 # Rule evaluation engine
│   │
│   ├── reporting/                         # Result reporting and formatting
│   │   ├── mod.rs                         # Module exports
│   │   ├── engine.rs                      # Report generation engine
│   │   ├── deduplication.rs               # Result deduplication
│   │   ├── delivery.rs                    # Report delivery mechanisms
│   │   ├── mappings.rs                    # Result mapping (CVSS, CWE, etc.)
│   │   ├── templates.rs                   # Report templates
│   │   ├── formats/
│   │   │   ├── json.rs
│   │   │   ├── html.rs
│   │   │   ├── pdf.rs
│   │   │   ├── sarif.rs
│   │   │   ├── csv.rs
│   │   │   ├── xlsx.rs
│   │   │   └── markdown.rs
│   │   └── types.rs                       # Report data structures
│   │
│   ├── license/                           # License verification and enforcement
│   │   ├── mod.rs                         # License status check
│   │   ├── anti_tamper.rs                 # Tamper detection
│   │   └── scan_auth.rs                   # Scan authorization
│   │
│   ├── signing/                           # Quantum-safe signing for scan tokens
│   │   ├── mod.rs
│   │   └── [signing implementation]
│   │
│   ├── modules/                           # Module IDs for server-side authorization
│   │   └── ids.rs
│   │
│   ├── ml/                                # Machine learning and inference
│   │   ├── mod.rs                         # Module exports
│   │   ├── auto_learning.rs               # Automatic pattern learning
│   │   ├── fp_classifier.rs               # False positive classification
│   │   ├── federated.rs                   # Federated learning (privacy-preserving)
│   │   ├── features.rs                    # Feature extraction
│   │   ├── training_data.rs               # Training data management
│   │   ├── privacy.rs                     # Privacy-preserving mechanisms
│   │   └── integration.rs                 # ML integration with scanners
│   │
│   ├── inference/                         # Probabilistic inference engine
│   │   ├── mod.rs                         # Module exports
│   │   ├── bayesian.rs                    # Bayesian inference
│   │   ├── signals.rs                     # Signal patterns
│   │   └── channels.rs                    # Communication channels
│   │
│   ├── cloud/                             # Cloud security scanning
│   │   ├── mod.rs                         # Module exports
│   │   ├── error_handling.rs              # Cloud-specific errors
│   │   └── optimizations.rs               # Cloud-specific optimizations
│   │
│   ├── database.rs                        # PostgreSQL connection pooling
│   ├── queue.rs                           # Redis job queue
│   ├── subdomain_enum.rs                  # Subdomain enumeration
│   ├── request_batcher.rs                 # Batch request optimization
│   ├── graphql_introspection.rs           # GraphQL schema parsing
│   ├── metrics.rs                         # Metrics collection
│   │
│   ├── realtime/                          # Real-time scanning features
│   ├── retest/                            # Vulnerability retesting
│   ├── nuclei/                            # Nuclei template management
│   │   ├── custom_executor.rs             # Custom executor for Nuclei templates
│   │   └── [other integration code]
│   │
│   ├── registry/                          # Vulnerability and finding registry
│   └── [other support modules]
│
├── examples/                              # Example code and usage
├── Cargo.toml                             # Rust dependencies and metadata
├── Cargo.lock                             # Locked dependency versions
├── build.rs                               # Build script
├── README.md                              # Project documentation
├── SECURITY.md                            # Security guidelines
└── [config files]
    ├── .gitleaks.toml                     # Secret scanning config
    ├── .semgrep.yml                       # Semgrep SAST config
    ├── .trivyignore                       # Trivy CVE ignore list
    └── Cross.toml                         # Cross-compilation config
```

## Directory Purposes

**`src/`:**
- Purpose: All Rust source code
- Contains: 239 .rs files organized by functional domain
- Key files: lib.rs (public API), cli/main.rs (CLI entry), scanners/mod.rs (orchestration)

**`src/scanners/`:**
- Purpose: 94+ vulnerability scanner implementations organized by type
- Contains: Individual scanner modules for each vulnerability class and tech stack
- Key files: mod.rs (registry), intelligent_orchestrator.rs (context-aware planning), registry.rs (metadata)

**`src/config/`:**
- Purpose: Configuration management, secrets, profiles, targets
- Contains: Config loading, hot reload, multi-backend secrets (Vault, keyring, env), scan profiles
- Key files: core.rs (AppConfig), loader.rs (ConfigLoader), validation.rs (ConfigValidator)

**`src/analysis/`:**
- Purpose: Multi-layer analysis and intelligence
- Contains: Response semantic analysis, attack planning, probabilistic inference, tech detection
- Key files: response_analyzer.rs, attack_planner.rs, hypothesis_engine.rs, intelligence_bus.rs

**`src/discovery/`:**
- Purpose: Asset enumeration (subdomains, endpoints)
- Contains: Subdomain discovery, endpoint fingerprinting
- Key files: subdomain_discovery.rs, endpoint_discovery.rs

**`src/reporting/`:**
- Purpose: Result formatting and delivery
- Contains: Multiple output formats (JSON, HTML, PDF, SARIF, CSV, XLSX, Markdown)
- Key files: engine.rs (generation), formats/ (individual format handlers)

**`src/license/`:**
- Purpose: License validation and scan authorization
- Contains: License status checking, anti-tampering, scan token generation
- Key files: mod.rs, anti_tamper.rs, scan_auth.rs

**`src/ml/`:**
- Purpose: Machine learning for pattern recognition and false positive reduction
- Contains: Auto-learning, false positive classification, federated learning
- Key files: fp_classifier.rs, federated.rs, features.rs

## Key File Locations

**Entry Points:**
- `src/cli/main.rs`: CLI binary with Clap argument parsing, main scan orchestration
- `src/lib.rs`: Library root exposing scanner modules for external use
- `src/scanners/mod.rs`: Scanner module registry orchestration

**Configuration:**
- `src/config/core.rs`: AppConfig and ScannerConfig structures
- `src/config/loader.rs`: ConfigLoader for TOML/YAML/JSON formats
- `src/config/validation.rs`: ConfigValidator for configuration validation

**Core Logic:**
- `src/types.rs`: ScanJob, ScanConfig, Vulnerability, ScanResults, ScanMode, Severity
- `src/crawler.rs`: WebCrawler with URL prioritization
- `src/http_client.rs`: HttpClient with caching, rate limiting, circuit breaking
- `src/scanners/intelligent_orchestrator.rs`: Context-aware scan planning
- `src/scanners/registry.rs`: Scanner metadata and selection logic

**Analysis:**
- `src/analysis/response_analyzer.rs`: Semantic response analysis
- `src/analysis/attack_planner.rs`: Attack chain planning
- `src/analysis/hypothesis_engine.rs`: Probabilistic inference
- `src/analysis/tech_detection.rs`: Technology stack detection

**Testing & Validation:**
- `src/validation/`: Input validation utilities
- `src/errors.rs`: Error types (ScannerError, NetworkError, HttpError, etc.)

## Naming Conventions

**Files:**
- Module files: `snake_case.rs` (e.g., `http_client.rs`, `attack_planner.rs`)
- Scanner files: vulnerability name in snake_case (e.g., `sqli_enhanced.rs`, `auth_bypass.rs`)
- Test files: suffixed `_test.rs` or in tests/ directory (not observed; project uses integration-focused approach)

**Directories:**
- Domain grouping: snake_case (e.g., `src/analysis/`, `src/reporting/`, `src/discovery/`)
- Related modules grouped in directories with mod.rs exports

**Functions:**
- Module functions: snake_case (e.g., `fn scan_target()`, `fn detect_technology()`)
- Builder patterns used for complex construction

**Types:**
- Structs: PascalCase (e.g., `HttpClient`, `IntelligentScanPlan`, `ResponseAnalyzer`)
- Enums: PascalCase (e.g., `ScanMode`, `Severity`, `TechCategory`)
- Traits: PascalCase (e.g., derived from serde::Serialize)

**Constants & Statics:**
- SCREAMING_SNAKE_CASE (e.g., `MAX_BODY_SIZE`, `BROWSER_USER_AGENTS`, `DEFAULT_POOL_IDLE_PER_HOST`)

## Where to Add New Code

**New Vulnerability Scanner:**
1. Create `src/scanners/{vulnerability_name}.rs`
2. Implement scanner with async scan function signature: `async fn scan() -> Vec<Vulnerability>`
3. Register scanner in `src/scanners/mod.rs` (pub mod {vulnerability_name})
4. Add metadata entry in `src/scanners/registry.rs` (ScannerRegistry::new())
5. Add payloads to `src/payloads*.rs` if not using existing payloads

**New Framework-Specific Scanner:**
1. Create `src/scanners/{framework_name}_security.rs` (or appropriate name)
2. Implement detection for framework-specific indicators
3. Register in `src/scanners/mod.rs` and `src/scanners/registry.rs`
4. Add TechCategory mapping in `src/scanners/registry.rs` to auto-select when tech detected

**New Analysis Module:**
1. Create `src/analysis/{feature_name}.rs`
2. Implement analysis logic (e.g., correlation, inference, detection)
3. Export from `src/analysis/mod.rs`
4. Wire into analysis flow via IntelligenceBus or ResponseAnalyzer

**New Output Format:**
1. Create `src/reporting/formats/{format_name}.rs`
2. Implement formatter implementing report trait
3. Register in `src/reporting/engine.rs`
4. Add format variant to CLI OutputFormat enum in `src/cli/main.rs`

**New Configuration Category:**
1. Create `src/config/{category}.rs` if domain-specific
2. Add to ConfigManager in `src/config/mod.rs`
3. Export from `src/config/mod.rs` re-exports section
4. Add validation in `src/config/validation.rs`

**Utilities & Helpers:**
- Shared detection utilities: `src/detection_helpers.rs`
- Tech-specific detection: `src/framework_detector.rs`, `src/cdn_detector.rs`
- DNS helpers: `src/dns_cache.rs`
- OOB helpers: `src/oob_detector.rs`
- Generic validation: `src/validation/` subdirectory

## Special Directories

**`src/scanners/hybrid_xss/`:**
- Purpose: Browser-less XSS detection module using hybrid approach
- Generated: No (committed source)
- Committed: Yes
- Contains: XSS detection implementations that don't require headless Chrome

**`src/scanners/external/`:**
- Purpose: External tool integrations (Nuclei, etc.)
- Generated: No (committed source)
- Committed: Yes

**`src/scanners/internal/`:**
- Purpose: Internal helper modules and shared scanner logic
- Generated: No (committed source)
- Committed: Yes

**`target/`:**
- Purpose: Build artifacts and compiled binaries
- Generated: Yes (from cargo build)
- Committed: No (in .gitignore)

**`.planning/codebase/`:**
- Purpose: GSD codebase analysis documents
- Generated: Yes (this analysis)
- Committed: No (documentation only)

**`.github/`:**
- Purpose: GitHub Actions CI/CD workflows
- Contains: Build, test, and release workflows
- Committed: Yes

## Import Organization Pattern

Based on observed patterns in `src/lib.rs` and module files:

1. **External crate imports** (third-party dependencies)
   ```rust
   use tokio;
   use anyhow::Result;
   use tracing::{debug, info};
   ```

2. **Internal module imports** (absolute paths via crate::)
   ```rust
   use crate::http_client::HttpClient;
   use crate::scanners::ScanEngine;
   use crate::types::{Vulnerability, ScanJob};
   ```

3. **Relative imports** (within same directory)
   ```rust
   mod payload_cache;
   use payload_cache::PayloadCache;
   ```

4. **Re-exports in mod.rs**
   ```rust
   pub use response_analyzer::ResponseAnalyzer;
   pub use attack_planner::AttackPlanner;
   ```

---

*Structure analysis: 2026-01-30*
