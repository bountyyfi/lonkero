<div align="center">

<img src="https://bountyyfi.s3.eu-north-1.amazonaws.com/lonkero.png" alt="Lonkero Logo" width="200"/>

### Wraps around your attack surface

Professional-grade scanner for real penetration testing. Fast. Modular. Rust.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-green.svg)](https://github.com/bountyyfi/lonkero)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/bountyyfi/lonkero)
[![Coverage](https://img.shields.io/badge/coverage-95%25-success.svg)](https://github.com/bountyyfi/lonkero)

**97+ Advanced Scanners** | **Intelligent Mode** | **Tech-Aware Routing** | **5% False Positives**

**[Official Website](https://lonkero.bountyy.fi/en)** | [Features](#core-capabilities) · [Installation](#installation) · [Quick Start](#quick-start) · [Architecture](#architecture)

---

</div>

## What is Lonkero?

Lonkero is a production-grade web security scanner designed for professional security testing:

- **v3.0 Intelligent Mode** - Context-aware scanning with tech detection, endpoint deduplication, and per-parameter risk scoring
- Near-zero false positives (5% vs industry 20-30%)
- Intelligent testing - Skips framework internals, focuses on real vulnerabilities
- Modern stack coverage - Next.js, React, GraphQL, gRPC, WebSocket, HTTP/3
- 80% faster scans - Smart parameter filtering eliminates noise
- Advanced blind vulnerability detection techniques
- **When tech detection fails, we run MORE tests, not fewer** - fallback layer with 35+ scanners

Unlike generic scanners that spam thousands of useless payloads, Lonkero uses context-aware filtering to test only what matters.

---

## Core Capabilities

### v3.0 Intelligent Scanning Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: Universal Scanners (always run)                       │
│  CORS, Headers, SSL, OpenRedirect, HttpSmuggling, HostHeader    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: Core Scanners (always run)                            │
│  XSS, SQLi, SSRF, CommandInjection, PathTraversal, IDOR, JWT    │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: Tech-Specific (when detected)                         │
│  NextJs, React, Django, Laravel, Express, WordPress...          │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 4: Fallback (when tech=Unknown → MORE tests)             │
│  35+ scanners: NoSQLi, XXE, Deserial, Log4j, Merlin, Cognito... │
└─────────────────────────────────────────────────────────────────┘
```

**Key insight**: When technology detection fails, the fallback layer runs MORE comprehensive tests to ensure nothing is missed.

### 97+ Security Scanners

| Category | Scanners | Focus Areas |
|----------|----------|-------------|
| **Injection** | 28 scanners | SQLi, XSS, XXE, NoSQL, Command, LDAP, XPath, SSRF, Template, Prototype Pollution, Host Header, Log4j/JNDI |
| **Authentication** | 20 scanners | JWT, OAuth, SAML, MFA, Session, Auth Bypass, IDOR, BOLA, Privilege Escalation, Cognito Enum, Client Route Bypass |
| **API Security** | 15 scanners | GraphQL (advanced), gRPC, REST, WebSocket, Rate Limiting, CORS, HTTP/3, Azure APIM |
| **Frameworks** | 12 scanners | Next.js (route discovery), React, Django, Laravel, WordPress, Drupal, Express, SvelteKit |
| **Configuration** | 14 scanners | Headers, SSL/TLS, Cloud, Containers, WAF Bypass, CSRF, DNS Security |
| **Business Logic** | 7 scanners | Race Conditions, Payment Bypass, Workflow Manipulation, Mass Assignment (advanced) |
| **Info Disclosure** | 11 scanners | Sensitive Data, Debug Leaks, Source Code, JS Secrets, Source Maps, Favicon Hash, HTML Injection |
| **Specialized** | 8 scanners | CVE Detection, Version Mapping, ReDoS, Google Dorking, Attack Surface Enum |

### Smart Scanning Features

- **Parameter Filtering** - Skips framework internals, prioritizes user input (80% faster scans)
- **Blind Detection** - Time-based, error-based, boolean-based techniques
- **Context-Aware** - Adapts testing based on detected technology stack
- **SPA Detection** - Identifies React/Vue/Angular apps, handles soft-404 pages, discovers real API endpoints
- **Route Discovery** - Automatically extracts routes from JavaScript bundles (Next.js App Router)
- **Headless Browser** - Network interception, multi-stage form detection, authenticated crawling

### Enterprise Integration

- **Compliance** - OWASP Top 10 2025, PCI DSS, GDPR, NIS2, DORA
- **CI/CD** - GitHub Actions, GitLab SAST, SARIF output
- **Reporting** - PDF, HTML, JSON, XLSX, CSV, SARIF, Markdown formats with detailed remediation

---

## Architecture

### Scanning Pipeline

```
                              Target URL
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 0: Reconnaissance                                        │
│  Tech Detection, Endpoint Discovery, JS Mining                  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Smart Filter (Context-Aware)                                   │
│  Skip: Framework internals, CSRF tokens, session IDs            │
│  Test: User inputs, API parameters, form fields                 │
└─────────────────────────────────────────────────────────────────┘
                                  │
    ┌─────────────────────────────┼─────────────────────────────┐
    │                             │                             │
    ▼                             ▼                             ▼
 Phase 1-3                    Phase 4-5                    Phase 6-8
 Injection                    Business                     Framework
 Authentication               API Security                 Configuration
 Authorization                                             Info Disclosure
    │                             │                             │
    └─────────────────────────────┼─────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  Report Generation (JSON, HTML, PDF, SARIF, CSV, XLSX, MD)      │
└─────────────────────────────────────────────────────────────────┘
```

All scanners are **context-aware** - they adapt testing based on detected technology stack.

---

## Context-Aware Filtering

Lonkero automatically skips untestable elements (framework state, CSRF tokens, language selectors) and prioritizes high-value injection points.

| Metric | Traditional | Lonkero |
|--------|-------------|---------|
| Parameters tested | 100 | 20 |
| Requests sent | 2,800 | 560 |
| Scan time | 28s | 6s |
| False positives | 15 | 1 |

---

## Blind Vulnerability Detection

Lonkero uses advanced techniques to detect blind vulnerabilities without relying on visible output:

### Time-Based Detection
- **Blind SQLi** - Binary search algorithm (5-7 requests vs 100+)
- **Command Injection** - Sleep/timeout analysis with statistical verification
- **XXE** - Response timing pattern analysis

### Error-Based Detection
- **SQL Injection** - Database error pattern matching
- **Path Traversal** - File inclusion error signatures
- **Template Injection** - Engine-specific error messages

### Boolean-Based Detection
- **Authentication Bypass** - Response differential analysis
- **Logic Flaws** - State change verification
- **IDOR** - Access control boundary testing

---

## SPA Detection & Soft-404 Handling

Lonkero v3.0 includes advanced Single Page Application (SPA) detection to eliminate false positives on modern JavaScript frameworks:

### Problem
SPAs (React, Vue, Angular, Next.js) return HTTP 200 for all routes, even non-existent ones. Traditional scanners report false positives because they see "successful" responses.

### Solution
Lonkero detects SPA signatures and handles soft-404s intelligently:

```
┌─────────────────────────────────────────────────────────────────┐
│  SPA Detection Signatures                                        │
├─────────────────────────────────────────────────────────────────┤
│  • <app-root> (Angular)                                          │
│  • <div id="root"> (React)                                       │
│  • __NEXT_DATA__ (Next.js)                                       │
│  • __NUXT__ (Nuxt.js)                                            │
│  • ng-version= (Angular)                                         │
│  • polyfills.js pattern                                          │
│  • /_next/static/ pattern                                        │
└─────────────────────────────────────────────────────────────────┘
```

### Headless Browser Features
- **Network Interception** - Captures actual API endpoints from JavaScript
- **Multi-Stage Forms** - Detects forms that appear after initial form submission
- **Authenticated Crawling** - Injects tokens into localStorage for auth-required SPAs
- **Route Discovery** - Extracts routes from JavaScript bundles

---

## Next.js Route Discovery

Lonkero automatically discovers Next.js App Router routes from JavaScript bundles:

### How It Works
1. **Script Analysis** - Fetches all `_next/static/chunks/*.js` files
2. **Pattern Extraction** - Finds route patterns like `/app/[path]/(page|layout)`
3. **Dynamic Segments** - Expands `[param]` with test values (`[lng]` → `en`, `de`, `fr`)
4. **Security Testing** - Tests discovered routes for middleware bypass vulnerabilities

### Discovered Route Testing
```
┌─────────────────────────────────────────────────────────────────┐
│  Route Discovery → Middleware Bypass Testing                     │
├─────────────────────────────────────────────────────────────────┤
│  1. Extract routes from JS bundles                               │
│  2. Filter protected routes (admin, dashboard, settings, etc.)   │
│  3. Expand dynamic segments [lng], [id], [slug]                  │
│  4. Test with x-middleware-subrequest header                     │
│  5. Report CVE-2025-29927 if bypass successful                   │
└─────────────────────────────────────────────────────────────────┘
```

### Patterns Detected
- App Router: `/app/dashboard/[id]/page` → `/dashboard/1`
- Route Groups: `/app/(auth)/login/page` → `/login`
- Catch-all: `/app/[...slug]/page` → `/test/page`
- Optional: `/app/[[...slug]]/page` → `/` or `/test`

---

## AWS Cognito Enumeration

Lonkero detects AWS Cognito user pools and tests for user enumeration vulnerabilities:

### Detection Methods
1. **JavaScript Analysis** - Extracts `userPoolId`, `clientId` from app bundles
2. **CSP Header Analysis** - Detects `cognito-idp.{region}.amazonaws.com` in Content-Security-Policy
3. **OAuth Redirect URLs** - Captures Cognito URLs from authentication redirects

### Enumeration Techniques
| API | Technique | Detection |
|-----|-----------|-----------|
| `ForgotPassword` | Response timing + CodeDeliveryDetails | User exists if delivery details returned |
| `SignUp` | Error message analysis | "User already exists" vs "Invalid parameter" |
| `InitiateAuth` | Error differentiation | "User not found" vs "Incorrect password" |

### Example Finding
```json
{
  "type": "AWS Cognito User Enumeration",
  "severity": "Medium",
  "evidence": "ForgotPassword returns CodeDeliveryDetails for existing users",
  "remediation": "Enable advanced security features in Cognito"
}
```

---

## GraphQL Advanced Security Testing

Lonkero includes comprehensive GraphQL security testing beyond basic introspection:

### Attack Techniques

| Attack | Description | Impact |
|--------|-------------|--------|
| **Introspection Abuse** | Extract full schema including hidden types | Information disclosure |
| **Alias Abuse** | Multiply queries using aliases for DoS | Resource exhaustion |
| **Batching DoS** | Send multiple operations in single request | API rate limit bypass |
| **Cost Analysis** | Exploit expensive resolvers | DoS via computation |
| **Persisted Queries** | Manipulate query hashes | Cache poisoning |
| **Directive Abuse** | Exploit custom directives | Authorization bypass |
| **Fragment Spreading** | Deep nesting via fragments | Stack overflow |
| **Subscription Vulns** | Abuse real-time subscriptions | Data leakage |
| **Authorization Bypass** | Query manipulation for access | Privilege escalation |

### Example Alias Abuse Attack
```graphql
query {
  a1: expensiveQuery { data }
  a2: expensiveQuery { data }
  a3: expensiveQuery { data }
  # ... 100 aliases = 100x server load
}
```

---

## Installation

### From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/bountyyfi/lonkero.git
cd lonkero

# Build release binary
cargo build --release

# Install
sudo cp target/release/lonkero /usr/local/bin/
```

### Prerequisites

- Rust 1.75+
- OpenSSL development libraries
- Valid license key (for premium features)

---

## Quick Start

### Basic Scan (v3.0 Intelligent Mode)

```bash
# Scan single URL - Intelligent mode is default, no --mode needed
lonkero scan https://example.com

# With crawling enabled for better endpoint discovery
lonkero scan https://example.com --crawl

# Output to JSON
lonkero scan https://example.com --format json -o report.json

# Output to PDF report
lonkero scan https://example.com --format pdf -o report.pdf
```

### Advanced Usage

```bash
# Scan with authentication (cookie)
lonkero scan https://example.com --cookie "session=abc123"

# Scan with custom headers
lonkero scan https://example.com --header "Authorization: Bearer token"

# Auto-login with credentials
lonkero scan https://example.com --auth-username admin --auth-password secret123
lonkero scan https://example.com --auth-username admin --auth-password secret123 --auth-login-url https://example.com/login

# Enable subdomain enumeration
lonkero scan https://example.com --subdomains

# CI/CD integration (SARIF output)
lonkero scan https://example.com --format sarif -o results.sarif

# Google dorking reconnaissance
lonkero scan https://example.com --dorks

# Run specific modules only
lonkero scan https://example.com --only sqli_enhanced,xss_enhanced,ssrf

# Skip specific modules
lonkero scan https://example.com --skip wordpress,drupal

# Control crawl depth (default: 3)
lonkero scan https://example.com --crawl --max-depth 5

# Disable rate limiting (use with caution)
lonkero scan https://example.com --no-rate-limit
```

### Configuration File

```yaml
# lonkero.yml
target: https://example.com
modules:
  - sqli_enhanced
  - xss_enhanced
  - xxe
  - ssrf
  - graphql_security
concurrency: 10
timeout: 30
headers:
  Authorization: Bearer token123
  X-API-Key: secret
output:
  format: json
  file: report.json
```

```bash
lonkero scan --config lonkero.yml
```

---

## Scanner Categories

### Authentication & Authorization (20 scanners)

- **JWT** - Algorithm confusion, weak secrets, None algorithm, key injection
- **OAuth 2.0** - Token theft, redirect manipulation, PKCE bypass, scope abuse
- **SAML** - Assertion bypass, signature wrapping, XML injection
- **MFA** - Bypass techniques, replay attacks, race conditions
- **Session Management** - Fixation, hijacking, prediction
- **Auth Bypass** - Parameter tampering, header injection, credential stuffing
- **IDOR** - Object reference manipulation, baseline detection
- **Privilege Escalation** - Horizontal and vertical privilege abuse
- **Client Route Auth Bypass** - SPA authentication bypass via client-side routing manipulation
- **Advanced Auth** - Complex authentication flow exploitation
- **Password Reset** - Token prediction, account takeover
- **WebAuthn** - Biometric authentication bypass
- **BOLA** - Broken object level authorization (API-specific IDOR with advanced baseline)
- **Cognito Enumeration** - AWS Cognito user pool enumeration via ForgotPassword, SignUp, InitiateAuth APIs with CSP header detection

### Injection Vulnerabilities (27 scanners)

- **SQL Injection** - Enhanced detection, blind (boolean/time/binary search), second-order
- **XSS** - Enhanced detection, DOM-based, mutation XSS, SVG-based, stored/reflected
- **XXE** - XML external entity, billion laughs, parameter entity
- **NoSQL Injection** - MongoDB, CouchDB, operator injection
- **Command Injection** - OS command execution, blind detection
- **LDAP Injection** - Directory service attacks
- **XPath Injection** - XML query manipulation
- **Template Injection** - SSTI (Jinja, Twig, Freemarker, Velocity, etc.)
- **SSRF** - Enhanced detection, blind SSRF, cloud metadata exploitation
- **Code Injection** - Dynamic code evaluation
- **CRLF Injection** - HTTP response splitting
- **Email Header Injection** - SMTP header manipulation
- **Host Header Injection** - Cache poisoning, password reset poisoning
- **XML Injection** - XML structure manipulation
- **SSI Injection** - Server-side includes
- **Prototype Pollution** - JavaScript object pollution
- **HTML Injection** - Non-XSS markup injection
- **HTTP Parameter Pollution** - HPP attacks
- **Deserialization** - Unsafe object deserialization

### API Security (15 scanners)

- **GraphQL Advanced** - Introspection, batching DoS, cost analysis, alias abuse, persisted queries, directive abuse, subscription vulnerabilities, fragment spreading, authorization bypass
- **gRPC** - Reflection, enumeration, metadata abuse
- **REST** - Mass assignment, API fuzzing, parameter pollution
- **WebSocket** - Message injection, protocol abuse
- **API Gateway** - Azure APIM cross-tenant bypass, generic gateway vulnerabilities
- **API Security** - Comprehensive API testing
- **Rate Limiting** - Bypass techniques
- **CORS** - Misconfiguration detection
- **Cache Poisoning** - Web cache deception
- **HTTP/3** - QUIC-specific vulnerabilities
- **HTTP Smuggling** - Request smuggling attacks

### Modern Framework Scanners (12 scanners)

- **Next.js** - Route discovery from JS bundles, middleware bypass (CVE-2024-34351, CVE-2025-29927), `_next/data` exposure, server actions, image SSRF, ISR token exposure
- **React** - DevTools exposure, hydration issues, client-side vulnerabilities
- **SvelteKit** - CSRF bypass, SSR vulnerabilities
- **Django** - DEBUG mode, ORM injection, middleware bypass
- **Laravel** - Ignition RCE, route enumeration, mass assignment
- **Express.js** - Middleware vulnerabilities, prototype pollution
- **WordPress** - Plugin vulnerabilities, XML-RPC, REST API abuse
- **Drupal** - Core vulnerabilities, module security
- **Liferay** - Portal-specific vulnerabilities
- **Tomcat** - Misconfiguration, default credentials
- **Varnish** - Cache misconfiguration
- **Angular** - Client-side template injection, router bypass

### Configuration & Security (13 scanners)

- **Security Headers** - HSTS, CSP, X-Frame-Options, referrer policy
- **CORS Misconfiguration** - Wildcard origins, credential exposure
- **SSL/TLS** - Weak ciphers, certificate validation
- **Cloud Security** - AWS, Azure, GCP misconfiguration
- **Cloud Storage** - S3 buckets, Azure blobs, GCS exposure
- **Firebase** - Database exposure, misconfiguration
- **Container Security** - Docker, Kubernetes vulnerabilities
- **WAF Bypass** - Web application firewall evasion
- **Clickjacking** - Frame injection, UI redressing
- **CSRF** - Cross-site request forgery

### Business Logic (7 scanners)

- **Business Logic** - Advanced workflow exploitation
- **Race Conditions** - TOCTOU, parallel request abuse, timing analysis
- **Payment Manipulation** - Price tampering, discount abuse
- **Workflow Bypass** - Multi-step form manipulation
- **File Upload Advanced** - Polyglot files (PNG+PHP, JPEG+JSP), SVG XSS/XXE/SSRF, ZIP bomb, zip slip, null byte bypass, double extension
- **Mass Assignment Advanced** - Nested object injection, dot notation, JSON deep merge, prototype pollution vectors, array parameter pollution
- **IDOR Analyzer** - Advanced object reference testing with baseline detection

### Information Disclosure (11 scanners)

- **Information Disclosure** - Sensitive data exposure
- **Sensitive Data** - PII, credentials, API keys
- **Debug Information** - Stack traces, verbose errors
- **Source Code** - Git exposure, backup files, `.env` files
- **JS Miner** - JavaScript secret extraction (AWS keys, API tokens, private keys)
- **JS Sensitive Info** - Client-side data leakage
- **Session Analyzer** - Session token analysis
- **Baseline Detector** - Deviation detection
- **Source Map Detection** - Exposed JavaScript source maps revealing original source code
- **Favicon Hash Detection** - Technology fingerprinting via favicon hash (Shodan-compatible)
- **HTML Injection** - Non-XSS markup injection for phishing and SEO poisoning

### Specialized Scanners (9 scanners)

- **CVE Detection** - Known vulnerability scanners (CVE-2025-55182, CVE-2025-55183, CVE-2025-55184)
- **Framework Vulnerabilities** - Generic framework CVEs with version detection
- **Merlin** - JavaScript library version detection and vulnerability mapping
- **Log4j/JNDI** - Log4Shell and JNDI injection detection
- **ReDoS** - Regular expression denial of service
- **Google Dorking** - Search engine reconnaissance (use `--dorks` flag)
- **Endpoint Discovery** - Multilingual path brute-force (Finnish, Swedish, German, French, Spanish, etc.)
- **Attack Surface Enum** - Comprehensive attack surface enumeration
- **DNS Security** - DNS configuration and zone transfer testing

---

## Premium Features

### Professional Tier

Advanced detection techniques requiring license authentication:

1. **sqli_blind_advanced** - Binary search blind SQLi (5-7 requests vs 100+)
2. **xss_dom_advanced** - Headless browser DOM XSS detection
3. **xss_svg_advanced** - SVG-based XSS polyglots
4. **path_traversal_advanced** - Unicode normalization bypasses
5. **business_logic_advanced** - Multi-step workflow exploitation
6. **file_upload_polyglot** - Magic byte manipulation (PNG+PHP, JPEG+JSP)
7. **html_injection** - Non-XSS markup injection (phishing, SEO poisoning)
8. **ssrf_cloud_metadata** - AWS/Azure/GCP metadata exploitation
9. **ssrf_protocol_smuggling** - gopher://, dict://, file:// protocol abuse
10. **websocket_injection** - Message tampering & injection
11. **graphql_batching_attacks** - Query batching DoS
12. **graphql_cost_analysis** - Query complexity exploitation
13. **smart_parameter_filtering** - AI-powered noise reduction

### Enterprise Tier (Coming Soon)

High-value features for critical infrastructure:

14. **oob_detection** - Out-of-band vulnerability detection infrastructure (Coming Soon)
15. **oob_dns_exfiltration** - DNS-based blind vulnerability verification (Coming Soon)
16. **oob_http_callbacks** - HTTP callback verification for blind attacks (Coming Soon)

---

## Compliance Mapping

### OWASP Top 10 2025

| OWASP Category | Lonkero Scanners |
|----------------|------------------|
| A01: Broken Access Control | IDOR, privilege escalation, client route bypass |
| A02: Cryptographic Failures | JWT weak secrets, SSL/TLS misconfig |
| A03: Injection | SQLi, XSS, XXE, NoSQL, CMD, LDAP, XPath, SSTI |
| A04: Insecure Design | Business logic, race conditions, workflow bypass |
| A05: Security Misconfiguration | Headers, CORS, debug mode, CDN bypass |
| A06: Vulnerable Components | Framework scanners (Next.js, Laravel, Django) |
| A07: Auth Failures | JWT, OAuth, SAML, MFA, session fixation |
| A08: Data Integrity Failures | File upload, cache poisoning, mass assignment |
| A09: Security Logging Failures | Information disclosure scanner |
| A10: SSRF | SSRF scanner with cloud metadata checks |

### PCI DSS 4.0

- Requirement 6.5.1: Injection flaws (SQLi, XSS, XXE)
- Requirement 6.5.3: Insecure cryptographic storage (JWT scanner)
- Requirement 6.5.4: Insecure communications (SSL/TLS scanner)
- Requirement 6.5.8: Improper access control (IDOR, privilege escalation)
- Requirement 6.5.10: Broken authentication (JWT, OAuth, SAML)

### GDPR / NIS2 / DORA

- Data exposure detection (sensitive data scanner)
- Encryption validation (SSL/TLS, JWT)
- Access control verification (IDOR, authorization bypass)
- Logging & monitoring (information disclosure)

---

## CI/CD Integration

### v3.0 - No Mode Selection Required

Lonkero v3.0 uses **Intelligent Mode by default** - no need to specify `--mode`. The scanner automatically:
- Detects technology stack
- Deduplicates endpoints and parameters
- Scores parameters by risk
- Selects appropriate scanners per-target
- Runs fallback scanners when tech is unknown

Legacy modes (`--mode fast/normal/thorough/insane`) are still available for backwards compatibility.

### GitHub Actions

```yaml
name: Lonkero Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: dtolnay/rust-action@stable

      - name: Clone and Build Lonkero
        run: |
          git clone https://github.com/bountyyfi/lonkero.git /tmp/lonkero
          cd /tmp/lonkero
          cargo build --release
          sudo cp target/release/lonkero /usr/local/bin/

      - name: Run Lonkero Scan
        env:
          LONKERO_LICENSE: ${{ secrets.LONKERO_LICENSE }}
        run: |
          # v3.0: Intelligent mode is default - no --mode needed
          lonkero scan https://staging.example.com \
            --format sarif \
            -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
lonkero-scan:
  stage: security
  image: rust:1.75
  variables:
    LONKERO_LICENSE: $LONKERO_LICENSE_KEY
  script:
    - git clone https://github.com/bountyyfi/lonkero.git /tmp/lonkero
    - cd /tmp/lonkero && cargo build --release
    # v3.0: Intelligent mode is default
    - /tmp/lonkero/target/release/lonkero scan $CI_ENVIRONMENT_URL --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Legacy Mode (Optional)

If you need the old behavior for specific use cases:

```bash
# Use legacy modes when needed
lonkero scan https://example.com --mode fast      # 50 payloads globally
lonkero scan https://example.com --mode normal    # 500 payloads globally
lonkero scan https://example.com --mode thorough  # 5000 payloads globally
lonkero scan https://example.com --mode insane    # All payloads
```

---

## Output Formats

### JSON

```json
{
  "scan_id": "scan_abc123",
  "target": "https://example.com",
  "start_time": "2025-01-15T10:00:00Z",
  "vulnerabilities": [
    {
      "id": "sqli_abc123",
      "type": "SQL Injection (Blind)",
      "severity": "Critical",
      "confidence": "High",
      "url": "https://example.com/login",
      "parameter": "username",
      "payload": "admin' AND SLEEP(5)--",
      "cwe": "CWE-89",
      "cvss": 9.1,
      "remediation": "Use parameterized queries..."
    }
  ]
}
```

### PDF

Professional PDF reports with executive summary, severity-colored findings, and detailed remediation steps.

```bash
lonkero scan https://example.com -o report.pdf
```

### SARIF (GitHub Security Tab)

Compatible with GitHub Advanced Security for automated PR comments and security alerts.

### HTML

Interactive dark-themed report with filtering, sorting, and vulnerability details.

### XLSX / CSV

Spreadsheet exports for integration with ticketing systems and spreadsheet analysis.

### Markdown

Plain text reports for documentation and version control.

---

## Competitive Comparison

| Feature | Lonkero | Burp Suite Pro | OWASP ZAP | Acunetix |
|---------|---------|----------------|-----------|----------|
| **Price** | [See website](https://lonkero.bountyy.fi/en) | $449/year | Free | $4,500/year |
| **False Positive Rate** | 5% | 10-15% | 20-30% | 10-15% |
| **Modern Framework Support** | Next.js, React, GraphQL | Limited | Limited | Limited |
| **Smart Parameter Filtering** | Yes | No | No | No |
| **OOB Detection** | Coming Soon | Yes | No | Yes |
| **CI/CD Integration** | SARIF, JSON | Limited | JSON | Limited |
| **Blind SQLi Binary Search** | Yes | No | No | Yes |
| **GraphQL Security** | Yes | Extension | No | Limited |
| **WebSocket Testing** | Yes | Yes | Limited | Yes |
| **License Model** | API-based | Per-user | Free | Per-user |

---

## Support & Documentation

- **Official Website**: [lonkero.bountyy.fi](https://lonkero.bountyy.fi/en)
- **Documentation**: [github.com/bountyyfi/lonkero](https://github.com/bountyyfi/lonkero)
- **Issues**: [github.com/bountyyfi/lonkero/issues](https://github.com/bountyyfi/lonkero/issues)
- **Email**: [info@bountyy.fi](mailto:info@bountyy.fi)
- **Company**: [bountyy.fi](https://bountyy.fi)

---

## License

**Copyright © 2026 Bountyy Oy. All rights reserved.**

This software is proprietary. Commercial use requires a valid license.

For licensing inquiries, visit [lonkero.bountyy.fi](https://lonkero.bountyy.fi/en) or contact [info@bountyy.fi](mailto:info@bountyy.fi).

---

**Made in Finland** 🇫🇮
