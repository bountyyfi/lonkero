<div align="center">

<img src="https://bountyyfi.s3.eu-north-1.amazonaws.com/lonkero.png" alt="Lonkero Logo" width="200"/>

### Wraps around your attack surface

Professional-grade scanner for real penetration testing. Fast. Modular. Rust.

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.6.0-green.svg)](https://github.com/bountyyfi/lonkero)
[![Release](https://github.com/bountyyfi/lonkero/actions/workflows/release.yml/badge.svg)](https://github.com/bountyyfi/lonkero/actions/workflows/release.yml)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/bountyyfi/lonkero)
[![Coverage](https://img.shields.io/badge/coverage-95%25-success.svg)](https://github.com/bountyyfi/lonkero)

**125+ Advanced Scanners** | **Intelligent Mode** | **ML Auto-Learning** | **Scanner Intelligence** | **OOBZero Engine** | **5% False Positives**

**[Official Website](https://lonkero.bountyy.fi/en)** | [Features](#core-capabilities) · [Installation](#installation) · [Quick Start](#quick-start) · [ML Features](#machine-learning-features) · [Scanner Intelligence](#scanner-intelligence-system) · [Architecture](#architecture)

---

</div>

## What is Lonkero?

Lonkero is a production-grade web security scanner designed for professional security testing:

- **v3.0 Intelligent Mode** - Context-aware scanning with tech detection, endpoint deduplication, and per-parameter risk scoring
- **ML Auto-Learning** - Learns from every scan to reduce false positives over time (federated learning available)
- **Scanner Intelligence System** - Real-time scanner communication, Bayesian hypothesis testing, multi-step attack planning, and semantic response understanding
- Near-zero false positives (5% vs industry 20-30%)
- Intelligent testing - Skips framework internals, focuses on real vulnerabilities
- Modern stack coverage - Next.js, React, GraphQL, gRPC, WebSocket, HTTP/3
- 80% faster scans - Smart parameter filtering eliminates noise
- Advanced blind vulnerability detection techniques
- **When tech detection fails, we run MORE tests, not fewer** - fallback layer with 35+ scanners

Unlike generic scanners that spam thousands of useless payloads, Lonkero uses context-aware filtering to test only what matters.

---

## v3.6 New Features

### Proof-Based XSS Scanner (No Chrome Required)

Complete replacement of Chrome-based XSS detection with a mathematical proof-based approach:

**Zero Browser Dependencies**
- **No Chrome/Chromium required** - Pure HTTP analysis with context-aware detection
- **2-3 requests per parameter** - vs 100+ with browser-based scanning
- **300x faster** - ~200ms per URL vs 60+ seconds with Chrome
- **No freezes or hangs** - Eliminates browser stability issues

**Mathematical Proof of Exploitability**
- **16 reflection contexts detected** - HTML body, JS strings, attributes, event handlers, javascript: URLs, comments, CSS, etc.
- **Escape analysis** - Detects HTML entities, JS escapes, URL encoding, character stripping
- **Context + Escaping = Proof** - Mathematically proves if XSS is exploitable

**Detection Coverage**
| XSS Type | Accuracy |
|----------|----------|
| Reflected (HTML body) | 99% |
| Reflected (JS string) | 95% |
| Reflected (Attribute) | 99% |
| DOM XSS (static analysis) | 85% |
| Template Injection | 90% |

**How It Works**
```
REQUEST 1: Baseline
  GET /page?q=CANARY_abc123     → Find reflection points

REQUEST 2: Probe
  GET /page?q=CANARY_abc123"'<>/\`${}   → Test escaping behavior

ANALYSIS (Pure Computation):
  1. Context detection (HTML, JS, attribute, etc.)
  2. Escape behavior analysis (what gets filtered?)
  3. Exploitability proof (context + escaping = XSS?)
  4. Payload generation (working exploit for context)
```

### Parameter Filter Improvements

- **XSS filter expanded** - Now tests parameters ending in `id`, `count`, `weight`, etc. (these can be reflected in HTML)
- **Better false positive prevention** - Still skips CSRF tokens, pagination, and boolean flags where XSS is impossible

### Payload Intensity Control

New `--payload-intensity` flag allows control over how many payloads are tested per parameter:

```bash
# Auto mode (default) - uses intelligent per-parameter risk scoring
lonkero scan https://example.com

# Maximum intensity - test with all 12,450+ XSS payloads
lonkero scan https://example.com --payload-intensity maximum

# Quick scan with minimal payloads (50 per parameter)
lonkero scan https://example.com --payload-intensity minimal
```

**Intensity Levels:**
| Level | Payloads | Use Case |
|-------|----------|----------|
| `auto` | Risk-based | Default - intelligent mode decides per-parameter |
| `minimal` | 50 | Quick validation, CI/CD pipelines |
| `standard` | 500 | Balanced coverage vs speed |
| `extended` | 5,000 | Thorough testing |
| `maximum` | 12,450+ | Full payload library, maximum coverage |

In `auto` mode (default), the intelligent orchestrator assigns intensity based on parameter risk:
- High-risk params (`password`, `cmd`, `query`) → Extended/Maximum
- Medium-risk params (`search`, `name`, `email`) → Standard
- Low-risk params (`page`, `limit`, `sort`) → Minimal

---

## v3.2 New Features

### Zero OOB: Blind SQL Injection Without External Callbacks

Traditional blind SQLi needs out-of-band callbacks. Collaborator, Interactsh, custom DNS. Infrastructure to deploy and maintain.

There's another way.

Test SLEEP(0), SLEEP(1), SLEEP(2), SLEEP(5). Calculate Pearson correlation. If r > 0.95, that's not noise - that's the database responding to your commands.

Better yet: extract data. Binary search on ASCII values, 7 requests per character. When you pull "admin" out of the database byte by byte, that's not inference. That's proof.

Combine signals with Bayesian weighting. Timing, content length, quote oscillation, boolean differentials. Each channel is weak alone. Together, they converge on certainty.

Trade-off: more requests than a single OOB callback. But zero external dependencies.

**New detection techniques:**
- **Calibrated SLEEP Correlation** - Multi-value timing analysis with Pearson correlation (r > 0.95 = confirmed)
- **Boolean Data Extraction** - Extract actual database content character by character (proof, not inference)
- **True Single-Packet Attack** - Raw TCP/TLS socket control for microsecond precision timing
- **Quote Oscillation Detection** - Pattern matching on ', '', ''', '''' responses
- **HTTPS Support** - TLS stream handling for single-packet timing attacks

---

## v3.1 New Features

### Detection Improvements
- **Fixed Static/SPA Skip Logic** - Cloudflare Workers, Vercel Functions, and Netlify Functions are now properly tested (they're dynamic, not static)
- **Fixed Node.js Command Injection** - Removed incorrect assumption that Node.js can't execute shell commands (`child_process` exists)
- **SSRF POST Body Testing** - Now tests POST JSON and form-encoded bodies, not just query parameters
- **Enhanced Endpoint Discovery** - 244+ new endpoint patterns for API, admin, debug, and tool paths

### New Scanners
- **Second-Order Injection** - Stores payloads in one endpoint, detects execution in another (XSS, SQLi, CMDi)
- **Auth Flow Tester** - Session fixation, password reset IDOR, MFA bypass, predictable session tokens

### Enhanced Scanners
- **JWT** - Expanded weak secret wordlist (21 secrets), fixed `alg:none` token format
- **Race Conditions** - Registration, inventory, voting, and single-use token TOCTOU tests
- **WebSocket** - Active endpoint discovery, CSWSH testing with 9 origin bypasses
- **Information Disclosure** - Pattern-based content detection (won't skip even if 404s are identical)

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

### 125+ Security Scanners

| Category | Scanners | Focus Areas |
|----------|----------|-------------|
| **Injection** | 31 scanners | SQLi, XSS, DOM XSS, XXE, NoSQL, Command, LDAP, XPath, SSRF, Template, Prototype Pollution, Host Header, Log4j/JNDI, DOM Clobbering, **Second-Order Injection (v3.1)** |
| **Authentication** | 28 scanners | JWT, OAuth, OIDC, SAML, MFA, 2FA Bypass, Session, Auth Bypass, IDOR, BOLA, Account Takeover, Password Reset Poisoning, Timing Attacks, Cognito Enum, Client Route Bypass, **Auth Flow Tester (v3.1)** |
| **API Security** | 20 scanners | GraphQL (advanced), GraphQL Batching, gRPC, REST, WebSocket, Rate Limiting, CORS, HTTP/3, Azure APIM, BFLA, API Versioning, OpenAPI Analyzer |
| **Frameworks** | 15 scanners | Next.js (route discovery), React, Django, Laravel, WordPress, Drupal, Joomla, Express, SvelteKit, Ruby on Rails, Spring Boot |
| **Configuration** | 17 scanners | Headers, CSP Bypass, SSL/TLS, Cloud, Containers, WAF Bypass, CSRF, DNS Security, Web Cache Deception, PostMessage Vulns |
| **Business Logic** | 8 scanners | Race Conditions, Payment Bypass, Workflow Manipulation, Mass Assignment (advanced), Timing Attacks |
| **Info Disclosure** | 11 scanners | Sensitive Data, Debug Leaks, Source Code, JS Secrets, Source Maps, Favicon Hash, HTML Injection |
| **Specialized** | 9 scanners | CVE Detection, Version Mapping, ReDoS, Google Dorking, Attack Surface Enum, Subdomain Takeover |

### Smart Scanning Features

- **Parameter Filtering** - Skips framework internals, prioritizes user input (80% faster scans)
- **Blind Detection** - Time-based, error-based, boolean-based techniques
- **Context-Aware** - Adapts testing based on detected technology stack
- **ASN Blocklist** - Uses [bad-asn-list](https://github.com/bountyyfi/bad-asn-list) to identify VPN providers, datacenters, and hosting services commonly used for malicious traffic, scraping, and automated abuse
- **SPA Detection** - Identifies React/Vue/Angular apps, handles soft-404 pages, discovers real API endpoints
- **Route Discovery** - Automatically extracts routes from JavaScript bundles (Next.js App Router)
- **Headless Browser** - Network interception, WebSocket capture, multi-stage form detection, authenticated crawling
- **Smart Crawler** - Priority queue (high-value targets first), semantic URL deduplication, adaptive rate limiting
- **State-Aware Crawling** - Tracks cookies, localStorage, sessionStorage across requests; detects state dependencies and CSRF tokens
- **Multi-Role Testing** - Parallel crawling with different user roles to detect BOLA, BFLA, and privilege escalation vulnerabilities
- **Form Replay System** - Records and replays multi-step wizard forms with dynamic token handling for security testing
- **Session Recording** - Full session capture (HAR format) with network, DOM interactions, and screenshots for vulnerability reproduction

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

### OOBZero Engine (v3.2)

**Zero-infrastructure blind SQL injection detection** - detect blind SQLi WITHOUT callback servers.

Traditional OOB detection requires external callback infrastructure (Burp Collaborator, Interactsh, custom DNS). OOBZero uses **multi-channel Bayesian inference combined with deterministic confirmation** to achieve similar detection rates with zero infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│  OOBZero Engine - Statistical Inference + Deterministic Proof    │
├─────────────────────────────────────────────────────────────────┤
│  Inference Channels:                                             │
│  • BooleanDifferential: AND 1=1 vs AND 1=2 response differences │
│  • ArithmeticEval: 7-1 returning same as 6 (math evaluated)     │
│  • QuoteCancellation: value'' returning same as value           │
│  • Resonance: Quote oscillation pattern (', '', ''', '''')      │
│  • Timing/Length/Entropy: Statistical content analysis          │
├─────────────────────────────────────────────────────────────────┤
│  Confirmation Techniques (v3.2):                                 │
│  • CalibratedSleep: SLEEP(0,1,2,5) with Pearson r > 0.95        │
│  • DataExtraction: Binary search ASCII extraction (7 req/char)  │
│  • TrueSinglePacket: Raw TCP/TLS microsecond timing             │
├─────────────────────────────────────────────────────────────────┤
│  Key Innovations:                                                │
│  • Negative evidence SUBTRACTS from confidence (no false pos)   │
│  • Confirmation requires 2+ INDEPENDENT signal classes          │
│  • Data extraction = PROOF, not inference                       │
│  • Pearson correlation on timing = deterministic confirmation   │
└─────────────────────────────────────────────────────────────────┘
```

**Mathematical Foundation:**
```
L_posterior = L_prior + Σᵢ (wᵢ · cᵢ · logit(Sᵢ))
P_posterior = σ(L_posterior)
```
Where negative evidence has negative weights, reducing confidence.

**Calibrated SLEEP Correlation:**
```
SLEEP(0) → baseline
SLEEP(1) → +1000ms
SLEEP(2) → +2000ms
SLEEP(5) → +5000ms

Pearson r > 0.95 = confirmed SQLi (not statistical inference)
```

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

### Headless Browser Features (Crawling Only)
- **Network Interception** - Captures actual API endpoints from JavaScript
- **WebSocket Capture** - Intercepts WebSocket connections (ws://, wss://) for security testing
- **Multi-Stage Forms** - Detects forms that appear after initial form submission
- **Authenticated Crawling** - Injects tokens into localStorage for auth-required SPAs
- **Route Discovery** - Extracts routes from JavaScript bundles

**Note:** XSS detection no longer requires a browser - the Proof-Based XSS Scanner uses pure HTTP analysis.

### Smart Crawler Features
- **Priority Queue Crawling** - Crawls high-value targets first (login, admin, API endpoints)
- **Semantic URL Deduplication** - Normalizes IDs, UUIDs, and query params to avoid duplicate testing
- **Adaptive Rate Limiting** - Respects robots.txt Crawl-delay, backs off on 429/503
- **Sitemap Discovery** - Automatically discovers URLs from sitemap.xml

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

## State-Aware Crawling

Lonkero v3.0 includes intelligent state tracking that understands stateful web applications:

### State Capture
```
┌─────────────────────────────────────────────────────────────────┐
│  State Tracking Across Requests                                  │
├─────────────────────────────────────────────────────────────────┤
│  • Cookies (auth tokens, session IDs, preferences)              │
│  • localStorage/sessionStorage values                           │
│  • URL parameters and hash fragments                            │
│  • Hidden form fields (CSRF tokens, state tokens)               │
│  • Authentication state detection                               │
└─────────────────────────────────────────────────────────────────┘
```

### Features
- **Dependency Detection**: Identifies which requests depend on state from previous requests
- **CSRF Token Tracking**: Detects tokens that need refreshing between requests
- **Pattern Recognition**: Identifies common state flows (login, cart, wizard forms)
- **Dependency Graph**: Builds a graph of state dependencies between endpoints

### Detected Patterns
| Pattern | Detection |
|---------|-----------|
| Auth Flow | Session cookies, JWT tokens, auth headers |
| Shopping Cart | Cart ID cookies, checkout state |
| Wizard Forms | Step tokens, form sequence tracking |
| CSRF Protection | Token fields matching common patterns |

---

## Multi-Role Authorization Testing

Parallel testing with multiple user roles to detect authorization vulnerabilities:

### How It Works
```
┌─────────────────────────────────────────────────────────────────┐
│  Multi-Role Orchestrator                                        │
├─────────────────────────────────────────────────────────────────┤
│  1. Initialize sessions for each role (guest, user, admin)      │
│  2. Synchronized crawl - test same URLs with all roles          │
│  3. Compare access patterns between roles                       │
│  4. Detect privilege escalation (vertical & horizontal)         │
│  5. Generate access matrix for review                           │
└─────────────────────────────────────────────────────────────────┘
```

### Detected Vulnerabilities
| Vulnerability | Description |
|---------------|-------------|
| **Vertical Privilege Escalation** | User accessing admin functions |
| **Horizontal Privilege Escalation (IDOR)** | User A accessing User B's data |
| **BOLA** | Broken Object Level Authorization |
| **BFLA** | Broken Function Level Authorization |

### Permission Levels
- `Guest` - Unauthenticated user
- `User` - Basic authenticated user
- `Moderator` - Power user
- `Admin` - Administrator
- `SuperAdmin` - System level access

### Usage
```bash
# Enable multi-role testing with credentials
lonkero scan https://example.com \
  --auth-username user@example.com --auth-password userpass \
  --admin-username admin@example.com --admin-password adminpass
```

---

## Form Replay System

Comprehensive recording and replay of multi-step form sequences for security testing:

### Capabilities
```
┌─────────────────────────────────────────────────────────────────┐
│  Form Replay Architecture                                       │
├─────────────────────────────────────────────────────────────────┤
│  FormRecorder → Records submissions during headless crawl       │
│  FormSequence → Ordered list of submissions (wizard flows)      │
│  FormReplayer → Replays sequences with payload injection        │
└─────────────────────────────────────────────────────────────────┘
```

### Features
- **Multi-Step Wizards**: Handles checkout flows, registration wizards, multi-page forms
- **Dynamic Token Handling**: Automatically refreshes CSRF tokens, nonces, timestamps
- **State Preservation**: Maintains session state between steps
- **Payload Injection**: Injects security payloads into specific fields while preserving flow

### Token Types Handled
| Token Type | Example |
|------------|---------|
| CSRF | `_token`, `csrf_token`, `authenticity_token` |
| Nonce | Single-use values that change per request |
| Timestamp | Time-based tokens for request validation |
| Session | Session-bound tokens |
| Captcha | Captcha challenge tokens (detected, not bypassed) |

---

## Session Recording

Full session capture for vulnerability reproduction and debugging:

### Recording Capabilities
- **Network**: All HTTP requests/responses with headers and bodies
- **DOM Interactions**: Clicks, form inputs, scrolls, submissions
- **Console**: JavaScript console messages and errors
- **Screenshots**: Captured at key events (navigation, errors)
- **WebSocket**: Message capture for real-time communications
- **Storage**: localStorage/sessionStorage/cookie changes

### Export Formats
| Format | Description |
|--------|-------------|
| **HAR** | HTTP Archive format - compatible with browser dev tools |
| **JSON** | Full timeline with all events |
| **JSON (Compressed)** | Gzip-compressed for storage efficiency |
| **HTML** | Interactive report with timeline and embedded screenshots |

### Use Cases
1. **Vulnerability Reproduction**: Replay exact steps that triggered a vulnerability
2. **Debug Complex Flows**: Understand multi-step attack chains
3. **Evidence Collection**: Export HAR/HTML for penetration test reports
4. **Session Analysis**: Review all network traffic for security issues

---

## Installation

### From crates.io

```bash
cargo install lonkero
```

### From GitHub Releases

Download pre-built binaries from [Releases](https://github.com/bountyyfi/lonkero/releases):
- Linux (x64, ARM64)
- macOS (x64, Apple Silicon)
- Windows (x64)

### From Source

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

- Rust 1.85+
- OpenSSL development libraries
- Valid license key (for premium features)

**Debian/Ubuntu:** Install required system dependencies before building:

```bash
sudo apt update && sudo apt install build-essential pkg-config libssl-dev -y
```

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

# Payload intensity control (v3.9)
lonkero scan https://example.com --payload-intensity maximum  # All 12,450+ XSS payloads
lonkero scan https://example.com --payload-intensity minimal  # Quick scan (50 payloads)

# Multi-role authorization testing (BOLA/BFLA detection)
lonkero scan https://example.com \
  --auth-username user@example.com --auth-password userpass \
  --admin-username admin@example.com --admin-password adminpass \
  --multi-role

# Session recording (HAR format)
lonkero scan https://example.com --record-session --session-format har

# Session recording with custom output
lonkero scan https://example.com --record-session --session-output scan_session.html --session-format html
```

### Crawler Priority System

The crawler uses a priority queue to maximize attack surface discovery:

```
┌─────────────────────────────────────────────────────────────────┐
│  URL Priority Scoring (higher = crawled first)                  │
├─────────────────────────────────────────────────────────────────┤
│  HIGH PRIORITY (+35 to +50):                                    │
│  • /login, /signin                     (+50)                    │
│  • /register, /signup                  (+45)                    │
│  • /admin, /dashboard                  (+40)                    │
│  • /graphql                            (+35)                    │
│  • /profile, /account, /settings       (+35)                    │
│  • /checkout, /payment, /cart          (+35)                    │
├─────────────────────────────────────────────────────────────────┤
│  MEDIUM PRIORITY (+10 to +30):                                  │
│  • Query parameters                    (+10 each, max +40)      │
│  • Dynamic path segments (/users/123)  (+10 each, max +30)      │
│  • /api, /v1/, /v2/                    (+25)                    │
│  • /search, /filter                    (+30)                    │
├─────────────────────────────────────────────────────────────────┤
│  LOW PRIORITY (deprioritized):                                  │
│  • Static files (.css, .js, .png)      (-80)                    │
│  • /static/, /assets/, /cdn/           (-40)                    │
│  • /blog/, /news/, /about              (-20)                    │
└─────────────────────────────────────────────────────────────────┘
```

### Semantic URL Deduplication

Vulnerabilities are deduplicated using semantic URL normalization to avoid duplicate reports:

```
┌─────────────────────────────────────────────────────────────────┐
│  URL Normalization Examples                                     │
├─────────────────────────────────────────────────────────────────┤
│  Numeric IDs:                                                   │
│  /users/123/posts/456  →  /users/{id}/posts/{id}                │
│  /users/789/posts/101  →  /users/{id}/posts/{id}  ✓ Same        │
├─────────────────────────────────────────────────────────────────┤
│  UUIDs:                                                         │
│  /item/550e8400-e29b-41d4-...  →  /item/{uuid}                  │
│  /item/f47ac10b-58cc-4372-...  →  /item/{uuid}    ✓ Same        │
├─────────────────────────────────────────────────────────────────┤
│  MongoDB ObjectIds:                                             │
│  /doc/507f1f77bcf86cd799439011  →  /doc/{oid}                   │
│  /doc/5eb63bbbe01eeed093cb22bb  →  /doc/{oid}     ✓ Same        │
├─────────────────────────────────────────────────────────────────┤
│  Query Parameters (sorted alphabetically):                      │
│  /search?b=2&a=1&c=3  →  /search?a=1&b=2&c=3                    │
│  /search?a=1&b=2&c=3  →  /search?a=1&b=2&c=3      ✓ Same        │
└─────────────────────────────────────────────────────────────────┘
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

### Authentication & Authorization (26 scanners)

- **JWT** - Algorithm confusion, weak secrets, None algorithm, key injection
- **OAuth 2.0** - Token theft, redirect manipulation, PKCE bypass, scope abuse
- **OIDC** - Provider detection (Okta, Auth0, Azure AD, Keycloak, Cognito), configuration vulnerabilities, token validation bypass
- **SAML** - Assertion bypass, signature wrapping, XML injection
- **MFA** - Bypass techniques, replay attacks, race conditions
- **2FA Bypass** - Rate limiting bypass, backup code enumeration, session manipulation, OTP brute-force
- **Session Management** - Fixation, hijacking, prediction
- **Auth Bypass** - Parameter tampering, header injection, credential stuffing
- **IDOR** - Object reference manipulation, baseline detection
- **Privilege Escalation** - Horizontal and vertical privilege abuse
- **Client Route Auth Bypass** - SPA authentication bypass via client-side routing manipulation
- **Advanced Auth** - Complex authentication flow exploitation
- **Account Takeover** - OAuth chain analysis, session fixation, token leakage, credential stuffing chains
- **Password Reset Poisoning** - Host header injection, token predictability, link manipulation, email parameter pollution
- **Timing Attacks** - Authentication timing analysis, user enumeration via response timing, race condition detection
- **WebAuthn** - Biometric authentication bypass
- **BOLA** - Broken object level authorization (API-specific IDOR with advanced baseline)
- **BFLA** - Broken Function Level Authorization, admin function discovery, privilege escalation
- **Cognito Enumeration** - AWS Cognito user pool enumeration via ForgotPassword, SignUp, InitiateAuth APIs with CSP header detection

### Injection Vulnerabilities (30 scanners)

- **SQL Injection** - Enhanced detection, blind (boolean/time/binary search), second-order
- **XSS (Proof-Based)** - Mathematical proof of exploitability via context analysis and escape behavior testing. No browser required. 2-3 requests per parameter. Detects reflected XSS in 16 different contexts (HTML body, JS strings, attributes, event handlers, etc.)
- **DOM XSS** - Static analysis of JavaScript for source-to-sink flows (location.hash → innerHTML, etc.) with sanitization detection
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
- **DOM Clobbering** - Named element collision, prototype pollution chains, HTML-based gadget discovery
- **HTML Injection** - Non-XSS markup injection
- **HTTP Parameter Pollution** - HPP attacks
- **Deserialization** - Unsafe object deserialization

### API Security (20 scanners)

- **GraphQL Advanced** - Introspection, batching DoS, cost analysis, alias abuse, persisted queries, directive abuse, subscription vulnerabilities, fragment spreading, authorization bypass
- **GraphQL Batching** - Batch DoS attacks, alias abuse for rate limit bypass, complexity abuse, authentication bypass via batching
- **gRPC** - Reflection, enumeration, metadata abuse
- **REST** - Mass assignment, API fuzzing, parameter pollution
- **WebSocket** - Message injection, protocol abuse
- **API Gateway** - Azure APIM cross-tenant bypass, generic gateway vulnerabilities
- **API Security** - Comprehensive API testing
- **API Versioning** - Version enumeration, security regression detection, bypass techniques, deprecated endpoint discovery
- **OpenAPI Analyzer** - Swagger 2.0/OpenAPI 3.x specification parsing, security definition analysis, endpoint enumeration
- **BFLA** - Broken Function Level Authorization, admin function discovery, horizontal/vertical privilege escalation
- **Rate Limiting** - Bypass techniques
- **CORS** - Misconfiguration detection
- **Cache Poisoning** - Web cache deception
- **HTTP/3** - QUIC-specific vulnerabilities
- **HTTP Smuggling** - Request smuggling attacks

### Modern Framework Scanners (15 scanners)

- **Next.js** - Route discovery from JS bundles, middleware bypass (CVE-2024-34351, CVE-2025-29927), `_next/data` exposure, server actions, image SSRF, ISR token exposure
- **React** - DevTools exposure, hydration issues, client-side vulnerabilities
- **SvelteKit** - CSRF bypass, SSR vulnerabilities
- **Django** - DEBUG mode, ORM injection, middleware bypass
- **Laravel** - Ignition RCE, route enumeration, mass assignment
- **Express.js** - Middleware vulnerabilities, prototype pollution
- **WordPress** - Plugin vulnerabilities, XML-RPC, REST API abuse
- **Drupal** - Core vulnerabilities, module security
- **Joomla** - CVE-2023-23752 (authentication bypass), CVE-2017-8917 (SQLi), admin exposure, API exploitation, extension vulnerabilities, installation leftovers
- **Ruby on Rails** - Debug mode exposure, environment/config file leaks, log exposure, session security, asset/source map exposure, git repository detection
- **Spring Boot** - Actuator endpoint exposure (env, heapdump, jolokia, shutdown), H2 console RCE, Swagger/OpenAPI exposure, configuration file leaks
- **Liferay** - Portal-specific vulnerabilities
- **Tomcat** - Misconfiguration, default credentials
- **Varnish** - Cache misconfiguration
- **Angular** - Client-side template injection, router bypass

### Configuration & Security (17 scanners)

- **Security Headers** - HSTS, CSP, X-Frame-Options, referrer policy
- **CSP Bypass** - Script gadgets, nonce reuse, base-uri attacks, JSONP endpoints, unsafe-inline detection
- **CORS Misconfiguration** - Wildcard origins, credential exposure
- **SSL/TLS** - Weak ciphers, certificate validation
- **Cloud Security** - AWS, Azure, GCP misconfiguration
- **Cloud Storage** - S3 buckets, Azure blobs, GCS exposure
- **Firebase** - Database exposure, misconfiguration
- **Container Security** - Docker, Kubernetes vulnerabilities
- **WAF Bypass** - Web application firewall evasion
- **Clickjacking** - Frame injection, UI redressing
- **CSRF** - Cross-site request forgery
- **PostMessage Vulns** - Origin validation bypass, XSS via postMessage, data exfiltration, cross-origin communication abuse
- **Web Cache Deception** - Path confusion attacks, cache infrastructure detection, sensitive data exposure via caching
- **Subdomain Takeover** - 25+ cloud service fingerprints (AWS, Azure, GitHub, Heroku, etc.), DNS/CNAME analysis

### Business Logic (8 scanners)

- **Business Logic** - Advanced workflow exploitation
- **Race Conditions** - TOCTOU, parallel request abuse, timing analysis
- **Timing Attacks** - Authentication timing, user enumeration via response timing, race condition detection
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

### Specialized Scanners (10 scanners)

- **CVE Detection** - Known vulnerability scanners (CVE-2025-55182, CVE-2025-55183, CVE-2025-55184)
- **Framework Vulnerabilities** - Generic framework CVEs with version detection
- **Subdomain Takeover** - 25+ cloud service fingerprints (AWS S3, CloudFront, Azure, GitHub Pages, Heroku, Shopify, etc.)
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
2. **xss_proof_based** - Mathematical proof-based XSS detection (16 contexts, no browser)
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

## Machine Learning Features

Lonkero v3.0 includes an integrated ML system that automatically learns from scan results to improve detection accuracy over time.

### Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Local Auto-Learning                                             │
│  • Learns from every scan automatically                          │
│  • No user verification required                                 │
│  • Reduces false positives based on response patterns            │
├─────────────────────────────────────────────────────────────────┤
│  Federated Learning (Opt-in)                                     │
│  • Share model weights (not data) with the community             │
│  • Benefit from collective knowledge                             │
│  • Differential privacy ensures no data leakage                  │
├─────────────────────────────────────────────────────────────────┤
│  GDPR Compliant                                                  │
│  • Explicit consent required                                     │
│  • Right to erasure (delete all data)                            │
│  • Right to access (export your data)                            │
│  • All data stored locally by default                            │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Auto-Learning**: After each scan, Lonkero analyzes vulnerabilities and their HTTP responses
2. **Feature Extraction**: Extracts 23 features (status codes, error patterns, reflection analysis, timing)
3. **Pattern Recognition**: Builds endpoint-specific patterns to reduce false positives
4. **Confidence Scoring**: Auto-confirms high-confidence true positives, rejects obvious false positives

### ML Commands

```bash
# Enable ML with local-only learning
lonkero ml enable

# Enable ML with federated learning (contribute to community model)
lonkero ml enable --federated

# View ML statistics
lonkero ml stats

# Disable ML (keep data)
lonkero ml disable

# Disable ML and delete all data
lonkero ml disable --delete-data

# Export your ML data (GDPR right to access)
lonkero ml export -o my_ml_data.json

# Delete all ML data (GDPR right to erasure)
lonkero ml delete-data

# Manually sync with federated network
lonkero ml sync
```

### Statistics Output

```bash
$ lonkero ml stats

ML Pipeline Statistics
======================
Status: Enabled
Federated: Enabled (1,247 contributors)

Session Stats:
  Processed: 45 findings
  Auto-confirmed: 12 true positives
  Auto-rejected: 28 false positives

Lifetime Stats:
  Total confirmed: 1,892
  Total rejected: 4,521
  Endpoint patterns: 347
  Can contribute: Yes
```

### Privacy & Consent

ML features require explicit user consent:

- **Local-only mode**: All data stays on your machine. Model weights are trained locally.
- **Federated mode**: Only aggregated model weights are shared (not raw data). Differential privacy with noise injection ensures individual findings cannot be reconstructed.

**Data stored locally** (in `~/.lonkero/ml/`):
- Training examples with extracted features
- Local model weights
- Endpoint patterns learned
- Verification history

**Data shared in federated mode**:
- Aggregated model weight gradients only
- Noise-injected to prevent reconstruction
- No URLs, payloads, or raw responses

### GDPR Compliance

| Right | Command | Description |
|-------|---------|-------------|
| Right to be informed | `lonkero ml stats` | View what data is collected |
| Right of access | `lonkero ml export` | Export all your ML data |
| Right to erasure | `lonkero ml delete-data` | Permanently delete all ML data |
| Right to withdraw consent | `lonkero ml disable` | Stop ML processing |

---

## Scanner Intelligence System

Lonkero v3.0 introduces a sophisticated intelligence system that makes scanners work together like a coordinated security team rather than isolated tools.

### Overview

```
+---------------------------------------------------------------------+
|  Intelligence Bus - Real-time Scanner Communication                  |
|  Scanners broadcast discoveries, others adapt immediately            |
+---------------------------------------------------------------------+
                                  |
          +-----------------------+-----------------------+
          |                       |                       |
          v                       v                       v
+-------------------+   +-------------------+   +-------------------+
| Hypothesis Engine |   | Attack Planner    |   | Response Analyzer |
| Bayesian-guided   |   | Multi-step attack |   | Semantic response |
| vulnerability     |   | chain planning    |   | understanding     |
| testing           |   | with goal search  |   | (NLP-lite)        |
+-------------------+   +-------------------+   +-------------------+
```

### Intelligence Bus

Real-time communication between scanners during a scan:

| Event Type | Description | Example |
|------------|-------------|---------|
| `AuthTypeDetected` | JWT, OAuth2, Session, SAML, OIDC detected | JWT scanner informs others to test algorithm confusion |
| `FrameworkDetected` | Framework with version identified | Django 4.2 detected, enable Django-specific tests |
| `WafDetected` | WAF type with bypass hints | Cloudflare detected, switch to bypass payloads |
| `VulnerabilityPattern` | SQL errors, stack traces found | MySQL error seen, prioritize MySQL-specific injection |
| `SensitiveParameter` | High-value parameter found | `admin_id` parameter found, IDOR scanner prioritizes it |
| `EndpointPattern` | API patterns discovered | REST CRUD pattern detected, test all HTTP methods |
| `ScannerInsight` | Bypass or weakness found | Rate limit bypass found, inform brute-force scanners |

**Example flow:**
1. Tech detector finds Django 4.2
2. Broadcasts `FrameworkDetected { name: "Django", version: "4.2" }`
3. Django scanner activates DEBUG mode tests
4. SQLi scanner switches to PostgreSQL payloads
5. Path traversal scanner tests Django-specific paths

### Hypothesis Engine

Bayesian-guided vulnerability testing that forms and tests hypotheses:

```
Traditional scanning:                Hypothesis-driven scanning:

Try payload 1 -> No result          Observe: param=id, numeric value
Try payload 2 -> No result          Hypothesis: SQL Injection (prior: 0.3)
Try payload 3 -> No result          Test: ' OR '1'='1 -> SQL error
Try payload 4 -> No result          Update: posterior = 0.85
Try payload 5 -> SQL error!         Refine: MySQL-specific
...500 payloads later...            Test: SLEEP(5) -> 5s delay
                                    Confirm: MySQL Blind SQLi (0.99)
```

**Key concepts:**
- **Prior probability**: Initial belief based on parameter name, context
- **Evidence collection**: Each test updates probability using Bayes' theorem
- **Information gain**: Select tests that maximize uncertainty reduction
- **Hypothesis refinement**: SQLi -> MySQL SQLi -> Blind MySQL SQLi

**Supported hypothesis types:**
- SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- XSS (HTML context, Attribute, JavaScript, URL)
- Command Injection (Linux, Windows)
- Path Traversal, SSRF, Auth Bypass, IDOR
- Template Injection, XXE, NoSQL Injection

### Attack Planner

Multi-step attack chain planning with goal-directed search:

```
Goal: Account Takeover

Current State:                    Attack Plan Generated:
- Known endpoint: /api/users      1. Enumerate users via /api/users IDOR
- No user list                    2. Extract email from user profile
- No session                      3. Trigger password reset
                                  4. Exploit token predictability
                  |               5. Gain victim session
                  v
         [BFS Path Finding]
                  |
                  v
         Execute step by step,
         update state after each
```

**Attack goals supported:**
- Account Takeover
- Privilege Escalation
- Data Exfiltration
- Remote Code Execution
- Internal Network Access
- Authentication Bypass

**Common attack chains:**
1. **Account Takeover**: User enum -> Password reset flaw -> Token prediction -> Session hijack
2. **Privilege Escalation**: IDOR on users -> Find admin ID -> Mass assignment -> Admin access
3. **RCE Chain**: File upload bypass -> Path traversal -> Execute uploaded shell

### Response Analyzer

Semantic understanding of HTTP responses (NLP-lite, no external dependencies):

| Analysis | Detection |
|----------|-----------|
| **SQL Errors** | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| **Stack Traces** | Python, Java, PHP, Node.js, .NET, Ruby, Go, Rust |
| **Auth States** | Authenticated, Expired, Invalid credentials, MFA required |
| **WAF Signatures** | Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva |
| **Data Exposure** | Internal IPs, file paths, API keys, tokens, credentials |
| **Business Context** | User management, payment, admin panel, file management |

**Example analysis:**
```
Response: 500 Internal Server Error
Body: "PG::SyntaxError: ERROR: syntax error at or near..."

Analysis:
- ResponseType: ServerError
- ErrorInfo: { type: Database, db: PostgreSQL }
- DataExposure: [StackTrace, DatabaseSchema]
- VulnerabilityHint: { type: "SQL Injection", confidence: 0.92 }
```

### Benefits

| Metric | Without Intelligence | With Intelligence |
|--------|---------------------|-------------------|
| Payloads tested | 5,000 | 800 |
| Time to first finding | 45s | 8s |
| False positive rate | 8% | 2% |
| Attack chains found | 0 | 3 |
| Context awareness | None | Full |

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

      - name: Install Dependencies
        run: sudo apt update && sudo apt install build-essential pkg-config libssl-dev -y

      - name: Clone and Build Lonkero
        run: |
          git clone https://github.com/bountyyfi/lonkero.git /tmp/lonkero
          cd /tmp/lonkero
          cargo build --release
          sudo cp target/release/lonkero /usr/local/bin/

      - name: Run Lonkero Scan
        env:
          LONKERO_LICENSE_KEY: ${{ secrets.LONKERO_LICENSE }}
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
  image: rust:1.85.1
  variables:
    LONKERO_LICENSE_KEY: $LONKERO_LICENSE
  script:
    - apt update && apt install -y build-essential pkg-config libssl-dev
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
| **ML Auto-Learning** | Yes (federated) | No | No | No |
| **Modern Framework Support** | Next.js, React, GraphQL | Limited | Limited | Limited |
| **Smart Parameter Filtering** | Yes | No | No | No |
| **Blind Detection** | OOBZero Engine | Burp Collaborator | No | OOB callbacks |
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
