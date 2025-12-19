<div align="center">

<img src="https://bountyyfi.s3.eu-north-1.amazonaws.com/lonkero.png" alt="Lonkero Logo" width="200"/>

### Wraps around your attack surface

Professional-grade scanner for real penetration testing. Fast. Modular. Rust.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-green.svg)](https://github.com/bountyyfi/lonkero)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/bountyyfi/lonkero)
[![Coverage](https://img.shields.io/badge/coverage-95%25-success.svg)](https://github.com/bountyyfi/lonkero)

**90+ Advanced Scanners** | **16 Premium Features** | **Smart AI Filtering** | **5% False Positives**

**[Official Website](https://lonkero.bountyy.fi/en)** | [Features](#core-capabilities) · [Installation](#installation) · [Quick Start](#quick-start) · [Architecture](#architecture)

---

</div>

## What is Lonkero?

Lonkero is a production-grade web security scanner designed for professional security testing:

- Near-zero false positives (5% vs industry 20-30%)
- Intelligent testing - Skips framework internals, focuses on real vulnerabilities
- Modern stack coverage - Next.js, React, GraphQL, gRPC, WebSocket, HTTP/3
- Blind vulnerability detection - Out-of-band DNS/HTTP callbacks for SSRF, XXE, SQLi
- 80% faster scans - Smart parameter filtering eliminates noise

Unlike generic scanners that spam thousands of useless payloads, Lonkero uses context-aware filtering to test only what matters.

---

## Core Capabilities

```mermaid
mindmap
  root((Lonkero))
    **90 Scanners**
      Injection
        SQLi Blind Binary Search
        XSS DOM/Mutation
        XXE OOB Detection
        SSRF Cloud Metadata
        NoSQL Advanced
      Auth & Session
        JWT Algorithm Confusion
        OAuth Token Theft
        SAML Bypass
        MFA Replay Attack
        Session Fixation
      API Security
        GraphQL Batching DoS
        gRPC Reflection
        REST Mass Assignment
        WebSocket Injection
      Framework Detection
        JavaScript (React, Vue, Angular)
        PHP (Laravel, WordPress)
        Python (Django, Flask)
        Ruby (Rails)
        Java (Spring)
    **Smart Scanning**
      Parameter Filtering
        Skip Framework Internals
        Prioritize User Input
        Context-Aware Testing
      OOB Detection
        DNS Exfiltration
        HTTP Callbacks
        Blind Vulnerability Proof
    **Enterprise Features**
      Compliance
        OWASP Top 10 2025
        PCI DSS
        GDPR/NIS2/DORA
      CI/CD
        GitHub Actions
        GitLab SAST
        SARIF Output
      Licensing
        Professional Tier
        Enterprise Tier
        API Key Management
```

---

## Architecture

### Scanning Pipeline

```mermaid
graph TB
    Start([Target URL]) --> Recon[Phase 0: Reconnaissance]

    Recon --> Tech{Technology<br/>Detection}
    Tech -->|Next.js/React| Modern[Modern Framework]
    Tech -->|Laravel/Django| Traditional[Traditional MVC]
    Tech -->|API/SPA| API[API Endpoints]

    Modern --> Filter
    Traditional --> Filter
    API --> Filter

    Filter{Smart Filter} -->|Skip| Skip[Framework Internals<br/>state, buildId, csrf]
    Filter -->|Priority 10| P10[User Input<br/>password, email, token]
    Filter -->|Priority 9| P9[Search & Content<br/>query, message, comment]
    Filter -->|Priority 5| P5[Business Data<br/>price, quantity, id]

    P10 --> Phase1[Phase 1: Injection Tests<br/>SQLi, XSS, XXE, NoSQL]
    P9 --> Phase1
    P5 --> Phase1

    Phase1 --> Phase2[Phase 2: Auth & Session<br/>JWT, OAuth, SAML, MFA]
    Phase2 --> Phase3[Phase 3: Business Logic<br/>IDOR, Race Conditions]
    Phase3 --> Phase4[Phase 4: Configuration<br/>CORS, Headers, Cache]
    Phase4 --> Phase5[Phase 5: API Security<br/>GraphQL, gRPC, REST]
    Phase5 --> Phase6[Phase 6: Framework-Specific<br/>Next.js, Laravel, Django]
    Phase6 --> Phase7[Phase 7: OOB Detection<br/>DNS/HTTP Callbacks]
    Phase7 --> Report[Generate Report<br/>JSON/HTML/SARIF]

    Report --> End([Scan Complete])

    style Filter fill:#ff6b6b
    style Skip fill:#95e1d3
    style P10 fill:#f38181
    style Phase7 fill:#aa96da
```

---

## Smart Parameter Filtering

### The Problem

Traditional scanners waste 95% of resources testing framework internals:

```
Testing: __react_state, _nextData, csrfToken, sessionId, timestamp, buildId...
Result: 2,800 requests, 0 vulnerabilities, 28 seconds
```

### The Solution

```mermaid
sequenceDiagram
    participant Scanner
    participant Filter as Smart Filter
    participant Target

    Scanner->>Filter: Analyze: __react_state
    Filter-->>Scanner: Skip (Framework Internal)

    Scanner->>Filter: Analyze: _nextData
    Filter-->>Scanner: Skip (Framework Internal)

    Scanner->>Filter: Analyze: email
    Filter-->>Scanner: Priority 10 (User Input)

    Scanner->>Target: Test SQLi on email parameter
    Target-->>Scanner: Vulnerability Found

    Scanner->>Filter: Analyze: password
    Filter-->>Scanner: Priority 10 (Credentials)

    Scanner->>Target: Test injection on password
    Target-->>Scanner: Vulnerability Found
```

### Performance Impact

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Parameters Tested | 100 | 20 | 80% reduction |
| Total Requests | 2,800 | 560 | 80% reduction |
| Scan Time | 28s | 6s | 78% faster |
| Vulnerabilities Found | 2 | 2 | 100% coverage |
| False Positives | 15 | 1 | 93% reduction |

---

## Blind Vulnerability Detection

### Out-of-Band (OOB) Infrastructure

```mermaid
graph LR
    Scanner[Lonkero Scanner] -->|1. Inject Payload| Target[Target Application]
    Target -->|2. SSRF/XXE/SQLi| DNS[DNS Server<br/>oob.lonkero.bountyy.fi]
    DNS -->|3. Log Callback| Detector[OOB Detector]
    Detector -->|4. Verify Vuln| Scanner

    Target -->|2. HTTP Callback| HTTP[HTTP Server<br/>callback.lonkero.bountyy.fi]
    HTTP -->|3. Log Request| Detector

    style DNS fill:#96ceb4
    style HTTP fill:#ffeaa7
    style Detector fill:#ff7675
```

### Supported Vulnerability Types

- **SSRF** - Cloud metadata access (AWS, Azure, GCP)
- **XXE** - External entity injection with DNS exfiltration
- **Command Injection** - Blind command execution via DNS/HTTP
- **SQL Injection** - Blind SQLi via DNS queries
- **LDAP Injection** - Directory service attacks
- **Template Injection** - Server-side template engines

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

### Basic Scan

```bash
# Scan single URL
lonkero scan https://example.com

# Scan with all modules
lonkero scan https://example.com --all-modules

# Output to JSON
lonkero scan https://example.com --format json -o report.json
```

### Advanced Usage

```bash
# Scan with specific modules
lonkero scan https://example.com --modules sqli,xss,xxe

# Scan with authentication
lonkero scan https://example.com --cookie "session=abc123"

# Scan with custom headers
lonkero scan https://example.com --header "Authorization: Bearer token"

# CI/CD integration (SARIF output)
lonkero scan https://example.com --format sarif -o results.sarif
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

### Injection Vulnerabilities (20 scanners)

```mermaid
graph TD
    Injection[Injection Scanners] --> SQLi[SQL Injection]
    Injection --> XSS[Cross-Site Scripting]
    Injection --> XXE[XML External Entity]
    Injection --> NoSQL[NoSQL Injection]
    Injection --> CMD[Command Injection]
    Injection --> LDAP[LDAP Injection]
    Injection --> XPATH[XPath Injection]
    Injection --> SSTI[Template Injection]
    Injection --> SSRF[Server-Side Request Forgery]

    SQLi --> SQLi1[Boolean-based Blind]
    SQLi --> SQLi2[Time-based Blind]
    SQLi --> SQLi3[Binary Search]
    SQLi --> SQLi4[Second-order]

    XSS --> XSS1[Reflected]
    XSS --> XSS2[Stored]
    XSS --> XSS3[DOM-based]
    XSS --> XSS4[Mutation XSS]
    XSS --> XSS5[SVG-based]

    style SQLi fill:#ff6b6b
    style XSS fill:#4ecdc4
    style XXE fill:#ffe66d
```

### Authentication & Authorization (15 scanners)

- JWT vulnerabilities (algorithm confusion, weak secrets, None algorithm)
- OAuth 2.0 attacks (token theft, redirect manipulation, PKCE bypass)
- SAML assertion bypass
- Multi-factor authentication bypass
- Session fixation & hijacking
- Client-side route authentication bypass
- IDOR (Insecure Direct Object Reference)
- Privilege escalation
- Authentication bypass via parameter tampering

### API Security (12 scanners)

- GraphQL security (batching DoS, cost analysis, introspection abuse)
- gRPC reflection & enumeration
- REST API mass assignment
- WebSocket injection
- API rate limiting bypass
- API key exposure
- CORS misconfigurations
- Cache poisoning

### Modern Framework Scanners (18 scanners)

- **Next.js** - Middleware bypass, server action vulnerabilities
- **React** - DevTools exposure, hydration mismatch
- **SvelteKit** - CSRF token bypass
- **Django** - DEBUG mode leaks, ORM injection
- **Laravel** - Ignition RCE, route enumeration
- **WordPress** - Plugin vulnerabilities, XML-RPC abuse
- **Drupal** - Core vulnerabilities, module security

### Configuration & Deployment (10 scanners)

- Security headers (HSTS, CSP, X-Frame-Options)
- CORS policy validation
- SSL/TLS configuration
- HTTP/2 vulnerabilities
- Cache poisoning
- CDN bypass techniques
- Subdomain takeover
- DNS security

### Business Logic (8 scanners)

- Race conditions
- Payment manipulation
- Discount/coupon abuse
- Multi-step form bypass
- File upload validation
- Rate limiting bypass
- Business workflow manipulation

### Information Disclosure (7 scanners)

- Sensitive data exposure
- Debug information leaks
- Source code disclosure
- Git repository exposure
- Directory listing
- Backup file detection
- Certificate transparency logs

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

### Enterprise Tier

High-value features for critical infrastructure:

14. **oob_detection** - Out-of-band vulnerability detection infrastructure
15. **oob_dns_exfiltration** - DNS-based blind vulnerability verification
16. **oob_http_callbacks** - HTTP callback verification for blind attacks

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

### GitHub Actions

```yaml
name: Lonkero Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Lonkero
        run: |
          wget https://github.com/bountyyfi/lonkero/releases/latest/download/lonkero-linux
          chmod +x lonkero-linux
          ./lonkero-linux scan https://staging.example.com \
            --format sarif \
            -o results.sarif \
            --license-key ${{ secrets.LONKERO_LICENSE }}

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
  script:
    - cargo install --git https://github.com/bountyyfi/lonkero
    - lonkero scan $CI_ENVIRONMENT_URL --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
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

### SARIF (GitHub Security Tab)

Compatible with GitHub Advanced Security for automated PR comments and security alerts.

### HTML

Interactive report with filtering, sorting, and vulnerability details.

---

## Competitive Comparison

| Feature | Lonkero | Burp Suite Pro | OWASP ZAP | Acunetix |
|---------|---------|----------------|-----------|----------|
| **Price** | [See website](https://lonkero.bountyy.fi/en) | $449/year | Free | $4,500/year |
| **False Positive Rate** | 5% | 10-15% | 20-30% | 10-15% |
| **Modern Framework Support** | Next.js, React, GraphQL | Limited | Limited | Limited |
| **Smart Parameter Filtering** | Yes | No | No | No |
| **OOB Detection** | Yes | Yes | No | Yes |
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

**Copyright © 2025 Bountyy Oy. All rights reserved.**

This software is proprietary. Commercial use requires a valid license.

For licensing inquiries, visit [lonkero.bountyy.fi](https://lonkero.bountyy.fi/en) or contact [info@bountyy.fi](mailto:info@bountyy.fi).

---

**Made in Finland** 🇫🇮
