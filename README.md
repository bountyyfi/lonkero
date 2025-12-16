# Lonkero

**Enterprise Web Security Scanner v2.0**

Web scanner built for actual pentests. Fast, modular, Rust.

```
    __                __
   / /   ____  ____  / /_____  _________
  / /   / __ \/ __ \/ //_/ _ \/ ___/ __ \
 / /___/ /_/ / / / / ,< /  __/ /  / /_/ /
/_____/\____/_/ /_/_/|_|\___/_/   \____/

        Enterprise Web Security Scanner
            (c) 2025 Bountyy Oy
```

## Table of Contents

- [What's New in v2.0](#whats-new-in-v20)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Scanner Modules](#scanner-modules)
- [Output Formats](#output-formats)
- [Scan Modes](#scan-modes)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Cloud Security Scanning](#cloud-security-scanning)
- [CI/CD Integration](#cicd-integration)
- [Command Reference](#command-reference)
- [License](#license)

## What's New in v2.0

### Enterprise-Grade Injection Scanners
Completely rewritten injection scanners with **programmatic payload generation** producing thousands of real-world bypass techniques:

**SSRF Scanner (2000+ payloads)**
- IP encoding matrix: decimal, hexadecimal, octal, IPv6, mixed encoding
- Cloud metadata paths for AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba
- Protocol smuggling: gopher, dict, file, ldap, tftp
- DNS rebinding and redirect chain detection
- Bypass techniques: URL parsing differentials, Unicode normalization, double encoding

**Path Traversal Scanner (2000+ payloads)**
- 28 traversal sequences (../, ..\, ..%2f, %2e%2e/, etc.)
- 15 depth levels with automatic path calculation
- 55+ target files (passwd, shadow, hosts, web.config, etc.)
- Encoding variations: URL, double, triple, Unicode, overlong UTF-8
- Null byte injection and truncation attacks

**Open Redirect Scanner (1500+ payloads)**
- 30+ evil domain variations with homoglyphs and punycode
- 45+ protocol variations (slashes, backslashes, case mutations)
- 100+ encoding combinations
- 23 bypass categories: whitelist, parser differential, CRLF, OAuth
- JavaScript and data URI payloads

**Command Injection Scanner (1000+ payloads)**
- Shell metacharacter matrix: 15 separators × 47 commands
- Command substitution: backticks, $(), nested
- Time-based blind detection with configurable delays
- IFS manipulation and environment variable tricks
- Windows (CMD, PowerShell) and Unix-specific payloads
- Filter evasion: wildcards, quotes, concatenation, base64

### Server Misconfiguration Scanners (NEW)

**Tomcat Misconfiguration Scanner**
- Stack traces enabled detection via malformed requests
- Manager/host-manager interface exposure
- Example applications accessible in production
- Version disclosure via error pages
- AJP protocol exposure (Ghostcat CVE-2020-1938 risk)

**Varnish Cache Misconfiguration Scanner**
- Unauthenticated PURGE method detection
- Unauthenticated BAN method for bulk cache invalidation
- Cache information disclosure via headers (X-Varnish, Via, X-Cache)
- Cache poisoning vectors (X-Forwarded-Host, X-Original-URL)
- Dangerous HTTP methods detection via OPTIONS

### Merlin - JavaScript Library Vulnerability Scanner
New **Merlin** module detects vulnerable third-party JavaScript libraries:
- **100+ libraries** with known CVEs (jQuery, Angular, Vue, React, Lodash, Moment, etc.)
- Detects versions from CDN URLs and JavaScript file content
- Checks against CVE database with severity ratings
- Reports exact vulnerable version and remediation (upgrade path)

### Advanced WAF Bypass Testing
12 bypass technique categories:
- Encoding bypasses (URL, Unicode, HTML entities)
- Protocol-level tricks (chunked encoding, HTTP method override)
- Header injection and smuggling techniques
- JSON/XML payload format manipulation

### HTTP Parameter Pollution Scanner
Detects HPP vulnerabilities across different server behaviors.

### Enhanced Compliance Mapping
Now maps findings to **6 compliance frameworks**:
- OWASP Top 10, PCI-DSS, HIPAA, ISO 27001, GDPR
- **NEW**: DORA (EU Digital Operational Resilience Act)
- **NEW**: NIS2 (EU Network and Information Security Directive)

### JavaScript Sensitive Information Scanner (NEW)
Deep analysis of JavaScript files for leaked secrets and sensitive data:

**API Keys & Tokens**
- Mapbox tokens (pk.eyJ/sk.eyJ) with billing abuse impact analysis (~$200K for 100M requests)
- OpenAI, Twilio, SendGrid, Mailgun API keys
- AWS, GCP, Azure credentials
- Stripe, PayPal, Square payment keys
- NPM, PyPI, RubyGems package tokens

**Internal Information**
- Employee email lists and corporate email patterns
- Jira tickets and project references
- Internal URLs (staging, dev, admin)
- Active Directory/LDAP references
- Organization chart and hierarchy data

**Development Artifacts**
- Debug endpoints and admin panels
- Source maps exposing original code
- TODO/FIXME comments with security context
- Hardcoded passwords and secrets

### Rate Limiting Scanner (NEW)
Tests authentication endpoints for missing or insufficient rate limiting:
- Signup endpoint brute force testing
- Login endpoint rate limit detection
- Password reset abuse potential
- OTP/2FA code brute force
- Generates unique test data per request to avoid caching

### CMS Security Scanners (Personal+ License)

**WordPress Security Scanner**
- **User Enumeration**: Author parameter, REST API, login error messages
- **XML-RPC Attacks**: Multicall brute force amplification, pingback SSRF
- **Plugin Vulnerabilities**: 18+ known vulnerable plugins with CVEs
- **Configuration Exposure**: wp-config.php backups, debug.log, error_log
- **Version Disclosure**: Generator meta, readme.html, feed links
- **Sensitive Files**: .htaccess, backup archives, installation scripts

**Drupal Security Scanner**
- **Drupalgeddon Detection**: CVE-2014-3704, CVE-2018-7600, CVE-2018-7602
- **User Enumeration**: User paths, JSON API, password reset timing
- **Module Vulnerabilities**: 15+ vulnerable contributed modules
- **Configuration Exposure**: settings.php backups, status report
- **Update/Install Scripts**: update.php, install.php exposure
- **API Security**: REST/JSON API exposure, cron.php without key

**Laravel Security Scanner**
- **Ignition RCE**: CVE-2021-3129 remote code execution detection
- **Debug Mode**: APP_DEBUG=true with environment variable exposure
- **Admin Panels**: Telescope, Horizon, Nova, Pulse exposure detection
- **Environment Files**: .env, .env.backup, .env.local exposure
- **Storage/Logs**: Directory listing, laravel.log, session files
- **Vendor Exposure**: PHPUnit RCE, composer.json/lock disclosure
- **Configuration**: Cached config, .git, artisan script exposure
- **API Security**: Unprotected routes, GraphQL playground
- **Livewire**: Component vulnerabilities, CSRF misconfigurations
- **Known CVEs**: Version-based vulnerability detection (7 CVEs)

**Express.js Security Scanner**
- **X-Powered-By Header**: Express framework disclosure detection
- **Development Mode**: Stack trace exposure, NODE_ENV detection
- **Security Headers**: Missing Helmet.js middleware detection
- **API Documentation**: Swagger UI, GraphQL Playground, GraphiQL exposure
- **Config Exposure**: package.json, .env, config files
- **Source Maps**: JavaScript source map exposure (.js.map files)
- **Process Manager**: PM2 dashboard and metrics exposure
- **Prototype Pollution**: Request body and query parameter pollution
- **CORS Issues**: Misconfigured CORS allowing credential theft
- **Session Security**: Cookie flags, secure session configuration
- **Debug Endpoints**: /debug, /metrics, /health with sensitive data
- **Known CVEs**: 12+ CVEs covering Express, qs, mongoose, jsonwebtoken, lodash, axios, socket.io

### Firebase Authentication Bypass (NEW)
Detects Firebase misconfigurations:
- **Signup Bypass**: Detects when email/password signup is enabled despite login-only UI
- **Anonymous Auth**: Unauthorized anonymous authentication
- **Firestore Rules**: Insecure database security rules
- **Storage Rules**: Public cloud storage access
- **API Key Exposure**: Unrestricted Firebase API keys

### Expanded Technology Detection
Lonkero now detects **80+ technologies** including:

**Servers**
- Apache Tomcat, Nginx, Apache, IIS, LiteSpeed, Caddy, OpenResty

**Modern JavaScript Frameworks**
- Qwik, Solid.js, Preact, Fresh, Hono
- Next.js, Nuxt.js, Remix, SvelteKit, Astro, Gatsby

**Backend Frameworks**
- **Python**: Flask, FastAPI, Tornado, Starlette, Django
- **Go**: Gin, Echo, Fiber, Chi, Gorilla
- **Rust**: Actix Web, Rocket, Axum, Warp
- **Node.js**: Express, Hono
- **PHP**: Laravel, Symfony
- **Ruby**: Ruby on Rails

**CDNs & Edge Networks**
- Cloudflare, Fastly, Akamai, CloudFront
- Bunny CDN, KeyCDN, StackPath
- Azure CDN, Google Cloud CDN

**API Gateways**
- Kong, Tyk, Apigee
- AWS API Gateway, Azure API Management
- Google Cloud Endpoints

### Enhanced Cloud Storage Security
- **Auto-Detection**: Automatically detects and scans S3, Azure Blob, and GCS URLs found during scans
- **Advanced Payloads**: 90+ sensitive file patterns including:
  - Git files (.git/config, .github/workflows)
  - Environment files (.env, .env.production, .env.backup)
  - AWS credentials (.aws/credentials, aws.json, credentials.json)
  - SSH keys (id_rsa, id_dsa, id_ecdsa, id_ed25519)
  - Database backups (backup.sql, database.sqlite)
  - IaC files (terraform.tfstate, docker-compose.yml)
  - CI/CD configs (.travis.yml, .gitlab-ci.yml)
- **Dated Backup Detection**: Intelligently tests for backup files with dates (backup-2024-01-01.sql)
- **JavaScript Mining Integration**: Extracts cloud storage URLs from JavaScript for automatic scanning

### Improved Scanner Engine
- **Context-Aware XSS Detection**: Enhanced detection with proper context handling
- **Unified SQL Injection**: Consolidated SQL injection detection with enhanced accuracy
- **Firebase Security**: Comprehensive Firebase authentication and configuration testing
- **False Positive Reduction**: Baseline detection, evidence tracking, and smart deduplication
- **Custom HTTP Methods**: Support for PURGE, BAN, and other non-standard methods

## Features

- **80+ Scanner Modules** - Comprehensive OWASP Top 10 coverage and beyond
- **Merlin JS Scanner** - Detects 100+ vulnerable JavaScript libraries with CVE mapping
- **CMS Security** - Advanced WordPress and Drupal vulnerability detection (Personal+ license)
- **Technology-Aware** - Detects 80+ frameworks, CDNs, API gateways and runs relevant tests only
- **High Performance** - Async Rust with HTTP/2 multiplexing, connection pooling
- **Low False Positives** - Evidence-based detection with baseline comparison
- **Multiple Output Formats** - JSON, HTML, SARIF, Markdown, CSV, XLSX, JUnit
- **Cloud Security** - S3, Azure Blob, GCS misconfigurations
- **CI/CD Ready** - SARIF output for GitHub Security, GitLab SAST
- **Configurable** - TOML configuration with scan profiles

## Installation

### From Source

```bash
git clone https://github.com/bountyyfi/lonkero.git
cd lonkero

# Build all binaries
cargo build --release

# Install main CLI
cargo install --path .

# Install cloud scanners (optional)
cargo install --path . --bin lonkero-aws-s3
cargo install --path . --bin lonkero-aws-ec2
cargo install --path . --bin lonkero-aws-rds
```

### Verify Installation

```bash
lonkero version
lonkero list --verbose
```

## Quick Start

### Basic Scan

```bash
# Scan a target
lonkero scan https://example.com

# Scan with HTML report
lonkero scan https://example.com -o report.html -f html

# Scan multiple targets
lonkero scan https://target1.com https://target2.com https://target3.com
```

### Authenticated Scan

```bash
# With session cookie
lonkero scan https://example.com --cookie "session=abc123"

# With bearer token
lonkero scan https://example.com --token "eyJhbGciOiJIUzI1NiIs..."

# With HTTP Basic Auth
lonkero scan https://example.com --basic-auth "admin:password"
```

### Thorough Scan

```bash
# Comprehensive scan with subdomain enumeration
lonkero scan https://example.com --mode thorough --subdomains --crawl
```

## How It Works

Lonkero executes scans in multiple phases:

### Phase 0: Reconnaissance
1. **Web Crawling** - Discovers URLs, forms, and input fields
2. **JavaScript Mining** - Extracts API endpoints, parameters, and secrets from JS files
3. **Technology Detection** - Identifies 80+ technologies:
   - Servers: Apache Tomcat, Nginx, IIS, LiteSpeed
   - JS Frameworks: Next.js, React, Vue, Angular, Qwik, Solid.js, Preact, Fresh, Hono
   - Backend: Flask, FastAPI, Gin, Fiber, Actix, Rocket, Django, Rails, Laravel
   - CDNs: Cloudflare, Fastly, Akamai, Bunny CDN, KeyCDN, StackPath
   - API Gateways: Kong, Tyk, AWS API Gateway, Azure API Management

### Phase 1: Parameter Injection Testing
Tests discovered parameters for:
- Cross-Site Scripting (XSS)
- SQL Injection (Error-based, Boolean-blind, UNION-based)
- Command Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- NoSQL Injection

### Phase 2: Security Configuration
- Security Headers analysis
- CORS misconfiguration
- CSRF protection
- Clickjacking protection

### Phase 3: Authentication Testing
- JWT vulnerabilities
- OAuth security
- SAML security
- Session management
- MFA bypass
- IDOR/BOLA

### Phase 4: API Security
- GraphQL introspection and injection
- REST API security
- gRPC security

### Phase 5: Advanced Injection (Technology-Aware)
Only runs relevant tests based on detected stack:
- SSTI (Python/PHP/Java only)
- XXE (non-Node.js stacks)
- Deserialization (PHP/Java only)
- LDAP Injection (Enterprise stacks)

### Phase 6: Protocol Testing
- HTTP Request Smuggling
- WebSocket security
- CRLF Injection
- Host Header Injection

### Phase 7: Business Logic
- Race conditions
- Mass assignment
- File upload vulnerabilities
- Open redirect
- Information disclosure

### Phase 8: Cloud Security
- Cloud storage misconfigurations
- Container security
- API Gateway security

## Scanner Modules

### Injection (16 modules)
| Module | Description |
|--------|-------------|
| xss | Cross-Site Scripting (Reflected, Stored, DOM) |
| sqli | SQL Injection (Error-based) |
| sqli_boolean | Boolean-based Blind SQL Injection |
| sqli_union | UNION-based SQL Injection |
| command_injection | OS Command Injection |
| path_traversal | Directory Traversal |
| ssrf | Server-Side Request Forgery |
| ssrf_blind | Blind SSRF with OOB callbacks |
| xxe | XML External Entity |
| ssti | Server-Side Template Injection |
| nosql | NoSQL Injection |
| ldap | LDAP Injection |
| code_injection | Code Injection (PHP, Python) |
| email_header_injection | Email Header Injection |
| http_parameter_pollution | HTTP Parameter Pollution |
| waf_bypass | Advanced WAF Bypass Techniques |

### Authentication (14 modules)
| Module | Description |
|--------|-------------|
| jwt | JWT Algorithm Confusion, Weak Secrets |
| jwt_vulnerabilities | Comprehensive JWT Analysis |
| jwt_analyzer | Deep JWT Security Analysis (alg:none, key confusion, claim tampering) |
| oauth | OAuth 2.0 Vulnerabilities |
| saml | SAML Security Issues |
| auth_bypass | Authentication Bypass |
| session_management | Session Security |
| session_analyzer | Session Fixation, Prediction, Entropy Analysis |
| mfa | MFA Bypass Detection |
| idor | Insecure Direct Object References |
| idor_analyzer | Advanced IDOR with UUID/Hash Pattern Detection |
| bola | Broken Object Level Authorization |
| advanced_auth | Advanced Authentication Testing |
| webauthn | WebAuthn/FIDO2 Security |

### Configuration (6 modules)
| Module | Description |
|--------|-------------|
| security_headers | Missing/Weak Security Headers |
| cors | CORS Misconfiguration |
| cors_misconfiguration | Advanced CORS Testing |
| clickjacking | Clickjacking Protection |
| tomcat_misconfig | Apache Tomcat Manager, Status, AJP Exposure |
| varnish_misconfig | Varnish Cache Bypass, Debug Headers, Purge Access |

### API Security (5 modules)
| Module | Description |
|--------|-------------|
| graphql | GraphQL Introspection, DoS |
| graphql_security | Advanced GraphQL Testing |
| api_security | REST/SOAP API Security |
| grpc | gRPC Security |
| api_gateway | API Gateway Misconfigurations |

### Protocol (5 modules)
| Module | Description |
|--------|-------------|
| http_smuggling | HTTP Request Smuggling |
| websocket | WebSocket Security |
| crlf_injection | CRLF Injection |
| host_header_injection | Host Header Attacks |
| http3 | HTTP/3 and QUIC Security |

### Business Logic (8 modules)
| Module | Description |
|--------|-------------|
| race_condition | Race Condition Vulnerabilities |
| business_logic | Business Logic Flaws |
| open_redirect | Open Redirect |
| mass_assignment | Mass Assignment |
| file_upload | File Upload Security |
| file_upload_vulnerabilities | Advanced File Upload Testing |
| cache_poisoning | Web Cache Poisoning |
| prototype_pollution | Prototype Pollution |

### Information Disclosure (4 modules)
| Module | Description |
|--------|-------------|
| information_disclosure | Sensitive Information Leakage |
| sensitive_data | Sensitive Data Exposure |
| js_miner | JavaScript Secret Mining |
| merlin | Vulnerable JavaScript Library Detection (100+ CVEs) |

### Specific CVE Checks (3 modules)
| Module | CVE | Severity |
|--------|-----|----------|
| cve_2025_55182 | React Server Components RCE | Critical (CVSS 10.0) |
| cve_2025_55183 | RSC Source Code Exposure | Medium (CVSS 5.3) |
| cve_2025_55184 | RSC Denial of Service | High (CVSS 7.5) |

### Server Misconfiguration (2 modules)
| Module | Description |
|--------|-------------|
| tomcat_misconfig | Tomcat Stack Traces, Manager Exposure, AJP (Ghostcat) |
| varnish_misconfig | Unauthenticated Cache Purge/Ban, Header Disclosure |

### Cloud Security (6 modules)
| Module | Description |
|--------|-------------|
| cloud_storage | S3, GCS, Azure Blob Misconfigurations |
| cloud_security | General Cloud Security |
| container | Container Security |
| framework_vulnerabilities | Framework-Specific Vulnerabilities |
| redos | Regular Expression Denial of Service |
| xml_injection | XML Injection |

## Output Formats

```bash
# JSON (default)
lonkero scan https://example.com -o results.json -f json

# HTML Report (styled, professional)
lonkero scan https://example.com -o report.html -f html

# SARIF (GitHub Security, IDE integration)
lonkero scan https://example.com -o results.sarif -f sarif

# Markdown
lonkero scan https://example.com -o report.md -f markdown

# CSV (spreadsheet import)
lonkero scan https://example.com -o results.csv -f csv

# JUnit XML (CI/CD test results)
lonkero scan https://example.com -o results.xml -f junit
```

## Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| fast | Minimal payloads, quick scan | Reconnaissance, CI/CD gates |
| normal | Balanced coverage (default) | Standard assessments |
| thorough | Comprehensive testing | Full security audits |
| insane | All payloads, maximum coverage | Research, deep testing |

```bash
lonkero scan https://example.com --mode fast
lonkero scan https://example.com --mode thorough
```

## Configuration

### Generate Configuration File

```bash
lonkero init -o lonkero.toml
```

### Configuration Example

```toml
[scanner]
mode = "normal"
concurrency = 50
timeout = 30
rate_limit = 100

[output]
format = "json"

[authentication]
cookie = "session=abc123"
# token = "Bearer eyJhbGciOiJIUzI1NiIs..."

[headers]
X-Custom-Header = "value"

[scanners]
skip = ["grpc", "websocket"]
# only = ["xss", "sqli", "ssrf"]
```

### Run with Configuration

```bash
lonkero scan https://example.com --config lonkero.toml
```

## Authentication

```bash
# Session cookie
lonkero scan https://example.com --cookie "session=abc123; csrf=token"

# Bearer token (JWT, API key)
lonkero scan https://example.com --token "eyJhbGciOiJIUzI1NiIs..."

# HTTP Basic Auth
lonkero scan https://example.com --basic-auth "username:password"

# Custom headers
lonkero scan https://example.com -H "X-API-Key: secret" -H "X-Tenant: acme"
```

## Cloud Security Scanning

### Automatic Cloud Storage Detection (NEW in v2.0)

Lonkero now automatically detects and scans cloud storage URLs during any scan:

```bash
# Regular scan automatically detects S3, Azure, GCS URLs
lonkero scan https://example.com

# If JavaScript files reference cloud storage:
# - https://bucket.s3.amazonaws.com/data.json
# - https://account.blob.core.windows.net/container
# These are automatically scanned for misconfigurations!
```

### AWS S3 Bucket Scanning

**1. Direct S3 URL Scan (auto-triggered)**
```bash
# Scan S3 bucket directly - automatically detects region and runs 90+ checks
lonkero scan https://bucket-name.s3.eu-north-1.amazonaws.com

# Works with all S3 URL formats:
lonkero scan https://bucket.s3.amazonaws.com
lonkero scan https://s3.region.amazonaws.com/bucket
```

**2. Advanced S3 Scanner (dedicated tool)**
```bash
# Public bucket scan (no credentials required)
lonkero-aws-s3 --url https://bucket-name.s3.eu-north-1.amazonaws.com/

# Scan multiple buckets
lonkero-aws-s3 --url https://bucket1.s3.us-east-1.amazonaws.com/,https://bucket2.s3.eu-west-1.amazonaws.com/

# Check for sensitive files (90+ patterns)
lonkero-aws-s3 --url https://bucket.s3.region.amazonaws.com/ --check-objects
```

**3. Authenticated Scan (requires AWS credentials)**
```bash
# Set credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# Scan your own buckets
lonkero-aws-s3 --regions us-east-1,eu-west-1
```

**Sensitive Files Checked (90+ patterns)**:
- Git: `.git/config`, `.git/HEAD`, `.github/workflows/deploy.yml`
- Environment: `.env`, `.env.local`, `.env.production`, `.env.backup`
- AWS Credentials: `.aws/credentials`, `.aws/config`, `credentials.json`
- SSH Keys: `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.pem`
- Databases: `backup.sql`, `database.sqlite`, `db.sql`
- Backups: `backup.zip`, `backup.tar.gz`, `backup-YYYY-MM-DD.sql`
- IaC: `terraform.tfstate`, `docker-compose.yml`, `kubernetes.yml`
- CI/CD: `.travis.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`

### AWS EC2 Scanning

```bash
lonkero-aws-ec2 --region us-east-1
```

### AWS RDS Scanning

```bash
lonkero-aws-rds --region us-east-1
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Lonkero
        run: cargo install --git https://github.com/bountyyfi/lonkero

      - name: Run Security Scan
        run: |
          lonkero scan ${{ secrets.TARGET_URL }} \
            --mode fast \
            -o results.sarif \
            -f sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - lonkero scan $TARGET_URL -o gl-sast-report.json -f json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Command Reference

### Main Commands

```bash
lonkero scan [OPTIONS] <TARGETS>...    # Scan targets for vulnerabilities
lonkero list [--verbose] [--category]  # List available scanner modules
lonkero validate <TARGETS>...          # Validate target URLs
lonkero init [-o <PATH>]               # Generate configuration file
lonkero version                        # Show version information
lonkero license status                 # Show license status
lonkero license activate <KEY>         # Activate license
```

### Scan Options

| Option | Description |
|--------|-------------|
| `-m, --mode` | Scan mode: fast, normal, thorough, insane |
| `-o, --output` | Output file path |
| `-f, --format` | Output format: json, html, sarif, markdown, csv, junit |
| `--subdomains` | Enable subdomain enumeration |
| `--crawl` | Enable web crawler (default: true) |
| `--max-depth` | Maximum crawl depth (default: 3) |
| `--concurrency` | Maximum concurrent requests (default: 50) |
| `--timeout` | Request timeout in seconds (default: 30) |
| `--rate-limit` | Requests per second (default: 100) |
| `--no-rate-limit` | Disable rate limiting |
| `--cookie` | Authentication cookie |
| `--token` | Bearer token |
| `--basic-auth` | HTTP Basic auth (user:pass) |
| `-H, --header` | Custom header (repeatable) |
| `--skip` | Skip scanner modules (comma-separated) |
| `--only` | Only run specific modules (comma-separated) |
| `--proxy` | Proxy URL (http://host:port) |
| `--insecure` | Disable TLS certificate verification |

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-d, --debug` | Enable debug output |
| `-q, --quiet` | Quiet mode (only vulnerabilities) |
| `-c, --config` | Configuration file path |
| `-L, --license-key` | License key |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Configuration or input error |
| 3 | Network or connection error |

## Performance

Lonkero is optimized for high-throughput scanning:

- HTTP/2 multiplexing with 100+ concurrent streams
- Connection pooling and keep-alive
- Adaptive rate limiting (auto-adjusts to target)
- DNS caching
- Response caching for duplicate requests
- Parallel scanner execution

Typical throughput:
- Fast mode: 1000+ tests/second
- Normal mode: 500+ tests/second
- Thorough mode: 100+ tests/second

## License

Copyright (c) 2025 Bountyy Oy. All rights reserved.

This software is proprietary. Commercial use requires a valid license.

Personal/non-commercial use is permitted for security research and education.

## Support

- Documentation: https://github.com/bountyyfi/lonkero
- Issues: https://github.com/bountyyfi/lonkero/issues
- Email: info@bountyy.fi
- Website: https://bountyy.fi

---

Made in Finland - Bountyy Oy
