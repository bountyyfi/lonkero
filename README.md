# Lonkero

**Enterprise Web Security Scanner v2.0**

Lonkero is a high-performance security scanner built in Rust with 64+ vulnerability detection modules. Designed for professional penetration testing, security assessments, and CI/CD integration.

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

## Features

- **64+ Scanner Modules** - Comprehensive OWASP Top 10 coverage and beyond
- **Technology-Aware** - Detects frameworks (Next.js, React, PHP, Django, etc.) and runs relevant tests only
- **High Performance** - Async Rust with HTTP/2 multiplexing, connection pooling, adaptive rate limiting
- **Low False Positives** - Evidence-based detection with baseline comparison
- **CVE Detection** - Scans for critical CVEs including CVE-2025-55182, CVE-2025-55183, CVE-2025-55184
- **Multiple Output Formats** - JSON, HTML, SARIF, Markdown, CSV, XLSX, JUnit
- **Cloud Security** - AWS S3/EC2/RDS/Lambda, Azure, GCP scanning
- **CI/CD Ready** - SARIF output for GitHub Security, GitLab SAST integration
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
3. **Technology Detection** - Identifies frameworks (Next.js, React, PHP, Django, etc.)
4. **CVE Checks** - Tests for critical CVEs based on detected technology

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

### Phase 8: Cloud Security (Ultra Mode)
- Cloud storage misconfigurations
- Container security
- API Gateway security

## Scanner Modules

### Injection (14 modules)
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

### Authentication (12 modules)
| Module | Description |
|--------|-------------|
| jwt | JWT Algorithm Confusion, Weak Secrets |
| jwt_vulnerabilities | Comprehensive JWT Analysis |
| oauth | OAuth 2.0 Vulnerabilities |
| saml | SAML Security Issues |
| auth_bypass | Authentication Bypass |
| session_management | Session Security |
| mfa | MFA Bypass Detection |
| idor | Insecure Direct Object References |
| bola | Broken Object Level Authorization |
| advanced_auth | Advanced Authentication Testing |
| auth_manager | Authentication Management Flaws |
| webauthn | WebAuthn/FIDO2 Security |

### Configuration (4 modules)
| Module | Description |
|--------|-------------|
| security_headers | Missing/Weak Security Headers |
| cors | CORS Misconfiguration |
| cors_misconfiguration | Advanced CORS Testing |
| clickjacking | Clickjacking Protection |

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

### Information Disclosure (3 modules)
| Module | Description |
|--------|-------------|
| information_disclosure | Sensitive Information Leakage |
| sensitive_data | Sensitive Data Exposure |
| js_miner | JavaScript Secret Mining |

### CVE Detection (4 modules)
| Module | CVE | Severity |
|--------|-----|----------|
| cve_2025_55182 | React Server Components RCE | Critical (CVSS 10.0) |
| cve_2025_55183 | RSC Source Code Exposure | Medium (CVSS 5.3) |
| cve_2025_55184 | RSC Denial of Service | High (CVSS 7.5) |
| azure_apim | Cross-Tenant Signup Bypass | High |

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
lonkero scan https://example.com --mode thorough --ultra
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
| `--ultra` | Enable ultra mode (more thorough) |

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
- Email: support@bountyy.fi, info@bountyy.fi
- Website: https://bountyy.fi

---

Made in Finland - Bountyy Oy
