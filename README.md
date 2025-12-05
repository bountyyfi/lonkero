# Lonkero
> ⚠️ **Alpha Release** - This software is in active development. APIs and features may change.

**Enterprise-Grade Web Security Vulnerability Scanner**

Lonkero is a high-performance, production-ready security scanner with 60+ attack modules for comprehensive web application security testing. Built in Rust for maximum performance and reliability.

```
    __                __
   / /   ____  ____  / /_____  _________
  / /   / __ \/ __ \/ //_/ _ \/ ___/ __ \
 / /___/ /_/ / / / / ,< /  __/ /  / /_/ /
/_____/\____/_/ /_/_/|_|\___/_/   \____/

        Enterprise Web Security Scanner
```

## Features

- **60+ Scanner Modules** - Comprehensive coverage of OWASP Top 10 and beyond
- **High Performance** - Async Rust with HTTP/2, connection pooling, and adaptive concurrency
- **Technology-Aware Scanning** - Detects frameworks (Next.js, React, PHP, etc.) and runs relevant tests
- **CVE Detection** - Scans for critical CVEs like CVE-2025-55182 (React RCE)
- **Multiple Output Formats** - JSON, HTML, PDF, SARIF, Markdown, CSV, XLSX, JUnit
- **Cloud Security** - AWS, Azure, GCP infrastructure scanning
- **Distributed Scanning** - Deploy agents in internal networks
- **CI/CD Integration** - SARIF output for GitHub Security, GitLab, etc.
- **Low False Positives** - Evidence-based detection to minimize noise
- **Configurable** - TOML/YAML configuration with scan profiles

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/bountyyfi/lonkero.git
cd lonkero

# Build release binary
cargo build --release

# Install to PATH
cargo install --path .
```

### Basic Usage

```bash
# Scan a single target
lonkero scan https://example.com

# Scan with HTML report output
lonkero scan https://example.com -o report.html -f html

# Thorough scan with subdomain enumeration
lonkero scan https://example.com --mode thorough --subdomains

# Multiple targets
lonkero scan https://target1.com https://target2.com https://target3.com

# Scan with authentication
lonkero scan https://example.com --cookie "session=abc123"
lonkero scan https://example.com --token "Bearer eyJhbGciOiJIUzI1NiIs..."
```

## Scanner Modules

### Injection Attacks
| Module | Description |
|--------|-------------|
| `xss` | Cross-Site Scripting (Reflected, Stored, DOM-based) |
| `sqli` | SQL Injection (Error-based, Blind, Time-based) |
| `command_injection` | OS Command Injection |
| `path_traversal` | Path/Directory Traversal |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity Injection |
| `ssti` | Server-Side Template Injection |
| `nosql` | NoSQL Injection (MongoDB, Redis) |
| `ldap` | LDAP Injection |
| `code_injection` | Code Injection (PHP, Python, Ruby) |
| `crlf` | CRLF Injection / HTTP Response Splitting |
| `xpath` | XPath Injection |
| `xml` | XML Injection |
| `ssi` | Server-Side Includes Injection |

### Authentication & Authorization
| Module | Description |
|--------|-------------|
| `jwt` | JWT Security Issues (Algorithm confusion, weak secrets) |
| `oauth` | OAuth 2.0 Vulnerabilities |
| `saml` | SAML Security Issues |
| `auth_bypass` | Authentication Bypass |
| `session` | Session Management Issues |
| `mfa` | MFA Bypass/Weaknesses |
| `idor` | Insecure Direct Object References |
| `webauthn` | WebAuthn/FIDO2 Security |

### Configuration & Headers
| Module | Description |
|--------|-------------|
| `security_headers` | Missing/Misconfigured Security Headers |
| `cors` | CORS Misconfiguration |
| `csrf` | Cross-Site Request Forgery |
| `clickjacking` | Clickjacking / UI Redressing |

### API Security
| Module | Description |
|--------|-------------|
| `graphql` | GraphQL Security (Introspection, DoS, Injection) |
| `api_security` | REST/SOAP API Security |
| `grpc` | gRPC Security |
| `api_gateway` | API Gateway Misconfigurations |

### Protocol & Transport
| Module | Description |
|--------|-------------|
| `websocket` | WebSocket Security |
| `http_smuggling` | HTTP Request Smuggling |
| `host_header` | Host Header Injection |
| `http3` | HTTP/3 and QUIC Security |

### Business Logic
| Module | Description |
|--------|-------------|
| `race_condition` | Race Condition Vulnerabilities |
| `business_logic` | Business Logic Flaws |
| `open_redirect` | Open Redirect |
| `mass_assignment` | Mass Assignment |

### Cloud Security
| Module | Description |
|--------|-------------|
| `cloud_storage` | S3, GCS, Azure Blob Misconfigurations |
| `container` | Container Security |
| `aws_ec2` | AWS EC2 Security |
| `aws_s3` | AWS S3 Bucket Security |
| `aws_rds` | AWS RDS Security |
| `aws_lambda` | AWS Lambda Security |
| `azure_storage` | Azure Storage Security |
| `azure_apim` | Azure API Management Security |
| `gcp_storage` | GCP Storage Security |

### Information Disclosure
| Module | Description |
|--------|-------------|
| `info_disclosure` | Sensitive Information Leakage |
| `sensitive_data` | Sensitive Data Exposure |
| `js_miner` | JavaScript Secret Mining |

### CVE Detection
| Module | Description |
|--------|-------------|
| `cve_2025_55182` | React Server Components RCE (CVSS 10.0) |
| `azure_apim` | Azure APIM Cross-Tenant Signup Bypass (GHSA-vcwf-73jp-r7mv) |

## Output Formats

```bash
# JSON (default)
lonkero scan https://example.com -o results.json -f json

# HTML Report
lonkero scan https://example.com -o report.html -f html

# SARIF (for GitHub Security)
lonkero scan https://example.com -o results.sarif -f sarif

# Markdown
lonkero scan https://example.com -o report.md -f markdown

# CSV
lonkero scan https://example.com -o results.csv -f csv

# JUnit XML (for CI/CD)
lonkero scan https://example.com -o results.xml -f junit
```

## Scan Modes

| Mode | Payloads | Speed | Use Case |
|------|----------|-------|----------|
| `fast` | 50 | Very Fast | Quick reconnaissance |
| `normal` | 500 | Balanced | Standard security assessment |
| `thorough` | 5000 | Slow | Comprehensive testing |
| `insane` | All | Very Slow | Full payload coverage |

```bash
lonkero scan https://example.com --mode fast      # Quick scan
lonkero scan https://example.com --mode normal    # Default
lonkero scan https://example.com --mode thorough  # Comprehensive
lonkero scan https://example.com --mode insane    # Everything
```

## Configuration

### Generate Config File

```bash
lonkero init -o lonkero.toml
```

### Sample Configuration

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
```

### Run with Config

```bash
lonkero scan https://example.com --config lonkero.toml
```

## Authentication Options

```bash
# Cookie-based auth
lonkero scan https://example.com --cookie "session=abc123; csrf=xyz"

# Bearer token
lonkero scan https://example.com --token "eyJhbGciOiJIUzI1NiIs..."

# HTTP Basic Auth
lonkero scan https://example.com --basic-auth "user:password"

# Custom headers
lonkero scan https://example.com -H "X-API-Key: secret123"
```

## Advanced Usage

### Subdomain Enumeration

```bash
lonkero scan https://example.com --subdomains
lonkero scan https://example.com --subdomains --ultra  # Thorough enumeration
```

### Web Crawling

```bash
lonkero scan https://example.com --crawl --max-depth 5
```

### Rate Limiting

```bash
lonkero scan https://example.com --rate-limit 10  # 10 req/sec
lonkero scan https://example.com --rate-limit 1000 --concurrency 100
```

### Selective Scanning

```bash
# Only specific scanners
lonkero scan https://example.com --only xss,sqli,ssrf

# Skip specific scanners
lonkero scan https://example.com --skip grpc,websocket,webauthn
```

### Proxy Support

```bash
lonkero scan https://example.com --proxy http://127.0.0.1:8080
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
      - uses: actions/checkout@v3

      - name: Run Lonkero Scan
        run: |
          lonkero scan ${{ secrets.TARGET_URL }} \
            --mode fast \
            -o results.sarif \
            -f sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
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

## Distributed Scanning

### Deploy Worker Nodes

```bash
# Start a worker connected to Redis queue
lonkero-worker --redis redis://localhost:6379
```

### Deploy Internal Agents

For scanning internal networks behind firewalls:

```bash
# Generate TLS certificates first
lonkero-agent \
  --server https://lonkero-server:8443 \
  --name "internal-agent-1" \
  --segment "dmz" \
  --tls-cert /etc/lonkero/agent-cert.pem \
  --tls-key /etc/lonkero/agent-key.pem \
  --tls-ca /etc/lonkero/ca-cert.pem
```

## Cloud Security Scanning

### AWS

```bash
# Scan AWS EC2 instances
lonkero-aws-ec2 --region us-east-1 --profile default

# Scan S3 buckets
lonkero-aws-s3 --region us-east-1

# Scan RDS instances
lonkero-aws-rds --region us-east-1
```

### Set AWS credentials via environment:

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1

lonkero-aws-s3
```

## Performance

Lonkero is optimized for high-throughput scanning:

- **HTTP/2 Multiplexing** - 100+ concurrent streams per connection
- **Connection Pooling** - Reuses connections across requests
- **Adaptive Rate Limiting** - Automatically adjusts to target limits
- **DNS Caching** - Reduces DNS lookup overhead
- **Response Caching** - Avoids duplicate requests
- **Parallel Scanners** - Runs multiple scanner modules concurrently

Typical performance on modern hardware:
- **Fast mode**: 1000+ tests/second
- **Normal mode**: 500+ tests/second
- **Thorough mode**: 100+ tests/second

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Configuration error |
| 3 | Network error |

## Command Reference

```bash
# Scan targets
lonkero scan [OPTIONS] <TARGETS>...

# List available scanners
lonkero list [--verbose] [--category <CATEGORY>]

# Validate target URLs
lonkero validate <TARGETS>...

# Generate config file
lonkero init [-o <PATH>]

# Show version
lonkero version
```

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-d, --debug` | Enable debug output |
| `-q, --quiet` | Quiet mode (only vulnerabilities) |
| `-c, --config` | Configuration file path |

### Scan Options

| Option | Description |
|--------|-------------|
| `-m, --mode` | Scan mode: fast, normal, thorough, insane |
| `-o, --output` | Output file path |
| `-f, --format` | Output format: json, html, sarif, markdown, csv |
| `--subdomains` | Enable subdomain enumeration |
| `--crawl` | Enable web crawler |
| `--max-depth` | Maximum crawl depth |
| `--concurrency` | Maximum concurrent requests |
| `--timeout` | Request timeout in seconds |
| `--rate-limit` | Requests per second limit |
| `--cookie` | Authentication cookie |
| `--token` | Bearer token |
| `--basic-auth` | HTTP Basic auth (user:pass) |
| `-H, --header` | Custom header |
| `--skip` | Skip scanner modules |
| `--only` | Only run scanner modules |
| `--proxy` | Proxy URL |
| `--insecure` | Disable TLS verification |
| `--ultra` | Enable ultra mode |

## License

Copyright (c) 2025 Bountyy Oy. All rights reserved.

This software is proprietary and confidential.

## Support

- **Email**: info@bountyy.fi
- **Issues**: https://github.com/bountyyfi/lonkero/issues

---

Made with security in mind by [Bountyy Oy](https://bountyy.fi)
