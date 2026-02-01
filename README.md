<div align="center">

<img src="https://bountyyfi.s3.eu-north-1.amazonaws.com/lonkero.png" alt="Lonkero" width="180"/>

# Lonkero

**Web security scanner that finds what others miss.**

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-3.9.0-green.svg)](https://github.com/bountyyfi/lonkero)
[![Release](https://github.com/bountyyfi/lonkero/actions/workflows/release.yml/badge.svg)](https://github.com/bountyyfi/lonkero/actions/workflows/release.yml)

130+ scanners · 5% false positives · No browser required · Zero OOB infrastructure

[Website](https://lonkero.bountyy.fi/en) · [Docs](#quick-start) · [Discussions](https://github.com/bountyyfi/lonkero/discussions)

</div>

---

## Install

```bash
cargo install lonkero
```

Or grab a binary from [releases](https://github.com/bountyyfi/lonkero/releases).

---

## Scan

```bash
lonkero scan https://target.com
```

No mode flags. No config files. Intelligent mode figures out what to test.

---

## What Makes It Different

### Proof-Based XSS Detection

No browser. No Chrome crashes. Just math.

Send a canary, send a probe with `"'<>`, analyze what gets escaped in what context. If the context is exploitable and escaping is insufficient, that's XSS. Mathematical proof, not execution.

- 2-3 requests per parameter (vs 100+ with browser)
- ~200ms per URL (vs 60+ seconds)
- 16 reflection contexts detected
- 99% accuracy on reflected XSS

### Zero-Infrastructure Blind SQLi

Everyone else needs callback servers. We use timing correlation.

```
SLEEP(0) → baseline
SLEEP(1) → +1000ms
SLEEP(2) → +2000ms
SLEEP(5) → +5000ms

Pearson r > 0.95 = confirmed SQLi
```

Binary search extraction: 7 requests per character. Pull actual data from the database. That's not inference, that's proof.

### Intelligent Scanning

When we detect Django, we test PostgreSQL injection and Django-specific paths. When we detect Next.js, we mine routes from JS bundles and test middleware bypass.

When we can't detect the stack? We run MORE scanners, not fewer. 35+ fallback scanners cover the unknown.

### Low False Positives

5% FP rate vs industry 20-30%. How:

- Differential analysis (compare responses, not just status codes)
- SQL error pattern matching (require actual SQL indicators, not just "response changed")
- XSS reflection checks (don't report SQLi when payload is just reflected)
- ML auto-learning from every scan

---

## Scanners

**Injection** (31): SQLi, XSS, XXE, NoSQL, Command Injection, LDAP, XPath, SSRF, Template Injection, Prototype Pollution, Log4j, DOM Clobbering, Second-Order Injection

**Auth** (28): JWT, OAuth, OIDC, SAML, MFA Bypass, Session attacks, IDOR, BOLA, BFLA, Account Takeover, Password Reset Poisoning, Cognito Enumeration

**API** (20): GraphQL (introspection, batching, aliases), gRPC, WebSocket, Rate Limit Bypass, CORS, Cache Poisoning, HTTP Smuggling

**Frameworks** (15): Next.js, React, Django, Laravel, WordPress, Drupal, Spring Boot, Rails, Express, Angular

**Business Logic** (8): Race Conditions, Payment Bypass, File Upload (polyglots, zip slip), Mass Assignment

**Specialized** (10): CVE Detection, Subdomain Takeover, ArcGIS PII Detection, ReDoS, Google Dorking

---

## Features

**Tech Detection** → Scanners adapt to detected framework
**Route Discovery** → Extract routes from Next.js/React bundles
**Smart Filtering** → Skip CSRF tokens, pagination, React internals (80% fewer requests)
**Fallback Layer** → Unknown tech = more tests, not fewer
**Scanner Communication** → Scanners share discoveries in real-time
**Attack Chaining** → Multi-step exploit path planning
**ML Learning** → Auto-learns from every scan, optional federated mode

---

## Output

```bash
lonkero scan https://target.com --format json -o report.json
lonkero scan https://target.com --format pdf -o report.pdf
lonkero scan https://target.com --format sarif -o results.sarif  # GitHub Security
lonkero scan https://target.com --format html -o report.html
```

---

## Examples

```bash
# With crawling
lonkero scan https://target.com --crawl

# Maximum payloads (12,450+ XSS)
lonkero scan https://target.com --payload-intensity maximum

# With auth
lonkero scan https://target.com --cookie "session=abc123"
lonkero scan https://target.com --header "Authorization: Bearer token"

# Multi-role testing (BOLA/BFLA)
lonkero scan https://target.com \
  --auth-username user@test.com --auth-password pass1 \
  --admin-username admin@test.com --admin-password pass2

# Specific scanners only
lonkero scan https://target.com --only sqli_enhanced,xss_enhanced,ssrf
```

---

## CI/CD

**GitHub Actions:**
```yaml
- run: lonkero scan ${{ vars.STAGING_URL }} --format sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

**GitLab:**
```yaml
lonkero-scan:
  script: lonkero scan $CI_ENVIRONMENT_URL --format json -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Comparison

| | Lonkero | Burp Pro | ZAP | Acunetix |
|---|---|---|---|---|
| False Positives | 5% | 10-15% | 20-30% | 10-15% |
| Browser Required | No | Optional | Optional | Yes |
| Blind SQLi Infra | None | Collaborator | None | OOB server |
| ML Learning | Yes | No | No | No |
| Modern Frameworks | Native | Extension | Limited | Limited |

---

## v3.9 Changes

- **SQLi differential analysis**: Require actual SQL error patterns before reporting. Eliminates false positives on sites that just reflect input.
- **Second-Order Injection scanner**: Stores payloads in one endpoint, detects execution in another.
- **RSS/Atom feed discovery**: XML XSS vectors via feed endpoints.

---

## Links

- [Website](https://lonkero.bountyy.fi/en)
- [Issues](https://github.com/bountyyfi/lonkero/issues)
- [Discussions](https://github.com/bountyyfi/lonkero/discussions)
- [Email](mailto:info@bountyy.fi)

---

<div align="center">

**Bountyy Oy** · Helsinki, Finland

*Lonkero = Finnish for "tentacle"*

</div>
