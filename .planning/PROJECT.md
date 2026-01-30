# Lonkero Security Scanner

## What This Is

Lonkero is a professional web security scanner built in Rust for penetration testers. It performs automated vulnerability detection (XSS, SQLi, SSRF, IDOR, etc.) across web applications at scale, using proof-based detection, multi-layer analysis, and Bayesian inference for accurate vulnerability identification.

## Core Value

Accurately detect exploitable vulnerabilities without false positives — every reported vulnerability should be actionable and verifiable.

## Current Milestone: v3.10 - Detection Rate Improvements

**Goal:** Significantly improve XSS and SQLi detection rates to catch more vulnerabilities across 1M+ diverse sites.

**Target features:**
- Enhanced XSS context detection (template injection, SVG/MathML, JSON)
- Expanded encoding/bypass mutations for WAF evasion
- HTTP header injection testing for SQLi
- Framework-specific payload generation
- Improved blind detection techniques

## Requirements

### Validated

- ✓ Proof-based XSS detection (95%+ accuracy) — v3.5
- ✓ 9-technique SQLi detection (error, boolean, union, time, binary, statistical, JSON, enhanced, OOBZero) — v3.5
- ✓ Multi-layer hybrid XSS detection (differential fuzzing, taint analysis, abstract interpretation) — v3.8
- ✓ 65,000+ SQLi payloads with WAF bypasses — v3.5
- ✓ Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) — v3.5
- ✓ CSP bypass detection with known gadgets — v3.7
- ✓ Second-order injection detection — v3.6
- ✓ NoSQL injection (MongoDB) — v3.6
- ✓ Session recording and export — v3.8

### Active

(Defined in REQUIREMENTS.md for this milestone)

### Out of Scope

- Browser-based detection (Chrome/Puppeteer) — Performance overhead too high for scale
- Active exploitation/data exfiltration — Scanner is detection-only
- Authentication credential testing — Requires explicit authorization
- DoS/DDoS payloads — Destructive, not acceptable

## Context

**Current Detection Gaps (from codebase analysis):**

XSS:
- Only 16 context types supported; missing JSON, SVG animation, meta refresh
- Template injection payloads exist in CSP bypass but not systematically tested
- Weak fuzzing strategy (16 payloads per parameter, no evolution)
- No post-message handler analysis for DOM XSS
- Limited encoding mutations (no hex/octal/Unicode variations)

SQLi:
- HTTP headers (X-Forwarded-For, User-Agent) not tested as injection points
- Column enumeration limited to 20 (real-world tables have 50+)
- Stacked queries technique defined but minimal implementation
- No GraphQL-specific detection
- Missing H2, MariaDB-specific, Sybase database types

**Technical Environment:**
- Rust 1.85+ with Tokio async runtime
- 2-3 HTTP requests per parameter (proof-based approach)
- No browser dependency (fast, scalable)

## Constraints

- **Performance**: Must maintain <5 requests per parameter average
- **Accuracy**: No increase in false positive rate
- **Compatibility**: Must work without browser (headless_chrome optional)
- **Scale**: Optimized for scanning 1M+ sites

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Proof-based over fuzzing | 95%+ accuracy with 2-3 requests vs thousands | ✓ Good |
| No browser dependency | Scale and speed, headless optional | ✓ Good |
| DashMap for concurrency | Lock-free concurrent access | — Pending |

---
*Last updated: 2026-01-30 after milestone v3.10 initialization*
