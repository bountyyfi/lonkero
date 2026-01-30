# Requirements: Lonkero v3.10 - Detection Rate Improvements

**Defined:** 2026-01-30
**Core Value:** Accurately detect exploitable vulnerabilities without false positives

## v3.10 Requirements

Requirements for this milestone. Each maps to roadmap phases.

### XSS Detection Improvements

- [ ] **XSS-01**: Scanner detects XSS in JSON response contexts (API responses that get eval'd/innerHTML'd client-side)
- [ ] **XSS-02**: Scanner detects SVG animation XSS (`<animate>`, `<set>`, `<animateMotion>` with javascript: URLs)
- [ ] **XSS-03**: Scanner detects Meta Refresh XSS (`<meta http-equiv="refresh" content="0;url=javascript:...">`)
- [ ] **XSS-04**: Scanner generates encoding mutation payloads (hex `\x3c`, octal `\74`, Unicode `\u003c`, UTF-7 `+ADw-`)
- [ ] **XSS-05**: Scanner includes polyglot payloads that work across multiple contexts (HTML, JS, attribute)
- [ ] **XSS-06**: Scanner detects MathML XSS (`<math><mtext>` context escapes)
- [ ] **XSS-07**: Scanner has expanded template literal payloads for ES6 contexts (`` `${...}` ``)

### SQLi Detection Improvements

- [ ] **SQLI-01**: Scanner tests HTTP headers as injection points (X-Forwarded-For, User-Agent, Referer, X-Real-IP)
- [ ] **SQLI-02**: Scanner tests cookies as injection points systematically
- [ ] **SQLI-03**: Scanner detects SQLi in GraphQL query arguments (`query { user(id: "1' OR '1'='1") }`)
- [ ] **SQLI-04**: Scanner has enhanced JSON body injection with proper escape analysis
- [ ] **SQLI-05**: Scanner tests UNION-based with up to 50 columns (increased from 20)
- [ ] **SQLI-06**: Scanner fully implements stacked queries technique for MSSQL, PostgreSQL
- [ ] **SQLI-07**: Scanner detects H2 database (common in Java apps) with specific payloads
- [ ] **SQLI-08**: Scanner distinguishes MariaDB from MySQL with database-specific payloads
- [ ] **SQLI-09**: Scanner detects CockroachDB (PostgreSQL-compatible but different errors)
- [ ] **SQLI-10**: Scanner detects Sybase/SAP ASE with specific error patterns

### Payload Database

- [ ] **PAY-01**: Payload database includes all new encoding variations (hex, octal, Unicode, UTF-7)
- [ ] **PAY-02**: Payload database includes polyglot XSS payloads (5+ variations)
- [ ] **PAY-03**: Payload database includes H2, MariaDB, CockroachDB, Sybase-specific payloads
- [ ] **PAY-04**: Payload database includes GraphQL injection payloads

## Future Requirements

Deferred to later milestones.

### XSS Differentiators (v3.11+)
- **XSS-F01**: Mutation-based fuzzing with genetic algorithm
- **XSS-F02**: CSP-aware payload generation based on parsed CSP header
- **XSS-F03**: Framework-specific XSS (React dangerouslySetInnerHTML, Vue v-html, Angular bypass)
- **XSS-F04**: PostMessage handler analysis for DOM XSS
- **XSS-F05**: Storage-based XSS (localStorage/sessionStorage to DOM sinks)

### SQLi Differentiators (v3.11+)
- **SQLI-F01**: DNS timing for WAF bypass (measure DNS resolution vs SLEEP)
- **SQLI-F02**: WebSocket SQLi testing
- **SQLI-F03**: Enhanced second-order SQLi with multi-page flow tracking
- **SQLI-F04**: Stored procedure enumeration and testing

## Out of Scope

Explicitly excluded from this milestone.

| Feature | Reason |
|---------|--------|
| Blind XSS via Email | Requires email monitoring infrastructure, slow feedback |
| Every Unicode variation | 1M+ characters = performance nightmare; use curated list |
| Browser automation for all tests | 300x slower; only for thorough mode confirmation |
| Data exfiltration | Detection only, not exploitation |
| Active SQL commands (DROP, DELETE) | Destructive, not acceptable for scanning |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| PAY-01 | Phase 1 | Pending |
| PAY-02 | Phase 1 | Pending |
| PAY-03 | Phase 1 | Pending |
| PAY-04 | Phase 1 | Pending |
| XSS-01 | Phase 2 | Pending |
| XSS-02 | Phase 2 | Pending |
| XSS-03 | Phase 2 | Pending |
| XSS-04 | Phase 2 | Pending |
| XSS-05 | Phase 2 | Pending |
| XSS-06 | Phase 2 | Pending |
| XSS-07 | Phase 2 | Pending |
| SQLI-01 | Phase 3 | Pending |
| SQLI-02 | Phase 3 | Pending |
| SQLI-03 | Phase 3 | Pending |
| SQLI-04 | Phase 3 | Pending |
| SQLI-07 | Phase 4 | Pending |
| SQLI-08 | Phase 4 | Pending |
| SQLI-09 | Phase 4 | Pending |
| SQLI-10 | Phase 4 | Pending |
| SQLI-05 | Phase 5 | Pending |
| SQLI-06 | Phase 5 | Pending |

**Coverage:**
- v3.10 requirements: 21 total
- Mapped to phases: 21 (100%)
- Unmapped: 0

---
*Requirements defined: 2026-01-30*
*Last updated: 2026-01-30 after roadmap creation*
