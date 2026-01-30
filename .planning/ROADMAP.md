# Roadmap: Lonkero v3.10 - Detection Rate Improvements

## Overview

This milestone enhances Lonkero's XSS and SQLi detection capabilities through expanded payload coverage, new attack contexts, and broader database support. The roadmap progresses from foundational payloads through XSS context detection to comprehensive SQLi injection point and database coverage.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Payload Foundation** - Build comprehensive payload database
- [ ] **Phase 2: XSS Context Expansion** - Detect XSS across new contexts
- [ ] **Phase 3: SQLi Injection Points** - Test new injection vectors
- [ ] **Phase 4: SQLi Database Detection** - Expand database fingerprinting
- [ ] **Phase 5: SQLi Technique Enhancement** - Strengthen detection methods

## Phase Details

### Phase 1: Payload Foundation
**Goal**: Scanner has comprehensive payload database supporting all v3.10 detection capabilities
**Depends on**: Nothing (first phase)
**Requirements**: PAY-01, PAY-02, PAY-03, PAY-04
**Success Criteria** (what must be TRUE):
  1. Payload database contains hex, octal, Unicode, and UTF-7 encoding variations for XSS contexts
  2. Payload database includes 5+ polyglot payloads that work across HTML, JS, and attribute contexts
  3. Payload database contains database-specific payloads for H2, MariaDB, CockroachDB, and Sybase
  4. Payload database includes GraphQL-specific injection payloads with query syntax
**Plans**: TBD

Plans:
- [ ] TBD during planning

### Phase 2: XSS Context Expansion
**Goal**: Scanner detects XSS vulnerabilities across JSON, SVG, MathML, meta refresh, and template literal contexts
**Depends on**: Phase 1 (requires encoding and polyglot payloads)
**Requirements**: XSS-01, XSS-02, XSS-03, XSS-04, XSS-05, XSS-06, XSS-07
**Success Criteria** (what must be TRUE):
  1. Scanner identifies and exploits XSS in JSON API responses that get evaluated client-side
  2. Scanner detects XSS via SVG animation elements with javascript: URLs
  3. Scanner detects meta refresh XSS with javascript: protocol redirects
  4. Scanner generates and tests payloads with multiple encoding schemes per context
  5. Scanner validates polyglot payloads work across detected context boundaries
  6. Scanner detects MathML context escapes that execute JavaScript
  7. Scanner tests ES6 template literal injection contexts with appropriate payloads
**Plans**: TBD

Plans:
- [ ] TBD during planning

### Phase 3: SQLi Injection Points
**Goal**: Scanner tests HTTP headers, cookies, and GraphQL as SQLi injection vectors
**Depends on**: Phase 1 (requires GraphQL payloads)
**Requirements**: SQLI-01, SQLI-02, SQLI-03, SQLI-04
**Success Criteria** (what must be TRUE):
  1. Scanner systematically tests X-Forwarded-For, User-Agent, Referer, and X-Real-IP headers for SQLi
  2. Scanner tests cookie values as injection points with proper escaping analysis
  3. Scanner detects SQLi in GraphQL query arguments with schema-aware mutations
  4. Scanner performs enhanced JSON body injection with context-specific escape detection
**Plans**: TBD

Plans:
- [ ] TBD during planning

### Phase 4: SQLi Database Detection
**Goal**: Scanner fingerprints and exploits H2, MariaDB, CockroachDB, and Sybase databases
**Depends on**: Phase 1 (requires database-specific payloads)
**Requirements**: SQLI-07, SQLI-08, SQLI-09, SQLI-10
**Success Criteria** (what must be TRUE):
  1. Scanner identifies H2 databases via specific error patterns and functions
  2. Scanner distinguishes MariaDB from MySQL using version-specific behavior
  3. Scanner detects CockroachDB through PostgreSQL-compatible error differences
  4. Scanner identifies Sybase/SAP ASE via unique error messages and syntax
**Plans**: TBD

Plans:
- [ ] TBD during planning

### Phase 5: SQLi Technique Enhancement
**Goal**: Scanner performs deeper exploitation through extended column enumeration and stacked queries
**Depends on**: Phase 4 (requires database fingerprinting for technique selection)
**Requirements**: SQLI-05, SQLI-06
**Success Criteria** (what must be TRUE):
  1. Scanner tests UNION-based injection with up to 50 columns for wide tables
  2. Scanner executes stacked queries on MSSQL and PostgreSQL with proper timing analysis
  3. Scanner adapts stacked query syntax based on detected database type
**Plans**: TBD

Plans:
- [ ] TBD during planning

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Payload Foundation | 0/TBD | Not started | - |
| 2. XSS Context Expansion | 0/TBD | Not started | - |
| 3. SQLi Injection Points | 0/TBD | Not started | - |
| 4. SQLi Database Detection | 0/TBD | Not started | - |
| 5. SQLi Technique Enhancement | 0/TBD | Not started | - |

---
*Roadmap created: 2026-01-30*
*Last updated: 2026-01-30*
