# Technology Stack for Enhanced XSS/SQLi Detection

**Project:** Lonkero Security Scanner - XSS/SQLi Improvements
**Researched:** 2026-01-30
**Confidence:** MEDIUM (WebSearch unavailable - recommendations based on training data + codebase analysis)

## Executive Summary

Based on analysis of the existing codebase (Lonkero v3.9), the scanner already implements:
- Proof-based XSS detection (reflection + context analysis)
- Multi-technique SQLi (error-based, boolean-blind, time-based, UNION)
- Template injection detection (Jinja2, Twig, etc.)
- Comprehensive payload libraries (100K+ XSS, 65K+ SQLi payloads)

**Gaps identified:**
- XSS: Template injection payloads limited, weak encoding mutation library, no polyglot generators
- SQLi: HTTP headers not tested, column enumeration basic, missing modern DB versions (CockroachDB, ClickHouse)
- Payload generation: Static payloads, no context-aware mutation engine
- Fuzzing: Basic iteration, no grammar-based or feedback-driven fuzzing

**Recommendation:** Add specialized Rust crates for mutation/fuzzing and external payload databases, NOT full rewrite.

---

## Recommended Stack Additions

### XSS Enhancement Crates

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `html5ever` | 0.27+ | HTML parsing/context detection | **Why:** Current context detection uses regex (error-prone). html5ever parses HTML into proper DOM tree, enabling accurate context detection for attributes, event handlers, script tags. **Integration:** Replace regex-based context detection in `proof_xss_scanner.rs` with tree-based parsing. |
| `swc_ecma_parser` | 0.153+ | JavaScript AST parsing | **Why:** Current DOM XSS detection uses regex for JS (lines 1038-1150 in proof_xss_scanner.rs). AST parsing enables accurate sink/source taint flow analysis. **Integration:** Replace regex patterns with proper data flow analysis. |
| `encoding_rs` | 0.8+ | Character encoding mutations | **Why:** XSS often bypasses filters via encoding (UTF-7, UTF-16, etc.). Current scanner lacks encoding mutation. **Integration:** Add encoding mutation layer to payload generation. |

**Decision rationale:** Existing XSS scanner (proof_xss_scanner.rs) has 99% accuracy for HTML contexts but uses regex for parsing. Upgrading to proper parsers catches edge cases (self-closing tags, malformed HTML, nested contexts).

### SQLi Enhancement Crates

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `sqlparser` | 0.52+ | SQL AST parsing | **Why:** Enables intelligent UNION column count detection by parsing database schema hints from error messages. **Integration:** Replace MAX_COLUMNS iteration (currently 20) with schema-aware enumeration. |
| `http` | 1.1+ (already present via reqwest) | HTTP header injection testing | **Why:** SQLi scanner only tests URL parameters. Many apps read SQL from User-Agent, Referer, X-Forwarded-For headers. **Integration:** Add header injection module to sqli_enhanced.rs. |

**Decision rationale:** Current SQLi scanner (sqli_enhanced.rs) is comprehensive for URL params but misses HTTP header attack surface. UNION technique iterates 1-20 columns blindly - schema parsing would be smarter.

### Payload Generation & Mutation

| Library | Version | Purpose | Integration |
|---------|---------|---------|-------------|
| `radamsa` (external) | 0.6+ | Mutation-based fuzzing | **Why:** Generate XSS/SQLi variants from seed payloads. **How:** Call via FFI or process spawn. Mutate base payloads before injection. |
| `grammarinator` (Python, optional) | 2023.1+ | Grammar-based fuzzing | **Why:** Generate syntactically valid SQL/HTML/JS mutations. **How:** Pre-generate corpus, load into Rust scanner. |

**Decision:** Use `radamsa` Rust bindings if available, otherwise spawn process. Grammar-based fuzzing is overkill unless scanning 1M+ sites reveals major gaps.

### Payload Databases (External)

These are NOT Rust crates - they're payload corpuses to import.

| Database | Size | Purpose | How to Integrate |
|----------|------|---------|------------------|
| **PayloadsAllTheThings** (GitHub) | ~15K XSS, ~8K SQLi | Community-maintained modern payloads | Clone repo, parse markdown, extract payloads, deduplicate with existing 100K corpus. Focus on 2024-2026 additions. |
| **FuzzDB** (archived but useful) | ~3K XSS, ~5K SQLi | Historical attack patterns | Parse and merge. Mark as "legacy" - useful for old frameworks. |
| **SecLists** | ~20K combined | OWASP-maintained | Parse `Fuzzing/` and `Injection/` directories. Filter polyglots into dedicated collection. |

**Recommendation:** Create `payloads_external.rs` module that loads these at build time (embedded with `include_str!` macro). Deduplicate against existing `payloads_comprehensive.rs`.

**Why external databases:** Current scanner has 100K+ payloads but static. External DBs provide:
- Modern framework bypasses (Next.js, Nuxt, SvelteKit edge cases)
- CSP bypass techniques (nonce extraction, JSONP, etc.)
- Database-specific SQLi (ClickHouse operators, CockroachDB quirks)

---

## What NOT to Add

### ❌ Avoid These Dependencies

| Technology | Why NOT |
|------------|---------|
| **headless_chrome** (for XSS) | Already present but v3.9 removed Chrome dependency for XSS. Don't reintroduce - proof-based approach is 300x faster. Keep Chrome only for SPA form discovery. |
| **AI/LLM payload generation** | Adds 500MB+ model files, unpredictable outputs, high latency. Current 100K corpus is sufficient. |
| **Full fuzzing frameworks (AFL, LibFuzzer)** | These are for binary fuzzing, not web app scanning. Radamsa is sufficient for mutation. |
| **Full JavaScript engine (V8, Deno)** | Current DOM XSS uses static analysis (regex). Upgrading to `swc_ecma_parser` AST is sufficient. Running full JS engine adds 50MB+ and execution risk. |

---

## Database-Specific Payloads

Current scanner supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite (lines 35-42 in sqli_enhanced.rs).

### Add Support For:

| Database | Version | Key Payloads | Rationale |
|----------|---------|--------------|-----------|
| **CockroachDB** | 23.x+ | `SHOW DATABASES`, `RETURNING` clause injection | Growing adoption in cloud-native apps. Similar to PostgreSQL but different errors. |
| **ClickHouse** | 24.x+ | `FORMAT JSON` injection, `clickhouse://` URL handlers | Popular for analytics. Uses custom SQL dialect. |
| **MariaDB** | 11.x+ | `RETURNING` (new in 10.5+), `JSON_TABLE` | Fork of MySQL with new features. |
| **TimescaleDB** | 2.x+ | Time-series specific functions like `time_bucket()` | PostgreSQL extension but different errors. |

**Implementation:** Add new `DatabaseType` variants and error signature patterns in `detect_database_type()` function.

---

## Encoding & Mutation Library

Current scanner lacks encoding mutation engine. Add:

### Character Encoding Mutations

```rust
// New module: src/encoding_mutations.rs
use encoding_rs::{UTF_7, UTF_16LE, UTF_16BE, WINDOWS_1252, ISO_8859_1};

pub fn mutate_payload_encodings(payload: &str) -> Vec<String> {
    vec![
        // UTF-7 (legacy but still bypasses some WAFs)
        encode_utf7(payload),
        // UTF-16 (bypasses byte-based filters)
        encode_utf16le(payload),
        encode_utf16be(payload),
        // Double encoding
        double_url_encode(payload),
        // Mixed case encoding (%41 = A, %61 = a)
        mixed_case_encode(payload),
        // Unicode normalization attacks
        nfc_normalize(payload),
        nfkc_normalize(payload),
    ]
}
```

**Rationale:** Many WAFs (Cloudflare, AWS WAF) use byte-based pattern matching. Character encoding mutations bypass these. Current scanner only does URL encoding (basic).

### Polyglot Payloads

XSS/SQLi payloads that work in multiple contexts:

```
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

**Implementation:** Add `polyglots.rs` module with 100+ tested polyglots from PayloadsAllTheThings and PortSwigger Research.

---

## HTTP Header Injection for SQLi

Current SQLi scanner only tests URL parameters. Add HTTP header testing:

### Headers to Test

| Header | Why Test | Example Payload |
|--------|----------|-----------------|
| `User-Agent` | Often logged to database | `Mozilla/5.0' OR '1'='1` |
| `Referer` | Logged for analytics | `https://evil.com/' UNION SELECT NULL--` |
| `X-Forwarded-For` | IP logging | `127.0.0.1' AND SLEEP(5)--` |
| `X-Real-IP` | Similar to X-Forwarded-For | `1.1.1.1' OR '1'='1` |
| `Cookie` | Session/tracking cookies | `sessionid=abc' OR '1'='1--` |
| `Accept-Language` | Localization queries | `en' OR '1'='1--` |

**Implementation:**
```rust
// In sqli_enhanced.rs, add new function:
async fn scan_http_headers(
    &self,
    url: &str,
    headers_to_test: Vec<&str>,
) -> Result<Vec<Vulnerability>> {
    // For each header, inject SQLi payloads
    // Use same techniques: error-based, boolean-blind, time-based
}
```

---

## Template Injection Improvements

Current scanner (template_injection.rs) has basic payloads for Jinja2, Twig, etc.

### Add Template Engines

| Engine | Framework | Payloads Needed |
|--------|-----------|-----------------|
| **Liquid** | Ruby/Jekyll | `{% assign x = "ls" %}{{ x | system }}` |
| **Nunjucks** | Node.js | `{{range.constructor("return process")()}}` |
| **Thymeleaf** | Java/Spring | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| **Razor** | .NET | `@System.Diagnostics.Process.Start("cmd")` |

**Rationale:** Current scanner only covers 8 engines (lines 116-189 in template_injection.rs). These 4 are common in 2025-2026 stacks.

---

## Fuzzing Strategy

Current scanner uses static payload iteration. Add feedback-driven fuzzing:

### Feedback-Driven Fuzzing

```rust
// New module: src/fuzzing/feedback_driven.rs

pub struct FeedbackFuzzer {
    coverage_map: HashMap<String, u32>, // Track which responses we've seen
    mutation_engine: RadamsaEngine,
}

impl FeedbackFuzzer {
    pub fn fuzz_parameter(&mut self, base_payload: &str) -> Vec<String> {
        let mut candidates = Vec::new();

        // Generate mutations
        for _ in 0..100 {
            let mutated = self.mutation_engine.mutate(base_payload);

            // Only keep mutations that might produce new behavior
            if self.is_novel_mutation(&mutated) {
                candidates.push(mutated);
            }
        }

        candidates
    }

    fn is_novel_mutation(&self, payload: &str) -> bool {
        // Check if this mutation has similar structure to previously tested payloads
        // Avoids testing near-duplicate payloads
        let signature = self.compute_signature(payload);
        !self.coverage_map.contains_key(&signature)
    }
}
```

**Rationale:** Current scanner tests all 100K+ payloads sequentially. Feedback fuzzing reduces this to ~1K high-value mutations per parameter.

---

## Column Enumeration for UNION SQLi

Current approach (sqli_enhanced.rs line 31):
```rust
const MAX_COLUMNS: usize = 20;
```

This iterates 1-20 blindly. Improve with:

### Adaptive Column Detection

```rust
async fn detect_column_count_adaptive(
    &self,
    url: &str,
    param: &str,
) -> Result<usize> {
    // Binary search for column count
    let mut low = 1;
    let mut high = 50; // Increase max

    while low < high {
        let mid = (low + high) / 2;
        let payload = format!("' UNION SELECT {nulls}--",
            nulls = "NULL,".repeat(mid).trim_end_matches(','));

        let response = self.test_payload(url, param, &payload).await?;

        if response.indicates_correct_column_count() {
            return Ok(mid);
        } else if response.indicates_too_few_columns() {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    Ok(low)
}
```

**Rationale:** Reduces 20 requests to ~6 (log2(50)) for column detection.

---

## Confidence Assessment

| Component | Confidence | Reasoning |
|-----------|------------|-----------|
| **HTML/JS Parsers** | HIGH | `html5ever` and `swc_ecma_parser` are well-established Rust crates. Used by Firefox and deno. |
| **Encoding Mutations** | HIGH | `encoding_rs` is Mozilla's official encoding library. |
| **SQLi Headers** | HIGH | HTTP header injection is documented attack vector (OWASP). |
| **External Payloads** | MEDIUM | PayloadsAllTheThings/SecLists updated regularly, but quality varies. Need manual curation. |
| **Fuzzing (Radamsa)** | MEDIUM | Radamsa effective for mutation fuzzing, but Rust bindings may be outdated. May need process spawning. |
| **New Databases** | MEDIUM | CockroachDB/ClickHouse gaining adoption, but payload effectiveness untested at scale. |
| **Adaptive Column Detection** | LOW | Binary search for columns is theory - may have false positives. Needs validation. |

---

## Implementation Priority

### Phase 1: High ROI, Low Effort
1. **HTTP header SQLi testing** - Copy existing techniques to headers (1-2 days)
2. **Import PayloadsAllTheThings** - Parse and deduplicate (1 day)
3. **Add encoding mutations** - Integrate `encoding_rs` (2-3 days)

### Phase 2: Moderate ROI, Moderate Effort
4. **Upgrade to html5ever parsing** - Replace regex context detection (3-5 days)
5. **Add new template engines** - 4 engines, 50 payloads each (2-3 days)
6. **New database support** - CockroachDB, ClickHouse signatures (2 days)

### Phase 3: Lower ROI, Higher Effort
7. **JavaScript AST parsing** - Integrate `swc_ecma_parser` for DOM XSS (5-7 days)
8. **Feedback-driven fuzzing** - Radamsa integration (3-5 days)
9. **Adaptive column detection** - Binary search UNION (2-3 days)

**Total estimated effort:** 21-35 days for all phases.

---

## Integration Notes

### Dependency Management

Add to `Cargo.toml`:
```toml
[dependencies]
# XSS enhancements
html5ever = "0.27"
markup5ever_rcdom = "0.3"  # DOM tree for html5ever
swc_ecma_parser = "0.153"
swc_common = "0.35"
encoding_rs = "0.8"

# SQLi enhancements
sqlparser = "0.52"

# Mutation fuzzing (if Rust bindings exist, otherwise spawn process)
# radamsa = "0.6"  # May not exist - check crates.io
```

### Payload Loading Strategy

Current scanner embeds payloads at compile time (100K+ strings). Adding more will bloat binary.

**Options:**
1. **Compile-time embedding** - Easy, but increases binary size (+5-10MB)
2. **Runtime loading** - Load from `payloads/` directory on disk
3. **Lazy static** - Use `once_cell` to load on first use

**Recommendation:** Compile-time for core payloads, runtime for extended corpus. Use feature flags:
```toml
[features]
default = ["core-payloads"]
extended-payloads = []  # Loads 200K+ from disk
```

---

## Testing Strategy

### Validation Corpus

Before deploying new payloads:
1. **False positive test** - Run against legitimate sites (with permission)
2. **True positive test** - Deploy intentionally vulnerable apps (DVWA, WebGoat, etc.)
3. **Performance test** - Measure scan time increase vs detection improvement

### Success Metrics

- **Detection rate:** +10-15% true positives on DVWA/WebGoat
- **False positive rate:** <5% (current baseline)
- **Scan time:** <2x increase (acceptable for +15% detection)

---

## Sources

### Crate Documentation
- html5ever: https://docs.rs/html5ever/ (HTML parsing standard)
- swc_ecma_parser: https://docs.rs/swc_ecma_parser/ (JavaScript AST)
- encoding_rs: https://docs.rs/encoding_rs/ (Mozilla encoding library)
- sqlparser: https://docs.rs/sqlparser/ (SQL parsing)

### Payload Databases
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists: https://github.com/danielmiessler/SecLists
- FuzzDB: https://github.com/fuzzdb-project/fuzzdb

### Research References
- PortSwigger Web Security Academy (XSS/SQLi research)
- OWASP Testing Guide v4.2 (injection testing methodology)

### Confidence Note
**WebSearch was unavailable** - recommendations based on:
1. Analysis of existing Lonkero codebase (v3.9)
2. Training data on Rust security libraries (Jan 2025 cutoff)
3. Standard web security testing practices (OWASP)

**Validation needed:** Crate versions, payload DB updates, Radamsa Rust bindings availability.

---

## Summary

**Add 5 Rust crates** (html5ever, swc_ecma_parser, encoding_rs, sqlparser) to improve parsing accuracy.

**Import 3 external payload databases** (PayloadsAllTheThings, SecLists, FuzzDB) for modern bypass techniques.

**Implement 4 new capabilities:**
1. HTTP header SQLi testing
2. Encoding mutation engine
3. Adaptive column detection
4. Feedback-driven fuzzing

**Avoid:** Chrome re-introduction, AI models, full fuzzing frameworks, JavaScript engines.

**Estimated impact:** +10-15% detection rate, <2x scan time, maintains <5% false positives.
