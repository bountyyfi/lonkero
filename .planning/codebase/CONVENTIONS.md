# Coding Conventions

**Analysis Date:** 2026-01-30

## Naming Patterns

**Files:**
- Snake_case for all `.rs` files (`http_client.rs`, `rate_limiter.rs`, `circuit_breaker.rs`)
- Module folders are snake_case (`src/scanners/`, `src/analysis/`, `src/discovery/`)
- Scanner modules follow pattern: `src/scanners/{vulnerability_type}.rs` (e.g., `cors.rs`, `csrf.rs`, `idor.rs`)
- Nested modules: `src/scanners/hybrid_xss/` contains related implementations (`taint_analyzer.rs`, `abstract_interpreter.rs`)

**Structs/Types:**
- PascalCase for all public struct names (`HttpClient`, `CsrfScanner`, `AdaptiveConcurrencyTracker`)
- PascalCase for enum names (`ScanMode`, `Severity`, `Confidence`, `ScannerError`)
- Error enums use pattern: `{Domain}Error` (e.g., `NetworkError`, `HttpError`, `DatabaseError`)

**Functions:**
- snake_case for all function names: `pub fn new()`, `pub async fn scan()`, `fn check_forms()`, `fn extract_domain()`
- Private helper functions start with underscore if unused: `_config`, `_characteristics`
- Constructor pattern: `pub fn new()`, builder pattern: `pub fn with_rate_limiter()`, `pub fn with_cache()`
- Async functions use `pub async fn` naming pattern consistently

**Variables:**
- snake_case for all variable names: `let target_domain`, `let vulnerabilities`, `let tests_run`
- Temporary iteration variables: `i`, `j` or domain-specific names (`form_match`, `metrics`)
- Configuration/const patterns: `DEFAULT_POOL_IDLE_PER_HOST`, `MAX_BODY_SIZE`, `BROWSER_USER_AGENTS`

**Type Names:**
- Serde derive-friendly patterns: `#[serde(rename_all = "camelCase")]` for JSON serialization
- Types with lifetime parameters use `'a` pattern
- Generic parameters use single-letter names: `T`, `U`, or semantic names like `S` for state

## Code Style

**Formatting:**
- Edition 2021 Rust (declared in `Cargo.toml`: `edition = "2021"`)
- Rust standard formatting via `rustfmt` (default)
- Line length: appears to be standard (typically 100-120 characters based on source)
- Indentation: 4 spaces (Rust standard)

**Linting:**
- No explicit `.clippy.toml` or linting configuration detected
- Follows Rust standard library conventions and idioms
- Uses `#[derive(...)]` for common traits (`Debug`, `Clone`, `Serialize`, `Deserialize`)

## Import Organization

**Order:**
1. Standard library imports (`use std::...`)
2. External crate imports (`use tokio::`, `use serde::`, `use regex::`)
3. Local crate imports (`use crate::...`)
4. Conditional imports in `#[cfg(test)]` blocks

**Path Aliases:**
- No path aliases detected (no `use crate::types as T` patterns)
- All imports use fully qualified crate paths
- Example from `src/http_client.rs`:
  ```rust
  use crate::analysis::{
      ErrorType, IntelligenceBus, PatternType, ResponseAnalyzer, SecurityIndicator,
  };
  use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
  ```

**Module Organization:**
- Barrel files: `src/scanners/mod.rs`, `src/analysis/mod.rs`, `src/config/mod.rs` export public modules
- Modules are declared as `pub mod {module_name}` in parent `mod.rs`
- Submodules use `pub use` for re-exporting specific types

## Error Handling

**Patterns:**
- Use `anyhow::Result<T>` for fallible operations (imported as `use anyhow::{Context, Result}`)
- Custom error types use `thiserror` crate with `#[derive(Error, Debug)]`
- Error enums provide detailed variants with context:
  ```rust
  #[error("Network error: {0}")]
  Network(#[from] NetworkError),

  #[error("Connection timeout after {timeout:?} to {url}")]
  ConnectionTimeout { url: String, timeout: Duration },
  ```
- Logging errors during failure: `debug!()`, `info!()`, `warn!()` via `tracing` crate
- Example from `src/scanners/csrf.rs`:
  ```rust
  match self.http_client.get(url).await {
      Ok(response) => { /* process */ },
      Err(e) => {
          debug!("Failed to fetch URL for CSRF check: {}", e);
      }
  }
  ```

## Logging

**Framework:** Rust `tracing` crate (v0.1)

**Patterns:**
- `info!()` for high-level scanner progress and completion:
  - `info!("[CORS] Scanning: {}", url)` at scan start
  - `info!("[SUCCESS] [CORS] Completed {} tests, found {} issues", tests_run, vulnerabilities.len())`
- `debug!()` for detailed diagnostic information:
  - `debug!("Failed to fetch URL for CSRF check: {}", e)`
  - `debug!("Target {}: response_time={:.2}ms, concurrency={}", target_domain, ...)`
- `warn!()` for warnings (few examples, but pattern exists)
- Structured logging with context: `info!("[SCANNER_NAME] Context: {}", details)`

**Initialization:** Configured via `tracing_subscriber` with `env-filter` feature (from `Cargo.toml`):
```
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
```

## Comments

**When to Comment:**
- File-level documentation using JSDoc-style comment blocks at top of each file:
  ```rust
  /**
   * Bountyy Oy - CORS Misconfiguration Scanner
   * Tests for insecure Cross-Origin Resource Sharing configurations
   *
   * @copyright 2026 Bountyy Oy
   * @license Proprietary - Enterprise Edition
   */
  ```
- Copyright notice on all files: `// Copyright (c) 2026 Bountyy Oy. All rights reserved.`
- Inline comments for non-obvious logic: `// Exponential moving average`, `// Backoff if high error rate`
- Security-critical comments (marked with all caps): `// CRITICAL SECURITY:`, `// SECURITY WARNING:`
- Comments explaining thresholds and magic numbers:
  ```rust
  if error_rate > 0.1 {  // >10% error rate
      // ...
  }
  ```

**Documentation Comments:**
- Not heavily used (JSDoc comments are in file headers)
- Some method documentation exists but is minimal:
  ```rust
  /// Scan URL for CORS misconfigurations
  pub async fn scan(...) -> Result<...>
  ```
- No per-field struct documentation detected in type definitions

## Function Design

**Size:**
- Small focused functions: typically 20-80 lines
- Helper methods extracted as private functions (`fn check_forms()`, `fn extract_domain()`)
- Async functions encapsulate I/O operations

**Parameters:**
- Use `&self` for mutable and immutable method receivers
- String parameters passed as `&str`, URLs as `&str`
- Collections returned or modified via `&mut Vec<T>` patterns
- Configuration objects passed as `&ScanConfig`
- Builder pattern: methods return `Self` for chaining

**Return Values:**
- `Result<(Vec<Vulnerability>, usize)>` pattern for scanner operations (returns found vulnerabilities + tests run)
- `Option<T>` for nullable values (e.g., `Option<String>` for extracted domain)
- Direct value returns for simple types: `pub fn is_intelligent(&self) -> bool`
- Custom Result type: `Result<T>` (aliased via anyhow)

## Module Design

**Exports:**
- Use `pub mod {name}` in parent modules to expose submodules
- Use `pub struct`, `pub enum`, `pub fn` for public API
- Private (non-exported) items are implicitly internal
- Example from `src/lib.rs`: Each module declared as `pub mod {module_name}` to expose API

**Barrel Files:**
- `src/scanners/mod.rs`: Re-exports all scanner modules
- `src/analysis/mod.rs`: Re-exports analysis submodules
- `src/config/mod.rs`: Re-exports configuration submodules
- Barrel files do NOT use `pub use` heavily; instead rely on module declarations

**Builder Pattern:**
- HttpClient uses builder pattern: `HttpClient::new()` → `with_rate_limiter()` → `with_cache()` → etc.
- Each builder method returns `Self` to enable chaining:
  ```rust
  pub fn with_rate_limiter(mut self, rate_limiter: Arc<AdaptiveRateLimiter>) -> Self {
      self.rate_limiter = Some(rate_limiter);
      self
  }
  ```

## Type Patterns

**Configuration:**
- Structs with `#[derive(Debug, Clone)]` for immutable config objects
- Serde `#[serde(...)]` annotations for serialization/deserialization
- Default implementations: `impl Default for {Type}`

**Wrapper Types:**
- `Arc<T>` for shared ownership and thread-safety (e.g., `Arc<HttpClient>`, `Arc<AdaptiveRateLimiter>`)
- `RwLock<T>` for concurrent read-write access (e.g., `Arc<RwLock<HashMap<...>>>`)

---

*Convention analysis: 2026-01-30*
