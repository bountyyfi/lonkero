# Testing Patterns

**Analysis Date:** 2026-01-30

## Test Framework

**Runner:**
- `tokio` test runtime (v1.48 with "full" features)
- Tests are co-located with source code, not in separate test directories
- Config: Implicit (no `Cargo.toml` test configuration detected beyond dev-dependencies)

**Assertion Library:**
- Standard Rust `assert!()`, `assert_eq!()`, `assert_ne!()` macros
- No external assertion library (all tests use built-in Rust assertions)

**Run Commands:**
```bash
cargo test                  # Run all tests
cargo test -- --test-threads=1      # Run tests sequentially (if needed for I/O)
cargo test -- --nocapture  # Run with output visible
cargo test {module}::{test_name}    # Run specific test
cargo test --lib          # Run library tests only
```

## Test File Organization

**Location:**
- **Co-located pattern**: Tests in same file as implementation using `#[cfg(test)]` blocks
- **No separate test directory**: All test modules are in `src/` alongside source code
- Every tested module has tests at the bottom in a `#[cfg(test)] mod tests { }` block

**Naming:**
- Test function names follow pattern: `test_{functionality}` (e.g., `test_initial_concurrency`, `test_success_recording`)
- Test module: `mod tests { }` (always named `tests`)
- Some tests prefix with behavior: `test_concurrency_increases_on_fast_responses`

**Structure:**
```
src/
├── module.rs              # Implementation + tests at bottom
│   └── #[cfg(test)] mod tests { }
├── scanners/
│   ├── csrf.rs           # Implementation + tests
│   ├── cors.rs           # Implementation + tests
│   └── mod.rs
```

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_concurrency() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        let concurrency = tracker.get_concurrency("example.com").await;
        assert_eq!(concurrency, 10);
    }
}
```

**Patterns:**
- **Setup**: Direct instantiation of objects with test-specific config:
  ```rust
  let tracker = AdaptiveConcurrencyTracker::new(10, 50);
  let config = CircuitBreakerConfig {
      failure_threshold: 3,
      success_threshold: 2,
      timeout: Duration::from_secs(5),
      half_open_max_requests: 2,
  };
  ```

- **Action**: Call the method being tested directly:
  ```rust
  tracker.record_success("example.com", Duration::from_millis(50)).await;
  ```

- **Assertion**: Use standard Rust assertions:
  ```rust
  assert_eq!(metrics.success_count, 1);
  assert!(concurrency > 10);
  assert!(metrics.avg_response_time_ms > 0.0);
  ```

- **Teardown**: Implicit - no cleanup code observed (async cleanup handled by Tokio runtime)

## Async Testing

**Pattern:** Tests using async code must be annotated with `#[tokio::test]`
- Example from `src/adaptive_concurrency.rs`:
  ```rust
  #[tokio::test]
  async fn test_success_recording() {
      let tracker = AdaptiveConcurrencyTracker::new(10, 50);

      tracker
          .record_success("example.com", Duration::from_millis(50))
          .await;

      let metrics = tracker.get_metrics("example.com").await.unwrap();
      assert_eq!(metrics.success_count, 1);
  }
  ```

- Macro `#[tokio::test]` handles async runtime setup automatically
- All await points properly handled within async functions
- Result unwrapping common pattern: `.await.unwrap()`

## Mocking

**Framework:** No explicit mocking library detected (no mockall, mocktopus, or similar in Cargo.toml)

**Patterns:**
- **Dependency Injection**: Tests construct objects with real dependencies (no mocks)
- **Direct testing**: If external dependencies needed, use Arc wrappers
- **Configuration-driven testing**: Tests pass different config to test different behaviors:
  ```rust
  let config = CircuitBreakerConfig {
      failure_threshold: 2,  // Different threshold per test
      success_threshold: 2,
      timeout: Duration::from_millis(100),
      half_open_max_requests: 2,
  };
  ```

**What to Mock:**
- HTTP responses: Would require custom implementation (not currently mocked)
- External services: Not detected in test code
- Network calls: Tests appear to avoid actual network I/O

**What NOT to Mock:**
- Core business logic: All core scanner/limiter logic is tested with real objects
- Configuration objects: Created directly for each test
- Async runtime: Tokio handles via `#[tokio::test]`

## Fixtures and Factories

**Test Data:**
- Configuration objects created inline for each test
- Example from `src/circuit_breaker.rs`:
  ```rust
  let config = CircuitBreakerConfig {
      failure_threshold: 3,
      success_count: 2,
      timeout: Duration::from_secs(5),
      half_open_max_requests: 2,
  };
  ```

- No factory pattern detected
- Duration constants used: `Duration::from_secs()`, `Duration::from_millis()`, `Duration::from_nanos()`

**Location:**
- Test fixtures defined inline within test functions
- No shared fixtures or setup functions detected
- Each test is fully self-contained

## Coverage

**Requirements:**
- No explicit coverage requirements detected in codebase
- No coverage configuration files found

**Estimated Coverage:**
- Large number of tests: 1490+ test functions identified via grep
- Core modules appear well-tested based on test file presence in all major areas
- Heavy testing in:
  - `src/adaptive_concurrency.rs` - concurrency tracking
  - `src/circuit_breaker.rs` - circuit breaker state transitions
  - `src/rate_limiter.rs` - adaptive rate limiting
  - `src/analysis/` modules - correlation and analysis
  - Configuration modules: `src/config/`

**View Coverage:**
```bash
cargo tarpaulin --out Html  # If tarpaulin is installed
# OR
cargo test --lib -- --nocapture  # To see test output
```

## Test Types

**Unit Tests:**
- **Scope**: Individual functions, types, and modules
- **Approach**: Direct function calls with specific inputs and assertions
- **Location**: Bottom of source files in `#[cfg(test)] mod tests`
- **Examples**:
  - `test_initial_concurrency()` - tests initial state
  - `test_concurrency_increases_on_fast_responses()` - tests adaptive behavior
  - `test_circuit_breaker_opens_after_failures()` - tests state machine

**Integration Tests:**
- Not explicitly organized in separate directory
- Appear to test module interactions via co-located tests
- Tests verify behavior across multiple functions (e.g., concurrency + rate limiting)
- Example: Tests that combine setting config → recording responses → checking adaptation

**E2E Tests:**
- Not detected in codebase
- No separate test runner or orchestration
- Full integration testing would likely happen at CLI level (`src/cli/main.rs`)

## Common Patterns

**Looping for State Changes:**
```rust
// From test_concurrency_increases_on_fast_responses
for _ in 0..20 {
    tracker
        .record_success("example.com", Duration::from_millis(50))
        .await;
}

let concurrency = tracker.get_concurrency("example.com").await;
assert!(concurrency > 10);
```

Pattern: Record multiple events, then verify state changed appropriately.

**Configuration-Driven Testing:**
```rust
let config = CircuitBreakerConfig {
    failure_threshold: 3,
    success_threshold: 2,
    timeout: Duration::from_secs(5),
    half_open_max_requests: 2,
};

let cb = CircuitBreaker::new(config);
// Test with this config
```

Pattern: Create different configs to test different scenarios.

**Unwrapping Results:**
```rust
let metrics = tracker.get_metrics("example.com").await.unwrap();
assert_eq!(metrics.error_count, 1);
```

Pattern: `.await.unwrap()` for infallible operations in tests.

**State Verification:**
```rust
let concurrency = tracker.get_concurrency("example.com").await;
assert!(concurrency < 10);  // Verify state changed as expected
```

Pattern: Call getter to verify internal state after operations.

## Testing Best Practices Observed

1. **Isolation**: Each test creates its own objects (no shared state)
2. **Clarity**: Test names clearly describe what's being tested
3. **Focused**: Tests check one primary assertion per test function
4. **Async-aware**: Proper use of `#[tokio::test]` for async code
5. **No external dependencies**: Tests don't require network or external services
6. **Fast execution**: Tests use `Duration::from_millis()` for quick async operations

## Known Testing Gaps

1. **No mocking library**: Tests that need to isolate from I/O (HTTP requests) likely create real clients
2. **No end-to-end tests**: No orchestrated multi-module test scenarios detected
3. **No property-based testing**: No use of quickcheck or proptest crate
4. **Limited error path testing**: Error scenarios appear underrepresented vs. happy path
5. **Scanner integration tests**: Individual scanner tests likely missing (only infrastructure modules tested)

---

*Testing analysis: 2026-01-30*
