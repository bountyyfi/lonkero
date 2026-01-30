# Technology Stack

**Analysis Date:** 2026-01-30

## Languages

**Primary:**
- Rust 1.85+ - Entire codebase, security scanner application

**Secondary:**
- None detected

## Runtime

**Environment:**
- Rust (compiled binary, no external runtime required)

**Package Manager:**
- Cargo (Rust)
- Lockfile: Present (`Cargo.lock`)

## Frameworks

**Core:**
- Tokio 1.48 - Asynchronous runtime with full features including tracing
- Reqwest 0.12.28 - HTTP client with HTTP/2, cookies, JSON support
- Clap 4.5.52 - Command-line argument parsing with derive macros

**Testing:**
- None explicitly configured (testing via `#[cfg(test)]` modules within files)

**Build/Dev:**
- Cross 0.2+ - Cross-platform compilation (aarch64-unknown-linux-gnu targets, see `Cross.toml`)

## Key Dependencies

**Critical:**
- `tokio-postgres` 0.7.15 - PostgreSQL database driver with connection pooling
- `deadpool-postgres` 0.14.1 - Connection pool for PostgreSQL
- `deadpool-redis` 0.22 - Connection pool for Redis queue management
- `headless_chrome` 1.0 - Headless browser for JavaScript rendering and form detection
- `tokio-tungstenite` 0.28 - WebSocket client for real-time protocol testing
- `ssh2` 0.9 - SSH client for secure authenticated scanning

**Security & Cryptography:**
- `hmac` 0.12 - HMAC authentication
- `sha2` 0.10 - SHA-256 hashing
- `blake3` 1.8 - Quantum-safe cryptographic hashing
- `keyring` 3.6.3 - OS keychain integration for credential storage
- `native-tls` 0.2 + `tokio-native-tls` 0.3 - TLS support for secure connections

**Infrastructure:**
- `hickory-resolver` 0.25 - Asynchronous DNS resolution (modern fork of trust-dns)
- `moka` 0.12 - In-memory caching with async support
- `governor` 0.10 - Token bucket rate limiting
- `lettre` 0.11 - SMTP email delivery (with Tokio 1 + Rustls TLS)
- `csv` 1.3 - CSV report generation
- `rust_xlsxwriter` 0.92.3 - Excel/XLSX report generation
- `flate2` 1.1 - Compression for session recordings

**Data & Serialization:**
- `serde` 1.0 - Serialization framework
- `serde_json` 1.0 - JSON serialization
- `serde_yaml` 0.9 - YAML configuration parsing
- `toml` 0.9 - TOML configuration parsing
- `chrono` 0.4 - Date/time handling with serde support

**HTML/URL Processing:**
- `scraper` 0.25 - HTML parsing and CSS selectors
- `html-escape` 0.2 - HTML entity escaping
- `url` 2.5 - URL parsing and manipulation
- `urlencoding` 2.1 - URL encoding/decoding
- `regex` 1.10 - Regular expressions for pattern matching

**Observability & Error Handling:**
- `tracing` 0.1 - Distributed tracing framework
- `tracing-subscriber` 0.3 - Logging backend with JSON output and environment filtering
- `tracing-log` 0.2 - Bridge from log macros to tracing
- `anyhow` 1.0 - Error context handling
- `thiserror` 2.0.17 - Structured error types

**Utilities:**
- `uuid` 1.18.1 - UUID generation (v4 support)
- `rand` 0.9 - Random number generation
- `ahash` 0.8 - Fast hashing algorithms
- `rayon` 1.10 - Data parallelism
- `parking_lot` 0.12 - Optimized synchronization primitives
- `once_cell` 1.20 - Single initialization patterns
- `validator` 0.20 - Struct validation with derive support
- `config` 0.15 - Configuration management with file watching via `notify` 8.2
- `dirs` 6.0 - Platform-specific directory paths (config, home)
- `hostname` 0.4 - Hardware hostname retrieval
- `hex` 0.4 - Hex encoding/decoding
- `base64` 0.22.1 - Base64 encoding/decoding
- `num_cpus` 1.16 - CPU count detection
- `nonzero_ext` 0.3 - Non-zero integer utilities

## Configuration

**Environment:**
- ENVIRONMENT: Controls dev/staging/production environment (defaults to "development")
- ACCEPT_INVALID_CERTS: Set to "true" (dev only) to accept self-signed certificates; defaults to "false" for production security
- Redis configuration via `RedisConfig` in config files
- PostgreSQL connection via `DatabaseConfig` in config files

**Build:**
- `Cargo.toml`: Main manifest with dependencies, binary, and library configuration
- `Cross.toml`: Cross-platform compilation targets (ARM64 Linux configurations)
- Profiles:
  - `release`: Optimized with LTO, single codegen unit, stripped symbols
  - `release-with-debug`: Release optimizations with debug info retained

## Platform Requirements

**Development:**
- Rust 1.85+ toolchain
- PostgreSQL (optional, disabled by default via config)
- Redis (for queue/caching)
- libssl-dev, libpq-dev (for native TLS and PostgreSQL compilation)

**Production:**
- Linux x86_64 or ARM64 (aarch64)
- PostgreSQL database (optional)
- Redis instance
- Outbound HTTP/HTTPS access (for scanning)
- OS keychain support for credential storage (Linux/macOS/Windows via `keyring` crate)

**Binary Output:**
- Single stripped executable ("lonkero") in release builds
- No external runtime dependencies beyond system libraries (libssl, libpq)

---

*Stack analysis: 2026-01-30*
