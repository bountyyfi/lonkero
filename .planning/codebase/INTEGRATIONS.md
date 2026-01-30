# External Integrations

**Analysis Date:** 2026-01-30

## APIs & External Services

**HTTP/REST:**
- Generic HTTP/HTTPS - All external target scanning via `reqwest` HTTP client
  - SDK/Client: `reqwest` 0.12.28
  - Auth: None (client-driven scanning tool)
  - Features: HTTP/2, custom headers, cookies, streaming, connection pooling (32 connections per host default)

**WebSocket:**
- WebSocket - Real-time endpoint discovery and testing
  - SDK/Client: `tokio-tungstenite` 0.28
  - Protocol: Native TLS support for secure WebSocket connections
  - Usage: See `src/scanners/websocket.rs`

**SSH:**
- SSH/SFTP - Authenticated scanning via secure channels
  - SDK/Client: `ssh2` 0.9
  - Auth: Username/password or key-based authentication
  - Usage: Custom SSH client integration for secure testing

**DNS:**
- DNS Resolution - Subdomain discovery via DNS queries
  - SDK/Client: `hickory-resolver` 0.25 (async, modern fork of trust-dns)
  - Usage: `src/discovery/subdomain_discovery.rs` for DNS-based enumeration

**Browser Automation:**
- Headless Chrome/Chromium - JavaScript rendering and form detection
  - SDK/Client: `headless_chrome` 1.0 with network interception (fetch feature)
  - Usage:
    - `src/framework_detector.rs` - Framework detection via rendered pages
    - `src/auth_context.rs` - Authentication session capture
    - `src/headless_crawler.rs` - JavaScript-rendered endpoint discovery
  - Features: Network request interception, Chrome DevTools Protocol (CDP), form discovery

## Data Storage

**Databases:**
- PostgreSQL 9.5+
  - Connection: Via `DatabaseConfig.database_url` (env var: POSTGRES_URL)
  - Client: `tokio-postgres` 0.7.15 + `deadpool-postgres` 0.14.1 connection pool
  - Default URL: `postgresql://lonkero:lonkero@localhost:5432/lonkero` (can be disabled)
  - Features: Batch operations, connection recycling, pool size configurable
  - Status: Optional - database writes disabled by default (`database.enabled: false`)
  - Location: `src/database.rs`

**Cache:**
- Redis - Job queuing, progress tracking, result storage, caching
  - Connection: Via `RedisConfig.url` (env var: REDIS_URL)
  - Client: `deadpool-redis` 0.22 connection pool
  - Usage:
    - `scan:queue` - Blocking pop for scan jobs (queue.rs)
    - `scan:{scan_id}:status` - Scan status with 24-hour TTL
    - `scan:{scan_id}:progress` - Pub/sub progress updates
    - `scan:{scan_id}:results` - Results storage with 7-day TTL
    - `scan:{scan_id}:error` - Error messages with 24-hour TTL
    - `scan:{scan_id}:tests` - Test counter tracking
  - Features: Pub/sub, key expiration, cluster mode support, TLS, authentication
  - Location: `src/queue.rs`, `src/realtime/mod.rs`

**File Storage:**
- Local filesystem only - Session recordings, reports, logs
  - Compression: `flate2` 1.1 for session recording compression
  - Platform dirs: `dirs` 6.0 for OS-specific configuration paths

## Authentication & Identity

**Auth Approach:**
- Custom auth context management - No external OAuth/OIDC for the scanner itself
  - Location: `src/auth_context.rs`
  - Features: Session capture, cookie handling, form-based login testing, authentication state tracking

**Credential Storage:**
- OS Keychain - Secure credential storage using platform keychain
  - SDK/Client: `keyring` 3.6.3
  - Usage: Secure storage of test credentials, API keys, SSH keys
  - Platforms: Linux (Secret Service), macOS (Keychain), Windows (Credential Manager)

## Monitoring & Observability

**Logging:**
- Framework: `tracing` 0.1 with `tracing-subscriber` 0.3
  - Output: Console + JSON structured logs
  - Configuration: Environment-based filtering via `env-filter` feature
  - Bridge: `tracing-log` for compatibility with `log` macros
  - Output format: JSON-structured logs for machine parsing
  - Location: `src/http_client.rs`, `src/database.rs`, `src/queue.rs`

**Error Tracking:**
- Not detected - Error handling is local via `anyhow` and `thiserror`
  - `anyhow` 1.0 - Error context chaining
  - `thiserror` 2.0.17 - Structured error type definitions

**Distributed Tracing:**
- Infrastructure: Tracing framework integrated but external trace backend not detected
  - Can be integrated with standard OTEL collectors via tracing ecosystem

## CI/CD & Deployment

**Hosting:**
- Self-hosted / Cloud-agnostic - Compiled Rust binary, runs on Linux x86_64 and ARM64
- Cross-platform builds via `Cross.toml` for ARM64 Linux (aarch64-unknown-linux-gnu)

**CI Pipeline:**
- Not detected in codebase (likely managed via GitHub Actions in `.github/workflows/`, not analyzed)

**Build Artifacts:**
- Single executable: `lonkero`
- Binary path in manifest: `src/cli/main.rs`
- Library export: `lonkero_scanner` (rlib format for external use)
- Build configuration: Release with LTO, stripped symbols for production

## Reporting & Delivery

**Email Delivery:**
- Framework: SMTP via `lettre` 0.11
  - Auth: SMTP credentials (username/password via `Credentials`)
  - Configuration: `EmailConfig` in `src/reporting/delivery.rs`
    - `smtp_server`: SMTP hostname
    - `smtp_port`: SMTP port (typically 587/465)
    - `smtp_username`: SMTP authentication username
    - `smtp_password`: SMTP authentication password
    - `from_email`: Sender email address
    - `from_name`: Sender display name
  - Features: TLS support (Tokio 1 + Rustls), multipart messages, attachments
  - Location: `src/reporting/delivery.rs`

**Webhooks:**
- Outbound HTTP webhooks - POST/custom HTTP to external endpoints
  - Configuration: `WebhookConfig` in `src/reporting/delivery.rs`
    - `url`: Webhook endpoint URL
    - `method`: HTTP method (GET, POST, PUT, etc.)
    - `headers`: Optional custom headers (HashMap)
  - Client: `reqwest::Client` for HTTP delivery
  - Usage: Send scan results, notifications to external systems
  - Location: `src/reporting/delivery.rs`

**Report Formats:**
- CSV - Via `csv` 1.3 crate
- XLSX (Excel) - Via `rust_xlsxwriter` 0.92.3 crate
- JSON - Via `serde_json` 1.0
- Attachments: Email reports support multipart delivery with file attachments

## Rate Limiting & Circuit Breaking

**Rate Limiting:**
- Framework: `governor` 0.10 token bucket algorithm
  - Adaptive rate limiting per `src/analysis/adaptive_rate_limiter.rs`
  - Usage: HTTP client includes optional rate limiter (see `HttpClient` in `src/http_client.rs`)

**Circuit Breaker:**
- Custom implementation: `src/circuit_breaker.rs`
  - Configuration: `CircuitBreakerConfig`
  - Optional integration with HTTP client for fault tolerance

## Caching

**In-Memory Cache:**
- Framework: `moka` 0.12 with async future support
  - Usage: Optional HTTP response caching in `HttpClient`
  - Key format: URL-based (string keys)
  - TTL: Configurable per cache instance

## Configuration Management

**Configuration Sources:**
- Format support: YAML, TOML, JSON (auto-detected)
- Configuration loader: `src/config/loader.rs`
- File watching: `notify` 8.2 for hot-reload detection
- Validation: `validator` 0.20 with derive macros
- Profiles: Support for scan profiles via `src/config/profiles.rs`
- Targets: Target configuration via `src/config/targets.rs`

**Configuration Hierarchy:**
1. Environment variables (with defaults)
2. Configuration files (YAML/TOML/JSON)
3. Code defaults in `DatabaseConfig`, `RedisConfig`, `ServerConfig`, `ScannerConfig`

## Environment Configuration

**Required env vars (critical):**
- `REDIS_URL`: Redis connection string (e.g., `redis://localhost:6379`)
- `POSTGRES_URL`: PostgreSQL connection string (optional, database disabled by default)
- `ENVIRONMENT`: Deployment environment (development/staging/production)
- `ACCEPT_INVALID_CERTS`: Set to "true" for dev-only self-signed certificate acceptance

**Optional env vars:**
- SMTP configuration (if email delivery enabled):
  - `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
  - `FROM_EMAIL`, `FROM_NAME`
- Database configuration:
  - `DATABASE_POOL_SIZE`, `DATABASE_BATCH_SIZE`, `DATABASE_ENABLED`
- Redis configuration:
  - `REDIS_POOL_SIZE`, `REDIS_CLUSTER_MODE`, `REDIS_USERNAME`, `REDIS_PASSWORD`

**Secrets location:**
- Environment variables (recommended)
- OS keychain via `keyring` 3.6.3 crate
- Configuration files (not recommended for secrets)

## Security Features

**TLS/SSL:**
- Certificate validation: Enabled by default (`ACCEPT_INVALID_CERTS=false`)
- Client: Native OS certificates via `native-tls`
- HTTPS enforcement: Standard HTTPS protocol support in all HTTP clients

**Cryptography:**
- HMAC: `hmac` 0.12 for JWT and signature testing
- SHA-256: `sha2` 0.10 for hash verification
- BLAKE3: `blake3` 1.8 for quantum-safe hashing
- Base64: `base64` 0.22.1 for encoding
- Hex: `hex` 0.4 for hex encoding

## External Scanning Targets

**No direct integrations**, but scanner is designed to test:
- Generic APIs (REST, GraphQL, gRPC)
- WebSocket endpoints
- SSH services
- DNS services
- Web applications with various frameworks (see scanner modules in `src/scanners/`)

---

*Integration audit: 2026-01-30*
