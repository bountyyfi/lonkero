// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Comprehensive Error Types
 * Production-ready error handling with thiserror
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use thiserror::Error;
use std::time::Duration;

/// Main scanner error type with comprehensive error variants
#[derive(Error, Debug)]
pub enum ScannerError {
    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// HTTP-related errors
    #[error("HTTP error: {0}")]
    Http(#[from] HttpError),

    /// Database-related errors
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    /// Circuit breaker errors
    #[error("Circuit breaker open for {host}: {reason}")]
    CircuitBreakerOpen {
        host: String,
        reason: String,
    },

    /// Rate limit errors
    #[error("Rate limit exceeded for {host}: retry after {retry_after:?}")]
    RateLimitExceeded {
        host: String,
        retry_after: Option<Duration>,
    },

    /// Resource exhaustion errors
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(#[from] ResourceError),

    /// Scanner-specific errors
    #[error("Scanner error: {0}")]
    Scanner(#[from] ScanError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Payload errors
    #[error("Payload error: {0}")]
    Payload(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Unsupported scan type errors
    #[error("Unsupported scan type: {0}")]
    UnsupportedScanType(String),

    /// Timeout errors
    #[error("Operation timed out after {duration:?}")]
    Timeout {
        duration: Duration,
    },

    /// General errors
    #[error("Scanner error: {0}")]
    General(String),
}

/// Network-specific errors with detailed classification
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection timeout after {timeout:?} to {url}")]
    ConnectionTimeout {
        url: String,
        timeout: Duration,
    },

    #[error("DNS resolution failed for {host}: {reason}")]
    DnsResolutionFailed {
        host: String,
        reason: String,
    },

    #[error("TLS handshake failed for {host}: {reason}")]
    TlsHandshakeFailed {
        host: String,
        reason: String,
    },

    #[error("Connection reset by peer for {url}")]
    ConnectionReset {
        url: String,
    },

    #[error("Connection refused for {url}")]
    ConnectionRefused {
        url: String,
    },

    #[error("Proxy error: {reason}")]
    ProxyError {
        reason: String,
    },

    #[error("Network unreachable for {url}")]
    NetworkUnreachable {
        url: String,
    },

    #[error("Too many redirects (>{max_redirects}) for {url}")]
    TooManyRedirects {
        url: String,
        max_redirects: usize,
    },

    #[error("Invalid URL: {url}")]
    InvalidUrl {
        url: String,
    },

    #[error("Network error: {0}")]
    Other(String),
}

/// HTTP-specific errors with status code classification
#[derive(Error, Debug)]
pub enum HttpError {
    #[error("HTTP {status_code} Client Error for {url}: {message}")]
    ClientError {
        status_code: u16,
        url: String,
        message: String,
    },

    #[error("HTTP {status_code} Server Error for {url}: {message}")]
    ServerError {
        status_code: u16,
        url: String,
        message: String,
    },

    #[error("Malformed HTTP response from {url}: {reason}")]
    MalformedResponse {
        url: String,
        reason: String,
    },

    #[error("Chunked encoding error from {url}: {reason}")]
    ChunkedEncodingError {
        url: String,
        reason: String,
    },

    #[error("Compression/decompression error from {url}: {reason}")]
    CompressionError {
        url: String,
        reason: String,
    },

    #[error("Character encoding error from {url}: {encoding}")]
    EncodingError {
        url: String,
        encoding: String,
    },

    #[error("Response body too large ({size} bytes) from {url}, max: {max_size}")]
    BodyTooLarge {
        url: String,
        size: usize,
        max_size: usize,
    },

    #[error("HTTP error: {0}")]
    Other(String),
}

/// Database-specific errors with transaction handling
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database connection failed: {reason}")]
    ConnectionFailed {
        reason: String,
    },

    #[error("Connection pool exhausted: {available}/{max} connections available")]
    PoolExhausted {
        available: usize,
        max: usize,
    },

    #[error("Transaction failed: {reason}")]
    TransactionFailed {
        reason: String,
    },

    #[error("Transaction rollback: {reason}")]
    TransactionRollback {
        reason: String,
    },

    #[error("Constraint violation: {constraint}")]
    ConstraintViolation {
        constraint: String,
    },

    #[error("Deadlock detected: {reason}")]
    Deadlock {
        reason: String,
    },

    #[error("Query timeout after {timeout:?}")]
    QueryTimeout {
        timeout: Duration,
    },

    #[error("Database error: {0}")]
    Other(String),
}

/// Resource exhaustion errors
#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Memory limit exceeded: {current} bytes, limit: {limit}")]
    MemoryLimitExceeded {
        current: usize,
        limit: usize,
    },

    #[error("Connection pool exhausted: {active}/{max} connections")]
    ConnectionPoolExhausted {
        active: usize,
        max: usize,
    },

    #[error("File descriptor limit reached: {current}/{limit}")]
    FileDescriptorLimit {
        current: usize,
        limit: usize,
    },

    #[error("CPU throttled: {current_usage}% usage, threshold: {threshold}%")]
    CpuThrottled {
        current_usage: f64,
        threshold: f64,
    },

    #[error("Disk space exhausted: {available} bytes available, required: {required}")]
    DiskSpaceExhausted {
        available: u64,
        required: u64,
    },

    #[error("Resource error: {0}")]
    Other(String),
}

/// Scanner-specific errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Payload execution failed for {url}: {reason}")]
    PayloadExecutionFailed {
        url: String,
        payload: String,
        reason: String,
    },

    #[error("Detection error for {url}: {reason}")]
    DetectionError {
        url: String,
        reason: String,
    },

    #[error("Response parsing failed for {url}: {reason}")]
    ResponseParsingFailed {
        url: String,
        reason: String,
    },

    #[error("Pattern matching error: {pattern}")]
    PatternMatchingError {
        pattern: String,
        reason: String,
    },

    #[error("Authentication failed for {url}: {reason}")]
    AuthenticationFailed {
        url: String,
        reason: String,
    },

    #[error("Scan aborted: {reason}")]
    ScanAborted {
        reason: String,
    },

    #[error("Scanner error: {0}")]
    Other(String),
}

impl NetworkError {
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            NetworkError::ConnectionTimeout { .. } => true,
            NetworkError::ConnectionReset { .. } => true,
            NetworkError::NetworkUnreachable { .. } => true,
            NetworkError::DnsResolutionFailed { .. } => false,
            NetworkError::TlsHandshakeFailed { .. } => false,
            NetworkError::ConnectionRefused { .. } => false,
            NetworkError::TooManyRedirects { .. } => false,
            NetworkError::InvalidUrl { .. } => false,
            NetworkError::ProxyError { .. } => true,
            NetworkError::Other(_) => false,
        }
    }
}

impl HttpError {
    /// Check if HTTP error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            HttpError::ServerError { status_code, .. } => {
                // Retry on 500, 502, 503, 504
                matches!(status_code, 500 | 502 | 503 | 504)
            }
            HttpError::ClientError { status_code, .. } => {
                // Retry on 429 (Too Many Requests) and 408 (Request Timeout)
                matches!(status_code, 408 | 429)
            }
            _ => false,
        }
    }

    /// Extract retry-after duration from error
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            HttpError::ClientError { status_code: 429, .. } => {
                Some(Duration::from_secs(60)) // Default 60s for rate limits
            }
            HttpError::ServerError { status_code: 503, .. } => {
                Some(Duration::from_secs(30)) // Default 30s for service unavailable
            }
            _ => None,
        }
    }
}

impl DatabaseError {
    /// Check if database error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            DatabaseError::ConnectionFailed { .. } => true,
            DatabaseError::PoolExhausted { .. } => true,
            DatabaseError::Deadlock { .. } => true,
            DatabaseError::QueryTimeout { .. } => true,
            DatabaseError::TransactionFailed { .. } => false,
            DatabaseError::TransactionRollback { .. } => false,
            DatabaseError::ConstraintViolation { .. } => false,
            DatabaseError::Other(_) => false,
        }
    }
}

impl ScannerError {
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ScannerError::Network(e) => e.is_retryable(),
            ScannerError::Http(e) => e.is_retryable(),
            ScannerError::Database(e) => e.is_retryable(),
            ScannerError::RateLimitExceeded { .. } => true,
            ScannerError::ResourceExhausted(_) => true,
            ScannerError::Timeout { .. } => true,
            _ => false,
        }
    }

    /// Get suggested retry delay for this error
    pub fn retry_delay(&self) -> Option<Duration> {
        match self {
            ScannerError::Http(e) => e.retry_after(),
            ScannerError::RateLimitExceeded { retry_after, .. } => *retry_after,
            ScannerError::Timeout { .. } => Some(Duration::from_secs(5)),
            _ => None,
        }
    }
}

/// Convert reqwest errors to our error types
impl From<reqwest::Error> for ScannerError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            ScannerError::Network(NetworkError::ConnectionTimeout {
                url: err.url().map(|u| u.to_string()).unwrap_or_default(),
                timeout: Duration::from_secs(30),
            })
        } else if err.is_connect() {
            if let Some(url) = err.url() {
                ScannerError::Network(NetworkError::ConnectionRefused {
                    url: url.to_string(),
                })
            } else {
                ScannerError::Network(NetworkError::Other(err.to_string()))
            }
        } else if err.is_status() {
            let status = err.status().unwrap();
            let url = err.url().map(|u| u.to_string()).unwrap_or_default();

            if status.is_client_error() {
                ScannerError::Http(HttpError::ClientError {
                    status_code: status.as_u16(),
                    url,
                    message: err.to_string(),
                })
            } else {
                ScannerError::Http(HttpError::ServerError {
                    status_code: status.as_u16(),
                    url,
                    message: err.to_string(),
                })
            }
        } else {
            ScannerError::General(err.to_string())
        }
    }
}

/// Convert tokio-postgres errors to our error types
impl From<tokio_postgres::Error> for ScannerError {
    fn from(err: tokio_postgres::Error) -> Self {
        ScannerError::Database(DatabaseError::Other(err.to_string()))
    }
}

/// Convert deadpool errors to our error types
impl From<deadpool_postgres::PoolError> for ScannerError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        ScannerError::Database(DatabaseError::ConnectionFailed {
            reason: err.to_string(),
        })
    }
}

/// Result type for scanner operations
pub type ScannerResult<T> = Result<T, ScannerError>;
