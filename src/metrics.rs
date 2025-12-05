// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Metrics Collection & Monitoring
 * Production-ready metrics with tracing integration
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Metrics collector for tracking errors and performance
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    enabled: bool,
    requests_total: Arc<AtomicU64>,
    requests_failed: Arc<AtomicU64>,
    requests_retried: Arc<AtomicU64>,
    circuit_breaker_opened: Arc<AtomicU64>,
    rate_limits: Arc<AtomicU64>,
    network_errors: Arc<AtomicU64>,
    database_errors: Arc<AtomicU64>,
    custom_counters: Arc<Mutex<HashMap<String, f64>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_failed: Arc::new(AtomicU64::new(0)),
            requests_retried: Arc::new(AtomicU64::new(0)),
            circuit_breaker_opened: Arc::new(AtomicU64::new(0)),
            rate_limits: Arc::new(AtomicU64::new(0)),
            network_errors: Arc::new(AtomicU64::new(0)),
            database_errors: Arc::new(AtomicU64::new(0)),
            custom_counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record an HTTP request
    pub fn record_request(&self, method: &str, status_code: u16, duration: Duration) {
        if !self.enabled {
            return;
        }

        self.requests_total.fetch_add(1, Ordering::Relaxed);

        debug!(
            method = method,
            status_code = status_code,
            duration_ms = duration.as_millis(),
            "HTTP request completed"
        );

        if status_code >= 400 {
            debug!(
                status_code = status_code,
                "HTTP error response"
            );
        }
    }

    /// Record a failed request
    pub fn record_request_failure(&self, method: &str, error_type: &str) {
        if !self.enabled {
            return;
        }

        self.requests_failed.fetch_add(1, Ordering::Relaxed);

        debug!(
            method = method,
            error_type = error_type,
            "HTTP request failed"
        );
    }

    /// Record a retry attempt
    pub fn record_retry(&self, attempt: u32, backoff: Duration) {
        if !self.enabled {
            return;
        }

        self.requests_retried.fetch_add(1, Ordering::Relaxed);

        debug!(
            attempt = attempt,
            backoff_ms = backoff.as_millis(),
            "Request retried"
        );
    }

    /// Record circuit breaker state change
    pub fn record_circuit_breaker_opened(&self, host: &str) {
        if !self.enabled {
            return;
        }

        self.circuit_breaker_opened.fetch_add(1, Ordering::Relaxed);

        info!(
            host = host,
            "Circuit breaker opened"
        );
    }

    /// Record rate limit hit
    pub fn record_rate_limit(&self, host: &str, status_code: u16) {
        if !self.enabled {
            return;
        }

        self.rate_limits.fetch_add(1, Ordering::Relaxed);

        debug!(
            host = host,
            status_code = status_code,
            "Rate limit hit"
        );
    }

    /// Record network error
    pub fn record_network_error(&self, error_type: &str) {
        if !self.enabled {
            return;
        }

        self.network_errors.fetch_add(1, Ordering::Relaxed);

        debug!(
            error_type = error_type,
            category = "network",
            "Network error"
        );
    }

    /// Record database error
    pub fn record_database_error(&self, error_type: &str) {
        if !self.enabled {
            return;
        }

        self.database_errors.fetch_add(1, Ordering::Relaxed);

        debug!(
            error_type = error_type,
            category = "database",
            "Database error"
        );
    }

    /// Record database query duration
    pub fn record_database_query(&self, operation: &str, duration: Duration) {
        if !self.enabled {
            return;
        }

        debug!(
            operation = operation,
            duration_ms = duration.as_millis(),
            "Database query completed"
        );
    }

    /// Update connection pool metrics
    pub fn update_connection_pool(&self, size: usize, available: usize) {
        if !self.enabled {
            return;
        }

        debug!(
            pool_size = size,
            pool_available = available,
            "Connection pool status"
        );
    }

    /// Update active connections
    pub fn update_active_connections(&self, count: usize) {
        if !self.enabled {
            return;
        }

        debug!(
            active_connections = count,
            "Active connections updated"
        );
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: usize) {
        if !self.enabled {
            return;
        }

        debug!(
            memory_bytes = bytes,
            "Memory usage updated"
        );
    }

    /// Update CPU usage
    pub fn update_cpu_usage(&self, percent: f64) {
        if !self.enabled {
            return;
        }

        debug!(
            cpu_percent = percent,
            "CPU usage updated"
        );
    }

    /// Get a custom counter value by name
    pub fn get_counter(&self, name: &str) -> f64 {
        if !self.enabled {
            return 0.0;
        }

        let counters = self.custom_counters.lock().unwrap();
        *counters.get(name).unwrap_or(&0.0)
    }

    /// Increment a custom counter by name
    pub fn increment_counter(&self, name: &str, value: f64) {
        if !self.enabled {
            return;
        }

        let mut counters = self.custom_counters.lock().unwrap();
        let counter = counters.entry(name.to_string()).or_insert(0.0);
        *counter += value;

        debug!(
            counter_name = name,
            value = value,
            new_value = *counter,
            "Counter incremented"
        );
    }

    /// Get metrics summary
    pub fn get_metrics_summary(&self) -> MetricsSummary {
        MetricsSummary {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            requests_retried: self.requests_retried.load(Ordering::Relaxed),
            circuit_breaker_opened: self.circuit_breaker_opened.load(Ordering::Relaxed),
            rate_limits: self.rate_limits.load(Ordering::Relaxed),
            network_errors: self.network_errors.load(Ordering::Relaxed),
            database_errors: self.database_errors.load(Ordering::Relaxed),
        }
    }
}

/// Metrics summary for reporting
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub requests_total: u64,
    pub requests_failed: u64,
    pub requests_retried: u64,
    pub circuit_breaker_opened: u64,
    pub rate_limits: u64,
    pub network_errors: u64,
    pub database_errors: u64,
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
    operation: String,
    metrics: Arc<MetricsCollector>,
}

impl Timer {
    /// Create a new timer
    pub fn new(operation: String, metrics: Arc<MetricsCollector>) -> Self {
        Self {
            start: Instant::now(),
            operation,
            metrics,
        }
    }

    /// Stop the timer and record the duration
    pub fn stop(self) -> Duration {
        let duration = self.start.elapsed();
        debug!(
            operation = %self.operation,
            duration_ms = duration.as_millis(),
            "Operation completed"
        );
        duration
    }

    /// Stop the timer and record as database query
    pub fn stop_database_query(self) {
        let duration = self.start.elapsed();
        self.metrics.record_database_query(&self.operation, duration);
    }
}

/// Error tracking for detailed error analysis
#[derive(Debug, Clone)]
pub struct ErrorTracker {
    metrics: Arc<MetricsCollector>,
}

impl ErrorTracker {
    /// Create a new error tracker
    pub fn new(metrics: Arc<MetricsCollector>) -> Self {
        Self { metrics }
    }

    /// Track an error
    pub fn track_error(&self, error: &crate::errors::ScannerError) {
        use crate::errors::ScannerError;

        match error {
            ScannerError::Network(e) => {
                let error_type = match e {
                    crate::errors::NetworkError::ConnectionTimeout { .. } => "connection_timeout",
                    crate::errors::NetworkError::DnsResolutionFailed { .. } => "dns_resolution_failed",
                    crate::errors::NetworkError::TlsHandshakeFailed { .. } => "tls_handshake_failed",
                    crate::errors::NetworkError::ConnectionReset { .. } => "connection_reset",
                    crate::errors::NetworkError::ConnectionRefused { .. } => "connection_refused",
                    crate::errors::NetworkError::ProxyError { .. } => "proxy_error",
                    crate::errors::NetworkError::NetworkUnreachable { .. } => "network_unreachable",
                    crate::errors::NetworkError::TooManyRedirects { .. } => "too_many_redirects",
                    crate::errors::NetworkError::InvalidUrl { .. } => "invalid_url",
                    crate::errors::NetworkError::Other(_) => "other",
                };
                self.metrics.record_network_error(error_type);
            }
            ScannerError::Http(_) => {
                debug!("HTTP error tracked");
            }
            ScannerError::Database(e) => {
                let error_type = match e {
                    crate::errors::DatabaseError::ConnectionFailed { .. } => "connection_failed",
                    crate::errors::DatabaseError::PoolExhausted { .. } => "pool_exhausted",
                    crate::errors::DatabaseError::TransactionFailed { .. } => "transaction_failed",
                    crate::errors::DatabaseError::TransactionRollback { .. } => "transaction_rollback",
                    crate::errors::DatabaseError::ConstraintViolation { .. } => "constraint_violation",
                    crate::errors::DatabaseError::Deadlock { .. } => "deadlock",
                    crate::errors::DatabaseError::QueryTimeout { .. } => "query_timeout",
                    crate::errors::DatabaseError::Other(_) => "other",
                };
                self.metrics.record_database_error(error_type);
            }
            ScannerError::CircuitBreakerOpen { host, .. } => {
                self.metrics.record_circuit_breaker_opened(host);
            }
            ScannerError::RateLimitExceeded { host, .. } => {
                self.metrics.record_rate_limit(host, 429);
            }
            _ => {
                debug!("Other error tracked");
            }
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let metrics = MetricsCollector::new(true);
        assert!(metrics.enabled);

        let metrics_disabled = MetricsCollector::new(false);
        assert!(!metrics_disabled.enabled);
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = MetricsCollector::new(true);

        metrics.record_request("GET", 200, Duration::from_millis(100));
        metrics.record_request_failure("POST", "timeout");
        metrics.record_retry(1, Duration::from_millis(200));

        let summary = metrics.get_metrics_summary();
        assert_eq!(summary.requests_total, 1);
        assert_eq!(summary.requests_failed, 1);
        assert_eq!(summary.requests_retried, 1);
    }

    #[test]
    fn test_timer() {
        let metrics = Arc::new(MetricsCollector::new(false));
        let timer = Timer::new("test_operation".to_string(), metrics);
        std::thread::sleep(Duration::from_millis(10));
        let duration = timer.stop();
        assert!(duration >= Duration::from_millis(10));
    }
}
