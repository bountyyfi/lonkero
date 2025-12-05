// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Prometheus Metrics Export for Rust Scanner
 * Production-ready monitoring with HTTP endpoint
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use axum::{
    extract::State,
    http::StatusCode,
    routing::get,
    Router,
};
use lazy_static::lazy_static;
use prometheus::{
    Counter, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder, Encoder,
};
use std::sync::Arc;
use tracing::{debug, info};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref HTTP_REQUESTS_TOTAL: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_http_requests_total", "Total HTTP requests")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref HTTP_REQUESTS_FAILED: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_http_requests_failed_total", "Total failed HTTP requests")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref HTTP_REQUEST_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("lonkero_rust_http_request_duration_seconds", "HTTP request duration")
            .namespace("lonkero")
            .subsystem("scanner")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0])
    ).expect("metric can be created");

    pub static ref VULNERABILITIES_FOUND: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_vulnerabilities_found_total", "Total vulnerabilities found")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref SCANS_ACTIVE: Gauge = Gauge::with_opts(
        Opts::new("lonkero_rust_scans_active", "Number of active scans")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref SCANS_TOTAL: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_scans_total", "Total scans executed")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref PAYLOADS_EXECUTED: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_payloads_executed_total", "Total payloads executed")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref CIRCUIT_BREAKER_OPENED: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_circuit_breaker_opened_total", "Circuit breaker opened events")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref RATE_LIMITS_HIT: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_rate_limits_hit_total", "Rate limit hits")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref NETWORK_ERRORS: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_network_errors_total", "Network errors")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref DATABASE_ERRORS: Counter = Counter::with_opts(
        Opts::new("lonkero_rust_database_errors_total", "Database errors")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref DATABASE_QUERY_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("lonkero_rust_database_query_duration_seconds", "Database query duration")
            .namespace("lonkero")
            .subsystem("scanner")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0])
    ).expect("metric can be created");

    pub static ref CONNECTION_POOL_SIZE: Gauge = Gauge::with_opts(
        Opts::new("lonkero_rust_connection_pool_size", "Database connection pool size")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref ACTIVE_CONNECTIONS: Gauge = Gauge::with_opts(
        Opts::new("lonkero_rust_active_connections", "Active database connections")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref MEMORY_USAGE_BYTES: Gauge = Gauge::with_opts(
        Opts::new("lonkero_rust_memory_usage_bytes", "Memory usage in bytes")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");

    pub static ref CPU_USAGE_PERCENT: Gauge = Gauge::with_opts(
        Opts::new("lonkero_rust_cpu_usage_percent", "CPU usage percentage")
            .namespace("lonkero")
            .subsystem("scanner")
    ).expect("metric can be created");
}

/// Initialize Prometheus metrics registry
pub fn init_metrics() {
    REGISTRY
        .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(HTTP_REQUESTS_FAILED.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(HTTP_REQUEST_DURATION.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(VULNERABILITIES_FOUND.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(SCANS_ACTIVE.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(SCANS_TOTAL.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(PAYLOADS_EXECUTED.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(CIRCUIT_BREAKER_OPENED.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RATE_LIMITS_HIT.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(NETWORK_ERRORS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(DATABASE_ERRORS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(DATABASE_QUERY_DURATION.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(CONNECTION_POOL_SIZE.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(ACTIVE_CONNECTIONS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(MEMORY_USAGE_BYTES.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(CPU_USAGE_PERCENT.clone()))
        .expect("collector can be registered");

    info!("Prometheus metrics initialized");
}

/// Handler for /metrics endpoint
async fn metrics_handler() -> Result<String, StatusCode> {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();

    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    String::from_utf8(buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Create metrics router
pub fn create_metrics_router() -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
}

/// Metrics collector with convenience methods
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    enabled: bool,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(enabled: bool) -> Self {
        if enabled {
            init_metrics();
        }
        Self { enabled }
    }

    /// Record an HTTP request
    pub fn record_request(&self, _method: &str, status_code: u16, duration: std::time::Duration) {
        if !self.enabled {
            return;
        }

        HTTP_REQUESTS_TOTAL.inc();
        HTTP_REQUEST_DURATION.observe(duration.as_secs_f64());

        if status_code >= 400 {
            HTTP_REQUESTS_FAILED.inc();
        }

        debug!(
            status_code = status_code,
            duration_ms = duration.as_millis(),
            "HTTP request completed"
        );
    }

    /// Record a failed request
    pub fn record_request_failure(&self, _method: &str, error_type: &str) {
        if !self.enabled {
            return;
        }

        HTTP_REQUESTS_FAILED.inc();

        debug!(
            error_type = error_type,
            "HTTP request failed"
        );
    }

    /// Record a vulnerability found
    pub fn record_vulnerability(&self) {
        if !self.enabled {
            return;
        }

        VULNERABILITIES_FOUND.inc();
        debug!("Vulnerability found");
    }

    /// Record scan start
    pub fn record_scan_start(&self) {
        if !self.enabled {
            return;
        }

        SCANS_TOTAL.inc();
        SCANS_ACTIVE.inc();
        debug!("Scan started");
    }

    /// Record scan completion
    pub fn record_scan_complete(&self) {
        if !self.enabled {
            return;
        }

        SCANS_ACTIVE.dec();
        debug!("Scan completed");
    }

    /// Record payload execution
    pub fn record_payload_executed(&self) {
        if !self.enabled {
            return;
        }

        PAYLOADS_EXECUTED.inc();
    }

    /// Record circuit breaker state change
    pub fn record_circuit_breaker_opened(&self, host: &str) {
        if !self.enabled {
            return;
        }

        CIRCUIT_BREAKER_OPENED.inc();

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

        RATE_LIMITS_HIT.inc();

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

        NETWORK_ERRORS.inc();

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

        DATABASE_ERRORS.inc();

        debug!(
            error_type = error_type,
            category = "database",
            "Database error"
        );
    }

    /// Record database query duration
    pub fn record_database_query(&self, operation: &str, duration: std::time::Duration) {
        if !self.enabled {
            return;
        }

        DATABASE_QUERY_DURATION.observe(duration.as_secs_f64());

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

        CONNECTION_POOL_SIZE.set(size as f64);
        ACTIVE_CONNECTIONS.set((size - available) as f64);

        debug!(
            pool_size = size,
            pool_available = available,
            "Connection pool status"
        );
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: usize) {
        if !self.enabled {
            return;
        }

        MEMORY_USAGE_BYTES.set(bytes as f64);

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

        CPU_USAGE_PERCENT.set(percent);

        debug!(
            cpu_percent = percent,
            "CPU usage updated"
        );
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
        let metrics = MetricsCollector::new(false);
        assert!(!metrics.enabled);
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = MetricsCollector::new(false);

        metrics.record_request("GET", 200, std::time::Duration::from_millis(100));
        metrics.record_vulnerability();
        metrics.record_scan_start();
        metrics.record_scan_complete();
    }
}
