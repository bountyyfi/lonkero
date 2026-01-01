// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Adaptive Concurrency Module
 * Dynamically adjusts concurrency based on target response times
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Tracks target-specific performance metrics
#[derive(Debug, Clone)]
struct TargetMetrics {
    current_concurrency: usize,
    avg_response_time_ms: f64,
    error_count: u64,
    success_count: u64,
    total_requests: u64,
}

impl TargetMetrics {
    fn new(initial_concurrency: usize) -> Self {
        Self {
            current_concurrency: initial_concurrency,
            avg_response_time_ms: 0.0,
            error_count: 0,
            success_count: 0,
            total_requests: 0,
        }
    }

    fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.error_count as f64 / self.total_requests as f64
    }
}

/// Adaptive concurrency tracker for target-specific optimization
pub struct AdaptiveConcurrencyTracker {
    targets: Arc<RwLock<HashMap<String, TargetMetrics>>>,
    initial_concurrency: usize,
    max_concurrency: usize,
}

impl AdaptiveConcurrencyTracker {
    /// Create a new adaptive concurrency tracker
    pub fn new(initial_concurrency: usize, max_concurrency: usize) -> Self {
        Self {
            targets: Arc::new(RwLock::new(HashMap::new())),
            initial_concurrency,
            max_concurrency,
        }
    }

    /// Get current concurrency level for a target
    pub async fn get_concurrency(&self, target_domain: &str) -> usize {
        let targets = self.targets.read().await;

        if let Some(metrics) = targets.get(target_domain) {
            metrics.current_concurrency
        } else {
            self.initial_concurrency
        }
    }

    /// Record a successful request
    pub async fn record_success(&self, target_domain: &str, response_time: Duration) {
        let mut targets = self.targets.write().await;

        let metrics = targets
            .entry(target_domain.to_string())
            .or_insert_with(|| TargetMetrics::new(self.initial_concurrency));

        metrics.success_count += 1;
        metrics.total_requests += 1;

        // Update average response time (exponential moving average)
        let response_ms = response_time.as_millis() as f64;
        if metrics.avg_response_time_ms == 0.0 {
            metrics.avg_response_time_ms = response_ms;
        } else {
            metrics.avg_response_time_ms =
                0.7 * metrics.avg_response_time_ms + 0.3 * response_ms;
        }

        // Adjust concurrency based on response time
        self.adjust_concurrency(metrics);

        debug!(
            "Target {}: response_time={:.2}ms, concurrency={}, error_rate={:.2}%",
            target_domain,
            metrics.avg_response_time_ms,
            metrics.current_concurrency,
            metrics.error_rate() * 100.0
        );
    }

    /// Record a failed request
    pub async fn record_error(&self, target_domain: &str) {
        let mut targets = self.targets.write().await;

        let metrics = targets
            .entry(target_domain.to_string())
            .or_insert_with(|| TargetMetrics::new(self.initial_concurrency));

        metrics.error_count += 1;
        metrics.total_requests += 1;

        // Adjust concurrency based on error rate
        self.adjust_concurrency(metrics);

        debug!(
            "Target {}: ERROR recorded, concurrency={}, error_rate={:.2}%",
            target_domain,
            metrics.current_concurrency,
            metrics.error_rate() * 100.0
        );
    }

    /// Adjust concurrency based on metrics
    fn adjust_concurrency(&self, metrics: &mut TargetMetrics) {
        let error_rate = metrics.error_rate();

        // Backoff if high error rate
        if error_rate > 0.1 {
            // >10% error rate
            let new_concurrency = (metrics.current_concurrency / 2).max(1);
            if new_concurrency != metrics.current_concurrency {
                info!(
                    "🔻 Reducing concurrency: {} -> {} (high error rate: {:.1}%)",
                    metrics.current_concurrency,
                    new_concurrency,
                    error_rate * 100.0
                );
                metrics.current_concurrency = new_concurrency;
            }
            return;
        }

        // Backoff if slow responses
        if metrics.avg_response_time_ms > 500.0 {
            let new_concurrency = (metrics.current_concurrency / 2).max(1);
            if new_concurrency != metrics.current_concurrency {
                info!(
                    "🔻 Reducing concurrency: {} -> {} (slow response: {:.2}ms)",
                    metrics.current_concurrency, new_concurrency, metrics.avg_response_time_ms
                );
                metrics.current_concurrency = new_concurrency;
            }
            return;
        }

        // Ramp up if fast responses and low error rate
        if metrics.avg_response_time_ms < 100.0 && error_rate < 0.01 {
            let new_concurrency = (metrics.current_concurrency * 2).min(self.max_concurrency);
            if new_concurrency != metrics.current_concurrency && metrics.total_requests > 10 {
                info!(
                    "🔺 Increasing concurrency: {} -> {} (fast response: {:.2}ms)",
                    metrics.current_concurrency, new_concurrency, metrics.avg_response_time_ms
                );
                metrics.current_concurrency = new_concurrency;
            }
        }
    }

    /// Get metrics for a target
    pub async fn get_metrics(&self, target_domain: &str) -> Option<TargetMetrics> {
        let targets = self.targets.read().await;
        targets.get(target_domain).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_concurrency() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        let concurrency = tracker.get_concurrency("example.com").await;
        assert_eq!(concurrency, 10);
    }

    #[tokio::test]
    async fn test_success_recording() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        tracker
            .record_success("example.com", Duration::from_millis(50))
            .await;

        let metrics = tracker.get_metrics("example.com").await.unwrap();
        assert_eq!(metrics.success_count, 1);
        assert_eq!(metrics.total_requests, 1);
        assert!(metrics.avg_response_time_ms > 0.0);
    }

    #[tokio::test]
    async fn test_error_recording() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        tracker.record_error("example.com").await;

        let metrics = tracker.get_metrics("example.com").await.unwrap();
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.total_requests, 1);
    }

    #[tokio::test]
    async fn test_concurrency_increases_on_fast_responses() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        // Record many fast successful requests
        for _ in 0..20 {
            tracker
                .record_success("example.com", Duration::from_millis(50))
                .await;
        }

        let concurrency = tracker.get_concurrency("example.com").await;
        // Should increase from 10
        assert!(concurrency > 10);
    }

    #[tokio::test]
    async fn test_concurrency_decreases_on_slow_responses() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        // Record slow responses
        for _ in 0..5 {
            tracker
                .record_success("example.com", Duration::from_millis(600))
                .await;
        }

        let concurrency = tracker.get_concurrency("example.com").await;
        // Should decrease from 10
        assert!(concurrency < 10);
    }

    #[tokio::test]
    async fn test_concurrency_decreases_on_errors() {
        let tracker = AdaptiveConcurrencyTracker::new(10, 50);

        // Record errors
        for _ in 0..5 {
            tracker.record_error("example.com").await;
        }

        let concurrency = tracker.get_concurrency("example.com").await;
        // Should decrease from 10
        assert!(concurrency < 10);
    }
}
