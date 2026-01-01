// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Adaptive Rate Limiter
 * Dynamically adjusts request rate based on target response patterns
 *
 * Features:
 * - Automatic rate limit detection via 429/503 responses
 * - Exponential backoff with jitter
 * - Per-domain rate tracking
 * - Retry-After header support
 * - Intelligent throttling based on response times
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Rate limit state for a specific domain
#[derive(Debug, Clone)]
pub struct DomainRateState {
    /// Current requests per second limit
    pub current_rps: f64,
    /// Minimum RPS (floor)
    pub min_rps: f64,
    /// Maximum RPS (ceiling)
    pub max_rps: f64,
    /// Last request timestamp
    pub last_request: Instant,
    /// Number of 429/503 responses received
    pub rate_limit_hits: u32,
    /// Number of successful requests since last rate limit
    pub success_streak: u32,
    /// Retry-After delay if received
    pub retry_after: Option<Duration>,
    /// Response time moving average (ms)
    pub avg_response_time_ms: f64,
    /// Baseline response time for this domain
    pub baseline_response_time_ms: f64,
    /// Whether rate limiting is detected
    pub rate_limiting_detected: bool,
}

impl Default for DomainRateState {
    fn default() -> Self {
        Self {
            current_rps: 10.0,  // Start with 10 RPS
            min_rps: 0.5,       // Never go below 0.5 RPS
            max_rps: 50.0,      // Never exceed 50 RPS
            last_request: Instant::now(),
            rate_limit_hits: 0,
            success_streak: 0,
            retry_after: None,
            avg_response_time_ms: 0.0,
            baseline_response_time_ms: 0.0,
            rate_limiting_detected: false,
        }
    }
}

/// Response metadata for rate limit analysis
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    pub status_code: u16,
    pub response_time_ms: u64,
    pub retry_after_secs: Option<u64>,
    pub has_rate_limit_headers: bool,
}

/// Adaptive Rate Limiter
pub struct AdaptiveRateLimiter {
    /// Per-domain rate state
    domain_states: Arc<RwLock<HashMap<String, DomainRateState>>>,
    /// Global configuration
    config: RateLimiterConfig,
}

#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Initial requests per second
    pub initial_rps: f64,
    /// Minimum requests per second
    pub min_rps: f64,
    /// Maximum requests per second
    pub max_rps: f64,
    /// Backoff multiplier on rate limit hit
    pub backoff_multiplier: f64,
    /// Recovery multiplier on success streak
    pub recovery_multiplier: f64,
    /// Success streak threshold before increasing rate
    pub recovery_threshold: u32,
    /// Response time threshold for slowdown (ms)
    pub slowdown_threshold_ms: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            initial_rps: 10.0,
            min_rps: 0.5,
            max_rps: 50.0,
            backoff_multiplier: 0.5,      // Halve rate on 429
            recovery_multiplier: 1.1,      // 10% increase on success streak
            recovery_threshold: 20,        // 20 successes before recovery
            slowdown_threshold_ms: 5000,   // Slow down if responses > 5s
        }
    }
}

impl AdaptiveRateLimiter {
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            domain_states: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Extract domain from URL
    fn extract_domain(url: &str) -> String {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| url.to_string())
    }

    /// Wait for rate limit before making request
    pub async fn wait_for_rate_limit(&self, url: &str) {
        let domain = Self::extract_domain(url);

        let delay = {
            let states = self.domain_states.read().await;
            if let Some(state) = states.get(&domain) {
                // Check for Retry-After
                if let Some(retry_after) = state.retry_after {
                    let elapsed = state.last_request.elapsed();
                    if elapsed < retry_after {
                        Some(retry_after - elapsed)
                    } else {
                        None
                    }
                } else {
                    // Calculate delay based on current RPS
                    let min_interval = Duration::from_secs_f64(1.0 / state.current_rps);
                    let elapsed = state.last_request.elapsed();
                    if elapsed < min_interval {
                        Some(min_interval - elapsed)
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        };

        if let Some(wait_time) = delay {
            // Add jitter (0-10% of wait time)
            let jitter_ms = (wait_time.as_millis() as f64 * rand::random::<f64>() * 0.1) as u64;
            let total_wait = wait_time + Duration::from_millis(jitter_ms);

            debug!("Rate limiting: waiting {:?} for {}", total_wait, domain);
            sleep(total_wait).await;
        }

        // Update last request time
        let mut states = self.domain_states.write().await;
        let state = states.entry(domain.clone()).or_insert_with(|| {
            DomainRateState {
                current_rps: self.config.initial_rps,
                min_rps: self.config.min_rps,
                max_rps: self.config.max_rps,
                ..Default::default()
            }
        });
        state.last_request = Instant::now();
    }

    /// Update rate limiter state based on response
    pub async fn update_from_response(&self, url: &str, response: &ResponseInfo) {
        let domain = Self::extract_domain(url);
        let mut states = self.domain_states.write().await;

        let state = states.entry(domain.clone()).or_insert_with(|| {
            DomainRateState {
                current_rps: self.config.initial_rps,
                min_rps: self.config.min_rps,
                max_rps: self.config.max_rps,
                ..Default::default()
            }
        });

        // Update response time moving average
        if state.avg_response_time_ms == 0.0 {
            state.avg_response_time_ms = response.response_time_ms as f64;
            state.baseline_response_time_ms = response.response_time_ms as f64;
        } else {
            // Exponential moving average
            state.avg_response_time_ms =
                state.avg_response_time_ms * 0.9 + response.response_time_ms as f64 * 0.1;
        }

        // Handle rate limit responses (429, 503)
        if response.status_code == 429 || response.status_code == 503 {
            state.rate_limit_hits += 1;
            state.success_streak = 0;
            state.rate_limiting_detected = true;

            // Apply exponential backoff
            let new_rps = (state.current_rps * self.config.backoff_multiplier)
                .max(state.min_rps);

            warn!(
                "Rate limit detected for {} ({}): reducing RPS from {:.2} to {:.2}",
                domain, response.status_code, state.current_rps, new_rps
            );
            state.current_rps = new_rps;

            // Handle Retry-After header
            if let Some(retry_secs) = response.retry_after_secs {
                state.retry_after = Some(Duration::from_secs(retry_secs));
                info!("Retry-After header detected: waiting {} seconds", retry_secs);
            }
        } else if response.status_code >= 200 && response.status_code < 400 {
            // Successful response
            state.success_streak += 1;
            state.retry_after = None;

            // Recovery: increase rate after success streak
            if state.success_streak >= self.config.recovery_threshold && state.rate_limiting_detected {
                let new_rps = (state.current_rps * self.config.recovery_multiplier)
                    .min(state.max_rps);

                if new_rps > state.current_rps {
                    debug!(
                        "Rate recovery for {}: increasing RPS from {:.2} to {:.2}",
                        domain, state.current_rps, new_rps
                    );
                    state.current_rps = new_rps;
                    state.success_streak = 0;
                }
            }

            // Slow down if response times are increasing significantly
            if response.response_time_ms > self.config.slowdown_threshold_ms
                && state.avg_response_time_ms > state.baseline_response_time_ms * 3.0
            {
                let new_rps = (state.current_rps * 0.8).max(state.min_rps);
                debug!(
                    "Response time slowdown for {}: reducing RPS from {:.2} to {:.2}",
                    domain, state.current_rps, new_rps
                );
                state.current_rps = new_rps;
            }
        }
    }

    /// Get current rate state for a domain
    pub async fn get_domain_state(&self, url: &str) -> Option<DomainRateState> {
        let domain = Self::extract_domain(url);
        let states = self.domain_states.read().await;
        states.get(&domain).cloned()
    }

    /// Get statistics for all domains
    pub async fn get_stats(&self) -> HashMap<String, DomainRateState> {
        let states = self.domain_states.read().await;
        states.clone()
    }

    /// Reset rate limiter state for a domain
    pub async fn reset_domain(&self, url: &str) {
        let domain = Self::extract_domain(url);
        let mut states = self.domain_states.write().await;
        states.remove(&domain);
    }

    /// Reset all rate limiter state
    pub async fn reset_all(&self) {
        let mut states = self.domain_states.write().await;
        states.clear();
    }
}

impl Default for AdaptiveRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_backoff() {
        let limiter = AdaptiveRateLimiter::new();

        // Simulate rate limit response
        let response = ResponseInfo {
            status_code: 429,
            response_time_ms: 100,
            retry_after_secs: Some(5),
            has_rate_limit_headers: true,
        };

        limiter.update_from_response("https://example.com/api", &response).await;

        let state = limiter.get_domain_state("https://example.com/api").await.unwrap();
        assert!(state.current_rps < 10.0, "RPS should decrease after 429");
        assert!(state.rate_limiting_detected);
        assert_eq!(state.retry_after, Some(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn test_rate_recovery() {
        let config = RateLimiterConfig {
            recovery_threshold: 3,  // Low threshold for testing
            ..Default::default()
        };
        let limiter = AdaptiveRateLimiter::with_config(config);

        // First, trigger rate limiting
        let rate_limit_response = ResponseInfo {
            status_code: 429,
            response_time_ms: 100,
            retry_after_secs: None,
            has_rate_limit_headers: true,
        };
        limiter.update_from_response("https://example.com", &rate_limit_response).await;

        let state_after_limit = limiter.get_domain_state("https://example.com").await.unwrap();
        let limited_rps = state_after_limit.current_rps;

        // Simulate successful responses
        let success_response = ResponseInfo {
            status_code: 200,
            response_time_ms: 100,
            retry_after_secs: None,
            has_rate_limit_headers: false,
        };

        for _ in 0..5 {
            limiter.update_from_response("https://example.com", &success_response).await;
        }

        let state_after_recovery = limiter.get_domain_state("https://example.com").await.unwrap();
        assert!(
            state_after_recovery.current_rps >= limited_rps,
            "RPS should recover after success streak"
        );
    }

    #[tokio::test]
    async fn test_domain_isolation() {
        let limiter = AdaptiveRateLimiter::new();

        let response = ResponseInfo {
            status_code: 429,
            response_time_ms: 100,
            retry_after_secs: None,
            has_rate_limit_headers: true,
        };

        // Rate limit one domain
        limiter.update_from_response("https://example.com/api", &response).await;

        // Other domain should be unaffected
        let other_state = limiter.get_domain_state("https://other.com/api").await;
        assert!(other_state.is_none(), "Other domain should not be affected");
    }
}
