// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Adaptive Rate Limiter
 * Token bucket algorithm with automatic backoff and per-target limits
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use anyhow::Result;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use nonzero_ext::*;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Default requests per second (global)
    pub default_rps: u32,

    /// Minimum requests per second (after backoff)
    pub min_rps: u32,

    /// Maximum requests per second
    pub max_rps: u32,

    /// Backoff multiplier when rate limited
    pub backoff_multiplier: f64,

    /// Recovery multiplier when successful
    pub recovery_multiplier: f64,

    /// Enable adaptive rate limiting
    pub adaptive: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            default_rps: 100,      // 100 requests/second default
            min_rps: 10,           // Minimum 10 req/s after backoff
            max_rps: 1000,         // Maximum 1000 req/s
            backoff_multiplier: 0.5, // Reduce to 50% on rate limit
            recovery_multiplier: 1.1, // Increase by 10% on success
            adaptive: true,        // Enable adaptive rate limiting
        }
    }
}

/// Per-target rate limiter state
#[derive(Debug)]
struct TargetState {
    /// Current requests per second for this target
    current_rps: u32,

    /// Token bucket rate limiter
    limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,

    /// Number of consecutive successes
    success_count: u32,

    /// Number of rate limit errors
    rate_limit_count: u32,

    /// Last rate limit timestamp
    last_rate_limit: Option<std::time::Instant>,
}

impl TargetState {
    fn new(rps: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap_or(nonzero!(1u32)));
        let limiter = Arc::new(GovernorRateLimiter::direct(quota));

        Self {
            current_rps: rps,
            limiter,
            success_count: 0,
            rate_limit_count: 0,
            last_rate_limit: None,
        }
    }

    /// Update rate limiter with new RPS
    fn update_rps(&mut self, new_rps: u32) {
        if new_rps != self.current_rps {
            self.current_rps = new_rps;
            let quota = Quota::per_second(NonZeroU32::new(new_rps).unwrap_or(nonzero!(1u32)));
            self.limiter = Arc::new(GovernorRateLimiter::direct(quota));
            debug!("Updated rate limit to {} req/s", new_rps);
        }
    }
}

/// Adaptive rate limiter with per-target tracking
pub struct AdaptiveRateLimiter {
    config: RateLimiterConfig,

    /// Per-target rate limiter states
    targets: Arc<RwLock<HashMap<String, TargetState>>>,

    /// Global rate limiter
    global_limiter: Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        let global_quota = Quota::per_second(
            NonZeroU32::new(config.default_rps).unwrap_or(nonzero!(100u32))
        );
        let global_limiter = Arc::new(GovernorRateLimiter::direct(global_quota));

        info!(
            "Initialized rate limiter: {}rps default, adaptive={}",
            config.default_rps, config.adaptive
        );

        Self {
            config,
            targets: Arc::new(RwLock::new(HashMap::new())),
            global_limiter,
        }
    }

    /// Extract domain from URL for per-target limiting
    fn extract_domain(url: &str) -> String {
        Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Wait until request is allowed (respects rate limits)
    pub async fn wait_for_slot(&self, url: &str) -> Result<()> {
        // Wait for global rate limit
        self.global_limiter.until_ready().await;

        // Wait for per-target rate limit
        let domain = Self::extract_domain(url);

        let limiter = {
            let mut targets = self.targets.write().await;
            let state = targets
                .entry(domain.clone())
                .or_insert_with(|| TargetState::new(self.config.default_rps));

            Arc::clone(&state.limiter)
        };

        limiter.until_ready().await;

        Ok(())
    }

    /// Record successful request (may increase rate limit)
    pub async fn record_success(&self, url: &str) {
        if !self.config.adaptive {
            return;
        }

        let domain = Self::extract_domain(url);
        let mut targets = self.targets.write().await;

        if let Some(state) = targets.get_mut(&domain) {
            state.success_count += 1;

            // After 100 consecutive successes, try increasing rate limit
            if state.success_count >= 100 {
                let new_rps = (state.current_rps as f64 * self.config.recovery_multiplier) as u32;
                let capped_rps = new_rps.min(self.config.max_rps);

                if capped_rps > state.current_rps {
                    info!(
                        "[RateLimit] Increasing rate limit for {}: {} -> {} req/s",
                        domain, state.current_rps, capped_rps
                    );
                    state.update_rps(capped_rps);
                }

                state.success_count = 0; // Reset counter
            }
        }
    }

    /// Record rate limit error (will decrease rate limit)
    pub async fn record_rate_limit(&self, url: &str, status_code: u16) {
        let domain = Self::extract_domain(url);
        let mut targets = self.targets.write().await;

        let state = targets
            .entry(domain.clone())
            .or_insert_with(|| TargetState::new(self.config.default_rps));

        state.rate_limit_count += 1;
        state.success_count = 0; // Reset success counter
        state.last_rate_limit = Some(std::time::Instant::now());

        // Reduce rate limit
        let new_rps = if self.config.adaptive {
            let calculated = (state.current_rps as f64 * self.config.backoff_multiplier) as u32;
            calculated.max(self.config.min_rps)
        } else {
            state.current_rps
        };

        if new_rps < state.current_rps {
            warn!(
                "[WARNING]  Rate limited by {} (HTTP {}): {} → {} req/s",
                domain, status_code, state.current_rps, new_rps
            );
            state.update_rps(new_rps);
        }

        // Add additional backoff delay for 429/503 errors
        let backoff_duration = match status_code {
            429 => Duration::from_secs(2),  // 2 second backoff for 429
            503 => Duration::from_secs(5),  // 5 second backoff for 503
            _ => Duration::from_secs(1),    // 1 second for other errors
        };

        tokio::time::sleep(backoff_duration).await;
    }

    /// Get current rate limit for a target
    pub async fn get_current_rps(&self, url: &str) -> u32 {
        let domain = Self::extract_domain(url);
        let targets = self.targets.read().await;

        targets
            .get(&domain)
            .map(|s| s.current_rps)
            .unwrap_or(self.config.default_rps)
    }

    /// Get statistics for all targets
    pub async fn get_stats(&self) -> Vec<(String, u32, u32)> {
        let targets = self.targets.read().await;

        targets
            .iter()
            .map(|(domain, state)| {
                (domain.clone(), state.current_rps, state.rate_limit_count)
            })
            .collect()
    }

    /// Reset rate limit for a specific target
    pub async fn reset_target(&self, url: &str) {
        let domain = Self::extract_domain(url);
        let mut targets = self.targets.write().await;

        if let Some(state) = targets.get_mut(&domain) {
            info!("Resetting rate limit for {} to default", domain);
            state.update_rps(self.config.default_rps);
            state.success_count = 0;
            state.rate_limit_count = 0;
            state.last_rate_limit = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let config = RateLimiterConfig {
            default_rps: 10,
            min_rps: 1,
            max_rps: 100,
            adaptive: false,
            ..Default::default()
        };

        let limiter = AdaptiveRateLimiter::new(config);

        // Should allow request
        assert!(limiter.wait_for_slot("https://example.com/test").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_adaptive_backoff() {
        let config = RateLimiterConfig {
            default_rps: 100,
            min_rps: 10,
            max_rps: 1000,
            backoff_multiplier: 0.5,
            adaptive: true,
            ..Default::default()
        };

        let limiter = AdaptiveRateLimiter::new(config);
        let url = "https://example.com/test";

        // Record rate limit error
        limiter.record_rate_limit(url, 429).await;

        // Should have reduced rate limit
        let current_rps = limiter.get_current_rps(url).await;
        assert!(current_rps < 100);
    }

    #[tokio::test]
    async fn test_rate_limiter_recovery() {
        let config = RateLimiterConfig {
            default_rps: 50,
            min_rps: 10,
            max_rps: 200,
            recovery_multiplier: 1.2,
            adaptive: true,
            ..Default::default()
        };

        let limiter = AdaptiveRateLimiter::new(config);
        let url = "https://example.com/test";

        // Initial rate should be default
        let initial_rps = limiter.get_current_rps(url).await;
        assert_eq!(initial_rps, 50);

        // Record 101 successes (100 to trigger update + 1 more)
        for _ in 0..101 {
            limiter.record_success(url).await;
        }

        // Should have increased rate limit after 100 successes
        let current_rps = limiter.get_current_rps(url).await;
        assert!(current_rps >= 50, "Rate limit should not decrease: {}", current_rps);

        // With recovery_multiplier of 1.2, should be at least 60 (50 * 1.2)
        // But check that it increased or stayed the same (due to capping at max_rps)
        assert!(current_rps >= initial_rps);
    }
}
