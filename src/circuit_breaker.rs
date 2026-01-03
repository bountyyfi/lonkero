// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Circuit Breaker Pattern
 * Prevents cascading failures by tracking endpoint health
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
struct CircuitStatus {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitStatus {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
        }
    }
}

pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout: Duration,
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    circuits: Arc<RwLock<HashMap<String, CircuitStatus>>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn extract_host(url: &str) -> String {
        Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub async fn is_request_allowed(&self, url: &str) -> bool {
        let host = Self::extract_host(url);
        let mut circuits = self.circuits.write().await;

        let status = circuits
            .entry(host.clone())
            .or_insert_with(CircuitStatus::new);

        match status.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let elapsed = status.last_state_change.elapsed();
                if elapsed >= self.config.timeout {
                    debug!("Circuit breaker transitioning to half-open for {}", host);
                    status.state = CircuitState::HalfOpen;
                    status.success_count = 0;
                    status.last_state_change = Instant::now();
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => status.success_count < self.config.half_open_max_requests,
        }
    }

    pub async fn record_success(&self, url: &str) {
        let host = Self::extract_host(url);
        let mut circuits = self.circuits.write().await;

        let status = circuits
            .entry(host.clone())
            .or_insert_with(CircuitStatus::new);

        match status.state {
            CircuitState::Closed => {
                status.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                status.success_count += 1;
                if status.success_count >= self.config.success_threshold {
                    debug!(
                        "Circuit breaker closing for {} after {} successes",
                        host, status.success_count
                    );
                    status.state = CircuitState::Closed;
                    status.failure_count = 0;
                    status.success_count = 0;
                    status.last_state_change = Instant::now();
                }
            }
            CircuitState::Open => {}
        }
    }

    pub async fn record_failure(&self, url: &str) {
        let host = Self::extract_host(url);
        let mut circuits = self.circuits.write().await;

        let status = circuits
            .entry(host.clone())
            .or_insert_with(CircuitStatus::new);

        status.failure_count += 1;
        status.last_failure_time = Some(Instant::now());

        match status.state {
            CircuitState::Closed => {
                if status.failure_count >= self.config.failure_threshold {
                    warn!(
                        "Circuit breaker opening for {} after {} consecutive failures",
                        host, status.failure_count
                    );
                    status.state = CircuitState::Open;
                    status.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                warn!(
                    "Circuit breaker reopening for {} after failure in half-open state",
                    host
                );
                status.state = CircuitState::Open;
                status.success_count = 0;
                status.last_state_change = Instant::now();
            }
            CircuitState::Open => {}
        }
    }

    pub async fn get_state(&self, url: &str) -> CircuitState {
        let host = Self::extract_host(url);
        let circuits = self.circuits.read().await;

        circuits
            .get(&host)
            .map(|s| s.state)
            .unwrap_or(CircuitState::Closed)
    }

    pub async fn get_stats(&self) -> Vec<(String, CircuitState, u32, u32)> {
        let circuits = self.circuits.read().await;

        circuits
            .iter()
            .map(|(host, status)| {
                (
                    host.clone(),
                    status.state,
                    status.failure_count,
                    status.success_count,
                )
            })
            .collect()
    }

    pub async fn reset(&self, url: &str) {
        let host = Self::extract_host(url);
        let mut circuits = self.circuits.write().await;

        if let Some(status) = circuits.get_mut(&host) {
            debug!("Resetting circuit breaker for {}", host);
            status.state = CircuitState::Closed;
            status.failure_count = 0;
            status.success_count = 0;
            status.last_state_change = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(5),
            half_open_max_requests: 2,
        };

        let cb = CircuitBreaker::new(config);
        let url = "https://example.com/api/test";

        assert!(cb.is_request_allowed(url).await);

        for _ in 0..3 {
            cb.record_failure(url).await;
        }

        assert_eq!(cb.get_state(url).await, CircuitState::Open);
        assert!(!cb.is_request_allowed(url).await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
        };

        let cb = CircuitBreaker::new(config);
        let url = "https://example.com/api/test";

        cb.record_failure(url).await;
        cb.record_failure(url).await;

        assert_eq!(cb.get_state(url).await, CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(cb.is_request_allowed(url).await);
        assert_eq!(cb.get_state(url).await, CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_circuit_breaker_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_requests: 2,
        };

        let cb = CircuitBreaker::new(config);
        let url = "https://example.com/api/test";

        cb.record_failure(url).await;
        cb.record_failure(url).await;
        assert_eq!(cb.get_state(url).await, CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(cb.is_request_allowed(url).await);

        cb.record_success(url).await;
        cb.record_success(url).await;

        assert_eq!(cb.get_state(url).await, CircuitState::Closed);
    }
}
