// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Error Handling
 * Comprehensive error handling for cloud operations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use tracing::{warn, error, debug};

/// Cloud-specific error types
#[derive(Error, Debug)]
pub enum CloudError {
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Timeout occurred: {0}")]
    TimeoutError(String),

    #[error("Resource not found: {0}")]
    NotFoundError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Retry configuration for cloud operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f64,
    pub retry_on_rate_limit: bool,
    pub retry_on_timeout: bool,
    pub retry_on_network_error: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff_ms: 100,
            max_backoff_ms: 30000,
            backoff_multiplier: 2.0,
            retry_on_rate_limit: true,
            retry_on_timeout: true,
            retry_on_network_error: true,
        }
    }
}

/// Exponential backoff calculator
pub struct ExponentialBackoff {
    config: RetryConfig,
    current_retry: u32,
}

impl ExponentialBackoff {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            current_retry: 0,
        }
    }

    pub fn next_backoff(&mut self) -> Option<Duration> {
        if self.current_retry >= self.config.max_retries {
            return None;
        }

        let backoff_ms = (self.config.initial_backoff_ms as f64
            * self.config.backoff_multiplier.powi(self.current_retry as i32))
            .min(self.config.max_backoff_ms as f64) as u64;

        self.current_retry += 1;

        Some(Duration::from_millis(backoff_ms))
    }

    pub fn reset(&mut self) {
        self.current_retry = 0;
    }

    pub fn should_retry(&self, error: &CloudError) -> bool {
        match error {
            CloudError::RateLimitError(_) => self.config.retry_on_rate_limit,
            CloudError::TimeoutError(_) => self.config.retry_on_timeout,
            CloudError::NetworkError(_) => self.config.retry_on_network_error,
            CloudError::ApiError(_) => true,
            _ => false,
        }
    }
}

/// Retry a cloud operation with exponential backoff
pub async fn retry_with_backoff<F, Fut, T>(
    operation: F,
    config: RetryConfig,
    operation_name: &str,
) -> Result<T, CloudError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, CloudError>>,
{
    let mut backoff = ExponentialBackoff::new(config);

    loop {
        match operation().await {
            Ok(result) => {
                debug!("{} succeeded", operation_name);
                return Ok(result);
            }
            Err(e) => {
                if !backoff.should_retry(&e) {
                    error!("{} failed with non-retryable error: {}", operation_name, e);
                    return Err(e);
                }

                if let Some(delay) = backoff.next_backoff() {
                    warn!(
                        "{} failed (attempt {}): {}. Retrying in {:?}",
                        operation_name,
                        backoff.current_retry,
                        e,
                        delay
                    );
                    sleep(delay).await;
                } else {
                    error!(
                        "{} failed after {} retries: {}",
                        operation_name,
                        backoff.current_retry,
                        e
                    );
                    return Err(e);
                }
            }
        }
    }
}

/// Rate limiter for cloud API calls
pub struct CloudRateLimiter {
    requests_per_second: u32,
    last_request_time: std::sync::Arc<tokio::sync::Mutex<tokio::time::Instant>>,
}

impl CloudRateLimiter {
    pub fn new(requests_per_second: u32) -> Self {
        Self {
            requests_per_second,
            last_request_time: std::sync::Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now())),
        }
    }

    pub async fn acquire(&self) {
        let mut last_time = self.last_request_time.lock().await;
        let min_interval = Duration::from_millis(1000 / self.requests_per_second as u64);
        let elapsed = last_time.elapsed();

        if elapsed < min_interval {
            let wait_time = min_interval - elapsed;
            drop(last_time); // Release lock before sleeping
            sleep(wait_time).await;
            let mut last_time = self.last_request_time.lock().await;
            *last_time = tokio::time::Instant::now();
        } else {
            *last_time = tokio::time::Instant::now();
        }
    }
}

/// Circuit breaker for cloud operations
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    state: std::sync::Arc<tokio::sync::RwLock<CircuitState>>,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    failure_count: std::sync::Arc<tokio::sync::RwLock<u32>>,
    success_count: std::sync::Arc<tokio::sync::RwLock<u32>>,
    last_failure_time: std::sync::Arc<tokio::sync::RwLock<Option<tokio::time::Instant>>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            state: std::sync::Arc::new(tokio::sync::RwLock::new(CircuitState::Closed)),
            failure_threshold,
            success_threshold,
            timeout,
            failure_count: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
            success_count: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
            last_failure_time: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub async fn call<F, Fut, T>(&self, operation: F) -> Result<T, CloudError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, CloudError>>,
    {
        // Check if circuit should transition to half-open
        {
            let state = self.state.read().await;
            if *state == CircuitState::Open {
                let last_failure = self.last_failure_time.read().await;
                if let Some(last_time) = *last_failure {
                    if last_time.elapsed() >= self.timeout {
                        drop(last_failure);
                        drop(state);
                        let mut state_write = self.state.write().await;
                        *state_write = CircuitState::HalfOpen;
                        debug!("Circuit breaker transitioning to HalfOpen");
                    } else {
                        return Err(CloudError::ApiError("Circuit breaker is open".to_string()));
                    }
                }
            }
        }

        match operation().await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(e)
            }
        }
    }

    async fn on_success(&self) {
        let state = self.state.read().await;

        match *state {
            CircuitState::HalfOpen => {
                drop(state);
                let mut success_count = self.success_count.write().await;
                *success_count += 1;

                if *success_count >= self.success_threshold {
                    let mut state_write = self.state.write().await;
                    *state_write = CircuitState::Closed;
                    *success_count = 0;
                    let mut failure_count = self.failure_count.write().await;
                    *failure_count = 0;
                    debug!("Circuit breaker closed");
                }
            }
            CircuitState::Closed => {
                drop(state);
                let mut failure_count = self.failure_count.write().await;
                *failure_count = 0;
            }
            _ => {}
        }
    }

    async fn on_failure(&self) {
        let state = self.state.read().await;

        match *state {
            CircuitState::Closed | CircuitState::HalfOpen => {
                drop(state);
                let mut failure_count = self.failure_count.write().await;
                *failure_count += 1;

                if *failure_count >= self.failure_threshold {
                    let mut state_write = self.state.write().await;
                    *state_write = CircuitState::Open;
                    let mut last_failure = self.last_failure_time.write().await;
                    *last_failure = Some(tokio::time::Instant::now());
                    warn!("Circuit breaker opened due to failures");
                }
            }
            _ => {}
        }
    }

    pub async fn get_state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exponential_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        let mut backoff = ExponentialBackoff::new(config);

        let delay1 = backoff.next_backoff().unwrap();
        assert_eq!(delay1.as_millis(), 100);

        let delay2 = backoff.next_backoff().unwrap();
        assert_eq!(delay2.as_millis(), 200);

        let delay3 = backoff.next_backoff().unwrap();
        assert_eq!(delay3.as_millis(), 400);

        let delay4 = backoff.next_backoff();
        assert!(delay4.is_none());
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let breaker = CircuitBreaker::new(2, 1, Duration::from_millis(100));

        // First failure
        let _ = breaker
            .call(|| async { Err::<(), CloudError>(CloudError::ApiError("test".to_string())) })
            .await;
        assert_eq!(breaker.get_state().await, CircuitState::Closed);

        // Second failure should open circuit
        let _ = breaker
            .call(|| async { Err::<(), CloudError>(CloudError::ApiError("test".to_string())) })
            .await;
        assert_eq!(breaker.get_state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = CloudRateLimiter::new(10); // 10 requests per second

        let start = tokio::time::Instant::now();
        for _ in 0..3 {
            limiter.acquire().await;
        }
        let elapsed = start.elapsed();

        // Should take at least 200ms for 3 requests at 10 rps
        assert!(elapsed.as_millis() >= 200);
    }
}
