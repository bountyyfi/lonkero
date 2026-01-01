// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Retry Logic with Exponential Backoff
 * Production-ready retry mechanisms with jitter
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::errors::{ScannerError, ScannerResult};
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry configuration with exponential backoff
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Initial backoff duration
    pub initial_backoff: Duration,

    /// Maximum backoff duration
    pub max_backoff: Duration,

    /// Backoff multiplier (typically 2.0 for exponential)
    pub backoff_multiplier: f64,

    /// Enable jitter to prevent thundering herd
    pub enable_jitter: bool,

    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            enable_jitter: true,
            jitter_factor: 0.3,
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with custom max attempts
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Create a new retry config with custom initial backoff
    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    /// Create a new retry config with custom max backoff
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Create a new retry config with custom multiplier
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Create a new retry config without jitter
    pub fn without_jitter(mut self) -> Self {
        self.enable_jitter = false;
        self
    }

    /// Calculate backoff duration for a given attempt
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_secs(0);
        }

        let base_backoff = self.initial_backoff.as_millis() as f64
            * self.backoff_multiplier.powi((attempt - 1) as i32);

        let capped_backoff = base_backoff.min(self.max_backoff.as_millis() as f64);

        let backoff_with_jitter = if self.enable_jitter {
            let mut rng = rand::rng();
            let jitter_range = capped_backoff * self.jitter_factor;
            let jitter = rng.random_range(-jitter_range..jitter_range);
            (capped_backoff + jitter).max(0.0)
        } else {
            capped_backoff
        };

        Duration::from_millis(backoff_with_jitter as u64)
    }
}

/// Retry a future with exponential backoff
pub async fn retry_with_backoff<F, Fut, T>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> ScannerResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ScannerResult<T>>,
{
    let mut attempt = 0;
    let mut last_error: Option<ScannerError> = None;

    while attempt < config.max_attempts {
        attempt += 1;

        debug!(
            attempt = attempt,
            max_attempts = config.max_attempts,
            operation = operation_name,
            "Executing operation"
        );

        match operation().await {
            Ok(result) => {
                if attempt > 1 {
                    debug!(
                        attempt = attempt,
                        operation = operation_name,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(err) => {
                let is_retryable = err.is_retryable();
                let custom_delay = err.retry_delay();

                warn!(
                    attempt = attempt,
                    max_attempts = config.max_attempts,
                    operation = operation_name,
                    error = %err,
                    retryable = is_retryable,
                    "Operation failed"
                );

                if !is_retryable {
                    debug!(
                        operation = operation_name,
                        "Error is not retryable, aborting"
                    );
                    return Err(err);
                }

                last_error = Some(err);

                if attempt < config.max_attempts {
                    let backoff = custom_delay.unwrap_or_else(|| config.calculate_backoff(attempt));

                    debug!(
                        attempt = attempt,
                        backoff_ms = backoff.as_millis(),
                        operation = operation_name,
                        "Backing off before retry"
                    );

                    tokio::time::sleep(backoff).await;
                } else {
                    warn!(
                        operation = operation_name,
                        attempts = attempt,
                        "Max retry attempts reached"
                    );
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ScannerError::General(format!(
            "Operation '{}' failed after {} attempts",
            operation_name, config.max_attempts
        ))
    }))
}

/// Retry a fallible operation with custom retry predicate
pub async fn retry_with_predicate<F, Fut, T, P>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
    mut should_retry: P,
) -> ScannerResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ScannerResult<T>>,
    P: FnMut(&ScannerError) -> bool,
{
    let mut attempt = 0;
    let mut last_error: Option<ScannerError> = None;

    while attempt < config.max_attempts {
        attempt += 1;

        match operation().await {
            Ok(result) => {
                if attempt > 1 {
                    debug!(
                        attempt = attempt,
                        operation = operation_name,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(err) => {
                if !should_retry(&err) {
                    debug!(
                        operation = operation_name,
                        "Custom predicate determined not to retry"
                    );
                    return Err(err);
                }

                warn!(
                    attempt = attempt,
                    max_attempts = config.max_attempts,
                    operation = operation_name,
                    error = %err,
                    "Operation failed, retrying"
                );

                last_error = Some(err);

                if attempt < config.max_attempts {
                    let backoff = config.calculate_backoff(attempt);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ScannerError::General(format!(
            "Operation '{}' failed after {} attempts",
            operation_name, config.max_attempts
        ))
    }))
}

/// Simplified retry for operations that don't need complex configuration
pub async fn simple_retry<F, Fut, T>(
    max_attempts: u32,
    operation_name: &str,
    operation: F,
) -> ScannerResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ScannerResult<T>>,
{
    let config = RetryConfig::default().with_max_attempts(max_attempts);
    retry_with_backoff(&config, operation_name, operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_backoff_calculation() {
        let config = RetryConfig {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            enable_jitter: false,
            jitter_factor: 0.0,
        };

        assert_eq!(config.calculate_backoff(0), Duration::from_secs(0));
        assert_eq!(config.calculate_backoff(1), Duration::from_millis(100));
        assert_eq!(config.calculate_backoff(2), Duration::from_millis(200));
        assert_eq!(config.calculate_backoff(3), Duration::from_millis(400));
        assert_eq!(config.calculate_backoff(4), Duration::from_millis(800));
    }

    #[test]
    fn test_backoff_with_max_cap() {
        let config = RetryConfig {
            max_attempts: 10,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            enable_jitter: false,
            jitter_factor: 0.0,
        };

        assert_eq!(config.calculate_backoff(1), Duration::from_secs(1));
        assert_eq!(config.calculate_backoff(2), Duration::from_secs(2));
        assert_eq!(config.calculate_backoff(3), Duration::from_secs(4));
        assert_eq!(config.calculate_backoff(4), Duration::from_secs(5));
        assert_eq!(config.calculate_backoff(5), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_retry_succeeds_eventually() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let config = RetryConfig::default().with_max_attempts(3).without_jitter();

        let result: ScannerResult<&str> = retry_with_backoff(&config, "test_operation", || {
            let counter = Arc::clone(&counter_clone);
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(ScannerError::Timeout {
                        duration: Duration::from_secs(1),
                    })
                } else {
                    Ok("Success")
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_fails_after_max_attempts() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let config = RetryConfig::default().with_max_attempts(3).without_jitter();

        let result: ScannerResult<()> = retry_with_backoff(&config, "test_operation", || {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(ScannerError::Timeout {
                    duration: Duration::from_secs(1),
                })
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_stops_on_non_retryable_error() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let config = RetryConfig::default().with_max_attempts(5).without_jitter();

        let result: ScannerResult<()> = retry_with_backoff(&config, "test_operation", || {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(ScannerError::Configuration("Invalid config".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
