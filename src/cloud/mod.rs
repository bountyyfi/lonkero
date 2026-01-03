// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Security Infrastructure
 * Core cloud security modules and utilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
pub mod error_handling;
pub mod optimizations;

// Re-exports
pub use error_handling::{
    retry_with_backoff, CircuitBreaker, CloudError, CloudRateLimiter, ExponentialBackoff,
    RetryConfig,
};
pub use optimizations::{
    BatchRequestProcessor, CloudConnectionPool, CloudMetadataCache, ConnectionGuard,
    ParallelExecutor, PerformanceMetrics, PoolStats, RequestDeduplicator,
};
