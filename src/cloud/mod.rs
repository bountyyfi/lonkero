// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Security Infrastructure
 * Core cloud security modules and utilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

pub mod error_handling;
pub mod optimizations;

// Re-exports
pub use error_handling::{CloudError, RetryConfig, ExponentialBackoff, CloudRateLimiter, CircuitBreaker, retry_with_backoff};
pub use optimizations::{
    CloudMetadataCache,
    CloudConnectionPool,
    ConnectionGuard,
    PoolStats,
    BatchRequestProcessor,
    ParallelExecutor,
    RequestDeduplicator,
    PerformanceMetrics,
};
