// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Analysis Module
 * Advanced analysis capabilities for web applications
 * © 2026 Bountyy Oy
 */

pub mod adaptive_rate_limiter;
pub mod correlation_engine;
pub mod tech_detection;

pub use adaptive_rate_limiter::{AdaptiveRateLimiter, RateLimiterConfig, ResponseInfo, DomainRateState};
pub use correlation_engine::{CorrelationEngine, CorrelationResult, DiscoveredChain, AttackChain};
pub use tech_detection::{TechDetector, DetectedTechnology, TechCategory};
