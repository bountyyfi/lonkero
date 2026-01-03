// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Engine Module
 * High-performance engines for various operations
 *
 * © 2026 Bountyy Oy
 */
pub mod rule_engine;

pub use rule_engine::{
    Asset, ComparisonOperator, Condition, EngineMetrics, EvaluationResult, LogicalOperator, Rule,
    RuleEngine, RuleMetadata,
};
