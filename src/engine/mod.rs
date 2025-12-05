// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Engine Module
 * High-performance engines for various operations
 *
 * © 2025 Bountyy Oy
 */

pub mod rule_engine;

pub use rule_engine::{
    RuleEngine, Rule, Condition, LogicalOperator, ComparisonOperator,
    Asset, EvaluationResult, EngineMetrics, RuleMetadata
};
