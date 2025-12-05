// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Security Scanner - Validation Module
 * Validation utilities for exclusions, targets, and scan configurations
 *
 * Copyright 2025 Bountyy Oy
 */

pub mod exclusion_validator;

pub use exclusion_validator::{
    ExclusionRule,
    ExclusionValidator,
    TimeWindow,
    ValidationResult,
    MatchedRule,
};
