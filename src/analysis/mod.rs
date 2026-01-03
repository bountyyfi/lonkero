// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Analysis Module
 * Advanced analysis capabilities for web applications
 * © 2026 Bountyy Oy
 */
pub mod adaptive_rate_limiter;
pub mod attack_planner;
pub mod correlation_engine;
pub mod hypothesis_engine;
pub mod intelligence_bus;
pub mod response_analyzer;
pub mod tech_detection;

pub use adaptive_rate_limiter::{
    AdaptiveRateLimiter, DomainRateState, RateLimiterConfig, ResponseInfo,
};
pub use attack_planner::{
    AttackGoal, AttackPlan, AttackPlanner, AttackState, AttackStep, AttackStepType,
    BruteForceTarget, DiscoveredSecret, EnumerationTarget, FuzzTarget, KnownVulnerability,
    OAuthTokenInfo, Outcome, ParameterKnowledge, ParameterType, PlannerStats, Prerequisite,
    ReconTarget, ResetTokenInfo, SecretType, SessionInfo, Severity as AttackSeverity, StateUpdate,
    UserType,
};
pub use correlation_engine::{AttackChain, CorrelationEngine, CorrelationResult, DiscoveredChain};
pub use hypothesis_engine::{
    ContextPriors, DbType, Evidence, EvidenceType, Hypothesis, HypothesisEngine, HypothesisStats,
    HypothesisStatus, HypothesisType, NoSqlDbType, OsType, ResponseHints, SsrfTarget,
    SuggestedTest, XssContext,
};
pub use intelligence_bus::*;
pub use response_analyzer::{
    AuthState, BusinessContext, BusinessContextType, DataExposure, ErrorInfo, ErrorType,
    ExposureType, ResponseAnalyzer, ResponseSemantics, ResponseType, SecurityIndicator,
    SemanticDifference, VulnerabilityHint,
};
pub use tech_detection::{DetectedTechnology, TechCategory, TechDetector};
