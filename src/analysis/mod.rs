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

pub use adaptive_rate_limiter::{AdaptiveRateLimiter, RateLimiterConfig, ResponseInfo, DomainRateState};
pub use attack_planner::{
    AttackPlanner, AttackPlan, AttackStep, AttackStepType, AttackGoal, AttackState,
    StateUpdate, Prerequisite, Outcome, KnownVulnerability, SessionInfo, UserType,
    Severity as AttackSeverity, ParameterType, ParameterKnowledge, DiscoveredSecret, SecretType,
    EnumerationTarget, BruteForceTarget, FuzzTarget, ReconTarget, PlannerStats,
    ResetTokenInfo, OAuthTokenInfo,
};
pub use correlation_engine::{CorrelationEngine, CorrelationResult, DiscoveredChain, AttackChain};
pub use hypothesis_engine::{
    HypothesisEngine, Hypothesis, HypothesisType, HypothesisStatus,
    Evidence, EvidenceType, SuggestedTest, ContextPriors, ResponseHints,
    DbType, XssContext, OsType, SsrfTarget, NoSqlDbType, HypothesisStats,
};
pub use intelligence_bus::*;
pub use response_analyzer::{
    ResponseAnalyzer, ResponseSemantics, ResponseType, AuthState, ErrorInfo, ErrorType,
    BusinessContext, BusinessContextType, DataExposure, ExposureType, SecurityIndicator,
    SemanticDifference, VulnerabilityHint,
};
pub use tech_detection::{TechDetector, DetectedTechnology, TechCategory};
