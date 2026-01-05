// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// OOBZero Engine
// ==============
//
// Zero-infrastructure blind vulnerability detection via Bayesian inference.
// Detect blind SQLi, blind XSS, and other blind vulns WITHOUT callback servers.
//
// ## The Problem
//
// Traditional blind vulnerability detection requires either:
// - Visible errors (error-based detection) - often disabled in production
// - Time delays (time-based detection) - slow and unreliable over networks
// - External callbacks (OOB detection) - requires infrastructure, blocked by firewalls
//
// ## The Solution: Probabilistic Inference
//
// This engine provides a fourth approach: **multi-channel side-channel inference**.
//
// By combining multiple weak signals from independent measurement channels,
// we achieve high-confidence detection even when no single signal is conclusive.
//
// ### Key Innovations:
//
// 1. **Distinct Signal Taxonomy** - Each signal type (BooleanDifferential,
//    ArithmeticEval, QuoteCancellation, etc.) represents a unique measurement
//
// 2. **Negative Evidence** - NoChange and ConsistentBehavior signals
//    SUBTRACT from confidence, preventing false positives
//
// 3. **Independence Requirements** - Confirmation requires 2+ independent
//    signal CLASSES, with no single signal contributing >60% of evidence
//
// 4. **Statistical Effect Sizes** - Uses Cohen's d and multiple samples
//    instead of brittle threshold comparisons
//
// ## Mathematical Foundation
//
// Log-odds Bayesian framework with correlation penalties:
//
// ```
// L_posterior = L_prior + Σᵢ (wᵢ · cᵢ · logit(Sᵢ))
// P_posterior = σ(L_posterior)
// ```
//
// Where:
// - wᵢ = reliability weight (negative for negative evidence!)
// - cᵢ = correlation penalty (prevents double-counting)
// - Sᵢ = probability from signal i
// - logit(p) = ln(p / (1-p))
// - σ(x) = 1 / (1 + e^(-x))
//
// ## Usage
//
// ```rust
// let analyzer = SideChannelAnalyzer::new(http_client);
// let result = analyzer.analyze_sqli(url, param, &baseline).await;
//
// if result.is_confirmed() {
//     // High confidence: 2+ independent classes, no single dominant signal
//     report_vulnerability(...);
// }
// ```

pub mod bayesian;
pub mod signals;
pub mod channels;

pub use bayesian::{BayesianCombiner, CombinedResult, Confidence, Signal, SignalType};
// SignalType now includes: Timing, Length, Entropy, Compression, ContentHash,
// Resonance, BooleanDifferential, ArithmeticEval, QuoteCancellation, CommentInjection,
// StatusCode, HeaderDiff, ErrorPattern, NoChange, ConsistentBehavior
pub use signals::{
    EntropyAnalyzer, ErrorPatternAnalyzer, HeaderAnalyzer, LengthAnalyzer,
    ResonanceAnalyzer, SideChannelSuite, StatusCodeAnalyzer, TimingAnalyzer,
};
pub use channels::{SideChannelAnalyzer, SideChannelResult};
