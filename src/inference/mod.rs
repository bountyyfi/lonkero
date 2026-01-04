// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Probabilistic Inference Engine for Low-Bandwidth Security Side Channels
//
// This module implements a Bayesian framework for combining weak signals
// from multiple detection channels to infer vulnerabilities without
// requiring out-of-band callbacks.
//
// ## The Core Insight
//
// Traditional vulnerability detection requires either:
// - Visible errors (error-based detection)
// - Time delays (time-based detection)
// - External callbacks (OOB detection)
//
// This module provides a fourth approach: **probabilistic inference**.
//
// By combining multiple weak signals (timing variations, content length
// changes, entropy shifts, compression ratio changes, etc.), we can
// infer vulnerabilities with high confidence even when no single signal
// is conclusive.
//
// ## Mathematical Foundation
//
// We use a log-odds Bayesian framework:
//
// ```
// L_posterior = L_prior + Σᵢ (wᵢ · cᵢ · logit(Sᵢ))
// P_posterior = σ(L_posterior)
// ```
//
// Where:
// - wᵢ = reliability weight of signal i
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
//     report_vulnerability(...);
// }
// ```

pub mod bayesian;
pub mod signals;
pub mod channels;

pub use bayesian::{BayesianCombiner, CombinedResult, Confidence, Signal, SignalType};
pub use signals::{
    EntropyAnalyzer, ErrorPatternAnalyzer, HeaderAnalyzer, LengthAnalyzer,
    ResonanceAnalyzer, SideChannelSuite, StatusCodeAnalyzer, TimingAnalyzer,
};
pub use channels::{SideChannelAnalyzer, SideChannelResult};
