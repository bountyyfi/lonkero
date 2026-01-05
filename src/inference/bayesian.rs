// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Bayesian Signal Combiner
//
// Combines multiple probabilistic signals using log-odds framework
// with correlation penalties and reliability weighting.

use std::collections::HashMap;

/// Signal types for vulnerability detection
///
/// IMPORTANT: Each signal type represents a DISTINCT measurement channel.
/// Do NOT reuse signal types for semantically different measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalType {
    // === Timing-based signals ===
    Timing,              // Response time analysis (z-score from baseline)

    // === Content-based signals ===
    Length,              // Content length differential
    Entropy,             // Response entropy changes (Shannon entropy)
    Compression,         // Compression ratio oracle
    ContentHash,         // Structural content fingerprint

    // === Behavioral signals ===
    Resonance,           // Quote oscillation pattern (', '', ''', '''')
    BooleanDifferential, // AND 1=1 vs AND 1=2 behavioral difference
    ArithmeticEval,      // 7-1 = 6 math evaluation detected
    QuoteCancellation,   // value'' = value detection
    CommentInjection,    // value'-- = value detection

    // === Encoding signals (NEW) ===
    HexEncoding,         // 0x61646D696E = admin (SQL decoded hex)
    UnicodeNorm,         // café vs cafe\u0301 normalization
    NullByteTrunc,       // value%00garbage = value (null truncation)
    CaseSensitivity,     // ADMIN vs admin (collation detection)

    // === WAF signals (NEW) ===
    WafBlock,            // WAF blocked payload (inverted signal)
    WafBypass,           // WAF bypassed = likely vulnerable

    // === HTTP signals ===
    StatusCode,          // HTTP status changes
    HeaderDiff,          // Header fingerprint changes

    // === Pattern detection ===
    ErrorPattern,        // Error message detection (regex-based)

    // === Negative evidence ===
    NoChange,            // Response unchanged (reduces confidence)
    ConsistentBehavior,  // Behavior is consistent regardless of payload
}

/// A single probabilistic signal
#[derive(Debug, Clone)]
pub struct Signal {
    pub signal_type: SignalType,
    pub probability: f64,    // P(vulnerable | signal) ∈ (0, 1)
    pub raw_evidence: f64,   // Raw measurement value
    pub description: String, // Human-readable explanation
}

impl Signal {
    pub fn new(signal_type: SignalType, probability: f64, evidence: f64, desc: &str) -> Self {
        Self {
            signal_type,
            probability: probability.clamp(0.001, 0.999), // Avoid log(0)
            raw_evidence: evidence,
            description: desc.to_string(),
        }
    }
}

/// Bayesian combiner for probabilistic signals
pub struct BayesianCombiner {
    /// Prior probability of vulnerability (before any signals)
    prior: f64,

    /// Reliability weights for each signal type
    weights: HashMap<SignalType, f64>,

    /// Correlation matrix between signal types
    /// correlation[i][j] = how correlated signals i and j are
    correlations: HashMap<(SignalType, SignalType), f64>,

    /// Temperature for probability calibration
    /// T > 1.0 = softer probabilities (less extreme, more calibrated)
    /// T < 1.0 = sharper probabilities (more extreme)
    /// T = 1.0 = no scaling (default)
    temperature: f64,
}

impl Default for BayesianCombiner {
    fn default() -> Self {
        Self::new()
    }
}

impl BayesianCombiner {
    pub fn new() -> Self {
        Self::with_temperature(1.0)
    }

    /// Create a combiner with custom temperature for calibration
    /// T > 1.0 = softer (more calibrated), T < 1.0 = sharper
    pub fn with_temperature(temperature: f64) -> Self {
        let mut combiner = Self {
            prior: 0.05, // 5% prior - vulnerabilities are relatively rare
            weights: HashMap::new(),
            correlations: HashMap::new(),
            temperature: temperature.max(0.1), // Prevent division issues
        };

        // Initialize reliability weights
        // Higher = more reliable signal
        //
        // Weight philosophy:
        // - Direct evidence (error patterns, behavioral diffs) = high weight
        // - Statistical signals (timing, length) = medium weight
        // - Negative evidence = negative weight (subtracts confidence)
        combiner.weights.insert(SignalType::Timing, 0.6);
        combiner.weights.insert(SignalType::Length, 0.5);
        combiner.weights.insert(SignalType::Entropy, 0.4);
        combiner.weights.insert(SignalType::Compression, 0.5);
        combiner.weights.insert(SignalType::ContentHash, 0.4);

        // Behavioral signals - these are the strongest evidence
        combiner.weights.insert(SignalType::Resonance, 0.8);
        combiner.weights.insert(SignalType::BooleanDifferential, 0.85);
        combiner.weights.insert(SignalType::ArithmeticEval, 0.9);
        combiner.weights.insert(SignalType::QuoteCancellation, 0.85);
        combiner.weights.insert(SignalType::CommentInjection, 0.85);

        // Encoding signals - strong evidence when detected
        combiner.weights.insert(SignalType::HexEncoding, 0.9);      // Very strong
        combiner.weights.insert(SignalType::UnicodeNorm, 0.75);     // Good signal
        combiner.weights.insert(SignalType::NullByteTrunc, 0.85);   // Classic SQLi indicator
        combiner.weights.insert(SignalType::CaseSensitivity, 0.6);  // Weaker but useful

        // WAF signals - inverted logic
        combiner.weights.insert(SignalType::WafBlock, 0.5);         // WAF blocked = payload is "dangerous"
        combiner.weights.insert(SignalType::WafBypass, 0.7);        // Bypass worked = likely vuln

        // HTTP signals
        combiner.weights.insert(SignalType::StatusCode, 0.7);
        combiner.weights.insert(SignalType::HeaderDiff, 0.4);

        // Pattern detection - very high weight when found
        combiner.weights.insert(SignalType::ErrorPattern, 0.95);

        // NEGATIVE EVIDENCE - these REDUCE confidence
        // Implemented as negative weights that subtract from log-odds
        combiner.weights.insert(SignalType::NoChange, -0.6);
        combiner.weights.insert(SignalType::ConsistentBehavior, -0.7);

        // Initialize correlation matrix
        combiner.init_correlations();

        combiner
    }

    /// Initialize correlation matrix
    /// Correlated signals shouldn't double-count evidence
    fn init_correlations(&mut self) {
        use SignalType::*;

        // All signal types
        let all_types = [
            Timing, Length, Entropy, Compression, ContentHash,
            Resonance, BooleanDifferential, ArithmeticEval, QuoteCancellation, CommentInjection,
            HexEncoding, UnicodeNorm, NullByteTrunc, CaseSensitivity,
            WafBlock, WafBypass,
            StatusCode, HeaderDiff, ErrorPattern,
            NoChange, ConsistentBehavior,
        ];

        // Self-correlation is always 1.0
        for st in all_types {
            self.correlations.insert((st, st), 1.0);
        }

        // Cross-correlations (symmetric)
        // Philosophy: signals from same measurement channel = high correlation
        //            signals from different channels = low/no correlation
        let pairs = [
            // === Content-based signals correlate with each other ===
            ((Length, Entropy), 0.5),
            ((Length, Compression), 0.7),      // Very correlated
            ((Length, ContentHash), 0.6),
            ((Entropy, Compression), 0.6),
            ((Entropy, ContentHash), 0.5),
            ((Compression, ContentHash), 0.5),

            // === Timing correlates weakly with content ===
            ((Timing, Length), 0.3),           // Bigger response = slower
            ((Timing, Entropy), 0.15),         // Processing complexity

            // === Timing vs behavioral signals (weak correlation) ===
            // Behavioral tests might affect timing slightly
            ((Timing, BooleanDifferential), 0.2),
            ((Timing, ArithmeticEval), 0.2),
            ((Timing, Resonance), 0.25),

            // === Behavioral signals are INDEPENDENT of each other ===
            // This is critical - boolean diff, arithmetic, quote cancellation
            // are distinct tests measuring different phenomena
            ((BooleanDifferential, ArithmeticEval), 0.1),  // Low correlation
            ((BooleanDifferential, QuoteCancellation), 0.15),
            ((BooleanDifferential, CommentInjection), 0.15),
            ((ArithmeticEval, QuoteCancellation), 0.1),
            ((ArithmeticEval, CommentInjection), 0.1),
            ((QuoteCancellation, CommentInjection), 0.2),

            // === Resonance vs other behavioral signals ===
            ((Resonance, BooleanDifferential), 0.3),
            ((Resonance, QuoteCancellation), 0.4),  // Similar mechanism
            ((Resonance, ArithmeticEval), 0.15),
            ((Resonance, CommentInjection), 0.35),

            // === HTTP signals ===
            ((StatusCode, ErrorPattern), 0.7),     // Error often changes status
            ((StatusCode, HeaderDiff), 0.5),
            ((ErrorPattern, HeaderDiff), 0.4),
            ((StatusCode, Length), 0.4),           // Error pages often different size
            ((StatusCode, Timing), 0.25),          // Errors may be faster/slower

            // === Encoding signals are INDEPENDENT of behavioral signals ===
            // They measure different phenomena (encoding vs query structure)
            ((HexEncoding, ArithmeticEval), 0.15),
            ((HexEncoding, BooleanDifferential), 0.1),
            ((HexEncoding, UnicodeNorm), 0.3),       // Both test encoding
            ((HexEncoding, NullByteTrunc), 0.2),
            ((UnicodeNorm, NullByteTrunc), 0.25),
            ((UnicodeNorm, CaseSensitivity), 0.4),   // Both test string handling
            ((NullByteTrunc, QuoteCancellation), 0.2),
            ((CaseSensitivity, BooleanDifferential), 0.15),

            // === WAF signals ===
            ((WafBlock, WafBypass), 0.6),            // Related but different
            ((WafBlock, StatusCode), 0.5),           // WAF often returns 403
            ((WafBypass, ErrorPattern), 0.3),        // Bypass might expose errors

            // === Negative evidence correlates with content signals ===
            ((NoChange, Length), 0.8),
            ((NoChange, ContentHash), 0.9),
            ((NoChange, Entropy), 0.6),
            ((ConsistentBehavior, NoChange), 0.7),
            ((ConsistentBehavior, Length), 0.5),
        ];

        for ((a, b), corr) in pairs {
            self.correlations.insert((a, b), corr);
            self.correlations.insert((b, a), corr); // Symmetric
        }
    }

    /// Get correlation between two signal types
    fn get_correlation(&self, a: SignalType, b: SignalType) -> f64 {
        self.correlations.get(&(a, b)).copied().unwrap_or(0.0)
    }

    /// Convert probability to log-odds
    /// logit(p) = ln(p / (1-p))
    #[inline]
    fn logit(p: f64) -> f64 {
        let p = p.clamp(0.001, 0.999);
        (p / (1.0 - p)).ln()
    }

    /// Convert log-odds to probability
    /// σ(x) = 1 / (1 + e^(-x))
    #[inline]
    fn sigmoid(x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    /// Calculate correlation penalty for a signal given already-processed signals
    ///
    /// The penalty reduces the weight of correlated signals to prevent
    /// double-counting of evidence from related channels.
    fn correlation_penalty(&self, signal_type: SignalType, processed: &[SignalType]) -> f64 {
        if processed.is_empty() {
            return 1.0; // No penalty for first signal
        }

        // Find maximum correlation with any processed signal
        let max_corr = processed.iter()
            .map(|&s| self.get_correlation(signal_type, s))
            .fold(0.0_f64, f64::max);

        // Penalty: (1 - max_correlation)
        // Fully correlated (1.0) → penalty = 0 (ignore signal)
        // Uncorrelated (0.0) → penalty = 1 (full weight)
        1.0 - max_corr
    }

    /// Combine multiple signals into a posterior probability
    ///
    /// Formula:
    /// L_posterior = L_prior + Σᵢ (wᵢ · cᵢ · logit(Sᵢ))
    /// P_posterior = σ(L_posterior)
    ///
    /// Where:
    ///   wᵢ = reliability weight (can be negative for negative evidence)
    ///   cᵢ = correlation penalty
    ///   Sᵢ = signal probability
    ///
    /// Key improvements over naive weighted averaging:
    /// 1. Negative evidence SUBTRACTS from log-odds
    /// 2. Independence requirements for confirmation
    /// 3. No single signal can contribute >60% of total weight
    pub fn combine(&self, signals: &[Signal]) -> CombinedResult {
        if signals.is_empty() {
            return CombinedResult {
                probability: self.prior,
                confidence: Confidence::None,
                log_odds: Self::logit(self.prior),
                signals_used: 0,
                independent_classes: 0,
                max_signal_weight_ratio: 0.0,
                explanation: "No signals provided".to_string(),
            };
        }

        // Start with prior log-odds
        let mut log_odds = Self::logit(self.prior);
        let mut processed: Vec<SignalType> = Vec::new();
        let mut explanations: Vec<String> = Vec::new();
        let mut contributions: Vec<(SignalType, f64)> = Vec::new();

        // Sort signals by absolute reliability (most reliable first)
        let mut sorted_signals = signals.to_vec();
        sorted_signals.sort_by(|a, b| {
            let wa = self.weights.get(&a.signal_type).unwrap_or(&0.5).abs();
            let wb = self.weights.get(&b.signal_type).unwrap_or(&0.5).abs();
            wb.partial_cmp(&wa).unwrap_or(std::cmp::Ordering::Equal)
        });

        for signal in &sorted_signals {
            // Get reliability weight (can be negative for negative evidence!)
            let weight = self.weights.get(&signal.signal_type).copied().unwrap_or(0.5);

            // Calculate correlation penalty
            let corr_penalty = self.correlation_penalty(signal.signal_type, &processed);

            // Skip if too correlated with existing signals
            if corr_penalty < 0.1 {
                explanations.push(format!(
                    "⊘ {:?}: skipped (correlated with existing signals)",
                    signal.signal_type
                ));
                continue;
            }

            // Calculate log-odds contribution
            // For negative evidence: weight is negative, so contribution subtracts
            let signal_logit = Self::logit(signal.probability);
            let contribution = weight * corr_penalty * signal_logit;

            // Update running log-odds
            log_odds += contribution;

            // Track what we've processed
            processed.push(signal.signal_type);
            contributions.push((signal.signal_type, contribution.abs()));

            // Build explanation
            let direction = if contribution > 0.0 { "↑" } else { "↓" };
            let evidence_type = if weight < 0.0 { " [NEG]" } else { "" };
            explanations.push(format!(
                "{} {:?}{}: P={:.2} w={:.2} c={:.2} → contribution={:+.3}",
                direction,
                signal.signal_type,
                evidence_type,
                signal.probability,
                weight,
                corr_penalty,
                contribution
            ));
        }

        // Count independent signal classes
        let independent_classes = Self::count_independent_classes(&processed);

        // Calculate max signal weight ratio (for independence check)
        let total_contribution: f64 = contributions.iter().map(|(_, c)| c).sum();
        let max_contribution = contributions.iter().map(|(_, c)| *c).fold(0.0_f64, f64::max);
        let max_signal_weight_ratio = if total_contribution > 0.0 {
            max_contribution / total_contribution
        } else {
            0.0
        };

        // Apply confidence dampening for few signals
        // Prevent overconfidence from single strong signal
        let signal_count_factor = (processed.len() as f64 / 3.0).min(1.0);
        log_odds *= signal_count_factor;

        // Apply temperature scaling for calibration
        // T > 1 softens probabilities (more calibrated)
        // T < 1 sharpens probabilities (more extreme)
        let scaled_log_odds = log_odds / self.temperature;

        // Convert back to probability
        let probability = Self::sigmoid(scaled_log_odds);

        // Determine confidence level with independence requirements
        let confidence = Confidence::from_combined_evidence(
            probability,
            processed.len(),
            independent_classes,
            max_signal_weight_ratio,
        );

        CombinedResult {
            probability,
            confidence,
            log_odds,
            signals_used: processed.len(),
            independent_classes,
            max_signal_weight_ratio,
            explanation: format!(
                "Prior: {:.3} → Posterior: {:.3} (classes: {}, max_weight: {:.1}%)\n{}",
                self.prior,
                probability,
                independent_classes,
                max_signal_weight_ratio * 100.0,
                explanations.join("\n")
            ),
        }
    }

    /// Count independent signal classes
    /// Signals in the same class are considered correlated
    fn count_independent_classes(signals: &[SignalType]) -> usize {
        use SignalType::*;

        // Define signal classes (groups of related signals)
        let get_class = |s: SignalType| -> &'static str {
            match s {
                Timing => "timing",
                Length | Entropy | Compression | ContentHash => "content",
                Resonance | BooleanDifferential | ArithmeticEval |
                QuoteCancellation | CommentInjection => "behavioral",
                HexEncoding | UnicodeNorm | NullByteTrunc | CaseSensitivity => "encoding",
                WafBlock | WafBypass => "waf",
                StatusCode | HeaderDiff => "http",
                ErrorPattern => "pattern",
                NoChange | ConsistentBehavior => "negative",
            }
        };

        let classes: std::collections::HashSet<&str> = signals
            .iter()
            .map(|s| get_class(*s))
            .collect();

        classes.len()
    }

    /// Quick check: is this likely a vulnerability?
    pub fn is_likely_vulnerable(&self, signals: &[Signal]) -> bool {
        let result = self.combine(signals);
        result.probability > 0.7 && result.signals_used >= 2
    }

    /// Quick check: is this confirmed vulnerable?
    pub fn is_confirmed(&self, signals: &[Signal]) -> bool {
        let result = self.combine(signals);
        result.probability > 0.9 && result.signals_used >= 3
    }
}

/// Result of combining multiple signals
#[derive(Debug, Clone)]
pub struct CombinedResult {
    /// Posterior probability of vulnerability
    pub probability: f64,

    /// Confidence level
    pub confidence: Confidence,

    /// Log-odds (for further combination)
    pub log_odds: f64,

    /// Number of signals actually used (after correlation filtering)
    pub signals_used: usize,

    /// Number of independent signal classes used
    pub independent_classes: usize,

    /// Maximum weight ratio of any single signal (for independence check)
    /// If this is > 0.6, a single signal dominates
    pub max_signal_weight_ratio: f64,

    /// Human-readable explanation of the combination
    pub explanation: String,
}

/// Confidence levels for detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    None,       // No signals or probability too low
    Low,        // Weak signals, few sources
    Medium,     // Moderate signals or limited sources
    High,       // Strong signals from multiple sources
    Confirmed,  // Very high probability, multiple INDEPENDENT sources
}

impl Confidence {
    /// Determine confidence from combined evidence
    ///
    /// Requirements for each level:
    /// - None: P < 0.3 or no signals
    /// - Low: P < 0.5 or only 1 signal class
    /// - Medium: P < 0.7 or only 2 signal classes
    /// - High: P < 0.9 or max_weight > 0.6 (single signal dominates)
    /// - Confirmed: P >= 0.9 AND 2+ independent classes AND no single signal > 60%
    fn from_combined_evidence(
        prob: f64,
        signal_count: usize,
        independent_classes: usize,
        max_weight_ratio: f64,
    ) -> Self {
        // Base requirement: enough probability
        if prob < 0.3 || signal_count == 0 {
            return Confidence::None;
        }

        if prob < 0.5 || independent_classes < 2 {
            return Confidence::Low;
        }

        if prob < 0.7 || independent_classes < 2 {
            return Confidence::Medium;
        }

        // For High/Confirmed, check independence requirements
        // A single signal contributing > 60% = not truly confirmed
        if max_weight_ratio > 0.6 {
            return Confidence::High; // Capped due to single-signal dominance
        }

        if prob < 0.9 || independent_classes < 2 {
            return Confidence::High;
        }

        // Confirmed: high probability + multiple independent classes + no dominance
        Confidence::Confirmed
    }

    /// Legacy method for backwards compatibility
    #[allow(dead_code)]
    fn from_probability_and_signals(prob: f64, signal_count: usize) -> Self {
        Self::from_combined_evidence(prob, signal_count, signal_count.min(3), 0.5)
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::None => write!(f, "NONE"),
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
            Confidence::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logit_sigmoid_inverse() {
        let combiner = BayesianCombiner::new();

        for p in [0.1, 0.3, 0.5, 0.7, 0.9] {
            let logit = BayesianCombiner::logit(p);
            let back = BayesianCombiner::sigmoid(logit);
            assert!((p - back).abs() < 0.001, "logit/sigmoid should be inverses");
        }
    }

    #[test]
    fn test_single_strong_signal() {
        let combiner = BayesianCombiner::new();

        let signals = vec![
            Signal::new(SignalType::ErrorPattern, 0.95, 1.0, "SQL error detected"),
        ];

        let result = combiner.combine(&signals);

        // Single signal should be dampened
        assert!(result.probability > 0.5);
        assert!(result.probability < 0.95); // Dampened from raw signal
        assert_eq!(result.signals_used, 1);
    }

    #[test]
    fn test_multiple_independent_signals() {
        let combiner = BayesianCombiner::new();

        let signals = vec![
            Signal::new(SignalType::Timing, 0.7, 50.0, "Response 50ms slower"),
            Signal::new(SignalType::Entropy, 0.65, 0.2, "Entropy changed"),
            Signal::new(SignalType::Resonance, 0.8, 1.0, "Quote oscillation detected"),
        ];

        let result = combiner.combine(&signals);

        // Multiple independent signals should increase confidence
        assert!(result.probability > 0.8);
        assert!(result.signals_used >= 3);
    }

    #[test]
    fn test_correlated_signals_penalized() {
        let combiner = BayesianCombiner::new();

        // Length and Compression are highly correlated
        let signals = vec![
            Signal::new(SignalType::Length, 0.8, 100.0, "Length changed"),
            Signal::new(SignalType::Compression, 0.8, 0.1, "Compression changed"),
        ];

        let result = combiner.combine(&signals);

        // Should not be 2x the single signal effect due to correlation
        let single = combiner.combine(&signals[..1]);
        let double_uncorrelated = single.probability * 2.0; // Naive expectation

        assert!(result.probability < double_uncorrelated);
    }

    #[test]
    fn test_no_signals() {
        let combiner = BayesianCombiner::new();
        let result = combiner.combine(&[]);

        assert_eq!(result.probability, combiner.prior);
        assert_eq!(result.signals_used, 0);
        assert_eq!(result.confidence, Confidence::None);
    }

    #[test]
    fn test_contradicting_signals() {
        let combiner = BayesianCombiner::new();

        // One says vulnerable, one says not
        let signals = vec![
            Signal::new(SignalType::Timing, 0.9, 100.0, "Timing anomaly"),
            Signal::new(SignalType::StatusCode, 0.1, 200.0, "Normal status"),
        ];

        let result = combiner.combine(&signals);

        // Should partially cancel out
        assert!(result.probability > 0.3);
        assert!(result.probability < 0.7);
    }

    #[test]
    fn test_negative_evidence_reduces_confidence() {
        let combiner = BayesianCombiner::new();

        // Positive signal
        let positive_only = vec![
            Signal::new(SignalType::ErrorPattern, 0.85, 1.0, "SQL error detected"),
        ];
        let result_positive = combiner.combine(&positive_only);

        // Same positive signal + negative evidence
        let with_negative = vec![
            Signal::new(SignalType::ErrorPattern, 0.85, 1.0, "SQL error detected"),
            Signal::new(SignalType::ConsistentBehavior, 0.9, 0.0, "No behavioral difference"),
        ];
        let result_with_neg = combiner.combine(&with_negative);

        // Negative evidence should reduce probability
        assert!(result_with_neg.probability < result_positive.probability,
            "Negative evidence should reduce confidence: {} should be < {}",
            result_with_neg.probability, result_positive.probability);
    }

    #[test]
    fn test_independent_classes_counted() {
        let combiner = BayesianCombiner::new();

        // Signals from different classes
        let signals = vec![
            Signal::new(SignalType::Timing, 0.8, 50.0, "Timing anomaly"),           // timing class
            Signal::new(SignalType::BooleanDifferential, 0.85, 2.0, "Boolean diff"), // behavioral class
            Signal::new(SignalType::ErrorPattern, 0.9, 1.0, "SQL error"),           // pattern class
        ];

        let result = combiner.combine(&signals);

        // Should have 3 independent classes
        assert_eq!(result.independent_classes, 3,
            "Should detect 3 independent signal classes");
    }

    #[test]
    fn test_single_signal_dominance_capped() {
        let combiner = BayesianCombiner::new();

        // Single very strong signal should not reach Confirmed
        let signals = vec![
            Signal::new(SignalType::ErrorPattern, 0.99, 1.0, "Very strong error pattern"),
        ];

        let result = combiner.combine(&signals);

        // Even with high probability, single signal shouldn't be Confirmed
        assert!(result.confidence != Confidence::Confirmed,
            "Single signal should not reach Confirmed status");
        assert!(result.max_signal_weight_ratio > 0.9,
            "Single signal should have >90% weight ratio");
    }

    #[test]
    fn test_behavioral_signals_independent() {
        let combiner = BayesianCombiner::new();

        // Multiple behavioral signals are in same class, but correlation is low
        let signals = vec![
            Signal::new(SignalType::BooleanDifferential, 0.85, 2.0, "Boolean diff"),
            Signal::new(SignalType::ArithmeticEval, 0.85, 0.95, "Arithmetic eval"),
            Signal::new(SignalType::QuoteCancellation, 0.8, 0.9, "Quote cancellation"),
        ];

        let result = combiner.combine(&signals);

        // All three should be used (low correlation between them)
        assert_eq!(result.signals_used, 3,
            "All behavioral signals should be used (low inter-correlation)");

        // But they're in the same class
        assert_eq!(result.independent_classes, 1,
            "All behavioral signals are in same class");
    }
}
