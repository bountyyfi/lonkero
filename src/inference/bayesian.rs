// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Bayesian Signal Combiner
//
// Combines multiple probabilistic signals using log-odds framework
// with correlation penalties and reliability weighting.

use std::collections::HashMap;

/// Signal types for vulnerability detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalType {
    Timing,         // Response time analysis
    Length,         // Content length differential
    Entropy,        // Response entropy changes
    Compression,    // Compression ratio oracle
    Resonance,      // Quote oscillation pattern
    StatusCode,     // HTTP status changes
    HeaderDiff,     // Header fingerprint changes
    ErrorPattern,   // Error message detection
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
}

impl Default for BayesianCombiner {
    fn default() -> Self {
        Self::new()
    }
}

impl BayesianCombiner {
    pub fn new() -> Self {
        let mut combiner = Self {
            prior: 0.05, // 5% prior - vulnerabilities are relatively rare
            weights: HashMap::new(),
            correlations: HashMap::new(),
        };

        // Initialize reliability weights
        // Higher = more reliable signal
        combiner.weights.insert(SignalType::Timing, 0.7);
        combiner.weights.insert(SignalType::Length, 0.6);
        combiner.weights.insert(SignalType::Entropy, 0.5);
        combiner.weights.insert(SignalType::Compression, 0.6);
        combiner.weights.insert(SignalType::Resonance, 0.85);  // Very reliable
        combiner.weights.insert(SignalType::StatusCode, 0.9);  // Very reliable
        combiner.weights.insert(SignalType::HeaderDiff, 0.5);
        combiner.weights.insert(SignalType::ErrorPattern, 0.95); // Most reliable

        // Initialize correlation matrix
        combiner.init_correlations();

        combiner
    }

    /// Initialize correlation matrix
    /// Correlated signals shouldn't double-count evidence
    fn init_correlations(&mut self) {
        use SignalType::*;

        // Self-correlation is always 1.0
        for st in [Timing, Length, Entropy, Compression, Resonance, StatusCode, HeaderDiff, ErrorPattern] {
            self.correlations.insert((st, st), 1.0);
        }

        // Cross-correlations (symmetric)
        let pairs = [
            // Timing correlates moderately with length (bigger response = slower)
            ((Timing, Length), 0.3),
            ((Timing, Resonance), 0.4),  // Both affected by query execution

            // Length and entropy are related (more content = different entropy)
            ((Length, Entropy), 0.5),
            ((Length, Compression), 0.7), // Highly correlated!

            // Entropy and compression measure similar things
            ((Entropy, Compression), 0.6),

            // Status code and error pattern often go together
            ((StatusCode, ErrorPattern), 0.8),
            ((StatusCode, HeaderDiff), 0.6),

            // Error pattern and header diff
            ((ErrorPattern, HeaderDiff), 0.5),
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
    ///   wᵢ = reliability weight
    ///   cᵢ = correlation penalty
    ///   Sᵢ = signal probability
    pub fn combine(&self, signals: &[Signal]) -> CombinedResult {
        if signals.is_empty() {
            return CombinedResult {
                probability: self.prior,
                confidence: Confidence::None,
                log_odds: Self::logit(self.prior),
                signals_used: 0,
                explanation: "No signals provided".to_string(),
            };
        }

        // Start with prior log-odds
        let mut log_odds = Self::logit(self.prior);
        let mut processed: Vec<SignalType> = Vec::new();
        let mut explanations: Vec<String> = Vec::new();
        let mut total_weight = 0.0;

        // Sort signals by reliability (most reliable first)
        let mut sorted_signals = signals.to_vec();
        sorted_signals.sort_by(|a, b| {
            let wa = self.weights.get(&a.signal_type).unwrap_or(&0.5);
            let wb = self.weights.get(&b.signal_type).unwrap_or(&0.5);
            wb.partial_cmp(wa).unwrap_or(std::cmp::Ordering::Equal)
        });

        for signal in &sorted_signals {
            // Get reliability weight
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
            let signal_logit = Self::logit(signal.probability);
            let contribution = weight * corr_penalty * signal_logit;

            // Update running log-odds
            log_odds += contribution;
            total_weight += weight * corr_penalty;

            // Track what we've processed
            processed.push(signal.signal_type);

            // Build explanation
            let direction = if signal.probability > 0.5 { "↑" } else { "↓" };
            explanations.push(format!(
                "{} {:?}: P={:.2} w={:.2} c={:.2} → contribution={:+.3}",
                direction,
                signal.signal_type,
                signal.probability,
                weight,
                corr_penalty,
                contribution
            ));
        }

        // Apply confidence dampening for few signals
        // Prevent overconfidence from single strong signal
        let signal_count_factor = (processed.len() as f64 / 3.0).min(1.0);
        log_odds *= signal_count_factor;

        // Convert back to probability
        let probability = Self::sigmoid(log_odds);

        // Determine confidence level
        let confidence = Confidence::from_probability_and_signals(probability, processed.len());

        CombinedResult {
            probability,
            confidence,
            log_odds,
            signals_used: processed.len(),
            explanation: format!(
                "Prior: {:.3} → Posterior: {:.3}\n{}",
                self.prior,
                probability,
                explanations.join("\n")
            ),
        }
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

    /// Human-readable explanation of the combination
    pub explanation: String,
}

/// Confidence levels for detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    None,       // No signals
    Low,        // Weak signals, few sources
    Medium,     // Moderate signals or limited sources
    High,       // Strong signals from multiple sources
    Confirmed,  // Very high probability, multiple independent sources
}

impl Confidence {
    fn from_probability_and_signals(prob: f64, signal_count: usize) -> Self {
        match (prob, signal_count) {
            (p, _) if p < 0.3 => Confidence::None,
            (p, n) if p < 0.5 || n < 2 => Confidence::Low,
            (p, n) if p < 0.7 || n < 3 => Confidence::Medium,
            (p, n) if p < 0.9 || n < 4 => Confidence::High,
            _ => Confidence::Confirmed,
        }
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
}
