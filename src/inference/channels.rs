// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Side-Channel Analyzer
//
// High-level interface for probabilistic vulnerability detection
// without requiring out-of-band callbacks.

use crate::http_client::{HttpClient, HttpResponse};
use crate::inference::bayesian::{BayesianCombiner, CombinedResult, Signal, SignalType};
use crate::inference::signals::{
    EntropyAnalyzer, ErrorPatternAnalyzer, HeaderAnalyzer, LengthAnalyzer,
    ResonanceAnalyzer, SideChannelSuite, StatusCodeAnalyzer, TimingAnalyzer,
};
use std::sync::Arc;
use tracing::{debug, info};

/// Side-channel analyzer for blind vulnerability detection
pub struct SideChannelAnalyzer {
    http_client: Arc<HttpClient>,
    combiner: BayesianCombiner,
}

impl SideChannelAnalyzer {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            combiner: BayesianCombiner::new(),
        }
    }

    /// Perform comprehensive side-channel analysis for SQL injection
    ///
    /// This is the main entry point for "no-OOB" blind SQLi detection.
    /// It combines multiple weak signals into a strong probabilistic inference.
    pub async fn analyze_sqli(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> SideChannelResult {
        info!(
            "[SideChannel] Analyzing {} parameter '{}' for blind SQLi",
            base_url, parameter
        );

        let mut all_signals: Vec<Signal> = Vec::new();

        // Initialize analyzers
        let suite = SideChannelSuite::new(baseline);
        let resonance = ResonanceAnalyzer::new(Arc::clone(&self.http_client));

        // ================================================================
        // Test 1: Simple quote injection
        // ================================================================
        let quote_url = self.build_test_url(base_url, parameter, "'");
        if let Ok(quote_resp) = self.http_client.get(&quote_url).await {
            let signals = suite.analyze(&quote_resp);
            debug!("[SideChannel] Quote test signals: {:?}", signals.len());
            all_signals.extend(signals);
        }

        // ================================================================
        // Test 2: Resonance analysis (quote oscillation)
        // ================================================================
        let resonance_signal = resonance.analyze(base_url, parameter, baseline).await;
        debug!("[SideChannel] Resonance signal: P={:.2}", resonance_signal.probability);
        all_signals.push(resonance_signal);

        // ================================================================
        // Test 3: Boolean differential
        // ================================================================
        let bool_signals = self.analyze_boolean_differential(base_url, parameter, baseline).await;
        all_signals.extend(bool_signals);

        // ================================================================
        // Test 4: Arithmetic injection
        // ================================================================
        let arith_signals = self.analyze_arithmetic(base_url, parameter, baseline).await;
        all_signals.extend(arith_signals);

        // ================================================================
        // Combine all signals
        // ================================================================
        let result = self.combiner.combine(&all_signals);

        info!(
            "[SideChannel] Combined result: P={:.3} confidence={} signals={}",
            result.probability, result.confidence, result.signals_used
        );

        SideChannelResult {
            url: base_url.to_string(),
            parameter: parameter.to_string(),
            combined: result,
            all_signals,
        }
    }

    /// Analyze boolean differential (AND 1=1 vs AND 1=2)
    ///
    /// Statistical approach: measure EFFECT SIZE, not just threshold.
    /// Effect size = (mean_true - mean_false) / pooled_std
    async fn analyze_boolean_differential(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Get current parameter value
        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        let true_payload = format!("{} AND 1=1", current_value);
        let false_payload = format!("{} AND 1=2", current_value);

        let true_url = self.build_test_url(base_url, parameter, &true_payload);
        let false_url = self.build_test_url(base_url, parameter, &false_payload);

        // Run MULTIPLE samples to get statistical stability
        let n_samples = 3;
        let mut true_lengths: Vec<f64> = Vec::new();
        let mut false_lengths: Vec<f64> = Vec::new();

        for _ in 0..n_samples {
            let (true_resp, false_resp) = tokio::join!(
                self.http_client.get(&true_url),
                self.http_client.get(&false_url)
            );

            if let Ok(tr) = true_resp {
                true_lengths.push(tr.body.len() as f64);
            }
            if let Ok(fr) = false_resp {
                false_lengths.push(fr.body.len() as f64);
            }
        }

        if true_lengths.len() >= 2 && false_lengths.len() >= 2 {
            // Calculate effect size (Cohen's d)
            let mean_true: f64 = true_lengths.iter().sum::<f64>() / true_lengths.len() as f64;
            let mean_false: f64 = false_lengths.iter().sum::<f64>() / false_lengths.len() as f64;

            let var_true: f64 = true_lengths.iter()
                .map(|x| (x - mean_true).powi(2))
                .sum::<f64>() / (true_lengths.len() - 1) as f64;
            let var_false: f64 = false_lengths.iter()
                .map(|x| (x - mean_false).powi(2))
                .sum::<f64>() / (false_lengths.len() - 1) as f64;

            let pooled_std = ((var_true + var_false) / 2.0).sqrt().max(1.0);
            let effect_size = (mean_true - mean_false).abs() / pooled_std;

            // Check consistency: true should match baseline, false should differ
            let baseline_len = baseline.body.len() as f64;
            let true_matches_baseline = (mean_true - baseline_len).abs() / baseline_len.max(1.0) < 0.1;
            let false_differs = (mean_false - baseline_len).abs() / baseline_len.max(1.0) > 0.2;

            // Effect size interpretation (Cohen's d):
            // 0.2 = small, 0.5 = medium, 0.8 = large
            let probability = if effect_size > 2.0 && true_matches_baseline && false_differs {
                0.95  // Very large effect, correct pattern
            } else if effect_size > 1.0 && true_matches_baseline {
                0.85
            } else if effect_size > 0.8 {
                0.7
            } else if effect_size > 0.5 {
                0.55
            } else {
                0.25  // Small effect = likely noise
            };

            signals.push(Signal::new(
                SignalType::BooleanDifferential,  // Correct type!
                probability,
                effect_size,
                &format!(
                    "Boolean differential: effect_size={:.2} (true={:.0}±{:.0}, false={:.0}±{:.0})",
                    effect_size, mean_true, var_true.sqrt(), mean_false, var_false.sqrt()
                ),
            ));

            // Add NEGATIVE evidence if no effect detected
            if effect_size < 0.3 {
                signals.push(Signal::new(
                    SignalType::ConsistentBehavior,
                    0.8,  // High confidence in no difference
                    effect_size,
                    "No boolean differential detected (consistent behavior)",
                ));
            }
        }

        signals
    }

    /// Analyze arithmetic injection
    ///
    /// Tests if (value+1)-1 returns same as value, indicating SQL math evaluation.
    /// Uses multiple samples for statistical confidence.
    async fn analyze_arithmetic(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Get current parameter value
        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Only works for numeric values
        let num_value: i64 = match current_value.parse() {
            Ok(n) if n > 1 => n,
            _ => return signals,
        };

        // Run multiple arithmetic tests for stability
        let test_cases = [
            (format!("{}-1+1", num_value), "n-1+1"),     // Should equal n
            (format!("{}*1", num_value), "n*1"),         // Should equal n
            (format!("{}/1", num_value), "n/1"),         // Should equal n
        ];

        let mut matching_tests = 0;
        let mut total_effect = 0.0;

        for (payload, _desc) in &test_cases {
            let url = self.build_test_url(base_url, parameter, payload);

            // Multiple samples per test
            let mut similarities: Vec<f64> = Vec::new();
            for _ in 0..2 {
                if let Ok(resp) = self.http_client.get(&url).await {
                    let sim = self.calculate_similarity_statistical(baseline, &resp);
                    similarities.push(sim);
                }
            }

            if !similarities.is_empty() {
                let avg_sim: f64 = similarities.iter().sum::<f64>() / similarities.len() as f64;
                if avg_sim > 0.85 {
                    matching_tests += 1;
                    total_effect += avg_sim;
                }
            }
        }

        // Calculate overall probability based on how many tests matched
        let probability = match matching_tests {
            3 => 0.95,  // All three arithmetic tests match = very strong
            2 => 0.85,
            1 => 0.6,
            0 => 0.2,
            _ => 0.1,
        };

        if matching_tests > 0 {
            signals.push(Signal::new(
                SignalType::ArithmeticEval,  // Correct type!
                probability,
                total_effect / matching_tests as f64,
                &format!(
                    "Arithmetic evaluation: {}/{} tests matched (n={})",
                    matching_tests, test_cases.len(), num_value
                ),
            ));
        } else {
            // Add negative evidence
            signals.push(Signal::new(
                SignalType::NoChange,
                0.7,
                0.0,
                "Arithmetic expressions not evaluated",
            ));
        }

        signals
    }

    /// Statistical similarity using relative difference and hash comparison
    fn calculate_similarity_statistical(&self, a: &HttpResponse, b: &HttpResponse) -> f64 {
        let mut score = 0.0;

        // Length similarity: relative difference
        let len_a = a.body.len() as f64;
        let len_b = b.body.len() as f64;
        let len_ratio = 1.0 - (len_a - len_b).abs() / len_a.max(len_b).max(1.0);
        score += 0.3 * len_ratio;

        // Status match
        if a.status_code == b.status_code {
            score += 0.2;
        }

        // Content hash (structural similarity)
        let hash_a = self.simple_hash(&a.body);
        let hash_b = self.simple_hash(&b.body);
        if hash_a == hash_b {
            score += 0.5;  // Exact content match
        } else if len_ratio > 0.95 {
            score += 0.2;  // Very similar length
        }

        score
    }

    /// Calculate similarity between two responses (0.0 to 1.0)
    fn calculate_similarity(&self, a: &HttpResponse, b: &HttpResponse) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // Status code match (weight: 0.3)
        if a.status_code == b.status_code {
            score += 0.3;
        }
        factors += 0.3;

        // Length similarity (weight: 0.4)
        let len_ratio = a.body.len().min(b.body.len()) as f64
            / a.body.len().max(b.body.len()).max(1) as f64;
        score += 0.4 * len_ratio;
        factors += 0.4;

        // Content hash (weight: 0.3)
        let hash_a = self.simple_hash(&a.body);
        let hash_b = self.simple_hash(&b.body);
        if hash_a == hash_b {
            score += 0.3;
        }
        factors += 0.3;

        score / factors
    }

    fn simple_hash(&self, s: &str) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in s.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    fn extract_param_value(&self, url: &str, param: &str) -> Option<String> {
        url::Url::parse(url).ok().and_then(|parsed| {
            parsed.query_pairs()
                .find(|(name, _)| name == param)
                .map(|(_, value)| value.to_string())
        })
    }

    fn build_test_url(&self, base_url: &str, param_name: &str, payload: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            let existing: Vec<(String, String)> = parsed
                .query_pairs()
                .filter(|(name, _)| name != param_name)
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();

            parsed.set_query(None);
            {
                let mut qp = parsed.query_pairs_mut();
                for (name, value) in &existing {
                    qp.append_pair(name, value);
                }
                qp.append_pair(param_name, payload);
            }
            parsed.to_string()
        } else {
            format!("{}?{}={}", base_url, param_name, urlencoding::encode(payload))
        }
    }
}

/// Result of side-channel analysis
#[derive(Debug)]
pub struct SideChannelResult {
    pub url: String,
    pub parameter: String,
    pub combined: CombinedResult,
    pub all_signals: Vec<Signal>,
}

impl SideChannelResult {
    /// Is this likely a vulnerability?
    pub fn is_likely_vulnerable(&self) -> bool {
        self.combined.probability > 0.7 && self.combined.signals_used >= 2
    }

    /// Is this a confirmed vulnerability?
    pub fn is_confirmed(&self) -> bool {
        self.combined.probability > 0.9 && self.combined.signals_used >= 3
    }

    /// Get a summary for logging
    pub fn summary(&self) -> String {
        format!(
            "P={:.1}% confidence={} signals={}/{}\n{}",
            self.combined.probability * 100.0,
            self.combined.confidence,
            self.combined.signals_used,
            self.all_signals.len(),
            self.combined.explanation
        )
    }
}
