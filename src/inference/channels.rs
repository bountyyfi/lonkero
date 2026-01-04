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

        let (true_resp, false_resp) = tokio::join!(
            self.http_client.get(&true_url),
            self.http_client.get(&false_url)
        );

        if let (Ok(true_r), Ok(false_r)) = (true_resp, false_resp) {
            // Check if true matches baseline and false differs
            let true_similarity = self.calculate_similarity(baseline, &true_r);
            let false_similarity = self.calculate_similarity(baseline, &false_r);
            let true_false_similarity = self.calculate_similarity(&true_r, &false_r);

            let differential = (true_similarity - false_similarity).abs();

            let probability = if true_similarity > 0.8 && false_similarity < 0.5 {
                0.95 // Perfect boolean differential
            } else if differential > 0.3 {
                0.8
            } else if differential > 0.15 {
                0.6
            } else {
                0.3
            };

            signals.push(Signal::new(
                SignalType::Resonance, // Using resonance as it's about behavioral differences
                probability,
                differential,
                &format!(
                    "Boolean differential: true_sim={:.2}, false_sim={:.2}, diff={:.2}",
                    true_similarity, false_similarity, differential
                ),
            ));
        }

        signals
    }

    /// Analyze arithmetic injection
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

        // Test: (value+1)-1 should equal value if math is evaluated
        let arithmetic_payload = format!("{}-1+1", num_value);
        let arith_url = self.build_test_url(base_url, parameter, &arithmetic_payload);

        if let Ok(arith_resp) = self.http_client.get(&arith_url).await {
            let similarity = self.calculate_similarity(baseline, &arith_resp);

            let probability = if similarity > 0.9 {
                0.95 // Math was evaluated!
            } else if similarity > 0.8 {
                0.7
            } else {
                0.3
            };

            if similarity > 0.8 {
                signals.push(Signal::new(
                    SignalType::Resonance,
                    probability,
                    similarity,
                    &format!(
                        "Arithmetic injection: {}-1+1 similarity={:.2}",
                        num_value, similarity
                    ),
                ));
            }
        }

        signals
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
