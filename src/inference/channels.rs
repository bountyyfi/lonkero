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
        // Test 5: Hex encoding evaluation (0x61646D696E = admin)
        // ================================================================
        let hex_signals = self.analyze_hex_encoding(base_url, parameter, baseline).await;
        all_signals.extend(hex_signals);

        // ================================================================
        // Test 6: Null byte truncation (value%00garbage = value)
        // ================================================================
        let null_signals = self.analyze_null_byte(base_url, parameter, baseline).await;
        all_signals.extend(null_signals);

        // ================================================================
        // Test 7: WAF detection (use blocked payloads as oracle)
        // ================================================================
        let waf_signals = self.analyze_waf_behavior(base_url, parameter, baseline).await;
        all_signals.extend(waf_signals);

        // ================================================================
        // Test 8: Micro-timing analysis (statistical, 20+ samples)
        // Only run if we don't have strong signals yet
        // ================================================================
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob < 0.7 {
            let timing_signals = self.analyze_micro_timing(base_url, parameter).await;
            all_signals.extend(timing_signals);
        }

        // ================================================================
        // Test 9: Advanced micro-timing leak detection (50+ samples)
        // Only run if still uncertain after basic tests
        // Uses bottom-quartile, bootstrapping, adaptive thresholding
        // ================================================================
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob > 0.3 && current_prob < 0.8 {
            // In the "uncertain zone" - worth investing in advanced timing
            let leak_signals = self.analyze_micro_timing_leak(base_url, parameter).await;
            all_signals.extend(leak_signals);
        }

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
                    let sim = self.calculate_similarity(baseline, &resp);
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

    /// Analyze hex encoding evaluation
    ///
    /// Tests if 0x61646D696E returns same as 'admin'
    /// If SQL decodes hex, they'll match → SQLi confirmed
    async fn analyze_hex_encoding(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Get current parameter value
        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "admin".to_string());

        // Convert value to hex: 'admin' → 0x61646D696E
        let hex_value = format!("0x{}", current_value.bytes()
            .map(|b| format!("{:02x}", b))
            .collect::<String>());

        let hex_url = self.build_test_url(base_url, parameter, &hex_value);

        if let Ok(hex_resp) = self.http_client.get(&hex_url).await {
            let similarity = self.calculate_similarity(baseline, &hex_resp);

            if similarity > 0.85 {
                // Hex was decoded by SQL!
                signals.push(Signal::new(
                    SignalType::HexEncoding,
                    0.92,
                    similarity,
                    &format!("Hex encoding {} decoded to match baseline", hex_value),
                ));
            } else if similarity < 0.3 {
                // Different response - hex not decoded (normal)
                // No signal either way
            }
        }

        signals
    }

    /// Analyze null byte truncation
    ///
    /// Tests if value%00garbage returns same as value
    /// If SQL truncates at null, they'll match → SQLi indicator
    async fn analyze_null_byte(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "test".to_string());

        // Test: value%00garbage (null byte + junk)
        let null_payload = format!("{}%00randomjunk12345", current_value);
        let null_url = self.build_test_url(base_url, parameter, &null_payload);

        if let Ok(null_resp) = self.http_client.get(&null_url).await {
            let similarity = self.calculate_similarity(baseline, &null_resp);

            if similarity > 0.85 {
                // Null byte truncated the junk!
                signals.push(Signal::new(
                    SignalType::NullByteTrunc,
                    0.88,
                    similarity,
                    "Null byte truncation detected (junk after %00 ignored)",
                ));
            }
        }

        // Also test with actual null byte (not URL encoded)
        let null_payload2 = format!("{}\x00morejunk", current_value);
        let null_url2 = self.build_test_url(base_url, parameter, &null_payload2);

        if let Ok(null_resp2) = self.http_client.get(&null_url2).await {
            let similarity = self.calculate_similarity(baseline, &null_resp2);

            if similarity > 0.85 && signals.is_empty() {
                signals.push(Signal::new(
                    SignalType::NullByteTrunc,
                    0.85,
                    similarity,
                    "Raw null byte truncation detected",
                ));
            }
        }

        signals
    }

    /// Analyze WAF behavior as oracle
    ///
    /// If WAF blocks some payloads but not others, that tells us:
    /// 1. There IS a WAF (context info)
    /// 2. What the WAF thinks is dangerous (inverted signal)
    /// 3. What bypasses work (if bypass works + behavior change = likely vuln)
    async fn analyze_waf_behavior(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Test 1: Obviously malicious payload (should be blocked by WAF)
        let obvious_sqli = format!("{}'OR'1'='1", current_value);
        let obvious_url = self.build_test_url(base_url, parameter, &obvious_sqli);

        let obvious_resp = self.http_client.get(&obvious_url).await.ok();
        let obvious_blocked = obvious_resp.as_ref()
            .map(|r| self.is_waf_block(r))
            .unwrap_or(false);

        // Test 2: Evasion payload (might bypass WAF)
        let bypass_sqli = format!("{}'+oR+'1'='1", current_value);  // Case mixing
        let bypass_url = self.build_test_url(base_url, parameter, &bypass_sqli);

        let bypass_resp = self.http_client.get(&bypass_url).await.ok();
        let bypass_blocked = bypass_resp.as_ref()
            .map(|r| self.is_waf_block(r))
            .unwrap_or(false);

        // Test 3: Another evasion (inline comment)
        let bypass2_sqli = format!("{}'+/**/OR/**/+'1'='1", current_value);
        let bypass2_url = self.build_test_url(base_url, parameter, &bypass2_sqli);

        let bypass2_resp = self.http_client.get(&bypass2_url).await.ok();
        let bypass2_blocked = bypass2_resp.as_ref()
            .map(|r| self.is_waf_block(r))
            .unwrap_or(false);

        // Analyze WAF behavior patterns
        if obvious_blocked {
            // WAF is present and blocking SQLi
            signals.push(Signal::new(
                SignalType::WafBlock,
                0.6,  // WAF blocking = payload is "dangerous" (indirect evidence)
                1.0,
                "WAF detected: blocking obvious SQLi patterns",
            ));

            // Check if bypass worked
            if !bypass_blocked || !bypass2_blocked {
                // Bypass worked!
                if let Some(ref bypass_r) = bypass_resp {
                    if !bypass_blocked {
                        let sim = self.calculate_similarity(baseline, bypass_r);
                        if sim > 0.7 {
                            signals.push(Signal::new(
                                SignalType::WafBypass,
                                0.75,
                                sim,
                                "WAF bypass succeeded (case mixing)",
                            ));
                        }
                    }
                }

                if let Some(ref bypass2_r) = bypass2_resp {
                    if !bypass2_blocked {
                        let sim = self.calculate_similarity(baseline, bypass2_r);
                        if sim > 0.7 {
                            signals.push(Signal::new(
                                SignalType::WafBypass,
                                0.78,
                                sim,
                                "WAF bypass succeeded (inline comments)",
                            ));
                        }
                    }
                }
            }
        }

        signals
    }

    /// Check if response indicates WAF block
    fn is_waf_block(&self, resp: &HttpResponse) -> bool {
        // Common WAF block indicators
        if resp.status_code == 403 || resp.status_code == 406 || resp.status_code == 429 {
            return true;
        }

        let body_lower = resp.body.to_lowercase();

        // Common WAF signatures
        let waf_patterns = [
            "access denied",
            "forbidden",
            "blocked",
            "security violation",
            "waf",
            "firewall",
            "cloudflare",
            "akamai",
            "imperva",
            "incapsula",
            "sucuri",
            "mod_security",
            "request blocked",
            "suspicious activity",
        ];

        waf_patterns.iter().any(|p| body_lower.contains(p))
    }

    /// Micro-timing analysis using statistical methods
    ///
    /// Principle: SQL operations have timing signatures even without SLEEP()
    /// - String comparison: O(n) timing leak
    /// - Hash lookup vs table scan: 10-100μs difference
    /// - Index hit vs miss: measurable difference
    ///
    /// Challenge: Network jitter (10-50ms) >> SQL timing (10-100μs)
    /// Solution: Many samples + statistical analysis (Mann-Whitney U test)
    async fn analyze_micro_timing(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Payload that should cause different DB behavior
        // Short string vs long string comparison (O(n) timing)
        let short_payload = format!("{}", current_value);
        let long_payload = format!("{}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", current_value);

        let short_url = self.build_test_url(base_url, parameter, &short_payload);
        let long_url = self.build_test_url(base_url, parameter, &long_payload);

        // Collect timing samples (alternating to reduce temporal bias)
        let n_samples = 20; // Balance between accuracy and speed
        let mut short_times: Vec<f64> = Vec::with_capacity(n_samples);
        let mut long_times: Vec<f64> = Vec::with_capacity(n_samples);

        for _ in 0..n_samples {
            // Alternate to reduce temporal correlation
            if let Ok(resp) = self.http_client.get(&short_url).await {
                short_times.push(resp.duration_ms as f64);
            }
            if let Ok(resp) = self.http_client.get(&long_url).await {
                long_times.push(resp.duration_ms as f64);
            }
        }

        if short_times.len() >= 10 && long_times.len() >= 10 {
            // Calculate statistics
            let short_mean = short_times.iter().sum::<f64>() / short_times.len() as f64;
            let long_mean = long_times.iter().sum::<f64>() / long_times.len() as f64;

            let short_var = short_times.iter()
                .map(|x| (x - short_mean).powi(2))
                .sum::<f64>() / (short_times.len() - 1) as f64;
            let long_var = long_times.iter()
                .map(|x| (x - long_mean).powi(2))
                .sum::<f64>() / (long_times.len() - 1) as f64;

            let short_std = short_var.sqrt().max(0.1);
            let long_std = long_var.sqrt().max(0.1);

            // Effect size (Cohen's d)
            let pooled_std = ((short_var + long_var) / 2.0).sqrt().max(0.1);
            let effect_size = (long_mean - short_mean).abs() / pooled_std;

            // Mann-Whitney U approximation via z-score
            // (Simplified: use t-test approximation for speed)
            let se = (short_var / short_times.len() as f64 + long_var / long_times.len() as f64).sqrt();
            let t_stat = if se > 0.0 { (long_mean - short_mean).abs() / se } else { 0.0 };

            // Consistency check: is the direction consistent?
            // Long payload should take LONGER if there's O(n) string comparison
            let direction_correct = long_mean > short_mean;

            // Calculate probability based on statistical significance
            let probability = if effect_size > 0.8 && t_stat > 2.5 && direction_correct {
                0.85  // Large effect, significant, correct direction
            } else if effect_size > 0.5 && t_stat > 2.0 && direction_correct {
                0.7   // Medium effect, significant
            } else if effect_size > 0.3 && t_stat > 1.5 {
                0.55  // Small effect, marginally significant
            } else {
                0.3   // No significant difference
            };

            if probability > 0.5 {
                signals.push(Signal::new(
                    SignalType::MicroTiming,
                    probability,
                    effect_size,
                    &format!(
                        "Micro-timing: short={:.1}ms±{:.1}, long={:.1}ms±{:.1}, d={:.2}, t={:.2}",
                        short_mean, short_std, long_mean, long_std, effect_size, t_stat
                    ),
                ));
            }
        }

        // Test 2: Compare baseline timing to payload timing
        // Check if SQLi payload causes timing anomaly
        let sqli_payloads = [
            format!("{}'", current_value),
            format!("{}--", current_value),
            format!("{} AND 1=1", current_value),
        ];

        let mut baseline_times: Vec<f64> = Vec::new();
        let mut payload_times: Vec<f64> = Vec::new();

        // Collect baseline samples
        for _ in 0..10 {
            if let Ok(resp) = self.http_client.get(base_url).await {
                baseline_times.push(resp.duration_ms as f64);
            }
        }

        // Collect payload samples
        for payload in &sqli_payloads {
            let url = self.build_test_url(base_url, parameter, payload);
            for _ in 0..5 {
                if let Ok(resp) = self.http_client.get(&url).await {
                    payload_times.push(resp.duration_ms as f64);
                }
            }
        }

        if baseline_times.len() >= 5 && payload_times.len() >= 5 {
            let baseline_mean = baseline_times.iter().sum::<f64>() / baseline_times.len() as f64;
            let payload_mean = payload_times.iter().sum::<f64>() / payload_times.len() as f64;

            let baseline_var = baseline_times.iter()
                .map(|x| (x - baseline_mean).powi(2))
                .sum::<f64>() / (baseline_times.len() - 1) as f64;

            // Check for timing anomaly (payload significantly slower OR faster)
            let z_score = (payload_mean - baseline_mean).abs() / baseline_var.sqrt().max(1.0);

            if z_score > 3.0 {
                // Significant timing difference with SQLi payloads
                let prob = if z_score > 5.0 { 0.75 } else { 0.6 };
                signals.push(Signal::new(
                    SignalType::MicroTiming,
                    prob,
                    z_score,
                    &format!(
                        "SQLi payload timing anomaly: baseline={:.1}ms, payload={:.1}ms, z={:.2}",
                        baseline_mean, payload_mean, z_score
                    ),
                ));
            }
        }

        signals
    }

    /// Advanced micro-timing leak detection
    ///
    /// Uses techniques from PortSwigger research and Spectre-style analysis:
    /// 1. Bottom-quartile filtering (fastest 25% as "clean" samples)
    /// 2. 50+ samples for statistical power
    /// 3. Bootstrapped confidence intervals
    /// 4. Adaptive thresholding using control requests
    /// 5. Strong negative evidence if no leak detected
    ///
    /// Detects:
    /// - O(n) string comparison timing leaks
    /// - Hash lookup vs table scan differences
    /// - Index hit vs miss (~10-100μs difference)
    async fn analyze_micro_timing_leak(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // ================================================================
        // Phase 1: Establish baseline jitter via control requests
        // Send identical requests to measure network/server variance
        // ================================================================
        let control_url = self.build_test_url(base_url, parameter, &current_value);
        let mut control_times: Vec<f64> = Vec::with_capacity(20);

        for _ in 0..20 {
            if let Ok(resp) = self.http_client.get(&control_url).await {
                control_times.push(resp.duration_ms as f64);
            }
        }

        if control_times.len() < 10 {
            return signals; // Not enough samples
        }

        // Calculate baseline jitter (standard deviation of control)
        let control_mean = control_times.iter().sum::<f64>() / control_times.len() as f64;
        let control_var = control_times.iter()
            .map(|x| (x - control_mean).powi(2))
            .sum::<f64>() / (control_times.len() - 1) as f64;
        let jitter_std = control_var.sqrt();

        // Adaptive threshold: 3 sigma above jitter is significant
        let significance_threshold = jitter_std * 3.0;

        // ================================================================
        // Phase 2: String length timing leak (O(n) comparison)
        // Short vs long string should show linear time difference
        // ================================================================
        let short_payload = current_value.clone();
        let long_payload = format!("{}{}", current_value, "A".repeat(50));

        let short_url = self.build_test_url(base_url, parameter, &short_payload);
        let long_url = self.build_test_url(base_url, parameter, &long_payload);

        // Collect 50 samples each (alternating to reduce temporal correlation)
        let n_samples = 50;
        let mut short_times: Vec<f64> = Vec::with_capacity(n_samples);
        let mut long_times: Vec<f64> = Vec::with_capacity(n_samples);

        for _ in 0..n_samples {
            if let Ok(resp) = self.http_client.get(&short_url).await {
                short_times.push(resp.duration_ms as f64);
            }
            if let Ok(resp) = self.http_client.get(&long_url).await {
                long_times.push(resp.duration_ms as f64);
            }
        }

        if short_times.len() >= 30 && long_times.len() >= 30 {
            // Bottom-quartile filtering: use fastest 25% as "clean" samples
            short_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
            long_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

            let q1_idx = short_times.len() / 4;
            let short_q1: Vec<f64> = short_times[..q1_idx.max(5)].to_vec();
            let long_q1: Vec<f64> = long_times[..q1_idx.max(5)].to_vec();

            let short_clean_mean = short_q1.iter().sum::<f64>() / short_q1.len() as f64;
            let long_clean_mean = long_q1.iter().sum::<f64>() / long_q1.len() as f64;

            // Time difference in bottom quartile
            let timing_diff = long_clean_mean - short_clean_mean;

            // Bootstrap confidence interval (1000 resamples)
            let bootstrap_diffs = self.bootstrap_timing_diff(&short_q1, &long_q1, 500);
            let (ci_low, ci_high) = self.confidence_interval_95(&bootstrap_diffs);

            // Check if CI excludes zero (statistically significant)
            let ci_excludes_zero = ci_low > 0.0 || ci_high < 0.0;

            // Effect size on clean samples
            let short_var = short_q1.iter()
                .map(|x| (x - short_clean_mean).powi(2))
                .sum::<f64>() / short_q1.len().max(1) as f64;
            let long_var = long_q1.iter()
                .map(|x| (x - long_clean_mean).powi(2))
                .sum::<f64>() / long_q1.len().max(1) as f64;
            let pooled_std = ((short_var + long_var) / 2.0).sqrt().max(0.01);
            let effect_size = timing_diff.abs() / pooled_std;

            // Direction check: long should be slower for O(n) string comparison
            let direction_correct = timing_diff > 0.0;

            // Calculate probability based on multiple criteria
            let probability = if effect_size > 1.5 && ci_excludes_zero && direction_correct
                && timing_diff > significance_threshold {
                0.92  // Very strong evidence
            } else if effect_size > 1.0 && ci_excludes_zero && direction_correct {
                0.82  // Strong evidence
            } else if effect_size > 0.5 && direction_correct && timing_diff > jitter_std {
                0.65  // Moderate evidence
            } else if effect_size > 0.3 {
                0.45  // Weak evidence
            } else {
                0.2   // No evidence
            };

            if probability >= 0.6 {
                signals.push(Signal::new(
                    SignalType::MicroTimingLeak,
                    probability,
                    effect_size,
                    &format!(
                        "O(n) timing leak: diff={:.2}ms, d={:.2}, CI=[{:.2},{:.2}], jitter={:.2}ms",
                        timing_diff, effect_size, ci_low, ci_high, jitter_std
                    ),
                ));
            } else if probability < 0.3 && short_times.len() >= 40 {
                // Strong negative evidence: many samples, no difference
                signals.push(Signal::new(
                    SignalType::ConsistentBehavior,
                    0.85,  // High confidence in NO leak
                    effect_size,
                    &format!(
                        "No timing leak detected (n={}, d={:.2}, jitter={:.2}ms)",
                        short_times.len(), effect_size, jitter_std
                    ),
                ));
            }
        }

        // ================================================================
        // Phase 3: SQL-specific timing patterns
        // Test payloads that should cause different DB operations
        // ================================================================
        let test_payloads = [
            // Index hit vs miss (if numeric)
            (format!("{}", current_value), "baseline"),
            (format!("999999999{}", current_value), "index_miss"),
            // Hash collision potential
            (format!("{}' AND 'a'='a", current_value), "always_true"),
            (format!("{}' AND 'a'='b", current_value), "always_false"),
        ];

        let mut timing_results: Vec<(String, f64, f64)> = Vec::new();

        for (payload, label) in &test_payloads {
            let url = self.build_test_url(base_url, parameter, payload);
            let mut times: Vec<f64> = Vec::new();

            for _ in 0..15 {
                if let Ok(resp) = self.http_client.get(&url).await {
                    times.push(resp.duration_ms as f64);
                }
            }

            if times.len() >= 10 {
                times.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let q1_mean = times[..times.len()/4].iter().sum::<f64>()
                    / (times.len()/4).max(1) as f64;
                let full_mean = times.iter().sum::<f64>() / times.len() as f64;
                timing_results.push((label.to_string(), q1_mean, full_mean));
            }
        }

        // Analyze timing differences between payloads
        if timing_results.len() >= 3 {
            // Compare always_true vs always_false (classic blind SQLi timing)
            let true_time = timing_results.iter()
                .find(|(l, _, _)| l == "always_true")
                .map(|(_, q1, _)| *q1);
            let false_time = timing_results.iter()
                .find(|(l, _, _)| l == "always_false")
                .map(|(_, q1, _)| *q1);

            if let (Some(t_true), Some(t_false)) = (true_time, false_time) {
                let diff = (t_true - t_false).abs();
                if diff > significance_threshold * 2.0 {
                    signals.push(Signal::new(
                        SignalType::MicroTimingLeak,
                        0.78,
                        diff / jitter_std.max(0.1),
                        &format!(
                            "Boolean blind timing: true={:.2}ms, false={:.2}ms, diff={:.2}ms",
                            t_true, t_false, diff
                        ),
                    ));
                }
            }
        }

        signals
    }

    /// Bootstrap resampling for timing difference confidence interval
    fn bootstrap_timing_diff(&self, a: &[f64], b: &[f64], n_resamples: usize) -> Vec<f64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut diffs = Vec::with_capacity(n_resamples);

        for i in 0..n_resamples {
            // Simple deterministic "random" selection based on index
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            let seed = hasher.finish();

            let a_sample: Vec<f64> = (0..a.len())
                .map(|j| a[((seed as usize + j * 7) % a.len())])
                .collect();
            let b_sample: Vec<f64> = (0..b.len())
                .map(|j| b[((seed as usize + j * 13) % b.len())])
                .collect();

            let a_mean = a_sample.iter().sum::<f64>() / a_sample.len() as f64;
            let b_mean = b_sample.iter().sum::<f64>() / b_sample.len() as f64;
            diffs.push(b_mean - a_mean);
        }

        diffs
    }

    /// Calculate 95% confidence interval from bootstrap samples
    fn confidence_interval_95(&self, samples: &[f64]) -> (f64, f64) {
        if samples.is_empty() {
            return (0.0, 0.0);
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let low_idx = (samples.len() as f64 * 0.025) as usize;
        let high_idx = (samples.len() as f64 * 0.975) as usize;

        (
            sorted.get(low_idx).copied().unwrap_or(0.0),
            sorted.get(high_idx.min(sorted.len() - 1)).copied().unwrap_or(0.0),
        )
    }

    /// Calculate similarity between two responses (0.0 to 1.0)
    ///
    /// Unified similarity function with configurable weighting:
    /// - Status code match: 20-30% weight
    /// - Length ratio: 30-40% weight
    /// - Content hash: 30-50% weight (exact match detection)
    fn calculate_similarity(&self, a: &HttpResponse, b: &HttpResponse) -> f64 {
        // Length similarity: relative difference
        let len_a = a.body.len() as f64;
        let len_b = b.body.len() as f64;
        let len_ratio = 1.0 - (len_a - len_b).abs() / len_a.max(len_b).max(1.0);

        // Status code match
        let status_match = if a.status_code == b.status_code { 1.0 } else { 0.0 };

        // Content hash (structural similarity via FNV-1a)
        let hash_a = self.fnv1a_hash(&a.body);
        let hash_b = self.fnv1a_hash(&b.body);
        let hash_match = if hash_a == hash_b { 1.0 } else { 0.0 };

        // Weighted combination
        // If exact hash match, that's very strong evidence
        if hash_match > 0.5 {
            0.2 * status_match + 0.3 * len_ratio + 0.5 * hash_match
        } else {
            // No exact match - rely more on length and status
            0.3 * status_match + 0.5 * len_ratio + 0.2 * (if len_ratio > 0.95 { 1.0 } else { 0.0 })
        }
    }

    /// FNV-1a hash for structural content comparison
    fn fnv1a_hash(&self, s: &str) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
        for b in s.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3); // FNV prime
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
