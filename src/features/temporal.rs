// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract temporal/timing analysis features.
/// 16 features total: 5 timing analysis, 5 multi-request patterns,
/// 4 consistency, 2 FP suppressors.
pub fn extract_temporal_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    // === Timing analysis (needs timing_samples) ===
    if let Some(ref samples) = ctx.timing_samples {
        if samples.len() >= 2 {
            let mut sorted: Vec<u64> = samples.clone();
            sorted.sort();

            let mean = sorted.iter().sum::<u64>() as f64 / sorted.len() as f64;
            let variance = sorted
                .iter()
                .map(|&x| {
                    let diff = x as f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / sorted.len() as f64;
            let stddev = variance.sqrt();

            // temporal:response_time_bimodal — two clusters in timing data
            let mut max_gap = 0u64;
            for w in sorted.windows(2) {
                let gap = w[1] - w[0];
                if gap > max_gap {
                    max_gap = gap;
                }
            }
            let range = sorted.last().unwrap_or(&1) - sorted.first().unwrap_or(&0);
            if range > 0 && max_gap as f64 > range as f64 * 0.5 {
                features.insert("temporal:response_time_bimodal".into(), 1.0);
            }

            // temporal:time_delay_proportional — delay proportional to injected sleep
            if let Some(delay) = ctx.injected_delay {
                let expected_ms = (delay * 1000.0) as u64;
                if expected_ms > 0 {
                    let actual = ctx.response.response_time_ms;
                    let ratio = actual as f64 / expected_ms as f64;
                    if (0.8..=1.2).contains(&ratio) {
                        features.insert("temporal:time_delay_proportional".into(), 1.0);
                    }
                }
            }

            // temporal:time_delay_consistent — 3+ samples within 15% of each other
            if sorted.len() >= 3 {
                let cv = if mean > 0.0 { stddev / mean } else { 0.0 };
                if cv < 0.15 && mean > 100.0 {
                    features.insert("temporal:time_delay_consistent".into(), 1.0);
                }
            }

            // temporal:baseline_timing_stable — baseline stddev < 10% of mean
            let baseline_time = ctx.baseline.response_time_ms as f64;
            if baseline_time > 0.0 {
                // Use the first few samples to estimate baseline stability
                let baseline_cv = stddev / baseline_time;
                if baseline_cv < 0.10 {
                    features.insert("temporal:baseline_timing_stable".into(), 1.0);
                }
            }

            // temporal:timing_jitter_low — probe timing stddev < 15% of mean
            if mean > 0.0 {
                let cv = stddev / mean;
                if cv < 0.15 {
                    features.insert("temporal:timing_jitter_low".into(), 1.0);
                }
            }

            // === FP suppressors ===

            // temporal:high_variance_baseline — baseline stddev > 30% of mean
            if mean > 0.0 && stddev / mean > 0.30 {
                features.insert("temporal:high_variance_baseline".into(), 1.0);
            }

            // temporal:shared_infra_noise — timing patterns match CDN/shared hosting jitter
            // High variance with no clear bimodal pattern suggests shared infra noise
            if mean > 0.0 && stddev / mean > 0.20 && max_gap as f64 <= range as f64 * 0.3 {
                features.insert("temporal:shared_infra_noise".into(), 1.0);
            }
        }
    }

    // === Multi-request patterns (needs probe_sequence) ===
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.len() >= 2 {
            let sizes: Vec<usize> = sequence.iter().map(|r| r.body_bytes).collect();
            let times: Vec<u64> = sequence.iter().map(|r| r.response_time_ms).collect();

            // temporal:escalating_response_size — response body lengths increasing
            let is_increasing = sizes.windows(2).all(|w| w[1] >= w[0]);
            if is_increasing && sizes.first() != sizes.last() {
                features.insert("temporal:escalating_response_size".into(), 1.0);
            }

            // temporal:diminishing_response_time — response times decrease (caching)
            let is_decreasing = times.windows(2).all(|w| w[1] <= w[0]);
            if is_decreasing && times.first() != times.last() {
                features.insert("temporal:diminishing_response_time".into(), 1.0);
            }

            // temporal:state_accumulation — server state grows with each request
            if sizes.len() >= 3 {
                let growth = sizes.windows(2).filter(|w| w[1] > w[0]).count();
                if growth == sizes.len() - 1 {
                    features.insert("temporal:state_accumulation".into(), 1.0);
                }
            }

            // temporal:counter_increment_detected — numeric values in body increment
            let numbers: Vec<Option<u64>> = sequence
                .iter()
                .map(|r| extract_first_number(&r.body))
                .collect();
            if numbers.len() >= 2 {
                let valid: Vec<u64> = numbers.iter().filter_map(|n| *n).collect();
                if valid.len() >= 2 {
                    let is_incrementing = valid.windows(2).all(|w| w[1] > w[0]);
                    if is_incrementing {
                        features.insert("temporal:counter_increment_detected".into(), 1.0);
                    }
                }
            }

            // temporal:sequence_dependency — response depends on request ordering
            if sequence.len() >= 3 {
                let first_body = &sequence[0].body;
                let last_body = &sequence[sequence.len() - 1].body;
                if first_body != last_body {
                    let first_status = sequence[0].status;
                    let last_status = sequence[sequence.len() - 1].status;
                    if first_status != last_status {
                        features.insert("temporal:sequence_dependency".into(), 1.0);
                    }
                }
            }
        }

        // === Consistency ===

        // temporal:result_stable_3_retries — identical response across 3 retries
        if sequence.len() >= 3 {
            let first = &sequence[0].body;
            let stable_3 = sequence[..3].iter().all(|r| &r.body == first);
            if stable_3 {
                features.insert("temporal:result_stable_3_retries".into(), 1.0);
            }

            // temporal:result_stable_5_retries — identical across 5 retries
            if sequence.len() >= 5 {
                let stable_5 = sequence[..5].iter().all(|r| &r.body == first);
                if stable_5 {
                    features.insert("temporal:result_stable_5_retries".into(), 1.0);
                }
            }
        }

        // temporal:degrading_over_time — signal strength decreases across retries
        if sequence.len() >= 3 {
            let payload_lower = ctx.probe_payload.to_lowercase();
            let match_counts: Vec<usize> = sequence
                .iter()
                .map(|r| {
                    r.body
                        .to_lowercase()
                        .matches(&payload_lower)
                        .count()
                })
                .collect();
            let is_degrading = match_counts.windows(2).all(|w| w[1] <= w[0])
                && match_counts.first() > match_counts.last();
            if is_degrading {
                features.insert("temporal:degrading_over_time".into(), 1.0);
            }
        }

        // temporal:only_first_request — only first request showed signal
        if sequence.len() >= 2 {
            let payload_lower = ctx.probe_payload.to_lowercase();
            let first_has = sequence[0]
                .body
                .to_lowercase()
                .contains(&payload_lower);
            let rest_have = sequence[1..]
                .iter()
                .any(|r| r.body.to_lowercase().contains(&payload_lower));
            if first_has && !rest_have {
                features.insert("temporal:only_first_request".into(), 1.0);
            }
        }
    }
}

/// Extract first numeric value from response body
fn extract_first_number(body: &str) -> Option<u64> {
    let mut num_str = String::new();
    let mut found_digit = false;
    for c in body.chars() {
        if c.is_ascii_digit() {
            num_str.push(c);
            found_digit = true;
        } else if found_digit {
            break;
        }
    }
    if found_digit {
        num_str.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_bimodal_timing() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "' AND SLEEP(5)--", response);
        // Two clusters: fast (100-120ms) and slow (5000-5100ms)
        ctx.timing_samples = Some(vec![100, 110, 120, 5000, 5050, 5100]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:response_time_bimodal"));
    }

    #[test]
    fn test_time_delay_proportional() {
        let mut response = make_response("OK", 200);
        response.response_time_ms = 3000;
        let mut ctx = make_ctx("sqli", "' AND SLEEP(3)--", response);
        ctx.injected_delay = Some(3.0);
        ctx.timing_samples = Some(vec![3000, 3100, 2900]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:time_delay_proportional"));
    }

    #[test]
    fn test_consistent_timing() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "' AND SLEEP(1)--", response);
        ctx.timing_samples = Some(vec![1000, 1020, 1010, 990, 1005]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:time_delay_consistent"));
        assert!(features.contains_key("temporal:timing_jitter_low"));
    }

    #[test]
    fn test_high_variance_baseline() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.timing_samples = Some(vec![100, 500, 200, 800, 300]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:high_variance_baseline"));
    }

    #[test]
    fn test_escalating_response_size() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.probe_sequence = Some(vec![
            make_response("a", 200),
            make_response("ab", 200),
            make_response("abc", 200),
            make_response("abcd", 200),
        ]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:escalating_response_size"));
        assert!(features.contains_key("temporal:state_accumulation"));
    }

    #[test]
    fn test_result_stable_3_retries() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.probe_sequence = Some(vec![
            make_response("same", 200),
            make_response("same", 200),
            make_response("same", 200),
        ]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:result_stable_3_retries"));
    }

    #[test]
    fn test_only_first_request() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("xss", "<script>", response);
        ctx.probe_sequence = Some(vec![
            make_response("found: <script>", 200),
            make_response("not found", 200),
            make_response("not found", 200),
        ]);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.contains_key("temporal:only_first_request"));
    }

    #[test]
    fn test_no_features_without_data() {
        let response = make_response("OK", 200);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_temporal_features(&ctx, &mut features);
        assert!(features.is_empty());
    }
}
