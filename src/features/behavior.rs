// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract behavioral/differential features by comparing probe responses against baseline.
/// 22 features total: 8 response diffing, 4 stateful, 6 probe sequence, 4 FP suppressors.
pub fn extract_behavior_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    // === Response diffing (probe vs baseline) ===

    // behavior:response_length_delta — 1.0 if |probe_len - baseline_len| / baseline_len > 0.20
    let baseline_len = ctx.baseline.body_bytes.max(1) as f64;
    let probe_len = ctx.response.body_bytes as f64;
    let len_ratio = (probe_len - baseline_len).abs() / baseline_len;
    if len_ratio > 0.20 {
        features.insert("behavior:response_length_delta".into(), len_ratio.min(1.0));
    }

    // behavior:response_word_delta — 1.0 if word count diff > 15%
    let baseline_words = ctx.baseline.body.split_whitespace().count().max(1) as f64;
    let probe_words = ctx.response.body.split_whitespace().count() as f64;
    let word_ratio = (probe_words - baseline_words).abs() / baseline_words;
    if word_ratio > 0.15 {
        features.insert("behavior:response_word_delta".into(), word_ratio.min(1.0));
    }

    // behavior:response_tag_delta — 1.0 if HTML tag count diff > 10%
    let baseline_tags = count_html_tags(&ctx.baseline.body).max(1) as f64;
    let probe_tags = count_html_tags(&ctx.response.body) as f64;
    let tag_ratio = (probe_tags - baseline_tags).abs() / baseline_tags;
    if tag_ratio > 0.10 {
        features.insert("behavior:response_tag_delta".into(), tag_ratio.min(1.0));
    }

    // behavior:status_code_delta — 1.0 if status codes differ
    if ctx.response.status != ctx.baseline.status {
        features.insert("behavior:status_code_delta".into(), 1.0);
    }

    // behavior:header_count_delta — 1.0 if header count differs by 2+
    let header_diff =
        (ctx.response.headers.len() as i64 - ctx.baseline.headers.len() as i64).unsigned_abs();
    if header_diff >= 2 {
        features.insert("behavior:header_count_delta".into(), 1.0);
    }

    // behavior:response_time_delta — 1.0 if timing diff > 2x baseline
    let baseline_time = ctx.baseline.response_time_ms.max(1) as f64;
    let probe_time = ctx.response.response_time_ms as f64;
    if probe_time > baseline_time * 2.0 {
        features.insert("behavior:response_time_delta".into(), 1.0);
    }

    // behavior:redirect_behavior_delta — 1.0 if Location header differs
    let baseline_loc = ctx.baseline.headers.get("location");
    let probe_loc = ctx.response.headers.get("location");
    if baseline_loc != probe_loc {
        if baseline_loc.is_some() || probe_loc.is_some() {
            features.insert("behavior:redirect_behavior_delta".into(), 1.0);
        }
    }

    // behavior:error_message_delta — 1.0 if error message text differs
    if ctx.response.status >= 400 && ctx.baseline.status >= 400 {
        let probe_errors = extract_error_text(&ctx.response.body);
        let baseline_errors = extract_error_text(&ctx.baseline.body);
        if !probe_errors.is_empty() && probe_errors != baseline_errors {
            features.insert("behavior:error_message_delta".into(), 1.0);
        }
    }

    // === Stateful analysis (needs probe_sequence) ===
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.len() >= 2 {
            // behavior:state_persisted_across_requests — injected value in subsequent GET
            let payload_lower = ctx.probe_payload.to_lowercase();
            for resp in sequence.iter().skip(1) {
                if resp.body.to_lowercase().contains(&payload_lower) {
                    features.insert("behavior:state_persisted_across_requests".into(), 1.0);
                    break;
                }
            }

            // behavior:second_order_trigger — payload stored then triggered later
            if !ctx.response.body.to_lowercase().contains(&payload_lower) {
                for resp in sequence.iter().skip(1) {
                    if resp.status >= 500
                        || resp.body.to_lowercase().contains(&payload_lower)
                    {
                        features.insert("behavior:second_order_trigger".into(), 1.0);
                        break;
                    }
                }
            }

            // behavior:session_state_mutated — session cookie changed after probe
            let initial_cookies = ctx.response.headers.get("set-cookie");
            for resp in sequence.iter().skip(1) {
                let later_cookies = resp.headers.get("set-cookie");
                if initial_cookies != later_cookies && later_cookies.is_some() {
                    features.insert("behavior:session_state_mutated".into(), 1.0);
                    break;
                }
            }

            // behavior:database_state_changed — subsequent read shows data written
            if sequence.len() >= 3 {
                let first_body = &sequence[0].body;
                let last_body = &sequence[sequence.len() - 1].body;
                if first_body != last_body
                    && last_body.to_lowercase().contains(&payload_lower)
                {
                    features.insert("behavior:database_state_changed".into(), 1.0);
                }
            }
        }
    }

    // === Probe sequence patterns ===
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.len() >= 2 {
            // behavior:progressive_disclosure — each probe reveals more data
            let lengths: Vec<usize> = sequence.iter().map(|r| r.body_bytes).collect();
            let is_increasing = lengths.windows(2).all(|w| w[1] > w[0]);
            if is_increasing && lengths.len() >= 3 {
                features.insert("behavior:progressive_disclosure".into(), 1.0);
            }

            // behavior:boundary_probe_diff — boundary values produce different behavior
            let status_set: std::collections::HashSet<u16> =
                sequence.iter().map(|r| r.status).collect();
            if status_set.len() >= 2 {
                features.insert("behavior:boundary_probe_diff".into(), 1.0);
            }

            // behavior:type_juggling_diff — different types produce different responses
            let body_set: std::collections::HashSet<usize> =
                sequence.iter().map(|r| r.body_bytes).collect();
            if body_set.len() >= 3 {
                features.insert("behavior:type_juggling_diff".into(), 1.0);
            }

            // behavior:encoding_handling_diff — different encodings produce different responses
            if ctx.encoding_used.is_some() {
                let sizes: Vec<usize> = sequence.iter().map(|r| r.body_bytes).collect();
                let size_set: std::collections::HashSet<usize> = sizes.iter().copied().collect();
                if size_set.len() >= 2 {
                    features.insert("behavior:encoding_handling_diff".into(), 1.0);
                }
            }

            // behavior:method_swap_diff — GET vs POST produce unexpected diff
            // Inferred from sequence having different status codes
            let statuses: Vec<u16> = sequence.iter().map(|r| r.status).collect();
            if statuses.len() >= 2 && statuses[0] != statuses[1] {
                features.insert("behavior:method_swap_diff".into(), 1.0);
            }

            // behavior:content_type_swap_diff — JSON vs form-encoded differ
            if sequence.len() >= 2 {
                let ct1 = sequence[0].headers.get("content-type");
                let ct2 = sequence[1].headers.get("content-type");
                if ct1 != ct2 {
                    features.insert("behavior:content_type_swap_diff".into(), 1.0);
                }
            }
        }
    }

    // === FP suppressors ===

    // behavior:all_probes_same_response — ALL probes get byte-identical response
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.len() >= 2 {
            let all_same = sequence
                .iter()
                .all(|r| r.body == ctx.response.body && r.status == ctx.response.status);
            if all_same {
                features.insert("behavior:all_probes_same_response".into(), 1.0);
            }
        }
    }

    // behavior:delta_within_noise — length/timing deltas < 5%
    if len_ratio < 0.05 {
        let time_delta = (probe_time - baseline_time).abs() / baseline_time;
        if time_delta < 0.05 {
            features.insert("behavior:delta_within_noise".into(), 1.0);
        }
    }

    // behavior:only_cosmetic_diff — only diff is timestamps/CSRF tokens/nonces
    let probe_stripped = strip_dynamic_content(&ctx.response.body);
    let baseline_stripped = strip_dynamic_content(&ctx.baseline.body);
    if ctx.response.body != ctx.baseline.body && probe_stripped == baseline_stripped {
        features.insert("behavior:only_cosmetic_diff".into(), 1.0);
    }

    // behavior:rate_limited_responses — diffs correlate with 429 status codes
    if ctx.response.status == 429 {
        features.insert("behavior:rate_limited_responses".into(), 1.0);
    }
    if let Some(ref sequence) = ctx.probe_sequence {
        if sequence.iter().any(|r| r.status == 429) {
            features.insert("behavior:rate_limited_responses".into(), 1.0);
        }
    }
}

/// Count HTML tags in a string
fn count_html_tags(body: &str) -> usize {
    body.matches('<').count()
}

/// Extract error-related text from response body
fn extract_error_text(body: &str) -> String {
    let lower = body.to_lowercase();
    let error_keywords = ["error", "exception", "warning", "fatal", "failed"];
    let mut parts = Vec::new();
    for keyword in &error_keywords {
        if lower.contains(keyword) {
            parts.push(*keyword);
        }
    }
    parts.join(",")
}

/// Strip dynamic content like timestamps, tokens, nonces for comparison
fn strip_dynamic_content(body: &str) -> String {
    let mut result = body.to_string();
    // Strip numeric timestamps (10-13 digits)
    let mut cleaned = String::new();
    let mut chars = result.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            let mut num = String::new();
            num.push(c);
            while let Some(&next) = chars.peek() {
                if next.is_ascii_digit() {
                    num.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            if num.len() >= 10 && num.len() <= 13 {
                cleaned.push_str("__TIMESTAMP__");
            } else {
                cleaned.push_str(&num);
            }
        } else {
            cleaned.push(c);
        }
    }
    result = cleaned;

    // Strip hex tokens (32+ hex chars)
    let mut cleaned2 = String::new();
    let mut chars2 = result.chars().peekable();
    while let Some(c) = chars2.next() {
        if c.is_ascii_hexdigit() {
            let mut hex = String::new();
            hex.push(c);
            while let Some(&next) = chars2.peek() {
                if next.is_ascii_hexdigit() {
                    hex.push(chars2.next().unwrap());
                } else {
                    break;
                }
            }
            if hex.len() >= 32 {
                cleaned2.push_str("__TOKEN__");
            } else {
                cleaned2.push_str(&hex);
            }
        } else {
            cleaned2.push(c);
        }
    }
    cleaned2
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_response_length_delta() {
        let response = make_response(&"x".repeat(200), 200);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:response_length_delta"));
    }

    #[test]
    fn test_status_code_delta() {
        let response = make_response("Error", 500);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:status_code_delta"));
    }

    #[test]
    fn test_delta_within_noise() {
        let response = make_response("<html><body>Normal page</body></html>", 200);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:delta_within_noise"));
    }

    #[test]
    fn test_only_cosmetic_diff() {
        let response = make_response(
            "<html><body>Normal page</body><span>1234567890123</span></html>",
            200,
        );
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.baseline.body =
            "<html><body>Normal page</body><span>9876543210987</span></html>".to_string();
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:only_cosmetic_diff"));
    }

    #[test]
    fn test_rate_limited() {
        let response = make_response("Too Many Requests", 429);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:rate_limited_responses"));
    }

    #[test]
    fn test_probe_sequence_state_persisted() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        ctx.probe_sequence = Some(vec![
            make_response("first", 200),
            make_response("found: <script>alert(1)</script>", 200),
        ]);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:state_persisted_across_requests"));
    }

    #[test]
    fn test_all_probes_same_response() {
        let response = make_response("same", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.probe_sequence = Some(vec![
            make_response("same", 200),
            make_response("same", 200),
        ]);
        let mut features = HashMap::new();
        extract_behavior_features(&ctx, &mut features);
        assert!(features.contains_key("behavior:all_probes_same_response"));
    }
}
