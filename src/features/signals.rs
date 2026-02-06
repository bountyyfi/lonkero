// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract cross-cutting signal features that apply to all probe categories
pub fn extract_signal_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    // signal:response_code_anomaly
    if ctx.response.status != ctx.baseline.status {
        features.insert("signal:response_code_anomaly".into(), 1.0);
    }

    // signal:response_size_anomaly
    let size_diff =
        (ctx.response.body_bytes as f64 - ctx.baseline.body_bytes as f64).abs();
    let size_ratio = size_diff / ctx.baseline.body_bytes.max(1) as f64;
    if size_ratio > 0.1 {
        features.insert("signal:response_size_anomaly".into(), size_ratio.min(1.0));
    }

    // signal:response_time_anomaly
    let time_ratio =
        ctx.response.response_time_ms as f64 / ctx.baseline.response_time_ms.max(1) as f64;
    if time_ratio > 2.0 || time_ratio < 0.3 {
        features.insert(
            "signal:response_time_anomaly".into(),
            ((time_ratio - 1.0).abs() / 5.0).min(1.0),
        );
    }

    // signal:error_triggered
    if ctx.response.status >= 400 && ctx.baseline.status < 400 {
        features.insert("signal:error_triggered".into(), 1.0);
    }

    // signal:input_reflected_anywhere
    if ctx.response.body.contains(&ctx.probe_payload) {
        features.insert("signal:input_reflected_anywhere".into(), 1.0);
        features.insert("signal:canary_token_reflected".into(), 1.0);
    }

    // signal:waf_detected
    let waf_indicators = [
        "mod_security",
        "cloudflare",
        "akamai",
        "imperva",
        "sucuri",
        "f5 big-ip",
        "barracuda",
        "fortiweb",
    ];
    let body_lower = ctx.response.body.to_lowercase();
    let server = ctx
        .response
        .headers
        .get("server")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    for waf in &waf_indicators {
        if body_lower.contains(waf) || server.contains(waf) {
            features.insert("signal:waf_detected".into(), 1.0);
            break;
        }
    }

    // signal:custom_error_page
    if ctx.response.status >= 400
        && ctx.response.body_bytes > 1000
        && !body_lower.contains("stack trace")
        && !body_lower.contains("traceback")
    {
        features.insert("signal:custom_error_page".into(), 1.0);
    }

    // signal:content_type_mismatch
    if let Some(ct) = ctx.response.headers.get("content-type") {
        if (ct.contains("json") && ctx.response.body.starts_with('<'))
            || (ct.contains("html") && ctx.response.body.starts_with('{'))
        {
            features.insert("signal:content_type_mismatch".into(), 1.0);
        }
    }

    // === v4 signal features ===

    // signal:response_entropy_anomaly — Shannon entropy of body differs >20% from baseline
    let probe_entropy = shannon_entropy(&ctx.response.body);
    let baseline_entropy = shannon_entropy(&ctx.baseline.body);
    if baseline_entropy > 0.0 {
        let entropy_diff = (probe_entropy - baseline_entropy).abs() / baseline_entropy;
        if entropy_diff > 0.20 {
            features.insert(
                "signal:response_entropy_anomaly".into(),
                entropy_diff.min(1.0),
            );
        }
    }

    // signal:error_class_changed — HTTP status class changed (2xx→4xx, 2xx→5xx)
    let baseline_class = ctx.baseline.status / 100;
    let probe_class = ctx.response.status / 100;
    if baseline_class != probe_class && baseline_class == 2 && probe_class >= 4 {
        features.insert("signal:error_class_changed".into(), 1.0);
    }

    // signal:new_headers_appeared — response has headers not in baseline
    let new_headers = ctx
        .response
        .headers
        .keys()
        .filter(|k| !ctx.baseline.headers.contains_key(*k))
        .count();
    if new_headers > 0 {
        features.insert(
            "signal:new_headers_appeared".into(),
            (new_headers as f64 / 5.0).min(1.0),
        );
    }

    // signal:body_structure_changed — JSON key count or HTML tag structure differs
    let probe_structure = count_structure_elements(&ctx.response.body);
    let baseline_structure = count_structure_elements(&ctx.baseline.body);
    if probe_structure != baseline_structure && baseline_structure > 0 {
        let diff = (probe_structure as f64 - baseline_structure as f64).abs()
            / baseline_structure as f64;
        if diff > 0.15 {
            features.insert("signal:body_structure_changed".into(), diff.min(1.0));
        }
    }

    // signal:cookie_behavior_changed — Set-Cookie headers differ from baseline
    let probe_cookies = ctx.response.headers.get("set-cookie");
    let baseline_cookies = ctx.baseline.headers.get("set-cookie");
    if probe_cookies != baseline_cookies && probe_cookies.is_some() {
        features.insert("signal:cookie_behavior_changed".into(), 1.0);
    }

    // signal:server_processing_indicator — response shows server processed input
    if ctx.response.status != 400
        && ctx.response.status != 403
        && ctx.response.body_bytes != ctx.baseline.body_bytes
        && !body_lower.contains("blocked")
        && !body_lower.contains("rejected")
        && !body_lower.contains("invalid")
    {
        features.insert("signal:server_processing_indicator".into(), 1.0);
    }

    // signal:param_reflected_in_header — input value appears in response header
    if ctx.probe_payload.len() >= 3 {
        for (_key, value) in &ctx.response.headers {
            if value.contains(&ctx.probe_payload) {
                features.insert("signal:param_reflected_in_header".into(), 1.0);
                break;
            }
        }
    }

    // signal:status_code_regression — probe got higher-severity status (200→500)
    if ctx.response.status >= 500 && ctx.baseline.status < 400 {
        features.insert("signal:status_code_regression".into(), 1.0);
    }
}

/// Calculate Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Count structural elements (JSON keys or HTML tags)
fn count_structure_elements(body: &str) -> usize {
    let trimmed = body.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        // JSON: count keys (occurrences of ":")
        trimmed.matches("\":").count()
    } else {
        // HTML: count tags
        trimmed.matches('<').count()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_error_triggered() {
        let response = make_response("Internal Server Error", 500);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:error_triggered"));
        assert!(features.contains_key("signal:response_code_anomaly"));
    }

    #[test]
    fn test_input_reflected() {
        let response = make_response("You searched for: <script>alert(1)</script>", 200);
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:input_reflected_anywhere"));
    }

    #[test]
    fn test_response_size_anomaly() {
        let mut response = make_response(&"x".repeat(500), 200);
        response.body_bytes = 500;
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:response_size_anomaly"));
    }

    #[test]
    fn test_response_time_anomaly() {
        let mut response = make_response("OK", 200);
        response.response_time_ms = 5000;
        let ctx = make_ctx("sqli", "' AND SLEEP(5)--", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:response_time_anomaly"));
    }

    #[test]
    fn test_waf_detected() {
        let mut response = make_response("Blocked by security", 200);
        response
            .headers
            .insert("server".to_string(), "cloudflare".to_string());
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:waf_detected"));
    }

    #[test]
    fn test_content_type_mismatch() {
        let mut response = make_response("{\"error\": true}", 200);
        response.headers.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(features.contains_key("signal:content_type_mismatch"));
    }

    #[test]
    fn test_no_anomaly_on_normal_response() {
        let response = make_response("<html><body>Normal page</body></html>", 200);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);

        assert!(!features.contains_key("signal:error_triggered"));
        assert!(!features.contains_key("signal:response_code_anomaly"));
    }

    #[test]
    fn test_error_class_changed() {
        let response = make_response("Internal Server Error", 500);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);
        assert!(features.contains_key("signal:error_class_changed"));
        assert!(features.contains_key("signal:status_code_regression"));
    }

    #[test]
    fn test_new_headers_appeared() {
        let mut response = make_response("OK", 200);
        response
            .headers
            .insert("x-debug-info".to_string(), "enabled".to_string());
        response
            .headers
            .insert("x-request-id".to_string(), "abc123".to_string());
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);
        assert!(features.contains_key("signal:new_headers_appeared"));
    }

    #[test]
    fn test_cookie_behavior_changed() {
        let mut response = make_response("OK", 200);
        response.headers.insert(
            "set-cookie".to_string(),
            "session=abc123; Path=/".to_string(),
        );
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);
        assert!(features.contains_key("signal:cookie_behavior_changed"));
    }

    #[test]
    fn test_param_reflected_in_header() {
        let mut response = make_response("OK", 200);
        response.headers.insert(
            "location".to_string(),
            "https://example.com/redirect?target=test_payload".to_string(),
        );
        let ctx = make_ctx("xss", "test_payload", response);
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);
        assert!(features.contains_key("signal:param_reflected_in_header"));
    }

    #[test]
    fn test_response_entropy_anomaly() {
        // Baseline: normal HTML. Probe: random-looking binary data with very different entropy
        let response = make_response(&"abcdefghij".repeat(50), 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.baseline.body = "aaaaaaaaaa".repeat(50);
        ctx.baseline.body_bytes = ctx.baseline.body.len();
        let mut features = HashMap::new();
        extract_signal_features(&ctx, &mut features);
        assert!(features.contains_key("signal:response_entropy_anomaly"));
    }
}
