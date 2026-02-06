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
}
