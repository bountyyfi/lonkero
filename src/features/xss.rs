// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract XSS features from a probe response
pub fn extract_xss_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body = &ctx.response.body;
    let body_lower = body.to_lowercase();
    let probe = &ctx.probe_payload;

    // Check if probe payload is reflected in response
    let reflected = body.contains(probe);
    let reflected_lower = body_lower.contains(&probe.to_lowercase());

    if !reflected && !reflected_lower {
        return; // No reflection, no XSS features to extract
    }

    // xss:reflection_unencoded - exact payload reflected
    if reflected {
        features.insert("xss:reflection_unencoded".into(), 1.0);
    }

    // xss:script_tag_reflected
    if body_lower.contains("<script") && reflected {
        features.insert("xss:script_tag_reflected".into(), 0.95);
    }

    // xss:event_handler_reflected
    for handler in &[
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
    ] {
        if body_lower.contains(handler) && reflected {
            features.insert("xss:event_handler_reflected".into(), 0.95);
            break;
        }
    }

    // xss:javascript_uri_reflected
    if body_lower.contains("javascript:") && reflected {
        features.insert("xss:javascript_uri_reflected".into(), 0.9);
    }

    // Context detection - WHERE is it reflected?
    if let Some(pos) = body.find(probe) {
        let before = &body[..pos];

        // xss:reflection_in_script_block
        let in_script = before.rfind("<script").map_or(false, |script_pos| {
            !before[script_pos..].contains("</script>")
        });
        if in_script {
            features.insert("xss:reflection_in_script_block".into(), 1.0);
        }

        // xss:reflection_in_attribute - check if inside an HTML attribute
        let in_attr = before.rfind('=').map_or(false, |eq_pos| {
            let after_eq = &before[eq_pos..];
            (after_eq.contains('"') && after_eq.matches('"').count() % 2 == 1)
                || (after_eq.contains('\'') && after_eq.matches('\'').count() % 2 == 1)
        });
        if in_attr {
            features.insert("xss:reflection_in_attribute".into(), 1.0);
        }

        // xss:reflection_in_html_body - default if not in special context
        if !in_script && !in_attr {
            features.insert("xss:reflection_in_html_body".into(), 1.0);
        }
    }

    // CSP analysis - check response headers
    if !ctx.response.headers.contains_key("content-security-policy") {
        // xss:no_csp_header
        features.insert("xss:no_csp_header".into(), 1.0);
    } else if let Some(csp) = ctx.response.headers.get("content-security-policy") {
        if csp.contains("unsafe-inline") {
            features.insert("xss:csp_allows_unsafe_inline".into(), 1.0);
        }
        if csp.contains("unsafe-eval") {
            features.insert("xss:csp_allows_unsafe_eval".into(), 1.0);
        }
        // Strict CSP suppresses XSS confidence
        if !csp.contains("unsafe-inline") && !csp.contains("unsafe-eval") {
            features.insert("xss:csp_blocks_execution".into(), 1.0);
        }
    }

    // xss:content_type_not_html - false positive suppressor
    if let Some(ct) = ctx.response.headers.get("content-type") {
        if !ct.contains("text/html") && !ct.contains("application/xhtml") {
            features.insert("xss:content_type_not_html".into(), 1.0);
        }
    }

    // xss:httponly_cookie_set
    if let Some(cookie) = ctx.response.headers.get("set-cookie") {
        if cookie.to_lowercase().contains("httponly") {
            features.insert("xss:httponly_cookie_set".into(), 1.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_reflected_xss_basic() {
        let response = make_response(
            "<html><body><script>alert(1)</script></body></html>",
            200,
        );
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:reflection_unencoded"));
        assert!(features.contains_key("xss:script_tag_reflected"));
    }

    #[test]
    fn test_no_reflection_no_features() {
        let response = make_response("<html><body>Safe content</body></html>", 200);
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.is_empty());
    }

    #[test]
    fn test_event_handler_detection() {
        let response = make_response(
            "<img src=x onerror=alert(1)>",
            200,
        );
        let ctx = make_ctx("xss", "<img src=x onerror=alert(1)>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:event_handler_reflected"));
    }

    #[test]
    fn test_no_csp_header() {
        let response = make_response("<script>alert(1)</script>", 200);
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:no_csp_header"));
    }

    #[test]
    fn test_strict_csp_suppression() {
        let mut response = make_response("<script>alert(1)</script>", 200);
        response.headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'; script-src 'self'".to_string(),
        );
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:csp_blocks_execution"));
        assert!(!features.contains_key("xss:no_csp_header"));
    }

    #[test]
    fn test_unsafe_inline_csp() {
        let mut response = make_response("<script>alert(1)</script>", 200);
        response.headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'; script-src 'unsafe-inline'".to_string(),
        );
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:csp_allows_unsafe_inline"));
    }

    #[test]
    fn test_reflection_in_script_block() {
        let response = make_response(
            "<html><script>var x = 'PAYLOAD';</script></html>",
            200,
        );
        let ctx = make_ctx("xss", "PAYLOAD", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:reflection_in_script_block"));
    }

    #[test]
    fn test_content_type_not_html() {
        let mut response = make_response("{\"value\": \"<script>alert(1)</script>\"}", 200);
        response.headers.insert(
            "content-type".to_string(),
            "application/json".to_string(),
        );
        let ctx = make_ctx("xss", "<script>alert(1)</script>", response);
        let mut features = HashMap::new();
        extract_xss_features(&ctx, &mut features);

        assert!(features.contains_key("xss:content_type_not_html"));
    }
}
