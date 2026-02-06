// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::ProbeContext;
use std::collections::HashMap;

/// Extract evasion/bypass tracking features.
/// 20 features total: 6 encoding evasion, 6 structural evasion, 6 WAF-specific, 2 FP suppressors.
pub fn extract_evasion_features(ctx: &ProbeContext, features: &mut HashMap<String, f64>) {
    let body_lower = ctx.response.body.to_lowercase();
    let payload_reflected = ctx.response.body.contains(&ctx.probe_payload);

    // === Encoding evasion ===
    // Set bypass feature to 1.0 only if raw_payload_blocked AND encoded version got through
    if ctx.raw_payload_blocked {
        if let Some(ref encoding) = ctx.encoding_used {
            let succeeded = payload_reflected
                || (ctx.response.status < 400 && ctx.response.status != ctx.baseline.status)
                || ctx.response.body_bytes != ctx.baseline.body_bytes;

            if succeeded {
                match encoding.as_str() {
                    "double_url" => {
                        features.insert("evasion:double_url_encode_bypass".into(), 1.0);
                    }
                    "unicode" => {
                        features.insert("evasion:unicode_normalize_bypass".into(), 1.0);
                    }
                    "html_entity" => {
                        features.insert("evasion:html_entity_bypass".into(), 1.0);
                    }
                    "hex" => {
                        features.insert("evasion:hex_encode_bypass".into(), 1.0);
                    }
                    "base64" => {
                        features.insert("evasion:base64_encode_bypass".into(), 1.0);
                    }
                    "overlong_utf8" => {
                        features.insert("evasion:overlong_utf8_bypass".into(), 1.0);
                    }
                    _ => {}
                }
            }
        }
    }

    // === Structural evasion ===
    // These fire when raw was blocked but structural variation succeeded
    if ctx.raw_payload_blocked {
        if let Some(ref encoding) = ctx.encoding_used {
            let succeeded = ctx.response.status < 400
                || payload_reflected
                || ctx.response.body_bytes != ctx.baseline.body_bytes;

            if succeeded {
                match encoding.as_str() {
                    "case_variation" => {
                        features.insert("evasion:case_variation_bypass".into(), 1.0);
                    }
                    "comment_insertion" => {
                        features.insert("evasion:comment_insertion_bypass".into(), 1.0);
                    }
                    "whitespace_variation" => {
                        features.insert("evasion:whitespace_variation_bypass".into(), 1.0);
                    }
                    "null_byte" => {
                        features.insert("evasion:null_byte_bypass".into(), 1.0);
                    }
                    "concatenation" => {
                        features.insert("evasion:concatenation_bypass".into(), 1.0);
                    }
                    "alternative_syntax" => {
                        features.insert("evasion:alternative_syntax_bypass".into(), 1.0);
                    }
                    _ => {}
                }
            }
        }
    }

    // === WAF-specific ===

    // evasion:waf_fingerprinted — WAF identified from headers or body
    let server = ctx
        .response
        .headers
        .get("server")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let has_waf = server.contains("cloudflare")
        || server.contains("imperva")
        || server.contains("sucuri")
        || server.contains("barracuda")
        || server.contains("fortiweb")
        || ctx.response.headers.contains_key("x-sucuri-id")
        || ctx.response.headers.contains_key("x-cdn")
        || body_lower.contains("modsecurity")
        || body_lower.contains("cloudflare")
        || body_lower.contains("akamai")
        || body_lower.contains("incapsula");

    if has_waf {
        features.insert("evasion:waf_fingerprinted".into(), 1.0);
    }

    // evasion:waf_rule_gap_found — specific rule bypass discovered
    if ctx.raw_payload_blocked && !payload_reflected && ctx.response.status < 400 {
        if ctx.encoding_used.is_some() && ctx.response.body_bytes != ctx.baseline.body_bytes {
            features.insert("evasion:waf_rule_gap_found".into(), 1.0);
        }
    }

    // evasion:waf_threshold_bypass — smaller/split payloads pass WAF
    if ctx.raw_payload_blocked && ctx.probe_payload.len() < 20 && ctx.response.status < 400 {
        features.insert("evasion:waf_threshold_bypass".into(), 1.0);
    }

    // evasion:waf_method_bypass — WAF only inspects GET/POST not PUT/PATCH
    if ctx.raw_payload_blocked {
        let method = ctx.request_method.to_uppercase();
        if (method == "PUT" || method == "PATCH" || method == "DELETE")
            && ctx.response.status < 400
        {
            features.insert("evasion:waf_method_bypass".into(), 1.0);
        }
    }

    // evasion:waf_content_type_bypass — WAF skips application/xml or multipart
    if let Some(ref headers) = ctx.request_headers {
        if ctx.raw_payload_blocked {
            if let Some(ct) = headers.get("content-type") {
                let ct_lower = ct.to_lowercase();
                if (ct_lower.contains("application/xml")
                    || ct_lower.contains("multipart/form-data"))
                    && ctx.response.status < 400
                {
                    features.insert("evasion:waf_content_type_bypass".into(), 1.0);
                }
            }
        }
    }

    // evasion:waf_chunked_bypass — chunked Transfer-Encoding bypasses WAF
    if let Some(ref headers) = ctx.request_headers {
        if ctx.raw_payload_blocked {
            if let Some(te) = headers.get("transfer-encoding") {
                if te.to_lowercase().contains("chunked") && ctx.response.status < 400 {
                    features.insert("evasion:waf_chunked_bypass".into(), 1.0);
                }
            }
        }
    }

    // === FP suppressors ===

    // evasion:bypass_not_exploitable — bypass got past filter but no actual vuln confirmed
    if ctx.raw_payload_blocked && ctx.encoding_used.is_some() {
        // Bypass was found but no actual vuln signal
        if !payload_reflected && ctx.response.status == ctx.baseline.status {
            features.insert("evasion:bypass_not_exploitable".into(), 1.0);
        }
    }

    // evasion:filter_is_application_logic — "filter" is input validation not security control
    if ctx.response.status == 400 || ctx.response.status == 422 {
        if body_lower.contains("invalid")
            || body_lower.contains("validation")
            || body_lower.contains("must be")
            || body_lower.contains("required field")
        {
            features.insert("evasion:filter_is_application_logic".into(), 1.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_waf_fingerprinted_cloudflare() {
        let mut response = make_response("Attention Required! | Cloudflare", 403);
        response
            .headers
            .insert("server".to_string(), "cloudflare".to_string());
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(features.contains_key("evasion:waf_fingerprinted"));
    }

    #[test]
    fn test_double_url_encode_bypass() {
        let response = make_response("SQL error near '%27'", 500);
        let mut ctx = make_ctx("sqli", "%2527", response);
        ctx.raw_payload_blocked = true;
        ctx.encoding_used = Some("double_url".to_string());
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(features.contains_key("evasion:double_url_encode_bypass"));
    }

    #[test]
    fn test_no_bypass_without_blocked() {
        let response = make_response("OK", 200);
        let mut ctx = make_ctx("sqli", "'", response);
        ctx.encoding_used = Some("double_url".to_string());
        ctx.raw_payload_blocked = false;
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(!features.contains_key("evasion:double_url_encode_bypass"));
    }

    #[test]
    fn test_filter_is_application_logic() {
        let response = make_response("Validation error: id must be a number", 422);
        let ctx = make_ctx("sqli", "'", response);
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(features.contains_key("evasion:filter_is_application_logic"));
    }

    #[test]
    fn test_waf_method_bypass() {
        let response = make_response("data", 200);
        let mut ctx = make_ctx("sqli", "' OR 1=1--", response);
        ctx.raw_payload_blocked = true;
        ctx.request_method = "PUT".to_string();
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(features.contains_key("evasion:waf_method_bypass"));
    }

    #[test]
    fn test_bypass_not_exploitable() {
        let response = make_response("<html><body>Normal page</body></html>", 200);
        let mut ctx = make_ctx("sqli", "' OR 1=1--", response);
        ctx.raw_payload_blocked = true;
        ctx.encoding_used = Some("unicode".to_string());
        let mut features = HashMap::new();
        extract_evasion_features(&ctx, &mut features);
        assert!(features.contains_key("evasion:bypass_not_exploitable"));
    }
}
