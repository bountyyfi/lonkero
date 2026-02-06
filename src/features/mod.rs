// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Feature Extraction Layer
 * Analyzes HTTP probe responses and maps signals to model feature keys
 *
 * Each extractor takes a ProbeContext and returns a HashMap of feature keys
 * to values (0.0-1.0). Feature keys must match the model weight keys exactly.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
pub mod cmdi;
pub mod signals;
pub mod sqli;
pub mod ssti;
pub mod traversal;
pub mod xss;

use std::collections::HashMap;

/// Location of the parameter being tested
#[derive(Debug, Clone, PartialEq)]
pub enum ParamLocation {
    Query,
    Body,
    Header,
    Path,
    Cookie,
}

/// HTTP response data for feature extraction
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_bytes: usize,
    pub response_time_ms: u64,
}

impl HttpResponse {
    /// Create from the crate's HttpResponse type
    pub fn from_client_response(resp: &crate::http_client::HttpResponse) -> Self {
        Self {
            status: resp.status_code,
            headers: resp.headers.clone(),
            body: resp.body.clone(),
            body_bytes: resp.body.len(),
            response_time_ms: resp.duration_ms,
        }
    }
}

/// Context for probe feature extraction
#[derive(Debug, Clone)]
pub struct ProbeContext {
    /// What was injected
    pub probe_payload: String,
    /// Category: "sqli", "xss", "ssti", "cmdi", "ssrf", "traversal", etc.
    pub probe_category: String,
    /// Which parameter was tested
    pub param_name: String,
    /// Where the parameter is located
    pub param_location: ParamLocation,
    /// Full request URL
    pub request_url: String,
    /// HTTP method used
    pub request_method: String,
    /// Response to the probe request
    pub response: HttpResponse,
    /// Normal response without injection (baseline)
    pub baseline: HttpResponse,
    /// For time-based probes: expected delay in seconds
    pub injected_delay: Option<f64>,
}

/// Extract features from a probe context.
/// Returns a HashMap of feature keys (e.g. "sqli:error_mysql_syntax") to
/// values between 0.0 and 1.0.
pub fn extract_features(ctx: &ProbeContext) -> HashMap<String, f64> {
    let mut features = HashMap::new();

    // Run category-specific extractors based on probe type
    match ctx.probe_category.as_str() {
        "sqli" => sqli::extract_sqli_features(ctx, &mut features),
        "xss" => xss::extract_xss_features(ctx, &mut features),
        "ssti" => ssti::extract_ssti_features(ctx, &mut features),
        "cmdi" => cmdi::extract_cmdi_features(ctx, &mut features),
        "traversal" => traversal::extract_traversal_features(ctx, &mut features),
        _ => {}
    }

    // Always run cross-cutting signal extractors
    signals::extract_signal_features(ctx, &mut features);

    features
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn make_baseline() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "<html><body>Normal page</body></html>".to_string(),
            body_bytes: 36,
            response_time_ms: 100,
        }
    }

    pub fn make_response(body: &str, status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: HashMap::new(),
            body: body.to_string(),
            body_bytes: body.len(),
            response_time_ms: 100,
        }
    }

    pub fn make_ctx(category: &str, payload: &str, response: HttpResponse) -> ProbeContext {
        ProbeContext {
            probe_payload: payload.to_string(),
            probe_category: category.to_string(),
            param_name: "id".to_string(),
            param_location: ParamLocation::Query,
            request_url: "https://example.com/test".to_string(),
            request_method: "GET".to_string(),
            response,
            baseline: make_baseline(),
            injected_delay: None,
        }
    }

    #[test]
    fn test_extract_features_sqli() {
        let response = make_response(
            "You have an error in your SQL syntax near '1'",
            500,
        );
        let ctx = make_ctx("sqli", "'", response);
        let features = extract_features(&ctx);

        assert!(features.contains_key("sqli:error_mysql_syntax"));
        assert!(features.contains_key("signal:error_triggered"));
    }

    #[test]
    fn test_extract_features_unknown_category() {
        let response = make_response("OK", 200);
        let ctx = make_ctx("unknown", "test", response);
        let features = extract_features(&ctx);

        // Should still have signal features
        assert!(!features.contains_key("sqli:error_mysql_syntax"));
    }
}
