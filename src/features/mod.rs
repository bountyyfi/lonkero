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
pub mod api;
pub mod behavior;
pub mod chain;
pub mod cloud;
pub mod cmdi;
pub mod combo;
pub mod evasion;
pub mod severity;
pub mod signals;
pub mod sqli;
pub mod ssti;
pub mod tech;
pub mod temporal;
pub mod traversal;
pub mod xss;

use crate::types::Vulnerability;
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

/// Authentication context for API feature extraction
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    pub has_auth_header: bool,
    pub auth_type: Option<String>,  // "Bearer", "Basic", "API-Key"
    pub user_role: Option<String>,  // "admin", "user", "anonymous"
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
    // === v4 fields ===
    /// For behavioral: multi-response analysis (sequence of responses from follow-up probes)
    pub probe_sequence: Option<Vec<HttpResponse>>,
    /// For temporal: multiple timing measurements in milliseconds
    pub timing_samples: Option<Vec<u64>>,
    /// For evasion: encoding used for this probe ("double_url", "unicode", "base64", etc.)
    pub encoding_used: Option<String>,
    /// For evasion: was the unencoded (raw) version of the payload blocked?
    pub raw_payload_blocked: bool,
    /// For API: request headers sent (to detect auth headers)
    pub request_headers: Option<HashMap<String, String>>,
    /// For API: authentication state
    pub auth_context: Option<AuthContext>,
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

/// Extract features with v3 pipeline: category + signals + tech + severity + combo.
/// This is the full pipeline that produces all 627 feature keys.
///
/// - `tech_features`: cached per target from `tech::extract_tech_features()`
/// - `is_authenticated` / `is_admin`: auth context for severity extraction
/// - `retry_results`: optional retry feature maps for combo consistency checks
pub fn extract_features_v3(
    ctx: &ProbeContext,
    tech_features: &HashMap<String, f64>,
    is_authenticated: bool,
    is_admin: bool,
    retry_results: Option<&[HashMap<String, f64>]>,
) -> HashMap<String, f64> {
    // 1. Run category + signal extractors (existing v2 pipeline)
    let mut features = extract_features(ctx);

    // 2. Merge tech features (cached per target)
    features.extend(tech_features.clone());

    // 3. Extract severity features (once per endpoint+param)
    let severity_features = severity::extract_severity_features(
        &ctx.request_url,
        &ctx.request_method,
        &ctx.param_name,
        &ctx.response,
        is_authenticated,
        is_admin,
    );
    features.extend(severity_features);

    // 4. Run combo extractor LAST (it reads what other extractors found)
    let combo_features = combo::extract_combo_features(&features, retry_results);
    features.extend(combo_features);

    features
}

/// Extract features with v4 pipeline: all 10 extraction layers.
/// Produces ~850 feature keys across 37 categories.
///
/// Layer order:
/// 1. Category-specific (sqli, xss, ssti, cmdi, traversal)
/// 2. Cross-cutting signals
/// 3. Behavioral/differential
/// 4. Evasion tracking
/// 5. API security
/// 6. Cloud misconfig
/// 7. Temporal/timing
/// 8. Tech fingerprinting (merged from cached)
/// 9. Severity context
/// 10. Combo boosters (MUST run last — depends on all other features)
pub fn extract_features_v4(
    ctx: &ProbeContext,
    tech_features: &HashMap<String, f64>,
    is_authenticated: bool,
    is_admin: bool,
    retry_results: Option<&[HashMap<String, f64>]>,
) -> HashMap<String, f64> {
    // Layer 1: Category-specific extractors
    let mut features = HashMap::new();
    match ctx.probe_category.as_str() {
        "sqli" => sqli::extract_sqli_features(ctx, &mut features),
        "xss" => xss::extract_xss_features(ctx, &mut features),
        "ssti" => ssti::extract_ssti_features(ctx, &mut features),
        "cmdi" => cmdi::extract_cmdi_features(ctx, &mut features),
        "traversal" => traversal::extract_traversal_features(ctx, &mut features),
        _ => {}
    }

    // Layer 2: Cross-cutting signals
    signals::extract_signal_features(ctx, &mut features);

    // Layer 3: Behavioral/differential
    behavior::extract_behavior_features(ctx, &mut features);

    // Layer 4: Evasion tracking
    evasion::extract_evasion_features(ctx, &mut features);

    // Layer 5: API security
    api::extract_api_features(ctx, &mut features);

    // Layer 6: Cloud misconfig
    cloud::extract_cloud_features(ctx, &mut features);

    // Layer 7: Temporal/timing
    temporal::extract_temporal_features(ctx, &mut features);

    // Layer 8: Tech fingerprinting (merged from cached)
    features.extend(tech_features.clone());

    // Layer 9: Severity context
    let severity_features = severity::extract_severity_features(
        &ctx.request_url,
        &ctx.request_method,
        &ctx.param_name,
        &ctx.response,
        is_authenticated,
        is_admin,
    );
    features.extend(severity_features);

    // Layer 10: Combo boosters (MUST run last — depends on all other features)
    let combo_features = combo::extract_combo_features(&features, retry_results);
    features.extend(combo_features);

    features
}

/// Extract chain features from a set of vulnerabilities.
/// POST-PROCESSING: runs on Vec<Vulnerability> AFTER all scanners complete, not per-probe.
pub fn extract_chain_features(vulns: &[Vulnerability]) -> HashMap<String, f64> {
    chain::extract_chain_features(vulns)
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
            probe_sequence: None,
            timing_samples: None,
            encoding_used: None,
            raw_payload_blocked: false,
            request_headers: None,
            auth_context: None,
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

    #[test]
    fn test_extract_features_v3_full_pipeline() {
        let response = make_response(
            "You have an error in your SQL syntax near '1'",
            500,
        );
        let ctx = make_ctx("sqli", "'", response);

        // Simulate tech features cached per target
        let mut tech_features = HashMap::new();
        tech_features.insert("tech:runtime_php".to_string(), 1.0);
        tech_features.insert("tech:db_mysql".to_string(), 1.0);

        let features = extract_features_v3(&ctx, &tech_features, false, false, None);

        // Category features
        assert!(features.contains_key("sqli:error_mysql_syntax"));
        // Signal features
        assert!(features.contains_key("signal:error_triggered"));
        // Tech features (merged in)
        assert!(features.contains_key("tech:runtime_php"));
        assert!(features.contains_key("tech:db_mysql"));
        // Severity features
        assert!(features.contains_key("severity:production_environment"));
        assert!(features.contains_key("severity:endpoint_is_public"));
        // Combo features (sqli error + input char triggers combo)
        assert!(features.contains_key("combo:sqli_error_plus_input_char"));
    }

    #[test]
    fn test_extract_features_v3_with_retries() {
        let response = make_response(
            "You have an error in your SQL syntax near '1'",
            500,
        );
        let ctx = make_ctx("sqli", "'", response);
        let tech_features = HashMap::new();

        // Simulate retry results with consistent signals
        let retry1: HashMap<String, f64> = [
            ("sqli:error_mysql_syntax".to_string(), 0.95),
            ("sqli:single_quote_triggers_error".to_string(), 1.0),
        ]
        .into_iter()
        .collect();
        let retry2: HashMap<String, f64> = [
            ("sqli:error_mysql_syntax".to_string(), 0.95),
            ("sqli:single_quote_triggers_error".to_string(), 1.0),
        ]
        .into_iter()
        .collect();
        let retries = vec![retry1, retry2];

        let features =
            extract_features_v3(&ctx, &tech_features, false, false, Some(&retries));

        assert!(features.contains_key("sqli:error_mysql_syntax"));
        assert!(features.contains_key("combo:consistent_across_retries"));
    }
}
