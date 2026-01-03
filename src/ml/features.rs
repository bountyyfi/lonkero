// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Feature Extraction
 * Extracts ML features from HTTP responses and vulnerability findings
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::HttpResponse;
use serde::{Deserialize, Serialize};

/// Extracted features from a vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFeatures {
    // Response characteristics
    pub status_code: u16,
    pub response_length: usize,
    pub response_time_ms: u64,

    // Content analysis
    pub has_html: bool,
    pub has_json: bool,
    pub has_xml: bool,
    pub has_javascript: bool,

    // Error detection
    pub has_sql_error: bool,
    pub has_stack_trace: bool,
    pub has_debug_info: bool,
    pub has_path_disclosure: bool,

    // Reflection analysis
    pub payload_reflected: bool,
    pub reflection_count: usize,
    pub reflection_in_attribute: bool,
    pub reflection_in_script: bool,
    pub reflection_encoded: bool,

    // Behavioral
    pub differs_from_baseline: bool,
    pub timing_anomaly: bool,
    pub status_changed: bool,
    pub length_changed_significantly: bool,

    // Context
    pub is_api_endpoint: bool,
    pub has_auth_headers: bool,
    pub has_session_cookie: bool,
}

impl VulnFeatures {
    /// Convert to feature vector for ML
    pub fn to_vector(&self) -> Vec<f32> {
        vec![
            // Response characteristics (normalized)
            self.status_code as f32 / 600.0,
            (self.response_length as f32).ln().max(0.0) / 20.0,
            (self.response_time_ms as f32).ln().max(0.0) / 10.0,
            // Content type flags
            self.has_html as u8 as f32,
            self.has_json as u8 as f32,
            self.has_xml as u8 as f32,
            self.has_javascript as u8 as f32,
            // Error flags
            self.has_sql_error as u8 as f32,
            self.has_stack_trace as u8 as f32,
            self.has_debug_info as u8 as f32,
            self.has_path_disclosure as u8 as f32,
            // Reflection flags
            self.payload_reflected as u8 as f32,
            (self.reflection_count as f32).min(10.0) / 10.0,
            self.reflection_in_attribute as u8 as f32,
            self.reflection_in_script as u8 as f32,
            self.reflection_encoded as u8 as f32,
            // Behavioral flags
            self.differs_from_baseline as u8 as f32,
            self.timing_anomaly as u8 as f32,
            self.status_changed as u8 as f32,
            self.length_changed_significantly as u8 as f32,
            // Context flags
            self.is_api_endpoint as u8 as f32,
            self.has_auth_headers as u8 as f32,
            self.has_session_cookie as u8 as f32,
        ]
    }

    /// Get feature names for interpretability
    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "status_code_norm",
            "response_length_log",
            "response_time_log",
            "has_html",
            "has_json",
            "has_xml",
            "has_javascript",
            "has_sql_error",
            "has_stack_trace",
            "has_debug_info",
            "has_path_disclosure",
            "payload_reflected",
            "reflection_count_norm",
            "reflection_in_attribute",
            "reflection_in_script",
            "reflection_encoded",
            "differs_from_baseline",
            "timing_anomaly",
            "status_changed",
            "length_changed_significantly",
            "is_api_endpoint",
            "has_auth_headers",
            "has_session_cookie",
        ]
    }
}

/// Feature extractor for ML pipeline
pub struct FeatureExtractor {
    // SQL error patterns
    sql_patterns: Vec<&'static str>,
    // Stack trace patterns
    stack_patterns: Vec<&'static str>,
    // Path disclosure patterns
    path_patterns: Vec<&'static str>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            sql_patterns: vec![
                "sql syntax",
                "mysql_",
                "ORA-",
                "PostgreSQL",
                "SQLite",
                "SQLSTATE",
                "syntax error",
                "unclosed quotation",
                "microsoft ole db",
                "odbc drivers",
            ],
            stack_patterns: vec![
                "at line",
                "stack trace",
                "Traceback",
                "Exception in",
                "Error at",
                ".java:",
                ".py:",
                ".php:",
                ".rb:",
                "at Object.",
            ],
            path_patterns: vec![
                "/var/www",
                "/home/",
                "C:\\",
                "D:\\",
                "/usr/",
                "/opt/",
                "wwwroot",
                "htdocs",
                "public_html",
            ],
        }
    }

    /// Extract features from HTTP response and vulnerability
    pub fn extract(
        &self,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
        payload: Option<&str>,
    ) -> VulnFeatures {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Content type detection
        let content_type = response
            .headers
            .get("content-type")
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        let has_html = content_type.contains("html") || body.contains("<html");
        let has_json =
            content_type.contains("json") || body.starts_with('{') || body.starts_with('[');
        let has_xml = content_type.contains("xml") || body.starts_with("<?xml");
        let has_javascript = content_type.contains("javascript") || body.contains("<script");

        // Error detection
        let has_sql_error = self.sql_patterns.iter().any(|p| body_lower.contains(p));
        let has_stack_trace = self.stack_patterns.iter().any(|p| body_lower.contains(p));
        let has_debug_info = body_lower.contains("debug") || body_lower.contains("verbose");
        let has_path_disclosure = self.path_patterns.iter().any(|p| body.contains(p));

        // Reflection analysis
        let (
            payload_reflected,
            reflection_count,
            reflection_in_attribute,
            reflection_in_script,
            reflection_encoded,
        ) = self.analyze_reflection(body, payload);

        // Baseline comparison
        let (differs_from_baseline, status_changed, length_changed_significantly) =
            self.compare_to_baseline(response, baseline);

        // Timing analysis (> 5 seconds is anomaly)
        let timing_anomaly = response.duration_ms > 5000;

        // Context detection
        let is_api_endpoint = body.starts_with('{')
            || body.starts_with('[')
            || response
                .headers
                .get("content-type")
                .map(|c| c.contains("json"))
                .unwrap_or(false);

        let has_auth_headers = response.headers.contains_key("authorization")
            || response.headers.contains_key("x-auth-token")
            || response.headers.contains_key("x-api-key");

        let has_session_cookie = response
            .headers
            .get("set-cookie")
            .map(|c| c.to_lowercase().contains("session") || c.to_lowercase().contains("sid"))
            .unwrap_or(false);

        VulnFeatures {
            status_code: response.status_code,
            response_length: body.len(),
            response_time_ms: response.duration_ms,
            has_html,
            has_json,
            has_xml,
            has_javascript,
            has_sql_error,
            has_stack_trace,
            has_debug_info,
            has_path_disclosure,
            payload_reflected,
            reflection_count,
            reflection_in_attribute,
            reflection_in_script,
            reflection_encoded,
            differs_from_baseline,
            timing_anomaly,
            status_changed,
            length_changed_significantly,
            is_api_endpoint,
            has_auth_headers,
            has_session_cookie,
        }
    }

    /// Analyze payload reflection in response
    fn analyze_reflection(
        &self,
        body: &str,
        payload: Option<&str>,
    ) -> (bool, usize, bool, bool, bool) {
        let Some(payload) = payload else {
            return (false, 0, false, false, false);
        };

        if payload.is_empty() {
            return (false, 0, false, false, false);
        }

        let payload_lower = payload.to_lowercase();
        let body_lower = body.to_lowercase();

        // Check for direct reflection
        let direct_count = body.matches(payload).count();
        let lower_count = body_lower.matches(&payload_lower).count();
        let reflected = direct_count > 0 || lower_count > 0;
        let count = direct_count.max(lower_count);

        // Check for reflection contexts
        let in_attribute =
            body.contains(&format!("=\"{}", payload)) || body.contains(&format!("='{}", payload));

        let in_script = {
            // Find script tags and check if payload is inside
            let script_pattern = regex::Regex::new(r"<script[^>]*>([\s\S]*?)</script>").unwrap();
            let mut found = false;
            for cap in script_pattern.captures_iter(body) {
                if cap
                    .get(1)
                    .map(|m| m.as_str().contains(payload))
                    .unwrap_or(false)
                {
                    found = true;
                    break;
                }
            }
            found
        };

        // Check for encoded versions
        let html_encoded = body.contains(&html_escape::encode_text(payload).to_string());
        let url_encoded = body.contains(&urlencoding::encode(payload).to_string());
        let encoded = html_encoded || url_encoded;

        (reflected, count, in_attribute, in_script, encoded)
    }

    /// Compare response to baseline
    fn compare_to_baseline(
        &self,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
    ) -> (bool, bool, bool) {
        let Some(baseline) = baseline else {
            return (false, false, false);
        };

        let status_changed = response.status_code != baseline.status_code;

        let length_ratio = response.body.len() as f64 / baseline.body.len().max(1) as f64;
        let length_changed_significantly = length_ratio < 0.5 || length_ratio > 2.0;

        let differs =
            status_changed || length_changed_significantly || response.body != baseline.body;

        (differs, status_changed, length_changed_significantly)
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnFeatures {
    /// Create GDPR-compliant features from vulnerability metadata only
    /// No raw response data is stored - only statistical features extracted from
    /// already-existing vulnerability evidence and description fields
    ///
    /// This method is safe to use without storing any PII or response data
    pub fn from_vulnerability(vuln: &crate::types::Vulnerability) -> Self {
        let evidence = vuln.evidence.as_deref().unwrap_or("");
        let description = &vuln.description;
        let evidence_lower = evidence.to_lowercase();
        let desc_lower = description.to_lowercase();
        let combined_lower = format!("{} {}", evidence_lower, desc_lower);

        // SQL error patterns
        let sql_patterns = [
            "sql syntax",
            "mysql",
            "ora-",
            "postgresql",
            "sqlite",
            "sqlstate",
            "syntax error",
            "quotation",
            "ole db",
            "odbc",
        ];
        let has_sql_error = sql_patterns.iter().any(|p| combined_lower.contains(p));

        // Stack trace patterns
        let stack_patterns = [
            "at line",
            "stack trace",
            "traceback",
            "exception in",
            ".java:",
            ".py:",
            ".php:",
            ".rb:",
            "at object.",
        ];
        let has_stack_trace = stack_patterns.iter().any(|p| combined_lower.contains(p));

        // Path disclosure patterns
        let path_patterns = [
            "/var/www",
            "/home/",
            "c:\\",
            "d:\\",
            "/usr/",
            "/opt/",
            "wwwroot",
            "htdocs",
            "public_html",
        ];
        let has_path_disclosure = path_patterns
            .iter()
            .any(|p| evidence_lower.contains(p) || desc_lower.contains(p));

        // Content type detection from vuln type/category
        let vuln_type_lower = vuln.vuln_type.to_lowercase();
        let category_lower = vuln.category.to_lowercase();

        let has_html = vuln_type_lower.contains("xss") || vuln_type_lower.contains("html");
        let has_json = category_lower.contains("api") || vuln_type_lower.contains("json");
        let has_xml = vuln_type_lower.contains("xml") || vuln_type_lower.contains("xxe");
        let has_javascript = vuln_type_lower.contains("xss") || vuln_type_lower.contains("dom");

        // Reflection detection from evidence
        let payload_reflected = evidence_lower.contains("reflected")
            || evidence_lower.contains("payload")
            || evidence.contains(vuln.payload.as_str());

        let reflection_in_attribute = evidence_lower.contains("attribute")
            || evidence_lower.contains("=\"")
            || evidence_lower.contains("='");

        let reflection_in_script =
            evidence_lower.contains("<script") || evidence_lower.contains("javascript:");

        // Behavioral indicators from description
        let timing_anomaly = desc_lower.contains("time")
            && (desc_lower.contains("delay")
                || desc_lower.contains("slow")
                || desc_lower.contains("ms"));

        let differs_from_baseline = desc_lower.contains("different")
            || desc_lower.contains("changed")
            || desc_lower.contains("baseline");

        // API endpoint detection from URL
        let url_lower = vuln.url.to_lowercase();
        let is_api_endpoint = url_lower.contains("/api/")
            || url_lower.contains("/graphql")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/rest/");

        // Auth detection from evidence/description
        let has_auth_headers = desc_lower.contains("authorization")
            || desc_lower.contains("auth header")
            || desc_lower.contains("bearer");

        let has_session_cookie = desc_lower.contains("session") || desc_lower.contains("cookie");

        Self {
            // Use placeholder values since we don't have raw response
            status_code: if vuln.verified { 200 } else { 0 },
            response_length: evidence.len(),
            response_time_ms: if timing_anomaly { 5000 } else { 100 },
            has_html,
            has_json,
            has_xml,
            has_javascript,
            has_sql_error,
            has_stack_trace,
            has_debug_info: desc_lower.contains("debug") || evidence_lower.contains("debug"),
            has_path_disclosure,
            payload_reflected,
            reflection_count: if payload_reflected { 1 } else { 0 },
            reflection_in_attribute,
            reflection_in_script,
            reflection_encoded: evidence_lower.contains("encoded")
                || evidence_lower.contains("&lt;"),
            differs_from_baseline,
            timing_anomaly,
            status_changed: false, // Can't determine without baseline
            length_changed_significantly: false, // Can't determine without baseline
            is_api_endpoint,
            has_auth_headers,
            has_session_cookie,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_response(body: &str, status: u16) -> HttpResponse {
        HttpResponse {
            status_code: status,
            headers: HashMap::new(),
            body: body.to_string(),
            duration_ms: 100,
        }
    }

    #[test]
    fn test_sql_error_detection() {
        let extractor = FeatureExtractor::new();
        let response = create_test_response("Error: You have an error in your SQL syntax", 500);

        let features = extractor.extract(&response, None, None);
        assert!(features.has_sql_error);
    }

    #[test]
    fn test_reflection_detection() {
        let extractor = FeatureExtractor::new();
        let response = create_test_response("<input value=\"<script>alert(1)</script>\">", 200);

        let features = extractor.extract(&response, None, Some("<script>alert(1)</script>"));
        assert!(features.payload_reflected);
        assert!(features.reflection_in_attribute);
    }

    #[test]
    fn test_feature_vector_length() {
        let features = VulnFeatures {
            status_code: 200,
            response_length: 1000,
            response_time_ms: 100,
            has_html: true,
            has_json: false,
            has_xml: false,
            has_javascript: true,
            has_sql_error: false,
            has_stack_trace: false,
            has_debug_info: false,
            has_path_disclosure: false,
            payload_reflected: true,
            reflection_count: 1,
            reflection_in_attribute: true,
            reflection_in_script: false,
            reflection_encoded: false,
            differs_from_baseline: true,
            timing_anomaly: false,
            status_changed: false,
            length_changed_significantly: false,
            is_api_endpoint: false,
            has_auth_headers: false,
            has_session_cookie: false,
        };

        let vector = features.to_vector();
        assert_eq!(vector.len(), VulnFeatures::feature_names().len());
    }
}
