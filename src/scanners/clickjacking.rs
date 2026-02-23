// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Clickjacking Scanner
 * Tests for clickjacking/UI redressing vulnerabilities
 *
 * Detects:
 * - Missing X-Frame-Options header
 * - Missing CSP frame-ancestors directive
 * - Misconfigured X-Frame-Options (invalid values)
 * - Misconfigured CSP frame-ancestors (wildcard, empty)
 * - Conflicting frame protection headers
 * - Deprecated JavaScript framebuster usage
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct ClickjackingScanner {
    http_client: Arc<HttpClient>,
}

impl ClickjackingScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for clickjacking vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Testing clickjacking protection");

        match self.http_client.get(url).await {
            Ok(response) => {
                // Skip if response is 404 Not Found or other error status codes
                // Clickjacking on non-existent pages is not a meaningful finding
                if response.status_code == 404 {
                    debug!("[Clickjacking] Skipping 404 response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Skip if response body indicates a "not found" error
                if self.is_not_found_response(&response.body) {
                    debug!("[Clickjacking] Skipping not-found error response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Skip 5xx server errors
                if response.status_code >= 500 {
                    debug!("[Clickjacking] Skipping server error response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Skip API/non-HTML responses - clickjacking only applies to
                // HTML pages that browsers render. JSON/XML responses cannot
                // be framed, so reporting missing X-Frame-Options on them
                // is a false positive.
                if self.is_api_or_non_html_response(&response) {
                    debug!("[Clickjacking] Skipping API/non-HTML response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Store characteristics for intelligent detection
                let _characteristics = AppCharacteristics::from_response(&response, url);
                let headers_vec: Vec<(String, String)> = response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Some(vuln) = self.analyze_headers(&headers_vec, &response.body, url) {
                    vulnerabilities.push(vuln);
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if response is an API or non-HTML response where clickjacking
    /// is not applicable. JSON/XML responses cannot be framed in a browser.
    fn is_api_or_non_html_response(&self, response: &crate::http_client::HttpResponse) -> bool {
        // Check content-type header
        if let Some(content_type) = response.header("content-type") {
            let ct_lower = content_type.to_lowercase();
            if ct_lower.contains("application/json")
                || ct_lower.contains("application/xml")
                || ct_lower.contains("text/xml")
                || ct_lower.contains("text/plain")
                || ct_lower.contains("application/octet-stream")
                || ct_lower.contains("image/")
                || ct_lower.contains("font/")
                || ct_lower.contains("application/pdf")
            {
                return true;
            }
        }

        // Heuristic: body looks like JSON/XML
        let body_trimmed = response.body.trim();
        if (body_trimmed.starts_with('{') && body_trimmed.ends_with('}'))
            || (body_trimmed.starts_with('[') && body_trimmed.ends_with(']'))
            || (body_trimmed.starts_with("<?xml") && body_trimmed.contains("?>"))
        {
            return true;
        }

        false
    }

    /// Check if response body indicates a "not found" or similar error
    fn is_not_found_response(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let not_found_patterns = [
            "\"error\":\"not found\"",
            "\"error\": \"not found\"",
            "\"message\":\"the requested resource does not exist\"",
            "resource does not exist",
            "endpoint not found",
            "route not found",
        ];

        for pattern in &not_found_patterns {
            if body_lower.contains(pattern) {
                return true;
            }
        }

        if body_lower.contains("\"success\":false") || body_lower.contains("\"success\": false") {
            if body_lower.contains("not found") || body_lower.contains("does not exist") {
                return true;
            }
        }

        false
    }

    /// Analyze headers for clickjacking protection
    fn analyze_headers(
        &self,
        headers: &[(String, String)],
        body: &str,
        url: &str,
    ) -> Option<Vulnerability> {
        // Get X-Frame-Options header
        let x_frame_options = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "x-frame-options")
            .map(|(_, v)| v);

        // Get Content-Security-Policy header
        let csp = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-security-policy")
            .map(|(_, v)| v);

        // Check X-Frame-Options
        let has_x_frame_options = x_frame_options.is_some();
        let has_valid_x_frame_options = if let Some(xfo) = x_frame_options {
            let xfo_upper = xfo.to_uppercase();
            xfo_upper == "DENY" || xfo_upper == "SAMEORIGIN"
        } else {
            false
        };

        // Check CSP frame-ancestors
        let (has_frame_ancestors, has_valid_frame_ancestors) = if let Some(csp_value) = csp {
            let has_fa = csp_value.to_lowercase().contains("frame-ancestors");
            let has_valid = csp_value.contains("frame-ancestors 'none'")
                || csp_value.contains("frame-ancestors 'self'");
            (has_fa, has_valid)
        } else {
            (false, false)
        };

        // Neither protection is present - check for JS framebuster
        if !has_x_frame_options && !has_frame_ancestors {
            // Check if there's a JavaScript framebuster
            if self.check_for_framebuster(body) {
                return Some(self.create_vulnerability(
                    url,
                    "CLICKJACKING_JS_FRAMEBUSTER",
                    "Relying on JavaScript framebuster (can be bypassed, use proper headers)",
                    "Protection: JavaScript framebuster detected (unreliable)",
                    Severity::Low,
                    Confidence::Medium,
                    3.7,
                    "1. Replace JavaScript framebuster with X-Frame-Options: DENY or SAMEORIGIN\n\
                     2. Or use CSP frame-ancestors directive\n\
                     3. JavaScript framebusters can be bypassed with sandbox attribute\n\
                     4. Use proper HTTP headers for reliable clickjacking protection",
                ));
            }

            return Some(self.create_vulnerability(
                url,
                "CLICKJACKING_NO_PROTECTION",
                "No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)",
                "Headers: X-Frame-Options: MISSING, Content-Security-Policy frame-ancestors: MISSING",
                Severity::Medium,
                Confidence::High,
                5.3,
                "1. Add X-Frame-Options: DENY or SAMEORIGIN header\n\
                 2. Or use CSP frame-ancestors directive: frame-ancestors 'none' or 'self'\n\
                 3. Implement both for defense in depth\n\
                 4. Test frame protection in different browsers\n\
                 5. Ensure protection covers all pages, especially login and sensitive operations",
            ));
        }

        // X-Frame-Options present but misconfigured
        if has_x_frame_options && !has_valid_x_frame_options {
            let xfo_value = x_frame_options.map(|s| s.as_str()).unwrap_or("unknown");
            return Some(self.create_vulnerability(
                url,
                "CLICKJACKING_MISCONFIGURED_XFO",
                &format!("Misconfigured X-Frame-Options header: {}", xfo_value),
                &format!("X-Frame-Options: {}", xfo_value),
                Severity::Medium,
                Confidence::High,
                5.0,
                "1. Set X-Frame-Options to DENY or SAMEORIGIN\n\
                 2. Avoid ALLOW-FROM (deprecated and not widely supported)\n\
                 3. Use CSP frame-ancestors for more fine-grained control\n\
                 4. Ensure header is sent on all responses",
            ));
        }

        // CSP frame-ancestors present but misconfigured
        if has_frame_ancestors && !has_valid_frame_ancestors {
            if let Some(csp_value) = csp {
                // Extract frame-ancestors value
                if let Some(fa_value) = self.extract_frame_ancestors(csp_value) {
                    // Check for wildcard
                    if fa_value.contains('*') {
                        return Some(self.create_vulnerability(
                            url,
                            "CLICKJACKING_CSP_WILDCARD",
                            "CSP frame-ancestors allows all origins (*)",
                            &format!("Content-Security-Policy: frame-ancestors {}", fa_value),
                            Severity::Medium,
                            Confidence::High,
                            5.3,
                            "1. Set frame-ancestors to 'none' or 'self'\n\
                             2. Avoid wildcard (*) which allows framing from any origin\n\
                             3. Specify explicit allowlist of trusted domains if needed\n\
                             4. Use 'none' for maximum protection",
                        ));
                    }

                    // Check for empty value
                    if fa_value.trim().is_empty() {
                        return Some(self.create_vulnerability(
                            url,
                            "CLICKJACKING_CSP_EMPTY",
                            "Empty CSP frame-ancestors directive",
                            "Content-Security-Policy: frame-ancestors (empty)",
                            Severity::Medium,
                            Confidence::High,
                            5.0,
                            "1. Set frame-ancestors to 'none' or 'self'\n\
                             2. Do not leave the directive empty\n\
                             3. Remove the directive if not needed (but X-Frame-Options should be present)",
                        ));
                    }
                }
            }
        }

        // Check for JavaScript framebuster (deprecated but still used)
        if self.check_for_framebuster(body)
            && !has_valid_x_frame_options
            && !has_valid_frame_ancestors
        {
            return Some(self.create_vulnerability(
                url,
                "CLICKJACKING_JS_FRAMEBUSTER",
                "Relies on JavaScript framebuster (deprecated/bypassable)",
                "Frame-busting JavaScript detected but no proper headers",
                Severity::Low,
                Confidence::Medium,
                4.0,
                "1. Replace JavaScript framebuster with X-Frame-Options or CSP headers\n\
                 2. JavaScript framebusters can be bypassed in many ways\n\
                 3. Use HTTP headers for reliable protection\n\
                 4. Keep JavaScript as additional layer but not primary defense",
            ));
        }

        // Protection is properly configured
        None
    }

    /// Extract frame-ancestors value from CSP
    fn extract_frame_ancestors(&self, csp: &str) -> Option<String> {
        if let Ok(regex) = regex::Regex::new(r"frame-ancestors\s+([^;]+)") {
            if let Some(captures) = regex.captures(csp) {
                return captures.get(1).map(|m| m.as_str().to_string());
            }
        }
        None
    }

    /// Check for JavaScript framebuster code
    fn check_for_framebuster(&self, body: &str) -> bool {
        let framebuster_patterns = vec![
            r"if\s*\(\s*top\s*!==\s*self\s*\)",
            r"if\s*\(\s*top\s*!=\s*self\s*\)",
            r"if\s*\(\s*top\.location\s*!==\s*self\.location\s*\)",
            r"if\s*\(\s*top\.location\s*!=\s*self\.location\s*\)",
            r"if\s*\(\s*parent\s*!==\s*self\s*\)",
            r"top\.location\s*=\s*self\.location",
            r"parent\.location\s*=\s*self\.location",
        ];

        for pattern in framebuster_patterns {
            if let Ok(regex) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if regex.is_match(body) {
                    return true;
                }
            }
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        confidence: Confidence,
        cvss: f32,
        remediation: &str,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("clickjacking_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-1021".to_string(),
            cvss,
            verified,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> ClickjackingScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        ClickjackingScanner::new(http_client)
    }

    #[test]
    fn test_no_protection() {
        let scanner = create_test_scanner();
        let headers = vec![];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "CLICKJACKING_NO_PROTECTION");
        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.cwe, "CWE-1021");
    }

    #[test]
    fn test_valid_x_frame_options_deny() {
        let scanner = create_test_scanner();
        let headers = vec![("X-Frame-Options".to_string(), "DENY".to_string())];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_none());
    }

    #[test]
    fn test_valid_x_frame_options_sameorigin() {
        let scanner = create_test_scanner();
        let headers = vec![("X-Frame-Options".to_string(), "SAMEORIGIN".to_string())];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_x_frame_options() {
        let scanner = create_test_scanner();
        let headers = vec![(
            "X-Frame-Options".to_string(),
            "ALLOW-FROM https://example.com".to_string(),
        )];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "CLICKJACKING_MISCONFIGURED_XFO");
    }

    #[test]
    fn test_valid_csp_frame_ancestors_none() {
        let scanner = create_test_scanner();
        let headers = vec![(
            "Content-Security-Policy".to_string(),
            "frame-ancestors 'none'".to_string(),
        )];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_none());
    }

    #[test]
    fn test_valid_csp_frame_ancestors_self() {
        let scanner = create_test_scanner();
        let headers = vec![(
            "Content-Security-Policy".to_string(),
            "default-src 'self'; frame-ancestors 'self'".to_string(),
        )];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_none());
    }

    #[test]
    fn test_csp_wildcard() {
        let scanner = create_test_scanner();
        let headers = vec![(
            "Content-Security-Policy".to_string(),
            "frame-ancestors *".to_string(),
        )];
        let body = "<html><body>Test</body></html>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "CLICKJACKING_CSP_WILDCARD");
        assert!(vuln.evidence.as_ref().unwrap().contains("*"));
    }

    #[test]
    fn test_check_for_framebuster() {
        let scanner = create_test_scanner();

        let body1 = "<script>if (top !== self) { top.location = self.location; }</script>";
        assert!(scanner.check_for_framebuster(body1));

        let body2 = "<script>if (top != self) { parent.location = self.location; }</script>";
        assert!(scanner.check_for_framebuster(body2));

        let body3 = "<script>console.log('test');</script>";
        assert!(!scanner.check_for_framebuster(body3));
    }

    #[test]
    fn test_js_framebuster_without_headers() {
        let scanner = create_test_scanner();
        let headers = vec![];
        let body = "<script>if (top !== self) { top.location = self.location; }</script>";

        let result = scanner.analyze_headers(&headers, body, "http://example.com");

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "CLICKJACKING_JS_FRAMEBUSTER");
        assert_eq!(vuln.severity, Severity::Low);
    }

    #[test]
    fn test_no_false_positive_on_api_response() {
        let scanner = create_test_scanner();

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/json".to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "{\"status\": \"ok\"}".to_string(),
            headers,
            duration_ms: 100,
        };

        assert!(
            scanner.is_api_or_non_html_response(&response),
            "JSON response should be detected as API - no clickjacking check needed"
        );
    }

    #[test]
    fn test_no_false_positive_on_json_body() {
        let scanner = create_test_scanner();

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "[{\"id\": 1}, {\"id\": 2}]".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            scanner.is_api_or_non_html_response(&response),
            "JSON array body should be detected as API"
        );
    }

    #[test]
    fn test_extract_frame_ancestors() {
        let scanner = create_test_scanner();

        let csp1 = "default-src 'self'; frame-ancestors 'none'";
        assert_eq!(
            scanner.extract_frame_ancestors(csp1),
            Some("'none'".to_string())
        );

        let csp2 = "frame-ancestors *";
        assert_eq!(scanner.extract_frame_ancestors(csp2), Some("*".to_string()));

        let csp3 = "frame-ancestors 'self' https://trusted.com";
        assert_eq!(
            scanner.extract_frame_ancestors(csp3),
            Some("'self' https://trusted.com".to_string())
        );
    }
}
