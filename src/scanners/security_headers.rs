// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Security Headers Scanner
 * Tests for missing or misconfigured HTTP security headers
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct SecurityHeadersScanner {
    http_client: Arc<HttpClient>,
}

impl SecurityHeadersScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for security header misconfigurations
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[Security Headers] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let tests_run = 1; // Single request to check all headers

        match self.http_client.get(url).await {
            Ok(response) => {
                // Skip if response is 404 Not Found or other error status codes
                // Security headers on non-existent pages are not meaningful findings
                if response.status_code == 404 {
                    debug!("[Security Headers] Skipping 404 response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Skip if response body indicates a "not found" error
                // (some APIs return 200 with error JSON instead of proper 404)
                if self.is_not_found_response(&response.body) {
                    debug!("[Security Headers] Skipping not-found error response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Skip 5xx server errors as they may have different header configurations
                if response.status_code >= 500 {
                    debug!("[Security Headers] Skipping server error response: {}", url);
                    return Ok((vulnerabilities, tests_run));
                }

                // Detect if this is an API/non-HTML response where most
                // browser security headers are irrelevant (reduces false positives)
                let is_api_response = self.is_api_or_non_html_response(&response);

                // HSTS and CORS apply to all response types
                self.check_hsts(&response, url, &mut vulnerabilities);
                self.check_cors_headers(&response, url, &mut vulnerabilities);

                // These headers only matter for HTML responses rendered in browsers.
                // Reporting them on JSON/XML API responses is a false positive.
                if !is_api_response {
                    self.check_csp(&response, url, &mut vulnerabilities);
                    self.check_x_frame_options(&response, url, &mut vulnerabilities);
                    self.check_x_content_type_options(&response, url, &mut vulnerabilities);
                    self.check_x_xss_protection(&response, url, &mut vulnerabilities);
                    self.check_referrer_policy(&response, url, &mut vulnerabilities);
                    self.check_permissions_policy(&response, url, &mut vulnerabilities);
                }
            }
            Err(e) => {
                debug!("Failed to fetch URL for header check: {}", e);
            }
        }

        info!(
            "[SUCCESS] [Security Headers] Completed scan, found {} issues",
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check if response is an API or non-HTML response where browser security
    /// headers (CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
    /// are not applicable. Reporting missing headers on JSON/XML API responses
    /// is a false positive since browsers don't render them as pages.
    fn is_api_or_non_html_response(&self, response: &HttpResponse) -> bool {
        // Check content-type header
        if let Some(content_type) = response.header("content-type") {
            let ct_lower = content_type.to_lowercase();
            // Non-HTML content types where browser security headers are irrelevant
            if ct_lower.contains("application/json")
                || ct_lower.contains("application/xml")
                || ct_lower.contains("text/xml")
                || ct_lower.contains("text/plain")
                || ct_lower.contains("application/octet-stream")
                || ct_lower.contains("image/")
                || ct_lower.contains("font/")
                || ct_lower.contains("application/pdf")
                || ct_lower.contains("application/javascript")
            {
                return true;
            }
        }

        // Heuristic: if body looks like JSON/XML but no content-type header
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
    /// Some APIs return 200 OK with error JSON instead of proper HTTP status codes
    fn is_not_found_response(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for common API error patterns indicating resource not found
        let not_found_patterns = [
            "\"error\":\"not found\"",
            "\"error\": \"not found\"",
            "\"message\":\"the requested resource does not exist\"",
            "\"message\": \"the requested resource does not exist\"",
            "resource does not exist",
            "endpoint not found",
            "route not found",
            "\"status\":\"not_found\"",
            "\"status\": \"not_found\"",
            "\"code\":404",
            "\"code\": 404",
        ];

        for pattern in &not_found_patterns {
            if body_lower.contains(pattern) {
                return true;
            }
        }

        // Check for JSON error response with success:false and error containing "not found"
        if body_lower.contains("\"success\":false") || body_lower.contains("\"success\": false") {
            if body_lower.contains("not found") || body_lower.contains("does not exist") {
                return true;
            }
        }

        false
    }

    /// Check HSTS (HTTP Strict Transport Security)
    fn check_hsts(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(hsts) = response.header("strict-transport-security") {
            // Check if max-age is too short
            if hsts.contains("max-age") {
                if hsts.contains("max-age=0") || hsts.contains("max-age=1") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Weak HSTS Configuration",
                        url,
                        Severity::Medium,
                        Confidence::High,
                        "HSTS max-age is too short (less than 1 year recommended)",
                        format!("HSTS header found but weak: {}", hsts),
                        5.0,
                    ));
                }
            }

            // Note: Missing includeSubDomains is a best practice recommendation,
            // not a vulnerability. Having HSTS at all is the important part.
            // Reporting this as a finding inflates results with false positives.
        } else if url.starts_with("https") {
            vulnerabilities.push(self.create_vulnerability(
                "Missing HSTS Header",
                url,
                Severity::Medium,
                Confidence::High,
                "HTTP Strict Transport Security (HSTS) header is missing",
                "HTTPS site without HSTS is vulnerable to SSL stripping attacks".to_string(),
                5.3,
            ));
        }
    }

    /// Check Content Security Policy
    fn check_csp(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(csp) = response.header("content-security-policy") {
            // Check for unsafe-inline or unsafe-eval
            if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
                vulnerabilities.push(self.create_vulnerability(
                    "Weak CSP Configuration",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "Content Security Policy allows unsafe-inline or unsafe-eval",
                    format!("CSP: {}", csp),
                    5.0,
                ));
            }

            // Check for wildcard sources
            if csp.contains("* ") || csp.contains(" *") {
                vulnerabilities.push(self.create_vulnerability(
                    "Permissive CSP Configuration",
                    url,
                    Severity::Low,
                    Confidence::High,
                    "Content Security Policy uses wildcard (*) allowing any source",
                    format!("CSP contains wildcard: {}", csp),
                    4.0,
                ));
            }
        } else {
            vulnerabilities.push(self.create_vulnerability(
                "Missing CSP Header",
                url,
                Severity::Medium,
                Confidence::High,
                "Content Security Policy (CSP) header is missing",
                "No CSP protection against XSS and data injection attacks".to_string(),
                5.3,
            ));
        }
    }

    /// Check X-Frame-Options
    /// NOTE: Clickjacking detection is handled by the dedicated ClickjackingScanner
    /// to avoid duplicate findings. This function is kept for reference but disabled.
    fn check_x_frame_options(
        &self,
        _response: &HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Disabled - clickjacking is detected by the dedicated ClickjackingScanner
        // to avoid duplicate vulnerability reports
    }

    /// Check X-Content-Type-Options
    fn check_x_content_type_options(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.header("x-content-type-options").is_none() {
            vulnerabilities.push(self.create_vulnerability(
                "Missing X-Content-Type-Options",
                url,
                Severity::Low,
                Confidence::High,
                "X-Content-Type-Options header is missing",
                "Browsers may MIME-sniff content, leading to security issues".to_string(),
                3.1,
            ));
        }
    }

    /// Check X-XSS-Protection
    fn check_x_xss_protection(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(xss_protection) = response.header("x-xss-protection") {
            if xss_protection == "0" {
                vulnerabilities.push(self.create_vulnerability(
                    "XSS Protection Disabled",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "X-XSS-Protection explicitly disabled (set to 0)",
                    "Browser XSS filter is turned off".to_string(),
                    4.0,
                ));
            }
        }
        // Note: X-XSS-Protection is deprecated, so we don't warn if it's missing
    }

    /// Check Referrer-Policy
    /// Only reports actively dangerous configurations (unsafe-url),
    /// NOT missing headers - most sites don't set Referrer-Policy and
    /// browsers use safe defaults (strict-origin-when-cross-origin).
    fn check_referrer_policy(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(referrer) = response.header("referrer-policy") {
            // Only report explicitly dangerous policies
            if referrer.contains("unsafe-url") {
                vulnerabilities.push(self.create_vulnerability(
                    "Weak Referrer Policy",
                    url,
                    Severity::Low,
                    Confidence::High,
                    "Referrer-Policy set to 'unsafe-url' leaks full URLs to third parties",
                    format!("Referrer-Policy: {}", referrer),
                    3.1,
                ));
            }
        }
        // Note: Missing Referrer-Policy is NOT reported because modern browsers
        // default to strict-origin-when-cross-origin which is safe.
        // Reporting it creates noise without security value.
    }

    /// Check Permissions-Policy (formerly Feature-Policy)
    /// Note: Missing Permissions-Policy is NOT reported as a finding because
    /// the vast majority of websites don't set this header and it's not a
    /// security vulnerability - just a defense-in-depth hardening measure.
    /// Reporting it creates noise that obscures real findings.
    fn check_permissions_policy(
        &self,
        _response: &HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Intentionally not reporting missing Permissions-Policy.
        // This header is a hardening recommendation, not a vulnerability.
        // Reporting it on every site creates too many false positives.
    }

    /// Check CORS headers for misconfigurations
    /// Note: CORS is thoroughly checked by the dedicated CorsScanner.
    /// This function is disabled to avoid duplicate findings.
    fn check_cors_headers(
        &self,
        _response: &HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Disabled - CORS misconfigurations are detected by the dedicated CorsScanner
        // to avoid duplicate vulnerability reports between the two scanners.
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("header_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Security Header Misconfiguration - {}", title),
            severity,
            confidence,
            category: "Configuration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-16".to_string(), // Configuration
            cvss,
            verified: true,
            false_positive: false,
            remediation: format!(
                r#"Configure proper security headers:

For {}:
- HSTS: Set Strict-Transport-Security with max-age=31536000; includeSubDomains; preload
- CSP: Implement strict Content-Security-Policy without unsafe-inline/unsafe-eval
- X-Frame-Options: Set to DENY or SAMEORIGIN, or use CSP frame-ancestors
- X-Content-Type-Options: Set to nosniff
- Referrer-Policy: Use strict-origin-when-cross-origin or no-referrer
- Permissions-Policy: Restrict unnecessary browser features

Recommended configuration (Nginx example):
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"#,
                title
            ),
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
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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
    use std::collections::HashMap;

    #[test]
    fn test_missing_hsts() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_hsts(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing HSTS");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_hsts_with_includesubdomains_no_false_positive() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_hsts(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "Should NOT report missing includeSubDomains as a vulnerability"
        );
    }

    #[test]
    fn test_missing_csp_on_html() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_csp(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing CSP on HTML response");
    }

    #[test]
    fn test_no_false_positives_on_api_response() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/json".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: "{\"status\": \"ok\"}".to_string(),
            headers,
            duration_ms: 100,
        };

        assert!(
            scanner.is_api_or_non_html_response(&response),
            "JSON response should be detected as API"
        );
    }

    #[test]
    fn test_no_false_positives_on_json_body() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: "{\"data\": [1, 2, 3]}".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            scanner.is_api_or_non_html_response(&response),
            "JSON body should be detected as API even without content-type"
        );
    }

    #[test]
    fn test_missing_referrer_policy_not_reported() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_referrer_policy(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "Should NOT report missing Referrer-Policy (browsers have safe defaults)"
        );
    }

    #[test]
    fn test_unsafe_url_referrer_policy_reported() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "referrer-policy".to_string(),
            "unsafe-url".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_referrer_policy(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            1,
            "Should report explicitly dangerous unsafe-url Referrer-Policy"
        );
    }

    #[test]
    fn test_missing_permissions_policy_not_reported() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_permissions_policy(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "Should NOT report missing Permissions-Policy (not a vulnerability)"
        );
    }

    #[test]
    fn test_weak_csp() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self' 'unsafe-inline'".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_csp(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect unsafe-inline in CSP");
    }

    #[test]
    fn test_cors_handled_by_dedicated_scanner() {
        // CORS checks are now handled by the dedicated CorsScanner
        // to avoid duplicate findings. The security_headers CORS check is disabled.
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        headers.insert(
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cors_headers(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "CORS should not be reported here - handled by dedicated CorsScanner"
        );
    }
}
