// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Open Redirect Scanner
 * Tests for open redirect vulnerabilities
 *
 * Detects:
 * - Open redirects to external domains
 * - Protocol-relative URL redirects (//)
 * - Dangerous protocol redirects (javascript:, data:, etc.)
 * - Whitelist bypass techniques
 * - Encoded redirect payloads
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct OpenRedirectScanner {
    http_client: Arc<HttpClient>,
}

impl OpenRedirectScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for open redirect vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing open redirect on parameter: {}", param_name);

        // Test various open redirect payloads
        let payloads = vec![
            // External domain redirects
            ("https://evil.com", "External HTTPS redirect"),
            ("http://evil.com", "External HTTP redirect"),
            ("//evil.com", "Protocol-relative redirect"),
            ("//google.com", "Protocol-relative to google.com"),

            // Dangerous protocols
            ("javascript:alert(1)", "JavaScript protocol"),
            ("data:text/html,<script>alert(1)</script>", "Data URI with XSS"),
            ("vbscript:msgbox(1)", "VBScript protocol"),

            // Whitelist bypasses
            ("https://evil.com@trusted.com", "User info bypass"),
            ("https://trusted.com.evil.com", "Subdomain bypass"),
            ("https://trusted.com/redirect?url=evil.com", "Nested redirect"),
            ("https://evil.com#trusted.com", "Fragment bypass"),
            ("https://evil.com?trusted.com", "Query bypass"),

            // Encoded variations
            ("https%3A%2F%2Fevil.com", "URL encoded HTTPS"),
            ("//evil%E3%80%82com", "Unicode encoded dot"),
            ("//evil\x00.com", "Null byte injection"),

            // CRLF injection for redirect
            ("%0d%0aLocation:%20https://evil.com", "CRLF injection redirect"),

            // Absolute paths (may redirect)
            ("/redirect?url=https://evil.com", "Absolute path redirect"),
            ("///evil.com", "Triple slash redirect"),
        ];

        for (payload, description) in payloads {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", url, param_name, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for redirects in Location header
                    if let Some(location) = response.headers.iter()
                        .find(|(k, _)| k.to_lowercase() == "location")
                        .map(|(_, v)| v)
                    {
                        if let Some(vuln) = self.analyze_redirect(
                            location,
                            payload,
                            description,
                            &test_url,
                            param_name,
                            response.status_code,
                        ) {
                            info!("Open redirect vulnerability detected: {}", description);
                            vulnerabilities.push(vuln);
                            break; // Found vulnerability, move to next parameter
                        }
                    }

                    // Also check for meta refresh redirects in HTML
                    if response.body.contains("http-equiv") && response.body.contains("refresh") {
                        if let Some(vuln) = self.analyze_meta_redirect(
                            &response.body,
                            payload,
                            description,
                            &test_url,
                            param_name,
                        ) {
                            info!("Open redirect via meta refresh detected");
                            vulnerabilities.push(vuln);
                            break;
                        }
                    }

                    // Check for JavaScript-based redirects
                    if response.body.contains("window.location") || response.body.contains("location.href") {
                        if self.contains_dangerous_redirect(&response.body, payload) {
                            vulnerabilities.push(self.create_vulnerability(
                                &test_url,
                                param_name,
                                payload,
                                "JavaScript-based open redirect",
                                "Payload reflected in JavaScript redirect",
                                Confidence::Medium,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for open redirect (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test common redirect parameter names
        let common_params = vec![
            "redirect".to_string(), "url".to_string(), "next".to_string(), "return".to_string(), "returnUrl".to_string(), "goto".to_string(),
            "dest".to_string(), "destination".to_string(), "continue".to_string(), "return_to".to_string(), "redir".to_string(),
            "target".to_string(), "link".to_string(), "forward".to_string(), "callback".to_string(), "callbackUrl".to_string(),
        ];

        for param in common_params {
            let (vulns, tests) = self.scan_parameter(url, &param, config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // If we found a vulnerability, we can stop testing
            if !all_vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((all_vulnerabilities, total_tests))
    }

    /// Analyze redirect Location header
    fn analyze_redirect(
        &self,
        location: &str,
        payload: &str,
        redirect_type: &str,
        url: &str,
        param_name: &str,
        status: u16,
    ) -> Option<Vulnerability> {
        // Only consider 3xx redirect statuses
        if !(300..400).contains(&status) {
            return None;
        }

        // Check for redirects to known test domains
        let test_domains = vec!["evil.com".to_string(), "google.com".to_string(), "example.com".to_string()];
        for domain in &test_domains {
            if location.contains(domain) {
                let desc = if !redirect_type.is_empty() {
                    format!("{} redirect to external domain: {}", redirect_type, domain)
                } else {
                    format!("Open redirect to external domain: {}", domain)
                };
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    &desc,
                    &format!("Redirect Location: {}", location),
                    Confidence::High,
                ));
            }
        }

        // Check for dangerous URL schemes
        let dangerous_schemes = vec![
            "javascript:",
            "data:",
            "vbscript:",
            "file:",
            "about:",
            "blob:",
        ];

        let location_lower = location.to_lowercase();
        for scheme in &dangerous_schemes {
            if location_lower.starts_with(scheme) {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    &format!("Dangerous protocol redirect: {}", scheme),
                    &format!("Redirect Location: {}", location),
                    Confidence::High,
                ));
            }
        }

        // Check for protocol-relative URLs
        if location.starts_with("//") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Protocol-relative URL redirect",
                &format!("Redirect Location: {}", location),
                Confidence::High,
            ));
        }

        // Check if payload is reflected in location header
        let payload_clean = payload
            .replace("https://", "")
            .replace("http://", "")
            .replace("//", "");

        if !payload_clean.is_empty() && location.contains(&payload_clean) {
            // Check if this is a safe internal redirect (starts with / but not //)
            if location.starts_with('/') && !location.starts_with("//") {
                // Safe internal redirect - not a vulnerability
                return None;
            }

            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Payload reflected in redirect location",
                &format!("Redirect Location: {}", location),
                Confidence::Medium,
            ));
        }

        None
    }

    /// Analyze meta refresh redirects
    fn analyze_meta_redirect(
        &self,
        body: &str,
        payload: &str,
        _description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // Look for meta refresh tags with payload
        if body.contains(payload) || body.contains(urlencoding::encode(payload).as_ref()) {
            // Check if it's in a meta refresh context
            if let Ok(regex) = regex::Regex::new(r#"<meta[^>]*http-equiv=["']refresh["'][^>]*>"#) {
                if let Some(meta_tag) = regex.find(body) {
                    let tag = meta_tag.as_str();
                    if tag.contains(payload) || tag.contains(urlencoding::encode(payload).as_ref()) {
                        return Some(self.create_vulnerability(
                            url,
                            param_name,
                            payload,
                            "Open redirect via meta refresh tag",
                            "Payload found in meta refresh redirect",
                            Confidence::Medium,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Check if response contains dangerous redirect
    fn contains_dangerous_redirect(&self, body: &str, payload: &str) -> bool {
        // Check if payload appears in JavaScript redirect context
        let redirect_patterns = vec![
            format!("window.location = '{}'", payload),
            format!("window.location = \"{}\"", payload),
            format!("location.href = '{}'", payload),
            format!("location.href = \"{}\"", payload),
            format!("window.location.href = '{}'", payload),
            format!("window.location.href = \"{}\"", payload),
        ];

        for pattern in &redirect_patterns {
            if body.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        confidence: Confidence,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("open_redirect_{}", uuid::Uuid::new_v4()),
            vuln_type: "Open Redirect".to_string(),
            severity: Severity::Medium,
            confidence,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Open redirect vulnerability in parameter '{}': {}",
                param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-601".to_string(),
            cvss: 6.1,
            verified,
            false_positive: false,
            remediation: "1. Validate redirect URLs against an allowlist of trusted domains\n\
                         2. Use relative URLs instead of absolute URLs when possible\n\
                         3. Never redirect to user-controlled URLs directly\n\
                         4. Implement proper URL parsing and validation\n\
                         5. Use indirect references (e.g., ID mapping) instead of direct URLs\n\
                         6. Warn users when redirecting to external sites\n\
                         7. Implement CSRF tokens for redirect operations".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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

    fn create_test_scanner() -> OpenRedirectScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        OpenRedirectScanner::new(http_client)
    }

    #[test]
    fn test_analyze_redirect_external_domain() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_redirect(
            "https://evil.com",
            "https://evil.com",
            "External redirect",
            "http://example.com",
            "redirect",
            302,
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "Open Redirect");
        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.cwe, "CWE-601");
    }

    #[test]
    fn test_analyze_redirect_javascript_protocol() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_redirect(
            "javascript:alert(1)",
            "javascript:alert(1)",
            "JavaScript protocol",
            "http://example.com",
            "url",
            302,
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("Dangerous protocol"));
    }

    #[test]
    fn test_analyze_redirect_protocol_relative() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_redirect(
            "//evil.com",
            "//evil.com",
            "Protocol-relative",
            "http://example.com",
            "next",
            301,
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("Protocol-relative"));
    }

    #[test]
    fn test_analyze_redirect_safe_internal() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_redirect(
            "/internal/page",
            "/internal/page",
            "Internal redirect",
            "http://example.com",
            "next",
            302,
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_redirect_non_redirect_status() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_redirect(
            "https://evil.com",
            "https://evil.com",
            "External redirect",
            "http://example.com",
            "redirect",
            200, // Not a redirect status
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_contains_dangerous_redirect() {
        let scanner = create_test_scanner();

        let body1 = "window.location = 'https://evil.com'";
        assert!(scanner.contains_dangerous_redirect(body1, "https://evil.com"));

        let body2 = "location.href = \"https://evil.com\"";
        assert!(scanner.contains_dangerous_redirect(body2, "https://evil.com"));

        let body3 = "window.location.href = 'https://evil.com'";
        assert!(scanner.contains_dangerous_redirect(body3, "https://evil.com"));

        let body4 = "console.log('test')";
        assert!(!scanner.contains_dangerous_redirect(body4, "https://evil.com"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/redirect",
            "url",
            "https://evil.com",
            "Open redirect to external domain",
            "Redirect Location: https://evil.com",
            Confidence::High,
        );

        assert_eq!(vuln.vuln_type, "Open Redirect");
        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.parameter, Some("url".to_string()));
        assert_eq!(vuln.cwe, "CWE-601");
        assert_eq!(vuln.cvss, 6.1);
        assert!(vuln.verified);
        assert!(vuln.remediation.contains("allowlist"));
    }
}
