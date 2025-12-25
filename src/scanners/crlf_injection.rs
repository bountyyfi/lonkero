// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CRLF Injection Scanner
 * Tests for HTTP response splitting and CRLF injection vulnerabilities
 *
 * Detects:
 * - HTTP header injection via CRLF (\r\n)
 * - HTTP response splitting
 * - Cookie injection via CRLF
 * - Location header injection
 * - Arbitrary header injection
 * - XSS via injected headers
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct CrlfInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl CrlfInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for CRLF injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!("[CRLF] Skipping framework/internal parameter: {}", param_name);
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[CRLF] Testing CRLF injection on parameter: {} (priority: {})",
              param_name,
              ParameterFilter::get_parameter_priority(param_name));

        // Test various CRLF injection payloads
        let payloads = vec![
            // Cookie injection
            ("%0d%0aSet-Cookie:%20admin=true", "Cookie injection (URL encoded)"),
            ("\r\nSet-Cookie: admin=true", "Cookie injection (literal CRLF)"),
            ("%0d%0aSet-Cookie:%20session=hijacked", "Session cookie injection"),
            ("\r\n\r\nSet-Cookie: token=stolen", "Double CRLF cookie injection"),

            // Location header injection
            ("%0d%0aLocation:%20https://evil.com", "Location header injection"),
            ("\r\nLocation: https://evil.com", "Location redirect injection"),

            // Arbitrary header injection
            ("%0d%0aX-Custom-Header:%20injected", "Custom header injection"),
            ("\r\nX-Injected: true", "Header injection (literal)"),

            // HTTP response splitting
            ("%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a", "HTTP response splitting (encoded)"),
            ("\r\n\r\nHTTP/1.1 200 OK\r\n", "HTTP response splitting (literal)"),
            ("%0d%0a%0d%0a<script>alert(1)</script>", "Response splitting with XSS"),

            // Content-Type injection
            ("%0d%0aContent-Type:%20text/html", "Content-Type header injection"),
            ("\r\nContent-Type: text/html\r\n\r\n<html><script>alert(1)</script></html>", "Content-Type with XSS"),

            // Multiple header injection
            ("%0d%0aX-Header1:%20value1%0d%0aX-Header2:%20value2", "Multiple headers"),

            // Unicode/alternative encodings
            ("%E5%98%8A%E5%98%8DSet-Cookie:%20admin=true", "Unicode CRLF"),
            ("%E5%98%8D%E5%98%8ASet-Cookie:%20admin=true", "Alternative Unicode"),

            // Null byte variants
            ("%00%0d%0aSet-Cookie:%20admin=true", "Null byte + CRLF"),
        ];

        for (payload, description) in payloads {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, payload)
            } else {
                format!("{}?{}={}", url, param_name, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let headers_vec: Vec<(String, String)> = response.headers.iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if let Some(vuln) = self.analyze_response(
                        &headers_vec,
                        &response.body,
                        payload,
                        description,
                        &test_url,
                        param_name,
                    ) {
                        info!("CRLF injection vulnerability detected: {}", description);
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, move to next parameter
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for CRLF injection (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Only test parameters discovered from actual forms/URLs - no spray-and-pray
        // The main scanner will call scan_parameter() with discovered params
        Ok((Vec::new(), 0))
    }

    /// Analyze response for CRLF injection indicators
    fn analyze_response(
        &self,
        headers: &[(String, String)],
        body: &str,
        payload: &str,
        _description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // Check for injected Set-Cookie header
        if payload.contains("Set-Cookie") {
            for (key, value) in headers {
                if key.to_lowercase() == "set-cookie" {
                    // Check for injected cookie values
                    if value.contains("admin=true")
                        || value.contains("session=hijacked")
                        || value.contains("token=stolen")
                    {
                        return Some(self.create_vulnerability(
                            url,
                            param_name,
                            payload,
                            "CRLF injection - Cookie injection",
                            &format!("Injected cookie detected: {}", value),
                            Confidence::High,
                        ));
                    }
                }
            }
        }

        // Check for injected Location header
        if payload.contains("Location") {
            for (key, value) in headers {
                if key.to_lowercase() == "location" {
                    if value.contains("evil.com") || value.contains("attacker") {
                        return Some(self.create_vulnerability(
                            url,
                            param_name,
                            payload,
                            "CRLF injection - Location header injection",
                            &format!("Injected Location header: {}", value),
                            Confidence::High,
                        ));
                    }
                }
            }
        }

        // Check for injected custom headers
        let injected_header_names = vec![
            "x-custom-header",
            "x-injected",
            "x-header1",
            "x-header2",
        ];

        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            for injected_name in &injected_header_names {
                if key_lower == *injected_name {
                    return Some(self.create_vulnerability(
                        url,
                        param_name,
                        payload,
                        "CRLF injection - Arbitrary header injection",
                        &format!("Injected header detected: {}: {}", key, value),
                        Confidence::High,
                    ));
                }
            }
        }

        // Check for HTTP response splitting in body
        if payload.contains("HTTP/1.1") && body.contains("HTTP/1.1 200 OK") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "CRLF injection - HTTP response splitting",
                "Multiple HTTP responses detected - response splitting successful",
                Confidence::Medium,
            ));
        }

        // Check for CRLF characters reflected in headers
        let headers_string = format!("{:?}", headers);
        if headers_string.contains("\\r\\n")
            || headers_string.contains("%0d%0a")
            || headers_string.contains("\r\n")
        {
            // Check if it's actually from our payload
            if payload.contains("%0d%0a") || payload.contains("\r\n") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "CRLF injection - CRLF characters in headers",
                    "CRLF characters detected in response headers",
                    Confidence::Medium,
                ));
            }
        }

        // Check for XSS via CRLF injection
        if payload.contains("<script>") && body.contains("<script>") {
            if body.contains("alert(1)") || body.contains("alert(") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "CRLF injection with XSS",
                    "CRLF injection allows script injection in response",
                    Confidence::High,
                ));
            }
        }

        None
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
            id: format!("crlf_injection_{}", uuid::Uuid::new_v4()),
            vuln_type: "CRLF Injection".to_string(),
            severity: Severity::High,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "CRLF injection vulnerability in parameter '{}': {}",
                param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-93".to_string(),
            cvss: 7.5,
            verified,
            false_positive: false,
            remediation: "1. Sanitize CRLF characters (\\r\\n, %0d%0a, %0a, %0d) from user input\n\
                         2. Validate and encode all user input before including in HTTP headers\n\
                         3. Use framework-provided header setting functions\n\
                         4. Implement proper input validation and output encoding\n\
                         5. Reject requests containing CRLF sequences\n\
                         6. Use allowlists for redirect URLs\n\
                         7. Set proper Content-Type and X-Content-Type-Options headers".to_string(),
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

    fn create_test_scanner() -> CrlfInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        CrlfInjectionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_cookie_injection() {
        let scanner = create_test_scanner();

        let headers = vec![
            ("Set-Cookie".to_string(), "admin=true".to_string()),
        ];
        let body = "";

        let result = scanner.analyze_response(
            &headers,
            body,
            "%0d%0aSet-Cookie:%20admin=true",
            "Cookie injection",
            "http://example.com",
            "redirect",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "CRLF Injection");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-93");
        assert!(vuln.description.contains("Cookie injection"));
    }

    #[test]
    fn test_analyze_location_injection() {
        let scanner = create_test_scanner();

        let headers = vec![
            ("Location".to_string(), "https://evil.com".to_string()),
        ];
        let body = "";

        let result = scanner.analyze_response(
            &headers,
            body,
            "%0d%0aLocation:%20https://evil.com",
            "Location injection",
            "http://example.com",
            "next",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("Location header injection"));
    }

    #[test]
    fn test_analyze_custom_header_injection() {
        let scanner = create_test_scanner();

        let headers = vec![
            ("X-Custom-Header".to_string(), "injected".to_string()),
        ];
        let body = "";

        let result = scanner.analyze_response(
            &headers,
            body,
            "%0d%0aX-Custom-Header:%20injected",
            "Header injection",
            "http://example.com",
            "url",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("Arbitrary header injection"));
    }

    #[test]
    fn test_analyze_response_splitting() {
        let scanner = create_test_scanner();

        let headers = vec![];
        let body = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Injected</html>";

        let result = scanner.analyze_response(
            &headers,
            body,
            "%0d%0a%0d%0aHTTP/1.1%20200%20OK",
            "Response splitting",
            "http://example.com",
            "page",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("HTTP response splitting"));
    }

    #[test]
    fn test_analyze_crlf_with_xss() {
        let scanner = create_test_scanner();

        let headers = vec![];
        let body = "<script>alert(1)</script>";

        let result = scanner.analyze_response(
            &headers,
            body,
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "CRLF with XSS",
            "http://example.com",
            "dest",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("XSS"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        let body = "<html><body>Normal page</body></html>";

        let result = scanner.analyze_response(
            &headers,
            body,
            "normal_value",
            "Normal request",
            "http://example.com",
            "param",
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/redirect",
            "url",
            "%0d%0aSet-Cookie:%20admin=true",
            "CRLF injection - Cookie injection",
            "Injected cookie: admin=true",
            Confidence::High,
        );

        assert_eq!(vuln.vuln_type, "CRLF Injection");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.parameter, Some("url".to_string()));
        assert_eq!(vuln.cwe, "CWE-93");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.verified);
        assert!(vuln.remediation.contains("CRLF characters"));
    }
}
