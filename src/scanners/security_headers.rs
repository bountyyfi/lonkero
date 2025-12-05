// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Security Headers Scanner
 * Tests for missing or misconfigured HTTP security headers
 *
 * @copyright 2025 Bountyy Oy
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
                // Check each security header
                self.check_hsts(&response, url, &mut vulnerabilities);
                self.check_csp(&response, url, &mut vulnerabilities);
                self.check_x_frame_options(&response, url, &mut vulnerabilities);
                self.check_x_content_type_options(&response, url, &mut vulnerabilities);
                self.check_x_xss_protection(&response, url, &mut vulnerabilities);
                self.check_referrer_policy(&response, url, &mut vulnerabilities);
                self.check_permissions_policy(&response, url, &mut vulnerabilities);
                self.check_cors_headers(&response, url, &mut vulnerabilities);
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

    /// Check HSTS (HTTP Strict Transport Security)
    fn check_hsts(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
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

            // Check for includeSubDomains
            if !hsts.contains("includeSubDomains") {
                vulnerabilities.push(self.create_vulnerability(
                    "HSTS Missing includeSubDomains",
                    url,
                    Severity::Low,
                    Confidence::High,
                    "HSTS configured without includeSubDomains directive",
                    "Subdomains are not protected by HSTS".to_string(),
                    3.0,
                ));
            }
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
    fn check_csp(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
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
    fn check_x_frame_options(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        let xfo = response.header("x-frame-options");
        let frame_ancestors = response.header("content-security-policy")
            .map(|csp| csp.contains("frame-ancestors"))
            .unwrap_or(false);

        if xfo.is_none() && !frame_ancestors {
            vulnerabilities.push(self.create_vulnerability(
                "Missing Clickjacking Protection",
                url,
                Severity::Medium,
                Confidence::High,
                "X-Frame-Options header is missing and CSP frame-ancestors not set",
                "Application vulnerable to clickjacking attacks".to_string(),
                4.3,
            ));
        } else if let Some(xfo_value) = xfo {
            if xfo_value.to_lowercase() == "allow" {
                vulnerabilities.push(self.create_vulnerability(
                    "Permissive X-Frame-Options",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "X-Frame-Options set to ALLOW - allows framing from any origin",
                    format!("X-Frame-Options: {}", xfo_value),
                    4.3,
                ));
            }
        }
    }

    /// Check X-Content-Type-Options
    fn check_x_content_type_options(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
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
    fn check_x_xss_protection(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
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
    fn check_referrer_policy(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        if let Some(referrer) = response.header("referrer-policy") {
            if referrer.contains("unsafe-url") || referrer == "no-referrer-when-downgrade" {
                vulnerabilities.push(self.create_vulnerability(
                    "Weak Referrer Policy",
                    url,
                    Severity::Low,
                    Confidence::High,
                    "Referrer-Policy may leak sensitive information in URLs",
                    format!("Referrer-Policy: {}", referrer),
                    3.1,
                ));
            }
        } else {
            vulnerabilities.push(self.create_vulnerability(
                "Missing Referrer-Policy",
                url,
                Severity::Low,
                Confidence::Medium,
                "Referrer-Policy header is missing",
                "Referrer information may be leaked to third parties".to_string(),
                3.0,
            ));
        }
    }

    /// Check Permissions-Policy (formerly Feature-Policy)
    fn check_permissions_policy(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        let has_permissions_policy = response.header("permissions-policy").is_some();
        let has_feature_policy = response.header("feature-policy").is_some();

        if !has_permissions_policy && !has_feature_policy {
            vulnerabilities.push(self.create_vulnerability(
                "Missing Permissions-Policy",
                url,
                Severity::Info,
                Confidence::Medium,
                "Permissions-Policy header is missing",
                "Consider restricting browser features (camera, microphone, geolocation, etc.)".to_string(),
                2.0,
            ));
        }
    }

    /// Check CORS headers for misconfigurations
    fn check_cors_headers(&self, response: &HttpResponse, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            // Check for wildcard with credentials
            if acao == "*" {
                if let Some(credentials) = response.header("access-control-allow-credentials") {
                    if credentials == "true" {
                        vulnerabilities.push(self.create_vulnerability(
                            "Insecure CORS Configuration",
                            url,
                            Severity::High,
                            Confidence::High,
                            "CORS allows all origins (*) with credentials enabled",
                            "This configuration allows any origin to make authenticated requests".to_string(),
                            6.5,
                        ));
                    }
                }
            }

            // Check for null origin
            if acao == "null" {
                vulnerabilities.push(self.create_vulnerability(
                    "CORS Allows Null Origin",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "CORS Access-Control-Allow-Origin set to 'null'",
                    "Null origin can be exploited via sandboxed iframes".to_string(),
                    5.3,
                ));
            }
        }
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
            remediation: format!(r#"Configure proper security headers:

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
"#, title),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
    fn test_missing_csp() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_csp(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing CSP");
    }

    #[test]
    fn test_weak_csp() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("content-security-policy".to_string(), "default-src 'self' 'unsafe-inline'".to_string());

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
    fn test_insecure_cors() {
        let scanner = SecurityHeadersScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        headers.insert("access-control-allow-credentials".to_string(), "true".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cors_headers(&response, "https://example.com", &mut vulns);

        assert!(vulns.len() > 0, "Should detect insecure CORS");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
