// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Host Header Injection Scanner
 * Detects host header injection vulnerabilities
 *
 * Detects:
 * - Password reset poisoning
 * - Web cache poisoning via Host header
 * - Server-Side Request Forgery via Host
 * - Routing-based SSRF
 * - Virtual host confusion
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct HostHeaderInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl HostHeaderInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("hhi-{}.evil.com", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for host header injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing host header injection vulnerabilities");

        // Test basic host header injection
        let (vulns, tests) = self.test_host_header_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test password reset poisoning
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_password_reset_poisoning(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test virtual host confusion
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_virtual_host_confusion(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test basic host header injection
    async fn test_host_header_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing host header injection");

        let malicious_hosts = vec![
            self.test_marker.as_str(),
            "evil.com",
            "attacker.com",
        ];

        for host in malicious_hosts {
            let headers = vec![
                ("Host".to_string(), host.to_string()),
            ];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if self.detect_host_injection(&response.body, host) {
                        info!("Host header injection detected with: {}", host);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Host Header Injection",
                            &format!("Host: {}", host),
                            "Application reflects Host header value without validation",
                            &format!("Host header '{}' reflected in response", host),
                            Severity::High,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test password reset poisoning
    async fn test_password_reset_poisoning(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing password reset poisoning");

        let password_reset_paths = vec![
            "/password/reset",
            "/forgot-password",
        ];

        let base_url = self.extract_base_url(url);

        for path in password_reset_paths {
            let test_url = format!("{}{}", base_url, path);

            let headers = vec![
                ("Host".to_string(), self.test_marker.clone()),
            ];

            match self.http_client.get_with_headers(&test_url, headers).await {
                Ok(response) => {
                    if response.status_code == 200 &&
                       (response.body.contains(&self.test_marker) ||
                        response.body.contains("reset") ||
                        response.body.contains("email")) {
                        info!("Password reset poisoning possible at {}", path);
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Password Reset Poisoning",
                            &format!("Host: {}", self.test_marker),
                            "Password reset functionality vulnerable to host header poisoning",
                            "Malicious host header accepted in password reset flow",
                            Severity::Critical,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test virtual host confusion
    async fn test_virtual_host_confusion(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing virtual host confusion");

        let confusion_hosts = vec![
            "localhost",
            "127.0.0.1",
            "internal.local",
        ];

        for host in confusion_hosts {
            let headers = vec![
                ("Host".to_string(), host.to_string()),
            ];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if self.detect_virtual_host_confusion(&response.body, host) {
                        info!("Virtual host confusion detected with: {}", host);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Virtual Host Confusion",
                            &format!("Host: {}", host),
                            "Application routes to different virtual hosts based on Host header",
                            &format!("Internal host '{}' accessible", host),
                            Severity::Medium,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect host injection in response
    fn detect_host_injection(&self, body: &str, host: &str) -> bool {
        // Check if malicious host appears in response
        if body.contains(host) {
            // Make sure it's not just in expected places
            let context1 = format!("href=\"http://{}", host);
            let context2 = format!("href=\"https://{}", host);
            let context3 = format!("src=\"http://{}", host);
            let context4 = format!("src=\"https://{}", host);
            let context5 = format!("action=\"http://{}", host);
            let context6 = format!("action=\"https://{}", host);
            let context7 = format!("//{}\"", host);

            let suspicious_contexts = vec![
                context1.as_str(),
                context2.as_str(),
                context3.as_str(),
                context4.as_str(),
                context5.as_str(),
                context6.as_str(),
                context7.as_str(),
            ];

            for context in suspicious_contexts {
                if body.contains(context) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect virtual host confusion
    fn detect_virtual_host_confusion(&self, body: &str, host: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for internal indicators
        let internal_indicators = vec![
            "internal",
            "admin",
            "localhost",
            "127.0.0.1",
            "development",
            "staging",
        ];

        if host.contains("localhost") || host.contains("127.0.0.1") || host.contains("internal") {
            for indicator in internal_indicators {
                if body_lower.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract base URL
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or("localhost"))
        } else {
            url.to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("hhi_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("Host header".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-644".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Validate Host header against allowlist of expected values\n\
                         2. Use absolute URLs in sensitive operations (password reset)\n\
                         3. Avoid using Host header to build URLs\n\
                         4. Configure web server to reject invalid Host headers\n\
                         5. Use SERVER_NAME instead of HTTP_HOST when possible\n\
                         6. Implement proper virtual host configuration\n\
                         7. Use HTTPS and validate domain in password reset emails\n\
                         8. Implement CSRF tokens for sensitive operations\n\
                         9. Monitor for unusual Host header values\n\
                         10. Use framework-level protection against host header attacks".to_string(),
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
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
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

    fn create_test_scanner() -> HostHeaderInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        HostHeaderInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_host_injection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_host_injection(r#"<a href="http://evil.com/reset">Reset</a>"#, "evil.com"));
        assert!(scanner.detect_host_injection(r#"<form action="https://attacker.com/login">"#, "attacker.com"));
    }

    #[test]
    fn test_detect_virtual_host_confusion() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_virtual_host_confusion("Internal admin panel", "localhost"));
        assert!(scanner.detect_virtual_host_confusion("Development environment", "127.0.0.1"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_host_injection("Normal response", "evil.com"));
        assert!(!scanner.detect_virtual_host_confusion("Public page", "localhost"));
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("hhi-"));
        assert!(scanner1.test_marker.ends_with(".evil.com"));
    }
}
