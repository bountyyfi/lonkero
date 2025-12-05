// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - XPath Injection Scanner
 * Detects XPath injection vulnerabilities
 *
 * Detects:
 * - Boolean-based blind XPath injection
 * - Error-based XPath injection
 * - XPath string manipulation
 * - XPath function abuse
 * - Authentication bypass via XPath
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct XPathInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl XPathInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for XPath injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing XPath injection vulnerabilities");

        // Test boolean-based XPath injection
        let (vulns, tests) = self.test_boolean_xpath(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test error-based XPath injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_error_xpath(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test authentication bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_auth_bypass_xpath(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test boolean-based XPath injection
    async fn test_boolean_xpath(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Testing boolean-based XPath injection");

        // Boolean payloads with true/false conditions
        let true_payloads = vec![
            "' or '1'='1",
            "' or 1=1 or ''='",
            "1' or '1'='1",
        ];

        let false_payloads = vec![
            "' or '1'='2",
            "' or 1=2 or ''='",
            "1' or '1'='2",
        ];

        // Test true condition
        let mut true_body = String::new();
        let mut true_status = 0;

        for payload in &true_payloads {
            let test_url = if url.contains('?') {
                format!("{}&q={}", url, urlencoding::encode(payload))
            } else {
                format!("{}?q={}", url, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    true_body = response.body.clone();
                    true_status = response.status_code;
                    break;
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        // Test false condition
        let mut false_body = String::new();
        let mut false_status = 0;

        for payload in &false_payloads {
            let test_url = if url.contains('?') {
                format!("{}&q={}", url, urlencoding::encode(payload))
            } else {
                format!("{}?q={}", url, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    false_body = response.body.clone();
                    false_status = response.status_code;
                    break;
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        // Compare responses
        if !true_body.is_empty() && !false_body.is_empty() {
            if true_body != false_body || true_status != false_status {
                info!("Boolean-based XPath injection detected");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Boolean-based XPath Injection",
                    "' or '1'='1",
                    "XPath query can be manipulated using boolean conditions",
                    "Different responses for true/false XPath conditions",
                    Severity::Critical,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test error-based XPath injection
    async fn test_error_xpath(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing error-based XPath injection");

        let error_payloads = vec![
            "'",
            "\"",
            "']",
            "')",
            "' and count(//*)>0 and '1'='1",
        ];

        for payload in error_payloads {
            let test_url = if url.contains('?') {
                format!("{}&q={}", url, urlencoding::encode(payload))
            } else {
                format!("{}?q={}", url, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_xpath_error(&response.body) {
                        info!("Error-based XPath injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Error-based XPath Injection",
                            payload,
                            "XPath errors reveal injection vulnerability",
                            "XPath syntax error detected in response",
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

    /// Test authentication bypass via XPath
    async fn test_auth_bypass_xpath(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Testing XPath authentication bypass");

        let bypass_payloads = vec![
            "admin' or '1'='1",
            "' or 1=1 or ''='",
            "admin'--",
            "' or count(//user)>0 or ''='",
        ];

        for payload in bypass_payloads {
            // Test as GET parameter
            let test_url = if url.contains('?') {
                format!("{}&username={}&password=test", url, urlencoding::encode(payload))
            } else {
                format!("{}?username={}&password=test", url, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_auth_bypass(&response.body, response.status_code) {
                        info!("XPath authentication bypass detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "XPath Authentication Bypass",
                            payload,
                            "Authentication can be bypassed using XPath injection",
                            "Successful authentication without valid credentials",
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

    /// Detect XPath errors in response
    fn detect_xpath_error(&self, body: &str) -> bool {
        let error_indicators = vec![
            "xpath",
            "xpatherror",
            "xpath syntax",
            "xpath expression",
            "xmlxpatheval",
            "xpathcontext",
            "domxpath",
            "invalid xpath",
            "xpath query error",
            "malformed xpath",
            "xpath compilation",
        ];

        let body_lower = body.to_lowercase();
        for indicator in error_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect successful authentication bypass
    fn detect_auth_bypass(&self, body: &str, status_code: u16) -> bool {
        let body_lower = body.to_lowercase();

        // Check for successful login indicators
        let success_indicators = vec![
            "welcome",
            "dashboard",
            "logged in",
            "authentication successful",
            "login successful",
            "profile",
            "admin panel",
        ];

        for indicator in success_indicators {
            if body_lower.contains(indicator) && status_code == 200 {
                return true;
            }
        }

        // Check for redirect (302) which might indicate successful login
        if status_code == 302 || status_code == 301 {
            return true;
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.6,
            Severity::Medium => 6.1,
            _ => 4.3,
        };

        Vulnerability {
            id: format!("xpath_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("XPath Injection ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("q".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-643".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Use parameterized XPath queries instead of string concatenation\n\
                         2. Validate and sanitize all user input before XPath processing\n\
                         3. Use precompiled XPath expressions with variable bindings\n\
                         4. Implement input allowlists for acceptable characters\n\
                         5. Escape XPath special characters: ' \" [ ] ( ) * / @\n\
                         6. Use XML databases with prepared statements when possible\n\
                         7. Implement least privilege for XML data access\n\
                         8. Avoid XPath for authentication - use secure alternatives\n\
                         9. Implement proper error handling without revealing XPath structure\n\
                         10. Consider using alternative query methods (e.g., DOM navigation)".to_string(),
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

    fn create_test_scanner() -> XPathInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        XPathInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_xpath_error() {
        let scanner = create_test_scanner();

        let errors = vec![
            "XPath syntax error at position 5",
            "Invalid XPath expression",
            "XPathEvalError: malformed query",
            "DOMXPath::query() error",
        ];

        for error in errors {
            assert!(scanner.detect_xpath_error(error));
        }
    }

    #[test]
    fn test_detect_auth_bypass() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_auth_bypass("Welcome to dashboard", 200));
        assert!(scanner.detect_auth_bypass("Login successful", 200));
        assert!(scanner.detect_auth_bypass("Redirect", 302));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_xpath_error("Normal response"));
        assert!(!scanner.detect_auth_bypass("Login failed", 401));
        assert!(!scanner.detect_auth_bypass("Invalid credentials", 200));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "Boolean-based XPath Injection",
            "' or '1'='1",
            "XPath injection detected",
            "Test evidence",
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "XPath Injection (Boolean-based XPath Injection)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-643");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }
}
