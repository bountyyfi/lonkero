// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for CORS (Cross-Origin Resource Sharing) misconfiguration vulnerabilities
pub struct CorsMisconfigurationScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl CorsMisconfigurationScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("cors-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run CORS misconfiguration scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting CORS misconfiguration scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test arbitrary origin reflection
        let (vulns, tests) = self.test_arbitrary_origin(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test null origin
        let (vulns, tests) = self.test_null_origin(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test wildcard with credentials
        let (vulns, tests) = self.test_wildcard_credentials(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test subdomain reflection
        let (vulns, tests) = self.test_subdomain_reflection(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test insecure origins
        let (vulns, tests) = self.test_insecure_origins(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "CORS misconfiguration scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test arbitrary origin reflection
    async fn test_arbitrary_origin(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing CORS arbitrary origin reflection");

        // Test arbitrary origins
        let test_origins = vec![
            format!("https://evil-{}.com", self.test_marker),
            "https://attacker.com".to_string(),
        ];

        for origin in test_origins {
            let headers = vec![("Origin".to_string(), origin.clone())];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if self.detect_arbitrary_origin_reflected(&response.headers, &origin) {
                        vulnerabilities.push(self.create_vulnerability(
                            "CORS Arbitrary Origin Reflection",
                            url,
                            &format!("Server reflects arbitrary origin '{}' in Access-Control-Allow-Origin header with credentials", origin),
                            Severity::High,
                            "CWE-346",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Arbitrary origin test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test null origin acceptance
    async fn test_null_origin(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing CORS null origin acceptance");

        let headers = vec![("Origin".to_string(), "null".to_string())];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if self.detect_null_origin_allowed(&response.headers) {
                    vulnerabilities.push(self.create_vulnerability(
                        "CORS Null Origin Allowed",
                        url,
                        "Server allows 'null' origin with credentials, enabling CORS bypass via sandboxed iframe",
                        Severity::High,
                        "CWE-346",
                    ));
                }
            }
            Err(e) => {
                info!("Null origin test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test wildcard origin with credentials
    async fn test_wildcard_credentials(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing CORS wildcard with credentials");

        let headers = vec![("Origin".to_string(), "https://example.com".to_string())];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if self.detect_wildcard_with_credentials(&response.headers) {
                    vulnerabilities.push(self.create_vulnerability(
                        "CORS Wildcard with Credentials",
                        url,
                        "Server uses wildcard '*' in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true",
                        Severity::High,
                        "CWE-346",
                    ));
                }
            }
            Err(e) => {
                info!("Wildcard credentials test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test subdomain reflection vulnerability
    async fn test_subdomain_reflection(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing CORS subdomain reflection");

        // Extract domain from URL
        if let Ok(parsed_url) = url::Url::parse(url) {
            if let Some(host) = parsed_url.host_str() {
                // Test subdomain variations
                let test_origins = vec![
                    format!("https://evil.{}", host),
                    format!("https://{}.evil.com", host),
                ];

                for origin in test_origins {
                    let headers = vec![("Origin".to_string(), origin.clone())];

                    match self.http_client.get_with_headers(url, headers).await {
                        Ok(response) => {
                            if self.detect_arbitrary_origin_reflected(&response.headers, &origin) {
                                vulnerabilities.push(self.create_vulnerability(
                                    "CORS Subdomain Reflection",
                                    url,
                                    &format!("Server reflects subdomain origin '{}' without proper validation", origin),
                                    Severity::Medium,
                                    "CWE-346",
                                ));
                                break;
                            }
                        }
                        Err(e) => {
                            info!("Subdomain reflection test failed: {}", e);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test insecure HTTP origins
    async fn test_insecure_origins(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing CORS insecure HTTP origins");

        // Test HTTP origin (insecure)
        let insecure_origin = "http://attacker.com".to_string();
        let headers = vec![("Origin".to_string(), insecure_origin.clone())];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if self.detect_arbitrary_origin_reflected(&response.headers, &insecure_origin) {
                    vulnerabilities.push(self.create_vulnerability(
                        "CORS Insecure HTTP Origin Allowed",
                        url,
                        "Server allows insecure HTTP origins, enabling man-in-the-middle attacks",
                        Severity::Medium,
                        "CWE-346",
                    ));
                }
            }
            Err(e) => {
                info!("Insecure origin test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect arbitrary origin reflection
    fn detect_arbitrary_origin_reflected(
        &self,
        headers: &std::collections::HashMap<String, String>,
        origin: &str,
    ) -> bool {
        for (key, value) in headers {
            let key_lower = key.to_lowercase();

            // Check if Access-Control-Allow-Origin reflects our origin
            if key_lower == "access-control-allow-origin" {
                if value == origin || value == "*" {
                    // Check if credentials are also allowed (critical)
                    for (cred_key, cred_value) in headers {
                        if cred_key.to_lowercase() == "access-control-allow-credentials"
                            && cred_value.to_lowercase() == "true"
                        {
                            return true;
                        }
                    }
                    // Even without credentials, arbitrary origin is a concern
                    if value == origin {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Detect null origin allowed
    fn detect_null_origin_allowed(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        let mut null_origin_allowed = false;
        let mut credentials_allowed = false;

        for (key, value) in headers {
            let key_lower = key.to_lowercase();

            if key_lower == "access-control-allow-origin" && value == "null" {
                null_origin_allowed = true;
            }

            if key_lower == "access-control-allow-credentials" && value.to_lowercase() == "true" {
                credentials_allowed = true;
            }
        }

        null_origin_allowed && credentials_allowed
    }

    /// Detect wildcard with credentials (actually invalid but some servers try)
    fn detect_wildcard_with_credentials(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        let mut wildcard_origin = false;
        let mut credentials_allowed = false;

        for (key, value) in headers {
            let key_lower = key.to_lowercase();

            if key_lower == "access-control-allow-origin" && value == "*" {
                wildcard_origin = true;
            }

            if key_lower == "access-control-allow-credentials" && value.to_lowercase() == "true" {
                credentials_allowed = true;
            }
        }

        wildcard_origin && credentials_allowed
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("cors_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Configuration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "CORS Arbitrary Origin Reflection" => {
                "Don't reflect arbitrary origins in Access-Control-Allow-Origin. Use a strict allow-list of trusted origins. Validate origins against the allow-list server-side. Never use Access-Control-Allow-Credentials: true with dynamic origins without proper validation.".to_string()
            }
            "CORS Null Origin Allowed" => {
                "Never allow 'null' origin in Access-Control-Allow-Origin, especially with credentials. The null origin can be triggered by sandboxed iframes and enables CORS bypass attacks. Use a strict allow-list of HTTPS origins.".to_string()
            }
            "CORS Wildcard with Credentials" => {
                "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This combination is actually invalid per spec but some browsers may honor it. Use specific trusted origins instead of wildcard when credentials are needed.".to_string()
            }
            "CORS Subdomain Reflection" => {
                "Validate origins against a strict allow-list. Don't use regex patterns that can match attacker-controlled subdomains. Each allowed origin should be explicitly listed. Be careful with subdomain wildcards.".to_string()
            }
            "CORS Insecure HTTP Origin Allowed" => {
                "Only allow HTTPS origins in production. HTTP origins are vulnerable to man-in-the-middle attacks. Implement strict HTTPS-only policy for CORS. Use HSTS to prevent protocol downgrade attacks.".to_string()
            }
            _ => {
                "Implement secure CORS policy: use strict allow-list of trusted HTTPS origins, never allow null origin with credentials, validate origins server-side, don't use wildcard with credentials, and implement proper authentication/authorization.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;
    use std::collections::HashMap;

    fn create_test_scanner() -> CorsMisconfigurationScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        CorsMisconfigurationScanner::new(client)
    }

    #[test]
    fn test_detect_arbitrary_origin_reflected() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://evil.com".to_string(),
        );
        headers.insert(
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        );

        assert!(scanner.detect_arbitrary_origin_reflected(&headers, "https://evil.com"));

        // Without credentials
        let mut headers2 = HashMap::new();
        headers2.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://evil.com".to_string(),
        );

        assert!(scanner.detect_arbitrary_origin_reflected(&headers2, "https://evil.com"));
    }

    #[test]
    fn test_detect_null_origin_allowed() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "null".to_string(),
        );
        headers.insert(
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        );

        assert!(scanner.detect_null_origin_allowed(&headers));

        // Without credentials should not trigger
        let mut headers2 = HashMap::new();
        headers2.insert(
            "Access-Control-Allow-Origin".to_string(),
            "null".to_string(),
        );

        assert!(!scanner.detect_null_origin_allowed(&headers2));
    }

    #[test]
    fn test_detect_wildcard_with_credentials() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
        headers.insert(
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        );

        assert!(scanner.detect_wildcard_with_credentials(&headers));

        // Without credentials should not trigger
        let mut headers2 = HashMap::new();
        headers2.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());

        assert!(!scanner.detect_wildcard_with_credentials(&headers2));
    }

    #[test]
    fn test_test_marker_uniqueness() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("cors-"));
    }
}
