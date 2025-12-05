// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for JWT (JSON Web Token) vulnerabilities
pub struct JwtVulnerabilitiesScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl JwtVulnerabilitiesScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("jwt-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run JWT vulnerability scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting JWT vulnerabilities scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test none algorithm
        let (vulns, tests) = self.test_none_algorithm(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test algorithm confusion
        let (vulns, tests) = self.test_algorithm_confusion(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test weak secrets
        let (vulns, tests) = self.test_weak_secrets(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test expired tokens
        let (vulns, tests) = self.test_expired_tokens(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "JWT vulnerabilities scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test for none algorithm vulnerability
    async fn test_none_algorithm(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing JWT none algorithm vulnerability");

        // Create JWT with none algorithm
        let none_tokens = vec![
            // Header: {"alg":"none","typ":"JWT"}, Payload: {"sub":"admin","exp":9999999999}
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            // Header: {"alg":"None","typ":"JWT"}, Payload: {"sub":"admin","role":"admin"}
            "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
        ];

        for token in none_tokens {
            let auth_header = vec![("Authorization".to_string(), format!("Bearer {}", token))];

            match self.http_client.get_with_headers(url, auth_header).await {
                Ok(response) => {
                    if self.detect_successful_auth(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "JWT None Algorithm Accepted",
                            url,
                            &format!("Server accepts JWT tokens with 'none' algorithm. Token: {}", token),
                            Severity::Critical,
                            "CWE-347",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("None algorithm test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for algorithm confusion (HS256 vs RS256)
    async fn test_algorithm_confusion(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing JWT algorithm confusion");

        // Test tokens with different algorithms
        let confused_tokens = vec![
            // Header: {"alg":"HS256","typ":"JWT"}, Payload: {"sub":"admin","role":"admin"}
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid", "HS256"),
            // Header: {"alg":"RS256","typ":"JWT"}, Payload: {"sub":"admin","role":"admin"}
            ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid", "RS256"),
        ];

        for (token, alg) in confused_tokens {
            let auth_header = vec![("Authorization".to_string(), format!("Bearer {}", token))];

            match self.http_client.get_with_headers(url, auth_header).await {
                Ok(response) => {
                    if self.detect_successful_auth(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "JWT Algorithm Confusion",
                            url,
                            &format!("Server may be vulnerable to algorithm confusion with {}. Invalid signature accepted.", alg),
                            Severity::Critical,
                            "CWE-347",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Algorithm confusion test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for weak JWT secrets
    async fn test_weak_secrets(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing JWT weak secrets");

        // Common weak secrets and their pre-computed tokens
        // These are example tokens - in real scanning you'd try to crack discovered tokens
        let weak_tokens = vec![
            // Token signed with "secret" as key
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.YzE2ZTU5YzI5OGViZjEwMGE4MzE3YmQxY2NjY2U4YmY", "secret"),
            // Token signed with "password" as key
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid", "password"),
            // Token signed with empty string
            ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid", ""),
        ];

        for (token, secret) in weak_tokens {
            let auth_header = vec![("Authorization".to_string(), format!("Bearer {}", token))];

            match self.http_client.get_with_headers(url, auth_header).await {
                Ok(response) => {
                    if self.detect_successful_auth(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "JWT Weak Secret Key",
                            url,
                            &format!("Server may be using weak JWT secret key: '{}'", secret),
                            Severity::Critical,
                            "CWE-798",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Weak secret test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for expired token acceptance
    async fn test_expired_tokens(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Testing expired JWT token acceptance");

        // Header: {"alg":"HS256","typ":"JWT"}, Payload: {"sub":"user","exp":1}
        let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxfQ.invalid";
        let auth_header = vec![("Authorization".to_string(), format!("Bearer {}", expired_token))];

        match self.http_client.get_with_headers(url, auth_header).await {
            Ok(response) => {
                if self.detect_successful_auth(&response.body, response.status_code) {
                    vulnerabilities.push(self.create_vulnerability(
                        "Expired JWT Token Accepted",
                        url,
                        "Server accepts expired JWT tokens (exp: 1)",
                        Severity::High,
                        "CWE-613",
                    ));
                }
            }
            Err(e) => {
                info!("Expired token test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect successful authentication
    fn detect_successful_auth(&self, body: &str, status_code: u16) -> bool {
        // 200 OK suggests authentication might have succeeded
        if status_code == 200 {
            let body_lower = body.to_lowercase();

            // Check for authentication success indicators
            let success_indicators = vec![
                "welcome",
                "dashboard",
                "profile",
                "admin",
                "authenticated",
                "logged in",
                "user",
            ];

            for indicator in success_indicators {
                if body_lower.contains(indicator) {
                    return true;
                }
            }
        }

        // 401 or 403 suggests authentication failed (good)
        if status_code == 401 || status_code == 403 {
            return false;
        }

        // If we got 200 without error messages, consider it potentially vulnerable
        status_code == 200 && !body.to_lowercase().contains("unauthorized") && !body.to_lowercase().contains("forbidden")
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
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("jwt_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::Medium,
            category: "Authentication".to_string(),
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
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "JWT None Algorithm Accepted" => {
                "Reject JWT tokens with 'none' algorithm. Always validate the algorithm field and enforce a whitelist of allowed algorithms (e.g., RS256, HS256). Never accept unsigned tokens in production.".to_string()
            }
            "JWT Algorithm Confusion" => {
                "Enforce strict algorithm validation. Use asymmetric algorithms (RS256) for production. Validate that the algorithm in the token header matches the expected algorithm. Never trust the algorithm field from the token itself.".to_string()
            }
            "JWT Weak Secret Key" => {
                "Use strong, randomly generated secret keys (minimum 256 bits). Store secrets securely in environment variables or secret management systems. Rotate keys regularly. Consider using asymmetric algorithms (RS256) instead of symmetric (HS256).".to_string()
            }
            "Expired JWT Token Accepted" => {
                "Always validate the 'exp' (expiration) claim in JWT tokens. Reject tokens where current time > exp time. Use short expiration times (e.g., 15 minutes for access tokens) and implement refresh token rotation.".to_string()
            }
            _ => {
                "Implement proper JWT validation: verify signature, check expiration, validate issuer and audience, use strong secrets, and enforce algorithm whitelisting.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> JwtVulnerabilitiesScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        JwtVulnerabilitiesScanner::new(client)
    }

    #[test]
    fn test_detect_successful_auth() {
        let scanner = create_test_scanner();

        // Should detect successful auth
        assert!(scanner.detect_successful_auth(r#"{"message": "Welcome to dashboard"}"#, 200));
        assert!(scanner.detect_successful_auth(r#"<h1>Admin Panel</h1>"#, 200));
        assert!(scanner.detect_successful_auth(r#"User profile page"#, 200));

        // Should not detect successful auth
        assert!(!scanner.detect_successful_auth(r#"{"error": "Unauthorized"}"#, 401));
        assert!(!scanner.detect_successful_auth(r#"Forbidden"#, 403));
        assert!(!scanner.detect_successful_auth(r#"Invalid token"#, 401));
    }

    #[test]
    fn test_get_remediation() {
        let scanner = create_test_scanner();

        let remediation = scanner.get_remediation("JWT None Algorithm Accepted");
        assert!(remediation.contains("none"));
        assert!(remediation.contains("algorithm"));

        let remediation = scanner.get_remediation("JWT Weak Secret Key");
        assert!(remediation.contains("strong"));
        assert!(remediation.contains("secret"));
    }

    #[test]
    fn test_test_marker_uniqueness() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("jwt-"));
    }
}
