// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Mass Assignment Scanner
 * Detects mass assignment vulnerabilities
 *
 * Detects:
 * - Parameter pollution attacks
 * - Role/privilege escalation via mass assignment
 * - Hidden field manipulation
 * - Account property injection
 * - Price/amount manipulation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct MassAssignmentScanner {
    http_client: Arc<HttpClient>,
}

impl MassAssignmentScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for mass assignment vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing mass assignment vulnerabilities");

        // Test role/privilege escalation
        let (vulns, tests) = self.test_role_escalation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test price manipulation
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_price_manipulation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test hidden field injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_hidden_field_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test role/privilege escalation via mass assignment
    async fn test_role_escalation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Testing role escalation via mass assignment");

        let dangerous_params = vec![
            ("role", "admin"),
            ("role", "administrator"),
            ("is_admin", "true"),
            ("is_admin", "1"),
            ("admin", "true"),
            ("privilege", "admin"),
        ];

        for (param, value) in dangerous_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_privilege_escalation(&response.body, param, value) {
                        info!("Mass assignment privilege escalation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Privilege Escalation via Mass Assignment",
                            &format!("{}={}", param, value),
                            "User privileges can be escalated by adding parameters",
                            &format!("Successfully set {}={} via mass assignment", param, value),
                            Severity::Critical,
                            "CWE-915",
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

    /// Test price/amount manipulation
    async fn test_price_manipulation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing price manipulation via mass assignment");

        let price_params = vec![
            ("price", "0"),
            ("price", "0.01"),
            ("amount", "0"),
            ("cost", "0"),
            ("total", "0"),
        ];

        for (param, value) in price_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_price_manipulation(&response.body, value) {
                        info!("Mass assignment price manipulation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Price Manipulation via Mass Assignment",
                            &format!("{}={}", param, value),
                            "Product prices can be manipulated via mass assignment",
                            &format!("Successfully set price to {} via mass assignment", value),
                            Severity::High,
                            "CWE-915",
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

    /// Test hidden field injection
    async fn test_hidden_field_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Testing hidden field injection");

        let hidden_params = vec![
            ("user_id", "1"),
            ("id", "1"),
            ("account_id", "1"),
            ("verified", "true"),
            ("active", "true"),
            ("status", "active"),
        ];

        for (param, value) in hidden_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_hidden_field_manipulation(&response.body, param) {
                        info!("Hidden field manipulation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Hidden Field Manipulation",
                            &format!("{}={}", param, value),
                            "Hidden fields can be manipulated via mass assignment",
                            &format!("Successfully manipulated hidden field: {}", param),
                            Severity::High,
                            "CWE-915",
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

    /// Detect privilege escalation
    fn detect_privilege_escalation(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if parameter was accepted
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("{}\":{}", param, value)) ||
           body_lower.contains(&format!("'{}':'{}'", param, value)) {
            return true;
        }

        // Check for privilege indicators
        let privilege_indicators = vec![
            "admin",
            "administrator",
            "privilege",
            "elevated",
            "superuser",
        ];

        for indicator in privilege_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect price manipulation
    fn detect_price_manipulation(&self, body: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if price was set to manipulated value
        if body_lower.contains(&format!("\"price\":\"{}\"", value)) ||
           body_lower.contains(&format!("\"price\":{}", value)) ||
           body_lower.contains(&format!("\"amount\":\"{}\"", value)) ||
           body_lower.contains(&format!("\"total\":\"{}\"", value)) {
            return true;
        }

        // Check for success indicators
        body_lower.contains("updated") || body_lower.contains("saved")
    }

    /// Detect hidden field manipulation
    fn detect_hidden_field_manipulation(&self, body: &str, param: &str) -> bool {
        let body_lower = body.to_lowercase();
        let param_lower = param.to_lowercase();

        // Check if hidden parameter appears in response
        if body_lower.contains(&format!("\"{}\":", param_lower)) ||
           body_lower.contains(&format!("'{}':", param_lower)) {
            return true;
        }

        // Check for update success
        body_lower.contains("updated") || body_lower.contains("modified")
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
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("ma_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::Medium,
            category: "Business Logic".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Use allowlists for bindable attributes (strong parameters)\n\
                         2. Never bind user input directly to model objects\n\
                         3. Explicitly define which fields can be mass-assigned\n\
                         4. Use DTOs (Data Transfer Objects) for user input\n\
                         5. Validate all input against expected schema\n\
                         6. Mark sensitive fields as read-only or protected\n\
                         7. Implement proper authorization checks before updates\n\
                         8. Use frameworks' built-in protection (Rails strong parameters, etc.)\n\
                         9. Avoid automatic parameter binding in frameworks\n\
                         10. Implement field-level access controls".to_string(),
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

    fn create_test_scanner() -> MassAssignmentScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        MassAssignmentScanner::new(http_client)
    }

    #[test]
    fn test_detect_privilege_escalation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_privilege_escalation(r#"{"role":"admin"}"#, "role", "admin"));
        assert!(scanner.detect_privilege_escalation("Welcome administrator", "is_admin", "true"));
    }

    #[test]
    fn test_detect_price_manipulation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_price_manipulation(r#"{"price":"0"}"#, "0"));
        assert!(scanner.detect_price_manipulation(r#"{"price":0}"#, "0"));
        assert!(scanner.detect_price_manipulation("Price updated successfully", "0.01"));
    }

    #[test]
    fn test_detect_hidden_field_manipulation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_hidden_field_manipulation(r#"{"user_id":1}"#, "user_id"));
        assert!(scanner.detect_hidden_field_manipulation("User updated", "verified"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_privilege_escalation("Normal response", "role", "user"));
        assert!(!scanner.detect_price_manipulation("Invalid request", "999"));
        assert!(!scanner.detect_hidden_field_manipulation("Error", "unknown"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "Privilege Escalation via Mass Assignment",
            "role=admin",
            "Mass assignment detected",
            "Role set to admin",
            Severity::Critical,
            "CWE-915",
        );

        assert_eq!(vuln.vuln_type, "Privilege Escalation via Mass Assignment");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-915");
        assert_eq!(vuln.cvss, 9.1);
    }
}
