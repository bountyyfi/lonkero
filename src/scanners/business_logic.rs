// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Business Logic Scanner
 * Detects business logic vulnerabilities
 *
 * Detects:
 * - Negative quantity/price manipulation
 * - Workflow bypass
 * - Parameter tampering for discounts
 * - Insufficient process validation
 * - State manipulation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct BusinessLogicScanner {
    http_client: Arc<HttpClient>,
}

impl BusinessLogicScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for business logic vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing business logic vulnerabilities");

        // Test negative values
        let (vulns, tests) = self.test_negative_values(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test workflow bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_workflow_bypass(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test parameter tampering
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_parameter_tampering(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test negative quantity/price values
    async fn test_negative_values(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Testing negative value handling");

        let negative_tests = vec![
            ("quantity", "-1"),
            ("quantity", "-10"),
            ("price", "-1.00"),
            ("amount", "-100"),
            ("discount", "200"),  // Over 100%
            ("balance", "-1000"),
        ];

        for (param, value) in negative_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_negative_value_accepted(&response.body, param, value) {
                        info!("Negative/invalid value accepted: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Negative Value Manipulation",
                            &format!("{}={}", param, value),
                            &format!("Application accepts negative/invalid {} value", param),
                            &format!("Successfully set {}={}", param, value),
                            Severity::High,
                            "CWE-840",
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

    /// Test workflow bypass
    async fn test_workflow_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Testing workflow bypass");

        let workflow_tests = vec![
            ("step", "10"),  // Skip to final step
            ("status", "completed"),
            ("state", "paid"),
            ("verified", "true"),
        ];

        for (param, value) in workflow_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_workflow_bypass(&response.body, value) {
                        info!("Workflow bypass detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Workflow Bypass",
                            &format!("{}={}", param, value),
                            "Application workflow can be bypassed by manipulating parameters",
                            &format!("Successfully bypassed workflow with {}={}", param, value),
                            Severity::High,
                            "CWE-841",
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

    /// Test parameter tampering
    async fn test_parameter_tampering(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing parameter tampering");

        let tampering_tests = vec![
            ("discount", "100"),
            ("discount_percent", "99"),
            ("shipping", "0"),
            ("tax", "0"),
            ("total", "0.01"),
        ];

        for (param, value) in tampering_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_parameter_tampering(&response.body, param, value) {
                        info!("Parameter tampering successful: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Parameter Tampering",
                            &format!("{}={}", param, value),
                            &format!("Business logic parameter '{}' can be manipulated", param),
                            &format!("Successfully tampered with {}={}", param, value),
                            Severity::High,
                            "CWE-472",
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

    /// Detect if negative value was accepted
    fn detect_negative_value_accepted(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if value appears in response as accepted
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("'{}':'{}'", param, value)) {
            return true;
        }

        // Check for success indicators
        let success_indicators = vec![
            "success",
            "updated",
            "saved",
            "accepted",
            "confirmed",
        ];

        for indicator in success_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect workflow bypass
    fn detect_workflow_bypass(&self, body: &str, target_state: &str) -> bool {
        let body_lower = body.to_lowercase();
        let target_lower = target_state.to_lowercase();

        // Check if target state is reflected
        if body_lower.contains(&target_lower) {
            // Check for success indicators
            let success_indicators = vec![
                "completed",
                "success",
                "confirmed",
                "approved",
                "verified",
            ];

            for indicator in success_indicators {
                if body_lower.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect parameter tampering
    fn detect_parameter_tampering(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if tampered value was accepted
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("{}={}", param, value)) {
            return true;
        }

        // Check for indicators that tampering worked
        if param.contains("discount") && body_lower.contains("discount") {
            return true;
        }

        if (param == "shipping" || param == "tax") && value == "0" {
            if body_lower.contains(&format!("{}:0", param)) ||
               body_lower.contains(&format!("{}\":0", param)) {
                return true;
            }
        }

        false
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
            id: format!("bl_{}", uuid::Uuid::new_v4().to_string()),
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
            remediation: "1. Implement server-side validation for all business logic\n\
                         2. Validate data types, ranges, and business rules\n\
                         3. Reject negative values for quantities and prices\n\
                         4. Implement proper state machine for workflows\n\
                         5. Validate workflow transitions server-side\n\
                         6. Never trust client-supplied business logic parameters\n\
                         7. Recalculate prices, totals, and discounts server-side\n\
                         8. Implement business rule engines for complex logic\n\
                         9. Log and monitor unusual parameter values\n\
                         10. Use database constraints for data integrity\n\
                         11. Implement authorization checks for each workflow step\n\
                         12. Test edge cases and boundary values".to_string(),
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

    fn create_test_scanner() -> BusinessLogicScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        BusinessLogicScanner::new(http_client)
    }

    #[test]
    fn test_detect_negative_value_accepted() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_negative_value_accepted(r#"{"quantity":"-1"}"#, "quantity", "-1"));
        assert!(scanner.detect_negative_value_accepted("Update successful", "price", "-10"));
    }

    #[test]
    fn test_detect_workflow_bypass() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_workflow_bypass("Order completed successfully", "completed"));
        assert!(scanner.detect_workflow_bypass("Payment verified", "verified"));
    }

    #[test]
    fn test_detect_parameter_tampering() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_parameter_tampering(r#"{"discount":"100"}"#, "discount", "100"));
        assert!(scanner.detect_parameter_tampering(r#"{"shipping":0}"#, "shipping", "0"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_negative_value_accepted("Invalid input", "quantity", "-1"));
        assert!(!scanner.detect_workflow_bypass("Error", "completed"));
        assert!(!scanner.detect_parameter_tampering("Failed", "discount", "100"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "Negative Value Manipulation",
            "quantity=-1",
            "Negative values accepted",
            "quantity set to -1",
            Severity::High,
            "CWE-840",
        );

        assert_eq!(vuln.vuln_type, "Negative Value Manipulation");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-840");
        assert_eq!(vuln.cvss, 7.5);
    }
}
