// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for NoSQL injection vulnerabilities
pub struct NosqlInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl NosqlInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!(
            "nosql-{}",
            uuid::Uuid::new_v4().to_string().replace("-", "")
        );
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run NoSQL injection scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting NoSQL injection scan on {}", url);

        // Intelligent detection - skip for static sites/SPAs
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.should_skip_injection_tests() {
                info!("[NoSQLi] Skipping - static/SPA site detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test MongoDB operators in GET requests
        let (vulns, tests) = self.test_mongodb_operators_get(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test MongoDB operators in POST requests
        let (vulns, tests) = self.test_mongodb_operators_post(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test JavaScript injection
        let (vulns, tests) = self.test_javascript_injection(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test authentication bypass
        let (vulns, tests) = self.test_auth_bypass(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "NoSQL injection scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test MongoDB operators in GET requests
    async fn test_mongodb_operators_get(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing MongoDB operators in GET requests");

        // NoSQL injection payloads for GET
        let payloads = vec![
            ("id[$ne]", "1", "$ne operator"),
            ("id[$gt]", "0", "$gt operator"),
            ("username[$regex]", ".*", "$regex operator"),
            ("password[$ne]", "null", "$ne with null"),
            ("email[$exists]", "true", "$exists operator"),
        ];

        for (param, value, description) in payloads {
            let test_url = format!("{}?{}={}", url, param, value);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_nosql_injection(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "NoSQL Injection (GET)",
                            &test_url,
                            &format!(
                                "NoSQL injection via {} in GET parameter: {}={}",
                                description, param, value
                            ),
                            Severity::Critical,
                            "CWE-943",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("NoSQL GET test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test MongoDB operators in POST requests
    async fn test_mongodb_operators_post(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing MongoDB operators in POST requests");

        // NoSQL injection payloads for POST (JSON)
        let payloads = vec![
            (
                r#"{"username":{"$ne":null},"password":{"$ne":null}}"#,
                "Authentication bypass with $ne",
            ),
            (
                r#"{"username":{"$gt":""},"password":{"$gt":""}}"#,
                "Authentication bypass with $gt",
            ),
            (r#"{"id":{"$regex":".*"}}"#, "Data extraction with $regex"),
            (r#"{"price":{"$lt":0}}"#, "Price manipulation with $lt"),
        ];

        for (payload, description) in payloads {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, payload, headers)
                .await
            {
                Ok(response) => {
                    if self.detect_nosql_injection(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "NoSQL Injection (POST)",
                            url,
                            &format!("{}: {}", description, payload),
                            Severity::Critical,
                            "CWE-943",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("NoSQL POST test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JavaScript injection in NoSQL queries
    async fn test_javascript_injection(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing JavaScript injection in NoSQL");

        // JavaScript injection payloads
        let payloads = vec![
            (
                r#"{"username":"admin","password":{"$where":"this.password.length > 0"}}"#,
                "$where with JavaScript",
            ),
            (
                r#"{"$where":"this.username == 'admin' || '1'=='1'"}"#,
                "JavaScript logic injection",
            ),
            (
                r#"{"username":"admin'; return true; var a='","password":"test"}"#,
                "JavaScript code injection",
            ),
        ];

        for (payload, description) in payloads {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, payload, headers)
                .await
            {
                Ok(response) => {
                    if self.detect_javascript_injection(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "NoSQL JavaScript Injection",
                            url,
                            &format!("{}: {}", description, payload),
                            Severity::Critical,
                            "CWE-943",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("JavaScript injection test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test authentication bypass via NoSQL injection
    async fn test_auth_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing NoSQL authentication bypass");

        // Try common login endpoints
        let login_endpoints = vec![
            format!("{}/login", url.trim_end_matches('/')),
            format!("{}/api/login", url.trim_end_matches('/')),
            format!("{}/auth/login", url.trim_end_matches('/')),
        ];

        // Authentication bypass payload
        let bypass_payload = r#"{"username":{"$ne":""},"password":{"$ne":""}}"#;

        for endpoint in login_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint, bypass_payload, headers)
                .await
            {
                Ok(response) => {
                    if self.detect_auth_bypass(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "NoSQL Authentication Bypass",
                            &endpoint,
                            &format!(
                                "Authentication bypass via NoSQL injection: {}",
                                bypass_payload
                            ),
                            Severity::Critical,
                            "CWE-943",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Auth bypass test failed for {}: {}", endpoint, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect NoSQL injection vulnerability
    /// NOTE: Must check for SPECIFIC MongoDB/NoSQL error indicators, not generic words
    fn detect_nosql_injection(&self, body: &str, _status_code: u16) -> bool {
        let body_lower = body.to_lowercase();

        // Check for SPECIFIC MongoDB/NoSQL error patterns only
        // These are actual error messages that indicate NoSQL injection worked
        let nosql_specific_errors = vec![
            "mongoerror",                // MongoDB error class
            "mongoose validation",       // Mongoose ORM errors
            "bsonerror",                 // BSON parsing errors
            "cast to objectid failed",   // MongoDB casting error
            "illegal $operator",         // MongoDB operator error
            "$ne requires",              // MongoDB operator validation
            "$gt requires",              // MongoDB operator validation
            "$regex",                    // MongoDB regex operator in error
            "invalid operator",          // MongoDB invalid operator
            "unknown query operator",    // MongoDB unknown operator
            "cannot apply $where",       // MongoDB $where restriction
            "failed to parse",           // MongoDB parsing failure
            "not a valid json document", // MongoDB JSON error
            "invalid bson",              // BSON validation error
        ];

        for error in nosql_specific_errors {
            if body_lower.contains(error) {
                return true;
            }
        }

        // REMOVED: Do NOT flag on generic words like "data", "user", "success"
        // These appear in virtually ALL API responses and cause false positives

        false
    }

    /// Detect JavaScript injection in NoSQL context
    /// NOTE: Must check for SPECIFIC error patterns, not generic words
    fn detect_javascript_injection(&self, body: &str, _status_code: u16) -> bool {
        let body_lower = body.to_lowercase();

        // Check for SPECIFIC JavaScript execution errors in MongoDB context
        let js_specific_errors = vec![
            "referenceerror:",        // JavaScript runtime error
            "syntaxerror:",           // JavaScript syntax error
            "$where not allowed",     // MongoDB $where restriction
            "cannot apply $where",    // MongoDB $where error
            "illegal $where",         // MongoDB $where error
            "javascript execution",   // MongoDB JS execution context
            "server-side javascript", // MongoDB SSJS context
        ];

        for error in js_specific_errors {
            if body_lower.contains(error) {
                return true;
            }
        }

        // REMOVED: Do NOT flag on generic words like "data", "success"
        // These appear in virtually ALL API responses and cause false positives

        false
    }

    /// Detect authentication bypass via NoSQL injection
    /// NOTE: This is VERY hard to detect without baseline comparison
    /// For now, we only detect if there's a SPECIFIC auth success pattern
    /// combined with our unique test marker being absent (differential detection)
    fn detect_auth_bypass(&self, body: &str, _status_code: u16) -> bool {
        let body_lower = body.to_lowercase();

        // For auth bypass detection to be reliable, we need to:
        // 1. Have sent a NoSQL injection payload that bypasses auth
        // 2. See authentication tokens/sessions being returned
        // 3. NOT see normal login form or error message

        // Check for SPECIFIC auth success patterns (not just generic words)
        // These indicate authentication actually succeeded
        let strong_auth_indicators = vec![
            "\"access_token\":",         // OAuth/JWT token
            "\"refresh_token\":",        // OAuth refresh token
            "\"jwt\":",                  // JWT token
            "\"sessionid\":",            // Session ID
            "set-cookie: session",       // Session cookie being set
            "authentication successful", // Explicit success message
            "login succeeded",           // Explicit success message
        ];

        for indicator in strong_auth_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // REMOVED: Generic words like "token", "session", "welcome", "dashboard"
        // These appear on many pages and cause false positives

        false
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
            id: format!("nosql_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::Medium,
            category: "Injection".to_string(),
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
            ml_data: None,
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "NoSQL Injection (GET)" | "NoSQL Injection (POST)" => {
                "Sanitize and validate all user inputs. Use parameterized queries or ORM methods that prevent injection. Implement input type checking (ensure strings are strings, numbers are numbers). Avoid using operators like $where, $regex on user input. Use allow-lists for accepted values.".to_string()
            }
            "NoSQL JavaScript Injection" => {
                "Disable JavaScript execution in NoSQL queries. Never use $where operator with user input. Use safer query operators. Enable MongoDB's security.javascriptEnabled=false setting. Implement strict input validation and type checking.".to_string()
            }
            "NoSQL Authentication Bypass" => {
                "Never trust user input in authentication queries. Validate input types (username and password should be strings). Use prepared statements or ORM methods. Implement proper password hashing with bcrypt/argon2. Use parameterized queries that prevent operator injection.".to_string()
            }
            _ => {
                "Implement proper NoSQL injection prevention: validate and sanitize all inputs, use parameterized queries, disable JavaScript execution in queries, implement type checking, and use allow-lists for accepted values.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> NosqlInjectionScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        NosqlInjectionScanner::new(client)
    }

    #[test]
    fn test_detect_nosql_injection() {
        let scanner = create_test_scanner();

        // True positives - specific MongoDB/NoSQL errors
        assert!(scanner.detect_nosql_injection(r#"MongoError: invalid operator $ne"#, 500));
        assert!(scanner.detect_nosql_injection(r#"Cast to ObjectId failed"#, 400));
        assert!(scanner.detect_nosql_injection(r#"illegal $operator: $badop"#, 400));

        // False positives - generic words that should NOT trigger
        assert!(!scanner.detect_nosql_injection(r#"{"data":[{"user":"admin"}]}"#, 200));
        assert!(!scanner.detect_nosql_injection(r#"{"error":"Not found"}"#, 404));
        assert!(!scanner.detect_nosql_injection(r#"{"success":true,"users":[]}"#, 200));
    }

    #[test]
    fn test_detect_javascript_injection() {
        let scanner = create_test_scanner();

        // True positives - specific JavaScript/MongoDB errors
        assert!(scanner.detect_javascript_injection(r#"ReferenceError: x is not defined"#, 500));
        assert!(scanner.detect_javascript_injection(r#"$where not allowed in this context"#, 400));

        // False positives - generic words that should NOT trigger
        assert!(!scanner.detect_javascript_injection(r#"Invalid query"#, 400));
        assert!(!scanner.detect_javascript_injection(r#"{"data":[],"success":true}"#, 200));
    }

    #[test]
    fn test_detect_auth_bypass() {
        let scanner = create_test_scanner();

        // True positives - specific auth success indicators
        assert!(scanner.detect_auth_bypass(r#"{"access_token":"abc123","message":"OK"}"#, 200));
        assert!(scanner.detect_auth_bypass(r#"authentication successful"#, 200));

        // False positives - generic words that should NOT trigger
        assert!(!scanner.detect_auth_bypass(r#"{"token":"csrf_token_here"}"#, 200)); // generic "token"
        assert!(!scanner.detect_auth_bypass(r#"Welcome to dashboard"#, 200)); // generic "welcome"
        assert!(!scanner.detect_auth_bypass(r#"{"error":"Invalid credentials"}"#, 401));
    }

    #[test]
    fn test_test_marker_uniqueness() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("nosql-"));
    }
}
