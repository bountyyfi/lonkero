// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Second-Order Injection Scanner
 * Detects second-order injection vulnerabilities where payloads are stored
 * in one request and triggered/executed in different endpoints later
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

/// Storage endpoint configuration
#[derive(Debug, Clone)]
struct StorageEndpoint {
    path_pattern: &'static str,
    method: &'static str,
    fields: Vec<&'static str>,
}

/// Trigger endpoint configuration
#[derive(Debug, Clone)]
struct TriggerEndpoint {
    path_pattern: &'static str,
    method: &'static str,
    description: &'static str,
}

/// Tracked payload information
#[derive(Debug, Clone)]
struct PayloadTracker {
    payload: String,
    storage_endpoint: String,
    field_name: String,
    marker: String,
    payload_type: PayloadType,
}

/// Type of injection payload
#[derive(Debug, Clone, PartialEq)]
enum PayloadType {
    Xss,
    Sqli,
    Command,
}

pub struct SecondOrderInjectionScanner {
    http_client: Arc<HttpClient>,
    unique_marker: String,
    stored_payloads: Vec<PayloadTracker>,
}

impl SecondOrderInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let unique_marker = format!("2ndord_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            unique_marker,
            stored_payloads: Vec::new(),
        }
    }

    /// Main scan entry point
    pub async fn scan(
        &mut self,
        base_url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting second-order injection scan");

        // Phase 1: Store payloads in common storage endpoints
        let storage_tests = self.store_payloads(base_url).await?;
        tests_run += storage_tests;

        info!("Stored {} payloads across endpoints", self.stored_payloads.len());

        // Phase 2: Check trigger endpoints for payload execution
        let (vulns, trigger_tests) = self.check_trigger_endpoints(base_url).await?;
        vulnerabilities.extend(vulns);
        tests_run += trigger_tests;

        Ok((vulnerabilities, tests_run))
    }

    /// Store injection payloads in common storage endpoints
    async fn store_payloads(&mut self, base_url: &str) -> Result<usize> {
        let mut tests_run = 0;

        // Define storage endpoints to test
        let storage_endpoints = self.get_storage_endpoints();

        for endpoint_config in storage_endpoints {
            tests_run += self.test_storage_endpoint(base_url, &endpoint_config).await?;
        }

        Ok(tests_run)
    }

    /// Test a single storage endpoint with payloads
    async fn test_storage_endpoint(
        &mut self,
        base_url: &str,
        config: &StorageEndpoint,
    ) -> Result<usize> {
        let mut tests_run = 0;
        let url = format!("{}{}", base_url, config.path_pattern);

        debug!("Testing storage endpoint: {}", url);

        // Generate payloads for each field
        for field in &config.fields {
            let payloads = self.generate_payloads(field);

            for (payload, payload_type) in payloads {
                tests_run += 1;

                // Attempt to store the payload
                let result = if config.method == "POST" {
                    self.send_storage_request(&url, field, &payload, config.method).await
                } else {
                    self.send_storage_request(&url, field, &payload, config.method).await
                };

                match result {
                    Ok(response) => {
                        // Track successful storage (assuming 2xx/3xx status codes indicate success)
                        if response.status_code >= 200 && response.status_code < 400 {
                            debug!("Payload stored successfully in {} field {}", url, field);

                            self.stored_payloads.push(PayloadTracker {
                                payload: payload.clone(),
                                storage_endpoint: url.clone(),
                                field_name: field.to_string(),
                                marker: self.unique_marker.clone(),
                                payload_type,
                            });
                        }
                    }
                    Err(e) => {
                        debug!("Failed to store payload at {}: {}", url, e);
                    }
                }
            }
        }

        Ok(tests_run)
    }

    /// Check trigger endpoints for payload execution
    async fn check_trigger_endpoints(&self, base_url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        if self.stored_payloads.is_empty() {
            info!("No payloads were successfully stored, skipping trigger checks");
            return Ok((vulnerabilities, tests_run));
        }

        let trigger_endpoints = self.get_trigger_endpoints();

        for trigger_config in trigger_endpoints {
            let url = format!("{}{}", base_url, trigger_config.path_pattern);
            tests_run += 1;

            debug!("Checking trigger endpoint: {}", url);

            match self.http_client.get(&url).await {
                Ok(response) => {
                    // Check if any stored payloads appear in the response
                    let detected = self.detect_payload_execution(&response.body);

                    if let Some(tracker) = detected {
                        info!("Second-order injection detected at {}", url);

                        let severity = match tracker.payload_type {
                            PayloadType::Xss => Severity::High,
                            PayloadType::Sqli => Severity::Critical,
                            PayloadType::Command => Severity::Critical,
                        };

                        let vuln = Vulnerability {
                            id: format!("2ndord_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: format!("Second-Order {} Injection", self.payload_type_name(&tracker.payload_type)),
                            severity,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: url.clone(),
                            parameter: Some(tracker.field_name.clone()),
                            payload: tracker.payload.clone(),
                            description: format!(
                                "A second-order injection vulnerability was detected. A payload was stored via {} in field '{}' and executed when viewing {}.",
                                tracker.storage_endpoint,
                                tracker.field_name,
                                url
                            ),
                            evidence: Some(format!(
                                "Stored payload: {}\nStorage endpoint: {}\nTrigger endpoint: {}\nMarker found in response: {}",
                                tracker.payload,
                                tracker.storage_endpoint,
                                url,
                                tracker.marker
                            )),
                            cwe: format!("CWE-{}", self.get_cwe(&tracker.payload_type)),
                            cvss: self.get_cvss(&tracker.payload_type),
                            verified: true,
                            false_positive: false,
                            remediation: self.get_remediation(&tracker.payload_type),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        };

                        vulnerabilities.push(vuln);
                    }
                }
                Err(e) => {
                    debug!("Failed to check trigger endpoint {}: {}", url, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Generate payloads for a specific field
    fn generate_payloads(&self, _field: &str) -> Vec<(String, PayloadType)> {
        let marker = &self.unique_marker;

        vec![
            // XSS payloads
            (format!("<script>alert('{}')</script>", marker), PayloadType::Xss),
            (format!("<img src=x onerror=alert('{}')>", marker), PayloadType::Xss),
            (format!("<svg onload=alert('{}')>", marker), PayloadType::Xss),
            (format!("'\"><script>alert('{}')</script>", marker), PayloadType::Xss),

            // SQLi payloads - designed to cause errors when viewed
            (format!("test' OR '1'='1' -- {}", marker), PayloadType::Sqli),
            (format!("test'; DROP TABLE users; -- {}", marker), PayloadType::Sqli),
            (format!("' UNION SELECT NULL, '{}', NULL --", marker), PayloadType::Sqli),
            (format!("1' AND 1=CONVERT(int, '{}') --", marker), PayloadType::Sqli),

            // Command injection payloads
            (format!("; echo '{}' #", marker), PayloadType::Command),
            (format!("| echo '{}' #", marker), PayloadType::Command),
            (format!("`echo '{}'`", marker), PayloadType::Command),
        ]
    }

    /// Send a storage request with the payload
    async fn send_storage_request(
        &self,
        url: &str,
        field: &str,
        payload: &str,
        method: &str,
    ) -> Result<crate::http_client::HttpResponse> {
        match method {
            "POST" => {
                // Try JSON first
                let json_body = format!(r#"{{"{}":"{}"}}"#, field, payload.replace('"', "\\\""));
                match self.http_client.post(url, json_body.clone()).await {
                    Ok(resp) => Ok(resp),
                    Err(_) => {
                        // Fallback to form data
                        let form_body = format!("{}={}", field, urlencoding::encode(payload));
                        self.http_client.post_form(url, &form_body).await
                    }
                }
            }
            "PUT" => {
                let json_body = format!(r#"{{"{}":"{}"}}"#, field, payload.replace('"', "\\\""));
                self.http_client.put(url, &json_body).await
            }
            _ => {
                // GET with query params (or fallback for other methods)
                let query_url = if url.contains('?') {
                    format!("{}&{}={}", url, field, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, field, urlencoding::encode(payload))
                };
                self.http_client.get(&query_url).await
            }
        }
    }

    /// Detect if any stored payload appears in the response
    fn detect_payload_execution(&self, response_body: &str) -> Option<PayloadTracker> {
        for tracker in &self.stored_payloads {
            // Check for marker presence
            if response_body.contains(&tracker.marker) {
                // Verify payload execution context
                match tracker.payload_type {
                    PayloadType::Xss => {
                        // Check if payload appears unencoded
                        if response_body.contains(&tracker.payload) {
                            return Some(tracker.clone());
                        }
                    }
                    PayloadType::Sqli => {
                        // Check for SQL error messages
                        if self.contains_sql_error(response_body) {
                            return Some(tracker.clone());
                        }
                        // Or check if marker appears in context suggesting SQL execution
                        if response_body.contains(&tracker.marker) {
                            return Some(tracker.clone());
                        }
                    }
                    PayloadType::Command => {
                        // Check if marker appears suggesting command execution
                        if response_body.contains(&tracker.marker) {
                            return Some(tracker.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if response contains SQL error messages
    fn contains_sql_error(&self, body: &str) -> bool {
        let sql_errors = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "SQLSTATE",
            "syntax error",
            "mysql_query",
            "pg_query",
            "sqlite3_",
            "Microsoft SQL",
            "ODBC Driver",
            "Oracle error",
            "Unclosed quotation mark",
            "quoted string not properly terminated",
        ];

        sql_errors.iter().any(|&error| body.contains(error))
    }

    /// Get storage endpoints configuration
    fn get_storage_endpoints(&self) -> Vec<StorageEndpoint> {
        vec![
            StorageEndpoint {
                path_pattern: "/profile",
                method: "POST",
                fields: vec!["name", "bio", "description", "username", "email"],
            },
            StorageEndpoint {
                path_pattern: "/profile/update",
                method: "POST",
                fields: vec!["name", "bio", "description", "username", "email"],
            },
            StorageEndpoint {
                path_pattern: "/settings",
                method: "POST",
                fields: vec!["name", "email", "description", "bio"],
            },
            StorageEndpoint {
                path_pattern: "/account",
                method: "POST",
                fields: vec!["name", "email", "username", "bio"],
            },
            StorageEndpoint {
                path_pattern: "/comment",
                method: "POST",
                fields: vec!["comment", "content", "text", "message", "body"],
            },
            StorageEndpoint {
                path_pattern: "/post",
                method: "POST",
                fields: vec!["title", "content", "body", "text"],
            },
            StorageEndpoint {
                path_pattern: "/message",
                method: "POST",
                fields: vec!["message", "content", "text", "subject", "body"],
            },
            StorageEndpoint {
                path_pattern: "/register",
                method: "POST",
                fields: vec!["username", "email", "name", "displayName"],
            },
            StorageEndpoint {
                path_pattern: "/signup",
                method: "POST",
                fields: vec!["username", "email", "name", "displayName"],
            },
            StorageEndpoint {
                path_pattern: "/api/profile",
                method: "POST",
                fields: vec!["name", "bio", "username"],
            },
            StorageEndpoint {
                path_pattern: "/api/user/update",
                method: "PUT",
                fields: vec!["name", "bio", "email"],
            },
        ]
    }

    /// Get trigger endpoints configuration
    fn get_trigger_endpoints(&self) -> Vec<TriggerEndpoint> {
        vec![
            // Admin endpoints
            TriggerEndpoint {
                path_pattern: "/admin/users",
                method: "GET",
                description: "Admin user list",
            },
            TriggerEndpoint {
                path_pattern: "/admin/audit",
                method: "GET",
                description: "Admin audit log",
            },
            TriggerEndpoint {
                path_pattern: "/admin/logs",
                method: "GET",
                description: "Admin logs view",
            },
            TriggerEndpoint {
                path_pattern: "/admin/dashboard",
                method: "GET",
                description: "Admin dashboard",
            },
            TriggerEndpoint {
                path_pattern: "/admin/comments",
                method: "GET",
                description: "Admin comments moderation",
            },
            TriggerEndpoint {
                path_pattern: "/admin/reports",
                method: "GET",
                description: "Admin reports",
            },
            // Report endpoints
            TriggerEndpoint {
                path_pattern: "/report/users",
                method: "GET",
                description: "User report",
            },
            TriggerEndpoint {
                path_pattern: "/report/activity",
                method: "GET",
                description: "Activity report",
            },
            // Audit endpoints
            TriggerEndpoint {
                path_pattern: "/audit/log",
                method: "GET",
                description: "Audit log",
            },
            TriggerEndpoint {
                path_pattern: "/audit/trail",
                method: "GET",
                description: "Audit trail",
            },
            // Logs endpoints
            TriggerEndpoint {
                path_pattern: "/logs",
                method: "GET",
                description: "Application logs",
            },
            TriggerEndpoint {
                path_pattern: "/logs/access",
                method: "GET",
                description: "Access logs",
            },
            // Search endpoints
            TriggerEndpoint {
                path_pattern: "/search?q=test",
                method: "GET",
                description: "Search results",
            },
            TriggerEndpoint {
                path_pattern: "/search/users?q=test",
                method: "GET",
                description: "User search",
            },
            // User profile views
            TriggerEndpoint {
                path_pattern: "/user/profile",
                method: "GET",
                description: "User profile view",
            },
            TriggerEndpoint {
                path_pattern: "/profile",
                method: "GET",
                description: "Profile view",
            },
            TriggerEndpoint {
                path_pattern: "/profile/view",
                method: "GET",
                description: "Profile detail view",
            },
            // API endpoints
            TriggerEndpoint {
                path_pattern: "/api/admin/users",
                method: "GET",
                description: "API admin users",
            },
            TriggerEndpoint {
                path_pattern: "/api/users",
                method: "GET",
                description: "API users list",
            },
            TriggerEndpoint {
                path_pattern: "/api/search?q=test",
                method: "GET",
                description: "API search",
            },
        ]
    }

    /// Get payload type name as string
    fn payload_type_name(&self, payload_type: &PayloadType) -> &'static str {
        match payload_type {
            PayloadType::Xss => "XSS",
            PayloadType::Sqli => "SQL",
            PayloadType::Command => "Command",
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, payload_type: &PayloadType) -> String {
        match payload_type {
            PayloadType::Xss => {
                "1. Sanitize all user input before storage\n\
                 2. Encode output when displaying stored data (HTML entity encoding)\n\
                 3. Implement Content Security Policy (CSP)\n\
                 4. Use context-aware output encoding\n\
                 5. Validate input against allowlist patterns".to_string()
            }
            PayloadType::Sqli => {
                "1. Use parameterized queries (prepared statements) for ALL database operations\n\
                 2. Never concatenate user input into SQL queries\n\
                 3. Implement proper input validation and sanitization\n\
                 4. Use ORM frameworks with built-in protection\n\
                 5. Apply least privilege principle for database accounts\n\
                 6. Perform regular security code reviews".to_string()
            }
            PayloadType::Command => {
                "1. Avoid executing system commands with user input\n\
                 2. Use safe APIs instead of shell commands\n\
                 3. If system commands are necessary, use allowlist validation\n\
                 4. Escape shell metacharacters properly\n\
                 5. Run with minimal privileges\n\
                 6. Use language-specific safe execution functions".to_string()
            }
        }
    }

    /// Get CWE identifier
    fn get_cwe(&self, payload_type: &PayloadType) -> u32 {
        match payload_type {
            PayloadType::Xss => 79,  // CWE-79: Cross-site Scripting (XSS)
            PayloadType::Sqli => 89,  // CWE-89: SQL Injection
            PayloadType::Command => 78,  // CWE-78: OS Command Injection
        }
    }

    /// Get CVSS score
    fn get_cvss(&self, payload_type: &PayloadType) -> f32 {
        match payload_type {
            PayloadType::Xss => 7.1,
            PayloadType::Sqli => 9.8,
            PayloadType::Command => 9.8,
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
                rng.random::<u64>() & 0xFFFFFFFFFFFF
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_error_detection() {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let scanner = SecondOrderInjectionScanner::new(http_client);

        assert!(scanner.contains_sql_error("Error: SQL syntax error near"));
        assert!(scanner.contains_sql_error("mysql_fetch_array() expects"));
        assert!(scanner.contains_sql_error("ORA-00933: SQL command not properly ended"));
        assert!(!scanner.contains_sql_error("This is a normal response"));
    }

    #[test]
    fn test_payload_generation() {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let scanner = SecondOrderInjectionScanner::new(http_client);
        let payloads = scanner.generate_payloads("username");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(_, t)| *t == PayloadType::Xss));
        assert!(payloads.iter().any(|(_, t)| *t == PayloadType::Sqli));
        assert!(payloads.iter().any(|(_, t)| *t == PayloadType::Command));
    }
}
