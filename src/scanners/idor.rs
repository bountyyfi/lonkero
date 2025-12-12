// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - IDOR (Insecure Direct Object References) Scanner
 * Tests for authorization bypass via direct object reference manipulation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use std::collections::HashMap;

pub struct IdorScanner {
    http_client: Arc<HttpClient>,
}

#[derive(Debug, Clone)]
struct IdPattern {
    value: String,
    id_type: IdType,
}

#[derive(Debug, Clone)]
enum IdType {
    Sequential,
    Uuid,
    Special,
}

#[derive(Debug)]
struct BolaTestResult {
    original_response: Option<crate::http_client::HttpResponse>,
    test_responses: Vec<(String, crate::http_client::HttpResponse)>,
    has_vulnerability: bool,
    evidence: String,
}

impl IdorScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Generate test IDs for BOLA testing
    fn generate_test_ids(&self, original_id: &str) -> Vec<IdPattern> {
        let mut test_ids = Vec::new();

        // Sequential numeric IDs
        if let Ok(num) = original_id.parse::<i32>() {
            test_ids.push(IdPattern { value: "1".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "2".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "100".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "999".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "1000".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "0".to_string(), id_type: IdType::Sequential });
            test_ids.push(IdPattern { value: "-1".to_string(), id_type: IdType::Sequential });

            // Add adjacent IDs
            if num > 0 {
                test_ids.push(IdPattern {
                    value: (num - 1).to_string(),
                    id_type: IdType::Sequential
                });
                test_ids.push(IdPattern {
                    value: (num + 1).to_string(),
                    id_type: IdType::Sequential
                });
            }
        }

        // UUID patterns
        let uuid_regex = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
        if uuid_regex.is_match(original_id) {
            // Null UUID
            test_ids.push(IdPattern {
                value: "00000000-0000-0000-0000-000000000000".to_string(),
                id_type: IdType::Uuid,
            });

            // Common test UUIDs
            test_ids.push(IdPattern {
                value: "11111111-1111-1111-1111-111111111111".to_string(),
                id_type: IdType::Uuid,
            });
            test_ids.push(IdPattern {
                value: "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
                id_type: IdType::Uuid,
            });

            // Increment last byte of UUID
            if let Some(incremented) = self.increment_uuid(original_id) {
                test_ids.push(IdPattern {
                    value: incremented,
                    id_type: IdType::Uuid,
                });
            }
        }

        // Special/common test values
        test_ids.push(IdPattern { value: "admin".to_string(), id_type: IdType::Special });
        test_ids.push(IdPattern { value: "test".to_string(), id_type: IdType::Special });
        test_ids.push(IdPattern { value: "root".to_string(), id_type: IdType::Special });
        test_ids.push(IdPattern { value: "user".to_string(), id_type: IdType::Special });

        test_ids
    }

    /// Increment the last byte of a UUID for testing
    fn increment_uuid(&self, uuid: &str) -> Option<String> {
        let parts: Vec<&str> = uuid.split('-').collect();
        if parts.len() != 5 {
            return None;
        }

        let last_part = parts[4];
        if let Ok(mut num) = u64::from_str_radix(last_part, 16) {
            num = num.wrapping_add(1);
            let new_last = format!("{:012x}", num);
            Some(format!("{}-{}-{}-{}-{}", parts[0], parts[1], parts[2], parts[3], new_last))
        } else {
            None
        }
    }

    /// Extract ID from URL
    fn extract_id_from_url(&self, url: &str) -> Option<String> {
        // Try UUID pattern first
        let uuid_regex = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
        if let Some(cap) = uuid_regex.find(url) {
            return Some(cap.as_str().to_string());
        }

        // Try numeric ID in path
        let path_id_regex = Regex::new(r"/(\d+)(?:/|$|\?)").unwrap();
        if let Some(cap) = path_id_regex.captures(url) {
            return cap.get(1).map(|m| m.as_str().to_string());
        }

        // Try ID in query parameters
        let query_id_regex = Regex::new(r"[?&](?:id|user_id|userId|account_id|accountId)=([^&]+)").unwrap();
        if let Some(cap) = query_id_regex.captures(url) {
            return cap.get(1).map(|m| m.as_str().to_string());
        }

        None
    }

    /// Test BOLA vulnerability with different IDs
    async fn test_bola_with_ids(&self, url: &str, http_method: &str) -> Result<BolaTestResult> {
        let original_id = self.extract_id_from_url(url);
        if original_id.is_none() {
            return Ok(BolaTestResult {
                original_response: None,
                test_responses: Vec::new(),
                has_vulnerability: false,
                evidence: "No ID found in URL".to_string(),
            });
        }

        let original_id = original_id.unwrap();

        // Get baseline response with original ID
        let original_response = match http_method {
            "GET" => self.http_client.get(url).await.ok(),
            "POST" => self.http_client.post(url, "{}").await.ok(),
            "PUT" => self.http_client.put(url, "{}").await.ok(),
            "DELETE" => self.http_client.delete(url).await.ok(),
            _ => self.http_client.get(url).await.ok(),
        };

        if original_response.is_none() {
            return Ok(BolaTestResult {
                original_response: None,
                test_responses: Vec::new(),
                has_vulnerability: false,
                evidence: "Failed to get original response".to_string(),
            });
        }

        let original_response = original_response.unwrap();
        let mut test_responses = Vec::new();
        let test_ids = self.generate_test_ids(&original_id);

        // Test with different IDs
        for id_pattern in test_ids {
            let test_url = url.replace(&original_id, &id_pattern.value);

            let test_response = match http_method {
                "GET" => self.http_client.get(&test_url).await.ok(),
                "POST" => self.http_client.post(&test_url, "{}").await.ok(),
                "PUT" => self.http_client.put(&test_url, "{}").await.ok(),
                "DELETE" => self.http_client.delete(&test_url).await.ok(),
                _ => self.http_client.get(&test_url).await.ok(),
            };

            if let Some(response) = test_response {
                test_responses.push((id_pattern.value.clone(), response));
            }
        }

        // Analyze responses for BOLA vulnerability
        let (has_vulnerability, evidence) = self.analyze_bola_responses(&original_response, &test_responses);

        Ok(BolaTestResult {
            original_response: Some(original_response),
            test_responses,
            has_vulnerability,
            evidence,
        })
    }

    /// Analyze responses to detect BOLA vulnerability
    fn analyze_bola_responses(
        &self,
        original: &crate::http_client::HttpResponse,
        test_responses: &[(String, crate::http_client::HttpResponse)],
    ) -> (bool, String) {
        let mut evidence_parts = Vec::new();
        let mut has_vulnerability = false;

        for (test_id, response) in test_responses {
            // Check if we got a 200 OK with different data
            if response.status_code == 200 {
                // Not 401/403, which would indicate proper auth
                if response.status_code != 401 && response.status_code != 403 {
                    // Check if response is different from original (different user's data)
                    if response.body != original.body && response.body.len() > 100 {
                        // Check if it contains sensitive data patterns
                        let has_sensitive_data = self.contains_sensitive_data(&response.body);

                        if has_sensitive_data {
                            has_vulnerability = true;
                            evidence_parts.push(format!(
                                "ID '{}' returned 200 OK with different sensitive data ({} bytes)",
                                test_id,
                                response.body.len()
                            ));
                        }
                    }
                }
            }
        }

        let evidence = if evidence_parts.is_empty() {
            "No BOLA vulnerability detected".to_string()
        } else {
            evidence_parts.join("; ")
        };

        (has_vulnerability, evidence)
    }

    /// Check if response contains sensitive data patterns
    fn contains_sensitive_data(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for JSON/API response patterns
        let has_json_structure = body.contains('{') && body.contains('}');

        // Sensitive field patterns in JSON
        let sensitive_patterns = vec![
            "email", "phone", "ssn", "password", "address", "credit_card",
            "account", "balance", "salary", "dob", "date_of_birth",
            "\"id\":", "\"user\":", "\"profile\":", "\"data\":",
        ];

        let sensitive_count = sensitive_patterns.iter()
            .filter(|&pattern| body_lower.contains(pattern))
            .count();

        // If it's JSON and has multiple sensitive fields, likely contains sensitive data
        has_json_structure && sensitive_count >= 2
    }

    /// Get common BOLA-vulnerable API endpoint patterns
    fn get_bola_vulnerable_patterns(&self) -> Vec<String> {
        vec![
            "/api/users/{id}".to_string(),
            "/api/user/{id}".to_string(),
            "/api/accounts/{id}".to_string(),
            "/api/account/{id}".to_string(),
            "/api/orders/{id}".to_string(),
            "/api/order/{id}".to_string(),
            "/api/documents/{id}".to_string(),
            "/api/document/{id}".to_string(),
            "/api/files/{id}".to_string(),
            "/api/file/{id}".to_string(),
            "/api/profile/{id}".to_string(),
            "/api/profiles/{id}".to_string(),
            "/api/v1/users/{id}".to_string(),
            "/api/v2/users/{id}".to_string(),
            "/api/v1/accounts/{id}".to_string(),
            "/api/v2/accounts/{id}".to_string(),
            "/api/invoices/{id}".to_string(),
            "/api/transactions/{id}".to_string(),
            "/api/payments/{id}".to_string(),
        ]
    }

    /// Check if URL matches common BOLA-vulnerable patterns
    fn matches_bola_pattern(&self, url: &str) -> bool {
        let patterns = self.get_bola_vulnerable_patterns();

        for pattern in patterns {
            // Convert pattern to regex (replace {id} with \d+ or UUID pattern)
            let regex_pattern = pattern
                .replace("/", "\\/")
                .replace("{id}", "(?:\\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");

            if let Ok(regex) = Regex::new(&regex_pattern) {
                if regex.is_match(url) {
                    return true;
                }
            }
        }

        false
    }

    /// Report BOLA vulnerability
    fn report_bola_vulnerability(
        &self,
        result: &BolaTestResult,
        url: &str,
        http_method: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let severity = match http_method {
            "DELETE" => Severity::Critical,
            "PUT" | "PATCH" => Severity::Critical,
            "GET" => Severity::High,
            _ => Severity::High,
        };

        let vuln_type = match http_method {
            "GET" => "BOLA - Broken Object Level Authorization (Read)",
            "PUT" | "PATCH" => "BOLA - Broken Object Level Authorization (Modify)",
            "DELETE" => "BOLA - Broken Object Level Authorization (Delete)",
            _ => "BOLA - Broken Object Level Authorization",
        };

        let description = match http_method {
            "GET" => "Application allows reading other users' data by manipulating ID parameters. Attackers can enumerate IDs to access unauthorized resources.",
            "PUT" | "PATCH" => "Application allows modifying other users' data by manipulating ID parameters. Attackers can change unauthorized resources.",
            "DELETE" => "Application allows deleting other users' resources by manipulating ID parameters. Attackers can destroy unauthorized data.",
            _ => "Application fails to properly authorize object-level access.",
        };

        vulnerabilities.push(Vulnerability {
            id: generate_uuid(),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Authorization".to_string(),
            url: url.to_string(),
            parameter: Some("id".to_string()),
            payload: format!("{} request with manipulated ID", http_method),
            description: description.to_string(),
            evidence: Some(result.evidence.clone()),
            cwe: "CWE-639".to_string(),
            cvss: match http_method {
                "DELETE" => 9.1,
                "PUT" | "PATCH" => 8.8,
                "GET" => 7.5,
                _ => 7.5,
            },
            verified: true,
            false_positive: false,
            remediation: format!(
                "1. CRITICAL: Implement proper authorization checks for {} operations\n\
                2. Verify user ownership/permissions before allowing access\n\
                3. Use indirect object references (session-based mappings)\n\
                4. Implement object-level access control (OLAC)\n\
                5. Never trust client-supplied IDs without validation\n\
                6. Log and monitor suspicious access patterns\n\
                7. Use UUIDs instead of sequential IDs to prevent enumeration\n\
                8. Implement rate limiting to slow down enumeration attacks",
                http_method
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // BOLA Test 1: Test GET requests with ID enumeration
        if self.extract_id_from_url(url).is_some() {
            tests_run += 1;
            if let Ok(bola_result) = self.test_bola_with_ids(url, "GET").await {
                if bola_result.has_vulnerability {
                    self.report_bola_vulnerability(&bola_result, url, "GET", &mut vulnerabilities);
                }
            }

            // BOLA Test 2: Test PUT requests (modify other users' data)
            tests_run += 1;
            if let Ok(bola_result) = self.test_bola_with_ids(url, "PUT").await {
                if bola_result.has_vulnerability {
                    self.report_bola_vulnerability(&bola_result, url, "PUT", &mut vulnerabilities);
                }
            }

            // BOLA Test 3: Test PATCH requests (modify other users' data)
            tests_run += 1;
            if let Ok(bola_result) = self.test_bola_with_ids(url, "PATCH").await {
                if bola_result.has_vulnerability {
                    self.report_bola_vulnerability(&bola_result, url, "PATCH", &mut vulnerabilities);
                }
            }

            // BOLA Test 4: Test DELETE requests (delete other users' resources)
            tests_run += 1;
            if let Ok(bola_result) = self.test_bola_with_ids(url, "DELETE").await {
                if bola_result.has_vulnerability {
                    self.report_bola_vulnerability(&bola_result, url, "DELETE", &mut vulnerabilities);
                }
            }
        }

        // Test 1: Check for numeric ID patterns
        tests_run += 1;
        let response = self.http_client.get(url).await?;
        self.check_numeric_ids(&response, url, &mut vulnerabilities);

        // Test 2: Test predictable sequential IDs
        tests_run += 1;
        if let Ok(seq_response) = self.test_sequential_access(url).await {
            self.check_sequential_access(&seq_response, url, &mut vulnerabilities);
        }

        // Test 3: Test UUID predictability
        tests_run += 1;
        if let Ok(uuid_response) = self.test_uuid_predictability(url).await {
            self.check_uuid_security(&uuid_response, url, &mut vulnerabilities);
        }

        // Test 4: Test horizontal privilege escalation
        tests_run += 1;
        if let Ok(horiz_response) = self.test_horizontal_escalation(url).await {
            self.check_horizontal_escalation(&horiz_response, url, &mut vulnerabilities);
        }

        // Test 5: Test vertical privilege escalation
        tests_run += 1;
        if let Ok(vert_response) = self.test_vertical_escalation(url).await {
            self.check_vertical_escalation(&vert_response, url, &mut vulnerabilities);
        }

        // Test 6: Test authorization headers
        tests_run += 1;
        if let Ok(auth_response) = self.test_missing_authorization(url).await {
            self.check_authorization_enforcement(&auth_response, url, &mut vulnerabilities);
        }

        // Test 7: Test file access control
        tests_run += 1;
        if let Ok(file_response) = self.test_file_access(url).await {
            self.check_file_access_control(&file_response, url, &mut vulnerabilities);
        }

        Ok((vulnerabilities, tests_run))
    }

    fn check_numeric_ids(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check for numeric ID patterns in URLs and responses
        let id_patterns = vec![
            r"/user/(\d+)",
            r"/users/(\d+)",
            r"/account/(\d+)",
            r"/profile/(\d+)",
            r"/document/(\d+)",
            r"/file/(\d+)",
            r"/order/(\d+)",
            r"/invoice/(\d+)",
            r"\?id=(\d+)",
            r"\?user_id=(\d+)",
            r"\?account_id=(\d+)",
        ];

        for pattern_str in &id_patterns {
            let pattern = Regex::new(pattern_str).unwrap();
            if pattern.is_match(url) || pattern.is_match(body) {
                // Check if authorization indicators are present
                let has_auth_check = body.to_lowercase().contains("unauthorized")
                    || body.to_lowercase().contains("forbidden")
                    || body.to_lowercase().contains("access denied");

                if !has_auth_check && response.status_code == 200 {
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "Potential IDOR - Predictable Numeric IDs".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "Authorization".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description: "Endpoint uses predictable numeric IDs without clear authorization checks. This may allow unauthorized access to other users' resources by manipulating ID parameters.".to_string(),
                        evidence: Some(format!("Numeric ID pattern detected: {}", pattern_str)),
                        cwe: "CWE-639".to_string(),
                        cvss: 8.1,
                        verified: false,
                        false_positive: false,
                        remediation: "1. Implement proper authorization checks for all object access\n2. Use unpredictable UUIDs instead of sequential IDs\n3. Verify user ownership/permissions before returning objects\n4. Implement object-level access control (OLAC)\n5. Use indirect references (session-based mappings)\n6. Log and monitor suspicious access patterns".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break; // Only report once per response
                }
            }
        }

        // Check for exposed database IDs in JSON responses
        if body.contains("\"id\":") || body.contains("\"userId\":") || body.contains("\"accountId\":") {
            let json_id_regex = Regex::new(r#""(?:id|user_id|userId|account_id|accountId)":\s*(\d+)"#).unwrap();
            if json_id_regex.is_match(body) {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Information Disclosure - Database IDs".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "API exposes internal database IDs in JSON responses. Sequential database IDs make IDOR attacks easier by allowing attackers to enumerate valid IDs.".to_string(),
                    evidence: Some("Database IDs found in JSON response".to_string()),
                    cwe: "CWE-200".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Use UUIDs or opaque tokens in public APIs\n2. Map internal IDs to external references\n3. Implement rate limiting to prevent enumeration\n4. Use GraphQL with proper field-level authorization\n5. Consider using HMACs to sign object references".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    async fn test_sequential_access(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Try incrementing numeric IDs to test for sequential access
        let id_regex = Regex::new(r"(\d+)").unwrap();

        if let Some(captures) = id_regex.captures(url) {
            if let Some(id_match) = captures.get(1) {
                let current_id: u32 = id_match.as_str().parse().unwrap_or(1);
                let next_id = current_id + 1;
                let test_url = url.replace(id_match.as_str(), &next_id.to_string());
                return self.http_client.get(&test_url).await;
            }
        }

        // If no ID found in URL, try adding one
        let test_url = if url.contains('?') {
            format!("{}&id=2", url)
        } else {
            format!("{}?id=2", url)
        };

        self.http_client.get(&test_url).await
    }

    fn check_sequential_access(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let status = response.status_code;

        // Only flag if we got a 200 response with sensitive data structure
        if status == 200 {
            // Check if this looks like a different user's data (not an error page)
            let has_user_data_structure = self.contains_sensitive_data(body);

            // Check that it's not showing an authorization error
            let has_auth_error = body.to_lowercase().contains("unauthorized")
                || body.to_lowercase().contains("forbidden")
                || body.to_lowercase().contains("access denied")
                || body.to_lowercase().contains("permission denied");

            // If we got structured user data without an auth error, likely BOLA
            if has_user_data_structure && !has_auth_error {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "BOLA - Sequential ID Access".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    category: "Authorization".to_string(),
                    url: url.to_string(),
                    parameter: Some("id".to_string()),
                    payload: "Sequential ID manipulation".to_string(),
                    description: "Application returns user data for sequential IDs without proper authorization. This allows attackers to enumerate and access other users' resources by incrementing ID values.".to_string(),
                    evidence: Some("Accessing adjacent IDs returns different user data without authorization errors".to_string()),
                    cwe: "CWE-639".to_string(),
                    cvss: 7.5,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Implement proper authorization checks before returning user data\n2. Verify that the requesting user has permission to access the requested resource\n3. Use UUIDs instead of sequential IDs\n4. Implement indirect object references\n5. Log and monitor access to sensitive resources".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    async fn test_uuid_predictability(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test if UUID v1 (time-based) is used, which can be predictable
        let uuid_regex = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();

        if uuid_regex.is_match(url) {
            return self.http_client.get(url).await;
        }

        self.http_client.get(url).await
    }

    fn check_uuid_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;

        // Check for UUID v1 patterns (time-based, potentially predictable)
        let uuid_v1_regex = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();

        if uuid_v1_regex.is_match(url) || uuid_v1_regex.is_match(body) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Weak UUID Implementation - UUID v1".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Cryptography".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Application uses UUID v1 (time-based UUIDs) which can be predictable. UUID v1 encodes timestamp and MAC address, making it easier to enumerate valid IDs.".to_string(),
                evidence: Some("UUID v1 pattern detected in URL or response".to_string()),
                cwe: "CWE-330".to_string(),
                cvss: 5.3,
                verified: false,
                false_positive: false,
                remediation: "1. Use UUID v4 (random) instead of v1 (time-based)\n2. Consider using cryptographically secure random IDs\n3. Implement rate limiting to prevent enumeration\n4. Still enforce authorization checks regardless of ID type\n5. Monitor for enumeration attacks".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_horizontal_escalation(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test accessing another user's resources (horizontal escalation)
        let test_params = vec![
            ("user_id", "999999"),
            ("userId", "999999"),
            ("account", "admin"),
            ("username", "administrator"),
        ];

        for (param, value) in &test_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    return Ok(response);
                }
            }
        }

        self.http_client.get(url).await
    }

    fn check_horizontal_escalation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let status = response.status_code;

        // Check if we got sensitive user data for a manipulated user parameter
        if status == 200 {
            let has_sensitive_data = self.contains_sensitive_data(body);

            // Check for specific PII patterns that indicate successful access to user data
            let body_lower = body.to_lowercase();
            let has_pii = body_lower.contains("email")
                || body_lower.contains("phone")
                || body_lower.contains("ssn")
                || body_lower.contains("address");

            // Check that it's not an auth error
            let has_auth_error = body_lower.contains("unauthorized")
                || body_lower.contains("forbidden")
                || body_lower.contains("access denied");

            // Only flag if we have both sensitive data structure AND PII, without auth errors
            if has_sensitive_data && has_pii && !has_auth_error {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "BOLA - Horizontal Privilege Escalation".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authorization".to_string(),
                    url: url.to_string(),
                    parameter: Some("user_id".to_string()),
                    payload: "Manipulated user identifier".to_string(),
                    description: "Application allows accessing other users' sensitive data by manipulating user identifiers. This horizontal privilege escalation allows attackers to read data belonging to other users at the same privilege level.".to_string(),
                    evidence: Some("Successfully accessed user PII with manipulated user identifier".to_string()),
                    cwe: "CWE-639".to_string(),
                    cvss: 8.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Implement user-specific authorization checks\n2. Verify the requesting user matches the resource owner\n3. Use session-based user context instead of trusting parameters\n4. Implement object-level access control (OLAC)\n5. Log and alert on suspicious cross-user access attempts\n6. Use indirect references or signed tokens for user identifiers".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    async fn test_vertical_escalation(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test accessing admin/privileged resources
        let admin_paths = vec![
            "/admin",
            "/administrator",
            "/management",
            "/settings",
            "/config",
        ];

        for path in &admin_paths {
            let test_url = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    return Ok(response);
                }
            }
        }

        // Test role parameter manipulation
        let test_url = if url.contains('?') {
            format!("{}&role=admin", url)
        } else {
            format!("{}?role=admin", url)
        };

        self.http_client.get(&test_url).await
    }

    fn check_vertical_escalation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();
        let status = response.status_code;

        // Check for admin panel access
        let admin_indicators = vec![
            "admin panel",
            "administrator",
            "manage users",
            "system settings",
            "configuration",
            "delete user",
            "all users",
        ];

        let has_admin_content = admin_indicators
            .iter()
            .any(|&indicator| body_lower.contains(indicator));

        if status == 200 && has_admin_content {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "IDOR - Vertical Privilege Escalation".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Authorization".to_string(),
                url: url.to_string(),
                parameter: Some("role".to_string()),
                payload: "role=admin".to_string(),
                description: "Vertical privilege escalation detected: Regular users can access administrative functions by manipulating parameters or paths.".to_string(),
                evidence: Some("Administrative interface accessible without proper authorization".to_string()),
                cwe: "CWE-269".to_string(),
                cvss: 9.9,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Implement role-based access control (RBAC)\n2. Verify user roles server-side for all privileged operations\n3. Never trust client-supplied role/permission parameters\n4. Implement defense in depth with multiple authorization layers\n5. Use principle of least privilege\n6. Conduct regular privilege escalation testing\n7. Monitor for unauthorized privilege changes".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_missing_authorization(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test accessing resources without authentication headers
        self.http_client.get(url).await
    }

    fn check_authorization_enforcement(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();
        let status = response.status_code;

        // Check if protected resources are accessible without auth
        let protected_content = vec![
            "user data",
            "account",
            "profile",
            "private",
            "confidential",
            "dashboard",
        ];

        let has_protected_content = protected_content
            .iter()
            .any(|&content| body_lower.contains(content));

        let requires_auth = response.headers.contains_key("www-authenticate")
            || status == 401
            || status == 403
            || body_lower.contains("login required")
            || body_lower.contains("authentication required");

        if status == 200 && has_protected_content && !requires_auth {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Authorization Check".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Authorization".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Protected resources are accessible without authentication. The application does not enforce authorization checks for sensitive endpoints.".to_string(),
                evidence: Some("Protected content accessible without authentication headers".to_string()),
                cwe: "CWE-306".to_string(),
                cvss: 7.5,
                verified: false,
                false_positive: false,
                remediation: "1. Implement authentication middleware for all protected routes\n2. Verify JWT/session tokens before processing requests\n3. Return 401 for unauthenticated requests\n4. Return 403 for authenticated but unauthorized requests\n5. Use security frameworks with built-in auth protection\n6. Implement defense in depth with multiple auth layers".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_file_access(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test file download/access endpoints
        let file_params = vec![
            ("file", "../../etc/passwd"),
            ("filename", "invoice_12345.pdf"),
            ("doc", "report.pdf"),
            ("attachment", "document_1.docx"),
        ];

        for (param, value) in &file_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    return Ok(response);
                }
            }
        }

        self.http_client.get(url).await
    }

    fn check_file_access_control(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let status = response.status_code;

        // Only report path traversal if we actually got /etc/passwd or similar sensitive content
        // Don't just report based on body size - that causes false positives on every website
        let has_path_traversal = url.contains("../") || url.contains("..\\");

        if status == 200 && has_path_traversal {
            // Check for actual path traversal evidence - file content like /etc/passwd
            let has_sensitive_file_content = body.contains("root:x:0:0:")
                || body.contains("[boot loader]")
                || body.contains("<?php")
                || body.contains("jdbc:")
                || body.contains("DB_PASSWORD");

            if has_sensitive_file_content {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "IDOR - Unauthorized File Access via Path Traversal".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authorization".to_string(),
                    url: url.to_string(),
                    parameter: Some("file".to_string()),
                    payload: "file=../../etc/passwd".to_string(),
                    description: "File download endpoint vulnerable to path traversal and IDOR. Attackers can access arbitrary files without authorization.".to_string(),
                    evidence: Some("Sensitive file content returned for path traversal attempt".to_string()),
                    cwe: "CWE-22".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Validate all file paths against whitelist\n2. Use indirect file references (download tokens)\n3. Verify user authorization for each file access\n4. Strip path traversal sequences (../, .\\)\n5. Store files outside web root\n6. Use secure file serving libraries\n7. Log all file access attempts".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
        // REMOVED: The generic "Unauthorized File Access" check was causing false positives
        // It reported if body.len() > 1000 which matches basically every webpage
    }
}

fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "idor_{:08x}{:04x}{:04x}{:04x}{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::{HttpClient, HttpResponse};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_numeric_id_detection() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"{"id": 12345, "username": "john", "email": "john@example.com"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_numeric_ids(&response, "https://example.com/api/user/12345", &mut vulns);

        assert!(vulns.len() >= 1, "Should detect numeric ID vulnerability");
    }

    #[tokio::test]
    async fn test_sequential_access_detection() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"{"user": "alice", "email": "alice@example.com", "profile": "data", "id": 123}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sequential_access(&response, "https://example.com/user/2", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect BOLA via sequential access");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn test_horizontal_escalation() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"{"id": 999999, "email": "victim@example.com", "ssn": "123-45-6789", "address": "123 Main St", "user": "victim"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_horizontal_escalation(&response, "https://example.com/api/user?user_id=999999", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect horizontal privilege escalation");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_vertical_escalation() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <h1>Admin Panel</h1>
                <div>Manage Users</div>
                <button>Delete User</button>
                <button>System Settings</button>
            "#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_vertical_escalation(&response, "https://example.com/admin?role=admin", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect vertical privilege escalation");
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert!(vulns[0].verified);
    }

    #[tokio::test]
    async fn test_file_access_control() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let mut headers = HashMap::new();
        headers.insert("content-disposition".to_string(), "attachment; filename=invoice.pdf".to_string());
        headers.insert("content-type".to_string(), "application/pdf".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: "%PDF-1.4 file content here...".to_string(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_file_access_control(&response, "https://example.com/download?file=invoice_12345.pdf", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect unauthorized file access");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
