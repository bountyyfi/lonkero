// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - BOLA (Broken Object Level Authorization) Scanner
 * Advanced testing for object-level authorization vulnerabilities
 *
 * Tests for horizontal privilege escalation where authenticated users can access
 * other users' resources by manipulating object IDs in API requests.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// BOLA (Broken Object Level Authorization) Scanner
///
/// This scanner identifies endpoints where authorization checks are missing or improperly
/// implemented, allowing users to access objects belonging to other users.
pub struct BolaScanner {
    http_client: Arc<HttpClient>,
}

impl BolaScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    ///
    /// Tests for BOLA vulnerabilities by:
    /// 1. Identifying endpoints with object IDs
    /// 2. Testing with different ID values
    /// 3. Analyzing response patterns for authorization bypass
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            info!("[SKIP] BOLA scanning requires valid license");
            return Ok((Vec::new(), 0));
        }

        info!("Starting BOLA (Broken Object Level Authorization) scan on {}", url);

        // Intelligent detection - skip if no auth context
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.should_skip_auth_tests() {
                info!("[BOLA] Skipping - no authentication detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Phase 1: Detect API endpoints with object IDs
        let endpoints = self.detect_object_id_endpoints(url).await?;

        if endpoints.is_empty() {
            debug!("No object ID endpoints detected");
            return Ok((vulnerabilities, tests_run));
        }

        info!("Detected {} potential BOLA test endpoints", endpoints.len());

        // Phase 2: Test numeric ID manipulation
        for endpoint in &endpoints {
            if endpoint.id_type == IdType::Numeric {
                tests_run += 1;
                if let Some(vuln) = self.test_numeric_id_bola(endpoint).await? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        // Phase 3: Test UUID manipulation
        for endpoint in &endpoints {
            if endpoint.id_type == IdType::Uuid {
                tests_run += 1;
                if let Some(vuln) = self.test_uuid_bola(endpoint).await? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        // Phase 4: Test query parameter ID manipulation
        for endpoint in &endpoints {
            if endpoint.id_type == IdType::QueryParam {
                tests_run += 1;
                if let Some(vuln) = self.test_query_param_bola(endpoint).await? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        // Phase 5: Test ID array/batch operations
        tests_run += 1;
        if let Ok(vulns) = self.test_batch_id_access(url).await {
            vulnerabilities.extend(vulns);
        }

        // Phase 6: Test ID wildcard/enumeration
        tests_run += 1;
        if let Ok(vulns) = self.test_id_enumeration(url).await {
            vulnerabilities.extend(vulns);
        }

        info!(
            "BOLA scan completed: {} tests run, {} vulnerabilities found",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect endpoints that contain object IDs
    async fn detect_object_id_endpoints(&self, url: &str) -> Result<Vec<ObjectEndpoint>> {
        let mut endpoints = Vec::new();

        // Common API patterns with numeric IDs
        let numeric_patterns = vec![
            (r"/api/users/(\d+)", "user"),
            (r"/api/v\d+/users/(\d+)", "user"),
            (r"/users/(\d+)", "user"),
            (r"/api/accounts/(\d+)", "account"),
            (r"/api/v\d+/accounts/(\d+)", "account"),
            (r"/accounts/(\d+)", "account"),
            (r"/api/orders/(\d+)", "order"),
            (r"/orders/(\d+)", "order"),
            (r"/api/invoices/(\d+)", "invoice"),
            (r"/invoices/(\d+)", "invoice"),
            (r"/api/documents/(\d+)", "document"),
            (r"/documents/(\d+)", "document"),
            (r"/api/files/(\d+)", "file"),
            (r"/files/(\d+)", "file"),
            (r"/api/profiles/(\d+)", "profile"),
            (r"/profiles/(\d+)", "profile"),
            (r"/api/posts/(\d+)", "post"),
            (r"/posts/(\d+)", "post"),
            (r"/api/comments/(\d+)", "comment"),
            (r"/comments/(\d+)", "comment"),
        ];

        // Test numeric ID patterns
        for (pattern_str, resource_type) in &numeric_patterns {
            let pattern = Regex::new(pattern_str)?;
            if let Some(captures) = pattern.captures(url) {
                if let Some(id_match) = captures.get(1) {
                    let id_value = id_match.as_str();
                    endpoints.push(ObjectEndpoint {
                        url: url.to_string(),
                        id_value: id_value.to_string(),
                        id_type: IdType::Numeric,
                        resource_type: resource_type.to_string(),
                        pattern: pattern_str.to_string(),
                    });
                    debug!("Detected numeric ID endpoint: {} (ID: {})", url, id_value);
                }
            }
        }

        // UUID patterns
        let uuid_pattern = Regex::new(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")?;
        if let Some(captures) = uuid_pattern.captures(url) {
            if let Some(uuid_match) = captures.get(1) {
                let uuid_value = uuid_match.as_str();
                endpoints.push(ObjectEndpoint {
                    url: url.to_string(),
                    id_value: uuid_value.to_string(),
                    id_type: IdType::Uuid,
                    resource_type: "resource".to_string(),
                    pattern: uuid_pattern.as_str().to_string(),
                });
                debug!("Detected UUID endpoint: {} (UUID: {})", url, uuid_value);
            }
        }

        // Query parameter patterns
        let query_patterns = vec![
            (r"[?&]id=(\d+)", "id"),
            (r"[?&]user_id=(\d+)", "user_id"),
            (r"[?&]userId=(\d+)", "userId"),
            (r"[?&]account_id=(\d+)", "account_id"),
            (r"[?&]accountId=(\d+)", "accountId"),
            (r"[?&]order_id=(\d+)", "order_id"),
            (r"[?&]orderId=(\d+)", "orderId"),
            (r"[?&]document_id=(\d+)", "document_id"),
            (r"[?&]documentId=(\d+)", "documentId"),
        ];

        for (pattern_str, param_name) in &query_patterns {
            let pattern = Regex::new(pattern_str)?;
            if let Some(captures) = pattern.captures(url) {
                if let Some(id_match) = captures.get(1) {
                    let id_value = id_match.as_str();
                    endpoints.push(ObjectEndpoint {
                        url: url.to_string(),
                        id_value: id_value.to_string(),
                        id_type: IdType::QueryParam,
                        resource_type: param_name.to_string(),
                        pattern: pattern_str.to_string(),
                    });
                    debug!("Detected query param endpoint: {} (Param: {}, ID: {})", url, param_name, id_value);
                }
            }
        }

        Ok(endpoints)
    }

    /// Test BOLA vulnerability with numeric ID manipulation
    async fn test_numeric_id_bola(&self, endpoint: &ObjectEndpoint) -> Result<Option<Vulnerability>> {
        debug!("Testing numeric ID BOLA: {}", endpoint.url);

        // Parse the current ID
        let current_id: i64 = endpoint.id_value.parse()?;

        // Generate test IDs
        let test_ids = vec![
            current_id + 1,          // Next sequential ID
            current_id - 1,          // Previous sequential ID
            current_id + 10,         // Skip ahead
            current_id * 2,          // Different user range
            1,                        // First ID
            999999,                   // High ID
        ];

        // Get baseline response
        let baseline = match self.http_client.get(&endpoint.url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline response: {}", e);
                return Ok(None);
            }
        };

        // Only test if baseline is successful
        if baseline.status_code != 200 {
            debug!("Baseline returned non-200 status: {}", baseline.status_code);
            return Ok(None);
        }

        // Test each ID variation
        for test_id in test_ids {
            let test_url = endpoint.url.replace(&endpoint.id_value, &test_id.to_string());

            match self.http_client.get(&test_url).await {
                Ok(test_response) => {
                    // Check for BOLA vulnerability indicators
                    if self.is_bola_vulnerable(&baseline, &test_response, &endpoint.resource_type) {
                        return Ok(Some(self.create_bola_vulnerability(
                            &endpoint.url,
                            &test_url,
                            &endpoint.id_value,
                            &test_id.to_string(),
                            &endpoint.resource_type,
                            &baseline,
                            &test_response,
                        )));
                    }
                }
                Err(e) => {
                    debug!("Test request failed for ID {}: {}", test_id, e);
                }
            }
        }

        Ok(None)
    }

    /// Test BOLA vulnerability with UUID manipulation
    async fn test_uuid_bola(&self, endpoint: &ObjectEndpoint) -> Result<Option<Vulnerability>> {
        debug!("Testing UUID BOLA: {}", endpoint.url);

        // Get baseline response
        let baseline = match self.http_client.get(&endpoint.url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline response: {}", e);
                return Ok(None);
            }
        };

        if baseline.status_code != 200 {
            return Ok(None);
        }

        // Generate test UUIDs by manipulating the original
        let test_uuids = self.generate_test_uuids(&endpoint.id_value);

        for test_uuid in test_uuids {
            let test_url = endpoint.url.replace(&endpoint.id_value, &test_uuid);

            match self.http_client.get(&test_url).await {
                Ok(test_response) => {
                    if self.is_bola_vulnerable(&baseline, &test_response, &endpoint.resource_type) {
                        return Ok(Some(self.create_bola_vulnerability(
                            &endpoint.url,
                            &test_url,
                            &endpoint.id_value,
                            &test_uuid,
                            &endpoint.resource_type,
                            &baseline,
                            &test_response,
                        )));
                    }
                }
                Err(e) => {
                    debug!("Test request failed for UUID {}: {}", test_uuid, e);
                }
            }
        }

        Ok(None)
    }

    /// Test BOLA vulnerability via query parameter manipulation
    async fn test_query_param_bola(&self, endpoint: &ObjectEndpoint) -> Result<Option<Vulnerability>> {
        debug!("Testing query param BOLA: {}", endpoint.url);

        // Parse current ID from URL
        let current_id: i64 = endpoint.id_value.parse()?;

        // Get baseline
        let baseline = match self.http_client.get(&endpoint.url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline response: {}", e);
                return Ok(None);
            }
        };

        if baseline.status_code != 200 {
            return Ok(None);
        }

        // Test different IDs
        let test_ids = vec![current_id + 1, current_id - 1, 1, 999];

        for test_id in test_ids {
            let test_url = endpoint.url.replace(&endpoint.id_value, &test_id.to_string());

            match self.http_client.get(&test_url).await {
                Ok(test_response) => {
                    if self.is_bola_vulnerable(&baseline, &test_response, &endpoint.resource_type) {
                        return Ok(Some(self.create_bola_vulnerability(
                            &endpoint.url,
                            &test_url,
                            &endpoint.id_value,
                            &test_id.to_string(),
                            &endpoint.resource_type,
                            &baseline,
                            &test_response,
                        )));
                    }
                }
                Err(e) => {
                    debug!("Test request failed for ID {}: {}", test_id, e);
                }
            }
        }

        Ok(None)
    }

    /// Test batch ID access (array of IDs)
    async fn test_batch_id_access(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test batch endpoints
        let batch_patterns = vec![
            format!("{}?ids=1,2,3,4,5", url.trim_end_matches('/')),
            format!("{}?ids[]=1&ids[]=2&ids[]=3", url.trim_end_matches('/')),
            format!("{}/batch?ids=1,2,3", url.trim_end_matches('/')),
        ];

        for test_url in batch_patterns {
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && self.contains_multiple_objects(&response.body) {
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "BOLA - Batch Object Access Without Authorization".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "Authorization".to_string(),
                        url: test_url.clone(),
                        parameter: Some("ids".to_string()),
                        payload: "ids=1,2,3,4,5".to_string(),
                        description: "API endpoint allows batch access to multiple objects without proper authorization checks. Attackers can retrieve data for multiple users/resources in a single request.".to_string(),
                        evidence: Some(format!("Batch endpoint returned {} objects without authorization", self.count_objects(&response.body))),
                        cwe: "CWE-639".to_string(),
                        cvss: 8.6,
                        verified: true,
                        false_positive: false,
                        remediation: "1. CRITICAL: Implement authorization checks for each object in batch requests\n2. Verify user has permission to access each requested ID\n3. Implement rate limiting for batch endpoints\n4. Limit maximum number of IDs per batch request\n5. Return only authorized objects, not errors for unauthorized ones\n6. Log batch access attempts for security monitoring\n7. Consider implementing pagination instead of batch access".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Test ID enumeration vulnerabilities
    async fn test_id_enumeration(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test if we can enumerate valid IDs by response differences
        let mut response_patterns: HashMap<u16, usize> = HashMap::new();

        for test_id in 1..=20 {
            let test_url = if url.contains('?') {
                format!("{}&id={}", url, test_id)
            } else {
                format!("{}?id={}", url, test_id)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                *response_patterns.entry(response.status_code).or_insert(0) += 1;
            }
        }

        // If we see both 200 and 404 responses, enumeration is possible
        if response_patterns.contains_key(&200) &&
           (response_patterns.contains_key(&404) || response_patterns.contains_key(&403)) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "BOLA - Object ID Enumeration Possible".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "Authorization".to_string(),
                url: url.to_string(),
                parameter: Some("id".to_string()),
                payload: "Sequential ID testing (1-20)".to_string(),
                description: "API reveals which object IDs exist through different response codes. Attackers can enumerate valid IDs and then attempt to access them. This leaks information about database contents and enables targeted attacks.".to_string(),
                evidence: Some(format!("Different status codes observed: {:?}", response_patterns)),
                cwe: "CWE-639".to_string(),
                cvss: 6.5,
                verified: true,
                false_positive: false,
                remediation: "1. Return consistent responses for both existing and non-existing objects\n2. Use 404 for all unauthorized/non-existing resources\n3. Implement rate limiting to prevent enumeration\n4. Use non-sequential UUIDs instead of numeric IDs\n5. Add delays or CAPTCHA after repeated failed access attempts\n6. Monitor for enumeration patterns in logs\n7. Consider using HMACs to sign object references".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        Ok(vulnerabilities)
    }

    /// Check if response indicates BOLA vulnerability
    fn is_bola_vulnerable(
        &self,
        baseline: &crate::http_client::HttpResponse,
        test_response: &crate::http_client::HttpResponse,
        resource_type: &str,
    ) -> bool {
        // Condition 1: Both requests returned 200 OK
        if test_response.status_code != 200 {
            return false;
        }

        // Condition 2: Should have returned 403 or 401 but didn't
        let missing_auth_check = test_response.status_code == 200;

        // Condition 3: Responses have similar structure but different data
        let responses_differ = baseline.body != test_response.body;
        let similar_size = {
            let baseline_size = baseline.body.len();
            let test_size = test_response.body.len();
            let diff_ratio = baseline_size.max(test_size) as f64 / baseline_size.min(test_size).max(1) as f64;
            diff_ratio < 3.0 // Within 3x size difference
        };

        // Condition 4: Response contains resource-specific data
        let contains_user_data = self.contains_sensitive_data(&test_response.body, resource_type);

        // Condition 5: Response doesn't contain error messages
        let no_error_indicators = !self.contains_error_messages(&test_response.body);

        // BOLA is likely if:
        // - Both returned 200
        // - Bodies are different (different user's data)
        // - Similar response structure
        // - Contains sensitive data
        // - No error messages
        missing_auth_check
            && responses_differ
            && similar_size
            && contains_user_data
            && no_error_indicators
    }

    /// Check if response contains sensitive user data
    fn contains_sensitive_data(&self, body: &str, resource_type: &str) -> bool {
        let sensitive_fields = vec![
            "email", "phone", "address", "ssn", "password",
            "credit_card", "card_number", "account_number",
            "balance", "salary", "income", "dob", "birth",
            "firstName", "lastName", "fullName", "username",
            "user_id", "userId", "account_id", "accountId",
        ];

        // Check for resource-specific patterns
        let resource_indicators = match resource_type {
            "user" | "profile" => vec!["email", "username", "firstName", "lastName"],
            "account" => vec!["balance", "account_number", "account_id"],
            "order" | "invoice" => vec!["total", "amount", "price", "payment"],
            "document" | "file" => vec!["filename", "content", "data"],
            _ => vec!["id", "name"],
        };

        // Check for sensitive fields
        let has_sensitive = sensitive_fields.iter().any(|&field| body.contains(field));
        let has_resource_data = resource_indicators.iter().any(|&field| body.contains(field));

        has_sensitive || has_resource_data
    }

    /// Check if response contains error messages
    fn contains_error_messages(&self, body: &str) -> bool {
        let error_indicators = vec![
            "error", "unauthorized", "forbidden", "access denied",
            "not found", "invalid", "denied", "restricted",
            "permission", "not authorized", "authentication required",
        ];

        let body_lower = body.to_lowercase();
        error_indicators.iter().any(|&indicator| body_lower.contains(indicator))
    }

    /// Check if body contains multiple objects
    fn contains_multiple_objects(&self, body: &str) -> bool {
        // Check for JSON arrays with multiple objects
        if body.trim().starts_with('[') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(array) = json.as_array() {
                    return array.len() > 1;
                }
            }
        }

        // Check for common batch response patterns
        body.contains(r#""data":[{"#) ||
        body.contains(r#""items":[{"#) ||
        body.contains(r#""results":[{"#)
    }

    /// Count objects in response
    fn count_objects(&self, body: &str) -> usize {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(array) = json.as_array() {
                return array.len();
            }
            if let Some(obj) = json.as_object() {
                for key in &["data", "items", "results"] {
                    if let Some(arr) = obj.get(*key).and_then(|v| v.as_array()) {
                        return arr.len();
                    }
                }
            }
        }
        0
    }

    /// Generate test UUIDs by manipulating the original
    fn generate_test_uuids(&self, original_uuid: &str) -> Vec<String> {
        let mut test_uuids = Vec::new();

        // Modify last character
        let mut chars: Vec<char> = original_uuid.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'f' { '0' } else { 'f' };
            test_uuids.push(chars.iter().collect());
        }

        // Modify first character after last dash
        let parts: Vec<&str> = original_uuid.split('-').collect();
        if parts.len() == 5 {
            let modified = format!(
                "{}-{}-{}-{}-{}",
                parts[0], parts[1], parts[2], parts[3],
                if parts[4].starts_with('f') {
                    format!("0{}", &parts[4][1..])
                } else {
                    format!("f{}", &parts[4][1..])
                }
            );
            test_uuids.push(modified);
        }

        // All zeros UUID (often used as default/test)
        test_uuids.push("00000000-0000-0000-0000-000000000000".to_string());

        // All ones UUID
        test_uuids.push("11111111-1111-1111-1111-111111111111".to_string());

        test_uuids
    }

    /// Create BOLA vulnerability record
    fn create_bola_vulnerability(
        &self,
        original_url: &str,
        _test_url: &str,
        original_id: &str,
        test_id: &str,
        resource_type: &str,
        baseline: &crate::http_client::HttpResponse,
        test_response: &crate::http_client::HttpResponse,
    ) -> Vulnerability {
        let evidence = format!(
            "Original request (ID: {}) returned {} bytes with status 200. \
             Test request (ID: {}) also returned {} bytes with status 200. \
             Both responses contain {} data but with different content, indicating successful \
             unauthorized access to another user's {}.",
            original_id,
            baseline.body.len(),
            test_id,
            test_response.body.len(),
            resource_type,
            resource_type
        );

        Vulnerability {
            id: generate_uuid(),
            vuln_type: "BOLA - Broken Object Level Authorization".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Authorization".to_string(),
            url: original_url.to_string(),
            parameter: Some("id".to_string()),
            payload: format!("Original ID: {}, Accessible ID: {}", original_id, test_id),
            description: format!(
                "Critical BOLA vulnerability detected: The API endpoint allows unauthorized access to {} objects by manipulating ID parameters. \
                Users can access other users' {} data by simply changing the ID in the request. \
                This is a horizontal privilege escalation vulnerability that exposes sensitive data without proper authorization checks.",
                resource_type, resource_type
            ),
            evidence: Some(evidence),
            cwe: "CWE-639".to_string(),
            cvss: 8.6,
            verified: true,
            false_positive: false,
            remediation: format!(
                "1. CRITICAL: Implement object-level authorization checks for all {} access\n\
                 2. Verify the authenticated user has permission to access the requested {} ID\n\
                 3. Use user context from authentication token, not from request parameters\n\
                 4. Implement Access Control Lists (ACLs) or Role-Based Access Control (RBAC)\n\
                 5. Return 403 Forbidden for unauthorized access attempts\n\
                 6. Use indirect object references (session-based mappings) instead of direct IDs\n\
                 7. Implement attribute-based access control (ABAC) for fine-grained permissions\n\
                 8. Add authorization middleware/decorators on all API endpoints\n\
                 9. Log all unauthorized access attempts for security monitoring\n\
                 10. Consider using UUIDs instead of sequential IDs to prevent enumeration\n\
                 11. Implement defense in depth with multiple authorization layers\n\
                 12. Regular security audits and penetration testing\n\n\
                 Example (pseudocode):\n\
                 ```\n\
                 function get{}(id) {{\n\
                   const {} = await database.find(id);\n\
                   if (!{} || {}.userId !== currentUser.id) {{\n\
                     throw new UnauthorizedError();\n\
                   }}\n\
                   return {};\n\
                 }}\n\
                 ```",
                resource_type, resource_type, resource_type, resource_type,
                resource_type, resource_type, resource_type
            ),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Object endpoint information
#[derive(Debug, Clone)]
struct ObjectEndpoint {
    url: String,
    id_value: String,
    id_type: IdType,
    resource_type: String,
    pattern: String,
}

/// Type of ID detected
#[derive(Debug, Clone, PartialEq)]
enum IdType {
    Numeric,
    Uuid,
    QueryParam,
}

/// Generate unique vulnerability ID
fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "bola_{:08x}{:04x}{:04x}{:04x}{:012x}",
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

    fn create_test_scanner() -> BolaScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        BolaScanner::new(http_client)
    }

    #[test]
    fn test_contains_sensitive_data() {
        let scanner = create_test_scanner();

        assert!(scanner.contains_sensitive_data(
            r#"{"email":"test@example.com","username":"john"}"#,
            "user"
        ));

        assert!(scanner.contains_sensitive_data(
            r#"{"account_number":"123456","balance":1000}"#,
            "account"
        ));

        assert!(!scanner.contains_sensitive_data(
            r#"{"status":"ok"}"#,
            "user"
        ));
    }

    #[test]
    fn test_contains_error_messages() {
        let scanner = create_test_scanner();

        assert!(scanner.contains_error_messages("Error: Access denied"));
        assert!(scanner.contains_error_messages("Unauthorized access"));
        assert!(scanner.contains_error_messages("Permission required"));
        assert!(!scanner.contains_error_messages(r#"{"status":"success"}"#));
    }

    #[test]
    fn test_contains_multiple_objects() {
        let scanner = create_test_scanner();

        assert!(scanner.contains_multiple_objects(r#"[{"id":1},{"id":2}]"#));
        assert!(scanner.contains_multiple_objects(r#"{"data":[{"id":1},{"id":2}]}"#));
        assert!(!scanner.contains_multiple_objects(r#"{"id":1}"#));
        assert!(!scanner.contains_multiple_objects(r#"[]"#));
    }

    #[test]
    fn test_count_objects() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.count_objects(r#"[{"id":1},{"id":2},{"id":3}]"#), 3);
        assert_eq!(scanner.count_objects(r#"{"data":[{"id":1},{"id":2}]}"#), 2);
        assert_eq!(scanner.count_objects(r#"{"id":1}"#), 0);
    }

    #[test]
    fn test_generate_test_uuids() {
        let scanner = create_test_scanner();
        let original = "12345678-1234-1234-1234-123456789abc";
        let test_uuids = scanner.generate_test_uuids(original);

        assert!(!test_uuids.is_empty());
        assert!(test_uuids.iter().all(|uuid| uuid != original));
        assert!(test_uuids.contains(&"00000000-0000-0000-0000-000000000000".to_string()));
    }

    #[test]
    fn test_is_bola_vulnerable() {
        let scanner = create_test_scanner();

        let baseline = HttpResponse {
            status_code: 200,
            body: r#"{"id":1,"email":"user1@example.com","username":"user1"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        // Vulnerable: Different user data, both 200
        let vulnerable_response = HttpResponse {
            status_code: 200,
            body: r#"{"id":2,"email":"user2@example.com","username":"user2"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.is_bola_vulnerable(&baseline, &vulnerable_response, "user"));

        // Not vulnerable: 403 response
        let forbidden_response = HttpResponse {
            status_code: 403,
            body: "Access denied".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.is_bola_vulnerable(&baseline, &forbidden_response, "user"));

        // Not vulnerable: Error message
        let error_response = HttpResponse {
            status_code: 200,
            body: r#"{"error":"Unauthorized access"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.is_bola_vulnerable(&baseline, &error_response, "user"));
    }

    #[tokio::test]
    async fn test_detect_object_id_endpoints() {
        let scanner = create_test_scanner();

        // Test numeric ID detection
        let endpoints = scanner.detect_object_id_endpoints("https://api.example.com/api/users/123").await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id_type, IdType::Numeric);
        assert_eq!(endpoints[0].id_value, "123");

        // Test UUID detection
        let endpoints = scanner.detect_object_id_endpoints(
            "https://api.example.com/api/users/12345678-1234-1234-1234-123456789abc"
        ).await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id_type, IdType::Uuid);

        // Test query param detection
        let endpoints = scanner.detect_object_id_endpoints(
            "https://api.example.com/api/users?user_id=123"
        ).await.unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id_type, IdType::QueryParam);
    }
}
