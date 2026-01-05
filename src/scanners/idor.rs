// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - IDOR (Insecure Direct Object References) Scanner
 * Tests for authorization bypass via direct object reference manipulation
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::info;

pub struct IdorScanner {
    http_client: Arc<HttpClient>,
}

impl IdorScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Check for numeric ID patterns in URL/response
        // This runs regardless of auth since predictable IDs are always a concern
        tests_run += 1;
        let response = self.http_client.get(url).await?;
        let characteristics = AppCharacteristics::from_response(&response, url);
        let has_auth = !characteristics.should_skip_auth_tests();

        // Always check for numeric ID patterns - predictable IDs are a problem even without auth
        self.check_numeric_ids(&response, url, &mut vulnerabilities);

        // Test 2: Test predictable sequential IDs (always run - ID enumeration doesn't need auth)
        tests_run += 1;
        if let Ok(seq_response) = self.test_sequential_access(url).await {
            self.check_sequential_access(&seq_response, url, &mut vulnerabilities);
        }

        // Test 3: Test UUID predictability (always run - weak UUIDs are always a risk)
        tests_run += 1;
        if let Ok(uuid_response) = self.test_uuid_predictability(url).await {
            self.check_uuid_security(&uuid_response, url, &mut vulnerabilities);
        }

        // Test 4: Test horizontal privilege escalation (needs auth context)
        if has_auth {
            tests_run += 1;
            if let Ok(horiz_response) = self.test_horizontal_escalation(url).await {
                self.check_horizontal_escalation(&horiz_response, url, &mut vulnerabilities);
            }
        }

        // Test 5: Test vertical privilege escalation (needs auth context)
        if has_auth {
            tests_run += 1;
            if let Ok(vert_response) = self.test_vertical_escalation(url).await {
                self.check_vertical_escalation(&vert_response, url, &mut vulnerabilities);
            }
        }

        // Test 6: Test authorization headers (always run - missing auth enforcement is always bad)
        tests_run += 1;
        if let Ok(auth_response) = self.test_missing_authorization(url).await {
            self.check_authorization_enforcement(&auth_response, url, &mut vulnerabilities);
        }

        // Test 7: Test file access control (always run - file access issues are always a concern)
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
                ml_data: None,
                    });
                    break; // Only report once per response
                }
            }
        }

        // Check for exposed database IDs in JSON responses
        if body.contains("\"id\":")
            || body.contains("\"userId\":")
            || body.contains("\"accountId\":")
        {
            let json_id_regex =
                Regex::new(r#""(?:id|user_id|userId|account_id|accountId)":\s*(\d+)"#).unwrap();
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
                ml_data: None,
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
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // DISABLED: This check was causing false positives
        // Simply returning 200 with common words like "user", "account" doesn't prove IDOR
        // Real IDOR detection requires comparing authenticated vs. different user's data
        // which requires actual authentication context this scanner doesn't have
    }

    async fn test_uuid_predictability(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
        // Test if UUID v1 (time-based) is used, which can be predictable
        let uuid_regex =
            Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();

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
        let uuid_v1_regex =
            Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();

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
                ml_data: None,
            });
        }
    }

    async fn test_horizontal_escalation(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
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
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // DISABLED: This check was causing false positives
        // Presence of words like "email", "address", "phone" on a page doesn't prove IDOR
        // Real IDOR requires comparing data from authenticated session vs manipulated IDs
        // We cannot detect this without proper authentication context
    }

    async fn test_vertical_escalation(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
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
                ml_data: None,
            });
        }
    }

    async fn test_missing_authorization(
        &self,
        url: &str,
    ) -> Result<crate::http_client::HttpResponse> {
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
                ml_data: None,
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
                ml_data: None,
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
            body: r#"{"user": "alice", "email": "alice@example.com", "profile": "data"}"#
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sequential_access(&response, "https://example.com/user/2", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect IDOR via sequential access");
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert!(vulns[0].verified);
    }

    #[tokio::test]
    async fn test_horizontal_escalation() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body:
                r#"{"email": "victim@example.com", "ssn": "123-45-6789", "address": "123 Main St"}"#
                    .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_horizontal_escalation(
            &response,
            "https://example.com/api/user?user_id=999999",
            &mut vulns,
        );

        assert_eq!(
            vulns.len(),
            1,
            "Should detect horizontal privilege escalation"
        );
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
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_vertical_escalation(
            &response,
            "https://example.com/admin?role=admin",
            &mut vulns,
        );

        assert_eq!(
            vulns.len(),
            1,
            "Should detect vertical privilege escalation"
        );
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert!(vulns[0].verified);
    }

    #[tokio::test]
    async fn test_file_access_control() {
        let scanner = IdorScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let mut headers = HashMap::new();
        headers.insert(
            "content-disposition".to_string(),
            "attachment; filename=invoice.pdf".to_string(),
        );
        headers.insert("content-type".to_string(), "application/pdf".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: "%PDF-1.4 file content here...".to_string(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_file_access_control(
            &response,
            "https://example.com/download?file=invoice_12345.pdf",
            &mut vulns,
        );

        assert_eq!(vulns.len(), 1, "Should detect unauthorized file access");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
