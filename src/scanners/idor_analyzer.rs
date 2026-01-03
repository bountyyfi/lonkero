// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! IDOR/BOLA Security Analyzer
//!
//! Tests for Insecure Direct Object References (IDOR) and
//! Broken Object Level Authorization (BOLA) vulnerabilities.
//!
//! Features:
//! - Multi-user authorization testing
//! - Object ID enumeration and access testing
//! - Horizontal privilege escalation (user A accessing user B's data)
//! - Vertical privilege escalation (user accessing admin endpoints)
//! - API endpoint authorization testing

use crate::auth_context::AuthSession;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

/// Common patterns that indicate object IDs in URLs and responses
const ID_PATTERNS: &[&str] = &[
    r"/(\d+)(?:/|$|\?)",          // /123, /123/, /123?
    r"/([a-f0-9]{24})(?:/|$|\?)", // MongoDB ObjectId
    r"/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$|\?)", // UUID
    r"[?&]id=(\d+)",              // ?id=123
    r"[?&]user_id=(\d+)",         // ?user_id=123
    r"[?&]userId=(\d+)",          // ?userId=123
    r"[?&]account[_-]?id=(\d+)",  // ?account_id=123
    r"[?&]order[_-]?id=(\d+)",    // ?order_id=123
    r"[?&]doc[_-]?id=(\d+)",      // ?doc_id=123
    r"[?&]file[_-]?id=(\d+)",     // ?file_id=123
];

/// API endpoints commonly vulnerable to IDOR
const SENSITIVE_ENDPOINTS: &[&str] = &[
    "/api/users/",
    "/api/user/",
    "/api/profile/",
    "/api/account/",
    "/api/orders/",
    "/api/order/",
    "/api/documents/",
    "/api/files/",
    "/api/messages/",
    "/api/notifications/",
    "/api/settings/",
    "/api/invoices/",
    "/api/payments/",
    "/api/subscriptions/",
    "/users/",
    "/user/",
    "/profile/",
    "/account/",
    "/admin/",
];

/// Extracted object reference from URL or response
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ObjectReference {
    pub id: String,
    pub id_type: ObjectIdType,
    pub source_url: String,
    pub context: String, // e.g., "url_path", "query_param", "response_body"
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum ObjectIdType {
    Numeric,
    Uuid,
    MongoId,
    Unknown,
}

impl ObjectIdType {
    fn from_id(id: &str) -> Self {
        if id.chars().all(|c| c.is_ascii_digit()) {
            ObjectIdType::Numeric
        } else if id.len() == 36 && id.chars().filter(|c| *c == '-').count() == 4 {
            ObjectIdType::Uuid
        } else if id.len() == 24 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            ObjectIdType::MongoId
        } else {
            ObjectIdType::Unknown
        }
    }
}

/// IDOR/BOLA Security Analyzer
pub struct IdorAnalyzer {
    http_client: Arc<HttpClient>,
    id_patterns: Vec<Regex>,
}

impl IdorAnalyzer {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let id_patterns = ID_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self {
            http_client,
            id_patterns,
        }
    }

    /// Analyze for IDOR vulnerabilities using two user sessions
    pub async fn analyze_with_users(
        &self,
        url: &str,
        user_a: &AuthSession,
        user_b: &AuthSession,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[IDOR] Starting multi-user authorization analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Step 1: Crawl as User A and collect object IDs
        info!("[IDOR] Collecting User A's object references...");
        let user_a_objects = self.collect_user_objects(url, user_a).await?;
        tests_run += 1;

        info!(
            "[IDOR] Found {} object references for User A",
            user_a_objects.len()
        );

        // Step 2: Crawl as User B and collect object IDs
        info!("[IDOR] Collecting User B's object references...");
        let user_b_objects = self.collect_user_objects(url, user_b).await?;
        tests_run += 1;

        info!(
            "[IDOR] Found {} object references for User B",
            user_b_objects.len()
        );

        // Step 3: Test horizontal privilege escalation
        // Try to access User A's objects as User B
        info!("[IDOR] Testing horizontal privilege escalation...");
        let horizontal_vulns = self
            .test_horizontal_access(&user_a_objects, user_b, url)
            .await?;
        tests_run += user_a_objects.len();
        vulnerabilities.extend(horizontal_vulns);

        // Also test User B's objects as User A
        let horizontal_vulns_rev = self
            .test_horizontal_access(&user_b_objects, user_a, url)
            .await?;
        tests_run += user_b_objects.len();
        vulnerabilities.extend(horizontal_vulns_rev);

        // Step 4: Test ID enumeration on sensitive endpoints
        info!("[IDOR] Testing ID enumeration...");
        let enum_vulns = self.test_id_enumeration(url, user_a).await?;
        tests_run += SENSITIVE_ENDPOINTS.len();
        vulnerabilities.extend(enum_vulns);

        // Step 5: Test unauthorized access patterns
        info!("[IDOR] Testing unauthorized access patterns...");
        let unauth_vulns = self.test_unauthorized_patterns(url, user_a).await?;
        tests_run += 1;
        vulnerabilities.extend(unauth_vulns);

        info!(
            "[IDOR] Analysis complete: {} tests, {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );
        Ok((vulnerabilities, tests_run))
    }

    /// Single-user IDOR analysis (without second user context)
    pub async fn analyze_single_user(
        &self,
        url: &str,
        session: &AuthSession,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[IDOR] Starting single-user IDOR analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Collect user's objects
        let user_objects = self.collect_user_objects(url, session).await?;
        tests_run += 1;

        // Test ID manipulation (increment/decrement IDs)
        info!("[IDOR] Testing ID manipulation...");
        for obj_ref in &user_objects {
            if obj_ref.id_type == ObjectIdType::Numeric {
                if let Ok(id_num) = obj_ref.id.parse::<i64>() {
                    // Try adjacent IDs
                    for delta in &[-1i64, 1, -10, 10, -100, 100] {
                        let test_id = (id_num + delta).to_string();
                        let test_url = obj_ref.source_url.replace(&obj_ref.id, &test_id);

                        if let Ok(response) =
                            self.http_client.get_authenticated(&test_url, session).await
                        {
                            tests_run += 1;

                            if self.indicates_data_access(&response.body, response.status_code) {
                                // Check if it's different data than original
                                let original_response = self
                                    .http_client
                                    .get_authenticated(&obj_ref.source_url, session)
                                    .await?;

                                if response.body != original_response.body
                                    && response.status_code == 200
                                {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("idor-enum-{}", uuid::Uuid::new_v4()),
                                        vuln_type: "IDOR via ID Enumeration".to_string(),
                                        severity: Severity::High,
                                        confidence: Confidence::Medium,
                                        category: "Broken Access Control".to_string(),
                                        url: test_url.clone(),
                                        parameter: Some(format!("ID: {}", test_id)),
                                        payload: format!("Original ID: {}, Test ID: {}", obj_ref.id, test_id),
                                        description: format!(
                                            "Able to access other objects by manipulating ID. Original: {}, Tested: {}",
                                            obj_ref.id, test_id
                                        ),
                                        evidence: Some(format!("Accessed different data with ID {}", test_id)),
                                        cwe: "CWE-639".to_string(),
                                        cvss: 7.5,
                                        verified: true,
                                        false_positive: false,
                                        remediation: "Implement proper object-level authorization checks. Verify the requesting user owns or has permission to access the requested object.".to_string(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                                    });
                                    break; // Found one, don't spam
                                }
                            }
                        }
                    }
                }
            }
        }

        // Test ID enumeration on sensitive endpoints
        let enum_vulns = self.test_id_enumeration(url, session).await?;
        tests_run += SENSITIVE_ENDPOINTS.len();
        vulnerabilities.extend(enum_vulns);

        info!(
            "[IDOR] Analysis complete: {} tests, {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );
        Ok((vulnerabilities, tests_run))
    }

    /// Collect object references for a user
    async fn collect_user_objects(
        &self,
        base_url: &str,
        session: &AuthSession,
    ) -> Result<HashSet<ObjectReference>> {
        let mut objects = HashSet::new();

        // Test common API endpoints
        for endpoint in SENSITIVE_ENDPOINTS {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            if let Ok(response) = self.http_client.get_authenticated(&test_url, session).await {
                if response.status_code == 200 {
                    // Extract IDs from response body
                    let body_objects =
                        self.extract_ids_from_text(&response.body, &test_url, "response_body");
                    objects.extend(body_objects);
                }
            }
        }

        // Also check the main URL
        if let Ok(response) = self.http_client.get_authenticated(base_url, session).await {
            let main_objects = self.extract_ids_from_text(&response.body, base_url, "main_page");
            objects.extend(main_objects);
        }

        Ok(objects)
    }

    /// Extract object IDs from text
    fn extract_ids_from_text(
        &self,
        text: &str,
        source_url: &str,
        context: &str,
    ) -> Vec<ObjectReference> {
        let mut refs = Vec::new();

        for pattern in &self.id_patterns {
            for cap in pattern.captures_iter(text) {
                if let Some(id_match) = cap.get(1) {
                    let id = id_match.as_str().to_string();

                    // Skip very common false positives
                    if id == "0" || id == "1" || id.len() > 100 {
                        continue;
                    }

                    refs.push(ObjectReference {
                        id: id.clone(),
                        id_type: ObjectIdType::from_id(&id),
                        source_url: source_url.to_string(),
                        context: context.to_string(),
                    });
                }
            }
        }

        // Also look for common JSON patterns
        let json_patterns = [
            (r#""id"\s*:\s*(\d+)"#, "json_id"),
            (r#""user_id"\s*:\s*(\d+)"#, "json_user_id"),
            (r#""userId"\s*:\s*(\d+)"#, "json_userId"),
            (r#""account_id"\s*:\s*(\d+)"#, "json_account_id"),
            (r#""_id"\s*:\s*"([a-f0-9]{24})""#, "json_mongo_id"),
        ];

        for (pattern, ctx) in &json_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(text) {
                    if let Some(id_match) = cap.get(1) {
                        let id = id_match.as_str().to_string();
                        if id != "0" && id != "1" {
                            refs.push(ObjectReference {
                                id: id.clone(),
                                id_type: ObjectIdType::from_id(&id),
                                source_url: source_url.to_string(),
                                context: ctx.to_string(),
                            });
                        }
                    }
                }
            }
        }

        refs
    }

    /// Test if User B can access User A's objects
    async fn test_horizontal_access(
        &self,
        user_a_objects: &HashSet<ObjectReference>,
        user_b_session: &AuthSession,
        base_url: &str,
    ) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for obj_ref in user_a_objects {
            // Construct URL with the object ID
            let test_urls = self.construct_test_urls(base_url, &obj_ref.id);

            for test_url in test_urls {
                if let Ok(response) = self
                    .http_client
                    .get_authenticated(&test_url, user_b_session)
                    .await
                {
                    if self.indicates_data_access(&response.body, response.status_code) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("idor-horizontal-{}", uuid::Uuid::new_v4()),
                            vuln_type: "Horizontal Privilege Escalation (IDOR)".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Broken Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: Some(format!("Object ID: {}", obj_ref.id)),
                            payload: format!("Accessed object {} as different user", obj_ref.id),
                            description: format!(
                                "User B can access User A's object (ID: {}). This indicates missing authorization checks.",
                                obj_ref.id
                            ),
                            evidence: Some(format!(
                                "Successfully accessed object {} as different user (status: {})",
                                obj_ref.id, response.status_code
                            )),
                            cwe: "CWE-639".to_string(),
                            cvss: 8.1,
                            verified: true,
                            false_positive: false,
                            remediation: "Implement object-level authorization. Verify the requesting user has permission to access each object before returning data.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                        break; // One finding per object is enough
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Test ID enumeration on sensitive endpoints
    async fn test_id_enumeration(
        &self,
        base_url: &str,
        session: &AuthSession,
    ) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test sequential IDs starting from 1
        let test_ids = vec!["1", "2", "100", "1000"];

        for endpoint in SENSITIVE_ENDPOINTS {
            for test_id in &test_ids {
                let test_url = format!("{}{}{}", base_url.trim_end_matches('/'), endpoint, test_id);

                if let Ok(response) = self.http_client.get_authenticated(&test_url, session).await {
                    if self.indicates_data_access(&response.body, response.status_code) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("idor-endpoint-{}", uuid::Uuid::new_v4()),
                            vuln_type: "IDOR on Sensitive Endpoint".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Broken Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: Some(format!("ID: {}", test_id)),
                            payload: format!("GET {}{}", endpoint, test_id),
                            description: format!(
                                "Endpoint {} allows access to arbitrary objects via ID enumeration",
                                endpoint
                            ),
                            evidence: Some(format!("Accessed {} with ID {} (status: {})", endpoint, test_id, response.status_code)),
                            cwe: "CWE-639".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Add authorization checks before returning object data. Ensure users can only access objects they own or have explicit permission to view.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                        break; // One per endpoint
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Test unauthorized access patterns
    async fn test_unauthorized_patterns(
        &self,
        base_url: &str,
        session: &AuthSession,
    ) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Admin-only endpoints to test
        let admin_endpoints = [
            "/admin",
            "/admin/",
            "/api/admin",
            "/api/admin/",
            "/admin/users",
            "/api/admin/users",
            "/admin/settings",
            "/admin/dashboard",
            "/management",
            "/api/management",
        ];

        for endpoint in &admin_endpoints {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            if let Ok(response) = self.http_client.get_authenticated(&test_url, session).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("admin")
                        || body_lower.contains("dashboard")
                        || body_lower.contains("users")
                        || body_lower.contains("settings")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: format!("idor-vertical-{}", uuid::Uuid::new_v4()),
                            vuln_type: "Vertical Privilege Escalation".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::Medium,
                            category: "Broken Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: format!("GET {}", endpoint),
                            description: format!(
                                "Non-admin user can access admin endpoint: {}",
                                endpoint
                            ),
                            evidence: Some(format!("Admin endpoint accessible (status: {})", response.status_code)),
                            cwe: "CWE-862".to_string(),
                            cvss: 9.1,
                            verified: true,
                            false_positive: false,
                            remediation: "Implement role-based access control. Admin endpoints should verify the requesting user has admin privileges before allowing access.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Construct test URLs with the given ID
    fn construct_test_urls(&self, base_url: &str, id: &str) -> Vec<String> {
        let mut urls = Vec::new();
        let base = base_url.trim_end_matches('/');

        // Common patterns
        urls.push(format!("{}/api/users/{}", base, id));
        urls.push(format!("{}/api/user/{}", base, id));
        urls.push(format!("{}/users/{}", base, id));
        urls.push(format!("{}/api/profile/{}", base, id));
        urls.push(format!("{}/api/account/{}", base, id));
        urls.push(format!("{}/api/data/{}", base, id));
        urls.push(format!("{}?id={}", base, id));
        urls.push(format!("{}?user_id={}", base, id));

        urls
    }

    /// Check if response indicates successful data access
    fn indicates_data_access(&self, body: &str, status: u16) -> bool {
        if status != 200 {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Positive indicators
        let positive = body_lower.contains("\"id\"")
            || body_lower.contains("\"user\"")
            || body_lower.contains("\"data\"")
            || body_lower.contains("\"email\"")
            || body_lower.contains("\"name\"")
            || body_lower.contains("\"profile\"");

        // Negative indicators (error messages)
        let negative = body_lower.contains("not found")
            || body_lower.contains("unauthorized")
            || body_lower.contains("forbidden")
            || body_lower.contains("access denied")
            || body_lower.contains("permission");

        positive && !negative
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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

    #[test]
    fn test_id_type_detection() {
        assert!(matches!(
            ObjectIdType::from_id("12345"),
            ObjectIdType::Numeric
        ));
        assert!(matches!(
            ObjectIdType::from_id("507f1f77bcf86cd799439011"),
            ObjectIdType::MongoId
        ));
        assert!(matches!(
            ObjectIdType::from_id("550e8400-e29b-41d4-a716-446655440000"),
            ObjectIdType::Uuid
        ));
    }
}
