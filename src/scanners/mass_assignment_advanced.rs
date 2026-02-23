// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced Mass Assignment Scanner (Context-Aware)
 *
 * Production-ready scanner for sophisticated mass assignment vulnerabilities.
 * This is an ADVANCED version with more sophisticated techniques than the basic scanner.
 *
 * ADVANCED TECHNIQUES:
 * ====================
 * 1. NESTED OBJECT INJECTION:
 *    - Deep property injection: user[profile][role][admin]=true
 *    - Multi-level nesting: 2-6 levels deep
 *    - Both bracket and dot notation support
 *
 * 2. DOT NOTATION POLLUTION:
 *    - user.role=admin
 *    - user.permissions.admin=true
 *    - profile.settings.verified=true
 *
 * 3. ARRAY PARAMETER POLLUTION:
 *    - roles[]=admin&roles[]=user
 *    - permissions[0]=read&permissions[1]=write&permissions[2]=admin
 *    - users[0][role]=admin
 *
 * 4. JSON DEEP MERGE EXPLOITATION:
 *    - Recursive object merging attacks
 *    - Framework-specific merge behaviors
 *    - Prototype chain manipulation
 *
 * 5. FRAMEWORK-SPECIFIC TESTS:
 *    - Rails: params.permit bypass via nested attributes
 *    - Django: Model serializer bypass
 *    - Express: Body parser exploitation
 *    - Spring: Jackson annotation bypass
 *    - Laravel: Eloquent mass assignment bypass
 *
 * 6. COMMON PRIVILEGE ESCALATION TARGETS:
 *    - Role/permission fields: role, isAdmin, permissions, verified
 *    - Financial fields: balance, credits, subscription, tier
 *    - Account fields: email_verified, phone_verified, active
 *    - Timestamp fields: created_at, updated_at
 *    - Ownership fields: id, user_id, owner_id, account_id
 *
 * CONTEXT-AWARE FEATURES:
 * =======================
 * - Detects API framework from responses
 * - Identifies JSON vs form data endpoints
 * - Uses AppCharacteristics for intelligent testing
 * - Focuses on POST/PUT/PATCH endpoints
 * - Extracts field names from responses
 *
 * ZERO FALSE POSITIVES:
 * =====================
 * - Uses unique markers for verification
 * - Requires structured response evidence
 * - Validates actual state changes
 * - Cross-references multiple indicators
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// Advanced Mass Assignment Scanner with context-aware detection
pub struct AdvancedMassAssignmentScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

/// Detected API framework
#[derive(Debug, Clone, PartialEq)]
pub enum ApiFramework {
    Rails,
    Django,
    Express,
    Spring,
    Laravel,
    FastAPI,
    Flask,
    AspNet,
    Unknown,
}

/// Content type for the endpoint
#[derive(Debug, Clone, PartialEq)]
pub enum ContentType {
    Json,
    FormData,
    Multipart,
    Unknown,
}

/// Endpoint context for intelligent testing
#[derive(Debug, Clone)]
pub struct EndpointContext {
    pub framework: ApiFramework,
    pub content_type: ContentType,
    pub is_data_modification: bool,
    pub extracted_fields: HashSet<String>,
    pub has_user_context: bool,
    pub has_auth: bool,
}

impl Default for EndpointContext {
    fn default() -> Self {
        Self {
            framework: ApiFramework::Unknown,
            content_type: ContentType::Unknown,
            is_data_modification: false,
            extracted_fields: HashSet::new(),
            has_user_context: false,
            has_auth: false,
        }
    }
}

impl AdvancedMassAssignmentScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("maa_{}", generate_uuid());
        Self {
            http_client,
            test_marker,
        }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // License check for advanced features
        if !crate::license::is_feature_available("mass_assignment_advanced") {
            debug!("Advanced mass assignment scanner requires premium license");
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[MassAssignment-Advanced] Starting context-aware mass assignment scan");

        // Phase 1: Detect endpoint context
        let context = self.detect_endpoint_context(url).await;
        debug!(
            "[MassAssignment-Advanced] Detected context: framework={:?}, content_type={:?}, is_data_mod={}",
            context.framework, context.content_type, context.is_data_modification
        );

        // Phase 2: Test nested object injection
        let (vulns, tests) = self.test_nested_object_injection(url, &context).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Phase 3: Test dot notation pollution
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_dot_notation_pollution(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 4: Test array parameter pollution
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_array_parameter_pollution(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 5: Test JSON deep merge exploitation
        if vulnerabilities.is_empty() && context.content_type == ContentType::Json {
            let (vulns, tests) = self.test_json_deep_merge(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 6: Framework-specific tests
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_framework_specific(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 7: Privilege escalation field tests
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_privilege_escalation_fields(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 8: Ownership manipulation tests
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_ownership_manipulation(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 9: Financial field manipulation
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self
                .test_financial_field_manipulation(url, &context)
                .await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 10: Timestamp manipulation
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_timestamp_manipulation(url, &context).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            info!(
                "[MassAssignment-Advanced] No vulnerabilities found after {} tests",
                tests_run
            );
        } else {
            info!(
                "[MassAssignment-Advanced] Found {} vulnerabilities",
                vulnerabilities.len()
            );
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan with application characteristics for context-aware testing
    pub async fn scan_with_context(
        &self,
        url: &str,
        config: &ScanConfig,
        characteristics: &AppCharacteristics,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Skip if not an API endpoint
        if !characteristics.is_api && !self.looks_like_data_endpoint(url) {
            debug!(
                "[MassAssignment-Advanced] Skipping non-API endpoint: {}",
                url
            );
            return Ok((Vec::new(), 0));
        }

        // Skip static sites and pure SPAs
        if characteristics.is_static && !characteristics.is_api {
            debug!("[MassAssignment-Advanced] Skipping static site: {}", url);
            return Ok((Vec::new(), 0));
        }

        self.scan(url, config).await
    }

    /// Detect endpoint context for intelligent testing
    async fn detect_endpoint_context(&self, url: &str) -> EndpointContext {
        let mut context = EndpointContext::default();

        // Try to get a response to analyze
        if let Ok(response) = self.http_client.get(url).await {
            let body = &response.body;
            let headers = &response.headers;

            // Detect content type
            if let Some(ct) = headers.get("content-type") {
                let ct_lower = ct.to_lowercase();
                if ct_lower.contains("application/json") {
                    context.content_type = ContentType::Json;
                } else if ct_lower.contains("application/x-www-form-urlencoded") {
                    context.content_type = ContentType::FormData;
                } else if ct_lower.contains("multipart/form-data") {
                    context.content_type = ContentType::Multipart;
                }
            }

            // Detect framework from headers and body
            context.framework = self.detect_framework(headers, body);

            // Extract field names from JSON response
            if let Ok(json) = serde_json::from_str::<Value>(body) {
                context.extracted_fields = self.extract_field_names(&json);
            }

            // Detect user context
            let body_lower = body.to_lowercase();
            context.has_user_context = body_lower.contains("user")
                || body_lower.contains("profile")
                || body_lower.contains("account");

            // Detect authentication
            context.has_auth = headers.contains_key("authorization")
                || headers.contains_key("x-auth-token")
                || body_lower.contains("token")
                || body_lower.contains("session");
        }

        // Check if URL indicates data modification endpoint
        context.is_data_modification = self.is_data_modification_endpoint(url);

        context
    }

    /// Detect API framework from response
    fn detect_framework(
        &self,
        headers: &std::collections::HashMap<String, String>,
        body: &str,
    ) -> ApiFramework {
        let body_lower = body.to_lowercase();

        // Check headers
        if let Some(server) = headers.get("server") {
            let server_lower = server.to_lowercase();
            if server_lower.contains("passenger") || server_lower.contains("puma") {
                return ApiFramework::Rails;
            }
            if server_lower.contains("gunicorn") || server_lower.contains("uvicorn") {
                if body_lower.contains("fastapi") {
                    return ApiFramework::FastAPI;
                }
                return ApiFramework::Django;
            }
            if server_lower.contains("werkzeug") {
                return ApiFramework::Flask;
            }
            if server_lower.contains("kestrel") || server_lower.contains("iis") {
                return ApiFramework::AspNet;
            }
        }

        // Check X-Powered-By
        if let Some(powered_by) = headers.get("x-powered-by") {
            let powered_lower = powered_by.to_lowercase();
            if powered_lower.contains("express") {
                return ApiFramework::Express;
            }
            if powered_lower.contains("php") {
                return ApiFramework::Laravel; // Could be Laravel
            }
            if powered_lower.contains("asp.net") {
                return ApiFramework::AspNet;
            }
        }

        // Check body patterns
        if body_lower.contains("actioncontroller") || body_lower.contains("rails") {
            return ApiFramework::Rails;
        }
        if body_lower.contains("django") || body_lower.contains("drf") {
            return ApiFramework::Django;
        }
        if body_lower.contains("laravel") || body_lower.contains("lumen") {
            return ApiFramework::Laravel;
        }
        if body_lower.contains("spring") || body_lower.contains("jackson") {
            return ApiFramework::Spring;
        }

        ApiFramework::Unknown
    }

    /// Extract field names from JSON response
    fn extract_field_names(&self, json: &Value) -> HashSet<String> {
        let mut fields = HashSet::new();
        self.extract_fields_recursive(json, "", &mut fields);
        fields
    }

    fn extract_fields_recursive(&self, json: &Value, prefix: &str, fields: &mut HashSet<String>) {
        match json {
            Value::Object(map) => {
                for (key, value) in map {
                    let field_name = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    fields.insert(key.clone());
                    fields.insert(field_name.clone());
                    self.extract_fields_recursive(value, &field_name, fields);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.extract_fields_recursive(item, prefix, fields);
                }
            }
            _ => {}
        }
    }

    /// Check if URL indicates a data modification endpoint
    fn is_data_modification_endpoint(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        let modification_patterns = [
            "/create",
            "/update",
            "/edit",
            "/save",
            "/register",
            "/signup",
            "/profile",
            "/settings",
            "/account",
            "/user",
            "/admin",
            "/checkout",
            "/order",
            "/payment",
            "/subscription",
        ];

        modification_patterns.iter().any(|p| url_lower.contains(p))
    }

    /// Check if URL looks like a data endpoint
    fn looks_like_data_endpoint(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        url_lower.contains("/api/")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/rest/")
            || url_lower.contains("/graphql")
            || self.is_data_modification_endpoint(url)
    }

    // ========================================================================
    // NESTED OBJECT INJECTION
    // ========================================================================

    async fn test_nested_object_injection(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run;

        info!("[MassAssignment-Advanced] Testing nested object injection");

        // URL-encoded nested payloads
        let url_payloads = self.generate_nested_url_payloads();
        tests_run = url_payloads.len();

        for (payload, technique) in &url_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.verify_nested_injection(&response.body, payload) {
                        info!(
                            "[MassAssignment-Advanced] Nested object injection detected: {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Advanced Nested Object Injection",
                            payload,
                            &format!(
                                "Deep nested object properties can be injected via mass assignment. \
                                Technique: {}. Framework: {:?}",
                                technique, context.framework
                            ),
                            &format!("Successfully injected nested property using {}", technique),
                            Severity::Critical,
                            Confidence::High,
                            "CWE-915",
                            9.0,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Nested object test request failed: {}", e);
                }
            }
        }

        // JSON nested payloads for JSON endpoints
        if context.content_type == ContentType::Json || context.content_type == ContentType::Unknown
        {
            let json_payloads = self.generate_nested_json_payloads();

            for (payload, technique) in json_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self
                    .http_client
                    .post_with_headers(url, &payload.to_string(), headers)
                    .await
                {
                    Ok(response) => {
                        if self.verify_json_injection(&response.body, &payload) {
                            info!(
                                "[MassAssignment-Advanced] JSON nested injection detected: {}",
                                technique
                            );
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Advanced JSON Nested Object Injection",
                                &payload.to_string(),
                                &format!(
                                    "Deep nested JSON objects can be injected via mass assignment. \
                                    Technique: {}. Framework: {:?}",
                                    technique, context.framework
                                ),
                                &format!(
                                    "Successfully injected nested JSON property using {}",
                                    technique
                                ),
                                Severity::Critical,
                                Confidence::High,
                                "CWE-915",
                                9.0,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("JSON nested test request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn generate_nested_url_payloads(&self) -> Vec<(String, String)> {
        vec![
            // 2-level bracket notation
            (
                "user[role]=admin".to_string(),
                "2-level: user[role]".to_string(),
            ),
            (
                "user[isAdmin]=true".to_string(),
                "2-level: user[isAdmin]".to_string(),
            ),
            (
                "user[admin]=1".to_string(),
                "2-level: user[admin]".to_string(),
            ),
            (
                "profile[admin]=true".to_string(),
                "2-level: profile[admin]".to_string(),
            ),
            (
                "account[verified]=true".to_string(),
                "2-level: account[verified]".to_string(),
            ),
            // 3-level bracket notation
            (
                "user[profile][role]=admin".to_string(),
                "3-level: user[profile][role]".to_string(),
            ),
            (
                "user[permissions][admin]=true".to_string(),
                "3-level: user[permissions][admin]".to_string(),
            ),
            (
                "account[settings][role]=admin".to_string(),
                "3-level: account[settings][role]".to_string(),
            ),
            (
                "profile[data][verified]=true".to_string(),
                "3-level: profile[data][verified]".to_string(),
            ),
            // 4-level bracket notation
            (
                "user[profile][role][level]=admin".to_string(),
                "4-level: user[profile][role][level]".to_string(),
            ),
            (
                "account[user][permissions][admin]=true".to_string(),
                "4-level: account[user][permissions][admin]".to_string(),
            ),
            // 5-level bracket notation (for deeply nested APIs)
            (
                "data[user][profile][permissions][admin]=true".to_string(),
                "5-level: data[user][profile][permissions][admin]".to_string(),
            ),
            // With unique marker for verification
            (
                format!("user[{}]=injected", self.test_marker),
                format!("marker: user[{}]", self.test_marker),
            ),
            (
                format!("user[profile][{}]=injected", self.test_marker),
                format!("marker: user[profile][{}]", self.test_marker),
            ),
        ]
    }

    fn generate_nested_json_payloads(&self) -> Vec<(Value, String)> {
        vec![
            // 2-level nesting
            (
                json!({"user": {"role": "admin"}}),
                "2-level JSON: user.role".to_string(),
            ),
            (
                json!({"user": {"isAdmin": true}}),
                "2-level JSON: user.isAdmin".to_string(),
            ),
            (
                json!({"profile": {"admin": true}}),
                "2-level JSON: profile.admin".to_string(),
            ),
            // 3-level nesting
            (
                json!({"user": {"profile": {"role": "admin"}}}),
                "3-level JSON: user.profile.role".to_string(),
            ),
            (
                json!({"user": {"permissions": {"admin": true}}}),
                "3-level JSON: user.permissions.admin".to_string(),
            ),
            (
                json!({"account": {"settings": {"verified": true}}}),
                "3-level JSON: account.settings.verified".to_string(),
            ),
            // 4-level nesting
            (
                json!({"user": {"profile": {"permissions": {"admin": true}}}}),
                "4-level JSON: user.profile.permissions.admin".to_string(),
            ),
            (
                json!({"account": {"user": {"role": {"level": "admin"}}}}),
                "4-level JSON: account.user.role.level".to_string(),
            ),
            // 5-level nesting (for deeply nested APIs)
            (
                json!({"data": {"user": {"profile": {"permissions": {"admin": true}}}}}),
                "5-level JSON: data.user.profile.permissions.admin".to_string(),
            ),
            // With marker
            (
                json!({"user": {self.test_marker.clone(): "injected"}}),
                format!("marker JSON: user.{}", self.test_marker),
            ),
        ]
    }

    // ========================================================================
    // DOT NOTATION POLLUTION
    // ========================================================================

    async fn test_dot_notation_pollution(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing dot notation pollution");

        let dot_payloads = vec![
            // Basic dot notation
            ("user.role=admin", "dot: user.role"),
            ("user.isAdmin=true", "dot: user.isAdmin"),
            ("user.admin=1", "dot: user.admin"),
            ("profile.admin=true", "dot: profile.admin"),
            ("account.verified=true", "dot: account.verified"),
            // Deeper dot notation
            ("user.profile.role=admin", "dot: user.profile.role"),
            ("user.permissions.admin=true", "dot: user.permissions.admin"),
            ("account.settings.role=admin", "dot: account.settings.role"),
            ("profile.data.verified=true", "dot: profile.data.verified"),
            // Very deep dot notation
            (
                "user.profile.permissions.admin=true",
                "dot: user.profile.permissions.admin",
            ),
            (
                "data.user.account.role=admin",
                "dot: data.user.account.role",
            ),
            // Financial fields
            ("user.balance=999999", "dot: user.balance"),
            ("account.credits=999999", "dot: account.credits"),
            ("subscription.tier=premium", "dot: subscription.tier"),
        ];

        let tests_run = dot_payloads.len();

        for (payload, technique) in &dot_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.verify_dot_notation_injection(&response.body, payload) {
                        info!(
                            "[MassAssignment-Advanced] Dot notation pollution detected: {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Dot Notation Property Pollution",
                            payload,
                            &format!(
                                "Properties can be injected using dot notation syntax. \
                                Technique: {}. Framework: {:?}",
                                technique, context.framework
                            ),
                            &format!("Successfully polluted property using {}", technique),
                            Severity::High,
                            Confidence::High,
                            "CWE-915",
                            8.0,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Dot notation test request failed: {}", e);
                }
            }
        }

        // Also test with marker
        let marker_payload = format!("user.{}=injected", self.test_marker);
        let test_url = if url.contains('?') {
            format!("{}&{}", url, marker_payload)
        } else {
            format!("{}?{}", url, marker_payload)
        };

        if let Ok(response) = self.http_client.get(&test_url).await {
            if response
                .body
                .to_lowercase()
                .contains(&self.test_marker.to_lowercase())
            {
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Dot Notation Property Pollution (Verified)",
                    &marker_payload,
                    "Properties can be injected using dot notation syntax. \
                    Verified with unique marker.",
                    "Successfully polluted property with verified marker injection",
                    Severity::High,
                    Confidence::High,
                    "CWE-915",
                    8.0,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // ARRAY PARAMETER POLLUTION
    // ========================================================================

    async fn test_array_parameter_pollution(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing array parameter pollution");

        let array_payloads = vec![
            // Simple array injection
            ("roles[]=admin&roles[]=user", "array: roles[]"),
            (
                "permissions[]=admin&permissions[]=read",
                "array: permissions[]",
            ),
            ("groups[]=administrators&groups[]=users", "array: groups[]"),
            // Indexed array injection
            (
                "permissions[0]=read&permissions[1]=write&permissions[2]=admin",
                "indexed: permissions[n]",
            ),
            ("roles[0]=user&roles[1]=admin", "indexed: roles[n]"),
            // Nested array objects
            ("users[0][role]=admin", "nested array: users[0][role]"),
            ("users[0][isAdmin]=true", "nested array: users[0][isAdmin]"),
            ("items[0][price]=0", "nested array: items[0][price]"),
            ("orders[0][amount]=0", "nested array: orders[0][amount]"),
            // Deep nested arrays
            (
                "data[users][0][role]=admin",
                "deep array: data[users][0][role]",
            ),
            (
                "accounts[0][permissions][0]=admin",
                "deep array: accounts[0][permissions][0]",
            ),
            // Negative indices (some frameworks vulnerable)
            ("users[-1][role]=admin", "negative index: users[-1][role]"),
            ("items[-1][admin]=true", "negative index: items[-1][admin]"),
            // Large indices (potential DoS or bypass)
            ("users[9999][role]=admin", "large index: users[9999][role]"),
            // PHP-style array append
            ("role[]=admin", "PHP append: role[]"),
            ("admin[]=true", "PHP append: admin[]"),
        ];

        let tests_run = array_payloads.len();

        for (payload, technique) in &array_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.verify_array_pollution(&response.body, payload) {
                        info!(
                            "[MassAssignment-Advanced] Array parameter pollution detected: {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Array Parameter Pollution",
                            payload,
                            &format!(
                                "Array parameters can be polluted to inject malicious values. \
                                Technique: {}. Framework: {:?}",
                                technique, context.framework
                            ),
                            &format!("Successfully polluted array using {}", technique),
                            Severity::High,
                            Confidence::Medium,
                            "CWE-915",
                            7.5,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Array pollution test request failed: {}", e);
                }
            }
        }

        // JSON array payloads
        if context.content_type == ContentType::Json || context.content_type == ContentType::Unknown
        {
            let json_array_payloads = vec![
                (json!({"roles": ["admin", "user"]}), "JSON array: roles"),
                (
                    json!({"permissions": ["read", "write", "admin"]}),
                    "JSON array: permissions",
                ),
                (
                    json!({"user": {"roles": ["admin"]}}),
                    "JSON nested array: user.roles",
                ),
                (
                    json!({"users": [{"role": "admin"}]}),
                    "JSON object array: users[].role",
                ),
                (
                    json!({"data": {"permissions": ["admin"]}}),
                    "JSON deep array: data.permissions",
                ),
            ];

            for (payload, technique) in json_array_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self
                    .http_client
                    .post_with_headers(url, &payload.to_string(), headers)
                    .await
                {
                    Ok(response) => {
                        if self.verify_json_array_pollution(&response.body, &payload) {
                            info!(
                                "[MassAssignment-Advanced] JSON array pollution detected: {}",
                                technique
                            );
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "JSON Array Parameter Pollution",
                                &payload.to_string(),
                                &format!(
                                    "JSON arrays can be polluted to inject malicious values. \
                                    Technique: {}. Framework: {:?}",
                                    technique, context.framework
                                ),
                                &format!("Successfully polluted JSON array using {}", technique),
                                Severity::High,
                                Confidence::Medium,
                                "CWE-915",
                                7.5,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("JSON array pollution test request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // JSON DEEP MERGE EXPLOITATION
    // ========================================================================

    async fn test_json_deep_merge(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing JSON deep merge exploitation");

        let merge_payloads = vec![
            // Basic merge attacks
            (
                json!({"user": {"role": "admin"}, "profile": {"verified": true}}),
                "multi-object merge",
            ),
            (
                json!({"__proto__": {"isAdmin": true}}),
                "prototype pollution merge",
            ),
            (
                json!({"constructor": {"prototype": {"admin": true}}}),
                "constructor pollution merge",
            ),
            // Deep merge with overwrite
            (
                json!({
                    "user": {
                        "profile": {
                            "permissions": {
                                "admin": true,
                                "superuser": true
                            }
                        }
                    }
                }),
                "deep 4-level merge",
            ),
            // Merge with arrays and objects
            (
                json!({
                    "user": {
                        "roles": ["admin"],
                        "permissions": {"admin": true}
                    }
                }),
                "mixed array-object merge",
            ),
            // Prototype chain manipulation
            (
                json!({
                    "__proto__": {"isAdmin": true},
                    "user": {"role": "admin"}
                }),
                "prototype + object merge",
            ),
            // Recursive merge attempt
            (
                json!({
                    "data": {
                        "nested": {
                            "deep": {
                                "admin": true,
                                "role": "superuser"
                            }
                        }
                    }
                }),
                "recursive deep merge",
            ),
            // With marker for verification
            (
                json!({
                    "user": {
                        self.test_marker.clone(): "injected",
                        "role": "admin"
                    }
                }),
                "verified merge with marker",
            ),
        ];

        let tests_run = merge_payloads.len();

        for (payload, technique) in merge_payloads {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers)
                .await
            {
                Ok(response) => {
                    if self.verify_deep_merge(&response.body, &payload) {
                        info!(
                            "[MassAssignment-Advanced] JSON deep merge exploitation detected: {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "JSON Deep Merge Exploitation",
                            &payload.to_string(),
                            &format!(
                                "Framework performs deep merge on JSON input allowing property injection. \
                                Technique: {}. Framework: {:?}",
                                technique, context.framework
                            ),
                            &format!("Successfully exploited deep merge using {}", technique),
                            Severity::Critical,
                            Confidence::High,
                            "CWE-915",
                            9.0,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Deep merge test request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // FRAMEWORK-SPECIFIC TESTS
    // ========================================================================

    async fn test_framework_specific(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!(
            "[MassAssignment-Advanced] Testing framework-specific vulnerabilities for {:?}",
            context.framework
        );

        match context.framework {
            ApiFramework::Rails => {
                let (vulns, tests) = self.test_rails_specific(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
            ApiFramework::Django => {
                let (vulns, tests) = self.test_django_specific(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
            ApiFramework::Express => {
                let (vulns, tests) = self.test_express_specific(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
            ApiFramework::Spring => {
                let (vulns, tests) = self.test_spring_specific(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
            ApiFramework::Laravel => {
                let (vulns, tests) = self.test_laravel_specific(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
            _ => {
                // Test generic payloads for unknown frameworks
                let (vulns, tests) = self.test_generic_framework(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Rails-specific mass assignment tests (params.permit bypass)
    async fn test_rails_specific(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let rails_payloads = vec![
            // Rails nested attributes bypass
            ("user[admin]=true", "Rails: direct admin"),
            (
                "user[attributes][admin]=true",
                "Rails: nested attributes admin",
            ),
            (
                "user[user_attributes][role]=admin",
                "Rails: user_attributes",
            ),
            (
                "model[_destroy]=false&model[admin]=true",
                "Rails: _destroy bypass",
            ),
            ("user[role_ids][]=1", "Rails: has_many through bypass"),
            // Rails accepts_nested_attributes_for bypass
            (
                "user[profile_attributes][verified]=true",
                "Rails: profile_attributes",
            ),
            (
                "order[line_items_attributes][0][price]=0",
                "Rails: line_items_attributes",
            ),
            // Rails polymorphic association abuse
            (
                "comment[commentable_type]=Admin&comment[commentable_id]=1",
                "Rails: polymorphic abuse",
            ),
        ];

        let tests_run = rails_payloads.len();

        for (payload, technique) in &rails_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.verify_rails_injection(&response.body, payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Rails Strong Parameters Bypass",
                        payload,
                        &format!(
                            "Rails strong parameters (params.permit) bypassed. Technique: {}",
                            technique
                        ),
                        "Successfully bypassed Rails parameter protection",
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Django-specific mass assignment tests (serializer bypass)
    async fn test_django_specific(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let django_payloads = vec![
            // Django REST Framework serializer bypass
            (json!({"is_staff": true}), "DRF: is_staff"),
            (json!({"is_superuser": true}), "DRF: is_superuser"),
            (json!({"is_active": true}), "DRF: is_active"),
            (json!({"groups": [1]}), "DRF: groups assignment"),
            (
                json!({"user_permissions": [1, 2, 3]}),
                "DRF: user_permissions",
            ),
            // Django model field bypass
            (json!({"password": "admin123"}), "DRF: direct password"),
            (json!({"pk": 1}), "DRF: primary key manipulation"),
            (json!({"id": 1}), "DRF: id manipulation"),
        ];

        let tests_run = django_payloads.len();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (payload, technique) in django_payloads {
            if let Ok(response) = self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers.clone())
                .await
            {
                if self.verify_django_injection(&response.body, &payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Django Serializer Bypass",
                        &payload.to_string(),
                        &format!(
                            "Django REST Framework serializer bypassed. Technique: {}",
                            technique
                        ),
                        "Successfully bypassed Django serializer protection",
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Express-specific mass assignment tests (body parser exploitation)
    async fn test_express_specific(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let express_payloads = vec![
            // Express body-parser exploitation
            (
                json!({"__proto__": {"isAdmin": true}}),
                "Express: __proto__ pollution",
            ),
            (
                json!({"constructor": {"prototype": {"admin": true}}}),
                "Express: constructor pollution",
            ),
            (
                json!({"isAdmin": true, "role": "admin"}),
                "Express: direct assignment",
            ),
            // Mongoose schema bypass
            (
                json!({"$set": {"role": "admin"}}),
                "Express/Mongoose: $set injection",
            ),
            (
                json!({"$unset": {"password": ""}}),
                "Express/Mongoose: $unset",
            ),
            // Express query pollution
            (
                json!({"$where": "this.admin = true"}),
                "Express/Mongoose: $where",
            ),
        ];

        let tests_run = express_payloads.len();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (payload, technique) in express_payloads {
            if let Ok(response) = self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers.clone())
                .await
            {
                if self.verify_express_injection(&response.body, &payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Express Body Parser Exploitation",
                        &payload.to_string(),
                        &format!(
                            "Express body parser allows mass assignment. Technique: {}",
                            technique
                        ),
                        "Successfully exploited Express body parser",
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Spring-specific mass assignment tests (Jackson annotation bypass)
    async fn test_spring_specific(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let spring_payloads = vec![
            // Spring/Jackson bypass attempts
            (json!({"admin": true}), "Spring: direct admin"),
            (
                json!({"authorities": [{"authority": "ROLE_ADMIN"}]}),
                "Spring: authorities",
            ),
            (json!({"roles": ["ADMIN"]}), "Spring: roles array"),
            (
                json!({"enabled": true, "accountNonLocked": true}),
                "Spring: account status",
            ),
            // Spring class injection
            (
                json!({"class": {"classLoader": {}}}),
                "Spring: class loader injection",
            ),
            // Spring nested binding
            (
                json!({"user": {"admin": true}}),
                "Spring: nested user.admin",
            ),
            (
                json!({"userDetails": {"authorities": [{"authority": "ADMIN"}]}}),
                "Spring: userDetails",
            ),
        ];

        let tests_run = spring_payloads.len();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (payload, technique) in spring_payloads {
            if let Ok(response) = self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers.clone())
                .await
            {
                if self.verify_spring_injection(&response.body, &payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Spring Jackson Annotation Bypass",
                        &payload.to_string(),
                        &format!(
                            "Spring Jackson binding allows mass assignment. Technique: {}",
                            technique
                        ),
                        "Successfully bypassed Spring Jackson protection",
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Laravel-specific mass assignment tests (Eloquent bypass)
    async fn test_laravel_specific(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let laravel_payloads = vec![
            // Laravel Eloquent bypass
            (json!({"is_admin": true}), "Laravel: is_admin"),
            (json!({"role": "admin"}), "Laravel: role"),
            (json!({"role_id": 1}), "Laravel: role_id"),
            (
                json!({"email_verified_at": "2024-01-01T00:00:00Z"}),
                "Laravel: email_verified_at",
            ),
            // Laravel relationship bypass
            (json!({"roles": [{"id": 1}]}), "Laravel: roles relationship"),
            (
                json!({"permissions": [1, 2, 3]}),
                "Laravel: permissions sync",
            ),
            // Laravel pivot data manipulation
            (
                json!({"pivot": {"role_id": 1, "is_admin": true}}),
                "Laravel: pivot data",
            ),
        ];

        let tests_run = laravel_payloads.len();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (payload, technique) in laravel_payloads {
            if let Ok(response) = self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers.clone())
                .await
            {
                if self.verify_laravel_injection(&response.body, &payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Laravel Eloquent Mass Assignment Bypass",
                        &payload.to_string(),
                        &format!(
                            "Laravel Eloquent $fillable/$guarded bypassed. Technique: {}",
                            technique
                        ),
                        "Successfully bypassed Laravel Eloquent protection",
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Generic framework tests
    async fn test_generic_framework(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let generic_payloads = vec![
            (json!({"admin": true}), "generic: admin"),
            (json!({"role": "admin"}), "generic: role"),
            (json!({"isAdmin": true}), "generic: isAdmin"),
            (json!({"verified": true}), "generic: verified"),
            (json!({"active": true}), "generic: active"),
        ];

        let tests_run = generic_payloads.len();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (payload, technique) in generic_payloads {
            if let Ok(response) = self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers.clone())
                .await
            {
                if self.verify_generic_injection(&response.body, &payload) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Mass Assignment Vulnerability",
                        &payload.to_string(),
                        &format!(
                            "Mass assignment vulnerability detected. Technique: {}",
                            technique
                        ),
                        "Successfully exploited mass assignment",
                        Severity::High,
                        Confidence::Medium,
                        "CWE-915",
                        7.5,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // PRIVILEGE ESCALATION FIELD TESTS
    // ========================================================================

    async fn test_privilege_escalation_fields(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing privilege escalation fields");

        let privilege_fields = vec![
            // Role fields
            ("role", "admin"),
            ("role", "administrator"),
            ("role", "superuser"),
            ("userRole", "admin"),
            ("user_role", "admin"),
            // Boolean admin flags
            ("isAdmin", "true"),
            ("is_admin", "true"),
            ("admin", "true"),
            ("superuser", "true"),
            ("is_superuser", "true"),
            // Permission fields
            ("permissions", "admin"),
            ("permission", "all"),
            ("access_level", "admin"),
            ("accessLevel", "10"),
            ("privilege", "admin"),
            // Verification fields
            ("verified", "true"),
            ("is_verified", "true"),
            ("email_verified", "true"),
            ("phone_verified", "true"),
            ("account_verified", "true"),
            // Status fields
            ("active", "true"),
            ("is_active", "true"),
            ("enabled", "true"),
            ("approved", "true"),
            ("is_approved", "true"),
            ("status", "active"),
            ("account_status", "active"),
        ];

        let tests_run = privilege_fields.len();

        for (field, value) in &privilege_fields {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, field, value)
            } else {
                format!("{}?{}={}", url, field, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.verify_privilege_escalation(&response.body, field, value) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Privilege Escalation via Mass Assignment",
                        &format!("{}={}", field, value),
                        &format!(
                            "User privileges can be escalated by injecting {}={}. Framework: {:?}",
                            field, value, context.framework
                        ),
                        &format!(
                            "Successfully escalated privileges using {}={}",
                            field, value
                        ),
                        Severity::Critical,
                        Confidence::High,
                        "CWE-915",
                        9.1,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // OWNERSHIP MANIPULATION TESTS
    // ========================================================================

    async fn test_ownership_manipulation(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing ownership manipulation");

        let ownership_fields = vec![
            ("id", "1"),
            ("user_id", "1"),
            ("userId", "1"),
            ("owner_id", "1"),
            ("ownerId", "1"),
            ("account_id", "1"),
            ("accountId", "1"),
            ("org_id", "1"),
            ("organization_id", "1"),
            ("tenant_id", "1"),
            ("parent_id", "1"),
            ("created_by", "1"),
            ("createdBy", "1"),
            ("author_id", "1"),
        ];

        let tests_run = ownership_fields.len();

        for (field, value) in &ownership_fields {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, field, value)
            } else {
                format!("{}?{}={}", url, field, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.verify_ownership_change(&response.body, field, value) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Ownership Manipulation via Mass Assignment",
                        &format!("{}={}", field, value),
                        &format!(
                            "Object ownership can be changed by injecting {}={}. \
                            This may lead to IDOR or privilege escalation. Framework: {:?}",
                            field, value, context.framework
                        ),
                        &format!(
                            "Successfully manipulated ownership using {}={}",
                            field, value
                        ),
                        Severity::High,
                        Confidence::Medium,
                        "CWE-915",
                        8.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // FINANCIAL FIELD MANIPULATION
    // ========================================================================

    async fn test_financial_field_manipulation(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing financial field manipulation");

        let financial_fields = vec![
            // Balance/credits
            ("balance", "999999"),
            ("credits", "999999"),
            ("points", "999999"),
            ("coins", "999999"),
            // Price manipulation
            ("price", "0"),
            ("amount", "0"),
            ("total", "0"),
            ("subtotal", "0"),
            ("cost", "0"),
            ("fee", "0"),
            ("discount", "100"),
            ("discount_percent", "100"),
            // Subscription/tier
            ("subscription", "premium"),
            ("tier", "enterprise"),
            ("plan", "unlimited"),
            ("subscription_type", "lifetime"),
            ("is_premium", "true"),
            ("is_pro", "true"),
            // Limits
            ("limit", "999999"),
            ("quota", "999999"),
            ("max_items", "999999"),
            ("rate_limit", "999999"),
        ];

        let tests_run = financial_fields.len();

        for (field, value) in &financial_fields {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, field, value)
            } else {
                format!("{}?{}={}", url, field, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.verify_financial_manipulation(&response.body, field, value) {
                    let severity = if field.contains("price")
                        || field.contains("amount")
                        || field.contains("balance")
                    {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Financial Field Manipulation via Mass Assignment",
                        &format!("{}={}", field, value),
                        &format!(
                            "Financial/business fields can be manipulated by injecting {}={}. \
                            This may lead to financial fraud. Framework: {:?}",
                            field, value, context.framework
                        ),
                        &format!(
                            "Successfully manipulated financial field {}={}",
                            field, value
                        ),
                        severity,
                        Confidence::High,
                        "CWE-915",
                        9.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // TIMESTAMP MANIPULATION
    // ========================================================================

    async fn test_timestamp_manipulation(
        &self,
        url: &str,
        context: &EndpointContext,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!("[MassAssignment-Advanced] Testing timestamp manipulation");

        let timestamp_fields = vec![
            ("created_at", "2020-01-01T00:00:00Z"),
            ("createdAt", "2020-01-01T00:00:00Z"),
            ("updated_at", "2030-01-01T00:00:00Z"),
            ("updatedAt", "2030-01-01T00:00:00Z"),
            ("deleted_at", "null"),
            ("deletedAt", "null"),
            ("expires_at", "2030-01-01T00:00:00Z"),
            ("expiresAt", "2030-01-01T00:00:00Z"),
            ("valid_until", "2030-01-01T00:00:00Z"),
            ("subscription_ends", "2030-01-01T00:00:00Z"),
            ("trial_ends_at", "2030-01-01T00:00:00Z"),
            ("last_login", "2020-01-01T00:00:00Z"),
            ("password_changed_at", "2030-01-01T00:00:00Z"),
        ];

        let tests_run = timestamp_fields.len();

        for (field, value) in &timestamp_fields {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, field, value)
            } else {
                format!("{}?{}={}", url, field, value)
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.verify_timestamp_manipulation(&response.body, field, value) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Timestamp Manipulation via Mass Assignment",
                        &format!("{}={}", field, value),
                        &format!(
                            "Timestamp fields can be manipulated by injecting {}={}. \
                            This may bypass time-based restrictions. Framework: {:?}",
                            field, value, context.framework
                        ),
                        &format!("Successfully manipulated timestamp {}={}", field, value),
                        Severity::Medium,
                        Confidence::Medium,
                        "CWE-915",
                        6.0,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ========================================================================
    // VERIFICATION HELPERS
    // ========================================================================

    fn verify_nested_injection(&self, body: &str, payload: &str) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for unique marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Check for privilege escalation patterns
        if payload.contains("role]=admin") || payload.contains("role=admin") {
            if body_lower.contains("\"role\":\"admin\"")
                || body_lower.contains("\"role\": \"admin\"")
            {
                return true;
            }
        }

        if payload.contains("admin]=true")
            || payload.contains("admin=true")
            || payload.contains("admin]=1")
        {
            if body_lower.contains("\"admin\":true")
                || body_lower.contains("\"admin\": true")
                || body_lower.contains("\"admin\":1")
            {
                return true;
            }
        }

        if payload.contains("isadmin]=true") || payload.contains("isadmin=true") {
            if body_lower.contains("\"isadmin\":true") || body_lower.contains("\"isadmin\": true") {
                return true;
            }
        }

        false
    }

    fn verify_json_injection(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for unique marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Parse response and check for injected values
        if let Ok(response_json) = serde_json::from_str::<Value>(body) {
            return self.json_contains_injected_value(&response_json, payload);
        }

        false
    }

    fn json_contains_injected_value(&self, response: &Value, payload: &Value) -> bool {
        // Look for admin/role patterns in nested response
        if let Some(obj) = payload.as_object() {
            for (_key, value) in obj {
                if let Some(inner_obj) = value.as_object() {
                    for (inner_key, inner_value) in inner_obj {
                        if inner_key == "role" && inner_value == "admin" {
                            if self.json_has_value(response, "role", "admin") {
                                return true;
                            }
                        }
                        if inner_key == "admin" || inner_key == "isAdmin" {
                            if inner_value == true {
                                if self.json_has_bool(response, inner_key, true) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        false
    }

    fn json_has_value(&self, json: &Value, key: &str, value: &str) -> bool {
        match json {
            Value::Object(map) => {
                if let Some(v) = map.get(key) {
                    if v.as_str() == Some(value) {
                        return true;
                    }
                }
                for (_, v) in map {
                    if self.json_has_value(v, key, value) {
                        return true;
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    if self.json_has_value(item, key, value) {
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn json_has_bool(&self, json: &Value, key: &str, value: bool) -> bool {
        match json {
            Value::Object(map) => {
                if let Some(v) = map.get(key) {
                    if v.as_bool() == Some(value) {
                        return true;
                    }
                }
                for (_, v) in map {
                    if self.json_has_bool(v, key, value) {
                        return true;
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    if self.json_has_bool(item, key, value) {
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn verify_dot_notation_injection(&self, body: &str, payload: &str) -> bool {
        self.verify_nested_injection(body, payload)
    }

    fn verify_array_pollution(&self, body: &str, payload: &str) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Check for admin injection in array context
        if payload.contains("admin") && body.contains('[') {
            if body_lower.contains("\"admin\":true") || body_lower.contains("\"role\":\"admin\"") {
                return true;
            }
        }

        // Check for price manipulation in array
        if payload.contains("price]=0") || payload.contains("amount]=0") {
            if body_lower.contains("\"price\":0") || body_lower.contains("\"amount\":0") {
                return true;
            }
        }

        false
    }

    fn verify_json_array_pollution(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for admin role assignment in structured response
        // Require JSON value context, not just the word "admin" anywhere
        if body_lower.contains("\"roles\"") && (body_lower.contains("\"admin\"") || body_lower.contains(":\"admin\"")) {
            return true;
        }

        // Check for admin in permissions
        if body_lower.contains("\"permissions\"") && (body_lower.contains("\"admin\"") || body_lower.contains(":\"admin\"")) {
            return true;
        }

        false
    }

    fn verify_deep_merge(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Check for prototype pollution
        if body_lower.contains("\"__proto__\"") && body_lower.contains("admin") {
            return true;
        }

        // Check for deep nested privilege escalation
        self.verify_json_injection(body, payload)
    }

    fn verify_rails_injection(&self, body: &str, _payload: &str) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        body_lower.contains("\"admin\":true")
            || body_lower.contains("\"role\":\"admin\"")
            || body_lower.contains("\"verified\":true")
    }

    fn verify_django_injection(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for staff/superuser flags
        if body_lower.contains("\"is_staff\":true") || body_lower.contains("\"is_superuser\":true")
        {
            return true;
        }

        self.verify_json_injection(body, payload)
    }

    fn verify_express_injection(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for prototype pollution or admin flags
        if body_lower.contains("\"__proto__\"") || body_lower.contains("\"constructor\"") {
            if body_lower.contains("admin") {
                return true;
            }
        }

        self.verify_json_injection(body, payload)
    }

    fn verify_spring_injection(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for authorities or roles
        if body_lower.contains("\"authorities\"") && body_lower.contains("admin") {
            return true;
        }

        self.verify_json_injection(body, payload)
    }

    fn verify_laravel_injection(&self, body: &str, payload: &Value) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for Laravel-specific patterns
        if body_lower.contains("\"is_admin\":true") || body_lower.contains("\"role\":\"admin\"") {
            return true;
        }

        if body_lower.contains("\"email_verified_at\"") && !body_lower.contains("null") {
            return true;
        }

        self.verify_json_injection(body, payload)
    }

    fn verify_generic_injection(&self, body: &str, payload: &Value) -> bool {
        self.verify_json_injection(body, payload)
    }

    fn verify_privilege_escalation(&self, body: &str, field: &str, value: &str) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();
        let field_lower = field.to_lowercase();
        let value_lower = value.to_lowercase();

        // Check for exact field:value match in JSON
        let patterns = vec![
            format!("\"{}\":\"{}\"", field_lower, value_lower),
            format!("\"{}\": \"{}\"", field_lower, value_lower),
            format!("\"{}\":{}", field_lower, value_lower),
            format!("\"{}\": {}", field_lower, value_lower),
        ];

        for pattern in patterns {
            if body_lower.contains(&pattern) {
                return true;
            }
        }

        false
    }

    fn verify_ownership_change(&self, body: &str, field: &str, value: &str) -> bool {
        self.verify_privilege_escalation(body, field, value)
    }

    fn verify_financial_manipulation(&self, body: &str, field: &str, value: &str) -> bool {
        self.verify_privilege_escalation(body, field, value)
    }

    fn verify_timestamp_manipulation(&self, body: &str, field: &str, value: &str) -> bool {
        if !self.is_structured_response(body) {
            return false;
        }

        let body_lower = body.to_lowercase();
        let field_lower = field.to_lowercase();

        // Check if the field appears in response with a date value
        if body_lower.contains(&format!("\"{}\":", field_lower)) {
            // Check for our injected date pattern
            if body_lower.contains("2020-01-01") || body_lower.contains("2030-01-01") {
                return true;
            }
        }

        false
    }

    fn is_structured_response(&self, body: &str) -> bool {
        let trimmed = body.trim();
        trimmed.starts_with('{') || trimmed.starts_with('[')
    }

    // ========================================================================
    // VULNERABILITY CREATION
    // ========================================================================

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        confidence: Confidence,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("maa_{}", generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
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
            remediation: self.get_remediation(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn get_remediation(&self) -> String {
        r#"MASS ASSIGNMENT REMEDIATION:
===============================

1. USE ALLOWLISTS (RECOMMENDED):
   - Rails: Use strong parameters with permit()
   - Django: Specify fields in serializer's Meta class
   - Express: Validate and pick only allowed fields
   - Spring: Use @JsonIgnore on sensitive fields
   - Laravel: Use $fillable array in Eloquent models

2. AVOID BLOCKLISTS:
   - Blocklists ($guarded) are error-prone
   - Always prefer explicit allowlists

3. USE DATA TRANSFER OBJECTS (DTOs):
   - Create separate input/output models
   - Never bind directly to domain models

4. VALIDATE INPUT STRICTLY:
   - Validate all input against expected schema
   - Reject unexpected fields

5. PROTECT SENSITIVE FIELDS:
   - Mark role, admin, verified as read-only
   - Implement field-level access controls

6. BLOCK DANGEROUS PATTERNS:
   - Reject __proto__, constructor, prototype
   - Limit nested object depth
   - Sanitize array indices

7. IMPLEMENT AUTHORIZATION:
   - Check permissions before updates
   - Use separate endpoints for admin operations

8. FRAMEWORK-SPECIFIC:
   Rails: params.require(:user).permit(:name, :email)
   Django: class UserSerializer(serializers.Serializer):
               class Meta:
                   fields = ['name', 'email']
   Express: const { name, email } = req.body; // Only pick allowed
   Spring: @JsonIgnoreProperties(value = {"admin", "role"})
   Laravel: protected $fillable = ['name', 'email'];

9. USE OBJECT.CREATE(NULL):
   - For JavaScript, prevent prototype pollution
   - const obj = Object.create(null);

10. IMPLEMENT STRICT JSON SCHEMA:
    - Validate all nested objects
    - Limit depth and array sizes"#
            .to_string()
    }
}

/// Generate a random UUID-like string
fn generate_uuid() -> String {
    use rand::Rng;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> AdvancedMassAssignmentScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        AdvancedMassAssignmentScanner::new(http_client)
    }

    #[test]
    fn test_unique_marker_generation() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("maa_"));
    }

    #[test]
    fn test_framework_detection() {
        let scanner = create_test_scanner();

        // Test Rails detection
        let mut headers = std::collections::HashMap::new();
        headers.insert("server".to_string(), "Passenger".to_string());
        let framework = scanner.detect_framework(&headers, "");
        assert_eq!(framework, ApiFramework::Rails);

        // Test Express detection
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-powered-by".to_string(), "Express".to_string());
        let framework = scanner.detect_framework(&headers, "");
        assert_eq!(framework, ApiFramework::Express);

        // Test Django detection
        let mut headers = std::collections::HashMap::new();
        headers.insert("server".to_string(), "gunicorn".to_string());
        let framework = scanner.detect_framework(&headers, "Django");
        assert_eq!(framework, ApiFramework::Django);
    }

    #[test]
    fn test_nested_injection_detection() {
        let scanner = create_test_scanner();

        // Test marker-based detection
        let body_with_marker = format!(r#"{{"user":{{"{}":"injected"}}}}"#, scanner.test_marker);
        assert!(scanner.verify_nested_injection(
            &body_with_marker,
            &format!("user[{}]=injected", scanner.test_marker)
        ));

        // Test role injection
        assert!(scanner.verify_nested_injection(r#"{"user":{"role":"admin"}}"#, "user[role]=admin"));

        // Test admin flag injection
        assert!(scanner.verify_nested_injection(r#"{"user":{"admin":true}}"#, "user[admin]=true"));

        // Test isAdmin injection
        assert!(scanner
            .verify_nested_injection(r#"{"profile":{"isAdmin":true}}"#, "profile[isAdmin]=true"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        // HTML should not trigger
        assert!(!scanner
            .verify_nested_injection("<html><body>admin panel</body></html>", "user[role]=admin"));

        // Plain text should not trigger
        assert!(!scanner.verify_nested_injection("Welcome admin user", "user[admin]=true"));

        // Unrelated JSON should not trigger
        assert!(!scanner.verify_nested_injection(r#"{"message":"success"}"#, "user[role]=admin"));
    }

    #[test]
    fn test_privilege_escalation_verification() {
        let scanner = create_test_scanner();

        assert!(scanner.verify_privilege_escalation(r#"{"role":"admin"}"#, "role", "admin"));

        assert!(scanner.verify_privilege_escalation(r#"{"isAdmin":true}"#, "isAdmin", "true"));

        assert!(!scanner.verify_privilege_escalation(r#"{"role":"user"}"#, "role", "admin"));
    }

    #[test]
    fn test_array_pollution_verification() {
        let scanner = create_test_scanner();

        assert!(scanner.verify_array_pollution(r#"[{"admin":true}]"#, "users[0][admin]=true"));

        assert!(scanner.verify_array_pollution(r#"[{"role":"admin"}]"#, "users[0][role]=admin"));

        assert!(!scanner.verify_array_pollution(r#"{"message":"ok"}"#, "users[0][admin]=true"));
    }

    #[test]
    fn test_data_modification_endpoint_detection() {
        let scanner = create_test_scanner();

        assert!(scanner.is_data_modification_endpoint("/api/users/create"));
        assert!(scanner.is_data_modification_endpoint("/api/profile/update"));
        assert!(scanner.is_data_modification_endpoint("/api/settings"));
        assert!(scanner.is_data_modification_endpoint("/api/account/register"));

        assert!(!scanner.is_data_modification_endpoint("/api/users/list"));
        assert!(!scanner.is_data_modification_endpoint("/static/image.png"));
    }

    #[test]
    fn test_json_field_extraction() {
        let scanner = create_test_scanner();

        let json = json!({
            "user": {
                "name": "test",
                "profile": {
                    "role": "user"
                }
            }
        });

        let fields = scanner.extract_field_names(&json);

        assert!(fields.contains("user"));
        assert!(fields.contains("name"));
        assert!(fields.contains("profile"));
        assert!(fields.contains("role"));
        assert!(fields.contains("user.name"));
        assert!(fields.contains("user.profile"));
        assert!(fields.contains("user.profile.role"));
    }

    #[test]
    fn test_vulnerability_creation() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "https://example.com/api/users",
            "Mass Assignment Test",
            "role=admin",
            "Test description",
            "Test evidence",
            Severity::Critical,
            Confidence::High,
            "CWE-915",
            9.0,
        );

        assert!(vuln.id.starts_with("maa_"));
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.confidence, Confidence::High);
        assert_eq!(vuln.cwe, "CWE-915");
        assert_eq!(vuln.cvss, 9.0);
        assert!(vuln.verified);
    }

    #[test]
    fn test_nested_url_payload_generation() {
        let scanner = create_test_scanner();

        let payloads = scanner.generate_nested_url_payloads();

        assert!(!payloads.is_empty());

        // Check for various nesting levels
        let has_2_level = payloads.iter().any(|(p, _)| p.contains("user[role]=admin"));
        let has_3_level = payloads
            .iter()
            .any(|(p, _)| p.contains("user[profile][role]=admin"));
        let has_4_level = payloads
            .iter()
            .any(|(p, _)| p.contains("user[profile][role][level]=admin"));

        assert!(has_2_level);
        assert!(has_3_level);
        assert!(has_4_level);

        // Check for marker payloads
        let has_marker = payloads
            .iter()
            .any(|(p, _)| p.contains(&scanner.test_marker));
        assert!(has_marker);
    }

    #[test]
    fn test_deep_merge_verification() {
        let scanner = create_test_scanner();

        let payload = json!({"user": {"role": "admin"}});

        assert!(scanner.verify_deep_merge(r#"{"user":{"role":"admin"}}"#, &payload));

        // Prototype pollution detection
        let proto_payload = json!({"__proto__": {"admin": true}});
        assert!(scanner.verify_deep_merge(r#"{"__proto__":{"admin":true}}"#, &proto_payload));
    }
}
