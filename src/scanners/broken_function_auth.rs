// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - BFLA (Broken Function Level Authorization) Scanner
 * OWASP API Security Top 10 #5 - Broken Function Level Authorization
 *
 * Tests for vertical privilege escalation where users can access
 * administrative or privileged functions without proper authorization.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use rand::Rng;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// BFLA (Broken Function Level Authorization) Scanner
///
/// This scanner identifies endpoints where function-level authorization checks
/// are missing or improperly implemented, allowing regular users to access
/// privileged/administrative functions.
pub struct BrokenFunctionAuthScanner {
    http_client: Arc<HttpClient>,
}

/// Detected API pattern
#[derive(Debug, Clone, PartialEq)]
pub enum ApiPattern {
    Rest,
    GraphQL,
    JsonRpc,
    Soap,
    Unknown,
}

/// Authorization scheme detected
#[derive(Debug, Clone, PartialEq)]
pub enum AuthScheme {
    Jwt,
    Session,
    ApiKey,
    Basic,
    OAuth,
    None,
    Unknown,
}

/// Privilege level of an endpoint
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivilegeLevel {
    Public,
    Authenticated,
    Elevated,
    Admin,
    SuperAdmin,
}

/// Information about a discovered endpoint
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub url: String,
    pub path: String,
    pub method: String,
    pub privilege_level: PrivilegeLevel,
    pub function_category: FunctionCategory,
    pub requires_auth: bool,
}

/// Function categories to test for BFLA
#[derive(Debug, Clone, PartialEq)]
pub enum FunctionCategory {
    UserManagement,    // Create/delete users
    Configuration,     // System configuration
    DataExport,        // Data export/import
    SystemOperations,  // System-level operations
    AuditLogs,         // Audit/logging controls
    FinancialOps,      // Financial operations
    RoleManagement,    // Role/permission changes
    ContentModeration, // Content moderation
    Analytics,         // Analytics/reporting
    Deployment,        // Deployment operations
    General,           // General admin functions
}

impl BrokenFunctionAuthScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    ///
    /// Tests for BFLA vulnerabilities by:
    /// 1. Detecting API patterns and authorization schemes
    /// 2. Discovering admin/privileged endpoints
    /// 3. Testing cross-privilege access
    /// 4. HTTP method tampering
    /// 5. Authorization bypass techniques
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            info!("[SKIP] BFLA scanning requires valid license");
            return Ok((Vec::new(), 0));
        }

        info!(
            "Starting BFLA (Broken Function Level Authorization) scan on {}",
            url
        );

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Phase 1: Fetch baseline and detect application characteristics
        let baseline_response = match self.http_client.get(url).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to fetch baseline response: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        // Skip if target is static/non-API site
        if characteristics.is_static && !characteristics.is_api {
            info!("[BFLA] Target appears to be a static site - skipping BFLA tests");
            return Ok((Vec::new(), 0));
        }

        // Phase 2: Detect API pattern and authorization scheme
        let api_pattern = self.detect_api_pattern(&baseline_response, url);
        let auth_scheme = self.detect_auth_scheme(&baseline_response);

        info!(
            "[BFLA] Detected API pattern: {:?}, Auth scheme: {:?}",
            api_pattern, auth_scheme
        );

        // Phase 3: Discover admin/privileged endpoints
        let admin_endpoints = self
            .discover_admin_endpoints(url, &baseline_response)
            .await?;
        info!(
            "[BFLA] Discovered {} potential admin endpoints",
            admin_endpoints.len()
        );

        if admin_endpoints.is_empty() {
            debug!("[BFLA] No admin endpoints discovered");
            return Ok((vulnerabilities, tests_run));
        }

        // Phase 4: Test each admin endpoint for BFLA
        for endpoint in &admin_endpoints {
            // Test with no authorization
            tests_run += 1;
            if let Some(vuln) = self.test_no_auth_access(endpoint).await? {
                vulnerabilities.push(vuln);
            }

            // Test with removed authorization header
            tests_run += 1;
            if let Some(vuln) = self
                .test_removed_auth_header(endpoint, &auth_scheme)
                .await?
            {
                vulnerabilities.push(vuln);
            }

            // Test HTTP method tampering
            let (method_vulns, method_tests) = self.test_http_method_tampering(endpoint).await?;
            vulnerabilities.extend(method_vulns);
            tests_run += method_tests;

            // Test role parameter manipulation
            tests_run += 1;
            if let Some(vuln) = self.test_role_parameter_manipulation(endpoint).await? {
                vulnerabilities.push(vuln);
            }

            // Test path traversal to admin functions
            tests_run += 1;
            if let Some(vuln) = self.test_path_traversal_bypass(endpoint).await? {
                vulnerabilities.push(vuln);
            }
        }

        // Phase 5: Test version enumeration bypass
        let (version_vulns, version_tests) = self.test_version_enumeration(url).await?;
        vulnerabilities.extend(version_vulns);
        tests_run += version_tests;

        // Phase 6: GraphQL-specific tests if GraphQL detected
        if api_pattern == ApiPattern::GraphQL {
            let (graphql_vulns, graphql_tests) =
                self.test_graphql_function_authorization(url).await?;
            vulnerabilities.extend(graphql_vulns);
            tests_run += graphql_tests;
        }

        // Phase 7: Test function category access patterns
        let (category_vulns, category_tests) = self
            .test_function_category_access(url, &admin_endpoints)
            .await?;
        vulnerabilities.extend(category_vulns);
        tests_run += category_tests;

        info!(
            "[BFLA] Scan completed: {} tests run, {} vulnerabilities found",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect API pattern from response
    fn detect_api_pattern(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
    ) -> ApiPattern {
        let body = &response.body;
        let body_lower = body.to_lowercase();
        let url_lower = url.to_lowercase();

        // GraphQL detection
        if url_lower.contains("/graphql") || body.contains("__schema") || body.contains("query {") {
            return ApiPattern::GraphQL;
        }

        // JSON-RPC detection
        if body.contains("\"jsonrpc\"")
            || body.contains("\"method\"") && body.contains("\"params\"")
        {
            return ApiPattern::JsonRpc;
        }

        // SOAP detection
        if body_lower.contains("soap:envelope") || body_lower.contains("wsdl") {
            return ApiPattern::Soap;
        }

        // REST detection (most common)
        if let Some(content_type) = response.headers.get("content-type") {
            if content_type.contains("application/json") {
                return ApiPattern::Rest;
            }
        }

        // Check URL patterns for REST
        if url_lower.contains("/api/")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/rest/")
        {
            return ApiPattern::Rest;
        }

        ApiPattern::Unknown
    }

    /// Detect authorization scheme from response
    fn detect_auth_scheme(&self, response: &crate::http_client::HttpResponse) -> AuthScheme {
        let headers = &response.headers;
        let body = &response.body;

        // Check for JWT indicators
        if body.contains("eyJ")
            || headers
                .get("authorization")
                .map_or(false, |h| h.contains("Bearer"))
        {
            return AuthScheme::Jwt;
        }

        // Check for API key
        if headers.contains_key("x-api-key") || body.contains("api_key") || body.contains("apiKey")
        {
            return AuthScheme::ApiKey;
        }

        // Check for OAuth
        if body.contains("oauth") || body.contains("access_token") {
            return AuthScheme::OAuth;
        }

        // Check for session cookies
        if let Some(cookie) = headers.get("set-cookie") {
            let cookie_lower = cookie.to_lowercase();
            if cookie_lower.contains("session")
                || cookie_lower.contains("phpsessid")
                || cookie_lower.contains("jsessionid")
            {
                return AuthScheme::Session;
            }
        }

        // Check for Basic auth
        if headers
            .get("www-authenticate")
            .map_or(false, |h| h.contains("Basic"))
        {
            return AuthScheme::Basic;
        }

        AuthScheme::Unknown
    }

    /// Discover admin/privileged endpoints
    async fn discover_admin_endpoints(
        &self,
        base_url: &str,
        baseline_response: &crate::http_client::HttpResponse,
    ) -> Result<Vec<EndpointInfo>> {
        let mut endpoints = Vec::new();
        let parsed_url = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Ok(endpoints),
        };

        let base = format!(
            "{}://{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or("")
        );

        // Common admin endpoint patterns
        let admin_patterns = vec![
            // Top-level admin paths
            ("/admin", PrivilegeLevel::Admin, FunctionCategory::General),
            ("/admin/", PrivilegeLevel::Admin, FunctionCategory::General),
            (
                "/administrator",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/management",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/internal",
                PrivilegeLevel::Elevated,
                FunctionCategory::General,
            ),
            (
                "/console",
                PrivilegeLevel::Admin,
                FunctionCategory::SystemOperations,
            ),
            (
                "/dashboard",
                PrivilegeLevel::Elevated,
                FunctionCategory::Analytics,
            ),
            ("/panel", PrivilegeLevel::Admin, FunctionCategory::General),
            (
                "/control",
                PrivilegeLevel::Admin,
                FunctionCategory::SystemOperations,
            ),
            (
                "/superadmin",
                PrivilegeLevel::SuperAdmin,
                FunctionCategory::General,
            ),
            // API admin paths
            (
                "/api/admin",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/api/v1/admin",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/api/v2/admin",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/api/internal",
                PrivilegeLevel::Elevated,
                FunctionCategory::General,
            ),
            (
                "/api/management",
                PrivilegeLevel::Admin,
                FunctionCategory::General,
            ),
            (
                "/api/admin/users",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            (
                "/api/admin/roles",
                PrivilegeLevel::Admin,
                FunctionCategory::RoleManagement,
            ),
            (
                "/api/admin/config",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            (
                "/api/admin/settings",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            // User management
            (
                "/api/users/create",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            (
                "/api/users/delete",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            (
                "/api/users/all",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            (
                "/api/users/list",
                PrivilegeLevel::Elevated,
                FunctionCategory::UserManagement,
            ),
            (
                "/users/manage",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            (
                "/users/admin",
                PrivilegeLevel::Admin,
                FunctionCategory::UserManagement,
            ),
            // Configuration
            (
                "/api/config",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            (
                "/api/settings",
                PrivilegeLevel::Elevated,
                FunctionCategory::Configuration,
            ),
            (
                "/api/configuration",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            (
                "/settings/system",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            (
                "/config/global",
                PrivilegeLevel::Admin,
                FunctionCategory::Configuration,
            ),
            // Data export/import
            (
                "/api/export",
                PrivilegeLevel::Elevated,
                FunctionCategory::DataExport,
            ),
            (
                "/api/import",
                PrivilegeLevel::Elevated,
                FunctionCategory::DataExport,
            ),
            (
                "/api/backup",
                PrivilegeLevel::Admin,
                FunctionCategory::DataExport,
            ),
            (
                "/api/data/export",
                PrivilegeLevel::Elevated,
                FunctionCategory::DataExport,
            ),
            (
                "/api/data/dump",
                PrivilegeLevel::Admin,
                FunctionCategory::DataExport,
            ),
            (
                "/export/all",
                PrivilegeLevel::Admin,
                FunctionCategory::DataExport,
            ),
            // System operations
            (
                "/api/system",
                PrivilegeLevel::Admin,
                FunctionCategory::SystemOperations,
            ),
            (
                "/api/health",
                PrivilegeLevel::Authenticated,
                FunctionCategory::SystemOperations,
            ),
            (
                "/api/status",
                PrivilegeLevel::Authenticated,
                FunctionCategory::SystemOperations,
            ),
            (
                "/api/restart",
                PrivilegeLevel::SuperAdmin,
                FunctionCategory::SystemOperations,
            ),
            (
                "/api/shutdown",
                PrivilegeLevel::SuperAdmin,
                FunctionCategory::SystemOperations,
            ),
            (
                "/system/info",
                PrivilegeLevel::Admin,
                FunctionCategory::SystemOperations,
            ),
            // Audit/logging
            (
                "/api/audit",
                PrivilegeLevel::Admin,
                FunctionCategory::AuditLogs,
            ),
            (
                "/api/logs",
                PrivilegeLevel::Admin,
                FunctionCategory::AuditLogs,
            ),
            (
                "/api/audit/logs",
                PrivilegeLevel::Admin,
                FunctionCategory::AuditLogs,
            ),
            (
                "/logs/access",
                PrivilegeLevel::Admin,
                FunctionCategory::AuditLogs,
            ),
            (
                "/logs/security",
                PrivilegeLevel::Admin,
                FunctionCategory::AuditLogs,
            ),
            // Financial operations
            (
                "/api/billing",
                PrivilegeLevel::Elevated,
                FunctionCategory::FinancialOps,
            ),
            (
                "/api/payments",
                PrivilegeLevel::Elevated,
                FunctionCategory::FinancialOps,
            ),
            (
                "/api/transactions",
                PrivilegeLevel::Elevated,
                FunctionCategory::FinancialOps,
            ),
            (
                "/api/refund",
                PrivilegeLevel::Elevated,
                FunctionCategory::FinancialOps,
            ),
            (
                "/api/invoice/create",
                PrivilegeLevel::Elevated,
                FunctionCategory::FinancialOps,
            ),
            // Role management
            (
                "/api/roles",
                PrivilegeLevel::Admin,
                FunctionCategory::RoleManagement,
            ),
            (
                "/api/permissions",
                PrivilegeLevel::Admin,
                FunctionCategory::RoleManagement,
            ),
            (
                "/api/acl",
                PrivilegeLevel::Admin,
                FunctionCategory::RoleManagement,
            ),
            (
                "/roles/assign",
                PrivilegeLevel::Admin,
                FunctionCategory::RoleManagement,
            ),
            // Content moderation
            (
                "/api/moderate",
                PrivilegeLevel::Elevated,
                FunctionCategory::ContentModeration,
            ),
            (
                "/api/content/approve",
                PrivilegeLevel::Elevated,
                FunctionCategory::ContentModeration,
            ),
            (
                "/api/content/delete",
                PrivilegeLevel::Elevated,
                FunctionCategory::ContentModeration,
            ),
            // Analytics
            (
                "/api/analytics",
                PrivilegeLevel::Elevated,
                FunctionCategory::Analytics,
            ),
            (
                "/api/reports",
                PrivilegeLevel::Elevated,
                FunctionCategory::Analytics,
            ),
            (
                "/api/stats",
                PrivilegeLevel::Elevated,
                FunctionCategory::Analytics,
            ),
            (
                "/api/metrics",
                PrivilegeLevel::Elevated,
                FunctionCategory::Analytics,
            ),
            // Deployment
            (
                "/api/deploy",
                PrivilegeLevel::Admin,
                FunctionCategory::Deployment,
            ),
            (
                "/api/release",
                PrivilegeLevel::Admin,
                FunctionCategory::Deployment,
            ),
            (
                "/api/publish",
                PrivilegeLevel::Elevated,
                FunctionCategory::Deployment,
            ),
        ];

        // Also extract endpoints from the response body
        let extracted_paths = self.extract_api_paths_from_body(&baseline_response.body);

        // Test common admin patterns
        for (path, privilege_level, category) in admin_patterns {
            let full_url = format!("{}{}", base, path);

            match self.http_client.get(&full_url).await {
                Ok(response) => {
                    // Consider endpoint exists if not 404
                    if response.status_code != 404 {
                        let requires_auth =
                            response.status_code == 401 || response.status_code == 403;

                        endpoints.push(EndpointInfo {
                            url: full_url,
                            path: path.to_string(),
                            method: "GET".to_string(),
                            privilege_level: privilege_level.clone(),
                            function_category: category.clone(),
                            requires_auth,
                        });

                        debug!(
                            "[BFLA] Found endpoint: {} (status: {})",
                            path, response.status_code
                        );
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Error checking {}: {}", path, e);
                }
            }
        }

        // Add extracted paths
        for path in extracted_paths {
            let full_url = format!("{}{}", base, path);
            if !endpoints.iter().any(|e| e.url == full_url) {
                let privilege_level = self.classify_path_privilege(&path);
                let category = self.classify_function_category(&path);

                endpoints.push(EndpointInfo {
                    url: full_url,
                    path: path.clone(),
                    method: "GET".to_string(),
                    privilege_level,
                    function_category: category,
                    requires_auth: true,
                });
            }
        }

        Ok(endpoints)
    }

    /// Extract API paths from response body
    fn extract_api_paths_from_body(&self, body: &str) -> Vec<String> {
        let mut paths = HashSet::new();

        // Pattern for API paths
        let patterns = vec![
            r#"["'](/api/[a-zA-Z0-9_/-]+)["']"#,
            r#"["'](/admin[a-zA-Z0-9_/-]*)["']"#,
            r#"["'](/management[a-zA-Z0-9_/-]*)["']"#,
            r#"["'](/internal[a-zA-Z0-9_/-]*)["']"#,
            r#"href=["']([^"']*admin[^"']*)["']"#,
            r#"action=["']([^"']*admin[^"']*)["']"#,
        ];

        for pattern_str in patterns {
            if let Ok(re) = Regex::new(pattern_str) {
                for cap in re.captures_iter(body) {
                    if let Some(path_match) = cap.get(1) {
                        let path = path_match.as_str();
                        // Filter out static assets
                        if !path.contains(".js")
                            && !path.contains(".css")
                            && !path.contains(".png")
                            && !path.contains(".jpg")
                            && !path.contains(".svg")
                        {
                            if path.starts_with('/') {
                                paths.insert(path.to_string());
                            }
                        }
                    }
                }
            }
        }

        paths.into_iter().collect()
    }

    /// Classify path privilege level
    fn classify_path_privilege(&self, path: &str) -> PrivilegeLevel {
        let path_lower = path.to_lowercase();

        if path_lower.contains("superadmin") || path_lower.contains("super_admin") {
            return PrivilegeLevel::SuperAdmin;
        }

        if path_lower.contains("admin")
            || path_lower.contains("management")
            || path_lower.contains("system")
        {
            return PrivilegeLevel::Admin;
        }

        if path_lower.contains("internal")
            || path_lower.contains("moderate")
            || path_lower.contains("elevated")
        {
            return PrivilegeLevel::Elevated;
        }

        if path_lower.contains("user") || path_lower.contains("account") {
            return PrivilegeLevel::Authenticated;
        }

        PrivilegeLevel::Authenticated
    }

    /// Classify function category
    fn classify_function_category(&self, path: &str) -> FunctionCategory {
        let path_lower = path.to_lowercase();

        if path_lower.contains("user") || path_lower.contains("account") {
            return FunctionCategory::UserManagement;
        }
        if path_lower.contains("config") || path_lower.contains("setting") {
            return FunctionCategory::Configuration;
        }
        if path_lower.contains("export")
            || path_lower.contains("import")
            || path_lower.contains("backup")
        {
            return FunctionCategory::DataExport;
        }
        if path_lower.contains("system")
            || path_lower.contains("restart")
            || path_lower.contains("shutdown")
        {
            return FunctionCategory::SystemOperations;
        }
        if path_lower.contains("audit") || path_lower.contains("log") {
            return FunctionCategory::AuditLogs;
        }
        if path_lower.contains("billing")
            || path_lower.contains("payment")
            || path_lower.contains("invoice")
        {
            return FunctionCategory::FinancialOps;
        }
        if path_lower.contains("role")
            || path_lower.contains("permission")
            || path_lower.contains("acl")
        {
            return FunctionCategory::RoleManagement;
        }
        if path_lower.contains("moderate") || path_lower.contains("approve") {
            return FunctionCategory::ContentModeration;
        }
        if path_lower.contains("analytics")
            || path_lower.contains("report")
            || path_lower.contains("stats")
        {
            return FunctionCategory::Analytics;
        }
        if path_lower.contains("deploy") || path_lower.contains("release") {
            return FunctionCategory::Deployment;
        }

        FunctionCategory::General
    }

    /// Test access without any authorization
    async fn test_no_auth_access(&self, endpoint: &EndpointInfo) -> Result<Option<Vulnerability>> {
        debug!("[BFLA] Testing no-auth access: {}", endpoint.url);

        let response = self.http_client.get(&endpoint.url).await?;

        // Check if we got access without authentication
        if response.status_code == 200 {
            let is_real_content =
                self.is_privileged_content(&response.body, &endpoint.function_category);

            if is_real_content {
                return Ok(Some(self.create_bfla_vulnerability(
                    &endpoint.url,
                    &endpoint.path,
                    "GET",
                    "No Authorization",
                    "Accessed admin endpoint without any authentication",
                    &response,
                    &endpoint.function_category,
                    &endpoint.privilege_level,
                )));
            }
        }

        Ok(None)
    }

    /// Test with removed authorization header
    async fn test_removed_auth_header(
        &self,
        endpoint: &EndpointInfo,
        auth_scheme: &AuthScheme,
    ) -> Result<Option<Vulnerability>> {
        debug!("[BFLA] Testing removed auth header: {}", endpoint.url);

        // Only test if endpoint previously required auth
        if !endpoint.requires_auth {
            return Ok(None);
        }

        // Headers that bypass auth checks
        let bypass_headers = match auth_scheme {
            AuthScheme::Jwt => vec![
                ("Authorization", "Bearer invalidtoken"),
                ("Authorization", "Bearer "),
                ("X-Auth-Token", ""),
            ],
            AuthScheme::ApiKey => vec![
                ("X-Api-Key", ""),
                ("X-API-Key", "invalid"),
                ("Api-Key", "test"),
            ],
            AuthScheme::Session => vec![("Cookie", "session=invalid"), ("Cookie", "")],
            _ => vec![("Authorization", ""), ("X-Auth-Token", "")],
        };

        for (header_name, header_value) in bypass_headers {
            let headers = vec![(header_name.to_string(), header_value.to_string())];

            match self
                .http_client
                .get_with_headers(&endpoint.url, headers)
                .await
            {
                Ok(response) => {
                    if response.status_code == 200 {
                        let is_real_content =
                            self.is_privileged_content(&response.body, &endpoint.function_category);

                        if is_real_content {
                            return Ok(Some(self.create_bfla_vulnerability(
                                &endpoint.url,
                                &endpoint.path,
                                "GET",
                                &format!("Empty/Invalid {} Header", header_name),
                                &format!(
                                    "Bypassed authorization using {}: {}",
                                    header_name, header_value
                                ),
                                &response,
                                &endpoint.function_category,
                                &endpoint.privilege_level,
                            )));
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Header bypass test error: {}", e);
                }
            }
        }

        Ok(None)
    }

    /// Test HTTP method tampering
    async fn test_http_method_tampering(
        &self,
        endpoint: &EndpointInfo,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let methods_to_test = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

        for method in methods_to_test {
            if method == endpoint.method {
                continue;
            }

            tests_run += 1;

            match self
                .http_client
                .request_with_method(method, &endpoint.url)
                .await
            {
                Ok(response) => {
                    // Check if different method bypassed auth
                    if response.status_code == 200 && endpoint.requires_auth {
                        let is_real_content =
                            self.is_privileged_content(&response.body, &endpoint.function_category);

                        if is_real_content {
                            vulnerabilities.push(self.create_bfla_vulnerability(
                                &endpoint.url,
                                &endpoint.path,
                                method,
                                "HTTP Method Tampering",
                                &format!(
                                    "Changed HTTP method from {} to {} to bypass authorization",
                                    endpoint.method, method
                                ),
                                &response,
                                &endpoint.function_category,
                                &endpoint.privilege_level,
                            ));
                        }
                    }

                    // Check for method-specific vulnerabilities
                    if method == "DELETE" && response.status_code == 200 {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "BFLA - Unprotected DELETE Method".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authorization".to_string(),
                            url: endpoint.url.clone(),
                            parameter: Some("HTTP Method".to_string()),
                            payload: format!("DELETE {}", endpoint.path),
                            description: format!(
                                "The DELETE method is allowed on admin endpoint {} without proper authorization. \
                                This could allow attackers to delete critical data or resources.",
                                endpoint.path
                            ),
                            evidence: Some(format!("DELETE request returned HTTP 200")),
                            cwe: "CWE-285".to_string(),
                            cvss: 9.0,
                            verified: true,
                            false_positive: false,
                            remediation: self.get_bfla_remediation(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Method {} test error: {}", method, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test role parameter manipulation
    async fn test_role_parameter_manipulation(
        &self,
        endpoint: &EndpointInfo,
    ) -> Result<Option<Vulnerability>> {
        debug!(
            "[BFLA] Testing role parameter manipulation: {}",
            endpoint.url
        );

        let role_params = vec![
            ("role", "admin"),
            ("role", "administrator"),
            ("role", "superuser"),
            ("user_role", "admin"),
            ("userRole", "admin"),
            ("is_admin", "true"),
            ("isAdmin", "true"),
            ("admin", "true"),
            ("privilege", "admin"),
            ("access_level", "admin"),
            ("accessLevel", "9999"),
            ("permissions", "all"),
        ];

        for (param_name, param_value) in role_params {
            let test_url = if endpoint.url.contains('?') {
                format!("{}&{}={}", endpoint.url, param_name, param_value)
            } else {
                format!("{}?{}={}", endpoint.url, param_name, param_value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let is_real_content =
                            self.is_privileged_content(&response.body, &endpoint.function_category);

                        if is_real_content {
                            return Ok(Some(self.create_bfla_vulnerability(
                                &test_url,
                                &endpoint.path,
                                "GET",
                                "Role Parameter Manipulation",
                                &format!(
                                    "Bypassed authorization by setting {}={}",
                                    param_name, param_value
                                ),
                                &response,
                                &endpoint.function_category,
                                &endpoint.privilege_level,
                            )));
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Role param test error: {}", e);
                }
            }
        }

        Ok(None)
    }

    /// Test path traversal to admin functions
    async fn test_path_traversal_bypass(
        &self,
        endpoint: &EndpointInfo,
    ) -> Result<Option<Vulnerability>> {
        debug!("[BFLA] Testing path traversal bypass: {}", endpoint.url);

        let parsed = match url::Url::parse(&endpoint.url) {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };

        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        let path_bypasses = vec![
            // Path normalization bypasses
            format!("{}/./admin", base),
            format!("{}/../admin", base),
            format!("{}/;/admin", base),
            format!("{}/.;/admin", base),
            format!("{}/..;/admin", base),
            format!("{}//admin", base),
            format!("{}/%2e/admin", base),
            format!("{}/%2e%2e/admin", base),
            format!("{}/.%2e/admin", base),
            format!("{}/admin%00", base),
            format!("{}/admin%20", base),
            format!("{}/admin%09", base),
            // Case variation
            format!("{}/ADMIN", base),
            format!("{}/Admin", base),
            format!("{}/aDmIn", base),
        ];

        for bypass_url in path_bypasses {
            match self.http_client.get(&bypass_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let is_real_content =
                            self.is_privileged_content(&response.body, &endpoint.function_category);

                        if is_real_content {
                            return Ok(Some(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "BFLA - Path Traversal Authorization Bypass".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "Authorization".to_string(),
                                url: bypass_url.clone(),
                                parameter: Some("Path".to_string()),
                                payload: bypass_url.clone(),
                                description: format!(
                                    "Admin functionality accessible via path traversal bypass. \
                                    The application's URL normalization allows bypassing function-level authorization checks."
                                ),
                                evidence: Some(format!("Bypass URL {} returned HTTP 200 with admin content", bypass_url)),
                                cwe: "CWE-285".to_string(),
                                cvss: 8.5,
                                verified: true,
                                false_positive: false,
                                remediation: self.get_bfla_remediation(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            }));
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Path traversal test error: {}", e);
                }
            }
        }

        Ok(None)
    }

    /// Test API version enumeration bypass
    async fn test_version_enumeration(
        &self,
        base_url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let parsed = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Ok((vulnerabilities, 0)),
        };

        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Version enumeration patterns
        let version_patterns = vec![
            ("/api/v0/admin", "/api/v1/admin"),
            ("/api/v1/admin", "/api/v2/admin"),
            ("/api/v2/admin", "/api/v3/admin"),
            ("/api/admin", "/api/v0/admin"),
            ("/api/admin", "/api/beta/admin"),
            ("/api/admin", "/api/internal/admin"),
            ("/api/admin", "/api/dev/admin"),
            ("/api/admin", "/api/test/admin"),
        ];

        for (protected_path, bypass_path) in version_patterns {
            tests_run += 1;

            // First check if protected path is actually protected
            let protected_url = format!("{}{}", base, protected_path);
            let protected_response = match self.http_client.get(&protected_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if protected_response.status_code != 401 && protected_response.status_code != 403 {
                continue;
            }

            // Try the bypass version
            let bypass_url = format!("{}{}", base, bypass_path);
            match self.http_client.get(&bypass_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let is_real_content =
                            self.is_privileged_content(&response.body, &FunctionCategory::General);

                        if is_real_content {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "BFLA - API Version Bypass".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "Authorization".to_string(),
                                url: bypass_url.clone(),
                                parameter: Some("API Version".to_string()),
                                payload: format!("{} -> {}", protected_path, bypass_path),
                                description: format!(
                                    "Admin functionality accessible via different API version. \
                                    Protected path '{}' returns 401/403, but '{}' is accessible. \
                                    This indicates inconsistent authorization across API versions.",
                                    protected_path, bypass_path
                                ),
                                evidence: Some(format!(
                                    "Protected {} returned {}, Bypass {} returned 200",
                                    protected_path, protected_response.status_code, bypass_path
                                )),
                                cwe: "CWE-285".to_string(),
                                cvss: 8.1,
                                verified: true,
                                false_positive: false,
                                remediation: self.get_bfla_remediation(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] Version bypass test error: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL function-level authorization
    async fn test_graphql_function_authorization(
        &self,
        base_url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let parsed = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Ok((vulnerabilities, 0)),
        };

        let graphql_url = format!(
            "{}://{}/graphql",
            parsed.scheme(),
            parsed.host_str().unwrap_or("")
        );

        // Admin mutations to test
        let admin_mutations = vec![
            (
                r#"{"query":"mutation { createUser(input: {email: \"test@test.com\", role: \"admin\"}) { id } }"}"#,
                "createUser with admin role",
                FunctionCategory::UserManagement,
            ),
            (
                r#"{"query":"mutation { deleteUser(id: \"1\") { success } }"}"#,
                "deleteUser",
                FunctionCategory::UserManagement,
            ),
            (
                r#"{"query":"mutation { updateRole(userId: \"1\", role: \"admin\") { success } }"}"#,
                "updateRole to admin",
                FunctionCategory::RoleManagement,
            ),
            (
                r#"{"query":"mutation { updateConfig(key: \"debug\", value: \"true\") { success } }"}"#,
                "updateConfig",
                FunctionCategory::Configuration,
            ),
            (
                r#"{"query":"mutation { exportAllData { url } }"}"#,
                "exportAllData",
                FunctionCategory::DataExport,
            ),
            (
                r#"{"query":"query { allUsers { id email role } }"}"#,
                "allUsers query",
                FunctionCategory::UserManagement,
            ),
            (
                r#"{"query":"query { systemConfig { key value } }"}"#,
                "systemConfig query",
                FunctionCategory::Configuration,
            ),
            (
                r#"{"query":"query { auditLogs { action user timestamp } }"}"#,
                "auditLogs query",
                FunctionCategory::AuditLogs,
            ),
        ];

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        for (query, operation_name, category) in admin_mutations {
            tests_run += 1;

            match self
                .http_client
                .post_with_headers(&graphql_url, query, headers.clone())
                .await
            {
                Ok(response) => {
                    if response.status_code == 200 && !response.body.contains("\"errors\"") {
                        // Check if we got actual data back
                        if response.body.contains("\"data\"") && !response.body.contains("null") {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "BFLA - GraphQL Admin Operation Accessible".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Authorization".to_string(),
                                url: graphql_url.clone(),
                                parameter: Some("GraphQL Operation".to_string()),
                                payload: operation_name.to_string(),
                                description: format!(
                                    "GraphQL admin operation '{}' is accessible without proper authorization. \
                                    This allows unauthorized users to execute privileged {} operations.",
                                    operation_name,
                                    format!("{:?}", category).to_lowercase()
                                ),
                                evidence: Some(format!(
                                    "GraphQL {} operation succeeded without authorization",
                                    operation_name
                                )),
                                cwe: "CWE-285".to_string(),
                                cvss: 9.0,
                                verified: true,
                                false_positive: false,
                                remediation: self.get_graphql_bfla_remediation(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] GraphQL test error: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test access patterns for specific function categories
    async fn test_function_category_access(
        &self,
        base_url: &str,
        _admin_endpoints: &[EndpointInfo],
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let parsed = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return Ok((vulnerabilities, 0)),
        };

        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // High-risk function patterns
        let high_risk_patterns: Vec<(&str, FunctionCategory, &str)> = vec![
            // User management - critical
            (
                "/api/users/promote",
                FunctionCategory::UserManagement,
                "POST",
            ),
            (
                "/api/users/demote",
                FunctionCategory::UserManagement,
                "POST",
            ),
            ("/api/users/ban", FunctionCategory::UserManagement, "POST"),
            ("/api/users/unban", FunctionCategory::UserManagement, "POST"),
            (
                "/api/admin/impersonate",
                FunctionCategory::UserManagement,
                "POST",
            ),
            // Configuration - critical
            (
                "/api/config/security",
                FunctionCategory::Configuration,
                "PUT",
            ),
            ("/api/config/auth", FunctionCategory::Configuration, "PUT"),
            ("/api/settings/cors", FunctionCategory::Configuration, "PUT"),
            // System operations - critical
            (
                "/api/system/restart",
                FunctionCategory::SystemOperations,
                "POST",
            ),
            (
                "/api/system/maintenance",
                FunctionCategory::SystemOperations,
                "POST",
            ),
            (
                "/api/cache/clear",
                FunctionCategory::SystemOperations,
                "POST",
            ),
            (
                "/api/db/migrate",
                FunctionCategory::SystemOperations,
                "POST",
            ),
            // Financial - critical
            (
                "/api/billing/adjust",
                FunctionCategory::FinancialOps,
                "POST",
            ),
            ("/api/credits/add", FunctionCategory::FinancialOps, "POST"),
            (
                "/api/subscription/override",
                FunctionCategory::FinancialOps,
                "POST",
            ),
        ];

        for (path, category, method) in high_risk_patterns {
            tests_run += 1;
            let full_url = format!("{}{}", base, path);

            let response = if method == "POST" {
                self.http_client.post(&full_url, String::new()).await
            } else {
                self.http_client.get(&full_url).await
            };

            match response {
                Ok(response) => {
                    if response.status_code == 200 {
                        let is_real_content = self.is_privileged_content(&response.body, &category);

                        if is_real_content || !response.body.contains("error") {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: format!("BFLA - Unprotected {} Function", format!("{:?}", category)),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Authorization".to_string(),
                                url: full_url.clone(),
                                parameter: Some("Function".to_string()),
                                payload: format!("{} {}", method, path),
                                description: format!(
                                    "Critical {} function '{}' is accessible without proper authorization. \
                                    This allows unauthorized users to perform privileged operations.",
                                    format!("{:?}", category).to_lowercase(),
                                    path
                                ),
                                evidence: Some(format!(
                                    "{} {} returned HTTP 200",
                                    method, path
                                )),
                                cwe: "CWE-285".to_string(),
                                cvss: 9.5,
                                verified: true,
                                false_positive: false,
                                remediation: self.get_bfla_remediation(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("[BFLA] High-risk function test error: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if response contains privileged content
    fn is_privileged_content(&self, body: &str, category: &FunctionCategory) -> bool {
        let body_lower = body.to_lowercase();

        // Check for error responses
        if body_lower.contains("error") && body_lower.contains("unauthorized") {
            return false;
        }
        if body_lower.contains("access denied") || body_lower.contains("forbidden") {
            return false;
        }

        // Minimum content length
        if body.len() < 50 {
            return false;
        }

        // Category-specific content indicators
        let indicators = match category {
            FunctionCategory::UserManagement => {
                vec!["users", "email", "role", "permissions", "account"]
            }
            FunctionCategory::Configuration => {
                vec!["config", "settings", "enabled", "disabled", "value"]
            }
            FunctionCategory::DataExport => {
                vec!["export", "download", "data", "file", "url"]
            }
            FunctionCategory::SystemOperations => {
                vec!["status", "health", "system", "process", "memory"]
            }
            FunctionCategory::AuditLogs => {
                vec!["log", "audit", "action", "timestamp", "event"]
            }
            FunctionCategory::FinancialOps => {
                vec!["balance", "transaction", "payment", "amount", "invoice"]
            }
            FunctionCategory::RoleManagement => {
                vec!["role", "permission", "grant", "revoke", "access"]
            }
            FunctionCategory::ContentModeration => {
                vec!["content", "approve", "reject", "moderate", "flag"]
            }
            FunctionCategory::Analytics => {
                vec!["stats", "metrics", "analytics", "report", "chart"]
            }
            FunctionCategory::Deployment => {
                vec!["deploy", "release", "version", "build", "artifact"]
            }
            FunctionCategory::General => {
                vec!["admin", "management", "dashboard", "panel"]
            }
        };

        // Check for JSON structure
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');

        // Check for HTML admin panel
        let is_admin_html = body_lower.contains("dashboard")
            || body_lower.contains("admin panel")
            || body_lower.contains("management");

        // Count matching indicators
        let matches = indicators
            .iter()
            .filter(|ind| body_lower.contains(*ind))
            .count();

        (is_json && matches >= 2) || (is_admin_html && matches >= 1) || matches >= 3
    }

    /// Create BFLA vulnerability
    fn create_bfla_vulnerability(
        &self,
        url: &str,
        path: &str,
        method: &str,
        technique: &str,
        detail: &str,
        response: &crate::http_client::HttpResponse,
        category: &FunctionCategory,
        privilege_level: &PrivilegeLevel,
    ) -> Vulnerability {
        let severity = match privilege_level {
            PrivilegeLevel::SuperAdmin => Severity::Critical,
            PrivilegeLevel::Admin => Severity::Critical,
            PrivilegeLevel::Elevated => Severity::High,
            _ => Severity::High,
        };

        let cvss = match privilege_level {
            PrivilegeLevel::SuperAdmin => 9.8,
            PrivilegeLevel::Admin => 9.0,
            PrivilegeLevel::Elevated => 8.1,
            _ => 7.5,
        };

        Vulnerability {
            id: generate_uuid(),
            vuln_type: format!("BFLA - Broken Function Level Authorization ({})", technique),
            severity,
            confidence: Confidence::High,
            category: "Authorization".to_string(),
            url: url.to_string(),
            parameter: Some(format!("{} method", method)),
            payload: format!("{} {} - {}", method, path, technique),
            description: format!(
                "Critical BFLA vulnerability detected on {} function: {}. \
                {} endpoint '{}' is accessible without proper {:?}-level authorization. \
                {} This allows unauthorized users to access privileged {} functionality.",
                format!("{:?}", category).to_lowercase(),
                path,
                format!("{:?}", privilege_level),
                path,
                privilege_level,
                detail,
                format!("{:?}", category).to_lowercase()
            ),
            evidence: Some(format!(
                "{} {} returned HTTP {} with {} bytes of {} content",
                method,
                path,
                response.status_code,
                response.body.len(),
                format!("{:?}", category).to_lowercase()
            )),
            cwe: "CWE-285".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_bfla_remediation(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get BFLA remediation advice
    fn get_bfla_remediation(&self) -> String {
        r#"CRITICAL: Implement proper function-level authorization

1. **Implement Role-Based Access Control (RBAC)**
   ```python
   from functools import wraps

   def require_role(required_role):
       def decorator(f):
           @wraps(f)
           def decorated_function(*args, **kwargs):
               user = get_current_user()
               if not user or user.role != required_role:
                   abort(403)  # Forbidden
               return f(*args, **kwargs)
           return decorated_function
       return decorator

   @app.route('/api/admin/users')
   @require_role('admin')
   def admin_users():
       return get_all_users()
   ```

2. **Centralized Authorization Middleware**
   ```javascript
   // Express.js middleware
   const authorizeAdmin = (req, res, next) => {
       const user = req.user;
       if (!user || !user.roles.includes('admin')) {
           return res.status(403).json({ error: 'Admin access required' });
       }
       next();
   };

   app.use('/api/admin/*', authorizeAdmin);
   ```

3. **Policy-Based Authorization**
   ```java
   @PreAuthorize("hasRole('ADMIN')")
   @GetMapping("/api/admin/config")
   public ResponseEntity<?> getConfig() {
       return ResponseEntity.ok(configService.getConfig());
   }
   ```

4. **Verify Authorization on Every Request**
   - Never rely on client-side role checks
   - Always verify roles server-side
   - Check both authentication AND authorization

5. **Consistent API Versioning**
   - Apply same authorization to all API versions
   - Deprecate old versions properly
   - Audit all endpoints across versions

6. **HTTP Method Authorization**
   - Authorize each HTTP method separately
   - DELETE/PUT/PATCH typically need higher privileges
   - Don't assume GET is safe

7. **Audit and Monitor**
   - Log all admin function access
   - Alert on unauthorized access attempts
   - Regular access control reviews

8. **Principle of Least Privilege**
   - Grant minimum required permissions
   - Separate read/write permissions
   - Use granular roles, not just admin/user

9. **Defense in Depth**
   - Multiple authorization layers
   - Network-level restrictions for admin endpoints
   - IP whitelisting for critical functions

References:
- OWASP API5:2023 - https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
"#.to_string()
    }

    /// Get GraphQL-specific BFLA remediation
    fn get_graphql_bfla_remediation(&self) -> String {
        r#"CRITICAL: Implement GraphQL function-level authorization

1. **Field-Level Authorization with Directives**
   ```graphql
   type Query {
       publicData: String
       adminData: String @auth(requires: ADMIN)
       allUsers: [User!]! @auth(requires: ADMIN)
   }

   type Mutation {
       createUser(input: CreateUserInput!): User! @auth(requires: ADMIN)
       deleteUser(id: ID!): Boolean! @auth(requires: ADMIN)
   }
   ```

2. **Resolver-Level Authorization**
   ```javascript
   const resolvers = {
       Mutation: {
           deleteUser: async (_, { id }, context) => {
               // Always check authorization in resolver
               if (!context.user || context.user.role !== 'ADMIN') {
                   throw new ForbiddenError('Admin access required');
               }
               return await UserService.deleteUser(id);
           }
       }
   };
   ```

3. **Use GraphQL Shield**
   ```javascript
   import { shield, rule, and, or } from 'graphql-shield';

   const isAdmin = rule()(async (parent, args, ctx) => {
       return ctx.user && ctx.user.role === 'ADMIN';
   });

   const permissions = shield({
       Query: {
           allUsers: isAdmin,
           systemConfig: isAdmin,
       },
       Mutation: {
           createUser: isAdmin,
           deleteUser: isAdmin,
       }
   });
   ```

4. **Disable Introspection in Production**
   ```javascript
   const server = new ApolloServer({
       schema,
       introspection: process.env.NODE_ENV !== 'production',
   });
   ```

5. **Query Complexity Analysis**
   - Limit query depth
   - Limit field count
   - Prevent expensive queries

References:
- GraphQL Security: https://graphql.org/learn/authorization/
- GraphQL Shield: https://github.com/maticzav/graphql-shield
"#
        .to_string()
    }
}

/// Generate unique vulnerability ID
fn generate_uuid() -> String {
    let mut rng = rand::rng();
    format!(
        "bfla_{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    use crate::http_client::HttpResponse;
    use std::collections::HashMap;

    fn create_test_scanner() -> BrokenFunctionAuthScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        BrokenFunctionAuthScanner::new(http_client)
    }

    #[test]
    fn test_classify_path_privilege() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.classify_path_privilege("/api/superadmin/users"),
            PrivilegeLevel::SuperAdmin
        );
        assert_eq!(
            scanner.classify_path_privilege("/api/admin/config"),
            PrivilegeLevel::Admin
        );
        assert_eq!(
            scanner.classify_path_privilege("/api/internal/stats"),
            PrivilegeLevel::Elevated
        );
        assert_eq!(
            scanner.classify_path_privilege("/api/users/me"),
            PrivilegeLevel::Authenticated
        );
    }

    #[test]
    fn test_classify_function_category() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.classify_function_category("/api/users/create"),
            FunctionCategory::UserManagement
        );
        assert_eq!(
            scanner.classify_function_category("/api/config/security"),
            FunctionCategory::Configuration
        );
        assert_eq!(
            scanner.classify_function_category("/api/export/data"),
            FunctionCategory::DataExport
        );
        assert_eq!(
            scanner.classify_function_category("/api/billing/invoice"),
            FunctionCategory::FinancialOps
        );
    }

    #[test]
    fn test_detect_api_pattern() {
        let scanner = create_test_scanner();

        // REST API
        let rest_response = HttpResponse {
            status_code: 200,
            body: r#"{"users": []}"#.to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h
            },
            duration_ms: 100,
        };
        assert_eq!(
            scanner.detect_api_pattern(&rest_response, "https://api.example.com/users"),
            ApiPattern::Rest
        );

        // GraphQL
        let graphql_response = HttpResponse {
            status_code: 200,
            body: r#"{"data": {"__schema": {}}}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        assert_eq!(
            scanner.detect_api_pattern(&graphql_response, "https://api.example.com/graphql"),
            ApiPattern::GraphQL
        );
    }

    #[test]
    fn test_detect_auth_scheme() {
        let scanner = create_test_scanner();

        // JWT
        let jwt_response = HttpResponse {
            status_code: 200,
            body: r#"{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        assert_eq!(scanner.detect_auth_scheme(&jwt_response), AuthScheme::Jwt);

        // Session
        let session_response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: {
                let mut h = HashMap::new();
                h.insert(
                    "set-cookie".to_string(),
                    "sessionid=abc123; HttpOnly".to_string(),
                );
                h
            },
            duration_ms: 100,
        };
        assert_eq!(
            scanner.detect_auth_scheme(&session_response),
            AuthScheme::Session
        );
    }

    #[test]
    fn test_is_privileged_content() {
        let scanner = create_test_scanner();

        // User management content
        assert!(scanner.is_privileged_content(
            r#"{"users": [{"id": 1, "email": "admin@example.com", "role": "admin"}]}"#,
            &FunctionCategory::UserManagement
        ));

        // Error response - not privileged
        assert!(!scanner.is_privileged_content(
            r#"{"error": "Unauthorized access"}"#,
            &FunctionCategory::UserManagement
        ));

        // Too short - not privileged
        assert!(!scanner.is_privileged_content("ok", &FunctionCategory::General));
    }

    #[test]
    fn test_extract_api_paths_from_body() {
        let scanner = create_test_scanner();

        let body = r#"
            <a href="/admin/users">Users</a>
            <script>
                fetch('/api/admin/config');
                const url = '/api/internal/stats';
            </script>
        "#;

        let paths = scanner.extract_api_paths_from_body(body);

        assert!(paths.contains(&"/admin/users".to_string()));
        assert!(paths.contains(&"/api/admin/config".to_string()));
    }

    #[test]
    fn test_generate_uuid() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();

        assert!(uuid1.starts_with("bfla_"));
        assert!(uuid2.starts_with("bfla_"));
        assert_ne!(uuid1, uuid2);
    }
}
