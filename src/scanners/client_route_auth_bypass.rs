// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Client Route Authorization Bypass Scanner
 *
 * SMART DISCOVERY: Instead of guessing paths, we extract ACTUAL routes from JavaScript
 * and test them for authorization bypass based on their declared requirements.
 *
 * What makes this scanner intelligent:
 * 1. Extracts real client-side routes from Vue Router, React Router, Angular Router
 * 2. Discovers authentication requirements from route metadata
 * 3. Discovers role requirements (RBAC) from route guards
 * 4. Tests only routes that SHOULD be protected
 * 5. Identifies IDOR vulnerabilities in parameterized routes
 *
 * Detects:
 * - Authentication bypass (accessing requireAuth routes without token)
 * - Role-based access control (RBAC) bypass
 * - IDOR in parameterized routes (/user/:id)
 * - Horizontal privilege escalation
 * - Direct object reference vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Client-side route extracted from JavaScript
#[derive(Debug, Clone)]
struct ClientRoute {
    path: String,
    requires_auth: bool,
    required_roles: Vec<String>,
    component: Option<String>,
    meta: HashMap<String, String>,
    framework: RouteFramework,
}

#[derive(Debug, Clone, PartialEq)]
enum RouteFramework {
    Vue,
    React,
    Angular,
    NextJS,
    Unknown,
}

pub struct ClientRouteAuthBypassScanner {
    http_client: Arc<HttpClient>,
}

impl ClientRouteAuthBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for client-side route authorization bypass vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[ClientRouteAuth] Scanning for client-side route auth bypass: {}", url);

        // Step 1: Fetch main page to discover JavaScript bundles
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[ClientRouteAuth] Failed to fetch main page: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Step 2: Extract JavaScript bundle URLs
        let js_urls = self.extract_js_bundle_urls(url, &response.body);

        if js_urls.is_empty() {
            info!("[ClientRouteAuth] No JavaScript bundles found - skipping");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[ClientRouteAuth] Found {} JavaScript bundles to analyze", js_urls.len());

        // Step 3: Fetch and analyze each JavaScript bundle
        let mut all_routes = Vec::new();

        for js_url in js_urls.iter().take(10) {  // Limit to first 10 bundles for performance
            tests_run += 1;

            if let Ok(js_response) = self.http_client.get(js_url).await {
                let routes = self.extract_routes_from_js(&js_response.body);

                if !routes.is_empty() {
                    info!("[ClientRouteAuth] Extracted {} routes from {}", routes.len(), js_url);
                    all_routes.extend(routes);
                }
            }
        }

        // Deduplicate routes by path
        let unique_routes = self.deduplicate_routes(all_routes);

        if unique_routes.is_empty() {
            info!("[ClientRouteAuth] No client-side routes discovered - skipping tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[ClientRouteAuth] Discovered {} unique client routes", unique_routes.len());

        // Log discovered routes for debugging
        for route in &unique_routes {
            debug!("[ClientRouteAuth] Route: {} (auth: {}, roles: {:?})",
                   route.path, route.requires_auth, route.required_roles);
        }

        // Step 4: Test routes for authorization bypass
        for route in &unique_routes {
            // Test 1: Authentication bypass (if route requires auth)
            if route.requires_auth {
                tests_run += 1;
                if let Some(vuln) = self.test_auth_bypass(url, route).await {
                    vulnerabilities.push(vuln);
                }
            }

            // Test 2: Role-based access control (RBAC) bypass
            if !route.required_roles.is_empty() {
                tests_run += 1;
                if let Some(vuln) = self.test_rbac_bypass(url, route).await {
                    vulnerabilities.push(vuln);
                }
            }

            // Test 3: IDOR testing for parameterized routes
            if route.path.contains(":id") || route.path.contains("/:") {
                tests_run += 1;
                if let Some(vuln) = self.test_idor(url, route).await {
                    vulnerabilities.push(vuln);
                }
            }
        }

        info!(
            "[SUCCESS] [ClientRouteAuth] Completed {} tests, found {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Extract JavaScript bundle URLs from HTML
    fn extract_js_bundle_urls(&self, base_url: &str, html: &str) -> Vec<String> {
        let mut js_urls = Vec::new();

        // Pattern 1: <script src="/app.js">
        let script_regex = Regex::new(r#"<script[^>]+src=["']([^"']+\.js[^"']*)["']"#).unwrap();

        for cap in script_regex.captures_iter(html) {
            if let Some(js_path) = cap.get(1) {
                let js_url = self.resolve_url(base_url, js_path.as_str());
                js_urls.push(js_url);
            }
        }

        // Pattern 2: Look for common bundle names in HTML
        let common_bundles = vec![
            "/app.js", "/main.js", "/bundle.js", "/vendor.js",
            "/js/app.js", "/js/main.js", "/static/js/main.js",
            "/dist/app.js", "/dist/main.js",
        ];

        for bundle in common_bundles {
            if html.contains(bundle) {
                js_urls.push(self.resolve_url(base_url, bundle));
            }
        }

        js_urls
    }

    /// Extract client-side routes from JavaScript code
    fn extract_routes_from_js(&self, js_code: &str) -> Vec<ClientRoute> {
        let mut routes = Vec::new();

        // Try each framework's route extraction
        routes.extend(self.extract_vue_routes(js_code));
        routes.extend(self.extract_react_routes(js_code));
        routes.extend(self.extract_angular_routes(js_code));
        routes.extend(self.extract_nextjs_routes(js_code));

        routes
    }

    /// Extract Vue Router routes
    fn extract_vue_routes(&self, js_code: &str) -> Vec<ClientRoute> {
        let mut routes = Vec::new();

        // Pattern 1: {path: "/admin", meta: {requireAuth: true}}
        let auth_regex = Regex::new(
            r#"(?:path|name):\s*["']([^"']+)["'][^}]*meta:\s*\{[^}]*requireAuth:\s*(!0|true)"#
        ).unwrap();

        for cap in auth_regex.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                routes.push(ClientRoute {
                    path: path.as_str().to_string(),
                    requires_auth: true,
                    required_roles: Vec::new(),
                    component: None,
                    meta: HashMap::new(),
                    framework: RouteFramework::Vue,
                });
            }
        }

        // Pattern 2: {path: "/admin", meta: {requireAnyRole: ["ADMIN", "MANAGEMENT"]}}
        let role_regex = Regex::new(
            r#"path:\s*["']([^"']+)["'][^}]*requireAnyRole:\s*\[([^\]]+)\]"#
        ).unwrap();

        for cap in role_regex.captures_iter(js_code) {
            if let (Some(path), Some(roles_str)) = (cap.get(1), cap.get(2)) {
                let roles: Vec<String> = roles_str
                    .as_str()
                    .split(',')
                    .map(|r| r.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                    .filter(|r| !r.is_empty())
                    .collect();

                routes.push(ClientRoute {
                    path: path.as_str().to_string(),
                    requires_auth: true,
                    required_roles: roles,
                    component: None,
                    meta: HashMap::new(),
                    framework: RouteFramework::Vue,
                });
            }
        }

        // Pattern 3: Simple path extraction (fallback)
        let path_regex = Regex::new(r#"path:\s*["']([/][^"']+)["']"#).unwrap();

        for cap in path_regex.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();

                // Skip if already found with metadata
                if routes.iter().any(|r| r.path == path_str) {
                    continue;
                }

                // Infer auth requirement from path patterns
                let requires_auth = path_str.contains("/admin")
                    || path_str.contains("/user")
                    || path_str.contains("/dashboard")
                    || path_str.contains("/profile")
                    || path_str.contains("/settings");

                if requires_auth {
                    routes.push(ClientRoute {
                        path: path_str.to_string(),
                        requires_auth,
                        required_roles: Vec::new(),
                        component: None,
                        meta: HashMap::new(),
                        framework: RouteFramework::Vue,
                    });
                }
            }
        }

        routes
    }

    /// Extract React Router routes
    fn extract_react_routes(&self, js_code: &str) -> Vec<ClientRoute> {
        let mut routes = Vec::new();

        // Pattern 1: <Route path="/admin" requireAuth />
        let route_regex = Regex::new(
            r#"<(?:Route|PrivateRoute)[^>]*path=["']([^"']+)["'][^>]*(?:requireAuth|private)"#
        ).unwrap();

        for cap in route_regex.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                routes.push(ClientRoute {
                    path: path.as_str().to_string(),
                    requires_auth: true,
                    required_roles: Vec::new(),
                    component: None,
                    meta: HashMap::new(),
                    framework: RouteFramework::React,
                });
            }
        }

        // Pattern 2: {path: "/admin", element: <Admin />, protected: true}
        let protected_regex = Regex::new(
            r#"path:\s*["']([^"']+)["'][^}]*(?:protected|requireAuth):\s*(!0|true)"#
        ).unwrap();

        for cap in protected_regex.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                routes.push(ClientRoute {
                    path: path.as_str().to_string(),
                    requires_auth: true,
                    required_roles: Vec::new(),
                    component: None,
                    meta: HashMap::new(),
                    framework: RouteFramework::React,
                });
            }
        }

        routes
    }

    /// Extract Angular Router routes
    fn extract_angular_routes(&self, js_code: &str) -> Vec<ClientRoute> {
        let mut routes = Vec::new();

        // Pattern: {path: 'admin', canActivate: [AuthGuard]}
        let guard_regex = Regex::new(
            r#"path:\s*["']([^"']+)["'][^}]*canActivate:\s*\[([^\]]+)\]"#
        ).unwrap();

        for cap in guard_regex.captures_iter(js_code) {
            if let (Some(path), Some(guards)) = (cap.get(1), cap.get(2)) {
                let has_auth_guard = guards.as_str().contains("Auth")
                    || guards.as_str().contains("Guard");

                if has_auth_guard {
                    routes.push(ClientRoute {
                        path: format!("/{}", path.as_str().trim_start_matches('/')),
                        requires_auth: true,
                        required_roles: Vec::new(),
                        component: None,
                        meta: HashMap::new(),
                        framework: RouteFramework::Angular,
                    });
                }
            }
        }

        routes
    }

    /// Extract Next.js routes (from getServerSideProps patterns)
    fn extract_nextjs_routes(&self, js_code: &str) -> Vec<ClientRoute> {
        let mut routes = Vec::new();

        // Pattern: getServerSideProps with session check
        if js_code.contains("getServerSideProps") && js_code.contains("session") {
            // Next.js routes are file-based, harder to extract from bundle
            // This is a placeholder for potential future enhancement
        }

        routes
    }

    /// Deduplicate routes by path
    fn deduplicate_routes(&self, routes: Vec<ClientRoute>) -> Vec<ClientRoute> {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for route in routes {
            if seen.insert(route.path.clone()) {
                unique.push(route);
            }
        }

        unique
    }

    /// Test if protected route can be accessed without authentication
    async fn test_auth_bypass(&self, base_url: &str, route: &ClientRoute) -> Option<Vulnerability> {
        let test_path = self.replace_route_params(&route.path, "1");
        let test_url = self.resolve_url(base_url, &test_path);

        debug!("[ClientRouteAuth] Testing auth bypass on: {}", test_url);

        let response = match self.http_client.get(&test_url).await {
            Ok(r) => r,
            Err(_) => return None,
        };

        // Check if we got actual protected content without authentication
        let is_bypass = response.status_code == 200
            && response.status_code != 404  // Route must exist
            && !response.body.to_lowercase().contains("login")
            && !response.body.to_lowercase().contains("sign in")
            && !response.body.to_lowercase().contains("unauthorized")
            && !response.body.to_lowercase().contains("not found")
            && !response.body.to_lowercase().contains("redirect")
            && response.body.len() > 500;  // Must have substantial content

        if is_bypass {
            info!("[VULN] Auth bypass found on route: {}", route.path);

            Some(Vulnerability {
                id: format!("crauth_{}", uuid::Uuid::new_v4().simple()),
                vuln_type: "Client Route Authentication Bypass".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Access Control".to_string(),
                url: test_url.clone(),
                parameter: Some("route".to_string()),
                payload: route.path.clone(),
                description: format!(
                    "Client-side route '{}' requires authentication but can be accessed without credentials. \
                     The route is declared with requireAuth=true in {} Router but server-side \
                     authorization is not enforced.",
                    route.path,
                    match route.framework {
                        RouteFramework::Vue => "Vue",
                        RouteFramework::React => "React",
                        RouteFramework::Angular => "Angular",
                        RouteFramework::NextJS => "Next.js",
                        RouteFramework::Unknown => "unknown",
                    }
                ),
                evidence: Some(format!(
                    "Route metadata indicates authentication required, but HTTP {} returned without credentials. \
                     Response length: {} bytes (substantial content suggests real page, not redirect).",
                    response.status_code, response.body.len()
                )),
                cwe: "CWE-306".to_string(),
                cvss: 9.1,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Implement server-side authentication checks\n\
                             2. Verify user session/token on EVERY request to protected routes\n\
                             3. Don't rely solely on client-side route guards\n\
                             4. Return 401 Unauthorized for unauthenticated requests\n\
                             5. Implement middleware/interceptors for route protection\n\
                             6. Use frameworks like Next.js getServerSideProps for SSR auth\n\
                             7. Validate JWT/session tokens server-side\n\
                             8. Log unauthorized access attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    /// Test if route with role requirements can be bypassed
    async fn test_rbac_bypass(&self, base_url: &str, route: &ClientRoute) -> Option<Vulnerability> {
        let test_path = self.replace_route_params(&route.path, "1");
        let test_url = self.resolve_url(base_url, &test_path);

        debug!("[ClientRouteAuth] Testing RBAC bypass on: {} (requires roles: {:?})",
               test_url, route.required_roles);

        // Try accessing without any authentication
        let response = match self.http_client.get(&test_url).await {
            Ok(r) => r,
            Err(_) => return None,
        };

        // Check if we can access role-protected route
        let is_bypass = response.status_code == 200
            && response.status_code != 404
            && !response.body.to_lowercase().contains("forbidden")
            && !response.body.to_lowercase().contains("unauthorized")
            && !response.body.to_lowercase().contains("login")
            && !response.body.to_lowercase().contains("not found")
            && response.body.len() > 500;

        if is_bypass {
            info!("[VULN] RBAC bypass found on route: {} (requires: {:?})",
                  route.path, route.required_roles);

            Some(Vulnerability {
                id: format!("crrbac_{}", uuid::Uuid::new_v4().simple()),
                vuln_type: "Client Route RBAC Bypass".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Access Control".to_string(),
                url: test_url.clone(),
                parameter: Some("role".to_string()),
                payload: route.path.clone(),
                description: format!(
                    "Client-side route '{}' requires roles {:?} but can be accessed without proper authorization. \
                     Role-based access control (RBAC) is declared in client-side router but not enforced server-side.",
                    route.path, route.required_roles
                ),
                evidence: Some(format!(
                    "Route declares requireAnyRole={:?} but HTTP {} returned full content without role verification. \
                     This allows privilege escalation to admin/management functionality.",
                    route.required_roles, response.status_code
                )),
                cwe: "CWE-639".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Implement server-side role verification\n\
                             2. Check user roles on EVERY request to protected routes\n\
                             3. Return 403 Forbidden for unauthorized roles\n\
                             4. Don't rely on client-side role guards\n\
                             5. Use role-based middleware/decorators (@RequireRole)\n\
                             6. Validate roles from JWT claims or session\n\
                             7. Log role bypass attempts for security monitoring\n\
                             8. Implement principle of least privilege".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    /// Test for IDOR vulnerabilities in parameterized routes
    async fn test_idor(&self, base_url: &str, route: &ClientRoute) -> Option<Vulnerability> {
        // Test common IDOR patterns
        let test_ids = vec!["1", "2", "999", "admin", "0"];

        for test_id in &test_ids {
            let test_path = self.replace_route_params(&route.path, test_id);
            let test_url = self.resolve_url(base_url, &test_path);

            debug!("[ClientRouteAuth] Testing IDOR on: {}", test_url);

            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check if we can access other users' data
                if response.status_code == 200
                    && response.status_code != 404
                    && response.body.len() > 500
                    && !response.body.to_lowercase().contains("not found")
                    && !response.body.to_lowercase().contains("unauthorized") {

                    info!("[VULN] Potential IDOR found on route: {} with ID: {}", route.path, test_id);

                    return Some(Vulnerability {
                        id: format!("crador_{}", uuid::Uuid::new_v4().simple()),
                        vuln_type: "Client Route IDOR".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "Access Control".to_string(),
                        url: test_url.clone(),
                        parameter: Some("id".to_string()),
                        payload: test_id.to_string(),
                        description: format!(
                            "Client-side route '{}' with ID parameter allows accessing arbitrary resources. \
                             Insecure Direct Object Reference (IDOR) vulnerability enables unauthorized data access.",
                            route.path
                        ),
                        evidence: Some(format!(
                            "Route pattern '{}' returned HTTP 200 with ID='{}'. No ownership verification detected. \
                             Users may access other users' data by manipulating the ID parameter.",
                            route.path, test_id
                        )),
                        cwe: "CWE-639".to_string(),
                        cvss: 7.5,
                        verified: false,
                        false_positive: false,
                        remediation: "1. Verify user ownership of requested resource\n\
                                     2. Check if current user ID matches resource owner\n\
                                     3. Implement server-side authorization checks\n\
                                     4. Use indirect references (UUIDs instead of sequential IDs)\n\
                                     5. Return 403 Forbidden for unauthorized access\n\
                                     6. Log IDOR attempts for security monitoring\n\
                                     7. Implement row-level security in database\n\
                                     8. Use GraphQL field-level authorization".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        None
    }

    /// Replace route parameters with test values
    fn replace_route_params(&self, path: &str, value: &str) -> String {
        path.replace(":id", value)
            .replace(":userId", value)
            .replace(":companyId", value)
            .replace(":orderId", value)
            .replace(":workerId", value)
            .replace(":shiftId", value)
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, base: &str, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }

        let base_trimmed = base.trim_end_matches('/');
        let path_trimmed = path.trim_start_matches('/');

        format!("{}/{}", base_trimmed, path_trimmed)
    }
}

// UUID helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn simple(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:08x}",
                rng.random::<u32>(),
                rng.random::<u32>()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vue_routes() {
        let scanner = ClientRouteAuthBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let js_code = r#"
            {path:"/admin",meta:{requireAnyRole:["ADMIN","MANAGEMENT"]}},
            {path:"/user/:id",meta:{requireAuth:true}},
            {path:"/driver",meta:{requireAnyRole:["DRIVER"]}}
        "#;

        let routes = scanner.extract_vue_routes(js_code);

        assert!(routes.len() >= 2);
        assert!(routes.iter().any(|r| r.path == "/admin"));
        assert!(routes.iter().any(|r| r.requires_auth));
    }

    #[test]
    fn test_replace_route_params() {
        let scanner = ClientRouteAuthBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        assert_eq!(scanner.replace_route_params("/user/:id", "123"), "/user/123");
        assert_eq!(scanner.replace_route_params("/company/:companyId/user/:userId", "1"),
                   "/company/1/user/1");
    }

    #[test]
    fn test_resolve_url() {
        let scanner = ClientRouteAuthBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        assert_eq!(
            scanner.resolve_url("https://example.com", "/admin"),
            "https://example.com/admin"
        );

        assert_eq!(
            scanner.resolve_url("https://example.com/", "admin"),
            "https://example.com/admin"
        );
    }
}
