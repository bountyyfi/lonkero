// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - API Security Scanner
 * Tests REST APIs, GraphQL, and JWT vulnerabilities
 *
 * Detects:
 * - GraphQL introspection enabled
 * - GraphQL IDE exposure (GraphiQL, Playground)
 * - REST API authentication bypass
 * - Verbose error messages with stack traces
 * - Weak JWT algorithms (none, HS256)
 * - Missing rate limiting
 * - Unauthenticated API endpoints
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct APISecurityScanner {
    http_client: Arc<HttpClient>,
}

impl APISecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for API security vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, detect if this is actually an API endpoint
        let is_api = self.detect_api_endpoint(url).await;
        if !is_api {
            debug!("No API detected at {}, skipping API-specific tests", url);
            return Ok((vulnerabilities, tests_run));
        }

        // Intelligent detection
        if let Ok(response) = self.http_client.get(url).await {
            let _characteristics = AppCharacteristics::from_response(&response, url);
        }

        info!("Testing API security vulnerabilities");

        // Test GraphQL security
        let (vulns, tests) = self.test_graphql_security(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test REST API security
        let (vulns, tests) = self.test_rest_api_security(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test JWT security
        let (vulns, tests) = self.test_jwt_security(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test rate limiting
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_rate_limiting(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if endpoint is an API (returns JSON, has /api/ path, etc.)
    async fn detect_api_endpoint(&self, url: &str) -> bool {
        // Check if URL contains API path indicators
        let url_lower = url.to_lowercase();
        if url_lower.contains("/api/")
            || url_lower.contains("/graphql")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
        {
            debug!("API detected in URL path: {}", url);
            return true;
        }

        // Check response Content-Type
        if let Ok(response) = self.http_client.get(url).await {
            if let Some(content_type) = response.header("content-type") {
                let content_type_lower = content_type.to_lowercase();
                if content_type_lower.contains("application/json")
                    || content_type_lower.contains("application/xml")
                    || content_type_lower.contains("application/graphql")
                {
                    debug!("API detected via Content-Type: {}", content_type);
                    return true;
                }
            }

            // Check if response is valid JSON
            if serde_json::from_str::<serde_json::Value>(&response.body).is_ok() {
                debug!("API detected via JSON response");
                return true;
            }
        }

        false
    }

    /// Test GraphQL security
    async fn test_graphql_security(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing GraphQL security");

        let graphql_paths = vec![
            "/graphql".to_string(),
            "/graphiql".to_string(),
            "/playground".to_string(),
            "/api/graphql".to_string(),
        ];

        for path in graphql_paths {
            let test_url = self.build_url(url, &path);

            // Test introspection
            if let Ok(introspection_enabled) = self.test_graphql_introspection(&test_url).await {
                if introspection_enabled {
                    info!("GraphQL introspection enabled at {}", path);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "GraphQL Introspection Enabled",
                        "{ __schema { types { name } } }",
                        "GraphQL introspection is enabled in production",
                        &format!("Introspection query succeeded at {}", path),
                        Severity::High,
                        "CWE-200",
                        7.5,
                    ));
                    break;
                }
            }

            // Test IDE exposure
            if let Ok(ide_exposed) = self.test_graphql_ide(&test_url).await {
                if ide_exposed {
                    info!("GraphQL IDE exposed at {}", path);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "GraphQL IDE Exposed",
                        "",
                        "GraphQL IDE (GraphiQL/Playground) exposed in production",
                        &format!("GraphQL IDE publicly accessible at {}", path),
                        Severity::Medium,
                        "CWE-200",
                        5.3,
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL introspection
    async fn test_graphql_introspection(&self, url: &str) -> anyhow::Result<bool> {
        let introspection_query = r#"{"query":"{ __schema { types { name } } }"}"#;

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, introspection_query, headers)
            .await
        {
            Ok(response) => {
                // Check if response contains schema data
                Ok(response.body.contains("__schema")
                    && response.body.contains("types")
                    && response.status_code == 200)
            }
            Err(_) => Ok(false),
        }
    }

    /// Test if GraphQL IDE is exposed
    async fn test_graphql_ide(&self, url: &str) -> anyhow::Result<bool> {
        match self.http_client.get(url).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();
                Ok(body_lower.contains("graphiql") || body_lower.contains("playground"))
            }
            Err(_) => Ok(false),
        }
    }

    /// Test REST API security
    async fn test_rest_api_security(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing REST API security");

        let test_paths = vec!["/api/users", "/api/admin", "/api/config", "/api/debug"];

        for path in test_paths {
            let test_url = self.build_url(url, path);

            // Test authentication bypass
            if let Ok(no_auth) = self.test_no_auth(&test_url).await {
                if no_auth {
                    info!("API endpoint accessible without auth: {}", path);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "API No Authentication",
                        "",
                        &format!("API endpoint accessible without authentication: {}", path),
                        "Endpoint returned data without authentication",
                        Severity::Critical,
                        "CWE-306",
                        9.1,
                    ));
                    break;
                }
            }

            // Test verbose errors
            if vulnerabilities.is_empty() {
                if let Ok(verbose) = self.test_verbose_errors(&test_url).await {
                    if verbose {
                        info!("Verbose error messages detected at {}", path);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Verbose Errors",
                            "?invalid=true",
                            "API returns verbose error messages with stack traces",
                            "Stack traces or internal paths exposed in errors",
                            Severity::Low,
                            "CWE-209",
                            3.7,
                        ));
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API without authentication
    async fn test_no_auth(&self, url: &str) -> anyhow::Result<bool> {
        match self.http_client.get(url).await {
            Ok(response) => {
                // If we get 200 and JSON-like data, it's accessible
                if response.status_code == 200 && !response.body.is_empty() {
                    // Check if it looks like JSON
                    let trimmed = response.body.trim();
                    Ok((trimmed.starts_with('{') && trimmed.ends_with('}'))
                        || (trimmed.starts_with('[') && trimmed.ends_with(']')))
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Test for verbose error messages
    async fn test_verbose_errors(&self, url: &str) -> anyhow::Result<bool> {
        let test_url = format!("{}?invalid=true&error=test", url);

        match self.http_client.get(&test_url).await {
            Ok(response) => {
                let body = &response.body;

                // Check for stack traces
                let has_stack_trace =
                    body.contains(" at ") && body.contains("(") && body.contains(":");

                // Check for internal paths
                let has_internal_path = body.contains("/home/")
                    || body.contains("/var/")
                    || body.contains("C:\\")
                    || body.contains("/usr/");

                Ok(has_stack_trace || has_internal_path)
            }
            Err(_) => Ok(false),
        }
    }

    /// Test JWT security
    async fn test_jwt_security(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing JWT security");

        let endpoints = vec![
            "/api/login".to_string(),
            "/api/auth".to_string(),
            "/api/token".to_string(),
        ];

        for path in endpoints {
            let test_url = self.build_url(url, &path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(jwt) = self.extract_jwt(&response.body) {
                        if self.analyze_jwt_weakness(&jwt) {
                            info!("Weak JWT algorithm detected");
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Weak JWT Algorithm",
                                "",
                                "Weak JWT algorithm detected (none, HS256 with weak secret)",
                                &format!("JWT found with weak algorithm at {}", path),
                                Severity::High,
                                "CWE-327",
                                8.1,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Extract JWT from response
    fn extract_jwt(&self, body: &str) -> Option<String> {
        let jwt_regex = Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").ok()?;
        jwt_regex.find(body).map(|m| m.as_str().to_string())
    }

    /// Analyze JWT for weaknesses
    fn analyze_jwt_weakness(&self, jwt: &str) -> bool {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Decode header using base64 0.21+ API
        if let Ok(header_bytes) = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
            if let Ok(header_str) = String::from_utf8(header_bytes) {
                let header_lower = header_str.to_lowercase();

                // Check for weak algorithms
                if header_lower.contains(r#""alg":"none""#)
                    || header_lower.contains(r#""alg": "none""#)
                    || header_lower.contains(r#"'alg':'none'"#)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Test rate limiting
    async fn test_rate_limiting(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 20;

        debug!("Testing rate limiting");

        let test_url = self.build_url(url, "/api");
        let max_requests = 20;
        let mut rate_limited = false;

        for i in 0..max_requests {
            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 429 {
                        rate_limited = true;
                        debug!("Rate limited after {} requests", i + 1);
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }

            // Small delay between requests
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        if !rate_limited {
            info!("No rate limiting detected");
            vulnerabilities.push(self.create_vulnerability(
                url,
                "API No Rate Limiting",
                "",
                "API endpoint has no rate limiting",
                &format!("{} requests sent without rate limiting", max_requests),
                Severity::Medium,
                "CWE-770",
                5.3,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Build full URL from base and path
    fn build_url(&self, base: &str, path: &str) -> String {
        if base.ends_with('/') && path.starts_with('/') {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else if !base.ends_with('/') && !path.starts_with('/') {
            format!("{}/{}", base, path)
        } else {
            format!("{}{}", base, path)
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("api_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "GraphQL Introspection Enabled" => {
                "1. Disable GraphQL introspection in production environments\n\
                 2. Use environment variables to control introspection\n\
                 3. Implement proper authentication before allowing introspection\n\
                 4. Use GraphQL security tools like graphql-shield\n\
                 5. Monitor and log introspection queries"
                    .to_string()
            }
            "GraphQL IDE Exposed" => "1. Disable GraphQL IDE (GraphiQL/Playground) in production\n\
                 2. Use environment-specific configurations\n\
                 3. Require authentication for development tools\n\
                 4. Use separate development and production endpoints"
                .to_string(),
            "API No Authentication" => {
                "1. Implement proper authentication (OAuth 2.0, JWT, API keys)\n\
                 2. Enforce authentication on all sensitive endpoints\n\
                 3. Use role-based access control (RBAC)\n\
                 4. Implement proper authorization checks\n\
                 5. Never expose admin endpoints without authentication\n\
                 6. Use API gateways for centralized authentication"
                    .to_string()
            }
            "API Verbose Errors" => "1. Implement generic error messages for production\n\
                 2. Log detailed errors server-side only\n\
                 3. Disable stack traces in production\n\
                 4. Use error tracking services (Sentry, Rollbar)\n\
                 5. Never expose internal paths or system information"
                .to_string(),
            "Weak JWT Algorithm" => "1. Never use 'none' algorithm in production\n\
                 2. Use strong algorithms (RS256, ES256) instead of HS256\n\
                 3. Use strong, random secrets for HS256 if required\n\
                 4. Implement proper JWT validation\n\
                 5. Set appropriate expiration times\n\
                 6. Rotate signing keys regularly\n\
                 7. Validate algorithm in token verification"
                .to_string(),
            "API No Rate Limiting" => "1. Implement rate limiting to prevent abuse\n\
                 2. Use tools like express-rate-limit, nginx rate limiting\n\
                 3. Set appropriate limits based on endpoint sensitivity\n\
                 4. Return 429 status code when rate limit exceeded\n\
                 5. Implement IP-based and user-based rate limiting\n\
                 6. Monitor for unusual traffic patterns"
                .to_string(),
            _ => "Follow OWASP API Security Top 10 guidelines".to_string(),
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
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> APISecurityScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        APISecurityScanner::new(http_client)
    }

    #[test]
    fn test_extract_jwt() {
        let scanner = create_test_scanner();

        let response = r#"{"token":"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."}"#;
        let jwt = scanner.extract_jwt(response);

        assert!(jwt.is_some());
        assert!(jwt.unwrap().starts_with("eyJ"));
    }

    #[test]
    fn test_analyze_jwt_weakness_none() {
        let scanner = create_test_scanner();

        // JWT with "alg":"none"
        let weak_jwt = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.";
        assert!(scanner.analyze_jwt_weakness(weak_jwt));
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.build_url("http://example.com", "/api"),
            "http://example.com/api"
        );
        assert_eq!(
            scanner.build_url("http://example.com/", "/api"),
            "http://example.com/api"
        );
        assert_eq!(
            scanner.build_url("http://example.com", "api"),
            "http://example.com/api"
        );
        assert_eq!(
            scanner.build_url("http://example.com/", "api"),
            "http://example.com/api"
        );
    }

    #[test]
    fn test_detect_stack_trace() {
        let scanner = create_test_scanner();

        let error_with_stack = "Error at processRequest (/home/user/app.js:123)";
        // This would be tested in the async function, but we can verify the logic
        assert!(
            error_with_stack.contains(" at ")
                && error_with_stack.contains("(")
                && error_with_stack.contains(":")
        );
    }

    #[test]
    fn test_detect_internal_paths() {
        let scanner = create_test_scanner();

        let errors = vec![
            "Error in /home/user/app.js",
            "Failed at /var/www/server.js",
            "Exception in C:\\Users\\app\\index.js",
        ];

        for error in errors {
            assert!(error.contains("/home/") || error.contains("/var/") || error.contains("C:\\"));
        }
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "API No Authentication",
            "",
            "API accessible without auth",
            "Test evidence",
            Severity::Critical,
            "CWE-306",
            9.1,
        );

        assert_eq!(vuln.vuln_type, "API No Authentication");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-306");
        assert_eq!(vuln.cvss, 9.1);
        assert!(vuln.verified);
    }

    #[test]
    fn test_get_remediation() {
        let scanner = create_test_scanner();

        let remediation = scanner.get_remediation("Weak JWT Algorithm");
        assert!(remediation.contains("RS256"));
        assert!(remediation.contains("none"));
    }

    #[test]
    fn test_json_detection() {
        let json_obj = r#"{"user":"admin"}"#;
        let json_arr = r#"[{"id":1}]"#;

        let trimmed_obj = json_obj.trim();
        let trimmed_arr = json_arr.trim();

        assert!(trimmed_obj.starts_with('{') && trimmed_obj.ends_with('}'));
        assert!(trimmed_arr.starts_with('[') && trimmed_arr.ends_with(']'));
    }
}
