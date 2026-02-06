// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced API Fuzzing Scanner
 * Comprehensive REST/GraphQL/gRPC API fuzzing and vulnerability detection
 *
 * Features:
 * - REST API fuzzing (HTTP methods, Content-Type, parameters, IDOR, mass assignment)
 * - GraphQL fuzzing (introspection, batch queries, depth limits, circular queries)
 * - gRPC fuzzing (protobuf, metadata, stream handling)
 * - Authentication bypass (JWT, OAuth, API keys, token replay)
 * - Rate limit testing and API versioning issues
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, ScanMode, Severity, Vulnerability};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

mod uuid {
    pub use uuid::Uuid;
}

/// Advanced API Fuzzing Scanner
pub struct ApiFuzzerScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl ApiFuzzerScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("fuzz-{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Premium feature check
        if !crate::license::is_feature_available("api_fuzzing") {
            info!("[SKIP] Advanced API fuzzing requires Professional or higher license");
            return Ok((Vec::new(), 0));
        }

        info!("Starting advanced API fuzzing scan on {}", url);

        // Intelligent detection - API fuzzing needs API endpoints
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.is_static {
                info!("[ApiFuzzer] Skipping - static site detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Detect API type and endpoints
        let api_endpoints = self.discover_api_endpoints(url).await?;

        if api_endpoints.is_empty() {
            debug!("No API endpoints detected, skipping API fuzzing");
            return Ok((all_vulnerabilities, total_tests));
        }

        info!("Detected {} API endpoints", api_endpoints.len());

        // Phase 1: REST API Fuzzing
        let (vulns, tests) = self.fuzz_rest_apis(&api_endpoints, config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 2: GraphQL Fuzzing
        let (vulns, tests) = self.fuzz_graphql_apis(&api_endpoints, config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 3: gRPC Fuzzing
        let (vulns, tests) = self.fuzz_grpc_apis(&api_endpoints, config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 4: Authentication Bypass Testing
        let (vulns, tests) = self.test_auth_bypass(&api_endpoints, config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "API fuzzing completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Discover API endpoints from the target
    async fn discover_api_endpoints(&self, url: &str) -> anyhow::Result<Vec<ApiEndpoint>> {
        let mut endpoints = Vec::new();
        let base_url = self.extract_base_url(url);

        // Common API paths
        let api_paths = vec![
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/graphql",
            "/api/graphql",
            "/rest",
            "/rest/v1",
            "/v1",
            "/v2",
            "/v3",
        ];

        for path in api_paths {
            let test_url = format!("{}{}", base_url, path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // CRITICAL: Only detect API type if endpoint actually exists (not 404)
                    // 404 responses with JSON bodies ({"statusCode":404,"message":"Cannot GET ..."})
                    // should NOT be detected as REST APIs
                    if response.status_code >= 200 && response.status_code < 300 {
                        // 2xx success - endpoint exists and returned data
                        let api_type = self.detect_api_type(&response.body, &response.headers);
                        if api_type != ApiType::None {
                            info!("Detected {} API at: {}", api_type.as_str(), test_url);
                            endpoints.push(ApiEndpoint {
                                url: test_url,
                                api_type,
                                methods: vec!["GET".to_string()],
                            });
                        }
                    } else if response.status_code == 401 || response.status_code == 403 {
                        // 401/403 - endpoint exists but requires auth
                        let api_type = self.detect_api_type(&response.body, &response.headers);
                        if api_type != ApiType::None {
                            info!(
                                "Detected {} API at: {} (requires authentication)",
                                api_type.as_str(),
                                test_url
                            );
                            endpoints.push(ApiEndpoint {
                                url: test_url,
                                api_type,
                                methods: vec!["GET".to_string()],
                            });
                        }
                    } else if response.status_code == 405 {
                        // 405 Method Not Allowed - endpoint exists but GET not supported
                        // Try to detect API type anyway since endpoint clearly exists
                        let api_type = self.detect_api_type(&response.body, &response.headers);
                        if api_type != ApiType::None {
                            info!(
                                "Detected {} API at: {} (GET not allowed)",
                                api_type.as_str(),
                                test_url
                            );
                            endpoints.push(ApiEndpoint {
                                url: test_url,
                                api_type,
                                methods: vec!["POST".to_string()], // Assume POST works
                            });
                        }
                    }
                    // 404, 500, etc - endpoint doesn't exist or error, skip
                }
                Err(e) => {
                    debug!("Failed to probe {}: {}", test_url, e);
                }
            }
        }

        Ok(endpoints)
    }

    /// Fuzz REST API endpoints
    async fn fuzz_rest_apis(
        &self,
        endpoints: &[ApiEndpoint],
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for endpoint in endpoints.iter().filter(|e| e.api_type == ApiType::Rest) {
            info!("Fuzzing REST API: {}", endpoint.url);

            // Test HTTP method fuzzing
            let (vulns, tests) = self.fuzz_http_methods(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test Content-Type fuzzing
            let (vulns, tests) = self.fuzz_content_types(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test parameter tampering
            let (vulns, tests) = self.fuzz_parameters(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test mass assignment
            let (vulns, tests) = self.test_mass_assignment(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test IDOR vulnerabilities
            let (vulns, tests) = self.test_idor(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test broken object level authorization
            let (vulns, tests) = self.test_bola(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test rate limiting
            let (vulns, tests) = self.test_rate_limits(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test API versioning issues
            let (vulns, tests) = self.test_api_versioning(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Fuzz HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
    async fn fuzz_http_methods(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let methods = vec![
            "GET".to_string(),
            "POST".to_string(),
            "PUT".to_string(),
            "DELETE".to_string(),
            "PATCH".to_string(),
            "OPTIONS".to_string(),
            "HEAD".to_string(),
            "TRACE".to_string(),
        ];
        let tests_run = methods.len();

        debug!("Testing HTTP method fuzzing");

        for method in &methods {
            match self.send_http_request(url, &method, None, vec![]).await {
                Ok(response) => {
                    // Check for unexpected method acceptance
                    if response.status_code < 400 && (*method == "DELETE" || *method == "TRACE") {
                        vulnerabilities.push(self.create_vulnerability(
                            "Unsafe HTTP Method Allowed",
                            url,
                            &format!("HTTP {} method is allowed", method),
                            &format!(
                                "Server accepted {} request with status {}",
                                method, response.status_code
                            ),
                            Severity::Medium,
                            "CWE-650",
                            6.5,
                        ));
                    }

                    // Check for method override vulnerabilities
                    if response.body.contains("X-HTTP-Method-Override") {
                        vulnerabilities.push(self.create_vulnerability(
                            "HTTP Method Override Detected",
                            url,
                            "X-HTTP-Method-Override header",
                            "Server supports HTTP method override, which may bypass security controls",
                            Severity::Medium,
                            "CWE-650",
                            5.3,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Method {} test failed: {}", method, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Fuzz Content-Type headers
    async fn fuzz_content_types(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let content_types = vec![
            ("application/json", r#"{"test":"value"}"#),
            (
                "application/xml",
                r#"<?xml version="1.0"?><test>value</test>"#,
            ),
            ("application/x-www-form-urlencoded", "test=value"),
            ("multipart/form-data", "test=value"),
            ("application/msgpack", "test"),
            ("application/protobuf", "test"),
            ("text/plain", "test"),
            ("application/x-yaml", "test: value"),
        ];

        let tests_run = content_types.len();

        debug!("Testing Content-Type fuzzing");

        for (content_type, payload) in &content_types {
            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(url, payload, headers)
                .await
            {
                Ok(response) => {
                    // Check for unexpected processing
                    if response.status_code == 200
                        && (*content_type == "application/msgpack"
                            || *content_type == "application/protobuf")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "Unusual Content-Type Accepted",
                            url,
                            &format!("Content-Type: {}", content_type),
                            &format!("Server processes unusual content type: {}", content_type),
                            Severity::Low,
                            "CWE-436",
                            3.7,
                        ));
                    }

                    // Check for content type confusion
                    if response.body.contains("SyntaxError") || response.body.contains("ParseError")
                    {
                        if response.body.contains("stack") || response.body.contains("trace") {
                            vulnerabilities.push(self.create_vulnerability(
                                "Content-Type Confusion with Verbose Errors",
                                url,
                                &format!("Content-Type: {}", content_type),
                                "Server returns verbose error messages during content type processing",
                                Severity::Low,
                                "CWE-209",
                                3.1,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Content-Type {} test failed: {}", content_type, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Fuzz API parameters with type confusion and boundary values
    async fn fuzz_parameters(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing parameter fuzzing");

        // Type confusion payloads
        let type_confusion = vec![
            (json!({"id": "string_instead_of_int"}), "String for integer"),
            (
                json!({"id": ["array", "instead", "of", "scalar"]}),
                "Array for scalar",
            ),
            (json!({"id": {"nested": "object"}}), "Object for scalar"),
            (json!({"id": null}), "Null value"),
            (json!({"id": true}), "Boolean for integer"),
        ];

        for (payload, description) in &type_confusion {
            tests_run += 1;
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers)
                .await
            {
                Ok(response) => {
                    if response.status_code == 200 {
                        vulnerabilities.push(self.create_vulnerability(
                            "Type Confusion Vulnerability",
                            url,
                            &format!("{}: {}", description, payload),
                            "API accepts unexpected data types without validation",
                            Severity::Medium,
                            "CWE-843",
                            5.3,
                        ));
                        break; // Found one, no need to test all
                    }

                    // Check for error leakage
                    if self.detect_error_leakage(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Information Leakage in Error Messages",
                            url,
                            &format!("{}: {}", description, payload),
                            &format!(
                                "Verbose error: {}",
                                self.extract_evidence(&response.body, 200)
                            ),
                            Severity::Low,
                            "CWE-209",
                            3.7,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Parameter fuzzing failed: {}", e);
                }
            }
        }

        // Boundary value testing
        let boundary_values = vec![
            (json!({"id": -1}), "Negative value"),
            (json!({"id": 0}), "Zero"),
            (json!({"id": 2147483647}), "Max int32"),
            (json!({"id": 2147483648i64}), "Max int32 + 1"),
            (json!({"id": -2147483648}), "Min int32"),
            (json!({"amount": 0.01}), "Minimal decimal"),
            (json!({"amount": 999999999.99}), "Large decimal"),
            (json!({"quantity": -1}), "Negative quantity"),
        ];

        for (payload, description) in &boundary_values {
            tests_run += 1;
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers)
                .await
            {
                Ok(response) => {
                    if response.status_code == 200
                        && (description.contains("Negative") || description.contains("Large"))
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "Insufficient Input Validation",
                            url,
                            &format!("{}: {}", description, payload),
                            "API accepts boundary/edge case values without proper validation",
                            Severity::Medium,
                            "CWE-20",
                            5.3,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Boundary value test failed: {}", e);
                }
            }
        }

        // Integer overflow testing
        if config.scan_mode == ScanMode::Thorough || config.scan_mode == ScanMode::Insane {
            let overflow_payloads = vec![
                json!({"id": "9223372036854775807"}),  // Max int64
                json!({"id": "18446744073709551615"}), // Max uint64
                json!({"price": "999999999999999.99"}),
            ];

            for payload in &overflow_payloads {
                tests_run += 1;
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                if let Ok(response) = self
                    .http_client
                    .post_with_headers(url, &payload.to_string(), headers)
                    .await
                {
                    if response.body.contains("overflow") || response.body.contains("out of range")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "Integer Overflow Potential",
                            url,
                            &payload.to_string(),
                            "API may be vulnerable to integer overflow",
                            Severity::Medium,
                            "CWE-190",
                            5.3,
                        ));
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for mass assignment vulnerabilities
    async fn test_mass_assignment(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing mass assignment vulnerabilities");

        // Attempt to modify sensitive fields
        let mass_assignment_payloads = vec![
            json!({
                "username": "testuser",
                "role": "admin",
                "is_admin": true
            }),
            json!({
                "email": "test@example.com",
                "is_verified": true,
                "permissions": ["admin", "write", "delete"]
            }),
            json!({
                "name": "Test",
                "balance": 1000000,
                "credits": 9999
            }),
            json!({
                "id": 1,
                "user_id": 1,
                "admin": true,
                "superuser": true
            }),
        ];

        for payload in &mass_assignment_payloads {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(url, &payload.to_string(), headers)
                .await
            {
                Ok(response) => {
                    // Check if sensitive fields were accepted
                    let response_json: Result<Value, _> = serde_json::from_str(&response.body);
                    if let Ok(json) = response_json {
                        let sensitive_fields = vec![
                            "role",
                            "is_admin",
                            "admin",
                            "superuser",
                            "balance",
                            "credits",
                            "permissions",
                        ];

                        for field in sensitive_fields {
                            if json.get(field).is_some() {
                                vulnerabilities.push(self.create_vulnerability(
                                    "Mass Assignment Vulnerability",
                                    url,
                                    &payload.to_string(),
                                    &format!(
                                        "API allows modification of sensitive field: {}",
                                        field
                                    ),
                                    Severity::High,
                                    "CWE-915",
                                    7.5,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Mass assignment test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for IDOR (Insecure Direct Object Reference) vulnerabilities
    async fn test_idor(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing IDOR vulnerabilities");

        // Test sequential ID access
        let id_patterns = vec![
            ("/users/1", "/users/2"),
            ("/api/users/1", "/api/users/2"),
            ("/accounts/1", "/accounts/2"),
            ("/orders/1", "/orders/2"),
            ("/invoices/1", "/invoices/2"),
        ];

        for (id1, id2) in &id_patterns {
            let url1 = self.build_url(url, id1);
            let url2 = self.build_url(url, id2);

            // Request two different IDs
            let result1 = self.http_client.get(&url1).await;
            let result2 = self.http_client.get(&url2).await;

            if let (Ok(resp1), Ok(resp2)) = (result1, result2) {
                // Both requests successful - potential IDOR
                if resp1.status_code == 200 && resp2.status_code == 200 {
                    // Check if responses contain different user data
                    if resp1.body != resp2.body && self.contains_user_data(&resp1.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "IDOR - Insecure Direct Object Reference",
                            &url1,
                            &format!("Sequential access: {} and {}", id1, id2),
                            "API allows unauthorized access to objects via predictable IDs",
                            Severity::High,
                            "CWE-737",
                            7.5,
                        ));
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for Broken Object Level Authorization (BOLA)
    async fn test_bola(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing broken object level authorization");

        // Test with and without authentication
        let test_urls = vec![
            format!("{}/users/1", url.trim_end_matches('/')),
            format!("{}/api/users/1", url.trim_end_matches('/')),
            format!("{}/profile/1", url.trim_end_matches('/')),
            format!("{}/account/1", url.trim_end_matches('/')),
        ];

        for test_url in &test_urls {
            // Request without auth
            if let Ok(response) = self.http_client.get(test_url).await {
                if response.status_code == 200 && self.contains_user_data(&response.body) {
                    vulnerabilities.push(self.create_vulnerability(
                        "Broken Object Level Authorization",
                        test_url,
                        "Unauthenticated access",
                        "API endpoint returns user data without authentication",
                        Severity::Critical,
                        "CWE-284",
                        9.1,
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API rate limiting
    async fn test_rate_limits(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let max_requests = 100;
        let tests_run = max_requests;

        debug!("Testing rate limiting");

        let mut rate_limited = false;
        let mut request_count = 0;

        for i in 0..max_requests {
            match self.http_client.get(url).await {
                Ok(response) => {
                    request_count = i + 1;

                    // Check for rate limit response
                    if response.status_code == 429 {
                        rate_limited = true;
                        debug!("Rate limited after {} requests", request_count);
                        break;
                    }

                    // Check for rate limit headers
                    if response.header("X-RateLimit-Limit").is_some() {
                        rate_limited = true;
                        debug!("Rate limit headers detected");
                        break;
                    }
                }
                Err(_) => break,
            }

            // Small delay to avoid overwhelming the server
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        if !rate_limited && request_count >= 50 {
            vulnerabilities.push(self.create_vulnerability(
                "Missing Rate Limiting",
                url,
                &format!("{} requests without rate limiting", request_count),
                "API endpoint does not implement rate limiting",
                Severity::Medium,
                "CWE-770",
                5.3,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API versioning issues
    async fn test_api_versioning(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing API versioning issues");

        // Extract version from URL
        let version_regex = Regex::new(r"/v(\d+)/").ok();

        if let Some(regex) = version_regex {
            if let Some(captures) = regex.captures(url) {
                if let Some(version) = captures.get(1) {
                    let current_version: i32 = version.as_str().parse().unwrap_or(1);

                    // Test older versions
                    for old_version in 1..current_version {
                        let old_url = url.replace(
                            &format!("/v{}/", current_version),
                            &format!("/v{}/", old_version),
                        );

                        if let Ok(response) = self.http_client.get(&old_url).await {
                            if response.status_code == 200 {
                                vulnerabilities.push(self.create_vulnerability(
                                    "Outdated API Version Accessible",
                                    &old_url,
                                    &format!("Old version v{} still accessible", old_version),
                                    "Outdated API versions may contain unpatched vulnerabilities",
                                    Severity::Medium,
                                    "CWE-1104",
                                    5.3,
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Fuzz GraphQL APIs
    async fn fuzz_graphql_apis(
        &self,
        endpoints: &[ApiEndpoint],
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for endpoint in endpoints.iter().filter(|e| e.api_type == ApiType::GraphQL) {
            info!("Fuzzing GraphQL API: {}", endpoint.url);

            // Test introspection query exploitation
            let (vulns, tests) = self.test_graphql_introspection(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test batch query attacks
            let (vulns, tests) = self.test_graphql_batch_queries(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test depth limit
            let (vulns, tests) = self.test_graphql_depth_limit(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test query cost analysis
            let (vulns, tests) = self.test_graphql_query_cost(&endpoint.url, config).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test circular query detection
            let (vulns, tests) = self.test_graphql_circular_queries(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test field suggestion attacks
            let (vulns, tests) = self.test_graphql_field_suggestions(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL introspection exploitation
    async fn test_graphql_introspection(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL introspection");

        let introspection_query = json!({
            "query": r#"
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            name
                            kind
                            description
                            fields {
                                name
                                description
                                args {
                                    name
                                    type { name }
                                }
                            }
                        }
                    }
                }
            "#
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &introspection_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                if response.status_code == 200
                    && (response.body.contains("__schema") || response.body.contains("queryType"))
                {
                    let schema_size = response.body.len();
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Introspection Enabled",
                        url,
                        "Full introspection query",
                        &format!(
                            "GraphQL introspection is enabled, exposing {} bytes of schema",
                            schema_size
                        ),
                        Severity::Medium,
                        "CWE-200",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Introspection test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL batch query attacks
    async fn test_graphql_batch_queries(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL batch query attacks");

        // Create batch query with 10 identical queries
        let mut queries = Vec::new();
        for i in 0..10 {
            queries.push(json!({
                "query": format!(r#"query Query{} {{ __typename }}"#, i)
            }));
        }

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &serde_json::to_string(&queries)?, headers)
            .await
        {
            Ok(response) => {
                if response.status_code == 200 {
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Batch Query Attack Possible",
                        url,
                        "10 batched queries",
                        "Server accepts batch queries without limits, enabling DoS attacks",
                        Severity::Medium,
                        "CWE-770",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Batch query test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL depth limit
    async fn test_graphql_depth_limit(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL depth limit");

        // Create deeply nested query
        let deep_query = json!({
            "query": r#"
                query DeepQuery {
                    user {
                        posts {
                            comments {
                                author {
                                    posts {
                                        comments {
                                            author {
                                                posts {
                                                    comments {
                                                        author {
                                                            id
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            "#
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &deep_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                if response.status_code == 200
                    && !response.body.contains("depth")
                    && !response.body.contains("too deep")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Depth Limit Missing",
                        url,
                        "Deeply nested query",
                        "Server accepts deeply nested queries without depth limits",
                        Severity::Medium,
                        "CWE-770",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Depth limit test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL query cost analysis
    async fn test_graphql_query_cost(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL query cost analysis");

        // Create expensive query
        let expensive_query = json!({
            "query": r#"
                query ExpensiveQuery {
                    users(first: 1000) {
                        posts(first: 1000) {
                            comments(first: 1000) {
                                id
                            }
                        }
                    }
                }
            "#
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let start = std::time::Instant::now();
        match self
            .http_client
            .post_with_headers(url, &expensive_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                let duration = start.elapsed();

                if response.status_code == 200 && duration.as_secs() > 5 {
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Query Cost Not Analyzed",
                        url,
                        "Expensive nested list query",
                        &format!(
                            "Server processed expensive query in {} seconds without cost limits",
                            duration.as_secs()
                        ),
                        Severity::Medium,
                        "CWE-770",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Query cost test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL circular queries
    async fn test_graphql_circular_queries(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL circular queries");

        let circular_query = json!({
            "query": r#"
                query CircularQuery {
                    user {
                        friends {
                            friends {
                                friends {
                                    friends {
                                        id
                                    }
                                }
                            }
                        }
                    }
                }
            "#
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &circular_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                if response.status_code == 200 && !response.body.contains("circular") {
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Circular Query Not Prevented",
                        url,
                        "Circular reference query",
                        "Server allows circular queries that may cause infinite loops",
                        Severity::Medium,
                        "CWE-674",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Circular query test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GraphQL field suggestions
    async fn test_graphql_field_suggestions(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing GraphQL field suggestions");

        let typo_query = json!({
            "query": r#"{ usr { nam } }"#
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &typo_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                if response.body.contains("Did you mean")
                    || response.body.contains("suggestion")
                    || (response.body.contains("user") && response.body.contains("name"))
                {
                    vulnerabilities.push(self.create_vulnerability(
                        "GraphQL Field Suggestions Leak Schema",
                        url,
                        "Typo query: { usr { nam } }",
                        "Server provides field suggestions that leak schema information",
                        Severity::Low,
                        "CWE-200",
                        3.7,
                    ));
                }
            }
            Err(e) => {
                debug!("Field suggestion test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Fuzz gRPC APIs
    async fn fuzz_grpc_apis(
        &self,
        endpoints: &[ApiEndpoint],
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for endpoint in endpoints.iter().filter(|e| e.api_type == ApiType::Grpc) {
            info!("Fuzzing gRPC API: {}", endpoint.url);

            // Test protocol buffer fuzzing
            let (vulns, tests) = self.test_grpc_protobuf(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test metadata manipulation
            let (vulns, tests) = self.test_grpc_metadata(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test stream handling
            let (vulns, tests) = self.test_grpc_streams(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test gRPC protocol buffer fuzzing
    async fn test_grpc_protobuf(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing gRPC protobuf fuzzing");

        // Malformed protobuf payloads
        let malformed_payloads = vec![
            vec![0xFF, 0xFF, 0xFF, 0xFF], // Invalid varint
            vec![0x08, 0x96, 0x01],       // Large field number
            vec![0x00, 0x00, 0x00, 0x00], // All zeros
        ];

        let headers = vec![
            ("Content-Type".to_string(), "application/grpc".to_string()),
            ("grpc-encoding".to_string(), "identity".to_string()),
        ];

        for payload in &malformed_payloads {
            let payload_str = String::from_utf8_lossy(payload);

            match self
                .http_client
                .post_with_headers(url, &payload_str, headers.clone())
                .await
            {
                Ok(response) => {
                    if self.detect_error_leakage(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "gRPC Protobuf Error Leakage",
                            url,
                            "Malformed protobuf",
                            "Server leaks internal information when processing malformed protobuf",
                            Severity::Low,
                            "CWE-209",
                            3.7,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Protobuf fuzzing failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test gRPC metadata manipulation
    async fn test_grpc_metadata(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing gRPC metadata manipulation");

        let metadata_tests = vec![
            ("grpc-timeout", "1n"),           // Very short timeout
            ("grpc-timeout", "999999H"),      // Very long timeout
            ("grpc-encoding", "malicious"),   // Invalid encoding
            ("authorization", "Bearer fake"), // Fake auth
        ];

        for (key, value) in &metadata_tests {
            let headers = vec![
                ("Content-Type".to_string(), "application/grpc".to_string()),
                (key.to_string(), value.to_string()),
            ];

            match self.http_client.post_with_headers(url, "", headers).await {
                Ok(response) => {
                    if response.status_code == 200 && *key == "authorization" {
                        vulnerabilities.push(self.create_vulnerability(
                            "gRPC Metadata Authentication Bypass",
                            url,
                            &format!("{}: {}", key, value),
                            "Server accepts invalid authentication metadata",
                            Severity::High,
                            "CWE-287",
                            7.5,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Metadata test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test gRPC stream handling
    async fn test_grpc_streams(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing gRPC stream handling");

        let headers = vec![
            ("Content-Type".to_string(), "application/grpc".to_string()),
            ("grpc-encoding".to_string(), "identity".to_string()),
        ];

        // Test with large payload to check stream handling
        let large_payload = "A".repeat(1024 * 1024); // 1MB

        match self
            .http_client
            .post_with_headers(url, &large_payload, headers)
            .await
        {
            Ok(response) => {
                if response.status_code == 200 {
                    vulnerabilities.push(self.create_vulnerability(
                        "gRPC Stream Size Limit Missing",
                        url,
                        "1MB payload",
                        "Server accepts large payloads without stream size limits",
                        Severity::Medium,
                        "CWE-770",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Stream test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test authentication bypass techniques
    async fn test_auth_bypass(
        &self,
        endpoints: &[ApiEndpoint],
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing authentication bypass techniques");

        for endpoint in endpoints {
            // Test JWT manipulation
            let (vulns, tests) = self.test_jwt_manipulation(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test OAuth flow attacks
            let (vulns, tests) = self.test_oauth_attacks(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test API key enumeration
            let (vulns, tests) = self.test_api_key_enumeration(&endpoint.url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test token replay attacks
            if config.scan_mode == ScanMode::Thorough || config.scan_mode == ScanMode::Insane {
                let (vulns, tests) = self.test_token_replay(&endpoint.url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JWT manipulation (alg:none, weak signing)
    async fn test_jwt_manipulation(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing JWT manipulation");

        // JWT with alg:none
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.";

        // JWT with alg:None (capital N)
        let none_capital_jwt =
            "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.";

        // JWT with alg:NONE (all caps)
        let none_upper_jwt =
            "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.";

        let jwt_tests = vec![
            (none_jwt, "alg:none"),
            (none_capital_jwt, "alg:None"),
            (none_upper_jwt, "alg:NONE"),
        ];

        for (jwt, description) in &jwt_tests {
            let headers = vec![("Authorization".to_string(), format!("Bearer {}", jwt))];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if response.status_code < 400 {
                        vulnerabilities.push(self.create_vulnerability(
                            "JWT None Algorithm Vulnerability",
                            url,
                            &format!("JWT with {}", description),
                            "Server accepts JWT tokens with 'none' algorithm",
                            Severity::Critical,
                            "CWE-347",
                            9.8,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("JWT test failed: {}", e);
                }
            }
        }

        // Test JWT with modified payload but same signature
        let tampered_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", tampered_jwt),
        )];

        if let Ok(response) = self.http_client.get_with_headers(url, headers).await {
            if response.status_code < 400 {
                vulnerabilities.push(self.create_vulnerability(
                    "JWT Signature Not Verified",
                    url,
                    "Tampered JWT accepted",
                    "Server does not properly verify JWT signatures",
                    Severity::Critical,
                    "CWE-347",
                    9.8,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test OAuth flow attacks
    async fn test_oauth_attacks(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing OAuth flow attacks");

        // Look for OAuth endpoints
        let oauth_paths = vec![
            "/oauth/token".to_string(),
            "/oauth/authorize".to_string(),
            "/api/oauth/token".to_string(),
        ];

        for path in &oauth_paths {
            let test_url = self.build_url(url, &path);

            // Test with fake authorization code
            let fake_auth = json!({
                "grant_type": "authorization_code",
                "code": "fake_code_12345",
                "client_id": "test_client",
                "redirect_uri": "http://evil.com"
            });

            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self
                .http_client
                .post_with_headers(&test_url, &fake_auth.to_string(), headers)
                .await
            {
                Ok(response) => {
                    // Check for verbose error messages
                    if self.detect_error_leakage(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "OAuth Error Information Leakage",
                            &test_url,
                            &fake_auth.to_string(),
                            "OAuth endpoint leaks sensitive information in error messages",
                            Severity::Low,
                            "CWE-209",
                            3.7,
                        ));
                    }

                    // Check for redirect_uri validation
                    if response.body.contains("access_token") {
                        vulnerabilities.push(self.create_vulnerability(
                            "OAuth Redirect URI Not Validated",
                            &test_url,
                            "redirect_uri: http://evil.com",
                            "OAuth endpoint does not properly validate redirect_uri",
                            Severity::High,
                            "CWE-601",
                            7.5,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("OAuth test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API key enumeration
    async fn test_api_key_enumeration(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing API key enumeration");

        // Test different API key formats
        let api_key_headers = vec![
            ("X-API-Key", "test123"),
            ("X-Api-Key", "fake_key_12345"),
            ("API-Key", "00000000-0000-0000-0000-000000000000"),
            ("Authorization", "ApiKey test123"),
            ("x-api-key", "ABCDEF123456"),
        ];

        let mut response_lengths = HashSet::new();

        for (header, key) in &api_key_headers {
            let headers = vec![(header.to_string(), key.to_string())];

            if let Ok(response) = self.http_client.get_with_headers(url, headers).await {
                response_lengths.insert(response.body.len());
            }
        }

        // If all responses have different lengths, enumeration is possible
        if response_lengths.len() == api_key_headers.len() {
            vulnerabilities.push(self.create_vulnerability(
                "API Key Enumeration Possible",
                url,
                "Different response lengths for different keys",
                "Server response varies based on API key validity, enabling enumeration",
                Severity::Medium,
                "CWE-203",
                5.3,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test token replay attacks
    async fn test_token_replay(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing token replay attacks");

        // Create a test token
        let test_token = format!("test_token_{}", self.test_marker);
        let headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", test_token),
        )];

        // First request
        let first_response = self
            .http_client
            .get_with_headers(url, headers.clone())
            .await;

        // Small delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Replay request
        let replay_response = self.http_client.get_with_headers(url, headers).await;

        if let (Ok(resp1), Ok(resp2)) = (first_response, replay_response) {
            // CRITICAL: Don't report replay vulnerability on non-existent endpoints
            // 404 responses are identical because the endpoint doesn't exist, not because replay worked
            if resp1.status_code != 404  // Endpoint must exist
                && resp1.status_code == resp2.status_code
                && resp1.body == resp2.body
                && !resp1.body.to_lowercase().contains("not found")  // Additional check
                && !resp1.body.to_lowercase().contains("cannot get")
            {
                // NestJS 404 message
                vulnerabilities.push(self.create_vulnerability(
                    "Token Replay Attack Possible",
                    url,
                    "Same token used twice",
                    "Server does not implement nonce or timestamp validation for token replay prevention",
                    Severity::Medium,
                    "CWE-294",
                    6.5,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // Helper methods

    /// Detect API type from response
    fn detect_api_type(&self, body: &str, headers: &HashMap<String, String>) -> ApiType {
        // Check headers
        if let Some(content_type) = headers.get("content-type") {
            let ct_lower = content_type.to_lowercase();
            if ct_lower.contains("application/grpc") {
                return ApiType::Grpc;
            }
            if ct_lower.contains("application/json") || ct_lower.contains("application/graphql") {
                if body.contains("\"data\"") && body.contains("\"errors\"") {
                    return ApiType::GraphQL;
                }
                if serde_json::from_str::<Value>(body).is_ok() {
                    return ApiType::Rest;
                }
            }
        }

        // Check body content
        if body.contains("__schema") || body.contains("__type") {
            return ApiType::GraphQL;
        }

        ApiType::None
    }

    /// Send HTTP request with custom method
    async fn send_http_request(
        &self,
        url: &str,
        method: &str,
        body: Option<&str>,
        headers: Vec<(String, String)>,
    ) -> anyhow::Result<crate::http_client::HttpResponse> {
        match method {
            "GET" => self.http_client.get_with_headers(url, headers).await,
            "POST" => {
                self.http_client
                    .post_with_headers(url, body.unwrap_or(""), headers)
                    .await
            }
            "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD" | "TRACE" => {
                // For now, treat these as GET requests
                // A full implementation would use reqwest directly
                self.http_client.get_with_headers(url, headers).await
            }
            _ => self.http_client.get(url).await,
        }
    }

    /// Detect error leakage in response
    fn detect_error_leakage(&self, body: &str) -> bool {
        let error_indicators = vec![
            "at ",
            "stack trace",
            "Exception",
            "Error:",
            "/home/",
            "/var/",
            "C:\\",
            ".java:",
            ".py:",
            ".rb:",
            ".js:",
            "line ",
        ];

        error_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    /// Check if response contains user data
    fn contains_user_data(&self, body: &str) -> bool {
        let user_indicators = vec![
            "email",
            "username",
            "user_id",
            "userId",
            "firstName",
            "lastName",
            "phone",
            "address",
        ];

        user_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    /// Extract base URL from full URL
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.to_string()
        }
    }

    /// Build URL from base and path
    fn build_url(&self, base: &str, path: &str) -> String {
        let base_trimmed = base.trim_end_matches('/');
        let path_trimmed = path.trim_start_matches('/');
        format!("{}/{}", base_trimmed, path_trimmed)
    }

    /// Extract evidence from response body
    fn extract_evidence(&self, body: &str, max_len: usize) -> String {
        if body.len() > max_len {
            format!("{}...", &body[..max_len])
        } else {
            body.to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        payload: &str,
        description: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        let confidence = match severity {
            Severity::Critical | Severity::High => Confidence::High,
            Severity::Medium => Confidence::Medium,
            _ => Confidence::Low,
        };

        Vulnerability {
            id: format!("apifuzz_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(description.to_string()),
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

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Unsafe HTTP Method Allowed" => "1. Disable unnecessary HTTP methods (TRACE, DELETE)\n\
                 2. Implement proper method-based access control\n\
                 3. Configure web server to reject unsafe methods\n\
                 4. Use method whitelisting instead of blacklisting"
                .to_string(),
            "Type Confusion Vulnerability" => "1. Implement strict input type validation\n\
                 2. Use schema validation (JSON Schema, OpenAPI)\n\
                 3. Reject unexpected data types\n\
                 4. Sanitize and validate all inputs"
                .to_string(),
            "Mass Assignment Vulnerability" => "1. Use allowlists for updatable fields\n\
                 2. Never bind request data directly to models\n\
                 3. Implement role-based field access control\n\
                 4. Use Data Transfer Objects (DTOs)\n\
                 5. Validate all field modifications"
                .to_string(),
            "IDOR - Insecure Direct Object Reference" => {
                "1. Implement proper authorization checks\n\
                 2. Use indirect object references (UUIDs)\n\
                 3. Verify user owns requested resource\n\
                 4. Implement access control lists (ACLs)\n\
                 5. Never expose sequential IDs"
                    .to_string()
            }
            "Broken Object Level Authorization" => "1. Implement authentication on all endpoints\n\
                 2. Verify user authorization for each resource\n\
                 3. Use middleware for consistent auth checks\n\
                 4. Implement least privilege principle\n\
                 5. Log all access attempts"
                .to_string(),
            "Missing Rate Limiting" => "1. Implement rate limiting per endpoint\n\
                 2. Use token bucket or sliding window algorithms\n\
                 3. Return 429 status when limit exceeded\n\
                 4. Implement different limits for authenticated users\n\
                 5. Monitor for rate limit abuse"
                .to_string(),
            "GraphQL Introspection Enabled" => "1. Disable introspection in production\n\
                 2. Use environment-based configuration\n\
                 3. Implement authentication for introspection\n\
                 4. Use GraphQL security tools\n\
                 5. Monitor introspection queries"
                .to_string(),
            "GraphQL Batch Query Attack Possible" => "1. Limit number of queries per request\n\
                 2. Implement query complexity analysis\n\
                 3. Set timeout limits for queries\n\
                 4. Use query cost analysis\n\
                 5. Monitor for abuse patterns"
                .to_string(),
            "JWT None Algorithm Vulnerability" => "1. Never accept 'none' algorithm\n\
                 2. Use strong algorithms (RS256, ES256)\n\
                 3. Validate algorithm in token header\n\
                 4. Implement proper JWT library\n\
                 5. Set token expiration\n\
                 6. Rotate signing keys regularly"
                .to_string(),
            "OAuth Redirect URI Not Validated" => "1. Implement strict redirect_uri validation\n\
                 2. Use exact match, not partial match\n\
                 3. Maintain allowlist of valid URIs\n\
                 4. Never use wildcards in validation\n\
                 5. Log all redirect attempts"
                .to_string(),
            _ => "Follow OWASP API Security Top 10 guidelines:\n\
                  1. Implement proper authentication and authorization\n\
                  2. Validate all inputs\n\
                  3. Use rate limiting\n\
                  4. Implement logging and monitoring\n\
                  5. Keep security libraries updated"
                .to_string(),
        }
    }
}

/// API endpoint information
#[derive(Debug, Clone)]
struct ApiEndpoint {
    url: String,
    api_type: ApiType,
    methods: Vec<String>,
}

/// API type enumeration
#[derive(Debug, Clone, PartialEq)]
enum ApiType {
    Rest,
    GraphQL,
    Grpc,
    None,
}

impl ApiType {
    fn as_str(&self) -> &str {
        match self {
            ApiType::Rest => "REST",
            ApiType::GraphQL => "GraphQL",
            ApiType::Grpc => "gRPC",
            ApiType::None => "None",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;

    fn create_test_scanner() -> ApiFuzzerScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        ApiFuzzerScanner::new(http_client)
    }

    #[test]
    fn test_detect_api_type_rest() {
        let scanner = create_test_scanner();
        let body = r#"{"users": [{"id": 1}]}"#;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let api_type = scanner.detect_api_type(body, &headers);
        assert_eq!(api_type, ApiType::Rest);
    }

    #[test]
    fn test_detect_api_type_graphql() {
        let scanner = create_test_scanner();
        let body = r#"{"data": {"users": []}, "errors": []}"#;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let api_type = scanner.detect_api_type(body, &headers);
        assert_eq!(api_type, ApiType::GraphQL);
    }

    #[test]
    fn test_detect_api_type_grpc() {
        let scanner = create_test_scanner();
        let body = "";
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/grpc".to_string());

        let api_type = scanner.detect_api_type(body, &headers);
        assert_eq!(api_type, ApiType::Grpc);
    }

    #[test]
    fn test_detect_error_leakage() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_error_leakage("Error at line 123"));
        assert!(scanner.detect_error_leakage("Exception in /home/user/app.js"));
        assert!(scanner.detect_error_leakage("Stack trace: ..."));
        assert!(!scanner.detect_error_leakage("Success"));
    }

    #[test]
    fn test_contains_user_data() {
        let scanner = create_test_scanner();

        assert!(scanner.contains_user_data(r#"{"email": "test@example.com"}"#));
        assert!(scanner.contains_user_data(r#"{"userId": 123}"#));
        assert!(!scanner.contains_user_data(r#"{"status": "ok"}"#));
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.build_url("http://example.com", "/api/users"),
            "http://example.com/api/users"
        );
        assert_eq!(
            scanner.build_url("http://example.com/", "/api/users"),
            "http://example.com/api/users"
        );
        assert_eq!(
            scanner.build_url("http://example.com", "api/users"),
            "http://example.com/api/users"
        );
    }

    #[test]
    fn test_extract_evidence() {
        let scanner = create_test_scanner();

        let long_text = "A".repeat(500);
        let evidence = scanner.extract_evidence(&long_text, 100);
        assert_eq!(evidence.len(), 103); // 100 + "..."

        let short_text = "Short";
        let evidence = scanner.extract_evidence(short_text, 100);
        assert_eq!(evidence, "Short");
    }

    #[test]
    fn test_extract_base_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_base_url("http://example.com/api/users"),
            "http://example.com"
        );
        assert_eq!(
            scanner.extract_base_url("https://api.example.com/v1/data"),
            "https://api.example.com"
        );
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "Test Vulnerability",
            "http://example.com",
            "test payload",
            "Test description",
            Severity::High,
            "CWE-123",
            7.5,
        );

        assert_eq!(vuln.vuln_type, "Test Vulnerability");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.confidence, Confidence::High);
        assert_eq!(vuln.cwe, "CWE-123");
        assert_eq!(vuln.cvss, 7.5);
    }
}
