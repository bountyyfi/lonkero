// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct ApiGatewayScanner {
    http_client: Arc<HttpClient>,
}

impl ApiGatewayScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for API Gateway security vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing API Gateway security vulnerabilities");

        let (vulns, tests) = self.test_rate_limit_bypass(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_api_key_leakage(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_api_versioning_issues(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_gateway_auth_bypass(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_schema_disclosure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Always test for BFF/Internal gateway exposure
        let (vulns, tests) = self.test_bff_internal_discovery(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        Ok((vulnerabilities, tests_run))
    }

    /// Test rate limit bypass via header manipulation
    /// Only reports if we can demonstrate rate limiting exists AND can be bypassed
    async fn test_rate_limit_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 25;

        debug!("Testing rate limit bypass via header manipulation");

        // Step 1: First establish that rate limiting EXISTS by making requests without bypass headers
        // Look for 429 response or rate limit headers
        let mut rate_limit_detected = false;
        let mut rate_limit_header = String::new();

        // Make baseline requests to detect rate limiting
        for _ in 0..10 {
            match self.http_client.get(url).await {
                Ok(response) => {
                    // Check for 429 status
                    if response.status_code == 429 {
                        rate_limit_detected = true;
                        break;
                    }
                    // Check for rate limit headers (X-RateLimit-*, RateLimit-*, Retry-After)
                    for (key, value) in &response.headers {
                        let key_lower = key.to_lowercase();
                        if key_lower.contains("ratelimit") || key_lower.contains("rate-limit") ||
                           key_lower == "retry-after" || key_lower.contains("x-rate") {
                            rate_limit_header = format!("{}: {}", key, value);
                            rate_limit_detected = true;
                        }
                    }
                }
                Err(_) => break,
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        // If no rate limiting detected, don't report false positive
        if !rate_limit_detected {
            debug!("No rate limiting detected on {} - skipping bypass test", url);
            return Ok((vulnerabilities, tests_run));
        }

        info!("Rate limiting detected ({}), testing header bypass",
              if rate_limit_header.is_empty() { "429 response" } else { &rate_limit_header });

        // Step 2: Now test if headers can bypass the rate limit
        let bypass_headers = vec![
            vec![("X-Forwarded-For".to_string(), "127.0.0.1".to_string())],
            vec![("X-Originating-IP".to_string(), "127.0.0.1".to_string())],
            vec![("X-Real-IP".to_string(), "127.0.0.1".to_string())],
            vec![("X-Client-IP".to_string(), "127.0.0.1".to_string())],
        ];

        for headers in bypass_headers {
            let mut success_count = 0;
            let mut got_429 = false;

            // Make multiple requests with bypass header
            for i in 0..5 {
                match self.http_client.get_with_headers(url, headers.clone()).await {
                    Ok(response) => {
                        if response.status_code == 200 || response.status_code == 304 {
                            success_count += 1;
                        } else if response.status_code == 429 {
                            got_429 = true;
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Request {} failed: {}", i, e);
                        break;
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
            }

            // Only report if we got 5 successful responses without hitting rate limit
            // AND we previously confirmed rate limiting exists
            if success_count >= 5 && !got_429 {
                let header_name = &headers[0].0;
                info!("Rate limit bypass confirmed via {} header", header_name);
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Rate Limit Bypass via Header Manipulation",
                    &format!("{}: 127.0.0.1", header_name),
                    &format!("Rate limiting can be bypassed by spoofing the '{}' header. Baseline rate limiting was detected ({}), but header manipulation allows unlimited requests.",
                        header_name, if rate_limit_header.is_empty() { "429 response" } else { &rate_limit_header }),
                    &format!("Rate limit bypassed: {} requests succeeded with {} header after rate limit was detected", success_count, header_name),
                    Severity::High,
                    "CWE-770",
                    7.5,
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for API key leakage
    async fn test_api_key_leakage(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing for API key leakage");

        let test_paths = vec![
            "/api/config",
            "/api/settings",
            "/api/env",
            "/api/debug",
            "/.env",
            "/config.json",
            "/swagger.json",
            "/openapi.json",
        ];

        for path in test_paths {
            let test_url = self.build_url(url, path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(api_key) = self.extract_api_key(&response.body) {
                        info!("API key leakage detected at {}", path);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Key Leakage",
                            "",
                            &format!("API key exposed in {} endpoint", path),
                            &format!("API key found: {}...", &api_key[..api_key.len().min(20)]),
                            Severity::Critical,
                            "CWE-798",
                            9.1,
                        ));
                        break;
                    }

                    if response.headers.iter().any(|(k, v)| {
                        k.to_lowercase().contains("api") && (
                            v.len() > 20 &&
                            (v.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'))
                        )
                    }) {
                        info!("API key leaked in response headers at {}", path);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Key Leakage in Headers",
                            "",
                            "API key exposed in HTTP response headers",
                            &format!("API key found in response headers at {}", path),
                            Severity::Critical,
                            "CWE-798",
                            9.1,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", test_url, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API versioning issues
    async fn test_api_versioning_issues(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing API versioning issues");

        let version_patterns = vec![
            ("/v1/", "/v0/"),
            ("/v2/", "/v1/"),
            ("/v3/", "/v2/"),
            ("/api/v1/", "/api/v0/"),
            ("/api/v2/", "/api/v1/"),
        ];

        for (current, old) in version_patterns {
            if url.contains(current) {
                let old_url = url.replace(current, old);

                match self.http_client.get(&old_url).await {
                    Ok(response) => {
                        if response.status_code == 200 && !response.body.is_empty() {
                            if !self.has_deprecation_warning(&response.body, &response.headers) {
                                info!("Deprecated API version accessible: {}", old);
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Deprecated API Version Accessible",
                                    "",
                                    &format!("Older API version {} is still accessible without deprecation warnings", old),
                                    &format!("Deprecated endpoint {} returned 200 OK", old),
                                    Severity::Medium,
                                    "CWE-477",
                                    5.3,
                                ));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Request to deprecated version failed: {}", e);
                    }
                }
            }
        }

        let test_versions = vec!["v0".to_string(), "v1".to_string(), "v2".to_string(), "v3".to_string(), "v4".to_string(), "v5".to_string()];
        for version in test_versions {
            let version_url = format!("{}/api/{}/users", self.extract_base_url(url), &version);

            match self.http_client.get(&version_url).await {
                Ok(response) => {
                    // Check if this is actually an API response, not an SPA fallback
                    // SPAs return HTML for all non-existent routes
                    let content_type = response.headers.get("content-type")
                        .or_else(|| response.headers.get("Content-Type"))
                        .map(|s| s.to_lowercase())
                        .unwrap_or_default();

                    let is_api_response = content_type.contains("application/json")
                        || content_type.contains("text/json")
                        || content_type.contains("application/xml");

                    // Don't report if it's HTML (likely SPA fallback)
                    let is_html = content_type.contains("text/html")
                        || response.body.trim_start().starts_with("<!DOCTYPE")
                        || response.body.trim_start().starts_with("<html");

                    if response.status_code == 200
                        && is_api_response
                        && !is_html
                        && !self.has_deprecation_warning(&response.body, &response.headers)
                    {
                        info!("Undocumented API version found: {}", version);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Undocumented API Version Exposed",
                            "",
                            &format!("Undocumented API version {} is publicly accessible", version),
                            &format!("Found accessible endpoint: {}", version_url),
                            Severity::Low,
                            "CWE-200",
                            3.7,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Version {} check failed: {}", version, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test gateway authentication bypass
    async fn test_gateway_auth_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing gateway authentication bypass");

        let bypass_techniques = vec![
            ("../api/admin", "Path Traversal"),
            ("/api/admin/..;/", "Path Parameter Bypass"),
            ("/api/admin%2f..%2f", "URL Encoding Bypass"),
            ("/api/admin/../admin", "Directory Traversal"),
            ("/api//admin", "Double Slash"),
            ("/api/./admin", "Current Directory"),
        ];

        for (bypass_path, technique) in bypass_techniques {
            let test_url = format!("{}{}", self.extract_base_url(url), bypass_path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.looks_like_admin_panel(&response.body) {
                        info!("Gateway auth bypass detected: {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Gateway Authentication Bypass",
                            bypass_path,
                            &format!("Gateway authentication can be bypassed using {}", technique),
                            &format!("Successfully accessed protected endpoint using {}", technique),
                            Severity::Critical,
                            "CWE-287",
                            9.8,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Bypass attempt failed: {}", e);
                }
            }
        }

        let header_bypasses = vec![
            vec![("X-Original-URL".to_string(), "/api/admin".to_string())],
            vec![("X-Rewrite-URL".to_string(), "/api/admin".to_string())],
            vec![("X-Forwarded-Path".to_string(), "/api/admin".to_string())],
            vec![("X-Custom-IP-Authorization".to_string(), "127.0.0.1".to_string())],
            vec![("X-ProxyUser-Ip".to_string(), "127.0.0.1".to_string())],
            vec![("Authorization".to_string(), "Bearer null".to_string())],
        ];

        for headers in header_bypasses {
            match self.http_client.get_with_headers(url, headers.clone()).await {
                Ok(response) => {
                    if response.status_code == 200 && self.looks_like_admin_panel(&response.body) {
                        let header_name = &headers[0].0;
                        info!("Gateway auth bypass via header: {}", header_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Gateway Authentication Bypass via Headers",
                            &format!("{}: {}", headers[0].0, headers[0].1),
                            &format!("Gateway authentication bypassed using {} header", header_name),
                            &format!("Successfully bypassed auth using {} header", header_name),
                            Severity::Critical,
                            "CWE-287",
                            9.8,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Header bypass failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for API schema disclosure
    async fn test_schema_disclosure(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing for API schema disclosure");

        let schema_endpoints = vec![
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api/swagger.json",
            "/api/openapi.json",
            "/docs",
            "/api/docs",
            "/redoc",
        ];

        for endpoint in schema_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.is_api_schema(&response.body) {
                        info!("API schema exposed at {}", endpoint);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Schema Disclosure",
                            "",
                            &format!("API schema/documentation publicly exposed at {}", endpoint),
                            &format!("OpenAPI/Swagger schema accessible at {}", endpoint),
                            Severity::Medium,
                            "CWE-200",
                            5.3,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Schema check failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for BFF (Backend-For-Frontend) and internal gateway exposure
    /// Detects: internal API URLs in redirects, BFF config endpoints, gatewayInternal exposure
    async fn test_bff_internal_discovery(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let base_url = self.extract_base_url(url);

        debug!("Testing for BFF/Internal gateway exposure");

        // Common BFF (Backend-For-Frontend) path patterns
        let bff_paths = vec![
            // BFF endpoints
            "/cx-bff/config/",
            "/cx-bff/config/.?params=test",
            "/bff/config/",
            "/bff/api/",
            "/_bff/",
            "/api-bff/",
            // Gateway internal endpoints
            "/gateway/internal/",
            "/gatewayInternal/",
            "/internal-api/",
            "/internal/",
            "/proxy/internal/",
            // Config discovery
            "/config/",
            "/api/config/",
            "/api/internal/",
            "/.internal/",
            // Graph/Federation
            "/graphql/internal/",
            "/federation/",
            // Service mesh
            "/service/internal/",
            "/mesh/",
            "/sidecar/",
        ];

        // Fuzz suffixes to append for path-based discovery
        let fuzz_suffixes = vec![
            "",
            "FUZZ",
            "test",
            "../",
            "..;/",
            "..",
            "config",
            "internal",
            "admin",
            "debug",
        ];

        for path in &bff_paths {
            for suffix in &fuzz_suffixes {
                let test_path = if suffix.is_empty() {
                    path.to_string()
                } else {
                    format!("{}{}", path, suffix)
                };

                let test_url = format!("{}{}", base_url, test_path);
                tests_run += 1;

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        // Check for 302 redirect to internal URLs
                        if response.status_code == 302 || response.status_code == 301 {
                            if let Some(location) = response.headers.get("location")
                                .or_else(|| response.headers.get("Location")) {
                                // Check if redirect reveals internal endpoints
                                if self.is_internal_url(location) {
                                    info!("Found internal URL in redirect: {}", location);
                                    vulnerabilities.push(self.create_vulnerability(
                                        &test_url,
                                        "Internal API URL Exposed via Redirect",
                                        &test_path,
                                        &format!(
                                            "BFF/Gateway endpoint redirects to internal API URL. \
                                            This exposes internal infrastructure details and may allow \
                                            access to internal services. Redirect target: {}",
                                            location
                                        ),
                                        &format!(
                                            "Request: GET {}\nStatus: {}\nLocation: {}",
                                            test_url, response.status_code, location
                                        ),
                                        Severity::High,
                                        "CWE-200",
                                        7.5,
                                    ));
                                }
                            }
                        }

                        // Check response body for internal gateway indicators
                        let internal_indicators = vec![
                            ("gatewayInternal", "Internal gateway URL exposed"),
                            ("internalApi", "Internal API reference"),
                            ("internal-service", "Internal service reference"),
                            ("backstage", "Backstage/internal reference"),
                            (".internal.", "Internal domain reference"),
                            ("localhost:", "Localhost reference"),
                            ("127.0.0.1:", "Loopback IP reference"),
                            ("10.0.", "Internal IP (10.x.x.x)"),
                            ("172.16.", "Internal IP (172.16.x.x)"),
                            ("192.168.", "Internal IP (192.168.x.x)"),
                        ];

                        for (indicator, desc) in &internal_indicators {
                            if response.body.contains(indicator) {
                                info!("Found internal indicator '{}' in response", indicator);

                                // Avoid duplicates
                                let vuln_exists = vulnerabilities.iter().any(|v| {
                                    v.evidence.as_ref().map(|e| e.contains(indicator)).unwrap_or(false)
                                });

                                if !vuln_exists {
                                    vulnerabilities.push(self.create_vulnerability(
                                        &test_url,
                                        "Internal Infrastructure Exposure",
                                        &test_path,
                                        &format!(
                                            "Response contains internal infrastructure reference: {}. \
                                            This may expose internal service URLs, IPs, or architecture details \
                                            that could aid attackers in lateral movement.",
                                            desc
                                        ),
                                        &format!(
                                            "Request: GET {}\nIndicator found: {}\nResponse excerpt: {}",
                                            test_url,
                                            indicator,
                                            self.extract_context(&response.body, indicator)
                                        ),
                                        Severity::Medium,
                                        "CWE-200",
                                        5.3,
                                    ));
                                }
                            }
                        }

                        // Check for path reflection in JSON error responses (401/403)
                        if (response.status_code == 401 || response.status_code == 403)
                            && response.body.contains("\"path\"")
                            && response.body.contains(&test_path.replace("FUZZ", ""))
                        {
                            // Check if it's a JSON response with path reflection
                            if response.body.trim_start().starts_with('{') {
                                info!("Found path reflection in JSON error response");

                                let vuln_exists = vulnerabilities.iter().any(|v| {
                                    v.vuln_type == "BFF Path Reflection in Error Response"
                                });

                                if !vuln_exists {
                                    vulnerabilities.push(self.create_vulnerability(
                                        &test_url,
                                        "BFF Path Reflection in Error Response",
                                        &test_path,
                                        "BFF/Gateway endpoint reflects the requested path in JSON error responses. \
                                        This can be used for endpoint enumeration and may indicate \
                                        additional hidden endpoints that could be discovered via fuzzing.",
                                        &format!(
                                            "Request: GET {}\nStatus: {}\nResponse:\n{}",
                                            test_url,
                                            response.status_code,
                                            self.truncate_body(&response.body, 500)
                                        ),
                                        Severity::Low,
                                        "CWE-200",
                                        3.1,
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("BFF test request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if URL appears to be internal
    fn is_internal_url(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();

        // Internal domain patterns
        url_lower.contains("internal") ||
        url_lower.contains("backstage") ||
        url_lower.contains("localhost") ||
        url_lower.contains("127.0.0.1") ||
        url_lower.contains("10.0.") ||
        url_lower.contains("10.1.") ||
        url_lower.contains("172.16.") ||
        url_lower.contains("172.17.") ||
        url_lower.contains("192.168.") ||
        url_lower.contains(".local") ||
        url_lower.contains(".corp") ||
        url_lower.contains(".internal") ||
        url_lower.contains(":8080") ||
        url_lower.contains(":3000") ||
        url_lower.contains(":5000") ||
        url_lower.contains(":9000") ||
        url_lower.contains("gateway-internal") ||
        url_lower.contains("api-internal")
    }

    /// Extract context around a match
    fn extract_context(&self, body: &str, needle: &str) -> String {
        if let Some(pos) = body.find(needle) {
            let start = pos.saturating_sub(50);
            let end = (pos + needle.len() + 50).min(body.len());
            format!("...{}...", &body[start..end])
        } else {
            String::new()
        }
    }

    /// Truncate body for evidence
    fn truncate_body(&self, body: &str, max_len: usize) -> String {
        if body.len() > max_len {
            format!("{}...", &body[..max_len])
        } else {
            body.to_string()
        }
    }

    fn extract_api_key(&self, body: &str) -> Option<String> {
        let patterns = vec![
            r#""api[_-]?key"\s*:\s*"([A-Za-z0-9\-_]{20,})""#,
            r#""apiKey"\s*:\s*"([A-Za-z0-9\-_]{20,})""#,
            r#""API_KEY"\s*:\s*"([A-Za-z0-9\-_]{20,})""#,
            r#""x-api-key"\s*:\s*"([A-Za-z0-9\-_]{20,})""#,
            r#"apikey=([A-Za-z0-9\-_]{20,})"#,
        ];

        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(body) {
                    if let Some(key) = captures.get(1) {
                        return Some(key.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    fn has_deprecation_warning(&self, body: &str, headers: &std::collections::HashMap<String, String>) -> bool {
        let body_lower = body.to_lowercase();
        let deprecation_indicators = vec![
            "deprecated",
            "sunset",
            "end of life",
            "no longer supported",
            "use v2",
            "use v3",
        ];

        for indicator in deprecation_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        for (key, value) in headers {
            if key.to_lowercase() == "deprecation" ||
               key.to_lowercase() == "sunset" ||
               value.to_lowercase().contains("deprecated") {
                return true;
            }
        }

        false
    }

    fn looks_like_admin_panel(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();
        let admin_indicators = vec![
            "admin",
            "dashboard",
            "control panel",
            "administrator",
            "users",
            "settings",
        ];

        let mut matches = 0;
        for indicator in admin_indicators {
            if body_lower.contains(indicator) {
                matches += 1;
            }
        }

        matches >= 2 || body_lower.contains("admin panel")
    }

    fn is_api_schema(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        (body_lower.contains("swagger") && body_lower.contains("\"paths\"")) ||
        (body_lower.contains("openapi") && body_lower.contains("\"paths\"")) ||
        (body_lower.contains("\"definitions\"") && body_lower.contains("\"parameters\"")) ||
        body_lower.contains("\"x-swagger-router-controller\"")
    }

    fn build_url(&self, base: &str, path: &str) -> String {
        if base.ends_with('/') && path.starts_with('/') {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else if !base.ends_with('/') && !path.starts_with('/') {
            format!("{}/{}", base, path)
        } else {
            format!("{}{}", base, path)
        }
    }

    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.to_string()
        }
    }

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
            id: format!("apigw_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "API Gateway Security".to_string(),
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
                ml_data: None,
        }
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Rate Limit Bypass via Header Manipulation" => {
                "1. Implement rate limiting at multiple layers (gateway + application)\n\
                 2. Do not trust client-provided IP headers (X-Forwarded-For, etc.)\n\
                 3. Use authenticated sessions for rate limiting when possible\n\
                 4. Validate and sanitize all headers before processing\n\
                 5. Configure gateway to strip untrusted headers\n\
                 6. Use composite rate limiting (IP + session + API key)\n\
                 7. Implement distributed rate limiting with Redis/Memcached\n\
                 8. Log and alert on rate limit bypass attempts".to_string()
            }
            "API Key Leakage" | "API Key Leakage in Headers" => {
                "1. Never expose API keys in responses, headers, or error messages\n\
                 2. Use environment variables for API key storage\n\
                 3. Implement proper access controls on configuration endpoints\n\
                 4. Rotate compromised API keys immediately\n\
                 5. Use short-lived tokens instead of long-lived API keys\n\
                 6. Implement API key hashing for storage\n\
                 7. Remove debug/config endpoints from production\n\
                 8. Use secrets management services (AWS Secrets Manager, Vault)".to_string()
            }
            "Deprecated API Version Accessible" | "Undocumented API Version Exposed" => {
                "1. Implement sunset headers for deprecated API versions\n\
                 2. Provide clear deprecation timelines and migration guides\n\
                 3. Disable old API versions after sunset period\n\
                 4. Return 410 Gone for truly deprecated endpoints\n\
                 5. Implement version negotiation in API gateway\n\
                 6. Log usage of deprecated endpoints for monitoring\n\
                 7. Redirect old versions to new versions when possible\n\
                 8. Document all supported API versions publicly".to_string()
            }
            "API Gateway Authentication Bypass" | "API Gateway Authentication Bypass via Headers" => {
                "1. Implement strict path normalization before authentication\n\
                 2. Do not trust client-provided routing headers (X-Original-URL, etc.)\n\
                 3. Use allowlist-based routing instead of blocklists\n\
                 4. Validate and sanitize all URL paths\n\
                 5. Configure gateway to reject path traversal attempts\n\
                 6. Implement defense in depth (gateway + app authentication)\n\
                 7. Log and alert on authentication bypass attempts\n\
                 8. Regular security testing of gateway configuration".to_string()
            }
            "API Schema Disclosure" => {
                "1. Restrict access to API documentation endpoints in production\n\
                 2. Use authentication for Swagger/OpenAPI endpoints\n\
                 3. Serve documentation on separate subdomain with auth\n\
                 4. Remove verbose error messages that leak schema info\n\
                 5. Use API gateway policies to block doc endpoints\n\
                 6. Implement IP allowlisting for documentation access\n\
                 7. Consider removing schema endpoints entirely in production\n\
                 8. Use different configurations for dev vs production".to_string()
            }
            "Internal API URL Exposed via Redirect" => {
                "1. Remove or restrict BFF config endpoints in production\n\
                 2. Do not expose internal service URLs in redirects\n\
                 3. Use relative URLs instead of absolute internal URLs\n\
                 4. Implement proper network segmentation\n\
                 5. Configure gateway to rewrite internal URLs before response\n\
                 6. Use API gateway URL transformation rules\n\
                 7. Audit all redirect responses for internal URL leakage\n\
                 8. Implement allowlist-based redirect validation".to_string()
            }
            "Internal Infrastructure Exposure" | "BFF Path Reflection in Error Response" => {
                "1. Sanitize error responses to remove internal references\n\
                 2. Use generic error messages without infrastructure details\n\
                 3. Configure BFF/gateway to strip internal URLs from responses\n\
                 4. Implement proper response transformation at gateway level\n\
                 5. Use environment-specific error handling (dev vs prod)\n\
                 6. Audit response bodies for internal IP/domain leakage\n\
                 7. Disable debug mode and verbose errors in production\n\
                 8. Use centralized error handling with sanitization".to_string()
            }
            _ => "Follow OWASP API Security Top 10 guidelines and implement defense in depth".to_string(),
        }
    }
}

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
    use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> ApiGatewayScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        ApiGatewayScanner::new(http_client)
    }

    #[test]
    fn test_extract_api_key() {
        let scanner = create_test_scanner();

        let bodies = vec![
            r#"{"api_key": "sk_live_1234567890abcdefghij"}"#,
            r#"{"apiKey": "AKIAIOSFODNN7EXAMPLE"}"#,
            r#"apikey=pk_test_abcdef1234567890"#,
        ];

        for body in bodies {
            assert!(scanner.extract_api_key(body).is_some());
        }
    }

    #[test]
    fn test_has_deprecation_warning() {
        let scanner = create_test_scanner();
        let mut headers = std::collections::HashMap::new();

        assert!(scanner.has_deprecation_warning("This API is deprecated", &headers));
        assert!(scanner.has_deprecation_warning("Sunset: version will EOL", &headers));

        headers.insert("Deprecation".to_string(), "true".to_string());
        assert!(scanner.has_deprecation_warning("", &headers));
    }

    #[test]
    fn test_looks_like_admin_panel() {
        let scanner = create_test_scanner();

        assert!(scanner.looks_like_admin_panel("Welcome to admin panel"));
        assert!(scanner.looks_like_admin_panel("Dashboard - Users and Settings"));
        assert!(!scanner.looks_like_admin_panel("Regular user page"));
    }

    #[test]
    fn test_is_api_schema() {
        let scanner = create_test_scanner();

        assert!(scanner.is_api_schema(r#"{"swagger":"2.0","paths":{}}"#));
        assert!(scanner.is_api_schema(r#"{"openapi":"3.0.0","paths":{}}"#));
        assert!(!scanner.is_api_schema("Regular response"));
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.build_url("http://example.com", "/api"), "http://example.com/api");
        assert_eq!(scanner.build_url("http://example.com/", "/api"), "http://example.com/api");
        assert_eq!(scanner.build_url("http://example.com", "api"), "http://example.com/api");
    }

    #[test]
    fn test_extract_base_url() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.extract_base_url("https://api.example.com/v1/users"), "https://api.example.com");
        assert_eq!(scanner.extract_base_url("http://localhost:8080/api"), "http://localhost:8080");
    }
}
