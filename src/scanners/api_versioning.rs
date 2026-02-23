// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - API Versioning Attacks Scanner
 * Context-aware scanner for API versioning vulnerabilities
 *
 * Detects:
 * - Deprecated API versions still accessible
 * - Missing security controls in old versions
 * - Version downgrade attacks
 * - Version parameter pollution
 * - Undocumented/hidden API versions
 * - Security regressions between versions
 * - Version enumeration vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

/// Versioning scheme detected in the API
#[derive(Debug, Clone, PartialEq)]
pub enum VersioningScheme {
    /// Path-based: /api/v1/, /v1/
    PathBased,
    /// Header-based: X-API-Version, Accept header
    HeaderBased,
    /// Query-based: ?api_version=1, ?v=1
    QueryBased,
    /// Mixed scheme (multiple detected)
    Mixed,
    /// Unknown/not detected
    Unknown,
}

/// Version information extracted from API
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub scheme: VersioningScheme,
    pub is_deprecated: bool,
    pub has_security_headers: bool,
    pub has_rate_limiting: bool,
    pub requires_auth: bool,
    pub response_time_ms: u64,
}

/// Scanner for API versioning vulnerabilities
pub struct ApiVersioningScanner {
    http_client: Arc<HttpClient>,
}

impl ApiVersioningScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Run API versioning vulnerability scan
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting API versioning vulnerability scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Step 1: Detect if this is an API endpoint
        let baseline_response = self.http_client.get(url).await?;
        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        if !characteristics.is_api && !self.looks_like_api_url(url) {
            info!("[API-Version] Not an API endpoint - skipping versioning tests");
            return Ok((all_vulnerabilities, total_tests));
        }

        info!("[API-Version] API endpoint detected, starting versioning analysis");

        // Step 2: Detect current versioning scheme
        let (scheme, current_version) =
            self.detect_versioning_scheme(url, &baseline_response).await;
        info!(
            "[API-Version] Detected scheme: {:?}, current version: {:?}",
            scheme, current_version
        );

        // Step 3: Enumerate available versions
        let (vulns, tests) = self
            .enumerate_versions(url, &scheme, &current_version)
            .await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Step 4: Test deprecated versions
        let (vulns, tests) = self
            .test_deprecated_versions(url, &scheme, &current_version)
            .await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Step 5: Test version bypass techniques
        let (vulns, tests) = self.test_version_bypass(url, &scheme).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Step 6: Compare security between versions
        let (vulns, tests) = self
            .compare_version_security(url, &scheme, &current_version)
            .await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Step 7: Test header-based versioning
        let (vulns, tests) = self.test_header_versioning(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Step 8: Test query-based versioning
        let (vulns, tests) = self.test_query_versioning(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "API versioning scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Check if URL looks like an API endpoint
    fn looks_like_api_url(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        url_lower.contains("/api/")
            || url_lower.contains("/api.")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
            || url_lower.contains("/v3/")
            || url_lower.contains("/graphql")
            || url_lower.contains("/rest/")
            || url_lower.contains("api.")
            || url_lower.contains("/json")
            || url_lower.contains("api-version")
    }

    /// Detect the versioning scheme used by the API
    async fn detect_versioning_scheme(
        &self,
        url: &str,
        baseline: &crate::http_client::HttpResponse,
    ) -> (VersioningScheme, Option<String>) {
        let url_lower = url.to_lowercase();
        let mut detected_scheme = VersioningScheme::Unknown;
        let mut current_version = None;

        // Check for path-based versioning
        let path_version_patterns = [
            (r"/v(\d+)/", "v"),
            (r"/v(\d+\.\d+)/", "v"),
            (r"/v(\d+\.\d+\.\d+)/", "v"),
            (r"/api/v(\d+)/", "v"),
            (r"/api/v(\d+\.\d+)/", "v"),
            (r"/(\d{4}-\d{2}-\d{2})/", "date"),
        ];

        for (pattern, prefix) in &path_version_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(&url_lower) {
                    if let Some(version_match) = captures.get(1) {
                        let version = if *prefix == "v" {
                            format!("v{}", version_match.as_str())
                        } else {
                            version_match.as_str().to_string()
                        };
                        current_version = Some(version);
                        detected_scheme = VersioningScheme::PathBased;
                        break;
                    }
                }
            }
        }

        // Check for header-based versioning in response
        let version_headers = ["api-version", "x-api-version", "x-version", "version"];
        for header in &version_headers {
            if let Some(value) = baseline.headers.get(*header) {
                if detected_scheme == VersioningScheme::PathBased {
                    detected_scheme = VersioningScheme::Mixed;
                } else {
                    detected_scheme = VersioningScheme::HeaderBased;
                }
                if current_version.is_none() {
                    current_version = Some(value.clone());
                }
                break;
            }
        }

        // Check for query-based versioning
        // Removed bare "v=" which matches countless unrelated params (save=, dev=, etc.)
        if url.contains("api_version=") || url.contains("version=") || url.contains("api_v=") {
            if detected_scheme != VersioningScheme::Unknown {
                detected_scheme = VersioningScheme::Mixed;
            } else {
                detected_scheme = VersioningScheme::QueryBased;
            }

            if let Ok(parsed) = url::Url::parse(url) {
                for (key, value) in parsed.query_pairs() {
                    if key == "api_version" || key == "version" || key == "v" {
                        if current_version.is_none() {
                            current_version = Some(value.to_string());
                        }
                        break;
                    }
                }
            }
        }

        (detected_scheme, current_version)
    }

    /// Enumerate available API versions
    async fn enumerate_versions(
        &self,
        url: &str,
        scheme: &VersioningScheme,
        current_version: &Option<String>,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Enumerating API versions");

        let base_url = self.extract_base_url(url);
        let api_path = self.extract_api_path(url);

        // Version patterns to test
        let numeric_versions: Vec<String> = (0..20).map(|i| format!("v{}", i)).collect();
        let semantic_versions = vec![
            "v1.0.0", "v1.0.1", "v1.1.0", "v1.2.0", "v2.0.0", "v2.1.0", "v2.2.0", "v0.1.0",
            "v0.2.0", "v0.9.0",
        ];
        let special_versions = vec![
            "beta", "alpha", "dev", "staging", "preview", "v0", "v1-beta", "v2-beta", "v1-alpha",
            "latest", "stable", "next", "canary",
        ];
        let date_versions = vec![
            "2023-01-01",
            "2023-06-01",
            "2023-12-01",
            "2024-01-01",
            "2024-06-01",
            "2024-12-01",
            "2025-01-01",
        ];

        let mut discovered_versions: Vec<String> = Vec::new();

        // Test path-based versions
        if matches!(
            scheme,
            VersioningScheme::PathBased | VersioningScheme::Mixed | VersioningScheme::Unknown
        ) {
            let all_versions: Vec<&str> = numeric_versions
                .iter()
                .map(|s| s.as_str())
                .chain(semantic_versions.iter().copied())
                .chain(special_versions.iter().copied())
                .chain(date_versions.iter().copied())
                .collect();

            for version in all_versions {
                let test_url = format!("{}/api/{}{}", base_url, version, api_path);
                tests_run += 1;

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if self.is_valid_api_response(&response) {
                            // Skip if it's the current version
                            if let Some(current) = current_version {
                                if version.contains(current) || current.contains(version) {
                                    continue;
                                }
                            }

                            discovered_versions.push(version.to_string());
                            info!(
                                "[API-Version] Discovered version: {} at {}",
                                version, test_url
                            );
                        }
                    }
                    Err(e) => {
                        debug!("Version enumeration request failed: {}", e);
                    }
                }

                // Add small delay to be polite
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // Early exit if we found many versions
                if discovered_versions.len() >= 5 {
                    break;
                }
            }
        }

        // Report undocumented versions
        if !discovered_versions.is_empty() {
            let hidden_versions: Vec<&String> = discovered_versions
                .iter()
                .filter(|v| {
                    special_versions.contains(&v.as_str())
                        || v.contains("beta")
                        || v.contains("alpha")
                        || v.contains("dev")
                })
                .collect();

            if !hidden_versions.is_empty() {
                vulnerabilities.push(
                    self.create_vulnerability(
                        url,
                        "Hidden/Development API Versions Exposed",
                        &hidden_versions
                            .iter()
                            .map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        &format!(
                            "Development or hidden API versions are publicly accessible: {}. \
                        These versions may contain debugging features, reduced security controls, \
                        or unfinished functionality that could be exploited.",
                            hidden_versions
                                .iter()
                                .map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        &format!(
                            "Discovered {} hidden/development API versions",
                            hidden_versions.len()
                        ),
                        Severity::Medium,
                        Confidence::High,
                        "CWE-693",
                        5.5,
                    ),
                );
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test deprecated API versions
    async fn test_deprecated_versions(
        &self,
        url: &str,
        scheme: &VersioningScheme,
        current_version: &Option<String>,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing deprecated API versions");

        let base_url = self.extract_base_url(url);
        let api_path = self.extract_api_path(url);

        // Determine old versions to test based on current version
        let old_versions = if let Some(current) = current_version {
            self.get_older_versions(current)
        } else {
            vec!["v0".to_string(), "v1".to_string()]
        };

        for old_version in &old_versions {
            let old_url = format!("{}/api/{}{}", base_url, old_version, api_path);
            tests_run += 1;

            match self.http_client.get(&old_url).await {
                Ok(response) => {
                    if self.is_valid_api_response(&response) {
                        // Check for deprecation warnings
                        let has_deprecation = self.has_deprecation_warning(&response);

                        if !has_deprecation {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Deprecated API Version Without Warning",
                                old_version,
                                &format!(
                                    "Old API version '{}' is accessible without deprecation warnings. \
                                    Deprecated versions may lack security patches, have known vulnerabilities, \
                                    or missing security controls that were added in newer versions.",
                                    old_version
                                ),
                                &format!(
                                    "Deprecated version {} accessible at {}. No Deprecation or Sunset headers found.",
                                    old_version, old_url
                                ),
                                Severity::Medium,
                                Confidence::High,
                                "CWE-693",
                                5.5,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Deprecated version test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test version bypass techniques
    async fn test_version_bypass(
        &self,
        url: &str,
        scheme: &VersioningScheme,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing version bypass techniques");

        let base_url = self.extract_base_url(url);

        // Version downgrade attacks
        let bypass_techniques = vec![
            // Path manipulation
            ("/api/v2/../v1/users", "Path traversal downgrade"),
            ("/api/v1;v=2/users", "Semicolon version injection"),
            ("/api/v1%00v2/users", "Null byte injection"),
            ("/api/V1/users", "Case manipulation"),
            ("/api/v01/users", "Leading zero bypass"),
            ("/api//v1/users", "Double slash bypass"),
            // Version confusion
            ("/api/v1.0/users", "Floating point version"),
            ("/api/v1.0.0/users", "Semantic version bypass"),
            ("/api/v-1/users", "Negative version"),
            ("/api/v999/users", "High version number"),
        ];

        for (bypass_path, technique) in &bypass_techniques {
            let test_url = format!("{}{}", base_url, bypass_path);
            tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.is_valid_api_response(&response) && response.status_code == 200 {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Version Bypass",
                            bypass_path,
                            &format!(
                                "API version validation can be bypassed using {}. \
                                This may allow access to unintended API versions or bypass \
                                version-specific security controls.",
                                technique
                            ),
                            &format!(
                                "Version bypass succeeded at {} using {}",
                                test_url, technique
                            ),
                            Severity::High,
                            Confidence::Medium,
                            "CWE-693",
                            7.0,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Version bypass test failed: {}", e);
                }
            }
        }

        // Test version parameter pollution
        let pollution_tests = vec![
            ("?v=1&v=2", "Parameter pollution"),
            (
                "?api_version=1&api_version=2",
                "Parameter pollution (api_version)",
            ),
            ("?v=1&api_version=2", "Mixed parameter pollution"),
            ("?v[]=1&v[]=2", "Array parameter pollution"),
        ];

        for (pollution_query, technique) in &pollution_tests {
            let test_url = format!(
                "{}{}",
                url.split('?').next().unwrap_or(url),
                pollution_query
            );
            tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.is_valid_api_response(&response) && response.status_code == 200 {
                        // Check if we got a different response than expected
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Version Parameter Pollution",
                            pollution_query,
                            &format!(
                                "API version parameter pollution detected using {}. \
                                The server may process version parameters inconsistently, \
                                potentially allowing version downgrade or confusion attacks.",
                                technique
                            ),
                            &format!("{} succeeded at {}", technique, test_url),
                            Severity::Medium,
                            Confidence::Medium,
                            "CWE-235",
                            5.5,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Version pollution test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Compare security between API versions
    async fn compare_version_security(
        &self,
        url: &str,
        scheme: &VersioningScheme,
        current_version: &Option<String>,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Comparing security between API versions");

        let base_url = self.extract_base_url(url);
        let api_path = self.extract_api_path(url);

        // Get current version security profile
        let current_security = self.get_version_security_profile(url).await?;
        tests_run += 1;

        // Get old versions to compare
        let old_versions = if let Some(current) = current_version {
            self.get_older_versions(current)
        } else {
            vec!["v1".to_string()]
        };

        for old_version in &old_versions {
            let old_url = format!("{}/api/{}{}", base_url, old_version, api_path);
            tests_run += 1;

            match self.get_version_security_profile(&old_url).await {
                Ok(old_security) => {
                    let mut regressions = Vec::new();

                    // Check for security regressions
                    if current_security.has_rate_limiting && !old_security.has_rate_limiting {
                        regressions.push("Rate limiting missing");
                    }
                    if current_security.requires_auth && !old_security.requires_auth {
                        regressions.push("Authentication not required");
                    }
                    if current_security.has_security_headers && !old_security.has_security_headers {
                        regressions.push("Security headers missing");
                    }

                    if !regressions.is_empty() {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "API Version Security Regression",
                            old_version,
                            &format!(
                                "Old API version '{}' has weaker security controls than the current version. \
                                Missing controls: {}. Attackers may target the older version to bypass \
                                security measures implemented in newer versions.",
                                old_version,
                                regressions.join(", ")
                            ),
                            &format!(
                                "Security regression in {}: {}",
                                old_version,
                                regressions.join("; ")
                            ),
                            Severity::High,
                            Confidence::High,
                            "CWE-693",
                            7.5,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Security profile comparison failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test header-based versioning
    async fn test_header_versioning(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing header-based API versioning");

        let version_headers = [
            (
                "X-API-Version",
                vec!["1", "0", "v1", "v0", "beta", "alpha", "dev"],
            ),
            ("Api-Version", vec!["1", "0", "v1", "v0", "beta"]),
            (
                "Accept",
                vec![
                    "application/vnd.api+json; version=1",
                    "application/vnd.api+json; version=0",
                    "application/vnd.api.v1+json",
                    "application/vnd.api.v0+json",
                ],
            ),
            ("X-Version", vec!["1", "0", "beta", "dev"]),
            ("Version", vec!["1", "0", "beta"]),
        ];

        // Get baseline response
        let baseline = self.http_client.get(url).await?;
        tests_run += 1;

        for (header_name, versions) in &version_headers {
            for version in versions {
                let headers = vec![(header_name.to_string(), version.to_string())];
                tests_run += 1;

                match self.http_client.get_with_headers(url, headers).await {
                    Ok(response) => {
                        // Check if header changed the response
                        if self.is_valid_api_response(&response)
                            && self.responses_differ(&baseline, &response)
                        {
                            // Check if we accessed a dev/beta version
                            if version.contains("beta")
                                || version.contains("alpha")
                                || version.contains("dev")
                                || *version == "0"
                            {
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Hidden API Version via Header",
                                    &format!("{}: {}", header_name, version),
                                    &format!(
                                        "Hidden/development API version accessible via {} header. \
                                        Version '{}' may have reduced security controls, debugging features, \
                                        or unfinished functionality.",
                                        header_name, version
                                    ),
                                    &format!(
                                        "Header-based version switch: {} = {} produced different response",
                                        header_name, version
                                    ),
                                    Severity::Medium,
                                    Confidence::High,
                                    "CWE-693",
                                    5.5,
                                ));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Header versioning test failed: {}", e);
                    }
                }
            }
        }

        // Test missing version header validation
        let invalid_headers = vec![
            ("X-API-Version", "invalid"),
            ("X-API-Version", "-1"),
            ("X-API-Version", "999"),
            ("X-API-Version", "../../../etc/passwd"),
            ("X-API-Version", "<script>alert(1)</script>"),
        ];

        for (header_name, value) in &invalid_headers {
            let headers = vec![(header_name.to_string(), value.to_string())];
            tests_run += 1;

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    // Check if invalid version was accepted
                    if response.status_code == 200 && self.is_valid_api_response(&response) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Missing API Version Validation",
                            &format!("{}: {}", header_name, value),
                            &format!(
                                "API accepts invalid version header value: '{}'. \
                                Missing validation of version parameters may lead to unexpected behavior \
                                or security bypasses.",
                                value
                            ),
                            &format!(
                                "Invalid version header accepted: {} = {}",
                                header_name, value
                            ),
                            Severity::Low,
                            Confidence::Medium,
                            "CWE-20",
                            3.7,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Invalid header test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test query-based versioning
    async fn test_query_versioning(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing query-based API versioning");

        let base_url = url.split('?').next().unwrap_or(url);

        let version_params = vec![
            (
                "api_version",
                vec!["1", "0", "v1", "v0", "beta", "alpha", "dev"],
            ),
            ("version", vec!["1", "0", "v1", "v0", "beta"]),
            ("v", vec!["1", "0", "beta", "dev"]),
            ("api-version", vec!["1", "0", "beta"]),
        ];

        // Get baseline response
        let baseline = self.http_client.get(base_url).await?;
        tests_run += 1;

        for (param_name, versions) in &version_params {
            for version in versions {
                let test_url = format!("{}?{}={}", base_url, param_name, version);
                tests_run += 1;

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if self.is_valid_api_response(&response)
                            && self.responses_differ(&baseline, &response)
                        {
                            // Check if we accessed a dev/beta version
                            if version.contains("beta")
                                || version.contains("alpha")
                                || version.contains("dev")
                                || *version == "0"
                            {
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Hidden API Version via Query Parameter",
                                    &format!("{}={}", param_name, version),
                                    &format!(
                                        "Hidden/development API version accessible via '{}' query parameter. \
                                        Version '{}' may have reduced security controls or debugging features.",
                                        param_name, version
                                    ),
                                    &format!(
                                        "Query-based version switch: {} = {} produced different response",
                                        param_name, version
                                    ),
                                    Severity::Medium,
                                    Confidence::High,
                                    "CWE-693",
                                    5.5,
                                ));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Query versioning test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Get security profile for a specific version
    async fn get_version_security_profile(&self, url: &str) -> anyhow::Result<VersionInfo> {
        let start = std::time::Instant::now();
        let response = self.http_client.get(url).await?;
        let duration = start.elapsed().as_millis() as u64;

        let has_security_headers = response.headers.contains_key("x-content-type-options")
            || response.headers.contains_key("x-frame-options")
            || response.headers.contains_key("strict-transport-security")
            || response.headers.contains_key("content-security-policy");

        let has_rate_limiting = response.headers.keys().any(|k| {
            let k_lower = k.to_lowercase();
            k_lower.contains("ratelimit")
                || k_lower.contains("rate-limit")
                || k_lower == "retry-after"
                || k_lower.contains("x-rate")
        }) || response.status_code == 429;

        let requires_auth = response.status_code == 401 || response.status_code == 403;

        let is_deprecated = self.has_deprecation_warning(&response);

        Ok(VersionInfo {
            version: "unknown".to_string(),
            scheme: VersioningScheme::Unknown,
            is_deprecated,
            has_security_headers,
            has_rate_limiting,
            requires_auth,
            response_time_ms: duration,
        })
    }

    /// Check if response indicates a valid API response
    fn is_valid_api_response(&self, response: &crate::http_client::HttpResponse) -> bool {
        // Check status code
        if response.status_code == 404 || response.status_code == 502 || response.status_code == 503
        {
            return false;
        }

        // Check content type
        if let Some(content_type) = response.headers.get("content-type") {
            let ct_lower = content_type.to_lowercase();
            if ct_lower.contains("application/json")
                || ct_lower.contains("application/xml")
                || ct_lower.contains("text/json")
            {
                return true;
            }
        }

        // Check if body looks like JSON
        let body_trimmed = response.body.trim();
        if (body_trimmed.starts_with('{') && body_trimmed.ends_with('}'))
            || (body_trimmed.starts_with('[') && body_trimmed.ends_with(']'))
        {
            return true;
        }

        // Check for common API error patterns
        let body_lower = response.body.to_lowercase();
        if body_lower.contains("\"error\"")
            || body_lower.contains("\"message\"")
            || body_lower.contains("\"status\"")
            || body_lower.contains("\"data\"")
        {
            return true;
        }

        false
    }

    /// Check if response has deprecation warning
    fn has_deprecation_warning(&self, response: &crate::http_client::HttpResponse) -> bool {
        // Check headers
        if response.headers.contains_key("deprecation")
            || response.headers.contains_key("sunset")
            || response
                .headers
                .get("warning")
                .map(|w| w.to_lowercase().contains("deprecated"))
                .unwrap_or(false)
        {
            return true;
        }

        // Check body
        let body_lower = response.body.to_lowercase();
        body_lower.contains("deprecated")
            || body_lower.contains("sunset")
            || body_lower.contains("end of life")
            || body_lower.contains("no longer supported")
    }

    /// Check if two responses differ significantly
    fn responses_differ(
        &self,
        baseline: &crate::http_client::HttpResponse,
        response: &crate::http_client::HttpResponse,
    ) -> bool {
        // Different status codes
        if baseline.status_code != response.status_code {
            return true;
        }

        // Significant body length difference
        let len_diff = (baseline.body.len() as i64 - response.body.len() as i64).abs();
        if len_diff > 100 {
            return true;
        }

        // Different content type
        let baseline_ct = baseline.headers.get("content-type");
        let response_ct = response.headers.get("content-type");
        if baseline_ct != response_ct {
            return true;
        }

        false
    }

    /// Get older versions based on current version
    fn get_older_versions(&self, current: &str) -> Vec<String> {
        let mut older_versions = Vec::new();

        // Extract version number
        let version_re = Regex::new(r"v?(\d+)").ok();
        if let Some(re) = version_re {
            if let Some(captures) = re.captures(current) {
                if let Some(version_num) = captures.get(1) {
                    if let Ok(num) = version_num.as_str().parse::<i32>() {
                        // Add all versions from 0 to current-1
                        for i in 0..num {
                            older_versions.push(format!("v{}", i));
                        }
                    }
                }
            }
        }

        // Add common old version patterns
        if !older_versions.contains(&"v0".to_string()) {
            older_versions.push("v0".to_string());
        }
        if !older_versions.contains(&"v1".to_string()) {
            older_versions.push("v1".to_string());
        }

        older_versions
    }

    /// Extract base URL from full URL
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                parsed.port().map(|p| format!(":{}", p)).unwrap_or_default()
            )
        } else {
            url.to_string()
        }
    }

    /// Extract API path (after version)
    fn extract_api_path(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path();

            // Remove version from path
            let version_patterns = [
                r"/api/v\d+/",
                r"/api/v\d+\.\d+/",
                r"/v\d+/",
                r"/v\d+\.\d+/",
                r"/\d{4}-\d{2}-\d{2}/",
            ];

            for pattern in &version_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(matched) = re.find(path) {
                        let after_version = &path[matched.end()..];
                        if !after_version.is_empty() {
                            return format!("/{}", after_version);
                        }
                    }
                }
            }

            // If path contains /api/, extract after it
            if let Some(pos) = path.find("/api/") {
                let after_api = &path[pos + 5..];
                // Skip version if present
                if let Ok(re) = Regex::new(r"^v\d+/") {
                    if let Some(matched) = re.find(after_api) {
                        return format!("/{}", &after_api[matched.end()..]);
                    }
                }
                return format!("/{}", after_api);
            }

            path.to_string()
        } else {
            "/users".to_string()
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
        confidence: Confidence,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("api_version_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
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
            "Hidden/Development API Versions Exposed" => {
                "1. Remove or restrict access to development/beta API versions in production\n\
                 2. Use environment-based configuration to disable test versions\n\
                 3. Implement proper access controls for internal API versions\n\
                 4. Document all supported API versions and their lifecycle\n\
                 5. Use API gateway rules to block access to hidden versions\n\
                 6. Implement IP allowlisting for development endpoints"
                    .to_string()
            }
            "Deprecated API Version Without Warning" => {
                "1. Implement Deprecation and Sunset headers for old API versions\n\
                 2. Return deprecation warnings in API responses (e.g., Warning header)\n\
                 3. Provide clear migration timelines and documentation\n\
                 4. Set a sunset date and disable old versions after that date\n\
                 5. Monitor usage of deprecated versions and notify consumers\n\
                 6. Consider returning 410 Gone for truly end-of-life versions"
                    .to_string()
            }
            "API Version Bypass" => {
                "1. Implement strict version validation at the API gateway level\n\
                 2. Normalize and validate all version-related path segments\n\
                 3. Reject requests with malformed version identifiers\n\
                 4. Use allowlist-based version matching instead of pattern matching\n\
                 5. Implement defense in depth with application-level validation\n\
                 6. Log and monitor version bypass attempts"
                    .to_string()
            }
            "API Version Parameter Pollution" => {
                "1. Implement strict parameter parsing that rejects duplicates\n\
                 2. Use consistent parameter handling across all layers\n\
                 3. Define and enforce parameter precedence rules\n\
                 4. Validate and sanitize all version parameters\n\
                 5. Use typed parameter binding instead of string parsing\n\
                 6. Test parameter handling with security tools"
                    .to_string()
            }
            "API Version Security Regression" => {
                "1. Apply all security controls consistently across API versions\n\
                 2. Backport critical security fixes to older supported versions\n\
                 3. Deprecate and sunset versions that cannot be secured\n\
                 4. Implement version-independent security policies at gateway\n\
                 5. Conduct security review when supporting multiple versions\n\
                 6. Document security differences between versions for consumers"
                    .to_string()
            }
            "Hidden API Version via Header" | "Hidden API Version via Query Parameter" => {
                "1. Restrict access to development/internal API versions\n\
                 2. Validate version headers/parameters against allowed values\n\
                 3. Use authentication for access to non-production versions\n\
                 4. Implement version allowlisting at the API gateway\n\
                 5. Log and alert on access attempts to hidden versions\n\
                 6. Remove support for undocumented version mechanisms"
                    .to_string()
            }
            "Missing API Version Validation" => {
                "1. Implement strict validation for all version parameters\n\
                 2. Reject invalid or malformed version values with clear errors\n\
                 3. Use type-safe version parsing with explicit validation\n\
                 4. Sanitize version inputs to prevent injection attacks\n\
                 5. Return 400 Bad Request for invalid version formats\n\
                 6. Document expected version format in API documentation"
                    .to_string()
            }
            _ => "1. Implement comprehensive API version management\n\
                 2. Use Deprecation and Sunset headers for version lifecycle\n\
                 3. Apply security controls consistently across versions\n\
                 4. Validate version parameters at API gateway level\n\
                 5. Monitor for version manipulation attempts\n\
                 6. Follow OWASP API Security guidelines"
                .to_string(),
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> ApiVersioningScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        ApiVersioningScanner::new(http_client)
    }

    #[test]
    fn test_looks_like_api_url() {
        let scanner = create_test_scanner();

        assert!(scanner.looks_like_api_url("https://example.com/api/users"));
        assert!(scanner.looks_like_api_url("https://example.com/v1/users"));
        assert!(scanner.looks_like_api_url("https://example.com/v2/products"));
        assert!(scanner.looks_like_api_url("https://api.example.com/users"));
        assert!(scanner.looks_like_api_url("https://example.com/graphql"));
        assert!(!scanner.looks_like_api_url("https://example.com/about"));
        assert!(!scanner.looks_like_api_url("https://example.com/contact"));
    }

    #[test]
    fn test_extract_base_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_base_url("https://api.example.com/v1/users"),
            "https://api.example.com"
        );
        assert_eq!(
            scanner.extract_base_url("http://localhost:8080/api/v2/products"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn test_extract_api_path() {
        let scanner = create_test_scanner();

        // Tests for path extraction
        let path1 = scanner.extract_api_path("https://example.com/api/v1/users/123");
        assert!(path1.contains("users") || path1.contains("123") || path1 == "/users/123");

        let path2 = scanner.extract_api_path("https://example.com/v2/products");
        assert!(path2.contains("products"));
    }

    #[test]
    fn test_get_older_versions() {
        let scanner = create_test_scanner();

        let older = scanner.get_older_versions("v3");
        assert!(older.contains(&"v0".to_string()));
        assert!(older.contains(&"v1".to_string()));
        assert!(older.contains(&"v2".to_string()));
        assert!(!older.contains(&"v3".to_string()));

        let older2 = scanner.get_older_versions("2");
        assert!(older2.contains(&"v0".to_string()));
        assert!(older2.contains(&"v1".to_string()));
    }

    #[test]
    fn test_responses_differ() {
        let scanner = create_test_scanner();

        let response1 = crate::http_client::HttpResponse {
            status_code: 200,
            body: "response body 1".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response2 = crate::http_client::HttpResponse {
            status_code: 200,
            body: "response body 1".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response3 = crate::http_client::HttpResponse {
            status_code: 401,
            body: "unauthorized".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.responses_differ(&response1, &response2));
        assert!(scanner.responses_differ(&response1, &response3));
    }

    #[test]
    fn test_is_valid_api_response() {
        let scanner = create_test_scanner();

        let json_response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"{"data": "test"}"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let array_response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"[{"id": 1}]"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let html_response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "<html><body>Hello</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let not_found = crate::http_client::HttpResponse {
            status_code: 404,
            body: "Not found".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.is_valid_api_response(&json_response));
        assert!(scanner.is_valid_api_response(&array_response));
        assert!(!scanner.is_valid_api_response(&html_response));
        assert!(!scanner.is_valid_api_response(&not_found));
    }

    #[test]
    fn test_has_deprecation_warning() {
        let scanner = create_test_scanner();

        let mut deprecated_headers = std::collections::HashMap::new();
        deprecated_headers.insert("deprecation".to_string(), "true".to_string());

        let deprecated_response = crate::http_client::HttpResponse {
            status_code: 200,
            body: "".to_string(),
            headers: deprecated_headers,
            duration_ms: 100,
        };

        let body_deprecated = crate::http_client::HttpResponse {
            status_code: 200,
            body: "This API version is deprecated".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let not_deprecated = crate::http_client::HttpResponse {
            status_code: 200,
            body: "Normal response".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.has_deprecation_warning(&deprecated_response));
        assert!(scanner.has_deprecation_warning(&body_deprecated));
        assert!(!scanner.has_deprecation_warning(&not_deprecated));
    }

    #[test]
    fn test_get_remediation() {
        let scanner = create_test_scanner();

        let remediation = scanner.get_remediation("API Version Bypass");
        assert!(remediation.contains("gateway"));
        assert!(remediation.contains("validation"));

        let remediation2 = scanner.get_remediation("Deprecated API Version Without Warning");
        assert!(remediation2.contains("Deprecation"));
        assert!(remediation2.contains("Sunset"));
    }

    #[test]
    fn test_versioning_scheme_detection_patterns() {
        // Test version pattern matching logic
        let path_patterns = vec![
            ("/api/v1/users", true, "v1"),
            ("/api/v2/products", true, "v2"),
            ("/v1/api/data", true, "v1"),
            ("/api/users", false, ""),
            ("/2024-01-01/resources", true, "2024-01-01"),
        ];

        for (path, should_match, expected_version) in path_patterns {
            let has_version =
                path.contains("/v") && regex::Regex::new(r"/v\d+").unwrap().is_match(path);

            if should_match && expected_version.starts_with('v') {
                assert!(has_version, "Expected version match for {}", path);
            }
        }
    }

    #[test]
    fn test_uuid_generation() {
        let id1 = uuid::Uuid::new_v4().to_string();
        let id2 = uuid::Uuid::new_v4().to_string();

        assert_ne!(id1, id2);
        assert!(id1.contains('-'));
        assert_eq!(id1.len(), 36); // UUID format: 8-4-4-4-12
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "https://example.com/api/v1/users",
            "API Version Bypass",
            "/api/v1/../v0/users",
            "Test description",
            "Test evidence",
            Severity::High,
            Confidence::High,
            "CWE-693",
            7.5,
        );

        assert_eq!(vuln.vuln_type, "API Version Bypass");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.confidence, Confidence::High);
        assert_eq!(vuln.cwe, "CWE-693");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.id.starts_with("api_version_"));
        assert!(vuln.verified);
        assert!(!vuln.false_positive);
    }
}
