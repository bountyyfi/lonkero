// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Web Cache Deception Scanner
 * Detects web cache deception vulnerabilities through path confusion attacks
 *
 * Detects:
 * - Path confusion with static extensions (.css, .js, .png, etc.)
 * - CDN/proxy cache exploitation (Cloudflare, Fastly, Varnish, Akamai)
 * - Sensitive data exposure via cached responses
 * - Path parameter injection attacks
 * - Cache key manipulation vulnerabilities
 *
 * References:
 * - https://portswigger.net/research/web-cache-deception
 * - CWE-525: Information Exposure Through Browser Caching
 * - CWE-524: Use of Cache Containing Sensitive Information
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Detected caching infrastructure type
#[derive(Debug, Clone, PartialEq)]
pub enum CacheInfrastructure {
    Cloudflare,
    Fastly,
    Varnish,
    Akamai,
    AmazonCloudFront,
    Azure,
    Nginx,
    Apache,
    Squid,
    Generic,
    None,
}

impl CacheInfrastructure {
    fn name(&self) -> &'static str {
        match self {
            CacheInfrastructure::Cloudflare => "Cloudflare",
            CacheInfrastructure::Fastly => "Fastly",
            CacheInfrastructure::Varnish => "Varnish",
            CacheInfrastructure::Akamai => "Akamai",
            CacheInfrastructure::AmazonCloudFront => "Amazon CloudFront",
            CacheInfrastructure::Azure => "Azure CDN",
            CacheInfrastructure::Nginx => "Nginx",
            CacheInfrastructure::Apache => "Apache",
            CacheInfrastructure::Squid => "Squid",
            CacheInfrastructure::Generic => "Generic Cache",
            CacheInfrastructure::None => "None",
        }
    }
}

/// Cache status from response headers
#[derive(Debug, Clone)]
pub struct CacheStatus {
    pub is_cached: bool,
    pub cache_hit: bool,
    pub infrastructure: CacheInfrastructure,
    pub max_age: Option<u64>,
    pub age: Option<u64>,
    pub cache_control: Option<String>,
    pub evidence: Vec<String>,
}

impl CacheStatus {
    fn empty() -> Self {
        Self {
            is_cached: false,
            cache_hit: false,
            infrastructure: CacheInfrastructure::None,
            max_age: None,
            age: None,
            cache_control: None,
            evidence: Vec::new(),
        }
    }
}

/// Sensitive data patterns detected in response
#[derive(Debug, Clone)]
struct SensitiveDataResult {
    has_sensitive_data: bool,
    has_user_data: bool,
    has_auth_tokens: bool,
    has_pii: bool,
    evidence: Vec<String>,
}

pub struct WebCacheDeceptionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl WebCacheDeceptionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("wcd_{}", generate_uuid());
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan for web cache deception vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License verification
        if !crate::license::verify_scan_authorized() {
            info!("[WebCacheDeception] License verification failed - skipping scan");
            return Ok((Vec::new(), 0));
        }

        // Feature availability check
        if !crate::license::is_feature_available("web_cache_deception") {
            info!("[WebCacheDeception] Feature not available in current license tier");
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[WebCacheDeception] Scanning: {}", url);

        // Step 1: Fetch initial response and detect characteristics
        tests_run += 1;
        let initial_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[WebCacheDeception] Could not fetch URL: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Step 2: Detect caching infrastructure
        tests_run += 1;
        let cache_status = self.detect_cache_infrastructure(&initial_response);

        if cache_status.infrastructure == CacheInfrastructure::None {
            info!("[WebCacheDeception] No caching infrastructure detected - skipping");
            return Ok((vulnerabilities, tests_run));
        }

        info!(
            "[WebCacheDeception] Detected cache infrastructure: {}",
            cache_status.infrastructure.name()
        );

        // Step 3: Detect application characteristics for context-aware testing
        let characteristics = AppCharacteristics::from_response(&initial_response, url);

        // Step 4: Check if the page contains sensitive content
        tests_run += 1;
        let sensitive_data = self.detect_sensitive_data(&initial_response);

        if !sensitive_data.has_sensitive_data && !sensitive_data.has_user_data {
            info!("[WebCacheDeception] No sensitive content detected - lower priority testing");
        }

        // Step 5: Test path confusion attacks with static extensions
        let (ext_vulns, ext_tests) = self
            .test_static_extension_confusion(url, &cache_status, &sensitive_data, config)
            .await?;
        vulnerabilities.extend(ext_vulns);
        tests_run += ext_tests;

        // Step 6: Test path parameter injection
        let (param_vulns, param_tests) = self
            .test_path_parameter_injection(url, &cache_status, &sensitive_data, config)
            .await?;
        vulnerabilities.extend(param_vulns);
        tests_run += param_tests;

        // Step 7: Test encoded path confusion
        let (enc_vulns, enc_tests) = self
            .test_encoded_path_confusion(url, &cache_status, &sensitive_data, config)
            .await?;
        vulnerabilities.extend(enc_vulns);
        tests_run += enc_tests;

        // Step 8: Test cache key normalization issues
        if characteristics.is_api || url.contains("/api/") {
            let (norm_vulns, norm_tests) = self
                .test_cache_key_normalization(url, &cache_status, config)
                .await?;
            vulnerabilities.extend(norm_vulns);
            tests_run += norm_tests;
        }

        // Step 9: Verify vulnerabilities with second request
        let verified_vulns = self.verify_vulnerabilities(vulnerabilities).await;

        info!(
            "[SUCCESS] [WebCacheDeception] Completed {} tests, found {} vulnerabilities",
            tests_run,
            verified_vulns.len()
        );

        Ok((verified_vulns, tests_run))
    }

    /// Scan with application characteristics context
    pub async fn scan_with_context(
        &self,
        url: &str,
        config: &ScanConfig,
        characteristics: &AppCharacteristics,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License verification
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        // Skip for static sites with no sensitive content
        if characteristics.is_static && !characteristics.has_authentication {
            info!("[WebCacheDeception] Static site without auth - skipping cache deception tests");
            return Ok((Vec::new(), 0));
        }

        // Run regular scan with context awareness
        self.scan(url, config).await
    }

    /// Detect caching infrastructure from response headers
    fn detect_cache_infrastructure(&self, response: &HttpResponse) -> CacheStatus {
        let mut status = CacheStatus::empty();

        // Check for CDN-specific headers

        // Cloudflare detection
        if let Some(cf_cache) = response.header("cf-cache-status") {
            status.infrastructure = CacheInfrastructure::Cloudflare;
            status.is_cached = true;
            status.cache_hit = cf_cache.to_lowercase().contains("hit");
            status.evidence.push(format!("CF-Cache-Status: {}", cf_cache));
        }

        if response.header("cf-ray").is_some() {
            status.infrastructure = CacheInfrastructure::Cloudflare;
            status.evidence.push("CF-Ray header present".to_string());
        }

        // Fastly detection
        if let Some(fastly_state) = response.header("x-served-by") {
            if fastly_state.to_lowercase().contains("cache-") {
                status.infrastructure = CacheInfrastructure::Fastly;
                status.is_cached = true;
                status.evidence.push(format!("X-Served-By: {}", fastly_state));
            }
        }

        if let Some(x_cache) = response.header("x-cache") {
            if x_cache.to_lowercase().contains("hit") {
                status.cache_hit = true;
                status.is_cached = true;
            }
            status.evidence.push(format!("X-Cache: {}", x_cache));

            // Detect Fastly from X-Cache pattern
            if x_cache.contains("cache-") {
                status.infrastructure = CacheInfrastructure::Fastly;
            }
        }

        // Varnish detection
        if let Some(via) = response.header("via") {
            if via.to_lowercase().contains("varnish") {
                status.infrastructure = CacheInfrastructure::Varnish;
                status.is_cached = true;
                status.evidence.push(format!("Via: {}", via));
            }
        }

        if let Some(x_varnish) = response.header("x-varnish") {
            status.infrastructure = CacheInfrastructure::Varnish;
            status.is_cached = true;
            status.evidence.push(format!("X-Varnish: {}", x_varnish));
        }

        // Akamai detection
        if let Some(akamai) = response.header("x-akamai-request-id") {
            status.infrastructure = CacheInfrastructure::Akamai;
            status.is_cached = true;
            status.evidence.push("X-Akamai-Request-ID present".to_string());
        }

        if let Some(x_cache) = response.header("x-cache-key") {
            status.evidence.push(format!("X-Cache-Key: {}", x_cache));
        }

        // Amazon CloudFront detection
        if let Some(amz_cf) = response.header("x-amz-cf-id") {
            status.infrastructure = CacheInfrastructure::AmazonCloudFront;
            status.is_cached = true;
            status.evidence.push("X-Amz-Cf-Id present".to_string());
        }

        if let Some(x_cache) = response.header("x-cache") {
            if x_cache.contains("CloudFront") {
                status.infrastructure = CacheInfrastructure::AmazonCloudFront;
            }
        }

        // Azure CDN detection
        if let Some(x_azure) = response.header("x-azure-ref") {
            status.infrastructure = CacheInfrastructure::Azure;
            status.is_cached = true;
            status.evidence.push("X-Azure-Ref present".to_string());
        }

        // Nginx detection
        if let Some(server) = response.header("server") {
            let server_lower = server.to_lowercase();
            if server_lower.contains("nginx") {
                if status.infrastructure == CacheInfrastructure::None {
                    status.infrastructure = CacheInfrastructure::Nginx;
                }
            } else if server_lower.contains("apache") {
                if status.infrastructure == CacheInfrastructure::None {
                    status.infrastructure = CacheInfrastructure::Apache;
                }
            } else if server_lower.contains("squid") {
                status.infrastructure = CacheInfrastructure::Squid;
                status.is_cached = true;
            }
        }

        // Parse Cache-Control header
        if let Some(cache_control) = response.header("cache-control") {
            status.cache_control = Some(cache_control.clone());
            let cc_lower = cache_control.to_lowercase();

            // Check for caching directives
            if cc_lower.contains("public") || cc_lower.contains("max-age") {
                status.is_cached = true;
            }

            // Extract max-age
            if let Some(pos) = cc_lower.find("max-age=") {
                let remainder = &cc_lower[pos + 8..];
                if let Some(end) = remainder.find(|c: char| !c.is_numeric()) {
                    if let Ok(age) = remainder[..end].parse() {
                        status.max_age = Some(age);
                    }
                } else if let Ok(age) = remainder.parse() {
                    status.max_age = Some(age);
                }
            }

            status.evidence.push(format!("Cache-Control: {}", cache_control));
        }

        // Parse Age header
        if let Some(age) = response.header("age") {
            if let Ok(age_val) = age.parse() {
                status.age = Some(age_val);
                status.is_cached = true;
                status.evidence.push(format!("Age: {}", age));
            }
        }

        // If we have Age header but no identified CDN, mark as generic cache
        if status.is_cached && status.infrastructure == CacheInfrastructure::None {
            status.infrastructure = CacheInfrastructure::Generic;
        }

        status
    }

    /// Detect sensitive data in response
    fn detect_sensitive_data(&self, response: &HttpResponse) -> SensitiveDataResult {
        let mut result = SensitiveDataResult {
            has_sensitive_data: false,
            has_user_data: false,
            has_auth_tokens: false,
            has_pii: false,
            evidence: Vec::new(),
        };

        let body_lower = response.body.to_lowercase();

        // Check for authentication/session indicators
        let auth_indicators = [
            ("session", "Session data"),
            ("sessionid", "Session ID"),
            ("jsessionid", "Java Session ID"),
            ("phpsessid", "PHP Session ID"),
            ("auth_token", "Authentication token"),
            ("access_token", "Access token"),
            ("bearer ", "Bearer token"),
            ("api_key", "API key"),
            ("apikey", "API key"),
        ];

        for (pattern, desc) in &auth_indicators {
            if body_lower.contains(pattern) {
                result.has_auth_tokens = true;
                result.has_sensitive_data = true;
                result.evidence.push(format!("{} detected", desc));
            }
        }

        // Check for user-specific content
        let user_indicators = [
            ("my account", "User account page"),
            ("my profile", "User profile"),
            ("welcome back", "Personalized greeting"),
            ("logged in as", "Login status"),
            ("your balance", "Financial data"),
            ("your orders", "Order history"),
            ("your settings", "User settings"),
            ("account settings", "Account configuration"),
            ("dashboard", "User dashboard"),
        ];

        for (pattern, desc) in &user_indicators {
            if body_lower.contains(pattern) {
                result.has_user_data = true;
                result.has_sensitive_data = true;
                result.evidence.push(format!("{} detected", desc));
                break;
            }
        }

        // Check for PII patterns
        let pii_patterns = [
            ("\"email\":", "Email field in JSON"),
            ("\"phone\":", "Phone field in JSON"),
            ("\"address\":", "Address field in JSON"),
            ("\"ssn\":", "SSN field in JSON"),
            ("social security", "Social Security reference"),
            ("credit card", "Credit card reference"),
            ("\"password\":", "Password field in JSON"),
            ("\"dob\":", "Date of birth field"),
            ("date_of_birth", "Date of birth"),
        ];

        for (pattern, desc) in &pii_patterns {
            if body_lower.contains(pattern) {
                result.has_pii = true;
                result.has_sensitive_data = true;
                result.evidence.push(format!("{} detected", desc));
            }
        }

        // Check cookies for session indicators
        if let Some(set_cookie) = response.header("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();
            if cookie_lower.contains("session")
                || cookie_lower.contains("auth")
                || cookie_lower.contains("token")
            {
                result.has_auth_tokens = true;
                result.has_sensitive_data = true;
                result.evidence.push("Session cookie in response".to_string());
            }
        }

        result
    }

    /// Test static file extension path confusion
    async fn test_static_extension_confusion(
        &self,
        url: &str,
        cache_status: &CacheStatus,
        sensitive_data: &SensitiveDataResult,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Static file extensions to test
        let static_extensions = vec![
            ".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
            ".eot", ".mp4", ".mp3", ".pdf", ".txt", ".xml",
        ];

        // Path confusion patterns
        let patterns = vec![
            // Direct extension append: /account/test.css
            |base: &str, ext: &str| format!("{}/test{}", base.trim_end_matches('/'), ext),
            // Extension only: /account/.css
            |base: &str, ext: &str| format!("{}/{}", base.trim_end_matches('/'), ext),
            // Non-existent file: /account/nonexistent.css
            |base: &str, ext: &str| format!("{}/nonexistent{}", base.trim_end_matches('/'), ext),
            // Random file: /account/[random].css
            |base: &str, ext: &str| {
                format!(
                    "{}/{}_cache{}",
                    base.trim_end_matches('/'),
                    generate_uuid(),
                    ext
                )
            },
        ];

        // Limit extensions based on scan intensity
        let test_extensions = if crate::license::is_feature_available("enterprise_cache_deception") {
            static_extensions
        } else {
            static_extensions[..6].to_vec() // First 6 most common
        };

        for ext in &test_extensions {
            for pattern_fn in &patterns {
                tests_run += 1;

                let deception_url = pattern_fn(url, ext);
                debug!("[WebCacheDeception] Testing: {}", deception_url);

                match self.http_client.get(&deception_url).await {
                    Ok(response) => {
                        // Check if response is cached
                        let deception_cache = self.detect_cache_infrastructure(&response);

                        // Check if response contains sensitive data similar to original
                        let deception_sensitive = self.detect_sensitive_data(&response);

                        // Vulnerability conditions:
                        // 1. Response returns 200 OK
                        // 2. Response is being cached (cache headers indicate caching)
                        // 3. Response contains sensitive data
                        if response.status_code == 200
                            && (deception_cache.is_cached || deception_cache.cache_hit)
                            && (deception_sensitive.has_sensitive_data
                                || deception_sensitive.has_user_data)
                        {
                            let severity = if deception_sensitive.has_pii
                                || deception_sensitive.has_auth_tokens
                            {
                                Severity::Critical
                            } else if deception_sensitive.has_user_data {
                                Severity::High
                            } else {
                                Severity::Medium
                            };

                            let cvss = match severity {
                                Severity::Critical => 8.6,
                                Severity::High => 7.5,
                                Severity::Medium => 6.5,
                                _ => 5.0,
                            };

                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Web Cache Deception - Static Extension",
                                &deception_url,
                                &format!(
                                    "Sensitive content cached when requesting path with static extension {}. \
                                    Attacker can trick authenticated user into visiting malicious URL, \
                                    causing their sensitive data to be cached and accessible.",
                                    ext
                                ),
                                &format!(
                                    "Cache Status: {} ({})\nSensitive Data: {:?}\nCache Evidence: {:?}",
                                    if deception_cache.cache_hit { "HIT" } else { "MISS" },
                                    deception_cache.infrastructure.name(),
                                    deception_sensitive.evidence,
                                    deception_cache.evidence
                                ),
                                severity,
                                cvss,
                                "CWE-525",
                            ));

                            // Found vulnerability, skip remaining patterns for this extension
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("[WebCacheDeception] Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test path parameter injection attacks
    async fn test_path_parameter_injection(
        &self,
        url: &str,
        cache_status: &CacheStatus,
        sensitive_data: &SensitiveDataResult,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Path parameter injection patterns (semicolon, encoded variants)
        let injection_patterns = vec![
            (";.css", "Semicolon injection"),
            (";.js", "Semicolon injection"),
            (";/test.css", "Semicolon path injection"),
            ("/.css", "Dot prefix injection"),
            ("/..;/cache.css", "Path traversal with semicolon"),
            ("/;test.css", "Semicolon parameter"),
            ("\\test.css", "Windows path separator"),
            ("/.../.css", "Triple dot injection"),
        ];

        let base_url = url.trim_end_matches('/');

        for (pattern, desc) in &injection_patterns {
            tests_run += 1;

            let deception_url = format!("{}{}", base_url, pattern);
            debug!("[WebCacheDeception] Testing path injection: {}", deception_url);

            match self.http_client.get(&deception_url).await {
                Ok(response) => {
                    let deception_cache = self.detect_cache_infrastructure(&response);
                    let deception_sensitive = self.detect_sensitive_data(&response);

                    if response.status_code == 200
                        && (deception_cache.is_cached || deception_cache.cache_hit)
                        && (deception_sensitive.has_sensitive_data
                            || deception_sensitive.has_user_data)
                    {
                        let is_critical = deception_sensitive.has_pii
                            || deception_sensitive.has_auth_tokens;
                        let severity = if is_critical {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("Web Cache Deception - {}", desc),
                            &deception_url,
                            &format!(
                                "Path parameter injection ({}) causes sensitive content to be cached. \
                                Server interprets path differently than cache, leading to cache deception.",
                                pattern
                            ),
                            &format!(
                                "Pattern: {}\nCache: {} ({})\nSensitive Data: {:?}",
                                pattern,
                                if deception_cache.cache_hit { "HIT" } else { "CACHED" },
                                deception_cache.infrastructure.name(),
                                deception_sensitive.evidence
                            ),
                            severity,
                            if is_critical { 8.6 } else { 7.5 },
                            "CWE-524",
                        ));
                    }
                }
                Err(e) => {
                    debug!("[WebCacheDeception] Path injection request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test encoded path confusion
    async fn test_encoded_path_confusion(
        &self,
        url: &str,
        cache_status: &CacheStatus,
        sensitive_data: &SensitiveDataResult,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // URL-encoded path confusion patterns
        let encoded_patterns = vec![
            ("%2F.css", "Encoded slash .css"),
            ("%2Ftest.css", "Encoded slash test.css"),
            ("%2F%2E%2E%2Fcache.css", "Double-encoded traversal"),
            ("%00.css", "Null byte injection"),
            ("%20.css", "Space injection"),
            (".%00.css", "Dot null injection"),
            ("%2e%2e%2f.css", "Encoded traversal"),
            ("%252F.css", "Double-encoded slash"),
            ("..%252f.css", "Mixed encoding traversal"),
        ];

        let base_url = url.trim_end_matches('/');

        for (pattern, desc) in &encoded_patterns {
            tests_run += 1;

            let deception_url = format!("{}{}", base_url, pattern);
            debug!("[WebCacheDeception] Testing encoded confusion: {}", deception_url);

            match self.http_client.get(&deception_url).await {
                Ok(response) => {
                    let deception_cache = self.detect_cache_infrastructure(&response);
                    let deception_sensitive = self.detect_sensitive_data(&response);

                    if response.status_code == 200
                        && (deception_cache.is_cached || deception_cache.cache_hit)
                        && (deception_sensitive.has_sensitive_data
                            || deception_sensitive.has_user_data)
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("Web Cache Deception - {}", desc),
                            &deception_url,
                            &format!(
                                "URL-encoded path confusion ({}) causes cache deception. \
                                Cache and origin server normalize paths differently.",
                                pattern
                            ),
                            &format!(
                                "Encoded Pattern: {}\nCache: {}\nSensitive Data: {:?}",
                                pattern,
                                deception_cache.infrastructure.name(),
                                deception_sensitive.evidence
                            ),
                            Severity::High,
                            7.5,
                            "CWE-524",
                        ));
                    }
                }
                Err(e) => {
                    debug!("[WebCacheDeception] Encoded confusion request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test cache key normalization issues
    async fn test_cache_key_normalization(
        &self,
        url: &str,
        cache_status: &CacheStatus,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test if cache key excludes query parameters that affect response
        let normalization_tests = vec![
            ("?_=.css", "Cache buster with extension"),
            ("?callback=test.js", "JSONP-style injection"),
            ("?format=.json", "Format parameter"),
            ("#.css", "Fragment identifier"),
            ("?.css", "Query with extension"),
        ];

        let base_url = url.trim_end_matches('/');

        for (suffix, desc) in &normalization_tests {
            tests_run += 1;

            let test_url = format!("{}{}", base_url, suffix);
            debug!("[WebCacheDeception] Testing normalization: {}", test_url);

            // Make first request
            let first_response = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Wait briefly and make second request
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            let second_response = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let first_cache = self.detect_cache_infrastructure(&first_response);
            let second_cache = self.detect_cache_infrastructure(&second_response);

            // Check if second request hit cache (indicating first was cached)
            if !first_cache.cache_hit && second_cache.cache_hit {
                let first_sensitive = self.detect_sensitive_data(&first_response);
                let second_sensitive = self.detect_sensitive_data(&second_response);

                if first_sensitive.has_sensitive_data || second_sensitive.has_sensitive_data {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        &format!("Cache Key Normalization - {}", desc),
                        &test_url,
                        &format!(
                            "Cache key normalization issue allows caching with modified URL ({}). \
                            Response containing sensitive data was cached.",
                            suffix
                        ),
                        &format!(
                            "First request: {} -> {}\nSecond request: {} -> HIT\nSensitive: {:?}",
                            suffix,
                            if first_cache.cache_hit { "HIT" } else { "MISS" },
                            suffix,
                            first_sensitive.evidence
                        ),
                        Severity::High,
                        7.0,
                        "CWE-524",
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Verify vulnerabilities with second request to confirm caching
    async fn verify_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
    ) -> Vec<Vulnerability> {
        let mut verified = Vec::new();

        for mut vuln in vulnerabilities {
            // Make a second request to verify the response is actually cached
            let deception_url = &vuln.payload;

            // Brief delay to allow caching
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            match self.http_client.get(deception_url).await {
                Ok(response) => {
                    let cache_status = self.detect_cache_infrastructure(&response);

                    // Verify it's a cache hit
                    if cache_status.cache_hit {
                        vuln.verified = true;
                        if let Some(ref mut evidence) = vuln.evidence {
                            *evidence = format!(
                                "{}\n\nVERIFIED: Second request returned cache HIT",
                                evidence
                            );
                        }
                        verified.push(vuln);
                    } else if cache_status.is_cached {
                        // Response is cached but not a hit - still a finding
                        vuln.confidence = Confidence::Medium;
                        verified.push(vuln);
                    } else {
                        // Not cached on second request - lower confidence
                        vuln.verified = false;
                        vuln.confidence = Confidence::Low;
                        if let Some(ref mut evidence) = vuln.evidence {
                            *evidence = format!(
                                "{}\n\nNOTE: Second request did not show cache hit - may be CDN-specific behavior",
                                evidence
                            );
                        }
                        verified.push(vuln);
                    }
                }
                Err(_) => {
                    // Keep vulnerability but mark as unverified
                    vuln.verified = false;
                    vuln.confidence = Confidence::Low;
                    verified.push(vuln);
                }
            }
        }

        verified
    }

    /// Create a vulnerability report
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cvss: f32,
        cwe: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("wcd_{}", generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cache Vulnerability".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss,
            verified: false, // Will be set during verification
            false_positive: false,
            remediation: WEB_CACHE_DECEPTION_REMEDIATION.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
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

/// Comprehensive remediation guidance
const WEB_CACHE_DECEPTION_REMEDIATION: &str = r#"IMMEDIATE ACTION REQUIRED - WEB CACHE DECEPTION VULNERABILITY

## Understanding the Vulnerability
Web cache deception occurs when an attacker can trick a cache into storing sensitive content that should never be cached. The attacker crafts a URL that:
1. Looks like a static resource to the cache (e.g., /account/settings/attacker.css)
2. But returns sensitive dynamic content from the origin server (e.g., /account/settings page data)

## Impact
- Sensitive user data (PII, session tokens) cached on shared CDN
- Attacker can access cached sensitive data of other users
- Session hijacking through cached authentication tokens
- Privacy violations and regulatory compliance issues (GDPR, CCPA)

## Remediation Steps

### 1. Cache Configuration - Strict Content-Type Matching
```nginx
# Nginx - Only cache actual static files
location ~* \.(css|js|png|jpg|gif|ico|svg|woff|woff2)$ {
    # Verify Content-Type matches expected static type
    add_header Cache-Control "public, max-age=31536000";
}

# Never cache HTML/JSON/dynamic content
location ~* \.(html|json|xml)$ {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
}
```

### 2. Cache Key Normalization
```
# CDN Configuration (Cloudflare, Fastly, Akamai)
- Include full path in cache key (including extensions)
- Normalize paths BEFORE caching decision
- Strip path parameters (;) before routing, not just caching
- Reject URLs with suspicious path patterns
```

### 3. Origin Server Path Validation
```python
# Django example
from django.http import HttpResponseBadRequest
import re

def validate_path(request):
    path = request.path

    # Block suspicious path patterns
    suspicious_patterns = [
        r'\.[a-z]+$',  # Path ending in extension for dynamic routes
        r';',           # Semicolon path parameters
        r'%2[fF]',      # Encoded slashes
        r'%00',         # Null bytes
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, path):
            return HttpResponseBadRequest("Invalid path")

    return None  # Path is valid
```

### 4. Response Headers for Dynamic Content
```javascript
// Express.js middleware
app.use((req, res, next) => {
    // For authenticated/dynamic routes
    if (req.isAuthenticated() || isDynamicRoute(req.path)) {
        res.set({
            'Cache-Control': 'private, no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Vary': 'Cookie, Authorization'
        });
    }
    next();
});
```

### 5. CDN-Specific Configurations

#### Cloudflare
```
Page Rules:
- Match: example.com/account/*
- Cache Level: Bypass

Cache Rules:
- When: URI Path starts with /api/ OR /account/ OR /dashboard/
- Then: Bypass cache
```

#### Fastly VCL
```vcl
sub vcl_recv {
    # Block path confusion attempts
    if (req.url ~ ".*\.[a-z]+$" && req.url ~ "/(account|api|user|dashboard)/") {
        error 400 "Bad Request";
    }

    # Never cache authenticated content
    if (req.http.Cookie ~ "session") {
        return(pass);
    }
}
```

#### Akamai
```
Property Manager:
- Match Path: /account/*, /api/*, /user/*
- Behavior: Bypass Caching

Advanced Metadata:
- Normalize URL before cache key generation
- Strip path parameters from URL
```

### 6. Security Testing
```bash
# Test for web cache deception
curl -v "https://target.com/account/test.css"
curl -v "https://target.com/account;.css"
curl -v "https://target.com/account%2F.css"

# Check if response contains sensitive data AND is cached
# Look for: X-Cache: HIT, CF-Cache-Status: HIT, Age: >0
```

### 7. Monitoring and Detection
```yaml
# SIEM Rule Example
rule:
  name: Web Cache Deception Attempt
  condition:
    - request.uri MATCHES ".*/(account|user|api|dashboard)/.*\.(css|js|png|jpg|gif)$"
    - response.status == 200
    - response.body CONTAINS ["session", "token", "email", "password"]
  action: alert
```

## Security Checklist
- [ ] CDN configured to verify Content-Type before caching
- [ ] Dynamic routes explicitly set Cache-Control: no-store
- [ ] Path normalization applied before cache key generation
- [ ] Semicolon and encoded paths blocked or normalized
- [ ] Vary header includes Cookie and Authorization
- [ ] Authenticated content never cached publicly
- [ ] Regular security testing for cache deception
- [ ] Monitoring for suspicious path patterns

## References
- PortSwigger Web Cache Deception: https://portswigger.net/research/web-cache-deception
- CWE-525: https://cwe.mitre.org/data/definitions/525.html
- CWE-524: https://cwe.mitre.org/data/definitions/524.html
- OWASP Cache Deception: https://owasp.org/www-community/attacks/Web_Cache_Deception
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_scanner() -> WebCacheDeceptionScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        WebCacheDeceptionScanner::new(http_client)
    }

    #[test]
    fn test_cloudflare_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("cf-cache-status".to_string(), "HIT".to_string());
        headers.insert("cf-ray".to_string(), "abc123".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::Cloudflare);
        assert!(status.cache_hit);
        assert!(status.is_cached);
    }

    #[test]
    fn test_fastly_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("x-served-by".to_string(), "cache-iad-1234".to_string());
        headers.insert("x-cache".to_string(), "HIT".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::Fastly);
        assert!(status.cache_hit);
    }

    #[test]
    fn test_varnish_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("via".to_string(), "1.1 varnish (Varnish/6.0)".to_string());
        headers.insert("x-varnish".to_string(), "123456".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::Varnish);
        assert!(status.is_cached);
    }

    #[test]
    fn test_akamai_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("x-akamai-request-id".to_string(), "abc123".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::Akamai);
        assert!(status.is_cached);
    }

    #[test]
    fn test_cloudfront_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("x-amz-cf-id".to_string(), "abc123".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::AmazonCloudFront);
        assert!(status.is_cached);
    }

    #[test]
    fn test_cache_control_parsing() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "cache-control".to_string(),
            "public, max-age=3600".to_string(),
        );
        headers.insert("age".to_string(), "120".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert!(status.is_cached);
        assert_eq!(status.max_age, Some(3600));
        assert_eq!(status.age, Some(120));
    }

    #[test]
    fn test_sensitive_data_detection() {
        let scanner = create_test_scanner();

        let response = HttpResponse {
            status_code: 200,
            body: r#"{"email":"user@example.com", "session":"abc123"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.detect_sensitive_data(&response);
        assert!(result.has_sensitive_data);
        assert!(result.has_pii); // email detected
        assert!(result.has_auth_tokens); // session detected
    }

    #[test]
    fn test_user_content_detection() {
        let scanner = create_test_scanner();

        let response = HttpResponse {
            status_code: 200,
            body: "Welcome back, John! View your account settings.".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.detect_sensitive_data(&response);
        assert!(result.has_user_data);
        assert!(result.has_sensitive_data);
    }

    #[test]
    fn test_session_cookie_detection() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "session_id=abc123; HttpOnly; Secure".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let result = scanner.detect_sensitive_data(&response);
        assert!(result.has_auth_tokens);
        assert!(result.has_sensitive_data);
    }

    #[test]
    fn test_no_cache_infrastructure() {
        let scanner = create_test_scanner();

        let headers = HashMap::new();

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let status = scanner.detect_cache_infrastructure(&response);
        assert_eq!(status.infrastructure, CacheInfrastructure::None);
        assert!(!status.is_cached);
    }

    #[test]
    fn test_unique_test_markers() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("wcd_"));
        assert!(scanner2.test_marker.starts_with("wcd_"));
    }

    #[test]
    fn test_generate_uuid() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();

        assert_ne!(uuid1, uuid2);
        assert_eq!(uuid1.len(), 32); // 8+4+4+4+12
    }
}
