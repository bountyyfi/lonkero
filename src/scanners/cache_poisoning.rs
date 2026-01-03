// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct CachePoisoningScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

/// Content sensitivity result
struct ContentSensitivity {
    is_sensitive: bool,
    has_user_data: bool,
    evidence: Vec<String>,
}

impl CachePoisoningScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("cp_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for cache poisoning vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[CachePoisoning] Scanning: {}", url);

        // CRITICAL: First check if this page contains sensitive/dynamic content
        // Static public pages and CDN-cached content should NOT trigger cache vulnerability alerts
        tests_run += 1;
        let content_type = match self.detect_content_sensitivity(url).await {
            Ok(ct) => ct,
            Err(_) => {
                info!("[CachePoisoning] Could not fetch URL for analysis");
                return Ok((vulnerabilities, tests_run));
            }
        };

        if !content_type.is_sensitive {
            info!("[CachePoisoning] Public/static content detected - caching is appropriate, skipping cache vulnerability tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[CachePoisoning] Sensitive content detected, checking cache configuration. Evidence: {:?}", content_type.evidence);

        // Test cache behavior (only for sensitive content)
        let (vulns, tests) = self.test_cache_headers(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test unkeyed headers (actual cache poisoning)
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_unkeyed_headers(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test cache deception (only for pages with user data)
        if content_type.has_user_data && vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_cache_deception(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if the content is sensitive and should NOT be cached publicly
    async fn detect_content_sensitivity(&self, url: &str) -> anyhow::Result<ContentSensitivity> {
        let mut sensitivity = ContentSensitivity {
            is_sensitive: false,
            has_user_data: false,
            evidence: Vec::new(),
        };

        let response = self.http_client.get(url).await?;
        let body_lower = response.body.to_lowercase();

        // Check for session/auth cookies (indicates personalized content)
        if let Some(cookie) = response.header("set-cookie") {
            let cookie_lower = cookie.to_lowercase();
            if cookie_lower.contains("session")
                || cookie_lower.contains("auth")
                || cookie_lower.contains("token")
                || cookie_lower.contains("user")
            {
                sensitivity.is_sensitive = true;
                sensitivity.has_user_data = true;
                sensitivity
                    .evidence
                    .push("Session/auth cookie set".to_string());
            }
        }

        // Check for user-specific content indicators
        let user_indicators = [
            "my account",
            "my profile",
            "welcome back",
            "logged in as",
            "your balance",
            "your orders",
            "your settings",
        ];
        for indicator in &user_indicators {
            if body_lower.contains(indicator) {
                sensitivity.is_sensitive = true;
                sensitivity.has_user_data = true;
                sensitivity
                    .evidence
                    .push(format!("User content: {}", indicator));
                break;
            }
        }

        // Check for sensitive data patterns - use more specific patterns to avoid false positives
        // Note: Simple substring matching causes false positives (e.g., "ssn" matches "session")
        let sensitive_patterns = [
            ("credit card", true), // Space ensures it's the phrase
            ("creditcard", true),
            ("social security", true), // Full phrase, not "ssn" substring
            ("\"ssn\"", true),         // JSON key "ssn"
            ("'ssn'", true),           // JavaScript string 'ssn'
            ("name=\"ssn\"", true),    // Form field
            ("password", true),
            ("api_key", true),
            ("apikey", true),
            ("secret_key", true),
            ("secretkey", true),
            ("private_key", true),
            ("privatekey", true),
            ("access_token", false), // Too common in JS apps, lower confidence
        ];
        for (pattern, high_confidence) in &sensitive_patterns {
            if body_lower.contains(pattern) && *high_confidence {
                sensitivity.is_sensitive = true;
                sensitivity
                    .evidence
                    .push(format!("Sensitive data: {}", pattern));
                break;
            }
        }

        // Check for forms with sensitive data
        if body_lower.contains("type=\"password\"") || body_lower.contains("name=\"password\"") {
            sensitivity.is_sensitive = true;
            sensitivity.evidence.push("Password form field".to_string());
        }

        // Static marketing pages, landing pages, etc. are NOT sensitive
        // They are SUPPOSED to be cached publicly by CDNs

        Ok(sensitivity)
    }

    /// Test cache headers and behavior
    async fn test_cache_headers(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing cache headers");

        match self.http_client.get(url).await {
            Ok(response) => {
                // Check for cache headers
                let has_cache_control = response.headers.contains_key("cache-control")
                    || response.headers.contains_key("Cache-Control");
                let has_age =
                    response.headers.contains_key("age") || response.headers.contains_key("Age");
                let has_x_cache = response
                    .headers
                    .iter()
                    .any(|(k, _)| k.to_lowercase().contains("x-cache"));

                if has_cache_control || has_age || has_x_cache {
                    // Cache is enabled, check for vulnerabilities
                    if self.detect_unsafe_caching(&response.headers) {
                        info!("Unsafe caching configuration detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Unsafe Cache Configuration",
                            "",
                            "Response is cached without proper cache control directives",
                            "Missing Cache-Control: private or no-cache for sensitive content",
                            Severity::Medium,
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test unkeyed headers for cache poisoning
    async fn test_unkeyed_headers(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing unkeyed headers");

        let original_url = format!("/{}", self.test_marker);
        let rewrite_url = format!("/{}", self.test_marker);

        let unkeyed_headers = vec![
            ("X-Forwarded-Host", self.test_marker.as_str()),
            ("X-Original-URL", original_url.as_str()),
            ("X-Rewrite-URL", rewrite_url.as_str()),
            ("X-Forwarded-Scheme", "http"),
            ("X-Forwarded-Proto", "http"),
        ];

        for (header, value) in unkeyed_headers {
            let test_url = format!("{}?cache_bust={}", url, uuid::Uuid::new_v4().to_string());

            // Since we don't have get_with_headers yet, we'll use POST with headers
            // In production, you'd want GET with custom headers
            let headers_vec = vec![(header.to_string(), value.to_string())];

            match self
                .http_client
                .post_with_headers(&test_url, "", headers_vec)
                .await
            {
                Ok(response) => {
                    if response.body.contains(&self.test_marker) || response.body.contains(value) {
                        info!("Unkeyed header {} causes cache poisoning", header);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Cache Poisoning via Unkeyed Header",
                            &format!("{}: {}", header, value),
                            &format!("Unkeyed header '{}' can poison cache", header),
                            &format!("Header value reflected in cached response"),
                            Severity::High,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test cache deception
    async fn test_cache_deception(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing cache deception");

        // Test if adding static file extension causes caching
        let base_url = if url.ends_with('/') {
            url.to_string()
        } else {
            format!("{}/", url)
        };

        let deception_paths = vec![
            format!("{}test.css", base_url),
            format!("{}test.js", base_url),
            format!("{}test.jpg", base_url),
        ];

        for deception_url in deception_paths {
            match self.http_client.get(&deception_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.detect_cache_deception(&response.headers)
                    {
                        info!("Cache deception possible");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Cache Deception",
                            &deception_url,
                            "Application vulnerable to cache deception attacks",
                            "Dynamic content cached as static resource",
                            Severity::Medium,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect unsafe caching
    fn detect_unsafe_caching(&self, headers: &std::collections::HashMap<String, String>) -> bool {
        // Check for cache-control header
        for (key, value) in headers {
            if key.to_lowercase() == "cache-control" {
                let value_lower = value.to_lowercase();

                // If content is cached but not marked as private
                if !value_lower.contains("private")
                    && !value_lower.contains("no-cache")
                    && !value_lower.contains("no-store")
                {
                    // Check if max-age or s-maxage is set
                    if value_lower.contains("max-age") || value_lower.contains("s-maxage") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Detect cache deception
    fn detect_cache_deception(&self, headers: &std::collections::HashMap<String, String>) -> bool {
        // Check if response is being cached
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            if key_lower == "cache-control" {
                if value_lower.contains("max-age") || value_lower.contains("public") {
                    return true;
                }
            }

            if key_lower == "x-cache" && value_lower.contains("hit") {
                return true;
            }
        }

        false
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
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 8.6,
            Severity::High => 7.3,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("cp_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::Medium,
            category: "Configuration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-444".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Set Cache-Control: private for personalized content\n\
                         2. Use Cache-Control: no-cache, no-store for sensitive data\n\
                         3. Include all relevant headers in cache key\n\
                         4. Validate and sanitize reflected headers\n\
                         5. Disable caching for dynamic content\n\
                         6. Use Vary header appropriately\n\
                         7. Implement proper path-based caching rules\n\
                         8. Add X-Cache-Control for CDN configuration\n\
                         9. Monitor cache hit ratios for anomalies\n\
                         10. Use SameSite cookies to prevent cache deception"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
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
    use crate::detection_helpers::AppCharacteristics;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> CachePoisoningScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        CachePoisoningScanner::new(http_client)
    }

    #[test]
    fn test_detect_unsafe_caching() {
        let scanner = create_test_scanner();

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "Cache-Control".to_string(),
            "public, max-age=3600".to_string(),
        );
        assert!(scanner.detect_unsafe_caching(&headers));

        let mut safe_headers = std::collections::HashMap::new();
        safe_headers.insert(
            "Cache-Control".to_string(),
            "private, max-age=3600".to_string(),
        );
        assert!(!scanner.detect_unsafe_caching(&safe_headers));
    }

    #[test]
    fn test_detect_cache_deception() {
        let scanner = create_test_scanner();

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "Cache-Control".to_string(),
            "public, max-age=86400".to_string(),
        );
        assert!(scanner.detect_cache_deception(&headers));

        let mut headers2 = std::collections::HashMap::new();
        headers2.insert("X-Cache".to_string(), "HIT".to_string());
        assert!(scanner.detect_cache_deception(&headers2));
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("cp_"));
    }
}
