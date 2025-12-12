// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Web Cache Deception Scanner
 * Detects Web Cache Deception vulnerabilities
 *
 * Web Cache Deception (WCD) exploits the discrepancy between how the web server
 * and CDN/cache interpret URLs. By appending static file extensions to dynamic
 * URLs, attackers can trick the CDN into caching sensitive content.
 *
 * Attack Example:
 * - Original URL: https://example.com/account/profile (dynamic, sensitive)
 * - WCD URL: https://example.com/account/profile.css
 * - If the web server ignores .css and returns profile data, but CDN caches it
 *   as static content, the attacker can access the cached sensitive data.
 *
 * Detects:
 * - Static file extension appending (/.css, /.js, /.png)
 * - Path confusion attacks
 * - Cache misinterpretation of dynamic content
 * - Sensitive data exposure via CDN caching
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct WebCacheDeceptionScanner {
    http_client: Arc<HttpClient>,
}

/// Response comparison result
struct ResponseComparison {
    is_similar: bool,
    similarity_score: f32,
    has_cache_headers: bool,
    cache_details: Vec<String>,
}

/// Cache header analysis result
struct CacheAnalysis {
    is_cacheable: bool,
    has_age_header: bool,
    has_cache_hit: bool,
    cache_control: Option<String>,
    cache_status: Vec<String>,
}

impl WebCacheDeceptionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for Web Cache Deception vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[WebCacheDeception] Scanning: {}", url);

        // First, check if the URL is a dynamic endpoint that might contain sensitive data
        tests_run += 1;
        let has_sensitive_content = match self.detect_sensitive_endpoint(url).await {
            Ok(is_sensitive) => is_sensitive,
            Err(_) => {
                info!("[WebCacheDeception] Could not fetch URL for analysis");
                return Ok((vulnerabilities, tests_run));
            }
        };

        if !has_sensitive_content {
            info!("[WebCacheDeception] No sensitive content detected, skipping WCD tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[WebCacheDeception] Sensitive endpoint detected, testing for cache deception");

        // Get the original response for comparison
        let original_response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Failed to fetch original URL: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Test various static file extensions
        let extensions = vec![
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".json", ".xml", ".txt",
        ];

        for extension in extensions {
            tests_run += 1;

            let test_url = format!("{}{}", url, extension);
            debug!("[WebCacheDeception] Testing URL: {}", test_url);

            match self.http_client.get(&test_url).await {
                Ok(test_response) => {
                    // Compare responses
                    let comparison = self.compare_responses(
                        &original_response.body,
                        &test_response.body,
                        &test_response.headers,
                    );

                    if comparison.is_similar && comparison.has_cache_headers {
                        info!(
                            "[WebCacheDeception] Vulnerability found with extension: {}",
                            extension
                        );

                        let vuln = self.create_vulnerability(
                            url,
                            &test_url,
                            extension,
                            comparison.similarity_score,
                            &comparison.cache_details,
                        );

                        vulnerabilities.push(vuln);

                        // Found a vulnerability, test a few more extensions but don't test all
                        if vulnerabilities.len() >= 3 {
                            info!("[WebCacheDeception] Found multiple WCD vectors, stopping scan");
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", test_url, e);
                }
            }
        }

        // Test path-based WCD attacks (e.g., /profile/../../static/file.css)
        if vulnerabilities.is_empty() {
            let (path_vulns, path_tests) = self.test_path_confusion(url, &original_response.body).await?;
            vulnerabilities.extend(path_vulns);
            tests_run += path_tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if endpoint contains sensitive/dynamic content
    async fn detect_sensitive_endpoint(&self, url: &str) -> anyhow::Result<bool> {
        let response = self.http_client.get(url).await?;
        let body_lower = response.body.to_lowercase();
        let url_lower = url.to_lowercase();

        // Check URL path for sensitive endpoints
        let sensitive_paths = vec![
            "/account", "/profile", "/user", "/settings", "/admin", "/dashboard",
            "/api/user", "/api/account", "/my", "/me", "/private", "/secure",
        ];

        for path in sensitive_paths {
            if url_lower.contains(path) {
                return Ok(true);
            }
        }

        // Check for session/authentication indicators
        if let Some(cookie) = response.header("set-cookie") {
            let cookie_lower = cookie.to_lowercase();
            if cookie_lower.contains("session")
                || cookie_lower.contains("auth")
                || cookie_lower.contains("token")
            {
                return Ok(true);
            }
        }

        // Check for user-specific content in response
        let user_indicators = vec![
            "logged in",
            "welcome back",
            "my account",
            "my profile",
            "user dashboard",
            "account settings",
            "personal information",
        ];

        for indicator in user_indicators {
            if body_lower.contains(indicator) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Compare original and test responses
    fn compare_responses(
        &self,
        original_body: &str,
        test_body: &str,
        test_headers: &HashMap<String, String>,
    ) -> ResponseComparison {
        // Calculate similarity score
        let similarity = self.calculate_similarity(original_body, test_body);

        // Analyze cache headers
        let cache_analysis = self.analyze_cache_headers(test_headers);

        ResponseComparison {
            is_similar: similarity > 0.8, // 80% similarity threshold
            similarity_score: similarity,
            has_cache_headers: cache_analysis.is_cacheable
                || cache_analysis.has_cache_hit
                || cache_analysis.has_age_header,
            cache_details: cache_analysis.cache_status,
        }
    }

    /// Calculate text similarity using simple character-based comparison
    fn calculate_similarity(&self, text1: &str, text2: &str) -> f32 {
        if text1.is_empty() || text2.is_empty() {
            return 0.0;
        }

        // Use length-based similarity for efficiency
        let len1 = text1.len() as f32;
        let len2 = text2.len() as f32;

        // If lengths are very different, not similar
        let length_ratio = len1.min(len2) / len1.max(len2);
        if length_ratio < 0.7 {
            return 0.0;
        }

        // Check content similarity by comparing substrings
        // For efficiency, compare first 1000 chars and last 500 chars
        let sample_size = 1000.min(text1.len()).min(text2.len());
        let start_match = if sample_size > 0 {
            &text1[..sample_size] == &text2[..sample_size]
        } else {
            false
        };

        let end_sample = 500.min(text1.len()).min(text2.len());
        let end_match = if end_sample > 0 {
            &text1[text1.len() - end_sample..] == &text2[text2.len() - end_sample..]
        } else {
            false
        };

        // Calculate score
        let mut score = length_ratio * 0.4;
        if start_match {
            score += 0.4;
        }
        if end_match {
            score += 0.2;
        }

        score
    }

    /// Analyze cache-related headers
    fn analyze_cache_headers(&self, headers: &HashMap<String, String>) -> CacheAnalysis {
        let mut analysis = CacheAnalysis {
            is_cacheable: false,
            has_age_header: false,
            has_cache_hit: false,
            cache_control: None,
            cache_status: Vec::new(),
        };

        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            match key_lower.as_str() {
                "cache-control" => {
                    analysis.cache_control = Some(value.clone());
                    // Check if content is cacheable (not private or no-store)
                    if !value_lower.contains("private")
                        && !value_lower.contains("no-store")
                        && !value_lower.contains("no-cache")
                    {
                        if value_lower.contains("public") || value_lower.contains("max-age") {
                            analysis.is_cacheable = true;
                            analysis.cache_status.push(format!("Cache-Control: {}", value));
                        }
                    }
                }
                "age" => {
                    analysis.has_age_header = true;
                    analysis.cache_status.push(format!("Age: {}", value));
                }
                "x-cache" => {
                    if value_lower.contains("hit") {
                        analysis.has_cache_hit = true;
                        analysis.cache_status.push(format!("X-Cache: {}", value));
                    }
                }
                "x-cache-status" => {
                    if value_lower.contains("hit") {
                        analysis.has_cache_hit = true;
                        analysis.cache_status.push(format!("X-Cache-Status: {}", value));
                    }
                }
                "cf-cache-status" => {
                    // Cloudflare cache status
                    if value_lower == "hit" || value_lower == "expired" {
                        analysis.has_cache_hit = true;
                        analysis.cache_status.push(format!("CF-Cache-Status: {}", value));
                    }
                }
                _ => {
                    // Check for other cache-related headers
                    if key_lower.contains("cache") {
                        analysis.cache_status.push(format!("{}: {}", key, value));
                    }
                }
            }
        }

        analysis
    }

    /// Test path confusion attacks
    async fn test_path_confusion(
        &self,
        url: &str,
        original_body: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("[WebCacheDeception] Testing path confusion attacks");

        // Parse URL to get path
        let parsed_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let base_path = parsed_url.path();

        // Test path confusion patterns
        let confusion_patterns = vec![
            format!("{}/../static/file.css", base_path),
            format!("{}/;/static.js", base_path),
            format!("{}%2f..%2fstatic.png", base_path),
        ];

        for pattern in confusion_patterns {
            let test_url = format!(
                "{}://{}{}",
                parsed_url.scheme(),
                parsed_url.host_str().unwrap_or(""),
                pattern
            );

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let similarity = self.calculate_similarity(original_body, &response.body);

                    if similarity > 0.8 {
                        let cache_analysis = self.analyze_cache_headers(&response.headers);

                        if cache_analysis.is_cacheable || cache_analysis.has_cache_hit {
                            info!("[WebCacheDeception] Path confusion vulnerability found");

                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                &test_url,
                                "path-confusion",
                                similarity,
                                &cache_analysis.cache_status,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Path confusion test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        original_url: &str,
        test_url: &str,
        attack_vector: &str,
        similarity: f32,
        cache_details: &[String],
    ) -> Vulnerability {
        let cache_evidence = if cache_details.is_empty() {
            "Cache headers detected".to_string()
        } else {
            cache_details.join(", ")
        };

        Vulnerability {
            id: format!("wcd_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "Web Cache Deception".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Caching".to_string(),
            url: original_url.to_string(),
            parameter: None,
            payload: test_url.to_string(),
            description: format!(
                "Web Cache Deception vulnerability detected. The endpoint serves the same sensitive \
                content when accessed with static file extension '{}', allowing attackers to cache \
                private data on public CDN/cache servers. Response similarity: {:.1}%.",
                attack_vector,
                similarity * 100.0
            ),
            evidence: Some(format!(
                "Attack URL: {}\nCache indicators: {}\nSimilarity score: {:.2}",
                test_url, cache_evidence, similarity
            )),
            cwe: "CWE-524".to_string(), // Information Exposure Through Caching
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "1. Implement strict URL validation - reject requests with unexpected file extensions\n\
                         2. Configure cache to NOT cache URLs with extensions on dynamic endpoints\n\
                         3. Set Cache-Control: private, no-store for all sensitive/dynamic content\n\
                         4. Use Vary header appropriately to include authentication in cache key\n\
                         5. Implement path normalization before routing\n\
                         6. Configure CDN/cache rules to exclude dynamic paths from caching\n\
                         7. Add security headers: X-Content-Type-Options: nosniff\n\
                         8. Regularly audit cache behavior for sensitive endpoints\n\
                         9. Consider using different domains for static vs dynamic content\n\
                         10. Implement request validation middleware to block suspicious patterns".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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

    fn create_test_scanner() -> WebCacheDeceptionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        WebCacheDeceptionScanner::new(http_client)
    }

    #[test]
    fn test_calculate_similarity() {
        let scanner = create_test_scanner();

        // Identical strings
        let similarity1 = scanner.calculate_similarity("test content", "test content");
        assert!(similarity1 > 0.9);

        // Completely different strings
        let similarity2 = scanner.calculate_similarity("test", "xyz");
        assert!(similarity2 < 0.5);

        // Empty strings
        let similarity3 = scanner.calculate_similarity("", "test");
        assert_eq!(similarity3, 0.0);
    }

    #[test]
    fn test_analyze_cache_headers() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "Cache-Control".to_string(),
            "public, max-age=3600".to_string(),
        );
        headers.insert("Age".to_string(), "120".to_string());
        headers.insert("X-Cache".to_string(), "HIT".to_string());

        let analysis = scanner.analyze_cache_headers(&headers);

        assert!(analysis.is_cacheable);
        assert!(analysis.has_age_header);
        assert!(analysis.has_cache_hit);
        assert!(!analysis.cache_status.is_empty());
    }

    #[test]
    fn test_analyze_private_cache() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert(
            "Cache-Control".to_string(),
            "private, no-store".to_string(),
        );

        let analysis = scanner.analyze_cache_headers(&headers);

        assert!(!analysis.is_cacheable);
    }

    #[test]
    fn test_cloudflare_cache_headers() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("CF-Cache-Status".to_string(), "HIT".to_string());

        let analysis = scanner.analyze_cache_headers(&headers);

        assert!(analysis.has_cache_hit);
    }
}
