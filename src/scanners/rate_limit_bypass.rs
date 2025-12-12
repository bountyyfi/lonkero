// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Rate Limiting Bypass Scanner
 * Detects rate limiting bypass vulnerabilities
 *
 * Tests:
 * - IP header spoofing (X-Forwarded-For, X-Real-IP, etc.)
 * - Case variation in paths (path normalization issues)
 * - Path manipulation (/../, //, trailing slashes)
 * - HTTP method changes (POST vs PUT vs GET)
 * - Parameter pollution
 * - URL encoding variations
 * - Null byte injection
 * - Origin header manipulation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct RateLimitBypassScanner {
    http_client: Arc<HttpClient>,
}

impl RateLimitBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan function
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Scanning: {}", url);

        // Step 1: Establish baseline - check if rate limiting exists
        info!("[RateLimitBypass] Establishing baseline to detect rate limiting");
        let (is_rate_limited, rate_limit_threshold, baseline_tests) =
            self.establish_baseline(url).await?;
        tests_run += baseline_tests;

        if !is_rate_limited {
            info!("[RateLimitBypass] No rate limiting detected - skipping bypass tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[RateLimitBypass] Rate limiting detected at ~{} requests, testing bypass techniques",
              rate_limit_threshold);

        // Step 2: Test IP header spoofing bypass
        let (vulns, tests) = self.test_ip_header_spoofing(url, rate_limit_threshold).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Step 3: Test case variation bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_case_variation(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Step 4: Test path manipulation bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_path_manipulation(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Step 5: Test HTTP method change bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_http_method_change(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Step 6: Test parameter pollution bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_parameter_pollution(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Step 7: Test URL encoding bypass
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_url_encoding(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Step 8: Test origin header manipulation
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_origin_manipulation(url, rate_limit_threshold).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Establish baseline by sending requests until rate limited
    async fn establish_baseline(&self, url: &str) -> Result<(bool, usize, usize)> {
        let max_requests = 50;
        let mut rate_limit_count = 0;
        let mut consecutive_429s = 0;

        for i in 0..max_requests {
            match self.http_client.get(url).await {
                Ok(response) => {
                    // Check for rate limit indicators
                    if response.status_code == 429 ||
                       response.status_code == 503 ||
                       response.body.to_lowercase().contains("rate limit") ||
                       response.body.to_lowercase().contains("too many requests") {
                        rate_limit_count = i;
                        consecutive_429s += 1;

                        // If we get 3 consecutive rate limit responses, confirm it's rate limited
                        if consecutive_429s >= 3 {
                            debug!("[RateLimitBypass] Rate limiting confirmed after {} requests", i);
                            return Ok((true, rate_limit_count, i + 1));
                        }
                    } else {
                        consecutive_429s = 0;
                    }
                }
                Err(_) => {
                    // Network errors don't count as rate limiting
                    continue;
                }
            }

            // Small delay to avoid overwhelming the server
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        Ok((false, 0, max_requests))
    }

    /// Test IP header spoofing bypass techniques
    async fn test_ip_header_spoofing(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing IP header spoofing bypass");

        // IP headers to test
        let ip_headers = vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
            ("CF-Connecting-IP", "1.2.3.4"),
            ("True-Client-IP", "1.2.3.4"),
            ("X-Forwarded", "127.0.0.1"),
            ("Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Host", "localhost"),
        ];

        for (header_name, header_value) in &ip_headers {
            // First, trigger rate limit
            for _ in 0..threshold + 5 {
                let _ = self.http_client.get(url).await;
                tests_run += 1;
            }

            // Now try to bypass with spoofed header
            let mut headers = HashMap::new();
            headers.insert(header_name.to_string(), header_value.to_string());

            let success_count = self.test_bypass_technique(url, Some(headers), None, 10).await?;
            tests_run += 10;

            // If we got more than 5 successful requests after being rate limited, it's a bypass
            if success_count > 5 {
                info!("[RateLimitBypass] IP header spoofing bypass found: {}", header_name);
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "IP Header Spoofing Bypass",
                    &format!("{}: {}", header_name, header_value),
                    &format!("Rate limiting can be bypassed by spoofing the {} header", header_name),
                    &format!("{}/10 requests succeeded after rate limit using {} header",
                            success_count, header_name),
                    Severity::High,
                    "CWE-841",
                ));
                break;
            }

            // Wait a bit before testing next header
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test case variation bypass
    async fn test_case_variation(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing case variation bypass");

        // Parse URL to extract path
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let path = parsed.path();

        // Skip if path is just "/"
        if path == "/" || path.is_empty() {
            return Ok((vulnerabilities, tests_run));
        }

        // Generate case variations
        let variations = vec![
            path.to_uppercase(),
            path.to_lowercase(),
            self.alternate_case(path),
        ];

        for variation in variations {
            // Skip if same as original
            if variation == path {
                continue;
            }

            let varied_url = url.replace(path, &variation);

            // Trigger rate limit on original
            for _ in 0..threshold + 5 {
                let _ = self.http_client.get(url).await;
                tests_run += 1;
            }

            // Try varied URL
            let success_count = self.test_bypass_technique(&varied_url, None, None, 10).await?;
            tests_run += 10;

            if success_count > 5 {
                info!("[RateLimitBypass] Case variation bypass found: {}", variation);
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Case Variation Bypass",
                    &variation,
                    "Rate limiting can be bypassed by changing the case of the URL path",
                    &format!("{}/10 requests succeeded using case variation: {}",
                            success_count, variation),
                    Severity::High,
                    "CWE-841",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test path manipulation bypass
    async fn test_path_manipulation(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing path manipulation bypass");

        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let path = parsed.path();

        // Path manipulation techniques
        let manipulations = vec![
            format!("{}/", path),                    // Trailing slash
            format!("{}.", path),                    // Trailing dot
            format!("{}/.", path),                   // Trailing slash-dot
            format!("{}//", path),                   // Double slash
            path.replace("/", "//"),                 // Double all slashes
            format!("{}/../{}", path, path.trim_start_matches('/')), // Path traversal
            format!("{}/./", path),                  // Current directory
            format!("{};", path),                    // Semicolon
            format!("{}%20", path),                  // Trailing space (encoded)
            format!("{}%00", path),                  // Null byte
        ];

        for manipulation in manipulations {
            let manipulated_url = url.replace(path, &manipulation);

            // Trigger rate limit
            for _ in 0..threshold + 5 {
                let _ = self.http_client.get(url).await;
                tests_run += 1;
            }

            // Try manipulated path
            let success_count = self.test_bypass_technique(&manipulated_url, None, None, 10).await?;
            tests_run += 10;

            if success_count > 5 {
                info!("[RateLimitBypass] Path manipulation bypass found: {}", manipulation);
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Path Manipulation Bypass",
                    &manipulation,
                    "Rate limiting can be bypassed by manipulating the URL path",
                    &format!("{}/10 requests succeeded using path manipulation: {}",
                            success_count, manipulation),
                    Severity::High,
                    "CWE-841",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test HTTP method change bypass
    async fn test_http_method_change(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing HTTP method change bypass");

        // Trigger rate limit with GET
        for _ in 0..threshold + 5 {
            let _ = self.http_client.get(url).await;
            tests_run += 1;
        }

        // Try POST method
        let mut post_success = 0;
        for _ in 0..10 {
            match self.http_client.post(url, "").await {
                Ok(response) => {
                    if response.status_code >= 200 && response.status_code < 300 {
                        post_success += 1;
                    }
                }
                Err(_) => {}
            }
            tests_run += 1;
        }

        if post_success > 5 {
            info!("[RateLimitBypass] HTTP method change bypass found: POST");
            vulnerabilities.push(self.create_vulnerability(
                url,
                "HTTP Method Change Bypass",
                "POST instead of GET",
                "Rate limiting can be bypassed by changing the HTTP method from GET to POST",
                &format!("{}/10 POST requests succeeded after GET rate limit", post_success),
                Severity::Medium,
                "CWE-841",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test parameter pollution bypass
    async fn test_parameter_pollution(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing parameter pollution bypass");

        // Only test if URL has query parameters
        if !url.contains('?') {
            return Ok((vulnerabilities, tests_run));
        }

        // Parse URL
        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Get first parameter
        let first_param = parsed.query_pairs().next();
        if first_param.is_none() {
            return Ok((vulnerabilities, tests_run));
        }

        let (param_name, param_value) = first_param.unwrap();

        // Create polluted URL (duplicate parameter)
        let polluted_url = format!("{}&{}={}", url, param_name, param_value);

        // Trigger rate limit
        for _ in 0..threshold + 5 {
            let _ = self.http_client.get(url).await;
            tests_run += 1;
        }

        // Try polluted URL
        let success_count = self.test_bypass_technique(&polluted_url, None, None, 10).await?;
        tests_run += 10;

        if success_count > 5 {
            info!("[RateLimitBypass] Parameter pollution bypass found");
            vulnerabilities.push(self.create_vulnerability(
                url,
                "Parameter Pollution Bypass",
                &polluted_url,
                "Rate limiting can be bypassed by duplicating query parameters",
                &format!("{}/10 requests succeeded using parameter pollution", success_count),
                Severity::Medium,
                "CWE-841",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test URL encoding bypass
    async fn test_url_encoding(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing URL encoding bypass");

        let parsed = match url::Url::parse(url) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let path = parsed.path();

        // Try different encoding variations
        let encoded_variations = vec![
            urlencoding::encode(path).to_string(),
            self.double_encode(path),
            self.unicode_encode(path),
        ];

        for encoded in encoded_variations {
            if encoded == path {
                continue;
            }

            let encoded_url = url.replace(path, &encoded);

            // Trigger rate limit
            for _ in 0..threshold + 5 {
                let _ = self.http_client.get(url).await;
                tests_run += 1;
            }

            // Try encoded URL
            let success_count = self.test_bypass_technique(&encoded_url, None, None, 10).await?;
            tests_run += 10;

            if success_count > 5 {
                info!("[RateLimitBypass] URL encoding bypass found");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "URL Encoding Bypass",
                    &encoded,
                    "Rate limiting can be bypassed by encoding the URL path",
                    &format!("{}/10 requests succeeded using URL encoding", success_count),
                    Severity::Medium,
                    "CWE-841",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test origin header manipulation
    async fn test_origin_manipulation(&self, url: &str, threshold: usize) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RateLimitBypass] Testing origin header manipulation");

        let origins = vec![
            "http://localhost",
            "http://127.0.0.1",
            "null",
            "http://internal",
        ];

        for origin in &origins {
            // Trigger rate limit
            for _ in 0..threshold + 5 {
                let _ = self.http_client.get(url).await;
                tests_run += 1;
            }

            // Try with origin header
            let mut headers = HashMap::new();
            headers.insert("Origin".to_string(), origin.to_string());

            let success_count = self.test_bypass_technique(url, Some(headers), None, 10).await?;
            tests_run += 10;

            if success_count > 5 {
                info!("[RateLimitBypass] Origin header bypass found: {}", origin);
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "Origin Header Bypass",
                    &format!("Origin: {}", origin),
                    "Rate limiting can be bypassed by manipulating the Origin header",
                    &format!("{}/10 requests succeeded using Origin: {}", success_count, origin),
                    Severity::Medium,
                    "CWE-841",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Helper: Test a bypass technique with multiple requests
    async fn test_bypass_technique(
        &self,
        url: &str,
        headers: Option<HashMap<String, String>>,
        _method: Option<&str>,
        count: usize,
    ) -> Result<usize> {
        let mut success_count = 0;

        for _ in 0..count {
            let response = if let Some(ref hdrs) = headers {
                // Create request with custom headers
                self.http_client.get_with_headers(url, hdrs).await
            } else {
                self.http_client.get(url).await
            };

            match response {
                Ok(resp) => {
                    // Consider it a success if we get a 2xx or 3xx response (not rate limited)
                    if resp.status_code >= 200 && resp.status_code < 400 {
                        success_count += 1;
                    }
                }
                Err(_) => {}
            }

            // Small delay between requests
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        Ok(success_count)
    }

    /// Helper: Alternate case of string
    fn alternate_case(&self, s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect()
    }

    /// Helper: Double URL encode
    fn double_encode(&self, s: &str) -> String {
        let once = urlencoding::encode(s);
        urlencoding::encode(&once).to_string()
    }

    /// Helper: Unicode encode (alternative representation)
    fn unicode_encode(&self, s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("\\u{:04x}", c as u32)
                }
            })
            .collect()
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("rate_limit_bypass_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Rate Limiting Bypass ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Implement rate limiting at multiple levels (IP, user session, API key)\n\
                         2. Normalize URLs before rate limit checks (lowercase, remove trailing slashes)\n\
                         3. Do not trust client-provided headers (X-Forwarded-For, etc.) for rate limiting\n\
                         4. Use a consistent request fingerprint (not just IP or URL)\n\
                         5. Implement rate limiting at the edge/WAF level\n\
                         6. Use distributed rate limiting (Redis, Memcached) for scaling\n\
                         7. Monitor for rate limit bypass attempts\n\
                         8. Apply rate limits to all HTTP methods\n\
                         9. Implement exponential backoff for repeated violations\n\
                         10. Use CAPTCHAs after multiple rate limit violations\n\
                         11. Log and alert on suspicious patterns\n\
                         12. Test rate limiting in CI/CD pipeline".to_string(),
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
    use std::sync::Arc;

    fn create_test_scanner() -> RateLimitBypassScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        RateLimitBypassScanner::new(http_client)
    }

    #[test]
    fn test_alternate_case() {
        let scanner = create_test_scanner();
        let result = scanner.alternate_case("/api/login");
        assert_eq!(result, "/ApI/LoGiN");
    }

    #[test]
    fn test_double_encode() {
        let scanner = create_test_scanner();
        let result = scanner.double_encode("/api/login");
        // Should be double encoded
        assert!(result.contains("%2F"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();
        let vuln = scanner.create_vulnerability(
            "http://example.com/api/login",
            "IP Header Spoofing Bypass",
            "X-Forwarded-For: 127.0.0.1",
            "Rate limiting bypassed via header spoofing",
            "8/10 requests succeeded",
            Severity::High,
            "CWE-841",
        );

        assert_eq!(vuln.vuln_type, "Rate Limiting Bypass (IP Header Spoofing Bypass)");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-841");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.verified);
    }
}
