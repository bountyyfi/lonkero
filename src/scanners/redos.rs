// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::scanners::registry::PayloadIntensity;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct RedosScanner {
    http_client: Arc<HttpClient>,
}

/// ReDoS test payload with escalating lengths
#[derive(Clone)]
struct RedosPayload {
    short: String,  // 10 chars
    medium: String, // 30 chars
    long: String,   // 60 chars
    description: String,
}

impl RedosScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for ReDoS vulnerabilities (default intensity)
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        self.scan_parameter_with_intensity(base_url, parameter, config, PayloadIntensity::Standard)
            .await
    }

    /// Scan a parameter for ReDoS vulnerabilities with specified intensity (intelligent mode)
    pub async fn scan_parameter_with_intensity(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
        intensity: PayloadIntensity,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Runtime verification (integrity check)
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::ReDoS) {
            debug!(
                "[ReDoS] Skipping framework/internal parameter: {}",
                parameter
            );
            return Ok((Vec::new(), 0));
        }

        debug!(
            "[ReDoS] Intelligent scanner - parameter: {} (intensity: {:?})",
            parameter, intensity
        );

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get payloads for testing
        let mut payloads = self.get_redos_payloads();

        // INTELLIGENT MODE: Limit payloads based on intensity
        let payload_limit = intensity.payload_limit();
        if payloads.len() > payload_limit {
            let original_count = payloads.len();
            payloads.truncate(payload_limit);
            info!(
                "[ReDoS] Intelligent mode: limited from {} to {} payloads (intensity: {:?})",
                original_count,
                payloads.len(),
                intensity
            );
        }

        debug!("Testing {} ReDoS payload patterns", payloads.len());

        // Test each payload pattern
        for payload in payloads {
            tests_run += 3; // We test 3 sizes per pattern

            // Test short payload (baseline)
            let short_url = self.build_test_url(base_url, parameter, &payload.short);
            let short_response = match self.http_client.get(&short_url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Short payload request failed: {}", e);
                    continue;
                }
            };

            let t1 = short_response.duration_ms;
            debug!(
                "Short payload ({} chars) response time: {}ms",
                payload.short.len(),
                t1
            );

            // Test medium payload
            let medium_url = self.build_test_url(base_url, parameter, &payload.medium);
            let medium_response = match self.http_client.get(&medium_url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Medium payload request failed: {}", e);
                    continue;
                }
            };

            let t2 = medium_response.duration_ms;
            debug!(
                "Medium payload ({} chars) response time: {}ms",
                payload.medium.len(),
                t2
            );

            // Test long payload
            let long_url = self.build_test_url(base_url, parameter, &payload.long);
            let long_response = match self.http_client.get(&long_url).await {
                Ok(r) => r,
                Err(e) => {
                    debug!("Long payload request failed or timed out: {}", e);

                    // Timeout indicates severe ReDoS
                    info!(
                        "ReDoS vulnerability detected (timeout): parameter '{}'",
                        parameter
                    );

                    vulnerabilities.push(self.create_vulnerability(
                        &long_url,
                        parameter,
                        &payload.long,
                        t1,
                        t2,
                        None,
                        &format!("{} - Request timed out", payload.description),
                        Severity::High,
                    ));

                    break; // Don't test more patterns if we found a timeout
                }
            };

            let t3 = long_response.duration_ms;
            debug!(
                "Long payload ({} chars) response time: {}ms",
                payload.long.len(),
                t3
            );

            // Analyze timing pattern for exponential growth
            if self.detect_exponential_timing(t1, t2, t3) {
                info!(
                    "ReDoS vulnerability detected in parameter '{}': {}ms -> {}ms -> {}ms",
                    parameter, t1, t2, t3
                );

                vulnerabilities.push(self.create_vulnerability(
                    &long_url,
                    parameter,
                    &payload.long,
                    t1,
                    t2,
                    Some(t3),
                    &payload.description,
                    Severity::High,
                ));

                break; // Found vulnerability, no need to test more patterns
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Build test URL with encoded payload
    fn build_test_url(&self, base_url: &str, parameter: &str, payload: &str) -> String {
        if base_url.contains('?') {
            format!(
                "{}&{}={}",
                base_url,
                parameter,
                urlencoding::encode(payload)
            )
        } else {
            format!(
                "{}?{}={}",
                base_url,
                parameter,
                urlencoding::encode(payload)
            )
        }
    }

    /// Detect exponential timing pattern indicating ReDoS
    fn detect_exponential_timing(&self, t1: u64, t2: u64, t3: u64) -> bool {
        // If any response is very slow (> 5 seconds), likely ReDoS
        if t3 > 5000 {
            return true;
        }

        // Check for exponential growth pattern
        // T3 should be significantly larger than T2, and T2 larger than T1
        // We use a factor of 3 to account for network variance
        if t3 > t2 * 3 && t2 > t1 {
            return true;
        }

        // Alternative check: if T3 is more than 2 seconds and significantly larger than T2
        if t3 > 2000 && t3 > t2 * 2 {
            return true;
        }

        false
    }

    /// Get ReDoS test payloads
    fn get_redos_payloads(&self) -> Vec<RedosPayload> {
        vec![
            // Pattern 1: Repeated 'a' with special char (triggers (a+)+ patterns)
            RedosPayload {
                short: "aaaaaaaaaa!".to_string(),
                medium: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!".to_string(),
                long: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!".to_string(),
                description: "Repeated characters with special terminator".to_string(),
            },
            // Pattern 2: Repeated '0' with special char (triggers digit patterns)
            RedosPayload {
                short: "0000000000!".to_string(),
                medium: "000000000000000000000000000000!".to_string(),
                long: "000000000000000000000000000000000000000000000000000000000000!".to_string(),
                description: "Repeated digits with special terminator".to_string(),
            },
            // Pattern 3: Repeated 'x' with backslash (triggers escape patterns)
            RedosPayload {
                short: "xxxxxxxxxx\\".to_string(),
                medium: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\".to_string(),
                long: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\".to_string(),
                description: "Repeated characters with escape sequence".to_string(),
            },
            // Pattern 4: Email-like pattern (triggers email validation regex)
            RedosPayload {
                short: "a]@a]@a]".to_string(),
                medium: "a]@a]@a]@a]@a]@a]@a]@a]@a]@a]".to_string(),
                long: "a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]@a]".to_string(),
                description: "Malformed email pattern".to_string(),
            },
            // Pattern 5: URL-like pattern (triggers URL validation regex)
            RedosPayload {
                short: "http://aaa".to_string(),
                medium: "http://aaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                long: "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                description: "Long URL pattern".to_string(),
            },
            // Pattern 6: Repeated word characters with dot (triggers (\w+\.)+ patterns)
            RedosPayload {
                short: "aaaa.aaaa.".to_string(),
                medium: "aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.".to_string(),
                long: "aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.aaaa.".to_string(),
                description: "Repeated word patterns with dots".to_string(),
            },
            // Pattern 7: Numbers with dot (triggers number validation)
            RedosPayload {
                short: "1111111111.".to_string(),
                medium: "111111111111111111111111111111.".to_string(),
                long: "111111111111111111111111111111111111111111111111111111111111.".to_string(),
                description: "Repeated numbers with decimal point".to_string(),
            },
            // Pattern 8: Mixed alphanumeric (triggers complex patterns)
            RedosPayload {
                short: "a1a1a1a1a1!".to_string(),
                medium: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1!".to_string(),
                long: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1!".to_string(),
                description: "Alternating alphanumeric pattern".to_string(),
            },
        ]
    }

    /// Create a ReDoS vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        parameter: &str,
        payload: &str,
        t1: u64,
        t2: u64,
        t3: Option<u64>,
        description: &str,
        severity: Severity,
    ) -> Vulnerability {
        let evidence = if let Some(time3) = t3 {
            format!(
                "Exponential timing detected: {}ms (10 chars) -> {}ms (30 chars) -> {}ms (60 chars). Growth pattern indicates catastrophic backtracking.",
                t1, t2, time3
            )
        } else {
            format!(
                "Request timed out at 60 character payload. Previous timings: {}ms (10 chars) -> {}ms (30 chars).",
                t1, t2
            )
        };

        Vulnerability {
            id: format!("redos_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "Regular Expression Denial of Service (ReDoS)".to_string(),
            severity,
            confidence: Confidence::High,
            category: "Denial of Service".to_string(),
            url: url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "ReDoS vulnerability detected in parameter '{}'. {}. The application uses inefficient regular expressions that exhibit catastrophic backtracking when processing specially crafted input.",
                parameter, description
            ),
            evidence: Some(evidence),
            cwe: "CWE-1333".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: r#"1. Review and optimize regular expressions to avoid catastrophic backtracking
2. Use atomic groups and possessive quantifiers to prevent backtracking
3. Set timeouts for regex operations (e.g., 100ms max)
4. Implement input length limits before regex validation
5. Use regex analysis tools to detect vulnerable patterns
6. Consider using alternative parsing methods for complex validation
7. Avoid nested quantifiers like (a+)+ or (a*)*
8. Use anchors (^ and $) to constrain pattern matching
9. Test regex patterns with long inputs during development
10. Consider using safe regex libraries with built-in protection"#.to_string(),
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

    fn create_test_scanner() -> RedosScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        RedosScanner::new(http_client)
    }

    #[test]
    fn test_detect_exponential_timing() {
        let scanner = create_test_scanner();

        // Test case 1: Clear exponential growth
        assert!(scanner.detect_exponential_timing(100, 500, 6000));

        // Test case 2: Very slow response (>5 seconds)
        assert!(scanner.detect_exponential_timing(100, 200, 6000));

        // Test case 3: Moderate growth pattern
        assert!(scanner.detect_exponential_timing(200, 600, 2500));

        // Test case 4: Normal timing (no ReDoS)
        assert!(!scanner.detect_exponential_timing(100, 120, 150));

        // Test case 5: Linear growth (not exponential)
        assert!(!scanner.detect_exponential_timing(100, 200, 300));
    }

    #[test]
    fn test_build_test_url() {
        let scanner = create_test_scanner();

        // Test with URL without query string
        let url1 = scanner.build_test_url("http://example.com/api", "param", "test");
        assert_eq!(url1, "http://example.com/api?param=test");

        // Test with URL with existing query string
        let url2 = scanner.build_test_url("http://example.com/api?foo=bar", "param", "test");
        assert_eq!(url2, "http://example.com/api?foo=bar&param=test");

        // Test with special characters (should be URL encoded)
        let url3 = scanner.build_test_url("http://example.com/api", "param", "a@b");
        assert!(url3.contains("%40")); // @ is encoded as %40
    }

    #[test]
    fn test_get_redos_payloads() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_redos_payloads();

        // Should have multiple payload patterns
        assert!(payloads.len() >= 5);

        // Each payload should have escalating sizes
        for payload in &payloads {
            assert!(payload.short.len() < payload.medium.len());
            assert!(payload.medium.len() < payload.long.len());
            assert!(!payload.description.is_empty());
        }

        // Check specific payload patterns exist
        assert!(payloads.iter().any(|p| p.short.starts_with("aaaa")));
        assert!(payloads.iter().any(|p| p.short.starts_with("0000")));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/api?param=test",
            "param",
            "aaaa...aaaa!",
            100,
            500,
            Some(6000),
            "Test pattern",
            Severity::High,
        );

        assert_eq!(
            vuln.vuln_type,
            "Regular Expression Denial of Service (ReDoS)"
        );
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.confidence, Confidence::High);
        assert_eq!(vuln.cwe, "CWE-1333");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.verified);
        assert!(!vuln.false_positive);
        assert!(vuln.evidence.is_some());
        assert!(vuln.evidence.unwrap().contains("100ms"));
        assert!(vuln.evidence.unwrap().contains("6000ms"));
    }

    #[test]
    fn test_create_vulnerability_timeout() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/api?param=test",
            "param",
            "aaaa...aaaa!",
            100,
            500,
            None, // Timeout case
            "Test pattern",
            Severity::High,
        );

        assert!(vuln.evidence.is_some());
        assert!(vuln.evidence.unwrap().contains("timed out"));
    }
}
