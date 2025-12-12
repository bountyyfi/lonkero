// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - ReDoS (Regular Expression Denial of Service) Scanner
 * Detects regex patterns vulnerable to exponential backtracking
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct RedosScanner {
    http_client: Arc<HttpClient>,
}

impl RedosScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a URL and parameter for ReDoS vulnerabilities using timing-based detection
    pub async fn scan(
        &self,
        url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Integrity verification
        if !crate::license::verify_rt_state() {
            return Ok((Vec::new(), 0));
        }

        info!("Testing parameter '{}' for ReDoS vulnerabilities", parameter);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Step 1: Establish baseline response time with benign input
        let baseline_payload = "test";
        let baseline_time = self.measure_response_time(url, parameter, baseline_payload).await?;

        debug!(
            "Baseline response time for parameter '{}': {}ms",
            parameter, baseline_time
        );

        // Step 2: Get ReDoS payloads based on scan mode
        let payloads = self.get_redos_payloads(config);

        debug!("Testing {} ReDoS payloads", payloads.len());

        // Step 3: Test each payload and compare response times
        for (payload_name, payload, shorter_payload) in payloads {
            tests_run += 1;

            // Test the full payload
            let full_payload_time = match self.measure_response_time(url, parameter, &payload).await {
                Ok(time) => time,
                Err(e) => {
                    debug!("Request failed for ReDoS payload '{}': {}", payload_name, e);
                    continue;
                }
            };

            debug!(
                "Payload '{}' response time: {}ms (baseline: {}ms)",
                payload_name, full_payload_time, baseline_time
            );

            // ReDoS detection: Response time significantly longer than baseline
            let threshold_ms = if config.ultra { 3000 } else { 5000 };

            if full_payload_time > threshold_ms && full_payload_time > baseline_time * 2 {
                // Step 4: Confirmation - Test with shorter payload
                // If it's truly ReDoS, shorter input should be much faster
                tests_run += 1;

                let short_payload_time = match self.measure_response_time(url, parameter, &shorter_payload).await {
                    Ok(time) => time,
                    Err(e) => {
                        debug!("Confirmation request failed: {}", e);
                        // Still report vulnerability but with lower confidence
                        self.create_redos_vulnerability(
                            url,
                            parameter,
                            &payload_name,
                            &payload,
                            full_payload_time,
                            baseline_time,
                            None,
                            Confidence::Medium,
                        );

                        continue;
                    }
                };

                debug!(
                    "Shorter payload response time: {}ms (confirms exponential behavior)",
                    short_payload_time
                );

                // Confirm ReDoS: Full payload is much slower than shortened version
                // This indicates exponential backtracking behavior
                if full_payload_time > short_payload_time * 3 {
                    info!(
                        "ReDoS vulnerability confirmed in parameter '{}': {}ms vs {}ms (baseline: {}ms)",
                        parameter, full_payload_time, short_payload_time, baseline_time
                    );

                    let vuln = self.create_redos_vulnerability(
                        url,
                        parameter,
                        &payload_name,
                        &payload,
                        full_payload_time,
                        baseline_time,
                        Some(short_payload_time),
                        Confidence::High,
                    );

                    vulnerabilities.push(vuln);

                    // Found confirmed ReDoS, no need to test more payloads for this parameter
                    break;
                } else {
                    // Slow response but not exponential - possibly network/server latency
                    debug!(
                        "Slow response but not exponential backtracking ({}ms vs {}ms)",
                        full_payload_time, short_payload_time
                    );
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Measure response time for a given payload
    async fn measure_response_time(
        &self,
        base_url: &str,
        parameter: &str,
        payload: &str,
    ) -> Result<u64> {
        let test_url = if base_url.contains('?') {
            format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
        } else {
            format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
        };

        let response = self.http_client.get(&test_url).await?;
        Ok(response.duration_ms)
    }

    /// Create a ReDoS vulnerability report
    fn create_redos_vulnerability(
        &self,
        url: &str,
        parameter: &str,
        payload_name: &str,
        payload: &str,
        response_time_ms: u64,
        baseline_time_ms: u64,
        short_payload_time_ms: Option<u64>,
        confidence: Confidence,
    ) -> Vulnerability {
        let evidence = if let Some(short_time) = short_payload_time_ms {
            format!(
                "Response time: {}ms ({}x baseline). Shorter payload: {}ms. Exponential backtracking confirmed.",
                response_time_ms,
                response_time_ms / baseline_time_ms.max(1),
                short_time
            )
        } else {
            format!(
                "Response time: {}ms ({}x baseline). Potential ReDoS detected.",
                response_time_ms,
                response_time_ms / baseline_time_ms.max(1)
            )
        };

        let severity = if response_time_ms > 10000 {
            Severity::Critical
        } else if response_time_ms > 5000 {
            Severity::High
        } else {
            Severity::Medium
        };

        Vulnerability {
            id: format!("redos_{}", crate::scanners::uuid::Uuid::new_v4().to_string()),
            vuln_type: "Regular Expression Denial of Service (ReDoS)".to_string(),
            severity,
            confidence,
            category: "Denial of Service".to_string(),
            url: url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "ReDoS vulnerability detected in parameter '{}' using payload type '{}'. \
                The application uses a regex pattern vulnerable to exponential backtracking, \
                which can cause severe performance degradation or complete service denial. \
                Response time increased from {}ms to {}ms.",
                parameter, payload_name, baseline_time_ms, response_time_ms
            ),
            evidence: Some(evidence),
            cwe: "CWE-1333".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: concat!(
                "1. Review and optimize regex patterns to avoid exponential backtracking\n",
                "2. Use regex engines with linear time complexity (e.g., RE2)\n",
                "3. Implement timeout limits for regex operations\n",
                "4. Validate input length before regex matching\n",
                "5. Test regex patterns with tools like regex101.com or ReDoS checkers\n",
                "6. Consider using simpler string matching when possible\n",
                "7. Implement rate limiting to mitigate DoS attacks"
            ).to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        }
    }

    /// Get ReDoS payloads based on scan mode
    /// Returns (name, full_payload, shorter_version) tuples
    fn get_redos_payloads(&self, config: &ScanConfig) -> Vec<(&'static str, String, String)> {
        let mut payloads = vec![
            // Evil regex: (a+)+ pattern
            (
                "Nested quantifiers (a+)+",
                "a".repeat(30) + "!",
                "a".repeat(15) + "!",
            ),
            // Long string with rejection at end
            (
                "Long string with final mismatch",
                "a".repeat(50) + "b",
                "a".repeat(25) + "b",
            ),
            // Email regex attack: (.+)*
            (
                "Email pattern exploit",
                "a]@a]".repeat(10),
                "a]@a]".repeat(5),
            ),
            // Nested groups
            (
                "Nested capture groups",
                format!("{}a]", "(".repeat(30)),
                format!("{}a]", "(".repeat(15)),
            ),
            // Bracket bomb
            (
                "Bracket repetition",
                "]".repeat(25),
                "]".repeat(12),
            ),
        ];

        // Add more intensive payloads for thorough/insane modes
        if config.ultra || matches!(config.scan_mode.as_str(), "thorough" | "insane") {
            payloads.extend(vec![
                // Script tag repetition (could trigger regex in XSS filters)
                (
                    "Script tag repetition",
                    "<script>".repeat(25),
                    "<script>".repeat(12),
                ),
                // URL pattern attack
                (
                    "URL pattern exploit",
                    format!("http://{}", "a".repeat(40) + "."),
                    format!("http://{}", "a".repeat(20) + "."),
                ),
                // JSON-like structure attack
                (
                    "JSON structure exploit",
                    format!("{}{}", "{".repeat(30), "}".repeat(30)),
                    format!("{}{}", "{".repeat(15), "}".repeat(15)),
                ),
                // HTML tag nesting
                (
                    "HTML tag nesting",
                    "<div><span><p><a>".repeat(10),
                    "<div><span><p><a>".repeat(5),
                ),
                // Path traversal pattern that might trigger regex
                (
                    "Path traversal pattern",
                    "../".repeat(50),
                    "../".repeat(25),
                ),
                // Unicode mixed with ASCII (can confuse some regex engines)
                (
                    "Unicode boundary attack",
                    format!("{}🔥", "a".repeat(40)),
                    format!("{}🔥", "a".repeat(20)),
                ),
                // SQL-like pattern (might trigger WAF regex)
                (
                    "SQL-like pattern",
                    format!("' OR '{}'='{}'", "1".repeat(20), "1".repeat(20)),
                    format!("' OR '{}'='{}'", "1".repeat(10), "1".repeat(10)),
                ),
                // XML bomb-like pattern
                (
                    "XML entity pattern",
                    "&lt;".repeat(40),
                    "&lt;".repeat(20),
                ),
            ]);
        }

        // For insane mode, add extreme test cases
        if config.scan_mode.as_str() == "insane" {
            payloads.extend(vec![
                (
                    "Extreme nested quantifiers",
                    "a".repeat(100) + "!",
                    "a".repeat(50) + "!",
                ),
                (
                    "Extreme email pattern",
                    "a]@a]".repeat(25),
                    "a]@a]".repeat(12),
                ),
                (
                    "Extreme bracket bomb",
                    "]".repeat(60),
                    "]".repeat(30),
                ),
                (
                    "Extreme URL pattern",
                    format!("{}", "http://aaa.".repeat(20)),
                    format!("{}", "http://aaa.".repeat(10)),
                ),
            ]);
        }

        payloads
    }

    /// Scan multiple parameters for ReDoS vulnerabilities
    pub async fn scan_parameters(
        &self,
        url: &str,
        parameters: &[String],
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Scanning {} parameters for ReDoS vulnerabilities", parameters.len());

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        for parameter in parameters {
            let (vulns, tests) = self.scan(url, parameter, config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;
        }

        Ok((all_vulnerabilities, total_tests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanMode;

    #[test]
    fn test_redos_payloads_fast_mode() {
        let scanner = RedosScanner::new(Arc::new(HttpClient::new().unwrap()));
        let config = ScanConfig {
            scan_mode: ScanMode::Fast,
            ultra: false,
            ..Default::default()
        };

        let payloads = scanner.get_redos_payloads(&config);
        assert_eq!(payloads.len(), 5, "Fast mode should have 5 basic payloads");
    }

    #[test]
    fn test_redos_payloads_thorough_mode() {
        let scanner = RedosScanner::new(Arc::new(HttpClient::new().unwrap()));
        let config = ScanConfig {
            scan_mode: ScanMode::Thorough,
            ultra: false,
            ..Default::default()
        };

        let payloads = scanner.get_redos_payloads(&config);
        assert!(payloads.len() > 5, "Thorough mode should have more payloads");
    }

    #[test]
    fn test_redos_payloads_insane_mode() {
        let scanner = RedosScanner::new(Arc::new(HttpClient::new().unwrap()));
        let config = ScanConfig {
            scan_mode: ScanMode::Insane,
            ultra: true,
            ..Default::default()
        };

        let payloads = scanner.get_redos_payloads(&config);
        assert!(payloads.len() > 13, "Insane mode should have maximum payloads");
    }

    #[test]
    fn test_payload_structure() {
        let scanner = RedosScanner::new(Arc::new(HttpClient::new().unwrap()));
        let config = ScanConfig::default();
        let payloads = scanner.get_redos_payloads(&config);

        // Verify each payload has shorter version
        for (name, full, shorter) in payloads {
            assert!(
                full.len() > shorter.len(),
                "Payload '{}': full version should be longer than shorter version",
                name
            );
        }
    }
}
