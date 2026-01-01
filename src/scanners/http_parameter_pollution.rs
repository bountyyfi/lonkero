// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - HTTP Parameter Pollution (HPP) Scanner
 * Detects HPP vulnerabilities where multiple parameters with same name cause unexpected behavior
 *
 * Attacks:
 * - Server-Side HPP: ?id=1&id=2 handled differently by backend
 * - Client-Side HPP: Reflected parameters causing XSS/injection
 * - WAF Bypass: Using HPP to bypass security filters
 * - Authentication Bypass: Manipulating auth parameters
 * - Authorization Bypass: Overriding role/permission parameters
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use crate::detection_helpers::{AppCharacteristics, is_payload_reflected_dangerously, did_payload_have_effect};
use std::sync::Arc;
use tracing::{debug, info};

pub struct HttpParameterPollutionScanner {
    http_client: Arc<HttpClient>,
}

impl HttpParameterPollutionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for HTTP Parameter Pollution vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut total_tests = 0;

        info!("[HPP] Starting HTTP Parameter Pollution scan on {}", url);

        // CRITICAL: Check if site is SPA/static first
        // HPP tests don't work on SPAs (same HTML for all params)
        let baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), 0)),
        };

        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        if characteristics.should_skip_injection_tests() {
            info!("[HPP] Site is SPA/static - skipping HPP tests (not applicable)");
            return Ok((Vec::new(), 0));
        }

        info!("[HPP] Dynamic site detected - proceeding with HPP tests");

        // Test server-side HPP
        let (vulns, tests) = self.test_server_side_hpp(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test WAF bypass via HPP
        let (vulns, tests) = self.test_waf_bypass_hpp(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test authentication bypass via HPP
        let (vulns, tests) = self.test_auth_bypass_hpp(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test client-side HPP (reflected)
        let (vulns, tests) = self.test_client_side_hpp(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test array parameter pollution
        let (vulns, tests) = self.test_array_pollution(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test JSON HPP
        let (vulns, tests) = self.test_json_hpp(url).await?;
        vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "[HPP] Scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, total_tests))
    }

    /// Test for server-side HPP (different backend behaviors)
    async fn test_server_side_hpp(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("[HPP] Testing server-side HTTP Parameter Pollution");

        // Common parameters that are often vulnerable
        let hpp_tests = vec![
            // Basic duplicate parameters
            ("id", vec!["1", "2"], "Basic ID pollution"),
            ("user", vec!["admin", "guest"], "User parameter pollution"),
            ("role", vec!["user", "admin"], "Role parameter pollution"),
            ("page", vec!["1", "99999"], "Pagination pollution"),
            ("action", vec!["view", "delete"], "Action parameter pollution"),
            ("redirect", vec!["safe.com", "evil.com"], "Redirect URL pollution"),
        ];

        for (param, values, description) in &hpp_tests {
            // Test with multiple same-name parameters: ?param=val1&param=val2
            let polluted_query = values
                .iter()
                .map(|v| format!("{}={}", param, v))
                .collect::<Vec<_>>()
                .join("&");

            let test_url = if url.contains('?') {
                format!("{}&{}", url, polluted_query)
            } else {
                format!("{}?{}", url, polluted_query)
            };

            // Also test comma-separated: ?param=val1,val2
            let comma_url = if url.contains('?') {
                format!("{}&{}={}", url, param, values.join(","))
            } else {
                format!("{}?{}={}", url, param, values.join(","))
            };

            // Test bracket notation: ?param[]=val1&param[]=val2
            let bracket_query = values
                .iter()
                .map(|v| format!("{}[]={}", param, v))
                .collect::<Vec<_>>()
                .join("&");

            let bracket_url = if url.contains('?') {
                format!("{}&{}", url, bracket_query)
            } else {
                format!("{}?{}", url, bracket_query)
            };

            // Send requests and compare behavior
            let baseline_url = format!("{}?{}={}", url.trim_end_matches('?'), param, values[0]);
            let (baseline, polluted, comma, bracket) = tokio::join!(
                self.http_client.get(&baseline_url),
                self.http_client.get(&test_url),
                self.http_client.get(&comma_url),
                self.http_client.get(&bracket_url)
            );

            // Check for HPP indicators
            if let (Ok(base_resp), Ok(poll_resp)) = (&baseline, &polluted) {
                let hpp_detected = self.detect_hpp_behavior(
                    &base_resp.body,
                    &poll_resp.body,
                    param,
                    values,
                );

                if hpp_detected {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Server-Side HTTP Parameter Pollution",
                        &polluted_query,
                        &format!(
                            "{}: Server processes multiple '{}' parameters differently. \
                             This can lead to business logic bypass, WAF evasion, or unexpected behavior.",
                            description, param
                        ),
                        &format!("Different behavior detected with {}={} vs {}",
                                 param, values[0], polluted_query),
                        Severity::Medium,
                        "CWE-235",
                    ));
                }
            }

            // NOTE: We do NOT report comma-separated or array bracket notation as vulnerabilities
            // unless they cause an actual security-relevant behavioral change.
            // Many APIs legitimately accept comma-separated values (e.g., ?fields=id,name,email)
            // and array bracket notation (e.g., ?ids[]=1&ids[]=2) - this is normal behavior.
            //
            // Only report if there's evidence of:
            // 1. Privilege escalation (second value grants higher privileges)
            // 2. Security control bypass
            // 3. Unexpected value override that causes business logic issues

            // Check comma-separated handling - ONLY if it causes privilege escalation
            if let (Ok(base_resp), Ok(comma_resp)) = (&baseline, &comma) {
                // Only report if the second value (e.g., "admin") appears in a privileged context
                // AND this is NEW (not in baseline)
                if *param == "role" || *param == "user" {
                    if self.detect_privilege_escalation_hpp(&comma_resp.body, &base_resp.body, values[1]) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "HTTP Parameter Pollution (Comma-Separated)",
                            &format!("{}={}", param, values.join(",")),
                            &format!(
                                "Privilege escalation via comma-separated '{}' parameter. \
                                 Second value '{}' grants elevated privileges.",
                                param, values[1]
                            ),
                            &format!("Privilege escalation via comma-separated {}", param),
                            Severity::High,
                            "CWE-235",
                        ));
                    }
                }
            }

            // Check array bracket notation - ONLY if it causes privilege escalation
            if let (Ok(base_resp), Ok(bracket_resp)) = (&baseline, &bracket) {
                if *param == "role" || *param == "user" {
                    if self.detect_privilege_escalation_hpp(&bracket_resp.body, &base_resp.body, values[1]) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "HTTP Parameter Pollution (Array Notation)",
                            &bracket_query,
                            &format!(
                                "Privilege escalation via array notation '{}[]' parameter. \
                                 Injected value '{}' grants elevated privileges.",
                                param, values[1]
                            ),
                            &format!("Privilege escalation via array notation {}[]", param),
                            Severity::High,
                            "CWE-235",
                        ));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test WAF bypass using HPP
    async fn test_waf_bypass_hpp(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("[HPP] Testing WAF bypass via HTTP Parameter Pollution");

        // Get baseline response for comparison
        let baseline = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), 0)),
        };

        // WAF bypass payloads using HPP
        let waf_bypass_tests = vec![
            // SQL injection split across parameters
            ("id", vec!["1' OR", " '1'='1"], "SQLi via HPP split"),
            // XSS split across parameters
            ("q", vec!["<script>", "alert(1)</script>"], "XSS via HPP split"),
            // Command injection split
            ("cmd", vec!["ls", " && cat /etc/passwd"], "Command injection via HPP"),
            // Path traversal split
            ("file", vec!["../", "../etc/passwd"], "Path traversal via HPP"),
            // LDAP injection split
            ("user", vec!["*)(", "uid=*))(|(uid=*"], "LDAP injection via HPP"),
        ];

        for (param, values, description) in &waf_bypass_tests {
            let polluted_query = values
                .iter()
                .map(|v| format!("{}={}", param, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            let test_url = if url.contains('?') {
                format!("{}&{}", url, polluted_query)
            } else {
                format!("{}?{}", url, polluted_query)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // CRITICAL: First check if payload had any effect vs baseline
                    let combined_payload = values.join("");
                    if !did_payload_have_effect(&baseline, &response, &combined_payload) {
                        debug!("[HPP] WAF bypass {} - no behavioral change, skipping", description);
                        continue;
                    }

                    // Check if WAF blocked single payload but allowed split (with baseline comparison)
                    let waf_bypassed = self.detect_waf_bypass(&response.body, &baseline.body, values);

                    if waf_bypassed {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "WAF Bypass via HTTP Parameter Pollution",
                            &polluted_query,
                            &format!(
                                "{}: WAF bypass achieved by splitting malicious payload across \
                                 multiple '{}' parameters. Combined payload may execute on server.",
                                description, param
                            ),
                            &format!("WAF bypass detected with split payload: {}", values.join(" + ")),
                            Severity::High,
                            "CWE-235",
                        ));
                    }
                }
                Err(e) => debug!("WAF bypass test failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test authentication bypass via HPP
    async fn test_auth_bypass_hpp(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("[HPP] Testing authentication bypass via HTTP Parameter Pollution");

        // Auth endpoints to test
        let auth_endpoints = vec![
            format!("{}/login", url.trim_end_matches('/')),
            format!("{}/auth", url.trim_end_matches('/')),
            format!("{}/api/auth", url.trim_end_matches('/')),
        ];

        // Auth parameter pollution tests
        let auth_tests = vec![
            ("username", vec!["admin", "guest"], "admin&username=guest"),
            ("role", vec!["admin", "user"], "role privilege escalation"),
            ("admin", vec!["true", "false"], "admin flag manipulation"),
            ("verified", vec!["true", "false"], "verified status manipulation"),
        ];

        for endpoint in &auth_endpoints {
            // Get baseline response for this endpoint first
            let baseline_response = match self.http_client.get(endpoint).await {
                Ok(r) => r,
                Err(_) => continue, // Endpoint doesn't exist, skip
            };

            for (param, values, description) in &auth_tests {
                let polluted_query = values
                    .iter()
                    .map(|v| format!("{}={}", param, v))
                    .collect::<Vec<_>>()
                    .join("&");

                // Test via POST body
                let post_body = polluted_query.clone();
                let headers = vec![
                    ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())
                ];

                match self.http_client.post_with_headers(endpoint, &post_body, headers).await {
                    Ok(response) => {
                        // CRITICAL: Pass baseline body to detect_auth_bypass to avoid false positives
                        let auth_bypassed = self.detect_auth_bypass(&response.body, &baseline_response.body, param, values);

                        if auth_bypassed {
                            vulnerabilities.push(self.create_vulnerability(
                                endpoint,
                                "Authentication Bypass via HTTP Parameter Pollution",
                                &post_body,
                                &format!(
                                    "{}: Authentication may be bypassed by sending multiple '{}' \
                                     parameters. Server may process privileged value.",
                                    description, param
                                ),
                                &format!("Auth bypass detected with {} pollution", param),
                                Severity::Critical,
                                "CWE-287",
                            ));
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test client-side HPP (reflected parameters)
    async fn test_client_side_hpp(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("[HPP] Testing client-side HTTP Parameter Pollution");

        // Test reflected parameters that might be used in links
        let canary = format!("hpp_test_{}", rand::random::<u32>());
        let xss_canary = format!("</a><img/src=x onerror=alert({})>", rand::random::<u32>());

        let client_hpp_tests = vec![
            ("url", vec![&canary, "http://evil.com"], "URL parameter reflection"),
            ("redirect", vec![&canary, "javascript:alert(1)"], "Redirect pollution"),
            ("callback", vec![&canary, &xss_canary], "Callback parameter pollution"),
            ("next", vec![&canary, "//evil.com"], "Next URL pollution"),
        ];

        for (param, values, description) in &client_hpp_tests {
            let polluted_query = values
                .iter()
                .map(|v| format!("{}={}", param, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            let test_url = if url.contains('?') {
                format!("{}&{}", url, polluted_query)
            } else {
                format!("{}?{}", url, polluted_query)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // CRITICAL: Use smart reflection detection (not substring matching!)
                    let dangerous_reflection = is_payload_reflected_dangerously(&response, values[1]);

                    // Also check if BOTH values appear in dangerous context
                    let both_dangerous = is_payload_reflected_dangerously(&response, values[0]) &&
                                        dangerous_reflection;

                    if both_dangerous || dangerous_reflection {
                        let severity = if dangerous_reflection {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Client-Side HTTP Parameter Pollution",
                            &polluted_query,
                            &format!(
                                "{}: Multiple '{}' parameter values are reflected in response. \
                                 This can lead to XSS, open redirect, or phishing attacks.",
                                description, param
                            ),
                            &format!("Both values reflected in response for {}", param),
                            severity,
                            "CWE-79",
                        ));
                    }
                }
                Err(e) => debug!("Client-side HPP test failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test array parameter pollution
    async fn test_array_pollution(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("[HPP] Testing array parameter pollution");

        // Array pollution patterns
        let array_tests = vec![
            // PHP array injection
            ("items[0]", "normal", "items[999]", "admin", "PHP array index manipulation"),
            // JSON-like array injection
            ("data[user]", "guest", "data[admin]", "true", "JSON-style array injection"),
            // Nested array manipulation
            ("config[role][0]", "user", "config[role][1]", "admin", "Nested array pollution"),
            // Array overflow
            ("ids[]", "1", "ids[]", "1' OR '1'='1", "Array SQLi injection"),
        ];

        for (param1, val1, param2, val2, description) in &array_tests {
            let polluted_query = format!("{}={}&{}={}", param1, val1, param2, val2);

            let test_url = if url.contains('?') {
                format!("{}&{}", url, polluted_query)
            } else {
                format!("{}?{}", url, polluted_query)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if array manipulation was processed
                    if self.detect_array_processing(&response.body, val2) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Array Parameter Pollution",
                            &polluted_query,
                            &format!(
                                "{}: Server processes array parameters that can be manipulated \
                                 to inject additional values or override existing ones.",
                                description
                            ),
                            &format!("Array manipulation detected: {} processed", param2),
                            Severity::Medium,
                            "CWE-235",
                        ));
                    }
                }
                Err(e) => debug!("Array pollution test failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JSON parameter pollution
    async fn test_json_hpp(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("[HPP] Testing JSON parameter pollution");

        let api_endpoints = vec![
            format!("{}/api", url.trim_end_matches('/')),
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // JSON pollution payloads - duplicate keys
        let json_tests = vec![
            (r#"{"role":"user","role":"admin"}"#, "Duplicate key pollution"),
            (r#"{"user":"guest","admin":true,"user":"admin"}"#, "Key override pollution"),
            (r#"{"__proto__":{"admin":true},"role":"user"}"#, "Prototype pollution"),
        ];

        for endpoint in &api_endpoints {
            // Get baseline response for this endpoint first
            let baseline_response = match self.http_client.get(endpoint).await {
                Ok(r) => r,
                Err(_) => continue, // Endpoint doesn't exist, skip
            };

            for (payload, description) in &json_tests {
                let headers = vec![
                    ("Content-Type".to_string(), "application/json".to_string())
                ];

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        // CRITICAL: Pass baseline body to detect_json_hpp to avoid false positives
                        let json_hpp = self.detect_json_hpp(&response.body, &baseline_response.body, payload);

                        if json_hpp {
                            vulnerabilities.push(self.create_vulnerability(
                                endpoint,
                                "JSON Parameter Pollution",
                                payload,
                                &format!(
                                    "{}: JSON parser accepts duplicate keys which may be processed \
                                     differently, allowing privilege escalation or data manipulation.",
                                    description
                                ),
                                "Duplicate JSON keys processed unexpectedly",
                                Severity::High,
                                "CWE-1321",
                            ));
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect HPP behavior differences - requires significant change AND evidence of value usage
    fn detect_hpp_behavior(
        &self,
        baseline: &str,
        polluted: &str,
        _param: &str,
        values: &[&str],
    ) -> bool {
        // Check for significant response differences (at least 20% change)
        let len_diff = (baseline.len() as i64 - polluted.len() as i64).abs();
        let len_ratio = if baseline.len() > 0 {
            len_diff as f64 / baseline.len() as f64
        } else {
            0.0
        };
        let significant_diff = len_ratio > 0.2;

        // CRITICAL: Only detect if values are NEW (not already in baseline)
        // This prevents false positives from generic words appearing in the page
        let baseline_lower = baseline.to_lowercase();
        let polluted_lower = polluted.to_lowercase();

        // Check if second value appears in response but NOT in baseline (indicates processing)
        let second_value_new = polluted_lower.contains(&values[1].to_lowercase()) &&
            !baseline_lower.contains(&values[1].to_lowercase());

        // Check for NEW concatenation (both values appearing together, but not in baseline)
        let new_concatenated = polluted.contains(values[0]) && polluted.contains(values[1]) &&
            (!baseline.contains(values[0]) || !baseline.contains(values[1]));

        // Must have BOTH: significant difference AND evidence of value processing
        significant_diff && (second_value_new || new_concatenated)
    }

    /// Detect if a specific value was accepted
    fn detect_value_accepted(&self, body: &str, value: &str) -> bool {
        body.contains(value) ||
            body.to_lowercase().contains(&value.to_lowercase())
    }

    /// Detect WAF bypass - REQUIRES baseline comparison to avoid false positives
    fn detect_waf_bypass(&self, body: &str, baseline_body: &str, split_values: &[&str]) -> bool {
        let body_lower = body.to_lowercase();
        let baseline_lower = baseline_body.to_lowercase();

        // CRITICAL: Check for NEW SQL error indicators (not present in baseline)
        // This prevents false positives from pages that normally contain "sql" or "syntax"
        let sql_indicators = vec![
            "you have an error in your sql",
            "sql syntax",
            "mysql_fetch",
            "pg_query",
            "sqlstate",
            "oledbexception",
            "sqlexception",
        ];
        for indicator in &sql_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                return true;
            }
        }

        // Check for NEW command execution indicators (not in baseline)
        if (body.contains("root:") && body.contains("/bin/") && !baseline_body.contains("root:")) {
            return true;
        }

        // Check for NEW XSS reflection of the actual payload
        // The combined payload must be reflected in a dangerous context
        let combined = split_values.join("");
        if combined.contains("script") || combined.contains("alert") {
            // Check for dangerous reflection of the XSS payload
            if is_payload_reflected_dangerously(&HttpResponse {
                status_code: 200,
                headers: std::collections::HashMap::new(),
                body: body.to_string(),
                duration_ms: 0,
            }, "alert(1)") {
                return true;
            }
        }

        false
    }

    /// Detect authentication bypass - REQUIRES baseline comparison to avoid false positives
    fn detect_auth_bypass(&self, body: &str, baseline_body: &str, _param: &str, values: &[&str]) -> bool {
        let body_lower = body.to_lowercase();
        let baseline_lower = baseline_body.to_lowercase();

        // CRITICAL: Check for NEW auth success indicators (not present in baseline)
        // This prevents false positives from pages that always show "success", "welcome", etc.
        let new_auth_success =
            (body_lower.contains("authenticated") && !baseline_lower.contains("authenticated")) ||
            (body_lower.contains("logged in") && !baseline_lower.contains("logged in")) ||
            (body_lower.contains("dashboard") && !baseline_lower.contains("dashboard"));

        // Check if privileged value was processed AND is NEW (not in baseline)
        let privileged_accepted = if values[0].to_lowercase().contains("admin") ||
            values[0].to_lowercase() == "true" {
            (body_lower.contains("role\":\"admin") && !baseline_lower.contains("role\":\"admin")) ||
            (body_lower.contains("is_admin\":true") && !baseline_lower.contains("is_admin\":true"))
        } else {
            false
        };

        new_auth_success || privileged_accepted
    }

    /// Detect dangerous reflection (XSS context)
    fn detect_dangerous_reflection(&self, body: &str, value: &str) -> bool {
        // Check if value appears in dangerous contexts
        let dangerous_contexts = vec![
            format!(r#"href="{}""#, value),
            format!(r#"href='{}'"#, value),
            format!(r#"src="{}""#, value),
            format!(r#"action="{}""#, value),
            format!("<script>{}", value),
            format!("javascript:{}", value),
            format!("onclick=\"{}\"", value),
        ];

        for context in &dangerous_contexts {
            if body.contains(context) || body.contains(&context.to_lowercase()) {
                return true;
            }
        }

        // Check for unescaped HTML
        body.contains("<script>") || body.contains("onerror=") || body.contains("onload=")
    }

    /// Detect array processing - REQUIRES baseline comparison
    fn detect_array_processing(&self, body: &str, injected_value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // CRITICAL: Don't just check if value appears - that causes false positives
        // The value must be in a security-relevant context

        // Check for SQL errors (if SQLi was attempted) - this is real evidence
        if injected_value.contains("'") &&
           (body_lower.contains("sql syntax") || body_lower.contains("you have an error in your sql")) {
            return true;
        }

        // Check for admin/privilege indicators in JSON context (structured data)
        if injected_value.contains("admin") {
            // Must be in JSON format to indicate actual privilege escalation
            if body_lower.contains("\"role\":\"admin\"") || body_lower.contains("\"is_admin\":true") {
                return true;
            }
        }

        // Don't report just because the value appears somewhere in the page
        // That's not evidence of a vulnerability
        false
    }

    /// Detect privilege escalation via HPP - REQUIRES baseline comparison
    fn detect_privilege_escalation_hpp(&self, body: &str, baseline_body: &str, privileged_value: &str) -> bool {
        let body_lower = body.to_lowercase();
        let baseline_lower = baseline_body.to_lowercase();
        let value_lower = privileged_value.to_lowercase();

        // CRITICAL: Only detect if the privileged value appears in a NEW context
        // that indicates actual privilege escalation (not just reflection)

        // Check for NEW role/privilege assignment in JSON response
        if value_lower == "admin" {
            // Must be in structured response showing admin role was assigned
            let admin_role_new = body_lower.contains("\"role\":\"admin\"") &&
                                 !baseline_lower.contains("\"role\":\"admin\"");
            let is_admin_new = body_lower.contains("\"is_admin\":true") &&
                              !baseline_lower.contains("\"is_admin\":true");
            let admin_granted_new = body_lower.contains("admin access granted") &&
                                   !baseline_lower.contains("admin access granted");

            if admin_role_new || is_admin_new || admin_granted_new {
                return true;
            }
        }

        // Check for NEW dashboard/admin panel access
        if (body_lower.contains("admin panel") || body_lower.contains("dashboard")) &&
           (!baseline_lower.contains("admin panel") && !baseline_lower.contains("dashboard")) {
            return true;
        }

        false
    }

    /// Detect JSON HPP - requires baseline comparison to avoid false positives
    fn detect_json_hpp(&self, body: &str, baseline_body: &str, payload: &str) -> bool {
        let body_lower = body.to_lowercase();
        let baseline_lower = baseline_body.to_lowercase();

        // Check for prototype pollution indicators - must be NEW (not in baseline)
        if payload.contains("__proto__") {
            let new_admin = body_lower.contains("admin") && !baseline_lower.contains("admin");
            let new_privilege = body_lower.contains("is_admin\":true") && !baseline_lower.contains("is_admin\":true");
            if new_admin || new_privilege {
                return true;
            }
        }

        // Check if duplicate key's second value was used - role must be NEW
        if payload.contains(r#""role":"admin""#) {
            if body_lower.contains("role\":\"admin") && !baseline_lower.contains("role\":\"admin") {
                return true;
            }
        }

        // Don't return true just for "success" being present - that causes tons of false positives!
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
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.1,
            Severity::Info => 0.0,
        };

        Vulnerability {
            id: format!("hpp_{}", generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::Medium,
            category: "HTTP Parameter Pollution".to_string(),
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

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Server-Side HTTP Parameter Pollution" => {
                "1. Use a consistent parameter handling strategy across all frameworks\n\
                 2. Explicitly handle cases where multiple parameters with same name are sent\n\
                 3. Use the first occurrence of a parameter and ignore duplicates\n\
                 4. Validate that each parameter appears only once\n\
                 5. Log and alert on duplicate parameter attempts".to_string()
            }
            "WAF Bypass via HTTP Parameter Pollution" => {
                "1. Configure WAF to normalize and combine duplicate parameters before inspection\n\
                 2. Implement parameter validation at application level as defense-in-depth\n\
                 3. Use strict parameter whitelisting\n\
                 4. Reject requests with duplicate parameters for sensitive endpoints\n\
                 5. Ensure WAF and application use same parameter parsing logic".to_string()
            }
            "Authentication Bypass via HTTP Parameter Pollution" => {
                "1. Never trust client-supplied role/permission parameters\n\
                 2. Validate authentication parameters server-side from trusted sources\n\
                 3. Reject requests with duplicate authentication parameters\n\
                 4. Use session-based authentication instead of parameter-based\n\
                 5. Implement strict input validation on all auth endpoints".to_string()
            }
            "Client-Side HTTP Parameter Pollution" => {
                "1. Properly encode all reflected parameter values\n\
                 2. Use context-aware output encoding (HTML, URL, JavaScript)\n\
                 3. Implement Content Security Policy (CSP)\n\
                 4. Validate and sanitize URL parameters before reflection\n\
                 5. Use allowlists for redirect URLs".to_string()
            }
            "Array Parameter Pollution" => {
                "1. Define explicit array size limits\n\
                 2. Validate array indices are within expected range\n\
                 3. Sanitize array values before processing\n\
                 4. Use typed parameters instead of string arrays where possible\n\
                 5. Implement schema validation for complex parameters".to_string()
            }
            "JSON Parameter Pollution" => {
                "1. Use a JSON parser that rejects duplicate keys\n\
                 2. Implement strict schema validation for JSON inputs\n\
                 3. Freeze objects to prevent prototype pollution\n\
                 4. Use Object.create(null) for dictionaries\n\
                 5. Sanitize JSON input before parsing".to_string()
            }
            _ => {
                "1. Implement strict parameter validation\n\
                 2. Reject requests with duplicate parameters\n\
                 3. Use consistent parameter handling across the application\n\
                 4. Log and monitor for parameter pollution attempts".to_string()
            }
        }
    }
}

/// Generate a simple UUID
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> HttpParameterPollutionScanner {
        let client = Arc::new(HttpClient::new(30000, 3).unwrap());
        HttpParameterPollutionScanner::new(client)
    }

    #[test]
    fn test_detect_value_accepted() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_value_accepted(r#"{"role":"admin"}"#, "admin"));
        assert!(scanner.detect_value_accepted("User: ADMIN logged in", "admin"));
        assert!(!scanner.detect_value_accepted("Access denied", "admin"));
    }

    #[test]
    fn test_detect_dangerous_reflection() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_dangerous_reflection(r#"<a href="javascript:alert(1)">Click</a>"#, "javascript:alert(1)"));
        assert!(scanner.detect_dangerous_reflection("<script>alert(1)</script>", "alert(1)"));
        assert!(!scanner.detect_dangerous_reflection("Safe content", "malicious"));
    }

    #[test]
    fn test_hpp_detection() {
        let scanner = create_test_scanner();

        // Test significant difference detection
        let baseline = "Short response";
        let polluted = "This is a much longer response with additional content that indicates different processing";

        assert!(scanner.detect_hpp_behavior(baseline, polluted, "test", &["val1", "val2"]));
    }

    #[test]
    fn test_waf_bypass_detection() {
        let scanner = create_test_scanner();

        // SQL error indicates bypass - must be NEW (not in baseline)
        assert!(scanner.detect_waf_bypass(
            "You have an error in your SQL syntax near...",
            "Normal page content",  // baseline without SQL error
            &["' OR", " '1'='1"]
        ));

        // Blocked by WAF - no vulnerability indicators
        assert!(!scanner.detect_waf_bypass(
            "Request blocked by firewall",
            "Normal page content",
            &["' OR", " '1'='1"]
        ));

        // SQL error already in baseline - not a NEW finding
        assert!(!scanner.detect_waf_bypass(
            "You have an error in your SQL syntax",
            "You have an error in your SQL syntax",  // same in baseline
            &["' OR", " '1'='1"]
        ));
    }

    #[test]
    fn test_no_false_positives_for_normal_arrays() {
        let scanner = create_test_scanner();

        // Normal API response should not be flagged as vulnerability
        assert!(!scanner.detect_array_processing(
            r#"{"items": ["item1", "item2"], "success": true}"#,
            "item2"
        ));

        // Comma-separated values in normal response - not a vuln
        assert!(!scanner.detect_privilege_escalation_hpp(
            r#"{"fields": "id,name,email"}"#,
            r#"{"fields": "id,name,email"}"#,
            "admin"
        ));
    }
}
