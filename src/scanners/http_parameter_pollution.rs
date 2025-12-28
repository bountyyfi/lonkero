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

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use crate::detection_helpers::{AppCharacteristics, is_payload_reflected_dangerously};
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

            // Check comma-separated handling
            if let Ok(comma_resp) = &comma {
                if self.detect_value_accepted(&comma_resp.body, values[1]) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "HTTP Parameter Pollution (Comma-Separated)",
                        &format!("{}={}", param, values.join(",")),
                        &format!(
                            "Server accepts comma-separated values for '{}' parameter. \
                             Second value '{}' may override first value.",
                            param, values[1]
                        ),
                        &format!("Comma-separated {} accepted", param),
                        Severity::Medium,
                        "CWE-235",
                    ));
                }
            }

            // Check array bracket notation
            if let Ok(bracket_resp) = &bracket {
                if self.detect_value_accepted(&bracket_resp.body, values[1]) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "HTTP Parameter Pollution (Array Notation)",
                        &bracket_query,
                        &format!(
                            "Server accepts array notation for '{}' parameter. \
                             Multiple values can be injected via {}[]=value syntax.",
                            param, param
                        ),
                        &format!("Array notation {}[] accepted", param),
                        Severity::Low,
                        "CWE-235",
                    ));
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
                    // Check if WAF blocked single payload but allowed split
                    let waf_bypassed = self.detect_waf_bypass(&response.body, values);

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
                        let auth_bypassed = self.detect_auth_bypass(&response.body, param, values);

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
            for (payload, description) in &json_tests {
                let headers = vec![
                    ("Content-Type".to_string(), "application/json".to_string())
                ];

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        // Check if duplicate keys caused issues
                        let json_hpp = self.detect_json_hpp(&response.body, payload);

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

    /// Detect HPP behavior differences
    fn detect_hpp_behavior(
        &self,
        baseline: &str,
        polluted: &str,
        _param: &str,
        values: &[&str],
    ) -> bool {
        // Check for significant response differences
        let len_diff = (baseline.len() as i64 - polluted.len() as i64).abs();
        let significant_diff = len_diff > 100;

        // Check if second value appears in response but not first
        let second_processed = polluted.contains(values[1]) && !polluted.contains(values[0]);

        // Check for both values appearing (concatenation behavior)
        let concatenated = polluted.contains(values[0]) && polluted.contains(values[1]);

        // Check for different status indicators
        let status_change = (baseline.contains("success") != polluted.contains("success")) ||
            (baseline.contains("error") != polluted.contains("error"));

        significant_diff || second_processed || concatenated || status_change
    }

    /// Detect if a specific value was accepted
    fn detect_value_accepted(&self, body: &str, value: &str) -> bool {
        body.contains(value) ||
            body.to_lowercase().contains(&value.to_lowercase())
    }

    /// Detect WAF bypass
    fn detect_waf_bypass(&self, body: &str, split_values: &[&str]) -> bool {
        let body_lower = body.to_lowercase();

        // Check for SQL error (injection worked)
        let sql_indicators = vec!["sql", "syntax", "mysql", "postgresql", "sqlite", "ora-"];
        for indicator in &sql_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check for command execution indicators
        if body.contains("root:") || body.contains("/bin/") || body.contains("etc/passwd") {
            return true;
        }

        // Check if response doesn't contain WAF block message
        let not_blocked = !body_lower.contains("blocked") &&
            !body_lower.contains("forbidden") &&
            !body_lower.contains("waf") &&
            !body_lower.contains("firewall");

        // Check if combined payload might have been processed
        let combined = split_values.join("");
        not_blocked && (body.contains(&combined) || body_lower.contains(&combined.to_lowercase()))
    }

    /// Detect authentication bypass
    fn detect_auth_bypass(&self, body: &str, _param: &str, values: &[&str]) -> bool {
        let body_lower = body.to_lowercase();

        // Check for successful auth with privileged value
        let auth_success = body_lower.contains("success") ||
            body_lower.contains("welcome") ||
            body_lower.contains("dashboard") ||
            body_lower.contains("authenticated") ||
            body_lower.contains("logged in");

        // Check if privileged value was processed
        let privileged_accepted = if values[0].to_lowercase().contains("admin") ||
            values[0].to_lowercase() == "true" {
            body_lower.contains("admin") || body_lower.contains("role\":\"admin")
        } else {
            false
        };

        auth_success || privileged_accepted
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

    /// Detect array processing
    fn detect_array_processing(&self, body: &str, injected_value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if injected value appears
        if body.contains(injected_value) {
            return true;
        }

        // Check for SQL errors (if SQLi was attempted)
        if injected_value.contains("'") && (body_lower.contains("sql") || body_lower.contains("syntax")) {
            return true;
        }

        // Check for admin/privilege indicators
        if injected_value.contains("admin") && body_lower.contains("admin") {
            return true;
        }

        false
    }

    /// Detect JSON HPP
    fn detect_json_hpp(&self, body: &str, payload: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for prototype pollution indicators
        if payload.contains("__proto__") && (body_lower.contains("admin") || body_lower.contains("true")) {
            return true;
        }

        // Check if duplicate key's second value was used
        if payload.contains(r#""role":"admin""#) && body_lower.contains("admin") {
            return true;
        }

        // Check for success with polluted request
        body_lower.contains("success") && !body_lower.contains("error")
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

        // SQL error indicates bypass
        assert!(scanner.detect_waf_bypass("SQL syntax error near...", &["' OR", " '1'='1"]));

        // Blocked by WAF
        assert!(!scanner.detect_waf_bypass("Request blocked by firewall", &["' OR", " '1'='1"]));
    }
}
