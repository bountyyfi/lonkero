// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Prototype Pollution Scanner
 * Tests for JavaScript prototype pollution vulnerabilities
 *
 * Detects:
 * - Query parameter prototype pollution (__proto__, constructor.prototype)
 * - JSON body prototype pollution
 * - Merge/deep copy vulnerabilities
 * - Object property injection
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct PrototypePollutionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl PrototypePollutionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("pp_{}", Self::generate_id());
        Self {
            http_client,
            test_marker,
        }
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }

    /// Scan for prototype pollution vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
        }

        info!("[ProtoPollution] Scanning for prototype pollution vulnerabilities");

        // Intelligent detection - prototype pollution is JS-specific
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            // Only skip if NOT a JS app AND static
            if !characteristics.is_spa && characteristics.should_skip_injection_tests() {
                info!("[ProtoPollution] Skipping - not a JavaScript application");
                return Ok((Vec::new(), 0));
            }
        }

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test 1: Query parameter pollution
        let (vulns, tests) = self.test_query_param_pollution(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 2: JSON body pollution
        let (vulns, tests) = self.test_json_body_pollution(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 3: Path-based pollution
        let (vulns, tests) = self.test_path_pollution(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 4: Form parameter pollution
        let (vulns, tests) = self.test_form_pollution(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "[ProtoPollution] Completed {} tests, found {} vulnerabilities",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test prototype pollution via query parameters
    async fn test_query_param_pollution(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Comprehensive prototype pollution payloads
        let marker = &self.test_marker;
        let payloads: Vec<(&str, &str, &str)> = vec![
            // __proto__ variants
            ("__proto__[polluted]", marker.as_str(), "proto_bracket"),
            ("__proto__.polluted", marker.as_str(), "proto_dot"),
            ("__proto__[toString]", "polluted", "proto_tostring"),
            ("__proto__[constructor]", "polluted", "proto_constructor"),

            // constructor.prototype variants
            ("constructor[prototype][polluted]", marker.as_str(), "constructor_bracket"),
            ("constructor.prototype.polluted", marker.as_str(), "constructor_dot"),

            // Nested pollution
            ("a].__proto__[polluted", marker.as_str(), "nested_proto"),
            ("a[__proto__][polluted]", marker.as_str(), "array_proto"),

            // URL encoded variants
            ("__proto__%5Bpolluted%5D", marker.as_str(), "encoded_bracket"),

            // Null byte injection
            ("__proto__\x00[polluted]", marker.as_str(), "null_byte"),
        ];

        for (param, value, payload_type) in &payloads {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            debug!("Testing query param pollution: {}", payload_type);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        response.status_code,
                        &test_url,
                        &format!("{}={}", param, value),
                        payload_type,
                        "Query Parameter",
                    ) {
                        vulnerabilities.push(vuln);
                        // Don't break - test all variants for comprehensive coverage
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test prototype pollution via JSON body
    async fn test_json_body_pollution(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test common API endpoints
        let api_endpoints = vec![
            format!("{}/api", url.trim_end_matches('/')),
            format!("{}/api/v1", url.trim_end_matches('/')),
            format!("{}/graphql", url.trim_end_matches('/')),
            url.to_string(),
        ];

        let json_payloads = vec![
            // Standard __proto__ pollution
            (
                format!(r#"{{"__proto__": {{"polluted": "{}"}}}}"#, self.test_marker),
                "json_proto_object",
            ),
            // Nested pollution
            (
                format!(r#"{{"user": {{"__proto__": {{"isAdmin": true, "marker": "{}"}}}}}}"#, self.test_marker),
                "json_nested_proto",
            ),
            // Constructor pollution
            (
                format!(r#"{{"constructor": {{"prototype": {{"polluted": "{}"}}}}}}"#, self.test_marker),
                "json_constructor",
            ),
            // Array prototype pollution
            (
                format!(r#"[{{"__proto__": {{"polluted": "{}"}}}}]"#, self.test_marker),
                "json_array_proto",
            ),
            // Deep nested pollution (common in lodash merge)
            (
                format!(r#"{{"a": {{"b": {{"__proto__": {{"polluted": "{}"}}}}}}}}"#, self.test_marker),
                "json_deep_proto",
            ),
        ];

        for endpoint in &api_endpoints {
            for (payload, payload_type) in &json_payloads {
                tests_run += 1;

                let headers = vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                ];

                debug!("Testing JSON pollution at {} with {}", endpoint, payload_type);

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        if let Some(vuln) = self.analyze_response(
                            &response.body,
                            response.status_code,
                            endpoint,
                            payload,
                            payload_type,
                            "JSON Body",
                        ) {
                            vulnerabilities.push(vuln);
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test prototype pollution via URL path
    async fn test_path_pollution(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base_url = url.trim_end_matches('/');

        let path_payloads = vec![
            ("/__proto__/polluted", "path_proto"),
            ("/constructor/prototype/polluted", "path_constructor"),
            ("/__proto__", "path_proto_root"),
        ];

        for (path, payload_type) in &path_payloads {
            tests_run += 1;
            let test_url = format!("{}{}", base_url, path);

            debug!("Testing path pollution: {}", payload_type);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Path pollution typically causes 500 errors or unusual behavior
                    if response.status_code == 500 {
                        let body_lower = response.body.to_lowercase();
                        if body_lower.contains("prototype")
                            || body_lower.contains("__proto__")
                            || body_lower.contains("cannot read property")
                            || body_lower.contains("undefined is not")
                        {
                            vulnerabilities.push(self.create_vulnerability(
                                &test_url,
                                path,
                                payload_type,
                                "URL Path",
                                Confidence::Medium,
                                "Server error with prototype-related message when accessing __proto__ path",
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test prototype pollution via form parameters
    async fn test_form_pollution(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let form_payloads = vec![
            (
                format!("__proto__[polluted]={}", self.test_marker),
                "form_proto_bracket",
            ),
            (
                format!("constructor[prototype][polluted]={}", self.test_marker),
                "form_constructor",
            ),
            (
                format!("data[__proto__][polluted]={}", self.test_marker),
                "form_nested_proto",
            ),
        ];

        for (payload, payload_type) in &form_payloads {
            tests_run += 1;

            let headers = vec![
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ];

            debug!("Testing form pollution: {}", payload_type);

            match self.http_client.post_with_headers(url, payload, headers).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        response.status_code,
                        url,
                        payload,
                        payload_type,
                        "Form Body",
                    ) {
                        vulnerabilities.push(vuln);
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Analyze response for prototype pollution indicators
    fn analyze_response(
        &self,
        body: &str,
        status_code: u16,
        url: &str,
        payload: &str,
        payload_type: &str,
        injection_point: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Check for our marker in response (strong indicator)
        if body.contains(&self.test_marker) {
            return Some(self.create_vulnerability(
                url,
                payload,
                payload_type,
                injection_point,
                Confidence::High,
                &format!("Test marker '{}' reflected in response - prototype pollution confirmed", self.test_marker),
            ));
        }

        // Check for server error with prototype-related messages
        if status_code == 500 {
            let error_indicators = [
                "prototype",
                "__proto__",
                "cannot read property",
                "undefined is not",
                "typeerror",
                "object.prototype",
                "constructor.prototype",
                "polluted",
            ];

            for indicator in &error_indicators {
                if body_lower.contains(indicator) {
                    return Some(self.create_vulnerability(
                        url,
                        payload,
                        payload_type,
                        injection_point,
                        Confidence::Medium,
                        &format!("Server error with '{}' in message when processing prototype pollution payload", indicator),
                    ));
                }
            }
        }

        // Check for behavior change indicators (weaker signal)
        if status_code == 200 {
            // Check if "polluted" or "isAdmin" appears in response (may indicate successful pollution)
            if body_lower.contains("\"polluted\"") || body_lower.contains("\"isadmin\":true") {
                return Some(self.create_vulnerability(
                    url,
                    payload,
                    payload_type,
                    injection_point,
                    Confidence::Medium,
                    "Pollution payload key appeared in response - possible prototype pollution",
                ));
            }
        }

        None
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        payload: &str,
        payload_type: &str,
        injection_point: &str,
        confidence: Confidence,
        evidence: &str,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);
        Vulnerability {
            id: format!("prototype_pollution_{}", Self::generate_id()),
            vuln_type: "Prototype Pollution".to_string(),
            severity: Severity::High,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(injection_point.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Prototype pollution vulnerability detected via {}.\n\n\
                Payload type: {}\n\n\
                Prototype pollution allows attackers to:\n\
                - Modify Object.prototype affecting all objects\n\
                - Bypass security checks (isAdmin, isAuthenticated)\n\
                - Achieve Remote Code Execution (via gadget chains)\n\
                - Cause Denial of Service\n\
                - Pollute application state globally",
                injection_point, payload_type
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-1321".to_string(), // Improperly Controlled Modification of Object Prototype Attributes
            cvss: 8.6,
            verified,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Input Validation**
   - Block keys containing '__proto__', 'constructor', 'prototype'
   - Validate JSON/object keys before processing

2. **Use Safe Object Operations**
   ```javascript
   // BAD: Vulnerable to pollution
   Object.assign({}, userInput);
   _.merge({}, userInput);

   // GOOD: Safe alternatives
   Object.assign(Object.create(null), userInput);
   structuredClone(userInput);
   ```

3. **Freeze Prototypes**
   ```javascript
   Object.freeze(Object.prototype);
   Object.freeze(Array.prototype);
   ```

4. **Use Map Instead of Object**
   ```javascript
   // For dynamic keys, use Map
   const data = new Map();
   data.set(userKey, userValue);
   ```

5. **Update Dependencies**
   - Update lodash (< 4.17.12 vulnerable)
   - Update qs (< 6.9.6 vulnerable)
   - Update merge-deep, deep-extend, etc.

6. **Use Schema Validation**
   ```javascript
   const Joi = require('joi');
   const schema = Joi.object({
     name: Joi.string().required(),
     email: Joi.string().email()
   }).unknown(false); // Reject unknown keys
   ```

References:
- https://portswigger.net/web-security/prototype-pollution
- https://github.com/nicolo-ribaudo/JSON.parseImmutable"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> PrototypePollutionScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        PrototypePollutionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_response_marker_found() {
        let scanner = create_test_scanner();
        let marker = scanner.test_marker.clone();

        let result = scanner.analyze_response(
            &format!("Response contains {} value", marker),
            200,
            "http://example.com",
            "__proto__[test]=value",
            "proto_bracket",
            "Query Parameter",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.confidence, Confidence::High);
    }

    #[test]
    fn test_analyze_response_error() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_response(
            "TypeError: Cannot read property 'x' of undefined",
            500,
            "http://example.com",
            "__proto__[test]=value",
            "proto_bracket",
            "Query Parameter",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.confidence, Confidence::Medium);
    }

    #[test]
    fn test_analyze_response_safe() {
        let scanner = create_test_scanner();

        let result = scanner.analyze_response(
            "Normal response body",
            200,
            "http://example.com",
            "__proto__[test]=value",
            "proto_bracket",
            "Query Parameter",
        );

        assert!(result.is_none());
    }
}
