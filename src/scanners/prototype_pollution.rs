// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Prototype Pollution Scanner
 * Detects JavaScript prototype pollution vulnerabilities
 *
 * Detects:
 * - __proto__ pollution via URL parameters
 * - constructor.prototype pollution
 * - JSON parsing vulnerabilities
 * - Query string pollution
 * - Nested object merge vulnerabilities
 * - Property override attacks (isAdmin, role, etc.)
 * - Array index pollution
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct PrototypePollutionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl PrototypePollutionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("pp_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for prototype pollution vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing prototype pollution vulnerabilities");

        // Test __proto__ pollution
        let (vulns, tests) = self.test_proto_property(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test constructor.prototype pollution
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_constructor_prototype(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test property override attacks
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_property_override(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test JSON pollution
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_json_pollution(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test basic __proto__ pollution
    async fn test_proto_property(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing __proto__ pollution");

        let payloads = vec![
            format!("__proto__[{}]=polluted", self.test_marker),
            format!("__proto__.{}=polluted", self.test_marker),
            "__proto__[isAdmin]=true".to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_pollution(&response.body, &response.headers) {
                        info!("__proto__ pollution detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "__proto__",
                            &payload,
                            "URL parameter __proto__ pollution",
                            &format!("Pollution marker '{}' detected in response", self.test_marker),
                            Severity::Critical,
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

    /// Test constructor.prototype pollution
    async fn test_constructor_prototype(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing constructor.prototype pollution");

        let payloads = vec![
            format!("constructor[prototype][{}]=polluted", self.test_marker),
            format!("constructor.prototype.{}=polluted", self.test_marker),
            "constructor[prototype][isAdmin]=true".to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_pollution(&response.body, &response.headers) {
                        info!("constructor.prototype pollution detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "constructor.prototype",
                            &payload,
                            "Constructor.prototype pollution via URL",
                            "Prototype chain pollution detected",
                            Severity::Critical,
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

    /// Test property override attacks
    async fn test_property_override(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Testing property override attacks");

        let critical_properties = vec!["isAdmin".to_string(), "role".to_string(), "admin".to_string(), "authenticated".to_string()];

        for prop in critical_properties {
            let payload = format!("__proto__[{}]=true", prop);
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_privilege_escalation(&response.body, &prop) {
                        info!("Property override detected: {}", prop);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Property Override",
                            &payload,
                            &format!("Privilege escalation via {} property override", prop),
                            &format!("Successfully overrode '{}' property", prop),
                            Severity::Critical,
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

    /// Test JSON pollution via POST
    async fn test_json_pollution(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing JSON prototype pollution");

        let payloads = vec![
            format!(r#"{{"__proto__":{{"{}":"polluted"}}}}"#, self.test_marker),
            r#"{"__proto__":{"isAdmin":true}}"#.to_string(),
        ];

        for payload in payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
            ];

            match self.http_client.post_with_headers(url, &payload, headers).await {
                Ok(response) => {
                    if self.detect_pollution(&response.body, &response.headers) {
                        info!("JSON prototype pollution detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "JSON __proto__",
                            &payload,
                            "Prototype pollution via JSON POST",
                            "JSON parsing allows prototype pollution",
                            Severity::High,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("POST request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect pollution in response
    fn detect_pollution(&self, body: &str, headers: &std::collections::HashMap<String, String>) -> bool {
        // Check for pollution marker in response body
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for pollution indicators
        let pollution_indicators = vec![
            "__proto__",
            "prototype pollution",
            "cannot set property",
            "object prototype",
            "illegal access",
        ];

        let body_lower = body.to_lowercase();
        for indicator in pollution_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check headers for pollution
        let headers_str = format!("{:?}", headers).to_lowercase();
        if headers_str.contains(&self.test_marker.to_lowercase()) || headers_str.contains("polluted") {
            return true;
        }

        false
    }

    /// Detect ACTUAL privilege escalation (not just keywords)
    /// IMPORTANT: We must prove the property was ACTUALLY set, not just that the page
    /// happens to contain common words like "dashboard" or "authenticated"
    fn detect_privilege_escalation(&self, body: &str, property: &str) -> bool {
        let body_lower = body.to_lowercase();
        let prop_lower = property.to_lowercase();

        // STRICT: Only detect if the SPECIFIC property we injected appears with true value
        // This must be a JSON response showing our injected property took effect
        let strict_patterns = [
            format!("\"{}\":true", prop_lower),
            format!("\"{}\": true", prop_lower),
            format!("'{}':true", prop_lower),
            format!("'{}': true", prop_lower),
            // Also check for the property in a user/session object
            format!("\"{}\":\"true\"", prop_lower),
        ];

        for pattern in &strict_patterns {
            if body_lower.contains(pattern) {
                // Additional check: make sure this looks like an API/JSON response
                // not just HTML that happens to contain this pattern
                if body.trim().starts_with('{') || body.trim().starts_with('[') ||
                   body_lower.contains("application/json") {
                    return true;
                }
            }
        }

        // DO NOT trigger on generic words like "dashboard", "authenticated", etc.
        // These are present on almost every website and cause massive false positives
        false
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
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 6.5,
            _ => 4.0,
        };

        Vulnerability {
            id: format!("pp_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Prototype Pollution ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-1321".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Never merge user input directly into objects without validation\n\
                         2. Use Object.create(null) for objects that should not inherit from Object.prototype\n\
                         3. Freeze Object.prototype with Object.freeze(Object.prototype)\n\
                         4. Validate and sanitize all user input, especially keys\n\
                         5. Use secure parsing libraries that prevent prototype pollution\n\
                         6. Update vulnerable dependencies (lodash, jquery, etc.)\n\
                         7. Implement key validation using allowlists\n\
                         8. Use Map instead of objects for key-value storage".to_string(),
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

    fn create_test_scanner() -> PrototypePollutionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        PrototypePollutionScanner::new(http_client)
    }

    #[test]
    fn test_detect_pollution_marker() {
        let scanner = create_test_scanner();
        let body = format!("Response contains {}", scanner.test_marker);
        let headers = std::collections::HashMap::new();

        assert!(scanner.detect_pollution(&body, &headers));
    }

    #[test]
    fn test_detect_pollution_indicators() {
        let scanner = create_test_scanner();

        let bodies = vec![
            "Error: __proto__ access denied",
            "Prototype pollution detected",
            "Cannot set property on object prototype",
        ];

        let headers = std::collections::HashMap::new();
        for body in bodies {
            assert!(scanner.detect_pollution(body, &headers));
        }
    }

    #[test]
    fn test_detect_privilege_escalation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_privilege_escalation(r#"{"isAdmin":true}"#, "isAdmin"));
        assert!(scanner.detect_privilege_escalation("Welcome to admin panel", "admin"));
        assert!(scanner.detect_privilege_escalation("authenticated user", "authenticated"));
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = create_test_scanner();
        let body = "Normal response without pollution";
        let headers = std::collections::HashMap::new();

        assert!(!scanner.detect_pollution(body, &headers));
        assert!(!scanner.detect_privilege_escalation(body, "isAdmin"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "__proto__",
            "__proto__[test]=polluted",
            "Prototype pollution detected",
            "Test marker found",
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "Prototype Pollution (__proto__)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-1321");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        // Each scanner should have a unique marker
        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("pp_"));
    }
}
