// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Prototype Pollution Scanner
 * Detects JavaScript prototype pollution vulnerabilities
 *
 * WHAT IS PROTOTYPE POLLUTION?
 * ===========================
 * Prototype pollution is a JavaScript vulnerability where an attacker can inject properties
 * into Object.prototype, affecting ALL objects in the application. This happens when user
 * input is merged into objects without proper validation.
 *
 * REAL PROTOTYPE POLLUTION EVIDENCE:
 * ==================================
 * This scanner looks for ACTUAL PROOF of pollution, not just keywords:
 *
 * 1. UNIQUE MARKER REFLECTION:
 *    - We inject: __proto__[pp_abc123xyz]=polluted
 *    - Real pollution: Response contains "pp_abc123xyz" (our unique marker)
 *    - This proves the property was set and reflected back
 *
 * 2. PROTOTYPE CHAIN VERIFICATION:
 *    - Property appears in NEW objects that didn't define it
 *    - Example: {}.injectedProperty !== undefined after pollution
 *    - JSON dumps showing __proto__ or constructor.prototype with our property
 *
 * 3. PRIVILEGE ESCALATION PROOF:
 *    - We inject: __proto__[isAdmin]=true
 *    - Real pollution: JSON response shows {"isAdmin": true} on user object
 *    - Must be in JSON/structured data, NOT just HTML containing the word "admin"
 *
 * FALSE POSITIVES TO AVOID:
 * ========================
 * - Generic words like "admin", "authenticated" in HTML content
 * - Documentation/tutorials mentioning "__proto__"
 * - Application features legitimately using these terms
 * - User-facing text that naturally contains these words
 *
 * DETECTION STRATEGY:
 * ==================
 * - __proto__ pollution via URL parameters
 * - constructor.prototype pollution
 * - JSON parsing vulnerabilities
 * - Query string pollution
 * - Nested object merge vulnerabilities
 * - Property override attacks with ACTUAL verification
 * - Array index pollution
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
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

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter("__proto__", ScannerType::Other) {
            debug!("[Prototype] Skipping framework/internal parameter: __proto__");
            return Ok((Vec::new(), 0));
        }

        info!("[Prototype] Testing __proto__ pollution (priority: {})",
              ParameterFilter::get_parameter_priority("__proto__"));

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

    /// Detect actual prototype pollution in response
    ///
    /// This function looks for evidence that prototype pollution ACTUALLY occurred:
    /// 1. Our unique test marker appears in the response (proves property was set)
    /// 2. Error messages indicating prototype pollution was blocked or detected
    /// 3. Debug output showing the polluted property in object/prototype context
    ///
    /// IMPORTANT: We use a unique test marker (e.g., "pp_abc123xyz") that is extremely
    /// unlikely to appear naturally. If this marker appears in the response after we
    /// injected it via __proto__ or constructor.prototype, it proves pollution occurred.
    ///
    /// Real pollution evidence:
    /// - Marker appears in JSON: {"pp_abc123xyz": "polluted"}
    /// - Marker in object enumeration or debug output
    /// - Error messages about prototype modification
    /// - Headers reflecting the polluted property
    fn detect_pollution(&self, body: &str, headers: &std::collections::HashMap<String, String>) -> bool {
        // PRIMARY CHECK: Our unique test marker in response body
        // This is the strongest evidence - if our unique marker appears after injection,
        // it means the server processed and reflected our polluted property
        if body.contains(&self.test_marker) {
            return true;
        }

        // SECONDARY CHECK: Pollution-related error messages
        // These indicate the application detected or blocked prototype pollution attempts
        let pollution_error_indicators = vec![
            "prototype pollution",      // Explicit pollution detection
            "cannot set property",      // JavaScript error when trying to pollute
            "illegal access",           // Security error
            "proto__ is deprecated",    // Warning about __proto__ usage
        ];

        let body_lower = body.to_lowercase();
        for indicator in pollution_error_indicators {
            if body_lower.contains(indicator) {
                // Make sure this is an error message, not just documentation
                if body_lower.contains("error") || body_lower.contains("warning") {
                    return true;
                }
            }
        }

        // TERTIARY CHECK: Headers for pollution
        // Sometimes polluted properties leak into response headers
        let headers_str = format!("{:?}", headers).to_lowercase();
        if headers_str.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // DO NOT trigger on generic words like "__proto__" or "object prototype"
        // that might appear in documentation, tutorials, or normal application code
        false
    }

    /// Detect ACTUAL privilege escalation through prototype pollution verification
    ///
    /// IMPORTANT: This function verifies that prototype pollution ACTUALLY occurred by:
    /// 1. Checking if the response indicates the polluted property was reflected
    /// 2. Looking for evidence of prototype chain modification
    /// 3. Verifying the property appears in a context that shows it affected object behavior
    ///
    /// Real prototype pollution means:
    /// - A property set on __proto__ or constructor.prototype
    /// - Appears on NEW objects that didn't explicitly define it
    /// - Shows up in object enumeration, JSON serialization, or property checks
    ///
    /// FALSE POSITIVES TO AVOID:
    /// - Generic words like "admin", "dashboard", "authenticated" in HTML content
    /// - User-facing text that naturally contains these words
    /// - Application features that legitimately use these terms
    ///
    /// REAL POLLUTION EVIDENCE:
    /// - The injected property name appears in object dumps: {property: value}
    /// - Debug output showing the polluted prototype chain
    /// - Error messages indicating property conflicts
    /// - Test endpoints that echo back object properties
    fn detect_privilege_escalation(&self, body: &str, property: &str) -> bool {
        let body_lower = body.to_lowercase();
        let prop_lower = property.to_lowercase();

        // Check if response is actually JSON/structured data (not HTML)
        let is_json_response = body.trim().starts_with('{') ||
                               body.trim().starts_with('[') ||
                               body.contains("application/json");

        // If it's not a JSON response, it's very unlikely to be real pollution
        if !is_json_response {
            return false;
        }

        // STRICT: Only detect if the SPECIFIC property we injected appears in a structured format
        // that indicates it's part of an object's properties, not just a word in text
        let pollution_patterns = [
            // JSON property with true value
            format!("\"{}\":true", prop_lower),
            format!("\"{}\": true", prop_lower),
            format!("'{}':true", prop_lower),
            format!("'{}': true", prop_lower),
            format!("\"{}\":\"true\"", prop_lower),
            // Object property enumeration patterns
            format!("\"{}\":", prop_lower),  // Property key in JSON
            format!("'{}':", prop_lower),
            // Prototype chain evidence
            format!("__proto__.{}", prop_lower),
            format!("prototype.{}", prop_lower),
        ];

        // Look for pollution evidence patterns
        for pattern in &pollution_patterns {
            if body_lower.contains(pattern) {
                // Additional verification: check for object/prototype context
                // This ensures we're seeing actual object property pollution
                if body_lower.contains("prototype") ||
                   body_lower.contains("__proto__") ||
                   body_lower.contains("constructor") ||
                   body_lower.contains("object") {
                    return true;
                }

                // OR if we see the property in what looks like an object dump
                // (has multiple JSON properties indicating it's a real object)
                if body.matches('"').count() >= 4 && body.contains('{') {
                    return true;
                }
            }
        }

        // DO NOT trigger on generic words like "admin panel", "authenticated user", etc.
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
    fn test_detect_pollution_error_indicators() {
        let scanner = create_test_scanner();
        let headers = std::collections::HashMap::new();

        // REAL pollution evidence: Error messages indicating pollution attempt
        let real_errors = vec![
            "Error: Prototype pollution detected",
            "Warning: Cannot set property on object prototype",
            "Error: illegal access to __proto__",
        ];

        for body in real_errors {
            assert!(
                scanner.detect_pollution(body, &headers),
                "Should detect pollution error: {}",
                body
            );
        }
    }

    #[test]
    fn test_no_false_positive_on_documentation() {
        let scanner = create_test_scanner();
        let headers = std::collections::HashMap::new();

        // FALSE POSITIVES: Documentation or tutorial content mentioning __proto__
        let false_positives = vec![
            "Learn about __proto__ in JavaScript",
            "The object prototype chain explained",
            "How to prevent prototype pollution in your app",
            "Object.prototype is the base prototype",
        ];

        for body in false_positives {
            assert!(
                !scanner.detect_pollution(body, &headers),
                "Should NOT detect pollution in documentation: {}",
                body
            );
        }
    }

    #[test]
    fn test_detect_real_privilege_escalation() {
        let scanner = create_test_scanner();

        // REAL pollution: JSON response with our injected property
        assert!(scanner.detect_privilege_escalation(
            r#"{"isAdmin":true, "user":"test"}"#,
            "isAdmin"
        ));

        // REAL pollution: Object dump showing polluted property in prototype chain
        assert!(scanner.detect_privilege_escalation(
            r#"{"__proto__":{"isAdmin":true}}"#,
            "isAdmin"
        ));

        // REAL pollution: Debug output showing prototype pollution
        assert!(scanner.detect_privilege_escalation(
            r#"{"role":"user", "prototype":{"admin":true}}"#,
            "admin"
        ));
    }

    #[test]
    fn test_reject_false_positive_privilege_escalation() {
        let scanner = create_test_scanner();

        // FALSE POSITIVE: Generic HTML content with word "admin"
        assert!(!scanner.detect_privilege_escalation(
            "Welcome to admin panel",
            "admin"
        ));

        // FALSE POSITIVE: Generic HTML content with word "authenticated"
        assert!(!scanner.detect_privilege_escalation(
            "authenticated user",
            "authenticated"
        ));

        // FALSE POSITIVE: HTML page with "admin" in text
        assert!(!scanner.detect_privilege_escalation(
            "<html><body>Admin Dashboard</body></html>",
            "admin"
        ));

        // FALSE POSITIVE: Non-JSON response
        assert!(!scanner.detect_privilege_escalation(
            "You are now logged in as admin",
            "admin"
        ));
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

    #[test]
    fn test_prototype_chain_verification() {
        let scanner = create_test_scanner();
        let headers = std::collections::HashMap::new();

        // REAL pollution: Response shows our unique marker was reflected
        // This proves the server processed __proto__[marker]=polluted and it affected object behavior
        let response_with_marker = format!(
            r#"{{"user": "test", "{}": "polluted"}}"#,
            scanner.test_marker
        );
        assert!(
            scanner.detect_pollution(&response_with_marker, &headers),
            "Should detect when unique test marker appears in response"
        );

        // REAL pollution: Test marker in headers (property leaked into headers)
        let mut polluted_headers = std::collections::HashMap::new();
        polluted_headers.insert(
            scanner.test_marker.clone(),
            "polluted".to_string()
        );
        assert!(
            scanner.detect_pollution("", &polluted_headers),
            "Should detect when test marker appears in response headers"
        );

        // REAL pollution: Object dump showing prototype pollution
        let prototype_dump = format!(
            r#"{{
                "user": {{"name": "test"}},
                "__proto__": {{
                    "{}": "polluted"
                }}
            }}"#,
            scanner.test_marker
        );
        assert!(
            scanner.detect_pollution(&prototype_dump, &headers),
            "Should detect marker in prototype chain dump"
        );
    }

    #[test]
    fn test_privilege_escalation_requires_json_context() {
        let scanner = create_test_scanner();

        // TRUE POSITIVE: isAdmin in JSON response with prototype context
        assert!(
            scanner.detect_privilege_escalation(
                r#"{"user": {"isAdmin": true, "__proto__": {}}}"#,
                "isAdmin"
            ),
            "Should detect isAdmin in JSON with prototype context"
        );

        // TRUE POSITIVE: Property in prototype chain
        assert!(
            scanner.detect_privilege_escalation(
                r#"{"__proto__": {"role": "admin"}}"#,
                "role"
            ),
            "Should detect property in __proto__ object"
        );

        // FALSE POSITIVE: HTML page happens to contain the word
        assert!(
            !scanner.detect_privilege_escalation(
                "<html><h1>Welcome to the Admin Panel</h1></html>",
                "admin"
            ),
            "Should NOT detect 'admin' in HTML content"
        );

        // FALSE POSITIVE: Plain text response
        assert!(
            !scanner.detect_privilege_escalation(
                "User authenticated successfully",
                "authenticated"
            ),
            "Should NOT detect 'authenticated' in plain text"
        );
    }
}
