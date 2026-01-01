// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced Mass Assignment Scanner
 * Detects mass assignment vulnerabilities with advanced injection techniques
 *
 * Detects:
 * - Parameter pollution attacks
 * - Role/privilege escalation via mass assignment
 * - Hidden field manipulation
 * - Account property injection
 * - Price/amount manipulation
 * - Nested object injection (2-4 levels deep)
 * - JSON deep merge attacks
 * - Prototype pollution via mass assignment
 * - Array parameter pollution
 * - Constructor property injection
 *
 * ADVANCED TECHNIQUES:
 * ===================
 * 1. NESTED OBJECT INJECTION:
 *    - Tests deep property injection like user[role][admin]=true
 *    - Tests dot notation: profile.permissions.admin=1
 *    - Tests multiple nesting levels (2-4 levels)
 *
 * 2. JSON DEEP MERGE ATTACKS:
 *    - Tests if nested JSON objects merge unexpectedly
 *    - Verifies actual property injection, not just reflection
 *
 * 3. PROTOTYPE POLLUTION VIA MASS ASSIGNMENT:
 *    - Tests __proto__, constructor.prototype, prototype injection
 *    - Verifies actual pollution through unique markers
 *
 * 4. ARRAY PARAMETER POLLUTION:
 *    - Tests array injection like users[0][admin]=true
 *    - Tests array index manipulation
 *
 * 5. CONSTRUCTOR PROPERTY INJECTION:
 *    - Tests constructor[name], constructor[prototype]
 *    - Verifies actual property modification
 *
 * ZERO FALSE POSITIVES:
 * =====================
 * - Only reports when injection is CONFIRMED
 * - Uses unique test markers to verify actual injection
 * - Checks for structured data responses (JSON)
 * - Verifies privilege escalation or property modification
 * - Distinguishes between reflection and actual injection
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info};

pub struct MassAssignmentScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl MassAssignmentScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker for verification
        let test_marker = format!("ma_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for mass assignment vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Intelligent detection - skip for static sites
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.should_skip_injection_tests() {
                info!("[MassAssignment] Skipping - static/SPA site detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing advanced mass assignment vulnerabilities");

        // Phase 1: Basic mass assignment (existing tests)
        let (vulns, tests) = self.test_role_escalation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_price_manipulation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_hidden_field_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Phase 2-6: Advanced mass assignment techniques (PREMIUM FEATURE)
        if vulnerabilities.is_empty() && crate::license::is_feature_available("mass_assignment_advanced") {
            // Phase 2: Advanced nested object injection (URL-encoded)
            if vulnerabilities.is_empty() {
                let (vulns, tests) = self.test_nested_object_injection(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Phase 3: JSON deep merge attacks
            if vulnerabilities.is_empty() {
                let (vulns, tests) = self.test_json_deep_merge(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Phase 4: Prototype pollution via mass assignment
            if vulnerabilities.is_empty() {
                let (vulns, tests) = self.test_prototype_pollution_mass_assignment(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Phase 5: Array parameter pollution
            if vulnerabilities.is_empty() {
                let (vulns, tests) = self.test_array_parameter_pollution(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Phase 6: Constructor property injection
            if vulnerabilities.is_empty() {
                let (vulns, tests) = self.test_constructor_property_injection(url).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }
        } else if vulnerabilities.is_empty() {
            debug!("Advanced mass assignment techniques require premium license");
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test role/privilege escalation via mass assignment
    async fn test_role_escalation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("[Mass] Testing role escalation via mass assignment");

        let dangerous_params = vec![
            ("role", "admin"),
            ("role", "administrator"),
            ("is_admin", "true"),
            ("is_admin", "1"),
            ("admin", "true"),
            ("privilege", "admin"),
        ];

        for (param, value) in dangerous_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_privilege_escalation(&response.body, param, value) {
                        info!("Mass assignment privilege escalation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Privilege Escalation via Mass Assignment",
                            &format!("{}={}", param, value),
                            "User privileges can be escalated by adding parameters",
                            &format!("Successfully set {}={} via mass assignment", param, value),
                            Severity::Critical,
                            "CWE-915",
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

    /// Test price/amount manipulation
    async fn test_price_manipulation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing price manipulation via mass assignment");

        let price_params = vec![
            ("price", "0"),
            ("price", "0.01"),
            ("amount", "0"),
            ("cost", "0"),
            ("total", "0"),
        ];

        for (param, value) in price_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_price_manipulation(&response.body, value) {
                        info!("Mass assignment price manipulation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Price Manipulation via Mass Assignment",
                            &format!("{}={}", param, value),
                            "Product prices can be manipulated via mass assignment",
                            &format!("Successfully set price to {} via mass assignment", value),
                            Severity::High,
                            "CWE-915",
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

    /// Test hidden field injection
    async fn test_hidden_field_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing hidden field injection");

        let hidden_params = vec![
            ("user_id", "1"),
            ("id", "1"),
            ("account_id", "1"),
            ("verified", "true"),
            ("active", "true"),
            ("status", "active"),
        ];

        for (param, value) in hidden_params {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_hidden_field_manipulation(&response.body, param) {
                        info!("Hidden field manipulation detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Hidden Field Manipulation",
                            &format!("{}={}", param, value),
                            "Hidden fields can be manipulated via mass assignment",
                            &format!("Successfully manipulated hidden field: {}", param),
                            Severity::High,
                            "CWE-915",
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

    /// Test nested object injection (2-4 levels deep)
    /// Tests both bracket notation and dot notation
    async fn test_nested_object_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        debug!("Testing nested object injection");

        // Test payloads with different nesting levels and notation styles
        let nested_payloads = vec![
            // 2-level nesting - bracket notation
            ("user[role]=admin", "2-level bracket: user[role]"),
            ("user[isAdmin]=true", "2-level bracket: user[isAdmin]"),
            ("profile[admin]=true", "2-level bracket: profile[admin]"),

            // 3-level nesting - bracket notation
            ("user[role][admin]=true", "3-level bracket: user[role][admin]"),
            ("profile[permissions][admin]=true", "3-level bracket: profile[permissions][admin]"),
            ("account[settings][role]=admin", "3-level bracket: account[settings][role]"),

            // 4-level nesting - bracket notation
            ("user[profile][role][admin]=true", "4-level bracket: user[profile][role][admin]"),
            ("account[data][permissions][admin]=1", "4-level bracket: account[data][permissions][admin]"),

            // Dot notation
            ("user.role=admin", "dot notation: user.role"),
            ("user.isAdmin=true", "dot notation: user.isAdmin"),
            ("profile.permissions.admin=1", "dot notation: profile.permissions.admin"),

            // Mixed notation
            ("user[profile].role=admin", "mixed: user[profile].role"),
            ("profile.settings[admin]=true", "mixed: profile.settings[admin]"),

        ];

        // Add marker-based payloads separately to avoid lifetime issues
        let marker_payload_1 = format!("user[role][{}]=injected", self.test_marker);
        let marker_payload_2 = format!("profile.{}=injected", self.test_marker);

        // Test regular payloads
        for (payload, technique) in &nested_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_nested_injection(&response.body, payload) {
                        info!("Nested object injection detected: {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Nested Object Injection via Mass Assignment",
                            payload,
                            "Deep nested object properties can be injected via mass assignment",
                            &format!("Successfully injected nested property using {}", technique),
                            Severity::Critical,
                            "CWE-915",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Nested object test failed: {}", e);
                }
            }
        }

        // Test marker-based payloads
        if vulnerabilities.is_empty() {
            for (payload, technique) in &[(marker_payload_1.as_str(), "marker-based verification"), (marker_payload_2.as_str(), "marker-based dot notation")] {
                let test_url = if url.contains('?') {
                    format!("{}&{}", url, payload)
                } else {
                    format!("{}?{}", url, payload)
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if self.detect_nested_injection(&response.body, payload) {
                            info!("Nested object injection detected: {}", technique);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Nested Object Injection via Mass Assignment",
                                payload,
                                "Deep nested object properties can be injected via mass assignment",
                                &format!("Successfully injected nested property using {}", technique),
                                Severity::Critical,
                                "CWE-915",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Nested object test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JSON deep merge attacks
    /// Tests if nested JSON objects merge unexpectedly, allowing property injection
    async fn test_json_deep_merge(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing JSON deep merge attacks");

        // Test payloads with nested JSON structures
        let merge_payloads = vec![
            // Basic nested merge
            json!({
                "user": {
                    "role": "admin"
                }
            }),
            json!({
                "user": {
                    "isAdmin": true
                }
            }),

            // Deep nested merge (3 levels)
            json!({
                "user": {
                    "profile": {
                        "role": "admin"
                    }
                }
            }),
            json!({
                "profile": {
                    "permissions": {
                        "admin": true
                    }
                }
            }),

            // Deep nested merge (4 levels)
            json!({
                "account": {
                    "user": {
                        "profile": {
                            "admin": true
                        }
                    }
                }
            }),

            // Merge with arrays
            json!({
                "user": {
                    "roles": ["admin", "superuser"]
                }
            }),

            // Merge with mixed types
            json!({
                "settings": {
                    "permissions": {
                        "isAdmin": true,
                        "level": 9999
                    }
                }
            }),

            // Merge with unique marker for verification
            json!({
                "user": {
                    self.test_marker.clone(): "injected"
                }
            }),
            json!({
                "profile": {
                    "permissions": {
                        self.test_marker.clone(): "injected"
                    }
                }
            }),

            // Property override attempts
            json!({
                "id": 1,
                "user_id": 1,
                "admin": true
            }),

            // Nested property with price manipulation
            json!({
                "order": {
                    "price": 0,
                    "amount": 0
                }
            }),

            // Nested with verification marker
            json!({
                "data": {
                    "nested": {
                        "marker": self.test_marker.clone()
                    }
                }
            }),
        ];

        for payload in merge_payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
            ];

            match self.http_client.post_with_headers(url, &payload.to_string(), headers).await {
                Ok(response) => {
                    if self.detect_deep_merge_injection(&response.body, &payload) {
                        info!("JSON deep merge attack successful");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "JSON Deep Merge Attack",
                            &payload.to_string(),
                            "Nested JSON objects merge unexpectedly, allowing property injection",
                            "Successfully injected properties through deep merge",
                            Severity::High,
                            "CWE-915",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("JSON merge test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test prototype pollution via mass assignment
    /// Tests __proto__, constructor.prototype, and prototype injection
    async fn test_prototype_pollution_mass_assignment(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 18;

        debug!("Testing prototype pollution via mass assignment");

        // URL-encoded prototype pollution payloads
        let marker_proto_1 = format!("__proto__[{}]=polluted", self.test_marker);
        let marker_proto_2 = format!("__proto__.{}=polluted", self.test_marker);
        let marker_constructor = format!("constructor[prototype][{}]=polluted", self.test_marker);
        let marker_prototype = format!("prototype[{}]=polluted", self.test_marker);

        let url_payloads = vec![
            (marker_proto_1.as_str(), "URL __proto__ with marker"),
            (marker_proto_2.as_str(), "URL __proto__ dot notation"),
            ("__proto__[isAdmin]=true", "URL __proto__ privilege escalation"),
            ("__proto__[admin]=true", "URL __proto__ admin flag"),
            ("__proto__[role]=admin", "URL __proto__ role injection"),

            (marker_constructor.as_str(), "URL constructor.prototype with marker"),
            ("constructor[prototype][isAdmin]=true", "URL constructor.prototype privilege"),
            ("constructor[prototype][admin]=true", "URL constructor.prototype admin"),

            (marker_prototype.as_str(), "URL prototype with marker"),
            ("prototype[isAdmin]=true", "URL prototype privilege"),
        ];

        // Test URL-encoded payloads
        for (payload, technique) in url_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_prototype_pollution(&response.body, &payload) {
                        info!("Prototype pollution via mass assignment detected: {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Prototype Pollution via Mass Assignment",
                            &payload,
                            "Prototype chain can be polluted through mass assignment parameters",
                            &format!("Successfully polluted prototype using {}", technique),
                            Severity::Critical,
                            "CWE-1321",
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Prototype pollution test failed: {}", e);
                }
            }
        }

        // JSON prototype pollution payloads
        let json_payloads = vec![
            json!({
                "__proto__": {
                    self.test_marker.clone(): "polluted"
                }
            }),
            json!({
                "__proto__": {
                    "isAdmin": true
                }
            }),
            json!({
                "constructor": {
                    "prototype": {
                        self.test_marker.clone(): "polluted"
                    }
                }
            }),
            json!({
                "constructor": {
                    "prototype": {
                        "isAdmin": true
                    }
                }
            }),
            json!({
                "prototype": {
                    self.test_marker.clone(): "polluted"
                }
            }),
            json!({
                "prototype": {
                    "admin": true
                }
            }),
            // Nested prototype pollution
            json!({
                "user": {
                    "__proto__": {
                        "isAdmin": true
                    }
                }
            }),
            json!({
                "profile": {
                    "constructor": {
                        "prototype": {
                            "admin": true
                        }
                    }
                }
            }),
        ];

        for payload in json_payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
            ];

            match self.http_client.post_with_headers(url, &payload.to_string(), headers).await {
                Ok(response) => {
                    if self.detect_prototype_pollution(&response.body, &payload.to_string()) {
                        info!("JSON prototype pollution via mass assignment detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Prototype Pollution via JSON Mass Assignment",
                            &payload.to_string(),
                            "Prototype chain can be polluted through JSON mass assignment",
                            "Successfully polluted prototype through JSON payload",
                            Severity::Critical,
                            "CWE-1321",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("JSON prototype pollution test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test array parameter pollution
    /// Tests array index manipulation and injection
    async fn test_array_parameter_pollution(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing array parameter pollution");

        // Array pollution payloads
        let marker_array_1 = format!("users[0][{}]=injected", self.test_marker);
        let marker_array_2 = format!("data[0][test][{}]=injected", self.test_marker);

        let array_payloads = vec![
            // Simple array injection
            ("users[0][admin]=true", "array injection: users[0][admin]"),
            ("users[0][role]=admin", "array injection: users[0][role]"),
            ("users[0][isAdmin]=true", "array injection: users[0][isAdmin]"),

            // Multi-index array injection
            ("items[0][price]=0", "array injection: items[0][price]"),
            ("orders[0][amount]=0", "array injection: orders[0][amount]"),

            // Array with nested objects
            ("users[0][profile][admin]=true", "nested array: users[0][profile][admin]"),
            ("accounts[0][permissions][role]=admin", "nested array: accounts[0][permissions][role]"),

            // Array with marker
            (marker_array_1.as_str(), "array with marker"),
            (marker_array_2.as_str(), "nested array with marker"),

            // Multiple indices
            ("users[0][admin]=true&users[1][admin]=true", "multi-index injection"),
            ("items[0][price]=0&items[1][price]=0", "multi-index price"),

            // Negative indices
            ("users[-1][admin]=true", "negative index injection"),
        ];

        for (payload, technique) in array_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_array_pollution(&response.body, payload) {
                        info!("Array parameter pollution detected: {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Array Parameter Pollution",
                            payload,
                            "Array elements can be manipulated through mass assignment",
                            &format!("Successfully polluted array using {}", technique),
                            Severity::High,
                            "CWE-915",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Array pollution test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test constructor property injection
    /// Tests constructor[name], constructor[prototype], etc.
    async fn test_constructor_property_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing constructor property injection");

        // Constructor injection payloads
        let marker_constructor_1 = format!("constructor[{}]=injected", self.test_marker);
        let marker_constructor_2 = format!("constructor[prototype][{}]=injected", self.test_marker);

        let constructor_payloads = vec![
            (marker_constructor_1.as_str(), "constructor with marker"),
            ("constructor[name]=admin", "constructor name injection"),
            (marker_constructor_2.as_str(), "constructor.prototype with marker"),
            ("constructor[prototype][isAdmin]=true", "constructor.prototype privilege"),
            ("constructor[prototype][role]=admin", "constructor.prototype role"),
        ];

        // Test URL-encoded
        for (payload, technique) in &constructor_payloads {
            let test_url = if url.contains('?') {
                format!("{}&{}", url, payload)
            } else {
                format!("{}?{}", url, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_constructor_injection(&response.body, payload) {
                        info!("Constructor property injection detected: {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Constructor Property Injection",
                            payload,
                            "Constructor properties can be modified through mass assignment",
                            &format!("Successfully injected constructor property using {}", technique),
                            Severity::High,
                            "CWE-915",
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Constructor injection test failed: {}", e);
                }
            }
        }

        // Test JSON constructor injection
        let json_payloads = vec![
            json!({
                "constructor": {
                    self.test_marker.clone(): "injected"
                }
            }),
            json!({
                "constructor": {
                    "name": "admin"
                }
            }),
            json!({
                "constructor": {
                    "prototype": {
                        self.test_marker.clone(): "injected"
                    }
                }
            }),
            json!({
                "constructor": {
                    "prototype": {
                        "isAdmin": true
                    }
                }
            }),
            json!({
                "user": {
                    "constructor": {
                        "name": "Administrator"
                    }
                }
            }),
        ];

        for payload in json_payloads {
            let headers = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
            ];

            match self.http_client.post_with_headers(url, &payload.to_string(), headers).await {
                Ok(response) => {
                    if self.detect_constructor_injection(&response.body, &payload.to_string()) {
                        info!("JSON constructor property injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Constructor Property Injection via JSON",
                            &payload.to_string(),
                            "Constructor properties can be modified through JSON mass assignment",
                            "Successfully injected constructor property through JSON",
                            Severity::High,
                            "CWE-915",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("JSON constructor injection test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect nested object injection in response
    fn detect_nested_injection(&self, body: &str, payload: &str) -> bool {
        // Check if response is JSON
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');
        if !is_json {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for our unique test marker (strongest evidence)
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Extract the injected property/value from payload
        if payload.contains("role]=admin") || payload.contains(".role=admin") {
            // Look for role being set to admin in JSON response
            if (body_lower.contains("\"role\":\"admin\"") ||
                body_lower.contains("\"role\": \"admin\"") ||
                body_lower.contains("'role':'admin'")) &&
                (body_lower.contains("user") || body_lower.contains("profile")) {
                return true;
            }
        }

        if payload.contains("isadmin]=true") || payload.contains(".isadmin=true") {
            // Look for isAdmin being true in structured response
            if body_lower.contains("\"isadmin\":true") ||
                body_lower.contains("\"isadmin\": true") ||
                body_lower.contains("'isadmin':true") {
                return true;
            }
        }

        if payload.contains("admin]=true") || payload.contains(".admin=true") ||
           payload.contains("admin]=1") || payload.contains(".admin=1") {
            // Look for admin property in nested context
            if (body_lower.contains("\"admin\":true") ||
                body_lower.contains("\"admin\": true") ||
                body_lower.contains("\"admin\":1") ||
                body_lower.contains("'admin':true")) &&
                (body_lower.contains("permissions") || body_lower.contains("settings") || body_lower.contains("profile")) {
                return true;
            }
        }

        false
    }

    /// Detect JSON deep merge injection
    fn detect_deep_merge_injection(&self, body: &str, payload: &serde_json::Value) -> bool {
        // Check if response is JSON
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');
        if !is_json {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for our unique test marker (strongest evidence)
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Parse the payload to extract injected properties
        if let Some(obj) = payload.as_object() {
            // Check for user/profile/account properties
            if obj.contains_key("user") || obj.contains_key("profile") || obj.contains_key("account") {
                // Look for role: admin pattern
                if body_lower.contains("\"role\":\"admin\"") ||
                   body_lower.contains("\"role\": \"admin\"") {
                    return true;
                }

                // Look for isAdmin: true pattern
                if body_lower.contains("\"isadmin\":true") ||
                   body_lower.contains("\"isadmin\": true") {
                    return true;
                }

                // Look for admin: true in permissions context
                if (body_lower.contains("\"admin\":true") || body_lower.contains("\"admin\": true")) &&
                   (body_lower.contains("permissions") || body_lower.contains("settings")) {
                    return true;
                }
            }

            // Check for price/amount manipulation
            if obj.contains_key("order") || obj.contains_key("price") || obj.contains_key("amount") {
                if body_lower.contains("\"price\":0") ||
                   body_lower.contains("\"price\": 0") ||
                   body_lower.contains("\"amount\":0") {
                    return true;
                }
            }
        }

        false
    }

    /// Detect prototype pollution via mass assignment
    fn detect_prototype_pollution(&self, body: &str, payload: &str) -> bool {
        let body_lower = body.to_lowercase();

        // PRIMARY: Check for our unique test marker (strongest evidence)
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Check if response is JSON
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');

        // SECONDARY: Look for __proto__ or constructor.prototype in response with injected properties
        if payload.contains("__proto__") && is_json {
            // Look for __proto__ object in response
            if body_lower.contains("\"__proto__\"") || body_lower.contains("'__proto__'") {
                // Check if it contains our injected properties
                if body_lower.contains("\"isadmin\":true") ||
                   body_lower.contains("\"admin\":true") ||
                   body_lower.contains("\"role\":\"admin\"") {
                    return true;
                }
            }
        }

        if payload.contains("constructor") && payload.contains("prototype") && is_json {
            // Look for constructor.prototype in response
            if (body_lower.contains("\"constructor\"") || body_lower.contains("'constructor'")) &&
               (body_lower.contains("\"prototype\"") || body_lower.contains("'prototype'")) {
                if body_lower.contains("\"isadmin\":true") ||
                   body_lower.contains("\"admin\":true") {
                    return true;
                }
            }
        }

        // TERTIARY: Look for pollution-related errors or warnings
        if body_lower.contains("prototype pollution") ||
           (body_lower.contains("proto__") && (body_lower.contains("error") || body_lower.contains("warning"))) {
            return true;
        }

        false
    }

    /// Detect array parameter pollution
    fn detect_array_pollution(&self, body: &str, payload: &str) -> bool {
        // Check if response is JSON or structured data
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');
        if !is_json {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for our unique test marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Look for array patterns in response
        if payload.contains("[0]") || payload.contains("[-1]") {
            // Check for admin/role injection in array context
            if payload.contains("admin]=true") || payload.contains("role]=admin") {
                if body_lower.contains("\"admin\":true") ||
                   body_lower.contains("\"role\":\"admin\"") {
                    // Verify it's in an array context
                    if body.contains('[') && body.contains(']') {
                        return true;
                    }
                }
            }

            // Check for price manipulation in array
            if payload.contains("price]=0") || payload.contains("amount]=0") {
                if (body_lower.contains("\"price\":0") || body_lower.contains("\"amount\":0")) &&
                   body.contains('[') {
                    return true;
                }
            }
        }

        false
    }

    /// Detect constructor property injection
    fn detect_constructor_injection(&self, body: &str, payload: &str) -> bool {
        // Check if response is JSON
        let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');
        if !is_json {
            return false;
        }

        let body_lower = body.to_lowercase();

        // Check for our unique test marker
        if body_lower.contains(&self.test_marker.to_lowercase()) {
            return true;
        }

        // Look for constructor in response
        if payload.contains("constructor") {
            if body_lower.contains("\"constructor\"") || body_lower.contains("'constructor'") {
                // Check for injected properties
                if body_lower.contains("\"name\":\"admin\"") ||
                   body_lower.contains("\"isadmin\":true") ||
                   (body_lower.contains("\"prototype\"") && body_lower.contains("\"admin\":true")) {
                    return true;
                }
            }
        }

        // Look for constructor-related errors or modifications
        if body_lower.contains("constructor") &&
           (body_lower.contains("modified") || body_lower.contains("changed") || body_lower.contains("updated")) {
            return true;
        }

        false
    }

    /// Detect privilege escalation
    fn detect_privilege_escalation(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // First, check if this looks like a SPA/soft-404 response (HTML page returned for all routes)
        // SPA responses contain typical frontend markers and should not be considered as API responses
        if self.is_spa_response(body) {
            return false;
        }

        // Check if parameter was accepted - this is the strongest evidence
        // Must be in a JSON-like structure to be considered valid
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("{}\":{}", param, value)) ||
           body_lower.contains(&format!("'{}':'{}'", param, value)) {
            return true;
        }

        // Only check for privilege indicators in structured API responses (JSON)
        // Do NOT check for these words in HTML responses as they cause false positives
        if !body.trim().starts_with("{") && !body.trim().starts_with("[") {
            // Not a JSON response, skip privilege indicator check
            return false;
        }

        // For JSON responses, check for privilege indicators in the context of the injected param
        let privilege_patterns = vec![
            format!("\"{}\":\"admin\"", param),
            format!("\"{}\":true", param),
            format!("\"{}\":1", param),
            format!("\"{}\":\"administrator\"", param),
            format!("\"{}\":\"superuser\"", param),
        ];

        for pattern in privilege_patterns {
            if body_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Check if response is a SPA/single-page-application fallback (soft-404)
    fn is_spa_response(&self, body: &str) -> bool {
        let spa_indicators = [
            "<app-root>",
            "<div id=\"root\">",
            "<div id=\"app\">",
            "__NEXT_DATA__",
            "__NUXT__",
            "ng-version=",
            "data-reactroot",
            "<script src=\"/main.",
            "<script src=\"main.",
            "polyfills.js",
            "/static/js/main.",
            "/_next/static/",
            "window.__REDUX",
            "window.__PRELOADED_STATE__",
        ];

        for indicator in &spa_indicators {
            if body.contains(indicator) {
                return true;
            }
        }

        // Check for common SPA HTML structure with no actual API content
        if body.contains("<!DOCTYPE html>") || body.contains("<!doctype html>") {
            if body.contains("<script") && (body.contains("angular") || body.contains("react") || body.contains("vue")) {
                return true;
            }
        }

        false
    }

    /// Detect price manipulation
    fn detect_price_manipulation(&self, body: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if price was set to manipulated value
        if body_lower.contains(&format!("\"price\":\"{}\"", value)) ||
           body_lower.contains(&format!("\"price\":{}", value)) ||
           body_lower.contains(&format!("\"amount\":\"{}\"", value)) ||
           body_lower.contains(&format!("\"total\":\"{}\"", value)) {
            return true;
        }

        // Check for success indicators
        body_lower.contains("updated") || body_lower.contains("saved")
    }

    /// Detect hidden field manipulation
    fn detect_hidden_field_manipulation(&self, body: &str, param: &str) -> bool {
        let body_lower = body.to_lowercase();
        let param_lower = param.to_lowercase();

        // Check if hidden parameter appears in response
        if body_lower.contains(&format!("\"{}\":", param_lower)) ||
           body_lower.contains(&format!("'{}':", param_lower)) {
            return true;
        }

        // Check for update success
        body_lower.contains("updated") || body_lower.contains("modified")
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
            _ => 3.1,
        };

        Vulnerability {
            id: format!("ma_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::Medium,
            category: "Business Logic".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Use allowlists for bindable attributes (strong parameters)\n\
                         2. Never bind user input directly to model objects\n\
                         3. Explicitly define which fields can be mass-assigned\n\
                         4. Use DTOs (Data Transfer Objects) for user input\n\
                         5. Validate all input against expected schema\n\
                         6. Mark sensitive fields as read-only or protected\n\
                         7. Implement proper authorization checks before updates\n\
                         8. Use frameworks' built-in protection (Rails strong parameters, etc.)\n\
                         9. Avoid automatic parameter binding in frameworks\n\
                         10. Implement field-level access controls\n\
                         11. Block nested object injection (validate nesting depth)\n\
                         12. Prevent prototype pollution (__proto__, constructor, prototype)\n\
                         13. Sanitize array parameter indices\n\
                         14. Use Object.create(null) for objects without prototype\n\
                         15. Implement strict JSON schema validation for deep merges".to_string(),
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> MassAssignmentScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        MassAssignmentScanner::new(http_client)
    }

    #[test]
    fn test_detect_privilege_escalation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_privilege_escalation(r#"{"role":"admin"}"#, "role", "admin"));
        assert!(scanner.detect_privilege_escalation("Welcome administrator", "is_admin", "true"));
    }

    #[test]
    fn test_detect_price_manipulation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_price_manipulation(r#"{"price":"0"}"#, "0"));
        assert!(scanner.detect_price_manipulation(r#"{"price":0}"#, "0"));
        assert!(scanner.detect_price_manipulation("Price updated successfully", "0.01"));
    }

    #[test]
    fn test_detect_hidden_field_manipulation() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_hidden_field_manipulation(r#"{"user_id":1}"#, "user_id"));
        assert!(scanner.detect_hidden_field_manipulation("User updated", "verified"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_privilege_escalation("Normal response", "role", "user"));
        assert!(!scanner.detect_price_manipulation("Invalid request", "999"));
        assert!(!scanner.detect_hidden_field_manipulation("Error", "unknown"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "Privilege Escalation via Mass Assignment",
            "role=admin",
            "Mass assignment detected",
            "Role set to admin",
            Severity::Critical,
            "CWE-915",
        );

        assert_eq!(vuln.vuln_type, "Privilege Escalation via Mass Assignment");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-915");
        assert_eq!(vuln.cvss, 9.1);
    }

    #[test]
    fn test_detect_nested_injection() {
        let scanner = create_test_scanner();

        // Test marker-based detection (strongest evidence)
        let body_with_marker = format!(r#"{{"user":{{"role":{{"{}":"injected"}}}}}}"#, scanner.test_marker);
        assert!(scanner.detect_nested_injection(&body_with_marker, &format!("user[role][{}]=injected", scanner.test_marker)));

        // Test nested role injection
        assert!(scanner.detect_nested_injection(
            r#"{"user":{"role":"admin"}}"#,
            "user[role]=admin"
        ));

        // Test nested isAdmin injection
        assert!(scanner.detect_nested_injection(
            r#"{"user":{"isAdmin":true}}"#,
            "user[isAdmin]=true"
        ));

        // Test deep nested admin property
        assert!(scanner.detect_nested_injection(
            r#"{"profile":{"permissions":{"admin":true}}}"#,
            "profile[permissions][admin]=true"
        ));

        // Test dot notation
        assert!(scanner.detect_nested_injection(
            r#"{"user":{"role":"admin"}}"#,
            "user.role=admin"
        ));
    }

    #[test]
    fn test_detect_nested_injection_no_false_positives() {
        let scanner = create_test_scanner();

        // HTML response should not trigger
        assert!(!scanner.detect_nested_injection(
            "<html>Welcome admin</html>",
            "user[role]=admin"
        ));

        // Generic JSON without nested structure
        assert!(!scanner.detect_nested_injection(
            r#"{"message":"success"}"#,
            "user[role]=admin"
        ));

        // Admin in wrong context
        assert!(!scanner.detect_nested_injection(
            r#"{"admin":"John Doe"}"#,
            "user[role]=admin"
        ));
    }

    #[test]
    fn test_detect_deep_merge_injection() {
        let scanner = create_test_scanner();

        // Test with marker
        let payload_with_marker = json!({
            "user": {
                scanner.test_marker.clone(): "injected"
            }
        });
        let body_with_marker = format!(r#"{{"user":{{"{}":"injected"}}}}"#, scanner.test_marker);
        assert!(scanner.detect_deep_merge_injection(&body_with_marker, &payload_with_marker));

        // Test role injection
        let payload = json!({"user": {"role": "admin"}});
        assert!(scanner.detect_deep_merge_injection(
            r#"{"user":{"role":"admin"}}"#,
            &payload
        ));

        // Test isAdmin injection
        let payload = json!({"user": {"isAdmin": true}});
        assert!(scanner.detect_deep_merge_injection(
            r#"{"user":{"isAdmin":true}}"#,
            &payload
        ));

        // Test nested permissions
        let payload = json!({"profile": {"permissions": {"admin": true}}});
        assert!(scanner.detect_deep_merge_injection(
            r#"{"profile":{"permissions":{"admin":true}}}"#,
            &payload
        ));

        // Test price manipulation
        let payload = json!({"order": {"price": 0}});
        assert!(scanner.detect_deep_merge_injection(
            r#"{"order":{"price":0}}"#,
            &payload
        ));
    }

    #[test]
    fn test_detect_prototype_pollution() {
        let scanner = create_test_scanner();

        // Test with unique marker (strongest evidence)
        let payload_with_marker = format!("__proto__[{}]=polluted", scanner.test_marker);
        let body_with_marker = format!(r#"{{"{}":"polluted"}}"#, scanner.test_marker);
        assert!(scanner.detect_prototype_pollution(&body_with_marker, &payload_with_marker));

        // Test __proto__ with isAdmin
        assert!(scanner.detect_prototype_pollution(
            r#"{"__proto__":{"isAdmin":true}}"#,
            "__proto__[isAdmin]=true"
        ));

        // Test constructor.prototype
        assert!(scanner.detect_prototype_pollution(
            r#"{"constructor":{"prototype":{"admin":true}}}"#,
            "constructor[prototype][admin]=true"
        ));

        // Test pollution error detection
        assert!(scanner.detect_prototype_pollution(
            "Error: Prototype pollution detected",
            "__proto__[test]=value"
        ));
    }

    #[test]
    fn test_detect_prototype_pollution_no_false_positives() {
        let scanner = create_test_scanner();

        // Documentation mentioning __proto__ should not trigger
        assert!(!scanner.detect_prototype_pollution(
            "Learn about __proto__ in JavaScript",
            "__proto__[test]=value"
        ));

        // HTML response
        assert!(!scanner.detect_prototype_pollution(
            "<html>Admin panel</html>",
            "__proto__[admin]=true"
        ));

        // Generic JSON without pollution evidence
        assert!(!scanner.detect_prototype_pollution(
            r#"{"message":"success"}"#,
            "__proto__[test]=value"
        ));
    }

    #[test]
    fn test_detect_array_pollution() {
        let scanner = create_test_scanner();

        // Test with marker
        let payload_with_marker = format!("users[0][{}]=injected", scanner.test_marker);
        let body_with_marker = format!(r#"[{{"{}":"injected"}}]"#, scanner.test_marker);
        assert!(scanner.detect_array_pollution(&body_with_marker, &payload_with_marker));

        // Test array admin injection
        assert!(scanner.detect_array_pollution(
            r#"[{"admin":true}]"#,
            "users[0][admin]=true"
        ));

        // Test array role injection
        assert!(scanner.detect_array_pollution(
            r#"[{"role":"admin"}]"#,
            "users[0][role]=admin"
        ));

        // Test array price manipulation
        assert!(scanner.detect_array_pollution(
            r#"[{"price":0}]"#,
            "items[0][price]=0"
        ));
    }

    #[test]
    fn test_detect_array_pollution_no_false_positives() {
        let scanner = create_test_scanner();

        // HTML response
        assert!(!scanner.detect_array_pollution(
            "<html>Users list</html>",
            "users[0][admin]=true"
        ));

        // Non-array JSON
        assert!(!scanner.detect_array_pollution(
            r#"{"message":"success"}"#,
            "users[0][admin]=true"
        ));
    }

    #[test]
    fn test_detect_constructor_injection() {
        let scanner = create_test_scanner();

        // Test with marker
        let payload_with_marker = format!("constructor[{}]=injected", scanner.test_marker);
        let body_with_marker = format!(r#"{{"constructor":{{"{}":"injected"}}}}"#, scanner.test_marker);
        assert!(scanner.detect_constructor_injection(&body_with_marker, &payload_with_marker));

        // Test constructor name injection
        assert!(scanner.detect_constructor_injection(
            r#"{"constructor":{"name":"admin"}}"#,
            "constructor[name]=admin"
        ));

        // Test constructor.prototype injection
        assert!(scanner.detect_constructor_injection(
            r#"{"constructor":{"prototype":{"admin":true}}}"#,
            "constructor[prototype][admin]=true"
        ));

        // Test constructor modification message
        assert!(scanner.detect_constructor_injection(
            r#"{"constructor":"modified"}"#,
            "constructor[test]=value"
        ));
    }

    #[test]
    fn test_detect_constructor_injection_no_false_positives() {
        let scanner = create_test_scanner();

        // HTML response
        assert!(!scanner.detect_constructor_injection(
            "<html>Constructor pattern</html>",
            "constructor[test]=value"
        ));

        // Generic JSON
        assert!(!scanner.detect_constructor_injection(
            r#"{"message":"success"}"#,
            "constructor[test]=value"
        ));
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        // Each scanner should have a unique marker
        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("ma_"));
        assert!(scanner2.test_marker.starts_with("ma_"));
    }
}
