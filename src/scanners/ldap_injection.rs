// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
/**
 * Bountyy Oy - LDAP Injection Scanner
 * Tests for LDAP injection vulnerabilities in directory services
 *
 * Detects:
 * - Authentication bypass via LDAP filter manipulation
 * - Search filter injection
 * - DN (Distinguished Name) injection
 * - Blind LDAP injection
 * - LDAP attribute enumeration
 * - Active Directory specific attacks
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use tracing::{debug, info};

pub struct LdapInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl LdapInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for LDAP injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!(
                "[LDAP] Skipping framework/internal parameter: {}",
                param_name
            );
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!(
            "[LDAP] Testing LDAP injection on parameter: {} (priority: {})",
            param_name,
            ParameterFilter::get_parameter_priority(param_name)
        );

        // Test various LDAP injection payloads
        let payload_tests = vec![
            // Authentication bypass
            ("*", "Wildcard authentication bypass", "auth_bypass"),
            (
                "*)(uid=*",
                "LDAP filter injection - uid wildcard",
                "filter_injection",
            ),
            ("*)(|(uid=*", "LDAP OR filter bypass", "filter_bypass"),
            (
                "*)(&",
                "LDAP AND filter manipulation",
                "filter_manipulation",
            ),
            (
                "*)|(objectclass=*",
                "Objectclass filter bypass",
                "objectclass_bypass",
            ),
            // Error-based detection
            (
                "(cn=admin))",
                "Unbalanced parentheses - right",
                "error_based",
            ),
            (
                "((cn=admin)",
                "Unbalanced parentheses - left",
                "error_based",
            ),
            ("(cn=admin", "Missing closing parenthesis", "error_based"),
            // Filter manipulation
            ("(cn=*)", "CN wildcard search", "search_filter"),
            ("(uid=*)", "UID wildcard search", "search_filter"),
            ("(objectclass=*)", "Objectclass wildcard", "search_filter"),
            (
                "(|(cn=*)(mail=*))",
                "OR condition injection",
                "complex_filter",
            ),
            (
                "(&(cn=*)(objectclass=*))",
                "AND condition injection",
                "complex_filter",
            ),
            // DN injection
            ("cn=admin,dc=example,dc=com", "DN injection", "dn_injection"),
            (
                "cn=*,dc=example,dc=com",
                "DN wildcard injection",
                "dn_injection",
            ),
            // Active Directory specific
            (
                "(adminCount=1)",
                "AD privileged account enumeration",
                "ad_specific",
            ),
            (
                "(userAccountControl:1.2.840.113556.1.4.803:=512)",
                "AD user account control",
                "ad_specific",
            ),
        ];

        for (payload, description, attack_type) in payload_tests {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", url, param_name, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        response.status_code,
                        payload,
                        description,
                        attack_type,
                        &test_url,
                        param_name,
                    ) {
                        info!("LDAP injection vulnerability detected: {}", description);
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, move to next parameter
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for LDAP injection (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Only test parameters discovered from actual forms/URLs - no spray-and-pray
        // The main scanner will call scan_parameter() with discovered params
        Ok((Vec::new(), 0))
    }

    /// Analyze response for LDAP injection indicators
    fn analyze_response(
        &self,
        body: &str,
        status: u16,
        payload: &str,
        description: &str,
        attack_type: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // LDAP error patterns
        let ldap_error_patterns = vec![
            "LDAP.*error",
            "javax\\.naming\\.directory",
            "LDAPException",
            "com\\.sun\\.jndi\\.ldap",
            "Invalid DN syntax",
            "Bad search filter",
            "Protocol error.*LDAP",
            "Unprocessed Continuation Reference",
            "Operations Error.*LDAP",
            "ldap_search",
            "ldap_bind",
            "LDAP injection",
            "naming exception",
            "directory context",
        ];

        // Check for LDAP error indicators
        for pattern in &ldap_error_patterns {
            if let Ok(regex) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if regex.is_match(body) {
                    return Some(self.create_vulnerability(
                        url,
                        param_name,
                        payload,
                        description,
                        "LDAP error message detected in response",
                        Confidence::High,
                        attack_type,
                    ));
                }
            }
        }

        // Check for successful LDAP filter bypass (unusually large response)
        if payload == "*" && body.len() > 10000 {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Wildcard query returned unusually large response",
                "Possible LDAP filter bypass - wildcard query returned excessive data",
                Confidence::Medium,
                attack_type,
            ));
        }

        // Check for authentication bypass patterns
        if payload.contains("admin") && status == 200 {
            let auth_success_patterns = vec![
                "welcome",
                "dashboard",
                "logged in",
                "authentication successful",
                "profile",
                "account",
            ];

            for pattern in &auth_success_patterns {
                if body.to_lowercase().contains(pattern) {
                    return Some(self.create_vulnerability(
                        url,
                        param_name,
                        payload,
                        "Potential authentication bypass via LDAP injection",
                        &format!(
                            "Successful authentication with LDAP payload - found '{}'",
                            pattern
                        ),
                        Confidence::Medium,
                        attack_type,
                    ));
                }
            }
        }

        // Check for LDAP attribute exposure
        let ldap_attributes = vec![
            "objectClass",
            "distinguishedName",
            "cn=",
            "ou=",
            "dc=",
            "uid=",
            "memberOf",
            "userPassword",
            "sAMAccountName",
        ];

        let mut attribute_count = 0;
        for attr in &ldap_attributes {
            if body.contains(attr) {
                attribute_count += 1;
            }
        }

        if attribute_count >= 3 {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "LDAP directory information disclosure",
                &format!(
                    "Response contains {} LDAP attributes - possible directory enumeration",
                    attribute_count
                ),
                Confidence::Medium,
                attack_type,
            ));
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        confidence: Confidence,
        attack_type: &str,
    ) -> Vulnerability {
        let severity = match attack_type {
            "auth_bypass" | "filter_bypass" => Severity::Critical,
            "filter_injection" | "dn_injection" | "ad_specific" => Severity::High,
            _ => Severity::Medium,
        };

        let cvss = match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("ldap_injection_{}", uuid::Uuid::new_v4()),
            vuln_type: "LDAP Injection".to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "LDAP injection vulnerability in parameter '{}': {}",
                param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-90".to_string(),
            cvss,
            verified,
            false_positive: false,
            remediation: self.get_remediation(attack_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice based on attack type
    fn get_remediation(&self, attack_type: &str) -> String {
        match attack_type {
            "auth_bypass" | "filter_bypass" => {
                "1. Use parameterized LDAP queries with proper escaping\n\
                 2. Validate and sanitize all user input before LDAP operations\n\
                 3. Implement proper authentication mechanisms\n\
                 4. Use LDAP libraries that support prepared statements\n\
                 5. Apply principle of least privilege to LDAP service accounts\n\
                 6. Implement input validation using allowlists\n\
                 7. Escape special LDAP characters: * ( ) \\ NUL"
                    .to_string()
            }
            "filter_injection" | "complex_filter" => {
                "1. Escape special LDAP filter characters: * ( ) \\ NUL\n\
                 2. Use LDAP filter encoding functions\n\
                 3. Validate filter syntax before execution\n\
                 4. Implement strict input validation\n\
                 5. Use allowlists for permitted characters\n\
                 6. Avoid string concatenation for LDAP filters"
                    .to_string()
            }
            "dn_injection" => "1. Validate DN format and structure\n\
                 2. Escape DN special characters: , + \" \\ < > ; = NUL\n\
                 3. Use DN parsing and validation libraries\n\
                 4. Implement proper input sanitization\n\
                 5. Verify DN components against allowed values"
                .to_string(),
            "ad_specific" => "1. Restrict access to Active Directory attributes\n\
                 2. Implement proper authorization checks\n\
                 3. Use secure LDAP (LDAPS) for all connections\n\
                 4. Monitor for unusual LDAP queries\n\
                 5. Apply security patches to AD infrastructure\n\
                 6. Limit exposure of sensitive AD attributes"
                .to_string(),
            _ => "1. Use parameterized LDAP queries\n\
                 2. Sanitize all user input\n\
                 3. Implement proper input validation\n\
                 4. Use prepared statements where available\n\
                 5. Apply principle of least privilege\n\
                 6. Enable LDAP query logging and monitoring"
                .to_string(),
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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
    use crate::http_client::HttpResponse;
    use std::sync::Arc;

    fn create_test_scanner() -> LdapInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        LdapInjectionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_ldap_error_response() {
        let scanner = create_test_scanner();

        let body = "Error: LDAPException - Invalid DN syntax";
        let result = scanner.analyze_response(
            body,
            500,
            "*)(uid=*",
            "LDAP filter injection",
            "filter_injection",
            "http://example.com/api/users",
            "username",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "LDAP Injection");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-90");
    }

    #[test]
    fn test_analyze_javax_naming_error() {
        let scanner = create_test_scanner();

        let body = "javax.naming.directory.InvalidSearchFilterException: Bad search filter";
        let result = scanner.analyze_response(
            body,
            500,
            "*)(&",
            "LDAP AND filter manipulation",
            "filter_manipulation",
            "http://example.com/search",
            "query",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.confidence, Confidence::High);
        assert!(vuln.description.contains("LDAP injection"));
    }

    #[test]
    fn test_analyze_wildcard_bypass() {
        let scanner = create_test_scanner();

        // Simulate large response from wildcard query
        let body = "A".repeat(15000);
        let result = scanner.analyze_response(
            &body,
            200,
            "*",
            "Wildcard authentication bypass",
            "auth_bypass",
            "http://example.com/auth",
            "username",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.evidence.unwrap().contains("wildcard query"));
    }

    #[test]
    fn test_analyze_auth_bypass() {
        let scanner = create_test_scanner();

        let body = "Welcome to your dashboard, admin!";
        let result = scanner.analyze_response(
            body,
            200,
            "*)(uid=admin",
            "Authentication bypass",
            "auth_bypass",
            "http://example.com/login",
            "username",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.description.contains("authentication bypass"));
    }

    #[test]
    fn test_analyze_ldap_attribute_disclosure() {
        let scanner = create_test_scanner();

        let body = r#"
            {
                "distinguishedName": "cn=admin,dc=example,dc=com",
                "cn": "admin",
                "objectClass": ["person", "user"],
                "memberOf": ["cn=Domain Admins,dc=example,dc=com"],
                "sAMAccountName": "admin"
            }
        "#;

        let result = scanner.analyze_response(
            body,
            200,
            "(cn=*)",
            "CN wildcard search",
            "search_filter",
            "http://example.com/ldap/search",
            "filter",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln
            .description
            .contains("directory information disclosure"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let body = "User not found";
        let result = scanner.analyze_response(
            body,
            404,
            "testuser",
            "Normal query",
            "normal",
            "http://example.com/users",
            "username",
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_get_remediation_auth_bypass() {
        let scanner = create_test_scanner();
        let remediation = scanner.get_remediation("auth_bypass");

        assert!(remediation.contains("parameterized LDAP queries"));
        assert!(remediation.contains("special LDAP characters"));
    }

    #[test]
    fn test_get_remediation_dn_injection() {
        let scanner = create_test_scanner();
        let remediation = scanner.get_remediation("dn_injection");

        assert!(remediation.contains("DN format"));
        assert!(remediation.contains("DN special characters"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/api",
            "user",
            "*)(uid=*",
            "LDAP filter bypass",
            "LDAP error detected",
            Confidence::High,
            "filter_bypass",
        );

        assert_eq!(vuln.vuln_type, "LDAP Injection");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.parameter, Some("user".to_string()));
        assert_eq!(vuln.cwe, "CWE-90");
        assert_eq!(vuln.cvss, 9.0);
        assert!(vuln.verified);
    }
}
