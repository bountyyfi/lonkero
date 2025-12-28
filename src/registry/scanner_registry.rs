// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Scanner Registry
 * Central registry for all available scanners with metadata and capabilities
 * © 2026 Bountyy Oy
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Scanner category enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScannerCategory {
    Injection,
    Authentication,
    Authorization,
    Configuration,
    Api,
    Cloud,
    Headers,
    Ssl,
    Session,
    BusinessLogic,
    FileUpload,
    Deserialization,
    Framework,
    InformationDisclosure,
    ClientSide,
    ServerSide,
    Network,
    Compliance,
}

/// Scanner risk level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Scanner capability flags
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScannerCapability {
    Get,
    Post,
    Put,
    Delete,
    Options,
    Websocket,
    Grpc,
    GraphQL,
    Cookies,
    Headers,
    Cloud,
    Docker,
    Kubernetes,
    Redirect,
}

/// Scanner metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerMetadata {
    pub name: String,
    pub display_name: String,
    pub category: ScannerCategory,
    pub description: String,
    pub risk_level: RiskLevel,
    pub default_enabled: bool,
    pub requires_auth: bool,
    pub slow_scanner: bool,
    pub dependencies: Vec<String>,
    pub capabilities: Vec<ScannerCapability>,
    pub config_schema: serde_json::Value,
    pub version: String,
    pub tags: Vec<String>,
}

/// Scanner configuration schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfigSchema {
    pub properties: HashMap<String, ConfigProperty>,
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigProperty {
    pub property_type: String,
    pub description: String,
    pub default: Option<serde_json::Value>,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
    pub enum_values: Option<Vec<String>>,
}

/// Scanner Registry
pub struct ScannerRegistry {
    scanners: HashMap<String, ScannerMetadata>,
}

impl ScannerRegistry {
    /// Create new scanner registry
    pub fn new() -> Self {
        let mut registry = Self {
            scanners: HashMap::new(),
        };
        registry.register_all_scanners();
        registry
    }

    /// Register a scanner
    pub fn register(&mut self, metadata: ScannerMetadata) {
        self.scanners.insert(metadata.name.clone(), metadata);
    }

    /// Get scanner metadata
    pub fn get(&self, name: &str) -> Option<&ScannerMetadata> {
        self.scanners.get(name)
    }

    /// Get all scanners
    pub fn get_all(&self) -> Vec<&ScannerMetadata> {
        self.scanners.values().collect()
    }

    /// Get scanners by category
    pub fn get_by_category(&self, category: &ScannerCategory) -> Vec<&ScannerMetadata> {
        self.scanners
            .values()
            .filter(|s| &s.category == category)
            .collect()
    }

    /// Get scanners by risk level
    pub fn get_by_risk_level(&self, risk_level: &RiskLevel) -> Vec<&ScannerMetadata> {
        self.scanners
            .values()
            .filter(|s| &s.risk_level == risk_level)
            .collect()
    }

    /// Get enabled scanners
    pub fn get_default_enabled(&self) -> Vec<&ScannerMetadata> {
        self.scanners
            .values()
            .filter(|s| s.default_enabled)
            .collect()
    }

    /// Get slow scanners
    pub fn get_slow_scanners(&self) -> Vec<&ScannerMetadata> {
        self.scanners
            .values()
            .filter(|s| s.slow_scanner)
            .collect()
    }

    /// Check if scanner exists
    pub fn exists(&self, name: &str) -> bool {
        self.scanners.contains_key(name)
    }

    /// Get scanner count
    pub fn count(&self) -> usize {
        self.scanners.len()
    }

    /// Get scanner categories
    pub fn get_categories(&self) -> Vec<ScannerCategory> {
        let mut categories: Vec<_> = self.scanners
            .values()
            .map(|s| s.category.clone())
            .collect();
        categories.sort_by_key(|c| format!("{:?}", c));
        categories.dedup();
        categories
    }

    /// Register all built-in scanners
    fn register_all_scanners(&mut self) {
        // Injection scanners
        self.register(create_xss_scanner());
        self.register(create_sqli_scanner());
        self.register(create_nosql_scanner());
        self.register(create_command_injection_scanner());
        self.register(create_xxe_scanner());
        self.register(create_ldap_injection_scanner());
        self.register(create_xpath_injection_scanner());
        self.register(create_ssti_scanner());
        self.register(create_crlf_injection_scanner());
        self.register(create_xml_injection_scanner());

        // Authentication scanners
        self.register(create_auth_bypass_scanner());
        self.register(create_session_management_scanner());
        self.register(create_jwt_scanner());
        self.register(create_oauth_scanner());
        self.register(create_saml_scanner());
        self.register(create_mfa_scanner());
        self.register(create_webauthn_scanner());

        // Authorization scanners
        self.register(create_idor_scanner());
        self.register(create_mass_assignment_scanner());

        // Configuration scanners
        self.register(create_security_headers_scanner());
        self.register(create_cors_scanner());
        self.register(create_clickjacking_scanner());

        // Session scanners
        self.register(create_csrf_scanner());

        // Server-side scanners
        self.register(create_ssrf_scanner());
        self.register(create_open_redirect_scanner());
        self.register(create_path_traversal_scanner());
        self.register(create_file_upload_scanner());
        self.register(create_deserialization_scanner());
        self.register(create_http_smuggling_scanner());
        self.register(create_cache_poisoning_scanner());
        self.register(create_host_header_injection_scanner());
        self.register(create_ssi_injection_scanner());

        // Client-side scanners
        self.register(create_prototype_pollution_scanner());

        // API scanners
        self.register(create_api_security_scanner());
        self.register(create_graphql_scanner());
        self.register(create_grpc_scanner());
        self.register(create_websocket_scanner());
        self.register(create_api_fuzzer_scanner());
        self.register(create_api_gateway_scanner());

        // Cloud scanners
        self.register(create_cloud_security_scanner());
        self.register(create_container_scanner());
        self.register(create_cloud_storage_scanner());

        // Information disclosure scanners
        self.register(create_information_disclosure_scanner());
        self.register(create_sensitive_data_scanner());
        self.register(create_js_miner_scanner());

        // Business logic scanners
        self.register(create_business_logic_scanner());
        self.register(create_race_condition_scanner());

        // Framework scanners
        self.register(create_framework_vulnerabilities_scanner());

        // Advanced scanners
        self.register(create_advanced_auth_scanner());
        self.register(create_http3_scanner());
        self.register(create_template_injection_scanner());
    }
}

// Global scanner registry instance
pub static SCANNER_REGISTRY: Lazy<ScannerRegistry> = Lazy::new(|| ScannerRegistry::new());

// Scanner factory functions

fn create_xss_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "xss".to_string(),
        display_name: "Cross-Site Scripting (XSS)".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects reflected and stored XSS vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({
            "properties": {
                "payload_set": {"type": "string", "enum": ["basic", "extended", "comprehensive"], "default": "extended"},
                "test_reflected": {"type": "boolean", "default": true},
                "test_stored": {"type": "boolean", "default": true},
                "test_dom": {"type": "boolean", "default": false}
            }
        }),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "injection".to_string()],
    }
}

fn create_sqli_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "sqli".to_string(),
        display_name: "SQL Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects SQL injection vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({
            "properties": {
                "test_error_based": {"type": "boolean", "default": true},
                "test_blind": {"type": "boolean", "default": true},
                "test_time_based": {"type": "boolean", "default": false}
            }
        }),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "injection".to_string(), "critical".to_string()],
    }
}

fn create_nosql_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "nosql".to_string(),
        display_name: "NoSQL Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects NoSQL injection vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "nosql".to_string()],
    }
}

fn create_command_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "command_injection".to_string(),
        display_name: "Command Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects OS command injection vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "injection".to_string(), "critical".to_string()],
    }
}

fn create_xxe_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "xxe".to_string(),
        display_name: "XML External Entity (XXE)".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects XXE vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "injection".to_string(), "xml".to_string()],
    }
}

fn create_ldap_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "ldap_injection".to_string(),
        display_name: "LDAP Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects LDAP injection vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "ldap".to_string()],
    }
}

fn create_xpath_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "xpath_injection".to_string(),
        display_name: "XPath Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects XPath injection vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "xpath".to_string()],
    }
}

fn create_ssti_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "ssti_advanced_scanner".to_string(),
        display_name: "Server-Side Template Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects SSTI vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "injection".to_string(), "critical".to_string()],
    }
}

fn create_crlf_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "crlf_injection".to_string(),
        display_name: "CRLF Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects CRLF injection vulnerabilities".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string()],
    }
}

fn create_xml_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "xml_injection".to_string(),
        display_name: "XML Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects XML injection vulnerabilities".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "xml".to_string()],
    }
}

// Authentication scanners
fn create_auth_bypass_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "auth_bypass".to_string(),
        display_name: "Authentication Bypass".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests for authentication bypass vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: true,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "authentication".to_string(), "critical".to_string()],
    }
}

fn create_session_management_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "session_management".to_string(),
        display_name: "Session Management".to_string(),
        category: ScannerCategory::Session,
        description: "Tests session security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: true,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post, ScannerCapability::Cookies],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "session".to_string()],
    }
}

fn create_jwt_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "jwt".to_string(),
        display_name: "JWT Security".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests JWT implementation security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "jwt".to_string()],
    }
}

fn create_oauth_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "oauth".to_string(),
        display_name: "OAuth Security".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests OAuth implementation".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post, ScannerCapability::Redirect],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "oauth".to_string()],
    }
}

fn create_saml_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "saml".to_string(),
        display_name: "SAML Security".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests SAML implementation".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "saml".to_string()],
    }
}

fn create_mfa_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "mfa".to_string(),
        display_name: "Multi-Factor Authentication".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests MFA implementation".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: false,
        dependencies: vec!["auth_bypass".to_string()],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "mfa".to_string()],
    }
}

fn create_webauthn_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "webauthn_scanner".to_string(),
        display_name: "WebAuthn Security".to_string(),
        category: ScannerCategory::Authentication,
        description: "Tests WebAuthn implementation".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "webauthn".to_string()],
    }
}

// Authorization scanners
fn create_idor_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "idor".to_string(),
        display_name: "Insecure Direct Object Reference".to_string(),
        category: ScannerCategory::Authorization,
        description: "Detects IDOR vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: true,
        slow_scanner: false,
        dependencies: vec!["auth_bypass".to_string()],
        capabilities: vec![
            ScannerCapability::Get,
            ScannerCapability::Post,
            ScannerCapability::Put,
            ScannerCapability::Delete,
        ],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "authorization".to_string()],
    }
}

fn create_mass_assignment_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "mass_assignment".to_string(),
        display_name: "Mass Assignment".to_string(),
        category: ScannerCategory::Authorization,
        description: "Detects mass assignment vulnerabilities".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post, ScannerCapability::Put],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authorization".to_string()],
    }
}

// Configuration scanners
fn create_security_headers_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "security_headers".to_string(),
        display_name: "Security Headers".to_string(),
        category: ScannerCategory::Headers,
        description: "Checks for missing security headers".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["configuration".to_string(), "headers".to_string()],
    }
}

fn create_cors_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "cors".to_string(),
        display_name: "CORS Misconfiguration".to_string(),
        category: ScannerCategory::Configuration,
        description: "Detects CORS misconfigurations".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Options],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["configuration".to_string(), "cors".to_string()],
    }
}

fn create_clickjacking_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "clickjacking".to_string(),
        display_name: "Clickjacking".to_string(),
        category: ScannerCategory::Configuration,
        description: "Tests for clickjacking vulnerabilities".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec!["security_headers".to_string()],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["configuration".to_string()],
    }
}

fn create_csrf_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "csrf".to_string(),
        display_name: "Cross-Site Request Forgery".to_string(),
        category: ScannerCategory::Session,
        description: "Detects CSRF vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "csrf".to_string()],
    }
}

// Server-side scanners
fn create_ssrf_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "ssrf".to_string(),
        display_name: "Server-Side Request Forgery".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects SSRF vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "ssrf".to_string(), "critical".to_string()],
    }
}

fn create_open_redirect_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "open_redirect".to_string(),
        display_name: "Open Redirect".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects open redirect vulnerabilities".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["redirect".to_string()],
    }
}

fn create_path_traversal_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "path_traversal".to_string(),
        display_name: "Path Traversal".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects directory traversal vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "file".to_string()],
    }
}

fn create_file_upload_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "file_upload".to_string(),
        display_name: "File Upload Vulnerabilities".to_string(),
        category: ScannerCategory::FileUpload,
        description: "Tests file upload security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "file".to_string()],
    }
}

fn create_deserialization_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "deserialization".to_string(),
        display_name: "Insecure Deserialization".to_string(),
        category: ScannerCategory::Deserialization,
        description: "Detects deserialization vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "deserialization".to_string(), "critical".to_string()],
    }
}

fn create_http_smuggling_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "http_smuggling".to_string(),
        display_name: "HTTP Request Smuggling".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects HTTP smuggling vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["http".to_string(), "smuggling".to_string(), "critical".to_string()],
    }
}

fn create_cache_poisoning_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "cache_poisoning".to_string(),
        display_name: "Cache Poisoning".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects cache poisoning vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["cache".to_string()],
    }
}

fn create_host_header_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "host_header_injection".to_string(),
        display_name: "Host Header Injection".to_string(),
        category: ScannerCategory::ServerSide,
        description: "Detects host header injection".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["headers".to_string(), "injection".to_string()],
    }
}

fn create_ssi_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "ssi_injection".to_string(),
        display_name: "Server-Side Includes Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects SSI injection vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "ssi".to_string()],
    }
}

fn create_prototype_pollution_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "prototype_pollution".to_string(),
        display_name: "Prototype Pollution".to_string(),
        category: ScannerCategory::ClientSide,
        description: "Detects prototype pollution vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["javascript".to_string(), "client-side".to_string()],
    }
}

// API scanners
fn create_api_security_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "api_security".to_string(),
        display_name: "API Security".to_string(),
        category: ScannerCategory::Api,
        description: "Comprehensive API security testing".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![
            ScannerCapability::Get,
            ScannerCapability::Post,
            ScannerCapability::Put,
            ScannerCapability::Delete,
        ],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "rest".to_string()],
    }
}

fn create_graphql_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "graphql".to_string(),
        display_name: "GraphQL Security".to_string(),
        category: ScannerCategory::Api,
        description: "Tests GraphQL API security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post, ScannerCapability::GraphQL],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "graphql".to_string()],
    }
}

fn create_grpc_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "grpc".to_string(),
        display_name: "gRPC Security".to_string(),
        category: ScannerCategory::Api,
        description: "Tests gRPC API security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Grpc],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "grpc".to_string()],
    }
}

fn create_websocket_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "websocket".to_string(),
        display_name: "WebSocket Security".to_string(),
        category: ScannerCategory::Api,
        description: "Tests WebSocket security".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Websocket],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "websocket".to_string()],
    }
}

fn create_api_fuzzer_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "api_fuzzer".to_string(),
        display_name: "API Fuzzing".to_string(),
        category: ScannerCategory::Api,
        description: "Fuzzes API endpoints".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec!["api_security".to_string()],
        capabilities: vec![
            ScannerCapability::Get,
            ScannerCapability::Post,
            ScannerCapability::Put,
            ScannerCapability::Delete,
        ],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "fuzzing".to_string()],
    }
}

fn create_api_gateway_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "api_gateway_scanner".to_string(),
        display_name: "API Gateway Security".to_string(),
        category: ScannerCategory::Api,
        description: "Tests API gateway configurations".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["api".to_string(), "gateway".to_string()],
    }
}

// Cloud scanners
fn create_cloud_security_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "cloud_security_scanner".to_string(),
        display_name: "Cloud Security".to_string(),
        category: ScannerCategory::Cloud,
        description: "Scans cloud misconfigurations".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Cloud],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["cloud".to_string(), "aws".to_string(), "azure".to_string(), "gcp".to_string()],
    }
}

fn create_container_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "container_scanner".to_string(),
        display_name: "Container Security".to_string(),
        category: ScannerCategory::Cloud,
        description: "Scans container configurations".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Docker, ScannerCapability::Kubernetes],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["cloud".to_string(), "docker".to_string(), "kubernetes".to_string()],
    }
}

fn create_cloud_storage_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "cloud_storage".to_string(),
        display_name: "Cloud Storage Security".to_string(),
        category: ScannerCategory::Cloud,
        description: "Tests cloud storage bucket security".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["cloud".to_string(), "storage".to_string(), "s3".to_string()],
    }
}

// Information disclosure scanners
fn create_information_disclosure_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "information_disclosure".to_string(),
        display_name: "Information Disclosure".to_string(),
        category: ScannerCategory::InformationDisclosure,
        description: "Detects sensitive information leaks".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["information".to_string(), "disclosure".to_string()],
    }
}

fn create_sensitive_data_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "sensitive_data".to_string(),
        display_name: "Sensitive Data Exposure".to_string(),
        category: ScannerCategory::InformationDisclosure,
        description: "Detects exposed sensitive data".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["owasp-top-10".to_string(), "sensitive-data".to_string()],
    }
}

fn create_js_miner_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "js_miner".to_string(),
        display_name: "JavaScript Mining".to_string(),
        category: ScannerCategory::InformationDisclosure,
        description: "Extracts sensitive data from JavaScript files".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["javascript".to_string(), "information".to_string()],
    }
}

// Business logic scanners
fn create_business_logic_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "business_logic".to_string(),
        display_name: "Business Logic Flaws".to_string(),
        category: ScannerCategory::BusinessLogic,
        description: "Detects business logic vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["business-logic".to_string()],
    }
}

fn create_race_condition_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "race_condition".to_string(),
        display_name: "Race Condition".to_string(),
        category: ScannerCategory::BusinessLogic,
        description: "Detects race condition vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: true,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Post, ScannerCapability::Put],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["race-condition".to_string(), "concurrency".to_string()],
    }
}

// Framework scanners
fn create_framework_vulnerabilities_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "framework_vulnerabilities".to_string(),
        display_name: "Framework Vulnerabilities".to_string(),
        category: ScannerCategory::Framework,
        description: "Detects known framework vulnerabilities".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["framework".to_string(), "cve".to_string()],
    }
}

// Advanced scanners
fn create_advanced_auth_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "advanced_auth".to_string(),
        display_name: "Advanced Authentication".to_string(),
        category: ScannerCategory::Authentication,
        description: "Advanced authentication testing".to_string(),
        risk_level: RiskLevel::High,
        default_enabled: false,
        requires_auth: true,
        slow_scanner: true,
        dependencies: vec!["auth_bypass".to_string()],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["authentication".to_string(), "advanced".to_string()],
    }
}

fn create_http3_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "http3_scanner".to_string(),
        display_name: "HTTP/3 Alt-Svc Headers".to_string(),
        category: ScannerCategory::Network,
        description: "Tests Alt-Svc header configurations via standard HTTP (does not use actual HTTP/3 protocol)".to_string(),
        risk_level: RiskLevel::Medium,
        default_enabled: false,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["http3".to_string(), "alt-svc".to_string(), "headers".to_string()],
    }
}

fn create_template_injection_scanner() -> ScannerMetadata {
    ScannerMetadata {
        name: "template_injection".to_string(),
        display_name: "Template Injection".to_string(),
        category: ScannerCategory::Injection,
        description: "Detects template injection vulnerabilities".to_string(),
        risk_level: RiskLevel::Critical,
        default_enabled: true,
        requires_auth: false,
        slow_scanner: false,
        dependencies: vec![],
        capabilities: vec![ScannerCapability::Get, ScannerCapability::Post],
        config_schema: serde_json::json!({"properties": {}}),
        version: "1.0.0".to_string(),
        tags: vec!["injection".to_string(), "template".to_string()],
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_registry() {
        let registry = ScannerRegistry::new();
        assert!(registry.count() > 0);
    }

    #[test]
    fn test_get_scanner() {
        let registry = ScannerRegistry::new();
        let scanner = registry.get("xss");
        assert!(scanner.is_some());
        assert_eq!(scanner.unwrap().name, "xss");
    }

    #[test]
    fn test_get_by_category() {
        let registry = ScannerRegistry::new();
        let injection_scanners = registry.get_by_category(&ScannerCategory::Injection);
        assert!(!injection_scanners.is_empty());
    }

    #[test]
    fn test_get_slow_scanners() {
        let registry = ScannerRegistry::new();
        let slow_scanners = registry.get_slow_scanners();
        assert!(!slow_scanners.is_empty());
    }
}
