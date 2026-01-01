// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,

    #[serde(default)]
    pub enabled_scanners: HashSet<String>,

    #[serde(default)]
    pub disabled_scanners: HashSet<String>,

    pub settings: ProfileSettings,

    #[serde(default)]
    pub payload_config: PayloadConfig,

    #[serde(default)]
    pub compliance: Option<ComplianceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ProfileSettings {
    #[validate(range(min = 1, max = 10000))]
    pub max_concurrency: usize,

    #[validate(range(min = 1, max = 3600))]
    pub request_timeout_secs: u64,

    #[validate(range(min = 1, max = 100000))]
    pub max_requests_per_second: u32,

    #[serde(default = "default_false")]
    pub stealth_mode: bool,

    #[validate(range(min = 100, max = 60000))]
    #[serde(default = "default_request_delay")]
    pub request_delay_ms: u64,

    #[validate(range(min = 0, max = 10))]
    pub max_retries: u32,

    #[serde(default = "default_true")]
    pub adaptive_rate_limiting: bool,

    #[serde(default = "default_true")]
    pub smart_payload_selection: bool,

    #[serde(default = "default_false")]
    pub early_termination: bool,

    #[validate(range(min = 1, max = 100))]
    #[serde(default = "default_scan_depth")]
    pub max_scan_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConfig {
    pub payload_set: PayloadSet,

    #[serde(default = "default_false")]
    pub include_comprehensive: bool,

    #[serde(default)]
    pub custom_payloads: Vec<String>,

    #[serde(default)]
    pub excluded_payloads: Vec<String>,

    #[serde(default = "default_true")]
    pub obfuscation_enabled: bool,

    #[serde(default = "default_true")]
    pub encoding_variations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub framework: ComplianceFramework,
    pub version: String,

    #[serde(default)]
    pub required_checks: Vec<String>,

    #[serde(default)]
    pub excluded_checks: Vec<String>,

    #[serde(default = "default_true")]
    pub generate_compliance_report: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadSet {
    Minimal,
    Basic,
    Standard,
    Comprehensive,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ComplianceFramework {
    PciDss,
    Hipaa,
    Gdpr,
    Sox,
    Iso27001,
    Nist,
    Cis,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            payload_set: PayloadSet::Standard,
            include_comprehensive: false,
            custom_payloads: Vec::new(),
            excluded_payloads: Vec::new(),
            obfuscation_enabled: true,
            encoding_variations: true,
        }
    }
}

impl ScanProfile {
    pub fn quick_scan() -> Self {
        let mut enabled_scanners = HashSet::new();
        enabled_scanners.insert("xss".to_string());
        enabled_scanners.insert("sql_injection".to_string());
        enabled_scanners.insert("command_injection".to_string());
        enabled_scanners.insert("path_traversal".to_string());

        Self {
            name: "quick-scan".to_string(),
            description: "Fast scan focusing on basic vulnerabilities".to_string(),
            enabled_scanners,
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 200,
                request_timeout_secs: 10,
                max_requests_per_second: 200,
                stealth_mode: false,
                request_delay_ms: 0,
                max_retries: 1,
                adaptive_rate_limiting: true,
                smart_payload_selection: true,
                early_termination: true,
                max_scan_depth: 3,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Basic,
                include_comprehensive: false,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: false,
                encoding_variations: false,
            },
            compliance: None,
        }
    }

    pub fn standard() -> Self {
        let mut enabled_scanners = HashSet::new();
        enabled_scanners.insert("xss".to_string());
        enabled_scanners.insert("sql_injection".to_string());
        enabled_scanners.insert("command_injection".to_string());
        enabled_scanners.insert("path_traversal".to_string());
        enabled_scanners.insert("csrf".to_string());
        enabled_scanners.insert("cors".to_string());
        enabled_scanners.insert("xxe".to_string());
        enabled_scanners.insert("ssrf".to_string());
        enabled_scanners.insert("idor".to_string());
        enabled_scanners.insert("auth_bypass".to_string());

        Self {
            name: "standard".to_string(),
            description: "Standard OWASP Top 10 vulnerability scan".to_string(),
            enabled_scanners,
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 100,
                request_timeout_secs: 30,
                max_requests_per_second: 100,
                stealth_mode: false,
                request_delay_ms: 0,
                max_retries: 2,
                adaptive_rate_limiting: true,
                smart_payload_selection: true,
                early_termination: false,
                max_scan_depth: 5,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Standard,
                include_comprehensive: false,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: true,
                encoding_variations: true,
            },
            compliance: None,
        }
    }

    pub fn comprehensive() -> Self {
        Self {
            name: "comprehensive".to_string(),
            description: "Full vulnerability coverage with all scanners enabled".to_string(),
            enabled_scanners: HashSet::new(),
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 50,
                request_timeout_secs: 60,
                max_requests_per_second: 50,
                stealth_mode: false,
                request_delay_ms: 0,
                max_retries: 3,
                adaptive_rate_limiting: true,
                smart_payload_selection: true,
                early_termination: false,
                max_scan_depth: 10,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Comprehensive,
                include_comprehensive: true,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: true,
                encoding_variations: true,
            },
            compliance: None,
        }
    }

    pub fn stealth() -> Self {
        let mut enabled_scanners = HashSet::new();
        enabled_scanners.insert("xss".to_string());
        enabled_scanners.insert("sql_injection".to_string());
        enabled_scanners.insert("csrf".to_string());
        enabled_scanners.insert("idor".to_string());

        Self {
            name: "stealth".to_string(),
            description: "Low request rate with evasion techniques".to_string(),
            enabled_scanners,
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 5,
                request_timeout_secs: 60,
                max_requests_per_second: 2,
                stealth_mode: true,
                request_delay_ms: 500,
                max_retries: 1,
                adaptive_rate_limiting: false,
                smart_payload_selection: true,
                early_termination: false,
                max_scan_depth: 3,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Basic,
                include_comprehensive: false,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: true,
                encoding_variations: true,
            },
            compliance: None,
        }
    }

    pub fn compliance_pci() -> Self {
        let mut enabled_scanners = HashSet::new();
        enabled_scanners.insert("sql_injection".to_string());
        enabled_scanners.insert("xss".to_string());
        enabled_scanners.insert("csrf".to_string());
        enabled_scanners.insert("auth_bypass".to_string());
        enabled_scanners.insert("session_management".to_string());
        enabled_scanners.insert("encryption".to_string());
        enabled_scanners.insert("access_control".to_string());
        enabled_scanners.insert("input_validation".to_string());

        Self {
            name: "compliance-pci".to_string(),
            description: "PCI-DSS compliance focused security testing".to_string(),
            enabled_scanners,
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 50,
                request_timeout_secs: 45,
                max_requests_per_second: 50,
                stealth_mode: false,
                request_delay_ms: 0,
                max_retries: 2,
                adaptive_rate_limiting: true,
                smart_payload_selection: true,
                early_termination: false,
                max_scan_depth: 7,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Standard,
                include_comprehensive: false,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: true,
                encoding_variations: true,
            },
            compliance: Some(ComplianceConfig {
                framework: ComplianceFramework::PciDss,
                version: "4.0".to_string(),
                required_checks: vec![
                    "6.5.1".to_string(),
                    "6.5.3".to_string(),
                    "6.5.7".to_string(),
                    "6.5.8".to_string(),
                    "6.5.10".to_string(),
                ],
                excluded_checks: Vec::new(),
                generate_compliance_report: true,
            }),
        }
    }

    pub fn compliance_hipaa() -> Self {
        let mut enabled_scanners = HashSet::new();
        enabled_scanners.insert("auth_bypass".to_string());
        enabled_scanners.insert("access_control".to_string());
        enabled_scanners.insert("encryption".to_string());
        enabled_scanners.insert("session_management".to_string());
        enabled_scanners.insert("audit_logging".to_string());
        enabled_scanners.insert("data_exposure".to_string());
        enabled_scanners.insert("idor".to_string());

        Self {
            name: "compliance-hipaa".to_string(),
            description: "HIPAA compliance focused security testing".to_string(),
            enabled_scanners,
            disabled_scanners: HashSet::new(),
            settings: ProfileSettings {
                max_concurrency: 50,
                request_timeout_secs: 45,
                max_requests_per_second: 50,
                stealth_mode: false,
                request_delay_ms: 0,
                max_retries: 2,
                adaptive_rate_limiting: true,
                smart_payload_selection: true,
                early_termination: false,
                max_scan_depth: 7,
            },
            payload_config: PayloadConfig {
                payload_set: PayloadSet::Standard,
                include_comprehensive: false,
                custom_payloads: Vec::new(),
                excluded_payloads: Vec::new(),
                obfuscation_enabled: true,
                encoding_variations: true,
            },
            compliance: Some(ComplianceConfig {
                framework: ComplianceFramework::Hipaa,
                version: "2013".to_string(),
                required_checks: vec![
                    "164.308(a)(1)".to_string(),
                    "164.308(a)(3)".to_string(),
                    "164.308(a)(4)".to_string(),
                    "164.312(a)(1)".to_string(),
                    "164.312(e)(1)".to_string(),
                ],
                excluded_checks: Vec::new(),
                generate_compliance_report: true,
            }),
        }
    }

    pub fn is_scanner_enabled(&self, scanner_name: &str) -> bool {
        if !self.disabled_scanners.is_empty() && self.disabled_scanners.contains(scanner_name) {
            return false;
        }

        if self.enabled_scanners.is_empty() {
            return true;
        }

        self.enabled_scanners.contains(scanner_name)
    }
}

pub struct ProfileRegistry {
    profiles: std::collections::HashMap<String, ScanProfile>,
}

impl ProfileRegistry {
    pub fn new() -> Self {
        let mut profiles = std::collections::HashMap::new();

        profiles.insert("quick-scan".to_string(), ScanProfile::quick_scan());
        profiles.insert("standard".to_string(), ScanProfile::standard());
        profiles.insert("comprehensive".to_string(), ScanProfile::comprehensive());
        profiles.insert("stealth".to_string(), ScanProfile::stealth());
        profiles.insert("compliance-pci".to_string(), ScanProfile::compliance_pci());
        profiles.insert("compliance-hipaa".to_string(), ScanProfile::compliance_hipaa());

        Self { profiles }
    }

    pub fn get(&self, name: &str) -> Option<&ScanProfile> {
        self.profiles.get(name)
    }

    pub fn register(&mut self, profile: ScanProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    pub fn list(&self) -> Vec<&ScanProfile> {
        self.profiles.values().collect()
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_request_delay() -> u64 {
    0
}

fn default_scan_depth() -> usize {
    5
}
