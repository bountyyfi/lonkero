// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::signing::ReportSignature;

/// Scan mode determines the intensity and scope of the security scan
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    Fast,
    Normal,
    Thorough,
    Insane,
}

impl Default for ScanMode {
    fn default() -> Self {
        ScanMode::Fast
    }
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Fast => write!(f, "fast"),
            ScanMode::Normal => write!(f, "normal"),
            ScanMode::Thorough => write!(f, "thorough"),
            ScanMode::Insane => write!(f, "insane"),
        }
    }
}

impl ScanMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Fast => "fast",
            ScanMode::Normal => "normal",
            ScanMode::Thorough => "thorough",
            ScanMode::Insane => "insane",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub scan_id: String,
    pub target: String,
    pub config: ScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanConfig {
    #[serde(default)]
    pub scan_mode: ScanMode,

    #[serde(default = "default_ultra")]
    pub ultra: bool,

    #[serde(default)]
    pub enable_crawler: bool,

    #[serde(default = "default_max_depth")]
    pub max_depth: u32,

    #[serde(default = "default_max_pages")]
    pub max_pages: u32,

    #[serde(default)]
    pub enum_subdomains: bool,

    #[serde(default)]
    pub auth_cookie: Option<String>,

    #[serde(default)]
    pub auth_token: Option<String>,

    #[serde(default)]
    pub auth_basic: Option<String>,

    #[serde(default)]
    pub custom_headers: Option<HashMap<String, String>>,
}

fn default_ultra() -> bool {
    true
}

fn default_max_depth() -> u32 {
    3
}

fn default_max_pages() -> u32 {
    100
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_mode: ScanMode::Fast,
            ultra: true,
            enable_crawler: false,
            max_depth: 3,
            max_pages: 100,
            enum_subdomains: false,
            auth_cookie: None,
            auth_token: None,
            auth_basic: None,
            custom_headers: None,
        }
    }
}

impl ScanConfig {
    pub fn payload_count(&self) -> usize {
        match self.scan_mode {
            ScanMode::Fast => 50,
            ScanMode::Normal => 500,
            ScanMode::Thorough => 5000,
            ScanMode::Insane => usize::MAX, // All payloads
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResults {
    pub scan_id: String,
    pub target: String,
    pub tests_run: u64,
    pub vulnerabilities: Vec<Vulnerability>,
    pub started_at: String,
    pub completed_at: String,
    pub duration_seconds: f64,
    #[serde(default)]
    pub early_terminated: bool,
    #[serde(default)]
    pub termination_reason: Option<String>,
    /// Scanner version and build info
    #[serde(default)]
    pub scanner_version: Option<String>,
    /// License signature watermark (for audit trail) - DEPRECATED: Use quantum_signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_signature: Option<String>,
    /// Quantum-safe cryptographic signature for result verification
    /// This signature is created by the Bountyy signing service and proves:
    /// 1. The scan was authorized before execution
    /// 2. The results have not been tampered with
    /// 3. The scan was performed by a legitimate Lonkero scanner
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantum_signature: Option<ReportSignature>,
    /// Scan authorization token ID (for audit correlation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_token_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub id: String,
    #[serde(rename = "type")]
    pub vuln_type: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: String,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: String,
    pub description: String,
    pub evidence: Option<String>,
    pub cwe: String,
    pub cvss: f32,
    pub verified: bool,
    pub false_positive: bool,
    pub remediation: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "HIGH"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub scan_id: String,
    pub progress: u8,
    pub phase: String,
    pub message: String,
}

impl Serialize for ScanProgress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ScanProgress", 4)?;
        state.serialize_field("scanId", &self.scan_id)?;
        state.serialize_field("progress", &self.progress)?;
        state.serialize_field("phase", &self.phase)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}
