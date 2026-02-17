// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::signing::ReportSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Scan mode determines the intensity and scope of the security scan
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Legacy mode: 50 payloads globally
    Fast,
    /// Legacy mode: 500 payloads globally
    Normal,
    /// Legacy mode: 5000 payloads globally
    Thorough,
    /// Legacy mode: unlimited payloads globally
    Insane,
    /// Intelligent context-aware mode (v3.0 default)
    /// Uses tech detection, endpoint deduplication, and per-parameter risk scoring
    Intelligent,
}

impl Default for ScanMode {
    fn default() -> Self {
        // v3.0: Intelligent mode is now the default
        ScanMode::Intelligent
    }
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Fast => write!(f, "fast"),
            ScanMode::Normal => write!(f, "normal"),
            ScanMode::Thorough => write!(f, "thorough"),
            ScanMode::Insane => write!(f, "insane"),
            ScanMode::Intelligent => write!(f, "intelligent"),
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
            ScanMode::Intelligent => "intelligent",
        }
    }

    /// Returns true if this is the intelligent context-aware mode
    pub fn is_intelligent(&self) -> bool {
        matches!(self, ScanMode::Intelligent)
    }

    /// Returns true if this is a legacy mode (fast/normal/thorough/insane)
    pub fn is_legacy(&self) -> bool {
        !self.is_intelligent()
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

    /// Only run these specific scanner modules (empty = run all)
    #[serde(default)]
    pub only_modules: Vec<String>,

    /// Skip these specific scanner modules
    #[serde(default)]
    pub skip_modules: Vec<String>,
}

impl ScanConfig {
    /// Check if a module should run based on --only and --skip filters.
    /// Returns true if the module is allowed to run.
    pub fn should_run_module(&self, module_id: &str) -> bool {
        // If --only is specified, only run modules in the list
        if !self.only_modules.is_empty() {
            if !self.only_modules.iter().any(|m| m == module_id) {
                return false;
            }
        }
        // If --skip is specified, skip modules in the list
        if self.skip_modules.iter().any(|m| m == module_id) {
            return false;
        }
        true
    }

    /// Check if ANY module from a list should run (for phase-level gating).
    pub fn should_run_any_module(&self, module_ids: &[&str]) -> bool {
        if self.only_modules.is_empty() {
            // No filter, check skip list
            return module_ids.iter().any(|id| !self.skip_modules.contains(&id.to_string()));
        }
        // Check if any of the given modules are in the only list
        module_ids.iter().any(|id| self.should_run_module(id))
    }
}

fn default_max_depth() -> u32 {
    3
}

fn default_max_pages() -> u32 {
    1000
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_mode: ScanMode::Fast,
            enable_crawler: false,
            max_depth: 3,
            max_pages: 1000,
            enum_subdomains: false,
            auth_cookie: None,
            auth_token: None,
            auth_basic: None,
            custom_headers: None,
            only_modules: Vec::new(),
            skip_modules: Vec::new(),
        }
    }
}

impl ScanConfig {
    /// Get the global payload count limit for legacy modes.
    /// For Intelligent mode, this returns 0 as payload intensity is determined per-parameter.
    pub fn payload_count(&self) -> usize {
        match self.scan_mode {
            ScanMode::Fast => 50,
            ScanMode::Normal => 500,
            ScanMode::Thorough => 5000,
            ScanMode::Insane => usize::MAX, // All payloads
            // Intelligent mode uses per-parameter payload intensity, not global count
            ScanMode::Intelligent => 0,
        }
    }

    /// Determine if cloud/container security scanning should run
    /// Enabled for Thorough, Insane, and Intelligent modes
    pub fn enable_cloud_scanning(&self) -> bool {
        matches!(
            self.scan_mode,
            ScanMode::Thorough | ScanMode::Insane | ScanMode::Intelligent
        )
    }

    /// Determine if extended subdomain enumeration should be used
    /// Enabled for Thorough, Insane, and Intelligent modes
    pub fn subdomain_extended(&self) -> bool {
        matches!(
            self.scan_mode,
            ScanMode::Thorough | ScanMode::Insane | ScanMode::Intelligent
        )
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

/// Response data captured for ML learning (GDPR-compliant)
/// Stores only extracted features, NOT raw response bodies
/// This is embedded in vulnerabilities when ML is enabled
#[derive(Debug, Clone)]
pub struct MlResponseData {
    /// Extracted features from the response (GDPR-safe - no raw data)
    pub features: crate::ml::VulnFeatures,
    /// The payload type/category (not the actual payload content for privacy)
    pub payload_category: Option<String>,
}

/// Simplified HTTP response metadata for ML (GDPR-compliant)
/// Only stores metadata, not actual response bodies
#[derive(Debug, Clone)]
pub struct MlHttpResponse {
    pub status_code: u16,
    pub body_length: usize,
    pub duration_ms: u64,
    pub content_type: Option<String>,
}

impl MlHttpResponse {
    /// Create from an http_client::HttpResponse (stores metadata only)
    pub fn from_http_response(resp: &crate::http_client::HttpResponse) -> Self {
        Self {
            status_code: resp.status_code,
            body_length: resp.body.len(),
            duration_ms: resp.duration_ms,
            content_type: resp.headers.get("content-type").cloned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Vulnerability {
    pub id: String,
    #[serde(rename = "type")]
    pub vuln_type: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
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
    /// ML model confidence score (0.0-1.0), set by MlEnhancer after scoring
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_confidence: Option<f64>,
    /// ML response data for learning (not serialized to reports)
    /// This field is skipped during serialization and defaults to None
    #[serde(skip)]
    pub ml_data: Option<MlResponseData>,
}

impl Vulnerability {
    /// Attach ML response data to this vulnerability for learning (GDPR-compliant)
    /// Extracts features immediately - no raw data is stored
    /// Call this when creating a vulnerability to enable ML learning
    pub fn with_ml_data(
        mut self,
        response: &crate::http_client::HttpResponse,
        baseline: Option<&crate::http_client::HttpResponse>,
        payload: Option<&str>,
    ) -> Self {
        // Extract features immediately - don't store raw response data
        let extractor = crate::ml::FeatureExtractor::new();
        let features = extractor.extract(response, baseline, payload);

        // Categorize payload without storing actual content
        let payload_category = payload.map(|p| Self::categorize_payload(p));

        self.ml_data = Some(MlResponseData {
            features,
            payload_category,
        });
        self
    }

    /// Categorize a payload into a privacy-safe category
    fn categorize_payload(payload: &str) -> String {
        let p = payload.to_lowercase();
        if p.contains("select") || p.contains("union") || p.contains("'--") {
            "sqli".to_string()
        } else if p.contains("<script") || p.contains("javascript:") || p.contains("onerror") {
            "xss".to_string()
        } else if p.contains("http://") || p.contains("https://") || p.contains("file://") {
            "ssrf".to_string()
        } else if p.contains(";") && (p.contains("ls") || p.contains("cat") || p.contains("id")) {
            "cmdi".to_string()
        } else if p.contains("../") || p.contains("..\\") {
            "path_traversal".to_string()
        } else if p.contains("sleep") || p.contains("waitfor") || p.contains("benchmark") {
            "time_based".to_string()
        } else {
            "other".to_string()
        }
    }

    /// Check if this vulnerability has ML data attached
    pub fn has_ml_data(&self) -> bool {
        self.ml_data.is_some()
    }

    /// Get extracted ML features (GDPR-safe - no raw data)
    pub fn get_ml_features(&self) -> Option<&crate::ml::VulnFeatures> {
        self.ml_data.as_ref().map(|ml| &ml.features)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    #[default]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    High,
    #[default]
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

/// Source of a discovered parameter
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParameterSource {
    HtmlForm,
    UrlQueryString,
    JavaScriptMined,
    ApiEndpoint,
    GraphQL,
    RequestHeader,
    Cookie,
    Unknown,
}

/// Type of endpoint being tested
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointType {
    FormSubmission,
    RestApi,
    GraphQlApi,
    JsonRpc,
    StaticContent,
    Unknown,
}

/// Context passed to scanners for intelligent testing
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Where this parameter was discovered
    pub parameter_source: ParameterSource,

    /// Type of endpoint
    pub endpoint_type: EndpointType,

    /// Detected technologies (framework, server, language)
    pub detected_tech: Vec<String>,

    /// Primary framework if detected (e.g., "Django", "Laravel", "Next.js")
    pub framework: Option<String>,

    /// Server type (e.g., "nginx", "Apache")
    pub server: Option<String>,

    /// Other parameters discovered on this endpoint
    pub other_parameters: Vec<String>,

    /// Is this a JSON API endpoint
    pub is_json_api: bool,

    /// Is this a GraphQL endpoint
    pub is_graphql: bool,

    /// Form structure if from a form
    pub form_fields: Vec<String>,

    /// Content-Type of responses
    pub content_type: Option<String>,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            parameter_source: ParameterSource::Unknown,
            endpoint_type: EndpointType::Unknown,
            detected_tech: Vec::new(),
            framework: None,
            server: None,
            other_parameters: Vec::new(),
            is_json_api: false,
            is_graphql: false,
            form_fields: Vec::new(),
            content_type: None,
        }
    }
}

impl ScanContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a specific technology is detected
    pub fn has_tech(&self, tech: &str) -> bool {
        self.detected_tech
            .iter()
            .any(|t| t.to_lowercase().contains(&tech.to_lowercase()))
    }

    /// Check if framework matches
    pub fn is_framework(&self, name: &str) -> bool {
        self.framework
            .as_ref()
            .map(|f| f.to_lowercase().contains(&name.to_lowercase()))
            .unwrap_or(false)
    }
}
