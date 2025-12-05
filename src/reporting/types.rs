// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::{ScanResults, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub include_executive_summary: bool,
    pub include_charts: bool,
    pub include_remediation: bool,
    pub include_compliance_mapping: bool,
    pub include_owasp_mapping: bool,
    pub deduplicate: bool,
    pub filter_false_positives: bool,
    pub min_severity: Option<String>,
    pub branding: Option<BrandingConfig>,
    pub template: Option<String>,
    pub compare_with: Option<String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Json,
            include_executive_summary: true,
            include_charts: true,
            include_remediation: true,
            include_compliance_mapping: true,
            include_owasp_mapping: true,
            deduplicate: true,
            filter_false_positives: true,
            min_severity: None,
            branding: None,
            template: None,
            compare_with: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Pdf,
    Html,
    Json,
    Csv,
    Sarif,
    JunitXml,
    Xlsx,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrandingConfig {
    pub company_name: String,
    pub logo_path: Option<String>,
    pub primary_color: String,
    pub secondary_color: String,
    pub report_title: Option<String>,
    pub footer_text: Option<String>,
}

impl Default for BrandingConfig {
    fn default() -> Self {
        Self {
            company_name: "Security Baseline Scanner".to_string(),
            logo_path: None,
            primary_color: "#2563eb".to_string(),
            secondary_color: "#1e40af".to_string(),
            report_title: None,
            footer_text: Some("Confidential - For Internal Use Only".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportOutput {
    pub format: ReportFormat,
    pub data: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnhancedReport {
    pub scan_results: ScanResults,
    pub executive_summary: ExecutiveSummary,
    pub vulnerability_breakdown: VulnerabilityBreakdown,
    pub owasp_mapping: HashMap<String, Vec<Vulnerability>>,
    pub cwe_mapping: HashMap<String, Vec<Vulnerability>>,
    pub compliance_mapping: ComplianceMapping,
    pub risk_assessment: RiskAssessment,
    pub trends: Option<TrendAnalysis>,
    pub generated_at: String,
    pub report_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutiveSummary {
    pub target: String,
    pub scan_date: String,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub risk_score: f64,
    pub risk_level: String,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityBreakdown {
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_confidence: HashMap<String, usize>,
    pub verified_count: usize,
    pub unverified_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceMapping {
    pub pci_dss: HashMap<String, Vec<String>>,
    pub hipaa: HashMap<String, Vec<String>>,
    pub soc2: HashMap<String, Vec<String>>,
    pub iso27001: HashMap<String, Vec<String>>,
    pub gdpr: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub overall_risk_score: f64,
    pub risk_level: String,
    pub risk_matrix: Vec<RiskMatrixEntry>,
    pub attack_surface_score: f64,
    pub exploitability_score: f64,
    pub business_impact_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskMatrixEntry {
    pub vulnerability_id: String,
    pub vulnerability_type: String,
    pub likelihood: String,
    pub impact: String,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendAnalysis {
    pub previous_scan_id: String,
    pub previous_scan_date: String,
    pub new_vulnerabilities: usize,
    pub fixed_vulnerabilities: usize,
    pub recurring_vulnerabilities: usize,
    pub risk_score_change: f64,
    pub severity_changes: HashMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunitTestSuites {
    pub name: String,
    pub tests: usize,
    pub failures: usize,
    pub time: f64,
    pub testsuites: Vec<JunitTestSuite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunitTestSuite {
    pub name: String,
    pub tests: usize,
    pub failures: usize,
    pub time: f64,
    pub testcases: Vec<JunitTestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunitTestCase {
    pub name: String,
    pub classname: String,
    pub time: f64,
    pub failure: Option<JunitFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JunitFailure {
    pub message: String,
    #[serde(rename = "type")]
    pub failure_type: String,
    pub text: String,
}
