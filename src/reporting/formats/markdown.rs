// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{BrandingConfig, EnhancedReport};
use anyhow::Result;

pub struct MarkdownReportGenerator;

impl MarkdownReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(
        &self,
        report: &EnhancedReport,
        branding: &BrandingConfig,
    ) -> Result<Vec<u8>> {
        let markdown = self.generate_markdown(report, branding);
        Ok(markdown.into_bytes())
    }

    fn generate_markdown(&self, report: &EnhancedReport, branding: &BrandingConfig) -> String {
        let mut md = String::new();

        md.push_str(&format!(
            "# {} - Security Assessment Report\n\n",
            branding.company_name
        ));
        md.push_str(&format!("**Target:** {}\n\n", report.scan_results.target));
        md.push_str(&format!("**Scan ID:** {}\n\n", report.scan_results.scan_id));
        md.push_str(&format!(
            "**Scan Date:** {}\n\n",
            report.executive_summary.scan_date
        ));
        md.push_str(&format!("**Generated:** {}\n\n", report.generated_at));
        md.push_str("---\n\n");

        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!("### Risk Assessment\n\n"));
        md.push_str(&format!(
            "**Overall Risk Score:** {:.2}/10.0 ({})\n\n",
            report.executive_summary.risk_score, report.executive_summary.risk_level
        ));

        md.push_str("### Vulnerability Summary\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!(
            "| [CRITICAL] | {} |\n",
            report.executive_summary.critical_count
        ));
        md.push_str(&format!(
            "| [HIGH] | {} |\n",
            report.executive_summary.high_count
        ));
        md.push_str(&format!(
            "| [MEDIUM] | {} |\n",
            report.executive_summary.medium_count
        ));
        md.push_str(&format!(
            "| [LOW] | {} |\n",
            report.executive_summary.low_count
        ));
        md.push_str(&format!(
            "| [INFO] | {} |\n",
            report.executive_summary.info_count
        ));
        md.push_str(&format!(
            "| **Total** | **{}** |\n\n",
            report.executive_summary.total_vulnerabilities
        ));

        md.push_str("### Key Findings\n\n");
        for finding in &report.executive_summary.key_findings {
            md.push_str(&format!("- {}\n", finding));
        }
        md.push_str("\n");

        md.push_str("### Recommendations\n\n");
        for (idx, rec) in report.executive_summary.recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", idx + 1, rec));
        }
        md.push_str("\n---\n\n");

        md.push_str("## Vulnerability Breakdown\n\n");
        md.push_str("### By Severity\n\n");
        for (severity, count) in &report.vulnerability_breakdown.by_severity {
            md.push_str(&format!("- **{}:** {}\n", severity, count));
        }
        md.push_str("\n");

        md.push_str("### By Category\n\n");
        for (category, count) in &report.vulnerability_breakdown.by_category {
            md.push_str(&format!("- **{}:** {}\n", category, count));
        }
        md.push_str("\n---\n\n");

        md.push_str("## OWASP Top 10 (2021) Mapping\n\n");
        for (category, vulns) in &report.owasp_mapping {
            md.push_str(&format!("### {}\n\n", category));
            md.push_str(&format!(
                "**Affected Vulnerabilities:** {}\n\n",
                vulns.len()
            ));
            md.push_str(&format!(
                "{}\n\n",
                crate::reporting::mappings::OWASPMapper::get_owasp_description(category)
            ));
        }
        md.push_str("---\n\n");

        md.push_str("## Compliance Mapping\n\n");

        if !report.compliance_mapping.pci_dss.is_empty() {
            md.push_str("### PCI-DSS Requirements\n\n");
            for (req, vulns) in &report.compliance_mapping.pci_dss {
                md.push_str(&format!("- **{}**: {} findings\n", req, vulns.len()));
            }
            md.push_str("\n");
        }

        if !report.compliance_mapping.hipaa.is_empty() {
            md.push_str("### HIPAA Requirements\n\n");
            for (req, vulns) in &report.compliance_mapping.hipaa {
                md.push_str(&format!("- **{}**: {} findings\n", req, vulns.len()));
            }
            md.push_str("\n");
        }

        if !report.compliance_mapping.soc2.is_empty() {
            md.push_str("### SOC 2 Controls\n\n");
            for (req, vulns) in &report.compliance_mapping.soc2 {
                md.push_str(&format!("- **{}**: {} findings\n", req, vulns.len()));
            }
            md.push_str("\n");
        }

        md.push_str("---\n\n");

        md.push_str("## Detailed Findings\n\n");
        for (idx, vuln) in report.scan_results.vulnerabilities.iter().enumerate() {
            md.push_str(&format!(
                "### {}. {} {}\n\n",
                idx + 1,
                self.get_severity_emoji(&vuln.severity),
                vuln.vuln_type
            ));

            md.push_str(&format!(
                "**Severity:** {} | **Confidence:** {} | **CVSS:** {:.1}\n\n",
                vuln.severity, vuln.confidence, vuln.cvss
            ));

            md.push_str(&format!(
                "**CWE:** {} | **Category:** {}\n\n",
                vuln.cwe, vuln.category
            ));

            md.push_str(&format!("**URL:** `{}`\n\n", vuln.url));

            if let Some(param) = &vuln.parameter {
                md.push_str(&format!("**Parameter:** `{}`\n\n", param));
            }

            if !vuln.payload.is_empty() {
                md.push_str(&format!("**Payload:**\n\n```\n{}\n```\n\n", vuln.payload));
            }

            md.push_str(&format!("**Description:**\n\n{}\n\n", vuln.description));

            if let Some(evidence) = &vuln.evidence {
                md.push_str(&format!("**Evidence:**\n\n```\n{}\n```\n\n", evidence));
            }

            md.push_str(&format!(
                "**Remediation:**\n\n```\n{}\n```\n\n",
                vuln.remediation
            ));

            md.push_str("---\n\n");
        }

        if let Some(footer) = &branding.footer_text {
            md.push_str(&format!("\n---\n\n*{}*\n", footer));
        }

        md
    }

    fn get_severity_emoji(&self, severity: &crate::types::Severity) -> &str {
        match severity {
            crate::types::Severity::Critical => "[CRITICAL]",
            crate::types::Severity::High => "[HIGH]",
            crate::types::Severity::Medium => "[MEDIUM]",
            crate::types::Severity::Low => "[LOW]",
            crate::types::Severity::Info => "[INFO]",
        }
    }
}

impl Default for MarkdownReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
