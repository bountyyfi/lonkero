// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::{
    deduplication::VulnerabilityDeduplicator,
    mappings::{ComplianceMapper, CWEMapper, OWASPMapper},
    types::*,
};
use crate::types::{ScanResults, Severity, Vulnerability};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;

pub struct ReportEngine {
    deduplicator: VulnerabilityDeduplicator,
}

impl ReportEngine {
    pub fn new() -> Self {
        Self {
            deduplicator: VulnerabilityDeduplicator::new(),
        }
    }

    pub async fn generate_report(
        &self,
        scan_results: ScanResults,
        config: ReportConfig,
    ) -> Result<ReportOutput> {
        let mut processed_results = scan_results.clone();

        if config.filter_false_positives {
            processed_results.vulnerabilities = self
                .deduplicator
                .filter_false_positives(processed_results.vulnerabilities);
        }

        if config.deduplicate {
            processed_results.vulnerabilities = self
                .deduplicator
                .deduplicate_advanced(processed_results.vulnerabilities);
        }

        if let Some(min_severity) = &config.min_severity {
            processed_results.vulnerabilities = self
                .deduplicator
                .filter_by_severity(processed_results.vulnerabilities, min_severity);
        }

        let enhanced_report = self.create_enhanced_report(processed_results, &config).await?;

        match config.format {
            ReportFormat::Pdf => self.generate_pdf_report(&enhanced_report, &config).await,
            ReportFormat::Html => self.generate_html_report(&enhanced_report, &config).await,
            ReportFormat::Json => self.generate_json_report(&enhanced_report).await,
            ReportFormat::Csv => self.generate_csv_report(&enhanced_report).await,
            ReportFormat::Sarif => self.generate_sarif_report(&enhanced_report).await,
            ReportFormat::JunitXml => self.generate_junit_report(&enhanced_report).await,
            ReportFormat::Xlsx => self.generate_xlsx_report(&enhanced_report).await,
            ReportFormat::Markdown => self.generate_markdown_report(&enhanced_report, &config).await,
        }
    }

    async fn create_enhanced_report(
        &self,
        scan_results: ScanResults,
        config: &ReportConfig,
    ) -> Result<EnhancedReport> {
        let executive_summary = self.generate_executive_summary(&scan_results);
        let vulnerability_breakdown = self.generate_vulnerability_breakdown(&scan_results.vulnerabilities);
        let owasp_mapping = if config.include_owasp_mapping {
            OWASPMapper::map_to_owasp_top10(&scan_results.vulnerabilities)
        } else {
            HashMap::new()
        };
        let cwe_mapping = CWEMapper::map_to_cwe(&scan_results.vulnerabilities);
        let compliance_mapping = if config.include_compliance_mapping {
            self.generate_compliance_mapping(&scan_results.vulnerabilities)
        } else {
            ComplianceMapping {
                pci_dss: HashMap::new(),
                hipaa: HashMap::new(),
                soc2: HashMap::new(),
                iso27001: HashMap::new(),
                gdpr: HashMap::new(),
                nist_csf: HashMap::new(),
                dora: HashMap::new(),
                nis2: HashMap::new(),
            }
        };
        let risk_assessment = self.generate_risk_assessment(&scan_results.vulnerabilities);
        let trends = None;

        Ok(EnhancedReport {
            scan_results,
            executive_summary,
            vulnerability_breakdown,
            owasp_mapping,
            cwe_mapping,
            compliance_mapping,
            risk_assessment,
            trends,
            generated_at: Utc::now().to_rfc3339(),
            report_version: "1.0.0".to_string(),
        })
    }

    fn generate_executive_summary(&self, scan_results: &ScanResults) -> ExecutiveSummary {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for vuln in &scan_results.vulnerabilities {
            match vuln.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Info => info_count += 1,
            }
        }

        let risk_score = self.calculate_risk_score(&scan_results.vulnerabilities);
        let risk_level = self.calculate_risk_level(risk_score);

        let key_findings = self.generate_key_findings(&scan_results.vulnerabilities);
        let recommendations = self.generate_recommendations(&scan_results.vulnerabilities);

        ExecutiveSummary {
            target: scan_results.target.clone(),
            scan_date: scan_results.started_at.clone(),
            total_vulnerabilities: scan_results.vulnerabilities.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            risk_score,
            risk_level,
            key_findings,
            recommendations,
            duration_seconds: scan_results.duration_seconds,
        }
    }

    fn generate_vulnerability_breakdown(&self, vulnerabilities: &[Vulnerability]) -> VulnerabilityBreakdown {
        let mut by_severity = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut verified_count = 0;

        for vuln in vulnerabilities {
            *by_severity.entry(vuln.severity.to_string()).or_insert(0) += 1;
            *by_category.entry(vuln.category.clone()).or_insert(0) += 1;
            *by_confidence.entry(vuln.confidence.to_string()).or_insert(0) += 1;
            if vuln.verified {
                verified_count += 1;
            }
        }

        VulnerabilityBreakdown {
            by_severity,
            by_category,
            by_confidence,
            verified_count,
            unverified_count: vulnerabilities.len() - verified_count,
        }
    }

    fn generate_compliance_mapping(&self, vulnerabilities: &[Vulnerability]) -> ComplianceMapping {
        ComplianceMapping {
            pci_dss: ComplianceMapper::map_to_pci_dss(vulnerabilities),
            hipaa: ComplianceMapper::map_to_hipaa(vulnerabilities),
            soc2: ComplianceMapper::map_to_soc2(vulnerabilities),
            iso27001: ComplianceMapper::map_to_iso27001(vulnerabilities),
            gdpr: ComplianceMapper::map_to_gdpr(vulnerabilities),
            nist_csf: ComplianceMapper::map_to_nist_csf(vulnerabilities),
            dora: ComplianceMapper::map_to_dora(vulnerabilities),
            nis2: ComplianceMapper::map_to_nis2(vulnerabilities),
        }
    }

    fn generate_risk_assessment(&self, vulnerabilities: &[Vulnerability]) -> RiskAssessment {
        let overall_risk_score = self.calculate_risk_score(vulnerabilities);
        let risk_level = self.calculate_risk_level(overall_risk_score);

        let mut risk_matrix = Vec::new();
        for vuln in vulnerabilities.iter().take(20) {
            risk_matrix.push(RiskMatrixEntry {
                vulnerability_id: vuln.id.clone(),
                vulnerability_type: vuln.vuln_type.clone(),
                likelihood: self.calculate_likelihood(vuln),
                impact: self.calculate_impact(vuln),
                risk_score: vuln.cvss as f64,
            });
        }

        let attack_surface_score = self.calculate_attack_surface_score(vulnerabilities);
        let exploitability_score = self.calculate_exploitability_score(vulnerabilities);
        let business_impact_score = self.calculate_business_impact_score(vulnerabilities);

        RiskAssessment {
            overall_risk_score,
            risk_level,
            risk_matrix,
            attack_surface_score,
            exploitability_score,
            business_impact_score,
        }
    }

    fn calculate_risk_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }

        let mut total_score = 0.0;
        let mut weights_sum = 0.0;

        for vuln in vulnerabilities {
            let severity_weight = match vuln.severity {
                Severity::Critical => 5.0,
                Severity::High => 4.0,
                Severity::Medium => 3.0,
                Severity::Low => 2.0,
                Severity::Info => 1.0,
            };

            let confidence_multiplier = match vuln.confidence {
                crate::types::Confidence::High => 1.0,
                crate::types::Confidence::Medium => 0.7,
                crate::types::Confidence::Low => 0.4,
            };

            total_score += vuln.cvss as f64 * severity_weight * confidence_multiplier;
            weights_sum += severity_weight * confidence_multiplier;
        }

        if weights_sum == 0.0 {
            0.0
        } else {
            (total_score / weights_sum).min(10.0)
        }
    }

    fn calculate_risk_level(&self, score: f64) -> String {
        match score {
            s if s >= 9.0 => "CRITICAL",
            s if s >= 7.0 => "HIGH",
            s if s >= 4.0 => "MEDIUM",
            s if s >= 1.0 => "LOW",
            _ => "INFO",
        }
        .to_string()
    }

    fn calculate_likelihood(&self, vuln: &Vulnerability) -> String {
        match vuln.confidence {
            crate::types::Confidence::High => "High",
            crate::types::Confidence::Medium => "Medium",
            crate::types::Confidence::Low => "Low",
        }
        .to_string()
    }

    fn calculate_impact(&self, vuln: &Vulnerability) -> String {
        match vuln.severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Informational",
        }
        .to_string()
    }

    fn calculate_attack_surface_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        let unique_urls: std::collections::HashSet<_> =
            vulnerabilities.iter().map(|v| &v.url).collect();

        (unique_urls.len() as f64 / 10.0).min(10.0)
    }

    fn calculate_exploitability_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }

        let verified_count = vulnerabilities.iter().filter(|v| v.verified).count();
        let high_confidence = vulnerabilities
            .iter()
            .filter(|v| v.confidence == crate::types::Confidence::High)
            .count();

        ((verified_count + high_confidence) as f64 / (vulnerabilities.len() * 2) as f64 * 10.0).min(10.0)
    }

    fn calculate_business_impact_score(&self, vulnerabilities: &[Vulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }

        let critical_count = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        let high_count = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();

        ((critical_count * 5 + high_count * 3) as f64 / vulnerabilities.len() as f64).min(10.0)
    }

    fn generate_key_findings(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut findings = Vec::new();

        let critical_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .collect();

        if !critical_vulns.is_empty() {
            findings.push(format!(
                "{} critical vulnerabilities discovered that require immediate attention",
                critical_vulns.len()
            ));
        }

        let vuln_types: std::collections::HashMap<_, usize> = vulnerabilities
            .iter()
            .fold(HashMap::new(), |mut map, v| {
                *map.entry(&v.vuln_type).or_insert(0) += 1;
                map
            });

        if let Some((vuln_type, count)) = vuln_types.iter().max_by_key(|(_, &count)| count) {
            findings.push(format!(
                "{} is the most common vulnerability type with {} occurrences",
                vuln_type, count
            ));
        }

        let injection_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| {
                v.category == "Injection" || v.vuln_type.contains("Injection") || v.vuln_type.contains("SQL") || v.vuln_type.contains("XSS")
            })
            .collect();

        if !injection_vulns.is_empty() {
            findings.push(format!(
                "{} injection-related vulnerabilities found, indicating input validation issues",
                injection_vulns.len()
            ));
        }

        findings
    }

    fn generate_recommendations(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let critical_count = vulnerabilities
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();

        if critical_count > 0 {
            recommendations.push(
                "Immediately address all critical vulnerabilities within 24-48 hours".to_string(),
            );
        }

        let injection_count = vulnerabilities
            .iter()
            .filter(|v| v.category == "Injection")
            .count();

        if injection_count > 5 {
            recommendations.push(
                "Implement comprehensive input validation and parameterized queries across the application".to_string(),
            );
        }

        let auth_issues = vulnerabilities
            .iter()
            .filter(|v| {
                v.vuln_type.contains("Authentication") || v.vuln_type.contains("Authorization")
            })
            .count();

        if auth_issues > 0 {
            recommendations.push(
                "Review and strengthen authentication and authorization mechanisms".to_string(),
            );
        }

        recommendations.push(
            "Conduct regular security assessments and penetration testing".to_string(),
        );
        recommendations.push(
            "Implement a security awareness training program for developers".to_string(),
        );

        recommendations
    }

    async fn generate_pdf_report(
        &self,
        report: &EnhancedReport,
        config: &ReportConfig,
    ) -> Result<ReportOutput> {
        let pdf_generator = crate::reporting::formats::pdf::PdfReportGenerator::new();
        let branding = config.branding.clone().unwrap_or_default();
        let data = pdf_generator.generate(report, &branding).await
            .context("Failed to generate PDF report")?;

        Ok(ReportOutput {
            format: ReportFormat::Pdf,
            data,
            filename: format!("security-report-{}.pdf", report.scan_results.scan_id),
            mime_type: "application/pdf".to_string(),
        })
    }

    async fn generate_html_report(
        &self,
        report: &EnhancedReport,
        config: &ReportConfig,
    ) -> Result<ReportOutput> {
        let html_generator = crate::reporting::formats::html::HtmlReportGenerator::new();
        let branding = config.branding.clone().unwrap_or_default();
        let data = html_generator.generate(report, &branding).await
            .context("Failed to generate HTML report")?;

        Ok(ReportOutput {
            format: ReportFormat::Html,
            data,
            filename: format!("security-report-{}.html", report.scan_results.scan_id),
            mime_type: "text/html".to_string(),
        })
    }

    async fn generate_json_report(&self, report: &EnhancedReport) -> Result<ReportOutput> {
        let json_generator = crate::reporting::formats::json::JsonReportGenerator::new();
        let data = json_generator.generate(report).await
            .context("Failed to generate JSON report")?;

        Ok(ReportOutput {
            format: ReportFormat::Json,
            data,
            filename: format!("security-report-{}.json", report.scan_results.scan_id),
            mime_type: "application/json".to_string(),
        })
    }

    async fn generate_csv_report(&self, report: &EnhancedReport) -> Result<ReportOutput> {
        let csv_generator = crate::reporting::formats::csv::CsvReportGenerator::new();
        let data = csv_generator.generate(report).await
            .context("Failed to generate CSV report")?;

        Ok(ReportOutput {
            format: ReportFormat::Csv,
            data,
            filename: format!("security-report-{}.csv", report.scan_results.scan_id),
            mime_type: "text/csv".to_string(),
        })
    }

    async fn generate_sarif_report(&self, report: &EnhancedReport) -> Result<ReportOutput> {
        let sarif_generator = crate::reporting::formats::sarif::SarifReportGenerator::new();
        let data = sarif_generator.generate(report).await
            .context("Failed to generate SARIF report")?;

        Ok(ReportOutput {
            format: ReportFormat::Sarif,
            data,
            filename: format!("security-report-{}.sarif", report.scan_results.scan_id),
            mime_type: "application/json".to_string(),
        })
    }

    async fn generate_junit_report(&self, report: &EnhancedReport) -> Result<ReportOutput> {
        let junit_generator = crate::reporting::formats::junit::JunitReportGenerator::new();
        let data = junit_generator.generate(report).await
            .context("Failed to generate JUnit XML report")?;

        Ok(ReportOutput {
            format: ReportFormat::JunitXml,
            data,
            filename: format!("security-report-{}.xml", report.scan_results.scan_id),
            mime_type: "application/xml".to_string(),
        })
    }

    async fn generate_xlsx_report(&self, report: &EnhancedReport) -> Result<ReportOutput> {
        let xlsx_generator = crate::reporting::formats::xlsx::XlsxReportGenerator::new();
        let data = xlsx_generator.generate(report).await
            .context("Failed to generate XLSX report")?;

        Ok(ReportOutput {
            format: ReportFormat::Xlsx,
            data,
            filename: format!("security-report-{}.xlsx", report.scan_results.scan_id),
            mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(),
        })
    }

    async fn generate_markdown_report(
        &self,
        report: &EnhancedReport,
        config: &ReportConfig,
    ) -> Result<ReportOutput> {
        let md_generator = crate::reporting::formats::markdown::MarkdownReportGenerator::new();
        let branding = config.branding.clone().unwrap_or_default();
        let data = md_generator.generate(report, &branding).await
            .context("Failed to generate Markdown report")?;

        Ok(ReportOutput {
            format: ReportFormat::Markdown,
            data,
            filename: format!("security-report-{}.md", report.scan_results.scan_id),
            mime_type: "text/markdown".to_string(),
        })
    }
}

impl Default for ReportEngine {
    fn default() -> Self {
        Self::new()
    }
}
