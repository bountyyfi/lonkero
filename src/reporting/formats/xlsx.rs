// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::EnhancedReport;
use anyhow::Result;
use rust_xlsxwriter::*;

pub struct XlsxReportGenerator;

impl XlsxReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport) -> Result<Vec<u8>> {
        let mut workbook = Workbook::new();

        self.add_summary_sheet(&mut workbook, report)?;
        self.add_vulnerabilities_sheet(&mut workbook, report)?;
        self.add_owasp_sheet(&mut workbook, report)?;
        self.add_compliance_sheet(&mut workbook, report)?;

        let temp_path = format!("/tmp/report_{}.xlsx", report.scan_results.scan_id);
        workbook.save(&temp_path)?;

        let data = std::fs::read(&temp_path)?;
        let _ = std::fs::remove_file(&temp_path);

        Ok(data)
    }

    fn add_summary_sheet(&self, workbook: &mut Workbook, report: &EnhancedReport) -> Result<()> {
        let worksheet = workbook.add_worksheet();
        worksheet.set_name("Summary")?;

        let header_format = Format::new()
            .set_bold()
            .set_font_size(14)
            .set_background_color(Color::RGB(0x2563eb));

        let bold_format = Format::new().set_bold();

        let mut row = 0;
        worksheet.write_with_format(row, 0, "Security Assessment Report", &header_format)?;
        row += 2;

        worksheet.write_with_format(row, 0, "Target:", &bold_format)?;
        worksheet.write(row, 1, &report.scan_results.target)?;
        row += 1;

        worksheet.write_with_format(row, 0, "Scan ID:", &bold_format)?;
        worksheet.write(row, 1, &report.scan_results.scan_id)?;
        row += 1;

        worksheet.write_with_format(row, 0, "Scan Date:", &bold_format)?;
        worksheet.write(row, 1, &report.executive_summary.scan_date)?;
        row += 2;

        worksheet.write_with_format(row, 0, "Risk Score:", &bold_format)?;
        worksheet.write(row, 1, report.executive_summary.risk_score)?;
        row += 1;

        worksheet.write_with_format(row, 0, "Risk Level:", &bold_format)?;
        worksheet.write(row, 1, &report.executive_summary.risk_level)?;
        row += 2;

        worksheet.write_with_format(row, 0, "Vulnerability Summary", &header_format)?;
        row += 1;

        worksheet.write_with_format(row, 0, "Severity", &bold_format)?;
        worksheet.write_with_format(row, 1, "Count", &bold_format)?;
        row += 1;

        worksheet.write(row, 0, "Critical")?;
        worksheet.write(row, 1, report.executive_summary.critical_count as u32)?;
        row += 1;

        worksheet.write(row, 0, "High")?;
        worksheet.write(row, 1, report.executive_summary.high_count as u32)?;
        row += 1;

        worksheet.write(row, 0, "Medium")?;
        worksheet.write(row, 1, report.executive_summary.medium_count as u32)?;
        row += 1;

        worksheet.write(row, 0, "Low")?;
        worksheet.write(row, 1, report.executive_summary.low_count as u32)?;
        row += 1;

        worksheet.write(row, 0, "Info")?;
        worksheet.write(row, 1, report.executive_summary.info_count as u32)?;

        worksheet.set_column_width(0, 20)?;
        worksheet.set_column_width(1, 50)?;

        Ok(())
    }

    fn add_vulnerabilities_sheet(&self, workbook: &mut Workbook, report: &EnhancedReport) -> Result<()> {
        let worksheet = workbook.add_worksheet();
        worksheet.set_name("Vulnerabilities")?;

        let header_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x2563eb));

        let mut row = 0;
        worksheet.write_with_format(row, 0, "ID", &header_format)?;
        worksheet.write_with_format(row, 1, "Type", &header_format)?;
        worksheet.write_with_format(row, 2, "Severity", &header_format)?;
        worksheet.write_with_format(row, 3, "Confidence", &header_format)?;
        worksheet.write_with_format(row, 4, "Category", &header_format)?;
        worksheet.write_with_format(row, 5, "URL", &header_format)?;
        worksheet.write_with_format(row, 6, "Parameter", &header_format)?;
        worksheet.write_with_format(row, 7, "CWE", &header_format)?;
        worksheet.write_with_format(row, 8, "CVSS", &header_format)?;
        worksheet.write_with_format(row, 9, "Verified", &header_format)?;
        worksheet.write_with_format(row, 10, "Description", &header_format)?;
        worksheet.write_with_format(row, 11, "Remediation", &header_format)?;

        row += 1;

        for vuln in &report.scan_results.vulnerabilities {
            worksheet.write(row, 0, &vuln.id)?;
            worksheet.write(row, 1, &vuln.vuln_type)?;
            worksheet.write(row, 2, &vuln.severity.to_string())?;
            worksheet.write(row, 3, &vuln.confidence.to_string())?;
            worksheet.write(row, 4, &vuln.category)?;
            worksheet.write(row, 5, &vuln.url)?;
            worksheet.write(row, 6, &vuln.parameter.clone().unwrap_or_default())?;
            worksheet.write(row, 7, &vuln.cwe)?;
            worksheet.write(row, 8, vuln.cvss)?;
            worksheet.write(row, 9, vuln.verified)?;
            worksheet.write(row, 10, &vuln.description)?;
            worksheet.write(row, 11, &vuln.remediation)?;

            row += 1;
        }

        worksheet.set_column_width(0, 15)?;
        worksheet.set_column_width(1, 25)?;
        worksheet.set_column_width(2, 12)?;
        worksheet.set_column_width(3, 12)?;
        worksheet.set_column_width(4, 15)?;
        worksheet.set_column_width(5, 50)?;
        worksheet.set_column_width(6, 15)?;
        worksheet.set_column_width(7, 10)?;
        worksheet.set_column_width(8, 8)?;
        worksheet.set_column_width(9, 10)?;
        worksheet.set_column_width(10, 60)?;
        worksheet.set_column_width(11, 60)?;

        Ok(())
    }

    fn add_owasp_sheet(&self, workbook: &mut Workbook, report: &EnhancedReport) -> Result<()> {
        let worksheet = workbook.add_worksheet();
        worksheet.set_name("OWASP Top 10")?;

        let header_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x2563eb));

        let mut row = 0;
        worksheet.write_with_format(row, 0, "OWASP Category", &header_format)?;
        worksheet.write_with_format(row, 1, "Vulnerability Count", &header_format)?;

        row += 1;

        for (category, vulns) in &report.owasp_mapping {
            worksheet.write(row, 0, category)?;
            worksheet.write(row, 1, vulns.len() as u64)?;
            row += 1;
        }

        worksheet.set_column_width(0, 50)?;
        worksheet.set_column_width(1, 20)?;

        Ok(())
    }

    fn add_compliance_sheet(&self, workbook: &mut Workbook, report: &EnhancedReport) -> Result<()> {
        let worksheet = workbook.add_worksheet();
        worksheet.set_name("Compliance")?;

        let header_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x2563eb));

        let mut row = 0;

        worksheet.write_with_format(row, 0, "PCI-DSS Requirements", &header_format)?;
        row += 1;

        for (req, vulns) in &report.compliance_mapping.pci_dss {
            worksheet.write(row, 0, req)?;
            worksheet.write(row, 1, vulns.len() as u64)?;
            row += 1;
        }

        row += 2;
        worksheet.write_with_format(row, 0, "HIPAA Requirements", &header_format)?;
        row += 1;

        for (req, vulns) in &report.compliance_mapping.hipaa {
            worksheet.write(row, 0, req)?;
            worksheet.write(row, 1, vulns.len() as u64)?;
            row += 1;
        }

        row += 2;
        worksheet.write_with_format(row, 0, "SOC 2 Controls", &header_format)?;
        row += 1;

        for (req, vulns) in &report.compliance_mapping.soc2 {
            worksheet.write(row, 0, req)?;
            worksheet.write(row, 1, vulns.len() as u64)?;
            row += 1;
        }

        worksheet.set_column_width(0, 60)?;
        worksheet.set_column_width(1, 20)?;

        Ok(())
    }
}

impl Default for XlsxReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
