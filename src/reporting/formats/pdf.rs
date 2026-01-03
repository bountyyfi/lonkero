// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{BrandingConfig, EnhancedReport};
use crate::types::Severity;
use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptions};
use std::ffi::OsStr;

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(
        &self,
        report: &EnhancedReport,
        branding: &BrandingConfig,
    ) -> Result<Vec<u8>> {
        // Generate PDF-optimized HTML
        let html = self.generate_pdf_html(report, branding);

        // Convert HTML to PDF using headless Chrome
        let pdf_data = self.html_to_pdf(&html)?;

        Ok(pdf_data)
    }

    fn generate_pdf_html(&self, report: &EnhancedReport, branding: &BrandingConfig) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {target}</title>
    <style>
        {css}
    </style>
</head>
<body>
    <div class="watermark">LONKERO</div>

    {header}
    {executive_summary}
    {vulnerabilities}
    {owasp_mapping}
    {compliance}
    {footer}
</body>
</html>"#,
            target = self.escape_html(&report.scan_results.target),
            css = self.get_pdf_css(),
            header = self.generate_header(report, branding),
            executive_summary = self.generate_executive_summary(&report.executive_summary),
            vulnerabilities = self.generate_vulnerabilities(&report.scan_results.vulnerabilities),
            owasp_mapping = self.generate_owasp_mapping(report),
            compliance = self.generate_compliance(report),
            footer = self.generate_footer(branding),
        )
    }

    fn get_pdf_css(&self) -> &'static str {
        r#"
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        @page {
            size: A4;
            margin: 20mm 15mm;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            font-size: 10pt;
            line-height: 1.5;
            color: #1a1a1a;
            background: #ffffff;
        }

        .watermark {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 60pt;
            font-weight: 800;
            color: rgba(57, 255, 20, 0.06);
            letter-spacing: 15px;
            z-index: -1;
            pointer-events: none;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 25px;
            page-break-inside: avoid;
        }

        .header h1 {
            font-size: 22pt;
            font-weight: 700;
            margin-bottom: 5px;
            color: #39ff14;
        }

        .header .subtitle {
            font-size: 11pt;
            color: #94a3b8;
            margin-bottom: 15px;
        }

        .header-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 9pt;
            color: #cbd5e1;
        }

        .header-meta span {
            display: inline-block;
        }

        /* Section */
        .section {
            margin-bottom: 25px;
            page-break-inside: avoid;
        }

        .section-title {
            font-size: 14pt;
            font-weight: 700;
            color: #0f172a;
            padding-bottom: 8px;
            border-bottom: 3px solid #39ff14;
            margin-bottom: 15px;
        }

        /* Stats Grid */
        .stats-grid {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .stat-card {
            flex: 1;
            text-align: center;
            padding: 15px 10px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }

        .stat-card.critical { background: #fef2f2; border-left: 4px solid #dc2626; }
        .stat-card.high { background: #fff7ed; border-left: 4px solid #ea580c; }
        .stat-card.medium { background: #fefce8; border-left: 4px solid #ca8a04; }
        .stat-card.low { background: #ecfeff; border-left: 4px solid #0891b2; }
        .stat-card.info { background: #f0fdf4; border-left: 4px solid #16a34a; }

        .stat-number {
            font-size: 24pt;
            font-weight: 700;
            display: block;
        }

        .stat-card.critical .stat-number { color: #dc2626; }
        .stat-card.high .stat-number { color: #ea580c; }
        .stat-card.medium .stat-number { color: #ca8a04; }
        .stat-card.low .stat-number { color: #0891b2; }
        .stat-card.info .stat-number { color: #16a34a; }

        .stat-label {
            font-size: 8pt;
            text-transform: uppercase;
            font-weight: 600;
            color: #64748b;
        }

        /* Risk Score */
        .risk-score-box {
            text-align: center;
            padding: 20px;
            background: #f8fafc;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .risk-score-value {
            font-size: 32pt;
            font-weight: 800;
        }

        .risk-score-value.critical { color: #dc2626; }
        .risk-score-value.high { color: #ea580c; }
        .risk-score-value.medium { color: #ca8a04; }
        .risk-score-value.low { color: #0891b2; }

        .risk-score-label {
            font-size: 10pt;
            color: #64748b;
            margin-top: 5px;
        }

        /* Key Findings & Recommendations */
        .findings-box {
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            border-radius: 0 6px 6px 0;
            margin-bottom: 15px;
        }

        .findings-box h3 {
            color: #b45309;
            font-size: 11pt;
            margin-bottom: 10px;
        }

        .recommendations-box {
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            padding: 15px;
            border-radius: 0 6px 6px 0;
        }

        .recommendations-box h3 {
            color: #15803d;
            font-size: 11pt;
            margin-bottom: 10px;
        }

        .findings-box ul, .recommendations-box ul {
            margin-left: 20px;
        }

        .findings-box li, .recommendations-box li {
            margin-bottom: 5px;
            font-size: 9pt;
        }

        /* Vulnerability Cards */
        .vuln-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 15px;
            page-break-inside: avoid;
            overflow: hidden;
        }

        .vuln-header {
            padding: 12px 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .vuln-header.critical { background: #fef2f2; border-bottom: 2px solid #dc2626; }
        .vuln-header.high { background: #fff7ed; border-bottom: 2px solid #ea580c; }
        .vuln-header.medium { background: #fefce8; border-bottom: 2px solid #ca8a04; }
        .vuln-header.low { background: #ecfeff; border-bottom: 2px solid #0891b2; }
        .vuln-header.info { background: #f0fdf4; border-bottom: 2px solid #16a34a; }

        .vuln-number {
            font-size: 9pt;
            font-weight: 700;
            color: #64748b;
        }

        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 8pt;
            font-weight: 700;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: #dc2626; color: white; }
        .severity-badge.high { background: #ea580c; color: white; }
        .severity-badge.medium { background: #ca8a04; color: white; }
        .severity-badge.low { background: #0891b2; color: white; }
        .severity-badge.info { background: #16a34a; color: white; }

        .vuln-title {
            flex: 1;
            font-weight: 600;
            font-size: 11pt;
            color: #0f172a;
        }

        .vuln-body {
            padding: 15px;
        }

        .vuln-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 9pt;
            color: #64748b;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid #e2e8f0;
        }

        .vuln-meta strong {
            color: #334155;
        }

        .vuln-field {
            margin-bottom: 12px;
        }

        .vuln-field-label {
            font-size: 9pt;
            font-weight: 600;
            color: #475569;
            margin-bottom: 4px;
        }

        .vuln-field-value {
            font-size: 9pt;
            color: #1e293b;
        }

        .url-value {
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 8pt;
            background: #f1f5f9;
            padding: 6px 10px;
            border-radius: 4px;
        }

        /* Code blocks */
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 8pt;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }

        .poc-section {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
        }

        .poc-section .vuln-field-label {
            color: #b45309;
        }

        .poc-section .code-block {
            background: #451a03;
            color: #fef3c7;
        }

        .evidence-section {
            background: #e0f2fe;
            border: 1px solid #0284c7;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
        }

        .evidence-section .vuln-field-label {
            color: #0369a1;
        }

        .evidence-section .code-block {
            background: #0c4a6e;
            color: #e0f2fe;
        }

        .remediation-section {
            background: #dcfce7;
            border: 1px solid #22c55e;
            border-radius: 6px;
            padding: 12px;
        }

        .remediation-section .vuln-field-label {
            color: #15803d;
        }

        .remediation-section .code-block {
            background: #14532d;
            color: #dcfce7;
        }

        /* OWASP & Compliance */
        .owasp-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
        }

        .owasp-item {
            background: #f8fafc;
            border-left: 3px solid #39ff14;
            padding: 10px;
            border-radius: 0 6px 6px 0;
        }

        .owasp-item h4 {
            font-size: 9pt;
            color: #0f172a;
            margin-bottom: 5px;
        }

        .owasp-item p {
            font-size: 8pt;
            color: #64748b;
        }

        .compliance-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }

        .compliance-card {
            background: #f8fafc;
            border-top: 3px solid #39ff14;
            padding: 15px;
            border-radius: 0 0 6px 6px;
        }

        .compliance-card h4 {
            font-size: 10pt;
            color: #0f172a;
            margin-bottom: 10px;
        }

        .compliance-card ul {
            list-style: none;
            font-size: 8pt;
        }

        .compliance-card li {
            padding: 4px 0;
            border-bottom: 1px solid #e2e8f0;
            color: #475569;
        }

        /* Footer */
        .footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 2px solid #e2e8f0;
            text-align: center;
            font-size: 8pt;
            color: #64748b;
        }

        .footer .brand {
            color: #39ff14;
            font-weight: 600;
        }
        "#
    }

    fn generate_header(&self, report: &EnhancedReport, branding: &BrandingConfig) -> String {
        format!(
            r#"<div class="header">
    <h1>{company}</h1>
    <div class="subtitle">{title}</div>
    <div class="header-meta">
        <span><strong>Target:</strong> {target}</span>
        <span><strong>Scan ID:</strong> {scan_id}</span>
        <span><strong>Date:</strong> {date}</span>
    </div>
</div>"#,
            company = self.escape_html(&branding.company_name),
            title = branding
                .report_title
                .as_ref()
                .unwrap_or(&"Security Assessment Report".to_string()),
            target = self.escape_html(&report.scan_results.target),
            scan_id = self.escape_html(&report.scan_results.scan_id),
            date = self.escape_html(&report.executive_summary.scan_date),
        )
    }

    fn generate_executive_summary(
        &self,
        summary: &crate::reporting::types::ExecutiveSummary,
    ) -> String {
        let risk_class = match summary.risk_level.to_lowercase().as_str() {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            _ => "low",
        };

        let findings_html: String = summary
            .key_findings
            .iter()
            .map(|f| format!("<li>{}</li>", self.escape_html(f)))
            .collect::<Vec<_>>()
            .join("\n");

        let recommendations_html: String = summary
            .recommendations
            .iter()
            .map(|r| format!("<li>{}</li>", self.escape_html(r)))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"<div class="section">
    <div class="section-title">Executive Summary</div>

    <div class="risk-score-box">
        <div class="risk-score-value {risk_class}">{score:.1}/10.0</div>
        <div class="risk-score-label">Overall Risk: {level}</div>
    </div>

    <div class="stats-grid">
        <div class="stat-card critical">
            <span class="stat-number">{critical}</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-card high">
            <span class="stat-number">{high}</span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-card medium">
            <span class="stat-number">{medium}</span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-card low">
            <span class="stat-number">{low}</span>
            <span class="stat-label">Low</span>
        </div>
        <div class="stat-card info">
            <span class="stat-number">{info}</span>
            <span class="stat-label">Info</span>
        </div>
    </div>

    <div class="findings-box">
        <h3>Key Findings</h3>
        <ul>{findings}</ul>
    </div>

    <div class="recommendations-box">
        <h3>Recommendations</h3>
        <ul>{recommendations}</ul>
    </div>
</div>"#,
            risk_class = risk_class,
            score = summary.risk_score,
            level = self.escape_html(&summary.risk_level),
            critical = summary.critical_count,
            high = summary.high_count,
            medium = summary.medium_count,
            low = summary.low_count,
            info = summary.info_count,
            findings = findings_html,
            recommendations = recommendations_html,
        )
    }

    fn generate_vulnerabilities(&self, vulnerabilities: &[crate::types::Vulnerability]) -> String {
        let vuln_cards: String = vulnerabilities
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                let severity_class = match v.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                    Severity::Info => "info",
                };

                let parameter_html = v
                    .parameter
                    .as_ref()
                    .map(|p| {
                        format!(
                            r#"<span><strong>Parameter:</strong> {}</span>"#,
                            self.escape_html(p)
                        )
                    })
                    .unwrap_or_default();

                let poc_html = if !v.payload.is_empty() && v.payload != "-" {
                    format!(
                        r#"<div class="poc-section">
                        <div class="vuln-field-label">Proof of Concept (PoC)</div>
                        <div class="code-block">{}</div>
                    </div>"#,
                        self.escape_html(&v.payload)
                    )
                } else {
                    String::new()
                };

                let evidence_html = v
                    .evidence
                    .as_ref()
                    .map(|e| {
                        format!(
                            r#"<div class="evidence-section">
                        <div class="vuln-field-label">Evidence</div>
                        <div class="code-block">{}</div>
                    </div>"#,
                            self.escape_html(e)
                        )
                    })
                    .unwrap_or_default();

                format!(
                    r#"<div class="vuln-card">
    <div class="vuln-header {severity_class}">
        <span class="vuln-number">#{num}</span>
        <span class="severity-badge {severity_class}">{severity}</span>
        <span class="vuln-title">{title}</span>
    </div>
    <div class="vuln-body">
        <div class="vuln-meta">
            <span><strong>Category:</strong> {category}</span>
            <span><strong>CWE:</strong> {cwe}</span>
            <span><strong>CVSS:</strong> {cvss:.1}</span>
            <span><strong>Confidence:</strong> {confidence}</span>
            {parameter}
        </div>

        <div class="vuln-field">
            <div class="vuln-field-label">URL</div>
            <div class="url-value">{url}</div>
        </div>

        <div class="vuln-field">
            <div class="vuln-field-label">Description</div>
            <div class="vuln-field-value">{description}</div>
        </div>

        {poc}
        {evidence}

        <div class="remediation-section">
            <div class="vuln-field-label">Remediation</div>
            <div class="code-block">{remediation}</div>
        </div>
    </div>
</div>"#,
                    num = idx + 1,
                    severity_class = severity_class,
                    severity = v.severity,
                    title = self.escape_html(&v.vuln_type),
                    category = self.escape_html(&v.category),
                    cwe = self.escape_html(&v.cwe),
                    cvss = v.cvss,
                    confidence = v.confidence,
                    parameter = parameter_html,
                    url = self.escape_html(&v.url),
                    description = self.escape_html(&v.description),
                    poc = poc_html,
                    evidence = evidence_html,
                    remediation = self.escape_html(&v.remediation),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"<div class="section">
    <div class="section-title">Detailed Findings ({} vulnerabilities)</div>
    {}
</div>"#,
            vulnerabilities.len(),
            vuln_cards
        )
    }

    fn generate_owasp_mapping(&self, report: &EnhancedReport) -> String {
        let items: String = report
            .owasp_mapping
            .iter()
            .map(|(category, vulns)| {
                format!(
                    r#"<div class="owasp-item">
    <h4>{} ({} findings)</h4>
    <p>{}</p>
</div>"#,
                    self.escape_html(category),
                    vulns.len(),
                    self.escape_html(
                        &crate::reporting::mappings::OWASPMapper::get_owasp_description(category)
                    )
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"<div class="section">
    <div class="section-title">OWASP Top 10 (2021) Mapping</div>
    <div class="owasp-grid">{}</div>
</div>"#,
            items
        )
    }

    fn generate_compliance(&self, report: &EnhancedReport) -> String {
        let pci_items: String = report
            .compliance_mapping
            .pci_dss
            .iter()
            .map(|(req, vulns)| {
                format!(
                    "<li>{} - {} findings</li>",
                    self.escape_html(req),
                    vulns.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let hipaa_items: String = report
            .compliance_mapping
            .hipaa
            .iter()
            .map(|(req, vulns)| {
                format!(
                    "<li>{} - {} findings</li>",
                    self.escape_html(req),
                    vulns.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let soc2_items: String = report
            .compliance_mapping
            .soc2
            .iter()
            .map(|(req, vulns)| {
                format!(
                    "<li>{} - {} findings</li>",
                    self.escape_html(req),
                    vulns.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"<div class="section">
    <div class="section-title">Compliance Mapping</div>
    <div class="compliance-grid">
        <div class="compliance-card">
            <h4>PCI-DSS</h4>
            <ul>{pci}</ul>
        </div>
        <div class="compliance-card">
            <h4>HIPAA</h4>
            <ul>{hipaa}</ul>
        </div>
        <div class="compliance-card">
            <h4>SOC 2</h4>
            <ul>{soc2}</ul>
        </div>
    </div>
</div>"#,
            pci = pci_items,
            hipaa = hipaa_items,
            soc2 = soc2_items,
        )
    }

    fn generate_footer(&self, branding: &BrandingConfig) -> String {
        let default_footer = "Confidential - For Internal Use Only".to_string();
        let footer_text = branding.footer_text.as_ref().unwrap_or(&default_footer);

        format!(
            r#"<div class="footer">
    <p>{}</p>
    <p>Generated by <span class="brand">LONKERO</span> - <a href="https://lonkero.bountyy.fi">lonkero.bountyy.fi</a></p>
</div>"#,
            self.escape_html(footer_text)
        )
    }

    fn escape_html(&self, text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }

    fn html_to_pdf(&self, html: &str) -> Result<Vec<u8>> {
        let launch_options = LaunchOptions {
            headless: true,
            sandbox: true,
            args: vec![
                OsStr::new("--disable-gpu"),
                OsStr::new("--no-sandbox"),
                OsStr::new("--disable-dev-shm-usage"),
                OsStr::new("--disable-setuid-sandbox"),
            ],
            ..Default::default()
        };

        let browser =
            Browser::new(launch_options).map_err(|e| anyhow!("Failed to launch browser: {}", e))?;

        let tab = browser
            .new_tab()
            .map_err(|e| anyhow!("Failed to create tab: {}", e))?;

        // Navigate to data URL with HTML content
        let data_url = format!("data:text/html;charset=utf-8,{}", urlencoding::encode(html));

        tab.navigate_to(&data_url)
            .map_err(|e| anyhow!("Failed to navigate: {}", e))?;

        tab.wait_until_navigated()
            .map_err(|e| anyhow!("Failed to wait for navigation: {}", e))?;

        // Wait for fonts and styles
        std::thread::sleep(std::time::Duration::from_millis(800));

        // Print to PDF
        let pdf_data = tab
            .print_to_pdf(Some(headless_chrome::types::PrintToPdfOptions {
                landscape: Some(false),
                display_header_footer: Some(false),
                print_background: Some(true),
                scale: Some(1.0),
                paper_width: Some(8.27),
                paper_height: Some(11.69),
                margin_top: Some(0.0),
                margin_bottom: Some(0.0),
                margin_left: Some(0.0),
                margin_right: Some(0.0),
                page_ranges: None,
                ignore_invalid_page_ranges: Some(true),
                header_template: None,
                footer_template: None,
                prefer_css_page_size: Some(true),
                transfer_mode: None,
                generate_tagged_pdf: None,
                generate_document_outline: None,
            }))
            .map_err(|e| anyhow!("Failed to generate PDF: {}", e))?;

        Ok(pdf_data)
    }
}

impl Default for PdfReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
