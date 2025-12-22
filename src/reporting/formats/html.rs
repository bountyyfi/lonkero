// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{BrandingConfig, EnhancedReport};
use anyhow::Result;

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport, branding: &BrandingConfig) -> Result<Vec<u8>> {
        let html = self.generate_html(report, branding);
        Ok(html.into_bytes())
    }

    fn generate_html(&self, report: &EnhancedReport, branding: &BrandingConfig) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {}</title>
    <style>
        {}
    </style>
</head>
<body>
    <div class="container">
        {}
        {}
        {}
        {}
        {}
        {}
        {}
    </div>
    <script>
        {}
    </script>
</body>
</html>"#,
            report.scan_results.target,
            self.get_css(branding),
            self.generate_header(report, branding),
            self.generate_executive_summary(&report.executive_summary),
            self.generate_charts(&report.executive_summary),
            self.generate_vulnerability_table(&report.scan_results.vulnerabilities),
            self.generate_owasp_mapping(report),
            self.generate_compliance_section(report),
            self.generate_footer(branding),
            self.get_javascript()
        )
    }

    fn get_css(&self, _branding: &BrandingConfig) -> String {
        format!(
            r#"
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'JetBrains Mono', monospace;
            line-height: 1.6;
            color: #e0e0e0;
            background-color: #0a0a0a;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #39ff14;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 0 30px rgba(57, 255, 20, 0.15);
            border: 1px solid #39ff14;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(57, 255, 20, 0.5);
            font-weight: 700;
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
            color: #b0b0b0;
        }}

        .section {{
            background: #111111;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
            border: 1px solid #2a2a2a;
        }}

        .section h2 {{
            color: #39ff14;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #39ff14;
            text-shadow: 0 0 10px rgba(57, 255, 20, 0.3);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
        }}

        .stat-card.critical {{
            background: #1a0808;
            border-left: 4px solid #ff4444;
        }}

        .stat-card.high {{
            background: #1a1208;
            border-left: 4px solid #ff8c00;
        }}

        .stat-card.medium {{
            background: #1a1a08;
            border-left: 4px solid #ffc107;
        }}

        .stat-card.low {{
            background: #081a1a;
            border-left: 4px solid #00bcd4;
        }}

        .stat-card.info {{
            background: #08101a;
            border-left: 4px solid #39ff14;
        }}

        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
            color: #39ff14;
            text-shadow: 0 0 10px rgba(57, 255, 20, 0.3);
        }}

        .stat-label {{
            font-size: 0.9em;
            color: #888;
            text-transform: uppercase;
        }}

        .risk-score {{
            font-size: 3em;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }}

        .risk-score.CRITICAL {{
            color: #dc3545;
        }}

        .risk-score.HIGH {{
            color: #fd7e14;
        }}

        .risk-score.MEDIUM {{
            color: #ffc107;
        }}

        .risk-score.LOW {{
            color: #0dcaf0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #2a2a2a;
            color: #e0e0e0;
        }}

        th {{
            background-color: #1a1a1a;
            color: #39ff14;
            font-weight: 600;
            border-bottom: 2px solid #39ff14;
        }}

        tr:hover {{
            background-color: #1a1a1a;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .severity-CRITICAL {{
            background-color: #dc3545;
            color: white;
        }}

        .severity-HIGH {{
            background-color: #fd7e14;
            color: white;
        }}

        .severity-MEDIUM {{
            background-color: #ffc107;
            color: #000;
        }}

        .severity-LOW {{
            background-color: #0dcaf0;
            color: #000;
        }}

        .severity-INFO {{
            background-color: #0d6efd;
            color: white;
        }}

        .confidence-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            margin-left: 5px;
        }}

        .confidence-HIGH {{
            background-color: #198754;
            color: white;
        }}

        .confidence-MEDIUM {{
            background-color: #ffc107;
            color: #000;
        }}

        .confidence-LOW {{
            background-color: #6c757d;
            color: white;
        }}

        .vuln-details {{
            display: none;
            padding: 15px;
            background: #0f0f0f;
            margin-top: 10px;
            border-left: 4px solid #39ff14;
            border-radius: 4px;
        }}

        .vuln-details.active {{
            display: block;
        }}

        .code-block {{
            background: #0a0a0a;
            color: #39ff14;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            border: 1px solid #2a2a2a;
        }}

        .poc-section {{
            background: #1a1a08;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }}

        .poc-section p {{
            margin: 0 0 10px 0;
            color: #ffc107;
            font-weight: bold;
        }}

        .poc-code {{
            background: #0a0a0a;
            color: #ffc107;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 0.85em;
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            border: 1px solid #2a2a2a;
        }}

        .evidence-section {{
            background: #081a1a;
            border: 1px solid #00bcd4;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }}

        .evidence-section p {{
            margin: 0 0 10px 0;
            color: #00bcd4;
            font-weight: bold;
        }}

        .evidence-code {{
            background: #0a0a0a;
            color: #00bcd4;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', Consolas, monospace;
            font-size: 0.85em;
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #2a2a2a;
        }}

        .chart-container {{
            height: 300px;
            margin: 30px 0;
        }}

        .owasp-item {{
            padding: 15px;
            margin: 10px 0;
            background: #1a1a1a;
            border-left: 4px solid #39ff14;
            border-radius: 4px;
        }}

        .owasp-item h3 {{
            color: #39ff14;
            margin-bottom: 10px;
        }}

        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .compliance-card {{
            padding: 20px;
            background: #1a1a1a;
            border-radius: 8px;
            border-top: 4px solid #39ff14;
            border: 1px solid #2a2a2a;
        }}

        .compliance-card h3 {{
            color: #39ff14;
            margin-bottom: 15px;
        }}

        .compliance-card ul {{
            list-style: none;
        }}

        .compliance-card li {{
            padding: 8px 0;
            border-bottom: 1px solid #2a2a2a;
            color: #b0b0b0;
        }}

        .compliance-card li:last-child {{
            border-bottom: none;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #39ff14;
            font-size: 0.9em;
            border-top: 1px solid #2a2a2a;
            margin-top: 20px;
        }}

        .expandable {{
            cursor: pointer;
        }}

        .expandable:hover {{
            background-color: #1a1a1a;
        }}

        .key-findings {{
            background: #1a1a08;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}

        .key-findings h3 {{
            color: #ffc107;
        }}

        .key-findings ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}

        .key-findings li {{
            margin: 8px 0;
            color: #b0b0b0;
        }}

        .recommendations {{
            background: #081a10;
            border-left: 4px solid #39ff14;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}

        .recommendations h3 {{
            color: #39ff14;
        }}

        .recommendations ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}

        .recommendations li {{
            margin: 8px 0;
            color: #b0b0b0;
        }}

        @media print {{
            .container {{
                max-width: 100%;
            }}

            .vuln-details {{
                display: block !important;
            }}

            body {{
                background-color: white;
                color: #333;
            }}

            .section {{
                background: white;
                border: 1px solid #ddd;
            }}
        }}
        "#
        )
    }

    fn generate_header(&self, report: &EnhancedReport, branding: &BrandingConfig) -> String {
        format!(
            r#"
    <div class="header">
        <h1>{}</h1>
        <p>Security Assessment Report</p>
        <p>Target: {} | Scan ID: {}</p>
        <p>Generated: {}</p>
    </div>
            "#,
            branding.company_name,
            report.scan_results.target,
            report.scan_results.scan_id,
            report.generated_at
        )
    }

    fn generate_executive_summary(&self, summary: &crate::reporting::types::ExecutiveSummary) -> String {
        format!(
            r#"
    <div class="section">
        <h2>Executive Summary</h2>

        <div class="risk-score {risk_level}">
            Risk Score: {risk_score:.2}/10.0
            <div style="font-size: 0.4em; color: #666;">{risk_level}</div>
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

        <div class="key-findings">
            <h3>Key Findings</h3>
            <ul>
                {findings}
            </ul>
        </div>

        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
                {recommendations}
            </ul>
        </div>
    </div>
            "#,
            risk_score = summary.risk_score,
            risk_level = summary.risk_level,
            critical = summary.critical_count,
            high = summary.high_count,
            medium = summary.medium_count,
            low = summary.low_count,
            info = summary.info_count,
            findings = summary
                .key_findings
                .iter()
                .map(|f| format!("<li>{}</li>", self.escape_html(f)))
                .collect::<Vec<_>>()
                .join("\n"),
            recommendations = summary
                .recommendations
                .iter()
                .map(|r| format!("<li>{}</li>", self.escape_html(r)))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    fn generate_charts(&self, summary: &crate::reporting::types::ExecutiveSummary) -> String {
        format!(
            r#"
    <div class="section">
        <h2>Vulnerability Distribution</h2>
        <div class="chart-container">
            <canvas id="severityChart"></canvas>
        </div>
        <script>
            const ctx = document.getElementById('severityChart');
            if (ctx) {{
                const data = {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: [{}, {}, {}, {}, {}],
                        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#0dcaf0', '#0d6efd']
                    }}]
                }};
                // Note: In production, include Chart.js library
                // For this demo, we're showing the data in a simple bar chart using CSS
            }}
        </script>
    </div>
            "#,
            summary.critical_count,
            summary.high_count,
            summary.medium_count,
            summary.low_count,
            summary.info_count
        )
    }

    fn generate_vulnerability_table(&self, vulnerabilities: &[crate::types::Vulnerability]) -> String {
        let rows = vulnerabilities
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                format!(
                    r#"
        <tr class="expandable" onclick="toggleDetails('vuln-{}')">
            <td>{}</td>
            <td>{}</td>
            <td>
                <span class="severity-badge severity-{}">{}</span>
                <span class="confidence-badge confidence-{}">{}</span>
            </td>
            <td>{}</td>
            <td>{:.1}</td>
            <td>{}</td>
        </tr>
        <tr>
            <td colspan="6">
                <div id="vuln-{}" class="vuln-details">
                    <p><strong>Description:</strong> {}</p>
                    <p><strong>URL:</strong> <code>{}</code></p>
                    {}
                    {}
                    {}
                    <p><strong>Remediation:</strong></p>
                    <div class="code-block">{}</div>
                </div>
            </td>
        </tr>
                    "#,
                    idx,
                    idx + 1,
                    self.escape_html(&v.vuln_type),
                    v.severity,
                    v.severity,
                    v.confidence,
                    v.confidence,
                    self.escape_html(&v.category),
                    v.cvss,
                    self.escape_html(&v.cwe),
                    idx,
                    self.escape_html(&v.description),
                    self.escape_html(&v.url),
                    v.parameter.as_ref().map(|p| format!("<p><strong>Parameter:</strong> <code>{}</code></p>", self.escape_html(p))).unwrap_or_default(),
                    if !v.payload.is_empty() && v.payload != "-" {
                        format!("<div class=\"poc-section\"><p><strong>Proof of Concept (PoC):</strong></p><pre class=\"poc-code\">{}</pre></div>", self.escape_html(&v.payload))
                    } else {
                        String::new()
                    },
                    v.evidence.as_ref().map(|e| format!("<div class=\"evidence-section\"><p><strong>Evidence:</strong></p><pre class=\"evidence-code\">{}</pre></div>", self.escape_html(e))).unwrap_or_default(),
                    self.escape_html(&v.remediation)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"
    <div class="section">
        <h2>Detailed Findings ({} vulnerabilities)</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>CVSS</th>
                    <th>CWE</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>
            "#,
            vulnerabilities.len(),
            rows
        )
    }

    fn generate_owasp_mapping(&self, report: &EnhancedReport) -> String {
        let items = report
            .owasp_mapping
            .iter()
            .map(|(category, vulns)| {
                format!(
                    r#"
        <div class="owasp-item">
            <h3>{} ({} vulnerabilities)</h3>
            <p>{}</p>
        </div>
                    "#,
                    self.escape_html(category),
                    vulns.len(),
                    self.escape_html(&crate::reporting::mappings::OWASPMapper::get_owasp_description(category))
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"
    <div class="section">
        <h2>OWASP Top 10 (2021) Mapping</h2>
        {}
    </div>
            "#,
            items
        )
    }

    fn generate_compliance_section(&self, report: &EnhancedReport) -> String {
        let pci_items = report
            .compliance_mapping
            .pci_dss
            .iter()
            .map(|(req, vulns)| {
                format!("<li>{} - {} findings</li>", self.escape_html(req), vulns.len())
            })
            .collect::<Vec<_>>()
            .join("\n");

        let hipaa_items = report
            .compliance_mapping
            .hipaa
            .iter()
            .map(|(req, vulns)| {
                format!("<li>{} - {} findings</li>", self.escape_html(req), vulns.len())
            })
            .collect::<Vec<_>>()
            .join("\n");

        let soc2_items = report
            .compliance_mapping
            .soc2
            .iter()
            .map(|(req, vulns)| {
                format!("<li>{} - {} findings</li>", self.escape_html(req), vulns.len())
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"
    <div class="section">
        <h2>Compliance Mapping</h2>
        <div class="compliance-grid">
            <div class="compliance-card">
                <h3>PCI-DSS</h3>
                <ul>{}</ul>
            </div>
            <div class="compliance-card">
                <h3>HIPAA</h3>
                <ul>{}</ul>
            </div>
            <div class="compliance-card">
                <h3>SOC 2</h3>
                <ul>{}</ul>
            </div>
        </div>
    </div>
            "#,
            pci_items, hipaa_items, soc2_items
        )
    }

    fn generate_footer(&self, branding: &BrandingConfig) -> String {
        format!(
            r#"
    <div class="footer">
        <p>{}</p>
        <p>Generated by <a href="https://lonkero.bountyy.fi/en" target="_blank" style="color: #39ff14; text-decoration: none;">Lonkero</a> - Wraps around your attack surface</p>
    </div>
            "#,
            branding.footer_text.as_ref().unwrap_or(&"Confidential - For Internal Use Only".to_string())
        )
    }

    fn get_javascript(&self) -> String {
        r#"
        function toggleDetails(id) {
            const element = document.getElementById(id);
            if (element) {
                element.classList.toggle('active');
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            console.log('Security Report Loaded');
        });
        "#
        .to_string()
    }

    fn escape_html(&self, text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }
}

impl Default for HtmlReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
