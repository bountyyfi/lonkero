// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::formats::html::HtmlReportGenerator;
use crate::reporting::types::{BrandingConfig, EnhancedReport};
use anyhow::{anyhow, Result};
use headless_chrome::{Browser, LaunchOptions};
use std::ffi::OsStr;

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport, branding: &BrandingConfig) -> Result<Vec<u8>> {
        // Generate HTML report with watermark CSS injected
        let html_generator = HtmlReportGenerator::new();
        let html_bytes = html_generator.generate(report, branding).await?;
        let html_content = String::from_utf8(html_bytes)?;

        // Inject watermark CSS and print-optimized styles
        let html_with_watermark = self.inject_pdf_styles(&html_content);

        // Convert HTML to PDF using headless Chrome
        let pdf_data = self.html_to_pdf(&html_with_watermark)?;

        Ok(pdf_data)
    }

    fn inject_pdf_styles(&self, html: &str) -> String {
        // Inject watermark and print styles before closing </head> tag
        let watermark_css = r#"
        <style>
            /* LONKERO Watermark */
            body::before {
                content: "LONKERO";
                position: fixed;
                bottom: 20px;
                left: 50%;
                transform: translateX(-50%);
                font-size: 72px;
                font-weight: bold;
                color: rgba(57, 255, 20, 0.08);
                z-index: 9999;
                pointer-events: none;
                font-family: 'JetBrains Mono', monospace;
                letter-spacing: 20px;
            }

            /* Print/PDF optimizations */
            @media print {
                body {
                    background-color: #0a0a0a !important;
                    color: #e0e0e0 !important;
                    -webkit-print-color-adjust: exact !important;
                    print-color-adjust: exact !important;
                }

                .header, .section, .stat-card, .key-findings, .recommendations,
                .owasp-item, .compliance-card, .code-block, .poc-section, .evidence-section {
                    -webkit-print-color-adjust: exact !important;
                    print-color-adjust: exact !important;
                }

                /* Ensure all vulnerability details are expanded for PDF */
                .vuln-details {
                    display: block !important;
                }

                /* Better page breaks */
                .section {
                    page-break-inside: avoid;
                }

                tr {
                    page-break-inside: avoid;
                }

                .vuln-details {
                    page-break-inside: avoid;
                }

                /* Ensure backgrounds print */
                * {
                    -webkit-print-color-adjust: exact !important;
                    print-color-adjust: exact !important;
                    color-adjust: exact !important;
                }
            }

            @page {
                size: A4;
                margin: 15mm;
            }
        </style>
        "#;

        // Inject before </head>
        if let Some(pos) = html.find("</head>") {
            let mut result = String::with_capacity(html.len() + watermark_css.len());
            result.push_str(&html[..pos]);
            result.push_str(watermark_css);
            result.push_str(&html[pos..]);
            result
        } else {
            html.to_string()
        }
    }

    fn html_to_pdf(&self, html: &str) -> Result<Vec<u8>> {
        // Launch headless Chrome
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

        let browser = Browser::new(launch_options)
            .map_err(|e| anyhow!("Failed to launch browser: {}", e))?;

        let tab = browser.new_tab()
            .map_err(|e| anyhow!("Failed to create tab: {}", e))?;

        // Navigate to data URL with HTML content
        let data_url = format!("data:text/html;charset=utf-8,{}", urlencoding::encode(html));

        tab.navigate_to(&data_url)
            .map_err(|e| anyhow!("Failed to navigate: {}", e))?;

        // Wait for page to load
        tab.wait_until_navigated()
            .map_err(|e| anyhow!("Failed to wait for navigation: {}", e))?;

        // Give it a moment for styles to apply
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Print to PDF with options
        let pdf_data = tab.print_to_pdf(Some(headless_chrome::types::PrintToPdfOptions {
            landscape: Some(false),
            display_header_footer: Some(true),
            print_background: Some(true),
            scale: Some(0.9),
            paper_width: Some(8.27),  // A4 width in inches
            paper_height: Some(11.69), // A4 height in inches
            margin_top: Some(0.4),
            margin_bottom: Some(0.4),
            margin_left: Some(0.4),
            margin_right: Some(0.4),
            page_ranges: None,
            ignore_invalid_page_ranges: Some(true),
            header_template: Some("<div style=\"font-size: 8px; color: #39ff14; width: 100%; text-align: center; font-family: monospace;\">LONKERO Security Assessment</div>".to_string()),
            footer_template: Some("<div style=\"font-size: 8px; color: #666; width: 100%; text-align: center; font-family: monospace;\"><span class=\"pageNumber\"></span> / <span class=\"totalPages\"></span></div>".to_string()),
            prefer_css_page_size: Some(false),
            transfer_mode: None,
            generate_tagged_pdf: None,
            generate_document_outline: None,
        })).map_err(|e| anyhow!("Failed to generate PDF: {}", e))?;

        Ok(pdf_data)
    }
}

impl Default for PdfReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
