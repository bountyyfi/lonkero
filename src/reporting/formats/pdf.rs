// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{BrandingConfig, EnhancedReport};
use anyhow::{Result, bail};

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, _report: &EnhancedReport, _branding: &BrandingConfig) -> Result<Vec<u8>> {
        // PDF generation temporarily disabled due to printpdf API compatibility issues
        // TODO: Implement with compatible printpdf version or alternative library
        bail!("PDF generation is temporarily unavailable. Please use HTML or JSON report format.")
    }
}

impl Default for PdfReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
