// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::EnhancedReport;
use anyhow::Result;

pub struct JsonReportGenerator;

impl JsonReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport) -> Result<Vec<u8>> {
        let json = serde_json::to_string_pretty(report)?;
        Ok(json.into_bytes())
    }
}

impl Default for JsonReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
