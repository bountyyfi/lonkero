// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::EnhancedReport;
use anyhow::Result;
use csv::Writer;

pub struct CsvReportGenerator;

impl CsvReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport) -> Result<Vec<u8>> {
        let mut wtr = Writer::from_writer(vec![]);

        wtr.write_record(&[
            "ID",
            "Type",
            "Severity",
            "Confidence",
            "Category",
            "URL",
            "Parameter",
            "CWE",
            "CVSS",
            "Verified",
            "False Positive",
            "Description",
            "Evidence",
            "Remediation",
            "Discovered At",
        ])?;

        for vuln in &report.scan_results.vulnerabilities {
            wtr.write_record(&[
                &vuln.id,
                &vuln.vuln_type,
                &vuln.severity.to_string(),
                &vuln.confidence.to_string(),
                &vuln.category,
                &vuln.url,
                &vuln.parameter.clone().unwrap_or_default(),
                &vuln.cwe,
                &vuln.cvss.to_string(),
                &vuln.verified.to_string(),
                &vuln.false_positive.to_string(),
                &vuln.description,
                &vuln.evidence.clone().unwrap_or_default(),
                &vuln.remediation,
                &vuln.discovered_at,
            ])?;
        }

        let data = wtr.into_inner()?;
        Ok(data)
    }
}

impl Default for CsvReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
