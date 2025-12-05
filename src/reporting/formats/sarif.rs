// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{
    EnhancedReport, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRun, SarifTool,
};
use anyhow::Result;

pub struct SarifReportGenerator;

impl SarifReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self, report: &EnhancedReport) -> Result<Vec<u8>> {
        let sarif_report = self.create_sarif_report(report);
        let json = serde_json::to_string_pretty(&sarif_report)?;
        Ok(json.into_bytes())
    }

    fn create_sarif_report(&self, report: &EnhancedReport) -> SarifReport {
        let results: Vec<SarifResult> = report
            .scan_results
            .vulnerabilities
            .iter()
            .map(|vuln| self.create_sarif_result(vuln))
            .collect();

        SarifReport {
            version: "2.1.0".to_string(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Lonkero Security Scanner".to_string(),
                        version: "1.0.0".to_string(),
                        information_uri: "https://bountyy.fi".to_string(),
                    },
                },
                results,
            }],
        }
    }

    fn create_sarif_result(&self, vuln: &crate::types::Vulnerability) -> SarifResult {
        let level = match vuln.severity {
            crate::types::Severity::Critical | crate::types::Severity::High => "error",
            crate::types::Severity::Medium => "warning",
            crate::types::Severity::Low | crate::types::Severity::Info => "note",
        };

        SarifResult {
            rule_id: vuln.cwe.clone(),
            level: level.to_string(),
            message: SarifMessage {
                text: format!("{}: {}", vuln.vuln_type, vuln.description),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: vuln.url.clone(),
                    },
                },
            }],
        }
    }
}

impl Default for SarifReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
