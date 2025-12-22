// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::reporting::types::{
    EnhancedReport, SarifArtifactLocation, SarifDriver, SarifFix, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRuleProperties, SarifRun,
    SarifTool,
};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

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
        // Collect unique rules from vulnerabilities
        let mut rules_map: HashMap<String, SarifRule> = HashMap::new();
        let mut seen_rule_ids: HashSet<String> = HashSet::new();

        for vuln in &report.scan_results.vulnerabilities {
            let rule_id = self.get_rule_id(vuln);
            if !seen_rule_ids.contains(&rule_id) {
                seen_rule_ids.insert(rule_id.clone());
                rules_map.insert(rule_id.clone(), self.create_rule(vuln, &rule_id));
            }
        }

        let rules: Vec<SarifRule> = rules_map.into_values().collect();

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
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://lonkero.bountyy.fi".to_string(),
                        rules: if rules.is_empty() { None } else { Some(rules) },
                    },
                },
                results,
            }],
        }
    }

    fn get_rule_id(&self, vuln: &crate::types::Vulnerability) -> String {
        // Use CWE as primary rule ID, fallback to vuln type
        if !vuln.cwe.is_empty() && vuln.cwe != "-" {
            vuln.cwe.clone()
        } else {
            // Create a rule ID from vuln type
            format!("lonkero/{}", vuln.vuln_type.to_lowercase().replace(' ', "-"))
        }
    }

    fn create_rule(&self, vuln: &crate::types::Vulnerability, rule_id: &str) -> SarifRule {
        // Map CVSS to GitHub security severity (0.0-10.0 scale as string)
        let security_severity = format!("{:.1}", vuln.cvss);

        // Determine precision based on confidence
        let precision = match vuln.confidence {
            crate::types::Confidence::High => "high",
            crate::types::Confidence::Medium => "medium",
            crate::types::Confidence::Low => "low",
        };

        // Build tags
        let mut tags = vec!["security".to_string()];
        tags.push(format!("severity/{}", vuln.severity.to_string().to_lowercase()));
        if !vuln.cwe.is_empty() && vuln.cwe != "-" {
            tags.push(vuln.cwe.clone());
        }

        SarifRule {
            id: rule_id.to_string(),
            name: vuln.vuln_type.clone(),
            short_description: SarifMessage {
                text: vuln.vuln_type.clone(),
            },
            full_description: SarifMessage {
                text: vuln.description.clone(),
            },
            help: Some(SarifMessage {
                text: vuln.remediation.clone(),
            }),
            help_uri: if !vuln.cwe.is_empty() && vuln.cwe.starts_with("CWE-") {
                Some(format!("https://cwe.mitre.org/data/definitions/{}.html",
                    vuln.cwe.trim_start_matches("CWE-")))
            } else {
                None
            },
            properties: Some(SarifRuleProperties {
                precision: Some(precision.to_string()),
                security_severity: Some(security_severity),
                tags: Some(tags),
            }),
        }
    }

    fn create_sarif_result(&self, vuln: &crate::types::Vulnerability) -> SarifResult {
        let level = match vuln.severity {
            crate::types::Severity::Critical | crate::types::Severity::High => "error",
            crate::types::Severity::Medium => "warning",
            crate::types::Severity::Low | crate::types::Severity::Info => "note",
        };

        // Build message with full context
        let message_text = format!(
            "[{}] {} - {} (CVSS: {:.1})",
            vuln.severity,
            vuln.vuln_type,
            vuln.description,
            vuln.cvss
        );

        // Create fingerprint for deduplication
        let mut fingerprints = HashMap::new();
        fingerprints.insert(
            "primaryLocationLineHash".to_string(),
            format!("{:x}", md5_hash(&format!("{}|{}|{}", vuln.url, vuln.vuln_type, vuln.parameter.as_ref().unwrap_or(&"-".to_string()))))
        );

        // Add partial fingerprints for grouping
        let mut partial_fingerprints = HashMap::new();
        partial_fingerprints.insert("vuln_type".to_string(), vuln.vuln_type.clone());
        if let Some(param) = &vuln.parameter {
            partial_fingerprints.insert("parameter".to_string(), param.clone());
        }

        // Add fix/remediation
        let fixes = if !vuln.remediation.is_empty() && vuln.remediation != "-" {
            Some(vec![SarifFix {
                description: SarifMessage {
                    text: vuln.remediation.clone(),
                },
            }])
        } else {
            None
        };

        SarifResult {
            rule_id: self.get_rule_id(vuln),
            level: level.to_string(),
            message: SarifMessage { text: message_text },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: vuln.url.clone(),
                    },
                },
            }],
            fingerprints: Some(fingerprints),
            partial_fingerprints: Some(partial_fingerprints),
            fixes,
        }
    }
}

// Simple hash function for fingerprinting
fn md5_hash(input: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

impl Default for SarifReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}
