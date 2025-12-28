// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::Vulnerability;
use std::collections::{HashMap, HashSet};

pub struct VulnerabilityDeduplicator {
    similarity_threshold: f64,
}

impl VulnerabilityDeduplicator {
    pub fn new() -> Self {
        Self {
            similarity_threshold: 0.85,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            similarity_threshold: threshold,
        }
    }

    pub fn deduplicate(&self, vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
        if vulnerabilities.is_empty() {
            return vulnerabilities;
        }

        let mut deduplicated = Vec::new();
        let mut seen_signatures = HashSet::new();

        for vuln in vulnerabilities {
            let signature = self.compute_signature(&vuln);

            if !seen_signatures.contains(&signature) {
                seen_signatures.insert(signature);
                deduplicated.push(vuln);
            }
        }

        deduplicated
    }

    pub fn deduplicate_advanced(&self, vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
        if vulnerabilities.is_empty() {
            return vulnerabilities;
        }

        let mut groups: HashMap<String, Vec<Vulnerability>> = HashMap::new();

        for vuln in vulnerabilities {
            let key = format!("{}:{}", vuln.vuln_type, vuln.url);
            groups.entry(key).or_insert_with(Vec::new).push(vuln);
        }

        let mut deduplicated = Vec::new();

        for (_, mut group) in groups {
            if group.len() == 1 {
                deduplicated.push(group.pop().unwrap());
            } else {
                group.sort_by(|a, b| {
                    b.confidence.to_string().cmp(&a.confidence.to_string())
                        .then(b.cvss.partial_cmp(&a.cvss).unwrap_or(std::cmp::Ordering::Equal))
                });
                deduplicated.push(group.into_iter().next().unwrap());
            }
        }

        deduplicated
    }

    fn compute_signature(&self, vuln: &Vulnerability) -> String {
        let param = vuln.parameter.as_ref().map(|s| s.as_str()).unwrap_or("");
        format!(
            "{}:{}:{}:{}",
            vuln.vuln_type,
            self.normalize_url(&vuln.url),
            param,
            vuln.cwe
        )
    }

    fn normalize_url(&self, url: &str) -> String {
        url.split('?').next().unwrap_or(url).to_lowercase()
    }

    pub fn filter_false_positives(&self, vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
        vulnerabilities
            .into_iter()
            .filter(|v| !v.false_positive)
            .collect()
    }

    pub fn filter_by_severity(
        &self,
        vulnerabilities: Vec<Vulnerability>,
        min_severity: &str,
    ) -> Vec<Vulnerability> {
        let threshold = match min_severity.to_uppercase().as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            "INFO" => 0,
            _ => 0,
        };

        vulnerabilities
            .into_iter()
            .filter(|v| self.severity_to_int(&v.severity) >= threshold)
            .collect()
    }

    fn severity_to_int(&self, severity: &crate::types::Severity) -> i32 {
        match severity {
            crate::types::Severity::Critical => 4,
            crate::types::Severity::High => 3,
            crate::types::Severity::Medium => 2,
            crate::types::Severity::Low => 1,
            crate::types::Severity::Info => 0,
        }
    }

    pub fn group_by_type(&self, vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<Vulnerability>> {
        let mut groups: HashMap<String, Vec<Vulnerability>> = HashMap::new();

        for vuln in vulnerabilities {
            groups
                .entry(vuln.vuln_type.clone())
                .or_insert_with(Vec::new)
                .push(vuln.clone());
        }

        groups
    }

    pub fn group_by_severity(&self, vulnerabilities: &[Vulnerability]) -> HashMap<String, Vec<Vulnerability>> {
        let mut groups: HashMap<String, Vec<Vulnerability>> = HashMap::new();

        for vuln in vulnerabilities {
            groups
                .entry(vuln.severity.to_string())
                .or_insert_with(Vec::new)
                .push(vuln.clone());
        }

        groups
    }
}

impl Default for VulnerabilityDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};
    use chrono::Utc;

    fn create_test_vulnerability(vuln_type: &str, url: &str) -> Vulnerability {
        Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Test".to_string(),
            url: url.to_string(),
            parameter: Some("test".to_string()),
            payload: "test".to_string(),
            description: "Test".to_string(),
            evidence: None,
            cwe: "CWE-79".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "Test".to_string(),
            discovered_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_deduplication() {
        let deduplicator = VulnerabilityDeduplicator::new();

        let vulns = vec![
            create_test_vulnerability("XSS", "http://example.com/test"),
            create_test_vulnerability("XSS", "http://example.com/test"),
            create_test_vulnerability("SQLi", "http://example.com/other"),
        ];

        let deduplicated = deduplicator.deduplicate(vulns);
        assert_eq!(deduplicated.len(), 2);
    }

    #[test]
    fn test_false_positive_filter() {
        let deduplicator = VulnerabilityDeduplicator::new();

        let mut vuln1 = create_test_vulnerability("XSS", "http://example.com/test");
        vuln1.false_positive = true;

        let vuln2 = create_test_vulnerability("SQLi", "http://example.com/other");

        let vulns = vec![vuln1, vuln2];
        let filtered = deduplicator.filter_false_positives(vulns);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].vuln_type, "SQLi");
    }
}
