// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::Vulnerability;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use url::Url;

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

    /// Semantic URL normalization for deduplication
    /// - Normalizes numeric IDs in path: /users/123/posts/456 -> /users/{id}/posts/{id}
    /// - Sorts query parameters alphabetically: ?b=2&a=1 -> ?a=1&b=2
    /// - Normalizes UUIDs: /item/550e8400-e29b-41d4-a716-446655440000 -> /item/{uuid}
    /// - Lowercases scheme and host
    fn normalize_url(&self, url_str: &str) -> String {
        // Try to parse as URL
        if let Ok(mut url) = Url::parse(url_str) {
            // 1. Normalize path - replace numeric IDs and UUIDs with placeholders
            let path = self.normalize_path(url.path());
            url.set_path(&path);

            // 2. Sort query parameters alphabetically
            let sorted_query = self.normalize_query_params(url.query());
            url.set_query(sorted_query.as_deref());

            // Return normalized URL (scheme + host are auto-lowercased by url crate)
            url.to_string()
        } else {
            // Fallback: just lowercase and strip query
            url_str.split('?').next().unwrap_or(url_str).to_lowercase()
        }
    }

    /// Normalize URL path by replacing dynamic segments with placeholders
    fn normalize_path(&self, path: &str) -> String {
        // UUID pattern (8-4-4-4-12 hex)
        let uuid_re = Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap();
        // Numeric ID pattern (standalone numbers in path segments)
        let numeric_re = Regex::new(r"^[0-9]+$").unwrap();
        // MongoDB ObjectId pattern (24 hex chars)
        let objectid_re = Regex::new(r"^[0-9a-fA-F]{24}$").unwrap();
        // Base64-like tokens (common for encoded IDs)
        let base64_re = Regex::new(r"^[A-Za-z0-9_-]{20,}$").unwrap();

        let segments: Vec<&str> = path.split('/').collect();
        let normalized: Vec<String> = segments
            .iter()
            .map(|segment| {
                if segment.is_empty() {
                    String::new()
                } else if uuid_re.is_match(segment) {
                    "{uuid}".to_string()
                } else if objectid_re.is_match(segment) {
                    "{oid}".to_string()
                } else if numeric_re.is_match(segment) {
                    "{id}".to_string()
                } else if base64_re.is_match(segment) && !segment.contains('.') {
                    // Avoid matching file extensions
                    "{token}".to_string()
                } else {
                    segment.to_lowercase()
                }
            })
            .collect();

        normalized.join("/")
    }

    /// Sort query parameters alphabetically for consistent comparison
    fn normalize_query_params(&self, query: Option<&str>) -> Option<String> {
        query.map(|q| {
            let mut params: Vec<(&str, &str)> = q
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let value = parts.next().unwrap_or("");
                    Some((key, value))
                })
                .collect();

            // Sort by key name
            params.sort_by(|a, b| a.0.cmp(b.0));

            // Rebuild query string
            params
                .iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        k.to_string()
                    } else {
                        format!("{}={}", k, v)
                    }
                })
                .collect::<Vec<_>>()
                .join("&")
        })
        .filter(|s| !s.is_empty())
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
            ml_data: None,
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

    #[test]
    fn test_semantic_url_normalization() {
        let deduplicator = VulnerabilityDeduplicator::new();

        // Test numeric ID normalization
        let url1 = deduplicator.normalize_url("https://example.com/users/123/posts/456");
        let url2 = deduplicator.normalize_url("https://example.com/users/789/posts/101");
        assert_eq!(url1, url2, "Numeric IDs should normalize to same pattern");

        // Test query param sorting
        let url3 = deduplicator.normalize_url("https://example.com/search?b=2&a=1&c=3");
        let url4 = deduplicator.normalize_url("https://example.com/search?a=1&b=2&c=3");
        assert_eq!(url3, url4, "Query params should be sorted alphabetically");

        // Test UUID normalization
        let url5 = deduplicator.normalize_url("https://example.com/item/550e8400-e29b-41d4-a716-446655440000");
        let url6 = deduplicator.normalize_url("https://example.com/item/f47ac10b-58cc-4372-a567-0e02b2c3d479");
        assert_eq!(url5, url6, "UUIDs should normalize to same pattern");

        // Test MongoDB ObjectId normalization
        let url7 = deduplicator.normalize_url("https://example.com/doc/507f1f77bcf86cd799439011");
        let url8 = deduplicator.normalize_url("https://example.com/doc/5eb63bbbe01eeed093cb22bb");
        assert_eq!(url7, url8, "ObjectIds should normalize to same pattern");
    }

    #[test]
    fn test_semantic_deduplication() {
        let deduplicator = VulnerabilityDeduplicator::new();

        // Same vulnerability on different user IDs should deduplicate
        let vulns = vec![
            create_test_vulnerability("IDOR", "https://api.example.com/users/123/profile"),
            create_test_vulnerability("IDOR", "https://api.example.com/users/456/profile"),
            create_test_vulnerability("IDOR", "https://api.example.com/users/789/profile"),
        ];

        let deduplicated = deduplicator.deduplicate(vulns);
        assert_eq!(deduplicated.len(), 1, "Same vuln on different IDs should deduplicate to 1");
    }
}
