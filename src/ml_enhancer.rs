// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! ML Enhancer - bridges scanner findings to the feature extractor and model scorer.
//!
//! Model scoring is ONE-WAY (server→client). No user data leaves the scanner.
//! The enhancer scores vulnerability findings locally using cached model weights.

use std::collections::HashMap;

use tracing::{debug, info};

use crate::features::{self, HttpResponse as FeatureHttpResponse, ProbeContext};
use crate::scorer::ModelScorer;
use crate::types::Vulnerability;

/// Integration bridge between scanner findings and the ML model scorer.
pub struct MlEnhancer {
    scorer: ModelScorer,
    /// Below this confidence threshold, findings are filtered as likely FPs
    min_confidence_threshold: f64,
}

impl MlEnhancer {
    pub fn new(scorer: ModelScorer) -> Self {
        Self {
            scorer,
            min_confidence_threshold: 0.15, // Conservative - only filter very low scores
        }
    }

    /// Score a vulnerability finding using the ML model.
    /// Returns (ml_confidence, features) or None if not enough data to score.
    pub fn score_finding(
        &self,
        vuln: &Vulnerability,
        probe_context: Option<&ProbeContext>,
    ) -> Option<(f64, HashMap<String, f64>)> {
        let mut extracted_features = HashMap::new();

        // If we have a full probe context (request + response), extract features
        if let Some(ctx) = probe_context {
            extracted_features = features::extract_features(ctx);
        }

        // Also extract features from vulnerability metadata
        self.enrich_features_from_vuln(&mut extracted_features, vuln);

        if extracted_features.is_empty() {
            return None;
        }

        // Score using the model
        let result = self.scorer.score_detailed(&extracted_features);
        Some((result.confidence, extracted_features))
    }

    /// Enhance a list of findings with ML confidence, optionally filtering FPs.
    pub fn enhance_findings(&self, vulns: &mut Vec<Vulnerability>, filter_fps: bool) {
        let original_count = vulns.len();
        let mut enhanced = Vec::with_capacity(vulns.len());

        for vuln in vulns.drain(..) {
            if let Some((ml_confidence, _features)) = self.score_finding(&vuln, None) {
                let mut v = vuln;
                v.ml_confidence = Some(ml_confidence);

                if filter_fps && ml_confidence < self.min_confidence_threshold {
                    debug!(
                        "[ML] Filtered FP: {} on {} (ml_conf={:.3})",
                        v.vuln_type, v.url, ml_confidence
                    );
                    continue; // Skip this finding
                }
                enhanced.push(v);
            } else {
                // No ML score available - keep the finding as-is
                enhanced.push(vuln);
            }
        }

        let filtered = original_count - enhanced.len();
        if filtered > 0 {
            info!(
                "[ML] Enhanced {} findings, filtered {} likely FPs",
                enhanced.len(),
                filtered
            );
        }

        *vulns = enhanced;
    }

    /// Extract features from Vulnerability metadata when we don't have ProbeContext.
    /// This bridges the gap between scanner output and model input.
    fn enrich_features_from_vuln(
        &self,
        extracted_features: &mut HashMap<String, f64>,
        vuln: &Vulnerability,
    ) {
        let vuln_type_lower = vuln.vuln_type.to_lowercase();
        let category = if vuln_type_lower.contains("sql") || vuln_type_lower.contains("sqli") {
            "sqli"
        } else if vuln_type_lower.contains("xss")
            || vuln_type_lower.contains("cross-site scripting")
        {
            "xss"
        } else if vuln_type_lower.contains("ssrf") {
            "ssrf"
        } else if vuln_type_lower.contains("traversal") || vuln_type_lower.contains("lfi") {
            "traversal"
        } else if vuln_type_lower.contains("command")
            || vuln_type_lower.contains("cmdi")
            || vuln_type_lower.contains("rce")
        {
            "cmdi"
        } else if vuln_type_lower.contains("ssti") || vuln_type_lower.contains("template") {
            "ssti"
        } else {
            "signal"
        };

        // Set severity context features from vuln metadata
        let url_lower = vuln.url.to_lowercase();
        if url_lower.contains("/login")
            || url_lower.contains("/auth")
            || url_lower.contains("/signin")
        {
            extracted_features.insert("severity:endpoint_is_login".into(), 1.0);
        }
        if url_lower.contains("/admin") || url_lower.contains("/dashboard") {
            extracted_features.insert("severity:endpoint_is_admin".into(), 1.0);
        }
        if url_lower.contains("/api/")
            || url_lower.contains("/v1/")
            || url_lower.contains("/v2/")
        {
            extracted_features.insert("severity:endpoint_is_api".into(), 1.0);
        }
        if url_lower.contains("/pay")
            || url_lower.contains("/checkout")
            || url_lower.contains("/billing")
        {
            extracted_features.insert("severity:endpoint_is_payment".into(), 1.0);
        }

        // Set signal features from evidence
        if let Some(ref evidence) = vuln.evidence {
            let evidence_lower = evidence.to_lowercase();
            if evidence_lower.contains("reflected") {
                extracted_features.insert("signal:input_reflected_anywhere".into(), 1.0);
            }
            if evidence_lower.contains("error") || evidence_lower.contains("exception") {
                extracted_features.insert("signal:error_triggered".into(), 1.0);
            }
        }

        // Map confidence tiers to category-specific features
        let conf = match vuln.confidence {
            crate::types::Confidence::High => 0.95,
            crate::types::Confidence::Medium => 0.75,
            crate::types::Confidence::Low => 0.4,
        };

        if conf > 0.9 {
            match category {
                "sqli" => {
                    extracted_features.insert("sqli:union_select_reflected".into(), 1.0);
                }
                "xss" => {
                    extracted_features.insert("xss:script_tag_reflected".into(), 1.0);
                }
                "ssrf" => {
                    extracted_features.insert("ssrf:cloud_metadata_accessed".into(), 1.0);
                }
                "cmdi" => {
                    extracted_features.insert("cmdi:os_command_output".into(), 1.0);
                }
                "ssti" => {
                    extracted_features.insert("ssti:rce_via_template".into(), 1.0);
                }
                "traversal" => {
                    extracted_features.insert("traversal:etc_passwd_content".into(), 1.0);
                }
                _ => {}
            }
        } else if conf > 0.7 {
            match category {
                "sqli" => {
                    extracted_features.insert("sqli:error_generic_db".into(), 1.0);
                }
                "xss" => {
                    extracted_features.insert("xss:reflection_unencoded".into(), 1.0);
                }
                "ssrf" => {
                    extracted_features.insert("ssrf:internal_ip_in_response".into(), 1.0);
                }
                "cmdi" => {
                    extracted_features.insert("cmdi:time_delay_via_sleep".into(), 1.0);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};

    fn make_scorer() -> ModelScorer {
        ModelScorer {
            weights: [
                ("sqli:error_mysql_syntax".to_string(), 2.0),
                ("sqli:union_select_reflected".to_string(), 3.0),
                ("signal:error_triggered".to_string(), 0.5),
                ("severity:endpoint_is_api".to_string(), 0.3),
                ("xss:reflection_unencoded".to_string(), 1.5),
                ("xss:script_tag_reflected".to_string(), 2.5),
            ]
            .into_iter()
            .collect(),
            bias: -0.35,
        }
    }

    fn make_vuln(vuln_type: &str, url: &str, confidence: Confidence) -> Vulnerability {
        Vulnerability {
            id: "test-1".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("id".to_string()),
            payload: "' OR 1=1--".to_string(),
            description: "Test vulnerability".to_string(),
            evidence: Some("SQL error in response".to_string()),
            cwe: "CWE-89".to_string(),
            cvss: 8.5,
            verified: false,
            false_positive: false,
            remediation: "Use parameterized queries".to_string(),
            discovered_at: "2026-01-01T00:00:00Z".to_string(),
            ml_confidence: None,
            ml_data: None,
        }
    }

    #[test]
    fn test_score_finding_from_vuln_metadata() {
        let enhancer = MlEnhancer::new(make_scorer());
        let vuln = make_vuln(
            "SQL Injection",
            "https://example.com/api/users?id=1",
            Confidence::High,
        );

        let result = enhancer.score_finding(&vuln, None);
        assert!(result.is_some());

        let (confidence, features) = result.unwrap();
        assert!(confidence > 0.5); // High confidence SQLi should score well
        assert!(features.contains_key("sqli:union_select_reflected")); // High confidence maps to this
        assert!(features.contains_key("severity:endpoint_is_api"));
        assert!(features.contains_key("signal:error_triggered")); // From evidence
    }

    #[test]
    fn test_enhance_findings_keeps_high_confidence() {
        let enhancer = MlEnhancer::new(make_scorer());
        let mut vulns = vec![make_vuln(
            "SQL Injection",
            "https://example.com/api/v1/users",
            Confidence::High,
        )];

        enhancer.enhance_findings(&mut vulns, true);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].ml_confidence.is_some());
        assert!(vulns[0].ml_confidence.unwrap() > 0.15);
    }

    #[test]
    fn test_enhance_findings_sets_ml_confidence() {
        let enhancer = MlEnhancer::new(make_scorer());
        let mut vulns = vec![make_vuln(
            "Cross-Site Scripting (XSS)",
            "https://example.com/search",
            Confidence::Medium,
        )];

        enhancer.enhance_findings(&mut vulns, false);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0].ml_confidence.is_some());
    }

    #[test]
    fn test_enrich_endpoint_features() {
        let enhancer = MlEnhancer::new(make_scorer());
        let vuln = make_vuln(
            "SQL Injection",
            "https://example.com/admin/dashboard",
            Confidence::Medium,
        );

        let (_, features) = enhancer.score_finding(&vuln, None).unwrap();
        assert!(features.contains_key("severity:endpoint_is_admin"));
    }

    #[test]
    fn test_enrich_payment_endpoint() {
        let enhancer = MlEnhancer::new(make_scorer());
        let vuln = make_vuln(
            "SQL Injection",
            "https://shop.example.com/checkout",
            Confidence::High,
        );

        let (_, features) = enhancer.score_finding(&vuln, None).unwrap();
        assert!(features.contains_key("severity:endpoint_is_payment"));
    }
}
