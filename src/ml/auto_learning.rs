// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Automatic Learning System
 * Learns from scan results without user verification
 *
 * Learning Signals (no user input needed):
 * =========================================
 *
 * 1. VERIFIED EXPLOITATION (strongest signal):
 *    - SQLi: Response contains DB error with our payload marker
 *    - XSS: Payload reflected unencoded in HTML context
 *    - SSRF: Got response from internal IP/metadata endpoint
 *    - Command Injection: Time-based delay matches expected
 *
 * 2. BEHAVIORAL SIGNALS:
 *    - Response differs significantly from baseline
 *    - Status code changed after injection
 *    - Response time anomaly (timing attacks)
 *    - Content-type changed unexpectedly
 *
 * 3. CROSS-SCANNER VALIDATION:
 *    - Multiple scanners found same issue = likely true
 *    - Only one low-confidence scanner = likely false
 *
 * 4. HISTORICAL PATTERNS:
 *    - Same endpoint/parameter had issue before
 *    - Similar technology had this vulnerability
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpResponse;
use crate::types::{Confidence, Severity, Vulnerability};
use super::features::{FeatureExtractor, VulnFeatures};
use super::training_data::{TrainingDataCollector, TrainingExample, VerificationStatus};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info};

/// Automatic verification result
#[derive(Debug, Clone)]
pub struct AutoVerification {
    /// Verification status
    pub status: VerificationStatus,
    /// Confidence in this verification (0.0 - 1.0)
    pub confidence: f32,
    /// Reasons for this determination
    pub reasons: Vec<String>,
    /// Exploitation evidence if verified
    pub evidence: Option<String>,
}

/// Automatic Learning Engine
pub struct AutoLearner {
    /// Feature extractor
    feature_extractor: FeatureExtractor,
    /// Training data collector
    data_collector: TrainingDataCollector,
    /// Historical findings by endpoint pattern
    endpoint_history: HashMap<String, Vec<HistoricalFinding>>,
    /// Vulnerability type patterns
    vuln_patterns: VulnPatterns,
}

/// Historical finding for pattern learning
#[derive(Debug, Clone)]
struct HistoricalFinding {
    vuln_type: String,
    url_pattern: String,
    was_true_positive: bool,
    features: Vec<f32>,
}

/// Patterns for verifying different vulnerability types
struct VulnPatterns {
    /// SQL error patterns that confirm SQLi
    sql_errors: Vec<&'static str>,
    /// Patterns that confirm XSS (payload reflected in dangerous context)
    xss_contexts: Vec<&'static str>,
    /// Patterns that confirm SSRF (internal responses)
    ssrf_indicators: Vec<&'static str>,
    /// Patterns that confirm command injection
    cmdi_indicators: Vec<&'static str>,
}

impl Default for VulnPatterns {
    fn default() -> Self {
        Self {
            sql_errors: vec![
                // MySQL
                "You have an error in your SQL syntax",
                "Warning: mysql_",
                "MySqlException",
                "com.mysql.jdbc",
                // PostgreSQL
                "ERROR:  syntax error at or near",
                "pg_query(): Query failed",
                "org.postgresql",
                // MSSQL
                "Unclosed quotation mark",
                "Microsoft OLE DB Provider for SQL Server",
                "SQLSTATE[42000]",
                // Oracle
                "ORA-00933",
                "ORA-01756",
                "oracle.jdbc",
                // SQLite
                "SQLITE_ERROR",
                "sqlite3.OperationalError",
                // Generic
                "SQL syntax.*MySQL",
                "valid MySQL result",
                "Database error",
            ],
            xss_contexts: vec![
                "<script>", // Direct script injection
                "javascript:", // JavaScript URI
                "onerror=", // Event handler
                "onload=",
                "onclick=",
                "onmouseover=",
                "onfocus=",
                "onsubmit=",
                "<img src=x onerror",
                "<svg onload",
                "expression(", // CSS expression
                "<iframe",
            ],
            ssrf_indicators: vec![
                "169.254.169.254", // AWS metadata
                "metadata.google.internal",
                "localhost",
                "127.0.0.1",
                "0.0.0.0",
                "::1",
                "internal",
                "intranet",
                "10.0.",
                "172.16.",
                "192.168.",
                "file:///",
            ],
            cmdi_indicators: vec![
                "uid=", // Unix id command
                "gid=",
                "groups=",
                "root:", // /etc/passwd
                "daemon:",
                "Windows IP Configuration", // ipconfig
                "Physical Address",
                "Default Gateway",
                "PING", // ping output
                "bytes from",
                "time=",
                "TTL=",
            ],
        }
    }
}

impl AutoLearner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            feature_extractor: FeatureExtractor::new(),
            data_collector: TrainingDataCollector::new()?,
            endpoint_history: HashMap::new(),
            vuln_patterns: VulnPatterns::default(),
        })
    }

    /// Automatically verify a vulnerability finding
    /// Returns verification result WITHOUT requiring user input
    pub fn auto_verify(
        &self,
        vuln: &Vulnerability,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
        payload: Option<&str>,
    ) -> AutoVerification {
        let mut reasons = Vec::new();
        let mut confidence = 0.0f32;
        let mut evidence = None;

        // 1. Check for verified exploitation evidence
        let exploitation = self.check_exploitation_evidence(
            &vuln.vuln_type,
            response,
            payload,
        );

        if let Some((exploit_evidence, exploit_confidence)) = exploitation {
            reasons.push(format!("Exploitation verified: {}", exploit_evidence));
            evidence = Some(exploit_evidence);
            confidence = confidence.max(exploit_confidence);
        }

        // 2. Behavioral analysis
        let features = self.feature_extractor.extract(response, baseline, payload);
        let behavioral = self.analyze_behavioral_signals(&features, &vuln.vuln_type);
        confidence = confidence.max(behavioral.confidence);
        reasons.extend(behavioral.reasons);

        // 3. Cross-validation with scanner confidence
        let scanner_signal = self.analyze_scanner_confidence(vuln);
        confidence = (confidence + scanner_signal) / 2.0;

        // 4. Historical pattern matching
        if let Some(historical_boost) = self.check_historical_patterns(vuln) {
            confidence = confidence * (1.0 + historical_boost * 0.2);
            reasons.push("Similar pattern previously verified".to_string());
        }

        // Determine final status
        let status = if confidence > 0.8 {
            VerificationStatus::Confirmed
        } else if confidence < 0.3 {
            VerificationStatus::FalsePositive
        } else {
            VerificationStatus::Unverified
        };

        if status == VerificationStatus::Confirmed {
            info!(
                "Auto-verified TRUE POSITIVE: {} at {} (confidence: {:.0}%)",
                vuln.vuln_type, vuln.url, confidence * 100.0
            );
        } else if status == VerificationStatus::FalsePositive {
            debug!(
                "Auto-verified FALSE POSITIVE: {} at {} (confidence: {:.0}%)",
                vuln.vuln_type, vuln.url, confidence * 100.0
            );
        }

        AutoVerification {
            status,
            confidence,
            reasons,
            evidence,
        }
    }

    /// Check for verified exploitation evidence
    fn check_exploitation_evidence(
        &self,
        vuln_type: &str,
        response: &HttpResponse,
        payload: Option<&str>,
    ) -> Option<(String, f32)> {
        let vuln_upper = vuln_type.to_uppercase();
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // SQL Injection verification
        if vuln_upper.contains("SQL") {
            for pattern in &self.vuln_patterns.sql_errors {
                if body.contains(pattern) || body_lower.contains(&pattern.to_lowercase()) {
                    return Some((
                        format!("SQL error exposed: {}", pattern),
                        0.95,
                    ));
                }
            }
        }

        // XSS verification
        if vuln_upper.contains("XSS") || vuln_upper.contains("CROSS-SITE") {
            if let Some(payload) = payload {
                // Check if payload is reflected in dangerous context
                for context in &self.vuln_patterns.xss_contexts {
                    if payload.to_lowercase().contains(&context.to_lowercase()) {
                        // Payload contains dangerous pattern
                        if body.contains(payload) {
                            // And it's reflected unencoded!
                            return Some((
                                format!("XSS payload reflected with {}", context),
                                0.95,
                            ));
                        }
                    }
                }

                // Check for unencoded reflection
                if body.contains(payload) && payload.contains('<') && payload.contains('>') {
                    return Some((
                        "Payload with HTML tags reflected unencoded".to_string(),
                        0.85,
                    ));
                }
            }
        }

        // SSRF verification
        if vuln_upper.contains("SSRF") {
            for indicator in &self.vuln_patterns.ssrf_indicators {
                if body.contains(indicator) || body_lower.contains(indicator) {
                    return Some((
                        format!("SSRF confirmed: internal resource accessed ({})", indicator),
                        0.90,
                    ));
                }
            }
        }

        // Command Injection verification
        if vuln_upper.contains("COMMAND") || vuln_upper.contains("CMDI") || vuln_upper.contains("RCE") {
            for indicator in &self.vuln_patterns.cmdi_indicators {
                if body.contains(indicator) {
                    return Some((
                        format!("Command output detected: {}", indicator),
                        0.90,
                    ));
                }
            }
        }

        // Time-based verification (blind injections)
        if let Some(timing) = response.timing_ms {
            if timing > 5000 && (vuln_upper.contains("BLIND") || vuln_upper.contains("TIME")) {
                return Some((
                    format!("Time-based injection confirmed: {}ms delay", timing),
                    0.75,
                ));
            }
        }

        None
    }

    /// Analyze behavioral signals
    fn analyze_behavioral_signals(
        &self,
        features: &VulnFeatures,
        vuln_type: &str,
    ) -> BehavioralAnalysis {
        let mut reasons = Vec::new();
        let mut score = 0.0f32;

        // Error patterns strongly indicate injection success
        if features.has_sql_error && vuln_type.to_uppercase().contains("SQL") {
            score += 0.4;
            reasons.push("SQL error pattern detected".to_string());
        }

        // Stack traces indicate error triggering (could be vuln)
        if features.has_stack_trace {
            score += 0.2;
            reasons.push("Application error triggered".to_string());
        }

        // Payload reflection is necessary for XSS
        if features.payload_reflected {
            if features.reflection_in_script {
                score += 0.4;
                reasons.push("Payload reflected in script context".to_string());
            } else if features.reflection_in_attribute {
                score += 0.3;
                reasons.push("Payload reflected in attribute context".to_string());
            } else if !features.reflection_encoded {
                score += 0.2;
                reasons.push("Payload reflected without encoding".to_string());
            }
        }

        // Baseline differences suggest the injection had effect
        if features.differs_from_baseline {
            score += 0.1;
            reasons.push("Response differs from baseline".to_string());

            if features.status_changed {
                score += 0.1;
                reasons.push("Status code changed after injection".to_string());
            }

            if features.length_changed_significantly {
                score += 0.05;
                reasons.push("Response length changed significantly".to_string());
            }
        }

        // Timing anomalies for blind injection
        if features.timing_anomaly {
            score += 0.3;
            reasons.push("Response timing anomaly detected".to_string());
        }

        BehavioralAnalysis {
            confidence: score.min(1.0),
            reasons,
        }
    }

    /// Analyze scanner's own confidence assessment
    fn analyze_scanner_confidence(&self, vuln: &Vulnerability) -> f32 {
        let base = match vuln.confidence {
            Confidence::High => 0.8,
            Confidence::Medium => 0.5,
            Confidence::Low => 0.3,
        };

        // Boost for verified flag
        if vuln.verified {
            return 0.95;
        }

        base
    }

    /// Check historical patterns for similar findings
    fn check_historical_patterns(&self, vuln: &Vulnerability) -> Option<f32> {
        let url_pattern = self.anonymize_url(&vuln.url);

        if let Some(history) = self.endpoint_history.get(&url_pattern) {
            let matching: Vec<_> = history.iter()
                .filter(|h| h.vuln_type == vuln.vuln_type)
                .collect();

            if !matching.is_empty() {
                let true_positive_rate = matching.iter()
                    .filter(|h| h.was_true_positive)
                    .count() as f32 / matching.len() as f32;

                return Some(true_positive_rate);
            }
        }

        None
    }

    /// Record learning from this finding
    pub fn learn_from_finding(
        &mut self,
        vuln: &Vulnerability,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
        payload: Option<&str>,
    ) -> Result<AutoVerification> {
        // Get automatic verification
        let verification = self.auto_verify(vuln, response, baseline, payload);

        // Only learn from high-confidence verifications
        if verification.confidence > 0.7 || verification.confidence < 0.3 {
            // Extract features for learning
            let features = self.feature_extractor.extract(response, baseline, payload);

            // Create training example
            let example = TrainingExample::from_vulnerability(
                vuln,
                response.status_code,
                response.body.len(),
                response.timing_ms.unwrap_or(0),
                response.headers.get("content-type").cloned(),
                features.payload_reflected,
                features.has_sql_error || features.has_stack_trace,
                features.differs_from_baseline,
            );

            // Record with auto-verification status
            let mut example = example;
            example.verification = verification.status;
            self.data_collector.record_example(&example)?;

            // Update historical patterns
            let url_pattern = self.anonymize_url(&vuln.url);
            self.endpoint_history
                .entry(url_pattern)
                .or_default()
                .push(HistoricalFinding {
                    vuln_type: vuln.vuln_type.clone(),
                    url_pattern: self.anonymize_url(&vuln.url),
                    was_true_positive: verification.status == VerificationStatus::Confirmed,
                    features: features.to_vector(),
                });

            debug!(
                "Auto-learned from {}: {:?} (confidence: {:.0}%)",
                vuln.vuln_type,
                verification.status,
                verification.confidence * 100.0
            );
        }

        Ok(verification)
    }

    /// Anonymize URL for pattern matching
    fn anonymize_url(&self, url: &str) -> String {
        let path = url::Url::parse(url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| url.to_string());

        let id_pattern = regex::Regex::new(r"/\d+").unwrap();
        let anonymized = id_pattern.replace_all(&path, "/{id}");

        let uuid_pattern = regex::Regex::new(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        ).unwrap();

        uuid_pattern.replace_all(&anonymized, "/{uuid}").to_string()
    }

    /// Get learning statistics
    pub fn get_stats(&self) -> LearningStats {
        let stats = self.data_collector.get_stats().unwrap_or_default();
        LearningStats {
            auto_confirmed: stats.confirmed_count,
            auto_rejected: stats.false_positive_count,
            pending_learning: stats.unverified_count,
            endpoint_patterns: self.endpoint_history.len(),
        }
    }
}

impl Default for AutoLearner {
    fn default() -> Self {
        Self::new().expect("Failed to create auto learner")
    }
}

#[derive(Debug)]
struct BehavioralAnalysis {
    confidence: f32,
    reasons: Vec<String>,
}

#[derive(Debug, Default)]
pub struct LearningStats {
    pub auto_confirmed: usize,
    pub auto_rejected: usize,
    pub pending_learning: usize,
    pub endpoint_patterns: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_response(body: &str, status: u16) -> HttpResponse {
        HttpResponse {
            status_code: status,
            headers: HashMap::new(),
            body: body.to_string(),
            timing_ms: Some(100),
            url: "https://example.com/test".to_string(),
        }
    }

    fn create_test_vuln(vuln_type: &str) -> Vulnerability {
        Vulnerability {
            id: "test-123".to_string(),
            vuln_type: vuln_type.to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Test".to_string(),
            url: "https://example.com/api/users/123".to_string(),
            parameter: Some("id".to_string()),
            payload: Some("' OR '1'='1".to_string()),
            description: "Test vulnerability".to_string(),
            evidence: None,
            cwe: Some("CWE-89".to_string()),
            cvss: None,
            verified: false,
            false_positive: false,
            remediation: None,
            discovered_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_sql_injection_auto_verify() {
        let learner = AutoLearner::new().unwrap();

        let vuln = create_test_vuln("SQL Injection");
        let response = create_test_response(
            "Error: You have an error in your SQL syntax near ''1'='1'",
            500,
        );

        let result = learner.auto_verify(&vuln, &response, None, Some("' OR '1'='1"));

        assert_eq!(result.status, VerificationStatus::Confirmed);
        assert!(result.confidence > 0.8);
        assert!(result.evidence.is_some());
    }

    #[test]
    fn test_xss_auto_verify() {
        let learner = AutoLearner::new().unwrap();

        let vuln = create_test_vuln("Cross-Site Scripting (XSS)");
        let payload = "<script>alert(1)</script>";
        let response = create_test_response(
            &format!("<html><body>Hello {}</body></html>", payload),
            200,
        );

        let result = learner.auto_verify(&vuln, &response, None, Some(payload));

        assert_eq!(result.status, VerificationStatus::Confirmed);
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn test_false_positive_detection() {
        let learner = AutoLearner::new().unwrap();

        let vuln = create_test_vuln("SQL Injection");
        // Normal response without any SQL errors
        let response = create_test_response(
            "<html><body>User profile page</body></html>",
            200,
        );

        let result = learner.auto_verify(&vuln, &response, None, Some("' OR '1'='1"));

        // Low confidence = likely false positive
        assert!(result.confidence < 0.5);
    }
}
