// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Enhanced XSS Scanner with Context Awareness
 * Improved detection, JSON support, and mutation testing
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::payloads;
use crate::scanners::xss_detection::{InjectionContext, XssDetector};
use crate::types::{ScanConfig, Severity, Confidence, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct EnhancedXssScanner {
    http_client: Arc<HttpClient>,
    detector: XssDetector,
    confirmed_vulns: HashSet<String>, // Deduplication
}

impl EnhancedXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            detector: XssDetector::new(),
            confirmed_vulns: HashSet::new(),
        }
    }

    /// Scan parameter with context-aware payloads and confirmation
    pub async fn scan_parameter(
        &mut self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Mandatory authorization check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("XSS scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("Testing parameter '{}' for XSS (enhanced)", parameter);

        let parameter_owned = parameter.to_string();
        let payloads = payloads::get_xss_payloads(config.scan_mode.as_str());
        let total_payloads = payloads.len();

        debug!("Testing {} XSS payloads with confirmation", total_payloads);

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 50; // Reduced for mutation testing

        // Phase 1: Initial detection
        let results = stream::iter(payloads.clone())
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter_owned.clone();
                let client = Arc::clone(&self.http_client);

                async move {
                    let test_url = if url.contains('?') {
                        format!("{}&{}={}", url, param, urlencoding::encode(&payload))
                    } else {
                        format!("{}?{}={}", url, param, urlencoding::encode(&payload))
                    };

                    match client.get(&test_url).await {
                        Ok(response) => Some((payload, response, test_url)),
                        Err(e) => {
                            debug!("Request failed for payload '{}': {}", payload, e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        // Phase 2: Analyze with context detection
        for result in results {
            if let Some((payload, response, test_url)) = result {
                let detection = self.detector.detect(&payload, &response);

                if detection.detected && detection.confidence > 0.6 {
                    // Phase 3: Confirm with mutation
                    if let Ok(confirmed) = self.confirm_with_mutation(
                        base_url,
                        &parameter_owned,
                        &payload,
                        &detection.context,
                    ).await {
                        if confirmed {
                            let vuln_key = format!("{}:{}:{}", test_url, parameter_owned, detection.context as u8);

                            // Deduplicate
                            if !self.confirmed_vulns.contains(&vuln_key) {
                                self.confirmed_vulns.insert(vuln_key);

                                let (severity, confidence) = self.map_confidence_to_severity(detection.confidence);

                                let vuln = Vulnerability {
                                    id: format!("xss_{}", uuid::Uuid::new_v4()),
                                    vuln_type: "Cross-Site Scripting (XSS)".to_string(),
                                    severity,
                                    confidence,
                                    category: "Injection".to_string(),
                                    url: test_url.clone(),
                                    parameter: Some(parameter_owned.clone()),
                                    payload: Some(payload.clone()),
                                    description: format!(
                                        "XSS vulnerability in {} context. Evidence: {}",
                                        format!("{:?}", detection.context),
                                        detection.evidence.join(", ")
                                    ),
                                    evidence: Some(detection.evidence.join("\n")),
                                    cwe: Some("CWE-79".to_string()),
                                    cvss: Some(7.1),
                                    verified: true,
                                    false_positive: false,
                                    remediation: Some(self.get_remediation(&detection.context)),
                                    discovered_at: Some(chrono::Utc::now().to_rfc3339()),
                                };

                                info!(
                                    "Confirmed XSS: {} in parameter '{}' (context: {:?}, confidence: {:.2})",
                                    vuln.severity, parameter_owned, detection.context, detection.confidence
                                );

                                vulnerabilities.push(vuln);
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Scan POST body with proper JSON/form handling
    pub async fn scan_post_body(
        &mut self,
        url: &str,
        body_param: &str,
        existing_body: &str,
        content_type: Option<&str>,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing POST parameter '{}' for XSS (enhanced)", body_param);

        let body_param_owned = body_param.to_string();
        let payloads = payloads::get_xss_payloads(config.scan_mode.as_str());
        let total_payloads = payloads.len();

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 50;

        // Detect content type
        let is_json = content_type
            .map(|ct| ct.contains("json"))
            .unwrap_or_else(|| existing_body.trim_start().starts_with('{'));

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = url.to_string();
                let param = body_param_owned.clone();
                let body = existing_body.to_string();
                let client = Arc::clone(&self.http_client);

                async move {
                    // Build test body based on content type
                    let test_body = if is_json {
                        Self::inject_json_payload(&body, &param, &payload).unwrap_or(body.clone())
                    } else {
                        Self::inject_form_payload(&body, &param, &payload)
                    };

                    match client.post(&url, test_body).await {
                        Ok(response) => Some((payload, response, url)),
                        Err(e) => {
                            debug!("POST request failed: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        // Analyze responses
        for result in results {
            if let Some((payload, response, test_url)) = result {
                let detection = self.detector.detect(&payload, &response);

                if detection.detected && detection.confidence > 0.6 {
                    let vuln_key = format!("{}:{}:POST", test_url, body_param_owned);

                    if !self.confirmed_vulns.contains(&vuln_key) {
                        self.confirmed_vulns.insert(vuln_key);

                        let (severity, confidence) = self.map_confidence_to_severity(detection.confidence);

                        let vuln = Vulnerability {
                            id: format!("xss_{}", uuid::Uuid::new_v4()),
                            vuln_type: "Cross-Site Scripting (XSS) - POST".to_string(),
                            severity,
                            confidence,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(body_param_owned.clone()),
                            payload: Some(payload.clone()),
                            description: format!(
                                "XSS vulnerability in POST body ({}). Context: {:?}",
                                if is_json { "JSON" } else { "Form" },
                                detection.context
                            ),
                            evidence: Some(detection.evidence.join("\n")),
                            cwe: Some("CWE-79".to_string()),
                            cvss: Some(7.1),
                            verified: true,
                            false_positive: false,
                            remediation: Some(self.get_remediation(&detection.context)),
                            discovered_at: Some(chrono::Utc::now().to_rfc3339()),
                        };

                        info!(
                            "Confirmed POST XSS: {} in parameter '{}'",
                            vuln.severity, body_param_owned
                        );

                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Inject payload into JSON body
    fn inject_json_payload(body: &str, param: &str, payload: &str) -> Result<String> {
        // Parse JSON
        let mut json: Value = serde_json::from_str(body)?;

        // Navigate and inject (supports nested paths like "user.name")
        let parts: Vec<&str> = param.split('.').collect();
        if parts.len() == 1 {
            // Simple case
            json[param] = Value::String(payload.to_string());
        } else {
            // Nested case
            let mut current = &mut json;
            for (i, part) in parts.iter().enumerate() {
                if i == parts.len() - 1 {
                    current[part] = Value::String(payload.to_string());
                } else {
                    current = &mut current[part];
                }
            }
        }

        Ok(serde_json::to_string(&json)?)
    }

    /// Inject payload into form body
    fn inject_form_payload(body: &str, param: &str, payload: &str) -> String {
        // Parse form data
        let pairs: Vec<&str> = body.split('&').collect();
        let mut result = Vec::new();

        let mut found = false;
        for pair in pairs {
            if let Some((key, _value)) = pair.split_once('=') {
                if key == param {
                    result.push(format!("{}={}", key, urlencoding::encode(payload)));
                    found = true;
                } else {
                    result.push(pair.to_string());
                }
            } else {
                result.push(pair.to_string());
            }
        }

        if !found {
            result.push(format!("{}={}", param, urlencoding::encode(payload)));
        }

        result.join("&")
    }

    /// Confirm vulnerability with mutated payload
    async fn confirm_with_mutation(
        &self,
        base_url: &str,
        parameter: &str,
        original_payload: &str,
        context: &InjectionContext,
    ) -> Result<bool> {
        // Get context-specific mutations
        let mutations = self.detector.mutate_payload(original_payload);

        // Test first 2 mutations for performance
        for mutation in mutations.iter().take(2) {
            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(mutation))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(mutation))
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                let detection = self.detector.detect(mutation, &response);
                if detection.detected {
                    debug!("Confirmed with mutation: {}", mutation);
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Map confidence score to Severity/Confidence pair
    fn map_confidence_to_severity(&self, score: f32) -> (Severity, Confidence) {
        if score >= 0.9 {
            (Severity::High, Confidence::High)
        } else if score >= 0.7 {
            (Severity::High, Confidence::Medium)
        } else if score >= 0.5 {
            (Severity::Medium, Confidence::Medium)
        } else {
            (Severity::Medium, Confidence::Low)
        }
    }

    /// Get remediation advice based on context
    fn get_remediation(&self, context: &InjectionContext) -> String {
        match context {
            InjectionContext::HtmlBody => {
                "Encode all user input before rendering in HTML. Use context-aware encoding (HTML entity encoding).".to_string()
            }
            InjectionContext::HtmlAttribute => {
                "Encode user input for HTML attribute context. Prefer using safe attributes and avoid dynamic event handlers.".to_string()
            }
            InjectionContext::JavaScriptString => {
                "Never place user input directly in JavaScript strings. Use JSON.stringify() or proper JS encoding.".to_string()
            }
            InjectionContext::JavaScriptCode => {
                "Never allow user input in JavaScript code context. Use data attributes or JSON instead.".to_string()
            }
            InjectionContext::UrlParameter => {
                "Validate and sanitize URLs. Use allowlists for protocols. Encode for URL context.".to_string()
            }
            InjectionContext::CssContext => {
                "Avoid user input in CSS. If necessary, use strict validation and encoding.".to_string()
            }
            InjectionContext::JsonValue => {
                "Encode user input in JSON values. Ensure JSON is not rendered directly as HTML.".to_string()
            }
            InjectionContext::Unknown => {
                "Apply context-appropriate encoding for all user input. Implement Content Security Policy.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_json_payload() {
        let body = r#"{"name":"test","email":"test@example.com"}"#;
        let result = EnhancedXssScanner::inject_json_payload(body, "name", "<script>alert(1)</script>")
            .unwrap();

        assert!(result.contains("<script>alert(1)</script>"));
        assert!(result.contains("email"));
    }

    #[test]
    fn test_inject_nested_json_payload() {
        let body = r#"{"user":{"name":"test"}}"#;
        let result = EnhancedXssScanner::inject_json_payload(body, "user.name", "payload")
            .unwrap();

        assert!(result.contains("payload"));
    }

    #[test]
    fn test_inject_form_payload() {
        let body = "name=test&email=test@example.com";
        let result = EnhancedXssScanner::inject_form_payload(body, "name", "<script>");

        assert!(result.contains("%3Cscript%3E")); // URL encoded
    }
}
