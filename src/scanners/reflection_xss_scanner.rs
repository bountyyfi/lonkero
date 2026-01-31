// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Reflection-based XSS Scanner (No Chrome Required)
//!
//! XSS scanner that works without headless Chrome by detecting
//! reflected payloads in HTTP responses. Detects:
//! - Reflected XSS in HTML context
//! - Reflected XSS in JavaScript context
//! - Reflected XSS in attribute context
//!
//! Uses comprehensive payload library (12,450+ payloads) with intensity-based
//! filtering for efficient scanning.

use crate::http_client::HttpClient;
use crate::payloads;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::scanners::registry::PayloadIntensity;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct ReflectionXssScanner {
    http_client: Arc<HttpClient>,
    /// Payload intensity - controls how many payloads to test
    intensity: PayloadIntensity,
}

impl ReflectionXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            intensity: PayloadIntensity::Standard,
        }
    }

    /// Create scanner with specific payload intensity
    pub fn with_intensity(http_client: Arc<HttpClient>, intensity: PayloadIntensity) -> Self {
        Self {
            http_client,
            intensity,
        }
    }

    /// Set payload intensity
    pub fn set_intensity(&mut self, intensity: PayloadIntensity) {
        self.intensity = intensity;
    }

    /// Scan URL for reflected XSS vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        self.scan_with_intensity(url, _config, self.intensity).await
    }

    /// Scan URL for reflected XSS with specific payload intensity
    pub async fn scan_with_intensity(
        &self,
        url: &str,
        _config: &ScanConfig,
        intensity: PayloadIntensity,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!(
            "[Reflection-XSS] Starting scan for: {} (intensity: {:?})",
            url, intensity
        );

        // Extract parameters from URL
        let params = self.extract_parameters(url);
        if params.is_empty() {
            debug!("[Reflection-XSS] No parameters found in URL");
            return Ok((vulnerabilities, tests_run));
        }

        // Get payloads based on intensity
        let comprehensive_payloads = payloads::get_xss_payloads_by_intensity(intensity);
        info!(
            "[Reflection-XSS] Testing with {} payloads",
            comprehensive_payloads.len()
        );

        // Test each parameter
        for (param_name, _original_value) in &params {
            // Skip non-injectable parameters
            if ParameterFilter::should_skip_parameter(param_name, ScannerType::XSS) {
                continue;
            }

            // First, test priority payloads (fast path)
            let mut found_vuln = false;
            for (payload, context, description) in self.get_priority_payloads() {
                tests_run += 1;

                let test_url = self.build_test_url(url, param_name, &payload);

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if let Some(vuln) = self.analyze_reflection(
                            &response.body,
                            &payload,
                            param_name,
                            url,
                            context,
                            description,
                        ) {
                            info!("[Reflection-XSS] Found XSS in parameter: {}", param_name);
                            vulnerabilities.push(vuln);
                            found_vuln = true;
                            break; // One vuln per parameter is enough
                        }
                    }
                    Err(e) => {
                        debug!("[Reflection-XSS] Request failed: {}", e);
                    }
                }
            }

            // If no vuln found with priority payloads, try comprehensive payloads
            if !found_vuln && intensity != PayloadIntensity::Minimal {
                for payload in &comprehensive_payloads {
                    tests_run += 1;

                    let test_url = self.build_test_url(url, param_name, payload);
                    let (context, description) = self.detect_payload_context(payload);

                    match self.http_client.get(&test_url).await {
                        Ok(response) => {
                            if let Some(vuln) = self.analyze_reflection(
                                &response.body,
                                payload,
                                param_name,
                                url,
                                context,
                                description,
                            ) {
                                info!(
                                    "[Reflection-XSS] Found XSS with comprehensive payload in: {}",
                                    param_name
                                );
                                vulnerabilities.push(vuln);
                                break; // One vuln per parameter is enough
                            }
                        }
                        Err(e) => {
                            debug!("[Reflection-XSS] Request failed: {}", e);
                        }
                    }
                }
            }
        }

        info!(
            "[Reflection-XSS] Scan complete: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Extract parameters from URL
    fn extract_parameters(&self, url: &str) -> Vec<(String, String)> {
        let mut params = Vec::new();

        if let Ok(parsed) = url::Url::parse(url) {
            for (key, value) in parsed.query_pairs() {
                params.push((key.to_string(), value.to_string()));
            }
        }

        params
    }

    /// Build test URL with payload
    fn build_test_url(&self, base_url: &str, param_name: &str, payload: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            let pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| {
                    if k == param_name {
                        (k.to_string(), payload.to_string())
                    } else {
                        (k.to_string(), v.to_string())
                    }
                })
                .collect();

            parsed.set_query(None);
            for (k, v) in pairs {
                parsed.query_pairs_mut().append_pair(&k, &v);
            }

            parsed.to_string()
        } else {
            base_url.to_string()
        }
    }

    /// Get XSS payloads with context information
    /// Uses comprehensive payload library (12,450+ payloads) limited by intensity
    fn get_xss_payloads(&self) -> Vec<(String, &'static str, &'static str)> {
        // Get comprehensive payloads based on intensity
        let comprehensive_payloads = payloads::get_xss_payloads_by_intensity(self.intensity);

        info!(
            "[Reflection-XSS] Using {} payloads (intensity: {:?})",
            comprehensive_payloads.len(),
            self.intensity
        );

        // Convert to tuple format with context detection
        comprehensive_payloads
            .into_iter()
            .map(|payload| {
                let (context, description) = self.detect_payload_context(&payload);
                (payload, context, description)
            })
            .collect()
    }

    /// Detect the context and description for a payload
    fn detect_payload_context(&self, payload: &str) -> (&'static str, &'static str) {
        let p = payload.to_lowercase();

        if p.contains("<script") {
            ("html", "Script tag injection")
        } else if p.contains("onerror=") || p.contains("onload=") || p.contains("onfocus=") {
            if p.contains("<img") || p.contains("<svg") || p.contains("<body") || p.contains("<input") {
                ("html", "Event handler injection")
            } else {
                ("attribute", "Attribute event handler")
            }
        } else if p.contains("onmouseover=") || p.contains("onclick=") || p.contains("onmouseenter=") {
            ("attribute", "Attribute event handler")
        } else if p.contains("javascript:") {
            ("html", "JavaScript URL")
        } else if p.starts_with("\"") || p.starts_with("'") {
            if p.contains("alert") || p.contains("confirm") || p.contains("prompt") {
                ("javascript", "JavaScript string breakout")
            } else {
                ("attribute", "Attribute breakout")
            }
        } else if p.contains("{{") || p.contains("${") || p.contains("<%") {
            ("template", "Template injection")
        } else if p.contains("<") && p.contains(">") {
            ("html", "HTML tag injection")
        } else {
            ("unknown", "XSS payload")
        }
    }

    /// Get hardcoded high-priority payloads for quick initial testing
    /// These are tested first before comprehensive payloads
    fn get_priority_payloads(&self) -> Vec<(String, &'static str, &'static str)> {
        vec![
            // HTML context - basic script injection
            (
                "<script>alert('XSS')</script>".to_string(),
                "html",
                "Script tag injection",
            ),
            // HTML context - img tag with onerror
            (
                "<img src=x onerror=alert('XSS')>".to_string(),
                "html",
                "IMG tag onerror handler",
            ),
            // HTML context - svg tag
            (
                "<svg onload=alert('XSS')>".to_string(),
                "html",
                "SVG onload handler",
            ),
            // Attribute context - breaking out of quotes
            (
                "\" onmouseover=\"alert('XSS')".to_string(),
                "attribute",
                "Attribute breakout (double quote)",
            ),
            (
                "' onmouseover='alert('XSS')".to_string(),
                "attribute",
                "Attribute breakout (single quote)",
            ),
            // JavaScript context
            (
                "';alert('XSS');//".to_string(),
                "javascript",
                "JavaScript string breakout",
            ),
            (
                "\";alert('XSS');//".to_string(),
                "javascript",
                "JavaScript string breakout (double quote)",
            ),
            // Event handler injection
            (
                "<body onload=alert('XSS')>".to_string(),
                "html",
                "Body onload handler",
            ),
            // Input with autofocus
            (
                "<input autofocus onfocus=alert('XSS')>".to_string(),
                "html",
                "Input autofocus onfocus",
            ),
            // Anchor tag with javascript
            (
                "<a href=\"javascript:alert('XSS')\">click</a>".to_string(),
                "html",
                "JavaScript URL in anchor",
            ),
            // Template injection that could lead to XSS
            (
                "{{constructor.constructor('alert(1)')()}}".to_string(),
                "template",
                "Template expression injection",
            ),
        ]
    }

    /// Analyze response for reflected XSS
    fn analyze_reflection(
        &self,
        body: &str,
        payload: &str,
        param_name: &str,
        url: &str,
        context: &str,
        description: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();
        let payload_lower = payload.to_lowercase();

        // Check if payload is reflected
        if !body_lower.contains(&payload_lower) {
            return None;
        }

        // Check if payload is in an executable context
        let (is_executable, confidence) = self.check_executable_context(body, payload, context);

        if !is_executable {
            return None;
        }

        Some(Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: format!("Reflected XSS in '{}' parameter", param_name),
            category: "XSS".to_string(),
            description: format!(
                "The parameter '{}' reflects user input without proper encoding. \
                 Detected {} in {} context.",
                param_name, description, context
            ),
            severity: Severity::High,
            confidence,
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            evidence: Some(self.extract_evidence(body, payload)),
            remediation: "Implement proper output encoding based on context:\n\
                - HTML context: HTML entity encode (<, >, &, \", ')\n\
                - JavaScript context: JavaScript escape or use JSON.stringify()\n\
                - Attribute context: HTML attribute encode\n\
                - URL context: URL encode\n\n\
                Use Content-Security-Policy header to prevent inline script execution.\n\
                Consider using a templating engine with auto-escaping.".to_string(),
            cwe: "CWE-79".to_string(),
            cvss: 6.1,
            verified: false,
            false_positive: false,
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        })
    }

    /// Check if reflected payload is in an executable context
    fn check_executable_context(&self, body: &str, payload: &str, expected_context: &str) -> (bool, Confidence) {
        // Look for the payload in different contexts

        // Check if it's inside a <script> tag
        let script_re = Regex::new(r"<script[^>]*>[\s\S]*?</script>").ok();
        if let Some(re) = script_re {
            for cap in re.find_iter(body) {
                if cap.as_str().to_lowercase().contains(&payload.to_lowercase()) {
                    return (true, Confidence::High);
                }
            }
        }

        // Check if we injected our own script tag
        if payload.contains("<script") && body.to_lowercase().contains(&payload.to_lowercase()) {
            // Verify it's not HTML-encoded
            if !body.contains("&lt;script") {
                return (true, Confidence::High);
            }
        }

        // Check for event handler injection (onload, onerror, onclick, etc.)
        let event_re = Regex::new(r#"on\w+\s*=\s*['"]*[^'">\s]*alert"#).ok();
        if let Some(re) = event_re {
            if re.is_match(&body.to_lowercase()) {
                return (true, Confidence::High);
            }
        }

        // Check for javascript: URL
        if payload.contains("javascript:") && body.to_lowercase().contains("javascript:") {
            if !body.contains("&quot;javascript:") && !body.contains("&#") {
                return (true, Confidence::Medium);
            }
        }

        // Check if payload is reflected but might be encoded
        if body.to_lowercase().contains(&payload.to_lowercase()) {
            // Lower confidence if we can't confirm execution context
            return (true, Confidence::Low);
        }

        (false, Confidence::Low)
    }

    /// Extract evidence snippet around the payload
    fn extract_evidence(&self, body: &str, payload: &str) -> String {
        let payload_lower = payload.to_lowercase();
        let body_lower = body.to_lowercase();

        if let Some(pos) = body_lower.find(&payload_lower) {
            let start = pos.saturating_sub(50);
            let end = (pos + payload.len() + 50).min(body.len());

            let snippet = &body[start..end];
            format!("...{}...", snippet.replace('\n', " ").replace('\r', ""))
        } else {
            "Payload reflected in response".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_parameters() {
        let scanner = ReflectionXssScanner::new(Arc::new(
            HttpClient::new(Default::default()).unwrap(),
        ));

        let params = scanner.extract_parameters("https://example.com?foo=bar&baz=qux");
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|(k, v)| k == "foo" && v == "bar"));
        assert!(params.iter().any(|(k, v)| k == "baz" && v == "qux"));
    }

    #[test]
    fn test_build_test_url() {
        let scanner = ReflectionXssScanner::new(Arc::new(
            HttpClient::new(Default::default()).unwrap(),
        ));

        let result = scanner.build_test_url(
            "https://example.com?name=test&id=1",
            "name",
            "<script>alert(1)</script>",
        );

        assert!(result.contains("<script>alert(1)</script>") || result.contains("%3Cscript"));
        assert!(result.contains("id=1"));
    }
}
