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
            (
                "<script>alert(1)</script>".to_string(),
                "html",
                "Script tag injection (numeric)",
            ),
            // HTML context - img tag with onerror (CRITICAL: most common XSS vector)
            (
                "<img src=x onerror=alert(1)>".to_string(),
                "html",
                "IMG tag onerror handler",
            ),
            (
                "<img src=x onerror=alert('XSS')>".to_string(),
                "html",
                "IMG tag onerror handler (string)",
            ),
            // HTML context - svg tag
            (
                "<svg onload=alert(1)>".to_string(),
                "html",
                "SVG onload handler",
            ),
            (
                "<svg/onload=alert(1)>".to_string(),
                "html",
                "SVG onload handler (no space)",
            ),
            // CRITICAL: Attribute breakout + tag injection (MOST COMMON REAL-WORLD XSS)
            (
                "\"><img src=x onerror=alert(1)>".to_string(),
                "html",
                "Attribute breakout + IMG onerror (double quote)",
            ),
            (
                "'><img src=x onerror=alert(1)>".to_string(),
                "html",
                "Attribute breakout + IMG onerror (single quote)",
            ),
            (
                "><img src=x onerror=alert(1)>".to_string(),
                "html",
                "Attribute breakout + IMG onerror (unquoted)",
            ),
            (
                "\"><svg onload=alert(1)>".to_string(),
                "html",
                "Attribute breakout + SVG onload (double quote)",
            ),
            (
                "'><svg onload=alert(1)>".to_string(),
                "html",
                "Attribute breakout + SVG onload (single quote)",
            ),
            (
                "\"><script>alert(1)</script>".to_string(),
                "html",
                "Attribute breakout + script tag (double quote)",
            ),
            (
                "'><script>alert(1)</script>".to_string(),
                "html",
                "Attribute breakout + script tag (single quote)",
            ),
            // Attribute context - breaking out and adding event handlers
            (
                "\" onmouseover=\"alert(1)".to_string(),
                "attribute",
                "Attribute breakout event handler (double quote)",
            ),
            (
                "' onmouseover='alert(1)".to_string(),
                "attribute",
                "Attribute breakout event handler (single quote)",
            ),
            (
                "\" onfocus=\"alert(1)\" autofocus=\"".to_string(),
                "attribute",
                "Attribute breakout onfocus + autofocus",
            ),
            (
                "\" onerror=\"alert(1)\" src=\"x".to_string(),
                "attribute",
                "Attribute breakout onerror",
            ),
            // JavaScript context
            (
                "';alert(1);//".to_string(),
                "javascript",
                "JavaScript string breakout (single quote)",
            ),
            (
                "\";alert(1);//".to_string(),
                "javascript",
                "JavaScript string breakout (double quote)",
            ),
            (
                "</script><script>alert(1)</script>".to_string(),
                "javascript",
                "Script tag breakout",
            ),
            // Event handler injection with common tags
            (
                "<body onload=alert(1)>".to_string(),
                "html",
                "Body onload handler",
            ),
            (
                "<input autofocus onfocus=alert(1)>".to_string(),
                "html",
                "Input autofocus onfocus",
            ),
            (
                "<details open ontoggle=alert(1)>".to_string(),
                "html",
                "Details ontoggle handler",
            ),
            (
                "<video src=x onerror=alert(1)>".to_string(),
                "html",
                "Video onerror handler",
            ),
            (
                "<audio src=x onerror=alert(1)>".to_string(),
                "html",
                "Audio onerror handler",
            ),
            // Anchor tag with javascript
            (
                "<a href=\"javascript:alert(1)\">click</a>".to_string(),
                "html",
                "JavaScript URL in anchor",
            ),
            (
                "<a href=javascript:alert(1)>click</a>".to_string(),
                "html",
                "JavaScript URL in anchor (unquoted)",
            ),
            // Form/iframe injection
            (
                "<iframe src=\"javascript:alert(1)\">".to_string(),
                "html",
                "Iframe javascript src",
            ),
            // Template injection that could lead to XSS
            (
                "{{constructor.constructor('alert(1)')()}}".to_string(),
                "template",
                "Template expression injection",
            ),
            (
                "${alert(1)}".to_string(),
                "template",
                "Template literal injection",
            ),
            // Context tag breakout
            (
                "</title><script>alert(1)</script>".to_string(),
                "html",
                "Title tag breakout",
            ),
            (
                "</textarea><script>alert(1)</script>".to_string(),
                "html",
                "Textarea tag breakout",
            ),
            (
                "</style><script>alert(1)</script>".to_string(),
                "html",
                "Style tag breakout",
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
        let body_lower = body.to_lowercase();
        let payload_lower = payload.to_lowercase();

        // Check if payload is HTML-encoded (safe - not exploitable)
        let has_html_encoding = body.contains("&lt;") || body.contains("&gt;") ||
                                body.contains("&#60;") || body.contains("&#62;") ||
                                body.contains("&#x3c;") || body.contains("&#x3e;");

        // Check if our specific payload appears HTML-encoded
        let payload_appears_encoded = {
            let encoded_lt = payload_lower.contains("<") &&
                            (body.contains(&payload_lower.replace("<", "&lt;")) ||
                             body.contains(&payload_lower.replace("<", "&#60;")) ||
                             body.contains(&payload_lower.replace("<", "&#x3c;")));
            let encoded_gt = payload_lower.contains(">") &&
                            (body.contains(&payload_lower.replace(">", "&gt;")) ||
                             body.contains(&payload_lower.replace(">", "&#62;")) ||
                             body.contains(&payload_lower.replace(">", "&#x3e;")));
            encoded_lt || encoded_gt
        };

        // If the exact payload with < and > appears unencoded, it's likely exploitable
        if payload_lower.contains("<") && payload_lower.contains(">") {
            if body_lower.contains(&payload_lower) && !payload_appears_encoded {
                // Check for common XSS patterns in the reflected content

                // Check for injected script tags
                if payload_lower.contains("<script") && body_lower.contains("<script") {
                    if !body.contains("&lt;script") && !body.contains("&#60;script") {
                        return (true, Confidence::High);
                    }
                }

                // Check for img/svg/body/etc with event handlers (CRITICAL CHECK)
                let dangerous_tag_patterns = [
                    r"<img[^>]+onerror\s*=",
                    r"<img[^>]+onload\s*=",
                    r"<svg[^>]*onload\s*=",
                    r"<svg/onload\s*=",
                    r"<body[^>]+onload\s*=",
                    r"<input[^>]+onfocus\s*=",
                    r"<details[^>]+ontoggle\s*=",
                    r"<video[^>]+onerror\s*=",
                    r"<audio[^>]+onerror\s*=",
                    r"<iframe[^>]+onload\s*=",
                    r"<marquee[^>]+onstart\s*=",
                    r"<object[^>]+onerror\s*=",
                    r"<embed[^>]+onerror\s*=",
                ];

                for pattern in dangerous_tag_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(&body_lower) {
                            return (true, Confidence::High);
                        }
                    }
                }
            }
        }

        // Check if it's inside a <script> tag
        let script_re = Regex::new(r"<script[^>]*>[\s\S]*?</script>").ok();
        if let Some(re) = script_re {
            for cap in re.find_iter(body) {
                if cap.as_str().to_lowercase().contains(&payload_lower) {
                    return (true, Confidence::High);
                }
            }
        }

        // Check if we injected our own script tag
        if payload_lower.contains("<script") && body_lower.contains(&payload_lower) {
            // Verify it's not HTML-encoded
            if !body.contains("&lt;script") && !body.contains("&#60;script") {
                return (true, Confidence::High);
            }
        }

        // Check for event handler injection in attributes
        // This catches: onclick=, onerror=, onload=, onfocus=, onmouseover=, etc.
        // Followed by any JS expression (not just 'alert')
        let event_patterns = [
            r#"on\w+\s*=\s*['"]?[^'">\s]*(alert|confirm|prompt|eval|document\.|window\.|location)"#,
            r#"on\w+\s*=\s*['"]?\s*\w+\s*\("#,  // Matches: onerror=alert( or onerror="alert(
            r#"on(error|load|click|focus|mouseover|mouseenter|input|change|submit|toggle)\s*="#,
        ];

        for pattern in event_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&body_lower) {
                    // Additional check: ensure it's not just pre-existing event handlers
                    // by checking if our payload characters are nearby
                    if body_lower.contains(&payload_lower) ||
                       (payload_lower.len() > 10 && body_lower.contains(&payload_lower[..10])) {
                        return (true, Confidence::High);
                    }
                }
            }
        }

        // Check for javascript: URL
        if payload_lower.contains("javascript:") && body_lower.contains("javascript:") {
            if !body.contains("&quot;javascript:") && !body.contains("&#") {
                // Verify the javascript: URL contains our payload
                if body_lower.contains(&payload_lower) {
                    return (true, Confidence::High);
                }
                return (true, Confidence::Medium);
            }
        }

        // Check for SVG with script or event handlers
        if body_lower.contains("<svg") &&
           (body_lower.contains("onload=") || body_lower.contains("<script")) {
            if body_lower.contains(&payload_lower) {
                return (true, Confidence::High);
            }
        }

        // Check if payload is reflected but might be encoded
        if body_lower.contains(&payload_lower) {
            // Check if it's in an attribute context that could be dangerous
            // e.g., the payload broke out of an attribute
            if payload_lower.starts_with("\"") || payload_lower.starts_with("'") ||
               payload_lower.starts_with(">") {
                // Attribute breakout payloads - check if they're actually breaking out
                if payload_lower.contains("onerror") || payload_lower.contains("onload") ||
                   payload_lower.contains("onclick") || payload_lower.contains("onfocus") ||
                   payload_lower.contains("<script") || payload_lower.contains("<img") ||
                   payload_lower.contains("<svg") {
                    return (true, Confidence::Medium);
                }
            }
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
