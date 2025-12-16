// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Advanced XSS Detection Module
 * Context-aware XSS detection with encoding bypass support
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpResponse;
use scraper::{Html, Selector};
use std::collections::HashSet;

/// Injection context determines where user input appears
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionContext {
    HtmlBody,          // <div>USER_INPUT</div>
    HtmlAttribute,     // <div class="USER_INPUT">
    JavaScriptString,  // var x = "USER_INPUT"
    JavaScriptCode,    // <script>USER_INPUT</script>
    UrlParameter,      // href="USER_INPUT"
    CssContext,        // style="color: USER_INPUT"
    JsonValue,         // {"key": "USER_INPUT"}
    Unknown,
}

/// XSS detection context and results
pub struct XssDetectionResult {
    pub detected: bool,
    pub context: InjectionContext,
    pub confidence: f32,  // 0.0 to 1.0
    pub evidence: Vec<String>,
    pub bypass_detected: bool,
}

pub struct XssDetector {
    // Selectors for parsing HTML
    script_selector: Selector,
    style_selector: Selector,
}

impl XssDetector {
    pub fn new() -> Self {
        Self {
            script_selector: Selector::parse("script").unwrap(),
            style_selector: Selector::parse("style").unwrap(),
        }
    }

    /// Main XSS detection method with context awareness
    pub fn detect(&self, payload: &str, response: &HttpResponse) -> XssDetectionResult {
        let body = &response.body;

        // 1. Check if payload is reflected
        if !self.is_reflected(payload, body) {
            return XssDetectionResult {
                detected: false,
                context: InjectionContext::Unknown,
                confidence: 0.0,
                evidence: Vec::new(),
                bypass_detected: false,
            };
        }

        // 2. Detect context
        let context = self.detect_context(payload, body);

        // 3. Check for executable context
        let mut evidence = Vec::new();
        let mut confidence = 0.0;
        let mut detected = false;

        match context {
            InjectionContext::HtmlBody => {
                if self.is_in_script_tag(body, payload) {
                    detected = true;
                    confidence = 0.95;
                    evidence.push("Payload in <script> tag".to_string());
                } else if self.is_in_event_handler(body, payload) {
                    detected = true;
                    confidence = 0.9;
                    evidence.push("Payload in event handler".to_string());
                }
            }
            InjectionContext::HtmlAttribute => {
                if self.is_unquoted_attribute(body, payload) {
                    detected = true;
                    confidence = 0.85;
                    evidence.push("Unquoted attribute value".to_string());
                } else if self.can_break_attribute(body, payload) {
                    detected = true;
                    confidence = 0.8;
                    evidence.push("Can break out of attribute".to_string());
                }
            }
            InjectionContext::JavaScriptString => {
                if self.can_break_js_string(body, payload) {
                    detected = true;
                    confidence = 0.9;
                    evidence.push("Can break JavaScript string".to_string());
                }
            }
            InjectionContext::JavaScriptCode => {
                detected = true;
                confidence = 0.95;
                evidence.push("Payload in JavaScript code context".to_string());
            }
            _ => {
                // Check for generic indicators
                if self.has_dangerous_patterns(body, payload) {
                    detected = true;
                    confidence = 0.5;
                    evidence.push("Potentially dangerous patterns found".to_string());
                }
            }
        }

        // 4. Check for encoding bypasses
        let bypass_detected = self.check_encoding_bypass(body, payload);
        if bypass_detected {
            detected = true;
            confidence = (confidence + 0.3_f32).min(1.0_f32);
            evidence.push("Encoding bypass detected".to_string());
        }

        XssDetectionResult {
            detected,
            context,
            confidence,
            evidence,
            bypass_detected,
        }
    }

    /// Check if payload is reflected (including encoded variations)
    fn is_reflected(&self, payload: &str, body: &str) -> bool {
        // Check literal match
        if body.contains(payload) {
            return true;
        }

        // Check HTML encoded
        let html_encoded = html_escape::encode_safe(payload).to_string();
        if body.contains(&html_encoded) {
            return true;
        }

        // Check URL encoded
        let url_encoded = urlencoding::encode(payload).to_string();
        if body.contains(&url_encoded) {
            return true;
        }

        // Check partially encoded (common in real apps)
        let partial_encoded = payload.replace('<', "&lt;").replace('>', "&gt;");
        body.contains(&partial_encoded)
    }

    /// Detect the context where payload appears
    fn detect_context(&self, payload: &str, body: &str) -> InjectionContext {
        // Parse as HTML
        let document = Html::parse_document(body);

        // Check if in script tag
        for element in document.select(&self.script_selector) {
            if element.text().collect::<String>().contains(payload) {
                return InjectionContext::JavaScriptCode;
            }
        }

        // Check if in style tag
        for element in document.select(&self.style_selector) {
            if element.text().collect::<String>().contains(payload) {
                return InjectionContext::CssContext;
            }
        }

        // Check if in JavaScript string
        if self.is_in_js_string_context(body, payload) {
            return InjectionContext::JavaScriptString;
        }

        // Check if in HTML attribute
        if self.is_in_attribute_context(body, payload) {
            return InjectionContext::HtmlAttribute;
        }

        // Check if in URL
        if self.is_in_url_context(body, payload) {
            return InjectionContext::UrlParameter;
        }

        // Default to HTML body
        InjectionContext::HtmlBody
    }

    /// Check if payload is inside <script> tag
    fn is_in_script_tag(&self, body: &str, payload: &str) -> bool {
        // Find payload position
        if let Some(pos) = body.find(payload) {
            let before = &body[..pos];
            // Count script tags before payload
            let open_tags = before.matches("<script").count();
            let close_tags = before.matches("</script>").count();
            return open_tags > close_tags;
        }
        false
    }

    /// Check if payload is in event handler
    fn is_in_event_handler(&self, body: &str, payload: &str) -> bool {
        let event_handlers = [
            "onclick=", "onload=", "onerror=", "onmouseover=",
            "onfocus=", "onblur=", "onchange=", "onsubmit=",
        ];

        if let Some(pos) = body.find(payload) {
            let before = &body[..pos.min(body.len())];
            let search_start = before.len().saturating_sub(100);
            let context = &before[search_start..];

            for handler in &event_handlers {
                if context.contains(handler) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if payload is in unquoted attribute
    fn is_unquoted_attribute(&self, body: &str, payload: &str) -> bool {
        if let Some(pos) = body.find(payload) {
            // Check characters around payload
            let before_char = if pos > 0 { body.chars().nth(pos - 1) } else { None };
            let after_pos = pos + payload.len();
            let after_char = body.chars().nth(after_pos);

            // If surrounded by space or >, it's likely unquoted
            matches!(before_char, Some(' ') | Some('>')) && matches!(after_char, Some(' ') | Some('>'))
        } else {
            false
        }
    }

    /// Check if payload can break out of attribute
    fn can_break_attribute(&self, body: &str, payload: &str) -> bool {
        // Check if payload contains quote characters that could break out
        let has_breaking_chars = payload.contains('"') || payload.contains('\'');

        if !has_breaking_chars {
            return false;
        }

        // Verify it's actually in an attribute
        if let Some(pos) = body.find(payload) {
            let before = &body[..pos];
            // Simple heuristic: count quotes before payload
            let double_quotes = before.matches('"').count();
            let single_quotes = before.matches('\'').count();

            // If odd number of quotes, we're inside an attribute
            double_quotes % 2 == 1 || single_quotes % 2 == 1
        } else {
            false
        }
    }

    /// Check if payload can break JavaScript string
    fn can_break_js_string(&self, body: &str, payload: &str) -> bool {
        // Check if payload contains characters that break JS strings
        let breaking_chars = ['\'', '"', '\\', '\n', '\r'];

        payload.chars().any(|c| breaking_chars.contains(&c))
    }

    /// Check if in JavaScript string context
    fn is_in_js_string_context(&self, body: &str, payload: &str) -> bool {
        if let Some(pos) = body.find(payload) {
            let before = &body[..pos];
            let after = &body[pos..];

            // Look for var x = " or similar patterns
            let var_pattern = regex::Regex::new(r#"(var|let|const)\s+\w+\s*=\s*['"]"#).unwrap();
            let has_var_before = var_pattern.is_match(&before[before.len().saturating_sub(50)..]);

            let has_quote_after = after.chars().take(20).any(|c| c == '"' || c == '\'');

            has_var_before && has_quote_after
        } else {
            false
        }
    }

    /// Check if in HTML attribute context
    fn is_in_attribute_context(&self, body: &str, payload: &str) -> bool {
        if let Some(pos) = body.find(payload) {
            let before = &body[..pos];
            let search_start = before.len().saturating_sub(50);
            let context = &before[search_start..];

            // Look for attribute patterns: name="
            context.contains('=') && (context.contains('"') || context.contains('\''))
        } else {
            false
        }
    }

    /// Check if in URL context
    fn is_in_url_context(&self, body: &str, payload: &str) -> bool {
        if let Some(pos) = body.find(payload) {
            let before = &body[..pos];
            let search_start = before.len().saturating_sub(20);
            let context = &before[search_start..];

            context.contains("href=") || context.contains("src=") || context.contains("action=")
        } else {
            false
        }
    }

    /// Check for dangerous patterns
    fn has_dangerous_patterns(&self, body: &str, payload: &str) -> bool {
        let dangerous = [
            "<script", "</script>", "onerror=", "onload=", "javascript:",
            "<iframe", "<object", "<embed", "eval(", "setTimeout(",
        ];

        dangerous.iter().any(|pattern| body.contains(pattern) && body.contains(payload))
    }

    /// Check for encoding bypass techniques
    fn check_encoding_bypass(&self, body: &str, payload: &str) -> bool {
        // Check for double encoding
        let double_encoded = urlencoding::encode(&urlencoding::encode(payload).to_string()).to_string();
        if body.contains(&double_encoded) {
            return true;
        }

        // Check for HTML entity encoding
        let entity_encoded = payload
            .chars()
            .map(|c| format!("&#{};", c as u32))
            .collect::<String>();
        if body.contains(&entity_encoded) {
            return true;
        }

        // Check for hex encoding
        let hex_encoded = payload
            .chars()
            .map(|c| format!("\\x{:02x}", c as u32))
            .collect::<String>();
        body.contains(&hex_encoded)
    }

    /// Generate payload mutations for confirmation
    pub fn mutate_payload(&self, original: &str) -> Vec<String> {
        let mut mutations = Vec::new();

        // Add original
        mutations.push(original.to_string());

        // Case variations
        mutations.push(original.to_uppercase());
        mutations.push(original.to_lowercase());

        // Spacing variations
        mutations.push(original.replace('>', " >"));
        mutations.push(original.replace('<', "< "));

        // Encoding variations
        mutations.push(self.url_encode(original));
        mutations.push(self.html_encode(original));

        // Event handler variations
        if original.contains("onerror") {
            mutations.push(original.replace("onerror", "ONERROR"));
            mutations.push(original.replace("onerror", "OnError"));
        }

        mutations
    }

    /// Get context-specific payloads
    pub fn get_context_payloads(&self, context: &InjectionContext) -> Vec<String> {
        match context {
            InjectionContext::HtmlBody => vec![
                "<script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "<svg onload=alert(1)>".to_string(),
            ],
            InjectionContext::HtmlAttribute => vec![
                "\" onload=\"alert(1)".to_string(),
                "' onload='alert(1)".to_string(),
                "onload=alert(1)".to_string(),
            ],
            InjectionContext::JavaScriptString => vec![
                "'; alert(1); //".to_string(),
                "\"; alert(1); //".to_string(),
                "\\'; alert(1); //".to_string(),
            ],
            InjectionContext::JavaScriptCode => vec![
                "alert(1)".to_string(),
                ";alert(1)//".to_string(),
            ],
            InjectionContext::UrlParameter => vec![
                "javascript:alert(1)".to_string(),
                "data:text/html,<script>alert(1)</script>".to_string(),
            ],
            InjectionContext::CssContext => vec![
                "expression(alert(1))".to_string(),
                "url(javascript:alert(1))".to_string(),
            ],
            InjectionContext::JsonValue => vec![
                "\"><script>alert(1)</script>".to_string(),
                "</script><script>alert(1)</script>".to_string(),
            ],
            InjectionContext::Unknown => vec![
                "<script>alert(1)</script>".to_string(),
            ],
        }
    }

    /// URL encode a string
    fn url_encode(&self, s: &str) -> String {
        urlencoding::encode(s).to_string()
    }

    /// HTML encode a string
    fn html_encode(&self, s: &str) -> String {
        html_escape::encode_safe(s).to_string()
    }
}

impl Default for XssDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_script_tag_injection() {
        let detector = XssDetector::new();
        let payload = "<script>alert(1)</script>";
        let response = HttpResponse {
            status: 200,
            headers: Default::default(),
            body: format!("<html><body>{}</body></html>", payload),
        };

        let result = detector.detect(payload, &response);
        assert!(result.detected);
        assert_eq!(result.context, InjectionContext::JavaScriptCode);
    }

    #[test]
    fn test_detect_event_handler() {
        let detector = XssDetector::new();
        let payload = "alert(1)";
        let response = HttpResponse {
            status: 200,
            headers: Default::default(),
            body: format!("<img src=x onerror={}>", payload),
        };

        let result = detector.detect(payload, &response);
        assert!(result.detected);
    }

    #[test]
    fn test_encoded_reflection_not_vulnerable() {
        let detector = XssDetector::new();
        let payload = "<script>alert(1)</script>";
        let response = HttpResponse {
            status: 200,
            headers: Default::default(),
            body: "&lt;script&gt;alert(1)&lt;/script&gt;".to_string(),
        };

        let result = detector.detect(payload, &response);
        // Should detect reflection but lower confidence
        assert!(result.confidence < 0.7);
    }
}
