// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * DOM-based XSS Scanner - Context-Aware Detection
 *
 * Comprehensive DOM XSS detection with:
 * - Static analysis of JavaScript source-to-sink flows
 * - Dynamic testing via headless browser
 * - Framework-specific detection (React, Vue, Angular)
 * - Pattern matching for dangerous constructs
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::{AppCharacteristics, AppType, SpaFramework};
use crate::headless_crawler::HeadlessCrawler;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, ScanMode, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// DOM XSS source categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomSource {
    LocationHash,
    LocationSearch,
    LocationHref,
    LocationPathname,
    DocumentUrl,
    DocumentUri,
    DocumentReferrer,
    WindowName,
    DocumentCookie,
    PostMessage,
    LocalStorage,
    SessionStorage,
    UrlSearchParams,
    HashParams,
    CustomSource(String),
}

impl DomSource {
    fn as_pattern(&self) -> &str {
        match self {
            Self::LocationHash => "location.hash",
            Self::LocationSearch => "location.search",
            Self::LocationHref => "location.href",
            Self::LocationPathname => "location.pathname",
            Self::DocumentUrl => "document.URL",
            Self::DocumentUri => "document.documentURI",
            Self::DocumentReferrer => "document.referrer",
            Self::WindowName => "window.name",
            Self::DocumentCookie => "document.cookie",
            Self::PostMessage => "postMessage",
            Self::LocalStorage => "localStorage",
            Self::SessionStorage => "sessionStorage",
            Self::UrlSearchParams => "URLSearchParams",
            Self::HashParams => "hashParams",
            Self::CustomSource(s) => s.as_str(),
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::LocationHash => "URL fragment identifier (after #)",
            Self::LocationSearch => "URL query string (after ?)",
            Self::LocationHref => "Complete URL",
            Self::LocationPathname => "URL path component",
            Self::DocumentUrl => "Document URL property",
            Self::DocumentUri => "Document URI property",
            Self::DocumentReferrer => "HTTP Referer header",
            Self::WindowName => "Window name property (cross-origin accessible)",
            Self::DocumentCookie => "Document cookies",
            Self::PostMessage => "Cross-origin postMessage data",
            Self::LocalStorage => "Local storage data",
            Self::SessionStorage => "Session storage data",
            Self::UrlSearchParams => "URLSearchParams API",
            Self::HashParams => "Hash-based parameters",
            Self::CustomSource(_) => "Custom source",
        }
    }

    fn all_sources() -> Vec<Self> {
        vec![
            Self::LocationHash,
            Self::LocationSearch,
            Self::LocationHref,
            Self::LocationPathname,
            Self::DocumentUrl,
            Self::DocumentUri,
            Self::DocumentReferrer,
            Self::WindowName,
            Self::DocumentCookie,
            Self::PostMessage,
            Self::LocalStorage,
            Self::SessionStorage,
            Self::UrlSearchParams,
        ]
    }
}

/// DOM XSS sink categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomSink {
    // JavaScript execution
    Eval,
    Function,
    SetTimeout,
    SetInterval,
    // HTML injection
    InnerHtml,
    OuterHtml,
    InsertAdjacentHtml,
    DocumentWrite,
    DocumentWriteln,
    // URL/attribute sinks
    ElementHref,
    ElementSrc,
    ElementAction,
    // jQuery sinks
    JQueryHtml,
    JQueryAppend,
    JQueryPrepend,
    JQueryAfter,
    JQueryBefore,
    JQueryReplaceWith,
    // Framework-specific
    ReactDangerouslySetInnerHTML,
    VueVHtml,
    AngularInnerHtmlBinding,
    AngularBypassSecurityTrust,
    // Template literals
    TemplateStringInScript,
    // Custom
    CustomSink(String),
}

impl DomSink {
    fn as_pattern(&self) -> &str {
        match self {
            Self::Eval => "eval(",
            Self::Function => "Function(",
            Self::SetTimeout => "setTimeout(",
            Self::SetInterval => "setInterval(",
            Self::InnerHtml => "innerHTML",
            Self::OuterHtml => "outerHTML",
            Self::InsertAdjacentHtml => "insertAdjacentHTML(",
            Self::DocumentWrite => "document.write(",
            Self::DocumentWriteln => "document.writeln(",
            Self::ElementHref => ".href=",
            Self::ElementSrc => ".src=",
            Self::ElementAction => ".action=",
            Self::JQueryHtml => ".html(",
            Self::JQueryAppend => ".append(",
            Self::JQueryPrepend => ".prepend(",
            Self::JQueryAfter => ".after(",
            Self::JQueryBefore => ".before(",
            Self::JQueryReplaceWith => ".replaceWith(",
            Self::ReactDangerouslySetInnerHTML => "dangerouslySetInnerHTML",
            Self::VueVHtml => "v-html",
            Self::AngularInnerHtmlBinding => "[innerHTML]",
            Self::AngularBypassSecurityTrust => "bypassSecurityTrust",
            Self::TemplateStringInScript => "${",
            Self::CustomSink(s) => s.as_str(),
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::Eval | Self::Function | Self::SetTimeout | Self::SetInterval => Severity::Critical,
            Self::DocumentWrite | Self::DocumentWriteln => Severity::High,
            Self::InnerHtml | Self::OuterHtml | Self::InsertAdjacentHtml => Severity::High,
            Self::ReactDangerouslySetInnerHTML | Self::VueVHtml | Self::AngularInnerHtmlBinding => {
                Severity::High
            }
            Self::AngularBypassSecurityTrust => Severity::Critical,
            Self::JQueryHtml
            | Self::JQueryAppend
            | Self::JQueryPrepend
            | Self::JQueryAfter
            | Self::JQueryBefore
            | Self::JQueryReplaceWith => Severity::High,
            Self::ElementHref | Self::ElementSrc | Self::ElementAction => Severity::Medium,
            Self::TemplateStringInScript => Severity::High,
            Self::CustomSink(_) => Severity::Medium,
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::Eval => "JavaScript code execution via eval()",
            Self::Function => "JavaScript code execution via Function constructor",
            Self::SetTimeout => "Delayed JavaScript execution with string argument",
            Self::SetInterval => "Repeated JavaScript execution with string argument",
            Self::InnerHtml => "Direct HTML insertion via innerHTML",
            Self::OuterHtml => "Direct HTML replacement via outerHTML",
            Self::InsertAdjacentHtml => "HTML insertion via insertAdjacentHTML",
            Self::DocumentWrite => "Document modification via document.write()",
            Self::DocumentWriteln => "Document modification via document.writeln()",
            Self::ElementHref => "URL assignment to href attribute",
            Self::ElementSrc => "URL assignment to src attribute",
            Self::ElementAction => "URL assignment to form action",
            Self::JQueryHtml => "jQuery HTML content setting",
            Self::JQueryAppend => "jQuery append content",
            Self::JQueryPrepend => "jQuery prepend content",
            Self::JQueryAfter => "jQuery after content",
            Self::JQueryBefore => "jQuery before content",
            Self::JQueryReplaceWith => "jQuery replace content",
            Self::ReactDangerouslySetInnerHTML => "React dangerouslySetInnerHTML bypass",
            Self::VueVHtml => "Vue v-html directive bypass",
            Self::AngularInnerHtmlBinding => "Angular [innerHTML] binding",
            Self::AngularBypassSecurityTrust => "Angular security bypass function",
            Self::TemplateStringInScript => "Template literal in script context",
            Self::CustomSink(_) => "Custom dangerous sink",
        }
    }

    fn all_sinks() -> Vec<Self> {
        vec![
            Self::Eval,
            Self::Function,
            Self::SetTimeout,
            Self::SetInterval,
            Self::InnerHtml,
            Self::OuterHtml,
            Self::InsertAdjacentHtml,
            Self::DocumentWrite,
            Self::DocumentWriteln,
            Self::ElementHref,
            Self::ElementSrc,
            Self::ElementAction,
            Self::JQueryHtml,
            Self::JQueryAppend,
            Self::JQueryPrepend,
            Self::JQueryAfter,
            Self::JQueryBefore,
            Self::JQueryReplaceWith,
            Self::ReactDangerouslySetInnerHTML,
            Self::VueVHtml,
            Self::AngularInnerHtmlBinding,
            Self::AngularBypassSecurityTrust,
        ]
    }

    fn framework_specific_sinks(framework: &SpaFramework) -> Vec<Self> {
        match framework {
            SpaFramework::React | SpaFramework::Next => {
                vec![Self::ReactDangerouslySetInnerHTML, Self::InnerHtml]
            }
            SpaFramework::Vue | SpaFramework::Nuxt => {
                vec![Self::VueVHtml, Self::InnerHtml]
            }
            SpaFramework::Angular => vec![
                Self::AngularInnerHtmlBinding,
                Self::AngularBypassSecurityTrust,
                Self::InnerHtml,
            ],
            SpaFramework::Svelte => vec![Self::InnerHtml],
            SpaFramework::Other => vec![Self::InnerHtml, Self::JQueryHtml],
        }
    }
}

/// Detected source-to-sink flow
#[derive(Debug, Clone)]
pub struct SourceToSinkFlow {
    pub source: DomSource,
    pub sink: DomSink,
    pub code_snippet: String,
    pub line_number: Option<usize>,
    pub confidence: Confidence,
    pub intermediate_variables: Vec<String>,
}

impl SourceToSinkFlow {
    fn to_flow_diagram(&self) -> String {
        let mut diagram = format!("[SOURCE: {}]", self.source.as_pattern());

        if !self.intermediate_variables.is_empty() {
            for var in &self.intermediate_variables {
                diagram.push_str(&format!(" -> [{}]", var));
            }
        }

        diagram.push_str(&format!(" -> [SINK: {}]", self.sink.as_pattern()));
        diagram
    }
}

/// DOM XSS Scanner
pub struct DomXssScanner {
    http_client: Arc<HttpClient>,
    confirmed_vulns: Arc<Mutex<HashSet<String>>>,
    dangerous_patterns: Vec<DangerousPattern>,
}

/// Pre-compiled dangerous pattern
struct DangerousPattern {
    name: String,
    regex: Regex,
    source: Option<DomSource>,
    sink: DomSink,
    severity: Severity,
    description: String,
}

impl DomXssScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
            dangerous_patterns: Self::compile_dangerous_patterns(),
        }
    }

    /// Compile regex patterns for dangerous constructs
    fn compile_dangerous_patterns() -> Vec<DangerousPattern> {
        let mut patterns = Vec::new();

        // Direct eval of location data
        if let Ok(regex) = Regex::new(r"eval\s*\(\s*(location\.(hash|search|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)") {
            patterns.push(DangerousPattern {
                name: "Direct eval of location data".to_string(),
                regex,
                source: Some(DomSource::LocationHref),
                sink: DomSink::Eval,
                severity: Severity::Critical,
                description: "User-controlled URL data passed directly to eval()".to_string(),
            });
        }

        // innerHTML assignment from location
        if let Ok(regex) = Regex::new(r"\.innerHTML\s*=\s*(location\.(hash|search|href)|document\.(URL|documentURI|referrer))") {
            patterns.push(DangerousPattern {
                name: "innerHTML assignment from URL".to_string(),
                regex,
                source: Some(DomSource::LocationHref),
                sink: DomSink::InnerHtml,
                severity: Severity::High,
                description: "User-controlled URL data assigned to innerHTML".to_string(),
            });
        }

        // document.write with user input
        if let Ok(regex) = Regex::new(r"document\.write(ln)?\s*\([^)]*?(location\.(hash|search|href)|window\.name|document\.(URL|referrer))") {
            patterns.push(DangerousPattern {
                name: "document.write with URL data".to_string(),
                regex,
                source: Some(DomSource::LocationHref),
                sink: DomSink::DocumentWrite,
                severity: Severity::High,
                description: "User-controlled URL data passed to document.write()".to_string(),
            });
        }

        // jQuery .html() with user input
        if let Ok(regex) = Regex::new(r"\$\([^)]*\)\.html\s*\(\s*(location\.(hash|search|href)|decodeURIComponent\s*\()") {
            patterns.push(DangerousPattern {
                name: "jQuery html() with URL data".to_string(),
                regex,
                source: Some(DomSource::LocationHash),
                sink: DomSink::JQueryHtml,
                severity: Severity::High,
                description: "User-controlled URL data passed to jQuery .html()".to_string(),
            });
        }

        // setTimeout/setInterval with string and user data
        if let Ok(regex) = Regex::new(r#"set(Timeout|Interval)\s*\(\s*[`'"'].*?(location\.(hash|search)|window\.name)"#) {
            patterns.push(DangerousPattern {
                name: "setTimeout/setInterval with URL data".to_string(),
                regex,
                source: Some(DomSource::LocationHash),
                sink: DomSink::SetTimeout,
                severity: Severity::Critical,
                description: "User-controlled URL data in setTimeout/setInterval string".to_string(),
            });
        }

        // postMessage without origin check
        if let Ok(regex) = Regex::new(r#"addEventListener\s*\(\s*['"]message['"]\s*,\s*function\s*\([^)]*\)\s*\{[^}]*(?!origin)[^}]*\.innerHTML"#) {
            patterns.push(DangerousPattern {
                name: "postMessage without origin check".to_string(),
                regex,
                source: Some(DomSource::PostMessage),
                sink: DomSink::InnerHtml,
                severity: Severity::High,
                description: "postMessage handler updates DOM without origin validation".to_string(),
            });
        }

        // React dangerouslySetInnerHTML with user input
        if let Ok(regex) = Regex::new(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(props\.|state\.|this\.props\.|this\.state\.|location\.)") {
            patterns.push(DangerousPattern {
                name: "React dangerouslySetInnerHTML with props/state".to_string(),
                regex,
                source: None,
                sink: DomSink::ReactDangerouslySetInnerHTML,
                severity: Severity::High,
                description: "React dangerouslySetInnerHTML using potentially user-controlled data".to_string(),
            });
        }

        // Vue v-html with user input
        if let Ok(regex) = Regex::new(r#"v-html\s*=\s*['"]?\s*(\$route\.query|\$route\.params|userInput|userData|content)"#) {
            patterns.push(DangerousPattern {
                name: "Vue v-html with route params".to_string(),
                regex,
                source: Some(DomSource::UrlSearchParams),
                sink: DomSink::VueVHtml,
                severity: Severity::High,
                description: "Vue v-html directive using route parameters".to_string(),
            });
        }

        // Angular [innerHTML] with user input
        if let Ok(regex) = Regex::new(r#"\[innerHTML\]\s*=\s*['"]?\s*(route\.params|queryParams|userContent)"#) {
            patterns.push(DangerousPattern {
                name: "Angular innerHTML binding".to_string(),
                regex,
                source: Some(DomSource::UrlSearchParams),
                sink: DomSink::AngularInnerHtmlBinding,
                severity: Severity::High,
                description: "Angular [innerHTML] binding with route parameters".to_string(),
            });
        }

        // Angular bypassSecurityTrust* usage
        if let Ok(regex) = Regex::new(r"bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\s*\(") {
            patterns.push(DangerousPattern {
                name: "Angular security bypass".to_string(),
                regex,
                source: None,
                sink: DomSink::AngularBypassSecurityTrust,
                severity: Severity::High,
                description: "Angular DomSanitizer bypass - verify input is trusted".to_string(),
            });
        }

        // URL assignment from user input
        if let Ok(regex) = Regex::new(r"\.(href|src|action)\s*=\s*(location\.(hash|search)|decodeURIComponent|unescape|window\.name)") {
            patterns.push(DangerousPattern {
                name: "URL attribute assignment".to_string(),
                regex,
                source: Some(DomSource::LocationHash),
                sink: DomSink::ElementHref,
                severity: Severity::Medium,
                description: "URL attribute assigned from user-controlled source".to_string(),
            });
        }

        // localStorage/sessionStorage to sink
        if let Ok(regex) = Regex::new(r"(localStorage|sessionStorage)\.getItem\s*\([^)]+\)[^;]*?\.innerHTML") {
            patterns.push(DangerousPattern {
                name: "Storage to innerHTML".to_string(),
                regex,
                source: Some(DomSource::LocalStorage),
                sink: DomSink::InnerHtml,
                severity: Severity::Medium,
                description: "localStorage/sessionStorage data assigned to innerHTML".to_string(),
            });
        }

        patterns
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Mandatory authorization check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("DOM XSS scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[DOM-XSS] Starting context-aware DOM XSS scan for: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Fetch the page to analyze
        let response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("[DOM-XSS] Failed to fetch URL {}: {}", url, e);
                return Ok((Vec::new(), 0));
            }
        };

        // Detect application characteristics
        let characteristics = AppCharacteristics::from_response(&response, url);

        // Skip non-JavaScript applications
        if characteristics.is_api && !characteristics.is_spa {
            debug!("[DOM-XSS] Skipping API-only endpoint (no JavaScript)");
            return Ok((Vec::new(), 0));
        }

        info!(
            "[DOM-XSS] Application type: {:?}, SPA: {}, Framework indicators: {:?}",
            characteristics.app_type, characteristics.is_spa, characteristics.framework_indicators
        );

        // Phase 1: Static Analysis
        let (static_vulns, static_tests) = self
            .static_analysis(&response.body, url, &characteristics)
            .await?;
        vulnerabilities.extend(static_vulns);
        tests_run += static_tests;

        // Phase 2: Pattern Matching
        let (pattern_vulns, pattern_tests) = self.pattern_analysis(&response.body, url).await?;
        vulnerabilities.extend(pattern_vulns);
        tests_run += pattern_tests;

        // Phase 3: Dynamic Testing (if headless browser available and mode permits)
        if matches!(
            config.scan_mode,
            ScanMode::Thorough | ScanMode::Insane | ScanMode::Intelligent
        ) {
            if HeadlessCrawler::is_available().await {
                let (dynamic_vulns, dynamic_tests) = self
                    .dynamic_analysis(url, &characteristics, config)
                    .await?;
                vulnerabilities.extend(dynamic_vulns);
                tests_run += dynamic_tests;
            } else {
                debug!("[DOM-XSS] Headless browser not available, skipping dynamic testing");
            }
        }

        // Phase 4: Framework-Specific Analysis
        if let AppType::SinglePageApp(ref framework) = characteristics.app_type {
            let (framework_vulns, framework_tests) = self
                .framework_specific_analysis(&response.body, url, framework)
                .await?;
            vulnerabilities.extend(framework_vulns);
            tests_run += framework_tests;
        }

        info!(
            "[DOM-XSS] Scan complete: {} vulnerabilities found, {} tests run",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Static analysis: Find source-to-sink flows in JavaScript
    async fn static_analysis(
        &self,
        body: &str,
        url: &str,
        characteristics: &AppCharacteristics,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[DOM-XSS] Running static analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let mut detected_flows: Vec<SourceToSinkFlow> = Vec::new();

        // Extract all JavaScript content
        let js_content = self.extract_javascript_content(body);

        // Get sources and sinks based on framework
        let sources = DomSource::all_sources();
        let sinks = if let AppType::SinglePageApp(ref framework) = characteristics.app_type {
            let mut framework_sinks = DomSink::framework_specific_sinks(framework);
            // Add common sinks too
            framework_sinks.extend(vec![
                DomSink::Eval,
                DomSink::Function,
                DomSink::SetTimeout,
                DomSink::SetInterval,
                DomSink::DocumentWrite,
            ]);
            framework_sinks
        } else {
            DomSink::all_sinks()
        };

        // Analyze each source-sink combination
        for source in &sources {
            for sink in &sinks {
                tests_run += 1;

                if let Some(flow) = self.detect_flow(&js_content, source, sink) {
                    // Check for duplicate
                    let flow_key = format!("{}:{}", source.as_pattern(), sink.as_pattern());
                    let mut confirmed = self.confirmed_vulns.lock().await;

                    if !confirmed.contains(&flow_key) {
                        confirmed.insert(flow_key);
                        detected_flows.push(flow);
                    }
                }
            }
        }

        // Convert flows to vulnerabilities
        for flow in detected_flows {
            let vuln = self.flow_to_vulnerability(&flow, url);
            vulnerabilities.push(vuln);
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Extract JavaScript content from HTML
    fn extract_javascript_content(&self, html: &str) -> String {
        let mut js_content = String::new();

        // Extract inline scripts
        let script_regex = Regex::new(r"(?s)<script[^>]*>(.*?)</script>").ok();
        if let Some(regex) = script_regex {
            for cap in regex.captures_iter(html) {
                if let Some(script) = cap.get(1) {
                    js_content.push_str(script.as_str());
                    js_content.push('\n');
                }
            }
        }

        // Extract event handlers
        let event_regex = Regex::new(r#"(?i)(on\w+)\s*=\s*["']([^"']+)["']"#).ok();
        if let Some(regex) = event_regex {
            for cap in regex.captures_iter(html) {
                if let Some(handler) = cap.get(2) {
                    js_content.push_str(handler.as_str());
                    js_content.push('\n');
                }
            }
        }

        // Extract href="javascript:" URLs
        let js_url_regex = Regex::new(r#"(?i)href\s*=\s*["']javascript:([^"']+)["']"#).ok();
        if let Some(regex) = js_url_regex {
            for cap in regex.captures_iter(html) {
                if let Some(code) = cap.get(1) {
                    js_content.push_str(code.as_str());
                    js_content.push('\n');
                }
            }
        }

        js_content
    }

    /// Detect source-to-sink flow
    fn detect_flow(&self, js_content: &str, source: &DomSource, sink: &DomSink) -> Option<SourceToSinkFlow> {
        let source_pattern = source.as_pattern();
        let sink_pattern = sink.as_pattern();

        // Check if both source and sink exist in the code
        if !js_content.contains(source_pattern) || !js_content.contains(sink_pattern) {
            return None;
        }

        // Find line numbers and proximity
        let lines: Vec<&str> = js_content.lines().collect();
        let mut source_lines = Vec::new();
        let mut sink_lines = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            if line.contains(source_pattern) {
                source_lines.push(i);
            }
            if line.contains(sink_pattern) {
                sink_lines.push(i);
            }
        }

        // Check for direct flow (same line or adjacent lines)
        for &source_line in &source_lines {
            for &sink_line in &sink_lines {
                let distance = if sink_line > source_line {
                    sink_line - source_line
                } else {
                    source_line - sink_line
                };

                // Direct flow: within 10 lines
                if distance <= 10 {
                    // Extract code snippet
                    let start = source_line.saturating_sub(2);
                    let end = (sink_line + 3).min(lines.len());
                    let snippet: String = lines[start..end].join("\n");

                    // Try to detect intermediate variables
                    let intermediate_vars = self.detect_intermediate_variables(&snippet, source_pattern);

                    let confidence = if distance == 0 {
                        Confidence::High
                    } else if distance <= 3 {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    };

                    return Some(SourceToSinkFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        code_snippet: snippet,
                        line_number: Some(source_line + 1),
                        confidence,
                        intermediate_variables: intermediate_vars,
                    });
                }
            }
        }

        // Check for indirect flow through variable assignment
        if let Some(flow) = self.detect_indirect_flow(js_content, source, sink, &lines) {
            return Some(flow);
        }

        None
    }

    /// Detect intermediate variables in a flow
    fn detect_intermediate_variables(&self, snippet: &str, source_pattern: &str) -> Vec<String> {
        let mut variables = Vec::new();

        // Look for variable assignments from source
        let var_regex = Regex::new(&format!(
            r"(?:var|let|const)\s+(\w+)\s*=\s*[^;]*{}",
            regex::escape(source_pattern)
        ))
        .ok();

        if let Some(regex) = var_regex {
            for cap in regex.captures_iter(snippet) {
                if let Some(var_name) = cap.get(1) {
                    variables.push(var_name.as_str().to_string());
                }
            }
        }

        variables
    }

    /// Detect indirect flow through variable assignments
    fn detect_indirect_flow(
        &self,
        js_content: &str,
        source: &DomSource,
        sink: &DomSink,
        _lines: &[&str],
    ) -> Option<SourceToSinkFlow> {
        // Build regex for variable assignment from source
        let source_pattern = regex::escape(source.as_pattern());
        let assign_regex = Regex::new(&format!(
            r"(?:var|let|const)\s+(\w+)\s*=\s*[^;]*{}",
            source_pattern
        ))
        .ok()?;

        // Find variables assigned from source
        let mut source_vars: Vec<String> = Vec::new();
        for cap in assign_regex.captures_iter(js_content) {
            if let Some(var_name) = cap.get(1) {
                source_vars.push(var_name.as_str().to_string());
            }
        }

        // Check if any of these variables reach the sink
        let sink_pattern = sink.as_pattern();
        for var in &source_vars {
            // Look for pattern: sink(var) or .sinkMethod(var)
            let sink_with_var = format!("{}.*{}", regex::escape(sink_pattern), regex::escape(var));
            if let Ok(regex) = Regex::new(&sink_with_var) {
                if regex.is_match(js_content) {
                    return Some(SourceToSinkFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        code_snippet: format!(
                            "Indirect flow via variable '{}'",
                            var
                        ),
                        line_number: None,
                        confidence: Confidence::Medium,
                        intermediate_variables: vec![var.clone()],
                    });
                }
            }

            // Also check if variable is used directly in sink
            let var_in_sink = format!(r"{}\s*\(\s*{}", regex::escape(sink_pattern), regex::escape(var));
            if let Ok(regex) = Regex::new(&var_in_sink) {
                if regex.is_match(js_content) {
                    return Some(SourceToSinkFlow {
                        source: source.clone(),
                        sink: sink.clone(),
                        code_snippet: format!(
                            "Variable '{}' from {} passed to {}",
                            var,
                            source.as_pattern(),
                            sink.as_pattern()
                        ),
                        line_number: None,
                        confidence: Confidence::Medium,
                        intermediate_variables: vec![var.clone()],
                    });
                }
            }
        }

        None
    }

    /// Pattern matching analysis
    async fn pattern_analysis(
        &self,
        body: &str,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[DOM-XSS] Running pattern analysis");

        let mut vulnerabilities = Vec::new();
        let tests_run = self.dangerous_patterns.len();

        for pattern in &self.dangerous_patterns {
            if pattern.regex.is_match(body) {
                // Extract matching code
                let match_text = pattern
                    .regex
                    .find(body)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                let vuln_key = format!("pattern:{}", pattern.name);
                let mut confirmed = self.confirmed_vulns.lock().await;

                if !confirmed.contains(&vuln_key) {
                    confirmed.insert(vuln_key);

                    let vuln = Vulnerability {
                        id: format!("dom_xss_{}", uuid::Uuid::new_v4()),
                        vuln_type: "DOM-based XSS".to_string(),
                        severity: pattern.severity.clone(),
                        confidence: Confidence::High,
                        category: "Injection".to_string(),
                        url: url.to_string(),
                        parameter: pattern.source.as_ref().map(|s| s.as_pattern().to_string()),
                        payload: match_text.clone(),
                        description: format!(
                            "DOM XSS Pattern Detected: {}. {}",
                            pattern.name, pattern.description
                        ),
                        evidence: Some(format!(
                            "Pattern: {}\nMatched Code:\n{}",
                            pattern.name, match_text
                        )),
                        cwe: "CWE-79".to_string(),
                        cvss: self.calculate_cvss(&pattern.severity),
                        verified: true,
                        false_positive: false,
                        remediation: self.get_remediation_for_sink(&pattern.sink),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    };

                    info!(
                        "[DOM-XSS] Pattern match: {} ({})",
                        pattern.name, pattern.severity
                    );
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Dynamic analysis using headless browser
    async fn dynamic_analysis(
        &self,
        url: &str,
        characteristics: &AppCharacteristics,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[DOM-XSS] Running dynamic analysis with headless browser");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Generate canary values for each source
        let canary_base = format!("DOMXSS{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());

        // Payloads for different sources
        let test_payloads: Vec<(DomSource, String, String)> = vec![
            // Hash-based
            (
                DomSource::LocationHash,
                format!("{}#<img src=x onerror=alert('{}')>", url, canary_base),
                canary_base.clone(),
            ),
            (
                DomSource::LocationHash,
                format!("{}#<svg onload=alert('{}')>", url, canary_base),
                canary_base.clone(),
            ),
            // Query parameter based
            (
                DomSource::LocationSearch,
                format!("{}?q=<img src=x onerror=alert('{}')>", url, canary_base),
                canary_base.clone(),
            ),
            (
                DomSource::LocationSearch,
                format!("{}?callback=alert//", url),
                "alert".to_string(),
            ),
            // JSONP-style callback injection
            (
                DomSource::UrlSearchParams,
                format!("{}?callback=<script>alert('{}')</script>", url, canary_base),
                canary_base.clone(),
            ),
        ];

        // Add framework-specific payloads
        let framework_payloads = match characteristics.app_type {
            AppType::SinglePageApp(SpaFramework::Vue | SpaFramework::Nuxt) => {
                vec![
                    format!("{}#{{{{constructor.constructor('alert(1)')()}}}}", url),
                    format!("{}?template={{{{7*7}}}}", url),
                ]
            }
            AppType::SinglePageApp(SpaFramework::Angular) => {
                vec![
                    format!("{}#{{{{constructor.constructor('alert(1)')()}}}}", url),
                    format!("{}?input={{{{$on.constructor('alert(1)')()}}}}", url),
                ]
            }
            _ => vec![],
        };

        let crawler = HeadlessCrawler::new(30);

        // Test each payload
        for (source, test_url, marker) in &test_payloads {
            tests_run += 1;

            match self
                .test_dynamic_payload(&crawler, test_url, marker)
                .await
            {
                Ok(true) => {
                    let vuln_key = format!("dynamic:{}:{}", source.as_pattern(), marker);
                    let mut confirmed = self.confirmed_vulns.lock().await;

                    if !confirmed.contains(&vuln_key) {
                        confirmed.insert(vuln_key);

                        let vuln = Vulnerability {
                            id: format!("dom_xss_{}", uuid::Uuid::new_v4()),
                            vuln_type: "DOM-based XSS (Confirmed)".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(source.as_pattern().to_string()),
                            payload: test_url.clone(),
                            description: format!(
                                "Confirmed DOM XSS via {}. JavaScript executed in browser context. Source: {}",
                                source.as_pattern(),
                                source.description()
                            ),
                            evidence: Some(format!(
                                "Canary marker '{}' triggered JavaScript execution.\nSource: {}\nTest URL: {}",
                                marker, source.as_pattern(), test_url
                            )),
                            cwe: "CWE-79".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: self.get_remediation_for_source(source),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        };

                        info!(
                            "[DOM-XSS] CONFIRMED: Dynamic XSS via {} with marker {}",
                            source.as_pattern(),
                            marker
                        );
                        vulnerabilities.push(vuln);
                    }
                }
                Ok(false) => {
                    debug!("[DOM-XSS] Dynamic test negative for {}", test_url);
                }
                Err(e) => {
                    debug!("[DOM-XSS] Dynamic test error: {}", e);
                }
            }
        }

        // Test framework-specific payloads
        for test_url in framework_payloads {
            tests_run += 1;
            if let Ok(true) = self
                .test_dynamic_payload(&crawler, &test_url, "49") // 7*7 = 49
                .await
            {
                let vuln_key = format!("dynamic:template:{}", test_url);
                let mut confirmed = self.confirmed_vulns.lock().await;

                if !confirmed.contains(&vuln_key) {
                    confirmed.insert(vuln_key);

                    let vuln = Vulnerability {
                        id: format!("dom_xss_template_{}", uuid::Uuid::new_v4()),
                        vuln_type: "Client-Side Template Injection".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Injection".to_string(),
                        url: test_url.clone(),
                        parameter: Some("template".to_string()),
                        payload: test_url.clone(),
                        description: "Client-side template injection leading to DOM XSS. Template expression was evaluated.".to_string(),
                        evidence: Some(format!("Template expression evaluated: 7*7=49\nURL: {}", test_url)),
                        cwe: "CWE-79".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Sanitize user input before interpolation in templates. Use text bindings instead of HTML bindings.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    };

                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test a payload dynamically using headless browser
    async fn test_dynamic_payload(
        &self,
        _crawler: &HeadlessCrawler,
        url: &str,
        marker: &str,
    ) -> Result<bool> {
        // Execute in blocking thread for headless_chrome
        let url_owned = url.to_string();
        let marker_owned = marker.to_string();

        let result = tokio::task::spawn_blocking(move || {
            Self::test_payload_sync(&url_owned, &marker_owned)
        })
        .await??;

        Ok(result)
    }

    /// Synchronous payload testing
    fn test_payload_sync(url: &str, marker: &str) -> Result<bool> {
        use headless_chrome::{Browser, LaunchOptions};
        use std::time::Duration;

        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )?;

        let tab = browser.new_tab()?;

        // Set up alert detection
        let alert_triggered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let alert_flag = alert_triggered.clone();

        // Override alert function to detect execution
        let js_override = format!(
            r#"
            window.originalAlert = window.alert;
            window.xssMarker = '{}';
            window.xssTriggered = false;
            window.alert = function(msg) {{
                if (msg && msg.toString().includes(window.xssMarker)) {{
                    window.xssTriggered = true;
                }}
                return undefined;
            }};
            "#,
            marker
        );

        tab.navigate_to("about:blank")?;
        tab.evaluate(&js_override, false)?;

        // Navigate to test URL
        match tab.navigate_to(url) {
            Ok(_) => {}
            Err(e) => {
                debug!("Navigation failed: {}", e);
                return Ok(false);
            }
        }

        // Wait for page load
        std::thread::sleep(Duration::from_secs(3));

        // Check if XSS triggered
        let check_js = "window.xssTriggered === true";
        if let Ok(result) = tab.evaluate(check_js, false) {
            if let Some(value) = result.value {
                if value.as_bool() == Some(true) {
                    return Ok(true);
                }
            }
        }

        // Also check DOM for marker (in case it rendered without alert)
        let check_dom = format!(
            "document.body && document.body.innerHTML.includes('{}')",
            marker
        );
        if let Ok(result) = tab.evaluate(&check_dom, false) {
            if let Some(value) = result.value {
                if value.as_bool() == Some(true) {
                    // Check if it's in a script context
                    let check_script = format!(
                        "Array.from(document.scripts).some(s => s.textContent.includes('{}'))",
                        marker
                    );
                    if let Ok(script_result) = tab.evaluate(&check_script, false) {
                        if script_result.value.and_then(|v| v.as_bool()) == Some(true) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Framework-specific analysis
    async fn framework_specific_analysis(
        &self,
        body: &str,
        url: &str,
        framework: &SpaFramework,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("[DOM-XSS] Running framework-specific analysis for {:?}", framework);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let patterns: Vec<(&str, &str, Severity)> = match framework {
            SpaFramework::React | SpaFramework::Next => {
                vec![
                    (
                        r"dangerouslySetInnerHTML\s*=\s*\{",
                        "React dangerouslySetInnerHTML usage detected",
                        Severity::Medium,
                    ),
                    (
                        r"__html\s*:\s*[^}]*\+",
                        "String concatenation in dangerouslySetInnerHTML",
                        Severity::High,
                    ),
                    (
                        r"createRef.*innerHTML",
                        "Direct innerHTML access via ref",
                        Severity::High,
                    ),
                    (
                        r"useRef.*\.current\.innerHTML\s*=",
                        "React useRef innerHTML assignment",
                        Severity::High,
                    ),
                ]
            }
            SpaFramework::Vue | SpaFramework::Nuxt => {
                vec![
                    (r"v-html\s*=", "Vue v-html directive usage", Severity::Medium),
                    (
                        r#"v-html\s*=\s*['""][^'""]*\$route"#,
                        "Vue v-html with route data",
                        Severity::High,
                    ),
                    (
                        r"\$refs\.[^.]+\.innerHTML\s*=",
                        "Vue $refs innerHTML assignment",
                        Severity::High,
                    ),
                    (
                        r"render\s*:\s*h\s*=>\s*h\([^,]+,\s*\{\s*domProps\s*:\s*\{\s*innerHTML",
                        "Vue render function innerHTML",
                        Severity::High,
                    ),
                ]
            }
            SpaFramework::Angular => {
                vec![
                    (r"\[innerHTML\]\s*=", "Angular innerHTML binding", Severity::Medium),
                    (
                        r#"\[innerHTML\]\s*=\s*['"][^'"]*route"#,
                        "Angular innerHTML with route params",
                        Severity::High,
                    ),
                    (
                        r"bypassSecurityTrustHtml\s*\(",
                        "Angular DomSanitizer bypass (HTML)",
                        Severity::High,
                    ),
                    (
                        r"bypassSecurityTrustScript\s*\(",
                        "Angular DomSanitizer bypass (Script)",
                        Severity::Critical,
                    ),
                    (
                        r"bypassSecurityTrustUrl\s*\(",
                        "Angular DomSanitizer bypass (URL)",
                        Severity::Medium,
                    ),
                    (
                        r"ElementRef.*nativeElement.*innerHTML",
                        "Angular ElementRef innerHTML",
                        Severity::High,
                    ),
                ]
            }
            SpaFramework::Svelte => {
                vec![
                    (r"\{@html\s+", "Svelte @html directive usage", Severity::Medium),
                    (
                        r"\{@html\s+[^}]*\$page",
                        "Svelte @html with page params",
                        Severity::High,
                    ),
                ]
            }
            SpaFramework::Other => {
                vec![
                    (r"\.innerHTML\s*=\s*[^;]*\+", "innerHTML with concatenation", Severity::Medium),
                    (r"\.html\s*\([^)]*\+", "jQuery html() with concatenation", Severity::Medium),
                ]
            }
        };

        for (pattern_str, description, severity) in patterns {
            tests_run += 1;

            if let Ok(regex) = Regex::new(pattern_str) {
                if regex.is_match(body) {
                    let vuln_key = format!("framework:{}:{}", framework_to_string(framework), pattern_str);
                    let mut confirmed = self.confirmed_vulns.lock().await;

                    if !confirmed.contains(&vuln_key) {
                        confirmed.insert(vuln_key);

                        // Extract matched code
                        let matched = regex
                            .find(body)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default();

                        let vuln = Vulnerability {
                            id: format!("dom_xss_fw_{}", uuid::Uuid::new_v4()),
                            vuln_type: format!("DOM XSS ({} Framework)", framework_to_string(framework)),
                            severity: severity.clone(),
                            confidence: Confidence::Medium,
                            category: "Injection".to_string(),
                            url: url.to_string(),
                            parameter: None,
                            payload: matched.clone(),
                            description: format!(
                                "{} (Framework: {}). Review for potential DOM XSS.",
                                description,
                                framework_to_string(framework)
                            ),
                            evidence: Some(format!(
                                "Pattern: {}\nMatched: {}\nFramework: {:?}",
                                pattern_str, matched, framework
                            )),
                            cwe: "CWE-79".to_string(),
                            cvss: self.calculate_cvss(&severity),
                            verified: false,
                            false_positive: false,
                            remediation: self.get_framework_remediation(framework),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        };

                        info!(
                            "[DOM-XSS] Framework pattern: {} in {:?}",
                            description, framework
                        );
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Convert flow to vulnerability
    fn flow_to_vulnerability(&self, flow: &SourceToSinkFlow, url: &str) -> Vulnerability {
        let flow_diagram = flow.to_flow_diagram();

        Vulnerability {
            id: format!("dom_xss_{}", uuid::Uuid::new_v4()),
            vuln_type: "DOM-based XSS".to_string(),
            severity: flow.sink.severity(),
            confidence: flow.confidence.clone(),
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(flow.source.as_pattern().to_string()),
            payload: flow.code_snippet.clone(),
            description: format!(
                "DOM XSS: Data flows from {} to {}. {}\n\nFlow: {}",
                flow.source.as_pattern(),
                flow.sink.as_pattern(),
                flow.sink.description(),
                flow_diagram
            ),
            evidence: Some(format!(
                "Source: {} - {}\nSink: {} - {}\nLine: {}\nFlow Diagram: {}\nCode:\n{}",
                flow.source.as_pattern(),
                flow.source.description(),
                flow.sink.as_pattern(),
                flow.sink.description(),
                flow.line_number.map(|n| n.to_string()).unwrap_or("unknown".to_string()),
                flow_diagram,
                flow.code_snippet
            )),
            cwe: "CWE-79".to_string(),
            cvss: self.calculate_cvss(&flow.sink.severity()),
            verified: false,
            false_positive: false,
            remediation: self.get_remediation_for_sink(&flow.sink),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }

    /// Calculate CVSS score based on severity
    fn calculate_cvss(&self, severity: &Severity) -> f32 {
        match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.5,
            Severity::Medium => 5.5,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        }
    }

    /// Get remediation for a specific sink
    fn get_remediation_for_sink(&self, sink: &DomSink) -> String {
        match sink {
            DomSink::Eval | DomSink::Function => {
                "Never use eval() or Function() with user-controlled data. Use JSON.parse() for data parsing. Consider Content Security Policy with 'unsafe-eval' disabled.".to_string()
            }
            DomSink::SetTimeout | DomSink::SetInterval => {
                "Avoid passing strings to setTimeout/setInterval. Use function references instead: setTimeout(function() { ... }, delay) instead of setTimeout('code', delay).".to_string()
            }
            DomSink::InnerHtml | DomSink::OuterHtml => {
                "Use textContent instead of innerHTML when possible. For HTML content, use a sanitization library like DOMPurify. Implement Content Security Policy.".to_string()
            }
            DomSink::InsertAdjacentHtml => {
                "Sanitize HTML content before using insertAdjacentHTML. Consider using createElement and appendChild instead.".to_string()
            }
            DomSink::DocumentWrite | DomSink::DocumentWriteln => {
                "Avoid document.write() entirely. Use DOM manipulation methods (createElement, appendChild) instead. document.write() is considered deprecated.".to_string()
            }
            DomSink::ElementHref | DomSink::ElementSrc | DomSink::ElementAction => {
                "Validate and sanitize URLs before assignment. Use allowlists for protocols (http, https). Consider using URL() constructor for parsing and validation.".to_string()
            }
            DomSink::JQueryHtml | DomSink::JQueryAppend | DomSink::JQueryPrepend
            | DomSink::JQueryAfter | DomSink::JQueryBefore | DomSink::JQueryReplaceWith => {
                "Use .text() instead of .html() when inserting user content. Sanitize HTML with DOMPurify before using jQuery HTML methods.".to_string()
            }
            DomSink::ReactDangerouslySetInnerHTML => {
                "Avoid dangerouslySetInnerHTML with user input. If necessary, sanitize with DOMPurify: { __html: DOMPurify.sanitize(userContent) }. Consider using React's built-in XSS protection.".to_string()
            }
            DomSink::VueVHtml => {
                "Avoid v-html with user input. Use {{ }} interpolation instead (auto-escaped). If HTML is required, sanitize with DOMPurify before binding.".to_string()
            }
            DomSink::AngularInnerHtmlBinding => {
                "Angular sanitizes [innerHTML] by default, but custom pipes or bypassSecurityTrust* can bypass this. Ensure user input is properly sanitized. Avoid bypassSecurityTrust* with user data.".to_string()
            }
            DomSink::AngularBypassSecurityTrust => {
                "CRITICAL: bypassSecurityTrust* functions disable Angular's built-in XSS protection. Only use with trusted, server-validated content. Never use with user input.".to_string()
            }
            DomSink::TemplateStringInScript => {
                "Avoid interpolating user data into template strings in script context. Encode data appropriately or use data attributes.".to_string()
            }
            DomSink::CustomSink(_) => {
                "Review custom sink for proper input sanitization. Apply context-appropriate encoding.".to_string()
            }
        }
    }

    /// Get remediation for a specific source
    fn get_remediation_for_source(&self, source: &DomSource) -> String {
        match source {
            DomSource::LocationHash | DomSource::LocationSearch | DomSource::LocationHref => {
                "Validate and sanitize all URL-derived data before use. Use URLSearchParams for safe parameter extraction. Implement input validation and encoding.".to_string()
            }
            DomSource::PostMessage => {
                "Always validate the origin of postMessage events. Check event.origin against an allowlist. Validate and sanitize message data before DOM insertion.".to_string()
            }
            DomSource::WindowName => {
                "window.name is accessible cross-origin. Never trust window.name content. Validate and sanitize before use.".to_string()
            }
            DomSource::DocumentReferrer => {
                "document.referrer can be attacker-controlled. Validate and sanitize before rendering in DOM.".to_string()
            }
            DomSource::LocalStorage | DomSource::SessionStorage => {
                "Storage data may have been set by attacker (via XSS). Validate and sanitize storage data before DOM insertion.".to_string()
            }
            _ => {
                "Validate and sanitize all user-controllable input before using in DOM sinks.".to_string()
            }
        }
    }

    /// Get framework-specific remediation
    fn get_framework_remediation(&self, framework: &SpaFramework) -> String {
        match framework {
            SpaFramework::React | SpaFramework::Next => {
                "React provides automatic XSS protection through JSX. Avoid dangerouslySetInnerHTML. If raw HTML is needed, sanitize with DOMPurify. Use React's built-in encoding for dynamic content.".to_string()
            }
            SpaFramework::Vue | SpaFramework::Nuxt => {
                "Vue automatically escapes content in {{ }} interpolation. Avoid v-html directive with user input. If raw HTML is needed, sanitize with DOMPurify before v-html binding.".to_string()
            }
            SpaFramework::Angular => {
                "Angular sanitizes by default. Avoid bypassSecurityTrust* functions with user input. Use Angular's DomSanitizer.sanitize() for custom sanitization. Review all [innerHTML] bindings.".to_string()
            }
            SpaFramework::Svelte => {
                "Svelte escapes content by default. Avoid {@html} directive with user input. Sanitize with DOMPurify if raw HTML is required.".to_string()
            }
            SpaFramework::Other => {
                "Apply framework-appropriate sanitization. Use textContent instead of innerHTML. Implement Content Security Policy.".to_string()
            }
        }
    }
}

/// Convert SpaFramework to string
fn framework_to_string(framework: &SpaFramework) -> &'static str {
    match framework {
        SpaFramework::React => "React",
        SpaFramework::Vue => "Vue",
        SpaFramework::Angular => "Angular",
        SpaFramework::Svelte => "Svelte",
        SpaFramework::Next => "Next.js",
        SpaFramework::Nuxt => "Nuxt.js",
        SpaFramework::Other => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dom_source_patterns() {
        let source = DomSource::LocationHash;
        assert_eq!(source.as_pattern(), "location.hash");

        let source = DomSource::PostMessage;
        assert_eq!(source.as_pattern(), "postMessage");
    }

    #[test]
    fn test_dom_sink_patterns() {
        let sink = DomSink::Eval;
        assert_eq!(sink.as_pattern(), "eval(");
        assert_eq!(sink.severity(), Severity::Critical);

        let sink = DomSink::InnerHtml;
        assert_eq!(sink.as_pattern(), "innerHTML");
        assert_eq!(sink.severity(), Severity::High);
    }

    #[test]
    fn test_flow_diagram() {
        let flow = SourceToSinkFlow {
            source: DomSource::LocationHash,
            sink: DomSink::InnerHtml,
            code_snippet: "element.innerHTML = location.hash".to_string(),
            line_number: Some(10),
            confidence: Confidence::High,
            intermediate_variables: vec!["hashData".to_string()],
        };

        let diagram = flow.to_flow_diagram();
        assert!(diagram.contains("SOURCE: location.hash"));
        assert!(diagram.contains("hashData"));
        assert!(diagram.contains("SINK: innerHTML"));
    }

    #[test]
    fn test_dangerous_patterns_compile() {
        let patterns = DomXssScanner::compile_dangerous_patterns();
        assert!(!patterns.is_empty());

        // Test that patterns match expected code
        let dangerous_code = "eval(location.hash)";
        let eval_pattern = patterns.iter().find(|p| p.name.contains("eval"));
        assert!(eval_pattern.is_some());
        assert!(eval_pattern.unwrap().regex.is_match(dangerous_code));
    }

    #[test]
    fn test_framework_sinks() {
        let react_sinks = DomSink::framework_specific_sinks(&SpaFramework::React);
        assert!(react_sinks.contains(&DomSink::ReactDangerouslySetInnerHTML));

        let vue_sinks = DomSink::framework_specific_sinks(&SpaFramework::Vue);
        assert!(vue_sinks.contains(&DomSink::VueVHtml));

        let angular_sinks = DomSink::framework_specific_sinks(&SpaFramework::Angular);
        assert!(angular_sinks.contains(&DomSink::AngularInnerHtmlBinding));
    }
}
