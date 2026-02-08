// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - DOM Clobbering Scanner
 * Context-aware detection of DOM clobbering vulnerabilities
 *
 * WHAT IS DOM CLOBBERING?
 * =======================
 * DOM clobbering exploits the HTML spec behavior where named elements
 * (with `id` or `name` attributes) are automatically added to the global
 * `window` and `document` objects, potentially overwriting existing
 * properties or undefined variables used by JavaScript code.
 *
 * CLOBBERING TECHNIQUES:
 * =====================
 * 1. Named element access: `<img name="x">` -> `window.x`
 * 2. ID-based access: `<div id="x">` -> `document.x` or `window.x`
 * 3. Form element clobbering: `<form id="x"><input name="y">` -> `x.y`
 * 4. Collection clobbering: Multiple elements with same name create HTMLCollection
 * 5. toString/valueOf override via anchor href
 * 6. Nested property clobbering via form + input combinations
 *
 * VULNERABLE PATTERNS:
 * ===================
 * - Code accessing `window.config`, `window.settings`, `window.data`
 * - Undefined global variable usage
 * - `document.getElementById` without existence check
 * - Attribute access on potentially clobbered objects
 *
 * EXPLOITATION SCENARIOS:
 * ======================
 * ```javascript
 * // Vulnerable code
 * if (window.config) {
 *   location.href = window.config.url;
 * }
 *
 * // Clobbering attack
 * <a id="config" href="javascript:alert(1)">
 * ```
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Common global variables that are often targeted for DOM clobbering
const COMMON_CLOBBER_TARGETS: &[&str] = &[
    // Configuration objects
    "config",
    "settings",
    "options",
    "data",
    "params",
    "props",
    "state",
    // Application-specific
    "APP",
    "CONFIG",
    "SETTINGS",
    "ENV",
    "API",
    "ENDPOINTS",
    "ROUTES",
    // Framework globals
    "jQuery",
    "angular",
    "Vue",
    "React",
    "Ember",
    "Backbone",
    // Common library globals
    "axios",
    "lodash",
    "_",
    "$",
    // Authentication/security
    "auth",
    "user",
    "session",
    "token",
    "csrf",
    // Analytics/tracking
    "analytics",
    "gtag",
    "dataLayer",
    // DOM manipulation
    "body",
    "head",
    "forms",
    "images",
    "links",
    "scripts",
];

/// Dangerous sinks that can lead to XSS when combined with clobbering
const DANGEROUS_SINKS: &[&str] = &[
    // Script execution
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    // DOM manipulation
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write(",
    "document.writeln(",
    // URL/navigation
    "location.href",
    "location.assign(",
    "location.replace(",
    "window.open(",
    // Source loading
    "src=",
    ".src",
    "href=",
    ".href",
    "action=",
    ".action",
    // jQuery methods
    ".html(",
    ".append(",
    ".prepend(",
    ".after(",
    ".before(",
    ".replaceWith(",
    // Attribute manipulation
    "setAttribute(",
    ".setAttribute(",
];

/// Patterns indicating HTML injection possibilities
const HTML_INJECTION_INDICATORS: &[&str] = &[
    // User input reflection
    "innerHTML =",
    "outerHTML =",
    ".html(",
    "document.write",
    // Template engines with unsafe modes
    "dangerouslySetInnerHTML",
    "v-html",
    "[innerHTML]",
    "{{{",
    // Markdown/rich text
    "marked(",
    "markdown(",
    "DOMPurify",
    "sanitize",
];

/// Results from DOM clobbering analysis
#[derive(Debug, Clone)]
pub struct DomClobberingResult {
    /// Detected global variables that might be clobberable
    pub clobberable_globals: Vec<ClobberableGlobal>,
    /// Detected HTML injection points
    pub html_injection_points: Vec<HtmlInjectionPoint>,
    /// Detected dangerous sink usages
    pub dangerous_sink_usages: Vec<DangerousSinkUsage>,
    /// Potential exploitation paths
    pub exploitation_paths: Vec<ExploitationPath>,
}

/// A global variable that might be clobberable
#[derive(Debug, Clone)]
pub struct ClobberableGlobal {
    pub name: String,
    pub access_pattern: String,
    pub source_snippet: String,
    pub is_nested: bool,
    pub nested_property: Option<String>,
}

/// An HTML injection point
#[derive(Debug, Clone)]
pub struct HtmlInjectionPoint {
    pub location: String,
    pub context: String,
    pub allows_id_name: bool,
}

/// Usage of a dangerous sink
#[derive(Debug, Clone)]
pub struct DangerousSinkUsage {
    pub sink: String,
    pub source_variable: Option<String>,
    pub snippet: String,
}

/// Complete exploitation path from clobber to sink
#[derive(Debug, Clone)]
pub struct ExploitationPath {
    pub clobbered_global: String,
    pub sink: String,
    pub technique: ClobberTechnique,
    pub poc_html: String,
    pub impact: String,
}

/// DOM clobbering technique used
#[derive(Debug, Clone, PartialEq)]
pub enum ClobberTechnique {
    /// <img id="x"> -> window.x
    IdAttribute,
    /// <img name="x"> -> window.x
    NameAttribute,
    /// <form id="x"><input name="y"> -> x.y
    FormInputNested,
    /// <a id="x" href="..."> -> window.x.toString()
    AnchorToString,
    /// Multiple <img name="x"> -> window.x (HTMLCollection)
    Collection,
    /// <form id="x"><img id="y"> -> nested clobbering
    DeepNested,
}

impl std::fmt::Display for ClobberTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClobberTechnique::IdAttribute => write!(f, "ID Attribute Clobbering"),
            ClobberTechnique::NameAttribute => write!(f, "Name Attribute Clobbering"),
            ClobberTechnique::FormInputNested => write!(f, "Form+Input Nested Clobbering"),
            ClobberTechnique::AnchorToString => write!(f, "Anchor toString Override"),
            ClobberTechnique::Collection => write!(f, "HTMLCollection Clobbering"),
            ClobberTechnique::DeepNested => write!(f, "Deep Nested Clobbering"),
        }
    }
}

/// DOM Clobbering Scanner
pub struct DomClobberingScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl DomClobberingScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("domclob_{}", Self::generate_id());
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
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!("[DOMClobbering] Starting DOM clobbering scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Fetch the page
        let response = match self.http_client.get(url).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("[DOMClobbering] Failed to fetch page: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        // Get app characteristics for context-aware scanning
        let app_characteristics = AppCharacteristics::from_response(&response, url);

        // Skip if this is a pure API endpoint
        if app_characteristics.is_api_only {
            debug!("[DOMClobbering] Skipping API-only endpoint");
            return Ok((Vec::new(), 0));
        }

        // Phase 1: Analyze JavaScript for global variable access patterns
        let (vulns, tests) = self
            .analyze_javascript(&response.body, url, &app_characteristics)
            .await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 2: Test for HTML injection points (prerequisite for clobbering)
        let (vulns, tests) = self.test_html_injection_for_clobbering(url, config).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 3: Analyze inline scripts for clobberable patterns
        let (vulns, tests) = self.analyze_inline_scripts(&response.body, url);
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 4: Analyze external JavaScript files
        let (vulns, tests) = self.analyze_external_scripts(url, &response.body).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Phase 5: Context-specific testing based on detected framework
        if app_characteristics.is_spa {
            let (vulns, tests) = self
                .test_spa_specific_clobbering(url, &response.body, &app_characteristics)
                .await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;
        }

        info!(
            "[DOMClobbering] Completed {} tests, found {} vulnerabilities",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Analyze JavaScript code for clobberable global variable patterns
    async fn analyze_javascript(
        &self,
        html_body: &str,
        url: &str,
        _app_characteristics: &AppCharacteristics,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract all JavaScript code (inline and external references)
        let js_content = self.extract_javascript_content(html_body);

        // Find global variable access patterns
        let clobberable_patterns = self.find_clobberable_patterns(&js_content);
        tests_run += clobberable_patterns.len();

        // Find dangerous sink usages
        let sink_usages = self.find_dangerous_sink_usages(&js_content);
        tests_run += sink_usages.len();

        // Correlate clobberable globals with dangerous sinks
        for pattern in &clobberable_patterns {
            for sink in &sink_usages {
                if self.can_reach_sink(
                    &pattern.name,
                    &pattern.nested_property,
                    &sink.source_variable,
                ) {
                    // Found a potential exploitation path
                    let exploitation_paths = self.generate_exploitation_paths(pattern, sink);

                    for path in exploitation_paths {
                        let vuln = self.create_vulnerability(url, &path, Confidence::Medium);
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Extract JavaScript content from HTML
    fn extract_javascript_content(&self, html_body: &str) -> String {
        let mut js_content = String::new();

        // Extract inline script content
        let script_re = Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap();
        for cap in script_re.captures_iter(html_body) {
            if let Some(content) = cap.get(1) {
                js_content.push_str(content.as_str());
                js_content.push('\n');
            }
        }

        // Also check for JavaScript in event handlers
        let event_re = Regex::new(r#"(?i)on\w+\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in event_re.captures_iter(html_body) {
            if let Some(content) = cap.get(1) {
                js_content.push_str(content.as_str());
                js_content.push('\n');
            }
        }

        js_content
    }

    /// Find patterns that indicate clobberable global variables
    fn find_clobberable_patterns(&self, js_content: &str) -> Vec<ClobberableGlobal> {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        // Pattern 1: window.X access
        let window_access_re = Regex::new(r"window\.([a-zA-Z_$][a-zA-Z0-9_$]*)").unwrap();
        for cap in window_access_re.captures_iter(js_content) {
            if let Some(name_match) = cap.get(1) {
                let name = name_match.as_str().to_string();
                if !seen.contains(&name) && self.is_potentially_clobberable(&name) {
                    seen.insert(name.clone());

                    // Check for nested property access
                    let start = cap.get(0).unwrap().end();
                    let remaining = &js_content[start..];
                    let nested_property = self.extract_nested_property(remaining);

                    let snippet_start = name_match.start().saturating_sub(30);
                    let snippet_end = (name_match.end() + 50).min(js_content.len());
                    let snippet = js_content[snippet_start..snippet_end].to_string();

                    patterns.push(ClobberableGlobal {
                        name: name.clone(),
                        access_pattern: format!("window.{}", name),
                        source_snippet: snippet,
                        is_nested: nested_property.is_some(),
                        nested_property,
                    });
                }
            }
        }

        // Pattern 2: document.X access (excluding common DOM methods)
        let document_access_re = Regex::new(r"document\.([a-zA-Z_$][a-zA-Z0-9_$]*)").unwrap();
        let dom_methods: HashSet<&str> = [
            "getElementById",
            "getElementsByClassName",
            "getElementsByTagName",
            "querySelector",
            "querySelectorAll",
            "createElement",
            "createTextNode",
            "write",
            "writeln",
            "body",
            "head",
            "documentElement",
            "cookie",
            "title",
            "domain",
            "referrer",
            "URL",
            "forms",
            "images",
            "links",
            "scripts",
            "anchors",
            "embeds",
            "plugins",
            "styleSheets",
            "readyState",
            "addEventListener",
            "removeEventListener",
            "dispatchEvent",
        ]
        .iter()
        .cloned()
        .collect();

        for cap in document_access_re.captures_iter(js_content) {
            if let Some(name_match) = cap.get(1) {
                let name = name_match.as_str().to_string();
                if !dom_methods.contains(name.as_str()) && !seen.contains(&name) {
                    seen.insert(name.clone());

                    let nested_property = {
                        let start = cap.get(0).unwrap().end();
                        let remaining = &js_content[start..];
                        self.extract_nested_property(remaining)
                    };

                    let snippet_start = name_match.start().saturating_sub(30);
                    let snippet_end = (name_match.end() + 50).min(js_content.len());
                    let snippet = js_content[snippet_start..snippet_end].to_string();

                    patterns.push(ClobberableGlobal {
                        name: name.clone(),
                        access_pattern: format!("document.{}", name),
                        source_snippet: snippet,
                        is_nested: nested_property.is_some(),
                        nested_property,
                    });
                }
            }
        }

        // Pattern 3: Direct global access for known targets
        for target in COMMON_CLOBBER_TARGETS {
            let direct_access_re = Regex::new(&format!(
                r"(?<![a-zA-Z0-9_$.]){}\s*\.",
                regex::escape(target)
            ))
            .ok();

            if let Some(re) = direct_access_re {
                if re.is_match(js_content) && !seen.contains(*target) {
                    seen.insert((*target).to_string());

                    // Find the actual snippet
                    if let Some(m) = re.find(js_content) {
                        let snippet_start = m.start().saturating_sub(20);
                        let snippet_end = (m.end() + 40).min(js_content.len());
                        let snippet = js_content[snippet_start..snippet_end].to_string();

                        patterns.push(ClobberableGlobal {
                            name: (*target).to_string(),
                            access_pattern: format!("global:{}", target),
                            source_snippet: snippet,
                            is_nested: true,
                            nested_property: None, // Will be determined by context
                        });
                    }
                }
            }
        }

        // Pattern 4: typeof checks (often indicate optional global)
        let typeof_re = Regex::new(
            r#"typeof\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:===?|!==?)\s*["']undefined["']"#,
        )
        .unwrap();
        for cap in typeof_re.captures_iter(js_content) {
            if let Some(name_match) = cap.get(1) {
                let name = name_match.as_str().to_string();
                if !seen.contains(&name) && self.is_potentially_clobberable(&name) {
                    seen.insert(name.clone());

                    let snippet_start = cap.get(0).unwrap().start().saturating_sub(10);
                    let snippet_end = (cap.get(0).unwrap().end() + 30).min(js_content.len());
                    let snippet = js_content[snippet_start..snippet_end].to_string();

                    patterns.push(ClobberableGlobal {
                        name: name.clone(),
                        access_pattern: format!("typeof:{}", name),
                        source_snippet: snippet,
                        is_nested: false,
                        nested_property: None,
                    });
                }
            }
        }

        patterns
    }

    /// Check if a variable name is potentially interesting for clobbering
    fn is_potentially_clobberable(&self, name: &str) -> bool {
        // Skip common built-ins
        let builtins: HashSet<&str> = [
            "undefined",
            "null",
            "NaN",
            "Infinity",
            "Object",
            "Array",
            "String",
            "Number",
            "Boolean",
            "Function",
            "Symbol",
            "Error",
            "JSON",
            "Math",
            "Date",
            "RegExp",
            "Promise",
            "Map",
            "Set",
            "WeakMap",
            "WeakSet",
            "console",
            "setTimeout",
            "setInterval",
            "clearTimeout",
            "clearInterval",
            "fetch",
            "XMLHttpRequest",
            "WebSocket",
            "localStorage",
            "sessionStorage",
            "navigator",
            "location",
            "history",
            "screen",
            "performance",
        ]
        .iter()
        .cloned()
        .collect();

        if builtins.contains(name) {
            return false;
        }

        // Check if it's in our known targets
        if COMMON_CLOBBER_TARGETS.contains(&name) {
            return true;
        }

        // Consider variables that look like configuration
        let config_patterns = [
            "config", "setting", "option", "data", "param", "prop", "state", "env",
        ];
        let name_lower = name.to_lowercase();
        for pattern in config_patterns {
            if name_lower.contains(pattern) {
                return true;
            }
        }

        // Generic names that might be undefined and clobberable
        name.len() >= 2
            && !name.starts_with('_')
            && name
                .chars()
                .next()
                .map(|c| c.is_lowercase())
                .unwrap_or(false)
    }

    /// Extract nested property access (e.g., .url from window.config.url)
    fn extract_nested_property(&self, remaining: &str) -> Option<String> {
        let nested_re = Regex::new(r"^\.([a-zA-Z_$][a-zA-Z0-9_$]*)").unwrap();
        if let Some(cap) = nested_re.captures(remaining) {
            if let Some(prop) = cap.get(1) {
                return Some(prop.as_str().to_string());
            }
        }
        None
    }

    /// Find dangerous sink usages in JavaScript
    fn find_dangerous_sink_usages(&self, js_content: &str) -> Vec<DangerousSinkUsage> {
        let mut usages = Vec::new();

        for sink in DANGEROUS_SINKS {
            let sink_re = Regex::new(&format!(
                r"([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*{}\s*",
                regex::escape(sink)
            ))
            .ok();

            if let Some(re) = sink_re {
                for cap in re.captures_iter(js_content) {
                    let full_match = cap.get(0).map(|m| m.as_str().to_string());
                    let source_var = cap.get(1).map(|m| m.as_str().to_string());

                    let snippet_start = cap.get(0).unwrap().start().saturating_sub(20);
                    let snippet_end = (cap.get(0).unwrap().end() + 40).min(js_content.len());
                    let snippet = js_content[snippet_start..snippet_end].to_string();

                    usages.push(DangerousSinkUsage {
                        sink: sink.to_string(),
                        source_variable: source_var,
                        snippet,
                    });
                }
            }

            // Also check for direct sink usage
            if js_content.contains(sink) {
                // Find context around the sink
                for (idx, _) in js_content.match_indices(sink) {
                    let snippet_start = idx.saturating_sub(40);
                    let snippet_end = (idx + sink.len() + 40).min(js_content.len());
                    let snippet = js_content[snippet_start..snippet_end].to_string();

                    // Try to extract source variable from context
                    let source_var = self.extract_source_variable(&snippet);

                    if !usages.iter().any(|u| u.snippet == snippet) {
                        usages.push(DangerousSinkUsage {
                            sink: sink.to_string(),
                            source_variable: source_var,
                            snippet,
                        });
                    }
                }
            }
        }

        usages
    }

    /// Extract source variable from a code snippet
    fn extract_source_variable(&self, snippet: &str) -> Option<String> {
        // Pattern: xxx = yyy.zzz or xxx = yyy
        let assign_re = Regex::new(r"=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)\s*[;,\)]").ok()?;
        if let Some(cap) = assign_re.captures(snippet) {
            return cap.get(1).map(|m| m.as_str().to_string());
        }
        None
    }

    /// Check if a clobbered variable can reach a dangerous sink
    fn can_reach_sink(
        &self,
        global_name: &str,
        nested_prop: &Option<String>,
        source_var: &Option<String>,
    ) -> bool {
        if let Some(source) = source_var {
            // Direct match
            if source == global_name {
                return true;
            }

            // Match with window. prefix
            if source == &format!("window.{}", global_name) {
                return true;
            }

            // Match with nested property
            if let Some(prop) = nested_prop {
                if source == &format!("{}.{}", global_name, prop)
                    || source == &format!("window.{}.{}", global_name, prop)
                {
                    return true;
                }
            }

            // Partial match (could be data flow)
            if source.contains(global_name) {
                return true;
            }
        }

        false
    }

    /// Generate exploitation paths for a clobberable global reaching a sink
    fn generate_exploitation_paths(
        &self,
        clobberable: &ClobberableGlobal,
        sink: &DangerousSinkUsage,
    ) -> Vec<ExploitationPath> {
        let mut paths = Vec::new();

        // Determine best clobbering technique based on context
        let techniques = if clobberable.is_nested {
            vec![
                ClobberTechnique::FormInputNested,
                ClobberTechnique::AnchorToString,
            ]
        } else {
            vec![
                ClobberTechnique::IdAttribute,
                ClobberTechnique::NameAttribute,
            ]
        };

        for technique in techniques {
            let poc_html =
                self.generate_poc_html(&clobberable.name, &clobberable.nested_property, &technique);
            let impact = self.determine_impact(&sink.sink);

            paths.push(ExploitationPath {
                clobbered_global: clobberable.name.clone(),
                sink: sink.sink.clone(),
                technique,
                poc_html,
                impact,
            });
        }

        paths
    }

    /// Generate proof-of-concept HTML for DOM clobbering
    fn generate_poc_html(
        &self,
        global_name: &str,
        nested_prop: &Option<String>,
        technique: &ClobberTechnique,
    ) -> String {
        match technique {
            ClobberTechnique::IdAttribute => {
                format!(
                    r#"<img id="{}" src="javascript:alert('XSS via DOM Clobbering')">"#,
                    global_name
                )
            }
            ClobberTechnique::NameAttribute => {
                format!(
                    r#"<img name="{}" src="javascript:alert('XSS via DOM Clobbering')">"#,
                    global_name
                )
            }
            ClobberTechnique::FormInputNested => {
                if let Some(prop) = nested_prop {
                    format!(
                        r#"<form id="{}"><input name="{}" value="javascript:alert('XSS')"></form>"#,
                        global_name, prop
                    )
                } else {
                    format!(
                        r#"<form id="{}"><input name="url" value="javascript:alert('XSS')"></form>"#,
                        global_name
                    )
                }
            }
            ClobberTechnique::AnchorToString => {
                format!(
                    r#"<a id="{}" href="javascript:alert('XSS')">click</a>"#,
                    global_name
                )
            }
            ClobberTechnique::Collection => {
                format!(
                    r#"<img name="{}"><img name="{}">"#,
                    global_name, global_name
                )
            }
            ClobberTechnique::DeepNested => {
                format!(
                    r#"<form id="{}"><form id="nested"><input name="value" value="malicious"></form></form>"#,
                    global_name
                )
            }
        }
    }

    /// Determine impact based on the dangerous sink
    fn determine_impact(&self, sink: &str) -> String {
        if sink.contains("eval")
            || sink.contains("Function")
            || sink.contains("setTimeout")
            || sink.contains("setInterval")
        {
            "Critical: Direct JavaScript execution".to_string()
        } else if sink.contains("innerHTML")
            || sink.contains("outerHTML")
            || sink.contains("document.write")
        {
            "High: HTML injection leading to XSS".to_string()
        } else if sink.contains("location") || sink.contains("href") || sink.contains("src") {
            "High: URL manipulation for open redirect or script injection".to_string()
        } else if sink.contains(".html(") || sink.contains("append") || sink.contains("prepend") {
            "High: jQuery-based DOM manipulation for XSS".to_string()
        } else {
            "Medium: Potential DOM manipulation".to_string()
        }
    }

    /// Test for HTML injection points that could enable DOM clobbering
    async fn test_html_injection_for_clobbering(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test payloads designed to check for DOM clobbering injection points
        let test_payloads = vec![
            // Simple ID clobbering test
            (
                format!(
                    r#"<img id="{}config{}">"#,
                    self.test_marker, self.test_marker
                ),
                "id_clobber",
            ),
            // Name clobbering test
            (
                format!(
                    r#"<img name="{}settings{}">"#,
                    self.test_marker, self.test_marker
                ),
                "name_clobber",
            ),
            // Form nested clobbering test
            (
                format!(
                    r#"<form id="{}form{}"><input name="url">"#,
                    self.test_marker, self.test_marker
                ),
                "form_clobber",
            ),
            // Anchor toString clobbering test
            (
                format!(
                    r#"<a id="{}anchor{}" href="javascript:1">"#,
                    self.test_marker, self.test_marker
                ),
                "anchor_clobber",
            ),
        ];

        // Try each payload in URL parameter if available
        let base_url = url.trim_end_matches('/');

        for (payload, payload_type) in &test_payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&test={}", base_url, urlencoding::encode(payload))
            } else {
                format!("{}?test={}", base_url, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if our marker was reflected without encoding
                    if response.body.contains(&self.test_marker) {
                        // Check if HTML structure was preserved
                        if self.check_html_injection_success(&response.body, payload) {
                            info!("[DOMClobbering] HTML injection detected: {}", payload_type);

                            vulnerabilities.push(self.create_injection_vulnerability(
                                url,
                                payload,
                                payload_type,
                                Confidence::High,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("[DOMClobbering] Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check if HTML injection was successful
    fn check_html_injection_success(&self, body: &str, payload: &str) -> bool {
        // Check for id attribute preservation
        if payload.contains("id=\"") {
            let id_re = Regex::new(&format!(
                r#"id="[^"]*{}[^"]*""#,
                regex::escape(&self.test_marker)
            ))
            .unwrap();
            if id_re.is_match(body) {
                return true;
            }
        }

        // Check for name attribute preservation
        if payload.contains("name=\"") {
            let name_re = Regex::new(&format!(
                r#"name="[^"]*{}[^"]*""#,
                regex::escape(&self.test_marker)
            ))
            .unwrap();
            if name_re.is_match(body) {
                return true;
            }
        }

        // Check for unencoded tag presence
        let tag_re = Regex::new(&format!(
            r"<[^>]*{}[^>]*>",
            regex::escape(&self.test_marker)
        ))
        .unwrap();
        tag_re.is_match(body)
    }

    /// Analyze inline scripts for clobberable patterns
    fn analyze_inline_scripts(&self, html_body: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract inline script content
        let script_re = Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap();

        for cap in script_re.captures_iter(html_body) {
            tests_run += 1;

            if let Some(script_content) = cap.get(1) {
                let script = script_content.as_str();

                // Look for dangerous patterns
                for target in COMMON_CLOBBER_TARGETS {
                    // Check for undefined check pattern: if (window.X || ...)
                    let undefined_check = format!(r"window\.{}\s*\|\|", regex::escape(target));
                    if let Ok(re) = Regex::new(&undefined_check) {
                        if re.is_match(script) {
                            // Check if it flows to a dangerous sink
                            for sink in DANGEROUS_SINKS {
                                if script.contains(sink) {
                                    let poc_html = self.generate_poc_html(
                                        target,
                                        &None,
                                        &ClobberTechnique::IdAttribute,
                                    );

                                    vulnerabilities.push(Vulnerability {
                                        id: format!("dom_clobber_{}", Self::generate_id()),
                                        vuln_type: "DOM Clobbering".to_string(),
                                        severity: Severity::Medium,
                                        confidence: Confidence::Medium,
                                        category: "Client-Side".to_string(),
                                        url: url.to_string(),
                                        parameter: Some(format!("window.{}", target)),
                                        payload: poc_html.clone(),
                                        description: format!(
                                            "Potential DOM clobbering vulnerability detected. The code checks for \
                                            window.{} which can be overridden via HTML injection with id/name attributes. \
                                            The value flows to dangerous sink: {}",
                                            target, sink
                                        ),
                                        evidence: Some(format!(
                                            "Pattern: {}\nSink: {}\nPoC: {}",
                                            undefined_check, sink, poc_html
                                        )),
                                        cwe: "CWE-79".to_string(),
                                        cvss: 6.1,
                                        verified: false,
                                        false_positive: false,
                                        remediation: self.get_remediation(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                    });

                                    break; // Only report once per target
                                }
                            }
                        }
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Analyze external JavaScript files
    async fn analyze_external_scripts(
        &self,
        url: &str,
        html_body: &str,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract script src URLs
        let script_src_re = Regex::new(r#"<script[^>]+src\s*=\s*["']([^"']+)["']"#).unwrap();
        let base_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return (Vec::new(), 0),
        };

        let mut js_urls: Vec<String> = Vec::new();

        for cap in script_src_re.captures_iter(html_body) {
            if let Some(src) = cap.get(1) {
                let src_str = src.as_str();

                // Skip third-party scripts
                if src_str.contains("cdn")
                    || src_str.contains("googleapis")
                    || src_str.contains("cloudflare")
                    || src_str.contains("jsdelivr")
                {
                    continue;
                }

                // Resolve relative URLs
                let full_url = if src_str.starts_with("http") {
                    src_str.to_string()
                } else if src_str.starts_with("//") {
                    format!("{}:{}", base_url.scheme(), src_str)
                } else if src_str.starts_with('/') {
                    format!(
                        "{}://{}{}",
                        base_url.scheme(),
                        base_url.host_str().unwrap_or(""),
                        src_str
                    )
                } else {
                    format!("{}/{}", url.trim_end_matches('/'), src_str)
                };

                if !js_urls.contains(&full_url) {
                    js_urls.push(full_url);
                }
            }
        }

        // Analyze first 5 JavaScript files
        for js_url in js_urls.iter().take(5) {
            tests_run += 1;

            match self.http_client.get(js_url).await {
                Ok(response) => {
                    let js_content = &response.body;

                    // Find clobberable patterns in external JS
                    let patterns = self.find_clobberable_patterns(js_content);
                    let sinks = self.find_dangerous_sink_usages(js_content);

                    for pattern in &patterns {
                        for sink in &sinks {
                            if self.can_reach_sink(
                                &pattern.name,
                                &pattern.nested_property,
                                &sink.source_variable,
                            ) {
                                let paths = self.generate_exploitation_paths(pattern, sink);

                                for path in paths {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("dom_clobber_ext_{}", Self::generate_id()),
                                        vuln_type: "DOM Clobbering".to_string(),
                                        severity: Severity::Medium,
                                        confidence: Confidence::Low,
                                        category: "Client-Side".to_string(),
                                        url: url.to_string(),
                                        parameter: Some(format!("window.{}", pattern.name)),
                                        payload: path.poc_html.clone(),
                                        description: format!(
                                            "Potential DOM clobbering in external script {}. \
                                            Variable {} can be clobbered and reaches sink: {}. \
                                            Technique: {}. {}",
                                            js_url,
                                            pattern.name,
                                            sink.sink,
                                            path.technique,
                                            path.impact
                                        ),
                                        evidence: Some(format!(
                                            "Script: {}\nPattern: {}\nSink: {}\nSnippet: {}",
                                            js_url,
                                            pattern.access_pattern,
                                            sink.sink,
                                            pattern.source_snippet
                                        )),
                                        cwe: "CWE-79".to_string(),
                                        cvss: 5.4,
                                        verified: false,
                                        false_positive: false,
                                        remediation: self.get_remediation(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("[DOMClobbering] Failed to fetch JS file {}: {}", js_url, e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// SPA-specific clobbering tests
    async fn test_spa_specific_clobbering(
        &self,
        url: &str,
        html_body: &str,
        app_characteristics: &AppCharacteristics,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Determine framework-specific targets
        let framework_targets: Vec<&str> = match &app_characteristics.app_type {
            crate::detection_helpers::AppType::SinglePageApp(framework) => match framework {
                crate::detection_helpers::SpaFramework::Vue => {
                    vec!["Vue", "$options", "$data", "$props", "$refs"]
                }
                crate::detection_helpers::SpaFramework::React => {
                    vec![
                        "React",
                        "ReactDOM",
                        "__REACT_DEVTOOLS_GLOBAL_HOOK__",
                        "__NEXT_DATA__",
                    ]
                }
                crate::detection_helpers::SpaFramework::Angular => {
                    vec!["angular", "ng", "$scope", "$rootScope"]
                }
                crate::detection_helpers::SpaFramework::Next => {
                    vec!["__NEXT_DATA__", "__NEXT_P", "next"]
                }
                crate::detection_helpers::SpaFramework::Nuxt => {
                    vec!["__NUXT__", "$nuxt", "Nuxt"]
                }
                crate::detection_helpers::SpaFramework::Svelte => {
                    vec!["Svelte", "__svelte__"]
                }
                crate::detection_helpers::SpaFramework::Other => {
                    vec!["app", "App", "config", "CONFIG"]
                }
            },
            _ => vec!["app", "config"],
        };

        for target in framework_targets {
            tests_run += 1;

            // Check if target is referenced in the page
            if html_body.contains(target) {
                // Check for dangerous usage patterns
                let danger_patterns = vec![
                    format!(r"{}\.[\w]+\s*=", target),
                    format!(r"Object\.assign\([^)]*{}", target),
                    format!(r"{}.*\.innerHTML", target),
                    format!(r"{}.*\.href", target),
                ];

                for pattern in danger_patterns {
                    if let Ok(re) = Regex::new(&pattern) {
                        if re.is_match(html_body) {
                            let poc_html = format!(
                                r#"<a id="{}" href="javascript:alert('{}')">clobber</a>"#,
                                target, target
                            );

                            vulnerabilities.push(Vulnerability {
                                id: format!("dom_clobber_spa_{}", Self::generate_id()),
                                vuln_type: "DOM Clobbering (SPA)".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Low,
                                category: "Client-Side".to_string(),
                                url: url.to_string(),
                                parameter: Some(target.to_string()),
                                payload: poc_html,
                                description: format!(
                                    "Potential DOM clobbering vulnerability in SPA framework. \
                                    The global variable '{}' is used in potentially dangerous patterns. \
                                    If HTML injection is possible, this could lead to XSS.",
                                    target
                                ),
                                evidence: Some(format!(
                                    "Framework target: {}\nDangerous pattern: {}",
                                    target, pattern
                                )),
                                cwe: "CWE-79".to_string(),
                                cvss: 5.4,
                                verified: false,
                                false_positive: false,
                                remediation: self.get_remediation(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });

                            break;
                        }
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Create vulnerability for complete exploitation path
    fn create_vulnerability(
        &self,
        url: &str,
        path: &ExploitationPath,
        confidence: Confidence,
    ) -> Vulnerability {
        let severity = if path.impact.contains("Critical") {
            Severity::High
        } else if path.impact.contains("High") {
            Severity::Medium
        } else {
            Severity::Low
        };

        let cvss = match severity {
            Severity::Critical => 9.6,
            Severity::High => 8.1,
            Severity::Medium => 6.1,
            Severity::Low => 3.7,
            Severity::Info => 0.0,
        };

        Vulnerability {
            id: format!("dom_clobber_{}", Self::generate_id()),
            vuln_type: "DOM Clobbering".to_string(),
            severity,
            confidence,
            category: "Client-Side".to_string(),
            url: url.to_string(),
            parameter: Some(format!("window.{}", path.clobbered_global)),
            payload: path.poc_html.clone(),
            description: format!(
                "DOM clobbering vulnerability detected. The global variable '{}' can be \
                overridden via HTML injection using {} technique. The clobbered value \
                reaches dangerous sink '{}'. {}",
                path.clobbered_global, path.technique, path.sink, path.impact
            ),
            evidence: Some(format!(
                "Clobbered Global: window.{}\nTechnique: {}\nSink: {}\nPoC HTML: {}",
                path.clobbered_global, path.technique, path.sink, path.poc_html
            )),
            cwe: "CWE-79".to_string(),
            cvss: cvss as f32,
            verified: false,
            false_positive: false,
            remediation: self.get_remediation(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Create vulnerability for HTML injection enabling clobbering
    fn create_injection_vulnerability(
        &self,
        url: &str,
        payload: &str,
        payload_type: &str,
        confidence: Confidence,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("dom_clobber_injection_{}", Self::generate_id()),
            vuln_type: "HTML Injection (DOM Clobbering Vector)".to_string(),
            severity: Severity::Medium,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("test".to_string()),
            payload: payload.to_string(),
            description: format!(
                "HTML injection vulnerability detected that enables DOM clobbering attacks. \
                The application reflects HTML with id/name attributes without proper sanitization. \
                Payload type: {}. This can be combined with JavaScript analysis to achieve XSS \
                via DOM clobbering.",
                payload_type
            ),
            evidence: Some(format!(
                "Payload: {}\nType: {}\nMarker: {} reflected with HTML structure preserved",
                payload, payload_type, self.test_marker
            )),
            cwe: "CWE-79".to_string(),
            cvss: 6.1,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice
    fn get_remediation(&self) -> String {
        r#"IMMEDIATE ACTIONS:

1. **Prevent HTML Injection**
   - Sanitize all user input before rendering as HTML
   - Use Content Security Policy (CSP) to restrict inline scripts
   - Encode HTML entities: &, <, >, ", '

2. **Secure Global Variable Access**
   ```javascript
   // BAD: Vulnerable to clobbering
   if (window.config) {
     location.href = window.config.url;
   }

   // GOOD: Use proper initialization
   const config = window.config || {};
   if (typeof config.url === 'string' && config.url.startsWith('https://')) {
     location.href = config.url;
   }

   // BETTER: Use data attributes or JSON embedded in script
   const config = JSON.parse(document.getElementById('config-data').textContent);
   ```

3. **Namespace Your Globals**
   ```javascript
   // Use unique, hard-to-guess namespaces
   window.__MYAPP_CONFIG_a8f3b2__ = { ... };
   ```

4. **Freeze Critical Objects**
   ```javascript
   Object.freeze(window.config);
   Object.defineProperty(window, 'config', {
     writable: false,
     configurable: false
   });
   ```

5. **Use Strict Mode and Module Scope**
   - Use ES modules to avoid global scope pollution
   - Enable strict mode to catch undefined variables

6. **Validate Before Use**
   ```javascript
   function isSafeElement(obj) {
     return obj && !(obj instanceof Element) && !(obj instanceof HTMLCollection);
   }

   if (isSafeElement(window.config)) {
     // Safe to use
   }
   ```

7. **Content Security Policy**
   Add CSP headers to prevent inline script execution:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'
   ```

References:
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://html.spec.whatwg.org/multipage/window-object.html#named-access-on-the-window-object
- https://owasp.org/www-community/attacks/DOM_Clobbering"#
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> DomClobberingScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        DomClobberingScanner::new(http_client)
    }

    #[test]
    fn test_find_clobberable_patterns() {
        let scanner = create_test_scanner();

        let js_code = r#"
            if (window.config) {
                document.location = window.config.url;
            }
            var settings = window.settings || {};
            typeof myData !== 'undefined' && myData.process();
        "#;

        let patterns = scanner.find_clobberable_patterns(js_code);

        assert!(patterns.iter().any(|p| p.name == "config"));
        assert!(patterns.iter().any(|p| p.name == "settings"));
    }

    #[test]
    fn test_find_dangerous_sink_usages() {
        let scanner = create_test_scanner();

        let js_code = r#"
            element.innerHTML = userInput;
            location.href = window.config.url;
            eval(dynamicCode);
        "#;

        let sinks = scanner.find_dangerous_sink_usages(js_code);

        assert!(sinks.iter().any(|s| s.sink.contains("innerHTML")));
        assert!(sinks.iter().any(|s| s.sink.contains("location.href")));
        assert!(sinks.iter().any(|s| s.sink.contains("eval")));
    }

    #[test]
    fn test_generate_poc_html() {
        let scanner = create_test_scanner();

        let poc = scanner.generate_poc_html(
            "config",
            &Some("url".to_string()),
            &ClobberTechnique::FormInputNested,
        );
        assert!(poc.contains("<form"));
        assert!(poc.contains("id=\"config\""));
        assert!(poc.contains("name=\"url\""));

        let poc_anchor =
            scanner.generate_poc_html("config", &None, &ClobberTechnique::AnchorToString);
        assert!(poc_anchor.contains("<a"));
        assert!(poc_anchor.contains("href=\"javascript:"));
    }

    #[test]
    fn test_is_potentially_clobberable() {
        let scanner = create_test_scanner();

        // Should be clobberable
        assert!(scanner.is_potentially_clobberable("config"));
        assert!(scanner.is_potentially_clobberable("settings"));
        assert!(scanner.is_potentially_clobberable("myConfig"));
        assert!(scanner.is_potentially_clobberable("appData"));

        // Should not be clobberable (builtins)
        assert!(!scanner.is_potentially_clobberable("Object"));
        assert!(!scanner.is_potentially_clobberable("Array"));
        assert!(!scanner.is_potentially_clobberable("console"));
        assert!(!scanner.is_potentially_clobberable("undefined"));
    }

    #[test]
    fn test_clobber_technique_display() {
        assert_eq!(
            format!("{}", ClobberTechnique::IdAttribute),
            "ID Attribute Clobbering"
        );
        assert_eq!(
            format!("{}", ClobberTechnique::FormInputNested),
            "Form+Input Nested Clobbering"
        );
        assert_eq!(
            format!("{}", ClobberTechnique::AnchorToString),
            "Anchor toString Override"
        );
    }

    #[test]
    fn test_can_reach_sink() {
        let scanner = create_test_scanner();

        // Direct match
        assert!(scanner.can_reach_sink("config", &None, &Some("config".to_string())));

        // Window prefix
        assert!(scanner.can_reach_sink("config", &None, &Some("window.config".to_string())));

        // Nested property
        assert!(scanner.can_reach_sink(
            "config",
            &Some("url".to_string()),
            &Some("config.url".to_string())
        ));

        // No match
        assert!(!scanner.can_reach_sink("config", &None, &Some("settings".to_string())));
    }

    #[test]
    fn test_extract_nested_property() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_nested_property(".url"),
            Some("url".to_string())
        );
        assert_eq!(
            scanner.extract_nested_property(".href = value"),
            Some("href".to_string())
        );
        assert_eq!(scanner.extract_nested_property(" = value"), None);
    }

    #[test]
    fn test_determine_impact() {
        let scanner = create_test_scanner();

        let impact_eval = scanner.determine_impact("eval(");
        assert!(impact_eval.contains("Critical"));

        let impact_inner = scanner.determine_impact("innerHTML");
        assert!(impact_inner.contains("High"));

        let impact_location = scanner.determine_impact("location.href");
        assert!(impact_location.contains("High"));
    }
}
