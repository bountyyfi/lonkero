// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript Source Map Scanner
//!
//! Detects and analyzes exposed .js.map files which can reveal:
//! - Original source code (before minification/bundling)
//! - Internal file paths and directory structure
//! - Comments, variable names, and business logic
//! - Hardcoded secrets that were "hidden" by minification

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

pub struct SourceMapScanner {
    http_client: Arc<HttpClient>,
}

/// Information extracted from a source map
#[derive(Debug, Clone)]
pub struct SourceMapInfo {
    pub url: String,
    pub sources: Vec<String>,
    pub has_source_content: bool,
    pub webpack_detected: bool,
    pub internal_paths: Vec<String>,
    pub potential_secrets: Vec<String>,
}

impl SourceMapScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for exposed source maps
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

        info!("Scanning for JavaScript source maps");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get the main page to find JS files
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Extract JS file URLs
        let js_urls = self.extract_js_urls(&response.body, url);
        info!(
            "Found {} JavaScript files to check for source maps",
            js_urls.len()
        );

        // Limit in fast mode
        let limit = if config.scan_mode.as_str() == "fast" {
            10
        } else {
            50
        };

        for js_url in js_urls.iter().take(limit) {
            // Try common source map URL patterns
            let map_urls = self.generate_map_urls(js_url);

            for map_url in map_urls {
                tests_run += 1;

                if let Ok(map_response) = self.http_client.get(&map_url).await {
                    if map_response.status_code == 200 {
                        // Verify it's actually a source map
                        if let Some(source_map_info) =
                            self.parse_source_map(&map_response.body, &map_url)
                        {
                            let vuln = self.create_vulnerability(&source_map_info, js_url);
                            vulnerabilities.push(vuln);

                            // Check for secrets in source content
                            if source_map_info.has_source_content {
                                if let Some(secret_vulns) =
                                    self.scan_source_content(&map_response.body, &map_url)
                                {
                                    vulnerabilities.extend(secret_vulns);
                                }
                            }

                            // One source map found per JS file is enough
                            break;
                        }
                    }
                }
            }

            // Also check for sourceMappingURL comment in the JS file itself
            tests_run += 1;
            if let Ok(js_response) = self.http_client.get(js_url).await {
                if let Some(embedded_map_url) =
                    self.extract_source_mapping_url(&js_response.body, js_url)
                {
                    if !vulnerabilities.iter().any(|v| v.url == embedded_map_url) {
                        tests_run += 1;
                        if let Ok(map_response) = self.http_client.get(&embedded_map_url).await {
                            if map_response.status_code == 200 {
                                if let Some(source_map_info) =
                                    self.parse_source_map(&map_response.body, &embedded_map_url)
                                {
                                    let vuln = self.create_vulnerability(&source_map_info, js_url);
                                    vulnerabilities.push(vuln);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also check for common bundler source map paths
        let common_paths = self.get_common_source_map_paths();
        let base_url = self.get_base_url(url);

        for path in common_paths
            .iter()
            .take(if config.scan_mode.as_str() == "fast" {
                10
            } else {
                30
            })
        {
            let test_url = format!("{}{}", base_url, path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    if let Some(source_map_info) = self.parse_source_map(&response.body, &test_url)
                    {
                        let vuln = self.create_vulnerability(&source_map_info, &test_url);
                        if !vulnerabilities.iter().any(|v| v.url == test_url) {
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        info!(
            "Source map scan completed: {} tests, {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Extract JS file URLs from HTML
    fn extract_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = HashSet::new();

        // Script src pattern
        let script_re = Regex::new(r#"<script[^>]*src=["']([^"']+\.js[^"']*)["']"#).unwrap();
        for cap in script_re.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let full_url = self.resolve_url(src.as_str(), base_url);
                // Skip third-party CDNs
                if !self.is_third_party(&full_url) {
                    urls.insert(full_url);
                }
            }
        }

        urls.into_iter().collect()
    }

    /// Generate possible source map URLs for a JS file
    fn generate_map_urls(&self, js_url: &str) -> Vec<String> {
        vec![
            format!("{}.map", js_url),
            js_url.replace(".js", ".js.map"),
            js_url.replace(".min.js", ".js.map"),
            js_url.replace(".bundle.js", ".bundle.js.map"),
            format!("{}.map", js_url.replace(".min.js", ".js")),
        ]
    }

    /// Extract sourceMappingURL from JS file
    fn extract_source_mapping_url(&self, js_content: &str, base_url: &str) -> Option<String> {
        // Look for //# sourceMappingURL= or //@ sourceMappingURL=
        let re = Regex::new(r#"//[#@]\s*sourceMappingURL=([^\s\n]+)"#).unwrap();

        if let Some(cap) = re.captures(js_content) {
            if let Some(map_url) = cap.get(1) {
                let url = map_url.as_str();
                // Handle data URLs (inline source maps)
                if url.starts_with("data:") {
                    return None; // Skip inline maps for now
                }
                return Some(self.resolve_url(url, base_url));
            }
        }
        None
    }

    /// Parse and validate source map JSON
    fn parse_source_map(&self, content: &str, url: &str) -> Option<SourceMapInfo> {
        // Quick validation - source maps must be JSON with specific fields
        if !content.trim_start().starts_with('{') {
            return None;
        }

        // Check for required source map fields
        let has_version = content.contains("\"version\"");
        let has_sources = content.contains("\"sources\"");
        let has_mappings = content.contains("\"mappings\"");

        if !has_version || !has_sources {
            return None;
        }

        // Extract sources array
        let sources = self.extract_sources_array(content);

        // Check for sourcesContent (actual source code)
        let has_source_content = content.contains("\"sourcesContent\"")
            && !content.contains("\"sourcesContent\":null")
            && !content.contains("\"sourcesContent\":[]");

        // Detect webpack
        let webpack_detected =
            content.contains("webpack://") || sources.iter().any(|s| s.contains("webpack"));

        // Extract internal paths
        let internal_paths: Vec<String> = sources
            .iter()
            .filter(|s| {
                s.contains("/src/")
                    || s.contains("/app/")
                    || s.contains("/lib/")
                    || s.contains("/components/")
                    || s.contains("/utils/")
                    || s.contains("/services/")
                    || s.contains("/api/")
            })
            .cloned()
            .collect();

        // Look for potential secrets in source map
        let potential_secrets = self.find_potential_secrets(content);

        Some(SourceMapInfo {
            url: url.to_string(),
            sources,
            has_source_content,
            webpack_detected,
            internal_paths,
            potential_secrets,
        })
    }

    /// Extract sources array from source map
    fn extract_sources_array(&self, content: &str) -> Vec<String> {
        let mut sources = Vec::new();

        // Simple extraction - find "sources": [...] and parse
        let re = Regex::new(r#""sources"\s*:\s*\[([^\]]+)\]"#).unwrap();
        if let Some(cap) = re.captures(content) {
            if let Some(array_content) = cap.get(1) {
                let source_re = Regex::new(r#""([^"]+)""#).unwrap();
                for src in source_re.captures_iter(array_content.as_str()) {
                    if let Some(s) = src.get(1) {
                        sources.push(s.as_str().to_string());
                    }
                }
            }
        }

        sources
    }

    /// Find potential secrets in source map content.
    ///
    /// Patterns are intentionally narrow-prefix / high-entropy tokens so a match is
    /// almost certainly a real credential. Generic "api_key = ..." style matches are
    /// deliberately avoided because source map `sourcesContent` contains original
    /// variable names and comments that trivially trigger them.
    fn find_potential_secrets(&self, content: &str) -> Vec<String> {
        // (pattern, label, severity_tag) – severity drives the finding's impact.
        // All patterns have vendor-specific prefixes or structural anchors that
        // uniquely identify live credentials.
        const PATTERNS: &[(&str, &str, &str)] = &[
            // AWS — prefixed key IDs are issued by IAM and cannot appear accidentally.
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "Critical"),
            (r"ASIA[0-9A-Z]{16}", "AWS STS Temporary Key", "High"),
            // Google — AIza prefix is a GCP API key; ya29. is an OAuth access token.
            (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key", "High"),
            (r"ya29\.[0-9A-Za-z_\-]{20,}", "Google OAuth Access Token", "High"),
            // GCP service account JSON — the exact string is unique to GCP keys.
            (
                r#""type"\s*:\s*"service_account""#,
                "GCP Service Account JSON",
                "Critical",
            ),
            // GitHub — prefix-based tokens.
            (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT (classic)", "Critical"),
            (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "High"),
            (r"ghs_[A-Za-z0-9]{36}", "GitHub App Server Token", "High"),
            (r"ghu_[A-Za-z0-9]{36}", "GitHub App User Token", "High"),
            (
                r"github_pat_[A-Za-z0-9_]{80,}",
                "GitHub Fine-grained PAT",
                "Critical",
            ),
            // GitLab
            (r"glpat-[A-Za-z0-9_\-]{20}", "GitLab PAT", "Critical"),
            // Slack
            (
                r"xox[baprs]-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}",
                "Slack Token",
                "High",
            ),
            (
                r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
                "Slack Webhook URL",
                "Medium",
            ),
            // Stripe — live keys only.
            (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", "Critical"),
            (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key", "High"),
            // SendGrid
            (
                r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
                "SendGrid API Key",
                "High",
            ),
            // Twilio
            (r"SK[a-f0-9]{32}", "Twilio API Key SID", "High"),
            // OpenAI / Anthropic
            (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", "Critical"),
            (r"sk-ant-[A-Za-z0-9_\-]{40,}", "Anthropic API Key", "Critical"),
            // Hugging Face
            (r"hf_[A-Za-z0-9]{34}", "Hugging Face Token", "High"),
            // Package / registry publishing tokens — immediate supply-chain risk.
            (r"npm_[A-Za-z0-9]{36}", "npm Token", "Critical"),
            (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "PyPI API Token", "Critical"),
            (r"dckr_pat_[A-Za-z0-9_\-]{56}", "Docker Hub PAT", "Critical"),
            // DigitalOcean
            (r"dop_v1_[a-f0-9]{64}", "DigitalOcean Token", "Critical"),
            // Shopify
            (r"shpat_[a-fA-F0-9]{32}", "Shopify Access Token", "Critical"),
            (r"shpss_[a-fA-F0-9]{32}", "Shopify Shared Secret", "Critical"),
            (r"shpca_[a-fA-F0-9]{32}", "Shopify Custom App Token", "Critical"),
            (r"shppa_[a-fA-F0-9]{32}", "Shopify Private App Token", "Critical"),
            // Square
            (r"sq0atp-[A-Za-z0-9_\-]{22}", "Square Access Token", "Critical"),
            (r"sq0csp-[A-Za-z0-9_\-]{43}", "Square OAuth Secret", "Critical"),
            // Mailgun / Mailchimp / Postmark
            (r"key-[a-f0-9]{32}", "Mailgun API Key", "High"),
            (r"[a-f0-9]{32}-us[0-9]{1,2}", "Mailchimp API Key", "High"),
            // Discord
            (
                r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
                "Discord Webhook URL",
                "Medium",
            ),
            (
                r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}",
                "Discord Bot Token",
                "Critical",
            ),
            // Sentry DSN — often public, but useful recon and pollution vector.
            (
                r"https://[a-fA-F0-9]+@[A-Za-z0-9]+\.ingest\.sentry\.io/[0-9]+",
                "Sentry DSN",
                "Low",
            ),
            // Azure — storage + SAS
            (
                r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}",
                "Azure Storage Account Key",
                "Critical",
            ),
            (
                r"sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&s[ir]=[A-Za-z0-9%]+&sig=[A-Za-z0-9%+/=]{20,}",
                "Azure Storage SAS Token",
                "High",
            ),
            // DB connection strings with embedded credentials (user:pass@host)
            (
                r#"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|mariadb|mssql|jdbc:[a-z]+)://[A-Za-z0-9._~%+-]+:[^@\s"'`<>]+@[A-Za-z0-9.\-]+"#,
                "Database Connection String with Credentials",
                "Critical",
            ),
            // PEM-armored private keys — can never be a false positive inside a source map.
            (
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
                "PEM Private Key Block",
                "Critical",
            ),
            // Framework master secrets — full session/cookie/crypto compromise.
            (r"base64:[A-Za-z0-9+/]{43}=", "Laravel APP_KEY", "Critical"),
            // JWT (three base64url segments with the standard {"alg header)
            (
                r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-+/=]{10,}",
                "JWT Token",
                "High",
            ),
            // Telegram bot token (context-filtered below)
            (r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", "Telegram Bot Token", "High"),
        ];

        let mut secrets = Vec::new();
        let mut seen = HashSet::new();
        let bytes = content.as_bytes();

        for (pattern, name, severity) in PATTERNS {
            let re = match Regex::new(pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for m in re.find_iter(content) {
                let matched = m.as_str();
                // Oversized matches are almost always runaway backtracks over
                // minified bundles — skip rather than truncate into nonsense.
                if matched.len() > 512 {
                    continue;
                }

                // Telegram token: in minified JS an object key like `{1234567890:abc…}`
                // perfectly matches the format but is not a real token. Require the
                // match to sit inside a string literal.
                if *name == "Telegram Bot Token" {
                    let start = m.start();
                    let end = m.end();
                    let prev_quote = start > 0
                        && matches!(bytes[start - 1], b'"' | b'\'' | b'`');
                    let next_quote = end < bytes.len()
                        && matches!(bytes[end], b'"' | b'\'' | b'`');
                    if !prev_quote && !next_quote {
                        continue;
                    }
                }

                let key = format!("{}|{}", name, matched);
                if !seen.insert(key) {
                    continue;
                }
                secrets.push(format!(
                    "[{}] {}: {}",
                    severity,
                    name,
                    Self::truncate(matched, 80)
                ));
                if secrets.len() >= 25 {
                    return secrets;
                }
            }
        }

        secrets
    }

    /// Scan source content for additional secrets
    fn scan_source_content(&self, content: &str, url: &str) -> Option<Vec<Vulnerability>> {
        let secrets = self.find_potential_secrets(content);

        if secrets.is_empty() {
            return None;
        }

        let vuln = Vulnerability {
            id: format!("srcmap_secrets_{}", Self::generate_id()),
            vuln_type: "Secrets in Source Map".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            category: "Information Disclosure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Found {} potential secrets/credentials in source map content. \
                Source maps can expose original source code including hardcoded secrets.",
                secrets.len()
            ),
            evidence: Some(secrets.join("\n")),
            cwe: "CWE-540".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "1. Remove source maps from production servers\n\
                2. If source maps are needed for error tracking, restrict access\n\
                3. Never include secrets in source code\n\
                4. Use environment variables for sensitive configuration"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        };

        Some(vec![vuln])
    }

    /// Get common source map paths to probe.
    ///
    /// Only static, deterministic paths are listed; hashed chunk filenames
    /// (`main.abc123.js.map`) are discovered dynamically via `sourceMappingURL`
    /// and HTML `<script>` extraction.
    fn get_common_source_map_paths(&self) -> Vec<&'static str> {
        vec![
            // Create React App / webpack default
            "/static/js/main.js.map",
            "/static/js/bundle.js.map",
            "/static/js/app.js.map",
            "/static/js/vendor.js.map",
            "/static/js/runtime.js.map",
            "/static/js/runtime-main.js.map",
            "/static/js/2.js.map",
            "/static/js/main.chunk.js.map",
            "/static/js/vendors.chunk.js.map",
            "/static/js/vendors~main.chunk.js.map",
            "/static/css/main.css.map",
            // Next.js (pages + app router)
            "/_next/static/chunks/main.js.map",
            "/_next/static/chunks/webpack.js.map",
            "/_next/static/chunks/polyfills.js.map",
            "/_next/static/chunks/framework.js.map",
            "/_next/static/chunks/pages/_app.js.map",
            "/_next/static/chunks/pages/index.js.map",
            "/_next/static/chunks/pages/_error.js.map",
            "/_next/static/chunks/app/layout.js.map",
            "/_next/static/chunks/app/page.js.map",
            "/_next/static/runtime/main.js.map",
            "/_next/static/runtime/webpack.js.map",
            "/_next/server/pages/index.js.map",
            "/_next/server/app/page.js.map",
            // Nuxt 3
            "/_nuxt/entry.js.map",
            "/_nuxt/index.js.map",
            "/_nuxt/runtime.js.map",
            "/_nuxt/app.js.map",
            "/_nuxt/error-component.js.map",
            // Vite
            "/assets/index.js.map",
            "/assets/main.js.map",
            "/assets/vendor.js.map",
            "/assets/index.css.map",
            // SvelteKit
            "/_app/immutable/start.js.map",
            "/_app/immutable/entry/app.js.map",
            "/_app/immutable/entry/start.js.map",
            // Remix
            "/build/index.js.map",
            "/build/entry.client.js.map",
            "/public/build/entry.client.js.map",
            "/public/build/root.js.map",
            // Gatsby
            "/commons.js.map",
            "/app.js.map",
            "/component---src-pages-index-js.map",
            "/webpack-runtime.js.map",
            // Angular CLI
            "/main.js.map",
            "/polyfills.js.map",
            "/runtime.js.map",
            "/vendor.js.map",
            "/scripts.js.map",
            "/styles.css.map",
            // Vue CLI
            "/js/app.js.map",
            "/js/chunk-vendors.js.map",
            "/js/chunk-common.js.map",
            "/css/app.css.map",
            // Ember
            "/assets/vendor.js.map",
            "/assets/ember-app.js.map",
            // NestJS / generic Node dist
            "/dist/main.js.map",
            "/dist/index.js.map",
            "/dist/server.js.map",
            "/dist/bundle.js.map",
            "/dist/app.js.map",
            // Parcel / Rollup / esbuild defaults
            "/dist/index.mjs.map",
            "/dist/bundle.mjs.map",
            // Generic fallbacks
            "/bundle.js.map",
            "/app.js.map",
            "/main.js.map",
            "/index.js.map",
            "/server.js.map",
            "/build/bundle.js.map",
            "/build/static/js/main.js.map",
            "/build/static/css/main.css.map",
            "/public/js/app.js.map",
            "/public/js/bundle.js.map",
            "/js/bundle.js.map",
            "/js/main.js.map",
            "/javascripts/application.js.map",
        ]
    }

    /// Create vulnerability for exposed source map
    fn create_vulnerability(&self, info: &SourceMapInfo, js_url: &str) -> Vulnerability {
        let severity = if info.has_source_content {
            Severity::High
        } else if !info.internal_paths.is_empty() {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut evidence_parts = vec![
            format!("Source map URL: {}", info.url),
            format!("Original JS: {}", js_url),
            format!("Contains source content: {}", info.has_source_content),
            format!("Webpack build: {}", info.webpack_detected),
            format!("Number of source files: {}", info.sources.len()),
        ];

        if !info.internal_paths.is_empty() {
            evidence_parts.push(format!(
                "\nInternal paths exposed:\n- {}",
                info.internal_paths
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n- ")
            ));
        }

        if !info.potential_secrets.is_empty() {
            evidence_parts.push(format!(
                "\nPotential secrets found:\n- {}",
                info.potential_secrets.join("\n- ")
            ));
        }

        Vulnerability {
            id: format!("srcmap_{}", Self::generate_id()),
            vuln_type: "JavaScript Source Map Exposed".to_string(),
            severity,
            confidence: Confidence::High,
            category: "Information Disclosure".to_string(),
            url: info.url.clone(),
            parameter: None,
            payload: String::new(),
            description: format!(
                "JavaScript source map file is publicly accessible. {} \
                This exposes the original, unminified source code which may reveal \
                business logic, internal APIs, comments, and potentially secrets.",
                if info.has_source_content {
                    "The source map contains full source code content."
                } else {
                    "The source map contains file references but no source content."
                }
            ),
            evidence: Some(evidence_parts.join("\n")),
            cwe: "CWE-540".to_string(),
            cvss: if info.has_source_content { 6.5 } else { 4.3 },
            verified: true,
            false_positive: false,
            remediation: "1. Remove .map files from production deployments\n\
                2. Configure web server to deny access to .map files\n\
                3. Use devtool: 'hidden-source-map' in webpack for private maps\n\
                4. If maps are needed, restrict access via authentication\n\
                5. Never include sensitive data in source code"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Check if URL is third-party
    fn is_third_party(&self, url: &str) -> bool {
        let third_party = [
            "cdn",
            "googleapis.com",
            "gstatic.com",
            "cloudflare",
            "jsdelivr",
            "unpkg.com",
            "jquery.com",
            "bootstrapcdn",
        ];
        let url_lower = url.to_lowercase();
        third_party.iter().any(|tp| url_lower.contains(tp))
    }

    /// Resolve relative URL
    fn resolve_url(&self, src: &str, base_url: &str) -> String {
        if src.starts_with("http://") || src.starts_with("https://") {
            return src.to_string();
        }

        if let Ok(base) = url::Url::parse(base_url) {
            if src.starts_with("//") {
                return format!("{}:{}", base.scheme(), src);
            }
            if let Ok(resolved) = base.join(src) {
                return resolved.to_string();
            }
        }

        src.to_string()
    }

    /// Get base URL
    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.to_string()
        }
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.len() > max {
            format!("{}...", &s[..max])
        } else {
            s.to_string()
        }
    }

    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:x}", nanos % 0xFFFFFFFF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_map_detection() {
        let source_map = r#"{
            "version": 3,
            "sources": ["webpack://app/src/index.js", "webpack://app/src/utils/api.js"],
            "sourcesContent": ["const api_key = 'sk_live_test123';"],
            "mappings": "AAAA"
        }"#;

        let scanner = SourceMapScanner::new(Arc::new(
            crate::http_client::HttpClient::new(5000, 3).unwrap(),
        ));

        let info = scanner.parse_source_map(source_map, "https://example.com/main.js.map");
        assert!(info.is_some());

        let info = info.unwrap();
        assert!(info.has_source_content);
        assert!(info.webpack_detected);
        assert_eq!(info.sources.len(), 2);
    }

    #[test]
    fn test_source_mapping_url_extraction() {
        let js_content = r#"
            !function(e){console.log(e)}();
            //# sourceMappingURL=app.js.map
        "#;

        let scanner = SourceMapScanner::new(Arc::new(
            crate::http_client::HttpClient::new(5000, 3).unwrap(),
        ));

        let url = scanner.extract_source_mapping_url(js_content, "https://example.com/js/app.js");
        assert!(url.is_some());
        assert!(url.unwrap().contains("app.js.map"));
    }
}
