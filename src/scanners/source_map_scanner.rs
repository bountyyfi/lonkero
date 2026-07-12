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

    /// Find potential secrets in source map content
    fn find_potential_secrets(&self, content: &str) -> Vec<String> {
        let mut secrets = Vec::new();

        // Prefixed / vendor-anchored patterns first (very low false-positive rate:
        // each requires a vendor-specific prefix + exact length + alphabet, so any
        // hit is almost certainly a real live key rather than a placeholder).
        let patterns = [
            // ---- Prefixed vendor tokens (near-zero FP) ----
            // GitHub personal, OAuth, user, refresh, server-to-server, saved tokens.
            (r#"gh[pousr]_[A-Za-z0-9]{36,255}"#, "GitHub Token"),
            // GitLab personal access tokens (glpat- prefix, 20-char b64url).
            (r#"glpat-[A-Za-z0-9_\-]{20,40}"#, "GitLab PAT"),
            // Slack bot / user / app tokens - the numeric-segment structure eliminates FPs.
            (
                r#"xox[abpors]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,40}"#,
                "Slack Token",
            ),
            // Slack webhook URLs (deliverable target).
            (
                r#"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24,40}"#,
                "Slack Webhook",
            ),
            // Discord webhook URLs (deliverable target).
            (
                r#"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80}"#,
                "Discord Webhook",
            ),
            // Google API keys (AIza + 35 chars, well-known).
            (r#"AIza[0-9A-Za-z_\-]{35}"#, "Google API Key"),
            // Google OAuth client tokens.
            (r#"ya29\.[0-9A-Za-z_\-]{68,}"#, "Google OAuth Token"),
            // Firebase database URL - direct pivot to often-open DBs.
            (
                r#"https://[a-z0-9\-]{3,63}\.firebaseio\.com"#,
                "Firebase DB URL",
            ),
            // AWS access keys - AKIA (long-lived), ASIA (session), ABIA/ACCA variants.
            (r#"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"#, "AWS Access Key"),
            // AWS secret access key: base64-ish 40-char string next to an AWS-y key.
            // The context word requirement + length keeps FP low.
            (
                r#"(?i)aws(?:.{0,20})?(?:secret|access)?[_\-]?key[^\n"']{0,10}["'][A-Za-z0-9/+=]{40}["']"#,
                "AWS Secret Key",
            ),
            // Stripe live/test/restricted keys.
            (r#"sk_live_[0-9a-zA-Z]{24,99}"#, "Stripe Secret Key"),
            (
                r#"rk_live_[0-9a-zA-Z]{24,99}"#,
                "Stripe Restricted Key",
            ),
            (r#"pk_live_[0-9a-zA-Z]{24,99}"#, "Stripe Publishable Key"),
            // Twilio account SID / auth token pairs.
            (r#"AC[a-f0-9]{32}"#, "Twilio Account SID"),
            (r#"SK[a-f0-9]{32}"#, "Twilio API Key SID"),
            // SendGrid API key (SG. + two b64url chunks separated by `.`).
            (
                r#"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"#,
                "SendGrid API Key",
            ),
            // Mailgun API keys.
            (r#"key-[0-9a-zA-Z]{32}"#, "Mailgun API Key"),
            // Mailchimp keys embed the datacenter suffix.
            (r#"[0-9a-f]{32}-us[0-9]{1,2}"#, "Mailchimp API Key"),
            // Square access tokens.
            (r#"sq0(?:atp|csp)-[0-9A-Za-z_\-]{22,43}"#, "Square Token"),
            // Shopify shared secrets and access tokens.
            (r#"shpss_[a-fA-F0-9]{32}"#, "Shopify Shared Secret"),
            (r#"shpat_[a-fA-F0-9]{32}"#, "Shopify Access Token"),
            (r#"shpca_[a-fA-F0-9]{32}"#, "Shopify Custom Access Token"),
            (r#"shppa_[a-fA-F0-9]{32}"#, "Shopify Private App Token"),
            // Heroku API keys are UUIDs anchored on a "heroku" context word.
            (
                r#"(?i)heroku[^\n]{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
                "Heroku API Key",
            ),
            // Digital Ocean personal access tokens.
            (r#"dop_v1_[a-f0-9]{64}"#, "DigitalOcean Token"),
            // npm publish tokens.
            (r#"npm_[A-Za-z0-9]{36}"#, "npm Access Token"),
            // JetBrains hub perm tokens.
            (
                r#"perm-[A-Za-z0-9]{8}\.[A-Za-z0-9]{5,}\.[A-Za-z0-9]{40,}"#,
                "JetBrains Token",
            ),
            // Datadog / New Relic / PagerDuty style keys are context-anchored.
            (
                r#"(?i)datadog[_\-]?(?:api|app)[_\-]?key["'\s:=]{1,10}["']?([a-f0-9]{32,40})["']?"#,
                "Datadog Key",
            ),
            (
                r#"NRAK-[A-Z0-9]{27}"#,
                "New Relic Personal API Key",
            ),
            // OpenAI and Anthropic API keys - dev-tool secrets that increasingly ship in bundles.
            (r#"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"#, "OpenAI API Key"),
            (
                r#"sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,}"#,
                "Anthropic API Key",
            ),
            // HuggingFace user access tokens.
            (r#"hf_[A-Za-z0-9]{34,40}"#, "HuggingFace Token"),
            // Cloudflare API tokens (40 char base62 with `-`/`_`).
            (
                r#"(?i)cf[_\-]?(?:api[_\-]?)?token["'\s:=]{1,10}["']([A-Za-z0-9_\-]{40})["']"#,
                "Cloudflare Token",
            ),
            // Cloudflare Global API keys are 37 hex chars beside a context word.
            (
                r#"(?i)cloudflare[^\n]{0,30}["']([a-f0-9]{37})["']"#,
                "Cloudflare Global Key",
            ),

            // ---- Private keys and JWTs (structural, high-signal) ----
            // PEM-encoded private key headers - unambiguous.
            (
                r#"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"#,
                "Private Key",
            ),
            // PuTTY private key format.
            (r#"PuTTY-User-Key-File-[23]"#, "PuTTY Private Key"),
            // JWT bearer tokens (three b64url segments) - kept a bit strict to avoid FP.
            (
                r#"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"#,
                "JWT",
            ),

            // ---- Connection strings & credentials embedded in URLs ----
            // MongoDB Atlas / SRV connection strings with inline creds.
            (
                r#"mongodb(?:\+srv)?://[^\s"'<>]{3,64}:[^\s"'<>@]{3,128}@[A-Za-z0-9.\-]{3,}"#,
                "MongoDB Connection String",
            ),
            // PostgreSQL connection with credentials.
            (
                r#"postgres(?:ql)?://[^\s"'<>]{1,64}:[^\s"'<>@]{1,128}@[A-Za-z0-9.\-]{3,}[:/][^\s"'<>]{1,64}"#,
                "PostgreSQL Connection String",
            ),
            // MySQL / MariaDB.
            (
                r#"mysql://[^\s"'<>]{1,64}:[^\s"'<>@]{1,128}@[A-Za-z0-9.\-]{3,}[:/][^\s"'<>]{1,64}"#,
                "MySQL Connection String",
            ),
            // Redis with password / rediss for TLS.
            (
                r#"redis[s]?://[^\s"'<>@:]{0,64}:[^\s"'<>@]{4,128}@[A-Za-z0-9.\-]{3,}"#,
                "Redis Connection String",
            ),
            // Generic HTTP(S) URL with inline basic-auth credentials.
            (
                r#"https?://[A-Za-z0-9._%+\-]{1,64}:[^\s"'<>@/?#]{4,128}@[A-Za-z0-9.\-]{3,64}"#,
                "URL with Credentials",
            ),

            // ---- Generic context-anchored secrets (kept last, tighter than before) ----
            // Require quote-delimited value, minimum entropy length, and reject
            // obvious placeholders elsewhere in post-processing.
            (
                r#"(?i)["']?api[_\-]?key["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{24,})["']"#,
                "API Key",
            ),
            (
                r#"(?i)["']?(?:client|consumer)[_\-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{24,})["']"#,
                "Client Secret",
            ),
            (
                r#"(?i)["']?(?:auth|access|bearer)[_\-]?token["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{24,})["']"#,
                "Auth Token",
            ),
            (
                r#"(?i)["']?refresh[_\-]?token["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{24,})["']"#,
                "Refresh Token",
            ),
            (
                r#"(?i)["']?private[_\-]?key["']?\s*[:=]\s*["']([A-Za-z0-9/+=_\-]{40,})["']"#,
                "Private Key Value",
            ),
        ];

        let mut seen: HashSet<String> = HashSet::new();
        for (pattern, name) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    if matched.is_empty() || matched.len() >= 200 {
                        continue;
                    }
                    // The extracted value (capture group 1) if present, else full match.
                    let value = cap
                        .get(1)
                        .map(|m| m.as_str())
                        .unwrap_or(matched);
                    if Self::looks_like_placeholder(value) {
                        continue;
                    }
                    // Dedupe on the (kind, first 32 chars of value) so identical
                    // bundle-repeated secrets don't fill the evidence list.
                    let key = format!(
                        "{}:{}",
                        name,
                        &value[..value.len().min(32)]
                    );
                    if !seen.insert(key) {
                        continue;
                    }
                    secrets.push(format!("{}: {}", name, Self::truncate(matched, 60)));
                }
            }
        }

        // Cap to keep evidence output readable.
        secrets.truncate(20);
        secrets
    }

    /// Reject values that are obviously placeholders / examples / hashes-of-nothing.
    /// Keeps false positive rate near zero for the generic context-anchored patterns.
    fn looks_like_placeholder(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        // Common placeholder tokens developers leave in code and templates.
        const NEEDLES: &[&str] = &[
            "your_", "your-", "yourapi", "yourkey", "yoursecret", "yourtoken",
            "example", "sample", "changeme", "dummy", "placeholder",
            "xxxx", "aaaa", "0000", "1234", "test_", "testkey", "testtoken",
            "insert_", "replace_", "todo", "fixme", "n/a", "none",
            "unknown", "null", "undefined", "process.env", "import.meta",
            "{{", "}}", "${", "%s", "<%=",
        ];
        if NEEDLES.iter().any(|n| lower.contains(n)) {
            return true;
        }
        // Single-character-repeated values (like "aaaaaaaaaaaaaaaa") - no entropy.
        if !lower.is_empty() && lower.chars().all(|c| c == lower.chars().next().unwrap()) {
            return true;
        }
        // Purely hex zeros / low-entropy.
        if lower.chars().all(|c| c == '0' || c == 'x') {
            return true;
        }
        false
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

    /// Get common source map paths to probe
    fn get_common_source_map_paths(&self) -> Vec<&'static str> {
        vec![
            // Webpack / Create React App
            "/static/js/main.js.map",
            "/static/js/bundle.js.map",
            "/static/js/app.js.map",
            "/static/js/vendor.js.map",
            "/static/js/vendors.js.map",
            "/static/js/runtime.js.map",
            "/static/js/2.js.map",
            "/static/js/3.js.map",
            "/static/js/main.chunk.js.map",
            "/static/js/vendors.chunk.js.map",
            "/static/js/runtime-main.js.map",
            "/static/js/runtime~main.js.map",
            "/static/css/main.css.map",
            // Next.js
            "/_next/static/chunks/main.js.map",
            "/_next/static/chunks/main-app.js.map",
            "/_next/static/chunks/webpack.js.map",
            "/_next/static/chunks/polyfills.js.map",
            "/_next/static/chunks/pages/_app.js.map",
            "/_next/static/chunks/pages/_error.js.map",
            "/_next/static/chunks/pages/index.js.map",
            "/_next/static/chunks/framework.js.map",
            "/_next/static/chunks/react-refresh.js.map",
            "/_next/static/chunks/app/layout.js.map",
            "/_next/static/chunks/app/page.js.map",
            // Vite
            "/assets/index.js.map",
            "/assets/main.js.map",
            "/assets/app.js.map",
            "/assets/vendor.js.map",
            "/assets/client.js.map",
            "/assets/entry-client.js.map",
            "/assets/entry-server.js.map",
            // Angular
            "/main.js.map",
            "/main-es2015.js.map",
            "/main-es5.js.map",
            "/polyfills.js.map",
            "/polyfills-es2015.js.map",
            "/polyfills-es5.js.map",
            "/runtime.js.map",
            "/runtime-es2015.js.map",
            "/runtime-es5.js.map",
            "/vendor.js.map",
            "/vendor-es2015.js.map",
            "/scripts.js.map",
            "/styles.css.map",
            // Vue / Nuxt
            "/js/app.js.map",
            "/js/chunk-vendors.js.map",
            "/js/chunk-common.js.map",
            "/_nuxt/app.js.map",
            "/_nuxt/vendor.js.map",
            "/_nuxt/entry.js.map",
            "/_nuxt/commons/app.js.map",
            // SvelteKit
            "/_app/immutable/entry/start.js.map",
            "/_app/immutable/entry/app.js.map",
            "/_app/immutable/chunks/index.js.map",
            "/_app/immutable/chunks/vendor.js.map",
            // Remix
            "/build/entry.client.js.map",
            "/build/root.js.map",
            "/build/_assets/entry.client.js.map",
            // Parcel
            "/parcel.js.map",
            "/index.js.map",
            "/dist/index.js.map",
            "/dist/main.js.map",
            // Rollup
            "/dist/bundle.esm.js.map",
            "/dist/bundle.cjs.js.map",
            "/dist/bundle.umd.js.map",
            "/dist/index.esm.js.map",
            // Ember
            "/assets/ember-app.js.map",
            "/assets/vendor.js.map",
            "/assets/dummy.js.map",
            // Gatsby
            "/commons.js.map",
            "/app-*.js.map",
            "/page-data.js.map",
            // Generic / old build output
            "/bundle.js.map",
            "/app.js.map",
            "/main.js.map",
            "/dist/bundle.js.map",
            "/dist/app.js.map",
            "/build/bundle.js.map",
            "/build/static/js/main.js.map",
            "/build/static/js/bundle.js.map",
            "/public/bundle.js.map",
            "/public/app.js.map",
            "/out/app.js.map",
            // Common CSS maps (often ship secret theme data / class names)
            "/css/app.css.map",
            "/css/main.css.map",
            "/styles/main.css.map",
            // Dev-server maps occasionally shipped to prod
            "/webpack-dev-server.js.map",
            "/static/js/devServer.js.map",
            // Astro
            "/_astro/client.js.map",
            "/_astro/hoisted.js.map",
            "/_astro/entry.js.map",
            "/_astro/index.js.map",
            // Qwik
            "/build/q-runtime.js.map",
            "/build/q-manifest.json.map",
            "/build/q-core.js.map",
            // SolidJS / Solid Start
            "/_build/assets/index.js.map",
            "/_build/assets/entry-client.js.map",
            "/_solid/index.js.map",
            // Fresh (Deno)
            "/_frsh/js/main.js.map",
            "/_fresh/js/main.js.map",
            // Bun bundler
            "/bun-app.js.map",
            "/out.js.map",
            "/build.js.map",
            // Rspack / Turbopack
            "/_rspack/main.js.map",
            "/_rspack/runtime.js.map",
            "/_turbo/main.js.map",
            "/_turbo/pack/chunks/main.js.map",
            // Blitz.js
            "/.blitz/main.js.map",
            "/.blitz/client.js.map",
            // RedwoodJS
            "/build/App.js.map",
            "/web/dist/App.js.map",
            "/web/dist/index.js.map",
            // Docusaurus
            "/assets/js/main.js.map",
            "/assets/js/runtime~main.js.map",
            // Storybook (often deployed with the app for QA)
            "/storybook-static/main.iframe.bundle.js.map",
            "/storybook-static/runtime~main.iframe.bundle.js.map",
            "/storybook/main.iframe.bundle.js.map",
            // Meteor
            "/packages/meteor.js.map",
            "/programs/web.browser/main.js.map",
            // Elm
            "/elm.js.map",
            // Aurelia
            "/dist/entry-bundle.js.map",
            // Backbone / older jQuery-era leftovers
            "/js/main.min.js.map",
            "/js/app.min.js.map",
            "/scripts/main.js.map",
            "/scripts/app.js.map",
            // Common developer-uploaded backups
            "/backup/main.js.map",
            "/old/main.js.map",
            "/src/index.js.map",
            "/src/main.js.map",
            "/js/main.js.map.bak",
            // Service worker source maps (SW code often ships auth/OTA logic)
            "/sw.js.map",
            "/service-worker.js.map",
            "/serviceWorker.js.map",
            "/firebase-messaging-sw.js.map",
            "/OneSignalSDKWorker.js.map",
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
