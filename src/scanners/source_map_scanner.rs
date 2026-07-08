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
        let mut candidates = vec![
            format!("{}.map", js_url),
            js_url.replace(".js", ".js.map"),
            js_url.replace(".min.js", ".js.map"),
            js_url.replace(".min.js", ".min.js.map"),
            js_url.replace(".bundle.js", ".bundle.js.map"),
            format!("{}.map", js_url.replace(".min.js", ".js")),
            // esbuild / SWC / Turbopack sometimes place maps in a sibling directory
            js_url.replace("/js/", "/js.map/"),
            js_url.replace("/dist/", "/dist/maps/") + ".map",
        ];
        // Deduplicate to avoid double-fetching
        candidates.sort();
        candidates.dedup();
        candidates
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
    ///
    /// Only high-signal patterns are included - each pattern is either a provider-specific
    /// fingerprint (AKIA/sk_live_/ghp_/...) or a keyword+value pair with tight length
    /// constraints. Generic matches are filtered against a placeholder list to avoid
    /// reporting `password="your_password_here"` or `token="xxx"` samples.
    fn find_potential_secrets(&self, content: &str) -> Vec<String> {
        let mut secrets = Vec::new();

        // Provider-specific signatures - almost zero false-positive rate
        let provider_patterns: &[(&str, &str)] = &[
            // AWS
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"ASIA[0-9A-Z]{16}", "AWS STS Session Token"),
            // Google / GCP
            (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
            (r"ya29\.[0-9A-Za-z_-]{20,}", "Google OAuth Access Token"),
            // Stripe
            (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
            (r"rk_live_[0-9a-zA-Z]{24,}", "Stripe Live Restricted Key"),
            (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key"),
            // GitHub
            (r"ghp_[0-9A-Za-z]{36}", "GitHub Personal Access Token"),
            (r"gho_[0-9A-Za-z]{36}", "GitHub OAuth Token"),
            (r"ghu_[0-9A-Za-z]{36}", "GitHub User-to-Server Token"),
            (r"ghs_[0-9A-Za-z]{36}", "GitHub Server-to-Server Token"),
            (r"ghr_[0-9A-Za-z]{36}", "GitHub Refresh Token"),
            (r"github_pat_[0-9A-Za-z_]{80,}", "GitHub Fine-Grained PAT"),
            // GitLab
            (r"glpat-[0-9A-Za-z_-]{20}", "GitLab Personal Access Token"),
            // Slack
            (r"xox[abpsr]-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]{32,}", "Slack Bot/User Token"),
            (r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{24,}", "Slack Webhook URL"),
            // Twilio
            (r"AC[a-f0-9]{32}", "Twilio Account SID"),
            (r"SK[a-f0-9]{32}", "Twilio API Key"),
            // SendGrid / Mailgun / Mailchimp
            (r"SG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}", "SendGrid API Key"),
            (r"key-[0-9a-f]{32}", "Mailgun API Key"),
            (r"[0-9a-f]{32}-us[0-9]{1,2}", "Mailchimp API Key"),
            // OpenAI / Anthropic
            (r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", "OpenAI API Key"),
            (r"sk-proj-[a-zA-Z0-9_-]{40,}", "OpenAI Project Key"),
            (r"sk-ant-api03-[a-zA-Z0-9_-]{80,}", "Anthropic API Key"),
            // Square
            (r"sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}", "Square OAuth Token"),
            // DigitalOcean
            (r"dop_v1_[0-9a-f]{64}", "DigitalOcean Personal Token"),
            (r"doo_v1_[0-9a-f]{64}", "DigitalOcean OAuth Token"),
            // Cloudflare
            (r"v1\.0-[0-9a-f]{40}-[0-9a-f]{80,}", "Cloudflare API Token"),
            // Firebase / Google refresh token
            (r"1//0[a-zA-Z0-9_-]{50,}", "Google OAuth Refresh Token"),
            // JWT (three base64url segments) - only report when it looks real
            (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
            // Private key blocks
            (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----", "Private Key Block"),
            // Database connection strings with embedded credentials
            (r#"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'"]+:[^@\s'"]{4,}@[^\s'"/]+"#, "DB Connection String with Credentials"),
        ];

        for (pattern, name) in provider_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    if matched.len() < 400 && !Self::is_placeholder_value(matched) {
                        secrets.push(format!("{}: {}", name, Self::truncate(matched, 60)));
                    }
                }
            }
        }

        // Keyword=value patterns with placeholder filtering
        let keyword_patterns: &[(&str, &str)] = &[
            (r#"["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,120})["\']"#, "API Key"),
            (r#"["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,120})["\']"#, "Secret Key"),
            (r#"["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,200})["\']"#, "Access Token"),
            (r#"["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,200})["\']"#, "Auth Token"),
            (r#"["\']?client[_-]?secret["\']?\s*[:=]\s*["\']([^"\']{16,200})["\']"#, "Client Secret"),
            (r#"["\']?private[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']"#, "Private Key Field"),
            (r#"["\']?bearer["\']?\s*[:=]\s*["\']([^"\']{20,200})["\']"#, "Bearer Token"),
            (r#"["\']?password["\']?\s*[:=]\s*["\']([^"\']{6,120})["\']"#, "Password"),
        ];

        for (pattern, name) in keyword_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let value = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    if value.is_empty() || Self::is_placeholder_value(value) {
                        continue;
                    }
                    // Reject values that look like template/env-var references
                    if value.starts_with("${") || value.starts_with("{{")
                        || value.starts_with("<%") || value.starts_with("process.env.")
                        || value.starts_with("import.meta.env.")
                    {
                        continue;
                    }
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    secrets.push(format!("{}: {}", name, Self::truncate(matched, 80)));
                }
            }
        }

        // Deduplicate while preserving order, limit to first 15
        let mut seen = HashSet::new();
        secrets.retain(|s| seen.insert(s.clone()));
        secrets.truncate(15);
        secrets
    }

    /// Check if a captured value is a placeholder / obvious sample rather than a real secret.
    /// Keeping this list tight is what makes the source map secret finder low-false-positive.
    fn is_placeholder_value(value: &str) -> bool {
        let v = value.to_lowercase();
        // Common example / placeholder / redacted markers
        let markers = [
            "your_", "your-", "yourapi", "yoursecret", "example", "changeme",
            "change-me", "change_me", "placeholder", "todo", "fixme", "insert-",
            "xxxxxxxx", "aaaaaaaa", "0000000000", "1234567890",
            "redacted", "hidden", "secret_here", "api_key_here", "token_here",
            "password_here", "abcdef123", "test-token", "test_token", "test-key",
            "test_key", "dummy", "sample", "fake-", "fake_", "sk_test_", "pk_test_",
            "not-a-real", "not_a_real", "notarealkey", "somekey", "sometoken",
            "your-key", "your_key", "your-token", "your_token",
        ];
        for m in markers {
            if v.contains(m) {
                return true;
            }
        }
        // Reject values that are only a single repeated character (e.g., "aaaaaaaaaaaaaaaa")
        if value.len() >= 8 {
            let first = value.chars().next().unwrap_or(' ');
            if value.chars().all(|c| c == first) {
                return true;
            }
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
            // Next.js (Pages Router + App Router)
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
            "/_next/static/chunks/app-pages-internals.js.map",
            "/_next/static/chunks/pages/_document.js.map",
            "/_next/static/development/_ssgManifest.js.map",
            "/_next/static/development/_buildManifest.js.map",
            // Vite
            "/assets/index.js.map",
            "/assets/main.js.map",
            "/assets/app.js.map",
            "/assets/vendor.js.map",
            "/assets/client.js.map",
            "/assets/entry-client.js.map",
            "/assets/entry-server.js.map",
            "/assets/index.css.map",
            // Angular (older + modern esbuild builder)
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
            "/chunk-common.js.map",
            "/chunk-vendors.js.map",
            // Vue / Nuxt (v2 + v3)
            "/js/app.js.map",
            "/js/chunk-vendors.js.map",
            "/js/chunk-common.js.map",
            "/_nuxt/app.js.map",
            "/_nuxt/vendor.js.map",
            "/_nuxt/entry.js.map",
            "/_nuxt/commons/app.js.map",
            "/_nuxt/client-manifest.js.map",
            "/_nuxt/server-manifest.js.map",
            // SvelteKit
            "/_app/immutable/entry/start.js.map",
            "/_app/immutable/entry/app.js.map",
            "/_app/immutable/chunks/index.js.map",
            "/_app/immutable/chunks/vendor.js.map",
            "/_app/immutable/nodes/0.js.map",
            "/_app/immutable/nodes/1.js.map",
            // Remix
            "/build/entry.client.js.map",
            "/build/root.js.map",
            "/build/_assets/entry.client.js.map",
            "/build/manifest.js.map",
            // Astro
            "/_astro/hoisted.js.map",
            "/_astro/client.js.map",
            "/_astro/entry.js.map",
            // Qwik / QwikCity
            "/build/q-manifest.json.map",
            "/build/q-bundle.js.map",
            // Solid Start
            "/_build/entry-client.js.map",
            "/_build/entry-server.js.map",
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
            // Docusaurus / Storybook (often shipped to marketing sites)
            "/build/main.js.map",
            "/storybook-static/main.js.map",
            "/storybook-static/runtime~main.js.map",
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
            "/hot-update.js.map",
            // React Native web / Expo
            "/static/js.map",
            "/AppEntry.js.map",
            "/index.bundle.map",
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
    /// Filtering these out avoids reporting exposed source maps for CDN-hosted vendor
    /// libraries that the target does not own (and cannot fix).
    fn is_third_party(&self, url: &str) -> bool {
        let third_party = [
            "cdn",
            "googleapis.com",
            "gstatic.com",
            "google-analytics.com",
            "googletagmanager.com",
            "cloudflare",
            "jsdelivr",
            "unpkg.com",
            "jquery.com",
            "bootstrapcdn",
            "cdnjs",
            "fontawesome.com",
            "typekit.net",
            "hotjar.com",
            "hs-scripts.com",
            "hs-analytics.net",
            "hsforms.net",
            "intercomcdn.com",
            "intercom.io",
            "segment.com",
            "segment.io",
            "amplitude.com",
            "sentry.io",
            "sentry-cdn.com",
            "datadoghq-browser-agent",
            "browser-intake",
            "fullstory.com",
            "logrocket.io",
            "mixpanel.com",
            "recaptcha.net",
            "clarity.ms",
            "onetrust.com",
            "cookielaw.org",
            "adobedtm.com",
            "demdex.net",
            "tealium.com",
            "stripe.com",
            "checkout.com",
            "paypalobjects.com",
            "braintreegateway.com",
            "auth0.com",
            "okta.com",
            "cognito-idp.",
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
