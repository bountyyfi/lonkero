// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! JavaScript Source Map Scanner
//!
//! Detects and analyzes exposed .js.map files which can reveal:
//! - Original source code (before minification/bundling)
//! - Internal file paths and directory structure
//! - Comments, variable names, and business logic
//! - Hardcoded secrets that were "hidden" by minification

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

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
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
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
        info!("Found {} JavaScript files to check for source maps", js_urls.len());

        // Limit in fast mode
        let limit = if config.scan_mode.as_str() == "fast" { 10 } else { 50 };

        for js_url in js_urls.iter().take(limit) {
            // Try common source map URL patterns
            let map_urls = self.generate_map_urls(js_url);

            for map_url in map_urls {
                tests_run += 1;

                if let Ok(map_response) = self.http_client.get(&map_url).await {
                    if map_response.status_code == 200 {
                        // Verify it's actually a source map
                        if let Some(source_map_info) = self.parse_source_map(&map_response.body, &map_url) {
                            let vuln = self.create_vulnerability(&source_map_info, js_url);
                            vulnerabilities.push(vuln);

                            // Check for secrets in source content
                            if source_map_info.has_source_content {
                                if let Some(secret_vulns) = self.scan_source_content(&map_response.body, &map_url) {
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
                if let Some(embedded_map_url) = self.extract_source_mapping_url(&js_response.body, js_url) {
                    if !vulnerabilities.iter().any(|v| v.url == embedded_map_url) {
                        tests_run += 1;
                        if let Ok(map_response) = self.http_client.get(&embedded_map_url).await {
                            if map_response.status_code == 200 {
                                if let Some(source_map_info) = self.parse_source_map(&map_response.body, &embedded_map_url) {
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

        for path in common_paths.iter().take(if config.scan_mode.as_str() == "fast" { 10 } else { 30 }) {
            let test_url = format!("{}{}", base_url, path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    if let Some(source_map_info) = self.parse_source_map(&response.body, &test_url) {
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
        let webpack_detected = content.contains("webpack://")
            || sources.iter().any(|s| s.contains("webpack"));

        // Extract internal paths
        let internal_paths: Vec<String> = sources
            .iter()
            .filter(|s| {
                s.contains("/src/") || s.contains("/app/") || s.contains("/lib/")
                    || s.contains("/components/") || s.contains("/utils/")
                    || s.contains("/services/") || s.contains("/api/")
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

        // API key patterns
        let patterns = [
            (r#"["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']"#, "API Key"),
            (r#"["\']?secret["\']?\s*[:=]\s*["\']([^"\']{16,})["\']"#, "Secret"),
            (r#"["\']?password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']"#, "Password"),
            (r#"["\']?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']"#, "Token"),
            (r#"AKIA[0-9A-Z]{16}"#, "AWS Key"),
            (r#"sk_live_[a-zA-Z0-9]{24,}"#, "Stripe Key"),
        ];

        for (pattern, name) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                    if matched.len() < 200 { // Avoid huge matches
                        secrets.push(format!("{}: {}", name, Self::truncate(matched, 50)));
                    }
                }
            }
        }

        // Limit to first 10
        secrets.truncate(10);
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
                4. Use environment variables for sensitive configuration".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        };

        Some(vec![vuln])
    }

    /// Get common source map paths to probe
    fn get_common_source_map_paths(&self) -> Vec<&'static str> {
        vec![
            // Webpack
            "/static/js/main.js.map",
            "/static/js/bundle.js.map",
            "/static/js/app.js.map",
            "/static/js/vendor.js.map",
            "/static/js/runtime.js.map",
            "/static/js/2.js.map",
            "/static/js/main.chunk.js.map",
            "/static/js/vendors.chunk.js.map",
            // Next.js
            "/_next/static/chunks/main.js.map",
            "/_next/static/chunks/webpack.js.map",
            "/_next/static/chunks/pages/_app.js.map",
            "/_next/static/chunks/framework.js.map",
            // Vite
            "/assets/index.js.map",
            "/assets/vendor.js.map",
            // Angular
            "/main.js.map",
            "/polyfills.js.map",
            "/runtime.js.map",
            "/vendor.js.map",
            // Vue
            "/js/app.js.map",
            "/js/chunk-vendors.js.map",
            // Generic
            "/bundle.js.map",
            "/app.js.map",
            "/main.js.map",
            "/dist/bundle.js.map",
            "/dist/app.js.map",
            "/build/bundle.js.map",
            "/build/static/js/main.js.map",
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
                info.internal_paths.iter().take(10).cloned().collect::<Vec<_>>().join("\n- ")
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
                5. Never include sensitive data in source code".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Check if URL is third-party
    fn is_third_party(&self, url: &str) -> bool {
        let third_party = [
            "cdn", "googleapis.com", "gstatic.com", "cloudflare",
            "jsdelivr", "unpkg.com", "jquery.com", "bootstrapcdn",
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
            crate::http_client::HttpClient::new(5000, 3).unwrap()
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
            crate::http_client::HttpClient::new(5000, 3).unwrap()
        ));

        let url = scanner.extract_source_mapping_url(js_content, "https://example.com/js/app.js");
        assert!(url.is_some());
        assert!(url.unwrap().contains("app.js.map"));
    }
}
