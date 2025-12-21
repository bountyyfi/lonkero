// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced SvelteKit Security Scanner
 * Comprehensive Svelte/SvelteKit vulnerability detection
 *
 * REQUIRES: Personal license or higher
 *
 * Detects:
 * - Server load function data exposure
 * - Form actions CSRF issues
 * - Hooks bypass vulnerabilities
 * - +server.js endpoint misconfigurations
 * - Environment variable exposure
 * - Server-only module leakage
 * - Source map and config exposure
 * - Prerender data leakage
 * - Known SvelteKit CVEs
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Personal Edition and above
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct SvelteKitSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: Vec<SvelteKitCVE>,
}

#[derive(Clone)]
struct SvelteKitCVE {
    cve_id: String,
    affected_versions: String,
    severity: Severity,
    description: String,
    check_type: CVECheckType,
}

#[derive(Clone, Debug)]
enum CVECheckType {
    CSRF,
    PathTraversal,
    OpenRedirect,
    DataExposure,
    XSS,
    DoS,
}

impl SvelteKitSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known SvelteKit CVEs
    fn build_cve_database() -> Vec<SvelteKitCVE> {
        vec![
            SvelteKitCVE {
                cve_id: "CVE-2024-23641".to_string(),
                affected_versions: "<2.4.1".to_string(),
                severity: Severity::High,
                description: "Cross-site Request Forgery (CSRF) in SvelteKit form actions due to improper origin validation".to_string(),
                check_type: CVECheckType::CSRF,
            },
            SvelteKitCVE {
                cve_id: "CVE-2024-24563".to_string(),
                affected_versions: "<2.4.3".to_string(),
                severity: Severity::High,
                description: "Path traversal vulnerability in SvelteKit static file serving allowing access to files outside webroot".to_string(),
                check_type: CVECheckType::PathTraversal,
            },
            SvelteKitCVE {
                cve_id: "CVE-2024-29893".to_string(),
                affected_versions: "<2.5.4".to_string(),
                severity: Severity::Medium,
                description: "Open redirect vulnerability in SvelteKit redirect handling".to_string(),
                check_type: CVECheckType::OpenRedirect,
            },
            SvelteKitCVE {
                cve_id: "CVE-2023-29008".to_string(),
                affected_versions: "<1.15.1".to_string(),
                severity: Severity::High,
                description: "CSRF bypass in SvelteKit form actions via Content-Type manipulation".to_string(),
                check_type: CVECheckType::CSRF,
            },
            SvelteKitCVE {
                cve_id: "CVE-2023-29007".to_string(),
                affected_versions: "<1.15.1".to_string(),
                severity: Severity::Medium,
                description: "Open redirect vulnerability in SvelteKit's goto() function".to_string(),
                check_type: CVECheckType::OpenRedirect,
            },
            SvelteKitCVE {
                cve_id: "CVE-2022-25869".to_string(),
                affected_versions: "svelte <3.49.0".to_string(),
                severity: Severity::Medium,
                description: "Cross-site scripting (XSS) in Svelte via a@href attribute".to_string(),
                check_type: CVECheckType::XSS,
            },
        ]
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Check license
        if !crate::license::has_feature("cms_security") {
            debug!("[SvelteKit] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Detect if target is running SvelteKit
        tests_run += 1;
        let (is_sveltekit, version) = self.detect_sveltekit(url).await;

        if !is_sveltekit {
            debug!("[SvelteKit] Target does not appear to be running SvelteKit");
            return Ok((vec![], tests_run));
        }

        info!("[SvelteKit] Detected SvelteKit application{}",
            version.as_ref().map(|v| format!(" (version: {})", v)).unwrap_or_default());

        // Test server load data exposure
        let (load_vulns, load_tests) = self.check_load_data_exposure(url, config).await?;
        vulnerabilities.extend(load_vulns);
        tests_run += load_tests;

        // Test form actions CSRF
        let (csrf_vulns, csrf_tests) = self.check_form_actions_csrf(url, config).await?;
        vulnerabilities.extend(csrf_vulns);
        tests_run += csrf_tests;

        // Test hooks bypass
        let (hooks_vulns, hooks_tests) = self.check_hooks_bypass(url, config).await?;
        vulnerabilities.extend(hooks_vulns);
        tests_run += hooks_tests;

        // Test +server.js endpoints
        let (server_vulns, server_tests) = self.check_server_endpoints(url, config).await?;
        vulnerabilities.extend(server_vulns);
        tests_run += server_tests;

        // Test environment variable exposure
        let (env_vulns, env_tests) = self.check_env_exposure(url, config).await?;
        vulnerabilities.extend(env_vulns);
        tests_run += env_tests;

        // Test source map exposure
        let (sourcemap_vulns, sourcemap_tests) = self.check_source_maps(url, config).await?;
        vulnerabilities.extend(sourcemap_vulns);
        tests_run += sourcemap_tests;

        // Test config file exposure
        let (config_vulns, config_tests) = self.check_config_exposure(url, config).await?;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        // Test prerender data leakage
        let (prerender_vulns, prerender_tests) = self.check_prerender_exposure(url, config).await?;
        vulnerabilities.extend(prerender_vulns);
        tests_run += prerender_tests;

        // Test path traversal (CVE-2024-24563)
        let (path_vulns, path_tests) = self.check_path_traversal(url, config).await?;
        vulnerabilities.extend(path_vulns);
        tests_run += path_tests;

        // Test open redirect vulnerabilities
        let (redirect_vulns, redirect_tests) = self.check_open_redirect(url, config).await?;
        vulnerabilities.extend(redirect_vulns);
        tests_run += redirect_tests;

        // Check known CVEs based on detected version
        if let Some(ref ver) = version {
            let (cve_vulns, cve_tests) = self.check_version_cves(url, ver, config).await?;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!("[SvelteKit] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running SvelteKit
    async fn detect_sveltekit(&self, url: &str) -> (bool, Option<String>) {
        let mut is_sveltekit = false;
        let mut version = None;

        // Check for SvelteKit indicators
        if let Ok(resp) = self.http_client.get(url).await {
            // Check for Svelte hydration markers
            if resp.body.contains("__sveltekit") ||
               resp.body.contains("data-sveltekit") ||
               resp.body.contains("__svelte") ||
               resp.body.contains("svelte-") ||
               resp.body.contains("/_app/") {
                is_sveltekit = true;
            }

            // Check for SvelteKit-specific paths
            if resp.body.contains("/_app/immutable/") ||
               resp.body.contains("/_app/version.json") {
                is_sveltekit = true;
            }

            // Extract version from HTML comments or JS
            let version_re = Regex::new(r#"(?i)svelte(?:kit)?[/\s:]*v?(\d+\.\d+(?:\.\d+)?)"#).ok();
            if let Some(re) = version_re {
                if let Some(caps) = re.captures(&resp.body) {
                    version = caps.get(1).map(|m| m.as_str().to_string());
                }
            }
        }

        // Check /_app/version.json
        let version_url = format!("{}/_app/version.json", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&version_url).await {
            if resp.status_code == 200 && resp.body.contains("version") {
                is_sveltekit = true;
                // Try to extract version
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp.body) {
                    if let Some(ver) = json.get("version").and_then(|v| v.as_str()) {
                        version = Some(ver.to_string());
                    }
                }
            }
        }

        // Check for SvelteKit-specific headers
        let test_url = format!("{}/api/health", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&test_url).await {
            // Check for SvelteKit error format
            if resp.body.contains("\"message\"") && resp.body.contains("404") {
                // SvelteKit has specific JSON error format
                is_sveltekit = true;
            }
        }

        (is_sveltekit, version)
    }

    /// Check for server load function data exposure
    async fn check_load_data_exposure(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // SvelteKit exposes page data via __data.json endpoints
        let pages_to_test = [
            "/",
            "/admin",
            "/dashboard",
            "/user",
            "/profile",
            "/settings",
            "/account",
            "/internal",
            "/api",
        ];

        for page in &pages_to_test {
            tests_run += 1;
            // SvelteKit uses __data.json for data fetching
            let data_url = format!("{}{}/__data.json", base, page.trim_end_matches('/'));

            if let Ok(resp) = self.http_client.get(&data_url).await {
                if resp.status_code == 200 && (resp.body.starts_with("{") || resp.body.starts_with("[")) {
                    // Check for sensitive data patterns
                    let sensitive_patterns = [
                        ("email", r#"(?i)["']email["']\s*:\s*["'][^"']+@[^"']+"#),
                        ("password", r#"(?i)["']password["']\s*:"#),
                        ("token", r#"(?i)["'](?:auth|access|api)?[_-]?token["']\s*:"#),
                        ("secret", r#"(?i)["'](?:secret|private)[_-]?(?:key)?["']\s*:"#),
                        ("user_id", r#"(?i)["']user[_-]?id["']\s*:"#),
                        ("session", r#"(?i)["']session["']\s*:"#),
                        ("api_key", r#"(?i)["']api[_-]?key["']\s*:"#),
                        ("database", r#"(?i)["'](?:db|database)[_-]?(?:url|connection)["']\s*:"#),
                    ];

                    let mut found_sensitive = Vec::new();
                    for (name, pattern) in &sensitive_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&resp.body) {
                                found_sensitive.push(*name);
                            }
                        }
                    }

                    if !found_sensitive.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_data_exposure_{}", Self::generate_id()),
                            vuln_type: "SvelteKit Load Data Exposure - Sensitive Information Leak".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: data_url.clone(),
                            parameter: Some(format!("{}/__data.json", page)),
                            payload: format!("GET {}/__data.json", page),
                            description: format!(
                                "SvelteKit's __data.json endpoint for '{}' exposes sensitive information. \
                                Server load functions return data that is serialized and accessible directly. \
                                Potentially leaked: {}",
                                page, found_sensitive.join(", ")
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Status: 200 OK\n\
                                Sensitive fields: {}\n\
                                Response preview: {}...",
                                data_url,
                                found_sensitive.join(", "),
                                &resp.body[..resp.body.len().min(300)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Review +page.server.js load functions for sensitive data\n\
                                          2. Filter sensitive fields before returning from load()\n\
                                          3. Use server-only modules for sensitive operations\n\
                                          4. Implement proper authorization in load functions\n\
                                          5. Use +server.js for sensitive API endpoints".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }

            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for CSRF vulnerabilities in form actions
    async fn check_form_actions_csrf(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common form action endpoints
        let action_endpoints = [
            "/?/login",
            "/?/register",
            "/?/submit",
            "/?/update",
            "/?/delete",
            "/?/create",
            "/login?/default",
            "/settings?/update",
            "/account?/delete",
        ];

        for endpoint in &action_endpoints {
            tests_run += 1;
            let action_url = format!("{}{}", base, endpoint);

            // Test CSRF by sending request without proper origin
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
            headers.insert("Origin".to_string(), "https://evil.com".to_string());

            let headers_vec: Vec<(String, String)> = headers.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if let Ok(resp) = self.http_client.post_with_headers(&action_url, "test=value", headers_vec).await {
                // CVE-2024-23641: Check if action accepts cross-origin requests
                if resp.status_code == 200 || resp.status_code == 303 {
                    // Check if it's not a proper rejection
                    if !resp.body.contains("CSRF") && !resp.body.contains("forbidden") && !resp.body.contains("403") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_csrf_{}", Self::generate_id()),
                            vuln_type: "SvelteKit Form Action CSRF Vulnerability".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "CSRF".to_string(),
                            url: action_url.clone(),
                            parameter: Some("form action".to_string()),
                            payload: "Origin: https://evil.com".to_string(),
                            description: format!(
                                "Form action endpoint '{}' may be vulnerable to CSRF attacks. \
                                The endpoint accepted a request from a different origin without proper validation. \
                                This may allow attackers to perform actions on behalf of authenticated users.",
                                endpoint
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Cross-origin request: Origin: https://evil.com\n\
                                Response status: {}\n\
                                No CSRF protection detected",
                                action_url, resp.status_code
                            )),
                            cwe: "CWE-352".to_string(),
                            cvss: 8.0,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Upgrade SvelteKit to version 2.4.1 or later\n\
                                          2. Implement CSRF tokens in forms\n\
                                          3. Validate Origin header in hooks\n\
                                          4. Use SameSite=Strict for session cookies\n\
                                          5. Consider implementing double-submit cookie pattern".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }

            // Test Content-Type bypass (CVE-2023-29008)
            tests_run += 1;
            let mut bypass_headers = HashMap::new();
            bypass_headers.insert("Content-Type".to_string(), "text/plain".to_string());

            let bypass_headers_vec: Vec<(String, String)> = bypass_headers.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            if let Ok(resp) = self.http_client.post_with_headers(&action_url, "test=value", bypass_headers_vec).await {
                if resp.status_code == 200 || resp.status_code == 303 {
                    vulnerabilities.push(Vulnerability {
                        id: format!("sveltekit_csrf_bypass_{}", Self::generate_id()),
                        vuln_type: "SvelteKit CSRF Protection Bypass via Content-Type".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "CSRF".to_string(),
                        url: action_url.clone(),
                        parameter: Some("Content-Type".to_string()),
                        payload: "Content-Type: text/plain".to_string(),
                        description: format!(
                            "Form action at '{}' accepts non-standard Content-Type headers, \
                            potentially bypassing CSRF protections (CVE-2023-29008).",
                            endpoint
                        ),
                        evidence: Some(format!(
                            "Request with Content-Type: text/plain accepted\nStatus: {}",
                            resp.status_code
                        )),
                        cwe: "CWE-352".to_string(),
                        cvss: 7.5,
                        verified: false,
                        false_positive: false,
                        remediation: "Upgrade SvelteKit to 1.15.1 or later and validate Content-Type strictly.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }

            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for hooks bypass vulnerabilities
    async fn check_hooks_bypass(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Protected paths that might have hooks-based auth
        let protected_paths = [
            "/admin",
            "/dashboard",
            "/api/admin",
            "/api/internal",
            "/protected",
            "/settings",
        ];

        for path in &protected_paths {
            tests_run += 1;
            let test_url = format!("{}{}", base, path);

            // First check normal access
            let normal_resp = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if normal_resp.status_code != 401 && normal_resp.status_code != 403 {
                continue; // Not protected
            }

            // Try to bypass with various techniques
            let bypass_attempts = [
                // Path manipulation
                (format!("{}/.", path), "Path with trailing dot"),
                (format!("{}//", path), "Double slash"),
                (format!("{}%00", path), "Null byte"),
                (format!("{}/..{}", path, path), "Path traversal"),
                // Case manipulation
                (path.to_uppercase(), "Uppercase path"),
                // URL encoding
                (path.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>(), "URL encoded"),
            ];

            for (bypass_path, technique) in &bypass_attempts {
                tests_run += 1;
                let bypass_url = format!("{}{}", base, bypass_path);

                if let Ok(bypass_resp) = self.http_client.get(&bypass_url).await {
                    if bypass_resp.status_code == 200 && normal_resp.status_code != 200 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_hooks_bypass_{}", Self::generate_id()),
                            vuln_type: "SvelteKit Hooks Bypass - Authentication Bypass".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: bypass_url.clone(),
                            parameter: Some("path".to_string()),
                            payload: format!("{}: {}", technique, bypass_path),
                            description: format!(
                                "Authentication hooks for '{}' can be bypassed using {}. \
                                Protected path returns {} normally but {} with bypass.",
                                path, technique, normal_resp.status_code, bypass_resp.status_code
                            ),
                            evidence: Some(format!(
                                "Normal: {} -> {}\n\
                                Bypass ({}): {} -> {}",
                                path, normal_resp.status_code,
                                technique, bypass_path, bypass_resp.status_code
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Normalize paths in hooks before authorization check\n\
                                          2. Use strict path matching\n\
                                          3. Implement authorization at both hooks and load function level\n\
                                          4. Validate paths against whitelist".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }

            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check +server.js endpoint security
    async fn check_server_endpoints(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common API endpoints in SvelteKit
        let api_endpoints = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/internal",
            "/api/debug",
            "/api/auth",
            "/api/session",
            "/api/graphql",
            "/api/health",
            "/api/status",
        ];

        for endpoint in &api_endpoints {
            tests_run += 1;
            let api_url = format!("{}{}", base, endpoint);

            if let Ok(resp) = self.http_client.get(&api_url).await {
                // Check for exposed internal APIs
                if resp.status_code == 200 {
                    let body_lower = resp.body.to_lowercase();

                    let is_sensitive = body_lower.contains("internal") ||
                        body_lower.contains("debug") ||
                        body_lower.contains("config") ||
                        body_lower.contains("database") ||
                        body_lower.contains("secret") ||
                        body_lower.contains("api_key");

                    if is_sensitive && (endpoint.contains("internal") || endpoint.contains("debug") || endpoint.contains("config")) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_api_exposure_{}", Self::generate_id()),
                            vuln_type: "SvelteKit +server.js Endpoint Exposed".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Information Disclosure".to_string(),
                            url: api_url.clone(),
                            parameter: Some(endpoint.to_string()),
                            payload: format!("GET {}", endpoint),
                            description: format!(
                                "Internal API endpoint '{}' is publicly accessible and may expose sensitive data.",
                                endpoint
                            ),
                            evidence: Some(format!(
                                "Status: 200 OK\n\
                                Contains sensitive keywords\n\
                                Preview: {}...",
                                &resp.body[..resp.body.len().min(300)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 6.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Add authentication checks in +server.js\n\
                                          2. Use hooks for API route protection\n\
                                          3. Remove debug/internal endpoints in production\n\
                                          4. Implement proper authorization".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }

                // Check CORS configuration
                tests_run += 1;
                let mut cors_headers = HashMap::new();
                cors_headers.insert("Origin".to_string(), "https://evil.com".to_string());

                let headers_vec: Vec<(String, String)> = cors_headers.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Ok(cors_resp) = self.http_client.get_with_headers(&api_url, headers_vec).await {
                    if let Some(acao) = cors_resp.headers.get("access-control-allow-origin") {
                        if acao == "https://evil.com" || acao == "*" {
                            let has_credentials = cors_resp.headers.get("access-control-allow-credentials")
                                .map(|v| v == "true")
                                .unwrap_or(false);

                            if has_credentials || acao == "https://evil.com" {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("sveltekit_cors_{}", Self::generate_id()),
                                    vuln_type: "SvelteKit API CORS Misconfiguration".to_string(),
                                    severity: if has_credentials { Severity::High } else { Severity::Medium },
                                    confidence: Confidence::High,
                                    category: "Misconfiguration".to_string(),
                                    url: api_url.clone(),
                                    parameter: Some("CORS".to_string()),
                                    payload: "Origin: https://evil.com".to_string(),
                                    description: format!(
                                        "API endpoint '{}' reflects arbitrary origins in CORS headers{}.",
                                        endpoint,
                                        if has_credentials { " WITH credentials" } else { "" }
                                    ),
                                    evidence: Some(format!(
                                        "Access-Control-Allow-Origin: {}\n\
                                        Allow-Credentials: {}",
                                        acao, has_credentials
                                    )),
                                    cwe: "CWE-942".to_string(),
                                    cvss: if has_credentials { 8.1 } else { 5.3 },
                                    verified: true,
                                    false_positive: false,
                                    remediation: "Configure CORS properly in hooks.server.js or +server.js:\n\
                                                  - Use specific allowed origins\n\
                                                  - Don't use wildcard with credentials\n\
                                                  - Validate Origin header".to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                                });
                            }
                        }
                    }
                }
            }

            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for environment variable exposure
    async fn check_env_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            // Look for server-side env variables in client JS
            // SvelteKit uses $env/static/private and $env/dynamic/private for server-only
            // $env/static/public and $env/dynamic/public should be safe
            let server_env_patterns = [
                (r#"(?i)DATABASE_URL\s*[=:]\s*["'][^"']+["']"#, "DATABASE_URL"),
                (r#"(?i)SECRET_KEY\s*[=:]\s*["'][^"']+["']"#, "SECRET_KEY"),
                (r#"(?i)JWT_SECRET\s*[=:]\s*["'][^"']+["']"#, "JWT_SECRET"),
                (r#"(?i)API_SECRET\s*[=:]\s*["'][^"']+["']"#, "API_SECRET"),
                (r#"(?i)PRIVATE_KEY\s*[=:]\s*["'][^"']+["']"#, "PRIVATE_KEY"),
                (r#"(?i)AWS_SECRET\s*[=:]\s*["'][^"']+["']"#, "AWS_SECRET"),
                (r#"(?i)STRIPE_SECRET\s*[=:]\s*["'][^"']+["']"#, "STRIPE_SECRET"),
                (r#"\$env/static/private"#, "$env/static/private import"),
                (r#"\$env/dynamic/private"#, "$env/dynamic/private import"),
            ];

            let mut exposed_vars = Vec::new();
            for (pattern, name) in &server_env_patterns {
                tests_run += 1;
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&resp.body) {
                        exposed_vars.push(*name);
                    }
                }
            }

            if !exposed_vars.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: format!("sveltekit_env_exposure_{}", Self::generate_id()),
                    vuln_type: "SvelteKit Server Environment Variables Exposed".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("Environment Variables".to_string()),
                    payload: "Client-side JavaScript".to_string(),
                    description: format!(
                        "Server-side environment variables or imports are exposed in client-side JavaScript. \
                        Found: {}. Only $env/static/public and $env/dynamic/public should be used in client code.",
                        exposed_vars.join(", ")
                    ),
                    evidence: Some(format!(
                        "Exposed: {}\n\
                        Impact: Attackers can extract credentials from client JS",
                        exposed_vars.join(", ")
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Use $env/static/public for public env vars only\n\
                                  2. Use $env/static/private in +page.server.js only\n\
                                  3. Never import private env in +page.svelte\n\
                                  4. Audit all env imports in the codebase\n\
                                  5. Rotate any exposed credentials".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for source map exposure
    async fn check_source_maps(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get main page to find JS files
        let resp = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vec![], tests_run)),
        };

        // Extract SvelteKit JS files
        let js_pattern = Regex::new(r#"/_app/[^"']+\.js"#)?;
        let js_files: Vec<String> = js_pattern.find_iter(&resp.body)
            .map(|m| format!("{}{}.map", url.trim_end_matches('/'), m.as_str()))
            .collect();

        for js_map in js_files.iter().take(5) {
            tests_run += 1;
            if let Ok(map_resp) = self.http_client.get(js_map).await {
                if map_resp.status_code == 200 && map_resp.body.contains("mappings") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("sveltekit_sourcemap_{}", Self::generate_id()),
                        vuln_type: "SvelteKit Source Map Exposure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: js_map.clone(),
                        parameter: Some("source map".to_string()),
                        payload: "GET *.js.map".to_string(),
                        description: "JavaScript source maps are publicly accessible, exposing Svelte component source code.".to_string(),
                        evidence: Some(format!(
                            "Source map: {}\n\
                            Status: 200 OK",
                            js_map
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Set kit.vite.build.sourcemap to false in svelte.config.js for production.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for config file exposure
    async fn check_config_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        let sensitive_files = [
            ("svelte.config.js", "SvelteKit configuration"),
            ("vite.config.js", "Vite configuration"),
            ("vite.config.ts", "Vite configuration"),
            (".env", "Environment variables"),
            (".env.local", "Local environment"),
            (".env.production", "Production environment"),
            ("package.json", "Package configuration"),
            ("tsconfig.json", "TypeScript configuration"),
            (".svelte-kit/output/server/manifest.json", "Server manifest"),
            ("_app/version.json", "Version info"),
        ];

        for (file, desc) in &sensitive_files {
            tests_run += 1;
            let file_url = format!("{}/{}", base, file);

            if let Ok(resp) = self.http_client.get(&file_url).await {
                if resp.status_code == 200 {
                    let is_config = resp.body.contains("export") ||
                        resp.body.contains("module") ||
                        resp.body.starts_with("{") ||
                        resp.body.contains("DATABASE") ||
                        resp.body.contains("SECRET");

                    if is_config {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_config_exposure_{}", Self::generate_id()),
                            vuln_type: format!("SvelteKit {} Exposed", desc),
                            severity: if file.contains(".env") { Severity::Critical } else { Severity::Medium },
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: file_url.clone(),
                            parameter: Some(file.to_string()),
                            payload: format!("GET /{}", file),
                            description: format!("The {} file is publicly accessible.", desc),
                            evidence: Some(format!(
                                "File: {}\n\
                                Status: 200\n\
                                Preview: {}...",
                                file, &resp.body[..resp.body.len().min(200)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: if file.contains(".env") { 9.1 } else { 5.3 },
                            verified: true,
                            false_positive: false,
                            remediation: "Configure server/adapter to block access to config files.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for prerender data leakage
    async fn check_prerender_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Check for prerendered __data.json files that might contain stale/sensitive data
        let prerender_paths = [
            "/__data.json",
            "/about/__data.json",
            "/blog/__data.json",
            "/products/__data.json",
        ];

        for path in &prerender_paths {
            tests_run += 1;
            let data_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&data_url).await {
                if resp.status_code == 200 && resp.body.starts_with("{") {
                    // Check if data appears to be prerendered (static)
                    // and contains potentially outdated sensitive info
                    let body_lower = resp.body.to_lowercase();
                    if body_lower.contains("user") || body_lower.contains("auth") || body_lower.contains("session") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sveltekit_prerender_{}", Self::generate_id()),
                            vuln_type: "SvelteKit Prerendered Data Exposure".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "Information Disclosure".to_string(),
                            url: data_url.clone(),
                            parameter: Some(path.to_string()),
                            payload: format!("GET {}", path),
                            description: format!(
                                "Prerendered __data.json at '{}' may contain cached user/auth data \
                                that persists across deployments.",
                                path
                            ),
                            evidence: Some(format!(
                                "Contains user/auth related data in prerendered output"
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Don't prerender pages with user-specific data\n\
                                          2. Use +page.server.js for dynamic user data\n\
                                          3. Add prerender = false for authenticated pages".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for path traversal (CVE-2024-24563)
    async fn check_path_traversal(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Path traversal payloads for static file serving
        let traversal_payloads = [
            ("/_app/../../../etc/passwd", "/etc/passwd"),
            ("/_app/..%2f..%2f..%2fetc/passwd", "/etc/passwd (encoded)"),
            ("/_app/....//....//....//etc/passwd", "/etc/passwd (double dot)"),
            ("/static/../../../package.json", "package.json"),
            ("/_app/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd (full encode)"),
        ];

        for (payload, desc) in &traversal_payloads {
            tests_run += 1;
            let test_url = format!("{}{}", base, payload);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                let is_success = resp.status_code == 200 && (
                    resp.body.contains("root:") ||  // /etc/passwd
                    resp.body.contains("\"name\":") ||  // package.json
                    resp.body.contains("dependencies")
                );

                if is_success {
                    vulnerabilities.push(Vulnerability {
                        id: format!("sveltekit_path_traversal_{}", Self::generate_id()),
                        vuln_type: "SvelteKit Path Traversal (CVE-2024-24563)".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Path Traversal".to_string(),
                        url: test_url.clone(),
                        parameter: Some("path".to_string()),
                        payload: payload.to_string(),
                        description: format!(
                            "Path traversal vulnerability in SvelteKit static file serving. \
                            Successfully accessed {} using traversal payload.",
                            desc
                        ),
                        evidence: Some(format!(
                            "Payload: {}\n\
                            Response indicates file access\n\
                            Status: {}",
                            payload, resp.status_code
                        )),
                        cwe: "CWE-22".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Upgrade SvelteKit to version 2.4.3 or later.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for open redirect vulnerabilities
    async fn check_open_redirect(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test redirect parameters
        let redirect_params = [
            ("redirect", "https://evil.com"),
            ("next", "https://evil.com"),
            ("return", "//evil.com"),
            ("url", "https://evil.com"),
            ("goto", "//evil.com"),
            ("returnTo", "https://evil.com"),
        ];

        for (param, payload) in &redirect_params {
            tests_run += 1;
            let test_url = format!("{}/?{}={}", base, param, urlencoding::encode(payload));

            if let Ok(resp) = self.http_client.get(&test_url).await {
                // Check for redirect to evil.com
                if resp.status_code == 302 || resp.status_code == 301 || resp.status_code == 307 {
                    if let Some(location) = resp.headers.get("location") {
                        if location.contains("evil.com") {
                            vulnerabilities.push(Vulnerability {
                                id: format!("sveltekit_open_redirect_{}", Self::generate_id()),
                                vuln_type: "SvelteKit Open Redirect".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                category: "Open Redirect".to_string(),
                                url: test_url.clone(),
                                parameter: Some(param.to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "Open redirect via '{}' parameter allows redirecting users to malicious sites.",
                                    param
                                ),
                                evidence: Some(format!(
                                    "Parameter: {}={}\n\
                                    Location header: {}",
                                    param, payload, location
                                )),
                                cwe: "CWE-601".to_string(),
                                cvss: 6.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Validate redirect URLs against allowlist\n\
                                              2. Use relative URLs for redirects\n\
                                              3. Upgrade SvelteKit to 2.5.4+ (CVE-2024-29893)".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for version-specific CVEs
    async fn check_version_cves(
        &self,
        url: &str,
        version: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let version_parts: Vec<u32> = version
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        if version_parts.len() < 2 {
            return Ok((vec![], tests_run));
        }

        let major = version_parts[0];
        let minor = version_parts[1];
        let patch = version_parts.get(2).copied().unwrap_or(0);

        for cve in &self.known_cves {
            tests_run += 1;

            let is_affected = match cve.cve_id.as_str() {
                "CVE-2024-23641" => major < 2 || (major == 2 && minor < 4) || (major == 2 && minor == 4 && patch < 1),
                "CVE-2024-24563" => major < 2 || (major == 2 && minor < 4) || (major == 2 && minor == 4 && patch < 3),
                "CVE-2024-29893" => major < 2 || (major == 2 && minor < 5) || (major == 2 && minor == 5 && patch < 4),
                "CVE-2023-29008" | "CVE-2023-29007" => major < 1 || (major == 1 && minor < 15) || (major == 1 && minor == 15 && patch < 1),
                "CVE-2022-25869" => false, // Svelte core, need different version check
                _ => false,
            };

            if is_affected {
                vulnerabilities.push(Vulnerability {
                    id: format!("sveltekit_cve_{}_{}", cve.cve_id, Self::generate_id()),
                    vuln_type: format!("SvelteKit {} - {:?}", cve.cve_id, cve.check_type),
                    severity: cve.severity.clone(),
                    confidence: Confidence::High,
                    category: "Known Vulnerability".to_string(),
                    url: url.to_string(),
                    parameter: Some(format!("SvelteKit {}", version)),
                    payload: format!("{}: {}", cve.cve_id, cve.affected_versions),
                    description: format!(
                        "{}\n\nDetected: {}\nAffected: {}",
                        cve.description, version, cve.affected_versions
                    ),
                    evidence: Some(format!(
                        "CVE: {}\nVersion: {}\nAffected: {}",
                        cve.cve_id, version, cve.affected_versions
                    )),
                    cwe: match cve.check_type {
                        CVECheckType::CSRF => "CWE-352",
                        CVECheckType::PathTraversal => "CWE-22",
                        CVECheckType::OpenRedirect => "CWE-601",
                        CVECheckType::XSS => "CWE-79",
                        _ => "CWE-1035",
                    }.to_string(),
                    cvss: match cve.severity {
                        Severity::Critical => 9.8,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.0,
                    },
                    verified: false,
                    false_positive: false,
                    remediation: format!("Upgrade SvelteKit. See: https://nvd.nist.gov/vuln/detail/{}", cve.cve_id),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}
