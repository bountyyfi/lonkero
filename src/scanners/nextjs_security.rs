// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced Next.js Security Scanner
 * Comprehensive Next.js vulnerability detection
 *
 * REQUIRES: Personal license or higher
 *
 * Detects:
 * - Middleware bypass vulnerabilities (CVE-2024-34351, etc.)
 * - Server component data exposure
 * - _next/data endpoint leakage
 * - API route misconfigurations
 * - Environment variable exposure
 * - Image optimization SSRF
 * - Draft/Preview mode exposure
 * - ISR revalidation token exposure
 * - Source map disclosure
 * - Next.js config exposure
 * - Known Next.js CVEs
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
use tracing::{debug, info, warn};

pub struct NextJsSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: Vec<NextJsCVE>,
}

#[derive(Clone)]
struct NextJsCVE {
    cve_id: String,
    affected_versions: String,
    severity: Severity,
    description: String,
    check_type: CVECheckType,
}

#[derive(Clone)]
enum CVECheckType {
    MiddlewareBypass,
    ServerAction,
    ImageOptimization,
    DataExposure,
    PathTraversal,
    SSRF,
    DoS,
}

impl NextJsSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known Next.js CVEs
    fn build_cve_database() -> Vec<NextJsCVE> {
        vec![
            // Middleware bypass vulnerabilities
            NextJsCVE {
                cve_id: "CVE-2024-34351".to_string(),
                affected_versions: "13.4.0 - 14.1.0".to_string(),
                severity: Severity::Critical,
                description: "Server-Side Request Forgery (SSRF) in Server Actions via Host header manipulation".to_string(),
                check_type: CVECheckType::MiddlewareBypass,
            },
            NextJsCVE {
                cve_id: "CVE-2024-34350".to_string(),
                affected_versions: "<14.1.1".to_string(),
                severity: Severity::High,
                description: "Inconsistent interpretation of crafted HTTP requests leading to authentication bypass".to_string(),
                check_type: CVECheckType::MiddlewareBypass,
            },
            NextJsCVE {
                cve_id: "CVE-2024-39693".to_string(),
                affected_versions: "<14.2.4".to_string(),
                severity: Severity::High,
                description: "Authorization bypass through x-middleware-subrequest header".to_string(),
                check_type: CVECheckType::MiddlewareBypass,
            },
            NextJsCVE {
                cve_id: "CVE-2025-29927".to_string(),
                affected_versions: "<14.2.25, <15.2.3".to_string(),
                severity: Severity::Critical,
                description: "Middleware bypass via x-middleware-subrequest header allowing auth bypass".to_string(),
                check_type: CVECheckType::MiddlewareBypass,
            },
            // Server Action vulnerabilities
            NextJsCVE {
                cve_id: "CVE-2024-46982".to_string(),
                affected_versions: "<14.2.10".to_string(),
                severity: Severity::High,
                description: "Cache poisoning in Server Actions leading to denial of service".to_string(),
                check_type: CVECheckType::DoS,
            },
            // Image optimization vulnerabilities
            NextJsCVE {
                cve_id: "CVE-2024-47831".to_string(),
                affected_versions: "<14.2.7".to_string(),
                severity: Severity::High,
                description: "SSRF vulnerability in image optimization allowing internal network access".to_string(),
                check_type: CVECheckType::ImageOptimization,
            },
            NextJsCVE {
                cve_id: "CVE-2023-46298".to_string(),
                affected_versions: "<13.4.20".to_string(),
                severity: Severity::High,
                description: "SSRF via image optimization with custom domains".to_string(),
                check_type: CVECheckType::ImageOptimization,
            },
            // Path traversal
            NextJsCVE {
                cve_id: "CVE-2024-51479".to_string(),
                affected_versions: "<14.2.18, <15.0.4".to_string(),
                severity: Severity::High,
                description: "Unauthorized access to root-level files via path traversal".to_string(),
                check_type: CVECheckType::PathTraversal,
            },
            // Data exposure
            NextJsCVE {
                cve_id: "CVE-2024-56332".to_string(),
                affected_versions: "<14.2.21, <15.1.2".to_string(),
                severity: Severity::Medium,
                description: "Information disclosure through error messages exposing internal paths".to_string(),
                check_type: CVECheckType::DataExposure,
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
            debug!("[Next.js] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Detect if target is running Next.js
        tests_run += 1;
        let (is_nextjs, version) = self.detect_nextjs(url).await;

        if !is_nextjs {
            debug!("[Next.js] Target does not appear to be running Next.js");
            return Ok((vec![], tests_run));
        }

        info!("[Next.js] Detected Next.js application{}",
            version.as_ref().map(|v| format!(" (version: {})", v)).unwrap_or_default());

        // Test middleware bypass vulnerabilities
        let (bypass_vulns, bypass_tests) = self.check_middleware_bypass(url, config).await?;
        vulnerabilities.extend(bypass_vulns);
        tests_run += bypass_tests;

        // Test _next/data exposure
        let (data_vulns, data_tests) = self.check_next_data_exposure(url, config).await?;
        vulnerabilities.extend(data_vulns);
        tests_run += data_tests;

        // Test API route misconfigurations
        let (api_vulns, api_tests) = self.check_api_routes(url, config).await?;
        vulnerabilities.extend(api_vulns);
        tests_run += api_tests;

        // Test environment variable exposure
        let (env_vulns, env_tests) = self.check_env_exposure(url, config).await?;
        vulnerabilities.extend(env_vulns);
        tests_run += env_tests;

        // Test image optimization SSRF
        let (img_vulns, img_tests) = self.check_image_ssrf(url, config).await?;
        vulnerabilities.extend(img_vulns);
        tests_run += img_tests;

        // Test draft/preview mode
        let (draft_vulns, draft_tests) = self.check_draft_mode(url, config).await?;
        vulnerabilities.extend(draft_vulns);
        tests_run += draft_tests;

        // Test ISR revalidation exposure
        let (isr_vulns, isr_tests) = self.check_isr_revalidation(url, config).await?;
        vulnerabilities.extend(isr_vulns);
        tests_run += isr_tests;

        // Test source map exposure
        let (sourcemap_vulns, sourcemap_tests) = self.check_source_maps(url, config).await?;
        vulnerabilities.extend(sourcemap_vulns);
        tests_run += sourcemap_tests;

        // Test Next.js config exposure
        let (config_vulns, config_tests) = self.check_config_exposure(url, config).await?;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        // Test server actions
        let (action_vulns, action_tests) = self.check_server_actions(url, config).await?;
        vulnerabilities.extend(action_vulns);
        tests_run += action_tests;

        // Check known CVEs based on detected version
        if let Some(ref ver) = version {
            let (cve_vulns, cve_tests) = self.check_version_cves(url, ver, config).await?;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!("[Next.js] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running Next.js
    async fn detect_nextjs(&self, url: &str) -> (bool, Option<String>) {
        // Check multiple indicators
        let mut is_nextjs = false;
        let mut version = None;

        // 1. Check _next directory
        let next_static = format!("{}/_next/static/", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&next_static).await {
            if resp.status_code != 404 {
                is_nextjs = true;
            }
        }

        // 2. Check for __NEXT_DATA__ script tag
        if let Ok(resp) = self.http_client.get(url).await {
            if resp.body.contains("__NEXT_DATA__") || resp.body.contains("_next/static") {
                is_nextjs = true;
            }

            // Extract version from build manifest or __NEXT_DATA__
            let version_re = Regex::new(r#"(?i)next(?:\.js)?[/\s]*v?(\d+\.\d+(?:\.\d+)?)"#).ok();
            if let Some(re) = version_re {
                if let Some(caps) = re.captures(&resp.body) {
                    version = caps.get(1).map(|m| m.as_str().to_string());
                }
            }

            // Check X-Powered-By header
            if let Some(powered_by) = resp.headers.get("x-powered-by") {
                let powered_by_lower = powered_by.to_lowercase();
                if powered_by_lower.contains("next.js") || powered_by_lower.contains("next") {
                    is_nextjs = true;
                    // Extract version from header
                    let header_version_re = Regex::new(r#"(?i)next\.js?\s*v?(\d+\.\d+(?:\.\d+)?)"#).ok();
                    if let Some(re) = header_version_re {
                        if let Some(caps) = re.captures(&powered_by) {
                            version = caps.get(1).map(|m| m.as_str().to_string());
                        }
                    }
                }
            }
        }

        // 3. Check for Next.js specific headers
        let api_test = format!("{}/api/health", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&api_test).await {
            // Check for Next.js cache headers
            if resp.headers.contains_key("x-nextjs-cache") ||
               resp.headers.contains_key("x-nextjs-matched-path") {
                is_nextjs = true;
            }
        }

        (is_nextjs, version)
    }

    /// Check for middleware bypass vulnerabilities
    async fn check_middleware_bypass(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test protected paths that might have middleware
        let protected_paths = [
            "/admin",
            "/dashboard",
            "/api/admin",
            "/api/private",
            "/protected",
            "/internal",
            "/settings",
            "/account",
        ];

        // CVE-2024-34351 / CVE-2025-29927: x-middleware-subrequest bypass
        for path in &protected_paths {
            tests_run += 1;
            let test_url = format!("{}{}", base, path);

            // First check if path is protected (returns 401/403 normally)
            let normal_resp = match self.http_client.get(&test_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if normal_resp.status_code != 401 && normal_resp.status_code != 403 {
                continue; // Not a protected path
            }

            // Try bypass with x-middleware-subrequest header
            tests_run += 1;
            let mut headers = HashMap::new();
            headers.insert("x-middleware-subrequest".to_string(), "1".to_string());

            let headers_vec: Vec<(String, String)> = headers.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if let Ok(bypass_resp) = self.http_client.get_with_headers(&test_url, headers_vec).await {
                // Check if we bypassed authentication
                if bypass_resp.status_code == 200 ||
                   (bypass_resp.status_code != 401 && bypass_resp.status_code != 403) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("nextjs_middleware_bypass_{}", Self::generate_id()),
                        vuln_type: "Next.js Middleware Bypass - Authentication Bypass".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: test_url.clone(),
                        parameter: Some("x-middleware-subrequest".to_string()),
                        payload: "x-middleware-subrequest: 1".to_string(),
                        description: format!(
                            "Next.js middleware authentication bypass via x-middleware-subrequest header. \
                            The protected path '{}' returns {} normally but {} with bypass header. \
                            This vulnerability (CVE-2025-29927/CVE-2024-39693) allows attackers to bypass \
                            authentication middleware by adding a special header that tricks Next.js into \
                            thinking the request is a subrequest from middleware itself.",
                            path, normal_resp.status_code, bypass_resp.status_code
                        ),
                        evidence: Some(format!(
                            "Normal request: {} {} (blocked)\n\
                            With x-middleware-subrequest: {} {} (bypassed)\n\
                            Response length: {} bytes",
                            "GET", test_url,
                            bypass_resp.status_code,
                            if bypass_resp.status_code == 200 { "OK" } else { "accessible" },
                            bypass_resp.body.len()
                        )),
                        cwe: "CWE-287".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Upgrade Next.js to latest version (14.2.25+ or 15.2.3+)\n\
                                      2. Add server-side authentication checks that don't rely solely on middleware\n\
                                      3. Implement defense in depth - validate auth at API route level\n\
                                      4. Use next.config.js to block x-middleware-subrequest header from external requests".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }

            // Try variations of the bypass
            let bypass_variations = [
                ("x-middleware-subrequest", "true"),
                ("x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware"),
                ("X-Middleware-Subrequest", "1"),
                ("x-middleware-prefetch", "1"),
                ("x-middleware-invoke", "1"),
            ];

            for (header, value) in bypass_variations {
                tests_run += 1;
                let mut headers = HashMap::new();
                headers.insert(header.to_string(), value.to_string());

                let headers_vec: Vec<(String, String)> = headers.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Ok(bypass_resp) = self.http_client.get_with_headers(&test_url, headers_vec).await {
                    if bypass_resp.status_code == 200 && normal_resp.status_code != 200 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("nextjs_middleware_bypass_{}", Self::generate_id()),
                            vuln_type: "Next.js Middleware Bypass Variant".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: test_url.clone(),
                            parameter: Some(header.to_string()),
                            payload: format!("{}: {}", header, value),
                            description: format!(
                                "Authentication bypass using {} header variant at path '{}'.",
                                header, path
                            ),
                            evidence: Some(format!(
                                "Bypass header: {}: {}\nStatus changed: {} -> {}",
                                header, value, normal_resp.status_code, bypass_resp.status_code
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "Upgrade Next.js and implement server-side auth validation.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }

            // Fast mode: stop after finding issues
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for _next/data exposure
    async fn check_next_data_exposure(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Fetch main page to get build ID
        let main_resp = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vec![], tests_run)),
        };

        // Extract buildId from __NEXT_DATA__
        let build_id_re = Regex::new(r#"buildId["']?\s*:\s*["']([^"']+)["']"#)?;
        let build_id = build_id_re.captures(&main_resp.body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        if build_id.is_none() {
            debug!("[Next.js] Could not extract buildId");
            return Ok((vec![], tests_run));
        }
        let build_id = build_id.unwrap();

        // Test _next/data endpoints for various pages
        let pages_to_test = [
            "/index",
            "/admin",
            "/dashboard",
            "/user",
            "/profile",
            "/settings",
            "/api-docs",
            "/internal",
        ];

        for page in &pages_to_test {
            tests_run += 1;
            let data_url = format!("{}/_next/data/{}{}.json", base, build_id, page);

            if let Ok(resp) = self.http_client.get(&data_url).await {
                if resp.status_code == 200 && resp.body.starts_with("{") {
                    // Check for sensitive data in the response
                    let sensitive_patterns = [
                        ("email", r#"(?i)["']email["']\s*:\s*["'][^"']+@[^"']+"#),
                        ("password", r#"(?i)["']password["']\s*:"#),
                        ("token", r#"(?i)["'](?:auth|access|api)?[_-]?token["']\s*:"#),
                        ("secret", r#"(?i)["'](?:secret|private)[_-]?(?:key)?["']\s*:"#),
                        ("user_id", r#"(?i)["']user[_-]?id["']\s*:"#),
                        ("session", r#"(?i)["']session["']\s*:"#),
                        ("credit_card", r#"\d{13,16}"#),
                        ("ssn", r#"\d{3}-\d{2}-\d{4}"#),
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
                            id: format!("nextjs_data_exposure_{}", Self::generate_id()),
                            vuln_type: "Next.js Data Exposure - Sensitive Information Leak".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: data_url.clone(),
                            parameter: Some(format!("_next/data/{}", page)),
                            payload: format!("GET /_next/data/{}{}.json", build_id, page),
                            description: format!(
                                "The Next.js _next/data endpoint for '{}' exposes sensitive information. \
                                Data from getServerSideProps/getStaticProps is accessible via direct \
                                URL access, potentially leaking: {}",
                                page, found_sensitive.join(", ")
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Status: 200 OK\n\
                                Content-Type: application/json\n\
                                Sensitive fields found: {}\n\
                                Response preview: {}...",
                                data_url,
                                found_sensitive.join(", "),
                                &resp.body[..resp.body.len().min(200)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Review getServerSideProps/getStaticProps for sensitive data exposure\n\
                                          2. Implement proper authorization in data fetching functions\n\
                                          3. Filter sensitive fields before returning props\n\
                                          4. Use authentication checks in getServerSideProps\n\
                                          5. Consider using API routes for sensitive data access".to_string(),
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

    /// Check API route misconfigurations
    async fn check_api_routes(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common API routes to check
        let api_routes = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/internal",
            "/api/debug",
            "/api/graphql",
            "/api/auth/[...nextauth]",
            "/api/auth/session",
            "/api/auth/providers",
            "/api/trpc",
            "/api/health",
            "/api/status",
            "/api/env",
            "/api/test",
        ];

        for route in &api_routes {
            tests_run += 1;
            let api_url = format!("{}{}", base, route);

            if let Ok(resp) = self.http_client.get(&api_url).await {
                // Check for exposed internal APIs
                if resp.status_code == 200 {
                    let body_lower = resp.body.to_lowercase();

                    // Check for sensitive data patterns
                    let is_sensitive = body_lower.contains("internal") ||
                        body_lower.contains("debug") ||
                        body_lower.contains("config") ||
                        body_lower.contains("database") ||
                        body_lower.contains("connection_string") ||
                        body_lower.contains("api_key") ||
                        body_lower.contains("secret");

                    if is_sensitive && (route.contains("internal") || route.contains("debug") || route.contains("config")) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("nextjs_api_exposure_{}", Self::generate_id()),
                            vuln_type: "Next.js API Route - Internal Endpoint Exposed".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Information Disclosure".to_string(),
                            url: api_url.clone(),
                            parameter: Some(route.to_string()),
                            payload: format!("GET {}", route),
                            description: format!(
                                "Internal API route '{}' is publicly accessible and returns sensitive data. \
                                This endpoint should be protected with authentication.",
                                route
                            ),
                            evidence: Some(format!(
                                "Status: 200 OK\n\
                                Contains sensitive keywords\n\
                                Response preview: {}...",
                                &resp.body[..resp.body.len().min(300)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 6.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Add authentication middleware to sensitive API routes\n\
                                          2. Use getServerSession for auth validation\n\
                                          3. Implement role-based access control\n\
                                          4. Remove debug/internal endpoints in production".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }

                // Check for CORS misconfiguration on API routes
                tests_run += 1;
                let mut headers = HashMap::new();
                headers.insert("Origin".to_string(), "https://evil.com".to_string());

                let headers_vec: Vec<(String, String)> = headers.iter()
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
                                    id: format!("nextjs_cors_misconfig_{}", Self::generate_id()),
                                    vuln_type: "Next.js API - CORS Misconfiguration".to_string(),
                                    severity: if has_credentials { Severity::High } else { Severity::Medium },
                                    confidence: Confidence::High,
                                    category: "Misconfiguration".to_string(),
                                    url: api_url.clone(),
                                    parameter: Some("CORS".to_string()),
                                    payload: "Origin: https://evil.com".to_string(),
                                    description: format!(
                                        "API route '{}' has permissive CORS configuration allowing requests from any origin{}.",
                                        route,
                                        if has_credentials { " WITH credentials" } else { "" }
                                    ),
                                    evidence: Some(format!(
                                        "Access-Control-Allow-Origin: {}\n\
                                        Access-Control-Allow-Credentials: {}",
                                        acao, has_credentials
                                    )),
                                    cwe: "CWE-942".to_string(),
                                    cvss: if has_credentials { 8.1 } else { 5.3 },
                                    verified: true,
                                    false_positive: false,
                                    remediation: "Configure CORS properly in next.config.js or API route:\n\
                                                  - Use specific allowed origins\n\
                                                  - Don't use wildcard with credentials\n\
                                                  - Validate Origin header server-side".to_string(),
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

        // Fetch page and check for exposed env variables
        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            // Look for server-side env variables exposed to client
            // These should only be NEXT_PUBLIC_* but sometimes devs leak others
            let server_env_patterns = [
                (r#"(?i)DATABASE_URL\s*[=:]\s*["'][^"']+["']"#, "DATABASE_URL"),
                (r#"(?i)(?:SECRET|PRIVATE)[_-]?KEY\s*[=:]\s*["'][^"']+["']"#, "SECRET_KEY"),
                (r#"(?i)JWT[_-]?SECRET\s*[=:]\s*["'][^"']+["']"#, "JWT_SECRET"),
                (r#"(?i)API[_-]?(?:KEY|SECRET)\s*[=:]\s*["'][^"']+["']"#, "API_KEY"),
                (r#"(?i)AWS[_-]?(?:ACCESS|SECRET)[^=]*[=:]\s*["'][^"']+["']"#, "AWS_CREDENTIALS"),
                (r#"(?i)STRIPE[_-]?(?:SECRET|SK_)[^=]*[=:]\s*["'][^"']+["']"#, "STRIPE_SECRET"),
                (r#"(?i)SENDGRID[_-]?(?:API|KEY)[^=]*[=:]\s*["'][^"']+["']"#, "SENDGRID_KEY"),
                (r#"(?i)MONGODB_URI\s*[=:]\s*["'][^"']+["']"#, "MONGODB_URI"),
                (r#"(?i)REDIS_URL\s*[=:]\s*["'][^"']+["']"#, "REDIS_URL"),
                (r#"(?i)NEXTAUTH_SECRET\s*[=:]\s*["'][^"']+["']"#, "NEXTAUTH_SECRET"),
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
                    id: format!("nextjs_env_exposure_{}", Self::generate_id()),
                    vuln_type: "Next.js Server Environment Variables Exposed".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("Environment Variables".to_string()),
                    payload: "Client-side JavaScript".to_string(),
                    description: format!(
                        "Server-side environment variables are exposed in client-side JavaScript. \
                        The following sensitive variables were found: {}. \
                        Only NEXT_PUBLIC_* variables should be accessible in the browser.",
                        exposed_vars.join(", ")
                    ),
                    evidence: Some(format!(
                        "Exposed variables: {}\n\
                        Found in: Client-side JavaScript bundle\n\
                        Impact: Attackers can extract credentials and secrets",
                        exposed_vars.join(", ")
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Never expose server-side env vars to client\n\
                                  2. Use NEXT_PUBLIC_ prefix ONLY for truly public values\n\
                                  3. Audit .env files and next.config.js for exposure\n\
                                  4. Rotate any exposed credentials immediately\n\
                                  5. Use server-side API routes to access sensitive data".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for image optimization SSRF
    async fn check_image_ssrf(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test SSRF payloads via _next/image
        let ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  // AWS metadata
            "http://metadata.google.internal/",          // GCP metadata
            "http://169.254.169.254/metadata/v1/",       // Azure/DO
            "http://127.0.0.1:22",                       // Local SSH
            "http://localhost:3000/api/internal",       // Local API
            "http://[::1]",                             // IPv6 localhost
            "http://0.0.0.0/",                          // Null route
        ];

        for payload in &ssrf_payloads {
            tests_run += 1;
            let encoded_url = urlencoding::encode(payload);
            let image_url = format!("{}/_next/image?url={}&w=64&q=75", base, encoded_url);

            if let Ok(resp) = self.http_client.get(&image_url).await {
                // Check for successful SSRF indicators
                let is_ssrf = resp.status_code == 200 && (
                    resp.body.contains("ami-") ||          // AWS metadata
                    resp.body.contains("instance-id") ||
                    resp.body.contains("meta-data") ||
                    resp.body.contains("computeMetadata") ||  // GCP
                    resp.body.contains("SSH-")             // SSH banner
                );

                if is_ssrf {
                    vulnerabilities.push(Vulnerability {
                        id: format!("nextjs_image_ssrf_{}", Self::generate_id()),
                        vuln_type: "Next.js Image Optimization SSRF".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "SSRF".to_string(),
                        url: image_url.clone(),
                        parameter: Some("url".to_string()),
                        payload: payload.to_string(),
                        description: format!(
                            "The Next.js image optimization endpoint is vulnerable to SSRF. \
                            Internal resources can be accessed via /_next/image?url=. \
                            Tested payload: {}", payload
                        ),
                        evidence: Some(format!(
                            "Request: GET {}\n\
                            Status: {}\n\
                            Response contains internal data indicators",
                            image_url, resp.status_code
                        )),
                        cwe: "CWE-918".to_string(),
                        cvss: 9.1,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Upgrade Next.js to latest version\n\
                                      2. Configure images.remotePatterns in next.config.js\n\
                                      3. Use allowlist for image domains\n\
                                      4. Disable image optimization if not needed\n\
                                      5. Block internal IP ranges at network level".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for draft/preview mode exposure
    async fn check_draft_mode(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Check draft mode API endpoints
        let draft_endpoints = [
            "/api/draft",
            "/api/preview",
            "/api/draft/enable",
            "/api/preview/enable",
            "/api/draft?secret=",
            "/api/preview?secret=",
        ];

        for endpoint in &draft_endpoints {
            tests_run += 1;
            let draft_url = format!("{}{}", base, endpoint);

            if let Ok(resp) = self.http_client.get(&draft_url).await {
                // Check if draft mode is accessible without proper secret
                if resp.status_code == 200 || resp.status_code == 307 {
                    // Check for draft mode cookies being set
                    let has_draft_cookie = resp.headers.get("set-cookie")
                        .map(|c| c.contains("__prerender_bypass") || c.contains("__next_preview_data"))
                        .unwrap_or(false);

                    if has_draft_cookie {
                        vulnerabilities.push(Vulnerability {
                            id: format!("nextjs_draft_mode_{}", Self::generate_id()),
                            vuln_type: "Next.js Draft Mode Accessible Without Secret".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Misconfiguration".to_string(),
                            url: draft_url.clone(),
                            parameter: Some("draft mode".to_string()),
                            payload: endpoint.to_string(),
                            description: "Next.js draft/preview mode can be enabled without proper authentication. \
                                          This allows attackers to bypass caching and potentially access unpublished content.".to_string(),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Draft cookies set: Yes\n\
                                Status: {}",
                                draft_url, resp.status_code
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Require secret token for draft mode activation\n\
                                          2. Validate secret in API route before enabling\n\
                                          3. Use environment variable for draft secret\n\
                                          4. Add rate limiting to draft endpoints".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for ISR revalidation token exposure
    async fn check_isr_revalidation(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test revalidation endpoints
        let revalidate_endpoints = [
            "/api/revalidate",
            "/api/revalidate-path",
            "/api/cache/revalidate",
            "/api/isr/revalidate",
        ];

        for endpoint in &revalidate_endpoints {
            tests_run += 1;
            let reval_url = format!("{}{}", base, endpoint);

            // Try without token
            if let Ok(resp) = self.http_client.get(&reval_url).await {
                if resp.status_code == 200 && resp.body.contains("revalidated") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("nextjs_isr_exposure_{}", Self::generate_id()),
                        vuln_type: "Next.js ISR Revalidation Without Authentication".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Misconfiguration".to_string(),
                        url: reval_url.clone(),
                        parameter: Some("revalidation".to_string()),
                        payload: endpoint.to_string(),
                        description: "ISR revalidation endpoint is accessible without authentication. \
                                      Attackers can force cache invalidation, causing DoS or displaying stale content.".to_string(),
                        evidence: Some(format!(
                            "Endpoint: {}\n\
                            Status: 200 OK\n\
                            Response indicates revalidation succeeded",
                            reval_url
                        )),
                        cwe: "CWE-287".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Add secret token validation to revalidation endpoint\n\
                                      2. Use webhook signature verification if triggered by CMS\n\
                                      3. Implement rate limiting\n\
                                      4. Use on-demand revalidation with proper auth".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
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

        // Extract JS file URLs
        let js_pattern = Regex::new(r#"/_next/static/[^"']+\.js"#)?;
        let js_files: Vec<String> = js_pattern.find_iter(&resp.body)
            .map(|m| format!("{}{}.map", url.trim_end_matches('/'), m.as_str()))
            .collect();

        for js_map in js_files.iter().take(5) {
            tests_run += 1;
            if let Ok(map_resp) = self.http_client.get(js_map).await {
                if map_resp.status_code == 200 && map_resp.body.contains("mappings") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("nextjs_sourcemap_{}", Self::generate_id()),
                        vuln_type: "Next.js Source Map Exposure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: js_map.clone(),
                        parameter: Some("source map".to_string()),
                        payload: "GET *.js.map".to_string(),
                        description: "JavaScript source maps are publicly accessible, exposing original source code. \
                                      This allows attackers to understand application logic and find vulnerabilities.".to_string(),
                        evidence: Some(format!(
                            "Source map URL: {}\n\
                            Status: 200 OK\n\
                            Contains mappings: Yes",
                            js_map
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Set productionBrowserSourceMaps: false in next.config.js\n\
                                      2. Remove .map files from production build\n\
                                      3. Use hideSourceMaps: true if using next-compose-plugins".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for Next.js config exposure
    async fn check_config_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Files that shouldn't be accessible
        let sensitive_files = [
            ("next.config.js", "Next.js configuration"),
            ("next.config.mjs", "Next.js configuration"),
            (".env", "Environment variables"),
            (".env.local", "Local environment variables"),
            (".env.production", "Production environment"),
            ("tsconfig.json", "TypeScript configuration"),
            ("package.json", "Package dependencies"),
            ("package-lock.json", "Dependency lock file"),
            (".next/BUILD_ID", "Build identifier"),
            (".next/build-manifest.json", "Build manifest"),
            (".next/routes-manifest.json", "Routes manifest"),
            (".next/prerender-manifest.json", "Prerender manifest"),
        ];

        for (file, desc) in &sensitive_files {
            tests_run += 1;
            let file_url = format!("{}/{}", base, file);

            if let Ok(resp) = self.http_client.get(&file_url).await {
                if resp.status_code == 200 {
                    let is_config = resp.body.contains("module.exports") ||
                        resp.body.contains("export default") ||
                        resp.body.starts_with("{") ||
                        resp.body.contains("DATABASE_URL") ||
                        resp.body.contains("API_KEY");

                    if is_config {
                        vulnerabilities.push(Vulnerability {
                            id: format!("nextjs_config_exposure_{}", Self::generate_id()),
                            vuln_type: format!("Next.js {} Exposed", desc),
                            severity: if file.contains(".env") { Severity::Critical } else { Severity::Medium },
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: file_url.clone(),
                            parameter: Some(file.to_string()),
                            payload: format!("GET /{}", file),
                            description: format!(
                                "The {} file is publicly accessible. This may expose sensitive configuration, \
                                API keys, or internal paths.", desc
                            ),
                            evidence: Some(format!(
                                "File: {}\n\
                                Status: 200 OK\n\
                                Preview: {}...",
                                file, &resp.body[..resp.body.len().min(200)]
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: if file.contains(".env") { 9.1 } else { 5.3 },
                            verified: true,
                            false_positive: false,
                            remediation: "1. Configure web server to block access to config files\n\
                                          2. Move sensitive files outside web root\n\
                                          3. Add to .gitignore and deploy excludes\n\
                                          4. Use next.config.js headers to block access".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for Server Actions vulnerabilities
    async fn check_server_actions(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test Server Actions endpoint with various manipulation techniques
        tests_run += 1;

        // CVE-2024-34351: Host header SSRF in Server Actions
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/x-component".to_string());
        headers.insert("Next-Action".to_string(), "test".to_string());
        headers.insert("Host".to_string(), "evil.com".to_string());

        let headers_vec: Vec<(String, String)> = headers.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Ok(resp) = self.http_client.post_with_headers(base, "[]", headers_vec).await {
            // Check if the response indicates SSRF potential
            if resp.body.contains("evil.com") ||
               resp.headers.get("location").map(|l| l.contains("evil.com")).unwrap_or(false) {
                vulnerabilities.push(Vulnerability {
                    id: format!("nextjs_server_action_ssrf_{}", Self::generate_id()),
                    vuln_type: "Next.js Server Actions SSRF (CVE-2024-34351)".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    category: "SSRF".to_string(),
                    url: base.to_string(),
                    parameter: Some("Host header".to_string()),
                    payload: "Host: evil.com".to_string(),
                    description: "Server Actions endpoint is vulnerable to SSRF via Host header manipulation. \
                                  Attackers can make the server send requests to arbitrary hosts.".to_string(),
                    evidence: Some(format!(
                        "Request with Host: evil.com\n\
                        Response references evil.com"
                    )),
                    cwe: "CWE-918".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Upgrade to Next.js 14.1.1 or later\n\
                                  2. Validate Host header in middleware\n\
                                  3. Use allowlist for redirect targets".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
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

        // Parse version
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

            // Simple version check - could be more sophisticated
            let is_affected = match cve.cve_id.as_str() {
                "CVE-2025-29927" => (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 25) ||
                                   (major == 15 && minor < 2) || (major == 15 && minor == 2 && patch < 3),
                "CVE-2024-39693" => major < 14 || (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 4),
                "CVE-2024-34351" => (major == 13 && minor >= 4) || (major == 14 && minor < 1),
                "CVE-2024-34350" => major < 14 || (major == 14 && minor < 1) || (major == 14 && minor == 1 && patch < 1),
                "CVE-2024-46982" => major < 14 || (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 10),
                "CVE-2024-47831" => major < 14 || (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 7),
                "CVE-2023-46298" => major < 13 || (major == 13 && minor < 4) || (major == 13 && minor == 4 && patch < 20),
                "CVE-2024-51479" => (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 18) ||
                                   (major == 15 && minor < 0) || (major == 15 && minor == 0 && patch < 4),
                "CVE-2024-56332" => (major == 14 && minor < 2) || (major == 14 && minor == 2 && patch < 21) ||
                                   (major == 15 && minor < 1) || (major == 15 && minor == 1 && patch < 2),
                _ => false,
            };

            if is_affected {
                vulnerabilities.push(Vulnerability {
                    id: format!("nextjs_cve_{}_{}", cve.cve_id, Self::generate_id()),
                    vuln_type: format!("Next.js {} - {}", cve.cve_id,
                        match cve.check_type {
                            CVECheckType::MiddlewareBypass => "Middleware Bypass",
                            CVECheckType::ServerAction => "Server Action Vulnerability",
                            CVECheckType::ImageOptimization => "Image Optimization SSRF",
                            CVECheckType::DataExposure => "Data Exposure",
                            CVECheckType::PathTraversal => "Path Traversal",
                            CVECheckType::SSRF => "SSRF",
                            CVECheckType::DoS => "Denial of Service",
                        }
                    ),
                    severity: cve.severity.clone(),
                    confidence: Confidence::High,
                    category: "Known Vulnerability".to_string(),
                    url: url.to_string(),
                    parameter: Some(format!("Next.js {}", version)),
                    payload: format!("{}: {}", cve.cve_id, cve.affected_versions),
                    description: format!(
                        "{}\n\nDetected version: {}\nAffected versions: {}",
                        cve.description, version, cve.affected_versions
                    ),
                    evidence: Some(format!(
                        "CVE: {}\n\
                        Detected Version: {}\n\
                        Affected: {}\n\
                        Severity: {:?}",
                        cve.cve_id, version, cve.affected_versions, cve.severity
                    )),
                    cwe: match cve.check_type {
                        CVECheckType::MiddlewareBypass => "CWE-287",
                        CVECheckType::SSRF | CVECheckType::ImageOptimization => "CWE-918",
                        CVECheckType::PathTraversal => "CWE-22",
                        CVECheckType::DataExposure => "CWE-200",
                        _ => "CWE-1035",
                    }.to_string(),
                    cvss: match cve.severity {
                        Severity::Critical => 9.8,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.0,
                    },
                    verified: false, // Version-based detection
                    false_positive: false,
                    remediation: format!(
                        "Upgrade Next.js to a patched version. Check: https://nvd.nist.gov/vuln/detail/{}",
                        cve.cve_id
                    ),
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
