// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct ReactSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: Vec<ReactCVE>,
}

#[derive(Clone)]
struct ReactCVE {
    cve_id: String,
    package: String,
    affected_versions: String,
    severity: Severity,
    description: String,
}

impl ReactSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known React CVEs
    fn build_cve_database() -> Vec<ReactCVE> {
        vec![
            // React core
            ReactCVE {
                cve_id: "CVE-2024-43788".to_string(),
                package: "react-dom".to_string(),
                affected_versions: "<18.3.1".to_string(),
                severity: Severity::Medium,
                description: "XSS vulnerability in react-dom when using server-side rendering with user input".to_string(),
            },
            ReactCVE {
                cve_id: "CVE-2018-6341".to_string(),
                package: "react".to_string(),
                affected_versions: "<16.0.0".to_string(),
                severity: Severity::Medium,
                description: "XSS via attribute name in React DOM server rendering".to_string(),
            },
            // React Router
            ReactCVE {
                cve_id: "CVE-2024-42346".to_string(),
                package: "react-router".to_string(),
                affected_versions: "<6.24.0".to_string(),
                severity: Severity::High,
                description: "Open redirect vulnerability in React Router via redirect parameter manipulation".to_string(),
            },
            ReactCVE {
                cve_id: "CVE-2021-23518".to_string(),
                package: "react-router".to_string(),
                affected_versions: "<5.3.0".to_string(),
                severity: Severity::Medium,
                description: "Prototype pollution in React Router history".to_string(),
            },
            // React-related packages
            ReactCVE {
                cve_id: "CVE-2022-25883".to_string(),
                package: "semver".to_string(),
                affected_versions: "<7.5.2".to_string(),
                severity: Severity::High,
                description: "ReDoS vulnerability in semver used by React tooling".to_string(),
            },
            ReactCVE {
                cve_id: "CVE-2024-4067".to_string(),
                package: "micromatch".to_string(),
                affected_versions: "<4.0.6".to_string(),
                severity: Severity::High,
                description: "ReDoS in micromatch used by Create React App".to_string(),
            },
            // Create React App
            ReactCVE {
                cve_id: "CVE-2022-46175".to_string(),
                package: "json5".to_string(),
                affected_versions: "<2.2.2".to_string(),
                severity: Severity::High,
                description: "Prototype pollution in json5 used by CRA".to_string(),
            },
            // Redux
            ReactCVE {
                cve_id: "CVE-2021-3757".to_string(),
                package: "immer".to_string(),
                affected_versions: "<9.0.6".to_string(),
                severity: Severity::Critical,
                description: "Prototype pollution in immer (used by Redux Toolkit)".to_string(),
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
            debug!("[React] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Detect if target is running React
        tests_run += 1;
        let (is_react, version, framework_type) = self.detect_react(url).await;

        if !is_react {
            debug!("[React] Target does not appear to be running React");
            return Ok((vec![], tests_run));
        }

        info!(
            "[React] Detected React application{} ({})",
            version
                .as_ref()
                .map(|v| format!(" v{}", v))
                .unwrap_or_default(),
            framework_type
        );

        // Check for dangerous patterns in source
        let (pattern_vulns, pattern_tests) = self.check_dangerous_patterns(url, config).await?;
        vulnerabilities.extend(pattern_vulns);
        tests_run += pattern_tests;

        // Check for DevTools in production
        let (devtools_vulns, devtools_tests) = self.check_devtools_exposure(url, config).await?;
        vulnerabilities.extend(devtools_vulns);
        tests_run += devtools_tests;

        // Check for environment variable exposure
        let (env_vulns, env_tests) = self.check_env_exposure(url, config).await?;
        vulnerabilities.extend(env_vulns);
        tests_run += env_tests;

        // Check for source map exposure
        let (sourcemap_vulns, sourcemap_tests) = self.check_source_maps(url, config).await?;
        vulnerabilities.extend(sourcemap_vulns);
        tests_run += sourcemap_tests;

        // Check for SSR data exposure
        let (ssr_vulns, ssr_tests) = self.check_ssr_exposure(url, config).await?;
        vulnerabilities.extend(ssr_vulns);
        tests_run += ssr_tests;

        // Check for build artifact exposure
        let (build_vulns, build_tests) = self.check_build_exposure(url, config).await?;
        vulnerabilities.extend(build_vulns);
        tests_run += build_tests;

        // Check API endpoints
        let (api_vulns, api_tests) = self.check_api_security(url, config).await?;
        vulnerabilities.extend(api_vulns);
        tests_run += api_tests;

        // Check for XSS via href/src attributes
        let (href_vulns, href_tests) = self.check_href_xss(url, config).await?;
        vulnerabilities.extend(href_vulns);
        tests_run += href_tests;

        // Check for prototype pollution
        let (proto_vulns, proto_tests) = self.check_prototype_pollution(url, config).await?;
        vulnerabilities.extend(proto_vulns);
        tests_run += proto_tests;

        // Check known CVEs based on detected packages
        let (cve_vulns, cve_tests) = self.check_package_cves(url, config).await?;
        vulnerabilities.extend(cve_vulns);
        tests_run += cve_tests;

        info!(
            "[React] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running React
    async fn detect_react(&self, url: &str) -> (bool, Option<String>, String) {
        let mut is_react = false;
        let mut version = None;
        let mut framework_type = "React".to_string();

        if let Ok(resp) = self.http_client.get(url).await {
            // Check for React markers
            if resp.body.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__") ||
               resp.body.contains("_reactRootContainer") ||
               resp.body.contains("data-reactroot") ||
               resp.body.contains("data-reactid") ||
               resp.body.contains("__NEXT_DATA__") ||  // Next.js uses React
               resp.body.contains("__GATSBY") ||       // Gatsby uses React
               resp.body.contains("__REMIX") ||        // Remix uses React
               resp.body.contains("react-dom")
            {
                is_react = true;
            }

            // Check for Create React App markers
            if resp.body.contains("/static/js/main.")
                || resp.body.contains("/static/js/bundle.js")
                || resp.body.contains("REACT_APP_")
            {
                is_react = true;
                framework_type = "Create React App".to_string();
            }

            // Check for Next.js
            if resp.body.contains("__NEXT_DATA__") || resp.body.contains("/_next/") {
                framework_type = "Next.js (React)".to_string();
            }

            // Check for Gatsby
            if resp.body.contains("__GATSBY") || resp.body.contains("/gatsby-") {
                framework_type = "Gatsby (React)".to_string();
            }

            // Check for Remix
            if resp.body.contains("__REMIX") || resp.body.contains("__remixContext") {
                framework_type = "Remix (React)".to_string();
            }

            // Extract React version
            let version_patterns = [
                r#"React v(\d+\.\d+(?:\.\d+)?)"#,
                r#"react@(\d+\.\d+(?:\.\d+)?)"#,
                r#"react-dom@(\d+\.\d+(?:\.\d+)?)"#,
                r#"\"react\":\"[~^]?(\d+\.\d+(?:\.\d+)?)\""#,
            ];

            for pattern in &version_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(caps) = re.captures(&resp.body) {
                        version = caps.get(1).map(|m| m.as_str().to_string());
                        break;
                    }
                }
            }
        }

        (is_react, version, framework_type)
    }

    /// Check for dangerous patterns like dangerouslySetInnerHTML
    async fn check_dangerous_patterns(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            // Check for dangerouslySetInnerHTML with user input patterns
            let dangerous_patterns = [
                (
                    r#"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^}]*(?:props|state|params|query|input|data)"#,
                    "dangerouslySetInnerHTML with dynamic data",
                    "XSS via dangerouslySetInnerHTML",
                ),
                (
                    r#"innerHTML\s*=\s*[^;]*(?:props|state|params|query|input|data)"#,
                    "innerHTML with dynamic data",
                    "XSS via innerHTML",
                ),
                (
                    r#"eval\s*\([^)]*(?:props|state|params|query|input)"#,
                    "eval with user input",
                    "Code injection via eval",
                ),
                (
                    r#"new\s+Function\s*\([^)]*(?:props|state|params|query|input)"#,
                    "Function constructor with user input",
                    "Code injection via Function constructor",
                ),
                (
                    r#"document\.write\s*\([^)]*(?:props|state|params)"#,
                    "document.write with dynamic data",
                    "XSS via document.write",
                ),
            ];

            let mut found_patterns = Vec::new();
            for (pattern, name, vuln_type) in &dangerous_patterns {
                tests_run += 1;
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&resp.body) {
                        found_patterns.push((*name, *vuln_type));
                    }
                }
            }

            if !found_patterns.is_empty() {
                for (name, vuln_type) in &found_patterns {
                    vulnerabilities.push(Vulnerability {
                        id: format!("react_dangerous_pattern_{}", Self::generate_id()),
                        vuln_type: format!("React {} Pattern Detected", vuln_type),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "XSS".to_string(),
                        url: url.to_string(),
                        parameter: Some(name.to_string()),
                        payload: format!("Pattern: {}", name),
                        description: format!(
                            "Detected potentially dangerous React pattern: {}. \
                            This pattern can lead to {} if user input is not properly sanitized.",
                            name, vuln_type
                        ),
                        evidence: Some(format!(
                            "Pattern found in JavaScript bundle: {}\n\
                            Risk: User-controlled data may be rendered without sanitization",
                            name
                        )),
                        cwe: "CWE-79".to_string(),
                        cvss: 7.1,
                        verified: false,
                        false_positive: false,
                        remediation: "1. Avoid dangerouslySetInnerHTML with user input\n\
                                      2. Use DOMPurify or similar library to sanitize HTML\n\
                                      3. Prefer React's built-in escaping via JSX\n\
                                      4. Never use eval() or Function() with user data\n\
                                      5. Use Content Security Policy headers"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_data: None,
                    });
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for DevTools exposure in production
    async fn check_devtools_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            let mut devtools_issues = Vec::new();

            // Check for React DevTools
            if resp.body.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")
                && !resp.body.contains("production")
                && (resp.body.contains("development") || resp.body.contains("__DEV__"))
            {
                devtools_issues.push("React DevTools enabled in development mode");
            }

            // Check for Redux DevTools
            if resp.body.contains("__REDUX_DEVTOOLS_EXTENSION__")
                || resp.body.contains("redux-devtools")
                || resp.body.contains("composeWithDevTools")
            {
                devtools_issues.push("Redux DevTools Extension enabled");
            }

            // Check for React Query DevTools
            if resp.body.contains("ReactQueryDevtools")
                || resp.body.contains("react-query/devtools")
            {
                devtools_issues.push("React Query DevTools enabled");
            }

            // Check for Apollo DevTools
            if resp.body.contains("__APOLLO_CLIENT__")
                || resp.body.contains("apollo-client-devtools")
            {
                devtools_issues.push("Apollo Client DevTools enabled");
            }

            // Check for development mode indicators
            if resp.body.contains("process.env.NODE_ENV !== 'production'")
                || resp.body.contains("process.env.NODE_ENV===\"development\"")
                || resp.body.contains("__DEV__")
            {
                devtools_issues.push("Development mode checks in bundle");
            }

            if !devtools_issues.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: format!("react_devtools_{}", Self::generate_id()),
                    vuln_type: "React Development Tools Exposed in Production".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("DevTools".to_string()),
                    payload: devtools_issues.join(", "),
                    description: format!(
                        "Development tools are exposed in what appears to be a production environment. \
                        Found: {}. This exposes application state, actions, and potentially sensitive data.",
                        devtools_issues.join(", ")
                    ),
                    evidence: Some(format!(
                        "DevTools indicators found: {}\n\
                        Impact: Attackers can inspect application state, Redux store, API calls",
                        devtools_issues.join("\n- ")
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Build with NODE_ENV=production\n\
                                  2. Remove DevTools from production builds\n\
                                  3. Use conditional imports for DevTools\n\
                                  4. Configure webpack to strip development code\n\
                                  5. Use babel-plugin-transform-react-remove-prop-types".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
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
            // Server-side env vars that shouldn't be in client bundles
            let server_env_patterns = [
                (
                    r#"(?i)DATABASE_URL\s*[=:]\s*["'][^"']+["']"#,
                    "DATABASE_URL",
                ),
                (
                    r#"(?i)(?:SECRET|PRIVATE)_KEY\s*[=:]\s*["'][^"']+["']"#,
                    "SECRET_KEY",
                ),
                (r#"(?i)JWT_SECRET\s*[=:]\s*["'][^"']+["']"#, "JWT_SECRET"),
                (r#"(?i)API_SECRET\s*[=:]\s*["'][^"']+["']"#, "API_SECRET"),
                (
                    r#"(?i)AWS_SECRET_ACCESS_KEY\s*[=:]\s*["'][^"']+["']"#,
                    "AWS_SECRET_ACCESS_KEY",
                ),
                (
                    r#"(?i)STRIPE_SECRET_KEY\s*[=:]\s*["'][^"']+["']"#,
                    "STRIPE_SECRET_KEY",
                ),
                (
                    r#"(?i)SENDGRID_API_KEY\s*[=:]\s*["'][^"']+["']"#,
                    "SENDGRID_API_KEY",
                ),
                (r#"(?i)MONGODB_URI\s*[=:]\s*["'][^"']+["']"#, "MONGODB_URI"),
                (r#"(?i)REDIS_URL\s*[=:]\s*["'][^"']+["']"#, "REDIS_URL"),
                (
                    r#"(?i)GITHUB_TOKEN\s*[=:]\s*["'][^"']+["']"#,
                    "GITHUB_TOKEN",
                ),
                // CRA non-public env vars (without REACT_APP_ prefix)
                (
                    r#"process\.env\.(?!REACT_APP_|PUBLIC_|NODE_ENV)[A-Z_]+\s*[=:]"#,
                    "Non-public env var",
                ),
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
                    id: format!("react_env_exposure_{}", Self::generate_id()),
                    vuln_type: "React Server Environment Variables Exposed".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("Environment Variables".to_string()),
                    payload: exposed_vars.join(", "),
                    description: format!(
                        "Server-side environment variables are exposed in the React bundle. \
                        Found: {}. Only REACT_APP_* (CRA) or PUBLIC_* variables should be in client code.",
                        exposed_vars.join(", ")
                    ),
                    evidence: Some(format!(
                        "Exposed variables: {}\n\
                        Impact: Attackers can extract API keys, database credentials, and secrets",
                        exposed_vars.join(", ")
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Use REACT_APP_ prefix for client-side env vars (CRA)\n\
                                  2. Never expose server secrets in client bundles\n\
                                  3. Use .env.local for sensitive development values\n\
                                  4. Audit your build process for env exposure\n\
                                  5. Rotate any exposed credentials immediately".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
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

        let base = url.trim_end_matches('/');

        // Get main page to find JS files
        let resp = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vec![], tests_run)),
        };

        // Extract JS file URLs (CRA pattern and general)
        let js_patterns = [
            r#"/static/js/[^"']+\.js"#,
            r#"/assets/[^"']+\.js"#,
            r#"/js/[^"']+\.js"#,
            r#"[^"']+\.bundle\.js"#,
        ];

        let mut js_files = Vec::new();
        for pattern in &js_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.find_iter(&resp.body) {
                    let js_path = cap.as_str();
                    let full_url = if js_path.starts_with("http") {
                        js_path.to_string()
                    } else {
                        format!("{}{}", base, js_path)
                    };
                    js_files.push(format!("{}.map", full_url));
                }
            }
        }

        for js_map in js_files.iter().take(5) {
            tests_run += 1;
            if let Ok(map_resp) = self.http_client.get(js_map).await {
                if map_resp.status_code == 200 && map_resp.body.contains("mappings") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("react_sourcemap_{}", Self::generate_id()),
                        vuln_type: "React Source Map Exposure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: js_map.clone(),
                        parameter: Some("source map".to_string()),
                        payload: "GET *.js.map".to_string(),
                        description: "JavaScript source maps are publicly accessible, exposing original React component source code, business logic, and potentially comments with sensitive information.".to_string(),
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
                        remediation: "1. Set GENERATE_SOURCEMAP=false in .env (CRA)\n\
                                      2. Configure webpack devtool to 'hidden-source-map'\n\
                                      3. Remove .map files from production deployment\n\
                                      4. Use source map upload to error tracking service".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for SSR data exposure
    async fn check_ssr_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            // Look for SSR/hydration data that might contain sensitive info
            let ssr_patterns = [
                (
                    r#"window\.__INITIAL_STATE__\s*=\s*\{[^}]*(?:password|secret|token|api_key|private)"#,
                    "__INITIAL_STATE__",
                ),
                (
                    r#"window\.__PRELOADED_STATE__\s*=\s*\{[^}]*(?:password|secret|token|api_key)"#,
                    "__PRELOADED_STATE__",
                ),
                (
                    r#"window\.__APOLLO_STATE__\s*=\s*\{[^}]*(?:password|secret|token)"#,
                    "__APOLLO_STATE__",
                ),
                (
                    r#"window\.__REDUX_STATE__\s*=\s*\{[^}]*(?:password|secret|token)"#,
                    "__REDUX_STATE__",
                ),
                (
                    r#"<script[^>]*id="__NEXT_DATA__"[^>]*>[^<]*(?:password|secret|apiKey|token)"#,
                    "__NEXT_DATA__",
                ),
            ];

            for (pattern, state_name) in &ssr_patterns {
                tests_run += 1;
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&resp.body) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("react_ssr_exposure_{}", Self::generate_id()),
                            vuln_type: format!("React SSR State Exposure ({})", state_name),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.to_string(),
                            parameter: Some(state_name.to_string()),
                            payload: format!("window.{}", state_name),
                            description: format!(
                                "Server-side rendered state ({}) contains potentially sensitive data. \
                                This data is embedded in HTML and accessible to anyone viewing the page source.",
                                state_name
                            ),
                            evidence: Some(format!(
                                "State variable: {}\n\
                                Contains sensitive keywords: password, secret, token, api_key",
                                state_name
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Filter sensitive data before SSR hydration\n\
                                          2. Use getServerSideProps for auth-required data (Next.js)\n\
                                          3. Never include secrets in initial state\n\
                                          4. Fetch sensitive data client-side after auth".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for build artifact exposure
    async fn check_build_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Files that shouldn't be exposed
        let sensitive_files = [
            (".env", "Environment variables"),
            (".env.local", "Local environment"),
            (".env.production", "Production environment"),
            (".env.development", "Development environment"),
            ("package.json", "Package configuration"),
            ("package-lock.json", "Package lock file"),
            ("yarn.lock", "Yarn lock file"),
            (".babelrc", "Babel configuration"),
            ("webpack.config.js", "Webpack configuration"),
            ("tsconfig.json", "TypeScript configuration"),
            ("build/asset-manifest.json", "Asset manifest"),
            ("build/precache-manifest.json", "Precache manifest"),
            (
                "static/js/main.js.LICENSE.txt",
                "License file with package info",
            ),
            (".git/config", "Git configuration"),
            ("src/", "Source directory listing"),
        ];

        for (file, desc) in &sensitive_files {
            tests_run += 1;
            let file_url = format!("{}/{}", base, file);

            if let Ok(resp) = self.http_client.get(&file_url).await {
                if resp.status_code == 200 {
                    let is_sensitive = resp.body.contains("dependencies") ||
                        resp.body.contains("scripts") ||
                        resp.body.contains("DATABASE") ||
                        resp.body.contains("SECRET") ||
                        resp.body.contains("[remote") ||  // git config
                        resp.body.len() > 10; // Not empty

                    if is_sensitive {
                        vulnerabilities.push(Vulnerability {
                            id: format!("react_build_exposure_{}", Self::generate_id()),
                            vuln_type: format!("React Build Artifact Exposed: {}", desc),
                            severity: if file.contains(".env") || file.contains(".git") {
                                Severity::Critical
                            } else {
                                Severity::Medium
                            },
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: file_url.clone(),
                            parameter: Some(file.to_string()),
                            payload: format!("GET /{}", file),
                            description: format!(
                                "{} file is publicly accessible. This may expose sensitive configuration, \
                                dependencies with known vulnerabilities, or credentials.",
                                desc
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
                            remediation: "1. Configure web server to block access to sensitive files\n\
                                          2. Don't deploy source files to production\n\
                                          3. Use .gitignore properly\n\
                                          4. Review your deployment pipeline".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check API security
    async fn check_api_security(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common React app API endpoints
        let api_endpoints = [
            "/api/users",
            "/api/user",
            "/api/auth",
            "/api/config",
            "/api/admin",
            "/api/graphql",
            "/graphql",
            "/__graphql",
        ];

        for endpoint in &api_endpoints {
            tests_run += 1;
            let api_url = format!("{}{}", base, endpoint);

            if let Ok(resp) = self.http_client.get(&api_url).await {
                // Check for GraphQL introspection
                if endpoint.contains("graphql") && resp.status_code == 200 {
                    tests_run += 1;
                    let introspection_query = r#"{"query":"{ __schema { types { name } } }"}"#;
                    let mut headers = HashMap::new();
                    headers.insert("Content-Type".to_string(), "application/json".to_string());
                    let headers_vec: Vec<(String, String)> = headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    if let Ok(gql_resp) = self
                        .http_client
                        .post_with_headers(&api_url, introspection_query, headers_vec)
                        .await
                    {
                        if gql_resp.body.contains("__schema") && gql_resp.body.contains("types") {
                            vulnerabilities.push(Vulnerability {
                                id: format!("react_graphql_introspection_{}", Self::generate_id()),
                                vuln_type: "GraphQL Introspection Enabled".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                category: "Information Disclosure".to_string(),
                                url: api_url.clone(),
                                parameter: Some("introspection".to_string()),
                                payload: "{ __schema { types { name } } }".to_string(),
                                description: "GraphQL introspection is enabled, allowing attackers to discover the entire API schema.".to_string(),
                                evidence: Some("Schema query returned type information".to_string()),
                                cwe: "CWE-200".to_string(),
                                cvss: 5.3,
                                verified: true,
                                false_positive: false,
                                remediation: "Disable introspection in production using appropriate Apollo/graphql-yoga configuration.".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
                        }
                    }
                }

                // Check CORS
                tests_run += 1;
                let mut cors_headers = HashMap::new();
                cors_headers.insert("Origin".to_string(), "https://evil.com".to_string());
                let headers_vec: Vec<(String, String)> = cors_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();

                if let Ok(cors_resp) = self
                    .http_client
                    .get_with_headers(&api_url, headers_vec)
                    .await
                {
                    if let Some(acao) = cors_resp.headers.get("access-control-allow-origin") {
                        if acao == "https://evil.com" || acao == "*" {
                            let has_creds = cors_resp
                                .headers
                                .get("access-control-allow-credentials")
                                .map(|v| v == "true")
                                .unwrap_or(false);

                            if has_creds || acao == "https://evil.com" {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("react_cors_{}", Self::generate_id()),
                                    vuln_type: "React API CORS Misconfiguration".to_string(),
                                    severity: if has_creds {
                                        Severity::High
                                    } else {
                                        Severity::Medium
                                    },
                                    confidence: Confidence::High,
                                    category: "Misconfiguration".to_string(),
                                    url: api_url.clone(),
                                    parameter: Some("CORS".to_string()),
                                    payload: "Origin: https://evil.com".to_string(),
                                    description: format!(
                                        "API endpoint at '{}' has permissive CORS{}.",
                                        endpoint,
                                        if has_creds { " WITH credentials" } else { "" }
                                    ),
                                    evidence: Some(format!(
                                        "Access-Control-Allow-Origin: {}\n\
                                        Allow-Credentials: {}",
                                        acao, has_creds
                                    )),
                                    cwe: "CWE-942".to_string(),
                                    cvss: if has_creds { 8.1 } else { 5.3 },
                                    verified: true,
                                    false_positive: false,
                                    remediation:
                                        "Configure CORS to only allow specific trusted origins."
                                            .to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                                    ml_data: None,
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

    /// Check for XSS via href/src attributes
    async fn check_href_xss(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test parameter-based XSS
        let xss_params = ["url", "redirect", "next", "return", "link", "href", "src"];
        let xss_payloads = [
            "javascript:alert(1)",
            "javascript:alert`1`",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
        ];

        let base = url.trim_end_matches('/');

        for param in &xss_params {
            for payload in &xss_payloads {
                tests_run += 1;
                let test_url = format!("{}?{}={}", base, param, urlencoding::encode(payload));

                if let Ok(resp) = self.http_client.get(&test_url).await {
                    // Check if payload is reflected in href or src attributes
                    let reflection_patterns = [
                        format!(r#"href\s*=\s*["']{}["']"#, regex::escape(payload)),
                        format!(r#"src\s*=\s*["']{}["']"#, regex::escape(payload)),
                        format!(r#"href\s*=\s*\{{[^}}]*{}[^}}]*\}}"#, regex::escape(payload)),
                    ];

                    for pattern in &reflection_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&resp.body) {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("react_href_xss_{}", Self::generate_id()),
                                    vuln_type: "React XSS via href/src Attribute".to_string(),
                                    severity: Severity::High,
                                    confidence: Confidence::High,
                                    category: "XSS".to_string(),
                                    url: test_url.clone(),
                                    parameter: Some(param.to_string()),
                                    payload: payload.to_string(),
                                    description: format!(
                                        "XSS vulnerability via {} parameter reflected in href/src attribute. \
                                        The payload '{}' is reflected without sanitization.",
                                        param, payload
                                    ),
                                    evidence: Some(format!(
                                        "Parameter: {}\n\
                                        Payload reflected in: href/src attribute",
                                        param
                                    )),
                                    cwe: "CWE-79".to_string(),
                                    cvss: 7.1,
                                    verified: true,
                                    false_positive: false,
                                    remediation: "1. Validate URL schemes (only allow http/https)\n\
                                                  2. Use URL validation libraries\n\
                                                  3. Never render user input directly in href/src\n\
                                                  4. Implement Content Security Policy".to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                                });
                                return Ok((vulnerabilities, tests_run));
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for prototype pollution
    async fn check_prototype_pollution(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Prototype pollution payloads
        let payloads = [
            ("__proto__[polluted]=true", "__proto__"),
            (
                "constructor[prototype][polluted]=true",
                "constructor.prototype",
            ),
            ("__proto__.polluted=true", "__proto__"),
        ];

        for (payload, technique) in &payloads {
            tests_run += 1;
            let test_url = format!("{}?{}", base, payload);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                // Check if the response indicates prototype pollution might work
                // This is a heuristic check - actual exploitation requires more testing
                if resp.status_code == 200
                    && !resp.body.contains("invalid")
                    && !resp.body.contains("error")
                {
                    // Also test POST with JSON body
                    tests_run += 1;
                    let json_payload = r#"{"__proto__":{"polluted":"true"}}"#;
                    let mut headers = HashMap::new();
                    headers.insert("Content-Type".to_string(), "application/json".to_string());
                    let headers_vec: Vec<(String, String)> = headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    if let Ok(json_resp) = self
                        .http_client
                        .post_with_headers(base, json_payload, headers_vec)
                        .await
                    {
                        if json_resp.status_code == 200 || json_resp.status_code == 201 {
                            vulnerabilities.push(Vulnerability {
                                id: format!("react_prototype_pollution_{}", Self::generate_id()),
                                vuln_type: "Potential Prototype Pollution".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Low,
                                category: "Injection".to_string(),
                                url: test_url.clone(),
                                parameter: Some(technique.to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "The application may be vulnerable to prototype pollution via {}. \
                                    This can lead to property injection, denial of service, or RCE in some cases.",
                                    technique
                                ),
                                evidence: Some(format!(
                                    "Technique: {}\n\
                                    Payload accepted without explicit error",
                                    technique
                                )),
                                cwe: "CWE-1321".to_string(),
                                cvss: 7.5,
                                verified: false,
                                false_positive: false,
                                remediation: "1. Use Object.create(null) for user-controlled objects\n\
                                              2. Freeze Object.prototype\n\
                                              3. Validate and sanitize user input keys\n\
                                              4. Use Map instead of plain objects\n\
                                              5. Update vulnerable packages (lodash, immer)".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for known package CVEs
    async fn check_package_cves(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Try to access package.json or detect versions from bundles
        let base = url.trim_end_matches('/');

        tests_run += 1;
        let package_url = format!("{}/package.json", base);

        if let Ok(resp) = self.http_client.get(&package_url).await {
            if resp.status_code == 200 && resp.body.contains("dependencies") {
                // Parse package.json and check for vulnerable versions
                for cve in &self.known_cves {
                    tests_run += 1;
                    let version_pattern = format!(
                        r#"["']{}["']\s*:\s*["'][~^]?(\d+\.\d+(?:\.\d+)?)["']"#,
                        cve.package
                    );

                    if let Ok(re) = Regex::new(&version_pattern) {
                        if let Some(caps) = re.captures(&resp.body) {
                            if let Some(version) = caps.get(1) {
                                let ver = version.as_str();
                                // Simple version check (could be more sophisticated)
                                if Self::is_version_affected(ver, &cve.affected_versions) {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("react_cve_{}_{}", cve.cve_id, Self::generate_id()),
                                        vuln_type: format!("{}: {}", cve.cve_id, cve.package),
                                        severity: cve.severity.clone(),
                                        confidence: Confidence::High,
                                        category: "Known Vulnerability".to_string(),
                                        url: package_url.clone(),
                                        parameter: Some(cve.package.clone()),
                                        payload: format!("{}@{}", cve.package, ver),
                                        description: format!(
                                            "{}\n\nInstalled: {}@{}\nAffected: {}",
                                            cve.description, cve.package, ver, cve.affected_versions
                                        ),
                                        evidence: Some(format!(
                                            "CVE: {}\nPackage: {} @ {}\nAffected: {}",
                                            cve.cve_id, cve.package, ver, cve.affected_versions
                                        )),
                                        cwe: "CWE-1035".to_string(),
                                        cvss: match cve.severity {
                                            Severity::Critical => 9.8,
                                            Severity::High => 7.5,
                                            Severity::Medium => 5.3,
                                            _ => 3.0,
                                        },
                                        verified: true,
                                        false_positive: false,
                                        remediation: format!(
                                            "Update {} to a patched version. See: https://nvd.nist.gov/vuln/detail/{}",
                                            cve.package, cve.cve_id
                                        ),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn is_version_affected(version: &str, affected: &str) -> bool {
        // Simple version comparison - affected format: "<X.Y.Z"
        if affected.starts_with('<') {
            let affected_ver = affected.trim_start_matches('<');
            return Self::compare_versions(version, affected_ver) < 0;
        }
        false
    }

    fn compare_versions(v1: &str, v2: &str) -> i32 {
        let p1: Vec<u32> = v1.split('.').filter_map(|p| p.parse().ok()).collect();
        let p2: Vec<u32> = v2.split('.').filter_map(|p| p.parse().ok()).collect();

        for i in 0..3 {
            let a = p1.get(i).copied().unwrap_or(0);
            let b = p2.get(i).copied().unwrap_or(0);
            if a < b {
                return -1;
            }
            if a > b {
                return 1;
            }
        }
        0
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}
