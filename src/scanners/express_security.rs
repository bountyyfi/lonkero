// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct ExpressSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: HashMap<String, Vec<ExpressCVE>>,
}

#[derive(Clone)]
struct ExpressCVE {
    cve_id: String,
    package: String,
    affected_versions: String,
    severity: Severity,
    description: String,
}

impl ExpressSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known Express/Node.js CVEs
    fn build_cve_database() -> HashMap<String, Vec<ExpressCVE>> {
        let mut db = HashMap::new();

        let cves = vec![
            // Express core
            ExpressCVE {
                cve_id: "CVE-2024-29041".to_string(),
                package: "express".to_string(),
                affected_versions: "<4.19.2".to_string(),
                severity: Severity::Medium,
                description: "Open redirect vulnerability in Express res.redirect()".to_string(),
            },
            ExpressCVE {
                cve_id: "CVE-2022-24999".to_string(),
                package: "qs".to_string(),
                affected_versions: "<6.10.3".to_string(),
                severity: Severity::High,
                description: "Prototype pollution in qs (query string parser)".to_string(),
            },
            // Body parser
            ExpressCVE {
                cve_id: "CVE-2022-24434".to_string(),
                package: "dicer".to_string(),
                affected_versions: "<0.3.1".to_string(),
                severity: Severity::High,
                description: "Denial of Service in dicer (used by busboy/multer)".to_string(),
            },
            // Mongoose
            ExpressCVE {
                cve_id: "CVE-2023-3696".to_string(),
                package: "mongoose".to_string(),
                affected_versions: "<7.3.4".to_string(),
                severity: Severity::Critical,
                description: "Prototype pollution in mongoose leading to RCE".to_string(),
            },
            // jsonwebtoken
            ExpressCVE {
                cve_id: "CVE-2022-23529".to_string(),
                package: "jsonwebtoken".to_string(),
                affected_versions: "<9.0.0".to_string(),
                severity: Severity::Critical,
                description: "JWT algorithm confusion allowing token forgery".to_string(),
            },
            ExpressCVE {
                cve_id: "CVE-2022-23540".to_string(),
                package: "jsonwebtoken".to_string(),
                affected_versions: "<9.0.0".to_string(),
                severity: Severity::High,
                description: "Insecure default algorithm in jsonwebtoken".to_string(),
            },
            // Lodash
            ExpressCVE {
                cve_id: "CVE-2021-23337".to_string(),
                package: "lodash".to_string(),
                affected_versions: "<4.17.21".to_string(),
                severity: Severity::High,
                description: "Command injection via template function".to_string(),
            },
            ExpressCVE {
                cve_id: "CVE-2020-8203".to_string(),
                package: "lodash".to_string(),
                affected_versions: "<4.17.19".to_string(),
                severity: Severity::High,
                description: "Prototype pollution in zipObjectDeep".to_string(),
            },
            // Axios
            ExpressCVE {
                cve_id: "CVE-2023-45857".to_string(),
                package: "axios".to_string(),
                affected_versions: "<1.6.0".to_string(),
                severity: Severity::High,
                description: "SSRF via crafted URL in axios".to_string(),
            },
            // Socket.io
            ExpressCVE {
                cve_id: "CVE-2022-25896".to_string(),
                package: "socket.io-parser".to_string(),
                affected_versions: "<4.2.1".to_string(),
                severity: Severity::Critical,
                description: "Insufficient validation leading to DoS in socket.io".to_string(),
            },
            // Node.js core
            ExpressCVE {
                cve_id: "CVE-2024-22019".to_string(),
                package: "nodejs".to_string(),
                affected_versions: "<20.11.0".to_string(),
                severity: Severity::High,
                description: "HTTP request smuggling via malformed headers".to_string(),
            },
            ExpressCVE {
                cve_id: "CVE-2023-44487".to_string(),
                package: "nodejs".to_string(),
                affected_versions: "<20.8.1".to_string(),
                severity: Severity::High,
                description: "HTTP/2 Rapid Reset Attack (DoS)".to_string(),
            },
        ];

        db.insert("express".to_string(), cves);
        db
    }

    /// Main scan function
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Check license
        if !crate::license::has_feature("cms_security") {
            debug!("Express security scanner requires Personal+ license");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, detect if this is an Express application
        let (is_express, version_info) = self.detect_express(url).await;
        tests_run += 1;

        if !is_express {
            debug!("Target does not appear to be an Express.js application");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Express] Detected Express.js application, running security checks");

        // Check for X-Powered-By header
        let (header_vulns, header_tests) = self.check_powered_by_header(url).await;
        vulnerabilities.extend(header_vulns);
        tests_run += header_tests;

        // Check for development mode / stack traces
        let (dev_vulns, dev_tests) = self.check_development_mode(url).await;
        vulnerabilities.extend(dev_vulns);
        tests_run += dev_tests;

        // Check for missing security headers
        let (security_vulns, security_tests) = self.check_security_headers(url).await;
        vulnerabilities.extend(security_vulns);
        tests_run += security_tests;

        // Check for exposed API documentation
        let (api_vulns, api_tests) = self.check_api_documentation(url).await;
        vulnerabilities.extend(api_vulns);
        tests_run += api_tests;

        // Check for exposed configuration files
        let (config_vulns, config_tests) = self.check_config_exposure(url).await;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        // Check for source map exposure
        let (sourcemap_vulns, sourcemap_tests) = self.check_source_maps(url).await;
        vulnerabilities.extend(sourcemap_vulns);
        tests_run += sourcemap_tests;

        // Check for process manager exposure
        let (pm_vulns, pm_tests) = self.check_process_manager(url).await;
        vulnerabilities.extend(pm_vulns);
        tests_run += pm_tests;

        // Check for prototype pollution
        let (proto_vulns, proto_tests) = self.check_prototype_pollution(url).await;
        vulnerabilities.extend(proto_vulns);
        tests_run += proto_tests;

        // Check CORS configuration
        let (cors_vulns, cors_tests) = self.check_cors_config(url).await;
        vulnerabilities.extend(cors_vulns);
        tests_run += cors_tests;

        // Check for session/cookie issues
        let (session_vulns, session_tests) = self.check_session_security(url).await;
        vulnerabilities.extend(session_vulns);
        tests_run += session_tests;

        // Check for debug endpoints
        let (debug_vulns, debug_tests) = self.check_debug_endpoints(url).await;
        vulnerabilities.extend(debug_vulns);
        tests_run += debug_tests;

        // Check for known CVEs based on detected packages
        if let Some(ref info) = version_info {
            let (cve_vulns, cve_tests) = self.check_package_cves(url, info).await;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!(
            "[Express] Completed: {} vulnerabilities found in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is an Express application
    async fn detect_express(&self, url: &str) -> (bool, Option<PackageInfo>) {
        let mut is_express = false;
        let mut package_info: Option<PackageInfo> = None;

        // Check main page for Express indicators
        if let Ok(response) = self.http_client.get(url).await {
            // Check X-Powered-By header
            if let Some(powered_by) = response.headers.get("x-powered-by") {
                let value = powered_by.as_str();
                if value.to_lowercase().contains("express") {
                    is_express = true;
                    // Try to extract version
                    if let Some(v) = Self::extract_express_version(value) {
                        package_info = Some(PackageInfo {
                            express_version: Some(v),
                            ..Default::default()
                        });
                    }
                }
            }

            // Check for Express-specific error responses
            let body = &response.body;
            if body.contains("Cannot GET")
                || body.contains("Cannot POST")
                || body.contains("Express")
                || body.contains("node_modules")
            {
                is_express = true;
            }

            // Check for common Express patterns
            let express_indicators = [
                "express-session",
                "connect.sid",
                "express:",
                "node_modules/express",
            ];

            for indicator in &express_indicators {
                if body.contains(indicator) {
                    is_express = true;
                    break;
                }
            }
        }

        // Check for Express-specific paths
        let express_paths = [
            "/api",
            "/api/v1",
            "/graphql",
            "/socket.io/",
            "/health",
            "/status",
        ];

        for path in &express_paths {
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code != 404 {
                    // Check response headers again
                    if let Some(powered_by) = response.headers.get("x-powered-by") {
                        let value = powered_by.as_str();
                        if value.to_lowercase().contains("express") {
                            is_express = true;
                        }
                    }
                }
            }
        }

        (is_express, package_info)
    }

    /// Extract Express version from header
    fn extract_express_version(header: &str) -> Option<String> {
        // Pattern: Express/4.18.2 or just Express
        if let Ok(re) = Regex::new(r"[Ee]xpress/?(\d+\.\d+\.\d+)?") {
            if let Some(caps) = re.captures(header) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
        None
    }

    /// Check for X-Powered-By header disclosure
    async fn check_powered_by_header(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        if let Ok(response) = self.http_client.get(url).await {
            if let Some(powered_by) = response.headers.get("x-powered-by") {
                let value = powered_by.as_str();
                vulnerabilities.push(Vulnerability {
                    id: format!("express_powered_by_{}", Self::generate_id()),
                    vuln_type: "Server Technology Disclosure".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("X-Powered-By".to_string()),
                    payload: value.to_string(),
                    description: format!(
                        "The X-Powered-By header reveals the server technology: '{}'\n\n\
                        This information helps attackers:\n\
                        - Identify specific framework vulnerabilities\n\
                        - Target known Express.js exploits\n\
                        - Fingerprint the technology stack",
                        value
                    ),
                    evidence: Some(format!("X-Powered-By: {}", value)),
                    cwe: "CWE-200".to_string(),
                    cvss: 3.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Disable the X-Powered-By header using Helmet.js:\n\
                                  ```javascript\n\
                                  const helmet = require('helmet');\n\
                                  app.use(helmet());\n\
                                  ```\n\
                                  Or manually:\n\
                                  ```javascript\n\
                                  app.disable('x-powered-by');\n\
                                  ```"
                    .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_data: None,
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for development mode exposure
    async fn check_development_mode(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test paths that might trigger errors
        let error_paths = [
            "/api/nonexistent-endpoint-12345",
            "/undefined-route-test",
            "/%00",
            "/api?__proto__[test]=1",
            "/api/users/../../../../etc/passwd",
        ];

        for path in &error_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                let body = &response.body;

                // Check for stack trace indicators
                let stack_indicators = [
                    "at Function.",
                    "at Object.",
                    "at Module.",
                    "at node:",
                    "/node_modules/",
                    "Error:",
                    "TypeError:",
                    "ReferenceError:",
                    "SyntaxError:",
                    "at process.",
                    ".js:",
                    "stack\":",
                    "\"stack\"",
                ];

                let mut found_indicators: Vec<&str> = Vec::new();
                for indicator in &stack_indicators {
                    if body.contains(indicator) {
                        found_indicators.push(indicator);
                    }
                }

                // Check for environment variable exposure
                let env_patterns = [
                    ("NODE_ENV", "development"),
                    ("DATABASE_URL", ""),
                    ("SECRET", ""),
                    ("API_KEY", ""),
                    ("JWT_SECRET", ""),
                    ("MONGO", ""),
                    ("REDIS", ""),
                ];

                let mut exposed_env: Vec<&str> = Vec::new();
                for (var, _) in &env_patterns {
                    if body.contains(var) {
                        exposed_env.push(var);
                    }
                }

                if found_indicators.len() >= 2 {
                    let severity = if !exposed_env.is_empty() {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("express_dev_mode_{}", Self::generate_id()),
                        vuln_type: "Express Development Mode Enabled".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Express.js is running in development mode or has verbose error handling enabled.\n\
                            Stack traces are exposed which reveal:\n\
                            - Internal file paths and structure\n\
                            - Dependency versions\n\
                            - Function names and code flow\n\
                            - Potentially sensitive environment variables\n\n\
                            Stack indicators found: {:?}\n\
                            Environment variables exposed: {:?}",
                            found_indicators, exposed_env
                        ),
                        evidence: Some(format!(
                            "Indicators: {}\n\
                            Environment vars: {}",
                            found_indicators.join(", "),
                            if exposed_env.is_empty() { "None visible".to_string() } else { exposed_env.join(", ") }
                        )),
                        cwe: "CWE-209".to_string(),
                        cvss: if !exposed_env.is_empty() { 7.5 } else { 5.5 },
                        verified: true,
                        false_positive: false,
                        remediation: "1. Set NODE_ENV=production in production\n\
                                      2. Use custom error handler that hides stack traces:\n\
                                      ```javascript\n\
                                      app.use((err, req, res, next) => {\n\
                                        console.error(err.stack);\n\
                                        res.status(500).json({ error: 'Internal Server Error' });\n\
                                      });\n\
                                      ```\n\
                                      3. Never expose environment variables in responses".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });

                    break; // Found dev mode indicator
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for missing security headers
    async fn check_security_headers(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        if let Ok(response) = self.http_client.get(url).await {
            let mut missing_headers: Vec<(&str, &str)> = Vec::new();

            // Essential security headers
            let security_headers = [
                (
                    "X-Content-Type-Options",
                    "nosniff",
                    "Prevents MIME-type sniffing attacks",
                ),
                (
                    "X-Frame-Options",
                    "DENY|SAMEORIGIN",
                    "Prevents clickjacking attacks",
                ),
                (
                    "Strict-Transport-Security",
                    "",
                    "Enforces HTTPS connections",
                ),
                ("X-XSS-Protection", "1; mode=block", "Legacy XSS protection"),
                (
                    "Content-Security-Policy",
                    "",
                    "Prevents XSS and injection attacks",
                ),
                (
                    "Referrer-Policy",
                    "",
                    "Controls referrer information leakage",
                ),
                ("Permissions-Policy", "", "Controls browser feature access"),
            ];

            for (header, _, desc) in &security_headers {
                let header_lower = header.to_lowercase();
                let has_header = response
                    .headers
                    .keys()
                    .any(|k| k.as_str().to_lowercase() == header_lower);

                if !has_header {
                    missing_headers.push((header, desc));
                }
            }

            if !missing_headers.is_empty() {
                let severity = if missing_headers.iter().any(|(h, _)| {
                    *h == "Content-Security-Policy" || *h == "Strict-Transport-Security"
                }) {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let header_list: Vec<String> = missing_headers
                    .iter()
                    .map(|(h, d)| format!("- {}: {}", h, d))
                    .collect();

                vulnerabilities.push(Vulnerability {
                    id: format!("express_missing_headers_{}", Self::generate_id()),
                    vuln_type: "Missing Security Headers".to_string(),
                    severity,
                    confidence: Confidence::High,
                    category: "Security Misconfiguration".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: "Security headers check".to_string(),
                    description: format!(
                        "The following security headers are missing:\n\n{}\n\n\
                        Missing security headers make the application vulnerable to various attacks \
                        including clickjacking, MIME-type confusion, and cross-site scripting.",
                        header_list.join("\n")
                    ),
                    evidence: Some(format!(
                        "Missing headers: {}",
                        missing_headers.iter().map(|(h, _)| *h).collect::<Vec<_>>().join(", ")
                    )),
                    cwe: "CWE-693".to_string(),
                    cvss: 4.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Install and configure Helmet.js:\n\
                                  ```javascript\n\
                                  const helmet = require('helmet');\n\
                                  app.use(helmet());\n\
                                  \n\
                                  // Or with custom options:\n\
                                  app.use(helmet({\n\
                                    contentSecurityPolicy: {\n\
                                      directives: {\n\
                                        defaultSrc: [\"'self'\"],\n\
                                        scriptSrc: [\"'self'\"],\n\
                                      },\n\
                                    },\n\
                                  }));\n\
                                  ```".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for exposed API documentation
    async fn check_api_documentation(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let api_doc_paths = [
            ("/swagger", "Swagger UI", "API documentation"),
            ("/swagger-ui", "Swagger UI", "API documentation"),
            ("/swagger-ui.html", "Swagger UI HTML", "API documentation"),
            ("/api-docs", "API Docs", "OpenAPI specification"),
            ("/api/docs", "API Docs", "OpenAPI specification"),
            ("/api/swagger", "Swagger", "API documentation"),
            ("/docs", "Documentation", "API documentation"),
            ("/graphql", "GraphQL Endpoint", "GraphQL API"),
            ("/graphiql", "GraphiQL", "GraphQL IDE"),
            ("/graphql/playground", "GraphQL Playground", "GraphQL IDE"),
            ("/playground", "Playground", "GraphQL IDE"),
            ("/altair", "Altair", "GraphQL client"),
            ("/voyager", "Voyager", "GraphQL schema viewer"),
            ("/api/explorer", "API Explorer", "API testing interface"),
            ("/explorer", "Explorer", "API explorer"),
        ];

        for (path, name, desc) in &api_doc_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    // Check for API documentation indicators
                    let is_swagger = body.contains("swagger")
                        || body.contains("openapi")
                        || body.contains("Swagger")
                        || body.contains("OpenAPI");
                    let is_graphql = body.contains("graphql")
                        || body.contains("GraphQL")
                        || body.contains("__schema")
                        || body.contains("query");
                    let has_endpoints = body.contains("\"paths\"")
                        || body.contains("\"endpoints\"")
                        || body.contains("\"routes\"");

                    if is_swagger || is_graphql || has_endpoints {
                        let severity = if path.contains("graphql")
                            || path.contains("graphiql")
                            || path.contains("playground")
                        {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(Vulnerability {
                            id: format!("express_api_docs_{}", Self::generate_id()),
                            vuln_type: format!("{} Exposed", name),
                            severity,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} ({}) is publicly accessible at {}.\n\n\
                                This exposes:\n\
                                - Complete API structure and endpoints\n\
                                - Request/response schemas\n\
                                - Authentication requirements\n\
                                - Internal business logic\n\
                                {}",
                                name,
                                desc,
                                path,
                                if is_graphql {
                                    "\n- GraphQL introspection allows full schema discovery"
                                } else {
                                    ""
                                }
                            ),
                            evidence: Some(format!(
                                "URL: {}\n\
                                Type: {}\n\
                                Response size: {} bytes",
                                test_url,
                                if is_graphql {
                                    "GraphQL"
                                } else {
                                    "REST/OpenAPI"
                                },
                                body.len()
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: if is_graphql { 6.5 } else { 5.0 },
                            verified: true,
                            false_positive: false,
                            remediation: format!(
                                "1. Disable {} in production\n\
                                2. Add authentication to the documentation endpoint\n\
                                3. For GraphQL, disable introspection:\n\
                                ```javascript\n\
                                const server = new ApolloServer({{\n\
                                  introspection: process.env.NODE_ENV !== 'production',\n\
                                }});\n\
                                ```",
                                name
                            ),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for exposed configuration files
    async fn check_config_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let config_files = [
            ("/package.json", "Package.json", Severity::Medium),
            ("/package-lock.json", "Package-lock.json", Severity::Medium),
            ("/yarn.lock", "Yarn lockfile", Severity::Low),
            ("/.env", "Environment file", Severity::Critical),
            ("/.env.local", "Local environment file", Severity::Critical),
            (
                "/.env.development",
                "Development environment",
                Severity::Critical,
            ),
            (
                "/.env.production",
                "Production environment",
                Severity::Critical,
            ),
            ("/config.json", "Config JSON", Severity::High),
            ("/config.js", "Config JS", Severity::High),
            ("/config/default.json", "Default config", Severity::High),
            (
                "/config/production.json",
                "Production config",
                Severity::High,
            ),
            ("/.npmrc", "NPM config", Severity::High),
            ("/.yarnrc", "Yarn config", Severity::Medium),
            ("/tsconfig.json", "TypeScript config", Severity::Low),
            ("/nodemon.json", "Nodemon config", Severity::Low),
            ("/pm2.config.js", "PM2 config", Severity::Medium),
            ("/ecosystem.config.js", "PM2 ecosystem", Severity::Medium),
            ("/.git/config", "Git config", Severity::High),
            ("/.gitignore", "Gitignore", Severity::Low),
            ("/Dockerfile", "Dockerfile", Severity::Medium),
            ("/docker-compose.yml", "Docker Compose", Severity::Medium),
        ];

        for (path, name, severity) in &config_files {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.len() > 10 {
                    let body = &response.body;

                    // Validate it's actually the expected file type
                    let is_valid = if path.contains("package") {
                        body.contains("\"name\"") || body.contains("\"dependencies\"")
                    } else if path.contains(".env") {
                        body.contains("=") && !body.contains("<html")
                    } else if path.ends_with(".json") {
                        body.trim().starts_with('{') || body.trim().starts_with('[')
                    } else if path.ends_with(".js") {
                        body.contains("module.exports") || body.contains("export ")
                    } else if path.contains(".git") {
                        body.contains("[core]") || body.contains("[remote")
                    } else {
                        true
                    };

                    if is_valid {
                        // Check for exposed secrets in content
                        let mut exposed_secrets: Vec<&str> = Vec::new();
                        let secret_patterns = [
                            "password",
                            "secret",
                            "api_key",
                            "apikey",
                            "token",
                            "private_key",
                            "auth",
                            "credential",
                            "mongo",
                            "redis",
                        ];

                        for pattern in &secret_patterns {
                            if body.to_lowercase().contains(pattern) {
                                exposed_secrets.push(pattern);
                            }
                        }

                        vulnerabilities.push(Vulnerability {
                            id: format!("express_config_exposure_{}", Self::generate_id()),
                            vuln_type: format!("{} Exposed", name),
                            severity: severity.clone(),
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} file is publicly accessible.\n\n\
                                This can expose:\n\
                                - Dependency versions (for CVE targeting)\n\
                                - Internal configuration\n\
                                - Environment variables and secrets\n\
                                - Infrastructure details\n\n\
                                Sensitive patterns found: {:?}",
                                name, exposed_secrets
                            ),
                            evidence: Some({
                                let secrets_str = if exposed_secrets.is_empty() {
                                    "None visible".to_string()
                                } else {
                                    exposed_secrets.join(", ")
                                };
                                format!(
                                    "File: {}\n\
                                    Size: {} bytes\n\
                                    Secrets found: {}",
                                    path,
                                    body.len(),
                                    secrets_str
                                )
                            }),
                            cwe: "CWE-200".to_string(),
                            cvss: match severity {
                                Severity::Critical => 9.5,
                                Severity::High => 7.5,
                                Severity::Medium => 5.5,
                                _ => 3.5,
                            },
                            verified: true,
                            false_positive: false,
                            remediation: format!(
                                "1. Block access to {} in web server config:\n\
                                - Nginx: location ~ /\\.{{ deny all; }}\n\
                                - Apache: <Files \".*\"> Require all denied </Files>\n\
                                2. Move config files outside web root\n\
                                3. Use environment variables instead of config files",
                                name
                            ),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for source map exposure
    async fn check_source_maps(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Common JS bundle paths
        let js_paths = [
            "/bundle.js.map",
            "/main.js.map",
            "/app.js.map",
            "/vendor.js.map",
            "/static/js/main.js.map",
            "/static/js/bundle.js.map",
            "/dist/bundle.js.map",
            "/build/static/js/main.js.map",
            "/assets/js/app.js.map",
        ];

        for path in &js_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    // Check if it's a valid source map
                    if body.contains("\"version\"")
                        && body.contains("\"sources\"")
                        && body.contains("\"mappings\"")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: format!("express_sourcemap_{}", Self::generate_id()),
                            vuln_type: "JavaScript Source Map Exposed".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: "JavaScript source map file is publicly accessible.\n\n\
                                         Source maps expose:\n\
                                         - Original unminified source code\n\
                                         - Internal file structure\n\
                                         - Comments and documentation\n\
                                         - Business logic and algorithms\n\
                                         - Potential hardcoded secrets"
                                .to_string(),
                            evidence: Some(format!(
                                "Source map at: {}\n\
                                Size: {} bytes",
                                test_url,
                                body.len()
                            )),
                            cwe: "CWE-540".to_string(),
                            cvss: 5.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Don't generate source maps for production builds\n\
                                          2. Or upload source maps to error tracking service only\n\
                                          3. Block .map files at web server level:\n\
                                          - Nginx: location ~* \\.map$ { deny all; }"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });

                        break; // Found one source map
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for process manager exposure
    async fn check_process_manager(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let pm_paths = [
            ("/_status", "Status Endpoint"),
            ("/_health", "Health Endpoint"),
            ("/pm2", "PM2 Dashboard"),
            ("/pm2/json", "PM2 JSON API"),
            ("/process", "Process Info"),
            ("/__inspect", "Node Inspector"),
            ("/debug", "Debug Endpoint"),
            ("/_debug", "Debug Endpoint"),
            ("/metrics", "Metrics Endpoint"),
            ("/prometheus", "Prometheus Metrics"),
            ("/_metrics", "Internal Metrics"),
        ];

        for (path, name) in &pm_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    // Check for process/metrics indicators
                    let process_indicators = [
                        "memory", "cpu", "uptime", "pid", "heap", "requests", "latency", "process",
                        "version",
                    ];

                    let found_count = process_indicators
                        .iter()
                        .filter(|i| body.to_lowercase().contains(*i))
                        .count();

                    if found_count >= 2 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("express_pm_exposed_{}", Self::generate_id()),
                            vuln_type: format!("{} Exposed", name),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} at {} is publicly accessible.\n\n\
                                This may expose:\n\
                                - Memory and CPU usage\n\
                                - Process IDs\n\
                                - Server uptime\n\
                                - Internal metrics\n\
                                - Version information",
                                name, path
                            ),
                            evidence: Some(format!("Endpoint: {}", test_url)),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.0,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Add authentication to status/metrics endpoints\n\
                                          2. Restrict access by IP address\n\
                                          3. Use internal network only for monitoring"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for prototype pollution vulnerabilities
    async fn check_prototype_pollution(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Prototype pollution test payloads
        let pollution_payloads = [
            ("__proto__[test]", "proto_bracket"),
            ("__proto__.test", "proto_dot"),
            ("constructor[prototype][test]", "constructor_bracket"),
            ("constructor.prototype.test", "constructor_dot"),
        ];

        // Test via query parameters
        for (payload, payload_type) in &pollution_payloads {
            tests_run += 1;
            let test_url = format!("{}?{}=polluted", url.trim_end_matches('/'), payload);

            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check if the server crashed or returned an error that indicates processing
                if response.status_code == 500 {
                    let body = &response.body;

                    // Check for prototype pollution error signatures
                    if body.contains("prototype")
                        || body.contains("__proto__")
                        || body.contains("constructor")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: format!("express_proto_pollution_{}", Self::generate_id()),
                            vuln_type: "Potential Prototype Pollution".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(payload.to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "The application may be vulnerable to prototype pollution.\n\n\
                                Payload type: {}\n\
                                The server returned a 500 error when processing prototype pollution payload.\n\n\
                                Prototype pollution can lead to:\n\
                                - Remote Code Execution\n\
                                - Denial of Service\n\
                                - Authentication bypass\n\
                                - Property injection",
                                payload_type
                            ),
                            evidence: Some(format!(
                                "URL: {}\n\
                                Status: 500\n\
                                Payload: {}",
                                test_url, payload
                            )),
                            cwe: "CWE-1321".to_string(),
                            cvss: 8.5,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Update all dependencies (especially lodash, qs, merge-deep)\n\
                                          2. Use Object.create(null) for untrusted data\n\
                                          3. Freeze Object.prototype:\n\
                                          ```javascript\n\
                                          Object.freeze(Object.prototype);\n\
                                          ```\n\
                                          4. Validate and sanitize user input\n\
                                          5. Use Maps instead of Objects for untrusted keys".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });

                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check CORS configuration
    async fn check_cors_config(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test with different origins
        let test_origins = [
            ("https://evil.com", "arbitrary"),
            ("null", "null"),
            (url, "reflection"),
        ];

        for (origin, origin_type) in &test_origins {
            tests_run += 1;

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Origin",
                origin
                    .parse()
                    .unwrap_or_else(|_| "https://test.com".parse().unwrap()),
            );

            // Convert HeaderMap to Vec for get_with_headers
            let headers_vec: Vec<(String, String)> = headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            // Make request with Origin header
            if let Ok(response) = self.http_client.get_with_headers(url, headers_vec).await {
                if let Some(acao) = response.headers.get("access-control-allow-origin") {
                    let value = acao.as_str();
                    let is_wildcard = value == "*";
                    let reflects_origin = value == *origin;
                    let allows_null = value == "null";

                    // Check for credentials
                    let allows_credentials = response
                        .headers
                        .get("access-control-allow-credentials")
                        .map(|v| v.as_str() == "true")
                        .unwrap_or(false);

                    if (is_wildcard && allows_credentials)
                        || (reflects_origin && *origin_type == "arbitrary")
                        || allows_null
                    {
                        let severity = if allows_credentials {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(Vulnerability {
                            id: format!("express_cors_{}", Self::generate_id()),
                            vuln_type: "CORS Misconfiguration".to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "Security Misconfiguration".to_string(),
                            url: url.to_string(),
                            parameter: Some("Origin".to_string()),
                            payload: origin.to_string(),
                            description: format!(
                                "CORS is misconfigured allowing cross-origin requests.\n\n\
                                Origin tested: {}\n\
                                Access-Control-Allow-Origin: {}\n\
                                Access-Control-Allow-Credentials: {}\n\n\
                                This allows:\n\
                                - Cross-origin data theft\n\
                                - CSRF attacks\n\
                                - Session hijacking (if credentials allowed)",
                                origin, value, allows_credentials
                            ),
                            evidence: Some(format!(
                                "ACAO: {}\n\
                                Credentials: {}\n\
                                Type: {}",
                                value, allows_credentials, origin_type
                            )),
                            cwe: "CWE-942".to_string(),
                            cvss: if allows_credentials { 8.0 } else { 5.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "Configure CORS properly:\n\
                                          ```javascript\n\
                                          const cors = require('cors');\n\
                                          app.use(cors({\n\
                                            origin: ['https://trusted-site.com'],\n\
                                            credentials: true\n\
                                          }));\n\
                                          ```\n\
                                          Never use wildcard (*) with credentials."
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });

                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check session and cookie security
    async fn check_session_security(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        if let Ok(response) = self.http_client.get(url).await {
            // Check Set-Cookie headers
            // For HashMap, get returns Option<&String>
            if let Some(cookie_value) = response.headers.get("set-cookie") {
                let value = cookie_value.as_str();
                let value_lower = value.to_lowercase();

                // Check for session cookie
                let is_session = value.contains("connect.sid")
                    || value.contains("session")
                    || value.contains("sess");

                if is_session {
                    let mut issues: Vec<&str> = Vec::new();

                    if !value_lower.contains("httponly") {
                        issues.push("Missing HttpOnly flag");
                    }
                    if !value_lower.contains("secure") && url.starts_with("https") {
                        issues.push("Missing Secure flag on HTTPS");
                    }
                    if !value_lower.contains("samesite") {
                        issues.push("Missing SameSite attribute");
                    }

                    if !issues.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: format!("express_session_cookie_{}", Self::generate_id()),
                            vuln_type: "Insecure Session Cookie".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Session Management".to_string(),
                            url: url.to_string(),
                            parameter: Some("Set-Cookie".to_string()),
                            payload: value.to_string(),
                            description: format!(
                                "Session cookie has security issues:\n\n{}\n\n\
                                These issues can lead to:\n\
                                - Session hijacking via XSS (missing HttpOnly)\n\
                                - Session theft over HTTP (missing Secure)\n\
                                - CSRF attacks (missing SameSite)",
                                issues
                                    .iter()
                                    .map(|i| format!("- {}", i))
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            ),
                            evidence: Some(format!("Cookie: {}", value)),
                            cwe: "CWE-614".to_string(),
                            cvss: 5.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Configure express-session properly:\n\
                                          ```javascript\n\
                                          app.use(session({\n\
                                            cookie: {\n\
                                              secure: true,\n\
                                              httpOnly: true,\n\
                                              sameSite: 'strict',\n\
                                              maxAge: 3600000\n\
                                            }\n\
                                          }));\n\
                                          ```"
                            .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for debug endpoints
    async fn check_debug_endpoints(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let debug_paths = [
            ("/debug", "Debug"),
            ("/_debug", "Debug"),
            ("/dev", "Development"),
            ("/_dev", "Development"),
            ("/test", "Test"),
            ("/_test", "Test"),
            ("/admin", "Admin"),
            ("/_admin", "Admin"),
            ("/console", "Console"),
            ("/shell", "Shell"),
            ("/eval", "Eval"),
            ("/exec", "Exec"),
            ("/repl", "REPL"),
        ];

        for (path, name) in &debug_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    // Check for dangerous functionality
                    let danger_indicators = [
                        "eval", "exec", "spawn", "shell", "command", "query", "sql", "mongo",
                        "redis",
                    ];

                    let found: Vec<_> = danger_indicators
                        .iter()
                        .filter(|i| body.to_lowercase().contains(*i))
                        .collect();

                    if !found.is_empty() || body.len() > 50 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("express_debug_endpoint_{}", Self::generate_id()),
                            vuln_type: format!("{} Endpoint Exposed", name),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Security Misconfiguration".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} endpoint at {} is accessible.\n\n\
                                This could potentially allow:\n\
                                - Code execution\n\
                                - Database access\n\
                                - System commands\n\n\
                                Dangerous patterns found: {:?}",
                                name, path, found
                            ),
                            evidence: Some(format!("Endpoint: {}", test_url)),
                            cwe: "CWE-489".to_string(),
                            cvss: 8.5,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Remove debug endpoints from production\n\
                                          2. Add strong authentication\n\
                                          3. Restrict by IP address\n\
                                          4. Use NODE_ENV to disable in production"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for known CVEs in detected packages
    async fn check_package_cves(
        &self,
        url: &str,
        _info: &PackageInfo,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        // Try to fetch package.json for version info
        let package_url = format!("{}/package.json", url.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&package_url).await {
            if response.status_code == 200 {
                if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&response.body) {
                    // Check dependencies against CVE database
                    if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
                        if let Some(cves) = self.known_cves.get("express") {
                            for cve in cves {
                                if let Some(version) =
                                    deps.get(&cve.package).and_then(|v| v.as_str())
                                {
                                    // Simple version check - could be more sophisticated
                                    let is_vulnerable =
                                        self.is_version_vulnerable(version, &cve.affected_versions);

                                    if is_vulnerable {
                                        vulnerabilities.push(Vulnerability {
                                            id: format!(
                                                "express_cve_{}_{}",
                                                cve.cve_id.replace("-", "_"),
                                                Self::generate_id()
                                            ),
                                            vuln_type: format!("{} in {}", cve.cve_id, cve.package),
                                            severity: cve.severity.clone(),
                                            confidence: Confidence::High,
                                            category: "Known Vulnerability".to_string(),
                                            url: url.to_string(),
                                            parameter: Some(cve.package.clone()),
                                            payload: version.to_string(),
                                            description: format!(
                                                "{}\n\n\
                                                Package: {}\n\
                                                Installed version: {}\n\
                                                Affected versions: {}",
                                                cve.description,
                                                cve.package,
                                                version,
                                                cve.affected_versions
                                            ),
                                            evidence: Some(format!(
                                                "CVE: {}\n\
                                                Package: {} @ {}\n\
                                                Vulnerable: {}",
                                                cve.cve_id,
                                                cve.package,
                                                version,
                                                cve.affected_versions
                                            )),
                                            cwe: "CWE-1035".to_string(),
                                            cvss: match cve.severity {
                                                Severity::Critical => 9.8,
                                                Severity::High => 8.0,
                                                Severity::Medium => 6.0,
                                                _ => 4.0,
                                            },
                                            verified: true,
                                            false_positive: false,
                                            remediation: format!(
                                                "Update {} to a patched version:\n\
                                                npm update {}\n\
                                                or\n\
                                                yarn upgrade {}",
                                                cve.package, cve.package, cve.package
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
        }

        (vulnerabilities, tests_run)
    }

    /// Check if version is vulnerable (simple comparison)
    fn is_version_vulnerable(&self, installed: &str, affected: &str) -> bool {
        // Simple implementation - just check if affected pattern matches
        // Format: "<4.19.2" or ">=1.0.0 <2.0.0"
        let version = installed
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches('>')
            .trim_start_matches('=')
            .trim_start_matches('<');

        if let Some(max_ver) = affected.strip_prefix('<') {
            // Compare versions
            return version < max_ver;
        }

        false
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
    }
}

#[derive(Default)]
struct PackageInfo {
    express_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_vulnerable() {
        let scanner = ExpressSecurityScanner::new(Arc::new(HttpClient::new().unwrap()));

        assert!(scanner.is_version_vulnerable("4.18.0", "<4.19.2"));
        assert!(!scanner.is_version_vulnerable("4.19.2", "<4.19.2"));
        assert!(!scanner.is_version_vulnerable("5.0.0", "<4.19.2"));
    }

    #[test]
    fn test_cve_database() {
        let db = ExpressSecurityScanner::build_cve_database();
        assert!(db.contains_key("express"));
        assert!(!db["express"].is_empty());
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            ExpressSecurityScanner::extract_express_version("Express/4.18.2"),
            Some("4.18.2".to_string())
        );
        assert_eq!(
            ExpressSecurityScanner::extract_express_version("Express"),
            None
        );
    }
}
