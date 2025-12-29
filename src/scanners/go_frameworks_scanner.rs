// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Go Web Frameworks Security Scanner
 * Comprehensive security scanning for Gin, Echo, Fiber, and Chi frameworks
 *
 * REQUIRES: Personal license or higher
 *
 * Detects:
 * - Framework detection via headers and error pages
 * - Debug/development mode indicators
 * - pprof profiling endpoints exposure (/debug/pprof/)
 * - expvar exposure (/debug/vars)
 * - Swagger/OpenAPI documentation exposure
 * - Default error handling with stack traces
 * - CORS misconfiguration
 * - Middleware bypass vulnerabilities
 * - Health/metrics endpoint exposure
 * - Template injection in Go templates
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Personal Edition and above
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq)]
pub enum GoFramework {
    Gin,
    Echo,
    Fiber,
    Chi,
    Unknown,
}

impl std::fmt::Display for GoFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoFramework::Gin => write!(f, "Gin"),
            GoFramework::Echo => write!(f, "Echo"),
            GoFramework::Fiber => write!(f, "Fiber"),
            GoFramework::Chi => write!(f, "Chi"),
            GoFramework::Unknown => write!(f, "Unknown Go Framework"),
        }
    }
}

pub struct GoFrameworksScanner {
    http_client: Arc<HttpClient>,
}

impl GoFrameworksScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(&self, target: &str, _config: &ScanConfig) -> Result<(Vec<Vulnerability>, usize)> {
        if !crate::license::has_feature("cms_security") {
            debug!("Go frameworks scanner requires Personal+ license");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let (detected_framework, is_go_app) = self.detect_go_framework(target).await;
        tests_run += 1;

        if !is_go_app {
            debug!("Target does not appear to be a Go web application");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Go] Detected {} application at {}", detected_framework, target);

        let (debug_vulns, debug_tests) = self.check_debug_mode(target, &detected_framework).await;
        vulnerabilities.extend(debug_vulns);
        tests_run += debug_tests;

        let (pprof_vulns, pprof_tests) = self.check_pprof_exposure(target).await;
        vulnerabilities.extend(pprof_vulns);
        tests_run += pprof_tests;

        let (expvar_vulns, expvar_tests) = self.check_expvar_exposure(target).await;
        vulnerabilities.extend(expvar_vulns);
        tests_run += expvar_tests;

        let (swagger_vulns, swagger_tests) = self.check_swagger_exposure(target).await;
        vulnerabilities.extend(swagger_vulns);
        tests_run += swagger_tests;

        let (error_vulns, error_tests) = self.check_error_handling(target, &detected_framework).await;
        vulnerabilities.extend(error_vulns);
        tests_run += error_tests;

        let (cors_vulns, cors_tests) = self.check_cors_misconfiguration(target).await;
        vulnerabilities.extend(cors_vulns);
        tests_run += cors_tests;

        let (middleware_vulns, middleware_tests) = self.check_middleware_bypass(target, &detected_framework).await;
        vulnerabilities.extend(middleware_vulns);
        tests_run += middleware_tests;

        let (health_vulns, health_tests) = self.check_health_metrics_exposure(target).await;
        vulnerabilities.extend(health_vulns);
        tests_run += health_tests;

        let (template_vulns, template_tests) = self.check_template_injection(target).await;
        vulnerabilities.extend(template_vulns);
        tests_run += template_tests;

        info!("[Go] Completed: {} vulnerabilities found in {} tests",
              vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    async fn detect_go_framework(&self, target: &str) -> (GoFramework, bool) {
        let mut is_go_app = false;
        let mut detected_framework = GoFramework::Unknown;

        if let Ok(response) = self.http_client.get(target).await {
            if let Some(server) = response.headers.get("server") {
                let server_lower = server.to_lowercase();
                if server_lower.contains("gin") {
                    detected_framework = GoFramework::Gin;
                    is_go_app = true;
                } else if server_lower.contains("echo") {
                    detected_framework = GoFramework::Echo;
                    is_go_app = true;
                } else if server_lower.contains("fiber") {
                    detected_framework = GoFramework::Fiber;
                    is_go_app = true;
                }
            }

            if let Some(powered_by) = response.headers.get("x-powered-by") {
                let powered_lower = powered_by.to_lowercase();
                if powered_lower.contains("go") || powered_lower.contains("golang") {
                    is_go_app = true;
                }
            }

            let body = &response.body;
            if body.contains("runtime error:") || body.contains("goroutine") ||
               body.contains("panic:") || body.contains(".go:") {
                is_go_app = true;
            }
        }

        let error_url = format!("{}/this-path-does-not-exist-go-test-12345", target.trim_end_matches('/'));
        if let Ok(response) = self.http_client.get(&error_url).await {
            let body = &response.body;

            if body.contains("gin-gonic") || body.contains("Gin Framework") ||
               (body.contains("404") && body.contains("gin")) {
                detected_framework = GoFramework::Gin;
                is_go_app = true;
            } else if body.contains("Echo") && body.contains("message") {
                detected_framework = GoFramework::Echo;
                is_go_app = true;
            } else if body.contains("Cannot") && body.contains("fiber") {
                detected_framework = GoFramework::Fiber;
                is_go_app = true;
            } else if body.contains("chi router") {
                detected_framework = GoFramework::Chi;
                is_go_app = true;
            }

            if body.contains("runtime/") || body.contains("goroutine ") ||
               body.contains("net/http") || body.contains(".go:") {
                is_go_app = true;
            }
        }

        let go_endpoints = [
            "/debug/pprof/",
            "/debug/vars",
            "/health",
            "/healthz",
            "/ready",
            "/readyz",
            "/metrics",
        ];

        for endpoint in &go_endpoints {
            let url = format!("{}{}", target.trim_end_matches('/'), endpoint);
            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;
                    if body.contains("goroutine") || body.contains("heap") ||
                       body.contains("cmdline") || body.contains("memstats") ||
                       body.contains("go_") {
                        is_go_app = true;
                        break;
                    }
                }
            }
        }

        (detected_framework, is_go_app)
    }

    async fn check_debug_mode(&self, target: &str, framework: &GoFramework) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let debug_indicators = match framework {
            GoFramework::Gin => vec![
                ("/debug", "Gin debug endpoint"),
                ("/gin-debug", "Gin framework debug"),
            ],
            GoFramework::Echo => vec![
                ("/debug", "Echo debug endpoint"),
                ("/.echo", "Echo internal endpoint"),
            ],
            GoFramework::Fiber => vec![
                ("/fiber/debug", "Fiber debug endpoint"),
                ("/.fiber", "Fiber internal endpoint"),
            ],
            GoFramework::Chi => vec![
                ("/debug", "Chi debug endpoint"),
            ],
            GoFramework::Unknown => vec![
                ("/debug", "Debug endpoint"),
                ("/_debug", "Internal debug endpoint"),
            ],
        };

        for (path, description) in debug_indicators {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;
                    let debug_patterns = [
                        "debug", "goroutine", "stack", "heap", "runtime",
                        "env", "config", "settings", "internal",
                    ];

                    let found_patterns: Vec<&str> = debug_patterns.iter()
                        .filter(|p| body.to_lowercase().contains(*p))
                        .copied()
                        .collect();

                    if !found_patterns.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("GO_DEBUG"),
                            vuln_type: "Debug Mode Enabled".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Security Misconfiguration".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} ({}) is accessible in production.\n\n\
                                Debug mode exposes:\n\
                                - Internal application state\n\
                                - Configuration values\n\
                                - Runtime information\n\
                                - Potential secrets and credentials\n\n\
                                Patterns found: {:?}",
                                description, framework, found_patterns
                            ),
                            evidence: Some(format!("Endpoint: {}, Patterns: {:?}", path, found_patterns)),
                            cwe: "CWE-489".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: format!(
                                "Disable debug mode in production:\n\
                                - For Gin: Set gin.SetMode(gin.ReleaseMode)\n\
                                - For Echo: Disable debug mode in production config\n\
                                - For Fiber: Set app.Config.DisableStartupMessage = true\n\
                                - Remove or protect all debug endpoints with authentication"
                            ),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    async fn check_pprof_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let pprof_endpoints = [
            ("/debug/pprof/", "pprof index", Severity::Critical),
            ("/debug/pprof/cmdline", "Command line arguments", Severity::High),
            ("/debug/pprof/profile", "CPU profile", Severity::Critical),
            ("/debug/pprof/symbol", "Symbol lookup", Severity::Medium),
            ("/debug/pprof/trace", "Execution trace", Severity::Critical),
            ("/debug/pprof/heap", "Heap profile", Severity::Critical),
            ("/debug/pprof/goroutine", "Goroutine stack traces", Severity::High),
            ("/debug/pprof/threadcreate", "Thread creation profile", Severity::Medium),
            ("/debug/pprof/block", "Block profile", Severity::Medium),
            ("/debug/pprof/mutex", "Mutex contention profile", Severity::Medium),
            ("/debug/pprof/allocs", "Memory allocation profile", Severity::High),
        ];

        let mut found_pprof = false;

        for (path, name, severity) in &pprof_endpoints {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    let is_pprof = body.contains("goroutine") ||
                                   body.contains("heap") ||
                                   body.contains("profile") ||
                                   body.contains("pprof") ||
                                   body.contains("Types of profiles") ||
                                   body.len() > 100;

                    if is_pprof {
                        found_pprof = true;

                        let cvss = match severity {
                            Severity::Critical => 9.8,
                            Severity::High => 8.5,
                            Severity::Medium => 6.5,
                            _ => 4.0,
                        };

                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("GO_PPROF"),
                            vuln_type: "pprof Profiling Exposed".to_string(),
                            severity: severity.clone(),
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Go pprof endpoint ({}) is publicly accessible.\n\n\
                                pprof exposure allows attackers to:\n\
                                - Download heap dumps containing secrets and session data\n\
                                - Obtain CPU profiles revealing business logic\n\
                                - Access command line arguments (may contain secrets)\n\
                                - View goroutine stacks exposing internal state\n\
                                - Perform denial of service via heavy profiling\n\n\
                                This is particularly dangerous as heap dumps can contain:\n\
                                - Database credentials\n\
                                - API keys and tokens\n\
                                - Session data and user information",
                                name
                            ),
                            evidence: Some(format!("Endpoint accessible: {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss,
                            verified: true,
                            false_positive: false,
                            remediation: "Remove pprof from production builds:\n\
                                          1. Do not import _ \"net/http/pprof\" in production\n\
                                          2. Use build tags to exclude pprof:\n\
                                             //go:build !release\n\
                                          3. If needed, protect with authentication:\n\
                                             ```go\n\
                                             pprofMux := http.NewServeMux()\n\
                                             pprofMux.HandleFunc(\"/debug/pprof/\", pprof.Index)\n\
                                             // Add auth middleware\n\
                                             ```\n\
                                          4. Bind pprof to localhost only in development".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        if found_pprof && vulnerabilities.len() > 3 {
            vulnerabilities.truncate(3);
        }

        (vulnerabilities, tests_run)
    }

    async fn check_expvar_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let expvar_paths = ["/debug/vars", "/vars", "/expvar"];

        for path in &expvar_paths {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    let expvar_indicators = [
                        "cmdline", "memstats", "Alloc", "TotalAlloc",
                        "Sys", "NumGC", "HeapAlloc", "HeapSys",
                    ];

                    let found_indicators: Vec<&str> = expvar_indicators.iter()
                        .filter(|i| body.contains(*i))
                        .copied()
                        .collect();

                    if !found_indicators.is_empty() {
                        let has_cmdline = body.contains("cmdline");
                        let severity = if has_cmdline { Severity::High } else { Severity::Medium };

                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("GO_EXPVAR"),
                            vuln_type: "expvar Debug Variables Exposed".to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Go expvar endpoint is publicly accessible.\n\n\
                                expvar exposes:\n\
                                - Memory statistics (heap, stack, GC)\n\
                                - Command line arguments (may contain secrets)\n\
                                - Custom application metrics\n\
                                - Runtime configuration\n\n\
                                Indicators found: {:?}",
                                found_indicators
                            ),
                            evidence: Some(format!("Endpoint: {}, Indicators: {:?}", path, found_indicators)),
                            cwe: "CWE-200".to_string(),
                            cvss: if has_cmdline { 7.5 } else { 5.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "Remove expvar from production:\n\
                                          1. Do not import _ \"expvar\" in production\n\
                                          2. Use build tags for conditional compilation\n\
                                          3. If needed, protect with authentication middleware\n\
                                          4. Consider using Prometheus metrics instead with proper access control".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    async fn check_swagger_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let swagger_paths = [
            ("/swagger/", "Swagger UI"),
            ("/swagger/index.html", "Swagger UI Index"),
            ("/swagger-ui/", "Swagger UI Alternative"),
            ("/api-docs", "API Documentation"),
            ("/docs", "Documentation"),
            ("/swagger.json", "Swagger JSON Spec"),
            ("/swagger.yaml", "Swagger YAML Spec"),
            ("/openapi.json", "OpenAPI JSON Spec"),
            ("/openapi.yaml", "OpenAPI YAML Spec"),
            ("/v1/swagger.json", "V1 Swagger Spec"),
            ("/v2/swagger.json", "V2 Swagger Spec"),
            ("/api/v1/swagger.json", "API V1 Swagger"),
        ];

        for (path, name) in &swagger_paths {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    let is_swagger = body.contains("swagger") ||
                                    body.contains("openapi") ||
                                    body.contains("\"paths\"") ||
                                    body.contains("\"info\"") ||
                                    body.contains("Swagger UI");

                    if is_swagger {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("GO_SWAGGER"),
                            vuln_type: "API Documentation Exposed".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "{} is publicly accessible.\n\n\
                                Exposed API documentation reveals:\n\
                                - Complete API endpoint structure\n\
                                - Request/response schemas\n\
                                - Authentication requirements\n\
                                - Internal business logic and workflows\n\
                                - Parameter names and validation rules",
                                name
                            ),
                            evidence: Some(format!("Swagger/OpenAPI at: {}", path)),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Protect API documentation in production:\n\
                                          1. Disable swagger in production builds:\n\
                                             ```go\n\
                                             if os.Getenv(\"ENV\") != \"production\" {\n\
                                                 r.GET(\"/swagger/*any\", ginSwagger.WrapHandler(swaggerFiles.Handler))\n\
                                             }\n\
                                             ```\n\
                                          2. Add authentication middleware to swagger routes\n\
                                          3. Use IP whitelisting for internal access only".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    async fn check_error_handling(&self, target: &str, framework: &GoFramework) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let error_triggers = [
            ("/api/nonexistent-endpoint-test-12345", "Invalid endpoint"),
            ("/%00", "Null byte"),
            ("/api?id=", "Empty parameter"),
            ("/api?id[]=1&id[]=2", "Array parameter"),
            ("/api/../../../etc/passwd", "Path traversal attempt"),
            ("/api?callback=<script>", "XSS in callback"),
        ];

        for (path, trigger_type) in &error_triggers {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                let body = &response.body;

                let stack_trace_indicators = [
                    "goroutine",
                    "runtime/",
                    "panic:",
                    ".go:",
                    "runtime error:",
                    "net/http",
                    "reflect.",
                    "main.go",
                    "handler.go",
                ];

                let found_traces: Vec<&str> = stack_trace_indicators.iter()
                    .filter(|i| body.contains(*i))
                    .copied()
                    .collect();

                if found_traces.len() >= 2 {
                    let has_file_paths = body.contains(".go:");
                    let severity = if has_file_paths { Severity::High } else { Severity::Medium };

                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("GO_STACK_TRACE"),
                        vuln_type: "Stack Trace Exposure".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: format!("{} ({})", path, trigger_type),
                        description: format!(
                            "Go application ({}) exposes stack traces in error responses.\n\n\
                            Stack traces reveal:\n\
                            - Internal file paths and structure\n\
                            - Function names and call flow\n\
                            - Line numbers for targeted attacks\n\
                            - Third-party library versions\n\
                            - Business logic implementation\n\n\
                            Trigger: {}\n\
                            Indicators found: {:?}",
                            framework, trigger_type, found_traces
                        ),
                        evidence: Some(format!("Stack trace indicators: {:?}", found_traces)),
                        cwe: "CWE-209".to_string(),
                        cvss: if has_file_paths { 6.5 } else { 5.0 },
                        verified: true,
                        false_positive: false,
                        remediation: format!(
                            "Implement custom error handling:\n\
                            For {}:\n\
                            ```go\n\
                            // Use recovery middleware\n\
                            r.Use(gin.Recovery())\n\
                            \n\
                            // Custom error handler\n\
                            r.NoRoute(func(c *gin.Context) {{\n\
                                c.JSON(404, gin.H{{\"error\": \"Not found\"}})\n\
                            }})\n\
                            ```\n\
                            Never expose stack traces in production responses.",
                            framework
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    async fn check_cors_misconfiguration(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let test_origins = [
            ("https://evil.com", "arbitrary origin"),
            ("null", "null origin"),
            (&format!("{}.evil.com", target.replace("https://", "").replace("http://", "").split('.').next().unwrap_or("test")), "subdomain variant"),
        ];

        for (origin, origin_type) in &test_origins {
            tests_run += 1;

            let headers = vec![("Origin".to_string(), origin.to_string())];

            if let Ok(response) = self.http_client.get_with_headers(target, headers).await {
                if let Some(acao) = response.headers.get("access-control-allow-origin") {
                    let acao_value = acao.as_str();
                    let allows_credentials = response.headers
                        .get("access-control-allow-credentials")
                        .map(|v| v.as_str() == "true")
                        .unwrap_or(false);

                    let is_wildcard = acao_value == "*";
                    let reflects_origin = acao_value == *origin;
                    let allows_null = acao_value == "null";

                    if (is_wildcard && allows_credentials) || reflects_origin || allows_null {
                        let severity = if allows_credentials && (reflects_origin || allows_null) {
                            Severity::High
                        } else if reflects_origin || allows_null {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("GO_CORS"),
                            vuln_type: "CORS Misconfiguration".to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "Security Misconfiguration".to_string(),
                            url: target.to_string(),
                            parameter: Some("Origin".to_string()),
                            payload: origin.to_string(),
                            description: format!(
                                "CORS is misconfigured allowing potentially malicious cross-origin requests.\n\n\
                                Test: {} origin\n\
                                Access-Control-Allow-Origin: {}\n\
                                Access-Control-Allow-Credentials: {}\n\n\
                                This can allow:\n\
                                - Cross-origin data theft\n\
                                - Session hijacking (if credentials allowed)\n\
                                - CSRF-like attacks",
                                origin_type, acao_value, allows_credentials
                            ),
                            evidence: Some(format!("ACAO: {}, Credentials: {}", acao_value, allows_credentials)),
                            cwe: "CWE-942".to_string(),
                            cvss: if allows_credentials { 8.0 } else { 5.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "Configure CORS properly:\n\
                                          ```go\n\
                                          // For Gin\n\
                                          config := cors.DefaultConfig()\n\
                                          config.AllowOrigins = []string{\"https://trusted-site.com\"}\n\
                                          config.AllowCredentials = true\n\
                                          r.Use(cors.New(config))\n\
                                          \n\
                                          // Never reflect arbitrary origins\n\
                                          // Never use * with credentials\n\
                                          ```".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    async fn check_middleware_bypass(&self, target: &str, framework: &GoFramework) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let protected_paths = ["/admin", "/api/admin", "/internal", "/private", "/dashboard"];

        for path in &protected_paths {
            let base_url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(base_response) = self.http_client.get(&base_url).await {
                if base_response.status_code == 401 || base_response.status_code == 403 {
                    let bypass_attempts = [
                        (format!("{}//", base_url), "double slash"),
                        (format!("{}/./", base_url), "dot segment"),
                        (format!("{}/../{}", base_url, path.trim_start_matches('/')), "path traversal"),
                        (format!("{}%2f", base_url), "URL encoded slash"),
                        (format!("{};", base_url), "semicolon"),
                        (format!("{}..;/", base_url), "dotdot semicolon"),
                        (format!("{}%00", base_url), "null byte"),
                        (format!("{}.json", base_url), "extension append"),
                    ];

                    for (bypass_url, technique) in &bypass_attempts {
                        tests_run += 1;

                        if let Ok(bypass_response) = self.http_client.get(bypass_url).await {
                            if bypass_response.status_code == 200 &&
                               bypass_response.body.len() > base_response.body.len() + 50 {
                                vulnerabilities.push(Vulnerability {
                                    id: generate_vuln_id("GO_MIDDLEWARE_BYPASS"),
                                    vuln_type: "Middleware/Auth Bypass".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::Medium,
                                    category: "Authorization Bypass".to_string(),
                                    url: bypass_url.clone(),
                                    parameter: None,
                                    payload: format!("{} technique", technique),
                                    description: format!(
                                        "Authentication/authorization middleware can be bypassed in {} framework.\n\n\
                                        Original path: {} (returned {})\n\
                                        Bypass path: {} (returned 200)\n\
                                        Technique: {}\n\n\
                                        This indicates the routing middleware does not properly normalize paths \
                                        before checking authorization.",
                                        framework, path, base_response.status_code, bypass_url, technique
                                    ),
                                    evidence: Some(format!(
                                        "Protected: {} -> {}, Bypassed: {} -> 200",
                                        path, base_response.status_code, bypass_url
                                    )),
                                    cwe: "CWE-863".to_string(),
                                    cvss: 9.8,
                                    verified: false,
                                    false_positive: false,
                                    remediation: format!(
                                        "Fix path normalization in {} middleware:\n\
                                        1. Normalize paths before authorization checks:\n\
                                           ```go\n\
                                           path := filepath.Clean(c.Request.URL.Path)\n\
                                           ```\n\
                                        2. Use strict route matching\n\
                                        3. Apply auth middleware at the router group level\n\
                                        4. Consider using a WAF for path normalization",
                                        framework
                                    ),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
            tests_run += 1;
        }

        (vulnerabilities, tests_run)
    }

    async fn check_health_metrics_exposure(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let health_endpoints = [
            ("/health", "Health check", Severity::Low),
            ("/healthz", "Kubernetes health", Severity::Low),
            ("/ready", "Readiness probe", Severity::Low),
            ("/readyz", "Kubernetes readiness", Severity::Low),
            ("/live", "Liveness probe", Severity::Low),
            ("/livez", "Kubernetes liveness", Severity::Low),
            ("/metrics", "Prometheus metrics", Severity::Medium),
            ("/prometheus", "Prometheus endpoint", Severity::Medium),
            ("/actuator", "Actuator-like endpoint", Severity::Medium),
            ("/status", "Status endpoint", Severity::Low),
            ("/_status", "Internal status", Severity::Medium),
            ("/info", "Info endpoint", Severity::Low),
            ("/version", "Version endpoint", Severity::Low),
            ("/build-info", "Build information", Severity::Low),
        ];

        let mut found_endpoints: Vec<(String, String, Severity)> = Vec::new();

        for (path, name, severity) in &health_endpoints {
            tests_run += 1;
            let url = format!("{}{}", target.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    if body.len() > 10 && (
                        body.contains("status") ||
                        body.contains("health") ||
                        body.contains("version") ||
                        body.contains("go_") ||
                        body.contains("process_") ||
                        body.contains("http_") ||
                        body.contains("{")
                    ) {
                        found_endpoints.push((path.to_string(), name.to_string(), severity.clone()));
                    }
                }
            }
        }

        if !found_endpoints.is_empty() {
            let has_metrics = found_endpoints.iter().any(|(p, _, _)| p.contains("metrics") || p.contains("prometheus"));
            let severity = if has_metrics { Severity::Medium } else { Severity::Low };

            let endpoint_list: Vec<String> = found_endpoints.iter()
                .map(|(p, n, _)| format!("{} ({})", p, n))
                .collect();

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("GO_HEALTH_METRICS"),
                vuln_type: "Health/Metrics Endpoints Exposed".to_string(),
                severity,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: target.to_string(),
                parameter: None,
                payload: endpoint_list.join(", "),
                description: format!(
                    "Multiple health and metrics endpoints are publicly accessible.\n\n\
                    Exposed endpoints:\n{}\n\n\
                    These endpoints may reveal:\n\
                    - Internal service status and dependencies\n\
                    - Database connection health\n\
                    - Memory and CPU usage patterns\n\
                    - Request latencies and error rates\n\
                    - Version and build information\n\
                    - Infrastructure details",
                    endpoint_list.iter().map(|e| format!("- {}", e)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(format!("Found {} exposed endpoints", found_endpoints.len())),
                cwe: "CWE-200".to_string(),
                cvss: if has_metrics { 5.3 } else { 3.7 },
                verified: true,
                false_positive: false,
                remediation: "Protect health and metrics endpoints:\n\
                              1. Restrict access by IP (internal network only)\n\
                              2. Use separate port for internal endpoints:\n\
                                 ```go\n\
                                 go func() {\n\
                                     internalMux := http.NewServeMux()\n\
                                     internalMux.HandleFunc(\"/health\", healthHandler)\n\
                                     http.ListenAndServe(\"127.0.0.1:8081\", internalMux)\n\
                                 }()\n\
                                 ```\n\
                              3. Add authentication for metrics endpoint\n\
                              4. Use Kubernetes network policies to restrict access".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    async fn check_template_injection(&self, target: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let template_payloads = [
            ("{{.}}", "Go template dot", "object dump"),
            ("{{printf \"%s\" .}}", "Printf injection", "format string"),
            ("{{range .}}{{.}}{{end}}", "Range iteration", "data iteration"),
            ("{{template \"name\"}}", "Template include", "template loading"),
            ("{{define \"x\"}}{{end}}", "Template define", "template definition"),
            ("{{$x := .}}", "Variable assignment", "variable access"),
        ];

        let test_endpoints = [
            "/search",
            "/api/search",
            "/render",
            "/template",
            "/preview",
            "/",
        ];

        let test_params = ["q", "query", "search", "name", "template", "text", "message", "title"];

        for endpoint in &test_endpoints {
            let base_url = format!("{}{}", target.trim_end_matches('/'), endpoint);

            for param in &test_params {
                for (payload, name, category) in &template_payloads {
                    tests_run += 1;

                    let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(payload));

                    if let Ok(response) = self.http_client.get(&test_url).await {
                        let body = &response.body;

                        let injection_indicators = [
                            "map[",
                            "struct",
                            "<nil>",
                            "runtime error",
                            "template:",
                            "execute template",
                            "unexpected",
                            "invalid",
                        ];

                        let rendered_cleanly = !body.contains("{{") &&
                                              !body.contains(payload) &&
                                              body.len() > 50;

                        let has_error = injection_indicators.iter()
                            .any(|i| body.to_lowercase().contains(&i.to_lowercase()));

                        if (rendered_cleanly && body.contains("[")) || has_error {
                            let severity = if has_error && body.contains("runtime") {
                                Severity::High
                            } else {
                                Severity::Medium
                            };

                            vulnerabilities.push(Vulnerability {
                                id: generate_vuln_id("GO_TEMPLATE_INJECTION"),
                                vuln_type: "Go Template Injection".to_string(),
                                severity,
                                confidence: Confidence::Medium,
                                category: "Server-Side Template Injection".to_string(),
                                url: test_url.clone(),
                                parameter: Some(param.to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "Potential Go template injection vulnerability detected.\n\n\
                                    Payload: {} ({})\n\
                                    Category: {}\n\
                                    Parameter: {}\n\n\
                                    Go template injection can lead to:\n\
                                    - Information disclosure via {{{{.}}}}\n\
                                    - Data enumeration via range\n\
                                    - Potential denial of service\n\
                                    - In some cases, code execution via custom functions",
                                    payload, name, category, param
                                ),
                                evidence: Some(format!(
                                    "Payload processed differently: {} bytes response",
                                    body.len()
                                )),
                                cwe: "CWE-1336".to_string(),
                                cvss: if has_error { 7.5 } else { 5.5 },
                                verified: false,
                                false_positive: false,
                                remediation: "Prevent Go template injection:\n\
                                              1. Never pass user input directly to templates:\n\
                                                 ```go\n\
                                                 // Bad\n\
                                                 tmpl.Execute(w, userInput)\n\
                                                 \n\
                                                 // Good\n\
                                                 data := struct{ Content string }{Content: userInput}\n\
                                                 tmpl.Execute(w, data)\n\
                                                 ```\n\
                                              2. Use text/template for untrusted input\n\
                                              3. Sanitize input before template rendering\n\
                                              4. Avoid dynamic template compilation from user input".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });

                            return (vulnerabilities, tests_run);
                        }
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }
}

fn generate_vuln_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{:x}", prefix, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_display() {
        assert_eq!(format!("{}", GoFramework::Gin), "Gin");
        assert_eq!(format!("{}", GoFramework::Echo), "Echo");
        assert_eq!(format!("{}", GoFramework::Fiber), "Fiber");
        assert_eq!(format!("{}", GoFramework::Chi), "Chi");
        assert_eq!(format!("{}", GoFramework::Unknown), "Unknown Go Framework");
    }

    #[test]
    fn test_generate_vuln_id() {
        let id1 = generate_vuln_id("GO_TEST");
        let id2 = generate_vuln_id("GO_TEST");
        assert!(id1.starts_with("GO_TEST-"));
        assert!(id1 != id2);
    }

    #[test]
    fn test_framework_equality() {
        assert_eq!(GoFramework::Gin, GoFramework::Gin);
        assert_ne!(GoFramework::Gin, GoFramework::Echo);
    }
}
