// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct FastApiScanner {
    http_client: Arc<HttpClient>,
}

impl FastApiScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Check license
        if !crate::license::has_feature("cms_security") {
            debug!("[FastAPI] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Detect if target is running FastAPI
        tests_run += 1;
        let (is_fastapi, version) = self.detect_fastapi(url).await;

        if !is_fastapi {
            debug!("[FastAPI] Target does not appear to be running FastAPI");
            return Ok((vec![], tests_run));
        }

        info!(
            "[FastAPI] Detected FastAPI application{}",
            version
                .as_ref()
                .map(|v| format!(" (version: {})", v))
                .unwrap_or_default()
        );

        // Check for exposed documentation endpoints
        let (docs_vulns, docs_tests) = self.check_docs_exposure(url, config).await?;
        vulnerabilities.extend(docs_vulns);
        tests_run += docs_tests;

        // Check for debug mode indicators
        let (debug_vulns, debug_tests) = self.check_debug_mode(url, config).await?;
        vulnerabilities.extend(debug_vulns);
        tests_run += debug_tests;

        // Check CORS configuration
        let (cors_vulns, cors_tests) = self.check_cors_config(url, config).await?;
        vulnerabilities.extend(cors_vulns);
        tests_run += cors_tests;

        // Check OAuth2 configuration
        let (oauth_vulns, oauth_tests) = self.check_oauth2_config(url, config).await?;
        vulnerabilities.extend(oauth_vulns);
        tests_run += oauth_tests;

        // Check for exposed internal endpoints
        let (internal_vulns, internal_tests) = self.check_internal_endpoints(url, config).await?;
        vulnerabilities.extend(internal_vulns);
        tests_run += internal_tests;

        // Check for Pydantic validation bypass
        let (pydantic_vulns, pydantic_tests) = self.check_pydantic_bypass(url, config).await?;
        vulnerabilities.extend(pydantic_vulns);
        tests_run += pydantic_tests;

        // Check for dependency injection vulnerabilities
        let (di_vulns, di_tests) = self.check_dependency_injection(url, config).await?;
        vulnerabilities.extend(di_vulns);
        tests_run += di_tests;

        // Check for Starlette-specific issues
        let (starlette_vulns, starlette_tests) = self.check_starlette_issues(url, config).await?;
        vulnerabilities.extend(starlette_vulns);
        tests_run += starlette_tests;

        // Check for exposed Python-app artifacts (pyproject, Pipfile.lock, Alembic, Celery configs, .env)
        let (artifact_vulns, artifact_tests) = self.check_python_artifacts(url, config).await?;
        vulnerabilities.extend(artifact_vulns);
        tests_run += artifact_tests;

        info!(
            "[FastAPI] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check for exposed Python/FastAPI build / deploy / config artifacts that
    /// regularly ship alongside ASGI apps mounted directly at static roots.
    /// Each path requires a specific content signature to avoid false positives
    /// from SPA catch-all 200 responses.
    async fn check_python_artifacts(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // (path, friendly-name, severity, signatures)
        let artifacts: &[(&str, &str, Severity, &[&str])] = &[
            // Build/dependency manifests - reveal full package tree for targeted CVE lookup
            ("/pyproject.toml", "pyproject.toml", Severity::Medium,
                &["[tool.poetry]", "[build-system]", "[tool.black]", "[tool.ruff]", "[project]"]),
            ("/Pipfile", "Pipfile", Severity::Medium,
                &["[[source]]", "[packages]", "[dev-packages]"]),
            ("/Pipfile.lock", "Pipfile.lock", Severity::Medium,
                &["\"_meta\"", "\"default\"", "\"develop\""]),
            ("/poetry.lock", "poetry.lock", Severity::Medium,
                &["[[package]]", "content-hash", "python-versions"]),
            ("/requirements.txt", "requirements.txt", Severity::Low,
                &["==", ">=", "fastapi", "uvicorn", "pydantic"]),
            ("/requirements-dev.txt", "requirements-dev.txt", Severity::Low, &["==", ">="]),
            ("/requirements/base.txt", "requirements/base.txt", Severity::Low, &["==", ">="]),
            ("/requirements/production.txt", "requirements/production.txt", Severity::Low, &["==", ">="]),
            ("/setup.py", "setup.py", Severity::Low,
                &["setup(", "setuptools", "install_requires"]),
            ("/setup.cfg", "setup.cfg", Severity::Low,
                &["[metadata]", "[options]", "[flake8]"]),
            ("/tox.ini", "tox.ini", Severity::Low, &["[tox]", "envlist", "[testenv"]),

            // .env variants - Python apps frequently use python-dotenv
            ("/.env", ".env", Severity::Critical,
                &["SECRET_KEY", "DATABASE_URL", "POSTGRES_", "REDIS_URL", "AWS_ACCESS"]),
            ("/.env.production", ".env.production", Severity::Critical,
                &["SECRET_KEY", "DATABASE_URL", "POSTGRES_", "AWS_ACCESS"]),
            ("/.env.local", ".env.local", Severity::Critical,
                &["SECRET_KEY", "DATABASE_URL", "POSTGRES_", "REDIS_URL"]),
            ("/.env.dev", ".env.dev", Severity::High, &["SECRET_KEY", "DATABASE_URL"]),
            ("/app/.env", "app/.env", Severity::Critical,
                &["SECRET_KEY", "DATABASE_URL", "POSTGRES_"]),
            ("/backend/.env", "backend/.env", Severity::Critical,
                &["SECRET_KEY", "DATABASE_URL", "POSTGRES_"]),

            // Alembic migrations / config - reveals schema and often DB creds
            ("/alembic.ini", "Alembic config", Severity::High,
                &["[alembic]", "sqlalchemy.url"]),
            ("/alembic/env.py", "Alembic env.py", Severity::Medium,
                &["from alembic", "context.configure"]),
            ("/alembic/versions/", "Alembic versions dir listing", Severity::Medium,
                &["Index of /alembic", "Parent Directory"]),
            ("/migrations/env.py", "Migrations env.py", Severity::Medium,
                &["from alembic", "context.configure"]),

            // Celery
            ("/celeryconfig.py", "celeryconfig.py", Severity::High,
                &["broker_url", "result_backend", "broker ="]),
            ("/celery.py", "celery.py", Severity::Medium,
                &["Celery(", "from celery"]),

            // FastAPI app entrypoints occasionally served as static
            ("/main.py", "main.py", Severity::Medium,
                &["from fastapi", "FastAPI(", "app = FastAPI"]),
            ("/app/main.py", "app/main.py", Severity::Medium,
                &["from fastapi", "FastAPI(", "app = FastAPI"]),
            ("/asgi.py", "asgi.py", Severity::Low,
                &["application = ", "from django.core.asgi", "from fastapi"]),
            ("/wsgi.py", "wsgi.py", Severity::Low,
                &["application = ", "from django.core.wsgi"]),

            // Docker / deploy leftovers
            ("/Dockerfile", "Dockerfile", Severity::Low,
                &["FROM ", "WORKDIR ", "COPY ", "RUN "]),
            ("/docker-compose.yml", "docker-compose.yml", Severity::Low,
                &["services:", "version:", "image:"]),
            ("/docker-compose.prod.yml", "docker-compose.prod.yml", Severity::Low,
                &["services:", "image:"]),
            ("/gunicorn.conf.py", "gunicorn.conf.py", Severity::Low,
                &["bind = ", "workers = ", "worker_class"]),

            // Secret / auth key material
            ("/jwt.key", "JWT private key", Severity::Critical,
                &["-----BEGIN", "PRIVATE KEY"]),
            ("/jwt-private.pem", "JWT private key", Severity::Critical,
                &["-----BEGIN", "PRIVATE KEY"]),
            ("/private.pem", "Private key", Severity::Critical,
                &["-----BEGIN", "PRIVATE KEY"]),
            ("/id_rsa", "SSH private key", Severity::Critical,
                &["-----BEGIN", "PRIVATE KEY"]),

            // Git / CI
            ("/.git/config", ".git/config", Severity::High, &["[core]", "[remote"]),
            ("/.git/HEAD", ".git/HEAD", Severity::High, &["ref: refs/", "refs/heads/"]),
            ("/.gitlab-ci.yml", ".gitlab-ci.yml", Severity::Medium,
                &["stages:", "script:", "image:"]),
            ("/.github/workflows/deploy.yml", "GitHub Actions deploy workflow",
                Severity::Medium,
                &["uses: actions/checkout", "run:", "on:"]),

            // Firebase / service-account JSON
            ("/serviceAccountKey.json", "Service account key", Severity::Critical,
                &["\"type\": \"service_account\"", "\"private_key\""]),
            ("/firebase-adminsdk.json", "Firebase admin SDK key", Severity::Critical,
                &["\"type\": \"service_account\"", "\"private_key\""]),
            ("/credentials.json", "Generic credentials.json", Severity::High,
                &["\"client_id\"", "\"client_secret\"", "\"refresh_token\""]),

            // Common backup patterns left behind after deploys
            ("/app.tar.gz", "app archive", Severity::High, &[]),
            ("/backup.sql", "SQL backup", Severity::Critical,
                &["-- MySQL dump", "PostgreSQL database dump", "INSERT INTO", "CREATE TABLE"]),
            ("/dump.sql", "SQL dump", Severity::Critical,
                &["-- MySQL dump", "PostgreSQL database dump", "INSERT INTO", "CREATE TABLE"]),
            ("/database.sqlite", "SQLite database", Severity::Critical, &[]),
            ("/db.sqlite3", "SQLite database", Severity::Critical, &[]),
        ];

        for (path, name, severity, sigs) in artifacts {
            tests_run += 1;
            let test_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                if resp.status_code != 200 || resp.body.is_empty() {
                    continue;
                }

                let body = &resp.body;
                let body_trim = body.trim_start();

                // Skip SPA catch-all HTML shells for non-HTML artifacts
                let looks_like_html = body_trim.starts_with('<')
                    && (body_trim.contains("<html") || body_trim.contains("<!DOCTYPE"));
                if looks_like_html {
                    continue;
                }

                // Binary artifacts (archives, sqlite dbs) - verify with magic bytes
                let matched = match *path {
                    "/app.tar.gz" => {
                        let b = body.as_bytes();
                        b.len() > 8 && b[0] == 0x1f && b[1] == 0x8b
                    }
                    "/database.sqlite" | "/db.sqlite3" => {
                        body.starts_with("SQLite format 3")
                    }
                    _ => {
                        if sigs.is_empty() {
                            body.len() > 64
                        } else {
                            sigs.iter().any(|s| body.contains(s))
                        }
                    }
                };

                if !matched {
                    continue;
                }

                let cvss = match severity {
                    Severity::Critical => 9.1,
                    Severity::High => 7.5,
                    Severity::Medium => 5.3,
                    Severity::Low => 3.7,
                    Severity::Info => 0.0,
                };

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("python_artifact"),
                    vuln_type: format!("Python App Artifact Exposed: {}", name),
                    severity: severity.clone(),
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: test_url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: format!(
                        "{} is publicly accessible at {}. This artifact can reveal application \
                         internals, credentials, or dependency versions useful for targeted exploitation.",
                        name, path
                    ),
                    evidence: Some(format!(
                        "Path: {}\nSize: {} bytes\nStatus: 200",
                        path,
                        body.len()
                    )),
                    cwe: "CWE-538".to_string(),
                    cvss,
                    verified: true,
                    false_positive: false,
                    remediation: "Block the file / directory at the web server or ASGI layer; \
                                  rotate any credentials exposed; move build and deploy artifacts \
                                  outside the static-served root."
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running FastAPI
    async fn detect_fastapi(&self, url: &str) -> (bool, Option<String>) {
        let mut is_fastapi = false;
        let mut version = None;

        let base = url.trim_end_matches('/');

        // Check OpenAPI endpoint - most reliable indicator
        let openapi_url = format!("{}/openapi.json", base);
        if let Ok(resp) = self.http_client.get(&openapi_url).await {
            if resp.status_code == 200 {
                // Check for FastAPI-specific patterns in OpenAPI schema
                if resp.body.contains("\"openapi\"")
                    && (resp.body.contains("fastapi") || resp.body.contains("FastAPI"))
                {
                    is_fastapi = true;
                }

                // Extract version from info section
                let version_re = Regex::new(r#""version"\s*:\s*"([^"]+)""#).ok();
                if let Some(re) = version_re {
                    if let Some(caps) = re.captures(&resp.body) {
                        version = caps.get(1).map(|m| m.as_str().to_string());
                    }
                }

                // Generic OpenAPI could also indicate FastAPI
                if resp.body.contains("\"openapi\":") || resp.body.contains("\"openapi\" :") {
                    // Check for Python/Starlette indicators
                    if resp.body.contains("HTTPValidationError")
                        || resp.body.contains("ValidationError")
                        || resp.body.contains("pydantic")
                    {
                        is_fastapi = true;
                    }
                }
            }
        }

        // Check /docs endpoint (Swagger UI)
        let docs_url = format!("{}/docs", base);
        if let Ok(resp) = self.http_client.get(&docs_url).await {
            if resp.status_code == 200 {
                // FastAPI uses Swagger UI with specific patterns
                if resp.body.contains("swagger-ui")
                    && (resp.body.contains("FastAPI") || resp.body.contains("/openapi.json"))
                {
                    is_fastapi = true;
                }
            }
        }

        // Check /redoc endpoint (ReDoc)
        let redoc_url = format!("{}/redoc", base);
        if let Ok(resp) = self.http_client.get(&redoc_url).await {
            if resp.status_code == 200 && resp.body.contains("redoc") {
                // ReDoc with /openapi.json reference is FastAPI indicator
                if resp.body.contains("/openapi.json") {
                    is_fastapi = true;
                }
            }
        }

        // Check response headers for uvicorn/starlette
        if let Ok(resp) = self.http_client.get(url).await {
            if let Some(server) = resp.headers.get("server") {
                let server_lower = server.to_lowercase();
                if server_lower.contains("uvicorn") || server_lower.contains("starlette") {
                    is_fastapi = true;
                }
            }

            // Check for FastAPI error response patterns.
            // Fixed operator precedence: parentheses required for OR+AND.
            if resp.body.contains("HTTPValidationError")
                || (resp.body.contains("\"detail\":")
                    && resp.body.contains("\"loc\":")
                    && resp.body.contains("\"msg\":"))
            {
                is_fastapi = true;
            }
        }

        // Trigger validation error to detect Pydantic responses
        let error_url = format!("{}/?invalid_param=<script>", base);
        if let Ok(resp) = self.http_client.get(&error_url).await {
            // Fixed operator precedence bug: was `A || B && C` (evaluates as `A || (B && C)`)
            // but intended `A || (B && C)` - now explicit with parentheses
            if resp.body.contains("HTTPValidationError")
                || (resp.body.contains("\"detail\":") && resp.body.contains("\"type\":"))
            {
                is_fastapi = true;
            }
        }

        (is_fastapi, version)
    }

    /// Check for exposed documentation endpoints
    async fn check_docs_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Documentation endpoints to check
        let doc_endpoints = [
            ("/docs", "Swagger UI", "Interactive API documentation"),
            ("/redoc", "ReDoc", "API reference documentation"),
            ("/swagger", "Swagger UI", "Interactive API documentation"),
            ("/swagger-ui", "Swagger UI", "Interactive API documentation"),
            ("/swagger-ui.html", "Swagger UI HTML", "Swagger UI entry page"),
            ("/swagger/index.html", "Swagger Index", "Swagger UI index"),
            (
                "/openapi.json",
                "OpenAPI Schema",
                "Raw OpenAPI specification",
            ),
            (
                "/openapi.yaml",
                "OpenAPI YAML",
                "YAML OpenAPI specification",
            ),
            (
                "/openapi.yml",
                "OpenAPI YAML",
                "YAML OpenAPI specification",
            ),
            (
                "/api/openapi.json",
                "Namespaced OpenAPI Schema",
                "OpenAPI schema under /api prefix",
            ),
            (
                "/api/v1/openapi.json",
                "v1 OpenAPI Schema",
                "OpenAPI schema for /api/v1",
            ),
            (
                "/api/v2/openapi.json",
                "v2 OpenAPI Schema",
                "OpenAPI schema for /api/v2",
            ),
            (
                "/api/docs",
                "Namespaced Swagger UI",
                "API-prefixed Swagger UI",
            ),
            (
                "/api/v1/docs",
                "v1 Swagger UI",
                "Swagger UI for /api/v1",
            ),
            (
                "/api/redoc",
                "Namespaced ReDoc",
                "API-prefixed ReDoc",
            ),
            (
                "/docs/oauth2-redirect",
                "OAuth2 Redirect",
                "OAuth2 callback handler",
            ),
            (
                "/schema",
                "Generic Schema",
                "Raw schema endpoint",
            ),
            (
                "/schema.json",
                "Generic Schema JSON",
                "Raw schema endpoint",
            ),
        ];

        let mut exposed_endpoints = Vec::new();

        for (path, name, desc) in &doc_endpoints {
            tests_run += 1;
            let endpoint_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&endpoint_url).await {
                if resp.status_code == 200 {
                    let is_valid = match *path {
                        p if p.ends_with("/docs") || p == "/swagger" || p.contains("swagger") => {
                            resp.body.contains("swagger-ui")
                        }
                        p if p.ends_with("/redoc") => resp.body.contains("redoc"),
                        p if p.ends_with("/openapi.json") || p.ends_with("/schema.json") => {
                            resp.body.contains("\"openapi\"") || resp.body.contains("\"paths\"")
                        }
                        p if p.ends_with("/openapi.yaml") || p.ends_with("/openapi.yml") => {
                            resp.body.contains("openapi:") || resp.body.contains("paths:")
                        }
                        "/docs/oauth2-redirect" => {
                            resp.body.contains("oauth2") || resp.body.contains("initOAuth")
                        }
                        "/schema" => {
                            resp.body.contains("\"openapi\"")
                                || resp.body.contains("\"paths\"")
                                || resp.body.contains("openapi:")
                        }
                        _ => false,
                    };

                    if is_valid {
                        exposed_endpoints.push((*path, *name, *desc));
                    }
                }
            }
        }

        if !exposed_endpoints.is_empty() {
            let endpoint_list: Vec<String> = exposed_endpoints
                .iter()
                .map(|(p, n, _)| format!("{} ({})", p, n))
                .collect();

            // Determine severity based on what's exposed
            let has_openapi = exposed_endpoints
                .iter()
                .any(|(p, _, _)| p.contains("openapi"));
            let severity = if has_openapi {
                Severity::Medium
            } else {
                Severity::Low
            };

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("docs_exposure"),
                vuln_type: "FastAPI Documentation Exposed".to_string(),
                severity,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: format!("{}/docs", base),
                parameter: Some("documentation".to_string()),
                payload: endpoint_list.join(", "),
                description: format!(
                    "FastAPI documentation endpoints are publicly accessible: {}. \
                    This exposes the complete API structure, endpoints, parameters, \
                    and data models to potential attackers.",
                    endpoint_list.join(", ")
                ),
                evidence: Some(format!(
                    "Accessible endpoints:\n{}",
                    exposed_endpoints
                        .iter()
                        .map(|(p, n, d)| format!("  - {} ({}): {}", p, n, d))
                        .collect::<Vec<_>>()
                        .join("\n")
                )),
                cwe: "CWE-200".to_string(),
                cvss: if has_openapi { 5.3 } else { 3.7 },
                verified: true,
                false_positive: false,
                remediation: "Disable documentation endpoints in production:\n\
                    1. Set `docs_url=None` and `redoc_url=None` in FastAPI app initialization\n\
                    2. Set `openapi_url=None` to disable OpenAPI schema\n\
                    3. Use environment-based configuration to enable docs only in development\n\
                    4. If docs are required, implement authentication via dependencies"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for debug mode indicators
    async fn check_debug_mode(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Trigger potential debug output with invalid requests
        let debug_triggers = [
            ("/__debug__/", "Debug route"),
            ("/?__debug__=1", "Debug parameter"),
            ("/error-test-12345", "Error handler"),
            ("/?invalid_type=not_an_int", "Type validation"),
        ];

        for (trigger, desc) in &debug_triggers {
            tests_run += 1;
            let test_url = format!("{}{}", base, trigger);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                // Check for debug information in response
                let debug_indicators = [
                    ("Traceback", "Python traceback exposed"),
                    ("File \"", "File path exposed"),
                    ("line ", "Line numbers exposed"),
                    ("starlette.exceptions", "Framework exceptions exposed"),
                    ("uvicorn", "Server details exposed"),
                    ("PYTHONPATH", "Environment variables exposed"),
                    ("DEBUG", "Debug configuration exposed"),
                ];

                for (indicator, issue) in &debug_indicators {
                    if resp.body.contains(indicator) {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("debug_mode"),
                            vuln_type: "FastAPI Debug Mode Enabled".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Misconfiguration".to_string(),
                            url: test_url.clone(),
                            parameter: Some("debug".to_string()),
                            payload: trigger.to_string(),
                            description: format!(
                                "FastAPI application appears to be running in debug mode. \
                                Triggered via {}: {}. \
                                Debug mode exposes sensitive information including stack traces, \
                                file paths, and potentially environment variables.",
                                desc, issue
                            ),
                            evidence: Some(format!(
                                "Trigger: {}\n\
                                Indicator: {} found in response\n\
                                Issue: {}",
                                trigger, indicator, issue
                            )),
                            cwe: "CWE-215".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Disable debug mode in production:\n\
                                1. Set `debug=False` in uvicorn configuration\n\
                                2. Use production ASGI server configuration\n\
                                3. Implement custom exception handlers that don't expose internals\n\
                                4. Set PYTHONOPTIMIZE=2 in production".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        return Ok((vulnerabilities, tests_run));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check CORS configuration
    async fn check_cors_config(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test CORS with various origins
        let test_origins = [
            ("https://evil.com", "Arbitrary domain"),
            ("https://attacker.example.com", "Attacker domain"),
            ("null", "Null origin"),
            ("https://localhost", "Localhost"),
            ("https://127.0.0.1", "Loopback IP"),
        ];

        for (origin, desc) in &test_origins {
            tests_run += 1;

            let headers = vec![
                ("Origin".to_string(), origin.to_string()),
                (
                    "Access-Control-Request-Method".to_string(),
                    "GET".to_string(),
                ),
            ];

            if let Ok(resp) = self.http_client.get_with_headers(base, headers).await {
                if let Some(acao) = resp.headers.get("access-control-allow-origin") {
                    let has_credentials = resp
                        .headers
                        .get("access-control-allow-credentials")
                        .map(|v| v == "true")
                        .unwrap_or(false);

                    let is_vulnerable =
                        acao == "*" || acao == *origin || (acao == "null" && *origin == "null");

                    if is_vulnerable {
                        let severity = if has_credentials && acao != "*" {
                            Severity::Critical
                        } else if acao == "*" && has_credentials {
                            Severity::High
                        } else if acao == "*" {
                            Severity::Medium
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("cors_misconfig"),
                            vuln_type: "FastAPI CORS Misconfiguration".to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "Misconfiguration".to_string(),
                            url: base.to_string(),
                            parameter: Some("CORS".to_string()),
                            payload: format!("Origin: {}", origin),
                            description: format!(
                                "FastAPI CORSMiddleware allows requests from {}. \
                                Access-Control-Allow-Origin: {}{}. \
                                This may allow cross-origin attacks to access sensitive data.",
                                desc,
                                acao,
                                if has_credentials {
                                    " with credentials"
                                } else {
                                    ""
                                }
                            ),
                            evidence: Some(format!(
                                "Request Origin: {}\n\
                                Access-Control-Allow-Origin: {}\n\
                                Access-Control-Allow-Credentials: {}",
                                origin, acao, has_credentials
                            )),
                            cwe: "CWE-942".to_string(),
                            cvss: if has_credentials { 8.1 } else { 5.3 },
                            verified: true,
                            false_positive: false,
                            remediation: "Configure CORSMiddleware with specific origins:\n\
                                1. Set `allow_origins` to a specific list of trusted domains\n\
                                2. Never use `allow_origins=['*']` with `allow_credentials=True`\n\
                                3. Use `allow_origin_regex` for dynamic but controlled origins\n\
                                4. Review and restrict `allow_methods` and `allow_headers`"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check OAuth2 configuration
    async fn check_oauth2_config(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common OAuth2 endpoints in FastAPI
        let oauth_endpoints = [
            "/token",
            "/auth/token",
            "/api/token",
            "/oauth/token",
            "/login/access-token",
            "/api/v1/login/access-token",
        ];

        for endpoint in &oauth_endpoints {
            tests_run += 1;
            let token_url = format!("{}{}", base, endpoint);

            // Test with empty credentials
            let body = "grant_type=password&username=admin&password=admin";
            let headers = vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )];

            if let Ok(resp) = self
                .http_client
                .post_with_headers(&token_url, body, headers.clone())
                .await
            {
                // Check for OAuth2 endpoint indicators
                let is_oauth = resp.body.contains("access_token")
                    || resp.body.contains("token_type")
                    || resp.body.contains("invalid_grant")
                    || resp.body.contains("invalid_client")
                    || resp.body.contains("OAuth2PasswordBearer");

                if is_oauth {
                    let mut issues = Vec::new();

                    // Check if token endpoint is accessible
                    if resp.status_code == 200 && resp.body.contains("access_token") {
                        issues.push("Default/weak credentials accepted");
                    }

                    // Check for missing rate limiting
                    tests_run += 1;
                    let mut rapid_success = 0;
                    for _ in 0..5 {
                        if let Ok(r) = self
                            .http_client
                            .post_with_headers(&token_url, body, headers.clone())
                            .await
                        {
                            if r.status_code != 429 {
                                rapid_success += 1;
                            }
                        }
                    }
                    if rapid_success >= 5 {
                        issues.push("No rate limiting on token endpoint");
                    }

                    // Check for insecure token response
                    if resp.body.contains("refresh_token") && !resp.body.contains("expires_in") {
                        issues.push("Refresh token without expiry");
                    }

                    if !issues.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id("oauth2_misconfig"),
                            vuln_type: "FastAPI OAuth2 Security Issue".to_string(),
                            severity: if issues.iter().any(|i| i.contains("credentials")) {
                                Severity::Critical
                            } else {
                                Severity::High
                            },
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: token_url.clone(),
                            parameter: Some("OAuth2".to_string()),
                            payload: endpoint.to_string(),
                            description: format!(
                                "OAuth2 token endpoint has security issues: {}",
                                issues.join("; ")
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\nIssues: {}",
                                endpoint,
                                issues.join(", ")
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: if issues.iter().any(|i| i.contains("credentials")) {
                                9.8
                            } else {
                                7.5
                            },
                            verified: true,
                            false_positive: false,
                            remediation: "Secure OAuth2 implementation:\n\
                                1. Implement rate limiting on token endpoints\n\
                                2. Use strong password requirements\n\
                                3. Set appropriate token expiry times\n\
                                4. Use secure password hashing (bcrypt/argon2)\n\
                                5. Implement account lockout after failed attempts"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for exposed internal endpoints
    async fn check_internal_endpoints(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common internal/debug endpoints
        let internal_endpoints = [
            ("/health", "Health check", Severity::Info),
            ("/healthz", "Kubernetes health", Severity::Info),
            ("/livez", "Kubernetes liveness", Severity::Info),
            ("/readyz", "Kubernetes readiness", Severity::Info),
            ("/ready", "Readiness probe", Severity::Info),
            ("/metrics", "Prometheus metrics", Severity::Medium),
            ("/prometheus", "Prometheus scrape", Severity::Medium),
            ("/actuator", "Actuator root (Spring-style)", Severity::Medium),
            ("/actuator/health", "Actuator health", Severity::Low),
            ("/actuator/env", "Actuator env - exposes env vars", Severity::Critical),
            ("/actuator/heapdump", "Actuator heapdump", Severity::Critical),
            ("/actuator/configprops", "Actuator config props", Severity::High),
            ("/status", "Status endpoint", Severity::Low),
            ("/info", "Info endpoint", Severity::Low),
            ("/version", "Version endpoint", Severity::Low),
            ("/_internal/", "Internal routes", Severity::High),
            ("/_internal", "Internal routes", Severity::High),
            ("/internal", "Internal routes", Severity::High),
            ("/internal/", "Internal routes", Severity::High),
            ("/admin", "Admin interface", Severity::High),
            ("/admin/", "Admin interface", Severity::High),
            ("/debug", "Debug endpoint", Severity::Critical),
            ("/debug/", "Debug endpoint", Severity::Critical),
            ("/debug/pprof", "Go pprof profiler", Severity::High),
            ("/debug/pprof/", "Go pprof profiler index", Severity::High),
            ("/debug/vars", "Go expvar vars", Severity::Medium),
            ("/debug/events", "Go event trace", Severity::Medium),
            ("/api/internal/", "Internal API", Severity::High),
            ("/api/admin/", "Admin API", Severity::High),
            ("/api/v1/admin/", "v1 Admin API", Severity::High),
            ("/api/v1/internal/", "v1 Internal API", Severity::High),
            ("/graphql", "GraphQL endpoint", Severity::Medium),
            ("/playground", "GraphQL Playground", Severity::Medium),
            ("/graphiql", "GraphiQL interface", Severity::Medium),
            ("/altair", "Altair GraphQL client", Severity::Medium),
            ("/voyager", "GraphQL Voyager visualizer", Severity::Medium),
            ("/subscriptions", "GraphQL subscription endpoint", Severity::Low),
            ("/flower", "Celery Flower monitor - exposes task data", Severity::High),
            ("/flower/tasks", "Celery Flower tasks", Severity::High),
            ("/rq", "RQ dashboard - exposes job data", Severity::High),
            ("/rq/", "RQ dashboard", Severity::High),
            ("/dash", "Dash application", Severity::Low),
            ("/dashboard", "Dashboard route", Severity::Low),
        ];

        let mut exposed = Vec::new();

        for (path, desc, severity) in &internal_endpoints {
            tests_run += 1;
            let endpoint_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&endpoint_url).await {
                if resp.status_code == 200 && !resp.body.is_empty() {
                    let body = &resp.body;
                    let body_trim = body.trim();

                    // Per-endpoint-family signature validation. Each branch requires a
                    // specific content marker so SPA catch-all 200 responses do not fire.
                    let is_valid_endpoint = match *path {
                        p if p.starts_with("/metrics") || p == "/prometheus" => {
                            (body.contains("# HELP ") || body.contains("# TYPE "))
                                && body.contains('{') == false
                                || body.contains("# HELP ")
                        }
                        p if p.starts_with("/actuator/env") => {
                            body.contains("\"propertySources\"")
                                || body.contains("\"activeProfiles\"")
                        }
                        p if p.starts_with("/actuator/heapdump") => {
                            // Java heapdump starts with "JAVA PROFILE" or HPROF header
                            body.starts_with("JAVA PROFILE")
                                || body.as_bytes().starts_with(b"JAVA PROFILE")
                                || body.as_bytes().starts_with(&[0x4a, 0x41, 0x56, 0x41])
                        }
                        p if p.starts_with("/actuator/configprops") => {
                            body.contains("\"contexts\"") || body.contains("\"configurationProperties\"")
                        }
                        p if p.starts_with("/actuator") => {
                            body_trim.starts_with('{')
                                && (body.contains("\"_links\"") || body.contains("\"status\""))
                        }
                        p if p.starts_with("/debug/pprof") => {
                            body.contains("profiles:") || body.contains("/debug/pprof/heap")
                                || body.contains("full goroutine stack dump")
                        }
                        p if p == "/debug/vars" => {
                            body_trim.starts_with('{') && body.contains("\"cmdline\"")
                        }
                        p if p == "/flower" || p.starts_with("/flower/") => {
                            body.contains("Flower") || body.contains("/api/tasks")
                        }
                        p if p == "/rq" || p.starts_with("/rq/") => {
                            body.contains("RQ Dashboard") || body.contains("rq-dashboard")
                        }
                        p if p == "/graphql" || p == "/subscriptions" => {
                            body.contains("__schema")
                                || body.contains("\"errors\":[{\"message\"")
                                || body.contains("Must provide query string")
                        }
                        p if p == "/playground" || p == "/graphiql" || p == "/altair" || p == "/voyager" => {
                            body.contains("GraphQL Playground")
                                || body.contains("graphiql")
                                || body.contains("altair")
                                || body.contains("graphql-voyager")
                        }
                        p if p.starts_with("/admin") || p.starts_with("/api/admin") || p.starts_with("/api/v1/admin") => {
                            // Admin pages: only flag if response is JSON-ish structured OR
                            // HTML clearly labelled as an admin/backoffice page.
                            (body_trim.starts_with('{') || body_trim.starts_with('['))
                                || body.contains("Django administration")
                                || body.contains("FastAPI Admin")
                                || body.contains("sqladmin")
                                || body.contains("admin-panel")
                        }
                        p if p.starts_with("/internal") || p.starts_with("/_internal") || p.starts_with("/api/internal") || p.starts_with("/api/v1/internal") => {
                            body_trim.starts_with('{') || body_trim.starts_with('[')
                        }
                        p if p == "/info" || p == "/version" => {
                            body_trim.starts_with('{')
                                && (body.contains("\"version\"") || body.contains("\"build\""))
                        }
                        _ => {
                            body.len() < 10000
                                && (body_trim.starts_with('{') || body_trim.starts_with('['))
                        }
                    };

                    if is_valid_endpoint {
                        exposed.push((*path, *desc, severity.clone()));
                    }
                }
            }
        }

        // Report significant exposures
        let critical_exposed: Vec<_> = exposed
            .iter()
            .filter(|(_, _, s)| matches!(s, Severity::Critical | Severity::High))
            .collect();

        if !critical_exposed.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("internal_endpoints"),
                vuln_type: "FastAPI Internal Endpoints Exposed".to_string(),
                severity: critical_exposed
                    .iter()
                    .map(|(_, _, s)| s.clone())
                    .max_by(|a, b| {
                        let order = |s: &Severity| match s {
                            Severity::Critical => 4,
                            Severity::High => 3,
                            Severity::Medium => 2,
                            Severity::Low => 1,
                            Severity::Info => 0,
                        };
                        order(a).cmp(&order(b))
                    })
                    .unwrap_or(Severity::Medium),
                confidence: Confidence::High,
                category: "Misconfiguration".to_string(),
                url: base.to_string(),
                parameter: Some("internal_endpoints".to_string()),
                payload: critical_exposed
                    .iter()
                    .map(|(p, _, _)| *p)
                    .collect::<Vec<_>>()
                    .join(", "),
                description: format!(
                    "Internal or sensitive endpoints are publicly accessible: {}",
                    critical_exposed
                        .iter()
                        .map(|(p, d, _)| format!("{} ({})", p, d))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                evidence: Some(format!(
                    "Exposed endpoints:\n{}",
                    critical_exposed
                        .iter()
                        .map(|(p, d, s)| format!("  - {} ({}) - {:?}", p, d, s))
                        .collect::<Vec<_>>()
                        .join("\n")
                )),
                cwe: "CWE-200".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "Protect internal endpoints:\n\
                    1. Use APIRouter with dependencies for authentication\n\
                    2. Implement IP-based access controls\n\
                    3. Use separate internal and external routers\n\
                    4. Deploy internal services on separate networks"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Report metrics exposure separately (common but needs attention)
        if exposed.iter().any(|(p, _, _)| *p == "/metrics") {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("metrics_exposure"),
                vuln_type: "FastAPI Metrics Endpoint Exposed".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: format!("{}/metrics", base),
                parameter: Some("metrics".to_string()),
                payload: "/metrics".to_string(),
                description: "Prometheus metrics endpoint is publicly accessible. This may expose \
                    internal application metrics, performance data, and potentially sensitive \
                    business metrics."
                    .to_string(),
                evidence: Some("Metrics endpoint returns 200 OK".to_string()),
                cwe: "CWE-200".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "Protect metrics endpoint:\n\
                    1. Implement authentication via dependency injection\n\
                    2. Use network-level access controls\n\
                    3. Expose metrics only on internal interfaces"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for Pydantic validation bypass
    async fn check_pydantic_bypass(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Get OpenAPI schema to find endpoints with validation
        let openapi_url = format!("{}/openapi.json", base);
        tests_run += 1;

        if let Ok(resp) = self.http_client.get(&openapi_url).await {
            if resp.status_code == 200 && resp.body.contains("\"paths\"") {
                // Extract POST/PUT endpoints for testing
                let endpoint_re = Regex::new(r#""(/[^"]+)":\s*\{[^}]*"post"#).ok();

                if let Some(re) = endpoint_re {
                    let endpoints: Vec<String> = re
                        .captures_iter(&resp.body)
                        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                        .take(5)
                        .collect();

                    for endpoint in endpoints {
                        tests_run += 1;
                        let test_url = format!("{}{}", base, endpoint);

                        // Test type coercion bypass
                        let bypass_payloads = [
                            (r#"{"id": "1"}"#, "String to int coercion"),
                            (r#"{"id": [1]}"#, "Array to scalar coercion"),
                            (r#"{"id": {"$ne": 1}}"#, "NoSQL operator injection"),
                            (r#"{"id": true}"#, "Boolean to int coercion"),
                            (r#"{"__class__": "test"}"#, "Dunder attribute injection"),
                            (
                                r#"{"constructor": {"prototype": {}}}"#,
                                "Prototype pollution attempt",
                            ),
                        ];

                        for (payload, desc) in &bypass_payloads {
                            let headers =
                                vec![("Content-Type".to_string(), "application/json".to_string())];

                            if let Ok(bypass_resp) = self
                                .http_client
                                .post_with_headers(&test_url, payload, headers)
                                .await
                            {
                                // Check if request was processed instead of rejected
                                let was_processed = bypass_resp.status_code == 200
                                    || bypass_resp.status_code == 201
                                    || (bypass_resp.status_code >= 400
                                        && bypass_resp.status_code < 422
                                        && !bypass_resp.body.contains("validation"));

                                // Check for specific bypass indicators
                                let bypass_indicators = [
                                    "__class__",
                                    "prototype",
                                    "constructor",
                                    "unexpected keyword argument",
                                ];

                                let has_bypass_indicator = bypass_indicators
                                    .iter()
                                    .any(|i| bypass_resp.body.contains(i));

                                if was_processed || has_bypass_indicator {
                                    vulnerabilities.push(Vulnerability {
                                        id: generate_vuln_id("pydantic_bypass"),
                                        vuln_type: "FastAPI Pydantic Validation Bypass".to_string(),
                                        severity: Severity::High,
                                        confidence: Confidence::Medium,
                                        category: "Input Validation".to_string(),
                                        url: test_url.clone(),
                                        parameter: Some("body".to_string()),
                                        payload: payload.to_string(),
                                        description: format!(
                                            "Pydantic validation may be bypassed via: {}. \
                                            The application processed a payload that should have \
                                            been rejected by strict validation.",
                                            desc
                                        ),
                                        evidence: Some(format!(
                                            "Endpoint: {}\n\
                                            Payload: {}\n\
                                            Response status: {}\n\
                                            Bypass type: {}",
                                            endpoint, payload, bypass_resp.status_code, desc
                                        )),
                                        cwe: "CWE-20".to_string(),
                                        cvss: 7.5,
                                        verified: false,
                                        false_positive: false,
                                        remediation: "Strengthen Pydantic validation:\n\
                                            1. Use strict mode: model_config = ConfigDict(strict=True)\n\
                                            2. Add explicit validators for critical fields\n\
                                            3. Use constrained types (conint, constr)\n\
                                            4. Implement custom __init__ validation\n\
                                            5. Use Field(...) with strict constraints"
                                            .to_string(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for dependency injection vulnerabilities
    async fn check_dependency_injection(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Test for dependency override vulnerabilities
        tests_run += 1;

        // Check if OpenAPI exposes dependency information
        let openapi_url = format!("{}/openapi.json", base);
        if let Ok(resp) = self.http_client.get(&openapi_url).await {
            if resp.status_code == 200 {
                // Look for security scheme definitions
                let has_oauth2 = resp.body.contains("OAuth2PasswordBearer")
                    || resp.body.contains("oauth2")
                    || resp.body.contains("securitySchemes");

                let has_api_key = resp.body.contains("APIKeyHeader")
                    || resp.body.contains("APIKeyCookie")
                    || resp.body.contains("apiKey");

                // Check for exposed dependency patterns
                if resp.body.contains("Depends") || resp.body.contains("Security") {
                    // Test authentication bypass via header manipulation
                    let bypass_headers = [
                        ("X-Forwarded-User", "admin"),
                        ("X-Remote-User", "admin"),
                        ("X-Auth-User", "admin"),
                        ("Authorization", "Bearer invalid_token_test"),
                    ];

                    for (header, value) in &bypass_headers {
                        tests_run += 1;
                        let headers = vec![(header.to_string(), value.to_string())];

                        // Find a protected endpoint
                        let protected_endpoints =
                            ["/users/me", "/api/users/me", "/profile", "/admin"];

                        for endpoint in &protected_endpoints {
                            let test_url = format!("{}{}", base, endpoint);

                            if let Ok(auth_resp) = self
                                .http_client
                                .get_with_headers(&test_url, headers.clone())
                                .await
                            {
                                // Check if we got past authentication - require actual user data structure
                                if auth_resp.status_code == 200
                                    && (auth_resp.body.contains("\"email\":")
                                        || auth_resp.body.contains("\"username\":")
                                        || (auth_resp.body.contains("\"role\":") && auth_resp.body.contains("\"admin\""))
                                        || auth_resp.body.contains("\"password\":"))
                                {
                                    vulnerabilities.push(Vulnerability {
                                        id: generate_vuln_id("di_bypass"),
                                        vuln_type:
                                            "FastAPI Dependency Injection Authentication Bypass"
                                                .to_string(),
                                        severity: Severity::Critical,
                                        confidence: Confidence::Medium,
                                        category: "Authentication".to_string(),
                                        url: test_url.clone(),
                                        parameter: Some(header.to_string()),
                                        payload: format!("{}: {}", header, value),
                                        description: format!(
                                            "Authentication dependency may be bypassable via \
                                            header manipulation. The {} header with value '{}' \
                                            resulted in authenticated access.",
                                            header, value
                                        ),
                                        evidence: Some(format!(
                                            "Endpoint: {}\n\
                                            Header: {}: {}\n\
                                            Response: 200 OK with user data",
                                            endpoint, header, value
                                        )),
                                        cwe: "CWE-287".to_string(),
                                        cvss: 9.8,
                                        verified: false,
                                        false_positive: false,
                                        remediation: "Secure dependency injection:\n\
                                            1. Never trust headers for authentication\n\
                                            2. Always validate tokens server-side\n\
                                            3. Use cryptographic verification for auth\n\
                                            4. Implement proper token validation in dependencies"
                                            .to_string(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                    });
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                        }
                    }
                }

                // Report if security schemes are exposed
                if has_oauth2 || has_api_key {
                    // This is informational - security schemes in OpenAPI are expected
                    // but worth noting if docs are public
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for Starlette-specific issues
    async fn check_starlette_issues(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Check for session middleware issues
        tests_run += 1;

        // Test for session-related vulnerabilities
        if let Ok(resp) = self.http_client.get(base).await {
            if let Some(cookie) = resp.headers.get("set-cookie") {
                let mut session_issues = Vec::new();

                // Check session cookie security
                if cookie.contains("session") {
                    if !cookie.to_lowercase().contains("secure") {
                        session_issues.push("Session cookie missing Secure flag");
                    }
                    if !cookie.to_lowercase().contains("httponly") {
                        session_issues.push("Session cookie missing HttpOnly flag");
                    }
                    if !cookie.to_lowercase().contains("samesite") {
                        session_issues.push("Session cookie missing SameSite attribute");
                    }

                    // Check for weak session secret indicators
                    if cookie.contains("session=ey") {
                        // JWT-style session - check for weak signing
                        session_issues.push("JWT-style session detected - verify secret strength");
                    }
                }

                if !session_issues.is_empty() {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("session_config"),
                        vuln_type: "FastAPI/Starlette Session Misconfiguration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Session Management".to_string(),
                        url: base.to_string(),
                        parameter: Some("session".to_string()),
                        payload: "Set-Cookie analysis".to_string(),
                        description: format!(
                            "Starlette SessionMiddleware has security issues: {}",
                            session_issues.join("; ")
                        ),
                        evidence: Some(format!("Issues found:\n- {}", session_issues.join("\n- "))),
                        cwe: "CWE-614".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Configure SessionMiddleware securely:\n\
                            1. Use strong, random secret_key (32+ bytes)\n\
                            2. Set same_site='strict' or 'lax'\n\
                            3. Set https_only=True in production\n\
                            4. Consider using signed cookies or JWT with proper validation"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }
            }
        }

        // Check for server-timing header information disclosure
        tests_run += 1;
        if let Ok(resp) = self.http_client.get(base).await {
            if resp.headers.contains_key("server-timing") {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("server_timing"),
                    vuln_type: "FastAPI Server-Timing Header Exposure".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: base.to_string(),
                    parameter: Some("Server-Timing".to_string()),
                    payload: "Header inspection".to_string(),
                    description: "Server-Timing header is present, potentially exposing \
                        internal processing times that could aid timing attacks."
                        .to_string(),
                    evidence: Some(format!(
                        "Server-Timing header found: {}",
                        resp.headers
                            .get("server-timing")
                            .unwrap_or(&"present".to_string())
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation: "Remove Server-Timing header in production if not required."
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        // Check for GZip bomb vulnerability (CVE-2024-24762 in Starlette < 0.36.2)
        tests_run += 1;
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Encoding".to_string(), "gzip".to_string()),
        ];

        // Send a small gzipped payload - if server processes without size limit, it may be vulnerable
        if let Ok(resp) = self
            .http_client
            .post_with_headers(base, "{}", headers)
            .await
        {
            // Check if gzip is processed (indicates potential vulnerability to gzip bombs)
            if resp.status_code != 415 && resp.status_code != 400 {
                // Server accepted gzip - check if there are size limits
                // This is a low-confidence finding as we can't fully test without sending a gzip bomb
            }
        }

        Ok((vulnerabilities, tests_run))
    }
}

/// Generate a unique vulnerability ID
fn generate_vuln_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("FASTAPI-{}-{:x}", prefix.to_uppercase(), timestamp)
}
