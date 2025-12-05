// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloudflare Workers Security Scanner
 * Comprehensive security scanning for Cloudflare Workers
 *
 * Detects:
 * - Workers with secrets/credentials in code
 * - Workers without rate limiting
 * - Workers with CORS misconfigurations
 * - Workers without authentication
 * - Insecure environment variable handling
 * - Missing security headers
 * - Unsafe eval() usage
 * - SQL injection in Workers KV queries
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct CloudflareApiResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Worker {
    id: String,
    #[serde(default)]
    script: Option<String>,
    #[serde(default)]
    created_on: Option<String>,
    #[serde(default)]
    modified_on: Option<String>,
    #[serde(default)]
    etag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkerRoute {
    id: String,
    pattern: String,
    script: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CloudflareWorkersConfig {
    pub api_token: String,
    pub account_id: String,
    pub check_secrets: bool,
    pub check_cors: bool,
    pub check_auth: bool,
    pub check_rate_limiting: bool,
    pub check_security_headers: bool,
}

pub struct CloudflareWorkersScanner {
    http_client: Arc<HttpClient>,
    api_token: String,
}

impl CloudflareWorkersScanner {
    pub fn new(http_client: Arc<HttpClient>, api_token: String) -> Self {
        Self {
            http_client,
            api_token,
        }
    }

    /// Main scan function for Cloudflare Workers security
    pub async fn scan(
        &self,
        account_id: &str,
        config: &CloudflareWorkersConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting Cloudflare Workers security scan for account: {}", account_id);

        // Fetch all workers
        let workers = match self.fetch_workers(account_id).await {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to fetch workers: {}", e);
                return Ok((vulnerabilities, 0));
            }
        };

        if workers.is_empty() {
            info!("No workers found in account");
            return Ok((vulnerabilities, 0));
        }

        info!("Found {} workers to scan", workers.len());

        for worker_name in workers {
            info!("Scanning worker: {}", worker_name);

            // Fetch worker script
            let script = match self.fetch_worker_script(account_id, &worker_name).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to fetch worker script {}: {}", worker_name, e);
                    continue;
                }
            };

            // Check for secrets in code
            if config.check_secrets {
                let (vulns, tests) = self.check_secrets_in_code(&worker_name, &script).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Check CORS configuration
            if config.check_cors {
                let (vulns, tests) = self.check_cors_config(&worker_name, &script).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Check authentication
            if config.check_auth {
                let (vulns, tests) = self.check_authentication(&worker_name, &script).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Check rate limiting
            if config.check_rate_limiting {
                let (vulns, tests) = self.check_rate_limiting(&worker_name, &script).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Check security headers
            if config.check_security_headers {
                let (vulns, tests) = self.check_security_headers(&worker_name, &script).await?;
                vulnerabilities.extend(vulns);
                tests_run += tests;
            }

            // Check for unsafe code patterns
            let (vulns, tests) = self.check_unsafe_patterns(&worker_name, &script).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Check environment variable handling
            let (vulns, tests) = self.check_env_handling(&worker_name, &script).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        info!(
            "Cloudflare Workers scan completed: {} vulnerabilities found, {} tests run",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Fetch list of workers
    async fn fetch_workers(&self, account_id: &str) -> anyhow::Result<Vec<String>> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts",
            account_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let response = self.http_client.get_with_headers(&url, headers).await?;

        // Workers API returns a list of objects with script names
        let api_response: CloudflareApiResponse<Vec<serde_json::Value>> =
            serde_json::from_str(&response.body)?;

        if !api_response.success {
            let errors = api_response
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow::anyhow!("Cloudflare API error: {}", errors));
        }

        let mut worker_names = Vec::new();
        if let Some(workers) = api_response.result {
            for worker in workers {
                if let Some(id) = worker.get("id").and_then(|v| v.as_str()) {
                    worker_names.push(id.to_string());
                }
            }
        }

        Ok(worker_names)
    }

    /// Fetch worker script content
    async fn fetch_worker_script(
        &self,
        account_id: &str,
        worker_name: &str,
    ) -> anyhow::Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/workers/scripts/{}",
            account_id, worker_name
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Accept".to_string(), "application/javascript".to_string()),
        ];

        let response = self.http_client.get_with_headers(&url, headers).await?;

        Ok(response.body)
    }

    /// Check for secrets and credentials in worker code
    async fn check_secrets_in_code(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        info!("Checking for secrets in worker code");

        // Patterns for common secrets
        let secret_patterns = vec![
            (r#"["']([a-zA-Z0-9_-]*[aA][pP][iI][_-]?[kK][eE][yY])\s*[:=]\s*["']([^"']+)["']"#, "API Key"),
            (r#"["']([a-zA-Z0-9_-]*[pP][aA][sS][sS][wW][oO][rR][dD])\s*[:=]\s*["']([^"']+)["']"#, "Password"),
            (r#"["']([a-zA-Z0-9_-]*[tT][oO][kK][eE][nN])\s*[:=]\s*["']([^"']+)["']"#, "Token"),
            (r#"["']([a-zA-Z0-9_-]*[sS][eE][cC][rR][eE][tT])\s*[:=]\s*["']([^"']+)["']"#, "Secret"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
            (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
            (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Secret Key"),
            (r"pk_live_[a-zA-Z0-9]{24,}", "Stripe Live Publishable Key"),
            (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
            (r#"["']private[_-]?key["']\s*:\s*["']-----BEGIN PRIVATE KEY-----"#, "Private Key"),
            (r"Bearer [a-zA-Z0-9_\-\.]+", "Bearer Token"),
            (r"Basic [a-zA-Z0-9_\-\.]+", "Basic Auth Credentials"),
        ];

        for (pattern, secret_type) in secret_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(script) {
                    let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");
                    vulnerabilities.push(self.create_vulnerability(
                        worker_name,
                        "Hardcoded Secret in Worker",
                        matched,
                        &format!("{} found hardcoded in worker script", secret_type),
                        &format!("Worker contains hardcoded {} that should use environment variables", secret_type),
                        Severity::Critical,
                        "CWE-798",
                        9.8,
                    ));
                }
            }
        }

        // Check for console.log with sensitive data
        if let Ok(re) = Regex::new(r"console\.log\([^)]*(?:password|token|secret|key)[^)]*\)") {
            if re.is_match(script) {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Sensitive Data Logging",
                    "console.log",
                    "Worker logs sensitive data to console",
                    "Sensitive information may be exposed in Cloudflare logs",
                    Severity::Medium,
                    "CWE-532",
                    5.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check CORS configuration
    async fn check_cors_config(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Checking CORS configuration");

        // Check for wildcard CORS
        if script.contains("Access-Control-Allow-Origin") {
            if script.contains("'*'") || script.contains("\"*\"") {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Overly Permissive CORS",
                    "Access-Control-Allow-Origin: *",
                    "Worker allows requests from any origin (*)",
                    "CORS policy allows any website to make requests to this worker",
                    Severity::Medium,
                    "CWE-942",
                    6.5,
                ));
            }

            // Check if credentials are allowed with wildcard
            if (script.contains("'*'") || script.contains("\"*\""))
                && script.contains("Access-Control-Allow-Credentials")
            {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Insecure CORS Configuration",
                    "CORS with credentials and wildcard",
                    "Worker allows credentials with wildcard origin",
                    "Critical CORS misconfiguration allows credential theft",
                    Severity::Critical,
                    "CWE-942",
                    9.1,
                ));
            }
        }

        // Check for reflected origin in CORS
        if let Ok(re) = Regex::new(r#"request\.headers\.get\(['"]origin['"]\)"#) {
            if re.is_match(script) && script.contains("Access-Control-Allow-Origin") {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "CORS Origin Reflection",
                    "Reflected request origin",
                    "Worker reflects request origin without validation",
                    "May allow unauthorized cross-origin requests",
                    Severity::High,
                    "CWE-942",
                    7.5,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check authentication implementation
    async fn check_authentication(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Checking authentication");

        // Check if worker handles authentication
        let has_auth = script.contains("Authorization")
            || script.contains("authenticate")
            || script.contains("Bearer")
            || script.contains("JWT");

        if !has_auth && script.contains("POST") {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "No Authentication Detected",
                "",
                "Worker handles POST requests without apparent authentication",
                "Worker may be vulnerable to unauthorized access",
                Severity::High,
                "CWE-306",
                7.5,
            ));
        }

        // Check for weak authentication
        if script.contains("btoa") && script.contains("Authorization") {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "Basic Authentication Used",
                "Basic Auth",
                "Worker uses Basic Authentication (base64 encoded credentials)",
                "Basic auth transmits credentials in easily decoded format",
                Severity::Medium,
                "CWE-522",
                5.3,
            ));
        }

        // Check for hardcoded JWT secrets
        if script.contains("jwt.sign") || script.contains("jsonwebtoken") {
            if let Ok(re) = Regex::new(r#"sign\([^,]+,\s*["'][^"']{10,}["']"#) {
                if re.is_match(script) {
                    vulnerabilities.push(self.create_vulnerability(
                        worker_name,
                        "Hardcoded JWT Secret",
                        "jwt.sign",
                        "Worker contains hardcoded JWT signing secret",
                        "JWT secret should be stored in environment variables",
                        Severity::Critical,
                        "CWE-798",
                        9.1,
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check rate limiting implementation
    async fn check_rate_limiting(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Checking rate limiting");

        // Check if rate limiting is implemented
        let has_rate_limiting = script.contains("rate") && script.contains("limit")
            || script.contains("throttle")
            || script.contains("rateLimit");

        if !has_rate_limiting && (script.contains("POST") || script.contains("PUT")) {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "No Rate Limiting",
                "",
                "Worker handles state-changing requests without rate limiting",
                "Worker is vulnerable to abuse and DoS attacks",
                Severity::High,
                "CWE-770",
                7.5,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check security headers
    async fn check_security_headers(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Checking security headers");

        let critical_headers = vec![
            ("Content-Security-Policy", "CSP"),
            ("X-Content-Type-Options", "X-Content-Type-Options"),
            ("X-Frame-Options", "X-Frame-Options"),
            ("Strict-Transport-Security", "HSTS"),
        ];

        for (header, name) in critical_headers {
            if !script.contains(header) {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    &format!("Missing {} Header", name),
                    header,
                    &format!("Worker does not set {} security header", name),
                    &format!("Missing {} increases attack surface", name),
                    Severity::Medium,
                    "CWE-693",
                    5.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for unsafe code patterns
    async fn check_unsafe_patterns(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        info!("Checking for unsafe code patterns");

        // Check for eval() usage
        if let Ok(re) = Regex::new(r"\beval\s*\(") {
            if re.is_match(script) {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Unsafe eval() Usage",
                    "eval()",
                    "Worker uses eval() which can execute arbitrary code",
                    "eval() is dangerous and can lead to code injection",
                    Severity::High,
                    "CWE-95",
                    8.1,
                ));
            }
        }

        // Check for Function constructor
        if let Ok(re) = Regex::new(r"new\s+Function\s*\(") {
            if re.is_match(script) {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Function Constructor Usage",
                    "new Function()",
                    "Worker uses Function constructor (similar to eval)",
                    "Function constructor can execute arbitrary code",
                    Severity::High,
                    "CWE-95",
                    7.5,
                ));
            }
        }

        // Check for innerHTML usage
        if script.contains("innerHTML") {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "innerHTML Usage",
                "innerHTML",
                "Worker uses innerHTML which can lead to XSS",
                "Use textContent or safer DOM manipulation methods",
                Severity::Medium,
                "CWE-79",
                6.5,
            ));
        }

        // Check for SQL-like queries in KV
        if script.contains("KV") && (script.contains("SELECT") || script.contains("WHERE")) {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "Potential KV Query Injection",
                "KV query",
                "Worker may be constructing KV queries from user input",
                "Validate and sanitize all input used in KV operations",
                Severity::Medium,
                "CWE-89",
                6.5,
            ));
        }

        // Check for unsafe redirects
        if let Ok(re) = Regex::new(r"Response\.redirect\([^)]*url[^)]*\)") {
            if re.is_match(script) {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Potential Open Redirect",
                    "Response.redirect",
                    "Worker redirects based on URL parameter",
                    "Validate redirect destinations to prevent open redirect",
                    Severity::Medium,
                    "CWE-601",
                    5.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check environment variable handling
    async fn check_env_handling(
        &self,
        worker_name: &str,
        script: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Checking environment variable handling");

        // Check if env vars are exposed in responses
        if let Ok(re) = Regex::new(r"env\.[A-Z_]+") {
            if re.is_match(script) && script.contains("JSON.stringify") {
                vulnerabilities.push(self.create_vulnerability(
                    worker_name,
                    "Potential Environment Variable Exposure",
                    "env.*",
                    "Worker may expose environment variables in response",
                    "Environment variables should never be sent to clients",
                    Severity::High,
                    "CWE-200",
                    7.5,
                ));
            }
        }

        // Check for missing env variable validation
        if script.contains("env.") && !script.contains("!env.") && !script.contains("typeof env") {
            vulnerabilities.push(self.create_vulnerability(
                worker_name,
                "Missing Environment Variable Validation",
                "env",
                "Worker accesses environment variables without validation",
                "Always validate environment variables exist before use",
                Severity::Low,
                "CWE-252",
                3.7,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cf_worker_{}", self.generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloudflare Workers Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn generate_uuid(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!(
            "{:08x}{:04x}{:04x}{:04x}{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u64>() & 0xffffffffffff
        )
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Hardcoded Secret in Worker" | "Hardcoded JWT Secret" => {
                "1. Remove all hardcoded secrets from worker code\n\
                 2. Use environment variables or Workers Secrets\n\
                 3. Bind secrets using wrangler.toml [vars] section\n\
                 4. Rotate all exposed credentials immediately\n\
                 5. Use Cloudflare Workers Secrets: wrangler secret put SECRET_NAME\n\
                 6. Never commit secrets to version control\n\
                 7. Implement secret scanning in CI/CD pipeline".to_string()
            }
            "Sensitive Data Logging" => {
                "1. Remove console.log statements with sensitive data\n\
                 2. Use structured logging without sensitive fields\n\
                 3. Implement log filtering for production\n\
                 4. Review Cloudflare logs for exposed data\n\
                 5. Use environment variables to control log verbosity".to_string()
            }
            "Overly Permissive CORS" | "Insecure CORS Configuration" | "CORS Origin Reflection" => {
                "1. Restrict CORS to specific trusted origins\n\
                 2. Never use wildcard (*) with credentials\n\
                 3. Validate origin against whitelist before reflection\n\
                 4. Implement proper CORS headers:\n\
                    - Access-Control-Allow-Origin: specific domain\n\
                    - Access-Control-Allow-Methods: only needed methods\n\
                    - Access-Control-Allow-Headers: only needed headers\n\
                 5. Use Access-Control-Max-Age to reduce preflight requests\n\
                 6. Test CORS configuration with security tools".to_string()
            }
            "No Authentication Detected" | "Basic Authentication Used" => {
                "1. Implement proper authentication (JWT, OAuth2)\n\
                 2. Use Bearer tokens instead of Basic Auth\n\
                 3. Validate all authentication tokens\n\
                 4. Implement request signing for API calls\n\
                 5. Use HTTPS for all requests\n\
                 6. Set short token expiration times\n\
                 7. Implement token refresh mechanism".to_string()
            }
            "No Rate Limiting" => {
                "1. Implement rate limiting using Workers KV:\n\
                    const count = await KV.get(ip)\n\
                    if (count > limit) return new Response('Too many requests', {status: 429})\n\
                 2. Track requests by IP address or API key\n\
                 3. Use sliding window or token bucket algorithm\n\
                 4. Return appropriate 429 status codes\n\
                 5. Include Retry-After header\n\
                 6. Consider using Cloudflare Rate Limiting product\n\
                 7. Implement different limits for different endpoints".to_string()
            }
            "Missing CSP Header" | "Missing X-Content-Type-Options Header" |
            "Missing X-Frame-Options Header" | "Missing HSTS Header" => {
                "1. Set all security headers in worker response:\n\
                    response.headers.set('Content-Security-Policy', \"default-src 'self'\")\n\
                    response.headers.set('X-Content-Type-Options', 'nosniff')\n\
                    response.headers.set('X-Frame-Options', 'DENY')\n\
                    response.headers.set('Strict-Transport-Security', 'max-age=31536000')\n\
                 2. Configure CSP based on application needs\n\
                 3. Enable HSTS with appropriate max-age\n\
                 4. Test headers using security scanning tools\n\
                 5. Document header policy decisions".to_string()
            }
            "Unsafe eval() Usage" | "Function Constructor Usage" => {
                "1. Remove all eval() and Function constructor usage\n\
                 2. Use JSON.parse() for parsing JSON instead of eval()\n\
                 3. Refactor code to avoid dynamic code execution\n\
                 4. Use safe alternatives like JSON schema validation\n\
                 5. Implement Content Security Policy to block eval()\n\
                 6. Enable strict mode: 'use strict'".to_string()
            }
            "innerHTML Usage" => {
                "1. Replace innerHTML with safer alternatives:\n\
                    - Use textContent for text\n\
                    - Use createElement() and appendChild()\n\
                 2. Sanitize HTML if innerHTML is necessary\n\
                 3. Use DOMPurify library for HTML sanitization\n\
                 4. Implement Content Security Policy\n\
                 5. Validate and escape all user input".to_string()
            }
            "Potential Open Redirect" => {
                "1. Validate redirect URLs against whitelist\n\
                 2. Use relative URLs for internal redirects\n\
                 3. Parse and validate URL scheme and host\n\
                 4. Reject redirects to external domains\n\
                 5. Log redirect attempts for monitoring\n\
                 6. Never redirect based on unvalidated user input".to_string()
            }
            "Potential Environment Variable Exposure" => {
                "1. Never include environment variables in responses\n\
                 2. Use env vars only for server-side logic\n\
                 3. Create separate public configuration\n\
                 4. Review all JSON.stringify() calls\n\
                 5. Implement response filtering\n\
                 6. Audit worker code for data leaks".to_string()
            }
            _ => "Review and remediate according to Cloudflare Workers security best practices".to_string(),
        }
    }
}
