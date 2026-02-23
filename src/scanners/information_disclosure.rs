// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::baseline_detector::BaselineDetector;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct InformationDisclosureScanner {
    http_client: Arc<HttpClient>,
    baseline_detector: BaselineDetector,
}

impl InformationDisclosureScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let baseline_detector = BaselineDetector::new(Arc::clone(&http_client));
        Self {
            http_client,
            baseline_detector,
        }
    }

    /// Scan endpoint for information disclosure vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // PREMIUM FEATURE: Information Disclosure requires Professional license
        if !crate::license::is_feature_available("information_disclosure") {
            debug!("[InfoDisclosure] Feature requires Professional license or higher");
            return Ok((vulnerabilities, tests_run));
        }

        info!("Testing information disclosure vulnerabilities");

        // Baseline detection: check if site responds identically to all requests
        // NOTE: We do NOT skip tests even if responses are identical, because
        // some sites return the same 404 page for everything but still expose
        // real sensitive files. Instead, we rely on pattern-based content detection.
        let baseline_result = self.baseline_detector.is_static_responder(url).await;
        if baseline_result.is_static_responder {
            warn!(
                "Site appears to respond identically to all requests ({:.1}% similarity). \
                Will still check for sensitive files using pattern-based detection.",
                baseline_result.similarity_score * 100.0
            );
        }

        // Test for sensitive file exposure
        let (vulns, tests) = self.test_sensitive_files(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for stack traces
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_stack_traces(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test for directory listing
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_directory_listing(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test for server information disclosure
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_server_disclosure(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for sensitive file exposure
    async fn test_sensitive_files(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 25; // Updated count

        debug!("Testing sensitive file exposure");

        let sensitive_files = vec![
            // Environment files
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.backup",
            // Config files
            "/config.php",
            "/config.json",
            "/config.yml",
            "/web.config",
            "/app.config",
            "/configuration.php",
            // Git files
            "/.git/config",
            "/.git/HEAD",
            // Package management
            "/composer.json",
            "/package.json",
            // Web server configs
            "/.htaccess",
            "/phpinfo.php",
            // Backup files
            "/backup.sql",
            "/db_backup.sql",
            "/database.sql",
            "/backup.zip",
            "/config.php.bak",
            "/index.php.old",
            "/site.tar.gz",
        ];

        let base_url = self.extract_base_url(url);

        for file in sensitive_files {
            let test_url = format!("{}{}", base_url, file);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200
                        && self.detect_sensitive_content(&response.body, file)
                    {
                        info!("Sensitive file exposed: {}", file);
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Sensitive File Exposure",
                            file,
                            &format!("Sensitive file {} is publicly accessible", file),
                            &format!("File {} returned 200 OK with sensitive content", file),
                            Severity::High,
                            "CWE-200",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for stack traces in error messages
    async fn test_stack_traces(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing for stack traces");

        // First get a baseline response to compare against
        let baseline = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), 0)),
        };

        let error_triggers = vec![
            "?error=1",
            "?debug=true",
            "?id=999999999",
            "?test='",
            "?param=<script>",
        ];

        for trigger in error_triggers {
            let test_url = format!("{}{}", url, trigger);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Skip 404 or not-found responses
                    if response.status_code == 404 || self.is_not_found_response(&response.body) {
                        debug!("Skipping 404/not-found response for stack trace check");
                        continue;
                    }

                    // Check if response is significantly different from baseline
                    // (if it's the same page, no error was triggered)
                    if self.responses_are_similar(&baseline.body, &response.body) {
                        debug!("Response similar to baseline, skipping stack trace check");
                        continue;
                    }

                    if self.detect_stack_trace(&response.body) {
                        info!("Stack trace detected in error response");
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Stack Trace Disclosure",
                            trigger,
                            "Application exposes stack traces in error messages",
                            "Stack trace with file paths and line numbers detected",
                            Severity::Medium,
                            "CWE-209",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if response body indicates a "not found" or similar error
    fn is_not_found_response(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for common API error patterns indicating resource not found
        let not_found_patterns = [
            "\"error\":\"not found\"",
            "\"error\": \"not found\"",
            "\"message\":\"the requested resource does not exist\"",
            "resource does not exist",
            "endpoint not found",
            "route not found",
        ];

        for pattern in &not_found_patterns {
            if body_lower.contains(pattern) {
                return true;
            }
        }

        // Check for JSON error response with success:false and error containing "not found"
        if body_lower.contains("\"success\":false") || body_lower.contains("\"success\": false") {
            if body_lower.contains("not found") || body_lower.contains("does not exist") {
                return true;
            }
        }

        false
    }

    /// Check if two responses are similar (same content = error trigger had no effect)
    fn responses_are_similar(&self, baseline: &str, response: &str) -> bool {
        // If lengths are very different, they're not similar
        let len_diff = (baseline.len() as i64 - response.len() as i64).abs();
        let max_len = baseline.len().max(response.len());

        if max_len == 0 {
            return true; // Both empty
        }

        // If length difference is more than 20%, they're different enough
        if len_diff > (max_len as i64 / 5) {
            return false;
        }

        // Simple character comparison for shorter strings
        if max_len < 10000 {
            let matching_chars = baseline
                .chars()
                .zip(response.chars())
                .filter(|(a, b)| a == b)
                .count();

            let similarity = matching_chars as f64 / max_len as f64;
            return similarity > 0.9; // 90% similar = same page
        }

        // For longer strings, just use length-based comparison
        (len_diff as f64 / max_len as f64) < 0.1
    }

    /// Test for directory listing
    async fn test_directory_listing(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing for directory listing");

        let base_url = self.extract_base_url(url);
        let directories = vec!["/uploads/", "/images/", "/files/", "/static/", "/assets/"];

        for dir in directories {
            let test_url = format!("{}{}", base_url, dir);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.detect_directory_listing(&response.body)
                    {
                        info!("Directory listing exposed: {}", dir);
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Directory Listing Enabled",
                            dir,
                            &format!("Directory listing is enabled for {}", dir),
                            "Directory index page detected",
                            Severity::Medium,
                            "CWE-548",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for server information disclosure
    async fn test_server_disclosure(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 1;

        debug!("Testing for server information disclosure");

        // Test 1: Check main URL headers
        match self.http_client.get(url).await {
            Ok(response) => {
                if let Some(evidence) = self.detect_server_disclosure(&response.headers) {
                    info!("Server information disclosed in headers: {}", evidence);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Server Version Disclosure",
                        "",
                        "Server headers reveal version information. This helps attackers identify \
                        known vulnerabilities for specific server versions.",
                        &evidence,
                        Severity::Low,
                        "CWE-200",
                    ));
                }

                // Check for debug mode
                if self.detect_debug_mode(&response.body, &response.headers) {
                    info!("Debug mode enabled");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Debug Mode Enabled",
                        "",
                        "Application is running in debug mode",
                        "Debug information exposed in response",
                        Severity::Medium,
                        "CWE-215",
                    ));
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        // Test 2: Check debug endpoints that might reveal server version.
        // Note: /health, /status, /version are intentionally exposed on many APIs
        // for operational monitoring. They are NOT debug endpoints and should not
        // be reported as info disclosure unless they expose detailed server info.
        // We focus on endpoints that expose SENSITIVE internal details.
        let base_url = self.extract_base_url(url);
        let debug_endpoints = vec![
            "/server-status",           // Apache mod_status - exposes request details
            "/server-info",             // Apache mod_info - exposes module details
            "/nginx_status",            // Nginx stub_status - connection metrics
            "/actuator/info",           // Spring Boot - App info
            "/actuator/env",            // Spring Boot - Environment variables (CRITICAL)
            "/actuator/configprops",    // Spring Boot - Configuration properties
            "/actuator/mappings",       // Spring Boot - URL mappings
            "/actuator/beans",          // Spring Boot - All beans
            "/actuator/heapdump",       // Spring Boot - Heap dump (CRITICAL)
            "/actuator/threaddump",     // Spring Boot - Thread dump
            "/actuator/metrics",        // Spring Boot - Metrics
            "/actuator/scheduledtasks", // Spring Boot - Scheduled tasks
            "/actuator/httptrace",      // Spring Boot - HTTP trace
            "/actuator/auditevents",    // Spring Boot - Audit events
            "/actuator/loggers",        // Spring Boot - Loggers
            "/actuator/sessions",       // Spring Boot - Sessions
            "/actuator/shutdown",       // Spring Boot - Shutdown (CRITICAL if POST)
            "/actuator/jolokia",        // Spring Boot - JMX over HTTP (RCE possible)
            "/actuator/gateway/routes", // Spring Cloud Gateway routes
            "/manage/env",              // Legacy Spring Boot
            "/manage/heapdump",         // Legacy Spring Boot
            "/env",                     // Direct actuator
            "/heapdump",                // Direct actuator
            "/trace",                   // Direct actuator
            "/dump",                    // Direct actuator
            "/__version__",             // Python apps
            "/health",                  // Health endpoint - only flagged if it leaks version info
            "/actuator/health",         // Spring Boot health - may expose component details
        ];

        for endpoint in debug_endpoints {
            tests_run += 1;
            let test_url = format!("{}{}", base_url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        // Check headers for version info
                        if let Some(evidence) = self.detect_server_disclosure(&response.headers) {
                            // Don't duplicate if we already found main header disclosure
                            if !vulnerabilities
                                .iter()
                                .any(|v| v.vuln_type == "Server Version Disclosure")
                            {
                                info!("Server version disclosed via debug endpoint: {}", endpoint);
                                vulnerabilities.push(self.create_vulnerability(
                                    &test_url,
                                    "Server Version Disclosure",
                                    endpoint,
                                    &format!(
                                        "Debug endpoint {} exposes server version information",
                                        endpoint
                                    ),
                                    &evidence,
                                    Severity::Low,
                                    "CWE-200",
                                ));
                            }
                        }

                        // Check body for version patterns
                        if let Some(body_evidence) = self.detect_version_in_body(&response.body) {
                            info!("Server version found in debug endpoint body: {}", endpoint);
                            vulnerabilities.push(self.create_vulnerability(
                                &test_url,
                                "Server Version Disclosure - Debug Endpoint",
                                endpoint,
                                &format!("Debug endpoint {} exposes detailed version/configuration information", endpoint),
                                &body_evidence,
                                Severity::Medium,
                                "CWE-200",
                            ));
                            break; // Found detailed disclosure, no need to continue
                        }
                    }
                }
                Err(e) => {
                    debug!("Debug endpoint {} check failed: {}", endpoint, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect version information in response body
    fn detect_version_in_body(&self, body: &str) -> Option<String> {
        use regex::Regex;

        let mut findings = Vec::new();

        // Common server version patterns
        let version_patterns = vec![
            (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
            (r"Apache/(\d+\.\d+\.\d+)", "Apache"),
            (r"PHP/(\d+\.\d+\.\d+)", "PHP"),
            (r"Python/(\d+\.\d+\.\d+)", "Python"),
            (r"Node\.js v?(\d+\.\d+\.\d+)", "Node.js"),
            (r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)", "OpenSSL"),
            (r"Tomcat/(\d+\.\d+\.\d+)", "Tomcat"),
            (r"JBoss[^0-9]*(\d+\.\d+\.\d+)", "JBoss"),
            (r"IIS/(\d+\.\d+)", "IIS"),
            (r"Express/(\d+\.\d+\.\d+)", "Express"),
            (r"Rails/(\d+\.\d+\.\d+)", "Rails"),
            (r"Django/(\d+\.\d+\.\d+)", "Django"),
            (r"Spring Boot[^0-9]*(\d+\.\d+\.\d+)", "Spring Boot"),
            (r"Laravel/(\d+\.\d+\.\d+)", "Laravel"),
            (r#""version"\s*:\s*"([^"]+)""#, "Application"),
            (r#""server"\s*:\s*"([^"]+)""#, "Server"),
            (r#""build"\s*:\s*"([^"]+)""#, "Build"),
        ];

        for (pattern, name) in version_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(body) {
                    if let Some(version) = cap.get(1) {
                        findings.push(format!("{}: {}", name, version.as_str()));
                    }
                }
            }
        }

        // Check for Spring Boot Actuator info
        if body.contains("\"app\"") && body.contains("\"version\"") {
            findings.push("Spring Boot Actuator info endpoint exposed".to_string());
        }

        // Check for server status pages
        if body.contains("Server Version:") || body.contains("Server Built:") {
            findings.push("Server status page exposed".to_string());
        }

        if findings.is_empty() {
            None
        } else {
            Some(format!(
                "Version information found:\n  {}",
                findings.join("\n  ")
            ))
        }
    }

    /// Detect sensitive content in file using pattern-based detection
    /// This ensures we only report findings when actual sensitive patterns are found,
    /// not just based on response similarity or status codes.
    fn detect_sensitive_content(&self, body: &str, filename: &str) -> bool {
        if body.is_empty() || body.len() < 10 {
            return false;
        }

        // Use pattern-based detection instead of relying on response similarity
        match filename {
            // .env files - look for KEY=value patterns
            f if f.contains(".env") => {
                // Specific .env patterns with KEY=VALUE format
                body.contains("DB_PASSWORD=")
                    || body.contains("DATABASE_PASSWORD=")
                    || body.contains("API_KEY=")
                    || body.contains("SECRET_KEY=")
                    || body.contains("AWS_SECRET=")
                    || body.contains("PRIVATE_KEY=")
                    || body.contains("JWT_SECRET=")
                    || body.contains("SESSION_SECRET=")
                    // Generic patterns
                    || (body.contains("=") && (
                        body.contains("PASSWORD")
                        || body.contains("SECRET")
                        || body.contains("API_KEY")
                        || body.contains("DATABASE")
                        || body.contains("TOKEN")
                    ))
            }
            // Git config files - look for git-specific patterns
            f if f.contains(".git") => {
                // Git config specific patterns
                body.contains("[core]")
                    || body.contains("[remote")
                    || body.contains("repositoryformatversion")
                    || body.contains("[branch")
                    || body.contains("filemode")
                    || body.contains("bare = ")
                    // Git HEAD file pattern
                    || body.contains("ref: refs/")
            }
            // Config files - look for configuration patterns
            f if f.contains("config") => {
                let body_lower = body.to_lowercase();
                // Must have actual config structure patterns
                (body_lower.contains("password") && (body_lower.contains("=") || body_lower.contains(":")))
                    || (body_lower.contains("secret") && (body_lower.contains("=") || body_lower.contains(":")))
                    || (body_lower.contains("database") && body_lower.contains("host"))
                    || (body_lower.contains("api") && (body_lower.contains("key") || body_lower.contains("token")))
                    || body_lower.contains("connectionstring")
            }
            // Backup SQL files - look for SQL dump patterns
            f if f.ends_with(".sql") || f.contains("backup.sql") || f.contains("db_backup") => {
                // SQL dump specific patterns
                body.contains("CREATE TABLE")
                    || body.contains("INSERT INTO")
                    || body.contains("DROP TABLE")
                    || body.contains("-- MySQL dump")
                    || body.contains("-- PostgreSQL database dump")
                    || body.contains("-- Dumping data for table")
                    || body.contains("LOCK TABLES")
                    || body.contains("mysqldump")
                    || body.contains("pg_dump")
            }
            // Backup archive files - look for archive patterns
            f if f.ends_with(".zip") || f.ends_with(".tar.gz") || f.ends_with(".tar") => {
                // Binary file signatures
                let bytes = body.as_bytes();
                body.starts_with("PK") // ZIP signature
                    || (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b) // GZIP signature
                    || body.contains("ustar") // TAR signature
                    || body.len() > 1000 // Likely binary if large enough
            }
            // Backup source files (.bak, .old) - look for source code patterns
            f if f.ends_with(".bak") || f.ends_with(".old") => {
                // Source code patterns
                body.contains("<?php")
                    || body.contains("function ")
                    || body.contains("class ")
                    || body.contains("def ")
                    || body.contains("import ")
                    || body.contains("require(")
                    || body.contains("include(")
                    || (body.contains("=") && body.contains(";"))
            }
            // package.json / composer.json
            f if f.contains("package.json") || f.contains("composer.json") => {
                (body.contains("dependencies") || body.contains("require"))
                    && (body.contains("{") && body.contains("}"))
            }
            // phpinfo files
            f if f.contains("phpinfo") => {
                // Must contain actual phpinfo() output indicators
                body.contains("PHP Version")
                    || body.contains("phpinfo()")
                    || body.contains("php.ini")
                    || body.contains("Configuration File")
                    || body.contains("Apache Environment")
            }
            // .htaccess files
            f if f.contains(".htaccess") => {
                body.contains("RewriteRule")
                    || body.contains("RewriteEngine")
                    || body.contains("AuthType")
                    || body.contains("Require ")
                    || body.contains("AllowOverride")
            }
            // For unknown files, require strong sensitive patterns
            _ => {
                let body_lower = body.to_lowercase();
                // Must have key=value or key:value patterns with sensitive keywords
                (body_lower.contains("password") && (body_lower.contains("=") || body_lower.contains(":")))
                    || (body_lower.contains("secret") && body_lower.contains("="))
                    || body_lower.contains("api_key=")
                    || body_lower.contains("private_key=")
                    || (body_lower.contains("credentials") && body_lower.contains(":"))
                    || body_lower.contains("token=")
            }
        }
    }

    /// Detect stack trace in response with specific language patterns
    /// Detects Python, Java, PHP, and Node.js error formats
    fn detect_stack_trace(&self, body: &str) -> bool {
        // Python stack traces - specific patterns
        if (body.contains("Traceback (most recent call last)")
            || body.contains("File \"") && body.contains("line "))
            && (body.contains(".py\"") || body.contains("in <module>") || body.contains("raise ")) {
            return true;
        }

        // Java stack traces - specific patterns
        if (body.contains("Exception") || body.contains("Error"))
            && (body.contains("at ") && (body.contains(".java:") || body.contains("(") && body.contains(")")))
            && (body.contains("Caused by:") || body.contains("at java.") || body.contains("at org.") || body.contains("at com.")) {
            return true;
        }

        // PHP error messages - specific patterns
        if (body.contains("Fatal error:")
            || body.contains("Warning:") && body.contains(" in ") && body.contains(" on line ")
            || body.contains("Parse error:")
            || body.contains("Notice:") && body.contains(".php"))
            && (body.contains("/") || body.contains("\\")) {
            return true;
        }

        // Node.js / JavaScript stack traces - specific patterns
        if (body.contains("Error:")
            || body.contains("TypeError:")
            || body.contains("ReferenceError:")
            || body.contains("SyntaxError:"))
            && (body.contains("at ") && (body.contains(".js:") || body.contains("(<anonymous>)") || body.contains("node_modules"))) {
            return true;
        }

        // .NET / C# stack traces - specific patterns
        if (body.contains("Exception") || body.contains("Error"))
            && (body.contains(".cs:line ") || body.contains("at System.") || body.contains("at Microsoft.")) {
            return true;
        }

        // Ruby stack traces - specific patterns
        if (body.contains("Error") || body.contains("Exception"))
            && (body.contains(".rb:") || body.contains("from ") && body.contains(":in `")) {
            return true;
        }

        // Generic stack trace patterns (fallback with stricter requirements)
        let body_lower = body.to_lowercase();
        let stack_trace_indicators = vec![
            "stack trace",
            "stacktrace",
            "backtrace",
            "call stack",
        ];

        for indicator in stack_trace_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Require strong evidence: file path + line number + function/method context
        (body.contains(" at ") && body.contains("(") && body.contains(":") && body.contains(")"))
            || (body.contains("File \"") && body.contains("line ") && body.contains(", in "))
            || (body.contains(" in ") && body.contains(" on line ") && body.contains("/"))
    }

    /// Detect directory listing
    fn detect_directory_listing(&self, body: &str) -> bool {
        // Strong indicators that almost certainly mean directory listing
        let strong_indicators = vec![
            "Index of /",
            "<title>Index of",
            "Directory listing for",
        ];

        let body_lower = body.to_lowercase();

        // A single strong indicator is sufficient
        for indicator in &strong_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Weaker indicators need at least 2 to match.
        // Note: Removed generic "apache" and "nginx" which match
        // any page mentioning those words (docs, blog posts, etc.)
        let weak_indicators = vec![
            "Parent Directory",
            "[DIR]",
            "[   ]",
            "Directory listing",
        ];

        let mut found_count = 0;
        for indicator in &weak_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                found_count += 1;
                if found_count >= 2 {
                    return true;
                }
            }
        }

        false
    }

    /// Detect server information disclosure
    /// Returns Some(evidence) if server info is disclosed, None otherwise
    fn detect_server_disclosure(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Option<String> {
        let mut evidence_parts = Vec::new();

        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            if key_lower == "server" || key_lower == "x-powered-by" {
                // Check if version information is present
                if value_lower.contains("/") || value_lower.chars().any(|c| c.is_numeric()) {
                    evidence_parts.push(format!("{}: {}", key, value));
                }
            }
        }

        if evidence_parts.is_empty() {
            None
        } else {
            Some(format!(
                "Server/framework version headers found:\n  {}",
                evidence_parts.join("\n  ")
            ))
        }
    }

    /// Detect debug mode
    fn detect_debug_mode(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        let body_lower = body.to_lowercase();

        // Check body for debug indicators
        let debug_indicators = vec![
            "debug mode",
            "debug=true",
            "debug:true",
            "development mode",
            "__debug__",
        ];

        for indicator in debug_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check headers
        for (key, value) in headers {
            if key.to_lowercase().contains("debug") || value.to_lowercase().contains("debug") {
                return true;
            }
        }

        false
    }

    /// Extract base URL
    fn extract_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("localhost");
            let scheme = parsed.scheme();

            if let Some(port) = parsed.port() {
                format!("{}://{}:{}", scheme, host, port)
            } else {
                format!("{}://{}", scheme, host)
            }
        } else {
            url.to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("info_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Information Disclosure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Remove or secure sensitive files (.env, config files)\n\
                         2. Disable stack traces in production\n\
                         3. Implement generic error messages\n\
                         4. Disable directory listing in web server config\n\
                         5. Remove server version headers\n\
                         6. Disable debug mode in production\n\
                         7. Use custom error pages\n\
                         8. Implement proper .gitignore and file permissions\n\
                         9. Remove development files from production\n\
                         10. Use Content Security Policy headers"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> InformationDisclosureScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        InformationDisclosureScanner::new(http_client)
    }

    #[test]
    fn test_detect_sensitive_content() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_sensitive_content("API_KEY=secret123", ".env"));
        assert!(scanner.detect_sensitive_content("DATABASE_URL=postgres://", ".env.local"));
        assert!(scanner.detect_sensitive_content(r#"{"password":"secret"}"#, "config.json"));
    }

    #[test]
    fn test_detect_stack_trace() {
        let scanner = create_test_scanner();

        let traces = vec![
            "Error at /home/user/app.rb:42",
            "Traceback (most recent call last):\n  File \"app.py\", line 10",
            "Exception in thread at Main.java:123",
        ];

        for trace in traces {
            assert!(scanner.detect_stack_trace(trace));
        }
    }

    #[test]
    fn test_detect_directory_listing() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_directory_listing("<title>Index of /uploads</title>\n[DIR] parent"));
        assert!(scanner.detect_directory_listing("Directory listing for /files\nParent Directory"));
    }

    #[test]
    fn test_detect_server_disclosure() {
        let scanner = create_test_scanner();

        let mut headers = std::collections::HashMap::new();
        headers.insert("Server".to_string(), "Apache/2.4.41".to_string());
        assert!(scanner.detect_server_disclosure(&headers).is_some());

        let mut headers2 = std::collections::HashMap::new();
        headers2.insert("X-Powered-By".to_string(), "PHP/7.4.3".to_string());
        assert!(scanner.detect_server_disclosure(&headers2).is_some());
    }

    #[test]
    fn test_detect_debug_mode() {
        let scanner = create_test_scanner();
        let headers = std::collections::HashMap::new();

        assert!(scanner.detect_debug_mode("Debug mode enabled", &headers));
        assert!(scanner.detect_debug_mode("DEBUG=true", &headers));
    }

    #[test]
    fn test_extract_base_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_base_url("http://example.com/path?q=1"),
            "http://example.com"
        );
        assert_eq!(
            scanner.extract_base_url("https://test.org:8080/api"),
            "https://test.org:8080"
        );
    }
}
