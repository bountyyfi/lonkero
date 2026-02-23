// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for sensitive data exposure (files, credentials, configuration)
pub struct SensitiveDataScanner {
    http_client: Arc<HttpClient>,
}

impl SensitiveDataScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Run sensitive data exposure scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting sensitive data exposure scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Parse base URL
        let url_obj = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                info!("Failed to parse URL: {}", e);
                return Ok((all_vulnerabilities, 0));
            }
        };

        let base_url = format!(
            "{}://{}",
            url_obj.scheme(),
            url_obj.host_str().unwrap_or("")
        );

        // Test sensitive file paths
        let sensitive_paths = self.get_sensitive_paths();

        for path in &sensitive_paths {
            total_tests += 1;
            let test_url = format!("{}{}", base_url, path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_sensitive_file(
                        &response.body,
                        response.status_code,
                        path,
                        &test_url,
                    ) {
                        all_vulnerabilities.push(vuln);
                    }
                }
                Err(_) => {
                    // File not accessible, continue
                }
            }
        }

        // Check main response for exposed credentials
        total_tests += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                let cred_vulns = self.scan_for_credentials(&response.body, url);
                all_vulnerabilities.extend(cred_vulns);
            }
            Err(_) => {
                // Continue
            }
        }

        info!(
            "Sensitive data exposure scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Get list of sensitive paths to test
    fn get_sensitive_paths(&self) -> Vec<&'static str> {
        vec![
            // Environment and config files
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/config.php",
            "/configuration.php",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/settings.json",
            "/settings.yml",
            "/web.config",
            "/application.properties",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/app.yml",
            // Git files
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.gitignore",
            // Package manager files
            "/package.json",
            "/package-lock.json",
            "/composer.json",
            "/composer.lock",
            "/yarn.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            // Database dumps
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/db.sql",
            "/mysql.sql",
            "/postgres.sql",
            "/data.sql",
            // Debug and info files
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/debug.php",
            "/_debug",
            "/debug",
            // Log files
            "/logs/error.log",
            "/logs/access.log",
            "/log/error.log",
            "/error.log",
            "/access.log",
            "/error_log",
            "/debug.log",
            // API documentation
            "/api/swagger.json",
            "/api-docs",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/graphql",
            "/v1/api-docs",
            "/api/v1/swagger",
            // Server status
            "/server-status",
            "/server-info",
            "/status",
            "/health",
            // Other sensitive files
            "/.DS_Store",
            "/robots.txt",
            "/.well-known/security.txt",
            "/sitemap.xml",
            "/admin/config",
            "/.htaccess",
            "/.htpasswd",
            "/web.config.bak",
            "/backup.zip",
            "/site.zip",
            "/www.zip",
        ]
    }

    /// Analyze response for sensitive file exposure
    fn analyze_sensitive_file(
        &self,
        body: &str,
        status_code: u16,
        path: &str,
        url: &str,
    ) -> Option<Vulnerability> {
        if status_code != 200 || body.is_empty() {
            return None;
        }

        let body_lower = body.to_lowercase();

        // .env file exposure
        if path.contains(".env") {
            let env_patterns = ["db_password=", "api_key=", "secret=", "password=", "token="];
            if env_patterns.iter().any(|p| body_lower.contains(p)) {
                return Some(self.create_vulnerability(
                    "Environment File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-215",
                    9.8,
                    "Remove .env files from web root. Use server-side environment variables. Add .env to .gitignore.",
                ));
            }
        }

        // Git repository exposure
        if path.contains(".git") {
            if body.contains("[core]")
                || body.contains("repositoryformatversion")
                || body.contains("ref: refs/")
            {
                return Some(self.create_vulnerability(
                    "Git Repository Files Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-540",
                    7.5,
                    "Remove .git directory from web root. Add server configuration to deny access to .git folders.",
                ));
            }
        }

        // Configuration files
        if path.contains("config") || path.contains("wp-config") || path.contains("web.config") {
            let cred_patterns = [
                "password",
                "username",
                "db_name",
                "db_user",
                "db_password",
                "db_host",
            ];
            if cred_patterns.iter().any(|p| body_lower.contains(p)) {
                return Some(self.create_vulnerability(
                    "Configuration File with Credentials Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Remove configuration files from web root. Store outside document root. Use environment variables.",
                ));
            }
        }

        // SQL dumps
        if path.contains(".sql") {
            if body.contains("INSERT INTO")
                || body.contains("CREATE TABLE")
                || body.contains("DROP TABLE")
            {
                return Some(self.create_vulnerability(
                    "Database Dump File Exposed",
                    url,
                    "SQL dump contains database structure and data",
                    Severity::Critical,
                    "CWE-538",
                    8.8,
                    "Remove SQL dump files from web root. Store backups securely outside public access.",
                ));
            }
        }

        // phpinfo exposure
        if path.contains("phpinfo") || path.contains("info.php") {
            if body.contains("PHP Version")
                || body.contains("phpinfo()")
                || body.contains("php.ini")
            {
                return Some(self.create_vulnerability(
                    "PHPInfo Page Exposed",
                    url,
                    "PHPInfo reveals server configuration and environment variables",
                    Severity::Medium,
                    "CWE-200",
                    5.3,
                    "Remove phpinfo() files from production. Disable in production environments.",
                ));
            }
        }

        // API documentation
        if path.contains("swagger") || path.contains("api-docs") || path.contains("openapi") {
            if body_lower.contains("swagger")
                || body_lower.contains("openapi")
                || body_lower.contains("\"paths\"")
            {
                return Some(self.create_vulnerability(
                    "API Documentation Exposed",
                    url,
                    "API documentation reveals endpoints and schema",
                    Severity::Medium,
                    "CWE-200",
                    5.3,
                    "Restrict access to API documentation in production. Require authentication.",
                ));
            }
        }

        // Log files - use word boundary check to avoid matching /blog, /catalog, /dialog, etc.
        let path_lower = path.to_lowercase();
        let is_log_path = path_lower.ends_with(".log")
            || path_lower.ends_with("/log")
            || path_lower.contains("/log/")
            || path_lower.contains("/logs/")
            || path_lower.contains("access.log")
            || path_lower.contains("error.log");
        if is_log_path {
            if (body.contains("ERROR") && body.contains("["))  // Log format: [ERROR] or [2024-01-01]
                || body.contains("Stack trace")
                || (body.contains("Exception") && body.contains(" at "))
            {
                return Some(self.create_vulnerability(
                    "Log File Exposed",
                    url,
                    "Log file may contain sensitive error information",
                    Severity::Medium,
                    "CWE-532",
                    5.3,
                    "Remove log files from web root. Configure logging to secure location. Disable directory listing.",
                ));
            }
        }

        // Server status pages
        if path.contains("server-status") || path.contains("server-info") {
            if body_lower.contains("apache")
                || body_lower.contains("server version")
                || body_lower.contains("uptime")
            {
                return Some(self.create_vulnerability(
                    "Server Status Page Exposed",
                    url,
                    "Server status reveals configuration and active connections",
                    Severity::Low,
                    "CWE-200",
                    3.7,
                    "Restrict access to server status pages. Require authentication or disable entirely.",
                ));
            }
        }

        // Package manager files (informational)
        if path.contains("package.json") || path.contains("composer.json") {
            if body_lower.contains("dependencies") || body_lower.contains("\"name\"") {
                return Some(self.create_vulnerability(
                    "Package Manager File Exposed",
                    url,
                    "Package file reveals dependencies and versions",
                    Severity::Info,
                    "CWE-200",
                    2.0,
                    "Consider restricting access to package manager files to prevent version enumeration.",
                ));
            }
        }

        None
    }

    /// Scan response body for exposed credentials
    fn scan_for_credentials(&self, body: &str, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // AWS Access Keys
        if let Some(matches) = self.regex_scan(body, r"AKIA[0-9A-Z]{16}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "AWS Access Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.5,
                    "Rotate AWS credentials immediately. Remove from client-side code. Use IAM roles.",
                ));
            }
        }

        // Stripe Secret Keys
        if let Some(matches) = self.regex_scan(body, r"sk_live_[a-zA-Z0-9]{24,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Stripe Secret Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.5,
                    "Rotate Stripe secret key immediately. Never expose secret keys client-side.",
                ));
            }
        }

        // Google API Keys
        if let Some(matches) = self.regex_scan(body, r"AIza[0-9A-Za-z\-_]{35}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Google API Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    7.5,
                    "Rotate Google API key. Implement API key restrictions (IP, referrer, API limits).",
                ));
            }
        }

        // GitHub Tokens
        if let Some(matches) = self.regex_scan(body, r"ghp_[a-zA-Z0-9]{36}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "GitHub Personal Access Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.0,
                    "Revoke GitHub token immediately. Use GitHub Apps or OAuth for authentication.",
                ));
            }
        }

        // Slack Tokens
        if let Some(matches) = self.regex_scan(body, r"xox[baprs]-[a-zA-Z0-9\-]{10,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Slack Token Exposed in Response",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    8.0,
                    "Revoke Slack token immediately. Rotate credentials. Use environment variables.",
                ));
            }
        }

        vulnerabilities
    }

    /// Perform regex scan and return matches
    fn regex_scan(&self, content: &str, pattern: &str) -> Option<Vec<String>> {
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let matches: Vec<String> = regex
            .find_iter(content)
            .map(|m| {
                let matched = m.as_str();
                if matched.len() > 40 {
                    format!("{}...", &matched[..40])
                } else {
                    matched.to_string()
                }
            })
            .collect();

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Truncate evidence to specified length
    fn truncate_evidence(&self, text: &str, max_len: usize) -> String {
        if text.len() > max_len {
            format!("{}...", &text[..max_len])
        } else {
            text.to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f32,
        remediation: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("sensdata_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Sensitive Data Exposure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> SensitiveDataScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        SensitiveDataScanner::new(client)
    }

    #[test]
    fn test_analyze_env_file() {
        let scanner = create_test_scanner();

        let body = "DB_PASSWORD=secret123\nAPI_KEY=abc123\nSECRET=xyz789";
        let vuln = scanner.analyze_sensitive_file(body, 200, "/.env", "https://example.com/.env");

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.vuln_type.contains("Environment File"));
    }

    #[test]
    fn test_analyze_git_config() {
        let scanner = create_test_scanner();

        let body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/.git/config",
            "https://example.com/.git/config",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert!(v.vuln_type.contains("Git Repository"));
    }

    #[test]
    fn test_analyze_sql_dump() {
        let scanner = create_test_scanner();

        let body = "CREATE TABLE users (id INT, name VARCHAR(255));\nINSERT INTO users VALUES (1, 'admin');";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/backup.sql",
            "https://example.com/backup.sql",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.vuln_type.contains("Database Dump"));
    }

    #[test]
    fn test_analyze_phpinfo() {
        let scanner = create_test_scanner();

        let body = "PHP Version 7.4.3\nSystem => Linux\nphp.ini => /etc/php/7.4/php.ini";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/phpinfo.php",
            "https://example.com/phpinfo.php",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert!(v.vuln_type.contains("PHPInfo"));
    }

    #[test]
    fn test_regex_scan_aws_key() {
        let scanner = create_test_scanner();

        let body = r#"{"aws_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let matches = scanner.regex_scan(body, r"AKIA[0-9A-Z]{16}");

        assert!(matches.is_some());
        let m = matches.unwrap();
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_scan_for_credentials() {
        let scanner = create_test_scanner();

        let body = r#"{"stripe_key": "sk_test_FAKE_KEY_FOR_TESTING_ONLY"}"#;
        let vulns = scanner.scan_for_credentials(body, "https://example.com");

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Stripe")));
    }

    #[test]
    fn test_get_sensitive_paths() {
        let scanner = create_test_scanner();
        let paths = scanner.get_sensitive_paths();

        assert!(paths.len() > 70);
        assert!(paths.contains(&"/.env"));
        assert!(paths.contains(&"/.git/config"));
        assert!(paths.contains(&"/phpinfo.php"));
        assert!(paths.contains(&"/backup.sql"));
    }
}
