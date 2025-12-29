// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct LaravelSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: HashMap<String, Vec<LaravelCVE>>,
}

#[derive(Clone)]
struct LaravelCVE {
    cve_id: String,
    affected_versions: String,
    severity: Severity,
    description: String,
    check_fn: Option<String>,
}

#[derive(Debug, Clone)]
struct LaravelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl LaravelSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known Laravel CVEs
    fn build_cve_database() -> HashMap<String, Vec<LaravelCVE>> {
        let mut db = HashMap::new();

        let cves = vec![
            // Ignition RCE - Critical
            LaravelCVE {
                cve_id: "CVE-2021-3129".to_string(),
                affected_versions: "<8.4.2".to_string(),
                severity: Severity::Critical,
                description: "Laravel Ignition Remote Code Execution via file_put_contents and phar deserialization".to_string(),
                check_fn: Some("check_ignition_rce".to_string()),
            },
            // Debug mode information disclosure
            LaravelCVE {
                cve_id: "CVE-2021-21263".to_string(),
                affected_versions: "<8.22.1".to_string(),
                severity: Severity::High,
                description: "Unexpected bindings in QueryBuilder can lead to SQL injection".to_string(),
                check_fn: None,
            },
            // Cookie serialization
            LaravelCVE {
                cve_id: "CVE-2018-15133".to_string(),
                affected_versions: "<5.6.30".to_string(),
                severity: Severity::Critical,
                description: "Remote Code Execution via cookie deserialization when APP_KEY is known".to_string(),
                check_fn: None,
            },
            // Token guard timing attack
            LaravelCVE {
                cve_id: "CVE-2020-13909".to_string(),
                affected_versions: "<7.16.1".to_string(),
                severity: Severity::Medium,
                description: "Timing attack in token guard authentication".to_string(),
                check_fn: None,
            },
            // Password reset token
            LaravelCVE {
                cve_id: "CVE-2019-9081".to_string(),
                affected_versions: "<5.8.4".to_string(),
                severity: Severity::High,
                description: "Password reset token collision vulnerability".to_string(),
                check_fn: None,
            },
            // Validation bypass
            LaravelCVE {
                cve_id: "CVE-2022-40482".to_string(),
                affected_versions: "<9.18.0".to_string(),
                severity: Severity::Medium,
                description: "Validation rule bypass using array syntax".to_string(),
                check_fn: None,
            },
            // Blade XSS
            LaravelCVE {
                cve_id: "CVE-2017-14775".to_string(),
                affected_versions: "<5.5.10".to_string(),
                severity: Severity::High,
                description: "Cross-site scripting via Blade templates".to_string(),
                check_fn: None,
            },
        ];

        db.insert("laravel".to_string(), cves);
        db
    }

    /// Main scan function
    pub async fn scan(&self, url: &str, _config: &ScanConfig) -> Result<(Vec<Vulnerability>, usize)> {
        // Check license
        if !crate::license::has_feature("cms_security") {
            debug!("Laravel security scanner requires Personal+ license");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, detect if this is a Laravel application
        let (is_laravel, version) = self.detect_laravel(url).await;
        tests_run += 1;

        if !is_laravel {
            debug!("Target does not appear to be a Laravel application");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Laravel] Detected Laravel application, running security checks");
        if let Some(ref v) = version {
            info!("[Laravel] Detected version: {}.{}.{}", v.major, v.minor, v.patch);
        }

        // Check for debug mode enabled
        let (debug_vulns, debug_tests) = self.check_debug_mode(url).await;
        vulnerabilities.extend(debug_vulns);
        tests_run += debug_tests;

        // Check for Ignition RCE (CVE-2021-3129)
        let (ignition_vulns, ignition_tests) = self.check_ignition_rce(url).await;
        vulnerabilities.extend(ignition_vulns);
        tests_run += ignition_tests;

        // Check for exposed admin panels
        let (admin_vulns, admin_tests) = self.check_admin_panels(url).await;
        vulnerabilities.extend(admin_vulns);
        tests_run += admin_tests;

        // Check for environment file exposure
        let (env_vulns, env_tests) = self.check_env_exposure(url).await;
        vulnerabilities.extend(env_vulns);
        tests_run += env_tests;

        // Check for storage directory access
        let (storage_vulns, storage_tests) = self.check_storage_exposure(url).await;
        vulnerabilities.extend(storage_vulns);
        tests_run += storage_tests;

        // Check for log file exposure
        let (log_vulns, log_tests) = self.check_log_exposure(url).await;
        vulnerabilities.extend(log_vulns);
        tests_run += log_tests;

        // Check for vendor directory exposure
        let (vendor_vulns, vendor_tests) = self.check_vendor_exposure(url).await;
        vulnerabilities.extend(vendor_vulns);
        tests_run += vendor_tests;

        // Check for configuration exposure
        let (config_vulns, config_tests) = self.check_config_exposure(url).await;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        // Check API routes
        let (api_vulns, api_tests) = self.check_api_routes(url).await;
        vulnerabilities.extend(api_vulns);
        tests_run += api_tests;

        // Check Livewire vulnerabilities
        let (livewire_vulns, livewire_tests) = self.check_livewire(url).await;
        vulnerabilities.extend(livewire_vulns);
        tests_run += livewire_tests;

        // Check for known CVEs based on version
        if let Some(ref v) = version {
            let (cve_vulns, cve_tests) = self.check_version_cves(url, v).await;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        // Check for common misconfigurations
        let (misc_vulns, misc_tests) = self.check_misconfigurations(url).await;
        vulnerabilities.extend(misc_vulns);
        tests_run += misc_tests;

        info!("[Laravel] Completed: {} vulnerabilities found in {} tests",
              vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is a Laravel application
    async fn detect_laravel(&self, url: &str) -> (bool, Option<LaravelVersion>) {
        let mut is_laravel = false;
        let mut version: Option<LaravelVersion> = None;

        // Check main page for Laravel indicators
        if let Ok(response) = self.http_client.get(url).await {
            let body = &response.body;
            let headers_str = format!("{:?}", response.headers);

            // Laravel indicators in response
            let laravel_indicators = [
                "laravel",
                "Laravel",
                "XSRF-TOKEN",
                "laravel_session",
                "_token",
                "csrf-token",
                "app.js",
                "vendor/laravel",
            ];

            for indicator in &laravel_indicators {
                if body.contains(indicator) || headers_str.contains(indicator) {
                    is_laravel = true;
                    break;
                }
            }

            // Check for Laravel session cookie
            if let Some(cookies) = response.headers.get("set-cookie") {
                let cookie_str = cookies.as_str();
                if cookie_str.contains("laravel_session") || cookie_str.contains("XSRF-TOKEN") {
                    is_laravel = true;
                }
            }

            // Try to extract version from error pages or headers
            if let Some(v) = self.extract_version_from_response(body) {
                version = Some(v);
                is_laravel = true;
            }
        }

        // Check for typical Laravel paths
        let laravel_paths = [
            "/api",
            "/sanctum/csrf-cookie",
            "/broadcasting/auth",
            "/_ignition/health-check",
            "/telescope",
            "/horizon",
        ];

        for path in &laravel_paths {
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code != 404 {
                    is_laravel = true;
                    // Check for version in error response
                    if version.is_none() {
                        if let Some(v) = self.extract_version_from_response(&response.body) {
                            version = Some(v);
                        }
                    }
                    break;
                }
            }
        }

        (is_laravel, version)
    }

    /// Extract Laravel version from response
    fn extract_version_from_response(&self, body: &str) -> Option<LaravelVersion> {
        // Pattern for Laravel version in stack traces or debug output
        let version_patterns = [
            r#"Laravel\s+v?(\d+)\.(\d+)\.(\d+)"#,
            r#"laravel/framework.*?(\d+)\.(\d+)\.(\d+)"#,
            r#"illuminate/.*?v(\d+)\.(\d+)\.(\d+)"#,
        ];

        for pattern in &version_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(body) {
                    if let (Some(major), Some(minor), Some(patch)) =
                        (caps.get(1), caps.get(2), caps.get(3)) {
                        return Some(LaravelVersion {
                            major: major.as_str().parse().unwrap_or(0),
                            minor: minor.as_str().parse().unwrap_or(0),
                            patch: patch.as_str().parse().unwrap_or(0),
                        });
                    }
                }
            }
        }

        None
    }

    /// Check for debug mode enabled
    async fn check_debug_mode(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test paths that might trigger errors
        let error_paths = [
            "/api/nonexistent-endpoint-test-12345",
            "/undefined-route-bountyy-test",
            "/%00",
            "/..%00",
            "/api?test[]=invalid",
        ];

        for path in &error_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                let body = &response.body;

                // Check for debug mode indicators
                let debug_indicators = [
                    "Whoops!",
                    "Stack trace",
                    "ErrorException",
                    "APP_DEBUG",
                    "APP_KEY",
                    "DB_PASSWORD",
                    "MAIL_PASSWORD",
                    "vendor/laravel",
                    "Illuminate\\",
                    "app/Http/Controllers",
                    "DebugBar",
                    "clockwork",
                    "Ignition",
                ];

                let mut found_indicators: Vec<&str> = Vec::new();
                for indicator in &debug_indicators {
                    if body.contains(indicator) {
                        found_indicators.push(indicator);
                    }
                }

                // Check for exposed environment variables
                let env_patterns = [
                    (r#"APP_KEY\s*[=:]\s*["']?([^"'\s]+)"#, "APP_KEY"),
                    (r#"DB_PASSWORD\s*[=:]\s*["']?([^"'\s]+)"#, "DB_PASSWORD"),
                    (r#"MAIL_PASSWORD\s*[=:]\s*["']?([^"'\s]+)"#, "MAIL_PASSWORD"),
                    (r#"AWS_SECRET\s*[=:]\s*["']?([^"'\s]+)"#, "AWS_SECRET"),
                    (r#"REDIS_PASSWORD\s*[=:]\s*["']?([^"'\s]+)"#, "REDIS_PASSWORD"),
                ];

                let mut exposed_secrets: Vec<String> = Vec::new();
                for (pattern, name) in &env_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(body) {
                            exposed_secrets.push(name.to_string());
                        }
                    }
                }

                if !found_indicators.is_empty() || !exposed_secrets.is_empty() {
                    let severity = if !exposed_secrets.is_empty() {
                        Severity::Critical
                    } else if found_indicators.iter().any(|i| *i == "APP_KEY" || *i == "DB_PASSWORD") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_debug_mode_{}", Self::generate_id()),
                        vuln_type: "Laravel Debug Mode Enabled".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Laravel application is running with APP_DEBUG=true in production. \
                            This exposes sensitive information including:\n\
                            - Full stack traces with file paths\n\
                            - Environment variables (potentially including secrets)\n\
                            - Database credentials\n\
                            - Application encryption key\n\n\
                            Exposed indicators: {:?}\n\
                            Exposed secrets: {:?}",
                            found_indicators, exposed_secrets
                        ),
                        evidence: Some(format!(
                            "Debug indicators found: {}\n\
                            Secrets potentially exposed: {}\n\
                            URL: {}",
                            found_indicators.join(", "),
                            if exposed_secrets.is_empty() { "None directly visible".to_string() } else { exposed_secrets.join(", ") },
                            test_url
                        )),
                        cwe: "CWE-215".to_string(),
                        cvss: if !exposed_secrets.is_empty() { 9.8 } else { 7.5 },
                        verified: true,
                        false_positive: false,
                        remediation: "1. Set APP_DEBUG=false in .env file for production\n\
                                      2. Run: php artisan config:cache\n\
                                      3. Ensure error reporting is disabled in php.ini\n\
                                      4. Use proper error logging instead of displaying errors\n\
                                      5. Consider using Laravel's logging to external services".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });

                    // Found debug mode, no need to test more paths
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for Laravel Ignition RCE (CVE-2021-3129)
    async fn check_ignition_rce(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Check Ignition health endpoint
        let ignition_paths = [
            "/_ignition/health-check",
            "/_ignition/execute-solution",
            "/_ignition/share-report",
            "/_ignition/scripts/",
            "/_ignition/styles/",
        ];

        for path in &ignition_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let is_health_check = path.contains("health-check");
                    let is_execute = path.contains("execute-solution");

                    if is_health_check && response.body.contains("ok") {
                        // Ignition is present and responding
                        info!("[Laravel] Ignition health-check endpoint accessible");
                    }

                    if is_execute || response.body.contains("execute-solution") {
                        // Critical: execute-solution endpoint accessible
                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_ignition_rce_{}", Self::generate_id()),
                            vuln_type: "Laravel Ignition RCE (CVE-2021-3129)".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Remote Code Execution".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Laravel Ignition execute-solution endpoint is accessible. \
                                This vulnerability (CVE-2021-3129) allows unauthenticated remote code \
                                execution through phar deserialization.\n\n\
                                Ignition versions < 2.5.2 (Laravel < 8.4.2) are vulnerable.\n\
                                An attacker can:\n\
                                1. Execute arbitrary PHP code on the server\n\
                                2. Read/write files on the filesystem\n\
                                3. Achieve full server compromise"
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Response code: {}\n\
                                CVE: CVE-2021-3129\n\
                                CVSS: 9.8 (Critical)",
                                test_url, response.status_code
                            )),
                            cwe: "CWE-502".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. IMMEDIATELY update Laravel and Ignition:\n\
                                          - Laravel 8.x: upgrade to >= 8.4.2\n\
                                          - Ignition: upgrade to >= 2.5.2\n\
                                          2. Or disable Ignition in production:\n\
                                          - Set APP_DEBUG=false\n\
                                          - Remove facade/ignition from composer.json\n\
                                          3. Block /_ignition paths at web server level".to_string(),
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

    /// Check for exposed admin panels
    async fn check_admin_panels(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let admin_panels = [
            ("/telescope", "Laravel Telescope", "Debug/profiling dashboard"),
            ("/telescope/requests", "Laravel Telescope Requests", "HTTP request logging"),
            ("/horizon", "Laravel Horizon", "Queue management dashboard"),
            ("/horizon/api/stats", "Laravel Horizon API", "Queue statistics API"),
            ("/nova", "Laravel Nova", "Admin panel"),
            ("/nova/login", "Laravel Nova Login", "Admin panel login"),
            ("/admin", "Admin Panel", "Generic admin panel"),
            ("/administrator", "Administrator Panel", "Generic admin panel"),
            ("/pulse", "Laravel Pulse", "Application monitoring"),
            ("/log-viewer", "Log Viewer", "Application log viewer"),
            ("/logs", "Logs", "Application logs"),
            ("/debugbar", "Laravel Debugbar", "Debug toolbar"),
            ("/clockwork", "Clockwork", "Debug profiler"),
            ("/__clockwork", "Clockwork API", "Debug profiler API"),
        ];

        for (path, name, description) in &admin_panels {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check if accessible (not 404, not redirect to login)
                let is_accessible = response.status_code == 200;
                let has_content = response.body.len() > 100;
                let is_login_redirect = response.body.to_lowercase().contains("login") ||
                                       response.body.to_lowercase().contains("unauthorized");

                if is_accessible && has_content && !is_login_redirect {
                    let severity = if path.contains("telescope") || path.contains("horizon") {
                        Severity::High
                    } else if path.contains("nova") {
                        Severity::Critical
                    } else if path.contains("log") {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_admin_panel_{}", Self::generate_id()),
                        vuln_type: format!("{} Exposed", name),
                        severity: severity.clone(),
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "{} ({}) is publicly accessible without authentication.\n\n\
                            This can expose:\n\
                            - Application requests and responses\n\
                            - Database queries and performance metrics\n\
                            - Queue jobs and failed jobs\n\
                            - Cached data\n\
                            - Environment configuration\n\
                            - User sessions",
                            name, description
                        ),
                        evidence: Some(format!(
                            "URL: {}\n\
                            Response code: {}\n\
                            Response size: {} bytes",
                            test_url, response.status_code, response.body.len()
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: if severity == Severity::Critical { 8.5 } else { 7.0 },
                        verified: true,
                        false_positive: false,
                        remediation: format!(
                            "1. Add authentication middleware to {} routes\n\
                            2. For Telescope/Horizon, configure gate authorization:\n\
                            - In TelescopeServiceProvider/HorizonServiceProvider\n\
                            - Use Gate::define('view{}', ...)\n\
                            3. Consider restricting by IP address in production\n\
                            4. Or disable {} entirely in production",
                            name, name.to_lowercase().replace(" ", ""), name
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for environment file exposure
    async fn check_env_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let env_files = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.staging",
            ".env.development",
            ".env.backup",
            ".env.bak",
            ".env.old",
            ".env.save",
            ".env.example",
            ".env.sample",
            "env",
            "env.php",
            ".env.php",
        ];

        for file in &env_files {
            tests_run += 1;
            let test_url = format!("{}/{}", url.trim_end_matches('/'), file);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    // Check if it looks like an env file
                    let body = &response.body;
                    let env_indicators = ["APP_", "DB_", "MAIL_", "REDIS_", "AWS_", "BROADCAST_"];

                    let is_env_file = env_indicators.iter().any(|i| body.contains(i));

                    if is_env_file {
                        // Extract what secrets are exposed
                        let mut exposed_vars: Vec<&str> = Vec::new();
                        let critical_vars = [
                            "APP_KEY", "DB_PASSWORD", "DB_USERNAME", "MAIL_PASSWORD",
                            "AWS_SECRET", "AWS_ACCESS", "REDIS_PASSWORD", "PUSHER_",
                            "STRIPE_", "PAYPAL_", "JWT_SECRET", "API_KEY",
                        ];

                        for var in &critical_vars {
                            if body.contains(var) {
                                exposed_vars.push(var);
                            }
                        }

                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_env_exposure_{}", Self::generate_id()),
                            vuln_type: "Laravel Environment File Exposed".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: file.to_string(),
                            description: format!(
                                "Laravel .env file is publicly accessible. This file contains \
                                all application secrets and configuration including:\n\
                                - Application encryption key (APP_KEY)\n\
                                - Database credentials\n\
                                - Third-party API keys\n\
                                - Mail server credentials\n\
                                - Cloud storage credentials\n\n\
                                Exposed sensitive variables: {:?}",
                                exposed_vars
                            ),
                            evidence: Some(format!(
                                "File: {}\n\
                                Exposed credentials: {}\n\
                                NOTE: Full contents not logged for security",
                                file, exposed_vars.join(", ")
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. IMMEDIATELY rotate all exposed credentials\n\
                                          2. Block .env files at web server level:\n\
                                          - Nginx: location ~ /\\.env { deny all; }\n\
                                          - Apache: <Files \".env*\"> Require all denied </Files>\n\
                                          3. Move .env outside web root\n\
                                          4. Review web server configuration\n\
                                          5. Audit for any unauthorized access using these credentials".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });

                        // Found env file, critical finding
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for storage directory exposure
    async fn check_storage_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let storage_paths = [
            "/storage",
            "/storage/app",
            "/storage/app/public",
            "/storage/framework",
            "/storage/framework/cache",
            "/storage/framework/sessions",
            "/storage/framework/views",
            "/storage/logs",
            "/storage/logs/laravel.log",
        ];

        for path in &storage_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                let is_directory_listing = response.body.contains("Index of") ||
                                          response.body.contains("Directory listing") ||
                                          response.body.contains("<title>Index of");
                let is_log_file = path.contains(".log") && response.status_code == 200 &&
                                 (response.body.contains("[stacktrace]") ||
                                  response.body.contains("production.ERROR") ||
                                  response.body.contains("local.ERROR"));
                let is_session_dir = path.contains("sessions") && response.status_code == 200;

                if is_directory_listing {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_storage_listing_{}", Self::generate_id()),
                        vuln_type: "Laravel Storage Directory Listing".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Laravel storage directory listing is enabled at {}. \
                            This can expose:\n\
                            - Uploaded files\n\
                            - Cached data\n\
                            - Session files\n\
                            - Compiled views\n\
                            - Application logs",
                            path
                        ),
                        evidence: Some(format!("Directory listing enabled at: {}", test_url)),
                        cwe: "CWE-548".to_string(),
                        cvss: 6.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Disable directory listing in web server:\n\
                                      - Nginx: autoindex off;\n\
                                      - Apache: Options -Indexes\n\
                                      2. Block storage directory from web access\n\
                                      3. Use storage:link for public files only".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                } else if is_log_file {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_log_exposure_{}", Self::generate_id()),
                        vuln_type: "Laravel Log File Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "Laravel log file is publicly accessible. Log files can contain:\n\
                                     - Stack traces with file paths\n\
                                     - SQL queries\n\
                                     - User data and emails\n\
                                     - Session tokens\n\
                                     - API responses\n\
                                     - Error messages with sensitive context".to_string(),
                        evidence: Some(format!("Log file accessible at: {}", test_url)),
                        cwe: "CWE-532".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Block storage/logs from web access\n\
                                      2. Move logs outside web root\n\
                                      3. Use external logging service (Papertrail, LogDNA)\n\
                                      4. Configure log rotation".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                } else if is_session_dir {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_session_exposure_{}", Self::generate_id()),
                        vuln_type: "Laravel Session Storage Exposed".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        category: "Session Hijacking".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "Laravel session storage directory is accessible. \
                                     This could allow session hijacking by reading session files.".to_string(),
                        evidence: Some(format!("Session directory accessible at: {}", test_url)),
                        cwe: "CWE-200".to_string(),
                        cvss: 8.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Use database or Redis session driver instead of file\n\
                                      2. Block storage/framework/sessions from web access\n\
                                      3. Configure SESSION_DRIVER=redis or database".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for log file exposure
    async fn check_log_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let log_paths = [
            "/laravel.log",
            "/storage/logs/laravel.log",
            "/logs/laravel.log",
            "/app/storage/logs/laravel.log",
            "/var/log/laravel.log",
        ];

        // Already checked in storage, just check root level
        for path in &log_paths {
            if path.contains("storage") {
                continue; // Already checked
            }

            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.contains("[stacktrace]") ||
                    response.body.contains(".ERROR:") ||
                    response.body.contains("Stack trace:")) {

                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_log_root_{}", Self::generate_id()),
                        vuln_type: "Laravel Log File at Root".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "Laravel log file found at web root level.".to_string(),
                        evidence: Some(format!("Log file at: {}", test_url)),
                        cwe: "CWE-532".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove log files from web-accessible locations.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for vendor directory exposure
    async fn check_vendor_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let vendor_paths = [
            "/vendor/autoload.php",
            "/vendor/composer/autoload_classmap.php",
            "/vendor/phpunit/phpunit/phpunit",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/vendor/laravel/framework/src/Illuminate/Foundation/Application.php",
            "/composer.json",
            "/composer.lock",
        ];

        for path in &vendor_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.len() > 50 {
                    let is_php = response.body.contains("<?php") || path.ends_with(".php");
                    let is_json = path.ends_with(".json") && response.body.contains("{");
                    let is_phpunit = path.contains("phpunit");

                    if is_php || is_json {
                        let severity = if is_phpunit { Severity::Critical } else { Severity::High };

                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_vendor_exposure_{}", Self::generate_id()),
                            vuln_type: if is_phpunit {
                                "PHPUnit Exposed (Potential RCE)".to_string()
                            } else if is_json {
                                "Composer Files Exposed".to_string()
                            } else {
                                "Vendor Directory Exposed".to_string()
                            },
                            severity,
                            confidence: Confidence::High,
                            category: if is_phpunit { "Remote Code Execution".to_string() } else { "Information Disclosure".to_string() },
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: if is_phpunit {
                                "PHPUnit is accessible from web. The eval-stdin.php script can be \
                                exploited for remote code execution.".to_string()
                            } else if is_json {
                                format!("Composer {} exposed, revealing all package dependencies and versions.", path)
                            } else {
                                "Vendor directory is web-accessible, exposing PHP source code.".to_string()
                            },
                            evidence: Some(format!("File accessible: {}", test_url)),
                            cwe: if is_phpunit { "CWE-94".to_string() } else { "CWE-200".to_string() },
                            cvss: if is_phpunit { 9.8 } else { 6.5 },
                            verified: true,
                            false_positive: false,
                            remediation: "1. Move vendor outside web root OR\n\
                                          2. Block vendor directory in web server config:\n\
                                          - Nginx: location /vendor { deny all; }\n\
                                          3. Remove PHPUnit from production: composer install --no-dev".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for configuration file exposure
    async fn check_config_exposure(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let config_paths = [
            "/bootstrap/cache/config.php",
            "/config/app.php",
            "/config/database.php",
            "/config/mail.php",
            "/config/services.php",
            "/config/auth.php",
            "/.git/config",
            "/.gitignore",
            "/artisan",
            "/server.php",
        ];

        for path in &config_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.len() > 50 {
                    let is_cached_config = path.contains("bootstrap/cache");
                    let is_git = path.contains(".git");
                    let is_artisan = path.contains("artisan");

                    if response.body.contains("<?php") || response.body.contains("[core]") {
                        let severity = if is_cached_config { Severity::Critical } else { Severity::High };

                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_config_exposure_{}", Self::generate_id()),
                            vuln_type: if is_cached_config {
                                "Laravel Cached Config Exposed".to_string()
                            } else if is_git {
                                "Git Repository Exposed".to_string()
                            } else if is_artisan {
                                "Artisan Script Exposed".to_string()
                            } else {
                                "Laravel Config File Exposed".to_string()
                            },
                            severity,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: if is_cached_config {
                                "Cached configuration contains ALL environment variables including secrets.".to_string()
                            } else if is_git {
                                "Git repository is exposed, potentially allowing source code download.".to_string()
                            } else {
                                format!("Configuration file {} is publicly accessible.", path)
                            },
                            evidence: Some(format!("Config file at: {}", test_url)),
                            cwe: "CWE-200".to_string(),
                            cvss: if is_cached_config { 9.5 } else { 7.0 },
                            verified: true,
                            false_positive: false,
                            remediation: "1. Block config and bootstrap directories from web access\n\
                                          2. Move configuration outside web root\n\
                                          3. Block .git directories".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check API routes for exposure
    async fn check_api_routes(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Common Laravel API endpoints that might be unprotected
        let api_paths = [
            "/api/users",
            "/api/user",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/debug",
            "/api/logs",
            "/api/v1/users",
            "/api/v1/config",
            "/graphql",
            "/graphql/playground",
            "/graphiql",
        ];

        for path in &api_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check for unprotected API returning data
                if response.status_code == 200 {
                    let body = &response.body;
                    let is_json = body.trim().starts_with('{') || body.trim().starts_with('[');
                    let has_user_data = body.contains("\"email\"") ||
                                       body.contains("\"password\"") ||
                                       body.contains("\"user\"") ||
                                       body.contains("\"admin\"");
                    let is_graphql = path.contains("graphql") &&
                                    (body.contains("__schema") || body.contains("playground"));

                    if (is_json && has_user_data) || is_graphql {
                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_api_exposure_{}", Self::generate_id()),
                            vuln_type: if is_graphql {
                                "GraphQL Endpoint Exposed".to_string()
                            } else {
                                "Unprotected API Endpoint".to_string()
                            },
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Broken Access Control".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "API endpoint {} is accessible without authentication and returns sensitive data.",
                                path
                            ),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Returns JSON: {}\n\
                                Contains user data: {}",
                                test_url, is_json, has_user_data
                            )),
                            cwe: "CWE-284".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Add authentication middleware to API routes\n\
                                          2. Use Laravel Sanctum or Passport for API auth\n\
                                          3. Implement rate limiting\n\
                                          4. Disable GraphQL playground in production".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check Livewire vulnerabilities
    async fn check_livewire(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let livewire_url = format!("{}/livewire/livewire.js", url.trim_end_matches('/'));

        if let Ok(response) = self.http_client.get(&livewire_url).await {
            if response.status_code == 200 && response.body.contains("Livewire") {
                info!("[Laravel] Livewire detected, checking for vulnerabilities");

                // Check for Livewire message endpoint
                tests_run += 1;
                let message_url = format!("{}/livewire/message", url.trim_end_matches('/'));

                if let Ok(msg_response) = self.http_client.get(&message_url).await {
                    // Livewire message endpoint should require POST with proper CSRF
                    if msg_response.status_code != 405 && msg_response.status_code != 419 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("laravel_livewire_exposure_{}", Self::generate_id()),
                            vuln_type: "Livewire Message Endpoint Misconfigured".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "Security Misconfiguration".to_string(),
                            url: message_url.clone(),
                            parameter: None,
                            payload: "/livewire/message".to_string(),
                            description: "Livewire message endpoint may be misconfigured. \
                                         Should return 405 for GET or 419 for missing CSRF.".to_string(),
                            evidence: Some(format!(
                                "Endpoint: {}\n\
                                Response code: {} (expected 405 or 419)",
                                message_url, msg_response.status_code
                            )),
                            cwe: "CWE-352".to_string(),
                            cvss: 5.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Ensure CSRF middleware is active for Livewire routes.".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check for known CVEs based on version
    async fn check_version_cves(&self, url: &str, version: &LaravelVersion) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        if let Some(cves) = self.known_cves.get("laravel") {
            for cve in cves {
                let is_vulnerable = self.is_version_vulnerable(version, &cve.affected_versions);

                if is_vulnerable {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_cve_{}_{}", cve.cve_id.replace("-", "_"), Self::generate_id()),
                        vuln_type: format!("Laravel {}", cve.cve_id),
                        severity: cve.severity.clone(),
                        confidence: Confidence::Medium,
                        category: "Known Vulnerability".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: format!("Version {}.{}.{}", version.major, version.minor, version.patch),
                        description: format!(
                            "{}\n\nAffected versions: {}\nDetected version: {}.{}.{}",
                            cve.description, cve.affected_versions,
                            version.major, version.minor, version.patch
                        ),
                        evidence: Some(format!(
                            "CVE: {}\n\
                            Detected Laravel version: {}.{}.{}\n\
                            Vulnerable range: {}",
                            cve.cve_id, version.major, version.minor, version.patch,
                            cve.affected_versions
                        )),
                        cwe: "CWE-1035".to_string(),
                        cvss: match cve.severity {
                            Severity::Critical => 9.8,
                            Severity::High => 8.0,
                            Severity::Medium => 6.0,
                            _ => 4.0,
                        },
                        verified: false,
                        false_positive: false,
                        remediation: format!(
                            "Upgrade Laravel to a patched version.\n\
                            Run: composer update laravel/framework\n\
                            CVE: {}", cve.cve_id
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check if version is vulnerable
    fn is_version_vulnerable(&self, version: &LaravelVersion, affected: &str) -> bool {
        // Simple version comparison - affected format: "<8.4.2"
        if let Some(stripped) = affected.strip_prefix('<') {
            if let Some((major, rest)) = stripped.split_once('.') {
                if let Ok(affected_major) = major.parse::<u32>() {
                    if version.major < affected_major {
                        return true;
                    } else if version.major == affected_major {
                        if let Some((minor, patch)) = rest.split_once('.') {
                            if let (Ok(affected_minor), Ok(affected_patch)) =
                                (minor.parse::<u32>(), patch.parse::<u32>()) {
                                if version.minor < affected_minor {
                                    return true;
                                } else if version.minor == affected_minor && version.patch < affected_patch {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check for common misconfigurations
    async fn check_misconfigurations(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Check CSRF cookie settings
        tests_run += 1;
        if let Ok(response) = self.http_client.get(url).await {
            if let Some(cookies) = response.headers.get("set-cookie") {
                let cookie_str = cookies.as_str();

                // Check for insecure cookie settings
                let has_xsrf = cookie_str.contains("XSRF-TOKEN");
                let has_secure = cookie_str.to_lowercase().contains("secure");
                let _has_httponly = cookie_str.to_lowercase().contains("httponly");
                let has_samesite = cookie_str.to_lowercase().contains("samesite");

                if has_xsrf && !has_secure && url.starts_with("https") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_cookie_secure_{}", Self::generate_id()),
                        vuln_type: "CSRF Cookie Missing Secure Flag".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Security Misconfiguration".to_string(),
                        url: url.to_string(),
                        parameter: Some("XSRF-TOKEN".to_string()),
                        payload: "Cookie flags".to_string(),
                        description: "XSRF-TOKEN cookie is missing Secure flag on HTTPS site.".to_string(),
                        evidence: Some(format!("Cookie: {}", cookie_str)),
                        cwe: "CWE-614".to_string(),
                        cvss: 4.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Set SESSION_SECURE_COOKIE=true in .env for HTTPS sites.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }

                if has_xsrf && !has_samesite {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_cookie_samesite_{}", Self::generate_id()),
                        vuln_type: "Cookie Missing SameSite Attribute".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "Security Misconfiguration".to_string(),
                        url: url.to_string(),
                        parameter: Some("XSRF-TOKEN".to_string()),
                        payload: "Cookie flags".to_string(),
                        description: "Cookies missing SameSite attribute for CSRF protection.".to_string(),
                        evidence: Some(format!("Cookie: {}", cookie_str)),
                        cwe: "CWE-1275".to_string(),
                        cvss: 3.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Set SESSION_SAME_SITE=lax or strict in .env".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            }
        }

        // Check for exposed routes list
        tests_run += 1;
        let routes_paths = ["/api/routes", "/routes", "/_routes"];
        for path in &routes_paths {
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.contains("\"uri\"") || response.body.contains("\"method\"")) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("laravel_routes_exposed_{}", Self::generate_id()),
                        vuln_type: "Laravel Routes List Exposed".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: "Application route list is publicly accessible.".to_string(),
                        evidence: Some(format!("Routes accessible at: {}", test_url)),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.0,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove route listing endpoint from production.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        format!("{:x}{:x}", duration.as_secs(), duration.subsec_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_vulnerable() {
        let scanner = LaravelSecurityScanner::new(Arc::new(HttpClient::new().unwrap()));

        let v8_3_0 = LaravelVersion { major: 8, minor: 3, patch: 0 };
        assert!(scanner.is_version_vulnerable(&v8_3_0, "<8.4.2"));

        let v8_4_2 = LaravelVersion { major: 8, minor: 4, patch: 2 };
        assert!(!scanner.is_version_vulnerable(&v8_4_2, "<8.4.2"));

        let v9_0_0 = LaravelVersion { major: 9, minor: 0, patch: 0 };
        assert!(!scanner.is_version_vulnerable(&v9_0_0, "<8.4.2"));
    }

    #[test]
    fn test_cve_database() {
        let db = LaravelSecurityScanner::build_cve_database();
        assert!(db.contains_key("laravel"));
        assert!(!db["laravel"].is_empty());

        // Check Ignition RCE is in database
        let has_ignition = db["laravel"].iter().any(|c| c.cve_id == "CVE-2021-3129");
        assert!(has_ignition);
    }
}
