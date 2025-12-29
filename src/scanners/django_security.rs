// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct DjangoSecurityScanner {
    http_client: Arc<HttpClient>,
    known_cves: Vec<DjangoCVE>,
}

#[derive(Clone)]
struct DjangoCVE {
    cve_id: String,
    affected_versions: String,
    severity: Severity,
    description: String,
    check_type: CVECheckType,
}

#[derive(Clone, Debug)]
enum CVECheckType {
    SQLInjection,
    XSS,
    CSRF,
    PathTraversal,
    RCE,
    DoS,
    OpenRedirect,
    InfoDisclosure,
}

impl DjangoSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_cves: Self::build_cve_database(),
        }
    }

    /// Build database of known Django CVEs
    fn build_cve_database() -> Vec<DjangoCVE> {
        vec![
            // Recent Django CVEs
            DjangoCVE {
                cve_id: "CVE-2024-45231".to_string(),
                affected_versions: "<4.2.16, <5.0.9, <5.1.1".to_string(),
                severity: Severity::Medium,
                description: "Potential user email enumeration via password reset form".to_string(),
                check_type: CVECheckType::InfoDisclosure,
            },
            DjangoCVE {
                cve_id: "CVE-2024-45230".to_string(),
                affected_versions: "<4.2.16, <5.0.9, <5.1.1".to_string(),
                severity: Severity::High,
                description: "Denial of service via urlize() and urlizetrunc() template filters".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2024-42005".to_string(),
                affected_versions: "<4.2.15, <5.0.8".to_string(),
                severity: Severity::Critical,
                description: "SQL injection in QuerySet.values() and values_list()".to_string(),
                check_type: CVECheckType::SQLInjection,
            },
            DjangoCVE {
                cve_id: "CVE-2024-41991".to_string(),
                affected_versions: "<4.2.15, <5.0.8".to_string(),
                severity: Severity::High,
                description: "Potential denial of service via file uploads".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2024-41990".to_string(),
                affected_versions: "<4.2.15, <5.0.8".to_string(),
                severity: Severity::High,
                description: "Potential denial of service in urlize template filter".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2024-41989".to_string(),
                affected_versions: "<4.2.15, <5.0.8".to_string(),
                severity: Severity::Medium,
                description: "Memory exhaustion via floatformat template filter".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2024-39614".to_string(),
                affected_versions: "<4.2.14, <5.0.7".to_string(),
                severity: Severity::High,
                description: "Denial of service via django.utils.translation.get_supported_language_variant()".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2024-39330".to_string(),
                affected_versions: "<4.2.14, <5.0.7".to_string(),
                severity: Severity::High,
                description: "Path traversal via Storage.save() method".to_string(),
                check_type: CVECheckType::PathTraversal,
            },
            DjangoCVE {
                cve_id: "CVE-2024-39329".to_string(),
                affected_versions: "<4.2.14, <5.0.7".to_string(),
                severity: Severity::Medium,
                description: "Username enumeration via timing difference in login".to_string(),
                check_type: CVECheckType::InfoDisclosure,
            },
            DjangoCVE {
                cve_id: "CVE-2023-46695".to_string(),
                affected_versions: "<3.2.23, <4.1.13, <4.2.7".to_string(),
                severity: Severity::High,
                description: "Potential denial of service in UsernameField on Windows".to_string(),
                check_type: CVECheckType::DoS,
            },
            DjangoCVE {
                cve_id: "CVE-2023-43665".to_string(),
                affected_versions: "<3.2.22, <4.1.12, <4.2.6".to_string(),
                severity: Severity::Medium,
                description: "Denial of service via Truncator class".to_string(),
                check_type: CVECheckType::DoS,
            },
            // Older but still relevant CVEs
            DjangoCVE {
                cve_id: "CVE-2022-34265".to_string(),
                affected_versions: "<3.2.14, <4.0.6".to_string(),
                severity: Severity::Critical,
                description: "Potential SQL injection via Trunc() and Extract() database functions".to_string(),
                check_type: CVECheckType::SQLInjection,
            },
            DjangoCVE {
                cve_id: "CVE-2021-44420".to_string(),
                affected_versions: "<2.2.25, <3.1.14, <3.2.10".to_string(),
                severity: Severity::High,
                description: "Potential bypass of upstream access control in URL paths".to_string(),
                check_type: CVECheckType::PathTraversal,
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
            debug!("[Django] Skipping - requires Personal license or higher");
            return Ok((vec![], 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Detect if target is running Django
        tests_run += 1;
        let (is_django, version) = self.detect_django(url).await;

        if !is_django {
            debug!("[Django] Target does not appear to be running Django");
            return Ok((vec![], tests_run));
        }

        info!("[Django] Detected Django application{}",
            version.as_ref().map(|v| format!(" (version: {})", v)).unwrap_or_default());

        // Check for DEBUG mode
        let (debug_vulns, debug_tests) = self.check_debug_mode(url, config).await?;
        vulnerabilities.extend(debug_vulns);
        tests_run += debug_tests;

        // Check admin interface
        let (admin_vulns, admin_tests) = self.check_admin_exposure(url, config).await?;
        vulnerabilities.extend(admin_vulns);
        tests_run += admin_tests;

        // Check for SECRET_KEY exposure
        let (secret_vulns, secret_tests) = self.check_secret_key_exposure(url, config).await?;
        vulnerabilities.extend(secret_vulns);
        tests_run += secret_tests;

        // Check security headers and cookies
        let (security_vulns, security_tests) = self.check_security_settings(url, config).await?;
        vulnerabilities.extend(security_vulns);
        tests_run += security_tests;

        // Check Django Debug Toolbar
        let (toolbar_vulns, toolbar_tests) = self.check_debug_toolbar(url, config).await?;
        vulnerabilities.extend(toolbar_vulns);
        tests_run += toolbar_tests;

        // Check config file exposure
        let (config_vulns, config_tests) = self.check_config_exposure(url, config).await?;
        vulnerabilities.extend(config_vulns);
        tests_run += config_tests;

        // Check REST Framework
        let (drf_vulns, drf_tests) = self.check_drf_security(url, config).await?;
        vulnerabilities.extend(drf_vulns);
        tests_run += drf_tests;

        // Check static/media exposure
        let (static_vulns, static_tests) = self.check_static_exposure(url, config).await?;
        vulnerabilities.extend(static_vulns);
        tests_run += static_tests;

        // Check Celery/Redis exposure
        let (celery_vulns, celery_tests) = self.check_celery_exposure(url, config).await?;
        vulnerabilities.extend(celery_vulns);
        tests_run += celery_tests;

        // Check known CVEs
        if let Some(ref ver) = version {
            let (cve_vulns, cve_tests) = self.check_version_cves(url, ver, config).await?;
            vulnerabilities.extend(cve_vulns);
            tests_run += cve_tests;
        }

        info!("[Django] Completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(), tests_run);

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if target is running Django
    async fn detect_django(&self, url: &str) -> (bool, Option<String>) {
        let mut is_django = false;
        let mut version = None;

        // Check multiple indicators
        if let Ok(resp) = self.http_client.get(url).await {
            // Check for Django-specific patterns
            if resp.body.contains("csrfmiddlewaretoken") ||
               resp.body.contains("__django__") ||
               resp.body.contains("django.contrib") {
                is_django = true;
            }

            // Check headers
            if let Some(server) = resp.headers.get("server") {
                if server.to_lowercase().contains("wsgiserver") ||
                   server.to_lowercase().contains("gunicorn") ||
                   server.to_lowercase().contains("uwsgi") {
                    is_django = true;
                }
            }

            // Check for Django error page
            if resp.body.contains("Django") && resp.body.contains("Technical") {
                is_django = true;
            }

            // Check Set-Cookie for Django session
            if let Some(cookie) = resp.headers.get("set-cookie") {
                if cookie.contains("sessionid") || cookie.contains("csrftoken") {
                    is_django = true;
                }
            }

            // Extract version from debug page or error
            let version_re = Regex::new(r#"Django[/\s]+v?(\d+\.\d+(?:\.\d+)?)"#).ok();
            if let Some(re) = version_re {
                if let Some(caps) = re.captures(&resp.body) {
                    version = caps.get(1).map(|m| m.as_str().to_string());
                }
            }
        }

        // Check for Django admin
        let admin_url = format!("{}/admin/", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&admin_url).await {
            if resp.body.contains("Django") ||
               resp.body.contains("administration") ||
               resp.body.contains("Log in") && resp.body.contains("csrfmiddlewaretoken") {
                is_django = true;
            }
        }

        (is_django, version)
    }

    /// Check for DEBUG=True exposure
    async fn check_debug_mode(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Trigger debug error page with invalid URLs
        let debug_triggers = [
            "/nonexistent-page-12345",
            "/admin/../../../",
            "/?debug=true",
            "/%00",
            "/static/../../",
        ];

        for trigger in &debug_triggers {
            tests_run += 1;
            let test_url = format!("{}{}", base, trigger);

            if let Ok(resp) = self.http_client.get(&test_url).await {
                // Check for Django debug page indicators
                let is_debug = resp.body.contains("You're seeing this error because you have <code>DEBUG = True</code>") ||
                    resp.body.contains("Technical 500") ||
                    resp.body.contains("INSTALLED_APPS") ||
                    resp.body.contains("Request Method:") && resp.body.contains("Exception Type:") ||
                    resp.body.contains("Django settings module") ||
                    resp.body.contains("Traceback (most recent call last)") && resp.body.contains("django");

                if is_debug {
                    // Check what sensitive info is exposed
                    let mut exposed_info = Vec::new();
                    if resp.body.contains("SECRET_KEY") { exposed_info.push("SECRET_KEY"); }
                    if resp.body.contains("DATABASE") { exposed_info.push("DATABASE credentials"); }
                    if resp.body.contains("ALLOWED_HOSTS") { exposed_info.push("ALLOWED_HOSTS"); }
                    if resp.body.contains("EMAIL_") { exposed_info.push("Email settings"); }
                    if resp.body.contains("AWS_") { exposed_info.push("AWS credentials"); }
                    if resp.body.contains("STRIPE_") { exposed_info.push("Stripe keys"); }

                    vulnerabilities.push(Vulnerability {
                        id: format!("django_debug_mode_{}", Self::generate_id()),
                        vuln_type: "Django DEBUG Mode Enabled in Production".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Misconfiguration".to_string(),
                        url: test_url.clone(),
                        parameter: Some("DEBUG".to_string()),
                        payload: trigger.to_string(),
                        description: format!(
                            "Django DEBUG mode is enabled, exposing sensitive application internals. \
                            The error page reveals: {}. This allows attackers to understand the application \
                            structure, extract credentials, and identify vulnerabilities.",
                            if exposed_info.is_empty() { "settings, traceback, environment".to_string() }
                            else { exposed_info.join(", ") }
                        ),
                        evidence: Some(format!(
                            "Debug page triggered by: {}\n\
                            Exposed information: {}\n\
                            Full traceback and settings visible",
                            trigger,
                            exposed_info.join(", ")
                        )),
                        cwe: "CWE-215".to_string(),
                        cvss: 9.1,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Set DEBUG=False in production settings\n\
                                      2. Use separate settings files for dev/prod\n\
                                      3. Set DEBUG=False environment variable\n\
                                      4. Configure proper error handling with custom 500 page\n\
                                      5. Review ALLOWED_HOSTS configuration".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check admin interface security
    async fn check_admin_exposure(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common admin URLs
        let admin_paths = [
            "/admin/",
            "/django-admin/",
            "/administrator/",
            "/admin/login/",
            "/backend/",
            "/manage/",
        ];

        for path in &admin_paths {
            tests_run += 1;
            let admin_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&admin_url).await {
                if resp.status_code == 200 || resp.status_code == 302 {
                    let is_admin = resp.body.contains("Django") ||
                        resp.body.contains("Log in") && resp.body.contains("csrf") ||
                        resp.body.contains("administration") ||
                        resp.body.contains("django-admin-login");

                    if is_admin {
                        let mut issues = Vec::new();

                        // Check if admin is accessible without auth redirect
                        if resp.status_code == 200 && !resp.body.contains("login") {
                            issues.push("Admin accessible without authentication".to_string());
                        }

                        // Check for default/weak credentials
                        tests_run += 1;
                        let default_creds = [
                            ("admin", "admin"),
                            ("admin", "password"),
                            ("admin", "123456"),
                            ("django", "django"),
                        ];

                        for (user, pass) in &default_creds {
                            let login_url = format!("{}login/", admin_url.trim_end_matches('/'));

                            // Get CSRF token first
                            if let Ok(login_page) = self.http_client.get(&login_url).await {
                                let csrf_re = Regex::new(r#"name=['\"]csrfmiddlewaretoken['\"] value=['\"]([^'\"]+)['\"]"#).ok();
                                if let Some(re) = csrf_re {
                                    if let Some(caps) = re.captures(&login_page.body) {
                                        let csrf_token = caps.get(1).map(|m| m.as_str()).unwrap_or("");

                                        let body = format!(
                                            "csrfmiddlewaretoken={}&username={}&password={}",
                                            csrf_token, user, pass
                                        );

                                        let mut headers = HashMap::new();
                                        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
                                        headers.insert("Referer".to_string(), login_url.clone());

                                        let headers_vec: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                                        if let Ok(login_resp) = self.http_client.post_with_headers(&login_url, &body, headers_vec).await {
                                            // Check for successful login (redirect to admin dashboard)
                                            if login_resp.status_code == 302 &&
                                               login_resp.headers.get("location").map(|l| !l.contains("login")).unwrap_or(false) {
                                                issues.push(format!("Default credentials: {}:{}", user, pass));
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !issues.is_empty() || *path == "/admin/" {
                            vulnerabilities.push(Vulnerability {
                                id: format!("django_admin_exposure_{}", Self::generate_id()),
                                vuln_type: "Django Admin Interface Exposed".to_string(),
                                severity: if issues.iter().any(|i| i.contains("credentials")) {
                                    Severity::Critical
                                } else {
                                    Severity::Medium
                                },
                                confidence: Confidence::High,
                                category: "Misconfiguration".to_string(),
                                url: admin_url.clone(),
                                parameter: Some("admin".to_string()),
                                payload: path.to_string(),
                                description: format!(
                                    "Django admin interface is publicly accessible at {}. {}",
                                    path,
                                    if issues.is_empty() {
                                        "Consider restricting access via IP whitelist or VPN.".to_string()
                                    } else {
                                        format!("Issues found: {}", issues.join(", "))
                                    }
                                ),
                                evidence: Some({
                                    let issues_str = if issues.is_empty() {
                                        "None".to_string()
                                    } else {
                                        issues.join(", ")
                                    };
                                    format!(
                                        "Admin URL: {}\n\
                                        Status: {}\n\
                                        Issues: {}",
                                        admin_url, resp.status_code, issues_str
                                    )
                                }),
                                cwe: "CWE-200".to_string(),
                                cvss: if issues.iter().any(|i| i.contains("credentials")) { 9.8 } else { 5.3 },
                                verified: true,
                                false_positive: false,
                                remediation: "1. Restrict admin access via ALLOWED_HOSTS\n\
                                              2. Use django-admin-honeypot\n\
                                              3. Change admin URL to non-default path\n\
                                              4. Implement IP whitelist or VPN requirement\n\
                                              5. Enable two-factor authentication\n\
                                              6. Use strong, unique admin passwords".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
                            break;
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

    /// Check for SECRET_KEY exposure
    async fn check_secret_key_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Files that might contain SECRET_KEY
        let secret_files = [
            "/settings.py",
            "/config/settings.py",
            "/myproject/settings.py",
            "/.env",
            "/.env.local",
            "/config/.env",
            "/secret_key.txt",
            "/secrets.json",
            "/.git/config",
        ];

        for file in &secret_files {
            tests_run += 1;
            let file_url = format!("{}{}", base, file);

            if let Ok(resp) = self.http_client.get(&file_url).await {
                if resp.status_code == 200 {
                    // Check for SECRET_KEY in response
                    let secret_patterns = [
                        r#"SECRET_KEY\s*=\s*['\"][^'\"]{20,}['\"]"#,
                        r#"DJANGO_SECRET_KEY\s*=\s*['\"][^'\"]+['\"]"#,
                        r#"secret_key['\"]?\s*[:=]\s*['\"][^'\"]+['\"]"#,
                    ];

                    for pattern in &secret_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&resp.body) {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("django_secret_key_{}", Self::generate_id()),
                                    vuln_type: "Django SECRET_KEY Exposed".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    category: "Information Disclosure".to_string(),
                                    url: file_url.clone(),
                                    parameter: Some("SECRET_KEY".to_string()),
                                    payload: file.to_string(),
                                    description: format!(
                                        "Django SECRET_KEY is exposed via {}. This key is used for \
                                        cryptographic signing and its exposure allows attackers to \
                                        forge session cookies, password reset tokens, and other signed data.",
                                        file
                                    ),
                                    evidence: Some(format!(
                                        "File: {}\n\
                                        SECRET_KEY pattern found in response\n\
                                        Impact: Session hijacking, CSRF bypass, token forgery",
                                        file
                                    )),
                                    cwe: "CWE-798".to_string(),
                                    cvss: 9.8,
                                    verified: true,
                                    false_positive: false,
                                    remediation: "1. Immediately rotate SECRET_KEY\n\
                                                  2. Move SECRET_KEY to environment variable\n\
                                                  3. Block access to config files via web server\n\
                                                  4. Invalidate all existing sessions\n\
                                                  5. Use django-environ for secure config".to_string(),
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

    /// Check security headers and cookie settings
    async fn check_security_settings(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            let mut issues = Vec::new();

            // Check session cookie security
            if let Some(cookie) = resp.headers.get("set-cookie") {
                if cookie.contains("sessionid") {
                    if !cookie.to_lowercase().contains("secure") {
                        issues.push("Session cookie missing Secure flag");
                    }
                    if !cookie.to_lowercase().contains("httponly") {
                        issues.push("Session cookie missing HttpOnly flag");
                    }
                    if !cookie.to_lowercase().contains("samesite") {
                        issues.push("Session cookie missing SameSite attribute");
                    }
                }
                if cookie.contains("csrftoken") && !cookie.to_lowercase().contains("secure") {
                    issues.push("CSRF cookie missing Secure flag");
                }
            }

            // Check security headers
            if !resp.headers.contains_key("x-frame-options") &&
               !resp.headers.contains_key("content-security-policy") {
                issues.push("Missing X-Frame-Options header (clickjacking)");
            }
            if !resp.headers.contains_key("x-content-type-options") {
                issues.push("Missing X-Content-Type-Options header");
            }
            if !resp.headers.contains_key("strict-transport-security") {
                issues.push("Missing HSTS header");
            }

            if !issues.is_empty() {
                vulnerabilities.push(Vulnerability {
                    id: format!("django_security_settings_{}", Self::generate_id()),
                    vuln_type: "Django Security Misconfiguration".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Misconfiguration".to_string(),
                    url: url.to_string(),
                    parameter: Some("Security Settings".to_string()),
                    payload: issues.join(", "),
                    description: format!(
                        "Django security settings are not properly configured. Found issues: {}",
                        issues.join("; ")
                    ),
                    evidence: Some(format!(
                        "Issues found:\n- {}",
                        issues.join("\n- ")
                    )),
                    cwe: "CWE-16".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "Add to settings.py:\n\
                                  SESSION_COOKIE_SECURE = True\n\
                                  SESSION_COOKIE_HTTPONLY = True\n\
                                  CSRF_COOKIE_SECURE = True\n\
                                  SECURE_HSTS_SECONDS = 31536000\n\
                                  SECURE_CONTENT_TYPE_NOSNIFF = True\n\
                                  X_FRAME_OPTIONS = 'DENY'".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for Django Debug Toolbar exposure
    async fn check_debug_toolbar(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        if let Ok(resp) = self.http_client.get(url).await {
            // Check for Debug Toolbar indicators
            let has_toolbar = resp.body.contains("djdt-") ||
                resp.body.contains("debug-toolbar") ||
                resp.body.contains("djDebug") ||
                resp.body.contains("/__debug__/");

            if has_toolbar {
                vulnerabilities.push(Vulnerability {
                    id: format!("django_debug_toolbar_{}", Self::generate_id()),
                    vuln_type: "Django Debug Toolbar Exposed in Production".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("Debug Toolbar".to_string()),
                    payload: "djdt-*".to_string(),
                    description: "Django Debug Toolbar is enabled and accessible. This exposes SQL queries, \
                                  settings, headers, request/response data, templates, and signals.".to_string(),
                    evidence: Some("Debug Toolbar elements found in HTML response".to_string()),
                    cwe: "CWE-215".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Remove debug_toolbar from INSTALLED_APPS in production\n\
                                  2. Use conditional installation based on DEBUG setting\n\
                                  3. Restrict INTERNAL_IPS to local addresses only\n\
                                  4. Use environment-specific settings files".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        // Check __debug__ URL
        tests_run += 1;
        let debug_url = format!("{}/__debug__/", url.trim_end_matches('/'));
        if let Ok(resp) = self.http_client.get(&debug_url).await {
            if resp.status_code == 200 {
                vulnerabilities.push(Vulnerability {
                    id: format!("django_debug_url_{}", Self::generate_id()),
                    vuln_type: "Django Debug Toolbar URL Accessible".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: debug_url,
                    parameter: Some("__debug__".to_string()),
                    payload: "/__debug__/".to_string(),
                    description: "The Django Debug Toolbar debug URL is publicly accessible.".to_string(),
                    evidence: Some("/__debug__/ returns 200 OK".to_string()),
                    cwe: "CWE-215".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Disable Debug Toolbar in production or restrict INTERNAL_IPS.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
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

        let config_files = [
            ("requirements.txt", "Python dependencies"),
            ("requirements.in", "Python dependencies"),
            ("Pipfile", "Pipenv dependencies"),
            ("Pipfile.lock", "Pipenv lock file"),
            ("pyproject.toml", "Project configuration"),
            ("setup.py", "Package setup"),
            ("manage.py", "Django management script"),
            ("wsgi.py", "WSGI configuration"),
            ("asgi.py", "ASGI configuration"),
            ("celery.py", "Celery configuration"),
            ("docker-compose.yml", "Docker configuration"),
            ("Dockerfile", "Docker build file"),
            (".gitignore", "Git ignore rules"),
            ("/static/admin/", "Admin static files"),
        ];

        for (file, desc) in &config_files {
            tests_run += 1;
            let file_url = format!("{}/{}", base, file);

            if let Ok(resp) = self.http_client.get(&file_url).await {
                if resp.status_code == 200 && resp.body.len() > 10 {
                    let is_sensitive = resp.body.contains("django") ||
                        resp.body.contains("Django") ||
                        resp.body.contains("celery") ||
                        resp.body.contains("postgres") ||
                        resp.body.contains("SECRET") ||
                        resp.body.contains("import");

                    if is_sensitive {
                        vulnerabilities.push(Vulnerability {
                            id: format!("django_config_exposure_{}", Self::generate_id()),
                            vuln_type: format!("Django Configuration Exposed: {}", desc),
                            severity: if file.contains(".env") || file.contains("secret") {
                                Severity::Critical
                            } else if file.contains("requirements") || file.contains("Pipfile") {
                                Severity::Medium
                            } else {
                                Severity::Low
                            },
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: file_url.clone(),
                            parameter: Some(file.to_string()),
                            payload: format!("GET /{}", file),
                            description: format!(
                                "{} file is publicly accessible. This may reveal dependencies, \
                                versions, and configuration details useful for attackers.",
                                desc
                            ),
                            evidence: Some(format!(
                                "File: {}\n\
                                Status: 200 OK\n\
                                Content length: {} bytes",
                                file, resp.body.len()
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Configure web server to deny access to config files\n\
                                          2. Move sensitive files outside web root\n\
                                          3. Use proper deployment practices".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check Django REST Framework security
    async fn check_drf_security(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Common DRF API endpoints
        let api_endpoints = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/rest/",
            "/api/users/",
            "/api/schema/",
            "/api-auth/",
        ];

        for endpoint in &api_endpoints {
            tests_run += 1;
            let api_url = format!("{}{}", base, endpoint);

            if let Ok(resp) = self.http_client.get(&api_url).await {
                // Check for browsable API
                if resp.status_code == 200 && resp.body.contains("rest_framework") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("django_drf_browsable_{}", Self::generate_id()),
                        vuln_type: "Django REST Framework Browsable API Exposed".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: api_url.clone(),
                        parameter: Some("browsable_api".to_string()),
                        payload: endpoint.to_string(),
                        description: "DRF Browsable API is enabled in production. While not a direct vulnerability, \
                                      it reveals API structure and may allow unauthorized data access.".to_string(),
                        evidence: Some(format!("Endpoint: {}", endpoint)),
                        cwe: "CWE-200".to_string(),
                        cvss: 3.7,
                        verified: true,
                        false_positive: false,
                        remediation: "Disable BrowsableAPIRenderer in production:\n\
                                      REST_FRAMEWORK = {'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer']}".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }

                // Check CORS
                tests_run += 1;
                let mut cors_headers = HashMap::new();
                cors_headers.insert("Origin".to_string(), "https://evil.com".to_string());

                let headers_vec: Vec<(String, String)> = cors_headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                if let Ok(cors_resp) = self.http_client.get_with_headers(&api_url, headers_vec).await {
                    if let Some(acao) = cors_resp.headers.get("access-control-allow-origin") {
                        if acao == "*" || acao == "https://evil.com" {
                            let has_creds = cors_resp.headers.get("access-control-allow-credentials")
                                .map(|v| v == "true")
                                .unwrap_or(false);

                            vulnerabilities.push(Vulnerability {
                                id: format!("django_cors_{}", Self::generate_id()),
                                vuln_type: "Django REST API CORS Misconfiguration".to_string(),
                                severity: if has_creds { Severity::High } else { Severity::Medium },
                                confidence: Confidence::High,
                                category: "Misconfiguration".to_string(),
                                url: api_url.clone(),
                                parameter: Some("CORS".to_string()),
                                payload: "Origin: https://evil.com".to_string(),
                                description: format!(
                                    "API allows cross-origin requests from any domain{}.",
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
                                remediation: "Use django-cors-headers with specific CORS_ALLOWED_ORIGINS list.".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                            });
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

    /// Check static/media file exposure
    async fn check_static_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Check media directory listing
        let media_paths = ["/media/", "/uploads/", "/files/", "/static/uploads/"];

        for path in &media_paths {
            tests_run += 1;
            let media_url = format!("{}{}", base, path);

            if let Ok(resp) = self.http_client.get(&media_url).await {
                // Check for directory listing
                if resp.status_code == 200 &&
                   (resp.body.contains("Index of") || resp.body.contains("<a href=")) &&
                   !resp.body.contains("<!DOCTYPE") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("django_directory_listing_{}", Self::generate_id()),
                        vuln_type: "Django Media Directory Listing Enabled".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: media_url.clone(),
                        parameter: Some("directory_listing".to_string()),
                        payload: path.to_string(),
                        description: format!(
                            "Directory listing is enabled at {}. This exposes uploaded files and \
                            may reveal sensitive documents.",
                            path
                        ),
                        evidence: Some(format!("Directory listing at: {}", media_url)),
                        cwe: "CWE-548".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Disable directory listing in web server configuration:\n\
                                      Apache: Options -Indexes\n\
                                      Nginx: autoindex off;".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check Celery/Redis exposure
    async fn check_celery_exposure(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base = url.trim_end_matches('/');

        // Check Flower (Celery monitoring)
        let flower_paths = ["/flower/", "/celery/", ":5555/", ":5555/dashboard"];

        for path in &flower_paths {
            tests_run += 1;
            let flower_url = if path.starts_with(':') {
                // Replace port in URL
                let port_re = Regex::new(r":\d+").ok();
                if let Some(re) = port_re {
                    re.replace(base, *path).to_string()
                } else {
                    continue;
                }
            } else {
                format!("{}{}", base, path)
            };

            if let Ok(resp) = self.http_client.get(&flower_url).await {
                if resp.status_code == 200 &&
                   (resp.body.contains("Flower") || resp.body.contains("celery") || resp.body.contains("tasks")) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("django_flower_{}", Self::generate_id()),
                        vuln_type: "Celery Flower Dashboard Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Misconfiguration".to_string(),
                        url: flower_url.clone(),
                        parameter: Some("flower".to_string()),
                        payload: path.to_string(),
                        description: "Celery Flower monitoring dashboard is publicly accessible. \
                                      This exposes task information, workers, and may allow task execution.".to_string(),
                        evidence: Some(format!("Flower dashboard at: {}", flower_url)),
                        cwe: "CWE-200".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Add authentication to Flower: flower --basic_auth=user:pass\n\
                                      2. Restrict access via firewall/VPN\n\
                                      3. Use flower --url_prefix with reverse proxy".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
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

            let is_affected = Self::check_version_affected(major, minor, patch, &cve.affected_versions);

            if is_affected {
                vulnerabilities.push(Vulnerability {
                    id: format!("django_cve_{}_{}", cve.cve_id, Self::generate_id()),
                    vuln_type: format!("Django {} - {:?}", cve.cve_id, cve.check_type),
                    severity: cve.severity.clone(),
                    confidence: Confidence::High,
                    category: "Known Vulnerability".to_string(),
                    url: url.to_string(),
                    parameter: Some(format!("Django {}", version)),
                    payload: format!("{}: {}", cve.cve_id, cve.affected_versions),
                    description: format!(
                        "{}\n\nDetected version: {}\nAffected: {}",
                        cve.description, version, cve.affected_versions
                    ),
                    evidence: Some(format!(
                        "CVE: {}\nVersion: {}\nAffected: {}",
                        cve.cve_id, version, cve.affected_versions
                    )),
                    cwe: match cve.check_type {
                        CVECheckType::SQLInjection => "CWE-89",
                        CVECheckType::XSS => "CWE-79",
                        CVECheckType::CSRF => "CWE-352",
                        CVECheckType::PathTraversal => "CWE-22",
                        CVECheckType::RCE => "CWE-94",
                        CVECheckType::DoS => "CWE-400",
                        CVECheckType::OpenRedirect => "CWE-601",
                        CVECheckType::InfoDisclosure => "CWE-200",
                    }.to_string(),
                    cvss: match cve.severity {
                        Severity::Critical => 9.8,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.0,
                    },
                    verified: false,
                    false_positive: false,
                    remediation: format!(
                        "Upgrade Django to a patched version. See: https://nvd.nist.gov/vuln/detail/{}",
                        cve.cve_id
                    ),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn check_version_affected(major: u32, minor: u32, patch: u32, affected: &str) -> bool {
        // Parse affected versions like "<4.2.16, <5.0.9, <5.1.1"
        for constraint in affected.split(',') {
            let constraint = constraint.trim();
            if constraint.starts_with('<') {
                let ver_str = constraint.trim_start_matches('<');
                let ver_parts: Vec<u32> = ver_str.split('.')
                    .filter_map(|p| p.parse().ok())
                    .collect();

                if ver_parts.len() >= 2 {
                    let a_major = ver_parts[0];
                    let a_minor = ver_parts[1];
                    let a_patch = ver_parts.get(2).copied().unwrap_or(0);

                    // Check if current version matches the major.minor and is less than patch
                    if major == a_major && minor == a_minor && patch < a_patch {
                        return true;
                    }
                    // Check if current version is older major.minor
                    if major == a_major && minor < a_minor {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}
