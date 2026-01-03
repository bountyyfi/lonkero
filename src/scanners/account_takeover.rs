// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Account Takeover Chains Scanner
 * Comprehensive detection of account takeover attack chains including:
 * - Password reset vulnerabilities
 * - Session/Cookie security issues
 * - Email-based account takeover
 * - OAuth/Social login vulnerabilities
 * - Phone-based account takeover
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::{endpoint_exists, AppCharacteristics};
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info};

/// Account Takeover Chains Scanner
/// Detects complex attack chains that lead to full account compromise
pub struct AccountTakeoverScanner {
    http_client: Arc<HttpClient>,
}

/// Authentication endpoint detection result
#[derive(Debug, Clone)]
struct AuthEndpoints {
    login: Vec<String>,
    password_reset: Vec<String>,
    email_change: Vec<String>,
    phone_change: Vec<String>,
    oauth_callback: Vec<String>,
    session_endpoints: Vec<String>,
}

impl AuthEndpoints {
    fn new() -> Self {
        Self {
            login: Vec::new(),
            password_reset: Vec::new(),
            email_change: Vec::new(),
            phone_change: Vec::new(),
            oauth_callback: Vec::new(),
            session_endpoints: Vec::new(),
        }
    }

    fn has_any(&self) -> bool {
        !self.login.is_empty()
            || !self.password_reset.is_empty()
            || !self.email_change.is_empty()
            || !self.phone_change.is_empty()
            || !self.oauth_callback.is_empty()
    }
}

impl AccountTakeoverScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check - required for scan authorization
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!("[ATO] Scanning for account takeover chains: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // CRITICAL: First detect application characteristics
        // Skip scanning for sites without authentication
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[ATO] Could not fetch URL: {}", e);
                return Ok((Vec::new(), tests_run));
            }
        };

        let characteristics = AppCharacteristics::from_response(&response, url);

        // Skip if no authentication functionality detected
        if characteristics.should_skip_auth_tests() {
            info!("[ATO] No authentication detected - skipping account takeover tests");
            return Ok((vulnerabilities, tests_run));
        }

        // Skip for pure SPAs - they handle auth client-side
        if characteristics.should_skip_injection_tests() && !characteristics.has_authentication {
            info!("[ATO] Site is SPA without server auth - skipping ATO tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[ATO] Authentication detected - proceeding with security tests");

        // Step 1: Map all authentication-related endpoints
        tests_run += 1;
        let auth_endpoints = self.discover_auth_endpoints(url, &response).await;

        if !auth_endpoints.has_any() {
            info!("[ATO] No specific auth endpoints found - running basic tests only");
        }

        // ==================== PASSWORD RESET VULNERABILITIES ====================
        info!("[ATO] Testing password reset vulnerabilities...");

        // Test password reset token in URL (Referer leakage)
        for reset_endpoint in &auth_endpoints.password_reset {
            tests_run += 1;
            let reset_vulns = self.test_password_reset_token_in_url(reset_endpoint).await;
            vulnerabilities.extend(reset_vulns);
        }

        // Test password reset token not invalidated after use
        for reset_endpoint in &auth_endpoints.password_reset {
            tests_run += 1;
            let reuse_vulns = self.test_password_reset_token_reuse(reset_endpoint).await;
            vulnerabilities.extend(reuse_vulns);
        }

        // Test predictable token generation
        for reset_endpoint in &auth_endpoints.password_reset {
            tests_run += 1;
            let predictable_vulns = self.test_predictable_reset_token(reset_endpoint).await;
            vulnerabilities.extend(predictable_vulns);
        }

        // Test host header injection in reset emails
        for reset_endpoint in &auth_endpoints.password_reset {
            tests_run += 1;
            let host_vulns = self.test_host_header_injection(reset_endpoint).await;
            vulnerabilities.extend(host_vulns);
        }

        // ==================== SESSION/COOKIE ISSUES ====================
        info!("[ATO] Testing session management vulnerabilities...");

        // Test session not invalidated on password change
        tests_run += 1;
        let session_vulns = self
            .test_session_fixation_on_password_change(url, &response)
            .await;
        vulnerabilities.extend(session_vulns);

        // Test cookie security (httpOnly, Secure, SameSite)
        tests_run += 1;
        let cookie_vulns = self.test_cookie_security(&response, url);
        vulnerabilities.extend(cookie_vulns);

        // Test concurrent session handling
        tests_run += 1;
        let concurrent_vulns = self.test_concurrent_sessions(url).await;
        vulnerabilities.extend(concurrent_vulns);

        // ==================== EMAIL-BASED ATO ====================
        info!("[ATO] Testing email-based account takeover vulnerabilities...");

        // Test email change without password confirmation
        for email_endpoint in &auth_endpoints.email_change {
            tests_run += 1;
            let email_vulns = self
                .test_email_change_without_password(email_endpoint)
                .await;
            vulnerabilities.extend(email_vulns);
        }

        // Test email enumeration via timing
        tests_run += 1;
        let enum_vulns = self.test_email_enumeration_timing(url).await;
        vulnerabilities.extend(enum_vulns);

        // Test case sensitivity issues in email
        tests_run += 1;
        let case_vulns = self.test_email_case_sensitivity(url).await;
        vulnerabilities.extend(case_vulns);

        // ==================== OAUTH/SOCIAL LOGIN ISSUES ====================
        info!("[ATO] Testing OAuth/Social login vulnerabilities...");

        // Test OAuth account linking without verification
        for oauth_endpoint in &auth_endpoints.oauth_callback {
            tests_run += 1;
            let oauth_vulns = self.test_oauth_account_linking(oauth_endpoint).await;
            vulnerabilities.extend(oauth_vulns);
        }

        // Test missing state parameter validation
        for oauth_endpoint in &auth_endpoints.oauth_callback {
            tests_run += 1;
            let state_vulns = self.test_oauth_state_validation(oauth_endpoint).await;
            vulnerabilities.extend(state_vulns);
        }

        // ==================== PHONE-BASED ATO ====================
        info!("[ATO] Testing phone-based account takeover vulnerabilities...");

        // Test phone number change without verification
        for phone_endpoint in &auth_endpoints.phone_change {
            tests_run += 1;
            let phone_vulns = self
                .test_phone_change_without_verification(phone_endpoint)
                .await;
            vulnerabilities.extend(phone_vulns);
        }

        // Test SMS code enumeration
        tests_run += 1;
        let sms_vulns = self.test_sms_code_enumeration(url).await;
        vulnerabilities.extend(sms_vulns);

        // ==================== COMBINED ATTACK CHAINS ====================
        info!("[ATO] Testing combined attack chains...");

        // Test account recovery chain vulnerabilities
        tests_run += 1;
        let chain_vulns = self.test_account_recovery_chain(url, &auth_endpoints).await;
        vulnerabilities.extend(chain_vulns);

        // Deduplicate vulnerabilities
        let mut seen_types = HashSet::new();
        let unique_vulns: Vec<Vulnerability> = vulnerabilities
            .into_iter()
            .filter(|v| {
                let key = format!(
                    "{}:{}:{}",
                    v.vuln_type,
                    v.url,
                    v.parameter.as_ref().unwrap_or(&String::new())
                );
                seen_types.insert(key)
            })
            .collect();

        info!(
            "[SUCCESS] [ATO] Completed {} tests, found {} unique issues",
            tests_run,
            unique_vulns.len()
        );

        Ok((unique_vulns, tests_run))
    }

    /// Discover authentication-related endpoints
    async fn discover_auth_endpoints(
        &self,
        base_url: &str,
        response: &crate::http_client::HttpResponse,
    ) -> AuthEndpoints {
        let mut endpoints = AuthEndpoints::new();
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Parse base URL
        let parsed = match url::Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return endpoints,
        };
        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Common password reset paths
        let reset_paths = vec![
            "/forgot-password",
            "/password/reset",
            "/reset-password",
            "/password/forgot",
            "/account/reset",
            "/auth/forgot",
            "/api/password/reset",
            "/api/auth/forgot-password",
            "/users/password/new",
            "/salasana/unohtunut", // Finnish
        ];

        for path in &reset_paths {
            let url = format!("{}{}", base, path);
            if let Ok(r) = self.http_client.get(&url).await {
                if endpoint_exists(&r, &[200, 302, 401]) {
                    endpoints.password_reset.push(url);
                }
            }
        }

        // Common email change paths
        let email_paths = vec![
            "/settings/email",
            "/account/email",
            "/profile/email",
            "/api/user/email",
            "/api/account/email",
            "/change-email",
        ];

        for path in &email_paths {
            let url = format!("{}{}", base, path);
            if let Ok(r) = self.http_client.get(&url).await {
                if endpoint_exists(&r, &[200, 302, 401, 403]) {
                    endpoints.email_change.push(url);
                }
            }
        }

        // Common phone change paths
        let phone_paths = vec![
            "/settings/phone",
            "/account/phone",
            "/profile/phone",
            "/api/user/phone",
            "/change-phone",
        ];

        for path in &phone_paths {
            let url = format!("{}{}", base, path);
            if let Ok(r) = self.http_client.get(&url).await {
                if endpoint_exists(&r, &[200, 302, 401, 403]) {
                    endpoints.phone_change.push(url);
                }
            }
        }

        // OAuth callback paths
        let oauth_paths = vec![
            "/oauth/callback",
            "/auth/callback",
            "/oauth2/callback",
            "/api/auth/callback",
            "/login/callback",
            "/social/callback",
        ];

        for path in &oauth_paths {
            let url = format!("{}{}", base, path);
            if let Ok(r) = self.http_client.get(&url).await {
                if endpoint_exists(&r, &[200, 302, 400, 401]) {
                    endpoints.oauth_callback.push(url);
                }
            }
        }

        // Extract login endpoints from HTML
        let login_patterns = vec![
            r#"action=["']([^"']*login[^"']*)["']"#,
            r#"href=["']([^"']*sign-?in[^"']*)["']"#,
            r#"href=["']([^"']*kirjaudu[^"']*)["']"#,
        ];

        for pattern in &login_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(body) {
                    if let Some(path) = cap.get(1) {
                        let url = if path.as_str().starts_with("http") {
                            path.as_str().to_string()
                        } else if path.as_str().starts_with('/') {
                            format!("{}{}", base, path.as_str())
                        } else {
                            format!("{}/{}", base, path.as_str())
                        };
                        if !endpoints.login.contains(&url) {
                            endpoints.login.push(url);
                        }
                    }
                }
            }
        }

        debug!(
            "[ATO] Discovered endpoints: {} login, {} reset, {} email, {} phone, {} oauth",
            endpoints.login.len(),
            endpoints.password_reset.len(),
            endpoints.email_change.len(),
            endpoints.phone_change.len(),
            endpoints.oauth_callback.len()
        );

        endpoints
    }

    // ==================== PASSWORD RESET TESTS ====================

    /// Test if password reset token is exposed in URL (leakable via Referer header)
    async fn test_password_reset_token_in_url(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing password reset token in URL: {}", endpoint);

        // Request the password reset page
        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        // Check if the URL contains token parameters
        let url_lower = endpoint.to_lowercase();
        let token_in_url = url_lower.contains("token=")
            || url_lower.contains("reset_token=")
            || url_lower.contains("code=")
            || url_lower.contains("key=");

        // Check response for reset links with tokens
        let body = &response.body;
        let token_patterns = vec![
            r#"href=["'][^"']*\?token=[^"']+["']"#,
            r#"href=["'][^"']*\?reset_token=[^"']+["']"#,
            r#"href=["'][^"']*\?code=[^"']+["']"#,
        ];

        let mut has_token_in_link = false;
        for pattern in &token_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    has_token_in_link = true;
                    break;
                }
            }
        }

        // Check if page loads external resources (potential Referer leak)
        let has_external_resources = body.contains("src=\"http")
            || body.contains("src='http")
            || body.contains("href=\"http")
            || body.contains("href='http");

        if (token_in_url || has_token_in_link) && has_external_resources {
            vulnerabilities.push(self.create_vulnerability(
                "Password Reset Token in URL - Referer Leakage",
                endpoint,
                Severity::High,
                Confidence::High,
                "Password reset tokens are transmitted in URL parameters. When the reset page loads \
                external resources (scripts, images, stylesheets), the token is leaked via the \
                Referer header to third-party servers. Attackers monitoring these servers or \
                network traffic can capture tokens and reset victim passwords.",
                format!(
                    "Token in URL: {}, External resources: {}, Token in links: {}",
                    token_in_url, has_external_resources, has_token_in_link
                ),
                "CWE-598",
                8.6,
            ));
        }

        // Also check if token appears in browser history / server logs warning
        if token_in_url {
            vulnerabilities.push(self.create_vulnerability(
                "Password Reset Token Exposure in URL",
                endpoint,
                Severity::Medium,
                Confidence::High,
                "Password reset tokens in URLs are exposed in browser history, server access logs, \
                proxy logs, and potentially shared links. Tokens should be transmitted via POST \
                body or secure headers instead.",
                "Token parameter found in URL query string".to_string(),
                "CWE-598",
                6.5,
            ));
        }

        vulnerabilities
    }

    /// Test if password reset token can be reused after consumption
    async fn test_password_reset_token_reuse(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing password reset token reuse: {}", endpoint);

        // We can't actually test token reuse without real tokens, but we can check
        // for indicators of weak implementation
        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body_lower = response.body.to_lowercase();

        // Check for single-use token enforcement indicators
        let has_single_use_indicator = body_lower.contains("token has been used")
            || body_lower.contains("link has expired")
            || body_lower.contains("one-time")
            || body_lower.contains("already used");

        // Check for weak expiration messages
        let has_weak_expiration = body_lower.contains("never expires")
            || body_lower.contains("no expiration")
            || (!body_lower.contains("expires") && !body_lower.contains("valid for"));

        if has_weak_expiration && !has_single_use_indicator {
            vulnerabilities.push(self.create_vulnerability(
                "Password Reset Token May Not Expire",
                endpoint,
                Severity::High,
                Confidence::Low,
                "Password reset implementation shows no evidence of token expiration. \
                Non-expiring tokens remain valid indefinitely, giving attackers unlimited time \
                to intercept and use them. Tokens should expire within 15-60 minutes.",
                "No expiration indicators found in password reset flow".to_string(),
                "CWE-613",
                7.5,
            ));
        }

        vulnerabilities
    }

    /// Test for predictable reset token generation
    async fn test_predictable_reset_token(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing predictable reset token: {}", endpoint);

        // Request multiple reset tokens and analyze patterns
        // Note: In real testing, we'd need to actually generate tokens

        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body = &response.body;

        // Look for exposed token patterns in the page
        let weak_token_patterns = vec![
            r#"token=(\d{4,8})"#,     // Numeric only tokens
            r#"token=([0-9a-f]{8})"#, // Short hex tokens
            r#"reset_code=(\d{6})"#,  // 6-digit codes
            r#"code=(\d+)"#,          // Numeric codes
        ];

        for pattern in &weak_token_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(body) {
                    if let Some(token) = cap.get(1) {
                        let token_str = token.as_str();

                        // Check for weak patterns
                        let is_sequential =
                            token_str.chars().all(|c| c.is_numeric()) && token_str.len() < 10;

                        let is_short = token_str.len() < 16;

                        if is_sequential || is_short {
                            vulnerabilities.push(self.create_vulnerability(
                                "Predictable Password Reset Token",
                                endpoint,
                                Severity::Critical,
                                Confidence::Medium,
                                format!(
                                    "Password reset tokens appear to be predictable or weak. \
                                    Token '{}...' is {} characters and may be enumerable. \
                                    Tokens should be at least 128 bits of cryptographically \
                                    random data.",
                                    &token_str[..std::cmp::min(8, token_str.len())],
                                    token_str.len()
                                ),
                                format!("Weak token pattern detected: {} chars", token_str.len()),
                                "CWE-330",
                                9.1,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test for host header injection in password reset
    async fn test_host_header_injection(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing host header injection: {}", endpoint);

        // Test with manipulated Host header
        let evil_host = "evil.com";
        let headers = vec![
            ("Host".to_string(), evil_host.to_string()),
            ("X-Forwarded-Host".to_string(), evil_host.to_string()),
        ];

        // Try posting a password reset request with evil Host header
        let test_data = "email=test@test.com";

        if let Ok(response) = self
            .http_client
            .post_with_headers(endpoint, test_data, headers)
            .await
        {
            let body_lower = response.body.to_lowercase();

            // Check if our evil host appears in the response
            if response.body.contains(evil_host) {
                vulnerabilities.push(self.create_vulnerability(
                    "Host Header Injection in Password Reset",
                    endpoint,
                    Severity::Critical,
                    Confidence::High,
                    "The application is vulnerable to Host header injection in password reset emails. \
                    Attackers can inject a malicious Host header, causing password reset links to \
                    point to attacker-controlled domains. When victims click these links, their \
                    reset tokens are sent to the attacker.",
                    format!("Evil host '{}' reflected in response", evil_host),
                    "CWE-74",
                    9.8,
                ));
            }

            // Check for X-Forwarded-Host being trusted
            if body_lower.contains("reset link sent")
                || body_lower.contains("email sent")
                || response.status_code == 200
            {
                // Request may have been processed - check if headers were trusted
                let x_headers = vec![
                    ("X-Forwarded-Host".to_string(), evil_host.to_string()),
                    ("X-Host".to_string(), evil_host.to_string()),
                    (
                        "X-Original-URL".to_string(),
                        format!("http://{}/reset", evil_host),
                    ),
                ];

                if let Ok(x_response) = self
                    .http_client
                    .post_with_headers(endpoint, test_data, x_headers)
                    .await
                {
                    if x_response.body.contains(evil_host) {
                        vulnerabilities.push(self.create_vulnerability(
                            "X-Forwarded-Host Header Poisoning",
                            endpoint,
                            Severity::Critical,
                            Confidence::High,
                            "Application trusts X-Forwarded-Host header for password reset URL generation. \
                            Attackers can poison this header to redirect reset links to malicious domains.",
                            "X-Forwarded-Host header reflected in response".to_string(),
                            "CWE-644",
                            9.8,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // ==================== SESSION/COOKIE TESTS ====================

    /// Test if session is invalidated on password change
    async fn test_session_fixation_on_password_change(
        &self,
        url: &str,
        response: &crate::http_client::HttpResponse,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing session invalidation on password change");

        // Check for session cookie in response
        let has_session = response
            .headers
            .get("set-cookie")
            .map(|c| {
                let c_lower = c.to_lowercase();
                c_lower.contains("session") || c_lower.contains("token") || c_lower.contains("auth")
            })
            .unwrap_or(false);

        if !has_session {
            return vulnerabilities;
        }

        // Look for password change functionality
        let body_lower = response.body.to_lowercase();
        let has_password_change = body_lower.contains("change password")
            || body_lower.contains("update password")
            || body_lower.contains("new password");

        // Check for session invalidation indicators
        let has_session_invalidation = body_lower.contains("all sessions")
            || body_lower.contains("log out everywhere")
            || body_lower.contains("invalidate")
            || body_lower.contains("force logout");

        if has_password_change && !has_session_invalidation {
            vulnerabilities.push(
                self.create_vulnerability(
                    "Session Not Invalidated on Password Change",
                    url,
                    Severity::High,
                    Confidence::Low,
                    "When users change their password, existing sessions should be invalidated. \
                If sessions persist, an attacker who has stolen a session token can maintain \
                access even after the victim changes their password. This enables persistent \
                account takeover.",
                    "Password change functionality found without session invalidation indicators"
                        .to_string(),
                    "CWE-384",
                    7.5,
                ),
            );
        }

        vulnerabilities
    }

    /// Test cookie security attributes
    fn test_cookie_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing cookie security");

        if let Some(set_cookie) = response.headers.get("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();

            // Check for session/auth cookies
            let is_session = cookie_lower.contains("session")
                || cookie_lower.contains("auth")
                || cookie_lower.contains("token")
                || cookie_lower.contains("sid");

            if !is_session {
                return vulnerabilities;
            }

            // Check HttpOnly flag (XSS protection)
            if !cookie_lower.contains("httponly") {
                vulnerabilities.push(self.create_vulnerability(
                    "Session Cookie Missing HttpOnly - XSS Account Takeover Risk",
                    url,
                    Severity::High,
                    Confidence::High,
                    "Session cookie lacks HttpOnly flag. If the application has XSS vulnerabilities, \
                    attackers can steal session cookies via JavaScript (document.cookie) and take over \
                    user accounts. This is a complete account takeover chain: XSS -> Cookie theft -> ATO.",
                    format!("Cookie: {}", &set_cookie[..std::cmp::min(100, set_cookie.len())]),
                    "CWE-1004",
                    7.5,
                ));
            }

            // Check Secure flag (HTTPS only)
            if url.starts_with("https") && !cookie_lower.contains("secure") {
                vulnerabilities.push(self.create_vulnerability(
                    "Session Cookie Missing Secure Flag - Network Interception Risk",
                    url,
                    Severity::High,
                    Confidence::High,
                    "HTTPS site sets session cookie without Secure flag. Cookie will be sent over \
                    HTTP connections, allowing network attackers to intercept sessions on unencrypted \
                    networks (public WiFi, compromised routers). This enables account takeover via \
                    session hijacking.",
                    "Session cookie on HTTPS without Secure flag".to_string(),
                    "CWE-614",
                    7.4,
                ));
            }

            // Check SameSite attribute (CSRF protection)
            if !cookie_lower.contains("samesite") {
                vulnerabilities.push(self.create_vulnerability(
                    "Session Cookie Missing SameSite - CSRF Account Takeover Risk",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "Session cookie lacks SameSite attribute. This allows CSRF attacks where \
                    attackers can perform actions on behalf of logged-in users, potentially \
                    leading to account takeover via password/email change.",
                    "No SameSite attribute on session cookie".to_string(),
                    "CWE-352",
                    6.5,
                ));
            }

            // SameSite=None without Secure is vulnerable
            if cookie_lower.contains("samesite=none") && !cookie_lower.contains("secure") {
                vulnerabilities.push(self.create_vulnerability(
                    "Insecure SameSite=None Cookie Configuration",
                    url,
                    Severity::High,
                    Confidence::High,
                    "Cookie has SameSite=None without Secure flag. Modern browsers will reject \
                    this cookie, breaking functionality. This also indicates security misunderstanding \
                    that may extend to other areas.",
                    "SameSite=None requires Secure flag".to_string(),
                    "CWE-614",
                    6.8,
                ));
            }
        }

        vulnerabilities
    }

    /// Test concurrent session handling
    async fn test_concurrent_sessions(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing concurrent session handling");

        // This is a heuristic test - we look for session limit indicators
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body_lower = response.body.to_lowercase();

        // Look for session management features
        let has_session_management = body_lower.contains("active sessions")
            || body_lower.contains("logged in devices")
            || body_lower.contains("session limit")
            || body_lower.contains("concurrent")
            || body_lower.contains("sign out other");

        let has_auth = body_lower.contains("login")
            || body_lower.contains("account")
            || body_lower.contains("profile");

        if has_auth && !has_session_management {
            vulnerabilities.push(self.create_vulnerability(
                "Missing Concurrent Session Controls",
                url,
                Severity::Medium,
                Confidence::Low,
                "No concurrent session management detected. Users cannot view or terminate \
                other active sessions. If an attacker gains access to a session (via XSS, \
                cookie theft, or session fixation), the legitimate user has no way to detect \
                or terminate the unauthorized session.",
                "No session management UI detected".to_string(),
                "CWE-384",
                5.3,
            ));
        }

        vulnerabilities
    }

    // ==================== EMAIL-BASED ATO TESTS ====================

    /// Test if email change requires password confirmation
    async fn test_email_change_without_password(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing email change without password: {}", endpoint);

        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body_lower = response.body.to_lowercase();

        // Check if password confirmation is required
        let has_password_field = body_lower.contains("type=\"password\"")
            || body_lower.contains("type='password'")
            || body_lower.contains("current_password")
            || body_lower.contains("current password")
            || body_lower.contains("confirm password");

        let is_email_change_page = body_lower.contains("email")
            && (body_lower.contains("change") || body_lower.contains("update"));

        if is_email_change_page && !has_password_field {
            vulnerabilities.push(self.create_vulnerability(
                "Email Change Without Password Confirmation",
                endpoint,
                Severity::High,
                Confidence::Medium,
                "Email address can be changed without password confirmation. If an attacker \
                gains temporary access to a victim's session (via XSS, session fixation, or \
                borrowed device), they can change the email and then reset the password, \
                achieving permanent account takeover.",
                "Email change form found without password confirmation field".to_string(),
                "CWE-620",
                8.1,
            ));
        }

        // Also test with POST request
        let test_data = "email=attacker@evil.com";
        if let Ok(post_response) = self.http_client.post_form(endpoint, test_data).await {
            let post_body_lower = post_response.body.to_lowercase();

            // Check if request was accepted without password
            let accepted = post_response.status_code == 200
                && (post_body_lower.contains("success")
                    || post_body_lower.contains("email updated")
                    || post_body_lower.contains("confirmation sent"));

            let needs_password = post_body_lower.contains("password required")
                || post_body_lower.contains("enter your password")
                || post_body_lower.contains("incorrect password");

            if accepted && !needs_password {
                vulnerabilities.push(self.create_vulnerability(
                    "Email Change Accepted Without Password",
                    endpoint,
                    Severity::Critical,
                    Confidence::High,
                    "Email address change was accepted without password verification. \
                    This is a critical account takeover vulnerability - any session compromise \
                    leads to permanent account takeover.",
                    "POST request to change email succeeded without password".to_string(),
                    "CWE-620",
                    9.1,
                ));
            }
        }

        vulnerabilities
    }

    /// Test for email enumeration via timing
    async fn test_email_enumeration_timing(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing email enumeration via timing");

        // Parse URL to find login/register endpoints
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };
        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        let endpoints = vec![
            format!("{}/login", base),
            format!("{}/forgot-password", base),
            format!("{}/register", base),
            format!("{}/api/auth/login", base),
        ];

        for endpoint in &endpoints {
            // Test with existing vs non-existing email timing
            let existing_email = "admin@test.com";
            let nonexistent_email = "nonexistent_xyz_12345@test.com";

            let mut existing_times = Vec::new();
            let mut nonexistent_times = Vec::new();

            for _ in 0..3 {
                // Test existing email
                let start = Instant::now();
                let _ = self
                    .http_client
                    .post_form(endpoint, &format!("email={}", existing_email))
                    .await;
                existing_times.push(start.elapsed().as_millis());

                sleep(Duration::from_millis(50)).await;

                // Test nonexistent email
                let start = Instant::now();
                let _ = self
                    .http_client
                    .post_form(endpoint, &format!("email={}", nonexistent_email))
                    .await;
                nonexistent_times.push(start.elapsed().as_millis());

                sleep(Duration::from_millis(50)).await;
            }

            // Calculate average times
            if existing_times.is_empty() || nonexistent_times.is_empty() {
                continue;
            }

            let avg_existing: u128 =
                existing_times.iter().sum::<u128>() / existing_times.len() as u128;
            let avg_nonexistent: u128 =
                nonexistent_times.iter().sum::<u128>() / nonexistent_times.len() as u128;

            // Significant timing difference suggests enumeration
            let diff = if avg_existing > avg_nonexistent {
                avg_existing - avg_nonexistent
            } else {
                avg_nonexistent - avg_existing
            };

            // More than 100ms difference is suspicious
            if diff > 100 {
                vulnerabilities.push(self.create_vulnerability(
                    "Email Enumeration via Timing Attack",
                    endpoint,
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Response time varies based on email existence. Existing emails take ~{}ms, \
                        non-existing emails take ~{}ms ({}ms difference). Attackers can enumerate \
                        valid user accounts by measuring response times.",
                        avg_existing, avg_nonexistent, diff
                    ),
                    format!(
                        "Timing difference: {}ms (existing) vs {}ms (nonexistent)",
                        avg_existing, avg_nonexistent
                    ),
                    "CWE-208",
                    5.3,
                ));
                break; // Found on one endpoint, no need to test more
            }
        }

        vulnerabilities
    }

    /// Test for case sensitivity issues in email handling
    async fn test_email_case_sensitivity(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing email case sensitivity");

        // Parse URL
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };
        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Test registration/login with case variations
        let register_endpoint = format!("{}/register", base);

        let test_emails = vec![
            "TEST@example.com",
            "test@example.com",
            "Test@example.com",
            "TEST@EXAMPLE.COM",
        ];

        let mut responses = HashMap::new();

        for email in &test_emails {
            let data = format!("email={}&password=TestPass123!", email);
            if let Ok(response) = self.http_client.post_form(&register_endpoint, &data).await {
                responses.insert(email.to_string(), response);
            }
        }

        // Check if different cases are treated as different accounts
        let mut unique_responses = HashSet::new();
        for (email, response) in &responses {
            let key = format!("{}:{}", response.status_code, response.body.len());
            if unique_responses.contains(&key) {
                continue;
            }

            // Check if registration succeeded for multiple case variants
            let body_lower = response.body.to_lowercase();
            let success = response.status_code == 200
                && (body_lower.contains("success")
                    || body_lower.contains("created")
                    || body_lower.contains("welcome"));

            if success {
                unique_responses.insert(key);
            }
        }

        // If multiple case variants succeeded, there's a case sensitivity issue
        if unique_responses.len() > 1 {
            vulnerabilities.push(self.create_vulnerability(
                "Email Case Sensitivity Account Takeover",
                &register_endpoint,
                Severity::High,
                Confidence::Medium,
                "Application treats email addresses with different cases as different accounts. \
                Attacker can register VICTIM@example.com and victim@example.com as separate accounts. \
                Password reset or OAuth flows may route to the wrong account, enabling account takeover.",
                "Multiple case variants of same email accepted as different accounts".to_string(),
                "CWE-178",
                8.1,
            ));
        }

        vulnerabilities
    }

    // ==================== OAUTH TESTS ====================

    /// Test OAuth account linking without email verification
    async fn test_oauth_account_linking(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing OAuth account linking: {}", endpoint);

        // Test OAuth callback without proper validation
        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body_lower = response.body.to_lowercase();

        // Check for account linking functionality
        let has_linking = body_lower.contains("link account")
            || body_lower.contains("connect account")
            || body_lower.contains("associate account");

        // Check for email verification requirement
        let requires_verification = body_lower.contains("verify email")
            || body_lower.contains("email verification")
            || body_lower.contains("confirm email");

        if has_linking && !requires_verification {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth Account Linking Without Email Verification",
                endpoint,
                Severity::Critical,
                Confidence::Medium,
                "OAuth accounts can be linked without verifying email ownership. An attacker can \
                create an OAuth account with the victim's email (unverified) and link it to an \
                existing account. If the OAuth provider doesn't verify emails, attacker gains \
                access to victim's account.",
                "Account linking found without email verification requirement".to_string(),
                "CWE-287",
                9.1,
            ));
        }

        // Test for OAuth provider email verification trust
        let test_callback = format!("{}?email=victim@example.com&provider=attacker", endpoint);
        if let Ok(callback_response) = self.http_client.get(&test_callback).await {
            let callback_body_lower = callback_response.body.to_lowercase();

            // Check if unverified email from provider is trusted
            if callback_response.status_code == 200
                && !callback_body_lower.contains("verify")
                && !callback_body_lower.contains("not verified")
            {
                vulnerabilities.push(self.create_vulnerability(
                    "OAuth Unverified Email Account Takeover",
                    endpoint,
                    Severity::Critical,
                    Confidence::Low,
                    "Application may trust unverified emails from OAuth providers. If OAuth provider \
                    allows unverified emails, attackers can claim victim's email and gain access \
                    to their account during OAuth login/registration.",
                    "Callback endpoint accepts email parameter".to_string(),
                    "CWE-287",
                    9.8,
                ));
            }
        }

        vulnerabilities
    }

    /// Test OAuth state parameter validation
    async fn test_oauth_state_validation(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing OAuth state validation: {}", endpoint);

        // Test callback without state parameter
        let test_url = format!("{}?code=test_code", endpoint);

        if let Ok(response) = self.http_client.get(&test_url).await {
            let body_lower = response.body.to_lowercase();

            // Check if request was processed without state
            let processed = response.status_code == 200 || response.status_code == 302;
            let has_state_error = body_lower.contains("state")
                && (body_lower.contains("invalid")
                    || body_lower.contains("missing")
                    || body_lower.contains("mismatch"));

            if processed && !has_state_error {
                vulnerabilities.push(self.create_vulnerability(
                    "Missing OAuth State Parameter Validation",
                    endpoint,
                    Severity::High,
                    Confidence::Medium,
                    "OAuth callback accepts requests without state parameter validation. \
                    This enables CSRF attacks where attacker can force victim to authenticate \
                    with attacker's OAuth account, then link it to victim's existing account \
                    (OAuth login CSRF account takeover).",
                    "OAuth callback processed without state parameter".to_string(),
                    "CWE-352",
                    7.5,
                ));
            }
        }

        // Test with invalid state
        let test_url_invalid = format!("{}?code=test_code&state=invalid_state", endpoint);

        if let Ok(response) = self.http_client.get(&test_url_invalid).await {
            let body_lower = response.body.to_lowercase();

            let processed = response.status_code == 200 || response.status_code == 302;
            let has_state_error = body_lower.contains("state")
                && (body_lower.contains("invalid")
                    || body_lower.contains("mismatch")
                    || body_lower.contains("error"));

            if processed && !has_state_error {
                vulnerabilities.push(self.create_vulnerability(
                    "Weak OAuth State Validation",
                    endpoint,
                    Severity::High,
                    Confidence::Medium,
                    "OAuth callback accepts invalid state parameter. State validation is \
                    insufficient or missing, enabling CSRF attacks on OAuth login flow.",
                    "Invalid state parameter accepted".to_string(),
                    "CWE-352",
                    7.5,
                ));
            }
        }

        vulnerabilities
    }

    // ==================== PHONE-BASED ATO TESTS ====================

    /// Test phone number change without verification
    async fn test_phone_change_without_verification(&self, endpoint: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!(
            "[ATO] Testing phone change without verification: {}",
            endpoint
        );

        let response = match self.http_client.get(endpoint).await {
            Ok(r) => r,
            Err(_) => return vulnerabilities,
        };

        let body_lower = response.body.to_lowercase();

        // Check for verification requirements
        let has_sms_verification = body_lower.contains("verification code")
            || body_lower.contains("sms code")
            || body_lower.contains("verify phone")
            || body_lower.contains("confirm phone");

        let has_password_required =
            body_lower.contains("type=\"password\"") || body_lower.contains("current password");

        let is_phone_change = body_lower.contains("phone")
            && (body_lower.contains("change") || body_lower.contains("update"));

        if is_phone_change && !has_sms_verification && !has_password_required {
            vulnerabilities.push(self.create_vulnerability(
                "Phone Number Change Without Verification",
                endpoint,
                Severity::High,
                Confidence::Medium,
                "Phone number can be changed without SMS verification or password. If the application \
                uses SMS for MFA or password reset, an attacker with session access can change the \
                phone to their own number and gain persistent access via SIM-based account recovery.",
                "Phone change form found without verification requirements".to_string(),
                "CWE-287",
                8.1,
            ));
        }

        // Test POST request
        let test_data = "phone=+1234567890";
        if let Ok(post_response) = self.http_client.post_form(endpoint, test_data).await {
            let post_body_lower = post_response.body.to_lowercase();

            let accepted = post_response.status_code == 200
                && (post_body_lower.contains("success")
                    || post_body_lower.contains("updated")
                    || post_body_lower.contains("changed"));

            let needs_verification = post_body_lower.contains("verification")
                || post_body_lower.contains("code sent")
                || post_body_lower.contains("confirm");

            if accepted && !needs_verification {
                vulnerabilities.push(self.create_vulnerability(
                    "Phone Change Accepted Without Verification",
                    endpoint,
                    Severity::Critical,
                    Confidence::High,
                    "Phone number change was accepted without any verification. Combined with \
                    SIM swapping vulnerabilities, this enables complete account takeover.",
                    "POST request to change phone succeeded without verification".to_string(),
                    "CWE-287",
                    9.1,
                ));
            }
        }

        vulnerabilities
    }

    /// Test SMS code enumeration
    async fn test_sms_code_enumeration(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing SMS code enumeration");

        // Parse URL
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vulnerabilities,
        };
        let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));

        // Common SMS verification endpoints
        let sms_endpoints = vec![
            format!("{}/verify-sms", base),
            format!("{}/api/auth/sms/verify", base),
            format!("{}/2fa/sms", base),
            format!("{}/mfa/sms/verify", base),
        ];

        for endpoint in &sms_endpoints {
            // Test multiple SMS codes rapidly
            let mut successful_attempts = 0;

            for i in 0..10 {
                let code = format!("{:06}", i);
                let data = format!("code={}", code);

                if let Ok(response) = self.http_client.post_form(&endpoint, &data).await {
                    // Count non-rate-limited responses
                    if response.status_code != 429 {
                        successful_attempts += 1;
                    }

                    // Check for rate limiting
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("rate limit")
                        || body_lower.contains("too many")
                        || response.status_code == 429
                    {
                        break;
                    }
                }

                sleep(Duration::from_millis(50)).await;
            }

            if successful_attempts >= 8 {
                vulnerabilities.push(self.create_vulnerability(
                    "SMS Code Enumeration - Missing Rate Limiting",
                    endpoint,
                    Severity::High,
                    Confidence::High,
                    format!(
                        "SMS verification endpoint lacks rate limiting. {} of 10 attempts succeeded \
                        without rate limiting. 6-digit SMS codes (1,000,000 combinations) can be \
                        brute-forced to bypass SMS-based MFA and gain account access.",
                        successful_attempts
                    ),
                    format!("{} attempts processed without rate limiting", successful_attempts),
                    "CWE-307",
                    8.1,
                ));
                break;
            }
        }

        vulnerabilities
    }

    // ==================== COMBINED ATTACK CHAIN TESTS ====================

    /// Test combined account recovery attack chain
    async fn test_account_recovery_chain(
        &self,
        url: &str,
        endpoints: &AuthEndpoints,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("[ATO] Testing account recovery chain vulnerabilities");

        // Check for dangerous combinations of vulnerabilities
        // that create complete ATO chains

        // Chain 1: Password reset + Email change without verification
        if !endpoints.password_reset.is_empty() && !endpoints.email_change.is_empty() {
            // Check if both lack proper security
            let mut reset_secure = false;
            let mut email_change_secure = false;

            for endpoint in &endpoints.password_reset {
                if let Ok(r) = self.http_client.get(endpoint).await {
                    let body_lower = r.body.to_lowercase();
                    if body_lower.contains("verify")
                        || body_lower.contains("confirm")
                        || body_lower.contains("security question")
                    {
                        reset_secure = true;
                    }
                }
            }

            for endpoint in &endpoints.email_change {
                if let Ok(r) = self.http_client.get(endpoint).await {
                    let body_lower = r.body.to_lowercase();
                    if body_lower.contains("password")
                        || body_lower.contains("verify")
                        || body_lower.contains("confirm")
                    {
                        email_change_secure = true;
                    }
                }
            }

            if !reset_secure || !email_change_secure {
                vulnerabilities.push(self.create_vulnerability(
                    "Account Recovery Chain Vulnerability",
                    url,
                    Severity::Critical,
                    Confidence::Medium,
                    "Dangerous account recovery chain detected. If either password reset or email \
                    change lacks proper verification, attackers can: 1) Change email without password, \
                    2) Request password reset to new email, 3) Complete full account takeover. \
                    Both operations must require strong re-authentication.",
                    "Password reset and email change endpoints found with weak security".to_string(),
                    "CWE-287",
                    9.1,
                ));
            }
        }

        // Chain 2: OAuth + Missing state = ATO
        if !endpoints.oauth_callback.is_empty() {
            for oauth in &endpoints.oauth_callback {
                let test_url = format!("{}?code=test", oauth);
                if let Ok(r) = self.http_client.get(&test_url).await {
                    let body_lower = r.body.to_lowercase();
                    if r.status_code == 200 && !body_lower.contains("state") {
                        vulnerabilities.push(self.create_vulnerability(
                            "OAuth CSRF to Account Takeover Chain",
                            oauth,
                            Severity::Critical,
                            Confidence::Medium,
                            "OAuth callback without state validation enables complete ATO chain: \
                            1) Attacker initiates OAuth with their account, 2) Captures OAuth callback URL, \
                            3) Tricks victim into visiting callback, 4) Victim's account linked to attacker's OAuth, \
                            5) Attacker logs in via OAuth = full account takeover.",
                            "OAuth callback accepts requests without state validation".to_string(),
                            "CWE-352",
                            9.8,
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    // ==================== HELPER METHODS ====================

    /// Create a vulnerability record with detailed remediation
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: impl Into<String>,
        evidence: String,
        cwe: &str,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: generate_uuid(),
            vuln_type: format!("Account Takeover - {}", title),
            severity,
            confidence,
            category: "Account Takeover".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.into(),
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(title),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, title: &str) -> String {
        match title {
            t if t.contains("Password Reset Token") => r#"IMMEDIATE ACTION REQUIRED:

1. **Use POST-Only Token Transmission**
   ```python
   # Django example
   def password_reset_confirm(request):
       if request.method != 'POST':
           return HttpResponseNotAllowed(['POST'])

       token = request.POST.get('token')  # Never in URL
       # Validate token...
   ```

2. **Implement Token Expiration**
   ```javascript
   // Generate token with 15-minute expiry
   const token = crypto.randomBytes(32).toString('hex');
   await redis.setex(`reset:${token}`, 900, userId);

   // On use, delete immediately
   const userId = await redis.get(`reset:${token}`);
   await redis.del(`reset:${token}`);
   ```

3. **Add Referrer-Policy Header**
   ```
   Referrer-Policy: no-referrer
   ```

4. **Avoid External Resources on Reset Pages**
   - Self-host all CSS/JS
   - Don't include third-party tracking
   - No external images

5. **Generate Cryptographically Strong Tokens**
   ```python
   import secrets
   token = secrets.token_urlsafe(32)  # 256 bits
   ```

References:
- OWASP Forgot Password Cheat Sheet
- CWE-598: Use of GET Request Method With Sensitive Query Strings
"#
            .to_string(),

            t if t.contains("Session") || t.contains("Cookie") => r#"IMMEDIATE ACTION REQUIRED:

1. **Set All Cookie Security Flags**
   ```javascript
   // Express.js
   res.cookie('session', token, {
       httpOnly: true,      // Prevents XSS cookie theft
       secure: true,        // HTTPS only
       sameSite: 'strict',  // CSRF protection
       maxAge: 3600000,     // 1 hour
       path: '/'
   });
   ```

2. **Invalidate Sessions on Password Change**
   ```python
   def change_password(user, new_password):
       user.set_password(new_password)
       # Invalidate ALL sessions for this user
       Session.objects.filter(user=user).delete()
       # Create new session for current request
       login(request, user)
   ```

3. **Implement Session Management UI**
   ```html
   <h3>Active Sessions</h3>
   <ul>
     {% for session in user.sessions.all %}
       <li>
         {{ session.device }} - {{ session.last_active }}
         <form method="POST" action="/logout-session/{{ session.id }}">
           <button>Terminate</button>
         </form>
       </li>
     {% endfor %}
   </ul>
   ```

4. **Limit Concurrent Sessions**
   ```python
   MAX_SESSIONS = 3
   if user.sessions.count() >= MAX_SESSIONS:
       user.sessions.oldest().delete()
   ```

References:
- OWASP Session Management Cheat Sheet
- CWE-384: Session Fixation
"#
            .to_string(),

            t if t.contains("Email") => r#"IMMEDIATE ACTION REQUIRED:

1. **Require Password for Email Changes**
   ```python
   def change_email(request):
       password = request.POST.get('current_password')
       if not user.check_password(password):
           return error('Password required')

       new_email = request.POST.get('new_email')
       # Send verification to NEW email
       send_email_verification(new_email, user)
   ```

2. **Implement Email Verification Flow**
   ```javascript
   async function changeEmail(userId, newEmail) {
       // Don't update email immediately
       const token = generateToken();
       await db.pendingEmailChanges.create({
           userId,
           newEmail,
           token,
           expiresAt: Date.now() + 3600000
       });

       await sendEmail(newEmail, {
           subject: 'Confirm Email Change',
           link: `/confirm-email?token=${token}`
       });
   }
   ```

3. **Normalize Email Addresses**
   ```python
   def normalize_email(email):
       email = email.strip().lower()
       local, domain = email.rsplit('@', 1)
       # Handle Gmail dots and plus addressing
       if domain in ['gmail.com', 'googlemail.com']:
           local = local.split('+')[0].replace('.', '')
       return f"{local}@{domain}"
   ```

4. **Use Constant-Time Comparisons**
   ```python
   import hmac
   def user_exists(email):
       # Same execution time regardless of result
       user = User.query.filter_by(email=email).first()
       hmac.compare_digest(str(bool(user)), 'True')
       return user is not None
   ```

References:
- OWASP Authentication Cheat Sheet
- CWE-620: Unverified Password Change
"#
            .to_string(),

            t if t.contains("OAuth") => r#"IMMEDIATE ACTION REQUIRED:

1. **Implement State Parameter**
   ```javascript
   // Generate state before redirect
   const state = crypto.randomBytes(32).toString('hex');
   req.session.oauth_state = state;

   const authUrl = `${OAUTH_URL}?client_id=${CLIENT_ID}` +
                   `&state=${state}&redirect_uri=${REDIRECT}`;

   // Validate on callback
   if (req.query.state !== req.session.oauth_state) {
       throw new Error('State mismatch - possible CSRF');
   }
   delete req.session.oauth_state;
   ```

2. **Verify Email from OAuth Provider**
   ```python
   def oauth_callback(request):
       profile = oauth_provider.get_profile(access_token)

       # CRITICAL: Check if email is verified
       if not profile.get('email_verified', False):
           return error('Email not verified by provider')

       # Check if email matches existing user
       user = User.query.filter_by(email=profile['email']).first()
       if user and not user.oauth_linked:
           # Require password to link accounts
           return redirect('/link-account')
   ```

3. **Prevent Account Takeover via OAuth**
   ```javascript
   async function linkOAuthAccount(userId, oauthProfile) {
       // Require password before linking
       const password = await promptPassword();
       if (!await user.verifyPassword(password)) {
           throw new Error('Password required to link account');
       }

       // Check email ownership
       if (oauthProfile.email !== user.email) {
           throw new Error('Email mismatch');
       }

       user.oauthId = oauthProfile.id;
       await user.save();
   }
   ```

4. **Use PKCE for Public Clients**
   ```javascript
   const codeVerifier = crypto.randomBytes(32).toString('base64url');
   const codeChallenge = crypto
       .createHash('sha256')
       .update(codeVerifier)
       .digest('base64url');

   // Include in auth request
   const authUrl = `${OAUTH_URL}?code_challenge=${codeChallenge}` +
                   `&code_challenge_method=S256`;
   ```

References:
- OAuth 2.0 Security Best Current Practice
- CWE-287: Improper Authentication
"#
            .to_string(),

            t if t.contains("Phone") || t.contains("SMS") => r#"IMMEDIATE ACTION REQUIRED:

1. **Require Password for Phone Changes**
   ```python
   def change_phone(request):
       # Require password
       if not user.check_password(request.POST['password']):
           return error('Password required')

       new_phone = request.POST['phone']
       # Send verification SMS
       code = generate_code()
       send_sms(new_phone, f'Verification code: {code}')

       # Store pending change
       cache.set(f'phone_change:{user.id}', {
           'phone': new_phone,
           'code': code
       }, timeout=300)
   ```

2. **Implement SMS Rate Limiting**
   ```python
   from ratelimit import limits

   @limits(calls=3, period=60)  # 3 attempts per minute
   @limits(calls=10, period=3600)  # 10 per hour
   def verify_sms_code(request):
       # ... verification logic
   ```

3. **Use Longer Verification Codes**
   ```javascript
   // Use 8-digit codes instead of 6-digit
   const code = crypto.randomInt(10000000, 99999999).toString();

   // Or use alphanumeric
   const code = crypto.randomBytes(6).toString('base64').slice(0, 8);
   ```

4. **Implement Lockout After Failed Attempts**
   ```python
   MAX_ATTEMPTS = 5
   LOCKOUT_TIME = 1800  # 30 minutes

   def verify_code(user, code):
       attempts = cache.get(f'sms_attempts:{user.id}', 0)
       if attempts >= MAX_ATTEMPTS:
           lockout_until = cache.get(f'sms_lockout:{user.id}')
           if lockout_until and time.time() < lockout_until:
               raise RateLimitError('Account locked')

       if code != expected_code:
           cache.incr(f'sms_attempts:{user.id}')
           if attempts + 1 >= MAX_ATTEMPTS:
               cache.set(f'sms_lockout:{user.id}',
                        time.time() + LOCKOUT_TIME)
           raise InvalidCodeError()

       cache.delete(f'sms_attempts:{user.id}')
   ```

References:
- NIST SP 800-63B (SMS discouraged for authentication)
- CWE-307: Improper Restriction of Excessive Authentication Attempts
"#
            .to_string(),

            t if t.contains("Host Header") => r#"IMMEDIATE ACTION REQUIRED:

1. **Whitelist Allowed Hosts**
   ```python
   # Django
   ALLOWED_HOSTS = ['www.example.com', 'example.com']

   # Flask
   from werkzeug.middleware.proxy_fix import ProxyFix
   app.wsgi_app = ProxyFix(app.wsgi_app, x_host=0)
   ```

2. **Never Trust Host Header for URLs**
   ```python
   # WRONG
   reset_link = f"http://{request.headers['Host']}/reset?token={token}"

   # CORRECT
   from django.conf import settings
   reset_link = f"{settings.SITE_URL}/reset?token={token}"
   ```

3. **Configure Web Server**
   ```nginx
   # Nginx - reject requests with invalid Host
   server {
       listen 80 default_server;
       server_name _;
       return 444;
   }

   server {
       listen 80;
       server_name www.example.com example.com;
       # ... your config
   }
   ```

4. **Validate X-Forwarded-Host**
   ```javascript
   // Express.js
   app.set('trust proxy', false);  // Don't trust X-Forwarded-*

   // Or validate specific values
   const allowedHosts = ['www.example.com'];
   app.use((req, res, next) => {
       const host = req.get('host');
       if (!allowedHosts.includes(host)) {
           return res.status(400).send('Invalid host');
       }
       next();
   });
   ```

References:
- OWASP HTTP Host Header Attacks
- CWE-74: Improper Neutralization of Special Elements
"#
            .to_string(),

            _ => r#"IMMEDIATE ACTION REQUIRED:

1. **Implement Defense in Depth**
   - Require strong authentication for sensitive operations
   - Use multi-factor authentication
   - Implement proper session management
   - Log and monitor for suspicious activity

2. **Follow Secure Development Practices**
   - Input validation on all parameters
   - Output encoding to prevent injection
   - Use parameterized queries
   - Implement proper access controls

3. **Security Testing**
   - Regular penetration testing
   - Automated security scanning
   - Code review for security issues
   - Bug bounty program

References:
- OWASP Top 10
- CWE/SANS Top 25
- NIST Cybersecurity Framework
"#
            .to_string(),
        }
    }
}

/// Generate UUID for vulnerability IDs
fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "ato_{:08x}{:04x}{:04x}{:04x}{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::{HttpClient, HttpResponse};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_cookie_security_missing_httponly() {
        let scanner = AccountTakeoverScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "session=abc123; Secure; SameSite=Strict".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let vulns = scanner.test_cookie_security(&response, "https://example.com");
        assert!(vulns.iter().any(|v| v.vuln_type.contains("HttpOnly")));
    }

    #[tokio::test]
    async fn test_cookie_security_missing_secure() {
        let scanner = AccountTakeoverScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "session=abc123; HttpOnly; SameSite=Strict".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let vulns = scanner.test_cookie_security(&response, "https://example.com");
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Secure")));
    }

    #[tokio::test]
    async fn test_cookie_security_complete() {
        let scanner = AccountTakeoverScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "session=abc123; HttpOnly; Secure; SameSite=Strict".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let vulns = scanner.test_cookie_security(&response, "https://example.com");
        assert!(
            vulns.is_empty(),
            "Secure cookie should not trigger vulnerabilities"
        );
    }

    #[test]
    fn test_auth_endpoints_detection() {
        let endpoints = AuthEndpoints::new();
        assert!(!endpoints.has_any());
    }

    #[test]
    fn test_uuid_generation() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();
        assert!(uuid1.starts_with("ato_"));
        assert!(uuid2.starts_with("ato_"));
        assert_ne!(uuid1, uuid2);
    }
}
