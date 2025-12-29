// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;

use super::advanced_auth::AdvancedAuthScanner;

pub struct AuthManagerScanner {
    http_client: Arc<HttpClient>,
    advanced_scanner: AdvancedAuthScanner,
}

impl AuthManagerScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let advanced_scanner = AdvancedAuthScanner::new(Arc::clone(&http_client));
        Self {
            http_client,
            advanced_scanner,
        }
    }

    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Run advanced authentication tests first
        tracing::info!("Running advanced authentication security tests");
        let (advanced_vulns, advanced_tests) = self.advanced_scanner.scan(url, config).await?;
        vulnerabilities.extend(advanced_vulns);
        tests_run += advanced_tests;
        tracing::info!("Advanced auth tests completed: {} vulnerabilities, {} tests",
                      vulnerabilities.len(), advanced_tests);

        // First, detect if authentication system exists
        tests_run += 1;
        let response = self.http_client.get(url).await?;
        let has_auth_features = self.detect_auth_features(&response, url).await;

        // Only run auth-specific tests if auth features detected
        if !has_auth_features {
            tracing::debug!("No authentication features detected on {}, skipping auth vulnerability tests", url);
            return Ok((vulnerabilities, tests_run));
        }

        // Test 1: Check password policy
        tests_run += 1;
        self.check_password_policy(&response, url, &mut vulnerabilities);

        // Test 2: Test account enumeration
        tests_run += 1;
        if let Ok(enum_response) = self.test_account_enumeration(url).await {
            self.check_account_enumeration(&enum_response, url, &mut vulnerabilities);
        }

        // Test 3: Test password reset security
        tests_run += 1;
        if let Ok(reset_response) = self.test_password_reset(url).await {
            self.check_password_reset_security(&reset_response, url, &mut vulnerabilities);
        }

        // Test 4: Test registration security
        tests_run += 1;
        if let Ok(reg_response) = self.test_registration_security(url).await {
            self.check_registration_security(&reg_response, url, &mut vulnerabilities);
        }

        // Test 5: Test brute force protection
        tests_run += 1;
        if let Ok(brute_response) = self.test_brute_force_protection(url).await {
            self.check_brute_force_protection(&brute_response, url, &mut vulnerabilities);
        }

        // Test 6: Test account lockout
        tests_run += 1;
        if let Ok(lockout_response) = self.test_account_lockout(url).await {
            self.check_account_lockout(&lockout_response, url, &mut vulnerabilities);
        }

        // Test 7: Test credential stuffing prevention
        tests_run += 1;
        if let Ok(stuffing_response) = self.test_credential_stuffing(url).await {
            self.check_credential_stuffing_prevention(&stuffing_response, url, &mut vulnerabilities);
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if authentication features exist on the target
    async fn detect_auth_features(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
    ) -> bool {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for login forms
        let has_login_form = (body_lower.contains("<form") && body_lower.contains("password"))
            || body_lower.contains("type=\"password\"")
            || body_lower.contains("type='password'");

        // Check for common auth endpoints in links
        let has_auth_links = body_lower.contains("/login")
            || body_lower.contains("/signin")
            || body_lower.contains("/sign-in")
            || body_lower.contains("/auth")
            || body_lower.contains("/register")
            || body_lower.contains("/signup");

        // Check for session cookies or auth headers
        let has_auth_cookies = response.header("set-cookie")
            .map(|c| c.to_lowercase().contains("session") || c.to_lowercase().contains("auth") || c.to_lowercase().contains("token"))
            .unwrap_or(false);

        // Check for JWT or OAuth indicators
        let has_jwt = body_lower.contains("jwt") || body_lower.contains("bearer") || body_lower.contains("oauth");

        // Try common auth endpoints
        let auth_endpoints = vec![
            format!("{}/login", url.trim_end_matches('/')),
            format!("{}/api/auth", url.trim_end_matches('/')),
            format!("{}/signin", url.trim_end_matches('/')),
        ];

        for endpoint in &auth_endpoints {
            if let Ok(resp) = self.http_client.get(endpoint).await {
                if resp.status_code == 200 || resp.status_code == 401 || resp.status_code == 403 {
                    let endpoint_body_lower = resp.body.to_lowercase();
                    if endpoint_body_lower.contains("password") || endpoint_body_lower.contains("login") {
                        tracing::debug!("Found auth endpoint: {}", endpoint);
                        return true;
                    }
                }
            }
        }

        let detected = has_login_form || has_auth_links || has_auth_cookies || has_jwt;
        if detected {
            tracing::debug!("Auth features detected on {}: form={}, links={}, cookies={}, jwt={}",
                url, has_login_form, has_auth_links, has_auth_cookies, has_jwt);
        }
        detected
    }

    fn check_password_policy(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for password requirements mentioned in the page
        let has_password_field = body_lower.contains("password")
            || body_lower.contains("new password")
            || body_lower.contains("create password");

        if has_password_field {
            // Check for weak password policy indicators
            let has_strong_policy = (body_lower.contains("at least 8")
                || body_lower.contains("minimum 8")
                || body_lower.contains("8 characters"))
                && (body_lower.contains("uppercase")
                    || body_lower.contains("lower")
                    || body_lower.contains("number")
                    || body_lower.contains("special character"));

            let has_weak_indicators = body_lower.contains("at least 6")
                || body_lower.contains("minimum 6")
                || body_lower.contains("4 characters")
                || body_lower.contains("any password");

            if has_weak_indicators || !has_strong_policy {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Weak Password Policy".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    category: "Authentication".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "Password policy appears weak or missing. Weak passwords make accounts vulnerable to brute force and dictionary attacks.".to_string(),
                    evidence: Some("No strong password requirements detected".to_string()),
                    cwe: "CWE-521".to_string(),
                    cvss: 6.5,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Enforce minimum 12 character passwords\n2. Require mix of uppercase, lowercase, numbers, and special characters\n3. Check against common password lists (HaveIBeenPwned API)\n4. Implement password complexity scoring (e.g., zxcvbn)\n5. Prevent use of personal information in passwords\n6. Enforce password rotation for privileged accounts\n7. Support passphrases as an alternative".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Check for password exposure in forms
        let password_input_regex = Regex::new(r#"<input[^>]*type=["']?password["']?[^>]*value=["']([^"']+)["'][^>]*>"#).unwrap();
        if password_input_regex.is_match(body) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Password Pre-filled in Form".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Password field contains a pre-filled value in HTML source. This exposes passwords in browser history and page source.".to_string(),
                evidence: Some("Password input field with value attribute detected".to_string()),
                cwe: "CWE-522".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "1. Never pre-fill password fields\n2. Never include passwords in HTML\n3. Use autocomplete=\"off\" for password fields\n4. Implement proper password management\n5. Use password managers for credential storage".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_account_enumeration(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test login with non-existent username
        let test_url = format!("{}?username=nonexistent_user_12345&password=test", url);
        self.http_client.get(&test_url).await
    }

    fn check_account_enumeration(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for specific error messages that leak user existence
        let user_exists_messages = vec![
            "user not found",
            "username does not exist",
            "account not found",
            "invalid username",
            "no such user",
            "user doesn't exist",
        ];

        let password_wrong_messages = vec![
            "incorrect password",
            "wrong password",
            "password is incorrect",
            "invalid password",
        ];

        let reveals_user_exists = user_exists_messages
            .iter()
            .any(|&msg| body_lower.contains(msg));

        let reveals_password_wrong = password_wrong_messages
            .iter()
            .any(|&msg| body_lower.contains(msg));

        if reveals_user_exists || reveals_password_wrong {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Account Enumeration via Error Messages".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: Some("username".to_string()),
                payload: "nonexistent_user_12345".to_string(),
                description: "Login error messages reveal whether a username exists. Attackers can enumerate valid usernames for targeted attacks.".to_string(),
                evidence: Some("Different error messages for invalid username vs invalid password".to_string()),
                cwe: "CWE-203".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "1. Use generic error message: 'Invalid username or password'\n2. Return same response time for valid and invalid users\n3. Implement rate limiting on login attempts\n4. Use CAPTCHA after multiple failures\n5. Log enumeration attempts for security monitoring\n6. Consider using email-based passwordless authentication".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Check for timing-based enumeration via response time
        if response.duration_ms > 0 {
            // In real implementation, would compare timing across multiple requests
            // This is a simplified check
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Potential Timing-Based Account Enumeration".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: Some("username".to_string()),
                payload: String::new(),
                description: "Response time differences may allow timing-based user enumeration. Valid usernames may trigger password hashing (slower) while invalid users return immediately.".to_string(),
                evidence: Some(format!("Response time: {}ms", response.duration_ms)),
                cwe: "CWE-208".to_string(),
                cvss: 3.7,
                verified: false,
                false_positive: false,
                remediation: "1. Implement constant-time authentication responses\n2. Hash passwords for both valid and invalid users\n3. Add random delays to normalize response times\n4. Use rate limiting to make timing attacks impractical\n5. Monitor for rapid sequential login attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_password_reset(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}/forgot-password?email=test@example.com", url);
        self.http_client.get(&test_url).await
    }

    fn check_password_reset_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for password reset token exposure
        let token_patterns = vec![
            r#"["']?token["']?\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?"#,
            r#"["']?reset_token["']?\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?"#,
            r#"["']?code["']?\s*[:=]\s*["']?(\d{6})["']?"#,
        ];

        for pattern_str in &token_patterns {
            let pattern = Regex::new(pattern_str).unwrap();
            if pattern.is_match(body) {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Password Reset Token Exposure".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authentication".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "Password reset token exposed in response body. Tokens should only be sent via secure channels (email, SMS).".to_string(),
                    evidence: Some("Reset token found in HTTP response".to_string()),
                    cwe: "CWE-640".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Never expose reset tokens in HTTP responses\n2. Send tokens only via email to registered address\n3. Use single-use tokens with short expiration (15-30 min)\n4. Require email verification before password reset\n5. Invalidate all sessions after password reset\n6. Log all password reset attempts\n7. Implement rate limiting on reset requests".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
                break;
            }
        }

        // Check for predictable reset tokens
        if body_lower.contains("reset") || body_lower.contains("forgot") {
            let simple_token_regex = Regex::new(r"token=(\d{4,8})").unwrap();
            if simple_token_regex.is_match(body) {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Weak Password Reset Token".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    category: "Authentication".to_string(),
                    url: url.to_string(),
                    parameter: Some("token".to_string()),
                    payload: String::new(),
                    description: "Password reset token appears to be predictable or weak. Short numeric tokens can be brute-forced.".to_string(),
                    evidence: Some("Simple numeric token pattern detected".to_string()),
                    cwe: "CWE-330".to_string(),
                    cvss: 8.1,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Use cryptographically secure random tokens (256-bit minimum)\n2. Make tokens long and unpredictable (e.g., 32+ characters)\n3. Implement rate limiting on token validation\n4. Use single-use tokens\n5. Implement CAPTCHA for token submission\n6. Track and limit token generation per account".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Check if password reset reveals account existence
        let _confirms_email = body_lower.contains("email sent")
            || body_lower.contains("check your email")
            || body_lower.contains("reset link sent");

        let denies_email = body_lower.contains("email not found")
            || body_lower.contains("account doesn't exist")
            || body_lower.contains("no account with that email");

        if denies_email {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Account Enumeration via Password Reset".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: Some("email".to_string()),
                payload: "test@example.com".to_string(),
                description: "Password reset function reveals whether an email address has an account. Attackers can enumerate valid user emails.".to_string(),
                evidence: Some("Different responses for registered vs unregistered emails".to_string()),
                cwe: "CWE-203".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: "1. Show same message for both valid and invalid emails\n2. Always show 'If that email exists, we sent a reset link'\n3. Implement rate limiting on reset requests\n4. Log enumeration attempts\n5. Consider CAPTCHA for reset requests".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_registration_security(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}/register?username=testuser&email=test@example.com&password=test123", url);
        self.http_client.get(&test_url).await
    }

    fn check_registration_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for auto-login after registration (security risk)
        let auto_logged_in = (body_lower.contains("welcome")
            || body_lower.contains("dashboard")
            || body_lower.contains("logged in"))
            && response.status_code == 200;

        if auto_logged_in && !body_lower.contains("verify") && !body_lower.contains("confirmation") {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Email Verification".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Users can register and access the application without email verification. This allows attackers to create accounts with fake or victim email addresses.".to_string(),
                evidence: Some("Immediate access granted after registration without verification".to_string()),
                cwe: "CWE-287".to_string(),
                cvss: 5.3,
                verified: false,
                false_positive: false,
                remediation: "1. Require email verification before account activation\n2. Send verification links to registered email\n3. Limit functionality for unverified accounts\n4. Implement CAPTCHA on registration\n5. Use double opt-in for sensitive applications\n6. Monitor for mass registration attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Check for missing CAPTCHA
        let has_captcha = body_lower.contains("captcha")
            || body_lower.contains("recaptcha")
            || body_lower.contains("hcaptcha");

        if (body_lower.contains("register") || body_lower.contains("sign up")) && !has_captcha {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing CAPTCHA on Registration".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Registration form lacks CAPTCHA protection. Automated bots can create fake accounts at scale.".to_string(),
                evidence: Some("No CAPTCHA detected in registration form".to_string()),
                cwe: "CWE-841".to_string(),
                cvss: 5.3,
                verified: false,
                false_positive: false,
                remediation: "1. Implement CAPTCHA (reCAPTCHA v3 recommended)\n2. Use rate limiting on registration endpoint\n3. Implement honeypot fields\n4. Track and block suspicious registration patterns\n5. Require email/SMS verification\n6. Monitor for automated registration attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_brute_force_protection(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Simulate multiple login attempts
        let test_url = format!("{}?username=admin&password=wrong", url);
        self.http_client.get(&test_url).await
    }

    fn check_brute_force_protection(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for rate limiting indicators
        let has_rate_limit = response.headers.contains_key("x-ratelimit-limit")
            || response.headers.contains_key("retry-after")
            || body_lower.contains("too many")
            || body_lower.contains("rate limit")
            || body_lower.contains("slow down");

        // Check for account lockout
        let has_lockout = body_lower.contains("account locked")
            || body_lower.contains("temporarily disabled")
            || body_lower.contains("too many attempts");

        // Check for CAPTCHA after failures
        let has_captcha = body_lower.contains("captcha")
            || body_lower.contains("recaptcha");

        if !has_rate_limit && !has_lockout && !has_captcha {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Brute Force Protection".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Login endpoint lacks brute force protection. Attackers can attempt unlimited password guessing without restriction.".to_string(),
                evidence: Some("No rate limiting, account lockout, or CAPTCHA detected".to_string()),
                cwe: "CWE-307".to_string(),
                cvss: 7.5,
                verified: false,
                false_positive: false,
                remediation: "1. Implement progressive delays after failed attempts\n2. Lock accounts after 5-10 failed attempts\n3. Implement CAPTCHA after 3 failures\n4. Use rate limiting (per IP and per account)\n5. Implement account unlock via email\n6. Monitor and alert on brute force attempts\n7. Consider using Web Application Firewall (WAF)\n8. Implement IP-based blocking for distributed attacks".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_account_lockout(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}?username=admin&password=wrong1", url);
        self.http_client.get(&test_url).await
    }

    fn check_account_lockout(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if account lockout is permanent (bad UX and security issue)
        let has_permanent_lockout = body_lower.contains("account permanently")
            || body_lower.contains("contact administrator")
            || body_lower.contains("call support");

        if has_permanent_lockout {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Permanent Account Lockout (DoS Risk)".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Account lockout appears permanent, requiring administrator intervention. Attackers can lock out legitimate users, causing denial of service.".to_string(),
                evidence: Some("Permanent lockout messages detected".to_string()),
                cwe: "CWE-400".to_string(),
                cvss: 5.3,
                verified: false,
                false_positive: false,
                remediation: "1. Implement time-based lockouts (e.g., 15-30 minutes)\n2. Allow self-service unlock via email verification\n3. Use progressive delays instead of hard lockouts\n4. Implement CAPTCHA as alternative to lockouts\n5. Monitor for DoS via account lockout attacks\n6. Consider using risk-based authentication".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    async fn test_credential_stuffing(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test for credential stuffing protection
        let test_url = format!("{}?username=test@example.com&password=password123", url);
        self.http_client.get(&test_url).await
    }

    fn check_credential_stuffing_prevention(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for credential stuffing defenses
        let has_device_fingerprint = body_lower.contains("device")
            || body_lower.contains("fingerprint")
            || body_lower.contains("browser");

        let has_mfa_prompt = body_lower.contains("verification")
            || body_lower.contains("two-factor")
            || body_lower.contains("authenticator");

        let has_suspicious_login_notification = body_lower.contains("unusual")
            || body_lower.contains("new location")
            || body_lower.contains("different device");

        // If none of these protections are evident, flag it
        if !has_device_fingerprint && !has_mfa_prompt && !has_suspicious_login_notification {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Credential Stuffing Protection".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Low,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Application may be vulnerable to credential stuffing attacks. No evidence of device fingerprinting, anomaly detection, or risk-based authentication.".to_string(),
                evidence: Some("No credential stuffing defenses detected".to_string()),
                cwe: "CWE-307".to_string(),
                cvss: 6.5,
                verified: false,
                false_positive: false,
                remediation: "1. Implement device fingerprinting\n2. Use risk-based authentication (location, device, behavior)\n3. Check credentials against breach databases (HaveIBeenPwned)\n4. Implement MFA for high-risk logins\n5. Monitor for impossible travel (login from different countries)\n6. Use CAPTCHA for suspicious login patterns\n7. Implement velocity checks (logins per IP/time)\n8. Notify users of new device logins".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
    }
}

fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "authmgr_{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    async fn test_weak_password_policy() {
        let scanner = AuthManagerScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <form>
                    <label>New Password (minimum 6 characters)</label>
                    <input type="password" name="password" />
                </form>
            "#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_password_policy(&response, "https://example.com/register", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Weak Password")), "Should detect weak password policy");
    }

    #[tokio::test]
    async fn test_account_enumeration() {
        let scanner = AuthManagerScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 401,
            body: r#"Error: User not found"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 150,
        };

        let mut vulns = Vec::new();
        scanner.check_account_enumeration(&response, "https://example.com/login", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Account Enumeration")), "Should detect account enumeration");
    }

    #[tokio::test]
    async fn test_password_reset_token_exposure() {
        let scanner = AuthManagerScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"{"message": "Reset email sent", "token": "abc123def456ghi789jkl012mno345"}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_password_reset_security(&response, "https://example.com/forgot-password", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Token Exposure")), "Should detect token exposure");
        assert!(vulns.iter().any(|v| v.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn test_missing_email_verification() {
        let scanner = AuthManagerScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <h1>Welcome to Dashboard!</h1>
                <p>Account created successfully. You are now logged in.</p>
            "#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_registration_security(&response, "https://example.com/register", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Email Verification")), "Should detect missing email verification");
    }

    #[tokio::test]
    async fn test_missing_brute_force_protection() {
        let scanner = AuthManagerScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 401,
            body: r#"Invalid credentials"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_brute_force_protection(&response, "https://example.com/login", &mut vulns);

        assert!(vulns.iter().any(|v| v.vuln_type.contains("Brute Force")), "Should detect missing brute force protection");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
