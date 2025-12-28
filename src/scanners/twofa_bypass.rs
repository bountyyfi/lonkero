// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Two-Factor Authentication (2FA) Bypass Scanner
 * Comprehensive scanner for detecting 2FA/MFA implementation vulnerabilities
 * and bypass techniques
 *
 * Tests for:
 * - Direct 2FA bypass (skipping verification step)
 * - OTP validation bypasses (null, empty, predictable values)
 * - Rate limiting issues (brute force susceptibility)
 * - Backup code security issues
 * - Recovery flow bypasses
 * - Implementation flaws (client-side state, exposed secrets)
 * - Session management issues
 * - OAuth/SSO 2FA enforcement gaps
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::{AppCharacteristics, endpoint_exists};
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info, warn};

/// 2FA method types detected
#[derive(Debug, Clone, PartialEq)]
pub enum TwoFaMethod {
    Totp,           // Time-based One-Time Password (Authenticator app)
    Sms,            // SMS-based OTP
    Email,          // Email-based OTP
    Push,           // Push notification
    HardwareToken,  // Hardware token (U2F, WebAuthn)
    BackupCodes,    // Recovery/backup codes
    Unknown,
}

/// 2FA endpoint information
#[derive(Debug, Clone)]
pub struct TwoFaEndpoint {
    pub url: String,
    pub method: TwoFaMethod,
    pub requires_auth: bool,
    pub has_rate_limiting: bool,
}

/// Scanner for 2FA bypass vulnerabilities
pub struct TwoFaBypassScanner {
    http_client: Arc<HttpClient>,
}

impl TwoFaBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // License check for premium features
        if !crate::license::is_feature_available("twofa_bypass") {
            info!("[2FA-Bypass] Premium feature - license required");
            return Ok((Vec::new(), 0));
        }

        info!("[2FA-Bypass] Starting comprehensive 2FA bypass scan on {}", url);

        // Step 1: Detect application characteristics
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                warn!("[2FA-Bypass] Failed to fetch target URL: {}", e);
                return Ok((Vec::new(), tests_run));
            }
        };

        let characteristics = AppCharacteristics::from_response(&response, url);

        // Skip if no authentication or MFA detected
        if !characteristics.has_authentication && !characteristics.has_mfa {
            info!("[2FA-Bypass] No authentication/MFA detected - skipping");
            return Ok((Vec::new(), tests_run));
        }

        // Skip pure SPAs without server-side logic
        if characteristics.should_skip_injection_tests() && !characteristics.has_mfa {
            info!("[2FA-Bypass] SPA/static site without MFA - skipping");
            return Ok((Vec::new(), tests_run));
        }

        let base_url = extract_base_url(url);

        // Step 2: Discover 2FA endpoints
        let twofa_endpoints = self.discover_twofa_endpoints(&base_url, &response.body).await;
        tests_run += 1;

        if twofa_endpoints.is_empty() && !characteristics.has_mfa {
            info!("[2FA-Bypass] No 2FA endpoints discovered - skipping");
            return Ok((Vec::new(), tests_run));
        }

        info!("[2FA-Bypass] Discovered {} potential 2FA endpoints", twofa_endpoints.len());

        // Step 3: Test direct bypass techniques
        let (direct_vulns, direct_tests) = self.test_direct_bypass(&base_url, &twofa_endpoints).await?;
        vulnerabilities.extend(direct_vulns);
        tests_run += direct_tests;

        // Step 4: Test OTP validation bypasses
        for endpoint in &twofa_endpoints {
            let (otp_vulns, otp_tests) = self.test_otp_bypass(&endpoint.url, &endpoint.method).await?;
            vulnerabilities.extend(otp_vulns);
            tests_run += otp_tests;
        }

        // Step 5: Test brute force susceptibility
        for endpoint in &twofa_endpoints {
            let (brute_vulns, brute_tests) = self.test_brute_force_susceptibility(&endpoint.url).await?;
            vulnerabilities.extend(brute_vulns);
            tests_run += brute_tests;
        }

        // Step 6: Test backup code security
        let (backup_vulns, backup_tests) = self.test_backup_code_security(&base_url).await?;
        vulnerabilities.extend(backup_vulns);
        tests_run += backup_tests;

        // Step 7: Test recovery flow bypasses
        let (recovery_vulns, recovery_tests) = self.test_recovery_bypass(&base_url).await?;
        vulnerabilities.extend(recovery_vulns);
        tests_run += recovery_tests;

        // Step 8: Test implementation flaws
        for endpoint in &twofa_endpoints {
            let (impl_vulns, impl_tests) = self.test_implementation_flaws(&base_url, endpoint).await?;
            vulnerabilities.extend(impl_vulns);
            tests_run += impl_tests;
        }

        // Step 9: Test session-related bypasses
        let (session_vulns, session_tests) = self.test_session_bypasses(&base_url, &twofa_endpoints).await?;
        vulnerabilities.extend(session_vulns);
        tests_run += session_tests;

        // Step 10: Test OAuth/SSO 2FA enforcement
        if characteristics.has_oauth {
            let (sso_vulns, sso_tests) = self.test_sso_bypass(&base_url).await?;
            vulnerabilities.extend(sso_vulns);
            tests_run += sso_tests;
        }

        // Deduplicate vulnerabilities
        let unique_vulns = deduplicate_vulnerabilities(vulnerabilities);

        info!(
            "[2FA-Bypass] Completed {} tests, found {} vulnerabilities",
            tests_run,
            unique_vulns.len()
        );

        Ok((unique_vulns, tests_run))
    }

    /// Discover 2FA-related endpoints
    async fn discover_twofa_endpoints(&self, base_url: &str, html_body: &str) -> Vec<TwoFaEndpoint> {
        let mut endpoints = Vec::new();
        let body_lower = html_body.to_lowercase();

        // Common 2FA endpoint patterns
        let endpoint_patterns = vec![
            // Verification endpoints
            ("/mfa/verify", TwoFaMethod::Unknown),
            ("/2fa/verify", TwoFaMethod::Unknown),
            ("/auth/mfa", TwoFaMethod::Unknown),
            ("/auth/2fa", TwoFaMethod::Unknown),
            ("/totp/verify", TwoFaMethod::Totp),
            ("/otp/verify", TwoFaMethod::Unknown),
            ("/verify-code", TwoFaMethod::Unknown),
            ("/verification", TwoFaMethod::Unknown),
            ("/challenge", TwoFaMethod::Unknown),
            ("/second-factor", TwoFaMethod::Unknown),
            // Enrollment endpoints
            ("/mfa/enroll", TwoFaMethod::Unknown),
            ("/mfa/setup", TwoFaMethod::Unknown),
            ("/2fa/setup", TwoFaMethod::Unknown),
            ("/totp/setup", TwoFaMethod::Totp),
            ("/authenticator/setup", TwoFaMethod::Totp),
            // SMS endpoints
            ("/sms/verify", TwoFaMethod::Sms),
            ("/sms/send", TwoFaMethod::Sms),
            ("/phone/verify", TwoFaMethod::Sms),
            // Email endpoints
            ("/email/verify", TwoFaMethod::Email),
            ("/email/otp", TwoFaMethod::Email),
            // Backup/recovery
            ("/mfa/backup", TwoFaMethod::BackupCodes),
            ("/2fa/recovery", TwoFaMethod::BackupCodes),
            ("/recovery-codes", TwoFaMethod::BackupCodes),
            ("/backup-codes", TwoFaMethod::BackupCodes),
        ];

        // Test each endpoint pattern
        for (path, method) in endpoint_patterns {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&url).await {
                // Check if endpoint actually exists
                if endpoint_exists(&response, &[200, 401, 403, 302]) {
                    // Detect method from response if unknown
                    let detected_method = if method == TwoFaMethod::Unknown {
                        self.detect_twofa_method(&response.body)
                    } else {
                        method.clone()
                    };

                    endpoints.push(TwoFaEndpoint {
                        url: url.clone(),
                        method: detected_method,
                        requires_auth: response.status_code == 401 || response.status_code == 403,
                        has_rate_limiting: self.detect_rate_limiting(&response),
                    });

                    debug!("[2FA-Bypass] Found endpoint: {} ({:?})", path, method);
                }
            }
        }

        // Also extract endpoints from HTML/JS
        let js_patterns = vec![
            r#"["'](/(?:mfa|2fa|totp|otp)/[^"']+)["']"#,
            r#"verify.*?["'](/[^"']+)["']"#,
            r#"two.?factor.*?["'](/[^"']+)["']"#,
        ];

        for pattern in js_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(html_body) {
                    if let Some(path) = cap.get(1) {
                        let url = format!("{}{}", base_url.trim_end_matches('/'), path.as_str());
                        if !endpoints.iter().any(|e| e.url == url) {
                            endpoints.push(TwoFaEndpoint {
                                url,
                                method: TwoFaMethod::Unknown,
                                requires_auth: false,
                                has_rate_limiting: false,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Detect 2FA method from response
    fn detect_twofa_method(&self, body: &str) -> TwoFaMethod {
        let body_lower = body.to_lowercase();

        if body_lower.contains("authenticator app") || body_lower.contains("totp") ||
           body_lower.contains("google authenticator") || body_lower.contains("authy") {
            TwoFaMethod::Totp
        } else if body_lower.contains("sms") || body_lower.contains("text message") ||
                  body_lower.contains("phone number") {
            TwoFaMethod::Sms
        } else if body_lower.contains("email") && body_lower.contains("code") {
            TwoFaMethod::Email
        } else if body_lower.contains("push notification") || body_lower.contains("approve") {
            TwoFaMethod::Push
        } else if body_lower.contains("security key") || body_lower.contains("u2f") ||
                  body_lower.contains("webauthn") || body_lower.contains("fido") {
            TwoFaMethod::HardwareToken
        } else if body_lower.contains("backup code") || body_lower.contains("recovery code") {
            TwoFaMethod::BackupCodes
        } else {
            TwoFaMethod::Unknown
        }
    }

    /// Detect rate limiting from response
    fn detect_rate_limiting(&self, response: &crate::http_client::HttpResponse) -> bool {
        response.headers.contains_key("x-ratelimit-limit") ||
        response.headers.contains_key("ratelimit-limit") ||
        response.headers.contains_key("retry-after") ||
        response.status_code == 429
    }

    /// Test direct bypass techniques
    async fn test_direct_bypass(
        &self,
        base_url: &str,
        endpoints: &[TwoFaEndpoint],
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing direct bypass techniques");

        // Common protected resources that should require 2FA
        let protected_paths = vec![
            "/dashboard", "/admin", "/settings", "/profile", "/account",
            "/api/user", "/api/account", "/api/settings", "/api/admin",
            "/panel", "/portal", "/home", "/internal",
        ];

        // Test 1: Skip 2FA step by directly accessing protected resources
        for path in &protected_paths {
            tests_run += 1;
            let protected_url = format!("{}{}", base_url.trim_end_matches('/'), path);

            if let Ok(response) = self.http_client.get(&protected_url).await {
                // Check if we got access without completing 2FA
                if self.check_protected_access(&response, path).await {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Bypass - Direct Resource Access",
                        &protected_url,
                        Severity::Critical,
                        Confidence::High,
                        format!(
                            "Protected resource '{}' is accessible without completing 2FA verification. \
                            The application allows direct access to authenticated resources by skipping \
                            the second factor verification step.",
                            path
                        ),
                        format!("HTTP {} returned for {} without 2FA completion", response.status_code, path),
                        "CWE-287",
                        9.5,
                    ));
                    break;
                }
            }
        }

        // Test 2: Manipulate response to indicate 2FA success
        for endpoint in endpoints {
            tests_run += 1;

            // Test with 2FA bypass parameters
            let bypass_params = vec![
                ("mfa_verified", "true"),
                ("2fa_complete", "true"),
                ("skip_2fa", "true"),
                ("verified", "true"),
                ("otp_verified", "1"),
                ("challenge_passed", "true"),
            ];

            for (param, value) in &bypass_params {
                let bypass_url = format!("{}?{}={}", endpoint.url, param, value);

                if let Ok(response) = self.http_client.get(&bypass_url).await {
                    if self.check_bypass_success(&response) {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Parameter Manipulation",
                            &bypass_url,
                            Severity::Critical,
                            Confidence::High,
                            format!(
                                "2FA verification can be bypassed by setting '{}={}' parameter. \
                                The application trusts client-side parameters to indicate 2FA completion.",
                                param, value
                            ),
                            format!("Parameter {}={} bypassed 2FA", param, value),
                            "CWE-288",
                            9.8,
                        ));
                        break;
                    }
                }
            }
        }

        // Test 3: Change HTTP method to bypass 2FA
        for endpoint in endpoints {
            tests_run += 1;

            // Try OPTIONS, HEAD - test if different HTTP methods bypass 2FA
            let methods = vec!["OPTIONS", "HEAD"];

            for method in methods {
                // Use request_with_method for arbitrary HTTP methods
                let response = self.http_client.request_with_method(method, &endpoint.url).await;

                if let Ok(resp) = response {
                    if resp.status_code == 200 && !resp.body.is_empty() {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - HTTP Method Override",
                            &endpoint.url,
                            Severity::High,
                            Confidence::Medium,
                            format!(
                                "2FA verification may be bypassable using {} method. \
                                Different HTTP methods return different responses than POST.",
                                method
                            ),
                            format!("{} method returned HTTP 200", method),
                            "CWE-287",
                            7.5,
                        ));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test OTP validation bypass techniques
    async fn test_otp_bypass(
        &self,
        endpoint: &str,
        _method: &TwoFaMethod,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing OTP validation bypasses on {}", endpoint);

        // Test weak OTP values
        let weak_otps = vec![
            ("", "Empty OTP"),
            ("null", "Null string OTP"),
            ("000000", "All zeros OTP"),
            ("123456", "Common OTP pattern"),
            ("111111", "Repeated digits OTP"),
            ("999999", "All nines OTP"),
            ("0", "Single digit OTP"),
            ("00000000", "Eight zeros OTP"),
            ("-1", "Negative OTP"),
            ("1.0", "Float OTP"),
            ("abcdef", "Alphabetic OTP"),
            ("      ", "Whitespace OTP"),
            ("\n", "Newline OTP"),
            ("true", "Boolean string OTP"),
            ("{}", "Empty object OTP"),
            ("[]", "Empty array OTP"),
        ];

        for (otp, description) in &weak_otps {
            tests_run += 1;

            // Test via query parameter
            let test_url = format!("{}?code={}", endpoint, urlencoding::encode(otp));
            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.check_bypass_success(&response) {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Bypass - Weak OTP Validation",
                        endpoint,
                        Severity::Critical,
                        Confidence::High,
                        format!(
                            "2FA verification accepts {} ('{}'). \
                            The OTP validation logic is flawed and accepts invalid values.",
                            description, otp
                        ),
                        format!("OTP '{}' was accepted", otp),
                        "CWE-287",
                        9.8,
                    ));
                    break;
                }
            }

            // Test via POST body
            let form_data = format!("code={}", urlencoding::encode(otp));
            if let Ok(response) = self.http_client.post_form(endpoint, &form_data).await {
                if self.check_bypass_success(&response) {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Bypass - Weak OTP Validation (POST)",
                        endpoint,
                        Severity::Critical,
                        Confidence::High,
                        format!(
                            "2FA verification accepts {} ('{}') via POST. \
                            The OTP validation logic is flawed and accepts invalid values.",
                            description, otp
                        ),
                        format!("OTP '{}' was accepted via POST", otp),
                        "CWE-287",
                        9.8,
                    ));
                    break;
                }
            }
        }

        // Test OTP parameter removal
        tests_run += 1;
        let no_otp_data = "username=test";
        if let Ok(response) = self.http_client.post_form(endpoint, no_otp_data).await {
            if self.check_bypass_success(&response) {
                vulnerabilities.push(self.create_vulnerability(
                    "2FA Bypass - Missing OTP Parameter Accepted",
                    endpoint,
                    Severity::Critical,
                    Confidence::High,
                    "2FA verification succeeds when OTP parameter is completely omitted. \
                    The application does not properly validate that an OTP was provided.",
                    "Request without OTP parameter succeeded",
                    "CWE-287",
                    9.8,
                ));
            }
        }

        // Test OTP in different parameter names
        tests_run += 1;
        let param_names = vec!["otp", "totp", "token", "verification_code", "auth_code", "2fa_code"];
        for param in param_names {
            let form_data = format!("{}=123456", param);
            if let Ok(response) = self.http_client.post_form(endpoint, &form_data).await {
                // Check for information disclosure about expected parameter
                if response.body.to_lowercase().contains("expected") ||
                   response.body.to_lowercase().contains("missing") {
                    debug!("[2FA-Bypass] Endpoint expects parameter: {}", param);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for brute force susceptibility
    async fn test_brute_force_susceptibility(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing rate limiting on {}", endpoint);

        let mut response_times = Vec::new();
        let mut successful_attempts = 0;
        let attempt_count = 20;

        let start_time = Instant::now();

        for i in 0..attempt_count {
            tests_run += 1;
            let test_code = format!("{:06}", i);
            let form_data = format!("code={}", test_code);

            let attempt_start = Instant::now();

            match self.http_client.post_form(endpoint, &form_data).await {
                Ok(response) => {
                    let duration = attempt_start.elapsed();
                    response_times.push(duration.as_millis());

                    // Check for rate limiting response
                    if response.status_code == 429 ||
                       response.body.to_lowercase().contains("rate limit") ||
                       response.body.to_lowercase().contains("too many attempts") ||
                       response.body.to_lowercase().contains("locked") ||
                       response.body.to_lowercase().contains("try again later") {
                        debug!("[2FA-Bypass] Rate limiting detected at attempt {}", i + 1);
                        break;
                    }

                    // Count successful processing (not actual auth success)
                    if response.status_code == 200 || response.status_code == 400 ||
                       response.status_code == 401 || response.status_code == 422 {
                        successful_attempts += 1;
                    }
                }
                Err(_) => break,
            }

            // Brief delay between attempts
            sleep(Duration::from_millis(50)).await;
        }

        let total_time = start_time.elapsed();

        // Report if no rate limiting detected after many attempts
        if successful_attempts >= 15 {
            let avg_time = if !response_times.is_empty() {
                response_times.iter().sum::<u128>() / response_times.len() as u128
            } else {
                0
            };

            // Calculate estimated brute force time
            let estimated_hours = (1_000_000.0 / successful_attempts as f64) *
                                  (total_time.as_secs_f64() / 3600.0);

            vulnerabilities.push(self.create_vulnerability(
                "2FA Bypass - Missing Rate Limiting (Brute Force Possible)",
                endpoint,
                Severity::Critical,
                Confidence::High,
                format!(
                    "No rate limiting detected on 2FA verification endpoint. \
                    Successfully submitted {} OTP attempts in {:.2} seconds. \
                    6-digit OTP codes (1,000,000 combinations) could be brute-forced in approximately {:.1} hours. \
                    Average response time: {}ms.",
                    successful_attempts,
                    total_time.as_secs_f32(),
                    estimated_hours,
                    avg_time
                ),
                format!("{} attempts without rate limiting", successful_attempts),
                "CWE-307",
                9.1,
            ));
        }

        // Check for timing attack vulnerability
        if response_times.len() >= 5 {
            let mean: u128 = response_times.iter().sum::<u128>() / response_times.len() as u128;
            let variance: u128 = response_times.iter()
                .map(|&t| {
                    let diff = if t > mean { t - mean } else { mean - t };
                    diff * diff
                })
                .sum::<u128>() / response_times.len() as u128;

            if variance > 2500 { // More than 50ms standard deviation
                vulnerabilities.push(self.create_vulnerability(
                    "2FA Timing Attack Vulnerability",
                    endpoint,
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Significant timing variance detected in OTP verification responses. \
                        Variance: {}ms^2, which may indicate non-constant-time comparison. \
                        This could allow attackers to determine correct OTP digits through timing analysis.",
                        variance
                    ),
                    format!("Timing variance: {}ms^2", variance),
                    "CWE-208",
                    5.3,
                ));
            }
        }

        // Check for account lockout
        tests_run += 1;
        if successful_attempts == attempt_count {
            vulnerabilities.push(self.create_vulnerability(
                "2FA Missing Account Lockout",
                endpoint,
                Severity::High,
                Confidence::Medium,
                format!(
                    "No account lockout mechanism detected after {} failed 2FA attempts. \
                    Attackers can continuously attempt to brute force the verification code \
                    without the account being locked.",
                    attempt_count
                ),
                format!("{} failed attempts without lockout", attempt_count),
                "CWE-307",
                7.5,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test backup code security
    async fn test_backup_code_security(
        &self,
        base_url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing backup code security");

        let backup_endpoints = vec![
            "/mfa/backup", "/2fa/recovery", "/backup-codes", "/recovery-codes",
            "/auth/backup", "/account/recovery", "/mfa/recovery",
        ];

        for path in &backup_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&endpoint).await {
                if !endpoint_exists(&response, &[200, 401, 403]) {
                    continue;
                }

                let body_lower = response.body.to_lowercase();

                // Check for exposed backup codes
                let code_pattern = Regex::new(r"[A-Z0-9]{4}[-\s]?[A-Z0-9]{4}[-\s]?[A-Z0-9]{4}").unwrap();
                if code_pattern.is_match(&response.body) &&
                   (body_lower.contains("backup") || body_lower.contains("recovery")) {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Backup Codes Exposed",
                        &endpoint,
                        Severity::High,
                        Confidence::High,
                        "Backup codes are exposed in the page response. These codes should only be \
                        shown once during generation and stored securely (hashed) in the database.",
                        "Backup codes visible in response body",
                        "CWE-200",
                        7.5,
                    ));
                }

                // Test backup code rate limiting
                let (backup_brute_vulns, backup_brute_tests) =
                    self.test_backup_code_brute_force(&endpoint).await?;
                vulnerabilities.extend(backup_brute_vulns);
                tests_run += backup_brute_tests;

                // Test predictable backup codes
                let (predictable_vulns, predictable_tests) =
                    self.test_predictable_backup_codes(&endpoint).await?;
                vulnerabilities.extend(predictable_vulns);
                tests_run += predictable_tests;

                // Test backup code reuse
                let (reuse_vulns, reuse_tests) =
                    self.test_backup_code_reuse(&endpoint).await?;
                vulnerabilities.extend(reuse_vulns);
                tests_run += reuse_tests;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test backup code brute force susceptibility
    async fn test_backup_code_brute_force(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut successful_attempts = 0;

        for i in 0..10 {
            let test_code = format!("AAAA-{:04}-BBBB", i);
            let form_data = format!("backup_code={}", test_code);

            if let Ok(response) = self.http_client.post_form(endpoint, &form_data).await {
                if response.status_code != 429 &&
                   !response.body.to_lowercase().contains("rate limit") &&
                   !response.body.to_lowercase().contains("locked") {
                    successful_attempts += 1;
                } else {
                    break;
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        if successful_attempts >= 8 {
            vulnerabilities.push(self.create_vulnerability(
                "2FA Backup Code - No Rate Limiting",
                endpoint,
                Severity::High,
                Confidence::Medium,
                format!(
                    "No rate limiting detected on backup code verification. \
                    {} attempts succeeded without being blocked. \
                    Attackers can enumerate valid backup codes through brute force.",
                    successful_attempts
                ),
                format!("{} backup code attempts without rate limiting", successful_attempts),
                "CWE-307",
                7.5,
            ));
        }

        Ok((vulnerabilities, 10))
    }

    /// Test for predictable backup codes
    async fn test_predictable_backup_codes(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        // Common weak patterns
        let weak_codes = vec![
            "0000-0000-0000", "1111-1111-1111", "1234-5678-9012",
            "AAAA-AAAA-AAAA", "ABCD-EFGH-IJKL", "TEST-CODE-0001",
        ];

        for code in &weak_codes {
            let form_data = format!("backup_code={}", code);
            if let Ok(response) = self.http_client.post_form(endpoint, &form_data).await {
                if self.check_bypass_success(&response) {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Bypass - Predictable Backup Code",
                        endpoint,
                        Severity::Critical,
                        Confidence::High,
                        format!(
                            "Backup code '{}' was accepted. Backup codes follow a predictable pattern, \
                            allowing attackers to enumerate valid codes.",
                            code
                        ),
                        format!("Weak backup code '{}' accepted", code),
                        "CWE-330",
                        9.8,
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, weak_codes.len()))
    }

    /// Test backup code reuse
    async fn test_backup_code_reuse(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        let test_code = "TEST-REUSE-1234";
        let form_data = format!("backup_code={}", test_code);

        // First attempt
        let first_response = match self.http_client.post_form(endpoint, &form_data).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, 1)),
        };

        // Short delay
        sleep(Duration::from_millis(100)).await;

        // Second attempt with same code
        if let Ok(second_response) = self.http_client.post_form(endpoint, &form_data).await {
            // If both succeed, codes are reusable
            if self.check_bypass_success(&first_response) &&
               self.check_bypass_success(&second_response) {
                vulnerabilities.push(self.create_vulnerability(
                    "2FA Bypass - Reusable Backup Codes",
                    endpoint,
                    Severity::High,
                    Confidence::High,
                    "Backup codes can be used multiple times. Single-use enforcement is missing, \
                    allowing an intercepted backup code to be used repeatedly.",
                    "Same backup code accepted twice",
                    "CWE-294",
                    7.3,
                ));
            }
        }

        Ok((vulnerabilities, 2))
    }

    /// Test recovery flow bypasses
    async fn test_recovery_bypass(
        &self,
        base_url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing recovery flow bypasses");

        // Password reset flow
        let reset_endpoints = vec![
            "/password/reset", "/forgot-password", "/reset-password",
            "/auth/reset", "/account/reset", "/api/password/reset",
        ];

        for path in &reset_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&endpoint).await {
                if endpoint_exists(&response, &[200, 302]) {
                    // Check if password reset bypasses 2FA
                    let body_lower = response.body.to_lowercase();

                    // If password reset form is accessible and doesn't mention 2FA
                    if (body_lower.contains("email") || body_lower.contains("password")) &&
                       !body_lower.contains("2fa") &&
                       !body_lower.contains("mfa") &&
                       !body_lower.contains("verification code") {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Password Reset Flow",
                            &endpoint,
                            Severity::High,
                            Confidence::Medium,
                            "Password reset flow may bypass 2FA. After resetting password, \
                            users can potentially log in without 2FA verification, as 2FA \
                            may be reset or bypassed during the password reset process.",
                            "Password reset form accessible without 2FA verification mention",
                            "CWE-287",
                            8.1,
                        ));
                    }
                }
            }
        }

        // Account recovery flow
        let recovery_endpoints = vec![
            "/account/recover", "/recovery", "/auth/recover", "/forgot",
        ];

        for path in &recovery_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&endpoint).await {
                if endpoint_exists(&response, &[200, 302]) {
                    let body_lower = response.body.to_lowercase();

                    if body_lower.contains("recover") && !body_lower.contains("2fa") {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Account Recovery Flow",
                            &endpoint,
                            Severity::High,
                            Confidence::Medium,
                            "Account recovery flow may bypass 2FA. Recovery mechanisms that \
                            don't re-verify 2FA or require its re-enrollment can be exploited \
                            to bypass second factor authentication.",
                            "Account recovery accessible without 2FA mention",
                            "CWE-287",
                            8.1,
                        ));
                    }
                }
            }
        }

        // Email change flow
        let email_change_endpoints = vec![
            "/settings/email", "/account/email", "/profile/email",
            "/api/user/email", "/auth/email/change",
        ];

        for path in &email_change_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&endpoint).await {
                if endpoint_exists(&response, &[200, 302, 401]) {
                    let body_lower = response.body.to_lowercase();

                    // Check if email change requires 2FA re-verification
                    if body_lower.contains("email") &&
                       !body_lower.contains("verification code") &&
                       !body_lower.contains("2fa") &&
                       response.status_code != 401 {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Email Change Without 2FA",
                            &endpoint,
                            Severity::Medium,
                            Confidence::Low,
                            "Email change may not require 2FA re-verification. Changing the \
                            account email could allow attackers to bypass 2FA by using the \
                            email-based recovery flow on the new email address.",
                            "Email change form accessible without 2FA verification",
                            "CWE-287",
                            6.5,
                        ));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test implementation flaws
    async fn test_implementation_flaws(
        &self,
        base_url: &str,
        endpoint: &TwoFaEndpoint,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing implementation flaws");

        // Test 1: Check for client-side 2FA state
        tests_run += 1;
        if let Ok(response) = self.http_client.get(&endpoint.url).await {
            let body_lower = response.body.to_lowercase();

            // Check for 2FA status stored in client-side
            let client_side_patterns = vec![
                r#"mfa_enabled["']?\s*[:=]\s*["']?(true|false)"#,
                r#"two_factor["']?\s*[:=]\s*["']?(enabled|disabled)"#,
                r#"localStorage.*2fa"#,
                r#"sessionStorage.*mfa"#,
                r#"cookie.*mfa_status"#,
            ];

            for pattern in &client_side_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Implementation Flaw - Client-Side State",
                            &endpoint.url,
                            Severity::High,
                            Confidence::Medium,
                            "2FA status appears to be stored or controlled client-side. \
                            Attackers may be able to manipulate browser storage or cookies \
                            to bypass 2FA verification.",
                            format!("Client-side 2FA state detected matching: {}", pattern),
                            "CWE-602",
                            8.1,
                        ));
                        break;
                    }
                }
            }
        }

        // Test 2: Check for exposed TOTP secret
        tests_run += 1;
        let setup_endpoints = vec![
            format!("{}/mfa/setup", base_url.trim_end_matches('/')),
            format!("{}/2fa/enroll", base_url.trim_end_matches('/')),
            format!("{}/totp/setup", base_url.trim_end_matches('/')),
        ];

        for setup_url in &setup_endpoints {
            if let Ok(response) = self.http_client.get(setup_url).await {
                // Check for exposed TOTP secret
                let secret_pattern = Regex::new(r"secret=([A-Z2-7]{16,})").unwrap();
                if let Some(cap) = secret_pattern.captures(&response.body) {
                    if let Some(secret) = cap.get(1) {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Implementation Flaw - TOTP Secret Exposed",
                            setup_url,
                            Severity::Critical,
                            Confidence::High,
                            format!(
                                "TOTP secret key is exposed in the page response ({}...). \
                                This allows attackers to generate valid 2FA codes. Secrets should \
                                only be transmitted via secure QR code images, never in plaintext.",
                                &secret.as_str()[..std::cmp::min(8, secret.as_str().len())]
                            ),
                            "TOTP secret exposed in otpauth:// URI",
                            "CWE-522",
                            9.8,
                        ));
                    }
                }
            }
        }

        // Test 3: Check for QR code without authentication
        tests_run += 1;
        for setup_url in &setup_endpoints {
            if let Ok(response) = self.http_client.get(setup_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    if (body_lower.contains("qr") || body_lower.contains("scan")) &&
                       !response.headers.contains_key("authorization") &&
                       !response.body.contains("login") {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Implementation Flaw - Unauthenticated QR Code Access",
                            setup_url,
                            Severity::High,
                            Confidence::Medium,
                            "2FA QR code enrollment page is accessible without authentication. \
                            Attackers could potentially register their own 2FA device on a \
                            victim's account.",
                            "QR code setup page accessible without auth",
                            "CWE-306",
                            8.1,
                        ));
                    }
                }
            }
        }

        // Test 4: Check for device trust manipulation
        tests_run += 1;
        let trust_params = vec![
            "trust_device=true", "remember_device=true", "skip_future_2fa=true",
            "trusted=1", "device_trusted=true",
        ];

        for param in &trust_params {
            let test_url = format!("{}?{}", endpoint.url, param);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if self.check_bypass_success(&response) {
                    vulnerabilities.push(self.create_vulnerability(
                        "2FA Bypass - Device Trust Manipulation",
                        &test_url,
                        Severity::High,
                        Confidence::Medium,
                        format!(
                            "2FA can be bypassed by setting '{}' parameter. \
                            The application trusts client-controlled device trust flags.",
                            param
                        ),
                        format!("Parameter {} bypassed 2FA", param),
                        "CWE-288",
                        8.5,
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test session-related bypasses
    async fn test_session_bypasses(
        &self,
        base_url: &str,
        endpoints: &[TwoFaEndpoint],
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing session-related bypasses");

        // Test 1: Check if 2FA is required on all session types
        tests_run += 1;
        let session_endpoints = vec![
            "/api/session", "/api/me", "/api/user", "/api/profile",
        ];

        for path in &session_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.http_client.get(&endpoint).await {
                if response.status_code == 200 {
                    let body = &response.body;

                    // Check if session data is returned without 2FA
                    if (body.contains("\"user\"") || body.contains("\"email\"") ||
                        body.contains("\"id\"")) &&
                       !body.contains("2fa_required") && !body.contains("mfa_pending") {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Session Without 2FA",
                            &endpoint,
                            Severity::Medium,
                            Confidence::Low,
                            "API session data accessible without 2FA verification. \
                            Some session types may not require 2FA completion.",
                            "Session data returned without 2FA",
                            "CWE-287",
                            6.5,
                        ));
                    }
                }
            }
        }

        // Test 2: Check for remember device cookie manipulation
        tests_run += 1;
        let cookie_names = vec![
            "remember_2fa", "trusted_device", "mfa_remember", "2fa_trusted",
            "device_token", "trust_token",
        ];

        for cookie_name in &cookie_names {
            for endpoint in endpoints {
                let headers = vec![
                    ("Cookie".to_string(), format!("{}=1", cookie_name)),
                ];

                if let Ok(response) = self.http_client.get_with_headers(&endpoint.url, headers).await {
                    if self.check_bypass_success(&response) {
                        vulnerabilities.push(self.create_vulnerability(
                            "2FA Bypass - Cookie Manipulation",
                            &endpoint.url,
                            Severity::Critical,
                            Confidence::High,
                            format!(
                                "2FA can be bypassed by setting '{}=1' cookie. \
                                The application trusts client-provided device trust cookies \
                                without proper cryptographic verification.",
                                cookie_name
                            ),
                            format!("Cookie {}=1 bypassed 2FA", cookie_name),
                            "CWE-288",
                            9.1,
                        ));
                        break;
                    }
                }
            }
        }

        // Test 3: Check for session fixation to bypass 2FA
        tests_run += 1;
        let session_ids = vec![
            "PHPSESSID", "JSESSIONID", "session", "sess_id", "sid",
        ];

        for sid_name in &session_ids {
            for endpoint in endpoints {
                let fixed_session = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let headers = vec![
                    ("Cookie".to_string(), format!("{}={}", sid_name, fixed_session)),
                ];

                if let Ok(response) = self.http_client.get_with_headers(&endpoint.url, headers).await {
                    // Check if session was accepted
                    if response.status_code == 200 && !response.body.contains("invalid session") {
                        // This needs manual verification but worth flagging
                        debug!("[2FA-Bypass] Session {} may be vulnerable to fixation", sid_name);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test OAuth/SSO 2FA enforcement
    async fn test_sso_bypass(
        &self,
        base_url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[2FA-Bypass] Testing OAuth/SSO 2FA enforcement");

        // Common SSO endpoints
        let sso_endpoints = vec![
            "/auth/google", "/auth/github", "/auth/microsoft", "/auth/facebook",
            "/oauth/callback", "/sso/login", "/auth/saml", "/login/sso",
            "/oauth2/authorize", "/connect/authorize",
        ];

        for path in &sso_endpoints {
            let endpoint = format!("{}{}", base_url.trim_end_matches('/'), path);
            tests_run += 1;

            if let Ok(response) = self.http_client.get(&endpoint).await {
                if endpoint_exists(&response, &[200, 302, 401]) {
                    let body_lower = response.body.to_lowercase();

                    // Check if SSO bypasses 2FA
                    if response.status_code == 302 {
                        // Following SSO redirect might bypass 2FA
                        if let Some(location) = response.headers.get("location") {
                            if location.contains("callback") || location.contains("oauth") {
                                vulnerabilities.push(self.create_vulnerability(
                                    "Potential 2FA Bypass via OAuth/SSO",
                                    &endpoint,
                                    Severity::Medium,
                                    Confidence::Low,
                                    format!(
                                        "OAuth/SSO login flow detected at {}. If the application \
                                        has 2FA enabled, ensure that SSO authentication also \
                                        enforces 2FA verification or requires a separate 2FA step \
                                        after SSO completion.",
                                        path
                                    ),
                                    format!("SSO redirect to: {}", location),
                                    "CWE-287",
                                    5.5,
                                ));
                            }
                        }
                    }

                    // Check if account linking bypasses 2FA
                    if body_lower.contains("link") && body_lower.contains("account") {
                        vulnerabilities.push(self.create_vulnerability(
                            "Potential 2FA Bypass via Account Linking",
                            &endpoint,
                            Severity::Medium,
                            Confidence::Low,
                            "Account linking functionality detected. Linking a social account \
                            may allow users to bypass 2FA by logging in with the linked account \
                            instead of the original credentials + 2FA.",
                            "Account linking option detected",
                            "CWE-287",
                            5.5,
                        ));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check if protected resource access was successful
    async fn check_protected_access(&self, response: &crate::http_client::HttpResponse, _path: &str) -> bool {
        let body_lower = response.body.to_lowercase();

        // Should NOT be a login/2FA page
        let not_auth_page = !body_lower.contains("login") &&
                           !body_lower.contains("sign in") &&
                           !body_lower.contains("verification code") &&
                           !body_lower.contains("enter code") &&
                           !body_lower.contains("2fa") &&
                           !body_lower.contains("mfa");

        // Should be an actual protected resource
        let is_protected_content = body_lower.contains("dashboard") ||
                                   body_lower.contains("settings") ||
                                   body_lower.contains("profile") ||
                                   body_lower.contains("account") ||
                                   body_lower.contains("admin");

        // Status should indicate success
        let success_status = response.status_code == 200;

        // Must have substantial content (not empty or error page)
        let has_content = response.body.len() > 500;

        success_status && not_auth_page && is_protected_content && has_content
    }

    /// Check if bypass was successful
    fn check_bypass_success(&self, response: &crate::http_client::HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();

        // Positive indicators (authentication success)
        let success_indicators = response.status_code == 200 || response.status_code == 302;

        let has_success_content = body_lower.contains("success") ||
                                  body_lower.contains("verified") ||
                                  body_lower.contains("authenticated") ||
                                  body_lower.contains("welcome") ||
                                  body_lower.contains("dashboard");

        // Negative indicators (still requiring auth)
        let requires_auth = body_lower.contains("invalid") ||
                           body_lower.contains("incorrect") ||
                           body_lower.contains("wrong") ||
                           body_lower.contains("failed") ||
                           body_lower.contains("error") ||
                           body_lower.contains("try again") ||
                           body_lower.contains("expired");

        // Check for session cookie being set
        let has_session_cookie = response.headers.get("set-cookie")
            .map(|c| c.to_lowercase().contains("session") || c.to_lowercase().contains("auth"))
            .unwrap_or(false);

        // Bypass is successful if we have success indicators and no auth failure indicators
        (success_indicators && (has_success_content || has_session_cookie)) && !requires_auth
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: impl Into<String>,
        evidence: impl Into<String>,
        cwe: &str,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: generate_uuid(),
            vuln_type: title.to_string(),
            severity,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.into(),
            evidence: Some(evidence.into()),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(title),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            title if title.contains("Direct Resource Access") => {
                r#"CRITICAL: Implement proper 2FA session state management:

1. **Server-Side 2FA State**
   - Store 2FA completion status in server-side session only
   - Never trust client-side indicators for 2FA status
   - Verify 2FA completion on every protected request

2. **Session State Machine**
   ```python
   # Example: Python/Flask
   @app.before_request
   def require_2fa():
       if request.endpoint in protected_endpoints:
           if not session.get('2fa_verified'):
               return redirect(url_for('2fa_verify'))
   ```

3. **API Protection**
   ```javascript
   // Express.js middleware
   const require2FA = (req, res, next) => {
       if (!req.session.twoFactorVerified) {
           return res.status(401).json({
               error: '2FA verification required',
               redirect: '/2fa/verify'
           });
       }
       next();
   };
   ```

4. **Database Flag**
   - Maintain 2FA session status in database
   - Invalidate on logout or suspicious activity

5. **Audit Logging**
   - Log all 2FA bypass attempts
   - Alert on access to protected resources without 2FA"#.to_string()
            },
            title if title.contains("Rate Limiting") || title.contains("Brute Force") => {
                r#"CRITICAL: Implement rate limiting and account lockout:

1. **Rate Limiting**
   ```python
   from flask_limiter import Limiter

   limiter = Limiter(app, key_func=get_remote_address)

   @app.route('/2fa/verify', methods=['POST'])
   @limiter.limit("5 per minute")
   def verify_2fa():
       # Verification logic
   ```

2. **Account Lockout**
   ```javascript
   const MAX_ATTEMPTS = 5;
   const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

   async function verify2FA(userId, code) {
       const attempts = await getFailedAttempts(userId);
       if (attempts >= MAX_ATTEMPTS) {
           throw new Error('Account locked. Try again later.');
       }
       // Verify code
   }
   ```

3. **Progressive Delays**
   - Add exponential backoff after failures
   - First failure: 1 second delay
   - Second failure: 2 seconds
   - Third failure: 4 seconds, etc.

4. **CAPTCHA After Failures**
   - Require CAPTCHA after 3 failed attempts
   - Use Google reCAPTCHA or similar

5. **Monitoring**
   - Alert on brute force patterns
   - Log all 2FA verification attempts"#.to_string()
            },
            title if title.contains("Backup Code") => {
                r#"CRITICAL: Secure backup code implementation:

1. **Cryptographically Random Generation**
   ```python
   import secrets

   def generate_backup_codes(count=10):
       codes = []
       for _ in range(count):
           code = secrets.token_hex(6).upper()
           formatted = f"{code[:4]}-{code[4:8]}-{code[8:]}"
           codes.append(formatted)
       return codes
   ```

2. **Hash Before Storage**
   ```python
   import bcrypt

   def store_backup_codes(user_id, codes):
       for code in codes:
           hashed = bcrypt.hashpw(code.encode(), bcrypt.gensalt())
           db.store_backup_code(user_id, hashed)
   ```

3. **Single-Use Enforcement**
   ```sql
   -- Mark code as used immediately
   UPDATE backup_codes
   SET used_at = NOW(), used = TRUE
   WHERE user_id = ? AND code_hash = ?
   ```

4. **Rate Limiting on Backup Codes**
   - Same rate limits as primary 2FA
   - Stricter limits (3 attempts per hour)

5. **User Notification**
   - Email user when backup code is used
   - Alert on repeated failed attempts"#.to_string()
            },
            title if title.contains("TOTP Secret") || title.contains("QR Code") => {
                r#"CRITICAL: Protect TOTP secrets:

1. **Never Expose Secrets in URLs or Responses**
   ```python
   # WRONG
   return jsonify({'secret': totp_secret, 'qr_url': qr_url})

   # CORRECT - Generate QR image server-side
   import qrcode
   import io

   def generate_qr_image(secret, user_email):
       uri = f"otpauth://totp/App:{user_email}?secret={secret}&issuer=App"
       qr = qrcode.make(uri)
       buffer = io.BytesIO()
       qr.save(buffer, format='PNG')
       return buffer.getvalue()
   ```

2. **Require Re-Authentication**
   - Require password before showing TOTP setup
   - Use time-limited setup tokens

3. **Secure Transmission**
   - Always use HTTPS
   - Set appropriate cache headers

4. **Access Control**
   - Require authentication for setup endpoints
   - Implement CSRF protection

5. **Audit Trail**
   - Log all TOTP enrollments
   - Alert on suspicious enrollment patterns"#.to_string()
            },
            title if title.contains("Recovery") || title.contains("Password Reset") => {
                r#"CRITICAL: Secure recovery flows:

1. **Require 2FA During Recovery**
   ```python
   def password_reset(request):
       user = get_user_by_email(request.email)
       if user.has_2fa_enabled:
           # Require backup code or alternative 2FA
           if not verify_backup_code(request.backup_code):
               return error("Valid backup code required")
       # Continue with reset
   ```

2. **Identity Verification**
   - Multiple verification factors
   - Security questions + email confirmation
   - Support ticket verification for high-value accounts

3. **Grace Period Warning**
   - If 2FA is disabled during recovery, require re-setup
   - Send email notifications of 2FA changes

4. **Account Lockdown Options**
   - Allow users to lock account if compromised
   - 24-hour cooling period for major changes

5. **Audit All Recovery Attempts**
   - Log IP, device, location
   - Alert on suspicious patterns"#.to_string()
            },
            _ => {
                r#"CRITICAL: General 2FA Security Best Practices:

1. **Server-Side Verification Only**
   - Never trust client-side 2FA status
   - Verify 2FA on every protected request
   - Store 2FA state in secure server-side sessions

2. **Rate Limiting**
   - Implement strict rate limits (5 attempts/minute)
   - Add exponential backoff
   - Account lockout after 10 failed attempts

3. **Secure OTP Validation**
   - Use constant-time comparison
   - Validate OTP length and format
   - Reject empty, null, or obviously invalid codes

4. **Cryptographic Best Practices**
   - Use TOTP (RFC 6238) compliant libraries
   - Hash backup codes before storage
   - Use secure random for code generation

5. **Session Management**
   - Invalidate pre-2FA sessions
   - Require 2FA on sensitive operations
   - Implement device trust properly (cryptographic)

6. **Recovery Procedures**
   - Require identity verification for recovery
   - Support secure backup codes (hashed, single-use)
   - Never bypass 2FA during password reset

7. **Monitoring & Alerting**
   - Log all 2FA events
   - Alert on brute force attempts
   - Notify users of 2FA changes

References:
- OWASP MFA Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html"#.to_string()
            }
        }
    }
}

/// Extract base URL from full URL
fn extract_base_url(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
    } else {
        url.to_string()
    }
}

/// Generate unique ID for vulnerability
fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "2fa_{:08x}{:04x}{:04x}{:04x}{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

/// Deduplicate vulnerabilities by type and URL
fn deduplicate_vulnerabilities(vulnerabilities: Vec<Vulnerability>) -> Vec<Vulnerability> {
    let mut seen = HashSet::new();
    vulnerabilities
        .into_iter()
        .filter(|v| {
            let key = format!("{}:{}", v.vuln_type, v.url);
            seen.insert(key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpResponse;

    fn create_test_scanner() -> TwoFaBypassScanner {
        TwoFaBypassScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()))
    }

    #[test]
    fn test_detect_twofa_method_totp() {
        let scanner = create_test_scanner();
        let body = "Enter your 6-digit code from your authenticator app";
        assert_eq!(scanner.detect_twofa_method(body), TwoFaMethod::Totp);
    }

    #[test]
    fn test_detect_twofa_method_sms() {
        let scanner = create_test_scanner();
        let body = "We sent a text message to your phone number";
        assert_eq!(scanner.detect_twofa_method(body), TwoFaMethod::Sms);
    }

    #[test]
    fn test_detect_twofa_method_email() {
        let scanner = create_test_scanner();
        let body = "Enter the code we sent to your email";
        assert_eq!(scanner.detect_twofa_method(body), TwoFaMethod::Email);
    }

    #[test]
    fn test_check_bypass_success_true() {
        let scanner = create_test_scanner();
        let response = HttpResponse {
            status_code: 200,
            body: "Welcome to your dashboard! Authentication successful.".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        assert!(scanner.check_bypass_success(&response));
    }

    #[test]
    fn test_check_bypass_success_false() {
        let scanner = create_test_scanner();
        let response = HttpResponse {
            status_code: 401,
            body: "Invalid verification code. Please try again.".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        assert!(!scanner.check_bypass_success(&response));
    }

    #[test]
    fn test_detect_rate_limiting() {
        let scanner = create_test_scanner();

        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());

        let response = HttpResponse {
            status_code: 200,
            body: "".to_string(),
            headers,
            duration_ms: 100,
        };

        assert!(scanner.detect_rate_limiting(&response));
    }

    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("https://example.com/path/to/page"),
            "https://example.com"
        );
        assert_eq!(
            extract_base_url("http://test.io:8080/api"),
            "http://test.io:8080"
        );
    }

    #[test]
    fn test_deduplicate_vulnerabilities() {
        let vulns = vec![
            Vulnerability {
                id: "1".to_string(),
                vuln_type: "Test".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Auth".to_string(),
                url: "https://example.com/a".to_string(),
                parameter: None,
                payload: String::new(),
                description: "Desc 1".to_string(),
                evidence: None,
                cwe: "CWE-287".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: String::new(),
                discovered_at: String::new(),
            },
            Vulnerability {
                id: "2".to_string(),
                vuln_type: "Test".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Auth".to_string(),
                url: "https://example.com/a".to_string(), // Same URL
                parameter: None,
                payload: String::new(),
                description: "Desc 2".to_string(),
                evidence: None,
                cwe: "CWE-287".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: String::new(),
                discovered_at: String::new(),
            },
        ];

        let deduped = deduplicate_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 1);
    }
}
