// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::detection_helpers::{endpoint_exists, AppCharacteristics};
/**
 * Bountyy Oy - MFA (Multi-Factor Authentication) Scanner
 * Tests for MFA implementation vulnerabilities and bypasses
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info};

pub struct MfaScanner {
    http_client: Arc<HttpClient>,
}

impl MfaScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // CRITICAL: First detect application characteristics
        // Don't test MFA on SPAs or static sites
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), tests_run)),
        };

        let characteristics = AppCharacteristics::from_response(&response, url);

        // Skip MFA tests if no real authentication or MFA detected
        if characteristics.should_skip_mfa_tests() {
            info!("[MFA] No MFA/authentication detected - skipping MFA tests");
            return Ok((Vec::new(), tests_run));
        }

        // Skip MFA tests on SPAs (they return same HTML for all routes)
        if characteristics.should_skip_injection_tests() {
            info!("[MFA] Site is SPA/static - skipping MFA tests (client-side only)");
            return Ok((Vec::new(), tests_run));
        }

        info!("[MFA] MFA/authentication detected - proceeding with security tests");

        let body_lower = response.body.to_lowercase();

        // Test 1: Check for MFA enforcement (only if auth indicators exist)
        if characteristics.has_authentication {
            self.check_mfa_enforcement(&response, url, &mut vulnerabilities);
        }

        // Test 2: Test for MFA bypass via parameter manipulation (only if MFA is mentioned)
        if characteristics.has_mfa {
            tests_run += 1;
            if let Ok(bypass_response) = self.test_mfa_bypass(url).await {
                self.check_mfa_bypass(&bypass_response, url, &mut vulnerabilities);
            }
        }

        // Test 3-7: Only run endpoint-specific tests if endpoints actually exist
        // CRITICAL: Don't test endpoints that don't exist (SPAs return 200 for everything!)
        let mfa_endpoints = vec![
            (
                format!("{}/mfa/verify", url.trim_end_matches('/')),
                "mfa_verify",
            ),
            (
                format!("{}/2fa/verify", url.trim_end_matches('/')),
                "2fa_verify",
            ),
            (
                format!("{}/auth/mfa", url.trim_end_matches('/')),
                "auth_mfa",
            ),
            (
                format!("{}/mfa/enroll", url.trim_end_matches('/')),
                "mfa_enroll",
            ),
        ];

        for (endpoint_url, _endpoint_type) in &mfa_endpoints {
            tests_run += 1;
            if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                // CRITICAL: Check if endpoint actually exists (not SPA fallback)
                if !endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                    debug!("[MFA] Endpoint {} doesn't exist - skipping", endpoint_url);
                    continue;
                }

                let endpoint_body_lower = endpoint_response.body.to_lowercase();

                // Only test rate limiting if this is actually an MFA verification page
                // MUCH stricter criteria than before!
                let is_mfa_page = (endpoint_body_lower.contains("verification code")
                    || endpoint_body_lower.contains("authenticator app")
                    || endpoint_body_lower.contains("totp"))
                    && (endpoint_body_lower.contains("<form")
                        || endpoint_body_lower.contains("<input"))
                    && (endpoint_response.status_code == 200
                        || endpoint_response.status_code == 401);

                if is_mfa_page {
                    self.check_rate_limiting(
                        &endpoint_response,
                        endpoint_url,
                        &mut vulnerabilities,
                    );
                }
            }
        }

        // Only test SMS MFA if there's evidence of phone-based auth
        if characteristics.has_mfa
            && (body_lower.contains("sms") || body_lower.contains("phone number"))
        {
            tests_run += 1;
            if let Ok(sms_response) = self.test_sms_mfa(url).await {
                self.check_sms_mfa_security(&sms_response, url, &mut vulnerabilities);
            }
        }

        // ADVANCED BYPASS TECHNIQUES - Only run if MFA is detected (PREMIUM FEATURE)
        if characteristics.has_mfa && crate::license::is_feature_available("mfa_bypass_advanced") {
            info!("[MFA] Running advanced bypass technique tests");

            // Test 5: OTP Replay Attack
            for (endpoint_url, _) in &mfa_endpoints {
                tests_run += 1;
                if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                    if endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                        let endpoint_body_lower = endpoint_response.body.to_lowercase();
                        let is_mfa_page = (endpoint_body_lower.contains("verification code")
                            || endpoint_body_lower.contains("authenticator app")
                            || endpoint_body_lower.contains("totp"))
                            && (endpoint_body_lower.contains("<form")
                                || endpoint_body_lower.contains("<input"));

                        if is_mfa_page {
                            if let Ok((replay_vulns, replay_tests)) =
                                self.test_otp_replay_attack(endpoint_url).await
                            {
                                vulnerabilities.extend(replay_vulns);
                                tests_run += replay_tests;
                            }
                        }
                    }
                }
            }

            // Test 6: Parallel Verification Attempts (Race Condition)
            for (endpoint_url, _) in &mfa_endpoints {
                tests_run += 1;
                if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                    if endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                        let endpoint_body_lower = endpoint_response.body.to_lowercase();
                        let is_mfa_page = (endpoint_body_lower.contains("verification code")
                            || endpoint_body_lower.contains("authenticator app")
                            || endpoint_body_lower.contains("totp"))
                            && (endpoint_body_lower.contains("<form")
                                || endpoint_body_lower.contains("<input"));

                        if is_mfa_page {
                            if let Ok((race_vulns, race_tests)) =
                                self.test_parallel_verification(endpoint_url).await
                            {
                                vulnerabilities.extend(race_vulns);
                                tests_run += race_tests;
                            }
                        }
                    }
                }
            }

            // Test 7: OTP Expiration Bypass
            for (endpoint_url, _) in &mfa_endpoints {
                tests_run += 1;
                if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                    if endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                        let endpoint_body_lower = endpoint_response.body.to_lowercase();
                        let is_mfa_page = (endpoint_body_lower.contains("verification code")
                            || endpoint_body_lower.contains("authenticator app")
                            || endpoint_body_lower.contains("totp"))
                            && (endpoint_body_lower.contains("<form")
                                || endpoint_body_lower.contains("<input"));

                        if is_mfa_page {
                            if let Ok((expiry_vulns, expiry_tests)) =
                                self.test_otp_expiration_bypass(endpoint_url).await
                            {
                                vulnerabilities.extend(expiry_vulns);
                                tests_run += expiry_tests;
                            }
                        }
                    }
                }
            }

            // Test 8: Timing-Based OTP Brute Force
            for (endpoint_url, _) in &mfa_endpoints {
                tests_run += 1;
                if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                    if endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                        let endpoint_body_lower = endpoint_response.body.to_lowercase();
                        let is_mfa_page = (endpoint_body_lower.contains("verification code")
                            || endpoint_body_lower.contains("authenticator app")
                            || endpoint_body_lower.contains("totp"))
                            && (endpoint_body_lower.contains("<form")
                                || endpoint_body_lower.contains("<input"));

                        if is_mfa_page {
                            if let Ok((brute_vulns, brute_tests)) =
                                self.test_timing_based_brute_force(endpoint_url).await
                            {
                                vulnerabilities.extend(brute_vulns);
                                tests_run += brute_tests;
                            }
                        }
                    }
                }
            }

            // Test 9: Backup Code Enumeration
            let backup_endpoints = vec![
                format!("{}/mfa/backup", url.trim_end_matches('/')),
                format!("{}/2fa/recovery", url.trim_end_matches('/')),
                format!("{}/auth/recovery", url.trim_end_matches('/')),
            ];

            for backup_endpoint in &backup_endpoints {
                tests_run += 1;
                if let Ok(endpoint_response) = self.http_client.get(backup_endpoint).await {
                    if endpoint_exists(&endpoint_response, &[200, 401, 403]) {
                        if let Ok((backup_enum_vulns, backup_enum_tests)) =
                            self.test_backup_code_enumeration(backup_endpoint).await
                        {
                            vulnerabilities.extend(backup_enum_vulns);
                            tests_run += backup_enum_tests;
                        }
                    }
                }
            }
        }

        // Deduplicate vulnerabilities by type
        // Multiple MFA endpoints might trigger the same vulnerability type
        let mut seen_types = HashSet::new();
        let unique_vulns: Vec<Vulnerability> = vulnerabilities
            .into_iter()
            .filter(|v| {
                let key = format!(
                    "{}:{}",
                    v.vuln_type,
                    v.parameter.as_ref().unwrap_or(&String::new())
                );
                seen_types.insert(key)
            })
            .collect();

        Ok((unique_vulns, tests_run))
    }

    fn check_mfa_enforcement(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if MFA is mentioned but not enforced
        let has_mfa_mention = body_lower.contains("two-factor")
            || body_lower.contains("2fa")
            || body_lower.contains("mfa")
            || body_lower.contains("multi-factor")
            || body_lower.contains("authenticator");

        let has_optional_indicators = body_lower.contains("optional")
            || body_lower.contains("skip")
            || body_lower.contains("later")
            || body_lower.contains("remind me");

        if has_mfa_mention && has_optional_indicators {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Weak MFA Enforcement".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Multi-Factor Authentication is not enforced. Users can skip or bypass MFA setup, leaving accounts vulnerable to credential theft.".to_string(),
                evidence: Some("MFA appears to be optional or can be skipped".to_string()),
                cwe: "CWE-287".to_string(),
                cvss: 7.5,
                verified: false,
                false_positive: false,
                remediation: "1. Enforce MFA for all users, especially privileged accounts\n2. Do not allow users to skip or postpone MFA setup\n3. Implement risk-based MFA for sensitive operations\n4. Use strong MFA methods (TOTP/U2F) over SMS".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Check for missing MFA entirely
        let has_auth_indicators = body_lower.contains("login")
            || body_lower.contains("sign in")
            || body_lower.contains("authentication");

        if has_auth_indicators && !has_mfa_mention {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Multi-Factor Authentication".to_string(),
                severity: Severity::High,
                confidence: Confidence::Low,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "No evidence of Multi-Factor Authentication implementation detected. Single-factor authentication is vulnerable to credential theft, phishing, and brute force attacks.".to_string(),
                evidence: Some("No MFA-related content found in authentication flow".to_string()),
                cwe: "CWE-308".to_string(),
                cvss: 8.1,
                verified: false,
                false_positive: false,
                remediation: "1. Implement MFA using TOTP (RFC 6238) or hardware tokens\n2. Support multiple MFA methods (authenticator app, U2F, WebAuthn)\n3. Enforce MFA for all users, especially administrators\n4. Provide secure MFA enrollment and recovery processes".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    async fn test_mfa_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test common MFA bypass parameters
        let bypass_params = vec![
            "mfa_required=false",
            "skip_mfa=true",
            "bypass_2fa=1",
            "trust_device=true",
            "remember_me=true",
            "mfa_verified=true",
        ];

        let test_url = if url.contains('?') {
            format!("{}&{}", url, bypass_params[0])
        } else {
            format!("{}?{}", url, bypass_params[0])
        };

        self.http_client.get(&test_url).await
    }

    fn check_mfa_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();
        let status = response.status_code;

        // CRITICAL: Be MUCH more strict about bypass detection
        // Generic keywords like "dashboard" and "welcome" are in EVERY SPA!

        // Check for STRONG bypass indicators (session tokens, specific success messages)
        let has_strong_bypass = response
            .headers
            .get("set-cookie")
            .map(|c| c.contains("session") || c.contains("auth_token"))
            .unwrap_or(false)
            || body_lower.contains("authentication successful")
            || body_lower.contains("mfa bypassed")
            || body_lower.contains("\"authenticated\":true");

        let has_mfa_check = body_lower.contains("verification")
            || body_lower.contains("2fa")
            || body_lower.contains("authenticator")
            || body_lower.contains("enter code");

        // Only report if we have STRONG evidence of bypass
        if (status == 200 || status == 302) && has_strong_bypass && !has_mfa_check {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "MFA Bypass Vulnerability".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("mfa_required".to_string()),
                payload: "mfa_required=false".to_string(),
                description: "MFA can be bypassed by manipulating request parameters. Attackers can skip the second authentication factor by modifying client-side parameters.".to_string(),
                evidence: Some(format!("Successful access with status {} without MFA verification", status)),
                cwe: "CWE-288".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation: "1. Enforce MFA server-side, never rely on client parameters\n2. Maintain MFA state in secure server-side sessions\n3. Validate MFA completion before granting access\n4. Use cryptographic tokens for MFA verification\n5. Log and monitor MFA bypass attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    async fn test_totp_weakness(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Test for weak TOTP implementation (sequential codes, predictable patterns)
        let test_url = format!("{}?totp_code=000000", url);
        self.http_client.get(&test_url).await
    }

    fn check_totp_weakness(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for weak TOTP acceptance - require specific API/JSON success patterns
        if body_lower.contains("\"success\":true")
            || body_lower.contains("\"verified\":true")
            || body_lower.contains("\"totp\":\"valid\"")
            || body_lower.contains("code accepted")
        {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Weak TOTP Implementation".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("totp_code".to_string()),
                payload: "000000".to_string(),
                description: "TOTP implementation accepts weak or predictable codes. The application may not be properly validating TOTP codes against RFC 6238 standards.".to_string(),
                evidence: Some("Weak TOTP code accepted".to_string()),
                cwe: "CWE-330".to_string(),
                cvss: 9.1,
                verified: false,
                false_positive: false,
                remediation: "1. Use RFC 6238 compliant TOTP libraries\n2. Enforce 6-8 digit codes with proper time windows\n3. Implement rate limiting on TOTP attempts\n4. Use secure random number generation\n5. Validate time synchronization with NTP".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Check for missing rate limiting
        let error_indicators = vec![
            "invalid".to_string(),
            "incorrect".to_string(),
            "wrong".to_string(),
            "failed".to_string(),
        ];
        let has_error = error_indicators
            .iter()
            .any(|indicator| body_lower.contains(indicator));

        let has_rate_limit = body_lower.contains("too many")
            || body_lower.contains("rate limit")
            || body_lower.contains("slow down")
            || body_lower.contains("locked");

        if has_error && !has_rate_limit {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing TOTP Rate Limiting".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("totp_code".to_string()),
                payload: String::new(),
                description: "No rate limiting detected on TOTP code verification. Attackers can brute force 6-digit TOTP codes (1,000,000 combinations) without restriction.".to_string(),
                evidence: Some("No rate limiting indicators found in error response".to_string()),
                cwe: "CWE-307".to_string(),
                cvss: 8.1,
                verified: false,
                false_positive: false,
                remediation: "1. Implement strict rate limiting (e.g., 3-5 attempts per time window)\n2. Use exponential backoff after failed attempts\n3. Lock account after multiple failures\n4. Log and alert on brute force attempts\n5. Consider using longer codes or U2F for high-security accounts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    async fn test_backup_codes(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}?backup_code=ABCD-1234-EFGH-5678", url);
        self.http_client.get(&test_url).await
    }

    fn check_backup_code_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for backup code exposure in response
        let backup_code_regex =
            Regex::new(r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}").unwrap();
        let has_exposed_codes = backup_code_regex.is_match(body);

        if has_exposed_codes && (body_lower.contains("backup") || body_lower.contains("recovery")) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Exposed MFA Backup Codes".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "MFA backup codes are exposed in the response. These codes should only be shown once during generation and never displayed again.".to_string(),
                evidence: Some("Backup codes found in response body".to_string()),
                cwe: "CWE-200".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "1. Show backup codes only once during generation\n2. Hash backup codes before storage (like passwords)\n3. Require authentication to regenerate backup codes\n4. Limit number of backup codes (e.g., 10)\n5. Invalidate backup codes after use\n6. Log backup code usage for security monitoring".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Check for reusable backup codes
        if body_lower.contains("reusable") || body_lower.contains("unlimited") {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Reusable MFA Backup Codes".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("backup_code".to_string()),
                payload: String::new(),
                description: "MFA backup codes appear to be reusable. Backup codes should be single-use to prevent replay attacks.".to_string(),
                evidence: Some("Indicators of reusable backup codes found".to_string()),
                cwe: "CWE-294".to_string(),
                cvss: 7.3,
                verified: false,
                false_positive: false,
                remediation: "1. Make backup codes single-use only\n2. Invalidate codes immediately after use\n3. Generate new codes when regenerating\n4. Track code usage in audit logs\n5. Alert users when backup codes are used".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    async fn test_mfa_enrollment(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}/mfa/enroll", url);
        self.http_client.get(&test_url).await
    }

    fn check_enrollment_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for QR code secret exposure
        let secret_regex = Regex::new(r"secret=([A-Z2-7]{16,})").unwrap();
        if let Some(capture) = secret_regex.captures(body) {
            if let Some(secret) = capture.get(1) {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Exposed TOTP Secret Key".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authentication".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: format!(
                        "TOTP secret key is exposed in the response. This allows attackers to generate valid MFA codes. Secret: {}...",
                        &secret.as_str()[..8]
                    ),
                    evidence: Some("TOTP secret found in otpauth:// URI".to_string()),
                    cwe: "CWE-522".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Never expose TOTP secrets in URLs or response bodies\n2. Use QR codes rendered server-side as images\n3. Ensure QR code URLs require authentication\n4. Implement proper access controls on enrollment endpoints\n5. Use HTTPS for all MFA enrollment flows\n6. Rotate secrets if exposure is detected".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        // Check for unauthenticated enrollment
        let status = response.status_code;
        if status == 200 && !body_lower.contains("login") && !body_lower.contains("unauthorized") {
            let has_enrollment = body_lower.contains("enroll")
                || body_lower.contains("setup")
                || body_lower.contains("qr code");

            if has_enrollment {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Unauthenticated MFA Enrollment".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    category: "Authentication".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "MFA enrollment endpoint accessible without authentication. Attackers could potentially enroll their own MFA devices on victim accounts.".to_string(),
                    evidence: Some("Enrollment page accessible without authentication redirect".to_string()),
                    cwe: "CWE-306".to_string(),
                    cvss: 8.1,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Require authentication before MFA enrollment\n2. Verify user identity before allowing MFA changes\n3. Send email/SMS notifications on MFA changes\n4. Require password re-entry for MFA operations\n5. Implement CSRF protection on enrollment endpoints".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }
    }

    async fn test_mfa_rate_limiting(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Try multiple failed attempts rapidly
        let test_url = format!("{}?totp_code=123456", url);
        self.http_client.get(&test_url).await
    }

    fn check_rate_limiting(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if rate limiting headers are present
        let has_rate_limit_header = response.headers.contains_key("x-ratelimit-limit")
            || response.headers.contains_key("ratelimit-limit")
            || response.headers.contains_key("retry-after");

        let has_rate_limit_message = body_lower.contains("rate limit")
            || body_lower.contains("too many attempts")
            || body_lower.contains("slow down");

        if !has_rate_limit_header && !has_rate_limit_message {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing MFA Rate Limiting".to_string(),
                severity: Severity::High,
                confidence: Confidence::Low,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "No rate limiting detected on MFA verification endpoint. Attackers can brute force MFA codes without restriction.".to_string(),
                evidence: Some("No rate limit headers or messages in response".to_string()),
                cwe: "CWE-307".to_string(),
                cvss: 7.5,
                verified: false,
                false_positive: false,
                remediation: "1. Implement aggressive rate limiting (3-5 attempts per minute)\n2. Use exponential backoff after failures\n3. Implement account lockout after excessive failures\n4. Add CAPTCHA after failed attempts\n5. Log and monitor brute force attempts\n6. Consider IP-based blocking for distributed attacks".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    async fn test_sms_mfa(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = format!("{}?mfa_method=sms", url);
        self.http_client.get(&test_url).await
    }

    fn check_sms_mfa_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check if SMS is the primary MFA method
        let has_sms_mfa = body_lower.contains("sms")
            || body_lower.contains("text message")
            || body_lower.contains("phone verification");

        let has_secure_alternatives = body_lower.contains("authenticator")
            || body_lower.contains("totp")
            || body_lower.contains("hardware token")
            || body_lower.contains("u2f")
            || body_lower.contains("webauthn");

        if has_sms_mfa && !has_secure_alternatives {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Weak MFA Method (SMS)".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("mfa_method".to_string()),
                payload: String::new(),
                description: "SMS-based MFA is vulnerable to SIM swapping, SS7 attacks, and interception. NIST recommends against SMS for authentication.".to_string(),
                evidence: Some("SMS appears to be primary or only MFA method".to_string()),
                cwe: "CWE-287".to_string(),
                cvss: 6.5,
                verified: false,
                false_positive: false,
                remediation: "1. Prefer TOTP (RFC 6238) or hardware tokens over SMS\n2. Support WebAuthn/FIDO2 for phishing-resistant MFA\n3. If using SMS, also offer authenticator apps\n4. Educate users about SMS security risks\n5. Implement fraud detection for SIM swap attempts\n6. Use push notifications as an alternative to SMS".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Check for phone number exposure
        let phone_regex = Regex::new(r"\+?1?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}").unwrap();
        if phone_regex.is_match(body) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Phone Number Information Disclosure".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description: "Full phone numbers are exposed in the response. This information can be used for social engineering or targeted attacks.".to_string(),
                evidence: Some("Full phone number found in response".to_string()),
                cwe: "CWE-200".to_string(),
                cvss: 4.3,
                verified: true,
                false_positive: false,
                remediation: "1. Mask phone numbers (e.g., show only last 4 digits: ***-***-1234)\n2. Only show full numbers to authenticated account owners\n3. Implement proper access controls on user data\n4. Use secure communication channels for PII".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }
    }

    // ==================== ADVANCED BYPASS TECHNIQUES ====================

    /// Test 1: OTP Replay Attack
    /// Simulates capturing an OTP and replaying it after initial use
    /// CRITICAL: Only reports if OTP is actually reusable (confirmed bypass)
    async fn test_otp_replay_attack(&self, endpoint: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3; // Initial attempt, first replay, second replay

        debug!("[MFA] Testing OTP replay attack on {}", endpoint);

        // Generate a test OTP (simulating a captured code)
        let test_otp = "123456";
        let test_data = format!("code={}", test_otp);

        // First attempt: Submit the OTP
        let first_response = match self.http_client.post_form(endpoint, &test_data).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let first_body_lower = first_response.body.to_lowercase();

        // Check if first submission was successful or at least processed
        let first_processed = first_response.status_code == 200
            || first_response.status_code == 302
            || first_body_lower.contains("incorrect")
            || first_body_lower.contains("invalid");

        if !first_processed {
            return Ok((vulnerabilities, tests_run));
        }

        // Small delay to simulate time passing
        sleep(Duration::from_millis(100)).await;

        // Second attempt: Replay the same OTP
        let replay_response = match self.http_client.post_form(endpoint, &test_data).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let replay_body_lower = replay_response.body.to_lowercase();

        // CRITICAL: Only report if replay was SUCCESSFUL (not rejected)
        let replay_successful = (replay_response.status_code == 200
            || replay_response.status_code == 302)
            && (replay_body_lower.contains("success")
                || replay_body_lower.contains("verified")
                || replay_body_lower.contains("authenticated")
                || replay_body_lower.contains("correct")
                || replay_response.headers.contains_key("set-cookie"));

        // Make sure it's not just accepting invalid codes in general
        let not_error = !replay_body_lower.contains("incorrect")
            && !replay_body_lower.contains("invalid")
            && !replay_body_lower.contains("wrong")
            && !replay_body_lower.contains("failed");

        if replay_successful && not_error {
            // Third attempt to confirm replayability
            sleep(Duration::from_millis(100)).await;
            let second_replay = match self.http_client.post_form(endpoint, &test_data).await {
                Ok(r) => r,
                Err(_) => return Ok((vulnerabilities, tests_run)),
            };

            let second_replay_lower = second_replay.body.to_lowercase();
            let second_replay_successful = (second_replay.status_code == 200
                || second_replay.status_code == 302)
                && (second_replay_lower.contains("success")
                    || second_replay_lower.contains("verified"));

            // Only report if BOTH replays succeeded (confirmed vulnerability)
            if second_replay_successful {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "OTP Replay Attack Vulnerability".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authentication".to_string(),
                    url: endpoint.to_string(),
                    parameter: Some("code".to_string()),
                    payload: test_otp.to_string(),
                    description: "OTP codes can be replayed multiple times. A captured OTP remains valid after initial use, allowing attackers to reuse intercepted codes. This completely defeats the purpose of MFA.".to_string(),
                    evidence: Some("Same OTP successfully verified multiple times (3 consecutive attempts)".to_string()),
                    cwe: "CWE-294".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Invalidate OTP immediately after first use\n2. Store used OTPs in a cache with TTL matching code validity period\n3. Check if code was previously used before verification\n4. For TOTP: track last successful timestamp to prevent replay\n5. For email/SMS OTP: mark as consumed in database\n6. Implement nonce or session-specific codes\n7. Log all OTP verification attempts for monitoring".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test 2: Parallel Verification Attempts (Race Condition)
    /// Tests if same OTP can be used simultaneously from multiple sessions
    /// This is a critical race condition vulnerability
    async fn test_parallel_verification(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5; // 5 concurrent attempts

        debug!(
            "[MFA] Testing parallel verification race condition on {}",
            endpoint
        );

        let test_otp = "654321";
        let test_data = format!("code={}", test_otp);

        // Launch 5 concurrent verification requests with the same OTP
        let mut handles = Vec::new();
        for i in 0..5 {
            let client = self.http_client.clone();
            let endpoint_clone = endpoint.to_string();
            let data_clone = test_data.clone();

            let handle = tokio::spawn(async move {
                debug!("[MFA] Parallel attempt {} starting", i);
                client.post_form(&endpoint_clone, &data_clone).await
            });

            handles.push(handle);
        }

        // Collect all results
        let mut successful_verifications = 0;
        let mut responses = Vec::new();

        for handle in handles {
            if let Ok(Ok(response)) = handle.await {
                responses.push(response);
            }
        }

        // Count how many were successful
        for response in &responses {
            let body_lower = response.body.to_lowercase();
            // Require specific MFA success patterns, not bare "success"/"verified"
            let is_success = (response.status_code == 200 || response.status_code == 302)
                && (body_lower.contains("\"success\":true")
                    || body_lower.contains("\"verified\":true")
                    || body_lower.contains("\"authenticated\":true")
                    || body_lower.contains("verification successful")
                    || body_lower.contains("code accepted"));

            let not_error = !body_lower.contains("incorrect")
                && !body_lower.contains("invalid")
                && !body_lower.contains("wrong");

            if is_success && not_error {
                successful_verifications += 1;
            }
        }

        // CRITICAL: Only report if multiple parallel verifications succeeded
        // This means the same OTP was accepted more than once simultaneously
        if successful_verifications >= 2 {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "MFA Race Condition - Parallel Verification".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: endpoint.to_string(),
                parameter: Some("code".to_string()),
                payload: test_otp.to_string(),
                description: format!(
                    "Race condition allows same OTP to be verified multiple times in parallel. {} out of 5 concurrent requests succeeded with the same code. Attackers can abuse this to authenticate multiple sessions with a single intercepted OTP.",
                    successful_verifications
                ),
                evidence: Some(format!("{} parallel verifications succeeded with identical OTP", successful_verifications)),
                cwe: "CWE-367".to_string(),
                cvss: 9.1,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Implement atomic OTP validation with distributed locking\n2. Use database transactions with row-level locking\n3. Check and mark OTP as used in a single atomic operation\n4. Implement Redis-based distributed locks for clustered environments\n5. Add request deduplication based on session + code hash\n6. Use optimistic locking with version numbers\n7. Reject subsequent attempts if code validation is in progress\n8. Add unique constraint on (user_id, code, timestamp) in database".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test 3: OTP Expiration Bypass
    /// Tests if the application properly validates OTP expiration
    /// Simulates using an OTP after it should have expired
    async fn test_otp_expiration_bypass(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[MFA] Testing OTP expiration bypass on {}", endpoint);

        // Test with timestamps that should be expired
        // TOTP codes typically expire every 30 seconds
        let expired_scenarios = vec![
            ("timestamp", "-300"),                  // 5 minutes ago
            ("timestamp", "-600"),                  // 10 minutes ago
            ("valid_until", "0"),                   // Already expired
            ("expires_at", "2020-01-01T00:00:00Z"), // Long expired
        ];

        for (param, value) in &expired_scenarios {
            tests_run += 1;

            let test_data = format!("code=123456&{}={}", param, value);

            match self.http_client.post_form(endpoint, &test_data).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check if expired code was accepted
                    let accepted = (response.status_code == 200 || response.status_code == 302)
                        && (body_lower.contains("success")
                            || body_lower.contains("verified")
                            || body_lower.contains("authenticated"));

                    let not_expired_error = !body_lower.contains("expired")
                        && !body_lower.contains("invalid")
                        && !body_lower.contains("timeout");

                    if accepted && not_expired_error {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "OTP Expiration Bypass".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: endpoint.to_string(),
                            parameter: Some(param.to_string()),
                            payload: format!("{}={}", param, value),
                            description: "OTP expiration is not properly validated. The application accepts codes that should have expired, extending the window for attackers to use intercepted codes.".to_string(),
                            evidence: Some(format!("Expired OTP accepted with {}={}", param, value)),
                            cwe: "CWE-613".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Validate OTP expiration server-side\n2. For TOTP: verify code is within acceptable time window (±1 period)\n3. For email/SMS OTP: enforce strict expiration (e.g., 5-10 minutes)\n4. Never trust client-provided timestamps\n5. Use server time for all expiration checks\n6. Invalidate codes immediately after use\n7. Implement maximum lifetime for all OTP types\n8. Log attempts to use expired codes".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break; // Found the vulnerability, no need to test more scenarios
                    }
                }
                Err(_) => continue,
            }
        }

        // Also test if server accepts manipulated TOTP window
        tests_run += 1;
        let window_test = "code=000000&time_step=999999"; // Extremely large time window

        match self.http_client.post_form(endpoint, window_test).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();
                if (response.status_code == 200 || response.status_code == 302)
                    && !body_lower.contains("invalid")
                    && !body_lower.contains("incorrect")
                {
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "TOTP Time Window Manipulation".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "Authentication".to_string(),
                        url: endpoint.to_string(),
                        parameter: Some("time_step".to_string()),
                        payload: "time_step=999999".to_string(),
                        description: "TOTP time window can be manipulated by the client. Attackers can extend the validity period of TOTP codes indefinitely.".to_string(),
                        evidence: Some("Server accepted client-provided time_step parameter".to_string()),
                        cwe: "CWE-20".to_string(),
                        cvss: 7.8,
                        verified: false,
                        false_positive: false,
                        remediation: "1. CRITICAL: Never accept time parameters from client\n2. Use fixed server-side TOTP window (typically ±1 period = 60 seconds)\n3. Implement RFC 6238 compliant TOTP validation\n4. Use trusted time source (NTP)\n5. Reject any client attempts to modify time-related parameters".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }
            }
            Err(_) => {}
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test 4: Timing-Based OTP Brute Force
    /// Tests rate limiting and timing analysis for OTP brute force
    /// Attempts rapid-fire OTP submissions to detect missing rate limits
    async fn test_timing_based_brute_force(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[MFA] Testing timing-based OTP brute force on {}", endpoint);

        let mut response_times = Vec::new();
        let mut successful_attempts = 0;
        let attempt_count = 15; // Test 15 rapid attempts

        let start_time = Instant::now();

        for i in 0..attempt_count {
            tests_run += 1;
            let test_code = format!("{:06}", i); // 000000, 000001, 000002, etc.
            let test_data = format!("code={}", test_code);

            let attempt_start = Instant::now();

            match self.http_client.post_form(endpoint, &test_data).await {
                Ok(response) => {
                    let attempt_duration = attempt_start.elapsed();
                    response_times.push(attempt_duration.as_millis());

                    let body_lower = response.body.to_lowercase();

                    // Check for rate limiting
                    let is_rate_limited = response.status_code == 429
                        || body_lower.contains("rate limit")
                        || body_lower.contains("too many")
                        || body_lower.contains("slow down");

                    // If we hit rate limiting, that's good (not vulnerable)
                    if is_rate_limited {
                        debug!("[MFA] Rate limiting detected at attempt {}", i + 1);
                        break;
                    }

                    // Check if attempt went through (successful or failed, but processed)
                    if response.status_code == 200
                        || response.status_code == 400
                        || response.status_code == 401
                    {
                        successful_attempts += 1;
                    }
                }
                Err(_) => break,
            }

            // Small delay to avoid overwhelming the server
            sleep(Duration::from_millis(50)).await;
        }

        let total_time = start_time.elapsed();

        // CRITICAL: Only report if we could make many attempts without rate limiting
        if successful_attempts >= 10 {
            // Calculate average response time for timing analysis
            let avg_response_time = if !response_times.is_empty() {
                response_times.iter().sum::<u128>() / response_times.len() as u128
            } else {
                0
            };

            // Check for timing attack vulnerability
            let timing_variance = if response_times.len() > 1 {
                let mean = avg_response_time;
                let variance = response_times
                    .iter()
                    .map(|&t| {
                        let diff = if t > mean { t - mean } else { mean - t };
                        diff * diff
                    })
                    .sum::<u128>()
                    / response_times.len() as u128;
                variance
            } else {
                0
            };

            // Report missing rate limiting
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Missing Rate Limiting - OTP Brute Force".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: endpoint.to_string(),
                parameter: Some("code".to_string()),
                payload: String::new(),
                description: format!(
                    "No rate limiting on OTP verification. Successfully submitted {} verification attempts in {:.2} seconds. For 6-digit codes (1,000,000 combinations), this would allow brute force in approximately {:.1} hours.",
                    successful_attempts,
                    total_time.as_secs_f32(),
                    (1_000_000.0 / successful_attempts as f32) * total_time.as_secs_f32() / 3600.0
                ),
                evidence: Some(format!("{} OTP attempts processed without rate limiting (avg response: {}ms)", successful_attempts, avg_response_time)),
                cwe: "CWE-307".to_string(),
                cvss: 9.1,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Implement strict rate limiting (3-5 attempts per session)\n2. Lock account after 5-10 failed attempts\n3. Require account recovery process after lockout\n4. Implement exponential backoff (delay increases with failures)\n5. Add CAPTCHA after 3 failed attempts\n6. Use longer OTP codes (8+ digits) for high-security accounts\n7. Implement IP-based rate limiting\n8. Monitor and alert on brute force patterns\n9. Consider adaptive authentication (step-up security)".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });

            // Report timing attack if significant variance detected
            if timing_variance > 1000 {
                // More than 1000ms² variance
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Timing Attack - OTP Validation".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    category: "Authentication".to_string(),
                    url: endpoint.to_string(),
                    parameter: Some("code".to_string()),
                    payload: String::new(),
                    description: format!(
                        "Response time variance detected in OTP validation (variance: {}ms²). This may allow timing attacks to distinguish correct vs incorrect codes.",
                        timing_variance
                    ),
                    evidence: Some(format!("Timing variance: {}ms², average response: {}ms", timing_variance, avg_response_time)),
                    cwe: "CWE-208".to_string(),
                    cvss: 5.3,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Use constant-time comparison for OTP validation\n2. Add random delay to normalize response times\n3. Always perform full validation even if early mismatch detected\n4. Hash codes before comparison if possible\n5. Implement response time monitoring\n6. Use timing-safe comparison functions".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test 5: Backup Code Enumeration
    /// Tests if backup codes follow predictable patterns
    /// Attempts to identify weak code generation that could be enumerated
    async fn test_backup_code_enumeration(
        &self,
        endpoint: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[MFA] Testing backup code enumeration on {}", endpoint);

        // Test common weak patterns in backup codes
        let timestamp_pattern = format!("{}-0001", chrono::Utc::now().format("%Y%m%d"));

        let weak_patterns = vec![
            // Sequential patterns
            "ABCD-EFGH-IJKL-MNOP",
            "1234-5678-9012-3456",
            "0000-0000-0000-0001",
            "1111-1111-1111-1111",
            // Common patterns
            "AAAA-BBBB-CCCC-DDDD",
            "0123-4567-8901-2345",
            // Timestamp-based (if using current date)
            timestamp_pattern.as_str(),
            // Simple incremental
            "CODE-0001-0001-0001",
            "BACK-UP01-CODE-0001",
        ];

        for pattern in &weak_patterns {
            tests_run += 1;
            let test_data = format!("backup_code={}", pattern);

            match self.http_client.post_form(endpoint, &test_data).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    let accepted = (response.status_code == 200 || response.status_code == 302)
                        && (body_lower.contains("success")
                            || body_lower.contains("verified")
                            || body_lower.contains("valid")
                            || body_lower.contains("authenticated"));

                    let not_invalid = !body_lower.contains("invalid")
                        && !body_lower.contains("incorrect")
                        && !body_lower.contains("wrong");

                    if accepted && not_invalid {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "Predictable MFA Backup Codes".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: endpoint.to_string(),
                            parameter: Some("backup_code".to_string()),
                            payload: pattern.to_string(),
                            description: format!(
                                "Backup codes follow predictable patterns. Code '{}' was accepted, indicating weak code generation. Attackers can enumerate valid backup codes.",
                                pattern
                            ),
                            evidence: Some(format!("Predictable backup code accepted: {}", pattern)),
                            cwe: "CWE-330".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Generate backup codes using cryptographically secure random numbers\n2. Use at least 128 bits of entropy per code\n3. Format codes as Base32/Base36 for readability (e.g., XXXX-XXXX-XXXX-XXXX)\n4. Generate 8-12 codes per user\n5. Make codes single-use only\n6. Invalidate all codes when new set is generated\n7. Hash codes before storage (like passwords)\n8. Implement rate limiting on backup code attempts\n9. Alert user when backup codes are used\n10. Example: use crypto.randomBytes(16).toString('base32')".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break; // Found vulnerability, no need to test more
                    }
                }
                Err(_) => continue,
            }
        }

        // Test for pattern-based enumeration vulnerability
        // Check if sequential codes exist by testing a range
        tests_run += 2;
        let base_code = "BACK-UP00-0000-";
        let mut sequential_successes = 0;

        for i in 1..=3 {
            let test_code = format!("{}{:04}", base_code, i);
            let test_data = format!("backup_code={}", test_code);

            if let Ok(response) = self.http_client.post_form(endpoint, &test_data).await {
                let body_lower = response.body.to_lowercase();
                if response.status_code == 200
                    && !body_lower.contains("invalid")
                    && !body_lower.contains("incorrect")
                {
                    sequential_successes += 1;
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        if sequential_successes >= 2 {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Sequential Backup Code Pattern".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Authentication".to_string(),
                url: endpoint.to_string(),
                parameter: Some("backup_code".to_string()),
                payload: base_code.to_string(),
                description: "Backup codes appear to follow a sequential pattern. Multiple codes with sequential numbers were accepted, indicating enumerable codes.".to_string(),
                evidence: Some(format!("{} sequential codes accepted", sequential_successes)),
                cwe: "CWE-330".to_string(),
                cvss: 8.1,
                verified: false,
                false_positive: false,
                remediation: "1. CRITICAL: Use cryptographically random code generation\n2. Avoid sequential or predictable patterns\n3. Each code should be independent and random\n4. Implement rate limiting to prevent enumeration\n5. Lock account after multiple failed backup code attempts\n6. Monitor for enumeration patterns".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }
}

fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "mfa_{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    async fn test_missing_mfa() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <html>
                <form action="/login" method="post">
                    <input name="username" />
                    <input name="password" type="password" />
                    <button>Sign In</button>
                </form>
                </html>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_mfa_enforcement(&response, "https://example.com/login", &mut vulns);

        assert!(
            vulns.iter().any(|v| v.vuln_type.contains("Missing")),
            "Should detect missing MFA"
        );
    }

    #[tokio::test]
    async fn test_optional_mfa() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <div>Enable Two-Factor Authentication</div>
                <button id="skip">Skip for now</button>
                <button id="later">Remind me later</button>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_mfa_enforcement(&response, "https://example.com/mfa", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect optional MFA");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn test_mfa_bypass() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <h1>Welcome to Dashboard</h1>
                <div>Logged in successfully</div>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_mfa_bypass(
            &response,
            "https://example.com/auth?mfa_required=false",
            &mut vulns,
        );

        assert_eq!(vulns.len(), 1, "Should detect MFA bypass");
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert!(vulns[0].verified);
    }

    #[tokio::test]
    async fn test_exposed_totp_secret() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <img src="qr-code.png" />
                <p>otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example</p>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_enrollment_security(&response, "https://example.com/mfa/enroll", &mut vulns);

        assert!(
            vulns
                .iter()
                .any(|v| v.vuln_type.contains("Exposed TOTP Secret")),
            "Should detect exposed TOTP secret"
        );
        assert!(vulns.iter().any(|v| v.severity == Severity::Critical));
    }

    #[tokio::test]
    async fn test_sms_mfa_weakness() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <div>We'll send a verification code to your phone</div>
                <form>
                    <input name="phone" value="+1-555-123-4567" />
                    <button>Send SMS Code</button>
                </form>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_sms_mfa_security(&response, "https://example.com/mfa", &mut vulns);

        assert!(
            vulns.iter().any(|v| v.vuln_type.contains("SMS")),
            "Should detect SMS MFA weakness"
        );
        assert!(
            vulns.iter().any(|v| v.vuln_type.contains("Phone Number")),
            "Should detect phone number exposure"
        );
    }

    #[tokio::test]
    async fn test_exposed_backup_codes() {
        let scanner = MfaScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <h2>Your Backup Recovery Codes</h2>
                <div>
                    ABCD-1234-EFGH-5678<br>
                    IJKL-9012-MNOP-3456<br>
                    QRST-7890-UVWX-1234
                </div>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_backup_code_security(&response, "https://example.com/mfa/backup", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect exposed backup codes");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
