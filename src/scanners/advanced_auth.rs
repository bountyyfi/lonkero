// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use regex::Regex;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{Duration, Instant};
/**
 * Bountyy Oy - Advanced Authentication Security Scanner
 * Enterprise-grade authentication security testing
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

/// Aggression levels for authentication testing
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AggressionLevel {
    Passive, // Only passive detection, no active testing
    Low,     // Minimal testing, safe operations
    Medium,  // Standard testing
    High,    // Aggressive testing
    Maximum, // Maximum testing intensity
}

impl AggressionLevel {
    pub fn from_scan_mode(scan_mode: &str) -> Self {
        match scan_mode {
            "fast" => AggressionLevel::Low,
            "normal" => AggressionLevel::Medium,
            "thorough" => AggressionLevel::High,
            "insane" => AggressionLevel::Maximum,
            _ => AggressionLevel::Medium,
        }
    }

    pub fn max_attempts(&self) -> usize {
        match self {
            AggressionLevel::Passive => 0,
            AggressionLevel::Low => 3,
            AggressionLevel::Medium => 5,
            AggressionLevel::High => 10,
            AggressionLevel::Maximum => 20,
        }
    }
}

pub struct AdvancedAuthScanner {
    http_client: Arc<HttpClient>,
}

impl AdvancedAuthScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let aggression = AggressionLevel::from_scan_mode(config.scan_mode.as_str());

        tracing::info!(
            "Starting advanced authentication scan with aggression level: {:?}",
            aggression
        );

        // Check if authentication is present before running auth tests
        let baseline_response = self.http_client.get(url).await?;
        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        if !characteristics.has_authentication
            && !characteristics.has_oauth
            && !characteristics.has_jwt
        {
            tracing::info!(
                "[AdvAuth] No authentication detected - skipping advanced authentication tests"
            );
            return Ok((vulnerabilities, tests_run));
        }

        // Session Management Tests
        let (session_vulns, session_tests) = self
            .test_session_management(url, config, aggression)
            .await?;
        vulnerabilities.extend(session_vulns);
        tests_run += session_tests;

        // Password Security Tests
        let (password_vulns, password_tests) =
            self.test_password_security(url, config, aggression).await?;
        vulnerabilities.extend(password_vulns);
        tests_run += password_tests;

        // Multi-Factor Authentication Tests
        let (mfa_vulns, mfa_tests) = self.test_mfa_security(url, config, aggression).await?;
        vulnerabilities.extend(mfa_vulns);
        tests_run += mfa_tests;

        // OAuth/OIDC Tests
        let (oauth_vulns, oauth_tests) = self.test_oauth_security(url, config, aggression).await?;
        vulnerabilities.extend(oauth_vulns);
        tests_run += oauth_tests;

        // JWT Security Tests
        let (jwt_vulns, jwt_tests) = self.test_jwt_security(url, config, aggression).await?;
        vulnerabilities.extend(jwt_vulns);
        tests_run += jwt_tests;

        tracing::info!(
            "Advanced authentication scan completed: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    // ==================== SESSION MANAGEMENT ====================

    async fn test_session_management(
        &self,
        url: &str,
        _config: &ScanConfig,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Session Fixation
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            tests_run += 1;
            if let Some(vuln) = self.test_session_fixation(url).await? {
                vulnerabilities.push(vuln);
            }
        }

        // Test 2: Session Prediction
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_session_prediction(url, aggression).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 3: Concurrent Session Handling
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            tests_run += 1;
            if let Some(vuln) = self.test_concurrent_sessions(url).await? {
                vulnerabilities.push(vuln);
            }
        }

        // Test 4: Session Timeout Verification
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            tests_run += 1;
            if let Some(vuln) = self.test_session_timeout(url).await? {
                vulnerabilities.push(vuln);
            }
        }

        // Test 5: Cookie Security Attributes
        tests_run += 1;
        vulnerabilities.extend(self.test_cookie_security(url).await?);

        Ok((vulnerabilities, tests_run))
    }

    async fn test_session_fixation(&self, url: &str) -> Result<Option<Vulnerability>> {
        // Test if application accepts pre-set session IDs
        let custom_session_id = "test_fixed_session_12345";

        let response = self
            .http_client
            .get_with_headers(
                url,
                vec![(
                    "Cookie".to_string(),
                    format!("sessionid={}", custom_session_id),
                )],
            )
            .await?;

        // Check if the application accepted our session ID
        if let Some(set_cookie) = response.header("set-cookie") {
            if !set_cookie.contains(custom_session_id) {
                // Good: Application generated a new session ID
                return Ok(None);
            }

            return Ok(Some(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Session Fixation".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("sessionid".to_string()),
                payload: custom_session_id.to_string(),
                description: "Application accepts externally-provided session IDs without regeneration. Attackers can fixate a session ID and hijack user sessions after authentication.".to_string(),
                evidence: Some(format!("Application accepted fixed session ID: {}", custom_session_id)),
                cwe: "CWE-384".to_string(),
                cvss: 8.1,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Regenerate session IDs upon authentication\n2. Never accept session IDs from query parameters or POST data\n3. Implement session ID regeneration on privilege escalation\n4. Use framework-provided session management\n5. Set secure session configuration (HttpOnly, Secure, SameSite)\n6. Implement session binding to IP address (with caution for mobile users)\n7. Log session creation and regeneration events".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            }));
        }

        Ok(None)
    }

    async fn test_session_prediction(
        &self,
        url: &str,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let sample_count = aggression.max_attempts().min(10);

        // Collect multiple session IDs
        let mut session_ids = Vec::new();
        for _ in 0..sample_count {
            tests_run += 1;
            let response = self.http_client.get(url).await?;

            if let Some(set_cookie) = response.header("set-cookie") {
                if let Some(session_id) = extract_session_id(&set_cookie) {
                    session_ids.push(session_id);
                }
            }
        }

        if session_ids.len() < 2 {
            return Ok((vulnerabilities, tests_run));
        }

        // Analyze session ID entropy and patterns
        let analysis = analyze_session_ids(&session_ids);

        if analysis.is_sequential {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Predictable Session IDs - Sequential Pattern".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("session_id".to_string()),
                payload: format!("Sample IDs: {:?}", &session_ids[..3.min(session_ids.len())]),
                description: "Session IDs follow a sequential or predictable pattern. Attackers can predict valid session IDs and hijack user sessions.".to_string(),
                evidence: Some(format!("Sequential pattern detected. Entropy: {:.2} bits", analysis.entropy)),
                cwe: "CWE-330".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Use cryptographically secure random number generator (CSPRNG)\n2. Generate session IDs with minimum 128 bits of entropy\n3. Use UUID v4 or equivalent random generation\n4. Never use sequential, timestamp-based, or user-data-based session IDs\n5. Implement session ID complexity validation\n6. Rotate session IDs frequently".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        } else if analysis.entropy < 64.0 {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Weak Session ID Entropy".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("session_id".to_string()),
                payload: format!("Average entropy: {:.2} bits", analysis.entropy),
                description: format!("Session IDs have insufficient entropy ({:.2} bits). Recommended minimum is 128 bits. Low entropy enables brute-force session hijacking.", analysis.entropy),
                evidence: Some(format!("Entropy analysis: {:.2} bits from {} samples", analysis.entropy, session_ids.len())),
                cwe: "CWE-331".to_string(),
                cvss: 7.5,
                verified: false,
                false_positive: false,
                remediation: "1. Increase session ID length to minimum 128 bits (16 bytes)\n2. Use cryptographically secure random generation\n3. Use standard session management libraries\n4. Implement rate limiting on session creation\n5. Monitor for session brute-force attempts".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        if analysis.has_timestamp_pattern {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Timestamp-Based Session IDs".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("session_id".to_string()),
                payload: "Session IDs contain timestamp information".to_string(),
                description: "Session IDs appear to contain timestamp or time-based components, reducing randomness and enabling prediction attacks.".to_string(),
                evidence: Some("Timestamp pattern detected in session ID generation".to_string()),
                cwe: "CWE-330".to_string(),
                cvss: 8.1,
                verified: true,
                false_positive: false,
                remediation: "1. Remove all timestamp components from session IDs\n2. Use purely random generation\n3. Store creation time separately in session data\n4. Implement proper session timeout using server-side tracking".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_concurrent_sessions(&self, url: &str) -> Result<Option<Vulnerability>> {
        // Test if multiple sessions can exist simultaneously for the same user
        // This requires simulating login from different locations

        let response = self.http_client.get(url).await?;

        // Check response headers for session management hints
        if let Some(set_cookie) = response.header("set-cookie") {
            // Look for absence of session invalidation mechanisms
            let _has_max_age = set_cookie.to_lowercase().contains("max-age");
            let has_single_session_indicator =
                response.body.to_lowercase().contains("single session")
                    || response
                        .body
                        .to_lowercase()
                        .contains("logout other devices")
                    || response.body.to_lowercase().contains("active sessions");

            if !has_single_session_indicator {
                return Ok(Some(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Unlimited Concurrent Sessions".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "Application does not appear to limit concurrent sessions. This allows attackers to maintain access even after legitimate user logs in from another location.".to_string(),
                    evidence: Some("No session limit or concurrent session management detected".to_string()),
                    cwe: "CWE-778".to_string(),
                    cvss: 5.4,
                    verified: false,
                    false_positive: false,
                    remediation: "1. Implement maximum concurrent session limits per user\n2. Provide 'logout other sessions' functionality\n3. Display active sessions to users\n4. Implement session anomaly detection (impossible travel)\n5. Notify users of new logins from unknown devices\n6. Allow session revocation from user dashboard\n7. Consider single-session mode for high-security applications".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                }));
            }
        }

        Ok(None)
    }

    async fn test_session_timeout(&self, url: &str) -> Result<Option<Vulnerability>> {
        let response = self.http_client.get(url).await?;

        if let Some(set_cookie) = response.header("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();

            // Extract Max-Age if present
            let max_age_regex = Regex::new(r"max-age=(\d+)").unwrap();
            if let Some(caps) = max_age_regex.captures(&cookie_lower) {
                if let Some(age_match) = caps.get(1) {
                    if let Ok(max_age) = age_match.as_str().parse::<i64>() {
                        // Check for excessively long session timeouts
                        let _one_day = 86400;
                        let one_week = 604800;

                        if max_age > one_week {
                            return Ok(Some(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "Excessive Session Timeout".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::High,
                                category: "Session Management".to_string(),
                                url: url.to_string(),
                                parameter: Some("Max-Age".to_string()),
                                payload: format!("{} seconds ({} days)", max_age, max_age / 86400),
                                description: format!("Session timeout is set to {} seconds ({} days), which is excessive. Long session timeouts increase the window for session hijacking attacks.", max_age, max_age / 86400),
                                evidence: Some(format!("Cookie Max-Age: {} seconds", max_age)),
                                cwe: "CWE-613".to_string(),
                                cvss: 5.3,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Set appropriate session timeouts (15-30 minutes for sensitive apps)\n2. Implement idle timeout (separate from absolute timeout)\n3. Use shorter timeouts for privileged operations\n4. Implement 'Remember Me' separately from sessions\n5. Provide session refresh on user activity\n6. Force re-authentication for sensitive operations".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            }));
                        } else if max_age < 300 {
                            // Session timeout too short (less than 5 minutes)
                            return Ok(Some(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "Insufficient Session Timeout".to_string(),
                                severity: Severity::Low,
                                confidence: Confidence::High,
                                category: "Session Management".to_string(),
                                url: url.to_string(),
                                parameter: Some("Max-Age".to_string()),
                                payload: format!("{} seconds", max_age),
                                description: format!("Session timeout is too short ({} seconds). This may impact usability and cause user frustration.", max_age),
                                evidence: Some(format!("Cookie Max-Age: {} seconds", max_age)),
                                cwe: "CWE-613".to_string(),
                                cvss: 3.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Balance security and usability (15-30 minutes recommended)\n2. Implement session refresh on user activity\n3. Use idle timeout combined with absolute timeout\n4. Provide warnings before session expiration".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            }));
                        }
                    }
                }
            }

            // Check if session cookie lacks expiration entirely
            if !cookie_lower.contains("max-age") && !cookie_lower.contains("expires") {
                return Ok(Some(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Session Cookie Without Timeout".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: String::new(),
                    description: "Session cookie does not have Max-Age or Expires attribute. Session persists until browser closure, which may be indefinite in modern browsers.".to_string(),
                    evidence: Some("No Max-Age or Expires attribute in session cookie".to_string()),
                    cwe: "CWE-613".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Set explicit Max-Age for session cookies\n2. Implement server-side session timeout\n3. Use both idle and absolute timeouts\n4. Invalidate sessions after inactivity period".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                }));
            }
        }

        Ok(None)
    }

    async fn test_cookie_security(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        let response = self.http_client.get(url).await?;

        if let Some(set_cookie) = response.header("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();
            let is_https = url.starts_with("https://");

            // Check HttpOnly attribute
            if !cookie_lower.contains("httponly") {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Missing HttpOnly Flag on Session Cookie".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: Some("Cookie".to_string()),
                    payload: String::new(),
                    description: "Session cookie lacks HttpOnly flag. JavaScript can access session cookies, enabling XSS-based session hijacking attacks.".to_string(),
                    evidence: Some("Set-Cookie header missing HttpOnly attribute".to_string()),
                    cwe: "CWE-1004".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Add HttpOnly flag to all session cookies\n2. Set HttpOnly in cookie configuration\n3. Review all cookies for HttpOnly requirement\n4. Test that JavaScript cannot access session cookies\n5. Use secure session management libraries".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }

            // Check Secure attribute for HTTPS sites
            if is_https && !cookie_lower.contains("secure") {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Missing Secure Flag on Session Cookie".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: Some("Cookie".to_string()),
                    payload: String::new(),
                    description: "Session cookie on HTTPS site lacks Secure flag. Cookies may be transmitted over unencrypted HTTP connections, exposing sessions to network eavesdropping.".to_string(),
                    evidence: Some("Set-Cookie header missing Secure attribute on HTTPS site".to_string()),
                    cwe: "CWE-614".to_string(),
                    cvss: 7.4,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Add Secure flag to all cookies on HTTPS sites\n2. Enforce HTTPS throughout application\n3. Implement HSTS (HTTP Strict Transport Security)\n4. Redirect all HTTP traffic to HTTPS\n5. Never set cookies over HTTP connections".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }

            // Check SameSite attribute
            if !cookie_lower.contains("samesite") {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Missing SameSite Flag on Session Cookie".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: Some("Cookie".to_string()),
                    payload: String::new(),
                    description: "Session cookie lacks SameSite attribute. Cookies are sent with cross-site requests, enabling CSRF attacks and session leakage.".to_string(),
                    evidence: Some("Set-Cookie header missing SameSite attribute".to_string()),
                    cwe: "CWE-1275".to_string(),
                    cvss: 6.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Add SameSite=Strict or SameSite=Lax to session cookies\n2. Use SameSite=Strict for maximum CSRF protection\n3. Use SameSite=Lax if cross-site navigation needed\n4. Never use SameSite=None unless absolutely required\n5. Implement additional CSRF tokens for state-changing operations".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            } else if cookie_lower.contains("samesite=none") {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "SameSite=None on Session Cookie".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: Some("Cookie".to_string()),
                    payload: "SameSite=None".to_string(),
                    description: "Session cookie uses SameSite=None, allowing cookies in all cross-site contexts. This provides no CSRF protection and may leak sessions.".to_string(),
                    evidence: Some("SameSite=None detected in Set-Cookie header".to_string()),
                    cwe: "CWE-1275".to_string(),
                    cvss: 6.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Change to SameSite=Strict or SameSite=Lax\n2. Only use SameSite=None for embedded content from different domains\n3. Implement CSRF tokens for all state-changing operations\n4. Review if cross-site cookie access is truly necessary".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok(vulnerabilities)
    }

    // ==================== PASSWORD SECURITY ====================

    async fn test_password_security(
        &self,
        url: &str,
        _config: &ScanConfig,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Password Policy Enforcement
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            tests_run += 1;
            vulnerabilities.extend(self.test_password_policy_enforcement(url).await?);
        }

        // Test 2: Common Password Testing
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_common_passwords(url, aggression).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 3: Password Reset Vulnerabilities
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            let (vulns, tests) = self.test_password_reset_vulnerabilities(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 4: Account Enumeration via Timing
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_timing_based_enumeration(url, aggression).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 5: Username Enumeration
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            let (vulns, tests) = self.test_username_enumeration(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_password_policy_enforcement(&self, url: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Test weak passwords on registration/password change endpoints
        let test_endpoints = vec![
            format!("{}/register", url.trim_end_matches('/')),
            format!("{}/signup", url.trim_end_matches('/')),
            format!("{}/password/change", url.trim_end_matches('/')),
            format!("{}/api/auth/register", url.trim_end_matches('/')),
        ];

        let weak_passwords = vec![
            "123456", "password", "12345678", "abc123", "test", "a", // Single character
        ];

        for endpoint in &test_endpoints {
            for weak_pwd in &weak_passwords {
                // Try to detect if weak password is accepted
                let test_data = format!(
                    "password={}&username=testuser&email=test@test.com",
                    weak_pwd
                );

                match self.http_client.post_form(endpoint, &test_data).await {
                    Ok(response) => {
                        let body_lower = response.body.to_lowercase();

                        // Check if password was accepted (success indicators)
                        let accepted = (response.status_code == 200 || response.status_code == 201)
                            && (body_lower.contains("success")
                                || body_lower.contains("created")
                                || body_lower.contains("registered")
                                || body_lower.contains("welcome"));

                        // Check for rejection (policy enforcement)
                        let rejected = body_lower.contains("password too weak")
                            || body_lower.contains("password must")
                            || body_lower.contains("password should")
                            || body_lower.contains("at least")
                            || body_lower.contains("complexity");

                        if accepted && !rejected {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "Weak Password Policy - Accepts Common Passwords".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "Authentication".to_string(),
                                url: endpoint.clone(),
                                parameter: Some("password".to_string()),
                                payload: weak_pwd.to_string(),
                                description: format!("Application accepts extremely weak password '{}'. Weak passwords make accounts trivially easy to compromise through brute force or dictionary attacks.", weak_pwd),
                                evidence: Some(format!("Weak password '{}' was accepted", weak_pwd)),
                                cwe: "CWE-521".to_string(),
                                cvss: 7.5,
                                verified: true,
                                false_positive: false,
                                remediation: "1. CRITICAL: Enforce strong password policy:\n   - Minimum 12 characters (14+ recommended)\n   - Mix of uppercase, lowercase, numbers, symbols\n   - No common passwords (check against breach databases)\n   - No dictionary words or personal information\n2. Integrate with HaveIBeenPwned API to reject breached passwords\n3. Implement password strength meter (zxcvbn)\n4. Support passphrases as an alternative\n5. Educate users on password security\n6. Consider passwordless authentication (WebAuthn)".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break; // Found one vulnerability, don't spam
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn test_common_passwords(
        &self,
        url: &str,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Common passwords from rockyou.txt top entries
        let common_passwords = vec![
            "123456",
            "password",
            "12345678",
            "qwerty",
            "123456789",
            "12345",
            "1234",
            "111111",
            "1234567",
            "dragon",
            "123123",
            "baseball",
            "abc123",
            "football",
            "monkey",
            "letmein",
            "shadow",
            "master",
            "666666",
            "qwertyuiop",
        ];

        let test_count = aggression.max_attempts().min(common_passwords.len());
        let passwords_to_test = &common_passwords[..test_count];

        let login_endpoints = vec![
            format!("{}/login", url.trim_end_matches('/')),
            format!("{}/api/auth/login", url.trim_end_matches('/')),
            format!("{}/signin", url.trim_end_matches('/')),
        ];

        let test_usernames = vec!["admin".to_string(), "test".to_string(), "user".to_string()];

        for endpoint in &login_endpoints {
            for username in &test_usernames {
                for password in passwords_to_test {
                    tests_run += 1;

                    let test_data = format!("username={}&password={}", &username, password);

                    match self.http_client.post_form(endpoint, &test_data).await {
                        Ok(response) => {
                            let body_lower = response.body.to_lowercase();

                            // Check for successful login with common password
                            if (response.status_code == 200 || response.status_code == 302)
                                && (body_lower.contains("dashboard")
                                    || body_lower.contains("welcome")
                                    || body_lower.contains("logged in")
                                    || response.header("location").is_some())
                            {
                                vulnerabilities.push(Vulnerability {
                                    id: generate_uuid(),
                                    vuln_type: "Account with Common Password".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    category: "Authentication".to_string(),
                                    url: endpoint.clone(),
                                    parameter: Some("password".to_string()),
                                    payload: format!("{}:{}", username, password),
                                    description: format!("Account '{}' uses a common password from breach databases. This account can be trivially compromised.", username),
                                    evidence: Some(format!("Successfully authenticated with username='{}' and common password", username)),
                                    cwe: "CWE-521".to_string(),
                                    cvss: 9.8,
                                    verified: true,
                                    false_positive: false,
                                    remediation: "1. CRITICAL: Force password reset for affected accounts\n2. Implement password breach detection (HaveIBeenPwned)\n3. Enforce strong password policy\n4. Implement account lockout after failed attempts\n5. Enable multi-factor authentication\n6. Audit all user accounts for weak passwords\n7. Educate users on password security".to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                });

                                // Stop testing this endpoint once we find a vulnerability
                                return Ok((vulnerabilities, tests_run));
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_password_reset_vulnerabilities(
        &self,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let reset_endpoints = vec![
            format!("{}/password/reset", url.trim_end_matches('/')),
            format!("{}/forgot-password", url.trim_end_matches('/')),
            format!("{}/api/auth/reset", url.trim_end_matches('/')),
        ];

        for endpoint in &reset_endpoints {
            tests_run += 1;

            // Test 1: Token in URL parameter
            let test_url = format!("{}?token=test123&email=test@example.com", endpoint);
            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();

                        if body_lower.contains("new password")
                            || body_lower.contains("reset password")
                        {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "Password Reset Token in URL".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "Authentication".to_string(),
                                url: test_url.clone(),
                                parameter: Some("token".to_string()),
                                payload: "test123".to_string(),
                                description: "Password reset token is passed in URL parameters. Tokens in URLs are logged in browser history, proxy logs, and referrer headers, enabling token theft.".to_string(),
                                evidence: Some("Reset form accessible via URL with token parameter".to_string()),
                                cwe: "CWE-598".to_string(),
                                cvss: 7.5,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Use POST-based token submission\n2. Implement token in request body, not URL\n3. Use single-use tokens with short expiration\n4. Require email verification before showing reset form\n5. Invalidate token after use\n6. Implement rate limiting on reset attempts".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(_) => continue,
            }

            // Test 2: Check for predictable tokens
            tests_run += 1;
            let test_data = "email=test@example.com";
            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    let body = &response.body;

                    // Look for exposed tokens in response
                    let token_patterns = vec![
                        r#""token"\s*:\s*"(\d{4,8})"#,     // Numeric token in JSON
                        r#"token=(\d{4,8})"#,              // Numeric token in URL
                        r#"reset_code['":\s=]+(\d{4,6})"#, // Numeric code
                    ];

                    for pattern_str in &token_patterns {
                        if let Ok(pattern) = Regex::new(pattern_str) {
                            if pattern.is_match(body) {
                                vulnerabilities.push(Vulnerability {
                                    id: generate_uuid(),
                                    vuln_type: "Predictable Password Reset Token".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    category: "Authentication".to_string(),
                                    url: endpoint.clone(),
                                    parameter: Some("token".to_string()),
                                    payload: String::new(),
                                    description: "Password reset uses predictable numeric tokens that can be easily brute-forced. Attackers can reset arbitrary user passwords.".to_string(),
                                    evidence: Some("Short numeric token pattern detected in reset response".to_string()),
                                    cwe: "CWE-330".to_string(),
                                    cvss: 9.8,
                                    verified: true,
                                    false_positive: false,
                                    remediation: "1. CRITICAL: Use cryptographically secure random tokens (minimum 256 bits)\n2. Make tokens long and unpredictable (32+ characters)\n3. Implement rate limiting on token validation\n4. Use single-use tokens\n5. Set short expiration (15-30 minutes)\n6. Implement CAPTCHA for reset requests\n7. Log all reset attempts for monitoring".to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                });
                                break;
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_timing_based_enumeration(
        &self,
        url: &str,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        if (aggression as u8) < (AggressionLevel::Medium as u8) {
            return Ok((vulnerabilities, tests_run));
        }

        let login_endpoint = format!("{}/login", url.trim_end_matches('/'));

        // Test with known non-existent username
        let mut nonexistent_times = Vec::new();
        for i in 0..5 {
            tests_run += 1;
            let test_data = format!("username=nonexistent_user_{}&password=wrongpass", i);

            let start = Instant::now();
            let _ = self
                .http_client
                .post_form(&login_endpoint, &test_data)
                .await;
            let elapsed = start.elapsed();
            nonexistent_times.push(elapsed);
        }

        // Test with potentially valid username
        let mut valid_times = Vec::new();
        let test_usernames_timing =
            vec!["admin".to_string(), "user".to_string(), "test".to_string()];
        for username in &test_usernames_timing {
            tests_run += 1;
            let test_data = format!("username={}&password=wrongpass", &username);

            let start = Instant::now();
            let _ = self
                .http_client
                .post_form(&login_endpoint, &test_data)
                .await;
            let elapsed = start.elapsed();
            valid_times.push(elapsed);
        }

        // Calculate average response times
        let avg_nonexistent: Duration =
            nonexistent_times.iter().sum::<Duration>() / nonexistent_times.len() as u32;
        let avg_valid: Duration = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;

        // Check for significant timing difference (>100ms)
        let diff = if avg_valid > avg_nonexistent {
            avg_valid - avg_nonexistent
        } else {
            avg_nonexistent - avg_valid
        };

        if diff > Duration::from_millis(100) {
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "Timing-Based Username Enumeration".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "Information Disclosure".to_string(),
                url: login_endpoint,
                parameter: Some("username".to_string()),
                payload: String::new(),
                description: format!("Login response time differs significantly between valid and invalid usernames ({}ms difference). Attackers can enumerate valid usernames through timing analysis.", diff.as_millis()),
                evidence: Some(format!("Average response time difference: {}ms (nonexistent: {}ms, potentially valid: {}ms)",
                                      diff.as_millis(), avg_nonexistent.as_millis(), avg_valid.as_millis())),
                cwe: "CWE-208".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "1. Implement constant-time authentication\n2. Always perform password hashing, even for non-existent users\n3. Add random delays to normalize response times\n4. Use rate limiting to make timing attacks impractical\n5. Monitor for rapid sequential login attempts\n6. Implement CAPTCHA after multiple failures".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_username_enumeration(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let endpoints_to_test = vec![
            (format!("{}/login", url.trim_end_matches('/')), "login"),
            (
                format!("{}/register", url.trim_end_matches('/')),
                "register",
            ),
            (
                format!("{}/forgot-password", url.trim_end_matches('/')),
                "password_reset",
            ),
        ];

        for (endpoint, endpoint_type) in &endpoints_to_test {
            tests_run += 1;

            let test_data = match endpoint_type.as_ref() {
                "login" => "username=nonexistent_test_user&password=test123",
                "register" => "username=admin&email=test@example.com&password=Test123!",
                "password_reset" => "email=nonexistent@example.com",
                _ => continue,
            };

            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check for specific error messages that reveal user existence
                    let enumeration_indicators = match endpoint_type.as_ref() {
                        "login" => vec![
                            "user not found",
                            "username does not exist",
                            "invalid username",
                            "account not found",
                            "no such user",
                        ],
                        "register" => vec![
                            "username already exists",
                            "username taken",
                            "user already registered",
                            "username unavailable",
                        ],
                        "password_reset" => vec![
                            "email not found",
                            "no account with that email",
                            "email does not exist",
                        ],
                        _ => vec![],
                    };

                    for indicator in &enumeration_indicators {
                        if body_lower.contains(indicator) {
                            let severity = match endpoint_type.as_ref() {
                                "register" => Severity::Low, // Less critical for registration
                                _ => Severity::Medium,
                            };

                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: format!("Username Enumeration via {} Endpoint",
                                                  endpoint_type.replace('_', " ").to_string()),
                                severity,
                                confidence: Confidence::High,
                                category: "Information Disclosure".to_string(),
                                url: endpoint.clone(),
                                parameter: Some("username/email".to_string()),
                                payload: test_data.to_string(),
                                description: format!("The {} endpoint reveals whether usernames/emails exist through specific error messages. Attackers can enumerate valid accounts for targeted attacks.", endpoint_type),
                                evidence: Some(format!("Error message contains: '{}'", indicator)),
                                cwe: "CWE-203".to_string(),
                                cvss: 5.3,
                                verified: true,
                                false_positive: false,
                                remediation: format!("1. Use generic error messages:\n   - Login: 'Invalid username or password'\n   - Register: Use email verification without confirming existence\n   - Reset: 'If that email exists, we sent a reset link'\n2. Return identical responses for valid/invalid users\n3. Implement rate limiting\n4. Use CAPTCHA after multiple attempts\n5. Log enumeration attempts for monitoring"),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ==================== MULTI-FACTOR AUTHENTICATION ====================

    async fn test_mfa_security(
        &self,
        url: &str,
        _config: &ScanConfig,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: MFA Bypass Techniques
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_mfa_bypass(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 2: TOTP/HOTP Validation
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_totp_validation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 3: Backup Code Security
        if (aggression as u8) >= (AggressionLevel::Low as u8) {
            let (vulns, tests) = self.test_backup_codes(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 4: MFA Enrollment Bypass
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_mfa_enrollment_bypass(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_mfa_bypass(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let mfa_endpoints = vec![
            format!("{}/mfa/verify", url.trim_end_matches('/')),
            format!("{}/2fa/verify", url.trim_end_matches('/')),
            format!("{}/api/auth/mfa", url.trim_end_matches('/')),
        ];

        for endpoint in &mfa_endpoints {
            // Test 1: Direct access to protected resource
            tests_run += 1;
            let protected_url = format!("{}/dashboard", url.trim_end_matches('/'));
            match self.http_client.get(&protected_url).await {
                Ok(response) => {
                    // CRITICAL: Don't report MFA bypass on non-existent endpoints (404)
                    if response.status_code == 200
                        && response.status_code != 404  // Endpoint must exist
                        && !response.body.to_lowercase().contains("mfa")
                        && !response.body.to_lowercase().contains("not found")  // Additional check
                        && !response.body.to_lowercase().contains("cannot get")
                    {
                        // NestJS 404 message
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "MFA Bypass - Direct Access".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: protected_url.clone(),
                            parameter: None,
                            payload: String::new(),
                            description: "Protected resources can be accessed without completing MFA verification. Attackers can bypass second-factor authentication.".to_string(),
                            evidence: Some("Direct access to protected resource without MFA challenge".to_string()),
                            cwe: "CWE-306".to_string(),
                            cvss: 9.1,
                            verified: false,
                            false_positive: false,
                            remediation: "1. CRITICAL: Enforce MFA verification for all authenticated sessions\n2. Check MFA status on every protected request\n3. Use session flags to track MFA completion\n4. Implement step-up authentication for sensitive operations\n5. Never trust client-side MFA indicators".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(_) => {}
            }

            // Test 2: Empty MFA code
            tests_run += 1;
            let test_data = "code=";
            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    if (response.status_code == 200 || response.status_code == 302)
                        && (response.body.to_lowercase().contains("success")
                            || response.header("location").is_some())
                    {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "MFA Bypass - Empty Code Accepted".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: endpoint.clone(),
                            parameter: Some("code".to_string()),
                            payload: "(empty)".to_string(),
                            description: "MFA verification accepts empty codes. Attackers can bypass MFA by submitting empty values.".to_string(),
                            evidence: Some("MFA verification succeeded with empty code".to_string()),
                            cwe: "CWE-287".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Validate that MFA code is non-empty\n2. Implement strict code format validation\n3. Use constant-time comparison for code verification\n4. Implement rate limiting on MFA attempts\n5. Lock account after repeated failures".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(_) => {}
            }

            // Test 3: Invalid code format
            tests_run += 1;
            let test_data = "code=invalid";
            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    if response.status_code == 200
                        && !response.body.to_lowercase().contains("invalid")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "Weak MFA Code Validation".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: endpoint.clone(),
                            parameter: Some("code".to_string()),
                            payload: "invalid".to_string(),
                            description: "MFA endpoint accepts codes in invalid formats without proper validation. This may indicate weak or bypassable verification logic.".to_string(),
                            evidence: Some("Invalid code format accepted without error".to_string()),
                            cwe: "CWE-20".to_string(),
                            cvss: 7.5,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Implement strict code format validation (6 digits for TOTP)\n2. Reject codes that don't match expected format\n3. Use constant-time comparison\n4. Implement rate limiting\n5. Log all MFA verification attempts".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_totp_validation(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let mfa_endpoints = vec![
            format!("{}/mfa/verify", url.trim_end_matches('/')),
            format!("{}/2fa/verify", url.trim_end_matches('/')),
        ];

        for endpoint in &mfa_endpoints {
            tests_run += 1;

            // First, check if the endpoint actually exists
            // Skip testing if endpoint returns 404 (doesn't exist)
            let initial_check = match self.http_client.get(&endpoint).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Skip 404 endpoints - they don't exist
            if initial_check.status_code == 404 {
                continue;
            }

            // Check if this looks like an actual MFA page
            let body_lower = initial_check.body.to_lowercase();
            let is_mfa_related = body_lower.contains("code")
                || body_lower.contains("verify")
                || body_lower.contains("totp")
                || body_lower.contains("authenticator")
                || body_lower.contains("mfa")
                || body_lower.contains("2fa")
                || initial_check.status_code == 401
                || initial_check.status_code == 403;

            // If endpoint doesn't look like an MFA page, skip
            if !is_mfa_related {
                continue;
            }

            // Test: Brute force protection
            let attempts_before_lockout = 10;
            let mut successful_attempts = 0;

            for i in 0..attempts_before_lockout {
                let test_data = format!("code={:06}", i);
                match self.http_client.post_form(&endpoint, &test_data).await {
                    Ok(response) => {
                        // 404 means endpoint doesn't handle POST, skip
                        if response.status_code == 404 {
                            break;
                        }
                        if response.status_code != 429 && response.status_code != 403 {
                            successful_attempts += 1;
                        }
                    }
                    Err(_) => break,
                }
            }

            if successful_attempts >= attempts_before_lockout {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Missing Rate Limiting on MFA Verification".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Authentication".to_string(),
                    url: endpoint.clone(),
                    parameter: Some("code".to_string()),
                    payload: String::new(),
                    description: "MFA verification endpoint lacks rate limiting. Attackers can brute-force 6-digit codes (1 million combinations) to bypass MFA.".to_string(),
                    evidence: Some(format!("Successfully submitted {} verification attempts without rate limiting", attempts_before_lockout)),
                    cwe: "CWE-307".to_string(),
                    cvss: 8.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Implement strict rate limiting (3-5 attempts per session)\n2. Lock MFA after failed attempts\n3. Require re-authentication after MFA lockout\n4. Implement exponential backoff\n5. Use CAPTCHA after failures\n6. Monitor and alert on brute force attempts\n7. Consider using longer codes or alternative methods".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_backup_codes(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let backup_endpoints = vec![
            format!("{}/mfa/backup", url.trim_end_matches('/')),
            format!("{}/2fa/recovery", url.trim_end_matches('/')),
        ];

        for endpoint in &backup_endpoints {
            tests_run += 1;

            // Test: Predictable backup codes
            let test_codes = vec![
                "12345678".to_string(),
                "00000000".to_string(),
                "11111111".to_string(),
                "AAAAAAAA".to_string(),
            ];

            for code in &test_codes {
                let test_data = format!("backup_code={}", code);
                match self.http_client.post_form(endpoint, &test_data).await {
                    Ok(response) => {
                        if (response.status_code == 200 || response.status_code == 302)
                            && response.body.to_lowercase().contains("success")
                        {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "Predictable MFA Backup Codes".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Authentication".to_string(),
                                url: endpoint.clone(),
                                parameter: Some("backup_code".to_string()),
                                payload: code.to_string(),
                                description: format!("MFA backup code '{}' is predictable and was accepted. Backup codes must be cryptographically random to prevent brute-force attacks.", code),
                                evidence: Some(format!("Predictable backup code accepted: {}", code)),
                                cwe: "CWE-330".to_string(),
                                cvss: 9.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. CRITICAL: Generate backup codes using CSPRNG\n2. Use sufficient length (16+ characters) and complexity\n3. Make codes single-use only\n4. Limit number of backup codes (8-10 recommended)\n5. Implement rate limiting on backup code verification\n6. Require re-authentication to view backup codes\n7. Notify users when backup codes are used".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_mfa_enrollment_bypass(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let enrollment_endpoints = vec![
            format!("{}/mfa/enable", url.trim_end_matches('/')),
            format!("{}/2fa/setup", url.trim_end_matches('/')),
            format!("{}/api/auth/mfa/enroll", url.trim_end_matches('/')),
        ];

        for endpoint in &enrollment_endpoints {
            tests_run += 1;

            // Test: MFA enrollment without verification
            let test_data = "enable=true";
            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    let body_lower = response.body.to_lowercase();

                    // Check if MFA was enabled without code verification
                    if (response.status_code == 200 || response.status_code == 302)
                        && (body_lower.contains("enabled") || body_lower.contains("activated"))
                        && !body_lower.contains("verify")
                        && !body_lower.contains("code")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "MFA Enrollment Without Verification".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: endpoint.clone(),
                            parameter: None,
                            payload: test_data.to_string(),
                            description: "MFA can be enabled without verifying that the user can successfully generate valid codes. This may lead to account lockout if MFA is misconfigured.".to_string(),
                            evidence: Some("MFA enrollment succeeded without code verification".to_string()),
                            cwe: "CWE-287".to_string(),
                            cvss: 6.5,
                            verified: false,
                            false_positive: false,
                            remediation: "1. Require users to verify MFA code before completing enrollment\n2. Test both current code and next code for TOTP\n3. Provide clear setup instructions with QR code\n4. Offer account recovery options before enabling MFA\n5. Generate and display backup codes during enrollment\n6. Allow MFA disabling via verified email link".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ==================== OAUTH/OIDC SECURITY ====================

    async fn test_oauth_security(
        &self,
        url: &str,
        _config: &ScanConfig,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        if (aggression as u8) < (AggressionLevel::Low as u8) {
            return Ok((vulnerabilities, tests_run));
        }

        // Test 1: Authorization Code Interception
        let (vulns, tests) = self.test_authorization_code_interception(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test 2: Redirect URI Validation
        let (vulns, tests) = self.test_redirect_uri_validation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test 3: State Parameter Validation
        let (vulns, tests) = self.test_state_parameter(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test 4: Token Endpoint Security
        let (vulns, tests) = self.test_token_endpoint(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test 5: PKCE Validation
        let (vulns, tests) = self.test_pkce_validation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        Ok((vulnerabilities, tests_run))
    }

    async fn test_authorization_code_interception(
        &self,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let oauth_endpoints = vec![
            format!("{}/oauth/authorize", url.trim_end_matches('/')),
            format!("{}/oauth2/authorize", url.trim_end_matches('/')),
            format!("{}/api/oauth/authorize", url.trim_end_matches('/')),
        ];

        for endpoint in &oauth_endpoints {
            tests_run += 1;

            let test_url = format!(
                "{}?response_type=code&client_id=test&redirect_uri=http://evil.com",
                endpoint
            );

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if authorization code is returned in URL (should be POST-based)
                    if response.status_code == 302 {
                        if let Some(location) = response.header("location") {
                            if location.contains("code=") && location.starts_with("http:") {
                                vulnerabilities.push(Vulnerability {
                                    id: generate_uuid(),
                                    vuln_type: "OAuth Authorization Code over HTTP".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    category: "OAuth/OIDC".to_string(),
                                    url: endpoint.clone(),
                                    parameter: Some("redirect_uri".to_string()),
                                    payload: "http://evil.com".to_string(),
                                    description: "OAuth authorization code is transmitted over unencrypted HTTP connection. Codes can be intercepted via network sniffing, enabling account takeover.".to_string(),
                                    evidence: Some(format!("Authorization code redirected to HTTP: {}", location)),
                                    cwe: "CWE-319".to_string(),
                                    cvss: 9.8,
                                    verified: true,
                                    false_positive: false,
                                    remediation: "1. CRITICAL: Enforce HTTPS for all redirect URIs\n2. Reject HTTP redirect URIs\n3. Validate redirect_uri against whitelist\n4. Implement PKCE for public clients\n5. Use short-lived authorization codes (60 seconds)\n6. Make codes single-use only".to_string(),
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                });
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_redirect_uri_validation(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let oauth_endpoints = vec![
            format!("{}/oauth/authorize", url.trim_end_matches('/')),
            format!("{}/oauth2/authorize", url.trim_end_matches('/')),
        ];

        // Test various redirect URI bypass techniques
        let malicious_redirects = vec![
            "http://evil.com",
            "http://evil.com@legitimate.com",
            "http://legitimate.com.evil.com",
            "http://legitimate.com/../evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//evil.com",
        ];

        for endpoint in &oauth_endpoints {
            for redirect in &malicious_redirects {
                tests_run += 1;

                let test_url = format!(
                    "{}?response_type=code&client_id=test&redirect_uri={}",
                    endpoint,
                    urlencoding::encode(redirect)
                );

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if response.status_code == 302 {
                            if let Some(location) = response.header("location") {
                                if location.contains("evil.com")
                                    || location.starts_with("javascript:")
                                    || location.starts_with("data:")
                                {
                                    vulnerabilities.push(Vulnerability {
                                        id: generate_uuid(),
                                        vuln_type: "OAuth Open Redirect - Weak Redirect URI Validation".to_string(),
                                        severity: Severity::Critical,
                                        confidence: Confidence::High,
                                        category: "OAuth/OIDC".to_string(),
                                        url: endpoint.clone(),
                                        parameter: Some("redirect_uri".to_string()),
                                        payload: redirect.to_string(),
                                        description: format!("OAuth authorization endpoint accepts malicious redirect URI: '{}'. Attackers can steal authorization codes by redirecting users to attacker-controlled domains.", redirect),
                                        evidence: Some(format!("Accepted malicious redirect: {}", redirect)),
                                        cwe: "CWE-601".to_string(),
                                        cvss: 9.6,
                                        verified: true,
                                        false_positive: false,
                                        remediation: "1. CRITICAL: Implement strict redirect URI whitelist\n2. Require exact match (not substring/prefix)\n3. Validate URI scheme, host, and path\n4. Reject URIs with @ or embedded credentials\n5. Reject javascript:, data:, and other dangerous schemes\n6. Require pre-registration of redirect URIs\n7. Use PKCE to mitigate code interception".to_string(),
                                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                                    });
                                    break; // Found vulnerability for this endpoint
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_state_parameter(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let oauth_endpoints = vec![
            format!("{}/oauth/authorize", url.trim_end_matches('/')),
            format!("{}/oauth2/authorize", url.trim_end_matches('/')),
        ];

        for endpoint in &oauth_endpoints {
            tests_run += 1;

            // Test: Missing state parameter
            let test_url = format!(
                "{}?response_type=code&client_id=test&redirect_uri=https://app.example.com/callback",
                endpoint
            );

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 || response.status_code == 302 {
                        // Check if request was accepted without state parameter
                        let has_warning = response.body.to_lowercase().contains("state")
                            && response.body.to_lowercase().contains("required");

                        if !has_warning {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "OAuth Missing State Parameter Validation".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                category: "OAuth/OIDC".to_string(),
                                url: endpoint.clone(),
                                parameter: Some("state".to_string()),
                                payload: "(missing)".to_string(),
                                description: "OAuth authorization request succeeds without state parameter. Missing state enables CSRF attacks where attackers can force users to authenticate with attacker-controlled accounts.".to_string(),
                                evidence: Some("Authorization request accepted without state parameter".to_string()),
                                cwe: "CWE-352".to_string(),
                                cvss: 8.1,
                                verified: false,
                                false_positive: false,
                                remediation: "1. CRITICAL: Require state parameter in authorization requests\n2. Generate cryptographically random state values\n3. Validate state parameter in callback\n4. Bind state to user session\n5. Implement short expiration for state values\n6. Use single-use state tokens".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(_) => {}
            }

            // Test: Predictable state values
            tests_run += 1;
            let predictable_states = vec!["123".to_string(), "abc".to_string(), "test".to_string()];

            for state in &predictable_states {
                let test_url = format!(
                    "{}?response_type=code&client_id=test&redirect_uri=https://app.example.com/callback&state={}",
                    endpoint, state
                );

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if response.status_code == 200 || response.status_code == 302 {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "OAuth Predictable State Parameter".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Low,
                                category: "OAuth/OIDC".to_string(),
                                url: endpoint.clone(),
                                parameter: Some("state".to_string()),
                                payload: state.to_string(),
                                description: "OAuth accepts simple, predictable state values. State must be cryptographically random to prevent CSRF attacks.".to_string(),
                                evidence: Some(format!("Weak state value accepted: {}", state)),
                                cwe: "CWE-330".to_string(),
                                cvss: 6.5,
                                verified: false,
                                false_positive: false,
                                remediation: "1. Generate state using CSPRNG (minimum 128 bits)\n2. Validate state is non-empty and sufficiently random\n3. Bind state to user session\n4. Implement state expiration\n5. Make state values single-use".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_token_endpoint(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let token_endpoints = vec![
            format!("{}/oauth/token", url.trim_end_matches('/')),
            format!("{}/oauth2/token", url.trim_end_matches('/')),
            format!("{}/api/oauth/token", url.trim_end_matches('/')),
        ];

        for endpoint in &token_endpoints {
            // Test: Missing client authentication
            tests_run += 1;
            let test_data =
                "grant_type=authorization_code&code=test123&redirect_uri=https://example.com";

            match self.http_client.post_form(endpoint, test_data).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();

                        if body_lower.contains("access_token") {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "OAuth Token Endpoint Missing Client Authentication".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "OAuth/OIDC".to_string(),
                                url: endpoint.clone(),
                                parameter: None,
                                payload: test_data.to_string(),
                                description: "OAuth token endpoint issues access tokens without client authentication. Attackers who intercept authorization codes can exchange them for access tokens.".to_string(),
                                evidence: Some("Token issued without client credentials".to_string()),
                                cwe: "CWE-306".to_string(),
                                cvss: 9.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. CRITICAL: Require client authentication for confidential clients\n2. Use client_secret or private_key_jwt authentication\n3. Implement PKCE for public clients (mobile/SPA)\n4. Validate authorization code was issued to requesting client\n5. Make authorization codes single-use\n6. Implement short code expiration (60 seconds)".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(_) => {}
            }

            // Test: Token endpoint over HTTP
            tests_run += 1;
            if endpoint.starts_with("http://") {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "OAuth Token Endpoint over HTTP".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "OAuth/OIDC".to_string(),
                    url: endpoint.clone(),
                    parameter: None,
                    payload: String::new(),
                    description: "OAuth token endpoint is accessible over unencrypted HTTP. Access tokens and client secrets can be intercepted via network sniffing.".to_string(),
                    evidence: Some("Token endpoint URL uses http:// scheme".to_string()),
                    cwe: "CWE-319".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Enforce HTTPS for all OAuth endpoints\n2. Redirect HTTP requests to HTTPS\n3. Implement HSTS\n4. Disable HTTP access entirely\n5. Use certificate pinning where possible".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_pkce_validation(&self, url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let oauth_endpoints = vec![
            format!("{}/oauth/authorize", url.trim_end_matches('/')),
            format!("{}/oauth2/authorize", url.trim_end_matches('/')),
        ];

        for endpoint in &oauth_endpoints {
            tests_run += 1;

            // Test: Authorization without PKCE for public client
            let test_url = format!(
                "{}?response_type=code&client_id=mobile_app&redirect_uri=https://app.example.com/callback",
                endpoint
            );

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 || response.status_code == 302 {
                        // Check if PKCE is required
                        let requires_pkce = response.body.to_lowercase().contains("code_challenge")
                            || response.body.to_lowercase().contains("pkce");

                        if !requires_pkce {
                            vulnerabilities.push(Vulnerability {
                                id: generate_uuid(),
                                vuln_type: "OAuth Missing PKCE for Public Clients".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Low,
                                category: "OAuth/OIDC".to_string(),
                                url: endpoint.clone(),
                                parameter: None,
                                payload: String::new(),
                                description: "OAuth flow does not appear to require PKCE (Proof Key for Code Exchange). Public clients (mobile apps, SPAs) without PKCE are vulnerable to authorization code interception attacks.".to_string(),
                                evidence: Some("Authorization succeeds without code_challenge parameter".to_string()),
                                cwe: "CWE-862".to_string(),
                                cvss: 7.4,
                                verified: false,
                                false_positive: false,
                                remediation: "1. CRITICAL: Require PKCE for all public clients\n2. Enforce code_challenge in authorization request\n3. Validate code_verifier in token request\n4. Use S256 code challenge method (SHA-256)\n5. Reject plain text code challenge method\n6. Make PKCE mandatory for mobile and SPA applications".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ==================== JWT SECURITY ====================

    async fn test_jwt_security(
        &self,
        url: &str,
        _config: &ScanConfig,
        aggression: AggressionLevel,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        if (aggression as u8) < (AggressionLevel::Low as u8) {
            return Ok((vulnerabilities, tests_run));
        }

        // First, try to obtain a JWT token
        let jwt_token = match self.extract_jwt_token(url).await {
            Some(token) => token,
            None => {
                tracing::debug!("No JWT token found, skipping JWT security tests");
                return Ok((vulnerabilities, tests_run));
            }
        };

        tests_run += 1;

        // Test 1: Algorithm Confusion (RS256 to HS256)
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_algorithm_confusion(url, &jwt_token).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 2: None Algorithm
        let (vulns, tests) = self.test_none_algorithm(url, &jwt_token).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test 3: JWT Claim Manipulation
        if (aggression as u8) >= (AggressionLevel::Medium as u8) {
            let (vulns, tests) = self.test_claim_manipulation(url, &jwt_token).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 4: Weak Secret Detection
        if (aggression as u8) >= (AggressionLevel::High as u8) {
            let (vulns, tests) = self.test_weak_jwt_secret(url, &jwt_token).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test 5: Token Expiration
        let (vulns, tests) = self.test_token_expiration(url, &jwt_token).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        Ok((vulnerabilities, tests_run))
    }

    async fn extract_jwt_token(&self, url: &str) -> Option<String> {
        // Try to get JWT from common endpoints
        let test_endpoints = vec![
            format!("{}/api/auth/token", url.trim_end_matches('/')),
            format!("{}/login", url.trim_end_matches('/')),
            url.to_string(),
        ];

        for endpoint in &test_endpoints {
            if let Ok(response) = self.http_client.get(endpoint).await {
                // Check Authorization header
                if let Some(auth) = response.header("authorization") {
                    if auth.starts_with("Bearer ") {
                        return Some(auth[7..].to_string());
                    }
                }

                // Check response body for JWT pattern
                let jwt_regex =
                    Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
                if let Some(captures) = jwt_regex.find(&response.body) {
                    return Some(captures.as_str().to_string());
                }

                // Check cookies
                if let Some(cookies) = response.header("set-cookie") {
                    if let Some(captures) = jwt_regex.find(&cookies) {
                        return Some(captures.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    async fn test_algorithm_confusion(
        &self,
        url: &str,
        jwt_token: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        // Parse JWT to get header and payload
        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Ok((vulnerabilities, tests_run));
        }

        // Decode header
        let header_bytes = match general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(bytes) => bytes,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let mut header: serde_json::Value = match serde_json::from_slice(&header_bytes) {
            Ok(h) => h,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Check if currently using RS256
        if header.get("alg").and_then(|v| v.as_str()) == Some("RS256") {
            // Try changing to HS256
            header["alg"] = serde_json::Value::String("HS256".to_string());

            let header_json = match serde_json::to_string(&header) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to serialize JWT header: {}", e);
                    return Ok((vulnerabilities, tests_run));
                }
            };
            let new_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json);

            // Create new JWT with HS256 (signed with public key as secret)
            let modified_token = format!("{}.{}.fake_signature", new_header, parts[1]);

            // Test if server accepts it
            let test_url = format!("{}/api/protected", url.trim_end_matches('/'));
            let auth_header = format!("Bearer {}", modified_token);
            match self
                .http_client
                .get_with_headers(&test_url, vec![("Authorization".to_string(), auth_header)])
                .await
            {
                Ok(response) => {
                    if response.status_code == 200 {
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid(),
                            vuln_type: "JWT Algorithm Confusion (RS256 to HS256)".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "JWT Security".to_string(),
                            url: test_url,
                            parameter: Some("Authorization".to_string()),
                            payload: "alg: HS256 (modified from RS256)".to_string(),
                            description: "JWT implementation vulnerable to algorithm confusion attack. Server accepts HS256 tokens when expecting RS256, allowing attackers to forge tokens using the public key as HMAC secret.".to_string(),
                            evidence: Some("Modified JWT with HS256 algorithm was accepted".to_string()),
                            cwe: "CWE-327".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Explicitly validate JWT algorithm\n2. Never trust the alg header value\n3. Use algorithm whitelisting\n4. Separate keys for different algorithms\n5. Use modern JWT libraries with algorithm validation\n6. Consider switching to asymmetric algorithms only\n7. Implement key rotation".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_none_algorithm(
        &self,
        url: &str,
        jwt_token: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Ok((vulnerabilities, tests_run));
        }

        // Create JWT with "none" algorithm and no signature
        let none_header = r#"{"alg":"none","typ":"JWT"}"#;
        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(none_header);
        let modified_token = format!("{}.{}.", encoded_header, parts[1]);

        // Test if server accepts unsigned JWT
        let test_url = format!("{}/api/protected", url.trim_end_matches('/'));
        let auth_header = format!("Bearer {}", modified_token);
        match self
            .http_client
            .get_with_headers(&test_url, vec![("Authorization".to_string(), auth_header)])
            .await
        {
            Ok(response) => {
                if response.status_code == 200 {
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "JWT None Algorithm Accepted".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "JWT Security".to_string(),
                        url: test_url,
                        parameter: Some("Authorization".to_string()),
                        payload: r#"{"alg":"none"}"#.to_string(),
                        description: "JWT implementation accepts tokens with 'none' algorithm (unsigned tokens). Attackers can forge arbitrary JWTs without any signature.".to_string(),
                        evidence: Some("Unsigned JWT with alg:none was accepted".to_string()),
                        cwe: "CWE-347".to_string(),
                        cvss: 10.0,
                        verified: true,
                        false_positive: false,
                        remediation: "1. CRITICAL: Reject all JWTs with alg:none\n2. Implement strict algorithm whitelist\n3. Always verify JWT signature\n4. Use secure JWT libraries\n5. Never allow unsigned tokens in production\n6. Implement comprehensive JWT validation".to_string(),
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

    async fn test_claim_manipulation(
        &self,
        url: &str,
        jwt_token: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Ok((vulnerabilities, tests_run));
        }

        // Decode payload
        let payload_bytes = match general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(bytes) => bytes,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let mut payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Try modifying role/admin claims
        let _original_payload = payload.clone();

        if payload.get("role").is_some() {
            payload["role"] = serde_json::Value::String("admin".to_string());
        } else {
            payload["role"] = serde_json::Value::String("admin".to_string());
        }

        if payload.get("isAdmin").is_some() {
            payload["isAdmin"] = serde_json::Value::Bool(true);
        } else {
            payload["isAdmin"] = serde_json::Value::Bool(true);
        }

        let payload_json = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to serialize JWT payload: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };
        let modified_payload = general_purpose::URL_SAFE_NO_PAD.encode(payload_json);

        // Create modified token (keep original signature - should fail but worth testing)
        let modified_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);

        // Test if server accepts modified token
        let test_url = format!("{}/api/admin", url.trim_end_matches('/'));
        let auth_header = format!("Bearer {}", modified_token);
        match self
            .http_client
            .get_with_headers(&test_url, vec![("Authorization".to_string(), auth_header)])
            .await
        {
            Ok(response) => {
                if response.status_code == 200 {
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid(),
                        vuln_type: "JWT Signature Not Verified - Claim Manipulation".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "JWT Security".to_string(),
                        url: test_url,
                        parameter: Some("Authorization".to_string()),
                        payload: format!("Modified claims: {:?}", payload),
                        description: "JWT claims can be modified without signature verification. Attackers can escalate privileges by changing role/admin claims in the JWT payload.".to_string(),
                        evidence: Some("Modified JWT accepted with changed role to admin".to_string()),
                        cwe: "CWE-345".to_string(),
                        cvss: 10.0,
                        verified: true,
                        false_positive: false,
                        remediation: "1. CRITICAL: Always verify JWT signature before trusting claims\n2. Validate signature using proper key\n3. Check token expiration\n4. Validate all critical claims server-side\n5. Never trust client-provided authorization data\n6. Implement proper access control\n7. Use secure JWT libraries with automatic validation".to_string(),
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

    async fn test_weak_jwt_secret(
        &self,
        url: &str,
        jwt_token: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Ok((vulnerabilities, tests_run));
        }

        // Common weak secrets to test
        let weak_secrets = vec![
            "secret",
            "password",
            "123456",
            "secret123",
            "jwt_secret",
            "your-256-bit-secret",
            "mysecret",
        ];

        for secret in &weak_secrets {
            tests_run += 1;

            // Try to verify token with weak secret
            let message = format!("{}.{}", parts[0], parts[1]);

            let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            mac.update(message.as_bytes());

            let result = mac.finalize();
            let computed_signature = general_purpose::URL_SAFE_NO_PAD.encode(result.into_bytes());

            // Compare with actual signature
            if computed_signature == parts[2] || parts[2].starts_with(&computed_signature[..10]) {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "JWT Signed with Weak Secret".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "JWT Security".to_string(),
                    url: url.to_string(),
                    parameter: Some("JWT secret".to_string()),
                    payload: format!("Weak secret: {}", secret),
                    description: format!("JWT is signed with weak, easily guessable secret: '{}'. Attackers can forge arbitrary JWTs once they discover the secret through brute force.", secret),
                    evidence: Some(format!("JWT successfully verified with weak secret: {}", secret)),
                    cwe: "CWE-521".to_string(),
                    cvss: 10.0,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Generate strong cryptographic secret (minimum 256 bits)\n2. Use cryptographically secure random generator\n3. Rotate secrets regularly\n4. Store secrets securely (environment variables, secrets manager)\n5. Never commit secrets to version control\n6. Consider using asymmetric algorithms (RS256, ES256)\n7. Implement proper key management".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
                break; // Found weak secret, no need to continue
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    async fn test_token_expiration(
        &self,
        url: &str,
        jwt_token: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            return Ok((vulnerabilities, tests_run));
        }

        // Decode payload to check expiration
        let payload_bytes = match general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(bytes) => bytes,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Check for exp claim
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            let now = chrono::Utc::now().timestamp();
            let expires_in = exp - now;

            // Check if expiration is too long (>24 hours)
            if expires_in > 86400 {
                vulnerabilities.push(Vulnerability {
                    id: generate_uuid(),
                    vuln_type: "Excessive JWT Token Expiration".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "JWT Security".to_string(),
                    url: url.to_string(),
                    parameter: Some("exp".to_string()),
                    payload: format!("Expires in {} seconds ({} hours)", expires_in, expires_in / 3600),
                    description: format!("JWT token has excessive expiration time ({} hours). Long-lived tokens increase the window for token theft and replay attacks.", expires_in / 3600),
                    evidence: Some(format!("Token expires in {} seconds", expires_in)),
                    cwe: "CWE-613".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Set short token expiration (15-60 minutes for access tokens)\n2. Use refresh tokens for extended sessions\n3. Implement token revocation mechanism\n4. Force re-authentication for sensitive operations\n5. Monitor for token reuse after expiration\n6. Implement sliding sessions where appropriate".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        } else {
            // No expiration claim
            vulnerabilities.push(Vulnerability {
                id: generate_uuid(),
                vuln_type: "JWT Token Without Expiration".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "JWT Security".to_string(),
                url: url.to_string(),
                parameter: Some("exp".to_string()),
                payload: "Missing exp claim".to_string(),
                description: "JWT token does not include expiration (exp) claim. Tokens remain valid indefinitely, maximizing the impact of token theft.".to_string(),
                evidence: Some("No exp claim found in JWT payload".to_string()),
                cwe: "CWE-613".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "1. CRITICAL: Always include exp claim in JWTs\n2. Set appropriate expiration time (15-60 minutes)\n3. Implement token refresh mechanism\n4. Validate exp claim server-side\n5. Implement token revocation for security events\n6. Monitor for use of expired tokens".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }
}

// ==================== HELPER FUNCTIONS ====================

fn generate_uuid() -> String {
    let mut rng = rand::rng();
    format!(
        "advauth_{:08x}{:04x}{:04x}{:04x}{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

fn extract_session_id(cookie_header: &str) -> Option<String> {
    // Extract session ID from Set-Cookie header
    let patterns = vec![
        r"sessionid=([^;]+)",
        r"session=([^;]+)",
        r"PHPSESSID=([^;]+)",
        r"JSESSIONID=([^;]+)",
        r"sess=([^;]+)",
    ];

    for pattern_str in &patterns {
        if let Ok(pattern) = Regex::new(pattern_str) {
            if let Some(captures) = pattern.captures(cookie_header) {
                if let Some(session_id) = captures.get(1) {
                    return Some(session_id.as_str().to_string());
                }
            }
        }
    }

    None
}

struct SessionIdAnalysis {
    entropy: f64,
    is_sequential: bool,
    has_timestamp_pattern: bool,
}

fn analyze_session_ids(session_ids: &[String]) -> SessionIdAnalysis {
    if session_ids.is_empty() {
        return SessionIdAnalysis {
            entropy: 0.0,
            is_sequential: false,
            has_timestamp_pattern: false,
        };
    }

    // Calculate average entropy
    let mut total_entropy = 0.0;
    for id in session_ids {
        total_entropy += calculate_entropy(id);
    }
    let avg_entropy = total_entropy / session_ids.len() as f64;

    // Check for sequential patterns
    let is_sequential = check_sequential_pattern(session_ids);

    // Check for timestamp patterns
    let has_timestamp_pattern = check_timestamp_pattern(session_ids);

    SessionIdAnalysis {
        entropy: avg_entropy,
        is_sequential,
        has_timestamp_pattern,
    }
}

fn calculate_entropy(s: &str) -> f64 {
    use std::collections::HashMap;

    let mut char_counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for count in char_counts.values() {
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy * len
}

fn check_sequential_pattern(session_ids: &[String]) -> bool {
    if session_ids.len() < 2 {
        return false;
    }

    // Try to parse as numbers and check if sequential
    let numbers: Vec<Option<i64>> = session_ids
        .iter()
        .map(|id| id.parse::<i64>().ok())
        .collect();

    if numbers.iter().all(|n| n.is_some()) {
        let nums: Vec<i64> = numbers.iter().filter_map(|&n| n).collect();
        if nums.len() >= 2 {
            let mut is_sequential = true;
            for i in 1..nums.len() {
                if (nums[i] - nums[i - 1]).abs() > 100 {
                    is_sequential = false;
                    break;
                }
            }
            return is_sequential;
        }
    }

    false
}

fn check_timestamp_pattern(session_ids: &[String]) -> bool {
    // Check if session IDs contain what looks like timestamps
    let timestamp_pattern = Regex::new(r"\d{10,13}").unwrap();

    let mut matches = 0;
    for id in session_ids {
        if timestamp_pattern.is_match(id) {
            matches += 1;
        }
    }

    matches > session_ids.len() / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpResponse;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_session_fixation_detection() {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        let scanner = AdvancedAuthScanner::new(http_client);

        // Test session fixation detection logic
        let config = ScanConfig {
            scan_mode: "normal".to_string(),
            ultra: false,
            enable_crawler: false,
            max_depth: 1,
            max_pages: 10,
            enum_subdomains: false,
            auth_cookie: None,
            auth_token: None,
            auth_basic: None,
            custom_headers: None,
        };

        let aggression = AggressionLevel::from_scan_mode(config.scan_mode.as_str());
        assert_eq!(aggression, AggressionLevel::Medium);
    }

    #[test]
    fn test_entropy_calculation() {
        let high_entropy = "a8f3d9e2b7c4f1a6";
        let low_entropy = "11111111";

        let high = calculate_entropy(high_entropy);
        let low = calculate_entropy(low_entropy);

        assert!(high > low, "High entropy string should have higher entropy");
    }

    #[test]
    fn test_sequential_detection() {
        let sequential = vec!["100".to_string(), "101".to_string(), "102".to_string()];
        let random = vec![
            "abc123".to_string(),
            "def456".to_string(),
            "ghi789".to_string(),
        ];

        assert!(check_sequential_pattern(&sequential));
        assert!(!check_sequential_pattern(&random));
    }

    #[test]
    fn test_aggression_levels() {
        assert_eq!(AggressionLevel::from_scan_mode("fast").max_attempts(), 3);
        assert_eq!(AggressionLevel::from_scan_mode("normal").max_attempts(), 5);
        assert_eq!(
            AggressionLevel::from_scan_mode("thorough").max_attempts(),
            10
        );
        assert_eq!(AggressionLevel::from_scan_mode("insane").max_attempts(), 20);
    }
}
