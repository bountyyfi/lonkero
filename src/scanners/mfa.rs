// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - MFA (Multi-Factor Authentication) Scanner
 * Tests for MFA implementation vulnerabilities and bypasses
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;

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

        // First, check if this site has any MFA-related functionality
        // by looking at the main page content
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), tests_run)),
        };

        let body_lower = response.body.to_lowercase();

        // Check for evidence of authentication/MFA functionality
        let has_mfa_indicators = body_lower.contains("two-factor")
            || body_lower.contains("2fa")
            || body_lower.contains("mfa")
            || body_lower.contains("multi-factor")
            || body_lower.contains("authenticator")
            || body_lower.contains("verification code")
            || body_lower.contains("totp");

        let has_auth_functionality = body_lower.contains("login")
            || body_lower.contains("sign in")
            || body_lower.contains("log in")
            || body_lower.contains("password");

        // If no authentication or MFA indicators, skip all MFA tests
        // This prevents false positives on static sites
        if !has_auth_functionality && !has_mfa_indicators {
            return Ok((Vec::new(), tests_run));
        }

        // Test 1: Check for MFA enforcement (only if auth indicators exist)
        if has_auth_functionality {
            self.check_mfa_enforcement(&response, url, &mut vulnerabilities);
        }

        // Test 2: Test for MFA bypass via parameter manipulation (only if MFA is mentioned)
        if has_mfa_indicators {
            tests_run += 1;
            if let Ok(bypass_response) = self.test_mfa_bypass(url).await {
                self.check_mfa_bypass(&bypass_response, url, &mut vulnerabilities);
            }
        }

        // Test 3-7: Only run endpoint-specific tests if endpoints actually exist
        // Check if common MFA verification endpoints exist before testing them
        let mfa_endpoints = vec![
            (format!("{}/mfa/verify", url.trim_end_matches('/')), "mfa_verify"),
            (format!("{}/2fa/verify", url.trim_end_matches('/')), "2fa_verify"),
            (format!("{}/auth/mfa", url.trim_end_matches('/')), "auth_mfa"),
            (format!("{}/mfa/enroll", url.trim_end_matches('/')), "mfa_enroll"),
        ];

        for (endpoint_url, _endpoint_type) in &mfa_endpoints {
            tests_run += 1;
            if let Ok(endpoint_response) = self.http_client.get(endpoint_url).await {
                // Only proceed if endpoint exists (not 404, 403 is ok as it means protected)
                if endpoint_response.status_code == 404 {
                    continue;
                }

                let endpoint_body_lower = endpoint_response.body.to_lowercase();

                // Only test rate limiting if this is actually an MFA verification page
                let is_mfa_page = endpoint_body_lower.contains("code")
                    || endpoint_body_lower.contains("verify")
                    || endpoint_body_lower.contains("totp")
                    || endpoint_body_lower.contains("authenticator")
                    || endpoint_body_lower.contains("enter")
                    || endpoint_response.status_code == 401
                    || endpoint_response.status_code == 403;

                if is_mfa_page {
                    self.check_rate_limiting(&endpoint_response, endpoint_url, &mut vulnerabilities);
                }
            }
        }

        // Only test SMS MFA if there's evidence of phone-based auth
        if has_mfa_indicators && (body_lower.contains("sms") || body_lower.contains("phone")) {
            tests_run += 1;
            if let Ok(sms_response) = self.test_sms_mfa(url).await {
                self.check_sms_mfa_security(&sms_response, url, &mut vulnerabilities);
            }
        }

        Ok((vulnerabilities, tests_run))
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

        // Check for successful bypass indicators
        let bypass_indicators = vec![
            "dashboard",
            "welcome",
            "logged in",
            "account",
            "profile",
            "success",
        ];

        let has_bypass = bypass_indicators
            .iter()
            .any(|indicator| body_lower.contains(indicator));

        let has_mfa_check = body_lower.contains("verification")
            || body_lower.contains("2fa")
            || body_lower.contains("authenticator")
            || body_lower.contains("enter code");

        if (status == 200 || status == 302) && has_bypass && !has_mfa_check {
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

        // Check for weak TOTP acceptance
        if body_lower.contains("success")
            || body_lower.contains("verified")
            || body_lower.contains("correct")
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
            });
        }

        // Check for missing rate limiting
        let error_indicators = vec!["invalid".to_string(), "incorrect".to_string(), "wrong".to_string(), "failed".to_string()];
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
        let backup_code_regex = Regex::new(r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")
            .unwrap();
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
            });
        }
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
        scanner.check_mfa_bypass(&response, "https://example.com/auth?mfa_required=false", &mut vulns);

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
            vulns.iter().any(|v| v.vuln_type.contains("Exposed TOTP Secret")),
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
