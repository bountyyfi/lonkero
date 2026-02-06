// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct WebAuthnScanner {
    http_client: Arc<HttpClient>,
}

impl WebAuthnScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for WebAuthn/FIDO2 security vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing WebAuthn/FIDO2 security vulnerabilities");

        let (vulns, tests) = self.test_webauthn_endpoints(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_weak_challenge_generation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_registration_flow(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_origin_validation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for WebAuthn endpoint exposure and configuration
    async fn test_webauthn_endpoints(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing WebAuthn endpoint configuration");

        let webauthn_endpoints = vec![
            ("/api/webauthn/register", "Registration"),
            ("/api/webauthn/authenticate", "Authentication"),
            ("/api/fido2/register", "FIDO2 Registration"),
            ("/api/fido2/authenticate", "FIDO2 Authentication"),
            ("/webauthn/register/begin", "Registration Begin"),
            ("/webauthn/register/complete", "Registration Complete"),
            ("/webauthn/login/begin", "Login Begin"),
            ("/webauthn/login/complete", "Login Complete"),
            ("/.well-known/webauthn", "WebAuthn Discovery"),
            ("/api/passkeys/register", "Passkey Registration"),
            ("/api/passkeys/authenticate", "Passkey Authentication"),
            ("/api/credentials/create", "Credential Creation"),
        ];

        for (endpoint, endpoint_name) in webauthn_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 && self.is_webauthn_response(&response.body) {
                        if self.has_weak_configuration(&response.body) {
                            info!("Weak WebAuthn configuration detected at {}", endpoint_name);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Weak WebAuthn Configuration",
                                "",
                                &format!(
                                    "{} endpoint has weak security configuration",
                                    endpoint_name
                                ),
                                "WebAuthn endpoint accessible with weak parameters",
                                Severity::High,
                                "CWE-287",
                                7.5,
                            ));
                            break;
                        }
                    }

                    if response.status_code == 200 && !response.body.is_empty() {
                        let body_lower = response.body.to_lowercase();
                        if body_lower.contains("challenge") && body_lower.contains("user") {
                            if !self.has_proper_csrf_protection(&response.headers) {
                                info!(
                                    "WebAuthn endpoint without CSRF protection: {}",
                                    endpoint_name
                                );
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "WebAuthn Endpoint Missing CSRF Protection",
                                    "",
                                    &format!("{} endpoint lacks CSRF protection", endpoint_name),
                                    "Challenge generation endpoint accessible without CSRF token",
                                    Severity::Medium,
                                    "CWE-352",
                                    6.5,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", endpoint, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for weak challenge generation
    async fn test_weak_challenge_generation(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing challenge generation strength");

        let challenge_endpoints = vec![
            "/api/webauthn/register/begin",
            "/api/webauthn/authenticate/begin",
            "/api/fido2/challenge",
            "/webauthn/challenge",
        ];

        for endpoint in challenge_endpoints {
            let test_url = self.build_url(url, endpoint);
            let mut challenges = Vec::new();

            for _ in 0..2 {
                match self.http_client.post(&test_url, "{}".to_string()).await {
                    Ok(response) => {
                        if response.status_code == 200 {
                            if let Some(challenge) = self.extract_challenge(&response.body) {
                                challenges.push(challenge);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Challenge request failed: {}", e);
                        break;
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if challenges.len() == 2 {
                if challenges[0] == challenges[1] {
                    info!("Predictable challenge detected at {}", endpoint);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Predictable WebAuthn Challenge",
                        "",
                        "WebAuthn challenge is not randomly generated",
                        &format!(
                            "Same challenge returned on multiple requests: {}",
                            challenges[0]
                        ),
                        Severity::Critical,
                        "CWE-330",
                        9.1,
                    ));
                    break;
                } else if self.is_weak_challenge(&challenges[0])
                    || self.is_weak_challenge(&challenges[1])
                {
                    info!("Weak challenge generation detected at {}", endpoint);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "Weak WebAuthn Challenge",
                        "",
                        "WebAuthn challenge uses weak entropy",
                        "Challenge appears to be weakly generated",
                        Severity::High,
                        "CWE-330",
                        7.5,
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test registration flow for vulnerabilities
    async fn test_registration_flow(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing WebAuthn registration flow");

        let registration_payloads = vec![
            (
                r#"{"user":{"id":"admin","name":"admin"}}"#,
                "User Enumeration",
            ),
            (
                r#"{"challenge":"AAAA","user":{"id":"test"}}"#,
                "Weak Challenge Acceptance",
            ),
            (r#"{"attestation":"none"}"#, "Missing Attestation"),
            (
                r#"{"userVerification":"discouraged"}"#,
                "Weak User Verification",
            ),
            (
                r#"{"authenticatorSelection":{"userVerification":"discouraged"}}"#,
                "Discouraged User Verification",
            ),
        ];

        let register_endpoints = vec![
            "/api/webauthn/register",
            "/api/webauthn/register/begin",
            "/webauthn/register",
        ];

        for endpoint in register_endpoints {
            let test_url = self.build_url(url, endpoint);

            for (payload, issue_name) in &registration_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self
                    .http_client
                    .post_with_headers(&test_url, payload, headers)
                    .await
                {
                    Ok(response) => {
                        if response.status_code == 200 && self.is_webauthn_response(&response.body)
                        {
                            if issue_name == &"Weak Challenge Acceptance"
                                && response.body.contains("AAAA")
                            {
                                info!("Registration accepts weak challenges");
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "WebAuthn Accepts Weak Challenges",
                                    payload,
                                    "Registration flow accepts attacker-controlled challenges",
                                    "Weak challenge accepted in registration",
                                    Severity::Critical,
                                    "CWE-330",
                                    9.1,
                                ));
                                return Ok((vulnerabilities, tests_run));
                            }

                            if issue_name == &"Weak User Verification" {
                                let body_lower = response.body.to_lowercase();
                                if body_lower.contains("discouraged")
                                    || body_lower.contains("userverification")
                                {
                                    info!("Registration allows discouraged user verification");
                                    vulnerabilities.push(self.create_vulnerability(
                                        url,
                                        "Weak User Verification Allowed",
                                        payload,
                                        "Registration allows 'discouraged' user verification",
                                        "User verification can be bypassed",
                                        Severity::High,
                                        "CWE-287",
                                        7.5,
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Registration test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test origin validation
    async fn test_origin_validation(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing WebAuthn origin validation");

        let malicious_origins = vec![
            "https://evil.com",
            "http://localhost",
            "https://attacker.example.com",
            "null",
        ];

        let auth_endpoints = vec![
            "/api/webauthn/authenticate",
            "/api/webauthn/login",
            "/webauthn/authenticate/complete",
        ];

        for endpoint in auth_endpoints {
            let test_url = self.build_url(url, endpoint);

            for origin in &malicious_origins {
                let headers = vec![
                    ("Origin".to_string(), origin.to_string()),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ];

                let payload = r#"{"id":"test","response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0="}}"#;

                match self
                    .http_client
                    .post_with_headers(&test_url, payload, headers)
                    .await
                {
                    Ok(response) => {
                        if response.status_code == 200
                            && !response.body.to_lowercase().contains("invalid")
                        {
                            info!(
                                "WebAuthn accepts requests from malicious origin: {}",
                                origin
                            );
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Missing WebAuthn Origin Validation",
                                &format!("Origin: {}", origin),
                                &format!("WebAuthn accepts authentication from origin: {}", origin),
                                "Missing or weak origin validation in WebAuthn flow",
                                Severity::Critical,
                                "CWE-346",
                                9.1,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("Origin test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn is_webauthn_response(&self, body: &str) -> bool {
        let webauthn_indicators = vec![
            "challenge",
            "publicKey",
            "rpId",
            "attestation",
            "userVerification",
            "authenticatorSelection",
            "credentialId",
        ];

        let body_lower = body.to_lowercase();
        let mut matches = 0;

        for indicator in webauthn_indicators {
            if body_lower.contains(indicator) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }

        false
    }

    fn has_weak_configuration(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        body_lower.contains(r#""attestation":"none""#)
            || body_lower.contains(r#""userverification":"discouraged""#)
            || body_lower.contains(r#"userverification":"preferred""#)
            || body_lower.contains(r#""requireresidentkey":false"#)
    }

    fn has_proper_csrf_protection(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        for (key, _value) in headers {
            let key_lower = key.to_lowercase();
            if key_lower.contains("csrf") || key_lower.contains("xsrf") {
                return true;
            }
        }
        false
    }

    fn extract_challenge(&self, body: &str) -> Option<String> {
        let patterns = vec![
            r#""challenge"\s*:\s*"([^"]+)""#,
            r#"'challenge'\s*:\s*'([^']+)'"#,
            r#"challenge:\s*"([^"]+)""#,
        ];

        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(body) {
                    if let Some(challenge) = captures.get(1) {
                        return Some(challenge.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    fn is_weak_challenge(&self, challenge: &str) -> bool {
        if challenge.len() < 16 {
            return true;
        }

        if let Some(first_char) = challenge.chars().next() {
            if challenge.chars().all(|c| c == first_char) {
                return true;
            }
        }

        if challenge == "AAAAAAAAAAAAAAAA"
            || challenge == "0000000000000000"
            || challenge == "1111111111111111"
        {
            return true;
        }

        let unique_chars: std::collections::HashSet<char> = challenge.chars().collect();
        if unique_chars.len() < 4 {
            return true;
        }

        false
    }

    fn build_url(&self, base: &str, path: &str) -> String {
        if let Ok(parsed) = url::Url::parse(base) {
            let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if base_url.ends_with('/') && path.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else if !base_url.ends_with('/') && !path.starts_with('/') {
                format!("{}/{}", base_url, path)
            } else {
                format!("{}{}", base_url, path)
            }
        } else {
            format!("{}{}", base, path)
        }
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("webauthn_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Weak WebAuthn Configuration" => {
                "1. Set attestation to 'direct' or 'indirect' for production\n\
                 2. Require userVerification='required' for sensitive operations\n\
                 3. Set requireResidentKey=true for passwordless authentication\n\
                 4. Use authenticatorAttachment='platform' for device-bound credentials\n\
                 5. Implement proper timeout values (60-120 seconds)\n\
                 6. Follow W3C WebAuthn Level 2 specifications\n\
                 7. Regular security audits of WebAuthn implementation\n\
                 8. Test with FIDO2 conformance tools"
                    .to_string()
            }
            "Predictable WebAuthn Challenge"
            | "Weak WebAuthn Challenge"
            | "WebAuthn Accepts Weak Challenges" => {
                "1. Generate challenges using cryptographically secure random number generator\n\
                 2. Use at least 32 bytes of entropy for challenges\n\
                 3. Store challenges server-side with short expiration (2-5 minutes)\n\
                 4. Never accept client-provided challenges\n\
                 5. Implement one-time use for challenges\n\
                 6. Use crypto.getRandomValues() or equivalent\n\
                 7. Validate challenge in every authentication/registration request\n\
                 8. Log and monitor for challenge reuse attempts"
                    .to_string()
            }
            "WebAuthn Endpoint Missing CSRF Protection" => {
                "1. Implement CSRF tokens for all WebAuthn endpoints\n\
                 2. Use SameSite cookie attribute\n\
                 3. Validate Origin and Referer headers\n\
                 4. Implement double-submit cookie pattern\n\
                 5. Use framework-specific CSRF protection\n\
                 6. Require authentication before challenge generation\n\
                 7. Rate limit WebAuthn endpoints\n\
                 8. Monitor for unusual registration patterns"
                    .to_string()
            }
            "Weak User Verification Allowed" => {
                "1. Set userVerification='required' for sensitive operations\n\
                 2. Reject 'discouraged' user verification in production\n\
                 3. Enforce biometric or PIN verification\n\
                 4. Validate UV flag in authenticator data\n\
                 5. Document user verification requirements\n\
                 6. Test with different authenticator types\n\
                 7. Implement step-up authentication for critical actions\n\
                 8. Regular security testing of verification flow"
                    .to_string()
            }
            "Missing WebAuthn Origin Validation" => "1. Validate origin matches expected RP ID\n\
                 2. Parse and verify clientDataJSON origin field\n\
                 3. Reject null, localhost, or unexpected origins\n\
                 4. Use strict origin matching (no wildcards)\n\
                 5. Validate both Origin header and clientData origin\n\
                 6. Implement allowlist of valid origins\n\
                 7. Log and alert on invalid origin attempts\n\
                 8. Follow FIDO2 origin validation requirements"
                .to_string(),
            _ => "Follow W3C WebAuthn and FIDO2 security best practices".to_string(),
        }
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection_helpers::AppCharacteristics;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> WebAuthnScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        WebAuthnScanner::new(http_client)
    }

    #[test]
    fn test_is_webauthn_response() {
        let scanner = create_test_scanner();

        let webauthn_json = r#"{"challenge":"abc123","publicKey":{"rpId":"example.com"}}"#;
        assert!(scanner.is_webauthn_response(webauthn_json));

        let attestation = r#"{"attestation":"direct","authenticatorSelection":{}}"#;
        assert!(scanner.is_webauthn_response(attestation));
    }

    #[test]
    fn test_has_weak_configuration() {
        let scanner = create_test_scanner();

        assert!(scanner.has_weak_configuration(r#"{"attestation":"none"}"#));
        assert!(scanner.has_weak_configuration(r#"{"userVerification":"discouraged"}"#));
        assert!(!scanner.has_weak_configuration(r#"{"userVerification":"required"}"#));
    }

    #[test]
    fn test_extract_challenge() {
        let scanner = create_test_scanner();

        let json = r#"{"challenge":"Y2hhbGxlbmdlMTIz","user":{"id":"test"}}"#;
        assert_eq!(
            scanner.extract_challenge(json),
            Some("Y2hhbGxlbmdlMTIz".to_string())
        );
    }

    #[test]
    fn test_is_weak_challenge() {
        let scanner = create_test_scanner();

        assert!(scanner.is_weak_challenge("AAAA"));
        assert!(scanner.is_weak_challenge("0000000000000000"));
        assert!(scanner.is_weak_challenge("AAAAAAAAAAAAAAAA"));
        assert!(!scanner.is_weak_challenge("aB3dE7gH9jK2mN5pQ8rS1tU4vW6xY0z"));
    }

    #[test]
    fn test_has_proper_csrf_protection() {
        let scanner = create_test_scanner();
        let mut headers = std::collections::HashMap::new();

        assert!(!scanner.has_proper_csrf_protection(&headers));

        headers.insert("X-CSRF-Token".to_string(), "token123".to_string());
        assert!(scanner.has_proper_csrf_protection(&headers));

        headers.clear();
        headers.insert("X-XSRF-Token".to_string(), "token456".to_string());
        assert!(scanner.has_proper_csrf_protection(&headers));
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.build_url("https://example.com", "/api/webauthn"),
            "https://example.com/api/webauthn"
        );
    }
}
