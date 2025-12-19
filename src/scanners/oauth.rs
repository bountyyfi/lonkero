// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - OAuth 2.0 Security Scanner
 * Tests for OAuth 2.0 vulnerabilities and misconfigurations
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use crate::detection_helpers::{AppCharacteristics, endpoint_exists};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, debug};

pub struct OAuthScanner {
    http_client: Arc<HttpClient>,
}

/// OAuth detection result
struct OAuthDetection {
    has_oauth: bool,
    has_oauth_endpoint: bool,
    has_oauth_flow: bool,
    has_oauth_js: bool,
    evidence: Vec<String>,
}

impl OAuthScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for OAuth 2.0 vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[OAuth] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // CRITICAL: First check application characteristics
        // Don't test OAuth on SPAs or sites without real OAuth
        tests_run += 1;
        let baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        if characteristics.should_skip_oauth_tests() {
            info!("[OAuth] No OAuth implementation detected - skipping OAuth tests");
            return Ok((vulnerabilities, tests_run));
        }

        if characteristics.should_skip_injection_tests() {
            info!("[OAuth] Site is SPA/static - OAuth tests not applicable (client-side only)");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[OAuth] Real OAuth detected - proceeding with vulnerability tests");

        // Test 1: Detect ACTUAL OAuth implementation (not just mentions)
        tests_run += 1;
        let oauth_detection = self.detect_oauth_implementation(url).await;

        if !oauth_detection.has_oauth {
            info!("[OAuth] No OAuth implementation detected on closer inspection");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[OAuth] OAuth implementation detected: {:?}", oauth_detection.evidence);

        // Test 2: Check for authorization code in URL (always relevant if URL has code)
        tests_run += 1;
        self.check_code_in_url(url, &mut vulnerabilities);

        // Test 3: Check for access token in URL (always relevant if URL has token)
        tests_run += 1;
        self.check_token_in_url(url, &mut vulnerabilities);

        // Test 4: Test redirect_uri validation (only if OAuth endpoints ACTUALLY exist)
        tests_run += 1;
        if oauth_detection.has_oauth_endpoint {
            // Test common OAuth endpoints
            let oauth_endpoints = vec![
                format!("{}/oauth/authorize", url.trim_end_matches('/')),
                format!("{}/oauth2/authorize", url.trim_end_matches('/')),
            ];

            for endpoint in &oauth_endpoints {
                if let Ok(response) = self.http_client.get(endpoint).await {
                    // CRITICAL: Only test if endpoint exists and isn't SPA fallback
                    if endpoint_exists(&response, &[200, 302, 400, 401]) {
                        self.check_redirect_uri_validation(&response, endpoint, &mut vulnerabilities);
                    } else {
                        debug!("[OAuth] Endpoint {} doesn't exist - skipping", endpoint);
                    }
                }
            }
        }

        // Test 5: Test state parameter (only if actual OAuth flow detected)
        tests_run += 1;
        if oauth_detection.has_oauth_flow {
            if let Ok(response) = self.test_state_parameter(url).await {
                // Only check if response isn't SPA shell
                if endpoint_exists(&response, &[200]) {
                    self.check_state_parameter(&response, url, &mut vulnerabilities);
                }
            }
        }

        // Test 6: Test for open redirector (only if OAuth endpoints found)
        tests_run += 1;
        if oauth_detection.has_oauth_endpoint {
            if let Ok(response) = self.test_open_redirect(url).await {
                if endpoint_exists(&response, &[302, 301]) {
                    self.check_open_redirect(&response, url, &mut vulnerabilities);
                }
            }
        }

        // Test 7: Check for insecure token storage (if OAuth JS code found)
        tests_run += 1;
        if oauth_detection.has_oauth_js {
            if let Ok(response) = self.http_client.get(url).await {
                self.check_insecure_token_storage(&response, url, &mut vulnerabilities);
            }
        }

        // Test 8: Test PKCE support (only for actual OAuth endpoints)
        tests_run += 1;
        if oauth_detection.has_oauth_endpoint {
            if let Ok(response) = self.test_pkce_support(url).await {
                if endpoint_exists(&response, &[200, 400]) {
                    self.check_pkce_support(&response, url, &mut vulnerabilities);
                }
            }
        }

        // Test 9: Test client_secret exposure (if OAuth JS code found)
        tests_run += 1;
        if oauth_detection.has_oauth_js {
            if let Ok(response) = self.http_client.get(url).await {
                self.check_client_secret_exposure(&response, url, &mut vulnerabilities);
            }
        }

        // Deduplicate vulnerabilities by type
        // Multiple OAuth endpoints (/oauth/authorize, /oauth2/authorize) might trigger same vulns
        let mut seen_types = HashSet::new();
        let unique_vulns: Vec<Vulnerability> = vulnerabilities
            .into_iter()
            .filter(|v| {
                let key = format!("{}:{}", v.vuln_type, v.parameter.as_ref().unwrap_or(&String::new()));
                seen_types.insert(key)
            })
            .collect();

        info!(
            "[SUCCESS] [OAuth] Completed {} tests, found {} unique issues",
            tests_run,
            unique_vulns.len()
        );

        Ok((unique_vulns, tests_run))
    }

    /// Detect ACTUAL OAuth implementation (not just keyword mentions)
    async fn detect_oauth_implementation(&self, url: &str) -> OAuthDetection {
        let mut detection = OAuthDetection {
            has_oauth: false,
            has_oauth_endpoint: false,
            has_oauth_flow: false,
            has_oauth_js: false,
            evidence: Vec::new(),
        };

        // Check URL for OAuth parameters
        let url_lower = url.to_lowercase();
        if url_lower.contains("client_id=") || url_lower.contains("response_type=") {
            detection.has_oauth = true;
            detection.has_oauth_flow = true;
            detection.evidence.push("OAuth parameters in URL".to_string());
        }

        // CRITICAL: Don't just check URL path - SPAs have client-side routes!
        // Only mark as OAuth endpoint if it's an actual server endpoint
        if url_lower.contains("/oauth") || url_lower.contains("/authorize") || url_lower.contains("/token") {
            // Will verify later if endpoint actually exists
            detection.evidence.push("OAuth-like path in URL".to_string());
        }

        // Fetch and analyze response
        if let Ok(response) = self.http_client.get(url).await {
            let body = &response.body;
            let body_lower = body.to_lowercase();

            // Check for actual OAuth endpoints in links/forms
            let oauth_endpoint_patterns = [
                "/oauth/authorize",
                "/oauth2/authorize",
                "/oauth/token",
                "/oauth2/token",
                "accounts.google.com/o/oauth2",
                "login.microsoftonline.com",
                "github.com/login/oauth",
                "facebook.com/v",
            ];

            for pattern in &oauth_endpoint_patterns {
                if body_lower.contains(pattern) {
                    detection.has_oauth = true;
                    detection.has_oauth_endpoint = true;
                    detection.evidence.push(format!("OAuth endpoint: {}", pattern));
                    break;
                }
            }

            // Check for OAuth flow in JavaScript (actual implementation, not just docs)
            let oauth_js_patterns = [
                "oauth.authorize(",
                "gapi.auth2",
                "FB.login(",
                "MSAL.",
                "oauth2client",
                "authorizationurl",
                "getaccesstoken",
            ];

            for pattern in &oauth_js_patterns {
                if body_lower.contains(pattern) {
                    detection.has_oauth = true;
                    detection.has_oauth_js = true;
                    detection.evidence.push(format!("OAuth JS: {}", pattern));
                    break;
                }
            }

            // Check for OAuth response parameters being handled
            if (body_lower.contains("response_type") && body_lower.contains("client_id"))
                || (body_lower.contains("access_token") && body_lower.contains("token_type"))
            {
                detection.has_oauth = true;
                detection.has_oauth_flow = true;
                detection.evidence.push("OAuth flow parameters".to_string());
            }

            // Check headers for OAuth
            if response.header("www-authenticate").map(|h| h.to_lowercase().contains("bearer")).unwrap_or(false) {
                detection.has_oauth = true;
                detection.evidence.push("Bearer authentication header".to_string());
            }
        }

        detection
    }

    /// Detect OAuth endpoint
    async fn detect_oauth_endpoint(&self, url: &str) -> bool {
        match self.http_client.get(url).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();
                body_lower.contains("oauth")
                    || body_lower.contains("authorization")
                    || body_lower.contains("access_token")
                    || body_lower.contains("client_id")
                    || body_lower.contains("redirect_uri")
            }
            Err(_) => false,
        }
    }

    /// Check for authorization code in URL (CVE-2016-1000351)
    fn check_code_in_url(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        if url.contains("code=") || url.contains("authorization_code=") {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth Authorization Code in URL",
                url,
                Severity::High,
                Confidence::High,
                "Authorization code exposed in URL - vulnerable to referrer leakage and browser history",
                "URL contains 'code=' parameter with authorization code".to_string(),
                6.5,
            ));
        }
    }

    /// Check for access token in URL (critical vulnerability)
    fn check_token_in_url(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        if url.contains("access_token=") || url.contains("token=") {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth Access Token in URL",
                url,
                Severity::Critical,
                Confidence::High,
                "Access token exposed in URL - severe security risk via referrer leakage",
                "URL contains 'access_token=' or 'token=' parameter".to_string(),
                9.1,
            ));
        }
    }

    /// Test redirect_uri validation
    async fn test_redirect_uri_validation(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Try to inject malicious redirect_uri
        let test_url = if url.contains('?') {
            format!("{}&redirect_uri=https://evil.com/callback", url)
        } else {
            format!("{}?redirect_uri=https://evil.com/callback", url)
        };

        self.http_client.get(&test_url).await
    }

    /// Check redirect_uri validation
    fn check_redirect_uri_validation(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If redirect succeeded or was accepted, validation is weak
        if response.status_code == 302 || response.status_code == 301 {
            if let Some(location) = response.header("location") {
                if location.contains("evil.com") {
                    vulnerabilities.push(self.create_vulnerability(
                        "OAuth redirect_uri Not Validated",
                        url,
                        Severity::Critical,
                        Confidence::High,
                        "OAuth provider accepts arbitrary redirect_uri - authorization code/token theft",
                        format!("Redirected to attacker domain: {}", location),
                        8.1,
                    ));
                }
            }
        } else if response.status_code == 200 && response.body.contains("evil.com") {
            // Check if malicious redirect_uri appears in response
            vulnerabilities.push(self.create_vulnerability(
                "OAuth redirect_uri Validation Weak",
                url,
                Severity::High,
                Confidence::Medium,
                "OAuth endpoint accepts unvalidated redirect_uri parameter",
                "Malicious redirect_uri parameter was processed".to_string(),
                7.4,
            ));
        }
    }

    /// Test state parameter (CSRF protection)
    async fn test_state_parameter(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Request without state parameter
        self.http_client.get(url).await
    }

    /// Check state parameter usage
    fn check_state_parameter(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // CRITICAL: Be MUCH more strict - don't just look for keywords!
        // Check if this is an actual OAuth authorization page with forms/inputs
        let is_oauth_auth_page = (body_lower.contains("<form") || body_lower.contains("action=")) &&
                                  (body_lower.contains("client_id") || body_lower.contains("response_type")) &&
                                  (body_lower.contains("oauth") || body_lower.contains("authorize"));

        // Only check for missing state if it's a REAL OAuth page
        if is_oauth_auth_page && !body_lower.contains("state") && !url.contains("state=") {
            vulnerabilities.push(self.create_vulnerability(
                "Missing OAuth state Parameter",
                url,
                Severity::Medium,
                Confidence::Medium,
                "OAuth flow does not enforce state parameter - vulnerable to CSRF",
                "No state parameter detected in OAuth authorization flow".to_string(),
                5.9,
            ));
        }
    }

    /// Test for open redirector
    async fn test_open_redirect(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let test_url = if url.contains('?') {
            format!("{}&redirect_uri=https://evil.com", url)
        } else {
            format!("{}?redirect_uri=https://evil.com", url)
        };

        self.http_client.get(&test_url).await
    }

    /// Check for open redirect
    fn check_open_redirect(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 302 || response.status_code == 301 {
            if let Some(location) = response.header("location") {
                if location.contains("evil.com") || location.starts_with("https://evil.com") {
                    vulnerabilities.push(self.create_vulnerability(
                        "OAuth Open Redirector",
                        url,
                        Severity::High,
                        Confidence::High,
                        "OAuth endpoint vulnerable to open redirect - enables phishing attacks",
                        format!("Redirected to: {}", location),
                        6.8,
                    ));
                }
            }
        }
    }

    /// Check for insecure token storage
    fn check_insecure_token_storage(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check if tokens are stored in localStorage or sessionStorage
        if body_lower.contains("localstorage.setitem") && body_lower.contains("access_token") {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth Token in localStorage",
                url,
                Severity::High,
                Confidence::Medium,
                "OAuth access token stored in localStorage - vulnerable to XSS",
                "JavaScript code stores access_token in localStorage".to_string(),
                7.1,
            ));
        }

        if body_lower.contains("sessionstorage.setitem") && body_lower.contains("access_token") {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth Token in sessionStorage",
                url,
                Severity::High,
                Confidence::Medium,
                "OAuth access token stored in sessionStorage - vulnerable to XSS",
                "JavaScript code stores access_token in sessionStorage".to_string(),
                7.1,
            ));
        }
    }

    /// Test PKCE support
    async fn test_pkce_support(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Request with PKCE parameters
        let test_url = if url.contains('?') {
            format!("{}&code_challenge=test&code_challenge_method=S256", url)
        } else {
            format!("{}?code_challenge=test&code_challenge_method=S256", url)
        };

        self.http_client.get(&test_url).await
    }

    /// Check PKCE support
    fn check_pkce_support(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // If this looks like a public client (SPA/mobile) but PKCE not mentioned
        if (body_lower.contains("public") || body_lower.contains("spa") || body_lower.contains("mobile"))
            && !body_lower.contains("code_challenge")
            && !body_lower.contains("pkce")
        {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth PKCE Not Implemented",
                url,
                Severity::Medium,
                Confidence::Low,
                "Public OAuth client does not use PKCE - vulnerable to authorization code interception",
                "No PKCE (code_challenge) detected for public client".to_string(),
                5.3,
            ));
        }
    }

    /// Check for client_secret exposure
    fn check_client_secret_exposure(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body = &response.body;
        let body_lower = body.to_lowercase();

        // Check for client_secret in response body or JavaScript (both snake_case and camelCase)
        if (body_lower.contains("client_secret") || body_lower.contains("clientsecret"))
            && (body.contains("=") || body.contains(":")) {
            vulnerabilities.push(self.create_vulnerability(
                "OAuth client_secret Exposed",
                url,
                Severity::Critical,
                Confidence::High,
                "OAuth client_secret exposed in client-side code - complete account takeover",
                "client_secret found in HTTP response body".to_string(),
                9.8,
            ));
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("oauth_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("OAuth 2.0 Vulnerability - {}", title),
            severity,
            confidence,
            category: "Authentication".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-346".to_string(), // Origin Validation Error
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Implement Strict redirect_uri Validation**
   ```python
   # Django example
   ALLOWED_REDIRECT_URIS = [
       'https://app.example.com/callback',
       'https://app.example.com/oauth/callback'
   ]

   def validate_redirect_uri(redirect_uri):
       if redirect_uri not in ALLOWED_REDIRECT_URIS:
           raise ValueError('Invalid redirect_uri')
       return redirect_uri
   ```

2. **Always Use state Parameter (CSRF Protection)**
   ```javascript
   // Generate cryptographically random state
   const state = crypto.randomBytes(32).toString('hex');
   sessionStorage.setItem('oauth_state', state);

   const authUrl = `${authEndpoint}?` +
     `client_id=${clientId}&` +
     `redirect_uri=${redirectUri}&` +
     `state=${state}&` +
     `response_type=code`;

   // On callback, validate state
   if (receivedState !== sessionStorage.getItem('oauth_state')) {
     throw new Error('State mismatch - possible CSRF');
   }
   ```

3. **Use Authorization Code Flow (NOT Implicit Flow)**
   ```javascript
   // CORRECT: Authorization Code Flow
   response_type=code  // Returns code, not token

   // WRONG: Implicit Flow (deprecated)
   response_type=token  // Returns token in URL - NEVER USE
   ```

4. **Implement PKCE for Public Clients (SPA/Mobile)**
   ```javascript
   // Generate PKCE challenge
   function generateCodeVerifier() {
     return crypto.randomBytes(32).toString('base64url');
   }

   function generateCodeChallenge(verifier) {
     return crypto.createHash('sha256')
       .update(verifier)
       .digest('base64url');
   }

   const codeVerifier = generateCodeVerifier();
   const codeChallenge = generateCodeChallenge(codeVerifier);

   // Authorization request
   const authUrl = `${authEndpoint}?` +
     `code_challenge=${codeChallenge}&` +
     `code_challenge_method=S256&` +
     `client_id=${clientId}`;

   // Token request includes verifier
   const tokenResponse = await fetch(tokenEndpoint, {
     method: 'POST',
     body: new URLSearchParams({
       code: authCode,
       code_verifier: codeVerifier,
       grant_type: 'authorization_code'
     })
   });
   ```

5. **Secure Token Storage**
   ```javascript
   // WRONG - vulnerable to XSS
   localStorage.setItem('access_token', token);
   sessionStorage.setItem('access_token', token);

   // CORRECT - use HttpOnly cookies
   // Server sets cookie with flags:
   Set-Cookie: access_token=xxx; HttpOnly; Secure; SameSite=Strict

   // Or use in-memory storage for SPAs
   let accessToken = null;  // In closure, not global
   ```

6. **NEVER Expose client_secret Client-Side**
   ```javascript
   // WRONG - client_secret in JavaScript
   const clientSecret = 'abc123...';  // NEVER DO THIS

   // CORRECT - use backend proxy
   // Frontend calls backend, backend uses client_secret
   const response = await fetch('/api/oauth/token', {
     method: 'POST',
     body: JSON.stringify({ code: authCode })
   });
   // Backend handles client_secret securely
   ```

7. **Use Short-Lived Access Tokens**
   ```python
   # Issue access tokens with 1-hour expiry
   access_token_expires = timedelta(hours=1)

   # Issue refresh tokens with 30-day expiry
   refresh_token_expires = timedelta(days=30)
   ```

8. **Implement Token Rotation**
   ```javascript
   // Rotate refresh tokens on each use
   async function refreshAccessToken(refreshToken) {
     const response = await fetch(tokenEndpoint, {
       method: 'POST',
       body: new URLSearchParams({
         grant_type: 'refresh_token',
         refresh_token: refreshToken
       })
     });

     const data = await response.json();
     // New access_token AND new refresh_token
     return {
       accessToken: data.access_token,
       newRefreshToken: data.refresh_token  // Invalidates old one
     };
   }
   ```

9. **Validate Audience and Issuer (JWT tokens)**
   ```javascript
   const jwt = require('jsonwebtoken');

   jwt.verify(token, publicKey, {
     audience: 'https://api.example.com',
     issuer: 'https://auth.example.com',
     algorithms: ['RS256']  // Never allow alg:none
   });
   ```

10. **Use HTTPS Only**
    - All OAuth endpoints MUST use HTTPS
    - Set Secure flag on all cookies
    - Use HSTS headers

11. **Implement Rate Limiting**
    ```python
    # Limit token endpoint requests
    @ratelimit(key='ip', rate='10/m', method='POST')
    def token_endpoint(request):
        # Token generation logic
        pass
    ```

12. **Security Checklist**
    - [ ] redirect_uri strictly validated against allowlist
    - [ ] state parameter required and validated
    - [ ] PKCE implemented for public clients
    - [ ] client_secret NEVER exposed client-side
    - [ ] Access tokens NOT in URL
    - [ ] Access tokens NOT in localStorage/sessionStorage
    - [ ] HttpOnly, Secure, SameSite cookies
    - [ ] Short-lived access tokens (≤1 hour)
    - [ ] Refresh token rotation implemented
    - [ ] HTTPS enforced everywhere
    - [ ] Rate limiting on token endpoint
    - [ ] Comprehensive logging and monitoring

References:
- OAuth 2.0 Security Best Current Practice: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- OAuth 2.0 for Browser-Based Apps: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
- PKCE RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
- OWASP OAuth 2.0 Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
    use std::collections::HashMap;

    #[test]
    fn test_code_in_url_detection() {
        let scanner = OAuthScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_code_in_url("https://app.example.com/callback?code=abc123", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect authorization code in URL");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_token_in_url_detection() {
        let scanner = OAuthScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_token_in_url("https://app.example.com/callback?access_token=xyz789", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect access token in URL");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_redirect_uri_validation() {
        let scanner = OAuthScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("location".to_string(), "https://evil.com/callback?code=abc123".to_string());

        let response = crate::http_client::HttpResponse {
            status_code: 302,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_redirect_uri_validation(&response, "https://auth.example.com/authorize", &mut vulns);

        assert!(vulns.len() > 0, "Should detect unvalidated redirect_uri");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_client_secret_exposure() {
        let scanner = OAuthScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"const clientSecret = "sk_live_abc123def456";"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_client_secret_exposure(&response, "https://app.example.com/config.js", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect exposed client_secret");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_insecure_token_storage() {
        let scanner = OAuthScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"localStorage.setItem('access_token', token);"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_insecure_token_storage(&response, "https://app.example.com/app.js", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect localStorage token storage");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
