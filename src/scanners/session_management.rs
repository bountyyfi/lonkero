// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Session Management Scanner
 * Tests for session management vulnerabilities
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct SessionManagementScanner {
    http_client: Arc<HttpClient>,
}

impl SessionManagementScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for session management vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[SessionMgmt] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get initial response to check cookies
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => {
                debug!("[NOTE] [SessionMgmt] Could not fetch URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        // CRITICAL: First check if the site actually uses sessions/authentication
        // Skip session scanning for static sites without any session mechanism
        tests_run += 1;
        let has_session_mechanism = self.detect_session_mechanism(&response);

        // Also use AppCharacteristics for intelligent detection
        let characteristics = AppCharacteristics::from_response(&response, url);
        if !has_session_mechanism || characteristics.should_skip_auth_tests() {
            info!("[SessionMgmt] No session mechanism detected - skipping session tests (likely static site)");
            return Ok((vulnerabilities, tests_run));
        }

        // Test 1: Check session cookie security
        tests_run += 1;
        self.check_cookie_security(&response, url, &mut vulnerabilities);

        // Test 2: Check session fixation
        tests_run += 1;
        self.check_session_fixation(&response, url, &mut vulnerabilities);

        // Test 3: Check session ID predictability
        tests_run += 1;
        self.check_session_id_predictability(&response, url, &mut vulnerabilities);

        // Test 4: Check session timeout (only if we have actual session cookies)
        tests_run += 1;
        if self.has_session_cookie(&response) {
            self.check_session_timeout(&response, url, &mut vulnerabilities);
        }

        // Test 5: Check session ID in URL
        tests_run += 1;
        self.check_session_in_url(url, &mut vulnerabilities);

        // Test 6: Check concurrent sessions (only with actual sessions)
        tests_run += 1;
        if self.has_session_cookie(&response) {
            self.check_concurrent_sessions(&response, url, &mut vulnerabilities);
        }

        // Test 7: Check logout functionality
        tests_run += 1;
        self.check_logout_security(&response, url, &mut vulnerabilities);

        info!(
            "[SUCCESS] [SessionMgmt] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if the site actually uses session/authentication mechanisms
    fn detect_session_mechanism(&self, response: &crate::http_client::HttpResponse) -> bool {
        // Check 1: Actual session cookies in Set-Cookie header
        if self.has_session_cookie(response) {
            return true;
        }

        // Check 2: Authentication-related headers
        let auth_headers = ["www-authenticate", "authorization", "x-auth-token"];
        for header in &auth_headers {
            if response.header(header).is_some() {
                return true;
            }
        }

        // Check 3: Login/auth forms in HTML (actual forms, not just text mentions)
        let body_lower = response.body.to_lowercase();
        let has_login_form = body_lower.contains("<form")
            && (body_lower.contains("type=\"password\"")
                || body_lower.contains("type='password'")
                || body_lower.contains("name=\"password\"")
                || body_lower.contains("name='password'"));

        if has_login_form {
            return true;
        }

        // Check 4: OAuth/OIDC indicators (actual implementation, not just mentions)
        let oauth_indicators = [
            "oauth/authorize",
            "oauth2/authorize",
            "/auth/callback",
            "client_id=",
            "response_type=code",
            "response_type=token",
        ];
        for indicator in &oauth_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Check if response has actual session cookies
    fn has_session_cookie(&self, response: &crate::http_client::HttpResponse) -> bool {
        if let Some(set_cookie) = response.header("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();
            return cookie_lower.contains("session")
                || cookie_lower.contains("jsessionid")
                || cookie_lower.contains("phpsessid")
                || cookie_lower.contains("asp.net_sessionid")
                || cookie_lower.contains("auth")
                || cookie_lower.contains("token")
                || cookie_lower.contains("sid=");
        }
        false
    }

    /// Check cookie security attributes
    fn check_cookie_security(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(set_cookie) = response.header("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();

            // Check if it's a session cookie
            let is_session = cookie_lower.contains("session")
                || cookie_lower.contains("jsessionid")
                || cookie_lower.contains("phpsessid")
                || cookie_lower.contains("asp.net_sessionid");

            if is_session {
                // Check for HttpOnly flag
                if !cookie_lower.contains("httponly") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Session Cookie Missing HttpOnly",
                        url,
                        Severity::High,
                        Confidence::High,
                        "Session cookie lacks HttpOnly flag - vulnerable to XSS theft",
                        format!(
                            "Cookie: {}",
                            set_cookie.chars().take(100).collect::<String>()
                        ),
                        7.5,
                    ));
                }

                // Check for Secure flag
                if url.starts_with("https") && !cookie_lower.contains("secure") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Session Cookie Missing Secure Flag",
                        url,
                        Severity::High,
                        Confidence::High,
                        "Session cookie lacks Secure flag - vulnerable to interception",
                        format!(
                            "HTTPS site with insecure cookie: {}",
                            set_cookie.chars().take(100).collect::<String>()
                        ),
                        7.4,
                    ));
                }

                // Check for SameSite attribute
                if !cookie_lower.contains("samesite") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Session Cookie Missing SameSite",
                        url,
                        Severity::Medium,
                        Confidence::High,
                        "Session cookie lacks SameSite attribute - vulnerable to CSRF",
                        "No SameSite attribute on session cookie".to_string(),
                        6.1,
                    ));
                }

                // Check for weak SameSite=None
                if cookie_lower.contains("samesite=none") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Session Cookie Uses SameSite=None",
                        url,
                        Severity::Medium,
                        Confidence::High,
                        "Session cookie uses SameSite=None - no CSRF protection",
                        "SameSite=None provides no protection against CSRF".to_string(),
                        5.9,
                    ));
                }

                // Check cookie expiration (session vs persistent)
                if cookie_lower.contains("max-age") || cookie_lower.contains("expires") {
                    // Extract max-age value if possible
                    if let Some(max_age_pos) = cookie_lower.find("max-age=") {
                        let max_age_str = &cookie_lower[max_age_pos + 8..];
                        if let Some(semicolon) = max_age_str.find(';') {
                            let max_age_value = &max_age_str[..semicolon];
                            if let Ok(seconds) = max_age_value.trim().parse::<u64>() {
                                // More than 24 hours (86400 seconds)
                                if seconds > 86400 {
                                    vulnerabilities.push(self.create_vulnerability(
                                        "Session Cookie Excessive Lifetime",
                                        url,
                                        Severity::Medium,
                                        Confidence::High,
                                        "Session cookie has excessive lifetime - increases attack window",
                                        format!("Session lifetime: {} seconds (>24 hours)", seconds),
                                        5.3,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for session fixation vulnerabilities
    /// Only reports when there is concrete evidence (session params in URL),
    /// not keyword matching in response bodies which causes false positives.
    fn check_session_fixation(
        &self,
        _response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Only report if a known session parameter is in the URL query string.
        // The old approach of searching for "session" in HTML body produces
        // false positives on any page mentioning sessions (docs, UI text, etc.)
        let url_lower = url.to_lowercase();
        let has_session_param = url_lower.contains("jsessionid=")
            || url_lower.contains("phpsessid=")
            || url_lower.contains("sessionid=")
            || url_lower.contains("session_id=")
            || url_lower.contains("aspsessionid=");

        if has_session_param {
            vulnerabilities.push(self.create_vulnerability(
                "Session ID in URL (Fixation Risk)",
                url,
                Severity::High,
                Confidence::High,
                "Session ID passed via URL parameter - vulnerable to session fixation and referrer leakage",
                "Known session parameter found in URL query string".to_string(),
                7.1,
            ));
        }

        // Note: "Session Not Regenerated After Login" check removed because
        // searching for "session_regenerate" in HTML response body is unreliable:
        // 1. Session regeneration is server-side logic not visible in HTML
        // 2. SPAs use token rotation, not PHP-style session_regenerate
        // 3. Keyword matching on "login" produces false positives on every
        //    page with a login link/button
    }

    /// Check session ID predictability
    fn check_session_id_predictability(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(set_cookie) = response.header("set-cookie") {
            // Extract session ID value
            if let Some(eq_pos) = set_cookie.find('=') {
                if let Some(semicolon) = set_cookie.find(';') {
                    let session_value = &set_cookie[eq_pos + 1..semicolon];

                    // Check for short/weak session IDs
                    if session_value.len() < 16 {
                        vulnerabilities.push(self.create_vulnerability(
                            "Weak Session ID Length",
                            url,
                            Severity::High,
                            Confidence::Medium,
                            "Session ID is too short - vulnerable to brute force",
                            format!(
                                "Session ID length: {} chars (minimum: 16)",
                                session_value.len()
                            ),
                            7.0,
                        ));
                    }

                    // Check for sequential/predictable patterns
                    if session_value.chars().all(|c| c.is_numeric()) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Predictable Session ID",
                            url,
                            Severity::Critical,
                            Confidence::Medium,
                            "Session ID uses only numbers - highly predictable",
                            "Session ID appears to be sequential/numeric".to_string(),
                            8.1,
                        ));
                    }

                    // Check for timestamp-based IDs
                    if session_value.len() == 10 && session_value.chars().all(|c| c.is_numeric()) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Timestamp-Based Session ID",
                            url,
                            Severity::Critical,
                            Confidence::Medium,
                            "Session ID appears to be timestamp-based - predictable",
                            "10-digit numeric session ID suggests timestamp".to_string(),
                            8.5,
                        ));
                    }
                }
            }
        }
    }

    /// Check session timeout configuration
    /// Note: Session timeout is a server-side configuration that cannot be
    /// reliably detected by scanning HTML response bodies. Searching for
    /// "timeout" keywords in HTML produces false positives. Instead, we only
    /// check the actual cookie attributes which are observable.
    fn check_session_timeout(
        &self,
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Intentionally not reporting based on body keyword matching.
        // Session timeout is configured server-side (web.xml, php.ini, etc.)
        // and cannot be detected by scanning HTML responses.
        // The cookie lifetime check in check_cookie_security() already
        // reports excessively long cookie max-age values.
    }

    /// Check for session ID in URL
    fn check_session_in_url(&self, url: &str, vulnerabilities: &mut Vec<Vulnerability>) {
        let url_lower = url.to_lowercase();

        let session_params = vec![
            "sessionid=",
            "session=",
            "sid=",
            "jsessionid=",
            "phpsessid=",
            "aspsessionid=",
            "token=",
        ];

        for param in &session_params {
            if url_lower.contains(param) {
                vulnerabilities.push(self.create_vulnerability(
                    "Session ID in URL",
                    url,
                    Severity::High,
                    Confidence::High,
                    "Session ID exposed in URL - vulnerable to referrer leakage and logs",
                    format!("Session parameter '{}' found in URL", param),
                    7.5,
                ));
                break;
            }
        }
    }

    /// Check concurrent session handling
    /// Note: Concurrent session limits are a server-side policy that cannot
    /// be detected by scanning HTML. Removed body keyword matching.
    fn check_concurrent_sessions(
        &self,
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Intentionally not reporting. Concurrent session tracking is a
        // server-side feature that cannot be detected from a single HTTP response.
        // Searching for "concurrent" or "multiple sessions" in HTML body
        // produces false positives on documentation pages and is not evidence
        // of actual concurrent session handling.
    }

    /// Check logout security
    /// Note: Proper session destruction on logout is server-side behavior
    /// that cannot be detected by scanning HTML response bodies.
    fn check_logout_security(
        &self,
        _response: &crate::http_client::HttpResponse,
        _url: &str,
        _vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Intentionally not reporting. Whether logout properly destroys sessions
        // is server-side behavior. Searching for "destroy" or "invalidate" in
        // HTML body is unreliable - the actual session destruction happens in
        // server-side code not visible in the HTTP response.
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
            id: format!("session_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Session Management - {}", title),
            severity,
            confidence,
            category: "Session Management".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-384".to_string(), // Session Fixation
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Set Secure Cookie Flags**
   ```javascript
   // Express.js
   app.use(session({
       secret: process.env.SESSION_SECRET,
       cookie: {
           httpOnly: true,      // Prevent XSS access
           secure: true,        // HTTPS only
           sameSite: 'strict',  // CSRF protection
           maxAge: 3600000      // 1 hour
       },
       resave: false,
       saveUninitialized: false
   }));
   ```

2. **Regenerate Session After Login**
   ```python
   # Django
   from django.contrib.auth import login

   def user_login(request, user):
       # Clear old session
       request.session.flush()

       # Authenticate and create new session
       login(request, user)

       # Regenerate session ID
       request.session.cycle_key()
   ```

3. **Use Strong Session IDs**
   ```javascript
   // Generate cryptographically random session IDs
   const crypto = require('crypto');

   function generateSessionId() {
       return crypto.randomBytes(32).toString('hex');  // 64 chars
   }

   // Never use:
   // - Sequential numbers
   // - Timestamps
   // - User IDs
   // - Predictable patterns
   ```

4. **Implement Session Timeout**
   ```java
   // Java Servlet
   @WebListener
   public class SessionConfig implements HttpSessionListener {
       @Override
       public void sessionCreated(HttpSessionEvent se) {
           se.getSession().setMaxInactiveInterval(1800);  // 30 minutes
       }
   }

   // Also implement absolute timeout
   session.setAttribute("createdAt", System.currentTimeMillis());

   // Check on each request
   long created = (long) session.getAttribute("createdAt");
   if (System.currentTimeMillis() - created > 28800000) {  // 8 hours
       session.invalidate();
   }
   ```

5. **Never Put Session ID in URL**
   ```javascript
   // WRONG
   res.redirect('/dashboard?sessionid=' + session.id);

   // CORRECT - Use cookies only
   res.cookie('sessionid', session.id, {
       httpOnly: true,
       secure: true,
       sameSite: 'strict'
   });
   res.redirect('/dashboard');
   ```

6. **Limit Concurrent Sessions**
   ```python
   # Track active sessions per user
   class SessionMiddleware:
       def __init__(self, max_sessions=3):
           self.max_sessions = max_sessions
           self.user_sessions = {}  # user_id -> [session_ids]

       def process_request(self, request):
           if request.user.is_authenticated:
               user_id = request.user.id
               current_session = request.session.session_key

               # Get user's sessions
               sessions = self.user_sessions.get(user_id, [])

               # Limit concurrent sessions
               if len(sessions) >= self.max_sessions:
                   oldest_session = sessions.pop(0)
                   Session.objects.filter(session_key=oldest_session).delete()

               # Add current session
               if current_session not in sessions:
                   sessions.append(current_session)
                   self.user_sessions[user_id] = sessions
   ```

7. **Implement Proper Logout**
   ```javascript
   // Node.js Express
   app.post('/logout', (req, res) => {
       // Destroy session server-side
       req.session.destroy((err) => {
           if (err) {
               return res.status(500).send('Logout failed');
           }

           // Clear session cookie
           res.clearCookie('sessionid');

           // Optionally: Blacklist token (if using JWT)
           if (req.session.token) {
               tokenBlacklist.add(req.session.token);
           }

           res.redirect('/login');
       });
   });
   ```

8. **Detect and Prevent Session Fixation**
   ```php
   // PHP
   session_start();

   // Before login
   $old_session_id = session_id();

   // After successful authentication
   if (authenticate($username, $password)) {
       // Regenerate session ID
       session_regenerate_id(true);  // Delete old session

       // Log the change
       log_security_event("Session regenerated", [
           'old_id' => $old_session_id,
           'new_id' => session_id(),
           'user' => $username
       ]);
   }
   ```

9. **Implement Session Binding**
   ```python
   # Bind session to IP and User-Agent
   def validate_session(request):
       session = request.session

       # Check IP address
       if session.get('ip') != request.META.get('REMOTE_ADDR'):
           session.flush()
           raise SecurityException("Session IP mismatch")

       # Check User-Agent
       if session.get('user_agent') != request.META.get('HTTP_USER_AGENT'):
           session.flush()
           raise SecurityException("Session User-Agent mismatch")

       return True

   # Set on session creation
   request.session['ip'] = request.META.get('REMOTE_ADDR')
   request.session['user_agent'] = request.META.get('HTTP_USER_AGENT')
   ```

10. **Security Checklist**
    - [ ] HttpOnly flag on all session cookies
    - [ ] Secure flag on all cookies (HTTPS only)
    - [ ] SameSite=Strict or SameSite=Lax
    - [ ] Session ID length ≥ 128 bits (16+ bytes)
    - [ ] Cryptographically random session IDs
    - [ ] Session regeneration after login
    - [ ] Session timeout: Idle (30 min) + Absolute (8 hours)
    - [ ] No session ID in URLs
    - [ ] Concurrent session limit enforced
    - [ ] Proper session destruction on logout
    - [ ] Session binding (IP + User-Agent)
    - [ ] Comprehensive session logging

11. **Monitoring & Detection**
    - Log all session creation/destruction
    - Alert on session fixation attempts
    - Monitor for session hijacking patterns
    - Track concurrent sessions per user
    - Alert on unusual session access patterns

References:
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-384 (Session Fixation): https://cwe.mitre.org/data/definitions/384.html
- CWE-613 (Insufficient Session Expiration): https://cwe.mitre.org/data/definitions/613.html
"#.to_string(),
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
    use std::collections::HashMap;

    #[test]
    fn test_missing_httponly() {
        let scanner = SessionManagementScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=abc123; Secure".to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cookie_security(&response, "https://example.com", &mut vulns);

        assert!(vulns.len() > 0, "Should detect missing HttpOnly");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_missing_secure_flag() {
        let scanner = SessionManagementScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=abc123; HttpOnly".to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cookie_security(&response, "https://example.com", &mut vulns);

        assert!(vulns.len() > 0, "Should detect missing Secure flag");
    }

    #[test]
    fn test_session_in_url() {
        let scanner = SessionManagementScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut vulns = Vec::new();
        scanner.check_session_in_url("https://example.com/dashboard?sessionid=abc123", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect session ID in URL");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_weak_session_id() {
        let scanner = SessionManagementScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=12345; HttpOnly; Secure".to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_session_id_predictability(&response, "https://example.com", &mut vulns);

        assert!(vulns.len() > 0, "Should detect weak/predictable session ID");
    }

    #[test]
    fn test_secure_cookie() {
        let scanner = SessionManagementScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; HttpOnly; Secure; SameSite=Strict"
                .to_string(),
        );

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cookie_security(&response, "https://example.com", &mut vulns);

        // Should not report issues for secure cookie
        assert_eq!(
            vulns.len(),
            0,
            "Should not report issues for properly configured cookie"
        );
    }
}
