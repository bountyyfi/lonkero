// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Authentication Flow Testing Scanner
 * Comprehensive testing of complete authentication journeys
 *
 * Tests:
 * - Session Fixation (session ID regeneration after login)
 * - Password Reset IDOR (user parameter manipulation)
 * - MFA Bypass (debug parameters, empty codes, direct access)
 * - Predictable Session Tokens (entropy and pattern analysis)
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

pub struct AuthFlowTester {
    http_client: Arc<HttpClient>,
}

impl AuthFlowTester {
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

        info!("[AuthFlow] Starting comprehensive authentication flow security testing");

        // Test 1: Session Fixation
        info!("[AuthFlow] Testing session fixation vulnerability");
        let (session_vulns, session_tests) = self.test_session_fixation(url).await;
        vulnerabilities.extend(session_vulns);
        tests_run += session_tests;

        // Test 2: Password Reset IDOR
        info!("[AuthFlow] Testing password reset IDOR");
        let (reset_vulns, reset_tests) = self.test_password_reset_idor(url).await;
        vulnerabilities.extend(reset_vulns);
        tests_run += reset_tests;

        // Test 3: MFA Bypass via Debug Parameters
        info!("[AuthFlow] Testing MFA bypass techniques");
        let (mfa_vulns, mfa_tests) = self.test_mfa_bypass_techniques(url).await;
        vulnerabilities.extend(mfa_vulns);
        tests_run += mfa_tests;

        // Test 4: Predictable Session Tokens
        info!("[AuthFlow] Testing session token predictability");
        let (token_vulns, token_tests) = self.test_session_token_predictability(url).await;
        vulnerabilities.extend(token_vulns);
        tests_run += token_tests;

        info!(
            "[SUCCESS] [AuthFlow] Completed {} tests, found {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Test 1: Session Fixation
    /// Get session ID before login, perform login, check if session ID changed
    async fn test_session_fixation(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[AuthFlow] Testing session fixation");

        // Discover login endpoints
        let login_endpoints = self.discover_login_endpoints(url).await;

        if login_endpoints.is_empty() {
            debug!("[AuthFlow] No login endpoints found for session fixation test");
            return (vulnerabilities, tests_run);
        }

        for login_url in &login_endpoints {
            tests_run += 1;

            // Step 1: Get session ID before login
            let pre_login_response = match self.http_client.get(login_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let pre_login_sessions = extract_all_session_cookies(&pre_login_response.headers);

            if pre_login_sessions.is_empty() {
                debug!("[AuthFlow] No session cookies found at {}", login_url);
                continue;
            }

            debug!(
                "[AuthFlow] Pre-login sessions collected: {} cookies",
                pre_login_sessions.len()
            );

            // Step 2: Attempt login (using test credentials)
            // Try common test credentials - if they fail, that's okay, we're looking for session ID change
            let test_credentials = vec![
                ("username=test&password=test", "application/x-www-form-urlencoded"),
                (r#"{"username":"test","password":"test"}"#, "application/json"),
            ];

            for (body, content_type) in &test_credentials {
                let headers = vec![("Content-Type".to_string(), content_type.to_string())];

                let post_login_response = match self
                    .http_client
                    .post_with_headers(login_url, body, headers)
                    .await
                {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                // Check if we got new session cookies
                let post_login_sessions = extract_all_session_cookies(&post_login_response.headers);

                if post_login_sessions.is_empty() {
                    continue;
                }

                // Step 3: Compare sessions - check if session ID changed
                let pre_set: HashSet<String> = pre_login_sessions.iter().cloned().collect();
                let post_set: HashSet<String> = post_login_sessions.iter().cloned().collect();

                let unchanged: Vec<_> = pre_set.intersection(&post_set).collect();

                if !unchanged.is_empty() {
                    info!(
                        "[CRITICAL] [AuthFlow] Session fixation detected at {}",
                        login_url
                    );
                    vulnerabilities.push(Vulnerability {
                        id: generate_uuid("session_fixation"),
                        vuln_type: "Session Fixation Vulnerability".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: login_url.to_string(),
                        parameter: Some("Session ID".to_string()),
                        payload: "Session tracking test".to_string(),
                        description: format!(
                            "Session ID is NOT regenerated after login. {} session value(s) remained \
                            unchanged after authentication attempt. This allows session fixation attacks \
                            where an attacker can force a victim to use a known session ID, then hijack \
                            the session after the victim logs in.",
                            unchanged.len()
                        ),
                        evidence: Some(format!(
                            "Pre-login sessions: {:?}\nPost-login sessions: {:?}\nUnchanged: {} session(s)",
                            pre_login_sessions, post_login_sessions, unchanged.len()
                        )),
                        cwe: "CWE-384".to_string(),
                        cvss: 9.1,
                        verified: true,
                        false_positive: false,
                        remediation: r#"CRITICAL FIX REQUIRED:

1. **Regenerate Session ID on Login**
   ```python
   # Django
   from django.contrib.auth import login
   request.session.flush()  # Clear old session
   login(request, user)     # Creates new session

   # Flask
   from flask import session
   session.clear()
   session.regenerate()
   session['user_id'] = user.id

   # Express.js
   req.session.regenerate((err) => {
       req.session.userId = user.id;
   });

   # PHP
   session_regenerate_id(true);  // Delete old session
   $_SESSION['user_id'] = $user['id'];
   ```

2. **Regenerate on Privilege Changes**
   Regenerate session when:
   - User logs in
   - User logs out
   - User privilege level changes
   - Admin access is granted

3. **Implement Additional Protection**
   - Bind session to IP address (with caution for mobile users)
   - Use HttpOnly and Secure flags on cookies
   - Implement session timeout
   - Use CSRF tokens

References:
- OWASP Session Fixation: https://owasp.org/www-community/attacks/Session_fixation
- CWE-384: https://cwe.mitre.org/data/definitions/384.html"#
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                    break; // Found the vulnerability, no need to test more
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test 2: Password Reset IDOR
    /// Request password reset for user A, try to change user ID parameter to reset user B's password
    async fn test_password_reset_idor(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[AuthFlow] Testing password reset IDOR");

        // Common password reset endpoints
        let reset_paths = vec![
            "/reset-password",
            "/forgot-password",
            "/password/reset",
            "/password/forgot",
            "/api/auth/reset",
            "/api/password/reset",
            "/auth/reset-password",
        ];

        let base_url = url.trim_end_matches('/');

        for path in &reset_paths {
            tests_run += 1;
            let reset_url = format!("{}{}", base_url, path);

            // Check if endpoint exists
            let check_response = match self.http_client.get(&reset_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Only proceed if it looks like a reset endpoint
            let body_lower = check_response.body.to_lowercase();
            if !body_lower.contains("reset")
                && !body_lower.contains("forgot")
                && !body_lower.contains("password")
            {
                continue;
            }

            debug!("[AuthFlow] Testing IDOR on {}", reset_url);

            // IDOR Test Scenarios
            let idor_tests = vec![
                // Scenario 1: User ID parameter manipulation
                (
                    "email=victim@example.com&user_id=123",
                    r#"{"email":"victim@example.com","user_id":123}"#,
                    "user_id parameter",
                ),
                (
                    "email=victim@example.com&id=123",
                    r#"{"email":"victim@example.com","id":123}"#,
                    "id parameter",
                ),
                (
                    "email=victim@example.com&userId=123",
                    r#"{"email":"victim@example.com","userId":123}"#,
                    "userId parameter",
                ),
                // Scenario 2: Email array injection
                (
                    "email[]=attacker@evil.com&email[]=victim@example.com",
                    r#"{"email":["attacker@evil.com","victim@example.com"]}"#,
                    "email array injection",
                ),
                // Scenario 3: Account parameter manipulation
                (
                    "email=victim@example.com&account=different_user",
                    r#"{"email":"victim@example.com","account":"different_user"}"#,
                    "account parameter",
                ),
                // Scenario 4: Token parameter pre-set (trying to set our own token)
                (
                    "email=victim@example.com&token=attacker_controlled_token",
                    r#"{"email":"victim@example.com","token":"attacker_controlled_token"}"#,
                    "token parameter manipulation",
                ),
            ];

            for (form_data, json_data, technique) in &idor_tests {
                // Test with form data
                let headers_form = vec![(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )];

                if let Ok(response) = self
                    .http_client
                    .post_with_headers(&reset_url, form_data, headers_form)
                    .await
                {
                    if self.check_idor_vulnerability(&response, technique) {
                        info!(
                            "[CRITICAL] [AuthFlow] Password reset IDOR detected via {}",
                            technique
                        );
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid("password_reset_idor"),
                            vuln_type: "Password Reset IDOR (Insecure Direct Object Reference)"
                                .to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Broken Access Control".to_string(),
                            url: reset_url.clone(),
                            parameter: Some(technique.to_string()),
                            payload: form_data.to_string(),
                            description: format!(
                                "Password reset endpoint is vulnerable to IDOR via {}. \
                                An attacker can manipulate the user identifier parameter to reset \
                                OTHER users' passwords. This allows complete account takeover of ANY \
                                user in the system without knowing their current password.\n\n\
                                Attack Flow:\n\
                                1. Attacker sends password reset request with victim's email\n\
                                2. Attacker manipulates user ID/account parameter to target victim\n\
                                3. Reset link/token is sent to attacker's email instead\n\
                                4. Attacker uses token to set new password for victim's account\n\
                                5. Complete account takeover achieved",
                                technique
                            ),
                            evidence: Some(format!(
                                "Endpoint accepted request with manipulated {}: {}\nResponse indicated success (status: {})",
                                technique, form_data, response.status_code
                            )),
                            cwe: "CWE-639".to_string(), // Authorization Bypass Through User-Controlled Key
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: r#"CRITICAL FIX REQUIRED:

1. **Validate User Ownership**
   ```python
   def reset_password(request):
       email = request.POST.get('email')

       # NEVER accept user_id from client!
       # user_id = request.POST.get('user_id')  # WRONG!

       # Lookup user by email only
       user = User.objects.get(email=email)

       # Generate token tied to THIS user
       token = create_reset_token(user)

       # Send reset link to the user's registered email ONLY
       send_reset_email(user.email, token)
   ```

2. **Server-Side Authorization**
   ```javascript
   // Node.js
   app.post('/reset-password', async (req, res) => {
       const { email } = req.body;

       // REJECT any user_id, id, or account parameters
       if (req.body.user_id || req.body.id || req.body.account) {
           return res.status(400).json({ error: 'Invalid parameters' });
       }

       // Look up user by email only
       const user = await User.findOne({ email });

       // Send reset to THEIR email only
       await sendResetEmail(user.email, generateToken(user));
   });
   ```

3. **Token Validation on Reset**
   ```python
   def confirm_password_reset(request):
       token = request.POST.get('token')
       new_password = request.POST.get('new_password')

       # Validate token and extract user from token
       reset_token = PasswordResetToken.objects.get(token=token)

       # CRITICAL: Use user from token, NOT from request
       user = reset_token.user

       # Verify token hasn't been used
       if reset_token.used:
           raise Exception("Token already used")

       # Verify token hasn't expired
       if reset_token.expires_at < now():
           raise Exception("Token expired")

       # Update password
       user.set_password(new_password)
       user.save()

       # Mark token as used
       reset_token.used = True
       reset_token.save()
   ```

4. **Reject Array Parameters**
   ```python
   # Ensure single email, not array
   if isinstance(request.POST.get('email'), list):
       raise ValidationError("Multiple emails not allowed")
   ```

5. **Rate Limiting**
   ```python
   @ratelimit(key='ip', rate='3/h')
   @ratelimit(key='user_or_ip', rate='5/d')
   def reset_password(request):
       # Implementation
   ```

6. **Security Checklist**
   - [ ] NEVER accept user_id, id, account from client
   - [ ] Look up user by email only
   - [ ] Send reset link to user's registered email only
   - [ ] Token must encode user identity securely
   - [ ] Validate token server-side
   - [ ] Implement rate limiting
   - [ ] Log all reset attempts
   - [ ] Alert users when password reset is requested

References:
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- CWE-639: https://cwe.mitre.org/data/definitions/639.html"#
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break;
                    }
                }

                // Test with JSON data
                let headers_json = vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )];

                if let Ok(response) = self
                    .http_client
                    .post_with_headers(&reset_url, json_data, headers_json)
                    .await
                {
                    if self.check_idor_vulnerability(&response, technique) {
                        vulnerabilities.push(create_idor_vulnerability(
                            &reset_url,
                            technique,
                            json_data,
                            &response,
                        ));
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test 3: MFA Bypass Techniques
    /// Look for debug parameters, empty codes, direct endpoint access
    async fn test_mfa_bypass_techniques(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("[AuthFlow] Testing MFA bypass techniques");

        // Discover MFA endpoints
        let mfa_endpoints = vec![
            "/mfa",
            "/2fa",
            "/auth/mfa",
            "/auth/2fa",
            "/verify",
            "/mfa/verify",
            "/2fa/verify",
            "/api/auth/mfa",
            "/api/mfa/verify",
        ];

        let base_url = url.trim_end_matches('/');

        for path in &mfa_endpoints {
            tests_run += 1;
            let mfa_url = format!("{}{}", base_url, path);

            // Check if MFA endpoint exists
            let check_response = match self.http_client.get(&mfa_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body_lower = check_response.body.to_lowercase();
            let is_mfa_page = body_lower.contains("mfa")
                || body_lower.contains("2fa")
                || body_lower.contains("two-factor")
                || body_lower.contains("verification code")
                || body_lower.contains("authenticator");

            if !is_mfa_page {
                continue;
            }

            debug!("[AuthFlow] Testing MFA bypasses on {}", mfa_url);

            // Test 1: Debug parameters
            let debug_params = vec![
                "skip_mfa=true",
                "bypass_mfa=1",
                "debug=1",
                "skip_2fa=true",
                "mfa_required=false",
                "dev_mode=true",
                "test_mode=true",
            ];

            for param in &debug_params {
                let test_url = format!("{}?{}", mfa_url, param);

                if let Ok(response) = self.http_client.get(&test_url).await {
                    let resp_lower = response.body.to_lowercase();

                    // Check for bypass indicators
                    let bypassed = (response.status_code == 200 || response.status_code == 302)
                        && (resp_lower.contains("dashboard")
                            || resp_lower.contains("welcome")
                            || resp_lower.contains("logged in")
                            || resp_lower.contains("\"authenticated\":true")
                            || resp_lower.contains("\"success\":true") || resp_lower.contains("\"status\":\"success\""))
                        && !resp_lower.contains("verification")
                        && !resp_lower.contains("enter code");

                    if bypassed {
                        info!(
                            "[CRITICAL] [AuthFlow] MFA bypass via debug parameter: {}",
                            param
                        );
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid("mfa_bypass_debug"),
                            vuln_type: "MFA Bypass via Debug Parameter".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: test_url.clone(),
                            parameter: Some(param.to_string()),
                            payload: param.to_string(),
                            description: format!(
                                "MFA can be completely bypassed using the debug parameter '{}'. \
                                This allows attackers to skip the second factor authentication entirely, \
                                reducing security to single-factor authentication. Debug/development \
                                parameters should NEVER be active in production.",
                                param
                            ),
                            evidence: Some(format!(
                                "Request to {} returned successful authentication (status: {})",
                                test_url, response.status_code
                            )),
                            cwe: "CWE-425".to_string(), // Direct Request (Forced Browsing)
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Remove All Debug Parameters in Production**
   ```python
   # NEVER allow this in production
   if request.GET.get('skip_mfa') == 'true':
       return redirect('dashboard')  # WRONG!

   # Use environment-based config
   DEBUG_MODE = os.getenv('DEBUG', 'false') == 'true'
   if DEBUG_MODE and not is_production():
       # Only allow in dev environments
       pass
   ```

2. **Environment-Based Feature Flags**
   ```javascript
   // Node.js
   if (process.env.NODE_ENV === 'production') {
       // Force MFA always
       if (!req.session.mfaVerified) {
           return res.redirect('/mfa/verify');
       }
   }
   ```

3. **Server-Side MFA Enforcement**
   ```python
   def require_mfa(view_func):
       def wrapper(request, *args, **kwargs):
           # NEVER check client parameters
           # if request.GET.get('skip_mfa'):  # WRONG!

           # Check server-side session state only
           if not request.session.get('mfa_verified'):
               return redirect('mfa_verify')

           return view_func(request, *args, **kwargs)
       return wrapper
   ```

4. **Remove Debug Code Before Deployment**
   ```python
   # BAD - Debug code in production
   if 'debug' in request.GET:
       user.mfa_verified = True

   # GOOD - No debug bypasses at all
   # MFA verification is mandatory, no exceptions
   ```

5. **Code Review Checklist**
   - [ ] No skip_mfa, bypass_mfa, debug parameters
   - [ ] No dev_mode, test_mode checks in production
   - [ ] MFA state stored server-side only
   - [ ] No client-controllable MFA bypass
   - [ ] Environment variables properly configured
   - [ ] Debug code removed before deployment

References:
- OWASP Authentication: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- CWE-425: https://cwe.mitre.org/data/definitions/425.html"#
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break;
                    }
                }
            }

            // Test 2: Empty MFA codes
            let empty_code_tests = vec![
                ("code=", "empty string"),
                ("code=000000", "zeros"),
                ("code=%20%20%20%20%20%20", "spaces"),
                (r#"{"code":""}"#, "empty JSON"),
                (r#"{"code":null}"#, "null JSON"),
            ];

            for (payload, technique) in &empty_code_tests {
                let content_type = if payload.starts_with('{') {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                };

                let headers = vec![("Content-Type".to_string(), content_type.to_string())];

                if let Ok(response) = self
                    .http_client
                    .post_with_headers(&mfa_url, payload, headers)
                    .await
                {
                    let resp_lower = response.body.to_lowercase();

                    let bypassed = (response.status_code == 200 || response.status_code == 302)
                        && (resp_lower.contains("\"success\":true") || resp_lower.contains("\"status\":\"success\"")
                            || resp_lower.contains("\"verified\":true")
                            || resp_lower.contains("welcome")
                            || resp_lower.contains("dashboard"))
                        && !resp_lower.contains("invalid")
                        && !resp_lower.contains("incorrect");

                    if bypassed {
                        info!(
                            "[CRITICAL] [AuthFlow] MFA bypass via {}: {}",
                            technique, payload
                        );
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid("mfa_bypass_empty"),
                            vuln_type: "MFA Bypass via Empty/Invalid Code".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Authentication".to_string(),
                            url: mfa_url.clone(),
                            parameter: Some("code".to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "MFA verification accepts {} as a valid code. This completely \
                                bypasses the MFA security mechanism, allowing attackers to authenticate \
                                with just the password.",
                                technique
                            ),
                            evidence: Some(format!(
                                "POST {} with {} returned success (status: {})",
                                mfa_url, payload, response.status_code
                            )),
                            cwe: "CWE-287".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: r#"CRITICAL FIX:

1. **Validate Code Properly**
   ```python
   def verify_mfa_code(user, code):
       # Validate code is not empty
       if not code or not code.strip():
           raise ValidationError("Code is required")

       # Validate code format
       if not code.isdigit() or len(code) != 6:
           raise ValidationError("Invalid code format")

       # Verify against TOTP
       totp = pyotp.TOTP(user.mfa_secret)
       if not totp.verify(code):
           raise ValidationError("Invalid code")

       return True
   ```

References:
- OWASP MFA: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"#
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                        break;
                    }
                }
            }

            // Test 3: Direct access to protected endpoints (skipping MFA step)
            let protected_endpoints = vec!["/dashboard", "/profile", "/settings", "/api/user"];

            for endpoint in &protected_endpoints {
                let protected_url = format!("{}{}", base_url, endpoint);

                if let Ok(response) = self.http_client.get(&protected_url).await {
                    let resp_lower = response.body.to_lowercase();

                    // Check if we can access without MFA
                    let accessible = response.status_code == 200
                        && (resp_lower.contains("dashboard")
                            || resp_lower.contains("profile")
                            || resp_lower.contains("settings"))
                        && !resp_lower.contains("login")
                        && !resp_lower.contains("mfa")
                        && !resp_lower.contains("verification");

                    if accessible {
                        info!(
                            "[CRITICAL] [AuthFlow] Protected endpoint accessible without MFA: {}",
                            protected_url
                        );
                        vulnerabilities.push(Vulnerability {
                            id: generate_uuid("mfa_bypass_direct"),
                            vuln_type: "MFA Bypass via Direct Endpoint Access".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::Medium,
                            category: "Authentication".to_string(),
                            url: protected_url.clone(),
                            parameter: None,
                            payload: "Direct GET request".to_string(),
                            description: format!(
                                "Protected endpoint '{}' is accessible without completing MFA verification. \
                                Users can bypass the MFA step by directly accessing protected pages.",
                                endpoint
                            ),
                            evidence: Some(format!(
                                "Direct access to {} returned protected content (status: {})",
                                protected_url, response.status_code
                            )),
                            cwe: "CWE-288".to_string(),
                            cvss: 8.1,
                            verified: true,
                            false_positive: false,
                            remediation: r#"FIX REQUIRED:

1. **Enforce MFA on All Protected Routes**
   ```python
   @require_mfa
   def dashboard(request):
       # Only accessible if MFA verified
       return render(request, 'dashboard.html')
   ```

2. **Check MFA in Middleware**
   ```javascript
   app.use((req, res, next) => {
       if (req.session.userId && !req.session.mfaVerified) {
           return res.redirect('/mfa/verify');
       }
       next();
   });
   ```
"#
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test 4: Predictable Session Tokens
    /// Collect multiple session tokens and check for patterns/low entropy
    async fn test_session_token_predictability(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10; // Collect 10 sessions

        debug!("[AuthFlow] Testing session token predictability");

        let mut session_tokens: Vec<String> = Vec::new();

        // Collect multiple session tokens
        for _ in 0..tests_run {
            if let Ok(response) = self.http_client.get(url).await {
                let tokens = extract_all_session_cookies(&response.headers);
                session_tokens.extend(tokens);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if session_tokens.len() < 5 {
            debug!("[AuthFlow] Not enough session tokens collected for analysis");
            return (vulnerabilities, tests_run);
        }

        debug!(
            "[AuthFlow] Collected {} session tokens for analysis",
            session_tokens.len()
        );

        // Analyze for predictability
        let analysis = analyze_token_entropy(&session_tokens);

        // Check for low entropy
        if analysis.estimated_entropy < 128.0 {
            info!(
                "[AuthFlow] Low entropy detected in session tokens: {:.1} bits",
                analysis.estimated_entropy
            );
            vulnerabilities.push(Vulnerability {
                id: generate_uuid("session_low_entropy"),
                vuln_type: "Predictable Session Tokens (Low Entropy)".to_string(),
                severity: if analysis.estimated_entropy < 64.0 {
                    Severity::Critical
                } else {
                    Severity::High
                },
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("Session Token".to_string()),
                payload: "Session collection analysis".to_string(),
                description: format!(
                    "Session tokens have insufficient entropy (~{:.1} bits). Industry standard \
                    requires at least 128 bits of entropy. Low entropy makes sessions predictable \
                    and vulnerable to brute-force attacks.\n\n\
                    Analysis:\n\
                    - Average length: {} characters\n\
                    - Character set size: {}\n\
                    - Estimated entropy: {:.1} bits\n\
                    - Unique tokens: {}/{}",
                    analysis.estimated_entropy,
                    analysis.avg_length,
                    analysis.charset_size,
                    analysis.estimated_entropy,
                    analysis.unique_count,
                    session_tokens.len()
                ),
                evidence: Some(format!(
                    "Collected {} tokens, {} unique. Avg length: {}, Charset: {}, Entropy: {:.1} bits",
                    session_tokens.len(),
                    analysis.unique_count,
                    analysis.avg_length,
                    analysis.charset_size,
                    analysis.estimated_entropy
                )),
                cwe: "CWE-330".to_string(),
                cvss: if analysis.estimated_entropy < 64.0 {
                    9.1
                } else {
                    7.5
                },
                verified: true,
                false_positive: false,
                remediation: r#"FIX REQUIRED:

1. **Use Cryptographically Secure Random Session IDs**
   ```python
   import secrets

   def generate_session_id():
       # 32 bytes = 256 bits of entropy
       return secrets.token_urlsafe(32)
   ```

2. **Sufficient Length and Charset**
   ```javascript
   const crypto = require('crypto');

   function generateSessionId() {
       // 32 bytes hex = 64 characters
       return crypto.randomBytes(32).toString('hex');
   }
   ```

3. **Never Use Predictable Sources**
   ```python
   # BAD - Predictable
   session_id = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()

   # GOOD - Cryptographically random
   session_id = secrets.token_urlsafe(32)
   ```

References:
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-330: https://cwe.mitre.org/data/definitions/330.html"#
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Check for sequential patterns
        if analysis.has_sequential {
            info!("[AuthFlow] Sequential pattern detected in session tokens");
            vulnerabilities.push(Vulnerability {
                id: generate_uuid("session_sequential"),
                vuln_type: "Sequential Session Token Pattern".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "Session Management".to_string(),
                url: url.to_string(),
                parameter: Some("Session Token".to_string()),
                payload: "Pattern analysis".to_string(),
                description:
                    "Session tokens follow a sequential or incrementing pattern. This makes them \
                    highly predictable - attackers can guess valid session IDs by observing the \
                    pattern and generating adjacent values."
                        .to_string(),
                evidence: Some("Sequential numeric components detected in tokens".to_string()),
                cwe: "CWE-330".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation:
                    "Use cryptographically secure random number generators. Never use counters, \
                    timestamps, or sequential values in session IDs."
                        .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        (vulnerabilities, tests_run)
    }

    // Helper Methods

    /// Discover login endpoints
    async fn discover_login_endpoints(&self, base_url: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        let base = base_url.trim_end_matches('/');

        let paths = vec![
            "/login",
            "/signin",
            "/sign-in",
            "/auth",
            "/auth/login",
            "/api/auth/login",
            "/api/login",
        ];

        for path in &paths {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.http_client.get(&url).await {
                let body_lower = response.body.to_lowercase();
                if body_lower.contains("password") || body_lower.contains("login") {
                    endpoints.push(url);
                }
            }
        }

        endpoints
    }

    /// Check if response indicates IDOR vulnerability
    fn check_idor_vulnerability(&self, response: &crate::http_client::HttpResponse, technique: &str) -> bool {
        let body_lower = response.body.to_lowercase();

        // Success indicators
        let success = (response.status_code == 200 || response.status_code == 201)
            && (body_lower.contains("email sent")
                || body_lower.contains("reset link")
                || body_lower.contains("check your email")
                || body_lower.contains("\"success\":true") || body_lower.contains("\"status\":\"success\""));

        // Rejection indicators
        let rejected = body_lower.contains("invalid")
            || body_lower.contains("error")
            || body_lower.contains("not allowed")
            || body_lower.contains("forbidden")
            || response.status_code >= 400;

        // Check if suspicious parameter was reflected (accepted)
        let param_reflected = if technique.contains("user_id") {
            body_lower.contains("user_id") || body_lower.contains("user id")
        } else if technique.contains("token") {
            body_lower.contains("attacker_controlled_token")
        } else {
            false
        };

        success && !rejected || param_reflected
    }
}

// Helper Functions

/// Extract all session cookies from headers
fn extract_all_session_cookies(headers: &std::collections::HashMap<String, String>) -> Vec<String> {
    let mut sessions = Vec::new();

    let session_names = [
        "session",
        "sess",
        "sid",
        "sessionid",
        "phpsessid",
        "jsessionid",
        "aspsessionid",
        "connect.sid",
        "_session",
    ];

    for (key, value) in headers {
        if key.to_lowercase() == "set-cookie" {
            for part in value.split(';') {
                let trimmed = part.trim();
                if let Some(eq_pos) = trimmed.find('=') {
                    let name = trimmed[..eq_pos].to_lowercase();
                    let val = trimmed[eq_pos + 1..].to_string();

                    for session_name in &session_names {
                        if name.contains(session_name) {
                            sessions.push(val.clone());
                            break;
                        }
                    }
                }
            }
        }
    }

    sessions
}

/// Analyze token entropy
fn analyze_token_entropy(tokens: &[String]) -> EntropyAnalysis {
    let unique: HashSet<String> = tokens.iter().cloned().collect();

    let avg_length = tokens.iter().map(|s| s.len()).sum::<usize>() / tokens.len().max(1);

    // Count unique characters
    let all_chars: HashSet<char> = tokens.iter().flat_map(|s| s.chars()).collect();
    let charset_size = all_chars.len();

    // Estimate entropy: log2(charset^length)
    let estimated_entropy = (avg_length as f64) * (charset_size as f64).log2();

    // Check for sequential patterns
    let has_sequential = detect_sequential_pattern(tokens);

    EntropyAnalysis {
        unique_count: unique.len(),
        avg_length,
        charset_size,
        estimated_entropy,
        has_sequential,
    }
}

/// Detect sequential patterns in tokens
fn detect_sequential_pattern(tokens: &[String]) -> bool {
    if tokens.len() < 3 {
        return false;
    }

    // Extract numeric portions
    let numbers: Vec<Option<i64>> = tokens
        .iter()
        .map(|s| {
            let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .collect();

    let valid_numbers: Vec<i64> = numbers.into_iter().flatten().collect();

    if valid_numbers.len() >= 3 {
        let mut is_sequential = true;
        for window in valid_numbers.windows(2) {
            if window[1] <= window[0] || window[1] - window[0] > 100 {
                is_sequential = false;
                break;
            }
        }
        return is_sequential;
    }

    false
}

struct EntropyAnalysis {
    unique_count: usize,
    avg_length: usize,
    charset_size: usize,
    estimated_entropy: f64,
    has_sequential: bool,
}

fn generate_uuid(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!(
        "{}_{:08x}{:04x}{:04x}",
        prefix,
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>()
    )
}

fn create_idor_vulnerability(
    url: &str,
    technique: &str,
    payload: &str,
    response: &crate::http_client::HttpResponse,
) -> Vulnerability {
    Vulnerability {
        id: generate_uuid("password_reset_idor"),
        vuln_type: "Password Reset IDOR".to_string(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        category: "Broken Access Control".to_string(),
        url: url.to_string(),
        parameter: Some(technique.to_string()),
        payload: payload.to_string(),
        description: format!("Password reset IDOR via {}", technique),
        evidence: Some(format!(
            "Request accepted with status {}",
            response.status_code
        )),
        cwe: "CWE-639".to_string(),
        cvss: 9.8,
        verified: true,
        false_positive: false,
        remediation: "Validate user ownership server-side. Never trust client-provided user IDs."
            .to_string(),
        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
    }
}
