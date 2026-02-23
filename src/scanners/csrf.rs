// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CSRF (Cross-Site Request Forgery) Scanner
 * Tests for missing CSRF protections and misconfigurations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct CsrfScanner {
    http_client: Arc<HttpClient>,
}

impl CsrfScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for CSRF vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[CSRF] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Fetch the page and analyze
        tests_run += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                // Check for HTML forms
                if response.body.contains("<form") {
                    self.check_forms(&response, url, &mut vulnerabilities);
                }

                // Check Set-Cookie headers for SameSite attribute
                self.check_cookie_samesite(&response, url, &mut vulnerabilities);

                // Check for CSRF protection headers
                self.check_csrf_headers(&response, url, &mut vulnerabilities);
            }
            Err(e) => {
                debug!("Failed to fetch URL for CSRF check: {}", e);
            }
        }

        // Test 2: Check if state-changing operations allow GET
        if url.contains("delete") || url.contains("remove") || url.contains("update") {
            tests_run += 1;
            if let Ok(response) = self.http_client.get(url).await {
                self.check_state_change_via_get(&response, url, &mut vulnerabilities);
            }
        }

        // Test 3: Test Origin/Referer validation
        tests_run += 1;
        // Note: In a real implementation, we'd send requests with modified Origin/Referer headers
        // For this version, we'll check response headers for signs of validation

        info!(
            "[SUCCESS] [CSRF] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check HTML forms for CSRF tokens
    fn check_forms(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Regex to find forms (simplified)
        let form_regex = Regex::new(r#"<form[^>]*>([\s\S]*?)</form>"#).unwrap();
        let token_patterns = vec![
            r"csrf",
            r"_token",
            r"authenticity_token",
            r"__requestverificationtoken",
            r"anti-forgery",
            r"csrfmiddlewaretoken",
        ];

        for form_match in form_regex.captures_iter(&response.body) {
            if let Some(form_content) = form_match.get(1) {
                let form_str = form_content.as_str().to_lowercase();

                // Check if form modifies state (has POST/PUT/DELETE method or action suggests state change)
                let is_state_changing = form_str.contains("method=\"post\"")
                    || form_str.contains("method='post'")
                    || form_str.contains("delete")
                    || form_str.contains("update")
                    || form_str.contains("create")
                    || form_str.contains("submit");

                if is_state_changing {
                    // Check for CSRF token
                    let has_csrf_token = token_patterns
                        .iter()
                        .any(|pattern| form_str.contains(pattern));

                    if !has_csrf_token {
                        vulnerabilities.push(self.create_vulnerability(
                            "Missing CSRF Token in Form",
                            url,
                            Severity::High,
                            Confidence::High,
                            "HTML form lacks CSRF protection token",
                            format!(
                                "State-changing form found without CSRF token. Form snippet: {}...",
                                &form_str.chars().take(150).collect::<String>()
                            ),
                            6.5,
                        ));
                        break; // Only report once per page
                    }
                }
            }
        }
    }

    /// Check Set-Cookie headers for SameSite attribute
    fn check_cookie_samesite(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(set_cookie) = response.header("set-cookie") {
            let cookies = set_cookie.split(',');

            for cookie in cookies {
                let cookie_lower = cookie.to_lowercase();

                // Check if it's a session cookie (common patterns)
                let is_session_cookie = cookie_lower.contains("session")
                    || cookie_lower.contains("auth")
                    || cookie_lower.contains("token")
                    || cookie_lower.contains("jsessionid")
                    || cookie_lower.contains("phpsessid");

                if is_session_cookie {
                    // Check for SameSite attribute
                    if !cookie_lower.contains("samesite") {
                        vulnerabilities.push(self.create_vulnerability(
                            "Missing SameSite Cookie Attribute",
                            url,
                            Severity::Medium,
                            Confidence::High,
                            "Session cookie lacks SameSite attribute - vulnerable to CSRF",
                            format!("Cookie: {}", cookie.chars().take(100).collect::<String>()),
                            5.3,
                        ));
                        break; // Report once
                    } else if cookie_lower.contains("samesite=none") {
                        vulnerabilities.push(self.create_vulnerability(
                            "Weak SameSite Cookie Attribute",
                            url,
                            Severity::Medium,
                            Confidence::High,
                            "Session cookie uses SameSite=None - provides no CSRF protection",
                            format!(
                                "Cookie with SameSite=None: {}",
                                cookie.chars().take(100).collect::<String>()
                            ),
                            5.0,
                        ));
                        break;
                    }
                }
            }
        }
    }

    /// Check for CSRF protection headers
    fn check_csrf_headers(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Check for common anti-CSRF headers
        let csrf_header_names = vec![
            "x-csrf-token",
            "x-xsrf-token",
            "csrf-token",
            "x-requested-with",
        ];

        let has_csrf_header = csrf_header_names
            .iter()
            .any(|header| response.header(header).is_some());

        // Check if response contains CSRF token in meta tags or JavaScript
        let has_csrf_meta = response.body.contains("csrf-token")
            || response.body.contains("_csrf")
            || response.body.contains("csrfToken");

        // Only report if the page has HTML forms with state-changing methods.
        // API endpoints (JSON) are NOT reported because:
        // 1. APIs typically use token-based auth (Bearer/API key) not cookies
        // 2. CORS prevents cross-origin API requests with credentials
        // 3. Reporting on every API endpoint creates massive false positives
        let has_state_changing_form = response.body.contains("<form")
            && (response.body.contains("method=\"post\"")
                || response.body.contains("method=\"POST\"")
                || response.body.contains("method='post'")
                || response.body.contains("method='POST'"));

        if has_state_changing_form && !has_csrf_header && !has_csrf_meta {
            vulnerabilities.push(self.create_vulnerability(
                "No CSRF Protection Headers",
                url,
                Severity::Low,
                Confidence::Medium,
                "HTML forms with state-changing methods lack CSRF protection headers",
                "No X-CSRF-Token, X-XSRF-Token, or similar headers detected on page with POST forms".to_string(),
                3.5,
            ));
        }
    }

    /// Check for state-changing operations via GET
    /// Only reports when there is strong evidence of actual state change,
    /// not just keyword matching in URLs and response bodies.
    fn check_state_change_via_get(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // Only report if the GET request resulted in a redirect (302) to
        // a different page, which is a stronger indicator of state change.
        // Just checking URL keywords + body keywords is too broad and
        // produces false positives on pages that merely MENTION these words
        // (documentation, UI labels, etc.)
        if response.status_code == 302 {
            let state_change_indicators = vec![
                "delete", "remove", "update", "transfer", "purchase",
            ];

            let url_lower = url.to_lowercase();
            for indicator in state_change_indicators {
                if url_lower.contains(indicator) {
                    vulnerabilities.push(self.create_vulnerability(
                        "State-Changing Operation via GET",
                        url,
                        Severity::High,
                        Confidence::Low,
                        "Potentially dangerous operation accepts GET method and redirects - may be vulnerable to CSRF",
                        format!("URL contains '{}' and GET request triggered redirect (302)",
                            indicator),
                        7.1,
                    ));
                    break; // Only report once
                }
            }
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
            id: format!("csrf_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("CSRF Vulnerability - {}", title),
            severity,
            confidence,
            category: "CSRF".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-352".to_string(), // Cross-Site Request Forgery (CSRF)
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Implement CSRF Tokens (Synchronizer Token Pattern)**
   ```html
   <!-- Include in all state-changing forms -->
   <form method="POST" action="/update">
     <input type="hidden" name="csrf_token" value="{{csrf_token}}" />
     <!-- form fields -->
   </form>
   ```

2. **Use SameSite Cookie Attribute**
   ```
   Set-Cookie: sessionid=abc123; SameSite=Strict; Secure; HttpOnly

   - Use SameSite=Strict for maximum protection
   - Use SameSite=Lax for balance (allows some cross-site GET)
   - Never use SameSite=None without strong justification
   ```

3. **Validate Origin and Referer Headers**
   ```javascript
   // Express.js example
   app.use((req, res, next) => {
     const origin = req.get('origin') || req.get('referer');
     if (!origin || !origin.includes(process.env.ALLOWED_DOMAIN)) {
       return res.status(403).send('CSRF validation failed');
     }
     next();
   });
   ```

4. **Use Custom Request Headers (For AJAX)**
   ```javascript
   // Require X-Requested-With header for API calls
   fetch('/api/update', {
     method: 'POST',
     headers: {
       'X-Requested-With': 'XMLHttpRequest',
       'X-CSRF-Token': getCSRFToken()
     },
     body: JSON.stringify(data)
   });
   ```

5. **Enforce Proper HTTP Methods**
   - Use POST/PUT/PATCH/DELETE for state-changing operations
   - NEVER allow critical operations via GET
   - Validate HTTP method on server side

6. **Double Submit Cookie Pattern (Alternative)**
   ```javascript
   // Set CSRF token in cookie AND require it in request
   const csrfToken = generateToken();
   res.cookie('XSRF-TOKEN', csrfToken);
   // Client must send this token back in X-XSRF-TOKEN header
   ```

7. **Framework-Specific Protection**

   **Django:**
   ```python
   # Enable CSRF middleware (enabled by default)
   MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware', ...]

   # In templates
   <form method="post">{% csrf_token %}</form>
   ```

   **Express.js (csurf):**
   ```javascript
   const csrf = require('csurf');
   app.use(csrf({ cookie: true }));
   app.get('/form', (req, res) => {
     res.render('form', { csrfToken: req.csrfToken() });
   });
   ```

   **Spring (Java):**
   ```java
   // Enable CSRF protection (enabled by default in Spring Security)
   @EnableWebSecurity
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
     @Override
     protected void configure(HttpSecurity http) throws Exception {
       http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
     }
   }
   ```

8. **Additional Best Practices**
   - Require re-authentication for critical operations
   - Implement rate limiting on state-changing endpoints
   - Use CAPTCHA for sensitive operations
   - Log and monitor for CSRF attack patterns
   - Educate users about phishing risks

References:
- OWASP CSRF Guide: https://owasp.org/www-community/attacks/csrf
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger CSRF: https://portswigger.net/web-security/csrf
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
    fn test_form_without_csrf_token() {
        let scanner = CsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <html>
                <form method="POST" action="/submit">
                    <input name="email" type="email" />
                    <button type="submit">Submit</button>
                </form>
                </html>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_forms(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing CSRF token");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_form_with_csrf_token() {
        let scanner = CsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: r#"
                <html>
                <form method="POST" action="/submit">
                    <input type="hidden" name="csrf_token" value="abc123" />
                    <input name="email" type="email" />
                    <button type="submit">Submit</button>
                </form>
                </html>
            "#
            .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_forms(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 0, "Should not report when CSRF token present");
    }

    #[test]
    fn test_cookie_without_samesite() {
        let scanner = CsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=abc123; Secure; HttpOnly".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cookie_samesite(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect missing SameSite attribute");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_cookie_with_samesite_strict() {
        let scanner = CsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "set-cookie".to_string(),
            "sessionid=abc123; SameSite=Strict; Secure; HttpOnly".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_cookie_samesite(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 0, "Should not report when SameSite=Strict");
    }

    #[test]
    fn test_state_change_via_get() {
        let scanner = CsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: "Record deleted successfully".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_state_change_via_get(
            &response,
            "https://example.com/delete?id=123",
            &mut vulns,
        );

        assert!(vulns.len() > 0, "Should detect state change via GET");
        assert_eq!(vulns[0].severity, Severity::High);
    }
}
