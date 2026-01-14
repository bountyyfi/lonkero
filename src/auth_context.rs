// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Authentication Context for Authenticated Scanning
//!
//! Handles automatic login, token extraction, and credential management
//! for scanning authenticated endpoints.

use anyhow::{Context, Result};
use kalamari::{Browser, BrowserConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Extracted authentication session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Cookies extracted after login (name -> value)
    pub cookies: HashMap<String, String>,
    /// Authorization header value (e.g., "Bearer xxx" or JWT)
    pub auth_header: Option<String>,
    /// CSRF token if detected
    pub csrf_token: Option<String>,
    /// Session storage items
    pub session_storage: HashMap<String, String>,
    /// Local storage items (may contain tokens)
    pub local_storage: HashMap<String, String>,
    /// The URL we're authenticated to
    pub authenticated_url: String,
    /// Whether login was successful
    pub is_authenticated: bool,
}

impl AuthSession {
    pub fn empty() -> Self {
        Self {
            cookies: HashMap::new(),
            auth_header: None,
            csrf_token: None,
            session_storage: HashMap::new(),
            local_storage: HashMap::new(),
            authenticated_url: String::new(),
            is_authenticated: false,
        }
    }

    /// Get cookie header string for HTTP requests
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }

    /// Get all auth headers to add to requests
    pub fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        if let Some(ref cookie) = self.cookie_header() {
            headers.push(("Cookie".to_string(), cookie.clone()));
        }

        if let Some(ref auth) = self.auth_header {
            headers.push(("Authorization".to_string(), auth.clone()));
        }

        if let Some(ref csrf) = self.csrf_token {
            // Common CSRF header names
            headers.push(("X-CSRF-Token".to_string(), csrf.clone()));
            headers.push(("X-XSRF-Token".to_string(), csrf.clone()));
        }

        headers
    }

    /// Check if we have any auth credentials
    pub fn has_credentials(&self) -> bool {
        !self.cookies.is_empty() || self.auth_header.is_some() || !self.local_storage.is_empty()
    }

    /// Try to find JWT token in storage or cookies
    pub fn find_jwt(&self) -> Option<String> {
        // Check local storage for common JWT keys
        for key in &[
            "token",
            "jwt",
            "access_token",
            "accessToken",
            "auth_token",
            "authToken",
            "id_token",
        ] {
            if let Some(token) = self.local_storage.get(*key) {
                if token.contains('.') && token.split('.').count() == 3 {
                    return Some(token.clone());
                }
            }
            if let Some(token) = self.session_storage.get(*key) {
                if token.contains('.') && token.split('.').count() == 3 {
                    return Some(token.clone());
                }
            }
        }

        // Check cookies
        for (_, value) in &self.cookies {
            if value.contains('.') && value.split('.').count() == 3 {
                // Looks like a JWT
                return Some(value.clone());
            }
        }

        // Check auth header
        if let Some(ref auth) = self.auth_header {
            if auth.starts_with("Bearer ") {
                let token = auth.trim_start_matches("Bearer ").trim();
                if token.contains('.') && token.split('.').count() == 3 {
                    return Some(token.to_string());
                }
            }
        }

        None
    }
}


/// Login credentials for automatic authentication
#[derive(Debug, Clone)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
    /// Optional: specific login URL (otherwise detected from target)
    pub login_url: Option<String>,
    /// Optional: username field name/selector
    pub username_field: Option<String>,
    /// Optional: password field name/selector
    pub password_field: Option<String>,
}

impl LoginCredentials {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            login_url: None,
            username_field: None,
            password_field: None,
        }
    }

    pub fn with_login_url(mut self, url: &str) -> Self {
        self.login_url = Some(url.to_string());
        self
    }
}

/// Authenticator that handles login and credential extraction
pub struct Authenticator {
    timeout: Duration,
}

impl Authenticator {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Perform login and extract authentication session
    pub async fn login(
        &self,
        base_url: &str,
        credentials: &LoginCredentials,
    ) -> Result<AuthSession> {
        info!("[Auth] Starting authentication for: {}", base_url);

        let login_url = credentials
            .login_url
            .clone()
            .unwrap_or_else(|| self.find_login_url(base_url));

        let browser_config = BrowserConfig::default()
            .timeout(self.timeout);

        let browser = Browser::new(browser_config).await
            .context("Failed to launch kalamari browser")?;

        let page = browser.new_page().await?;

        // Navigate to login page
        page.navigate(&login_url).await
            .context("Failed to navigate to login page")?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Find and fill login form
        let username_selectors = credentials
            .username_field
            .clone()
            .map(|f| vec![f])
            .unwrap_or_else(|| {
                vec![
                    "[name='username']".to_string(),
                    "[name='email']".to_string(),
                    "[name='user']".to_string(),
                    "[name='login']".to_string(),
                    "[type='email']".to_string(),
                    "#username".to_string(),
                    "#email".to_string(),
                    "[autocomplete='username']".to_string(),
                ]
            });

        let password_selectors = credentials
            .password_field
            .clone()
            .map(|f| vec![f])
            .unwrap_or_else(|| {
                vec![
                    "[name='password']".to_string(),
                    "[name='pass']".to_string(),
                    "[type='password']".to_string(),
                    "#password".to_string(),
                    "[autocomplete='current-password']".to_string(),
                ]
            });

        // Fill username
        let js_fill_username = format!(
            r#"
            (function() {{
                const selectors = {};
                for (const sel of selectors) {{
                    const el = document.querySelector(sel);
                    if (el) {{
                        el.value = '{}';
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return sel;
                    }}
                }}
                return null;
            }})()
            "#,
            serde_json::to_string(&username_selectors).unwrap(),
            credentials.username.replace("'", "\\'")
        );

        let username_result = page.evaluate(&js_fill_username)?;
        debug!("[Auth] Username field: {:?}", username_result);

        // Fill password
        let js_fill_password = format!(
            r#"
            (function() {{
                const selectors = {};
                for (const sel of selectors) {{
                    const el = document.querySelector(sel);
                    if (el) {{
                        el.value = '{}';
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return sel;
                    }}
                }}
                return null;
            }})()
            "#,
            serde_json::to_string(&password_selectors).unwrap(),
            credentials.password.replace("'", "\\'")
        );

        let password_result = page.evaluate(&js_fill_password)?;
        debug!("[Auth] Password field: {:?}", password_result);

        // Small delay to let form validation run
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Submit form
        let js_submit = r#"
            (function() {
                // Try submit button first
                const submitBtn = document.querySelector(
                    'button[type="submit"], input[type="submit"], ' +
                    'button:contains("Login"), button:contains("Sign in"), ' +
                    '[class*="login"], [class*="submit"]'
                );
                if (submitBtn) {
                    submitBtn.click();
                    return 'clicked_button';
                }

                // Try form submit
                const form = document.querySelector('form');
                if (form) {
                    form.submit();
                    return 'form_submit';
                }

                // Try Enter key on password field
                const passField = document.querySelector('[type="password"]');
                if (passField) {
                    passField.dispatchEvent(new KeyboardEvent('keypress', { key: 'Enter', keyCode: 13 }));
                    return 'enter_key';
                }

                return 'no_submit_found';
            })()
        "#;

        let submit_result = page.evaluate(js_submit)?;
        debug!("[Auth] Submit result: {:?}", submit_result);

        // Wait for login to complete (navigation or AJAX)
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Manually extract auth data
        let mut session = AuthSession::empty();
        session.authenticated_url = login_url.clone();

        // Extract cookies via JS evaluation (document.cookie)
        let js_cookies = r#"
            (function() {
                var cookies = {};
                document.cookie.split(';').forEach(function(cookie) {
                    var parts = cookie.trim().split('=');
                    if (parts.length >= 2) {
                        cookies[parts[0].trim()] = parts.slice(1).join('=');
                    }
                });
                return JSON.stringify(cookies);
            })()
        "#;
        if let Ok(result) = page.evaluate(js_cookies) {
            if let Some(json_str) = result.as_string() {
                if let Ok(cookies) = serde_json::from_str::<HashMap<String, String>>(&json_str) {
                    session.cookies = cookies;
                }
            }
        }

        // Extract localStorage via JS evaluation
        let js_local_storage = r#"
            (function() {
                var items = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return JSON.stringify(items);
            })()
        "#;
        if let Ok(result) = page.evaluate(js_local_storage) {
            if let Some(json_str) = result.as_string() {
                if let Ok(storage) = serde_json::from_str::<HashMap<String, String>>(&json_str) {
                    session.local_storage = storage;
                }
            }
        }

        // Extract sessionStorage via JS evaluation
        let js_session_storage = r#"
            (function() {
                var items = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return JSON.stringify(items);
            })()
        "#;
        if let Ok(result) = page.evaluate(js_session_storage) {
            if let Some(json_str) = result.as_string() {
                if let Ok(storage) = serde_json::from_str::<HashMap<String, String>>(&json_str) {
                    session.session_storage = storage;
                }
            }
        }

        // Check for session cookies
        let session_cookie_names = [
            "session",
            "sess",
            "PHPSESSID",
            "JSESSIONID",
            "connect.sid",
            "auth",
            "token",
        ];
        for name in &session_cookie_names {
            if session
                .cookies
                .keys()
                .any(|k: &String| k.to_lowercase().contains(name))
            {
                session.is_authenticated = true;
                break;
            }
        }

        // If we have a JWT or auth header, consider authenticated
        if session.auth_header.is_some() || session.find_jwt().is_some() {
            session.is_authenticated = true;
        }

        if session.is_authenticated {
            info!(
                "[Auth] Login successful! Extracted {} cookies, {} storage items",
                session.cookies.len(),
                session.local_storage.len() + session.session_storage.len()
            );
            if session.find_jwt().is_some() {
                info!("[Auth] JWT token detected in session");
            }
        } else {
            warn!("[Auth] Login may have failed - no clear auth indicators found");
        }

        Ok(session)
    }

    /// Find login URL from base URL
    fn find_login_url(&self, base_url: &str) -> String {
        // Common login paths
        let _login_paths = [
            "/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/account/login",
            "/api/auth/login",
        ];

        // For now, just try /login - in production would probe each
        format!("{}/login", base_url.trim_end_matches('/'))
    }

    /// Extract session from provided cookies/tokens (no login needed)
    pub fn from_token(token: &str, token_type: &str) -> AuthSession {
        let mut session = AuthSession::empty();
        session.is_authenticated = true;

        match token_type.to_lowercase().as_str() {
            "bearer" | "jwt" => {
                session.auth_header = Some(format!("Bearer {}", token));
            }
            "cookie" => {
                // Parse cookie string
                for part in token.split(';') {
                    let trimmed = part.trim();
                    if let Some(eq_pos) = trimmed.find('=') {
                        let name = trimmed[..eq_pos].to_string();
                        let value = trimmed[eq_pos + 1..].to_string();
                        session.cookies.insert(name, value);
                    }
                }
            }
            "api_key" | "apikey" => {
                session.auth_header = Some(token.to_string());
            }
            _ => {
                // Assume bearer token
                session.auth_header = Some(format!("Bearer {}", token));
            }
        }

        session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_session_cookie_header() {
        let mut session = AuthSession::empty();
        session
            .cookies
            .insert("session".to_string(), "abc123".to_string());
        session
            .cookies
            .insert("user".to_string(), "test".to_string());

        let header = session.cookie_header().unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("user=test"));
    }

    #[test]
    fn test_find_jwt() {
        let mut session = AuthSession::empty();
        session.local_storage.insert(
            "token".to_string(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".to_string()
        );

        let jwt = session.find_jwt();
        assert!(jwt.is_some());
        assert!(jwt.unwrap().starts_with("eyJ"));
    }

    #[test]
    fn test_from_token() {
        let session = Authenticator::from_token("my_jwt_token", "bearer");
        assert_eq!(session.auth_header, Some("Bearer my_jwt_token".to_string()));
        assert!(session.is_authenticated);

        let session2 = Authenticator::from_token("session=abc; user=test", "cookie");
        assert!(session2.cookies.contains_key("session"));
        assert!(session2.is_authenticated);
    }
}
