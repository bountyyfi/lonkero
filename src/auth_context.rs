// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Authentication Context for Authenticated Scanning
//!
//! Handles automatic login, token extraction, and credential management
//! for scanning authenticated endpoints.

use anyhow::{Context, Result};
use headless_chrome::{Browser, LaunchOptions};
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
                    .join("; ")
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
        !self.cookies.is_empty()
            || self.auth_header.is_some()
            || !self.local_storage.is_empty()
    }

    /// Try to find JWT token in storage or cookies
    pub fn find_jwt(&self) -> Option<String> {
        // Check local storage for common JWT keys
        for key in &["token", "jwt", "access_token", "accessToken", "auth_token", "authToken", "id_token"] {
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
    pub async fn login(&self, base_url: &str, credentials: &LoginCredentials) -> Result<AuthSession> {
        info!("[Auth] Starting authentication for: {}", base_url);

        let login_url = credentials.login_url.clone()
            .unwrap_or_else(|| self.find_login_url(base_url));

        let creds = credentials.clone();
        let timeout = self.timeout;

        let session = tokio::task::spawn_blocking(move || {
            Self::login_sync(&login_url, &creds, timeout)
        })
        .await
        .context("Login task panicked")??;

        if session.is_authenticated {
            info!("[Auth] Login successful! Extracted {} cookies, {} storage items",
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
        let _login_paths = ["/login", "/signin", "/auth/login", "/user/login", "/account/login", "/api/auth/login"];

        // For now, just try /login - in production would probe each
        format!("{}/login", base_url.trim_end_matches('/'))
    }

    /// Synchronous login implementation
    fn login_sync(login_url: &str, credentials: &LoginCredentials, timeout: Duration) -> Result<AuthSession> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Navigate to login page
        tab.navigate_to(login_url).context("Failed to navigate to login page")?;
        tab.wait_until_navigated().context("Navigation timeout")?;
        std::thread::sleep(Duration::from_secs(2));

        // Find and fill login form
        let username_selectors = credentials.username_field.clone()
            .map(|f| vec![f])
            .unwrap_or_else(|| vec![
                "[name='username']".to_string(),
                "[name='email']".to_string(),
                "[name='user']".to_string(),
                "[name='login']".to_string(),
                "[type='email']".to_string(),
                "#username".to_string(),
                "#email".to_string(),
                "[autocomplete='username']".to_string(),
            ]);

        let password_selectors = credentials.password_field.clone()
            .map(|f| vec![f])
            .unwrap_or_else(|| vec![
                "[name='password']".to_string(),
                "[name='pass']".to_string(),
                "[type='password']".to_string(),
                "#password".to_string(),
                "[autocomplete='current-password']".to_string(),
            ]);

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

        let username_result = tab.evaluate(&js_fill_username, true)?;
        debug!("[Auth] Username field: {:?}", username_result.value);

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

        let password_result = tab.evaluate(&js_fill_password, true)?;
        debug!("[Auth] Password field: {:?}", password_result.value);

        // Small delay to let form validation run
        std::thread::sleep(Duration::from_millis(500));

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

        let submit_result = tab.evaluate(js_submit, true)?;
        debug!("[Auth] Submit result: {:?}", submit_result.value);

        // Wait for login to complete (navigation or AJAX)
        std::thread::sleep(Duration::from_secs(3));

        // Try waiting for any navigation
        let _ = tab.wait_until_navigated();
        std::thread::sleep(Duration::from_secs(1));

        // Extract all auth data
        Self::extract_auth_session(&tab, login_url)
    }

    /// Extract authentication session from browser tab
    fn extract_auth_session(tab: &headless_chrome::Tab, original_url: &str) -> Result<AuthSession> {
        let js_extract = r#"
            (function() {
                const result = {
                    cookies: {},
                    localStorage: {},
                    sessionStorage: {},
                    authHeader: null,
                    csrfToken: null,
                    currentUrl: window.location.href
                };

                // Get cookies
                document.cookie.split(';').forEach(cookie => {
                    const [name, value] = cookie.trim().split('=');
                    if (name && value) {
                        result.cookies[name] = value;
                    }
                });

                // Get localStorage
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    result.localStorage[key] = localStorage.getItem(key);
                }

                // Get sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    result.sessionStorage[key] = sessionStorage.getItem(key);
                }

                // Look for CSRF tokens in meta tags
                const csrfMeta = document.querySelector('meta[name="csrf-token"], meta[name="_csrf"], meta[name="csrf"]');
                if (csrfMeta) {
                    result.csrfToken = csrfMeta.getAttribute('content');
                }

                // Look for CSRF in hidden inputs
                if (!result.csrfToken) {
                    const csrfInput = document.querySelector('input[name="_csrf"], input[name="csrf_token"], input[name="_token"]');
                    if (csrfInput) {
                        result.csrfToken = csrfInput.value;
                    }
                }

                // Check for auth token in common locations
                const tokenKeys = ['token', 'jwt', 'access_token', 'accessToken', 'auth_token', 'authToken'];
                for (const key of tokenKeys) {
                    if (result.localStorage[key]) {
                        result.authHeader = 'Bearer ' + result.localStorage[key];
                        break;
                    }
                    if (result.sessionStorage[key]) {
                        result.authHeader = 'Bearer ' + result.sessionStorage[key];
                        break;
                    }
                }

                return JSON.stringify(result);
            })()
        "#;

        let result = tab.evaluate(js_extract, true).context("Failed to extract auth data")?;

        let mut session = AuthSession::empty();
        session.authenticated_url = original_url.to_string();

        if let Some(json_str) = result.value {
            if let Some(s) = json_str.as_str() {
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(s) {
                    // Extract cookies
                    if let Some(cookies) = data.get("cookies").and_then(|v| v.as_object()) {
                        for (k, v) in cookies {
                            if let Some(val) = v.as_str() {
                                session.cookies.insert(k.clone(), val.to_string());
                            }
                        }
                    }

                    // Extract localStorage
                    if let Some(storage) = data.get("localStorage").and_then(|v| v.as_object()) {
                        for (k, v) in storage {
                            if let Some(val) = v.as_str() {
                                session.local_storage.insert(k.clone(), val.to_string());
                            }
                        }
                    }

                    // Extract sessionStorage
                    if let Some(storage) = data.get("sessionStorage").and_then(|v| v.as_object()) {
                        for (k, v) in storage {
                            if let Some(val) = v.as_str() {
                                session.session_storage.insert(k.clone(), val.to_string());
                            }
                        }
                    }

                    // Extract auth header
                    if let Some(auth) = data.get("authHeader").and_then(|v| v.as_str()) {
                        session.auth_header = Some(auth.to_string());
                    }

                    // Extract CSRF
                    if let Some(csrf) = data.get("csrfToken").and_then(|v| v.as_str()) {
                        session.csrf_token = Some(csrf.to_string());
                    }

                    // Check current URL to see if we redirected (sign of successful login)
                    if let Some(current_url) = data.get("currentUrl").and_then(|v| v.as_str()) {
                        // If URL changed from login page, likely logged in
                        if current_url != original_url && !current_url.contains("login") && !current_url.contains("error") {
                            session.is_authenticated = true;
                        }
                    }
                }
            }
        }

        // Also check if we have session cookies (another sign of auth)
        let session_cookie_names = ["session", "sess", "PHPSESSID", "JSESSIONID", "connect.sid", "auth", "token"];
        for name in &session_cookie_names {
            if session.cookies.keys().any(|k| k.to_lowercase().contains(name)) {
                session.is_authenticated = true;
                break;
            }
        }

        // If we have a JWT or auth header, consider authenticated
        if session.auth_header.is_some() || session.find_jwt().is_some() {
            session.is_authenticated = true;
        }

        Ok(session)
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
        session.cookies.insert("session".to_string(), "abc123".to_string());
        session.cookies.insert("user".to_string(), "test".to_string());

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
