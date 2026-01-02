// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Chrome/Chromium to render SPAs and extract real form elements

use crate::crawler::{DiscoveredForm, FormInput};
use anyhow::{Context, Result};
use headless_chrome::browser::tab::RequestPausedDecision;
use headless_chrome::protocol::cdp::Fetch::{
    events::RequestPausedEvent, ContinueRequest, HeaderEntry, RequestPattern, RequestStage,
};
use headless_chrome::{Browser, LaunchOptions, Tab};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// ============================================================================
// Configuration constants for timing and limits
// ============================================================================

/// Wait time for JavaScript to render after page load (milliseconds)
const JS_RENDER_WAIT_MS: u64 = 1500;
/// Wait time after form submission (milliseconds)
const FORM_SUBMIT_WAIT_MS: u64 = 3000;
/// Wait time after auth reload (milliseconds)
const POST_AUTH_RELOAD_WAIT_MS: u64 = 2000;
/// Wait time after clicking navigation elements (milliseconds)
const CLICK_NAVIGATION_WAIT_MS: u64 = 500;
/// Delay after filling form fields (milliseconds)
const POST_FILL_DELAY_MS: u64 = 300;

/// Maximum SPA routes to collect
const MAX_SPA_ROUTES: usize = 500;
/// Maximum GraphQL operations to collect
const MAX_GRAPHQL_OPERATIONS: usize = 200;
/// Maximum WebSocket endpoints to collect
const MAX_WEBSOCKET_ENDPOINTS: usize = 100;
/// Maximum links to collect
const MAX_LINKS_FOUND: usize = 1000;

// ============================================================================
// Helper functions
// ============================================================================

/// Safely escape a string for use in JavaScript code.
/// Uses JSON encoding which handles all special characters correctly.
fn js_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

// ============================================================================
// Lazy-compiled regex patterns for route extraction (compiled once at startup)
// ============================================================================

// Vue Router route patterns
static VUE_AUTH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"(?:path|name):\s*["']([^"']+)["'][^}]*meta:\s*\{[^}]*require(?:Auth|Login|Authentication):\s*(!0|true)"#
    ).expect("Invalid VUE_AUTH_REGEX pattern")
});

static VUE_ROLE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"path:\s*["']([^"']+)["'][^}]*require(?:Any)?Role[s]?:\s*\[([^\]]+)\]"#
    ).expect("Invalid VUE_ROLE_REGEX pattern")
});

static VUE_PATH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"path:\s*["']([/][^"']+)["']"#).expect("Invalid VUE_PATH_REGEX pattern")
});

// React Router patterns
static REACT_ROUTE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"<(?:Route|PrivateRoute)[^>]*path=["']([^"']+)["'][^>]*(?:requireAuth|private|protected)"#
    ).expect("Invalid REACT_ROUTE_REGEX pattern")
});

static REACT_PROTECTED_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"path:\s*["']([^"']+)["'][^}]*(?:protected|requireAuth|private):\s*(!0|true)"#
    ).expect("Invalid REACT_PROTECTED_REGEX pattern")
});

static REACT_BROWSER_ROUTER_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"createBrowserRouter\s*\(\s*\[[^\]]*path:\s*["']([^"']+)["']"#
    ).expect("Invalid REACT_BROWSER_ROUTER_REGEX pattern")
});

// Angular Router patterns
static ANGULAR_GUARD_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"path:\s*["']([^"']+)["'][^}]*canActivate:\s*\[([^\]]+)\]"#
    ).expect("Invalid ANGULAR_GUARD_REGEX pattern")
});

static ANGULAR_ROUTER_MODULE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"RouterModule\.for(?:Root|Child)\s*\(\s*\[[^\]]*path:\s*["']([^"']+)["']"#
    ).expect("Invalid ANGULAR_ROUTER_MODULE_REGEX pattern")
});

// Next.js/Nuxt patterns
static NEXTJS_PAGES_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"(?:pages|routes)\s*:\s*\[[^\]]*(?:route|path|href):\s*["']([^"']+)["']"#
    ).expect("Invalid NEXTJS_PAGES_REGEX pattern")
});

static NUXT_PATH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"(?:path|route):\s*["']([/][^"']+)["']"#).expect("Invalid NUXT_PATH_REGEX pattern")
});

// Generic route patterns
static GENERIC_NAVIGATE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"navigate\s*\(\s*["']([/][a-zA-Z0-9_\-/]+)["']"#).expect("Invalid GENERIC_NAVIGATE_REGEX pattern")
});

static GENERIC_PUSH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"(?:push|replace)\s*\(\s*["']([/][a-zA-Z0-9_\-/]+)["']"#).expect("Invalid GENERIC_PUSH_REGEX pattern")
});

static GENERIC_TO_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"to:\s*["']([/][a-zA-Z0-9_\-/]+)["']"#).expect("Invalid GENERIC_TO_REGEX pattern")
});

static GENERIC_HREF_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"href:\s*["']([/][a-zA-Z0-9_\-/]+)["']"#).expect("Invalid GENERIC_HREF_REGEX pattern")
});

static GENERIC_REDIRECT_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"redirect:\s*["']([/][a-zA-Z0-9_\-/]+)["']"#).expect("Invalid GENERIC_REDIRECT_REGEX pattern")
});

// Route validation regex
static LOCALE_PATH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"^/[a-z]{2}$").expect("Invalid LOCALE_PATH_REGEX pattern")
});

/// Maximum number of requests to capture (prevents unbounded memory growth)
const MAX_CAPTURED_REQUESTS: usize = 500;

// ============================================================================
// Network Activity Tracker - for idle detection instead of fixed delays
// ============================================================================

/// Tracks network activity to determine when page has finished loading
struct NetworkTracker {
    pending_requests: AtomicUsize,
    last_activity: Mutex<Instant>,
}

impl NetworkTracker {
    fn new() -> Self {
        Self {
            pending_requests: AtomicUsize::new(0),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    fn request_started(&self) {
        self.pending_requests.fetch_add(1, Ordering::SeqCst);
    }

    fn request_finished(&self) {
        // Use fetch_update to atomically decrement only if > 0 (prevents underflow)
        let _ = self.pending_requests.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
            if x > 0 { Some(x - 1) } else { Some(0) }
        });
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    fn pending_count(&self) -> usize {
        self.pending_requests.load(Ordering::SeqCst)
    }

    fn time_since_last_activity(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::from_secs(0))
    }
}

// ============================================================================
// Page State Tracker - for deduplication across crawl
// ============================================================================

/// Represents page state for deduplication (URL + content hash)
#[derive(Clone, Debug)]
struct PageState {
    url_without_hash: String,
    content_hash: u64,
}

impl PartialEq for PageState {
    fn eq(&self, other: &Self) -> bool {
        self.url_without_hash == other.url_without_hash && self.content_hash == other.content_hash
    }
}

impl Eq for PageState {}

impl Hash for PageState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url_without_hash.hash(state);
        self.content_hash.hash(state);
    }
}

/// Configuration for enhanced headless crawling
#[derive(Debug, Clone)]
pub struct HeadlessCrawlerConfig {
    /// Maximum time to wait for network idle (ms)
    pub network_idle_timeout_ms: u64,
    /// Time with no network activity to consider "idle" (ms)
    pub network_idle_threshold_ms: u64,
    /// Maximum click depth when exploring interactive elements
    pub max_click_depth: usize,
    /// Maximum clicks per page
    pub max_clicks_per_page: usize,
    /// Maximum pages to crawl
    pub max_pages: usize,
    /// Enable automatic session refresh on 401/403
    pub auto_session_refresh: bool,
    /// Maximum number of session refresh attempts
    pub max_session_refresh_attempts: usize,
}

/// Session state for tracking authentication during crawl
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Current auth token (if any)
    pub token: Option<String>,
    /// OAuth refresh token (if available)
    pub refresh_token: Option<String>,
    /// Token expiry time (if known)
    pub expires_at: Option<Instant>,
    /// Number of consecutive 401/403 responses
    pub auth_failure_count: usize,
    /// Session cookies to maintain
    pub cookies: HashMap<String, String>,
}

impl Default for HeadlessCrawlerConfig {
    fn default() -> Self {
        Self {
            network_idle_timeout_ms: 30000,
            network_idle_threshold_ms: 500,
            max_click_depth: 2,
            max_clicks_per_page: 10,
            max_pages: 50,
            auto_session_refresh: true,
            max_session_refresh_attempts: 3,
        }
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            token: None,
            refresh_token: None,
            expires_at: None,
            auth_failure_count: 0,
            cookies: HashMap::new(),
        }
    }
}

impl SessionState {
    /// Create new session state with an auth token
    pub fn with_token(token: String) -> Self {
        Self {
            token: Some(token),
            ..Default::default()
        }
    }

    /// Create new session with both access and refresh tokens
    pub fn with_tokens(access_token: String, refresh_token: Option<String>) -> Self {
        Self {
            token: Some(access_token),
            refresh_token,
            ..Default::default()
        }
    }

    /// Check if session appears expired (based on failures or expiry time)
    pub fn is_expired(&self) -> bool {
        // If we've seen auth failures, assume expired
        if self.auth_failure_count >= 2 {
            return true;
        }

        // Check explicit expiry time
        if let Some(expires_at) = self.expires_at {
            if Instant::now() >= expires_at {
                return true;
            }
        }

        false
    }

    /// Record an authentication failure (401/403)
    pub fn record_auth_failure(&mut self) {
        self.auth_failure_count += 1;
        debug!("[Session] Auth failure #{}", self.auth_failure_count);
    }

    /// Reset auth failure count after successful request
    pub fn reset_auth_failures(&mut self) {
        if self.auth_failure_count > 0 {
            debug!("[Session] Reset auth failures (was {})", self.auth_failure_count);
            self.auth_failure_count = 0;
        }
    }

    /// Update token after refresh
    pub fn update_token(&mut self, new_token: String, expires_in_secs: Option<u64>) {
        self.token = Some(new_token);
        self.auth_failure_count = 0;
        if let Some(secs) = expires_in_secs {
            // Set expiry with a buffer (refresh 30 seconds early)
            self.expires_at = Some(Instant::now() + Duration::from_secs(secs.saturating_sub(30)));
        }
        info!("[Session] Token refreshed successfully");
    }
}

/// Headless browser crawler for SPA form detection
pub struct HeadlessCrawler {
    timeout: Duration,
    /// Optional JWT/Bearer token for authenticated scanning
    auth_token: Option<String>,
    /// Custom HTTP headers to inject into all requests (e.g., Authorization, Cookie)
    custom_headers: HashMap<String, String>,
    /// Session state for tracking auth during long crawls
    session_state: Arc<Mutex<SessionState>>,
    /// Crawler configuration
    config: HeadlessCrawlerConfig,
}

impl HeadlessCrawler {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: None,
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(SessionState::default())),
            config: HeadlessCrawlerConfig::default(),
        }
    }

    /// Create a new headless crawler with authentication token
    pub fn with_auth(timeout_secs: u64, token: Option<String>) -> Self {
        let session_state = if let Some(ref t) = token {
            SessionState::with_token(t.clone())
        } else {
            SessionState::default()
        };

        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: token,
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(session_state)),
            config: HeadlessCrawlerConfig::default(),
        }
    }

    /// Create crawler with full configuration
    pub fn with_config(timeout_secs: u64, token: Option<String>, config: HeadlessCrawlerConfig) -> Self {
        let session_state = if let Some(ref t) = token {
            SessionState::with_token(t.clone())
        } else {
            SessionState::default()
        };

        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: token,
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(session_state)),
            config,
        }
    }

    /// Create crawler with session state for token refresh support
    pub fn with_session(timeout_secs: u64, session: SessionState, config: HeadlessCrawlerConfig) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: session.token.clone(),
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(session)),
            config,
        }
    }

    /// Create crawler with custom HTTP headers (e.g., Authorization, Cookie)
    /// Headers will be injected into all browser requests via Chrome DevTools Protocol
    pub fn with_headers(timeout_secs: u64, token: Option<String>, headers: HashMap<String, String>) -> Self {
        let session_state = if let Some(ref t) = token {
            SessionState::with_token(t.clone())
        } else {
            SessionState::default()
        };

        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: token,
            custom_headers: headers,
            session_state: Arc::new(Mutex::new(session_state)),
            config: HeadlessCrawlerConfig::default(),
        }
    }

    /// Create crawler with both custom headers and full configuration
    pub fn with_headers_and_config(
        timeout_secs: u64,
        token: Option<String>,
        headers: HashMap<String, String>,
        config: HeadlessCrawlerConfig,
    ) -> Self {
        let session_state = if let Some(ref t) = token {
            SessionState::with_token(t.clone())
        } else {
            SessionState::default()
        };

        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: token,
            custom_headers: headers,
            session_state: Arc::new(Mutex::new(session_state)),
            config,
        }
    }

    /// Check if session needs refresh (proactive check before expiry)
    pub fn needs_token_refresh(&self) -> bool {
        if let Ok(session) = self.session_state.lock() {
            session.is_expired()
        } else {
            false
        }
    }

    /// Refresh the auth token using refresh_token (for OAuth flows)
    /// Returns the new access token if successful
    pub async fn refresh_token(&self, refresh_endpoint: &str) -> Result<String> {
        let refresh_token = {
            let session = self.session_state.lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock session state"))?;
            session.refresh_token.clone()
                .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?
        };

        info!("[Session] Attempting token refresh at {}", refresh_endpoint);

        let endpoint = refresh_endpoint.to_string();
        let timeout = self.timeout;

        // Perform token refresh
        let result = tokio::task::spawn_blocking(move || {
            Self::refresh_token_sync(&endpoint, &refresh_token, timeout)
        })
        .await
        .context("Token refresh task panicked")??;

        // Update session state with new token
        if let Ok(mut session) = self.session_state.lock() {
            session.update_token(result.access_token.clone(), result.expires_in);
        }

        Ok(result.access_token)
    }

    /// Synchronous token refresh
    fn refresh_token_sync(endpoint: &str, refresh_token: &str, timeout: Duration) -> Result<TokenRefreshResult> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch browser for token refresh")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Parse base URL from endpoint
        let base_url = url::Url::parse(endpoint).context("Invalid refresh endpoint")?;
        let origin = format!("{}://{}", base_url.scheme(), base_url.host_str().unwrap_or(""));

        // Navigate to origin first to set up context
        tab.navigate_to(&origin).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;

        // Perform token refresh via fetch
        let js_refresh = format!(r#"
            (async function() {{
                try {{
                    const response = await fetch('{}', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            refresh_token: '{}',
                            grant_type: 'refresh_token'
                        }})
                    }});

                    if (!response.ok) {{
                        return JSON.stringify({{ error: 'HTTP ' + response.status }});
                    }}

                    const data = await response.json();
                    return JSON.stringify({{
                        access_token: data.access_token || data.accessToken || data.token,
                        expires_in: data.expires_in || data.expiresIn || 3600
                    }});
                }} catch (e) {{
                    return JSON.stringify({{ error: e.message }});
                }}
            }})()
        "#, endpoint, refresh_token);

        std::thread::sleep(Duration::from_millis(500));

        let result = tab.evaluate(&js_refresh, true)
            .context("Failed to execute refresh request")?;

        let json_str = result.value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| anyhow::anyhow!("No response from refresh request"))?;

        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .context("Failed to parse refresh response")?;

        if let Some(error) = parsed.get("error").and_then(|v| v.as_str()) {
            return Err(anyhow::anyhow!("Token refresh failed: {}", error));
        }

        let access_token = parsed.get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("No access_token in refresh response"))?
            .to_string();

        let expires_in = parsed.get("expires_in")
            .and_then(|v| v.as_u64());

        Ok(TokenRefreshResult { access_token, expires_in })
    }

    /// Record an auth failure (call when getting 401/403)
    pub fn record_auth_failure(&self) {
        if let Ok(mut session) = self.session_state.lock() {
            session.record_auth_failure();
        }
    }

    /// Reset auth failures (call after successful authenticated request)
    pub fn record_auth_success(&self) {
        if let Ok(mut session) = self.session_state.lock() {
            session.reset_auth_failures();
        }
    }

    /// Get current token (may return refreshed token if refresh was done)
    pub fn get_current_token(&self) -> Option<String> {
        if let Ok(session) = self.session_state.lock() {
            session.token.clone()
        } else {
            self.auth_token.clone()
        }
    }

    /// Check if we should attempt session refresh based on failure count
    pub fn should_attempt_refresh(&self) -> bool {
        if !self.config.auto_session_refresh {
            return false;
        }

        if let Ok(session) = self.session_state.lock() {
            // Only attempt refresh if we have a refresh token and haven't exceeded attempts
            session.refresh_token.is_some() &&
            session.auth_failure_count > 0 &&
            session.auth_failure_count <= self.config.max_session_refresh_attempts
        } else {
            false
        }
    }

    /// Extract forms from a JavaScript-rendered page
    pub async fn extract_forms(&self, url: &str) -> Result<Vec<DiscoveredForm>> {
        info!("[Headless] Launching browser for: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();

        // Run headless_chrome in blocking task (it's synchronous)
        let forms = tokio::task::spawn_blocking(move || {
            Self::extract_forms_sync(&url_owned, timeout, auth_token.as_deref())
        })
        .await
        .context("Headless browser task panicked")??;

        info!("[Headless] Found {} forms on {}", forms.len(), url);
        Ok(forms)
    }

    /// Synchronous form extraction (runs in blocking thread)
    fn extract_forms_sync(url: &str, timeout: Duration, auth_token: Option<&str>) -> Result<Vec<DiscoveredForm>> {
        // Launch browser
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch options error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        // Create new tab and navigate
        let tab = browser.new_tab().context("Failed to create new tab")?;

        // If we have an auth token, first navigate to the base URL and inject it
        if let Some(token) = auth_token {
            info!("[Headless] Injecting authentication token into browser session");

            // Navigate to the URL first to set up the origin
            tab.navigate_to(url)
                .context("Failed to navigate to URL")?;
            tab.wait_until_navigated()
                .context("Navigation timeout")?;

            // Inject token into localStorage (common pattern for SPAs)
            let escaped_token = js_escape(token);
            let js_inject_token = format!(r#"
                localStorage.setItem('token', {});
                localStorage.setItem('accessToken', {});
                localStorage.setItem('auth_token', {});
                localStorage.setItem('jwt', {});
            "#, escaped_token, escaped_token, escaped_token, escaped_token);
            let _ = tab.evaluate(&js_inject_token, false);

            // Reload the page to apply authentication
            tab.reload(true, None)
                .context("Failed to reload with auth")?;
            tab.wait_until_navigated()
                .context("Navigation timeout after auth")?;
        } else {
            tab.navigate_to(url)
                .context("Failed to navigate to URL")?;
            tab.wait_until_navigated()
                .context("Navigation timeout")?;
        }

        // Additional wait for JS to render
        std::thread::sleep(Duration::from_secs(2));

        // Extract forms using JavaScript - handles all input types including SELECT
        let js_extract = r#"
            (function() {
                const results = [];

                // Helper to extract input info including SELECT options
                function extractInput(el, index) {
                    const tagName = el.tagName.toLowerCase();
                    // Get name from multiple sources, generate fallback if none exist
                    let name = el.name || el.id || el.getAttribute('aria-label') || el.placeholder;
                    if (!name) {
                        // Generate fallback name from type/tag and index for controlled inputs
                        const inputType = el.type || tagName;
                        name = inputType + '_field_' + index;
                    }

                    const inputType = el.type || tagName;
                    if (inputType === 'hidden' || inputType === 'submit' || inputType === 'button') return null;

                    const info = {
                        name: name,
                        type: inputType,
                        value: el.value || null,
                        options: null,
                        required: el.required || el.getAttribute('aria-required') === 'true'
                    };

                    // For SELECT elements, get all options
                    if (tagName === 'select') {
                        info.type = 'select';
                        info.options = [];
                        el.querySelectorAll('option').forEach(opt => {
                            if (opt.value && opt.value !== '') {
                                info.options.push(opt.value);
                            }
                        });
                        // Set value to first valid option if not already set
                        if (!info.value && info.options.length > 0) {
                            info.value = info.options[0];
                        }
                    }

                    // For checkboxes/radio, capture checked state
                    if (inputType === 'checkbox' || inputType === 'radio') {
                        info.value = el.checked ? (el.value || 'on') : null;
                    }

                    return info;
                }

                // Get all form elements
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    let idx = 0;
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'POST').toUpperCase(),
                            inputs: inputs
                        });
                    }
                });

                // Find form-like containers
                document.querySelectorAll('[class*="form"], [class*="contact"], [class*="signup"], [class*="login"], [role="form"]').forEach(container => {
                    if (container.closest('form')) return;
                    const inputs = [];
                    let idx = 0;
                    container.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // Find standalone inputs
                const standalone = [];
                let standaloneIdx = 0;
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select').forEach(el => {
                    if (!el.closest('form') && !el.closest('[class*="form"]')) {
                        const info = extractInput(el, standaloneIdx++);
                        if (info) standalone.push(info);
                    }
                });
                if (standalone.length > 0) {
                    results.push({
                        action: window.location.href,
                        method: 'POST',
                        inputs: standalone
                    });
                }

                return JSON.stringify(results);
            })()
        "#;

        let result = tab.evaluate(js_extract, true)
            .context("Failed to execute JavaScript")?;

        let mut forms = Vec::new();

        if let Some(json_str) = result.value {
            if let Some(s) = json_str.as_str() {
                if let Ok(form_data) = serde_json::from_str::<Vec<serde_json::Value>>(s) {
                    for form_obj in form_data {
                        let action = form_obj
                            .get("action")
                            .and_then(|v| v.as_str())
                            .unwrap_or(url)
                            .to_string();

                        let method = form_obj
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("POST")
                            .to_uppercase();

                        let mut inputs = Vec::new();
                        if let Some(inputs_arr) = form_obj.get("inputs").and_then(|v| v.as_array()) {
                            for input_obj in inputs_arr {
                                let name = input_obj
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                if !name.is_empty() {
                                    let input_type = input_obj
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("text")
                                        .to_string();

                                    let value = input_obj
                                        .get("value")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    // Extract SELECT options if present
                                    let options = input_obj
                                        .get("options")
                                        .and_then(|v| v.as_array())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                .collect()
                                        });

                                    let required = input_obj
                                        .get("required")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    inputs.push(FormInput {
                                        name,
                                        input_type,
                                        value,
                                        options,
                                        required,
                                    });
                                }
                            }
                        }

                        if !inputs.is_empty() {
                            // Filter out language/locale selectors and navigation elements
                            let is_language_selector = inputs.len() == 1
                                && inputs[0].input_type == "select"
                                && Self::is_language_selector(&inputs[0]);

                            // Skip forms with only a single select (likely nav/filter elements)
                            let is_single_select = inputs.len() == 1 && inputs[0].input_type == "select";

                            // Skip forms with auto-generated names like "input_1", "select_field_0"
                            let has_only_generated_names = inputs.iter().all(|i| {
                                i.name.starts_with("input_") ||
                                i.name.starts_with("select_") ||
                                i.name.contains("_field_")
                            });

                            if is_language_selector {
                                debug!("[Headless] Skipping language selector at {}", action);
                            } else if is_single_select && has_only_generated_names {
                                debug!("[Headless] Skipping standalone select without proper name at {}", action);
                            } else {
                                debug!("[Headless] Form at {} with {} inputs", action, inputs.len());
                                forms.push(DiscoveredForm {
                                    action,
                                    method,
                                    inputs,
                                    discovered_at: url.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(forms)
    }

    /// Check if headless browser is available
    pub async fn is_available() -> bool {
        tokio::task::spawn_blocking(|| {
            let options = match LaunchOptions::default_builder()
                .headless(true)
                .build() {
                    Ok(o) => o,
                    Err(_) => return false,
                };
            Browser::new(options).is_ok()
        })
        .await
        .unwrap_or(false)
    }

    /// Detect multi-stage forms by filling and submitting forms
    /// Returns (initial_forms, follow_up_forms) - follow_up_forms appear after submission
    pub async fn detect_multi_stage_forms(&self, url: &str, form_values: &[(String, String)]) -> Result<Vec<DiscoveredForm>> {
        info!("[Headless] Detecting multi-stage forms at: {}", url);

        let url_owned = url.to_string();
        let values_owned: Vec<(String, String)> = form_values.to_vec();
        let timeout = self.timeout;

        let forms = tokio::task::spawn_blocking(move || {
            Self::detect_multi_stage_sync(&url_owned, &values_owned, timeout)
        })
        .await
        .context("Multi-stage detection task panicked")??;

        info!("[Headless] Multi-stage detection found {} follow-up forms", forms.len());
        Ok(forms)
    }

    // ========================================================================
    // CSRF Token Extraction and Refresh for Multi-Step Forms
    // ========================================================================

    /// Extract CSRF token from a page - fresh token for each form submission
    /// This is critical for multi-step forms where tokens change between steps
    pub async fn extract_csrf_token(&self, url: &str) -> Result<Option<CsrfTokenInfo>> {
        let url_owned = url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();

        let token_info = tokio::task::spawn_blocking(move || {
            Self::extract_csrf_token_sync(&url_owned, timeout, auth_token.as_deref())
        })
        .await
        .context("CSRF token extraction task panicked")??;

        if let Some(ref info) = token_info {
            info!("[CSRF] Extracted token '{}' from field '{}'",
                &info.value[..info.value.len().min(20)], info.field_name);
        }

        Ok(token_info)
    }

    /// Synchronous CSRF token extraction
    fn extract_csrf_token_sync(url: &str, timeout: Duration, auth_token: Option<&str>) -> Result<Option<CsrfTokenInfo>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Inject auth token if provided
        if let Some(token) = auth_token {
            tab.navigate_to(url).context("Failed to navigate")?;
            tab.wait_until_navigated().context("Navigation timeout")?;

            let escaped_token = js_escape(token);
            let js_inject = format!(r#"
                localStorage.setItem('token', {});
                localStorage.setItem('accessToken', {});
                sessionStorage.setItem('token', {});
            "#, escaped_token, escaped_token, escaped_token);
            let _ = tab.evaluate(&js_inject, false);

            tab.reload(true, None)?;
            tab.wait_until_navigated()?;
        } else {
            tab.navigate_to(url).context("Failed to navigate")?;
            tab.wait_until_navigated().context("Navigation timeout")?;
        }

        std::thread::sleep(Duration::from_millis(POST_AUTH_RELOAD_WAIT_MS));

        // Extract CSRF token using comprehensive patterns
        let js_extract = r#"
            (function() {
                // Common CSRF token field names
                const csrfPatterns = [
                    'csrf', '_csrf', 'csrfToken', 'csrf_token', 'CSRFToken',
                    '_token', 'token', 'authenticity_token',
                    '__RequestVerificationToken', 'RequestVerificationToken',
                    'csrfmiddlewaretoken', 'anti-forgery', 'antiforgery',
                    'XSRF-TOKEN', 'xsrf-token', '_xsrf',
                    'formToken', 'form_token', 'nonce', '_nonce',
                    'verification_token', 'security_token'
                ];

                // Check hidden inputs
                for (const pattern of csrfPatterns) {
                    // By name attribute
                    let el = document.querySelector(`input[name="${pattern}"]`) ||
                             document.querySelector(`input[name*="${pattern}" i]`);
                    if (el && el.value) {
                        return JSON.stringify({
                            field_name: el.name,
                            value: el.value,
                            source: 'hidden_input'
                        });
                    }

                    // By id attribute
                    el = document.getElementById(pattern);
                    if (el && el.value) {
                        return JSON.stringify({
                            field_name: el.name || el.id,
                            value: el.value,
                            source: 'hidden_input'
                        });
                    }
                }

                // Check meta tags (common in Rails, Next.js)
                const metaTags = [
                    'meta[name="csrf-token"]',
                    'meta[name="csrf_token"]',
                    'meta[name="_token"]',
                    'meta[name="csrf-param"]'
                ];
                for (const selector of metaTags) {
                    const meta = document.querySelector(selector);
                    if (meta && meta.content) {
                        const paramMeta = document.querySelector('meta[name="csrf-param"]');
                        return JSON.stringify({
                            field_name: paramMeta?.content || 'csrf_token',
                            value: meta.content,
                            source: 'meta_tag'
                        });
                    }
                }

                // Check cookies
                const cookies = document.cookie.split(';');
                for (const cookie of cookies) {
                    const [name, value] = cookie.trim().split('=');
                    const nameLower = name.toLowerCase();
                    if (nameLower.includes('csrf') || nameLower.includes('xsrf') || name === '_token') {
                        return JSON.stringify({
                            field_name: name,
                            value: decodeURIComponent(value),
                            source: 'cookie'
                        });
                    }
                }

                // Check window/global variables (common in SPAs)
                const globalPatterns = ['csrfToken', 'csrf_token', 'CSRF_TOKEN', '__csrf'];
                for (const pattern of globalPatterns) {
                    if (window[pattern]) {
                        return JSON.stringify({
                            field_name: pattern,
                            value: window[pattern],
                            source: 'window_variable'
                        });
                    }
                }

                return null;
            })()
        "#;

        let result = tab.evaluate(js_extract, true)
            .context("Failed to extract CSRF token")?;

        if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
            if json_str != "null" {
                let info: CsrfTokenInfo = serde_json::from_str(&json_str)
                    .context("Failed to parse CSRF token info")?;
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    /// Refresh CSRF token by re-fetching the page
    /// Use this before each form submission in multi-step flows
    pub async fn refresh_csrf_token(&self, url: &str, current_token: Option<&str>) -> Result<Option<CsrfTokenInfo>> {
        info!("[CSRF] Refreshing token for {}", url);

        let new_token = self.extract_csrf_token(url).await?;

        // Warn if token didn't change (might indicate static token or error)
        if let (Some(old), Some(ref new)) = (current_token, &new_token) {
            if old == new.value {
                debug!("[CSRF] Warning: Token unchanged after refresh - may be static or session-bound");
            } else {
                info!("[CSRF] Token refreshed successfully");
            }
        }

        Ok(new_token)
    }

    /// Submit form with fresh CSRF token - handles multi-step flows
    pub async fn submit_form_with_csrf(
        &self,
        url: &str,
        form_action: &str,
        form_values: &[(String, String)],
    ) -> Result<FormSubmissionResult> {
        // Extract fresh CSRF token
        let csrf_token = self.extract_csrf_token(url).await?;

        // Build form data with CSRF token
        let mut values = form_values.to_vec();
        if let Some(ref token) = csrf_token {
            // Remove any existing CSRF field and add the fresh one
            values.retain(|(k, _)| !k.to_lowercase().contains("csrf") && !k.to_lowercase().contains("token"));
            values.push((token.field_name.clone(), token.value.clone()));
        }

        let url_owned = url.to_string();
        let action_owned = form_action.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();

        let result = tokio::task::spawn_blocking(move || {
            Self::submit_form_sync(&url_owned, &action_owned, &values, timeout, auth_token.as_deref())
        })
        .await
        .context("Form submission task panicked")??;

        Ok(result)
    }

    /// Synchronous form submission
    fn submit_form_sync(
        url: &str,
        form_action: &str,
        form_values: &[(String, String)],
        timeout: Duration,
        auth_token: Option<&str>,
    ) -> Result<FormSubmissionResult> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Navigate and inject auth if needed
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;

        if let Some(token) = auth_token {
            let escaped_token = js_escape(token);
            let js_inject = format!(r#"
                localStorage.setItem('token', {});
                localStorage.setItem('accessToken', {});
            "#, escaped_token, escaped_token);
            let _ = tab.evaluate(&js_inject, false);
            tab.reload(true, None)?;
            tab.wait_until_navigated()?;
        }

        std::thread::sleep(Duration::from_millis(POST_AUTH_RELOAD_WAIT_MS));

        // Fill all form fields
        for (name, value) in form_values {
            let escaped_name = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string());
            let escaped_value = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string());
            let js_fill = format!(
                r#"
                (function() {{
                    const name = {};
                    const value = {};
                    const el = document.querySelector('[name="' + name + '"]') ||
                               document.getElementById(name) ||
                               document.querySelector('input[type="hidden"][name*="' + name + '"]');
                    if (el) {{
                        el.value = value;
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }}
                    return false;
                }})()
                "#,
                escaped_name,
                escaped_value
            );
            let _ = tab.evaluate(&js_fill, true);
        }

        // Submit the form
        let escaped_action = serde_json::to_string(form_action).unwrap_or_else(|_| "\"\"".to_string());
        let js_submit = format!(r#"
            (function() {{
                // Try to find form by action
                const action = {};
                let form = document.querySelector('form[action*="' + action + '"]');
                if (!form) form = document.querySelector('form');

                if (form) {{
                    const submit = form.querySelector('[type="submit"], button:not([type="button"])');
                    if (submit) {{
                        submit.click();
                        return 'clicked';
                    }}
                    form.submit();
                    return 'submitted';
                }}
                return 'no_form';
            }})()
        "#, escaped_action);

        let submit_result = tab.evaluate(&js_submit, true)?;
        let submit_status = submit_result.value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        std::thread::sleep(Duration::from_secs(3));

        // Get final URL after submission
        let final_url = tab.evaluate("window.location.href", false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| url.to_string());

        // Check for error indicators
        let has_error = tab.evaluate(r#"
            (function() {
                const errorPatterns = ['.error', '.alert-danger', '.form-error', '[class*="error"]'];
                for (const pattern of errorPatterns) {
                    if (document.querySelector(pattern)) return true;
                }
                return false;
            })()
        "#, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(FormSubmissionResult {
            success: submit_status != "no_form" && !has_error,
            final_url,
            submit_status,
            has_error,
        })
    }

    /// Synchronous multi-stage form detection
    fn detect_multi_stage_sync(url: &str, form_values: &[(String, String)], timeout: Duration) -> Result<Vec<DiscoveredForm>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;
        std::thread::sleep(Duration::from_secs(2));

        // Fill form fields
        for (name, value) in form_values {
            let escaped_name = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string());
            let escaped_value = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string());
            let js_fill = format!(
                r#"
                (function() {{
                    const name = {};
                    const value = {};
                    const el = document.querySelector('[name="' + name + '"]') || document.getElementById(name);
                    if (el) {{
                        el.value = value;
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }}
                    return false;
                }})()
                "#,
                escaped_name,
                escaped_value
            );
            let _ = tab.evaluate(&js_fill, true);
        }

        // Submit form
        let js_submit = r#"
            (function() {
                const form = document.querySelector('form');
                if (form) {
                    const submit = form.querySelector('[type="submit"], button:not([type="button"])');
                    if (submit) {
                        submit.click();
                        return 'clicked';
                    }
                    form.submit();
                    return 'submitted';
                }
                return 'no_form';
            })()
        "#;

        let result = tab.evaluate(js_submit, true).context("Failed to submit form")?;
        debug!("[Headless] Form submit result: {:?}", result.value);

        // Wait for page to update after submission
        std::thread::sleep(Duration::from_secs(3));

        // Check for new forms on the page (could be same page with new form or redirected)
        let forms = Self::extract_forms_from_tab(&tab, url)?;

        Ok(forms)
    }

    /// Extract forms from an existing tab
    fn extract_forms_from_tab(tab: &headless_chrome::Tab, original_url: &str) -> Result<Vec<DiscoveredForm>> {
        // Comprehensive form extraction - handles Vue/Vuetify, React, Angular, and traditional forms
        let js_extract = r#"
            (function() {
                const results = [];
                const processedContainers = new Set();

                function extractInput(el, index) {
                    const tagName = el.tagName.toLowerCase();
                    // Get name from multiple sources, generate fallback if none exist
                    let name = el.name || el.id || el.getAttribute('aria-label') || el.placeholder;

                    // For Vuetify, check parent label
                    if (!name) {
                        const label = el.closest('.v-input')?.querySelector('.v-label')?.textContent?.trim();
                        if (label) name = label.toLowerCase().replace(/[^a-z0-9]/g, '_');
                    }

                    if (!name) {
                        // Generate fallback name from type/tag and index
                        const inputType = el.type || tagName;
                        name = inputType + '_field_' + index;
                    }

                    const inputType = el.type || tagName;
                    if (inputType === 'hidden' || inputType === 'submit' || inputType === 'button') return null;

                    const info = {
                        name: name,
                        type: inputType,
                        value: el.value || null,
                        options: null,
                        required: el.required || el.getAttribute('aria-required') === 'true' || el.closest('.v-input--required') !== null
                    };

                    // For SELECT elements
                    if (tagName === 'select') {
                        info.type = 'select';
                        info.options = [];
                        el.querySelectorAll('option').forEach(opt => {
                            if (opt.value && opt.value !== '') {
                                info.options.push(opt.value);
                            }
                        });
                        if (!info.value && info.options.length > 0) {
                            info.value = info.options[0];
                        }
                    }

                    // For Vuetify select/autocomplete - check for hidden input with options
                    const vuetifySelect = el.closest('.v-select, .v-autocomplete, .v-combobox');
                    if (vuetifySelect) {
                        info.type = 'select';
                        const menuItems = document.querySelectorAll('.v-list-item');
                        if (menuItems.length > 0) {
                            info.options = Array.from(menuItems).map(item => item.textContent?.trim()).filter(Boolean);
                        }
                    }

                    if (inputType === 'checkbox' || inputType === 'radio') {
                        info.value = el.checked ? (el.value || 'on') : null;
                    }

                    return info;
                }

                // 1. Traditional <form> elements
                document.querySelectorAll('form').forEach(form => {
                    processedContainers.add(form);
                    const inputs = [];
                    let idx = 0;
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: form.action || window.location.href,
                            method: (form.method || 'POST').toUpperCase(),
                            inputs: inputs
                        });
                    }
                });

                // 2. Vuetify v-form components (rendered as div with specific classes)
                document.querySelectorAll('.v-form, [class*="v-form"]').forEach(vform => {
                    if (processedContainers.has(vform)) return;
                    processedContainers.add(vform);
                    const inputs = [];
                    let idx = 0;
                    vform.querySelectorAll('input, textarea, select, .v-input input, .v-input textarea').forEach(el => {
                        if (el.closest('.v-form') === vform || el.closest('[class*="v-form"]') === vform) {
                            const info = extractInput(el, idx++);
                            if (info) inputs.push(info);
                        }
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // 3. Form-like containers by class patterns
                const formPatterns = [
                    '[class*="form"]', '[class*="Form"]',
                    '[class*="contact"]', '[class*="signup"]', '[class*="signin"]', '[class*="login"]', '[class*="register"]',
                    '[class*="checkout"]', '[class*="payment"]', '[class*="shipping"]', '[class*="calculator"]',
                    '[role="form"]', '[data-form]'
                ];
                document.querySelectorAll(formPatterns.join(', ')).forEach(container => {
                    if (processedContainers.has(container)) return;
                    if (container.closest('form') || container.closest('.v-form')) return;
                    processedContainers.add(container);

                    const inputs = [];
                    let idx = 0;
                    container.querySelectorAll('input, textarea, select').forEach(el => {
                        const info = extractInput(el, idx++);
                        if (info) inputs.push(info);
                    });
                    if (inputs.length > 0) {
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // 4. Vuetify cards/dialogs that contain inputs (common pattern)
                document.querySelectorAll('.v-card, .v-dialog, .v-sheet').forEach(container => {
                    if (processedContainers.has(container)) return;
                    const inputs = [];
                    let idx = 0;
                    container.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach(el => {
                        if (!el.closest('form') && !el.closest('.v-form')) {
                            const info = extractInput(el, idx++);
                            if (info) inputs.push(info);
                        }
                    });
                    if (inputs.length >= 2) { // At least 2 inputs to be considered a form
                        processedContainers.add(container);
                        results.push({
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });

                // 5. Any remaining standalone inputs not in a form
                const standalone = [];
                let standaloneIdx = 0;
                document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]), textarea, select').forEach(el => {
                    // Skip if already processed
                    for (const container of processedContainers) {
                        if (container.contains(el)) return;
                    }
                    const info = extractInput(el, standaloneIdx++);
                    if (info) standalone.push(info);
                });
                if (standalone.length > 0) {
                    results.push({
                        action: window.location.href,
                        method: 'POST',
                        inputs: standalone
                    });
                }

                return JSON.stringify(results);
            })()
        "#;

        let result = tab.evaluate(js_extract, true).context("Failed to extract forms")?;
        let mut forms = Vec::new();

        if let Some(json_str) = result.value {
            if let Some(s) = json_str.as_str() {
                if let Ok(form_data) = serde_json::from_str::<Vec<serde_json::Value>>(s) {
                    for form_obj in form_data {
                        let action = form_obj.get("action")
                            .and_then(|v| v.as_str())
                            .unwrap_or(original_url)
                            .to_string();

                        let method = form_obj.get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("POST")
                            .to_uppercase();

                        let mut inputs = Vec::new();
                        if let Some(inputs_arr) = form_obj.get("inputs").and_then(|v| v.as_array()) {
                            for input_obj in inputs_arr {
                                let name = input_obj.get("name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                if !name.is_empty() {
                                    let input_type = input_obj.get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("text")
                                        .to_string();

                                    let value = input_obj.get("value")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    let options = input_obj.get("options")
                                        .and_then(|v| v.as_array())
                                        .map(|arr| {
                                            arr.iter()
                                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                .collect()
                                        });

                                    let required = input_obj.get("required")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    inputs.push(FormInput {
                                        name,
                                        input_type,
                                        value,
                                        options,
                                        required,
                                    });
                                }
                            }
                        }

                        if !inputs.is_empty() {
                            // Filter out language/locale selectors and navigation elements
                            let is_language_selector = inputs.len() == 1
                                && inputs[0].input_type == "select"
                                && Self::is_language_selector(&inputs[0]);

                            // Skip forms with only a single select (likely nav/filter elements)
                            let is_single_select = inputs.len() == 1 && inputs[0].input_type == "select";

                            // Skip forms with auto-generated names like "input_1", "select_field_0"
                            let has_only_generated_names = inputs.iter().all(|i| {
                                i.name.starts_with("input_") ||
                                i.name.starts_with("select_") ||
                                i.name.contains("_field_")
                            });

                            if is_language_selector {
                                debug!("[Headless] Skipping language selector at {}", action);
                            } else if is_single_select && has_only_generated_names {
                                debug!("[Headless] Skipping standalone select without proper name at {}", action);
                            } else {
                                debug!("[Headless] Form at {} with {} inputs", action, inputs.len());
                                forms.push(DiscoveredForm {
                                    action,
                                    method,
                                    inputs,
                                    discovered_at: original_url.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(forms)
    }

    /// Check if a form input looks like a language/locale selector
    fn is_language_selector(input: &FormInput) -> bool {
        let name_lower = input.name.to_lowercase();

        // Check name patterns - require word boundaries to avoid false positives
        let lang_name_patterns = [
            "lang", "language", "locale", "i18n", "l10n",
            "country", "region", "culture", "lng", "idioma",
            "sprache", "langue", "kieli",
        ];

        // Require exact match or word boundary match (with _ or -)
        let has_lang_name = lang_name_patterns.iter().any(|p| {
            name_lower == *p ||
            name_lower.starts_with(&format!("{}_", p)) ||
            name_lower.starts_with(&format!("{}-", p)) ||
            name_lower.ends_with(&format!("_{}", p)) ||
            name_lower.ends_with(&format!("-{}", p)) ||
            name_lower.contains(&format!("_{}_", p)) ||
            name_lower.contains(&format!("-{}-", p))
        });

        // Check if options look like language codes or names
        let has_lang_options = if let Some(options) = &input.options {
            // Exact language codes (2-3 chars)
            let lang_codes = [
                "en", "fi", "sv", "de", "fr", "es", "it", "nl", "pt", "ru", "zh", "ja", "ko",
                "da", "no", "pl", "cs", "hu", "ro", "bg", "el", "tr", "ar", "he", "th", "vi",
            ];
            // Full language names
            let lang_names = [
                "english", "finnish", "swedish", "german", "french", "spanish", "suomi",
                "svenska", "deutsch", "français", "español", "italiano", "português",
                "russian", "chinese", "japanese", "korean", "dutch", "polish",
            ];

            let code_matches = options.iter().filter(|opt| {
                let opt_lower = opt.to_lowercase().trim().to_string();
                // Exact match for codes, or code with region (en-US, en_GB)
                lang_codes.iter().any(|c| {
                    opt_lower == *c ||
                    opt_lower.starts_with(&format!("{}-", c)) ||
                    opt_lower.starts_with(&format!("{}_", c))
                })
            }).count();

            let name_matches = options.iter().filter(|opt| {
                let opt_lower = opt.to_lowercase();
                lang_names.iter().any(|n| opt_lower == *n)
            }).count();

            // If more than half of options are language codes/names, it's a language selector
            let total_options = options.len();
            total_options > 0 && (code_matches * 2 >= total_options || name_matches * 2 >= total_options)
        } else {
            false
        };

        has_lang_name || has_lang_options
    }

    /// Discover the actual API endpoint for SPA forms by intercepting network requests
    /// This is crucial for React/Next.js apps where forms don't have HTML action attributes
    /// but instead use fetch/axios to POST to API routes
    pub async fn discover_form_endpoints(&self, url: &str) -> Result<Vec<DiscoveredEndpoint>> {
        info!("[Headless] Discovering form endpoints via network interception: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();
        let custom_headers = self.custom_headers.clone();

        let endpoints = tokio::task::spawn_blocking(move || {
            Self::discover_endpoints_sync(&url_owned, timeout, auth_token.as_deref(), &custom_headers)
        })
        .await
        .context("Form endpoint discovery task panicked")??;

        info!("[Headless] Discovered {} potential form endpoints", endpoints.len());
        Ok(endpoints)
    }

    /// Synchronous endpoint discovery with network interception
    fn discover_endpoints_sync(
        url: &str,
        timeout: Duration,
        auth_token: Option<&str>,
        custom_headers: &HashMap<String, String>,
    ) -> Result<Vec<DiscoveredEndpoint>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // If we have auth token, inject it before setting up interception
        if let Some(token) = auth_token {
            info!("[Headless] Setting up authenticated session for endpoint discovery");

            // Navigate first to set origin
            tab.navigate_to(url).context("Failed to navigate for auth setup")?;
            tab.wait_until_navigated().context("Auth setup navigation timeout")?;

            // Inject token into localStorage
            let escaped_token = js_escape(token);
            let js_inject_token = format!(r#"
                localStorage.setItem('token', {});
                localStorage.setItem('accessToken', {});
                localStorage.setItem('auth_token', {});
                localStorage.setItem('jwt', {});
            "#, escaped_token, escaped_token, escaped_token, escaped_token);
            let _ = tab.evaluate(&js_inject_token, false);
        }

        // Store captured requests
        let captured_requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured_requests);

        // Build custom headers for request interception (Authorization, Cookie, etc.)
        let header_entries: Vec<HeaderEntry> = custom_headers
            .iter()
            .map(|(k, v)| HeaderEntry {
                name: k.clone(),
                value: v.clone(),
            })
            .collect();
        let headers_for_interception = Arc::new(header_entries);
        let headers_clone = Arc::clone(&headers_for_interception);

        // Enable network interception - intercept all POST/PUT requests
        let patterns = vec![
            RequestPattern {
                url_pattern: Some("*".to_string()),
                resource_Type: None,
                request_stage: Some(RequestStage::Request),
            },
        ];

        tab.enable_fetch(Some(&patterns), None)
            .context("Failed to enable fetch interception")?;

        // Set up the request interceptor with header injection
        tab.enable_request_interception(Arc::new(
            move |_transport, _session_id, intercepted: RequestPausedEvent| {
                let request = &intercepted.params.request;
                let method = if request.method.is_empty() { "GET" } else { &request.method };

                // Only capture POST/PUT/PATCH requests (form submissions)
                if method == "POST" || method == "PUT" || method == "PATCH" {
                    let url = request.url.clone();
                    let post_data = request.post_data.clone();

                    debug!("[Headless] Intercepted {} request to: {}", method, url);

                    if let Ok(mut captured) = captured_clone.lock() {
                        captured.push(CapturedRequest {
                            url,
                            method: method.to_string(),
                            post_data,
                            content_type: request.headers.0.as_ref()
                                .and_then(|h| h.get("Content-Type").or_else(|| h.get("content-type")))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                        });
                    }
                }

                // Continue the request with custom headers injected (Authorization, Cookie, etc.)
                if headers_clone.is_empty() {
                    RequestPausedDecision::Continue(None)
                } else {
                    RequestPausedDecision::Continue(Some(ContinueRequest {
                        request_id: intercepted.params.request_id.clone(),
                        url: None,
                        method: None,
                        post_data: None,
                        headers: Some(headers_clone.to_vec()),
                        intercept_response: None,
                    }))
                }
            },
        ))?;

        // Navigate to the page
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;
        std::thread::sleep(Duration::from_secs(2));

        // Find and try to submit forms with test data
        let js_fill_and_submit = r#"
            (function() {
                const results = [];

                // Find all forms and form-like containers
                const forms = document.querySelectorAll('form, [class*="form"], [class*="contact"], [role="form"]');

                forms.forEach((form, formIndex) => {
                    // Fill inputs with test data
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        const type = el.type || el.tagName.toLowerCase();
                        if (type === 'hidden' || type === 'submit' || type === 'button') return;

                        // Fill with test values based on input type/name
                        let testValue = 'test';
                        const name = (el.name || el.id || '').toLowerCase();

                        if (type === 'email' || name.includes('email')) {
                            testValue = 'test@example.com';
                        } else if (type === 'tel' || name.includes('phone')) {
                            testValue = '+1234567890';
                        } else if (name.includes('name')) {
                            testValue = 'Test User';
                        } else if (name.includes('message') || name.includes('comment') || type === 'textarea') {
                            testValue = 'Test message';
                        } else if (type === 'select') {
                            // Select first non-empty option
                            const opt = el.querySelector('option[value]:not([value=""])');
                            if (opt) testValue = opt.value;
                        } else if (type === 'checkbox' || type === 'radio') {
                            el.checked = true;
                            return;
                        }

                        el.value = testValue;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    });

                    results.push({ formIndex, filled: true });
                });

                return JSON.stringify(results);
            })()
        "#;

        let _ = tab.evaluate(js_fill_and_submit, true);

        // Try to submit the first form
        let js_submit = r#"
            (function() {
                // Try clicking submit buttons
                const submitBtn = document.querySelector(
                    'form button[type="submit"], form input[type="submit"], ' +
                    'form button:not([type="button"]), ' +
                    '[class*="form"] button[type="submit"], ' +
                    '[class*="form"] button:not([type="button"]), ' +
                    'button[class*="submit"], button[class*="send"]'
                );

                if (submitBtn) {
                    submitBtn.click();
                    return 'clicked_submit';
                }

                // Try form.submit()
                const form = document.querySelector('form');
                if (form) {
                    // Create and dispatch submit event (allows JS handlers to run)
                    const event = new Event('submit', { bubbles: true, cancelable: true });
                    form.dispatchEvent(event);
                    return 'dispatched_submit';
                }

                return 'no_form_found';
            })()
        "#;

        let submit_result = tab.evaluate(js_submit, true);
        debug!("[Headless] Submit result: {:?}", submit_result.ok().and_then(|r| r.value));

        // Wait for any async requests to complete
        std::thread::sleep(Duration::from_secs(3));

        // Disable interception
        let _ = tab.disable_fetch();

        // Get captured requests
        let endpoints = captured_requests.lock()
            .map(|captured| {
                captured.iter()
                    .filter(|req| {
                        // Filter to only include likely form submission endpoints
                        let url_lower = req.url.to_lowercase();
                        // Exclude tracking/analytics
                        !url_lower.contains("analytics") &&
                        !url_lower.contains("tracking") &&
                        !url_lower.contains("pixel") &&
                        !url_lower.contains("gtag") &&
                        !url_lower.contains("facebook.com") &&
                        !url_lower.contains("google-analytics")
                    })
                    .map(|req| DiscoveredEndpoint {
                        url: req.url.clone(),
                        method: req.method.clone(),
                        content_type: req.content_type.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(endpoints)
    }

    // ========================================================================
    // V2 Enhanced Features: Network Idle, State Dedup, Click Depth
    // ========================================================================

    /// Wait for network to become idle instead of using fixed sleep
    /// More accurate than fixed delays - handles both fast and slow sites correctly
    fn wait_for_network_idle_sync(
        tab: &Tab,
        tracker: &NetworkTracker,
        config: &HeadlessCrawlerConfig,
    ) -> Result<()> {
        let idle_threshold = Duration::from_millis(config.network_idle_threshold_ms);
        let timeout = Duration::from_millis(config.network_idle_timeout_ms);
        let start = Instant::now();

        // Wait for initial navigation
        let _ = tab.wait_until_navigated();

        // Poll for idle state
        loop {
            if start.elapsed() > timeout {
                debug!("[HeadlessCrawler] Network idle timeout reached after {:?}", start.elapsed());
                break;
            }

            let pending = tracker.pending_count();
            let idle_time = tracker.time_since_last_activity();

            if pending == 0 && idle_time >= idle_threshold {
                debug!("[HeadlessCrawler] Network idle after {:?} (no activity for {:?})", start.elapsed(), idle_time);
                break;
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }

    /// Compute page state hash for deduplication
    /// Prevents re-crawling the same content at different URLs (common in SPAs)
    fn compute_page_state_sync(tab: &Tab, url: &str) -> Result<PageState> {
        // Hash visible DOM content - more stable than full HTML
        let js = r#"
            (() => {
                const content = document.body ? document.body.innerText : '';
                let hash = 0;
                for (let i = 0; i < content.length; i++) {
                    const char = content.charCodeAt(i);
                    hash = ((hash << 5) - hash) + char;
                    hash = hash & hash; // Convert to 32bit integer
                }
                return Math.abs(hash);
            })()
        "#;

        let content_hash = tab
            .evaluate(js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Normalize URL (remove hash/fragment for comparison)
        let url_without_hash = url::Url::parse(url)
            .map(|mut u| {
                u.set_fragment(None);
                u.to_string()
            })
            .unwrap_or_else(|_| url.to_string());

        Ok(PageState {
            url_without_hash,
            content_hash,
        })
    }

    /// Click interactive elements with depth tracking
    /// Prevents infinite click loops on stateful SPAs
    fn click_interactive_with_depth(
        tab: &Tab,
        config: &HeadlessCrawlerConfig,
        current_depth: usize,
    ) -> Result<usize> {
        if current_depth >= config.max_click_depth {
            debug!("[HeadlessCrawler] Max click depth {} reached, stopping", config.max_click_depth);
            return Ok(0);
        }

        let clickable_selectors = [
            "[data-toggle]",
            "[role='button']:not([disabled])",
            ".hamburger",
            ".menu-toggle",
            "[aria-expanded='false']",
            ".dropdown-toggle",
            ".nav-link",
            "[data-bs-toggle]",
            ".accordion-button",
            "button:not([type='submit']):not([disabled])",
        ];

        let mut total_clicks = 0;

        for selector in clickable_selectors {
            if total_clicks >= config.max_clicks_per_page {
                break;
            }

            let remaining = config.max_clicks_per_page - total_clicks;
            let js = format!(
                r#"
                (() => {{
                    const elements = document.querySelectorAll('{}');
                    let clicked = 0;
                    const maxClicks = {};

                    elements.forEach(el => {{
                        if (clicked >= maxClicks) return;

                        // Skip if not visible
                        const rect = el.getBoundingClientRect();
                        if (rect.width === 0 || rect.height === 0) return;

                        // Skip if already expanded
                        if (el.getAttribute('aria-expanded') === 'true') return;

                        try {{
                            el.click();
                            clicked++;
                        }} catch(e) {{}}
                    }});
                    return clicked;
                }})()
            "#,
                selector, remaining
            );

            if let Ok(result) = tab.evaluate(&js, false) {
                if let Some(count) = result.value.and_then(|v| v.as_i64()) {
                    if count > 0 {
                        debug!("[HeadlessCrawler] Clicked {} elements matching {} (depth {})", count, selector, current_depth);
                        total_clicks += count as usize;

                        // Brief pause for content to appear
                        std::thread::sleep(Duration::from_millis(300));
                    }
                }
            }
        }

        Ok(total_clicks)
    }

    /// Parse POST data into parameter names, recursing into nested JSON objects
    /// Extracts paths like "user.email", "user.profile.name" from nested JSON
    fn parse_post_params_recursive(post_data: &str) -> HashSet<String> {
        let mut params = HashSet::new();

        // Try parsing as JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(post_data) {
            Self::extract_json_keys_recursive(&json, "", &mut params);
        }
        // Fallback to form-urlencoded
        else {
            for pair in post_data.split('&') {
                if let Some((key, _)) = pair.split_once('=') {
                    let decoded = urlencoding::decode(key).unwrap_or_else(|_| key.into());
                    params.insert(decoded.to_string());
                }
            }
        }

        params
    }

    /// Recursively extract keys from JSON, building dot-notation paths
    fn extract_json_keys_recursive(
        value: &serde_json::Value,
        prefix: &str,
        params: &mut HashSet<String>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let full_key = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    params.insert(full_key.clone());
                    // Recurse into nested objects
                    Self::extract_json_keys_recursive(val, &full_key, params);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let full_key = format!("{}[{}]", prefix, i);
                    // Recurse into array elements (especially objects)
                    Self::extract_json_keys_recursive(val, &full_key, params);
                }
            }
            _ => {
                // Scalar values - don't add as params (parent key already added)
            }
        }
    }
}

/// Result from a token refresh attempt
#[derive(Debug, Clone)]
struct TokenRefreshResult {
    access_token: String,
    expires_in: Option<u64>,
}

/// CSRF token information extracted from page
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CsrfTokenInfo {
    /// Name of the CSRF field (e.g., "_token", "csrf_token")
    pub field_name: String,
    /// The actual token value
    pub value: String,
    /// Where the token was found (hidden_input, meta_tag, cookie, window_variable)
    pub source: String,
}

// ============================================================================
// Smart Form Auto-Fill Rules
// ============================================================================

/// Smart form auto-fill utility for context-aware field value generation
pub struct FormAutoFill;

impl FormAutoFill {
    /// Generate a smart test value based on field name and type
    /// This mimics Burp Suite's smart form filling capability
    pub fn generate_value(field_name: &str, field_type: &str, options: Option<&[String]>) -> String {
        let name_lower = field_name.to_lowercase();
        let type_lower = field_type.to_lowercase();

        // Handle select elements with options
        if type_lower == "select" {
            if let Some(opts) = options {
                if !opts.is_empty() {
                    // Return first non-empty option
                    return opts.iter()
                        .find(|o| !o.is_empty())
                        .cloned()
                        .unwrap_or_else(|| opts[0].clone());
                }
            }
            return "1".to_string();
        }

        // Email fields
        if type_lower == "email" || name_lower.contains("email") || name_lower.contains("e-mail")
            || name_lower.contains("sähköposti") || name_lower.contains("correo") {
            return "test@example.com".to_string();
        }

        // Phone fields
        if type_lower == "tel" || name_lower.contains("phone") || name_lower.contains("mobile")
            || name_lower.contains("puhelin") || name_lower.contains("telephone")
            || name_lower.contains("telefono") || name_lower.contains("cel") {
            return "+1234567890".to_string();
        }

        // Name fields
        if name_lower.contains("first") && name_lower.contains("name") || name_lower == "firstname"
            || name_lower.contains("etunimi") || name_lower.contains("nombre") {
            return "John".to_string();
        }
        if name_lower.contains("last") && name_lower.contains("name") || name_lower == "lastname"
            || name_lower.contains("sukunimi") || name_lower.contains("apellido") {
            return "Doe".to_string();
        }
        if name_lower == "name" || name_lower.contains("fullname") || name_lower.contains("full_name")
            || name_lower == "nimi" || name_lower.contains("nombre_completo") {
            return "John Doe".to_string();
        }

        // Username fields
        if name_lower.contains("username") || name_lower.contains("user_name")
            || name_lower.contains("käyttäjänimi") || name_lower.contains("usuario") {
            return "testuser123".to_string();
        }

        // Password fields
        if type_lower == "password" || name_lower.contains("password") || name_lower.contains("passwd")
            || name_lower.contains("salasana") || name_lower.contains("contraseña") {
            return "TestP@ss123!".to_string();
        }

        // URL fields
        if type_lower == "url" || name_lower.contains("url") || name_lower.contains("website")
            || name_lower.contains("homepage") || name_lower.contains("link") {
            return "https://example.com".to_string();
        }

        // Date fields
        if type_lower == "date" || name_lower.contains("date") || name_lower.contains("birth")
            || name_lower.contains("syntymä") || name_lower.contains("fecha") {
            return "1990-01-15".to_string();
        }

        // Datetime fields
        if type_lower == "datetime" || type_lower == "datetime-local" {
            return "2024-01-15T10:00".to_string();
        }

        // Time fields
        if type_lower == "time" {
            return "10:00".to_string();
        }

        // Number/quantity fields
        if type_lower == "number" || name_lower.contains("quantity") || name_lower.contains("amount")
            || name_lower.contains("count") || name_lower.contains("määrä") {
            return "1".to_string();
        }

        // Age fields
        if name_lower.contains("age") || name_lower == "ikä" || name_lower.contains("edad") {
            return "30".to_string();
        }

        // Zipcode/postal code fields
        if name_lower.contains("zip") || name_lower.contains("postal") || name_lower.contains("postinumero")
            || name_lower.contains("código_postal") || name_lower.contains("plz") {
            return "12345".to_string();
        }

        // City fields
        if name_lower.contains("city") || name_lower.contains("kaupunki") || name_lower.contains("ciudad")
            || name_lower.contains("stadt") || name_lower.contains("ville") {
            return "Helsinki".to_string();
        }

        // Country fields
        if name_lower.contains("country") || name_lower.contains("maa") || name_lower.contains("país")
            || name_lower.contains("land") || name_lower.contains("pays") {
            return "Finland".to_string();
        }

        // Address fields
        if name_lower.contains("address") || name_lower.contains("osoite") || name_lower.contains("dirección")
            || name_lower.contains("street") || name_lower.contains("katu") {
            return "123 Test Street".to_string();
        }

        // Company fields
        if name_lower.contains("company") || name_lower.contains("organization") || name_lower.contains("yritys")
            || name_lower.contains("empresa") || name_lower.contains("firma") {
            return "Test Company Oy".to_string();
        }

        // Title fields
        if name_lower.contains("title") || name_lower.contains("otsikko") || name_lower.contains("título") {
            return "Test Title".to_string();
        }

        // Subject fields
        if name_lower.contains("subject") || name_lower.contains("aihe") || name_lower.contains("asunto") {
            return "Test Subject".to_string();
        }

        // Message/comment/description fields
        if type_lower == "textarea" || name_lower.contains("message") || name_lower.contains("comment")
            || name_lower.contains("description") || name_lower.contains("viesti")
            || name_lower.contains("kuvaus") || name_lower.contains("mensaje")
            || name_lower.contains("feedback") || name_lower.contains("palaute") {
            return "This is a test message for form validation.".to_string();
        }

        // Checkbox/radio fields
        if type_lower == "checkbox" || type_lower == "radio" {
            return "on".to_string();
        }

        // Credit card number (use obvious test value)
        if name_lower.contains("card") && name_lower.contains("number")
            || name_lower.contains("credit") || name_lower.contains("cc_num") {
            return "4111111111111111".to_string(); // Standard test card
        }

        // CVV/CVC
        if name_lower.contains("cvv") || name_lower.contains("cvc") || name_lower.contains("security_code") {
            return "123".to_string();
        }

        // Card expiry
        if name_lower.contains("expir") || name_lower.contains("exp_") {
            if name_lower.contains("month") || name_lower.contains("mm") {
                return "12".to_string();
            }
            if name_lower.contains("year") || name_lower.contains("yy") {
                return "25".to_string();
            }
            return "12/25".to_string();
        }

        // SSN/personal ID (use obvious fake)
        if name_lower.contains("ssn") || name_lower.contains("social_security")
            || name_lower.contains("henkilötunnus") {
            return "123-45-6789".to_string();
        }

        // Search fields
        if type_lower == "search" || name_lower.contains("search") || name_lower.contains("query")
            || name_lower.contains("q") || name_lower.contains("haku") {
            return "test search".to_string();
        }

        // Hidden fields (usually should preserve original value)
        if type_lower == "hidden" {
            return String::new(); // Don't override hidden fields
        }

        // ID/reference fields
        if name_lower.contains("id") && (name_lower.contains("user") || name_lower.contains("ref")
            || name_lower.contains("customer") || name_lower.contains("order")) {
            return "123".to_string();
        }

        // Color fields
        if type_lower == "color" {
            return "#ff0000".to_string();
        }

        // Range fields
        if type_lower == "range" {
            return "50".to_string();
        }

        // File fields (can't really auto-fill)
        if type_lower == "file" {
            return String::new();
        }

        // Default fallback
        "test".to_string()
    }

    /// Generate test values for all form inputs
    pub fn fill_form(inputs: &[crate::crawler::FormInput]) -> Vec<(String, String)> {
        inputs.iter()
            .filter(|input| !input.name.is_empty())
            .filter(|input| input.input_type.to_lowercase() != "hidden") // Don't override hidden fields
            .filter(|input| input.input_type.to_lowercase() != "submit") // Skip submit buttons
            .map(|input| {
                let options: Option<Vec<String>> = input.options.clone();
                let value = Self::generate_value(
                    &input.name,
                    &input.input_type,
                    options.as_ref().map(|v| v.as_slice())
                );
                (input.name.clone(), value)
            })
            .collect()
    }

    /// Generate test values with custom overrides
    pub fn fill_form_with_overrides(
        inputs: &[crate::crawler::FormInput],
        overrides: &HashMap<String, String>,
    ) -> Vec<(String, String)> {
        inputs.iter()
            .filter(|input| !input.name.is_empty())
            .filter(|input| input.input_type.to_lowercase() != "hidden")
            .filter(|input| input.input_type.to_lowercase() != "submit")
            .map(|input| {
                // Check if we have an override for this field
                let value = if let Some(override_val) = overrides.get(&input.name) {
                    override_val.clone()
                } else {
                    let options: Option<Vec<String>> = input.options.clone();
                    Self::generate_value(
                        &input.name,
                        &input.input_type,
                        options.as_ref().map(|v| v.as_slice())
                    )
                };
                (input.name.clone(), value)
            })
            .collect()
    }

    /// Check if a field value looks like a "test" or "dummy" value
    /// Useful for detecting if form was auto-filled
    pub fn is_test_value(value: &str) -> bool {
        let v = value.to_lowercase();
        v.contains("test") || v.contains("example") || v.contains("dummy")
            || v == "john" || v == "doe" || v == "john doe"
            || v == "testuser" || v == "testuser123"
            || v.contains("@example.com") || v.contains("@test.com")
            || v == "123 test street" || v == "test company"
            || v == "4111111111111111" // Test card
    }
}

/// Result of form submission
#[derive(Debug, Clone)]
pub struct FormSubmissionResult {
    /// Whether submission appeared successful
    pub success: bool,
    /// Final URL after submission (may have redirected)
    pub final_url: String,
    /// How the form was submitted (clicked, submitted, no_form)
    pub submit_status: String,
    /// Whether error indicators were found on the page
    pub has_error: bool,
}

/// Captured network request during form submission interception
#[derive(Debug, Clone)]
struct CapturedRequest {
    url: String,
    method: String,
    post_data: Option<String>,
    content_type: Option<String>,
}

/// Discovered form submission endpoint
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub content_type: Option<String>,
}

/// Complete site crawl results
#[derive(Debug, Clone, Default)]
pub struct SiteCrawlResults {
    /// All pages visited during crawl
    pub pages_visited: Vec<String>,
    /// All forms discovered across the site
    pub forms: Vec<DiscoveredForm>,
    /// All API endpoints discovered via network interception
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    /// Internal links found but not yet visited (for reference)
    pub links_found: Vec<String>,
    /// JavaScript files discovered (for JS Miner analysis)
    pub js_files: Vec<String>,
    /// GraphQL operations discovered in JS bundles
    pub graphql_operations: Vec<GraphQLOperation>,
    /// GraphQL endpoints discovered
    pub graphql_endpoints: Vec<String>,
    /// WebSocket endpoints discovered (ws:// or wss://)
    pub websocket_endpoints: Vec<String>,
    /// Login forms detected during crawl
    pub login_forms: Vec<DetectedLoginForm>,
    /// State tracking results (state changes, dependencies, patterns)
    pub state_tracking: Option<crate::state_tracker::StateTrackingResults>,
    /// Form replay data (recorded sequences for security testing)
    pub form_replay_data: Option<crate::form_replay::FormRecorderResults>,
    /// SPA routes discovered from JavaScript bundles (Vue Router, React Router, Angular Router)
    pub spa_routes: Vec<SpaRoute>,
}

/// Client-side route discovered from SPA framework
#[derive(Debug, Clone)]
pub struct SpaRoute {
    /// Route path (e.g., "/admin", "/user/:id")
    pub path: String,
    /// Whether route requires authentication (if detectable)
    pub requires_auth: bool,
    /// Required roles if RBAC detected
    pub required_roles: Vec<String>,
    /// Framework that defined this route
    pub framework: SpaFramework,
    /// Source JS file where route was found
    pub source_file: String,
}

/// SPA framework type
#[derive(Debug, Clone, PartialEq)]
pub enum SpaFramework {
    Vue,
    React,
    Angular,
    NextJS,
    Nuxt,
    Unknown,
}

/// Discovered GraphQL operation (query, mutation, subscription)
#[derive(Debug, Clone)]
pub struct GraphQLOperation {
    /// Operation type: query, mutation, subscription
    pub operation_type: String,
    /// Operation name
    pub name: String,
    /// Raw operation string
    pub raw: String,
    /// Source file where discovered
    pub source: String,
}

/// Detected login form with auto-fill capability
#[derive(Debug, Clone, Default)]
pub struct DetectedLoginForm {
    /// URL where the login form was found
    pub url: String,
    /// Form action URL (may be same-page for SPA)
    pub action: String,
    /// Form method (POST/GET)
    pub method: String,
    /// Username/email field selector
    pub username_selector: String,
    /// Password field selector
    pub password_selector: String,
    /// Submit button selector (if found)
    pub submit_selector: Option<String>,
    /// Whether this is an OAuth/SSO login (detected external redirect)
    pub is_oauth: bool,
    /// OAuth provider detected (Google, GitHub, Okta, etc.)
    pub oauth_provider: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Credentials for auto-login
#[derive(Debug, Clone)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

/// Result of login attempt
#[derive(Debug, Clone)]
pub struct LoginResult {
    /// Whether login was successful
    pub success: bool,
    /// Auth token extracted after login (if any)
    pub token: Option<String>,
    /// Cookies set after login
    pub cookies: HashMap<String, String>,
    /// URL we landed on after login
    pub redirect_url: Option<String>,
    /// Error message if login failed
    pub error: Option<String>,
}

impl HeadlessCrawler {
    /// Crawl entire authenticated site - discover all pages, forms, and API endpoints
    /// This is the main entry point for comprehensive site scanning
    pub async fn crawl_authenticated_site(&self, start_url: &str, max_pages: usize) -> Result<SiteCrawlResults> {
        info!("[Headless] Starting full authenticated site crawl: {}", start_url);

        let url_owned = start_url.to_string();
        let timeout = self.timeout;
        let auth_token = self.auth_token.clone();
        let custom_headers = self.custom_headers.clone();

        let results = tokio::task::spawn_blocking(move || {
            Self::crawl_site_sync(&url_owned, timeout, auth_token.as_deref(), max_pages, &custom_headers)
        })
        .await
        .context("Site crawl task panicked")??;

        info!(
            "[Headless] Site crawl complete: {} pages, {} forms, {} API endpoints",
            results.pages_visited.len(),
            results.forms.len(),
            results.api_endpoints.len()
        );
        Ok(results)
    }

    /// Synchronous full site crawl
    fn crawl_site_sync(
        start_url: &str,
        timeout: Duration,
        auth_token: Option<&str>,
        max_pages: usize,
        custom_headers: &HashMap<String, String>,
    ) -> Result<SiteCrawlResults> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?,
        )
        .context("Failed to launch Chrome/Chromium")?;

        let tab = browser.new_tab().context("Failed to create tab")?;

        // Parse base URL for same-origin checks
        let base_url = url::Url::parse(start_url).context("Invalid start URL")?;
        let base_host = base_url.host_str().unwrap_or("").to_string();

        // Inject WebSocket interceptor script before any page JS runs
        // This wraps the native WebSocket constructor to capture all WS connections
        let ws_interceptor_script = r#"
            (function() {
                // Store captured WebSocket URLs in a global array
                window.__lonkero_ws_endpoints = window.__lonkero_ws_endpoints || [];

                // Save original WebSocket constructor
                const OriginalWebSocket = window.WebSocket;

                // Create proxy constructor
                window.WebSocket = function(url, protocols) {
                    // Capture the URL
                    if (url && !window.__lonkero_ws_endpoints.includes(url)) {
                        window.__lonkero_ws_endpoints.push(url);
                        console.log('[Lonkero] Captured WebSocket:', url);
                    }

                    // Call original constructor
                    if (protocols !== undefined) {
                        return new OriginalWebSocket(url, protocols);
                    }
                    return new OriginalWebSocket(url);
                };

                // Copy static properties and prototype
                window.WebSocket.prototype = OriginalWebSocket.prototype;
                window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
                window.WebSocket.OPEN = OriginalWebSocket.OPEN;
                window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
                window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
            })();
        "#;

        // Use evaluate with addScriptToEvaluateOnNewDocument behavior
        // First navigate, then inject and reload to ensure script runs before page JS
        let _ = tab.evaluate(ws_interceptor_script, false);
        debug!("[Headless] Injected WebSocket interceptor script");

        // Track visited pages and pages to visit
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut to_visit: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        to_visit.push_back(start_url.to_string());

        let mut results = SiteCrawlResults::default();

        // Set up network interception for API discovery
        let captured_requests: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured_requests);

        // Build custom headers for request interception (Authorization, Cookie, etc.)
        let header_entries: Vec<HeaderEntry> = custom_headers
            .iter()
            .map(|(k, v)| HeaderEntry {
                name: k.clone(),
                value: v.clone(),
            })
            .collect();
        let headers_for_interception = Arc::new(header_entries);
        let headers_clone = Arc::clone(&headers_for_interception);

        if !custom_headers.is_empty() {
            info!("[Headless] Injecting {} custom headers into all requests", custom_headers.len());
            for (k, _) in custom_headers {
                debug!("[Headless] Will inject header: {}", k);
            }
        }

        let patterns = vec![RequestPattern {
            url_pattern: Some("*".to_string()),
            resource_Type: None,
            request_stage: Some(RequestStage::Request),
        }];

        tab.enable_fetch(Some(&patterns), None)
            .context("Failed to enable fetch interception")?;

        tab.enable_request_interception(Arc::new(
            move |_transport, _session_id, intercepted: RequestPausedEvent| {
                let request = &intercepted.params.request;
                let method = if request.method.is_empty() {
                    "GET"
                } else {
                    &request.method
                };

                // Capture ALL HTTP methods for API endpoints (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
                // This ensures full coverage like Burp Suite's crawler
                let url_lower = request.url.to_lowercase();

                // Identify API-like endpoints
                let is_api_path = url_lower.contains("/api/")
                    || url_lower.contains("/graphql")
                    || url_lower.contains("/gql")
                    || url_lower.contains("/v1/")
                    || url_lower.contains("/v2/")
                    || url_lower.contains("/v3/")
                    || url_lower.contains("/rest/")
                    || url_lower.contains("/ajax/")
                    || url_lower.contains("/rpc/")
                    || url_lower.contains("/webhook")
                    || url_lower.contains("/callback");

                // All non-GET methods are interesting (POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
                let is_data_method = method != "GET";

                // For GET requests, check if they look like API calls by extension/path
                let is_api_get = method == "GET" && (
                    is_api_path
                    || url_lower.ends_with(".json")
                    || url_lower.ends_with(".xml")
                    || url_lower.contains("?format=json")
                    || url_lower.contains("&format=json")
                );

                // Capture if it's an API path, data-modifying method, or API-like GET
                let is_api_request = is_api_path || is_data_method || is_api_get;

                if is_api_request {
                    // Filter out tracking/analytics and static assets
                    let should_capture = !url_lower.contains("analytics")
                        && !url_lower.contains("tracking")
                        && !url_lower.contains("pixel")
                        && !url_lower.contains("gtag")
                        && !url_lower.contains("facebook.com")
                        && !url_lower.contains("google-analytics")
                        && !url_lower.contains("sentry.io")
                        && !url_lower.contains("cdn.");

                    if should_capture {
                        if let Ok(mut captured) = captured_clone.lock() {
                            // Avoid duplicates and limit total captures
                            let exists = captured.iter().any(|r| r.url == request.url && r.method == method);
                            if !exists && captured.len() < MAX_CAPTURED_REQUESTS {
                                debug!("[Headless] Captured API: {} {}", method, request.url);
                                captured.push(CapturedRequest {
                                    url: request.url.clone(),
                                    method: method.to_string(),
                                    post_data: request.post_data.clone(),
                                    content_type: request
                                        .headers
                                        .0
                                        .as_ref()
                                        .and_then(|h| {
                                            h.get("Content-Type").or_else(|| h.get("content-type"))
                                        })
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                });
                            }
                        }
                    }
                }

                // Continue the request with custom headers injected (Authorization, Cookie, etc.)
                if headers_clone.is_empty() {
                    RequestPausedDecision::Continue(None)
                } else {
                    RequestPausedDecision::Continue(Some(ContinueRequest {
                        request_id: intercepted.params.request_id.clone(),
                        url: None,
                        method: None,
                        post_data: None,
                        headers: Some(headers_clone.to_vec()),
                        intercept_response: None,
                    }))
                }
            },
        ))?;

        // Navigate to start URL and inject auth token
        tab.navigate_to(start_url)
            .context("Failed to navigate to start URL")?;
        tab.wait_until_navigated()
            .context("Navigation timeout")?;

        if let Some(token) = auth_token {
            info!("[Headless] Injecting authentication token");
            let escaped_token = js_escape(token);
            let js_inject_token = format!(
                r#"
                localStorage.setItem('token', {});
                localStorage.setItem('accessToken', {});
                localStorage.setItem('auth_token', {});
                localStorage.setItem('jwt', {});
                sessionStorage.setItem('token', {});
                sessionStorage.setItem('accessToken', {});
            "#,
                escaped_token, escaped_token, escaped_token, escaped_token, escaped_token, escaped_token
            );
            let _ = tab.evaluate(&js_inject_token, false);

            // Reload to apply auth
            tab.reload(true, None).context("Failed to reload with auth")?;
            tab.wait_until_navigated()
                .context("Navigation timeout after auth")?;
        }

        // Crawl loop
        while let Some(current_url) = to_visit.pop_front() {
            if visited.contains(&current_url) {
                continue;
            }

            if visited.len() >= max_pages {
                info!(
                    "[Headless] Reached max pages limit ({}), stopping crawl",
                    max_pages
                );
                break;
            }

            // Navigate to the page
            if current_url != start_url || visited.is_empty() {
                debug!("[Headless] Navigating to: {}", current_url);
                if tab.navigate_to(&current_url).is_err() {
                    warn!("[Headless] Failed to navigate to: {}", current_url);
                    continue;
                }
                if tab.wait_until_navigated().is_err() {
                    warn!("[Headless] Navigation timeout for: {}", current_url);
                    continue;
                }
            }

            visited.insert(current_url.clone());
            results.pages_visited.push(current_url.clone());

            // Wait for JS to render first - SPAs often redirect via JavaScript after initial load
            std::thread::sleep(Duration::from_millis(1500));

            // Check if we were redirected to a different URL (e.g., auth page)
            // This is important for detecting Cognito/OAuth login redirects
            // We check AFTER the JS render wait because SPAs redirect via JavaScript
            if let Ok(actual_url) = tab.evaluate("window.location.href", false) {
                if let Some(actual_url_str) = actual_url.value.as_ref().and_then(|v| v.as_str()) {
                    if actual_url_str != current_url && !visited.contains(actual_url_str) {
                        info!("[Headless] Detected redirect: {} -> {}", current_url, actual_url_str);
                        // Add the redirect URL to pages_visited for Cognito/OAuth detection
                        results.pages_visited.push(actual_url_str.to_string());
                        // Mark it as visited to avoid re-crawling
                        visited.insert(actual_url_str.to_string());
                    }
                }
            }

            // Extract forms from current page
            match Self::extract_forms_from_tab(&tab, &current_url) {
                Ok(page_forms) => {
                    info!(
                        "[Headless] Page {} - found {} forms",
                        current_url,
                        page_forms.len()
                    );
                    results.forms.extend(page_forms);
                }
                Err(e) => {
                    warn!("[Headless] Failed to extract forms from {}: {}", current_url, e);
                }
            }

            // Extract internal links
            let js_extract_links = format!(
                r#"
                (function() {{
                    const links = new Set();
                    const baseHost = '{}';

                    // Get all anchor links
                    document.querySelectorAll('a[href]').forEach(a => {{
                        try {{
                            const href = a.href;
                            if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) return;

                            const url = new URL(href, window.location.origin);
                            // Same origin check
                            if (url.hostname === baseHost || url.hostname.endsWith('.' + baseHost)) {{
                                // Skip file downloads and external resources
                                const path = url.pathname.toLowerCase();
                                if (path.endsWith('.pdf') || path.endsWith('.zip') || path.endsWith('.doc')) return;
                                if (path.endsWith('.png') || path.endsWith('.jpg') || path.endsWith('.gif')) return;

                                // Clean URL (remove hash)
                                url.hash = '';
                                links.add(url.href);
                            }}
                        }} catch(e) {{}}
                    }});

                    // Also check for SPA navigation links (router-link, etc)
                    document.querySelectorAll('[to], [routerlink], [ng-href]').forEach(el => {{
                        const to = el.getAttribute('to') || el.getAttribute('routerlink') || el.getAttribute('ng-href');
                        if (to && !to.startsWith('#')) {{
                            try {{
                                const url = new URL(to, window.location.origin);
                                if (url.hostname === baseHost) {{
                                    links.add(url.href);
                                }}
                            }} catch(e) {{}}
                        }}
                    }});

                    return JSON.stringify(Array.from(links));
                }})()
            "#,
                base_host
            );

            if let Ok(result) = tab.evaluate(&js_extract_links, true) {
                if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(links) = serde_json::from_str::<Vec<String>>(&json_str) {
                        for link in links {
                            if !visited.contains(&link) && !to_visit.contains(&link) {
                                to_visit.push_back(link.clone());
                                results.links_found.push(link);
                            }
                        }
                    }
                }
            }

            // ================================================================
            // Click-through Navigation - Actually click elements to discover routes
            // ================================================================
            let click_navigation = format!(
                r#"
                (function() {{
                    const discovered = [];
                    const baseHost = '{}';
                    const startUrl = window.location.href;
                    let clickCount = 0;
                    const maxClicks = 15;

                    // Helper to capture current URL after click
                    function captureUrl() {{
                        const url = window.location.href;
                        if (url && !discovered.includes(url)) {{
                            discovered.push(url);
                        }}
                    }}

                    // Selector for clickable navigation elements
                    const navSelectors = [
                        'nav a[href]',
                        '[role="navigation"] a',
                        '.nav-link',
                        '.menu-item a',
                        '.sidebar a',
                        '.navigation a',
                        '[class*="nav"] a[href]',
                        '[class*="menu"] a[href]',
                        'header a[href]',
                        '.header a[href]',
                        // Vue/React router links
                        '[to]',
                        'router-link',
                        '[routerlink]',
                        // Buttons that might navigate
                        'button[data-href]',
                        '[role="link"]',
                        // Tabs and toggles
                        '[role="tab"]',
                        '.tab',
                        '.v-tab',
                        // Accordions/dropdowns
                        '[data-toggle]',
                        '.dropdown-toggle',
                        '[aria-haspopup="true"]',
                    ];

                    const allElements = document.querySelectorAll(navSelectors.join(', '));

                    allElements.forEach((el, i) => {{
                        if (clickCount >= maxClicks) return;

                        try {{
                            // Check if internal link
                            const href = el.href || el.getAttribute('to') || el.getAttribute('routerlink');
                            if (href) {{
                                if (href.startsWith('http') && !href.includes(baseHost)) return;
                                if (href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) return;
                            }}

                            // Click the element
                            el.click();
                            clickCount++;

                            // Small delay and capture URL
                            setTimeout(captureUrl, 100);

                        }} catch(e) {{}}
                    }});

                    // Return after giving clicks time to process
                    return JSON.stringify(discovered);
                }})()
                "#,
                base_host
            );

            // Execute click navigation
            if let Ok(click_result) = tab.evaluate(&click_navigation, true) {
                // Wait for navigations to complete
                std::thread::sleep(Duration::from_millis(500));

                if let Some(json_str) = click_result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(click_urls) = serde_json::from_str::<Vec<String>>(&json_str) {
                        for url in click_urls {
                            if !visited.contains(&url) && !to_visit.contains(&url) {
                                debug!("[Headless] Click navigation discovered: {}", url);
                                to_visit.push_back(url.clone());
                                results.links_found.push(url);
                            }
                        }
                    }
                }
            }

            // Also check for URL changes via history API
            if let Ok(history_result) = tab.evaluate("window.location.href", false) {
                if let Some(current_url) = history_result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if !visited.contains(&current_url) && !to_visit.contains(&current_url) {
                        to_visit.push_back(current_url.clone());
                        results.links_found.push(current_url);
                    }
                }
            }
        }

        // Disable interception
        let _ = tab.disable_fetch();

        // Collect API endpoints
        if let Ok(captured) = captured_requests.lock() {
            for req in captured.iter() {
                results.api_endpoints.push(DiscoveredEndpoint {
                    url: req.url.clone(),
                    method: req.method.clone(),
                    content_type: req.content_type.clone(),
                });

                // Collect GraphQL endpoints
                if req.url.to_lowercase().contains("graphql") {
                    if !results.graphql_endpoints.contains(&req.url) {
                        results.graphql_endpoints.push(req.url.clone());
                    }
                }
            }
        }

        // Collect WebSocket endpoints captured by the interceptor
        let ws_extract = r#"
            (function() {
                return JSON.stringify(window.__lonkero_ws_endpoints || []);
            })()
        "#;

        if let Ok(ws_result) = tab.evaluate(ws_extract, true) {
            if let Some(json_str) = ws_result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                if let Ok(ws_urls) = serde_json::from_str::<Vec<String>>(&json_str) {
                    for ws_url in ws_urls {
                        if !results.websocket_endpoints.contains(&ws_url) {
                            info!("[Headless] Discovered WebSocket endpoint: {}", ws_url);
                            results.websocket_endpoints.push(ws_url);
                        }
                    }
                }
            }
        }

        // Extract JS files and GraphQL operations from all visited pages
        // Navigate back to start URL for final JS extraction
        if tab.navigate_to(start_url).is_ok() {
            let _ = tab.wait_until_navigated();
            std::thread::sleep(Duration::from_millis(1000));

            // Extract all JS file URLs
            let js_extract = format!(
                r#"
                (function() {{
                    const jsFiles = new Set();
                    const baseHost = '{}';

                    // Get all script tags with src
                    document.querySelectorAll('script[src]').forEach(script => {{
                        try {{
                            const src = script.src;
                            if (src && !src.includes('analytics') && !src.includes('gtag') &&
                                !src.includes('facebook') && !src.includes('twitter') &&
                                !src.includes('cdn.') && !src.includes('googletagmanager')) {{
                                const url = new URL(src, window.location.origin);
                                if (url.hostname === baseHost || url.hostname.endsWith('.' + baseHost)) {{
                                    jsFiles.add(url.href);
                                }}
                            }}
                        }} catch(e) {{}}
                    }});

                    return JSON.stringify(Array.from(jsFiles));
                }})()
            "#,
                base_host
            );

            if let Ok(result) = tab.evaluate(&js_extract, true) {
                if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(files) = serde_json::from_str::<Vec<String>>(&json_str) {
                        results.js_files = files.clone();
                        info!("[Headless] Found {} JavaScript files for analysis", results.js_files.len());

                        // ================================================================
                        // SPA Route Extraction from JS Bundles
                        // ================================================================
                        info!("[Headless] Extracting SPA routes from JavaScript bundles...");

                        for js_url in files.iter().take(5) {
                            // Fetch JS content using browser's fetch API
                            let fetch_js = format!(
                                r#"
                                (async function() {{
                                    try {{
                                        const response = await fetch('{}');
                                        if (response.ok) {{
                                            const text = await response.text();
                                            return text.substring(0, 500000); // Limit to 500KB
                                        }}
                                        return '';
                                    }} catch(e) {{
                                        return '';
                                    }}
                                }})()
                                "#,
                                js_url
                            );

                            if let Ok(fetch_result) = tab.evaluate(&fetch_js, true) {
                                if let Some(js_content) = fetch_result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                                    if !js_content.is_empty() {
                                        let routes = Self::extract_spa_routes_from_js(&js_content, js_url);

                                        if !routes.is_empty() {
                                            info!("[Headless] Extracted {} SPA routes from {}", routes.len(), js_url);

                                            // Add routes to results
                                            for route in &routes {
                                                debug!("[Headless] Found route: {} (auth: {}, roles: {:?}, framework: {:?})",
                                                    route.path, route.requires_auth, route.required_roles, route.framework);
                                            }

                                            results.spa_routes.extend(routes);
                                        }
                                    }
                                }
                            }
                        }

                        // Deduplicate spa_routes by path
                        let mut seen_paths = std::collections::HashSet::new();
                        results.spa_routes.retain(|r| seen_paths.insert(r.path.clone()));

                        if !results.spa_routes.is_empty() {
                            info!("[Headless] Total {} unique SPA routes discovered", results.spa_routes.len());
                        }
                    }
                }
            }

            // ================================================================
            // Vue/React Router Hook Injection - Capture routes dynamically
            // ================================================================
            let router_hook = r#"
                (function() {
                    const routes = [];

                    // Vue Router hook
                    if (window.$router || window.app?.$router || window.__VUE_APP__?.$router) {
                        try {
                            const router = window.$router || window.app?.$router || window.__VUE_APP__?.$router;
                            if (router && router.options && router.options.routes) {
                                router.options.routes.forEach(function extractRoute(route) {
                                    if (route.path) {
                                        routes.push({
                                            path: route.path,
                                            requireAuth: route.meta?.requireAuth || route.meta?.requireLogin || false,
                                            roles: route.meta?.requireAnyRole || route.meta?.roles || [],
                                            framework: 'vue'
                                        });
                                    }
                                    if (route.children) {
                                        route.children.forEach(extractRoute);
                                    }
                                });
                            }
                        } catch(e) {}
                    }

                    // React Router hook (react-router-dom v6)
                    if (window.__REACT_ROUTER_ROUTES__ || window.__remixRouteModules) {
                        try {
                            const reactRoutes = window.__REACT_ROUTER_ROUTES__ || [];
                            reactRoutes.forEach(function extractReactRoute(route) {
                                if (route.path) {
                                    routes.push({
                                        path: route.path,
                                        requireAuth: route.protected || route.requireAuth || false,
                                        roles: route.roles || [],
                                        framework: 'react'
                                    });
                                }
                                if (route.children) {
                                    route.children.forEach(extractReactRoute);
                                }
                            });
                        } catch(e) {}
                    }

                    // Angular Router hook
                    if (window.ng && window.getAllAngularRootElements) {
                        try {
                            const root = window.getAllAngularRootElements()[0];
                            if (root) {
                                const injector = root.injector || root.__ngContext__?.injector;
                                // Angular routing info is harder to access but try common patterns
                            }
                        } catch(e) {}
                    }

                    return JSON.stringify(routes);
                })()
            "#;

            if let Ok(router_result) = tab.evaluate(router_hook, true) {
                if let Some(json_str) = router_result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(dynamic_routes) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                        for route_obj in dynamic_routes {
                            let path = route_obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            if !path.is_empty() && Self::is_valid_route_path(path) {
                                let framework_str = route_obj.get("framework").and_then(|v| v.as_str()).unwrap_or("unknown");
                                let framework = match framework_str {
                                    "vue" => SpaFramework::Vue,
                                    "react" => SpaFramework::React,
                                    "angular" => SpaFramework::Angular,
                                    _ => SpaFramework::Unknown,
                                };

                                let requires_auth = route_obj.get("requireAuth").and_then(|v| v.as_bool()).unwrap_or(false);

                                let roles: Vec<String> = route_obj.get("roles")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                    .unwrap_or_default();

                                // Only add if not already present
                                if !results.spa_routes.iter().any(|r| r.path == path) {
                                    info!("[Headless] Dynamic route discovered: {} (framework: {:?})", path, framework);
                                    results.spa_routes.push(SpaRoute {
                                        path: path.to_string(),
                                        requires_auth,
                                        required_roles: roles,
                                        framework,
                                        source_file: "runtime".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Extract GraphQL operations from window/global scope
            let gql_extract = r#"
                (function() {
                    const operations = [];

                    // Check for Apollo Client queries in cache
                    if (window.__APOLLO_CLIENT__) {
                        try {
                            const cache = window.__APOLLO_CLIENT__.cache;
                            if (cache && cache.data && cache.data.data) {
                                Object.keys(cache.data.data).forEach(key => {
                                    if (key.includes('Query') || key.includes('Mutation')) {
                                        operations.push({
                                            type: key.includes('Mutation') ? 'mutation' : 'query',
                                            name: key,
                                            raw: key
                                        });
                                    }
                                });
                            }
                        } catch(e) {}
                    }

                    // Check for Vue Apollo
                    if (window.__VUE_APOLLO_CLIENT__) {
                        operations.push({ type: 'endpoint', name: 'Vue Apollo Client detected', raw: '' });
                    }

                    // Search for GraphQL strings in all script content (inline scripts)
                    document.querySelectorAll('script:not([src])').forEach(script => {
                        const content = script.textContent || '';

                        // Find query/mutation definitions
                        const patterns = [
                            /(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]/g,
                            /gql`([^`]+)`/g
                        ];

                        patterns.forEach(pattern => {
                            let match;
                            while ((match = pattern.exec(content)) !== null) {
                                const name = match[1] || 'anonymous';
                                const type = match[0].startsWith('mutation') ? 'mutation' :
                                            match[0].startsWith('subscription') ? 'subscription' : 'query';
                                operations.push({
                                    type: type,
                                    name: name.substring(0, 50),
                                    raw: match[0].substring(0, 200)
                                });
                            }
                        });
                    });

                    // Check for GraphQL endpoint in page variables
                    const pageContent = document.documentElement.innerHTML;
                    const gqlEndpointMatch = pageContent.match(/["'](https?:\/\/[^"']+\/graphql[^"']*)/);
                    if (gqlEndpointMatch) {
                        operations.push({
                            type: 'endpoint',
                            name: gqlEndpointMatch[1],
                            raw: gqlEndpointMatch[1]
                        });
                    }

                    return JSON.stringify(operations);
                })()
            "#;

            if let Ok(result) = tab.evaluate(gql_extract, true) {
                if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                    if let Ok(ops) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                        for op in ops {
                            let op_type = op.get("type").and_then(|v| v.as_str()).unwrap_or("query");
                            let name = op.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let raw = op.get("raw").and_then(|v| v.as_str()).unwrap_or("");

                            if op_type == "endpoint" && !name.is_empty() {
                                if !results.graphql_endpoints.contains(&name.to_string()) {
                                    results.graphql_endpoints.push(name.to_string());
                                }
                            } else if !name.is_empty() {
                                results.graphql_operations.push(GraphQLOperation {
                                    operation_type: op_type.to_string(),
                                    name: name.to_string(),
                                    raw: raw.to_string(),
                                    source: start_url.to_string(),
                                });
                            }
                        }

                        if !results.graphql_operations.is_empty() {
                            info!("[Headless] Discovered {} GraphQL operations", results.graphql_operations.len());
                        }
                        if !results.graphql_endpoints.is_empty() {
                            info!("[Headless] Discovered {} GraphQL endpoints", results.graphql_endpoints.len());
                        }
                    }
                }
            }
        }

        // Store remaining links for reference
        results.links_found = to_visit.into_iter().collect();

        Ok(results)
    }

    /// Detect login forms on a page
    /// Returns detected login forms with selectors for auto-fill
    pub async fn detect_login_forms(&self, url: &str) -> Result<Vec<DetectedLoginForm>> {
        info!("[Headless] Detecting login forms on: {}", url);

        let url_owned = url.to_string();
        let timeout = self.timeout;

        let result = tokio::task::spawn_blocking(move || {
            Self::detect_login_forms_sync(&url_owned, timeout)
        })
        .await
        .context("Login form detection task panicked")??;

        if !result.is_empty() {
            info!("[Headless] Detected {} login form(s)", result.len());
        }

        Ok(result)
    }

    /// Synchronous login form detection
    fn detect_login_forms_sync(url: &str, timeout: Duration) -> Result<Vec<DetectedLoginForm>> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch browser")?;

        let tab = browser.new_tab().context("Failed to create tab")?;
        tab.navigate_to(url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;

        // Wait for JS to render
        std::thread::sleep(Duration::from_millis(1500));

        // JavaScript to detect login forms
        let detect_script = r#"
            (function() {
                const forms = [];

                // Common login form patterns
                const usernameSelectors = [
                    'input[type="email"]',
                    'input[name*="email" i]',
                    'input[name*="username" i]',
                    'input[name*="login" i]',
                    'input[name*="user" i]',
                    'input[id*="email" i]',
                    'input[id*="username" i]',
                    'input[id*="login" i]',
                    'input[placeholder*="email" i]',
                    'input[placeholder*="username" i]',
                    'input[autocomplete="email"]',
                    'input[autocomplete="username"]',
                ];

                const passwordSelectors = [
                    'input[type="password"]',
                    'input[name*="password" i]',
                    'input[name*="passwd" i]',
                    'input[id*="password" i]',
                    'input[autocomplete="current-password"]',
                    'input[autocomplete="new-password"]',
                ];

                const submitSelectors = [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:contains("Login")',
                    'button:contains("Sign in")',
                    'button:contains("Log in")',
                    '[class*="login" i][class*="btn" i]',
                    '[class*="signin" i][class*="btn" i]',
                    'button[class*="submit" i]',
                ];

                // OAuth provider patterns
                const oauthPatterns = {
                    'Google': [/accounts\.google\.com/, /oauth.*google/i, /google.*oauth/i, /Sign in with Google/i],
                    'GitHub': [/github\.com.*oauth/, /oauth.*github/i, /Sign in with GitHub/i],
                    'Microsoft': [/login\.microsoftonline\.com/, /oauth.*microsoft/i, /Sign in with Microsoft/i],
                    'Okta': [/okta\.com/, /\/oauth2\//, /Sign in with Okta/i],
                    'Auth0': [/auth0\.com/, /\/authorize\?/],
                    'Facebook': [/facebook\.com.*oauth/, /Sign in with Facebook/i],
                    'Apple': [/appleid\.apple\.com/, /Sign in with Apple/i],
                    'AWS Cognito': [/cognito.*amazonaws\.com/, /amazoncognito/i],
                };

                // Find password fields first (most reliable indicator of login form)
                document.querySelectorAll(passwordSelectors.join(', ')).forEach(passwordField => {
                    // Find the form or container
                    let container = passwordField.closest('form') || passwordField.closest('[class*="login" i]') ||
                                   passwordField.closest('[class*="signin" i]') || passwordField.closest('[class*="auth" i]');

                    if (!container) {
                        // No form, look for nearby username field
                        container = passwordField.parentElement?.parentElement?.parentElement;
                    }

                    if (!container) return;

                    // Find username field in same container
                    let usernameField = null;
                    for (const sel of usernameSelectors) {
                        usernameField = container.querySelector(sel);
                        if (usernameField && usernameField !== passwordField) break;
                    }

                    // Fall back to any visible text input before password
                    if (!usernameField) {
                        const allInputs = container.querySelectorAll('input[type="text"], input[type="email"], input:not([type])');
                        for (const inp of allInputs) {
                            if (inp.offsetParent !== null && inp !== passwordField) {
                                usernameField = inp;
                                break;
                            }
                        }
                    }

                    if (!usernameField) return;

                    // Find submit button
                    let submitButton = null;
                    for (const sel of submitSelectors) {
                        try {
                            submitButton = container.querySelector(sel);
                            if (submitButton) break;
                        } catch (e) {}
                    }

                    // Check for OAuth buttons/links
                    let isOAuth = false;
                    let oauthProvider = null;
                    const containerHtml = container.innerHTML.toLowerCase();
                    const links = container.querySelectorAll('a[href]');

                    for (const [provider, patterns] of Object.entries(oauthPatterns)) {
                        for (const pattern of patterns) {
                            if (pattern.test(containerHtml)) {
                                isOAuth = true;
                                oauthProvider = provider;
                                break;
                            }
                            for (const link of links) {
                                if (pattern.test(link.href)) {
                                    isOAuth = true;
                                    oauthProvider = provider;
                                    break;
                                }
                            }
                            if (isOAuth) break;
                        }
                        if (isOAuth) break;
                    }

                    // Generate unique selector for username field
                    const usernameSelector = usernameField.id ? '#' + CSS.escape(usernameField.id) :
                                            usernameField.name ? `input[name="${CSS.escape(usernameField.name)}"]` :
                                            generateSelector(usernameField);

                    // Generate unique selector for password field
                    const passwordSelector = passwordField.id ? '#' + CSS.escape(passwordField.id) :
                                            passwordField.name ? `input[name="${CSS.escape(passwordField.name)}"]` :
                                            'input[type="password"]';

                    // Generate submit selector
                    let submitSelector = null;
                    if (submitButton) {
                        submitSelector = submitButton.id ? '#' + CSS.escape(submitButton.id) :
                                        submitButton.type === 'submit' ? '[type="submit"]' :
                                        generateSelector(submitButton);
                    }

                    // Calculate confidence
                    let confidence = 0.5;
                    if (container.tagName === 'FORM') confidence += 0.2;
                    if (usernameField.type === 'email' || usernameField.name?.includes('email')) confidence += 0.1;
                    if (submitButton) confidence += 0.1;
                    if (containerHtml.includes('login') || containerHtml.includes('sign in')) confidence += 0.1;

                    forms.push({
                        url: window.location.href,
                        action: container.tagName === 'FORM' ? (container.action || window.location.href) : window.location.href,
                        method: container.tagName === 'FORM' ? (container.method || 'POST').toUpperCase() : 'POST',
                        usernameSelector: usernameSelector,
                        passwordSelector: passwordSelector,
                        submitSelector: submitSelector,
                        isOAuth: isOAuth,
                        oauthProvider: oauthProvider,
                        confidence: Math.min(confidence, 1.0)
                    });
                });

                // Helper to generate CSS selector
                function generateSelector(el) {
                    if (el.id) return '#' + CSS.escape(el.id);
                    const path = [];
                    while (el && el.nodeType === 1) {
                        let selector = el.tagName.toLowerCase();
                        if (el.className) {
                            selector += '.' + el.className.split(/\s+/).filter(c => c).map(c => CSS.escape(c)).join('.');
                        }
                        path.unshift(selector);
                        el = el.parentElement;
                        if (path.length > 3) break;
                    }
                    return path.join(' > ');
                }

                return JSON.stringify(forms);
            })()
        "#;

        let mut detected_forms = Vec::new();

        if let Ok(result) = tab.evaluate(detect_script, true) {
            if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                if let Ok(forms) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                    for form in forms {
                        let login_form = DetectedLoginForm {
                            url: form.get("url").and_then(|v| v.as_str()).unwrap_or(url).to_string(),
                            action: form.get("action").and_then(|v| v.as_str()).unwrap_or(url).to_string(),
                            method: form.get("method").and_then(|v| v.as_str()).unwrap_or("POST").to_string(),
                            username_selector: form.get("usernameSelector").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            password_selector: form.get("passwordSelector").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            submit_selector: form.get("submitSelector").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            is_oauth: form.get("isOAuth").and_then(|v| v.as_bool()).unwrap_or(false),
                            oauth_provider: form.get("oauthProvider").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            confidence: form.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5) as f32,
                        };

                        if !login_form.username_selector.is_empty() && !login_form.password_selector.is_empty() {
                            debug!("[Headless] Found login form: username={}, password={}, confidence={}",
                                login_form.username_selector, login_form.password_selector, login_form.confidence);
                            detected_forms.push(login_form);
                        }
                    }
                }
            }
        }

        Ok(detected_forms)
    }

    /// Attempt to login using detected form and provided credentials
    /// Returns the auth token if login is successful
    pub async fn attempt_login(
        &self,
        login_form: &DetectedLoginForm,
        credentials: &LoginCredentials,
    ) -> Result<LoginResult> {
        info!("[Headless] Attempting login at: {}", login_form.url);

        let form = login_form.clone();
        let creds = credentials.clone();
        let timeout = self.timeout;

        let result = tokio::task::spawn_blocking(move || {
            Self::attempt_login_sync(&form, &creds, timeout)
        })
        .await
        .context("Login attempt task panicked")??;

        if result.success {
            info!("[Headless] Login successful! Token extracted: {}", result.token.is_some());
        } else {
            warn!("[Headless] Login failed: {:?}", result.error);
        }

        Ok(result)
    }

    /// Synchronous login attempt
    fn attempt_login_sync(
        form: &DetectedLoginForm,
        credentials: &LoginCredentials,
        timeout: Duration,
    ) -> Result<LoginResult> {
        let browser = Browser::new(
            LaunchOptions::default_builder()
                .headless(true)
                .idle_browser_timeout(timeout)
                .build()
                .map_err(|e| anyhow::anyhow!("Browser launch error: {}", e))?
        )
        .context("Failed to launch browser")?;

        let tab = browser.new_tab().context("Failed to create tab")?;
        tab.navigate_to(&form.url).context("Failed to navigate")?;
        tab.wait_until_navigated().context("Navigation timeout")?;

        // Wait for form to render
        std::thread::sleep(Duration::from_millis(1500));

        // Fill in username
        let fill_username = format!(
            r#"
            (function() {{
                const field = document.querySelector('{}');
                if (!field) return 'Username field not found';
                field.value = '{}';
                field.dispatchEvent(new Event('input', {{ bubbles: true }}));
                field.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return 'ok';
            }})()
            "#,
            form.username_selector.replace('\'', "\\'"),
            credentials.username.replace('\'', "\\'")
        );

        if let Ok(result) = tab.evaluate(&fill_username, true) {
            if let Some(s) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                if s != "ok" {
                    return Ok(LoginResult {
                        success: false,
                        token: None,
                        cookies: HashMap::new(),
                        redirect_url: None,
                        error: Some(s),
                    });
                }
            }
        }

        // Fill in password
        let fill_password = format!(
            r#"
            (function() {{
                const field = document.querySelector('{}');
                if (!field) return 'Password field not found';
                field.value = '{}';
                field.dispatchEvent(new Event('input', {{ bubbles: true }}));
                field.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return 'ok';
            }})()
            "#,
            form.password_selector.replace('\'', "\\'"),
            credentials.password.replace('\'', "\\'")
        );

        if let Ok(result) = tab.evaluate(&fill_password, true) {
            if let Some(s) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                if s != "ok" {
                    return Ok(LoginResult {
                        success: false,
                        token: None,
                        cookies: HashMap::new(),
                        redirect_url: None,
                        error: Some(s),
                    });
                }
            }
        }

        // Small delay to let any JS validation run
        std::thread::sleep(Duration::from_millis(300));

        // Submit the form
        let submit_script = if let Some(ref submit_sel) = form.submit_selector {
            format!(
                r#"
                (function() {{
                    const btn = document.querySelector('{}');
                    if (btn) {{
                        btn.click();
                        return 'clicked';
                    }}
                    // Fallback: submit form directly
                    const form = document.querySelector('form');
                    if (form) {{
                        form.submit();
                        return 'submitted';
                    }}
                    return 'no_submit';
                }})()
                "#,
                submit_sel.replace('\'', "\\'")
            )
        } else {
            r#"
            (function() {
                // Try Enter key on password field
                const pwd = document.querySelector('input[type="password"]');
                if (pwd) {
                    pwd.dispatchEvent(new KeyboardEvent('keypress', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
                    return 'enter';
                }
                // Fallback: submit form
                const form = document.querySelector('form');
                if (form) {
                    form.submit();
                    return 'submitted';
                }
                return 'no_submit';
            })()
            "#.to_string()
        };

        let _ = tab.evaluate(&submit_script, true);

        // Wait for login to complete (navigation or AJAX)
        std::thread::sleep(Duration::from_millis(3000));

        // Check if we navigated somewhere new (success indicator)
        let current_url = tab.get_url();
        let redirected = current_url != form.url;

        // Try to extract auth token from localStorage/sessionStorage
        let extract_token = r#"
            (function() {
                const tokens = {};

                // Check localStorage
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    const value = localStorage.getItem(key);
                    if (key.toLowerCase().includes('token') ||
                        key.toLowerCase().includes('jwt') ||
                        key.toLowerCase().includes('auth') ||
                        key.toLowerCase().includes('access')) {
                        tokens[key] = value;
                    }
                }

                // Check sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    const value = sessionStorage.getItem(key);
                    if (key.toLowerCase().includes('token') ||
                        key.toLowerCase().includes('jwt') ||
                        key.toLowerCase().includes('auth') ||
                        key.toLowerCase().includes('access')) {
                        tokens['session_' + key] = value;
                    }
                }

                return JSON.stringify(tokens);
            })()
        "#;

        let mut extracted_token: Option<String> = None;
        if let Ok(result) = tab.evaluate(extract_token, true) {
            if let Some(json_str) = result.value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                if let Ok(tokens) = serde_json::from_str::<HashMap<String, String>>(&json_str) {
                    // Get the first token found
                    for (key, value) in tokens {
                        if !value.is_empty() && value.len() > 10 {
                            debug!("[Headless] Found token in {}: {}...", key, &value[..value.len().min(20)]);
                            extracted_token = Some(value);
                            break;
                        }
                    }
                }
            }
        }

        // Get cookies
        let mut cookies = HashMap::new();
        if let Ok(cookie_list) = tab.get_cookies() {
            for cookie in cookie_list {
                cookies.insert(cookie.name, cookie.value);
            }
        }

        // Determine success
        let success = extracted_token.is_some() || redirected || !cookies.is_empty();

        Ok(LoginResult {
            success,
            token: extracted_token,
            cookies,
            redirect_url: if redirected { Some(current_url) } else { None },
            error: if !success { Some("Login may have failed - no token or redirect detected".to_string()) } else { None },
        })
    }

    /// Discover login pages by crawling common paths
    pub async fn discover_login_pages(&self, base_url: &str) -> Result<Vec<String>> {
        let common_login_paths = vec![
            "/login",
            "/signin",
            "/sign-in",
            "/auth/login",
            "/auth/signin",
            "/user/login",
            "/account/login",
            "/admin/login",
            "/admin",
            "/portal",
            "/sso",
            "/oauth",
        ];

        let base = base_url.trim_end_matches('/');
        let mut login_pages = Vec::new();

        for path in common_login_paths {
            let url = format!("{}{}", base, path);
            if let Ok(forms) = self.detect_login_forms(&url).await {
                if !forms.is_empty() {
                    login_pages.push(url);
                }
            }
        }

        Ok(login_pages)
    }

    // ============================================================================
    // SPA Route Extraction - Extract routes from Vue/React/Angular JS bundles
    // ============================================================================

    /// Extract SPA routes from JavaScript content
    /// Supports Vue Router, React Router, Angular Router, Next.js, Nuxt
    pub fn extract_spa_routes_from_js(js_content: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Extract Vue Router routes
        routes.extend(Self::extract_vue_routes(js_content, source_file));

        // Extract React Router routes
        routes.extend(Self::extract_react_routes(js_content, source_file));

        // Extract Angular routes
        routes.extend(Self::extract_angular_routes(js_content, source_file));

        // Extract Next.js/Nuxt routes from patterns
        routes.extend(Self::extract_nextjs_routes(js_content, source_file));

        // Extract generic path patterns as fallback
        routes.extend(Self::extract_generic_routes(js_content, source_file));

        // Deduplicate by path
        let mut seen = std::collections::HashSet::new();
        routes.retain(|r| seen.insert(r.path.clone()));

        routes
    }

    /// Extract Vue Router routes from JS bundle
    fn extract_vue_routes(js_code: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Pattern 1: {path: "/admin", meta: {requireAuth: true}}
        for cap in VUE_AUTH_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    routes.push(SpaRoute {
                        path: path_str.to_string(),
                        requires_auth: true,
                        required_roles: Vec::new(),
                        framework: SpaFramework::Vue,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        // Pattern 2: {path: "/admin", meta: {requireAnyRole: ["ADMIN", "MANAGER"]}}
        for cap in VUE_ROLE_REGEX.captures_iter(js_code) {
            if let (Some(path), Some(roles_str)) = (cap.get(1), cap.get(2)) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    let roles: Vec<String> = roles_str
                        .as_str()
                        .split(',')
                        .map(|r| r.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                        .filter(|r| !r.is_empty())
                        .collect();

                    // Check if already added
                    if !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                        routes.push(SpaRoute {
                            path: path_str.to_string(),
                            requires_auth: true,
                            required_roles: roles,
                            framework: SpaFramework::Vue,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        // Pattern 3: Simple path extraction from routes array
        for cap in VUE_PATH_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();

                // Skip if already found with metadata
                if routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                    continue;
                }

                if Self::is_valid_route_path(path_str) {
                    // Infer auth requirement from path name
                    let requires_auth = Self::infer_auth_from_path(path_str);

                    routes.push(SpaRoute {
                        path: path_str.to_string(),
                        requires_auth,
                        required_roles: Vec::new(),
                        framework: SpaFramework::Vue,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        routes
    }

    /// Extract React Router routes from JS bundle
    fn extract_react_routes(js_code: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Pattern 1: <Route path="/admin" requireAuth />
        for cap in REACT_ROUTE_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    routes.push(SpaRoute {
                        path: path_str.to_string(),
                        requires_auth: true,
                        required_roles: Vec::new(),
                        framework: SpaFramework::React,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        // Pattern 2: {path: "/admin", element: <Admin />, protected: true}
        for cap in REACT_PROTECTED_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    if !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                        routes.push(SpaRoute {
                            path: path_str.to_string(),
                            requires_auth: true,
                            required_roles: Vec::new(),
                            framework: SpaFramework::React,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        // Pattern 3: createBrowserRouter routes array
        for cap in REACT_BROWSER_ROUTER_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    if !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                        routes.push(SpaRoute {
                            path: path_str.to_string(),
                            requires_auth: Self::infer_auth_from_path(path_str),
                            required_roles: Vec::new(),
                            framework: SpaFramework::React,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        routes
    }

    /// Extract Angular Router routes from JS bundle
    fn extract_angular_routes(js_code: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Pattern: {path: 'admin', canActivate: [AuthGuard]}
        for cap in ANGULAR_GUARD_REGEX.captures_iter(js_code) {
            if let (Some(path), Some(guards)) = (cap.get(1), cap.get(2)) {
                let has_auth_guard = guards.as_str().contains("Auth")
                    || guards.as_str().contains("Guard")
                    || guards.as_str().contains("Login");

                if has_auth_guard {
                    let path_str = format!("/{}", path.as_str().trim_start_matches('/'));
                    if Self::is_valid_route_path(&path_str) {
                        routes.push(SpaRoute {
                            path: path_str,
                            requires_auth: true,
                            required_roles: Vec::new(),
                            framework: SpaFramework::Angular,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        // Pattern: RouterModule.forRoot/forChild routes
        for cap in ANGULAR_ROUTER_MODULE_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = format!("/{}", path.as_str().trim_start_matches('/'));
                if Self::is_valid_route_path(&path_str) && !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                    routes.push(SpaRoute {
                        path: path_str.clone(),
                        requires_auth: Self::infer_auth_from_path(&path_str),
                        required_roles: Vec::new(),
                        framework: SpaFramework::Angular,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        routes
    }

    /// Extract Next.js/Nuxt routes from patterns
    fn extract_nextjs_routes(js_code: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Next.js: Look for pages array or route definitions
        for cap in NEXTJS_PAGES_REGEX.captures_iter(js_code) {
            if let Some(path) = cap.get(1) {
                let path_str = path.as_str();
                if path_str.starts_with('/') && Self::is_valid_route_path(path_str) {
                    routes.push(SpaRoute {
                        path: path_str.to_string(),
                        requires_auth: Self::infer_auth_from_path(path_str),
                        required_roles: Vec::new(),
                        framework: SpaFramework::NextJS,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        // Nuxt: Look for __NUXT__ or nuxtjs patterns
        if js_code.contains("__NUXT__") || js_code.contains("nuxt") {
            for cap in NUXT_PATH_REGEX.captures_iter(js_code) {
                if let Some(path) = cap.get(1) {
                    let path_str = path.as_str();
                    if Self::is_valid_route_path(path_str) && !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                        routes.push(SpaRoute {
                            path: path_str.to_string(),
                            requires_auth: Self::infer_auth_from_path(path_str),
                            required_roles: Vec::new(),
                            framework: SpaFramework::Nuxt,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        routes
    }

    /// Extract generic route patterns as fallback
    fn extract_generic_routes(js_code: &str, source_file: &str) -> Vec<SpaRoute> {
        let mut routes = Vec::new();

        // Use pre-compiled lazy regexes for generic patterns
        let regexes: Vec<&regex::Regex> = vec![
            &*GENERIC_NAVIGATE_REGEX,
            &*GENERIC_PUSH_REGEX,
            &*GENERIC_TO_REGEX,
            &*GENERIC_HREF_REGEX,
            &*GENERIC_REDIRECT_REGEX,
        ];

        for re in regexes {
            for cap in re.captures_iter(js_code) {
                if let Some(path) = cap.get(1) {
                    let path_str = path.as_str();
                    if Self::is_valid_route_path(path_str) && !routes.iter().any(|r: &SpaRoute| r.path == path_str) {
                        routes.push(SpaRoute {
                            path: path_str.to_string(),
                            requires_auth: Self::infer_auth_from_path(path_str),
                            required_roles: Vec::new(),
                            framework: SpaFramework::Unknown,
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        routes
    }

    /// Check if path looks like a valid route (not a file path or URL fragment)
    fn is_valid_route_path(path: &str) -> bool {
        // Must start with /
        if !path.starts_with('/') {
            return false;
        }

        // Skip file extensions (static assets)
        let static_extensions = [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".map"];
        if static_extensions.iter().any(|ext| path.ends_with(ext)) {
            return false;
        }

        // Skip language/locale only paths (e.g., /en, /fi, /de) using pre-compiled regex
        if path.len() <= 4 {
            if LOCALE_PATH_REGEX.is_match(path) {
                return false;
            }
        }

        // Skip API/GraphQL paths (those are already captured separately)
        if path.contains("/api/") || path.contains("/graphql") {
            return false;
        }

        // Must be reasonable length
        path.len() >= 2 && path.len() <= 100
    }

    /// Infer auth requirement from path name
    fn infer_auth_from_path(path: &str) -> bool {
        let protected_patterns = [
            "/admin", "/dashboard", "/account", "/profile", "/settings",
            "/user", "/users", "/my-", "/private", "/internal",
            "/manage", "/management", "/config", "/configuration",
            "/panel", "/portal", "/console", "/workspace",
            "/billing", "/subscription", "/payment", "/orders",
            "/reports", "/analytics", "/metrics", "/stats",
        ];

        let path_lower = path.to_lowercase();
        protected_patterns.iter().any(|p| path_lower.contains(p))
    }

    /// Convert route path with parameters to a testable URL
    /// e.g., /user/:id -> /user/1
    pub fn route_to_test_url(base_url: &str, route_path: &str) -> String {
        let base = base_url.trim_end_matches('/');

        // Replace common parameter patterns with test values
        let test_path = route_path
            .replace(":id", "1")
            .replace(":userId", "1")
            .replace(":companyId", "1")
            .replace(":orderId", "1")
            .replace(":workerId", "1")
            .replace(":slug", "test")
            .replace(":uuid", "00000000-0000-0000-0000-000000000001")
            // Handle [param] Next.js style
            .replace("[id]", "1")
            .replace("[slug]", "test")
            // Handle {param} style
            .replace("{id}", "1")
            .replace("{userId}", "1");

        format!("{}{}", base, test_path)
    }
}

// ============================================================================
// Headless Crawler Trigger Logic - decides when to use headless vs static crawl
// ============================================================================

use crate::crawler::CrawlResults;

/// Enhanced trigger logic to decide when to use headless browser crawling
/// Returns true if the static crawl results suggest the site needs JavaScript rendering
pub fn should_use_headless(
    static_results: &CrawlResults,
    detected_frameworks: &std::collections::HashSet<String>,
    html_content: Option<&str>,
) -> bool {
    let mut score = 0;

    // SPA with no forms = definitely needs JS
    if static_results.is_spa && static_results.forms.is_empty() {
        info!("[HeadlessCrawler] Trigger: SPA detected with no forms (+50)");
        score += 50;
    }

    // Heavy JS but couldn't crawl anything
    if static_results.crawled_urls.len() <= 1 && static_results.scripts.len() > 3 {
        info!("[HeadlessCrawler] Trigger: Heavy JS, minimal crawl results (+40)");
        score += 40;
    }

    // Known SPA frameworks
    let spa_frameworks = [
        "react",
        "vue",
        "angular",
        "svelte",
        "next.js",
        "nuxt",
        "sveltekit",
        "gatsby",
        "remix",
    ];
    let has_spa_framework = spa_frameworks.iter().any(|f| {
        detected_frameworks
            .iter()
            .any(|d| d.to_lowercase().contains(f))
    });

    if has_spa_framework {
        info!("[HeadlessCrawler] Trigger: SPA framework detected (+30)");
        score += 30;
    }

    // Ratio-based: more scripts than content
    let content_count = static_results.forms.len() + static_results.links.len() + 1;
    let script_ratio = static_results.scripts.len() as f32 / content_count as f32;

    if script_ratio > 2.0 {
        info!(
            "[HeadlessCrawler] Trigger: High script-to-content ratio {:.1} (+25)",
            script_ratio
        );
        score += 25;
    }

    // All forms submit to same page = SPA form handling
    if !static_results.forms.is_empty() {
        let first_action = &static_results.forms[0].action;
        let all_same_action = static_results.forms.iter().all(|f| {
            f.action.is_empty() || f.action == *first_action || f.action.starts_with('#')
        });

        if all_same_action {
            info!("[HeadlessCrawler] Trigger: All forms have same/empty action (+20)");
            score += 20;
        }
    }

    // Additional signals from HTML content
    if let Some(html) = html_content {
        let html_lower = html.to_lowercase();

        // WebSocket usage (real-time apps are always SPAs)
        if html_lower.contains("websocket") || html_lower.contains("socket.io") {
            info!("[HeadlessCrawler] Trigger: WebSocket detected (+30)");
            score += 30;
        }

        // Service worker registration
        if html_lower.contains("serviceworker.register") {
            info!("[HeadlessCrawler] Trigger: Service worker detected (+25)");
            score += 25;
        }

        // GraphQL endpoint hints
        if html_lower.contains("/graphql") || html_lower.contains("__schema") {
            info!("[HeadlessCrawler] Trigger: GraphQL detected (+20)");
            score += 20;
        }

        // Lazy loading patterns
        if html_lower.contains("data-src=") || html_lower.contains("loading=\"lazy\"") {
            info!("[HeadlessCrawler] Trigger: Lazy loading detected (+10)");
            score += 10;
        }

        // Next.js/Nuxt hydration data
        if html_lower.contains("__next_data__") || html_lower.contains("__nuxt__") {
            info!("[HeadlessCrawler] Trigger: SSR hydration data detected (+35)");
            score += 35;
        }

        // Hash-based routing (common in SPAs)
        if html_lower.contains("hashchange") || html_lower.contains("/#/") {
            info!("[HeadlessCrawler] Trigger: Hash routing detected (+25)");
            score += 25;
        }

        // Angular-specific patterns
        if html_lower.contains("ng-app") || html_lower.contains("ng-controller") || html_lower.contains("[ngif]") {
            info!("[HeadlessCrawler] Trigger: Angular patterns detected (+30)");
            score += 30;
        }

        // Vue-specific patterns
        if html_lower.contains("v-if") || html_lower.contains("v-for") || html_lower.contains("v-model") {
            info!("[HeadlessCrawler] Trigger: Vue patterns detected (+30)");
            score += 30;
        }

        // React-specific patterns (often minified but sometimes visible)
        if html_lower.contains("data-reactroot") || html_lower.contains("__react") {
            info!("[HeadlessCrawler] Trigger: React patterns detected (+30)");
            score += 30;
        }

        // Bundler patterns (webpack, vite, parcel)
        if html_lower.contains("chunk-") || html_lower.contains(".chunk.js") || html_lower.contains("bundle.js") {
            info!("[HeadlessCrawler] Trigger: JS bundler detected (+15)");
            score += 15;
        }
    }

    let trigger = score >= 40;
    if trigger {
        info!(
            "[HeadlessCrawler] Headless crawl TRIGGERED with score {} (threshold: 40)",
            score
        );
    } else {
        debug!(
            "[HeadlessCrawler] Headless crawl NOT needed (score {} < 40)",
            score
        );
    }

    trigger
}

/// Convert SiteCrawlResults to CrawlResults for integration with main scanner
impl SiteCrawlResults {
    /// Merge headless crawl results into existing CrawlResults
    pub fn merge_into(&self, target: &mut CrawlResults) {
        // Add discovered forms
        target.forms.extend(self.forms.clone());

        // Add visited pages as crawled URLs
        for page in &self.pages_visited {
            target.crawled_urls.insert(page.clone());
        }

        // Add discovered links
        for link in &self.links_found {
            target.links.insert(link.clone());
        }

        // Add API endpoints
        for endpoint in &self.api_endpoints {
            target.api_endpoints.insert(endpoint.url.clone());
        }

        // Add GraphQL endpoints to API endpoints
        for gql_endpoint in &self.graphql_endpoints {
            target.api_endpoints.insert(gql_endpoint.clone());
        }

        // Add WebSocket endpoints
        for ws_endpoint in &self.websocket_endpoints {
            target.websocket_endpoints.insert(ws_endpoint.clone());
        }

        // Add SPA routes as crawlable URLs
        // Extract base URL from visited pages to construct full URLs
        let base_url = self.pages_visited.first()
            .and_then(|url| url::Url::parse(url).ok())
            .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")))
            .unwrap_or_default();

        if !base_url.is_empty() {
            for spa_route in &self.spa_routes {
                let full_url = HeadlessCrawler::route_to_test_url(&base_url, &spa_route.path);
                target.links.insert(full_url.clone());
                // Also add to crawled_urls if it looks testable (no dynamic params)
                if !spa_route.path.contains(':') && !spa_route.path.contains('[') {
                    target.crawled_urls.insert(full_url);
                }
            }

            if !self.spa_routes.is_empty() {
                info!("[HeadlessCrawler] Added {} SPA routes to crawl targets", self.spa_routes.len());
            }
        }

        // Deduplicate forms after merge
        target.deduplicate_forms();

        info!(
            "[HeadlessCrawler] Merged {} pages, {} forms, {} API endpoints, {} WebSocket endpoints, {} SPA routes into CrawlResults",
            self.pages_visited.len(),
            self.forms.len(),
            self.api_endpoints.len() + self.graphql_endpoints.len(),
            self.websocket_endpoints.len(),
            self.spa_routes.len()
        );
    }

    /// Convert to CrawlResults (for standalone use)
    pub fn to_crawl_results(&self) -> CrawlResults {
        let mut results = CrawlResults::new();
        self.merge_into(&mut results);
        results.is_spa = true; // If we used headless, it's likely an SPA
        results
    }
}

#[cfg(test)]
mod trigger_tests {
    use super::*;

    #[test]
    fn test_should_use_headless_spa_no_forms() {
        let mut results = CrawlResults::new();
        results.is_spa = true;

        assert!(should_use_headless(&results, &std::collections::HashSet::new(), None));
    }

    #[test]
    fn test_should_use_headless_heavy_js() {
        use crate::crawler::DiscoveredScript;

        let mut results = CrawlResults::new();
        results.crawled_urls.insert("https://example.com".to_string());
        results.scripts = vec![
            DiscoveredScript { url: "1.js".to_string(), content: String::new() },
            DiscoveredScript { url: "2.js".to_string(), content: String::new() },
            DiscoveredScript { url: "3.js".to_string(), content: String::new() },
            DiscoveredScript { url: "4.js".to_string(), content: String::new() },
        ];

        assert!(should_use_headless(&results, &std::collections::HashSet::new(), None));
    }

    #[test]
    fn test_should_not_use_headless_static_site() {
        let mut results = CrawlResults::new();
        results.crawled_urls.insert("https://example.com".to_string());
        results.crawled_urls.insert("https://example.com/about".to_string());
        results.links = (0..20).map(|i| format!("https://example.com/page{}", i)).collect();
        results.forms.push(DiscoveredForm {
            action: "/contact".to_string(),
            method: "POST".to_string(),
            inputs: vec![],
            discovered_at: "/".to_string(),
        });

        assert!(!should_use_headless(&results, &std::collections::HashSet::new(), None));
    }

    #[test]
    fn test_websocket_trigger() {
        let results = CrawlResults::new();
        let html = r#"<script>const socket = new WebSocket('wss://example.com')</script>"#;

        assert!(should_use_headless(&results, &std::collections::HashSet::new(), Some(html)));
    }

    #[test]
    fn test_next_data_trigger() {
        let results = CrawlResults::new();
        let html = r#"<script id="__NEXT_DATA__">{"props":{}}</script>"#;

        assert!(should_use_headless(&results, &std::collections::HashSet::new(), Some(html)));
    }
}
