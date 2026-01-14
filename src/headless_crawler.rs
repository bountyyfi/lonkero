// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Headless browser crawler for JavaScript-rendered pages
//! Uses Kalamari (pure Rust) to render SPAs and extract real form elements

use crate::auth_context::AuthSession;
use crate::crawler::{DiscoveredForm, FormInput};
use anyhow::{Context, Result};
use kalamari::{
    Browser, BrowserConfig,
    Crawler, CrawlConfig,
    Form,
    ScriptAnalyzer, ScriptSource,
    SpaFramework,
};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

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
fn js_escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

// ============================================================================
// Lazy-compiled regex patterns for route extraction
// ============================================================================

// Vue Router route patterns
static VUE_AUTH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"(?:path|name):\s*["']([^"']+)["'][^}]*meta:\s*\{[^}]*require(?:Auth|Login|Authentication):\s*(!0|true)"#
    ).expect("Invalid VUE_AUTH_REGEX pattern")
});

static VUE_ROLE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"path:\s*["']([^"']+)["'][^}]*require(?:Any)?Role[s]?:\s*\[([^\]]+)\]"#)
        .expect("Invalid VUE_ROLE_REGEX pattern")
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
        r#"path:\s*["']([^"']+)["'][^}]*(?:protected|requireAuth|private):\s*(!0|true)"#,
    )
    .expect("Invalid REACT_PROTECTED_REGEX pattern")
});

// Angular Router patterns
static ANGULAR_GUARD_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"path:\s*["']([^"']+)["'][^}]*canActivate:\s*\[([^\]]+)\]"#)
        .expect("Invalid ANGULAR_GUARD_REGEX pattern")
});

// Generic route patterns
static GENERIC_NAVIGATE_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"navigate\s*\(\s*["']([/][a-zA-Z0-9_\-/]+)["']"#)
        .expect("Invalid GENERIC_NAVIGATE_REGEX pattern")
});

static GENERIC_PUSH_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"(?:push|replace)\s*\(\s*["']([/][a-zA-Z0-9_\-/]+)["']"#)
        .expect("Invalid GENERIC_PUSH_REGEX pattern")
});

// Route validation regex
static LOCALE_PATH_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"^/[a-z]{2}$").expect("Invalid LOCALE_PATH_REGEX pattern"));

/// Maximum number of requests to capture
const MAX_CAPTURED_REQUESTS: usize = 500;

// ============================================================================
// Page State
// ============================================================================

#[derive(Debug, Clone)]
pub struct PageState {
    pub url: String,
    pub html_hash: u64,
}

impl PartialEq for PageState {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.html_hash == other.html_hash
    }
}

impl Eq for PageState {}

impl Hash for PageState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.url.hash(state);
        self.html_hash.hash(state);
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct HeadlessCrawlerConfig {
    pub max_depth: usize,
    pub max_pages: usize,
    pub follow_external: bool,
    pub extract_forms: bool,
    pub extract_spa_routes: bool,
    pub extract_api_endpoints: bool,
    pub enable_auth_detection: bool,
}

impl Default for HeadlessCrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            follow_external: false,
            extract_forms: true,
            extract_spa_routes: true,
            extract_api_endpoints: true,
            enable_auth_detection: true,
        }
    }
}

// ============================================================================
// Session State
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct SessionState {
    pub token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<Instant>,
    pub cookies: HashMap<String, String>,
}

impl SessionState {
    pub fn with_token(token: String) -> Self {
        Self {
            token: Some(token),
            refresh_token: None,
            expires_at: None,
            cookies: HashMap::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() > expires_at
        } else {
            false
        }
    }

    pub fn update_token(&mut self, token: String, expires_in_secs: Option<u64>) {
        self.token = Some(token);
        if let Some(secs) = expires_in_secs {
            // Refresh 60 seconds before actual expiry
            self.expires_at = Some(Instant::now() + Duration::from_secs(secs.saturating_sub(60)));
        }
    }
}

// ============================================================================
// Token Refresh Result
// ============================================================================

#[derive(Debug)]
struct TokenRefreshResult {
    access_token: String,
    expires_in: Option<u64>,
}

// ============================================================================
// Headless Crawler
// ============================================================================

/// Headless browser crawler for SPA form detection
pub struct HeadlessCrawler {
    timeout: Duration,
    /// Optional JWT/Bearer token for authenticated scanning
    auth_token: Option<String>,
    /// Custom HTTP headers to inject into all requests
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

    pub fn with_config(
        timeout_secs: u64,
        token: Option<String>,
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
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(session_state)),
            config,
        }
    }

    pub fn with_session(
        timeout_secs: u64,
        session: SessionState,
        config: HeadlessCrawlerConfig,
    ) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            auth_token: session.token.clone(),
            custom_headers: HashMap::new(),
            session_state: Arc::new(Mutex::new(session)),
            config,
        }
    }

    pub fn with_headers(
        timeout_secs: u64,
        token: Option<String>,
        headers: HashMap<String, String>,
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
            config: HeadlessCrawlerConfig::default(),
        }
    }

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

    pub fn needs_token_refresh(&self) -> bool {
        if let Ok(session) = self.session_state.lock() {
            session.is_expired()
        } else {
            false
        }
    }

    /// Refresh the auth token using refresh_token
    pub async fn refresh_token(&self, refresh_endpoint: &str) -> Result<String> {
        let refresh_token = {
            let session = self
                .session_state
                .lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock session state"))?;
            session
                .refresh_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No refresh token available"))?
        };

        info!("[Session] Attempting token refresh at {}", refresh_endpoint);

        let browser_config = BrowserConfig::default()
            .timeout(self.timeout);

        let browser = Browser::new(browser_config).await
            .context("Failed to launch browser for token refresh")?;

        let page = browser.new_page().await?;

        // Parse base URL from endpoint
        let base_url = url::Url::parse(refresh_endpoint).context("Invalid refresh endpoint")?;
        let origin = format!(
            "{}://{}",
            base_url.scheme(),
            base_url.host_str().unwrap_or("")
        );

        // Navigate to origin first to set up context
        page.navigate(&origin).await?;

        // Perform token refresh via fetch
        let js_refresh = format!(
            r#"
            (async function() {{
                try {{
                    const response = await fetch('{}', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ refresh_token: '{}' }})
                    }});
                    const data = await response.json();
                    return JSON.stringify({{
                        success: true,
                        access_token: data.access_token || data.token,
                        expires_in: data.expires_in
                    }});
                }} catch (e) {{
                    return JSON.stringify({{ success: false, error: e.message }});
                }}
            }})()
            "#,
            refresh_endpoint, refresh_token
        );

        let result = page.evaluate(&js_refresh)?;

        if let Some(json_str) = result.as_string() {
            let parsed: serde_json::Value = serde_json::from_str(json_str)?;
            if parsed.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let access_token = parsed
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("No access token in response"))?
                    .to_string();
                let expires_in = parsed.get("expires_in").and_then(|v| v.as_u64());

                // Update session state
                if let Ok(mut session) = self.session_state.lock() {
                    session.update_token(access_token.clone(), expires_in);
                }

                return Ok(access_token);
            }
        }

        Err(anyhow::anyhow!("Token refresh failed"))
    }

    /// Crawl a site and extract forms, links, and SPA routes
    pub async fn crawl_site(&self, url: &str) -> Result<SiteCrawlResults> {
        info!("[HeadlessCrawler] Starting crawl of {}", url);

        let browser_config = BrowserConfig::default()
            .timeout(self.timeout);

        let browser = Arc::new(Browser::new(browser_config).await
            .context("Failed to launch browser")?);

        // Set up auth if available
        if let Some(ref token) = self.auth_token {
            browser.set_auth_token(token.clone());
        }

        // Set custom headers
        for (key, value) in &self.custom_headers {
            browser.set_custom_auth(key, value);
        }

        // Configure crawler
        let crawl_config = CrawlConfig::new()
            .max_depth(self.config.max_depth as u32)
            .max_pages(self.config.max_pages)
            .same_domain_only(!self.config.follow_external)
            .exclude("logout")
            .exclude("signout")
            .exclude("sign-out");

        let crawler = Crawler::new(browser.clone(), crawl_config);
        let results = crawler.crawl(url).await?;

        // Process results
        let mut site_results = SiteCrawlResults::new(url.to_string());

        for result in results {
            // Collect links
            for link in result.links {
                if site_results.links.len() < MAX_LINKS_FOUND {
                    site_results.links.insert(link);
                }
            }

            // Collect forms
            if self.config.extract_forms {
                for form in &result.forms {
                    // Convert FormInfo inline (type is private)
                    let inputs: Vec<FormInput> = form
                        .fields
                        .iter()
                        .map(|field_name| FormInput {
                            name: field_name.clone(),
                            input_type: "text".to_string(),
                            value: None,
                            options: None,
                            required: false,
                        })
                        .collect();

                    let discovered = DiscoveredForm {
                        action: form.action.clone().unwrap_or_else(|| result.url.clone()),
                        method: form.method.to_uppercase(),
                        inputs,
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    };
                    site_results.forms.push(discovered);
                }
            }
        }

        // Extract SPA routes from scripts
        if self.config.extract_spa_routes {
            let page = browser.new_page().await?;
            page.navigate(url).await?;
            tokio::time::sleep(Duration::from_millis(JS_RENDER_WAIT_MS)).await;

            // Extract scripts from document
            let scripts = self.extract_script_sources(&page);
            let analyzer = ScriptAnalyzer::new();

            for script in &scripts {
                // Find SPA routes
                let routes = analyzer.find_routes(script);
                for route in routes {
                    if site_results.spa_routes.len() < MAX_SPA_ROUTES {
                        site_results.spa_routes.push(SpaRoute {
                            path: route.path,
                            requires_auth: route.requires_auth,
                            roles: Vec::new(), // kalamari SpaRoute doesn't have roles
                            framework: Some(route.framework),
                        });
                    }
                }

                // Find WebSocket endpoints
                let ws_endpoints = analyzer.find_websocket_endpoints(script);
                for endpoint in ws_endpoints {
                    if site_results.websocket_endpoints.len() < MAX_WEBSOCKET_ENDPOINTS {
                        site_results.websocket_endpoints.push(endpoint.url);
                    }
                }

                // Find GraphQL operations
                let graphql_ops = self.extract_graphql_operations(&script.content);
                for op in graphql_ops {
                    if site_results.graphql_operations.len() < MAX_GRAPHQL_OPERATIONS {
                        site_results.graphql_operations.push(op);
                    }
                }

                // Find API endpoints
                if self.config.extract_api_endpoints {
                    let api_endpoints = analyzer.find_api_endpoints(script);
                    for endpoint in api_endpoints {
                        site_results.discovered_endpoints.push(DiscoveredEndpoint {
                            url: endpoint,
                            method: "GET".to_string(),
                            source: "script_analysis".to_string(),
                            content_type: None,
                        });
                    }
                }
            }

            // Collect network events for API discovery
            let network_events = browser.network_events();
            for event in network_events.iter().take(MAX_CAPTURED_REQUESTS) {
                let url = &event.request.url;
                if url.contains("/api/") || url.contains("/graphql") {
                    site_results.discovered_endpoints.push(DiscoveredEndpoint {
                        url: url.clone(),
                        method: event.request.method.clone(),
                        source: "network_capture".to_string(),
                        content_type: None,
                    });
                }
            }
        }

        info!(
            "[HeadlessCrawler] Crawl complete: {} links, {} forms, {} SPA routes",
            site_results.links.len(),
            site_results.forms.len(),
            site_results.spa_routes.len()
        );

        Ok(site_results)
    }

    /// Extract forms from a single page
    pub async fn extract_forms(&self, url: &str) -> Result<Vec<DiscoveredForm>> {
        info!("[HeadlessCrawler] Extracting forms from {}", url);

        let browser_config = BrowserConfig::default()
            .timeout(self.timeout);

        let browser = Browser::new(browser_config).await?;

        // Set up auth if available
        if let Some(ref token) = self.auth_token {
            browser.set_auth_token(token.clone());
        }

        // Set custom headers
        for (key, value) in &self.custom_headers {
            browser.set_custom_auth(key, value);
        }

        let page = browser.new_page().await?;
        page.navigate(url).await?;
        tokio::time::sleep(Duration::from_millis(JS_RENDER_WAIT_MS)).await;

        let forms = page.forms();
        let mut discovered_forms = Vec::new();

        for form in forms {
            discovered_forms.push(self.convert_form(&form, url));
        }

        info!("[HeadlessCrawler] Found {} forms", discovered_forms.len());
        Ok(discovered_forms)
    }

    /// Convert kalamari Form to lonkero DiscoveredForm
    fn convert_form(&self, form: &Form, _page_url: &str) -> DiscoveredForm {
        let inputs: Vec<FormInput> = form
            .fields
            .iter()
            .filter_map(|field| {
                // Skip fields without names
                field.name.as_ref().map(|name| FormInput {
                    name: name.clone(),
                    input_type: field.field_type.clone(),
                    value: field.value.clone(),
                    options: if field.options.is_empty() {
                        None
                    } else {
                        Some(field.options.iter().map(|o| o.value.clone()).collect())
                    },
                    required: field.required,
                })
            })
            .collect();

        DiscoveredForm {
            action: form.action.clone().unwrap_or_default(),
            method: form.method.to_uppercase(),
            inputs,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Extract CSRF token from a page's forms
    pub async fn extract_csrf_token(&self, url: &str) -> Result<Option<CsrfTokenInfo>> {
        let browser_config = BrowserConfig::default().timeout(self.timeout);
        let browser = Browser::new(browser_config).await?;
        let page = browser.new_page().await?;

        page.navigate(url).await?;
        tokio::time::sleep(Duration::from_millis(JS_RENDER_WAIT_MS)).await;

        // Look for CSRF tokens in forms
        for form in page.forms() {
            if let Some(token) = form.csrf_token() {
                // Find the field name
                for field in &form.fields {
                    if let Some(name) = &field.name {
                        let name_lower = name.to_lowercase();
                        if name_lower.contains("csrf") || name_lower.contains("token") || name_lower.contains("_token") {
                            if field.value.as_ref().map(|v| v == &token).unwrap_or(false) {
                                return Ok(Some(CsrfTokenInfo {
                                    name: name.clone(),
                                    value: token,
                                    input_type: field.field_type.clone(),
                                }));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Submit a form with CSRF token handling
    pub async fn submit_form_with_csrf(
        &self,
        source_url: &str,
        action_url: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<FormSubmissionResult> {
        let browser_config = BrowserConfig::default().timeout(self.timeout);
        let browser = Browser::new(browser_config).await?;
        let page = browser.new_page().await?;

        // Navigate to source page first to establish session/get CSRF
        page.navigate(source_url).await?;
        tokio::time::sleep(Duration::from_millis(JS_RENDER_WAIT_MS)).await;

        // Fill form fields via JavaScript
        for (name, value) in form_data {
            let selector = format!("[name='{}']", name);
            let _ = page.fill(&selector, value);
        }

        // Submit via JavaScript
        let js_submit = r#"
            (function() {
                var form = document.querySelector('form');
                if (form) {
                    form.submit();
                    return true;
                }
                return false;
            })()
        "#;
        let _ = page.evaluate(js_submit);

        // Wait for navigation
        tokio::time::sleep(Duration::from_millis(FORM_SUBMIT_WAIT_MS)).await;

        // Get current URL after submission
        let current_url = page.url();

        Ok(FormSubmissionResult {
            success: true,
            status_code: None,
            redirect_url: current_url,
            response_body: page.content(),
            error: None,
        })
    }

    /// Crawl an authenticated site (uses session from auth_context)
    pub async fn crawl_authenticated_site(&self, url: &str, max_pages: usize) -> Result<SiteCrawlResults> {
        // For now, delegate to regular crawl - auth is handled via browser.set_auth_token
        let mut config = self.config.clone();
        config.max_pages = max_pages;

        let crawler = HeadlessCrawler {
            config,
            auth_token: self.auth_token.clone(),
            custom_headers: self.custom_headers.clone(),
            timeout: self.timeout,
            session_state: self.session_state.clone(),
        };

        crawler.crawl_site(url).await
    }

    /// Discover form endpoints on a page (intercepts form submissions)
    pub async fn discover_form_endpoints(&self, url: &str) -> Result<Vec<DiscoveredEndpoint>> {
        let forms = self.extract_forms(url).await?;

        // Convert forms to discovered endpoints
        let endpoints: Vec<DiscoveredEndpoint> = forms
            .iter()
            .map(|form| DiscoveredEndpoint {
                url: form.action.clone(),
                method: form.method.clone(),
                source: "form_discovery".to_string(),
                content_type: Some("application/x-www-form-urlencoded".to_string()),
            })
            .collect();

        Ok(endpoints)
    }

    /// Extract GraphQL operations from script content
    fn extract_graphql_operations(&self, content: &str) -> Vec<GraphQLOperation> {
        let mut operations = Vec::new();

        // Look for query/mutation definitions
        let query_regex = regex::Regex::new(r#"(query|mutation)\s+(\w+)"#).unwrap();
        for cap in query_regex.captures_iter(content) {
            operations.push(GraphQLOperation {
                operation_type: cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                name: cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(),
                source: "script_analysis".to_string(),
            });
        }

        operations
    }

    /// Extract script sources from a page's document
    fn extract_script_sources(&self, page: &Arc<kalamari::Page>) -> Vec<ScriptSource> {
        let mut scripts = Vec::new();

        if let Some(doc) = page.document() {
            for script_element in doc.scripts() {
                let script_type = script_element.get_attribute("type");
                let is_async = script_element.get_attribute("async").is_some();
                let is_defer = script_element.get_attribute("defer").is_some();
                let nonce = script_element.get_attribute("nonce");

                if let Some(src) = script_element.src() {
                    // External script - we'd need to fetch it
                    // For now, just record it with empty content
                    scripts.push(ScriptSource {
                        url: src,
                        content: String::new(),
                        is_inline: false,
                        script_type,
                        is_async,
                        is_defer,
                        nonce,
                    });
                } else {
                    // Inline script
                    let content = script_element.text_content();
                    if !content.trim().is_empty() {
                        scripts.push(ScriptSource {
                            url: "inline".to_string(),
                            content,
                            is_inline: true,
                            script_type,
                            is_async,
                            is_defer,
                            nonce,
                        });
                    }
                }
            }
        }

        scripts
    }

    /// Detect login forms and attempt authentication
    pub async fn detect_and_login(
        &self,
        url: &str,
        credentials: &LoginCredentials,
    ) -> Result<LoginResult> {
        info!("[HeadlessCrawler] Detecting login form at {}", url);

        let browser_config = BrowserConfig::default()
            .timeout(self.timeout);

        let browser = Browser::new(browser_config).await?;
        let page = browser.new_page().await?;

        page.navigate(url).await?;
        tokio::time::sleep(Duration::from_millis(JS_RENDER_WAIT_MS)).await;

        let forms = page.forms();

        // Find login form
        let login_form = forms.iter().find(|f| {
            f.fields.iter().any(|field| {
                field.field_type == "password"
                    || field.name.as_ref().map(|n| n.to_lowercase().contains("password")).unwrap_or(false)
            })
        });

        let Some(form) = login_form else {
            return Ok(LoginResult {
                success: false,
                session: None,
                error: Some("No login form found".to_string()),
            });
        };

        // Fill form fields via JavaScript
        for field in &form.fields {
            let name_lower = field.name.as_ref().map(|n| n.to_lowercase()).unwrap_or_default();
            let selector = field.name.as_ref().map(|n| format!("[name='{}']", n));

            if let Some(selector) = selector {
                if name_lower.contains("user") || name_lower.contains("email") || field.field_type == "email" {
                    let _ = page.fill(&selector, &credentials.username);
                } else if name_lower.contains("pass") || field.field_type == "password" {
                    let _ = page.fill(&selector, &credentials.password);
                }
            }
        }

        // Submit form using form selector
        let form_selector = "form";  // Default, could be improved
        page.submit_form(form_selector).await?;
        tokio::time::sleep(Duration::from_millis(FORM_SUBMIT_WAIT_MS)).await;

        // Extract auth session via JavaScript
        let mut session = AuthSession::empty();

        // Get cookies
        let js_cookies = r#"JSON.stringify(Object.fromEntries(document.cookie.split(';').map(c => c.trim().split('='))))"#;
        if let Ok(result) = page.evaluate(js_cookies) {
            if let Some(json) = result.as_string() {
                if let Ok(cookies) = serde_json::from_str::<HashMap<String, String>>(&json) {
                    session.cookies = cookies;
                }
            }
        }

        // Check for session indicators
        let has_session_cookie = session.cookies.keys().any(|k| {
            let kl = k.to_lowercase();
            kl.contains("session") || kl.contains("auth") || kl.contains("token")
        });

        session.is_authenticated = has_session_cookie;

        let success = session.is_authenticated;
        Ok(LoginResult {
            success,
            session: if success { Some(session) } else { None },
            error: if success { None } else { Some("Login failed".to_string()) },
        })
    }
}

// ============================================================================
// Result types
// ============================================================================

#[derive(Debug, Clone)]
pub struct CsrfTokenInfo {
    pub name: String,
    pub value: String,
    pub input_type: String,
}

pub struct FormAutoFill;

impl FormAutoFill {
    /// Generate test data for a form field based on its name and type
    pub fn generate_test_value(field_name: &str, field_type: &str) -> String {
        let name_lower = field_name.to_lowercase();

        match field_type {
            "email" => "test@example.com".to_string(),
            "tel" | "phone" => "+1234567890".to_string(),
            "url" => "https://example.com".to_string(),
            "number" => "42".to_string(),
            "date" => "2024-01-01".to_string(),
            "time" => "12:00".to_string(),
            "datetime-local" => "2024-01-01T12:00".to_string(),
            "month" => "2024-01".to_string(),
            "week" => "2024-W01".to_string(),
            "color" => "#ff0000".to_string(),
            "range" => "50".to_string(),
            "password" => "TestPassword123!".to_string(),
            _ => {
                if name_lower.contains("email") {
                    "test@example.com".to_string()
                } else if name_lower.contains("phone") || name_lower.contains("tel") {
                    "+1234567890".to_string()
                } else if name_lower.contains("name") {
                    "Test User".to_string()
                } else if name_lower.contains("address") {
                    "123 Test Street".to_string()
                } else if name_lower.contains("city") {
                    "Test City".to_string()
                } else if name_lower.contains("zip") || name_lower.contains("postal") {
                    "12345".to_string()
                } else if name_lower.contains("country") {
                    "US".to_string()
                } else if name_lower.contains("comment") || name_lower.contains("message") {
                    "Test comment".to_string()
                } else {
                    "test_value".to_string()
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FormSubmissionResult {
    pub success: bool,
    pub status_code: Option<u16>,
    pub redirect_url: Option<String>,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SiteCrawlResults {
    pub base_url: String,
    pub links: HashSet<String>,
    pub forms: Vec<DiscoveredForm>,
    pub spa_routes: Vec<SpaRoute>,
    pub graphql_operations: Vec<GraphQLOperation>,
    pub websocket_endpoints: Vec<String>,
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    pub auth_session: Option<AuthSession>,
    pub pages_visited: HashSet<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub js_files: Vec<String>,
    pub graphql_endpoints: HashSet<String>,
}

impl SiteCrawlResults {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            links: HashSet::new(),
            forms: Vec::new(),
            spa_routes: Vec::new(),
            graphql_operations: Vec::new(),
            websocket_endpoints: Vec::new(),
            discovered_endpoints: Vec::new(),
            auth_session: None,
            pages_visited: HashSet::new(),
            api_endpoints: Vec::new(),
            js_files: Vec::new(),
            graphql_endpoints: HashSet::new(),
        }
    }

    pub fn merge(&mut self, other: SiteCrawlResults) {
        self.links.extend(other.links);
        self.forms.extend(other.forms);
        self.spa_routes.extend(other.spa_routes);
        self.graphql_operations.extend(other.graphql_operations);
        self.websocket_endpoints.extend(other.websocket_endpoints);
        self.discovered_endpoints.extend(other.discovered_endpoints);
        self.pages_visited.extend(other.pages_visited);
        self.api_endpoints.extend(other.api_endpoints);
        self.js_files.extend(other.js_files);
        self.graphql_endpoints.extend(other.graphql_endpoints);
        if self.auth_session.is_none() {
            self.auth_session = other.auth_session;
        }
    }

    /// Merge results into a CrawlResults struct
    pub fn merge_into(&self, crawl_results: &mut crate::crawler::CrawlResults) {
        crawl_results.links.extend(self.links.clone());
        crawl_results.api_endpoints.extend(self.api_endpoints.iter().map(|ep| ep.url.clone()));
        crawl_results.websocket_endpoints.extend(self.websocket_endpoints.iter().cloned());
        for form in &self.forms {
            crawl_results.forms.push(form.clone());
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpaRoute {
    pub path: String,
    pub requires_auth: bool,
    pub roles: Vec<String>,
    pub framework: Option<SpaFramework>,
}

#[derive(Debug, Clone)]
pub struct GraphQLOperation {
    pub operation_type: String,
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct DetectedLoginForm {
    pub form: DiscoveredForm,
    pub username_field: Option<String>,
    pub password_field: Option<String>,
    pub submit_button: Option<String>,
    pub has_remember_me: bool,
    pub has_csrf: bool,
}

#[derive(Debug, Clone)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub success: bool,
    pub session: Option<AuthSession>,
    pub error: Option<String>,
}

// ============================================================================
// Helper function for deciding when to use headless browser
// ============================================================================

/// Determine if a page needs headless browser rendering
pub fn should_use_headless(
    crawl_results: &crate::crawler::CrawlResults,
    detected_technologies: &std::collections::HashSet<String>,
    html_content: Option<&str>,
) -> bool {
    // If crawl results indicate SPA, use headless
    if crawl_results.is_spa {
        return true;
    }

    // Check detected technologies for SPA frameworks
    let spa_technologies = [
        "react", "vue", "angular", "nuxt", "next", "svelte", "ember", "gatsby"
    ];
    for tech in &spa_technologies {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains(tech)) {
            return true;
        }
    }

    // Check HTML content if provided
    let Some(html) = html_content else {
        return false;
    };

    let html_lower = html.to_lowercase();

    // SPA framework indicators
    let spa_indicators = [
        "ng-app", "ng-controller", // Angular
        "data-reactroot", "__next", // React/Next.js
        "data-v-", "__nuxt", // Vue/Nuxt
        "ember-view", // Ember
        "data-svelte", // Svelte
    ];

    for indicator in &spa_indicators {
        if html_lower.contains(indicator) {
            return true;
        }
    }

    // Heavy JavaScript loading
    let script_count = html_lower.matches("<script").count();
    if script_count > 10 {
        return true;
    }

    // Dynamic content placeholders
    let dynamic_indicators = [
        "loading...",
        "{{",
        "ng-bind",
        "v-if",
        "v-for",
        ":src",
        "@click",
    ];

    for indicator in &dynamic_indicators {
        if html_lower.contains(indicator) {
            return true;
        }
    }

    false
}

impl SiteCrawlResults {
    /// Get all unique URLs found during crawl
    pub fn all_urls(&self) -> Vec<String> {
        let mut urls: Vec<String> = self.links.iter().cloned().collect();

        // Add form action URLs
        for form in &self.forms {
            if !urls.contains(&form.action) {
                urls.push(form.action.clone());
            }
        }

        // Add SPA routes as full URLs
        if let Ok(base) = url::Url::parse(&self.base_url) {
            for route in &self.spa_routes {
                if let Ok(full_url) = base.join(&route.path) {
                    let url_str = full_url.to_string();
                    if !urls.contains(&url_str) {
                        urls.push(url_str);
                    }
                }
            }
        }

        urls
    }

    /// Get authenticated routes that require auth
    pub fn auth_required_routes(&self) -> Vec<&SpaRoute> {
        self.spa_routes.iter().filter(|r| r.requires_auth).collect()
    }

    /// Get routes requiring specific roles
    pub fn role_protected_routes(&self) -> Vec<&SpaRoute> {
        self.spa_routes.iter().filter(|r| !r.roles.is_empty()).collect()
    }
}
