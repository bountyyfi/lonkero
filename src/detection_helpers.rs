// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Detection Helpers - Reduce False Positives Across All Scanners
 *
 * This module provides smart detection logic to prevent false positives when
 * scanning diverse tech stacks (SPAs, static sites, APIs, etc.)
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::HttpResponse;
use std::collections::HashMap;
use tracing::{debug, info};
use regex::Regex;

/// Application type detection result
#[derive(Debug, Clone, PartialEq)]
pub enum AppType {
    SinglePageApp(SpaFramework),
    StaticSite,
    ServerRendered,
    Api,
    Unknown,
}

/// SPA framework detection
#[derive(Debug, Clone, PartialEq)]
pub enum SpaFramework {
    Vue,
    React,
    Angular,
    Svelte,
    Next,
    Nuxt,
    Other,
}

/// Comprehensive application characteristics
#[derive(Debug, Clone)]
pub struct AppCharacteristics {
    pub app_type: AppType,
    pub is_spa: bool,
    pub is_static: bool,
    pub is_api: bool,
    pub is_api_only: bool,
    pub has_server_side_rendering: bool,
    pub has_authentication: bool,
    pub has_oauth: bool,
    pub has_jwt: bool,
    pub has_mfa: bool,
    pub has_file_upload: bool,
    pub uses_client_side_routing: bool,
    pub framework_indicators: Vec<String>,
}

impl AppCharacteristics {
    /// Create default characteristics
    pub fn default() -> Self {
        Self {
            app_type: AppType::Unknown,
            is_spa: false,
            is_static: false,
            is_api: false,
            is_api_only: false,
            has_server_side_rendering: false,
            has_authentication: false,
            has_oauth: false,
            has_jwt: false,
            has_mfa: false,
            has_file_upload: false,
            uses_client_side_routing: false,
            framework_indicators: Vec::new(),
        }
    }

    /// Detect application characteristics from response
    pub fn from_response(response: &HttpResponse, url: &str) -> Self {
        let body = &response.body;
        let body_lower = body.to_lowercase();
        let headers = &response.headers;

        let mut characteristics = Self::default();

        // Detect SPA frameworks
        let spa_framework = detect_spa_framework(body, headers);
        if spa_framework.is_some() {
            characteristics.is_spa = true;
            characteristics.app_type = AppType::SinglePageApp(spa_framework.unwrap());
            characteristics.uses_client_side_routing = true;
        }

        // Detect static sites
        if is_static_site(body, headers, &body_lower) {
            characteristics.is_static = true;
            if !characteristics.is_spa {
                characteristics.app_type = AppType::StaticSite;
            }
        }

        // Detect API-only responses
        if is_api_response(body, headers, url) {
            characteristics.is_api = true;
            characteristics.is_api_only = true;
            characteristics.app_type = AppType::Api;
        } else if url.contains("/api/") || url.contains("/graphql") || url.contains("/v1/") || url.contains("/v2/") {
            // Likely API endpoint even if not pure JSON
            characteristics.is_api = true;
        }

        // Detect server-side rendering
        if has_server_side_rendering(body, &body_lower) {
            characteristics.has_server_side_rendering = true;
            if characteristics.app_type == AppType::Unknown {
                characteristics.app_type = AppType::ServerRendered;
            }
        }

        // Detect authentication mechanisms (ONLY if actual evidence exists)
        characteristics.has_authentication = has_real_authentication(body, headers, &body_lower);
        characteristics.has_oauth = has_real_oauth(body, headers, &body_lower);
        characteristics.has_jwt = has_real_jwt(body, headers, &body_lower);
        characteristics.has_mfa = has_real_mfa(body, &body_lower);

        // Detect file upload capabilities
        characteristics.has_file_upload = has_file_upload(body, &body_lower);

        // Detect framework indicators
        characteristics.framework_indicators = detect_framework_indicators(body, headers);

        debug!("[Detection] App characteristics: {:?}", characteristics.app_type);

        characteristics
    }

    /// Should skip injection tests (SPAs return same HTML for all routes)
    pub fn should_skip_injection_tests(&self) -> bool {
        self.is_spa || self.is_static
    }

    /// Should skip auth tests (no authentication present)
    pub fn should_skip_auth_tests(&self) -> bool {
        !self.has_authentication
    }

    /// Should skip OAuth tests
    pub fn should_skip_oauth_tests(&self) -> bool {
        !self.has_oauth
    }

    /// Should skip JWT tests
    pub fn should_skip_jwt_tests(&self) -> bool {
        !self.has_jwt
    }

    /// Should skip MFA tests
    pub fn should_skip_mfa_tests(&self) -> bool {
        !self.has_mfa && !self.has_authentication
    }
}

/// Detect SPA framework
fn detect_spa_framework(body: &str, _headers: &HashMap<String, String>) -> Option<SpaFramework> {
    let body_lower = body.to_lowercase();

    // Vue.js detection (strong indicators)
    if (body.contains("data-v-") || body.contains("__NUXT__") || body.contains("Vue.component")) &&
       (body.contains("app.js") || body.contains("chunk-vendors") || body.contains("vue-router")) {
        info!("[Detection] Vue.js SPA detected");
        return Some(SpaFramework::Vue);
    }

    // React detection (strong indicators)
    if (body.contains("data-reactroot") || body.contains("data-reactid") ||
        body.contains("__REACT_") || body.contains("_next/static")) &&
       (body.contains("react-dom") || body.contains("main.chunk.js") || body.contains("bundle.js")) {
        info!("[Detection] React SPA detected");
        return Some(SpaFramework::React);
    }

    // Angular detection (strong indicators)
    if (body.contains("ng-version") || body.contains("ng-app") || body_lower.contains("angular")) &&
       (body.contains("main.js") || body.contains("polyfills") || body.contains("runtime.js")) {
        info!("[Detection] Angular SPA detected");
        return Some(SpaFramework::Angular);
    }

    // Next.js detection
    if body.contains("_next/static") || body.contains("__NEXT_DATA__") {
        info!("[Detection] Next.js (React SSR) detected");
        return Some(SpaFramework::Next);
    }

    // Nuxt.js detection
    if body.contains("__NUXT__") || body_lower.contains("nuxt.js") {
        info!("[Detection] Nuxt.js (Vue SSR) detected");
        return Some(SpaFramework::Nuxt);
    }

    // Svelte detection
    if body_lower.contains("svelte") && (body.contains("build/bundle") || body.contains("global.css")) {
        info!("[Detection] Svelte SPA detected");
        return Some(SpaFramework::Svelte);
    }

    // Generic SPA indicators (fallback)
    let has_spa_shell = body.contains("<div id=\"app\"") ||
                        body.contains("<div id=\"root\"") ||
                        body.contains("<noscript>You need to enable JavaScript") ||
                        body.contains("This app requires JavaScript");

    let has_js_bundle = body.contains("app.js") || body.contains("main.js") ||
                        body.contains("bundle.js") || body.contains("chunk");

    if has_spa_shell && has_js_bundle {
        info!("[Detection] Generic SPA detected");
        return Some(SpaFramework::Other);
    }

    None
}

/// Detect if site is static (no server-side logic)
fn is_static_site(body: &str, headers: &HashMap<String, String>, body_lower: &str) -> bool {
    // Check for static site generators
    let static_generators = [
        "jekyll", "hugo", "gatsby", "eleventy", "hexo",
        "gridsome", "vuepress", "docusaurus"
    ];

    for generator in &static_generators {
        if body_lower.contains(generator) ||
           headers.get("x-powered-by").map(|h| h.to_lowercase().contains(generator)).unwrap_or(false) {
            return true;
        }
    }

    // Check for GitHub Pages, Netlify, Vercel (static hosting)
    if let Some(server) = headers.get("server") {
        let server_lower = server.to_lowercase();
        if server_lower.contains("github.com") ||
           server_lower.contains("netlify") ||
           server_lower.contains("vercel") {
            return true;
        }
    }

    // No dynamic content indicators
    let no_forms = !body.contains("<form");
    let no_csrf_tokens = !body.contains("csrf") && !body.contains("_token");
    let no_session_cookies = !headers.get("set-cookie")
        .map(|c| c.contains("session") || c.contains("PHPSESSID") || c.contains("JSESSIONID"))
        .unwrap_or(false);

    no_forms && no_csrf_tokens && no_session_cookies && body.len() < 100_000
}

/// Detect API-only response (no HTML)
fn is_api_response(body: &str, headers: &HashMap<String, String>, url: &str) -> bool {
    // Check content-type header
    if let Some(content_type) = headers.get("content-type") {
        let ct_lower = content_type.to_lowercase();
        if ct_lower.contains("application/json") ||
           ct_lower.contains("application/xml") ||
           ct_lower.contains("text/xml") {
            return true;
        }
    }

    // Check if URL path suggests API
    let url_lower = url.to_lowercase();
    let api_paths = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/"];
    for path in &api_paths {
        if url_lower.contains(path) {
            // Also check body is JSON/XML, not HTML
            let body_trimmed = body.trim();
            if (body_trimmed.starts_with('{') && body_trimmed.ends_with('}')) ||
               (body_trimmed.starts_with('[') && body_trimmed.ends_with(']')) ||
               (body_trimmed.starts_with('<') && body_trimmed.contains("<?xml")) {
                return true;
            }
        }
    }

    false
}

/// Detect server-side rendering
fn has_server_side_rendering(body: &str, body_lower: &str) -> bool {
    // SSR frameworks inject data into HTML
    body.contains("__INITIAL_STATE__") ||
    body.contains("__PRELOADED_STATE__") ||
    body.contains("window.__DATA__") ||
    body.contains("__NEXT_DATA__") ||
    body.contains("__NUXT__") ||
    // PHP/JSP/ASP indicators
    body_lower.contains("x-powered-by: php") ||
    body.contains("<%") || // JSP/ASP
    body.contains("<?php") ||
    // Template engines
    body_lower.contains("handlebars") ||
    body_lower.contains("mustache") ||
    body_lower.contains("ejs")
}

/// Detect REAL authentication (not just keyword mentions)
fn has_real_authentication(body: &str, headers: &HashMap<String, String>, body_lower: &str) -> bool {
    // Check for auth cookies (strong indicator)
    if let Some(cookies) = headers.get("set-cookie") {
        let cookie_lower = cookies.to_lowercase();
        if cookie_lower.contains("session") ||
           cookie_lower.contains("auth") ||
           cookie_lower.contains("token") ||
           cookie_lower.contains("phpsessid") ||
           cookie_lower.contains("jsessionid") {
            info!("[Detection] Real authentication detected: session cookie");
            return true;
        }
    }

    // Check for auth headers
    if headers.contains_key("www-authenticate") || headers.contains_key("authorization") {
        info!("[Detection] Real authentication detected: auth headers");
        return true;
    }

    // Check for login forms WITH CSRF protection (real auth, not static demo)
    let has_login_form = (body_lower.contains("<form") &&
                          (body_lower.contains("login") || body_lower.contains("sign in"))) &&
                         (body.contains("password") || body.contains("type=\"password\""));

    let has_csrf = body.contains("csrf") || body.contains("_token") || body.contains("authenticity_token");

    if has_login_form && has_csrf {
        info!("[Detection] Real authentication detected: login form with CSRF");
        return true;
    }

    // Check for auth API endpoints (in script tags)
    if body.contains("/api/auth") || body.contains("/auth/login") ||
       body.contains("authentication") && body.contains("endpoint") {
        info!("[Detection] Real authentication detected: auth endpoints");
        return true;
    }

    false
}

/// Detect REAL OAuth implementation (not just documentation)
fn has_real_oauth(body: &str, _headers: &HashMap<String, String>, body_lower: &str) -> bool {
    // OAuth URLs in actual forms/buttons (not docs)
    let oauth_providers = [
        "accounts.google.com/o/oauth2",
        "login.microsoftonline.com",
        "github.com/login/oauth",
        "facebook.com/v",
        "oauth.twitter.com",
        "appleid.apple.com/auth"
    ];

    for provider in &oauth_providers {
        if body.contains(provider) && (body.contains("href=") || body.contains("action=")) {
            info!("[Detection] Real OAuth detected: provider {}", provider);
            return true;
        }
    }

    // Check for OAuth endpoints with actual implementation
    let has_oauth_endpoint = (body_lower.contains("/oauth/authorize") ||
                             body_lower.contains("/oauth2/authorize")) &&
                            (body.contains("client_id") || body.contains("response_type"));

    if has_oauth_endpoint {
        info!("[Detection] Real OAuth detected: oauth endpoint with params");
        return true;
    }

    // Check for OAuth JS libraries (actual implementation, not docs)
    let oauth_libs = ["gapi.auth2", "MSAL.", "passport.authenticate"];
    for lib in &oauth_libs {
        if body.contains(lib) && !body_lower.contains("documentation") {
            info!("[Detection] Real OAuth detected: {} library", lib);
            return true;
        }
    }

    false
}

/// Detect REAL JWT usage (not just mentions in docs)
fn has_real_jwt(body: &str, headers: &HashMap<String, String>, body_lower: &str) -> bool {
    // Check Authorization header with Bearer token
    if let Some(auth) = headers.get("authorization") {
        if auth.starts_with("Bearer ") && auth.len() > 50 {
            info!("[Detection] Real JWT detected: Bearer token in header");
            return true;
        }
    }

    // Check for JWT in Set-Cookie
    if let Some(cookies) = headers.get("set-cookie") {
        // JWT pattern: xxx.yyy.zzz (3 base64 parts)
        if cookies.contains("eyJ") || cookies.matches('.').count() >= 2 {
            info!("[Detection] Real JWT detected: JWT in cookie");
            return true;
        }
    }

    // Check for JWT in localStorage/sessionStorage calls (actual code, not docs)
    if (body.contains("localStorage.setItem(") || body.contains("sessionStorage.setItem(")) &&
       (body.contains("\"token\"") || body.contains("'token'") ||
        body.contains("\"jwt\"") || body.contains("'jwt'")) &&
       !body_lower.contains("example") && !body_lower.contains("documentation") {
        info!("[Detection] Real JWT detected: token storage in JS");
        return true;
    }

    // Check for JWT libraries (actual usage)
    let jwt_libs = ["jsonwebtoken", "jose", "jwt-decode", "njwt"];
    for lib in &jwt_libs {
        if body.contains(lib) && body.contains("import") && !body_lower.contains("documentation") {
            info!("[Detection] Real JWT detected: {} library", lib);
            return true;
        }
    }

    false
}

/// Detect REAL MFA implementation (not just mentions)
fn has_real_mfa(body: &str, body_lower: &str) -> bool {
    // Check for MFA enrollment/verification forms (actual implementation)
    let has_mfa_form = (body_lower.contains("verification code") ||
                        body_lower.contains("authenticator app") ||
                        body_lower.contains("totp")) &&
                       (body.contains("<form") || body.contains("<input"));

    if has_mfa_form && !body_lower.contains("documentation") && !body_lower.contains("learn more") {
        info!("[Detection] Real MFA detected: MFA form");
        return true;
    }

    // Check for QR code generation (actual enrollment)
    if (body.contains("otpauth://totp/") || body_lower.contains("qr code")) &&
       body.contains("secret=") {
        info!("[Detection] Real MFA detected: TOTP enrollment");
        return true;
    }

    // Check for MFA libraries (actual implementation)
    let mfa_libs = ["speakeasy", "otplib", "authenticator", "qrcode"];
    for lib in &mfa_libs {
        if body.contains(lib) && body.contains("import") && !body_lower.contains("documentation") {
            info!("[Detection] Real MFA detected: {} library", lib);
            return true;
        }
    }

    false
}

/// Detect framework indicators
fn detect_framework_indicators(body: &str, headers: &HashMap<String, String>) -> Vec<String> {
    let mut indicators = Vec::new();

    // From headers
    if let Some(powered_by) = headers.get("x-powered-by") {
        indicators.push(format!("X-Powered-By: {}", powered_by));
    }
    if let Some(server) = headers.get("server") {
        indicators.push(format!("Server: {}", server));
    }

    // From body
    let frameworks = [
        ("Vue.js", "data-v-"),
        ("React", "data-reactroot"),
        ("Angular", "ng-version"),
        ("Next.js", "_next/static"),
        ("Nuxt.js", "__NUXT__"),
        ("Django", "csrfmiddlewaretoken"),
        ("Rails", "authenticity_token"),
        ("Laravel", "laravel_session"),
        ("Express", "express"),
        ("WordPress", "wp-content"),
    ];

    for (name, indicator) in &frameworks {
        if body.contains(indicator) {
            indicators.push(name.to_string());
        }
    }

    indicators
}

/// Check if URL is a SPA client-side route
pub fn is_spa_route(url: &str, base_response: &HttpResponse) -> bool {
    // If we already know it's a SPA, any path is a client-side route
    let characteristics = AppCharacteristics::from_response(base_response, url);
    characteristics.is_spa && characteristics.uses_client_side_routing
}

/// Smart payload reflection detection (context-aware)
pub fn is_payload_reflected_dangerously(response: &HttpResponse, payload: &str) -> bool {
    let body = &response.body;

    // Don't match if payload appears in framework bundles
    if body.contains("<script src=") && body.len() > 100_000 {
        debug!("[Detection] Skipping reflection check - likely framework bundle");
        return false;
    }

    // Check for EXACT payload in dangerous contexts (not substring matching!)
    let dangerous_contexts = vec![
        // HTML contexts
        format!(">{}<", payload),           // <tag>PAYLOAD</tag>
        format!(">{}</", payload),          // <tag>PAYLOAD</tag>
        // Attribute contexts
        format!("=\"{}\"", payload),        // attr="PAYLOAD"
        format!("='{}'", payload),          // attr='PAYLOAD'
        format!("='{}'>", payload),         // attr='PAYLOAD'>
        // JavaScript contexts
        format!("('{}')", payload),         // func('PAYLOAD')
        format!("(\"{}\")", payload),       // func("PAYLOAD")
        // URL contexts
        format!("href=\"{}\"", payload),    // href="PAYLOAD"
        format!("src=\"{}\"", payload),     // src="PAYLOAD"
        format!("action=\"{}\"", payload),  // action="PAYLOAD"
    ];

    for context in &dangerous_contexts {
        if body.contains(context) {
            info!("[Detection] Dangerous reflection detected: {}", context);
            return true;
        }
    }

    // Check for unescaped script execution
    let unescaped_patterns = vec![
        format!("<script>{}", payload),
        format!("{}</script>", payload),
        format!("onerror={}", payload),
        format!("onclick={}", payload),
        format!("onload={}", payload),
        format!("javascript:{}", payload),
    ];

    for pattern in &unescaped_patterns {
        if body.contains(pattern.as_str()) {
            info!("[Detection] Unescaped execution context detected");
            return true;
        }
    }

    false
}

/// Check if endpoint actually exists (not SPA fallback)
pub fn endpoint_exists(response: &HttpResponse, expected_status_codes: &[u16]) -> bool {
    // 404 = doesn't exist
    if response.status_code == 404 {
        return false;
    }

    // If we expect specific status codes, check them
    if !expected_status_codes.is_empty() && !expected_status_codes.contains(&response.status_code) {
        return false;
    }

    // For SPAs, check if response is just the app shell
    let body = &response.body;
    let is_spa_shell = (body.contains("<div id=\"app\"") || body.contains("<div id=\"root\"")) &&
                       body.contains("app.js") || body.contains("main.js");

    if is_spa_shell && response.status_code == 200 {
        debug!("[Detection] Endpoint returns SPA shell - likely doesn't exist");
        return false;
    }

    true
}

/// Discover API endpoints from JavaScript and HTML
/// Returns actual endpoint URLs discovered from the application
pub fn discover_api_endpoints(base_url: &str, html_body: &str) -> Vec<String> {
    let mut endpoints = Vec::new();
    let base_lower = base_url.to_lowercase();

    // Extract API URLs from JavaScript
    let api_patterns = vec![
        r#"["']https?://[^"']+/(?:api|graphql|v\d+)[^"']*["']"#,
        r#"baseURL:\s*["']([^"']+)["']"#,
        r#"API_URL\s*=\s*["']([^"']+)["']"#,
        r#"GRAPHQL_ENDPOINT\s*=\s*["']([^"']+)["']"#,
        r#"axios\.(?:get|post)\(["']([^"']+)["']"#,
        r#"fetch\(["']([^"']+)["']"#,
    ];

    for pattern in &api_patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(html_body) {
                if let Some(url_match) = cap.get(1).or_else(|| cap.get(0)) {
                    let url = url_match.as_str().trim_matches(|c| c == '"' || c == '\'');

                    // Resolve relative URLs
                    let full_url = if url.starts_with("http") {
                        url.to_string()
                    } else if url.starts_with('/') {
                        // Get base domain from base_url
                        if let Ok(parsed) = url::Url::parse(base_url) {
                            format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), url)
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                    if !endpoints.contains(&full_url) {
                        info!("[Discovery] Found API endpoint: {}", full_url);
                        endpoints.push(full_url);
                    }
                }
            }
        }
    }

    // Only add default paths if URL doesn't already contain them AND we found no endpoints
    if endpoints.is_empty() {
        if !base_lower.contains("/api") && !base_lower.contains("/graphql") && !base_lower.contains("/v1") {
            // Might be a traditional site - add common API paths
            endpoints.push(format!("{}/api", base_url.trim_end_matches('/')));
            endpoints.push(format!("{}/graphql", base_url.trim_end_matches('/')));
        } else {
            // URL already contains API path - use it as-is
            endpoints.push(base_url.to_string());
        }
    }

    endpoints
}

/// Check if technology is present before running scanner
pub fn detect_technology(tech: &str, html_body: &str, headers: &HashMap<String, String>) -> bool {
    let body_lower = html_body.to_lowercase();

    match tech {
        "firebase" => {
            html_body.contains("firebase") ||
            html_body.contains("firebaseapp.com") ||
            html_body.contains("__firebase") ||
            html_body.contains("/__/firebase/")
        },
        "aws" => {
            html_body.contains("amazonaws.com") ||
            html_body.contains("aws-amplify") ||
            html_body.contains("s3.") ||
            body_lower.contains("cloudfront")
        },
        "azure" => {
            html_body.contains("azure") ||
            html_body.contains("blob.core.windows.net") ||
            html_body.contains("azurewebsites.net")
        },
        "gcp" | "google-cloud" => {
            html_body.contains("storage.googleapis.com") ||
            html_body.contains("cloudrun.app") ||
            html_body.contains("appspot.com")
        },
        "docker" | "container" => {
            headers.get("server").map(|s| s.contains("docker")).unwrap_or(false) ||
            html_body.contains("/.well-known/docker") ||
            html_body.contains(":2375") || html_body.contains(":2376")
        },
        "kubernetes" => {
            html_body.contains("kubernetes") ||
            html_body.contains("k8s.io") ||
            html_body.contains(":6443") || html_body.contains(":8001")
        },
        _ => true, // Unknown tech - allow scanner to run
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vue_spa_detection() {
        let body = r#"<!DOCTYPE html><html><head></head><body><div id="app"></div><script src="/js/chunk-vendors.js"></script><script src="/js/app.js"></script></body></html>"#;
        let response = HttpResponse {
            status_code: 200,
            body: body.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let characteristics = AppCharacteristics::from_response(&response, "https://example.com");
        assert!(characteristics.is_spa);
        assert!(matches!(characteristics.app_type, AppType::SinglePageApp(SpaFramework::Vue)));
        assert!(characteristics.should_skip_injection_tests());
    }

    #[test]
    fn test_react_spa_detection() {
        let body = r#"<!DOCTYPE html><html><head></head><body><div id="root" data-reactroot=""></div><script src="/static/js/main.chunk.js"></script></body></html>"#;
        let response = HttpResponse {
            status_code: 200,
            body: body.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let characteristics = AppCharacteristics::from_response(&response, "https://example.com");
        assert!(characteristics.is_spa);
        assert!(matches!(characteristics.app_type, AppType::SinglePageApp(SpaFramework::React)));
    }

    #[test]
    fn test_real_oauth_detection() {
        let body = r#"<a href="https://accounts.google.com/o/oauth2/auth?client_id=123">Login with Google</a>"#;
        let response = HttpResponse {
            status_code: 200,
            body: body.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let characteristics = AppCharacteristics::from_response(&response, "https://example.com");
        assert!(characteristics.has_oauth);
        assert!(!characteristics.should_skip_oauth_tests());
    }

    #[test]
    fn test_fake_oauth_detection() {
        let body = r#"<p>Learn about OAuth 2.0 in our documentation. Example: /oauth/authorize?client_id=...</p>"#;
        let response = HttpResponse {
            status_code: 200,
            body: body.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let characteristics = AppCharacteristics::from_response(&response, "https://example.com");
        assert!(!characteristics.has_oauth);
        assert!(characteristics.should_skip_oauth_tests());
    }

    #[test]
    fn test_dangerous_reflection() {
        let response = HttpResponse {
            status_code: 200,
            body: "<div>User: <script>alert(1)</script></div>".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(is_payload_reflected_dangerously(&response, "alert(1)"));
    }

    #[test]
    fn test_safe_reflection_in_bundle() {
        // Simulate framework bundle containing "alert" in source code
        let response = HttpResponse {
            status_code: 200,
            body: format!("<script src='/app.js'></script>{}", "a".repeat(200_000)),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(!is_payload_reflected_dangerously(&response, "alert(1)"));
    }
}

/// Detect if the site has file upload functionality
fn has_file_upload(body: &str, body_lower: &str) -> bool {
    // Check for file upload form elements
    if body_lower.contains("type=\"file\"") ||
       body_lower.contains("type='file'") ||
       body_lower.contains("input file") ||
       body_lower.contains("multipart/form-data") {
        return true;
    }

    // Check for upload-related endpoints/text
    if body_lower.contains("upload") && (
        body_lower.contains("drag") ||
        body_lower.contains("drop") ||
        body_lower.contains("choose file") ||
        body_lower.contains("select file")
    ) {
        return true;
    }

    // Check for file upload libraries
    if body.contains("dropzone") ||
       body.contains("filepond") ||
       body.contains("uppy") ||
       body.contains("fine-uploader") {
        return true;
    }

    false
}
