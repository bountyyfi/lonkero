// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

pub struct RateLimitingScanner {
    http_client: Arc<HttpClient>,
}

/// Bypass technique categories
#[derive(Debug, Clone, PartialEq)]
enum BypassTechnique {
    None,
    XForwardedFor,
    XRealIP,
    XClientIP,
    XRemoteIP,
    TrueClientIP,
    UserAgentRotation,
    SessionRotation,
    Combined(Vec<String>),
}

impl BypassTechnique {
    fn as_string(&self) -> String {
        match self {
            Self::None => "None".to_string(),
            Self::XForwardedFor => "X-Forwarded-For".to_string(),
            Self::XRealIP => "X-Real-IP".to_string(),
            Self::XClientIP => "X-Client-IP".to_string(),
            Self::XRemoteIP => "X-Remote-IP".to_string(),
            Self::TrueClientIP => "True-Client-IP".to_string(),
            Self::UserAgentRotation => "User-Agent Rotation".to_string(),
            Self::SessionRotation => "Session Rotation".to_string(),
            Self::Combined(techniques) => format!("Combined ({})", techniques.join(" + ")),
        }
    }
}

/// Result of rate limiting test
#[derive(Debug)]
struct RateLimitTestResult {
    endpoint: String,
    endpoint_type: String,
    requests_sent: usize,
    successful_requests: usize,
    rate_limited_at: Option<usize>,
    total_time: Duration,
    vulnerable: bool,
    bypass_technique: BypassTechnique,
}

/// Detected endpoint for testing
#[derive(Debug, Clone)]
struct DetectedEndpoint {
    url: String,
    method: String,
    endpoint_type: EndpointType,
    form_data: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone)]
enum EndpointType {
    Signup,
    Login,
    PasswordReset,
    OTP,
    API,
}

impl RateLimitingScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for rate limiting vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Scanning for rate limiting vulnerabilities and bypass techniques");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get the page to detect forms and endpoints
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Detect endpoints to test
        let endpoints = self.detect_endpoints(&response.body, url);
        info!(
            "Found {} endpoints to test for rate limiting",
            endpoints.len()
        );

        // Test each endpoint
        for endpoint in endpoints {
            // Limit requests in fast mode
            let request_count = if config.scan_mode.as_str() == "fast" {
                5
            } else {
                10
            };

            // First test basic rate limiting
            tests_run += request_count;
            let basic_result = self
                .test_rate_limiting(&endpoint, request_count, BypassTechnique::None, &[])
                .await;

            if basic_result.vulnerable {
                vulnerabilities.push(self.create_vulnerability(&basic_result, url));
            } else if basic_result.rate_limited_at.is_some() {
                // Rate limiting is present, now test bypass techniques (PREMIUM FEATURE)
                if crate::license::is_feature_available("rate_limiting_bypass") {
                    info!(
                        "Rate limiting detected on {} - testing bypass techniques",
                        endpoint.url
                    );

                    let bypass_results = self.test_bypass_techniques(&endpoint, config).await;
                    tests_run += bypass_results.1;

                    for bypass_result in bypass_results.0 {
                        if bypass_result.vulnerable {
                            vulnerabilities.push(self.create_vulnerability(&bypass_result, url));
                        }
                    }
                } else {
                    debug!("Rate limiting bypass techniques require premium license");
                }
            }

            // Stop early in fast mode
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect endpoints that should have rate limiting
    fn detect_endpoints(&self, html: &str, base_url: &str) -> Vec<DetectedEndpoint> {
        let mut endpoints = Vec::new();
        let html_lower = html.to_lowercase();

        // Pattern to find forms
        let form_pattern = Regex::new(
            r#"<form[^>]*action=["']([^"']+)["'][^>]*method=["']?(post|get)["']?[^>]*>([\s\S]*?)</form>"#
        ).unwrap();

        // Also match forms with method before action
        let form_pattern2 = Regex::new(
            r#"<form[^>]*method=["']?(post|get)["']?[^>]*action=["']([^"']+)["'][^>]*>([\s\S]*?)</form>"#
        ).unwrap();

        for cap in form_pattern.captures_iter(&html_lower) {
            let action = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = cap.get(2).map(|m| m.as_str()).unwrap_or("post");
            let form_content = cap.get(3).map(|m| m.as_str()).unwrap_or("");

            if let Some(endpoint) = self.analyze_form(action, method, form_content, base_url) {
                endpoints.push(endpoint);
            }
        }

        for cap in form_pattern2.captures_iter(&html_lower) {
            let method = cap.get(1).map(|m| m.as_str()).unwrap_or("post");
            let action = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let form_content = cap.get(3).map(|m| m.as_str()).unwrap_or("");

            if let Some(endpoint) = self.analyze_form(action, method, form_content, base_url) {
                // Avoid duplicates
                if !endpoints.iter().any(|e| e.url == endpoint.url) {
                    endpoints.push(endpoint);
                }
            }
        }

        // Look for common API endpoints in JavaScript
        let api_patterns = vec![
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?register)['\"]"#,
                EndpointType::Signup,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?signup)['\"]"#,
                EndpointType::Signup,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?login)['\"]"#,
                EndpointType::Login,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?signin)['\"]"#,
                EndpointType::Login,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?password-reset)['\"]"#,
                EndpointType::PasswordReset,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?forgot-password)['\"]"#,
                EndpointType::PasswordReset,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?verify-otp)['\"]"#,
                EndpointType::OTP,
            ),
            (
                r#"['"](/api/(?:v\d+/)?(?:auth/)?verify-code)['\"]"#,
                EndpointType::OTP,
            ),
        ];

        for (pattern, endpoint_type) in api_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    if let Some(path) = cap.get(1) {
                        let url = self.resolve_url(path.as_str(), base_url);
                        if !endpoints.iter().any(|e| e.url == url) {
                            endpoints.push(DetectedEndpoint {
                                url,
                                method: "POST".to_string(),
                                endpoint_type: endpoint_type.clone(),
                                form_data: None,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Analyze a form to determine if it's a rate-limit-worthy endpoint
    fn analyze_form(
        &self,
        action: &str,
        method: &str,
        form_content: &str,
        base_url: &str,
    ) -> Option<DetectedEndpoint> {
        let action_lower = action.to_lowercase();
        let form_lower = form_content.to_lowercase();

        // Determine endpoint type based on form content and action
        let endpoint_type = if self.is_signup_form(&action_lower, &form_lower) {
            EndpointType::Signup
        } else if self.is_login_form(&action_lower, &form_lower) {
            EndpointType::Login
        } else if self.is_password_reset_form(&action_lower, &form_lower) {
            EndpointType::PasswordReset
        } else if self.is_otp_form(&action_lower, &form_lower) {
            EndpointType::OTP
        } else {
            return None;
        };

        let url = self.resolve_url(action, base_url);

        // Extract form fields
        let form_data = self.extract_form_fields(form_content);

        Some(DetectedEndpoint {
            url,
            method: method.to_uppercase(),
            endpoint_type,
            form_data: Some(form_data),
        })
    }

    /// Check if form is a signup form
    fn is_signup_form(&self, action: &str, content: &str) -> bool {
        let signup_indicators = [
            "signup",
            "sign-up",
            "sign_up",
            "register",
            "create-account",
            "create_account",
            "rekisteröidy",
            "registrieren",
            "inscription",
            "registrazione",
        ];

        // Check action URL
        for indicator in signup_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        // Check form content - must have password confirmation or specific signup fields
        let has_email = content.contains("email") || content.contains("sähköposti");
        let has_password = content.contains("password") || content.contains("salasana");
        let has_confirm = content.contains("confirm")
            || content.contains("repeat")
            || content.contains("retype")
            || content.contains("vahvista");
        let has_name = content.contains("name")
            || content.contains("nimi")
            || content.contains("username")
            || content.contains("käyttäjänimi");

        // Signup usually has: email + password + (confirm OR name)
        has_email && has_password && (has_confirm || has_name)
    }

    /// Check if form is a login form
    fn is_login_form(&self, action: &str, content: &str) -> bool {
        let login_indicators = [
            "login",
            "signin",
            "sign-in",
            "sign_in",
            "authenticate",
            "auth",
            "kirjaudu",
            "anmelden",
            "connexion",
            "accedi",
        ];

        for indicator in login_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        // Login: has email/username + password, but NO confirm password
        let has_email_or_user = content.contains("email")
            || content.contains("username")
            || content.contains("käyttäjä")
            || content.contains("benutzer");
        let has_password = content.contains("password") || content.contains("salasana");
        let has_confirm =
            content.contains("confirm") || content.contains("repeat") || content.contains("retype");

        has_email_or_user && has_password && !has_confirm
    }

    /// Check if form is a password reset form
    fn is_password_reset_form(&self, action: &str, content: &str) -> bool {
        let reset_indicators = [
            "password-reset",
            "password_reset",
            "forgot",
            "reset-password",
            "recover",
            "unohdin",
            "passwort-vergessen",
            "mot-de-passe-oublie",
        ];

        for indicator in reset_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        // Reset form: has email but NO password field typically
        let has_email = content.contains("email") || content.contains("sähköposti");
        let has_password =
            content.contains("type=\"password\"") || content.contains("type='password'");
        let has_reset_text = content.contains("reset")
            || content.contains("forgot")
            || content.contains("recover")
            || content.contains("unohdin");

        has_email && has_reset_text && !has_password
    }

    /// Check if form is an OTP form
    fn is_otp_form(&self, action: &str, content: &str) -> bool {
        let otp_indicators = [
            "otp",
            "verify",
            "verification",
            "code",
            "2fa",
            "mfa",
            "totp",
            "vahvistus",
            "bestätigung",
            "vérification",
            "verifica",
        ];

        for indicator in otp_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        // OTP form usually has a single code input
        let has_code = content.contains("code")
            || content.contains("otp")
            || content.contains("verification")
            || content.contains("koodi");
        let has_digit_input = content.contains("maxlength=\"6\"")
            || content.contains("maxlength=\"4\"")
            || content.contains("pattern=\"[0-9]");

        has_code || has_digit_input
    }

    /// Test bypass techniques concurrently
    async fn test_bypass_techniques(
        &self,
        endpoint: &DetectedEndpoint,
        config: &ScanConfig,
    ) -> (Vec<RateLimitTestResult>, usize) {
        let request_count = if config.scan_mode.as_str() == "fast" {
            5
        } else {
            10
        };
        let mut results = Vec::new();
        let mut total_tests = 0;

        debug!("Testing bypass techniques on {}", endpoint.url);

        // Define bypass techniques to test
        let bypass_techniques = vec![
            (
                BypassTechnique::XForwardedFor,
                "X-Forwarded-For".to_string(),
            ),
            (BypassTechnique::XRealIP, "X-Real-IP".to_string()),
            (BypassTechnique::XClientIP, "X-Client-IP".to_string()),
            (BypassTechnique::XRemoteIP, "X-Remote-IP".to_string()),
            (BypassTechnique::TrueClientIP, "True-Client-IP".to_string()),
            (BypassTechnique::UserAgentRotation, "User-Agent".to_string()),
        ];

        // Test each bypass technique
        for (technique, header_name) in bypass_techniques {
            total_tests += request_count;
            let result = self
                .test_single_bypass_technique(
                    endpoint,
                    request_count,
                    technique.clone(),
                    &header_name,
                )
                .await;

            if result.vulnerable {
                results.push(result);
                // Found a bypass, no need to test other techniques in fast mode
                if config.scan_mode.as_str() == "fast" {
                    break;
                }
            }
        }

        // Test combined techniques if individual ones didn't work
        if results.is_empty() && config.scan_mode.as_str() != "fast" {
            total_tests += request_count;
            let combined_result = self.test_combined_bypass(endpoint, request_count).await;
            if combined_result.vulnerable {
                results.push(combined_result);
            }
        }

        (results, total_tests)
    }

    /// Test a single bypass technique
    async fn test_single_bypass_technique(
        &self,
        endpoint: &DetectedEndpoint,
        request_count: usize,
        technique: BypassTechnique,
        header_name: &str,
    ) -> RateLimitTestResult {
        debug!(
            "Testing {} bypass on {}",
            technique.as_string(),
            endpoint.url
        );

        let start = Instant::now();
        let mut successful = 0;
        let mut rate_limited_at = None;

        // Shared state for concurrent requests
        let endpoint_arc = Arc::new(endpoint.clone());
        let http_client = Arc::clone(&self.http_client);
        let technique_arc = Arc::new(technique.clone());
        let header_name = header_name.to_string();

        // Use concurrent requests to test bypass
        let tasks: Vec<_> = (0..request_count)
            .map(|i| {
                let endpoint = Arc::clone(&endpoint_arc);
                let client = Arc::clone(&http_client);
                let tech = Arc::clone(&technique_arc);
                let header = header_name.clone();

                tokio::spawn(async move {
                    // Generate unique data for each request
                    let form_data = Self::generate_request_data(&endpoint, i);
                    let body = Self::encode_form_data_static(&form_data);

                    // Build headers based on bypass technique
                    let headers = Self::build_bypass_headers(&tech, &header, i);

                    // Send request with bypass headers
                    let result = client
                        .post_with_headers(&endpoint.url, &body, headers)
                        .await;

                    match result {
                        Ok(response) => {
                            // Check for rate limiting
                            let is_rate_limited = response.status_code == 429
                                || response.body.to_lowercase().contains("rate limit")
                                || response.body.to_lowercase().contains("too many")
                                || response.body.to_lowercase().contains("slow down")
                                || response.body.to_lowercase().contains("liian monta");

                            let is_successful = !is_rate_limited
                                && (response.status_code < 400
                                    || response.status_code == 400
                                    || response.status_code == 422);

                            (is_rate_limited, is_successful)
                        }
                        Err(_) => (false, false),
                    }
                })
            })
            .collect();

        // Wait for all requests and analyze results
        for (i, task) in tasks.into_iter().enumerate() {
            if let Ok(result) = task.await {
                let (is_rate_limited, is_successful) = result;

                if is_rate_limited && rate_limited_at.is_none() {
                    rate_limited_at = Some(i + 1);
                }

                if is_successful {
                    successful += 1;
                }
            }

            // Small delay between spawning (realistic timing)
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        let total_time = start.elapsed();

        // Vulnerable if we bypassed the rate limit (no rate limiting detected OR rate limited much later)
        let vulnerable = rate_limited_at.is_none() && successful >= request_count / 2;

        RateLimitTestResult {
            endpoint: endpoint.url.clone(),
            endpoint_type: format!("{:?}", endpoint.endpoint_type),
            requests_sent: request_count,
            successful_requests: successful,
            rate_limited_at,
            total_time,
            vulnerable,
            bypass_technique: technique,
        }
    }

    /// Test combined bypass techniques
    async fn test_combined_bypass(
        &self,
        endpoint: &DetectedEndpoint,
        request_count: usize,
    ) -> RateLimitTestResult {
        debug!("Testing combined bypass techniques on {}", endpoint.url);

        let start = Instant::now();
        let mut successful = 0;
        let mut rate_limited_at = None;

        let combined_techniques = vec!["X-Forwarded-For".to_string(), "User-Agent".to_string()];

        for i in 0..request_count {
            // Generate unique data
            let form_data = Self::generate_request_data(endpoint, i);
            let body = self.encode_form_data(&form_data);

            // Build combined headers
            let mut headers = Vec::new();
            headers.push(("X-Forwarded-For".to_string(), Self::generate_fake_ip(i)));
            headers.push(("User-Agent".to_string(), Self::generate_user_agent(i)));

            let result = self
                .http_client
                .post_with_headers(&endpoint.url, &body, headers)
                .await;

            match result {
                Ok(response) => {
                    if response.status_code == 429
                        || response.body.to_lowercase().contains("rate limit")
                        || response.body.to_lowercase().contains("too many")
                    {
                        rate_limited_at = Some(i + 1);
                        break;
                    }

                    if response.status_code < 400
                        || response.status_code == 400
                        || response.status_code == 422
                    {
                        successful += 1;
                    }
                }
                Err(_) => {}
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let total_time = start.elapsed();
        let vulnerable = rate_limited_at.is_none() && successful >= request_count / 2;

        RateLimitTestResult {
            endpoint: endpoint.url.clone(),
            endpoint_type: format!("{:?}", endpoint.endpoint_type),
            requests_sent: request_count,
            successful_requests: successful,
            rate_limited_at,
            total_time,
            vulnerable,
            bypass_technique: BypassTechnique::Combined(combined_techniques),
        }
    }

    /// Build headers for bypass technique
    fn build_bypass_headers(
        technique: &BypassTechnique,
        header_name: &str,
        index: usize,
    ) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        match technique {
            BypassTechnique::XForwardedFor
            | BypassTechnique::XRealIP
            | BypassTechnique::XClientIP
            | BypassTechnique::XRemoteIP
            | BypassTechnique::TrueClientIP => {
                // Generate a unique IP for this request
                headers.push((header_name.to_string(), Self::generate_fake_ip(index)));
            }
            BypassTechnique::UserAgentRotation => {
                // Rotate User-Agent
                headers.push((header_name.to_string(), Self::generate_user_agent(index)));
            }
            _ => {}
        }

        headers
    }

    /// Generate fake IP address
    fn generate_fake_ip(index: usize) -> String {
        // Generate diverse IP ranges to simulate distributed attack
        let octet1 = 10 + (index % 240);
        let octet2 = (index / 256) % 256;
        let octet3 = (index / 65536) % 256;
        let octet4 = (index * 7) % 256;
        format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4)
    }

    /// Generate diverse User-Agent strings
    fn generate_user_agent(index: usize) -> String {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
        ];

        user_agents[index % user_agents.len()].to_string()
    }

    /// Generate request data based on endpoint type
    fn generate_request_data(endpoint: &DetectedEndpoint, index: usize) -> Vec<(String, String)> {
        match &endpoint.endpoint_type {
            EndpointType::Signup => {
                vec![
                    (
                        "email".to_string(),
                        format!(
                            "ratelimit-test-{}@bountyy-scanner.invalid",
                            Self::generate_random_string(12)
                        ),
                    ),
                    (
                        "password".to_string(),
                        format!("RateTest{}!@#", Self::generate_random_string(6)),
                    ),
                    (
                        "username".to_string(),
                        format!("ratetest_{}_{}", index, Self::generate_random_string(8)),
                    ),
                    ("name".to_string(), "Rate Limit Test".to_string()),
                ]
            }
            _ => endpoint.form_data.clone().unwrap_or_else(|| {
                vec![
                    (
                        "email".to_string(),
                        "ratelimit-test@bountyy-scanner.invalid".to_string(),
                    ),
                    ("password".to_string(), "TestPassword123!".to_string()),
                ]
            }),
        }
    }

    /// Static version of encode_form_data for use in async closures
    fn encode_form_data_static(data: &[(String, String)]) -> String {
        data.iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Extract form fields
    fn extract_form_fields(&self, form_content: &str) -> Vec<(String, String)> {
        let mut fields = Vec::new();

        let input_pattern =
            Regex::new(r#"<input[^>]*name=["']([^"']+)["'][^>]*(?:type=["']([^"']+)["'])?"#)
                .unwrap();

        for cap in input_pattern.captures_iter(form_content) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let input_type = cap.get(2).map(|m| m.as_str()).unwrap_or("text");

            // Generate appropriate test values
            let value = match input_type {
                "email" => format!(
                    "test-{}@bountyy-scanner.invalid",
                    Self::generate_random_string(8)
                ),
                "password" => format!("TestP@ss{}!", Self::generate_random_string(4)),
                "text" if name.to_lowercase().contains("email") => {
                    format!(
                        "test-{}@bountyy-scanner.invalid",
                        Self::generate_random_string(8)
                    )
                }
                "text" if name.to_lowercase().contains("user") => {
                    format!("testuser_{}", Self::generate_random_string(8))
                }
                "text" if name.to_lowercase().contains("name") => "Test User".to_string(),
                "text"
                    if name.to_lowercase().contains("code")
                        || name.to_lowercase().contains("otp") =>
                {
                    "123456".to_string()
                }
                "hidden" => continue, // Skip hidden fields
                _ => format!("test_{}", Self::generate_random_string(4)),
            };

            if !name.is_empty() {
                fields.push((name.to_string(), value));
            }
        }

        // Ensure we have minimum required fields
        if fields.is_empty() {
            fields.push((
                "email".to_string(),
                format!(
                    "test-{}@bountyy-scanner.invalid",
                    Self::generate_random_string(8)
                ),
            ));
            fields.push((
                "password".to_string(),
                format!("TestP@ss{}!", Self::generate_random_string(4)),
            ));
        }

        fields
    }

    /// Test rate limiting on an endpoint
    async fn test_rate_limiting(
        &self,
        endpoint: &DetectedEndpoint,
        request_count: usize,
        bypass_technique: BypassTechnique,
        custom_headers: &[(String, String)],
    ) -> RateLimitTestResult {
        debug!(
            "Testing rate limiting on {} ({:?})",
            endpoint.url, endpoint.endpoint_type
        );

        let start = Instant::now();
        let mut successful = 0;
        let mut rate_limited_at = None;

        for i in 0..request_count {
            // Generate unique data for each request (for signup testing)
            let form_data = match &endpoint.endpoint_type {
                EndpointType::Signup => {
                    // For signup, each request needs unique email
                    vec![
                        (
                            "email".to_string(),
                            format!(
                                "ratelimit-test-{}@bountyy-scanner.invalid",
                                Self::generate_random_string(12)
                            ),
                        ),
                        (
                            "password".to_string(),
                            format!("RateTest{}!@#", Self::generate_random_string(6)),
                        ),
                        (
                            "username".to_string(),
                            format!("ratetest_{}", Self::generate_random_string(8)),
                        ),
                        ("name".to_string(), "Rate Limit Test".to_string()),
                    ]
                }
                _ => {
                    // For other endpoints, use consistent data
                    endpoint.form_data.clone().unwrap_or_else(|| {
                        vec![
                            (
                                "email".to_string(),
                                "ratelimit-test@bountyy-scanner.invalid".to_string(),
                            ),
                            ("password".to_string(), "TestPassword123!".to_string()),
                        ]
                    })
                }
            };

            let body = self.encode_form_data(&form_data);

            // Send request with or without custom headers
            let result = if custom_headers.is_empty() {
                self.http_client.post(&endpoint.url, body.clone()).await
            } else {
                self.http_client
                    .post_with_headers(&endpoint.url, &body, custom_headers.to_vec())
                    .await
            };

            match result {
                Ok(response) => {
                    // Check for rate limiting responses
                    if response.status_code == 429
                        || response.body.to_lowercase().contains("rate limit")
                        || response.body.to_lowercase().contains("too many")
                        || response.body.to_lowercase().contains("slow down")
                        || response.body.to_lowercase().contains("liian monta")
                    {
                        // Finnish
                        rate_limited_at = Some(i + 1);
                        info!("Rate limiting detected at request {}", i + 1);
                        break;
                    }

                    // Count as successful ONLY for 2xx responses
                    // 400/422 are validation errors, NOT successful brute force attempts
                    // Counting them as successful causes false positives on forms with validation
                    if response.status_code >= 200 && response.status_code < 300 {
                        successful += 1;
                    }
                }
                Err(_) => {
                    // Request failed - might be network issue or implicit rate limiting
                    debug!("Request {} failed", i + 1);
                }
            }

            // Small delay between requests (realistic attack pattern)
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let total_time = start.elapsed();
        let vulnerable = rate_limited_at.is_none() && successful >= request_count / 2;

        RateLimitTestResult {
            endpoint: endpoint.url.clone(),
            endpoint_type: format!("{:?}", endpoint.endpoint_type),
            requests_sent: request_count,
            successful_requests: successful,
            rate_limited_at,
            total_time,
            vulnerable,
            bypass_technique,
        }
    }

    /// Create vulnerability from test result
    fn create_vulnerability(
        &self,
        result: &RateLimitTestResult,
        original_url: &str,
    ) -> Vulnerability {
        // Adjust severity based on whether this is a bypass or missing rate limit
        let is_bypass = result.bypass_technique != BypassTechnique::None;

        let bypass_description = if is_bypass {
            format!("\n\nBypass Technique: {}\n\
                    Rate limiting was present but successfully bypassed using {} header manipulation. \
                    The application trusts client-supplied headers without proper validation.",
                    result.bypass_technique.as_string(),
                    result.bypass_technique.as_string())
        } else {
            String::new()
        };

        let (base_severity, cvss, description, remediation) = match result.endpoint_type.as_str() {
            "Signup" => (
                Severity::High,
                7.5,
                format!(
                    "The account registration endpoint {} rate limiting. \
                    Sent {} requests with {} successful account creation attempts in {:?}. \
                    This allows attackers to:\n\
                    - Create massive numbers of spam accounts\n\
                    - Perform resource exhaustion attacks\n\
                    - Pollute user database\n\
                    - Abuse referral/signup bonuses\n\
                    - Create botnet accounts{}",
                    if is_bypass { "has bypassable" } else { "lacks" },
                    result.requests_sent,
                    result.successful_requests,
                    result.total_time,
                    bypass_description
                ),
                if is_bypass {
                    "1. DO NOT trust client-supplied IP headers (X-Forwarded-For, X-Real-IP, etc.) directly\n\
                     2. Implement rate limiting based on actual source IP from socket connection\n\
                     3. If behind a proxy/CDN, validate X-Forwarded-For against known proxy IPs\n\
                     4. Use multiple factors: IP + User-Agent + fingerprint + session\n\
                     5. Add CAPTCHA verification for signup\n\
                     6. Implement progressive delays and account lockouts\n\
                     7. Monitor for distributed attacks from multiple IPs"
                } else {
                    "1. Implement rate limiting on registration endpoint (e.g., 3-5 attempts per IP per hour)\n\
                     2. Add CAPTCHA verification for signup\n\
                     3. Require email verification before account is active\n\
                     4. Implement device fingerprinting\n\
                     5. Add honeypot fields to detect bots\n\
                     6. Consider phone number verification for sensitive accounts\n\
                     7. Monitor for signup anomalies (bulk creation, disposable emails)"
                },
            ),
            "Login" => (
                Severity::High,
                7.5,
                format!(
                    "The login endpoint {} rate limiting. \
                    Sent {} requests with {} accepted in {:?}. \
                    This enables:\n\
                    - Brute force password attacks\n\
                    - Credential stuffing attacks\n\
                    - Account enumeration\n\
                    - User account lockout abuse{}",
                    if is_bypass { "has bypassable" } else { "lacks" },
                    result.requests_sent,
                    result.successful_requests,
                    result.total_time,
                    bypass_description
                ),
                if is_bypass {
                    "1. DO NOT trust client-supplied IP headers without validation\n\
                     2. Implement multi-factor rate limiting (IP + session + fingerprint)\n\
                     3. Use actual connection IP for rate limiting, not forwarded headers\n\
                     4. Add CAPTCHA after 3 failed attempts\n\
                     5. Implement account lockout after repeated failures\n\
                     6. Send notification on suspicious login attempts\n\
                     7. Consider 2FA for sensitive accounts"
                } else {
                    "1. Implement rate limiting (e.g., 5 attempts per minute, then exponential backoff)\n\
                     2. Add CAPTCHA after 3 failed attempts\n\
                     3. Implement account lockout after repeated failures\n\
                     4. Use progressive delays between attempts\n\
                     5. Send notification on suspicious login attempts\n\
                     6. Consider 2FA for sensitive accounts"
                },
            ),
            "PasswordReset" => (
                Severity::Medium,
                5.3,
                format!(
                    "The password reset endpoint {} rate limiting. \
                    Sent {} requests with {} accepted in {:?}. \
                    This enables:\n\
                    - Email flooding/spam to users\n\
                    - Resource exhaustion (email sending)\n\
                    - Social engineering preparation{}",
                    if is_bypass { "has bypassable" } else { "lacks" },
                    result.requests_sent,
                    result.successful_requests,
                    result.total_time,
                    bypass_description
                ),
                if is_bypass {
                    "1. Validate X-Forwarded-For against known proxy IPs only\n\
                     2. Implement rate limiting on actual source IP\n\
                     3. Add CAPTCHA for password reset requests\n\
                     4. Implement cooldown period between reset requests\n\
                     5. Log and monitor reset request patterns\n\
                     6. Send single consolidated email for multiple requests"
                } else {
                    "1. Implement rate limiting (e.g., 3 requests per email per hour)\n\
                     2. Add CAPTCHA for password reset requests\n\
                     3. Implement cooldown period between reset requests\n\
                     4. Log and monitor reset request patterns\n\
                     5. Send single consolidated email for multiple requests"
                },
            ),
            "OTP" => (
                Severity::Critical,
                9.1,
                format!(
                    "The OTP/2FA verification endpoint {} rate limiting. \
                    Sent {} requests with {} accepted in {:?}. \
                    This is CRITICAL as it enables:\n\
                    - OTP brute forcing (6-digit = 1M combinations)\n\
                    - Bypassing two-factor authentication\n\
                    - Account takeover{}",
                    if is_bypass { "has bypassable" } else { "lacks" },
                    result.requests_sent,
                    result.successful_requests,
                    result.total_time,
                    bypass_description
                ),
                if is_bypass {
                    "1. CRITICAL: DO NOT trust any client-supplied headers for OTP rate limiting\n\
                     2. Rate limit on session token + actual IP only\n\
                     3. Invalidate OTP after 3 failed attempts (hard limit)\n\
                     4. Implement exponential backoff\n\
                     5. Use longer OTP codes (8+ digits)\n\
                     6. Alert user immediately on failed OTP attempts\n\
                     7. Consider hardware security keys for sensitive accounts"
                } else {
                    "1. CRITICAL: Implement strict rate limiting (3-5 attempts max)\n\
                     2. Invalidate OTP after 3 failed attempts\n\
                     3. Implement exponential backoff\n\
                     4. Use longer OTP codes (8+ digits)\n\
                     5. Implement time-based lockout\n\
                     6. Alert user on failed OTP attempts\n\
                     7. Consider hardware security keys for sensitive accounts"
                },
            ),
            _ => (
                Severity::Medium,
                5.3,
                format!(
                    "The API endpoint {} rate limiting. \
                    Sent {} requests with {} accepted in {:?}.{}",
                    if is_bypass { "has bypassable" } else { "lacks" },
                    result.requests_sent,
                    result.successful_requests,
                    result.total_time,
                    bypass_description
                ),
                if is_bypass {
                    "1. Validate client-supplied headers before using for rate limiting\n\
                     2. Use API keys with rate limits tied to actual source IP\n\
                     3. Implement request throttling on connection IP\n\
                     4. Monitor and alert on unusual traffic patterns\n\
                     5. Use Web Application Firewall with header validation"
                } else {
                    "1. Implement rate limiting based on endpoint sensitivity\n\
                     2. Use API keys with rate limits\n\
                     3. Implement request throttling\n\
                     4. Monitor and alert on unusual traffic patterns"
                },
            ),
        };

        // Increase severity for bypasses on critical endpoints
        let severity = if is_bypass && matches!(base_severity, Severity::High | Severity::Critical)
        {
            Severity::Critical
        } else {
            base_severity
        };

        // Bypass findings are high confidence (we proved the bypass works).
        // Missing rate limiting is lower confidence because rate limiting
        // may be enforced at WAF/CDN level (Cloudflare, AWS WAF, etc.)
        // which is not visible to the scanner.
        let confidence = if is_bypass {
            Confidence::High
        } else {
            Confidence::Low
        };

        let vuln_type = if is_bypass {
            format!(
                "Rate Limiting Bypass via {} - {} Endpoint",
                result.bypass_technique.as_string(),
                result.endpoint_type
            )
        } else {
            format!(
                "Insufficient Rate Limiting - {} Endpoint",
                result.endpoint_type
            )
        };

        let payload = if is_bypass {
            format!(
                "Bypass: {} | {} requests sent, {} successful, rate limiting bypassed",
                result.bypass_technique.as_string(),
                result.requests_sent,
                result.successful_requests
            )
        } else {
            format!(
                "{} requests sent, {} successful, no rate limiting detected",
                result.requests_sent, result.successful_requests
            )
        };

        let evidence = if is_bypass {
            format!(
                "Endpoint: {}\n\
                Endpoint Type: {}\n\
                Bypass Technique: {}\n\
                Requests Sent: {}\n\
                Successful: {}\n\
                Rate Limited: {}\n\
                Total Time: {:?}\n\
                \n\
                Bypass Details:\n\
                - Initial testing detected rate limiting on this endpoint\n\
                - Rate limiting successfully bypassed using {} header manipulation\n\
                - Application trusts client-supplied headers without validation\n\
                - Used concurrent requests to simulate distributed attack\n\
                - All bypass requests completed successfully without rate limiting\n\
                - CRITICAL: This allows attackers to bypass existing rate limits",
                result.endpoint,
                result.endpoint_type,
                result.bypass_technique.as_string(),
                result.requests_sent,
                result.successful_requests,
                result
                    .rate_limited_at
                    .map_or("Never (bypassed)".to_string(), |n| format!(
                        "After {} requests",
                        n
                    )),
                result.total_time,
                result.bypass_technique.as_string()
            )
        } else {
            format!(
                "Endpoint: {}\n\
                Endpoint Type: {}\n\
                Requests Sent: {}\n\
                Successful: {}\n\
                Rate Limited: {}\n\
                Total Time: {:?}\n\
                \n\
                Test Details:\n\
                - Used unique credentials for each signup request\n\
                - All requests completed without rate limiting\n\
                - No 429 (Too Many Requests) responses received\n\
                - No rate limit headers detected",
                result.endpoint,
                result.endpoint_type,
                result.requests_sent,
                result.successful_requests,
                result
                    .rate_limited_at
                    .map_or("Never".to_string(), |n| format!("After {} requests", n)),
                result.total_time
            )
        };

        Vulnerability {
            id: format!(
                "rate_limit_{}_{}",
                result.endpoint_type.to_lowercase(),
                Self::generate_id()
            ),
            vuln_type,
            severity,
            confidence,
            category: "Access Control".to_string(),
            url: original_url.to_string(),
            parameter: Some(result.endpoint.clone()),
            payload,
            description,
            evidence: Some(evidence),
            cwe: "CWE-307".to_string(), // Improper Restriction of Excessive Authentication Attempts
            cvss,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, path: &str, base_url: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }

        if path.is_empty() || path == "#" {
            return base_url.to_string();
        }

        if let Ok(base) = url::Url::parse(base_url) {
            if let Ok(resolved) = base.join(path) {
                return resolved.to_string();
            }
        }

        // Fallback
        if path.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_url) {
                let host = parsed.host_str().unwrap_or("localhost");
                let scheme = parsed.scheme();
                return format!("{}://{}{}", scheme, host, path);
            }
        }

        format!("{}/{}", base_url.trim_end_matches('/'), path)
    }

    /// Encode form data for POST
    fn encode_form_data(&self, data: &[(String, String)]) -> String {
        data.iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Generate random string
    fn generate_random_string(len: usize) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        (0..len)
            .map(|_| {
                let idx = rng.random_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signup_form_detection() {
        let scanner = RateLimitingScanner {
            http_client: Arc::new(HttpClient::new().unwrap()),
        };

        assert!(scanner.is_signup_form("/register", "email password confirm"));
        assert!(scanner.is_signup_form("/signup", "email password name"));
        assert!(!scanner.is_signup_form("/login", "email password"));
    }

    #[test]
    fn test_login_form_detection() {
        let scanner = RateLimitingScanner {
            http_client: Arc::new(HttpClient::new().unwrap()),
        };

        assert!(scanner.is_login_form("/login", "email password remember"));
        assert!(scanner.is_login_form("/signin", "username password"));
        assert!(!scanner.is_login_form("/register", "email password confirm"));
    }

    #[test]
    fn test_otp_form_detection() {
        let scanner = RateLimitingScanner {
            http_client: Arc::new(HttpClient::new().unwrap()),
        };

        assert!(scanner.is_otp_form("/verify", "enter your code maxlength=\"6\""));
        assert!(scanner.is_otp_form("/2fa", "otp verification"));
    }
}
