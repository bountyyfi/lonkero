// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Context-Aware Timing Attack Scanner
 * Detects timing-based side channel vulnerabilities
 *
 * Detects:
 * - Username enumeration via timing
 * - Password verification timing differences
 * - Token validation timing leaks
 * - Database query timing inference
 * - Cryptographic timing vulnerabilities
 * - HMAC/signature verification timing
 *
 * Features:
 * - High-precision timing measurement
 * - Statistical analysis (mean, std dev, t-test)
 * - Network jitter compensation
 * - Outlier removal
 * - Context-aware endpoint detection
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::detection_helpers::{AppCharacteristics, endpoint_exists};
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Minimum samples for statistical analysis
const MIN_SAMPLES: usize = 10;
/// Default samples per test
const DEFAULT_SAMPLES: usize = 15;
/// Maximum samples for thorough testing
const MAX_SAMPLES: usize = 20;
/// Significance threshold (number of standard deviations)
const SIGNIFICANCE_THRESHOLD: f64 = 2.0;
/// Minimum timing difference to consider (milliseconds)
const MIN_TIMING_DIFF_MS: f64 = 5.0;
/// Network jitter tolerance (milliseconds)
const JITTER_TOLERANCE_MS: f64 = 10.0;

/// Timing attack detection type
#[derive(Debug, Clone, PartialEq)]
pub enum TimingAttackType {
    UsernameEnumeration,
    PasswordVerification,
    TokenValidation,
    DatabaseQuery,
    CryptographicOperation,
    HmacVerification,
    JwtValidation,
    ApiKeyValidation,
}

impl TimingAttackType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UsernameEnumeration => "Username Enumeration",
            Self::PasswordVerification => "Password Verification",
            Self::TokenValidation => "Token Validation",
            Self::DatabaseQuery => "Database Query",
            Self::CryptographicOperation => "Cryptographic Operation",
            Self::HmacVerification => "HMAC Verification",
            Self::JwtValidation => "JWT Validation",
            Self::ApiKeyValidation => "API Key Validation",
        }
    }

    fn cwe(&self) -> &'static str {
        match self {
            Self::UsernameEnumeration => "CWE-208",
            Self::PasswordVerification => "CWE-208",
            Self::TokenValidation => "CWE-208",
            Self::DatabaseQuery => "CWE-203",
            Self::CryptographicOperation => "CWE-208",
            Self::HmacVerification => "CWE-208",
            Self::JwtValidation => "CWE-208",
            Self::ApiKeyValidation => "CWE-203",
        }
    }
}

/// Statistical analysis result for timing measurements
#[derive(Debug, Clone)]
struct TimingStatistics {
    /// Sample size
    sample_count: usize,
    /// Mean response time in milliseconds
    mean_ms: f64,
    /// Standard deviation in milliseconds
    std_dev_ms: f64,
    /// Minimum response time
    min_ms: f64,
    /// Maximum response time
    max_ms: f64,
    /// Median response time
    median_ms: f64,
    /// Cleaned samples (outliers removed)
    cleaned_samples: Vec<f64>,
}

impl TimingStatistics {
    fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.len() < 3 {
            return None;
        }

        // Remove outliers using IQR method
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let q1_idx = sorted.len() / 4;
        let q3_idx = (3 * sorted.len()) / 4;
        let q1 = sorted[q1_idx];
        let q3 = sorted[q3_idx];
        let iqr = q3 - q1;
        let lower_bound = q1 - 1.5 * iqr;
        let upper_bound = q3 + 1.5 * iqr;

        let cleaned: Vec<f64> = sorted
            .iter()
            .copied()
            .filter(|&x| x >= lower_bound && x <= upper_bound)
            .collect();

        if cleaned.len() < 3 {
            return None;
        }

        let n = cleaned.len() as f64;
        let mean = cleaned.iter().sum::<f64>() / n;
        let variance = cleaned.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        let std_dev = variance.sqrt();

        let mut cleaned_sorted = cleaned.clone();
        cleaned_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if cleaned_sorted.len() % 2 == 0 {
            let mid = cleaned_sorted.len() / 2;
            (cleaned_sorted[mid - 1] + cleaned_sorted[mid]) / 2.0
        } else {
            cleaned_sorted[cleaned_sorted.len() / 2]
        };

        Some(Self {
            sample_count: cleaned.len(),
            mean_ms: mean,
            std_dev_ms: std_dev,
            min_ms: *cleaned_sorted.first()?,
            max_ms: *cleaned_sorted.last()?,
            median_ms: median,
            cleaned_samples: cleaned,
        })
    }
}

/// Result of comparing two timing distributions
#[derive(Debug, Clone)]
struct TimingComparison {
    /// Statistics for first group
    group_a: TimingStatistics,
    /// Statistics for second group
    group_b: TimingStatistics,
    /// Difference in means (ms)
    mean_diff_ms: f64,
    /// T-statistic value
    t_statistic: f64,
    /// Is the difference statistically significant?
    is_significant: bool,
    /// Estimated timing leak magnitude
    leak_magnitude_ms: f64,
}

impl TimingComparison {
    fn from_stats(group_a: TimingStatistics, group_b: TimingStatistics) -> Self {
        let mean_diff = (group_a.mean_ms - group_b.mean_ms).abs();

        // Welch's t-test for unequal variances
        let var_a = group_a.std_dev_ms.powi(2);
        let var_b = group_b.std_dev_ms.powi(2);
        let n_a = group_a.sample_count as f64;
        let n_b = group_b.sample_count as f64;

        let se = ((var_a / n_a) + (var_b / n_b)).sqrt();
        let t_statistic = if se > 0.0 {
            mean_diff / se
        } else {
            0.0
        };

        // Check if difference is significant
        // Using 2 standard deviations as threshold (approx. 95% confidence)
        let is_significant = t_statistic > SIGNIFICANCE_THRESHOLD
            && mean_diff > MIN_TIMING_DIFF_MS
            && mean_diff > (group_a.std_dev_ms + group_b.std_dev_ms) / 2.0;

        Self {
            group_a,
            group_b,
            mean_diff_ms: mean_diff,
            t_statistic,
            is_significant,
            leak_magnitude_ms: mean_diff,
        }
    }
}

/// Detected authentication endpoint
#[derive(Debug, Clone)]
struct AuthEndpoint {
    url: String,
    endpoint_type: AuthEndpointType,
    method: String,
    username_field: Option<String>,
    password_field: Option<String>,
    token_field: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum AuthEndpointType {
    Login,
    Register,
    PasswordReset,
    TokenVerification,
    ApiAuthentication,
    OtpVerification,
}

pub struct TimingAttackScanner {
    http_client: Arc<HttpClient>,
}

impl TimingAttackScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // PREMIUM FEATURE: Timing attack scanner requires Professional license
        if !crate::license::is_feature_available("timing_attacks") {
            info!("[TimingAttack] Feature requires Professional license or higher");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[TimingAttack] Starting context-aware timing attack scan");

        // First, get baseline and detect app characteristics
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[TimingAttack] Failed to fetch base URL: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        let characteristics = AppCharacteristics::from_response(&response, url);

        // Skip timing tests if no authentication detected
        if !characteristics.has_authentication && !characteristics.has_jwt && !characteristics.has_oauth {
            info!("[TimingAttack] No authentication detected - skipping timing attack tests");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[TimingAttack] Authentication detected - proceeding with timing analysis");

        // Detect authentication endpoints
        let auth_endpoints = self.detect_auth_endpoints(url, &response.body).await;

        if auth_endpoints.is_empty() {
            info!("[TimingAttack] No authentication endpoints found");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[TimingAttack] Found {} potential auth endpoints", auth_endpoints.len());

        // Determine sample count based on scan mode
        let sample_count = match config.scan_mode.as_str() {
            "fast" => MIN_SAMPLES,
            "thorough" | "insane" => MAX_SAMPLES,
            _ => DEFAULT_SAMPLES,
        };

        // Test each authentication endpoint
        for endpoint in &auth_endpoints {
            match endpoint.endpoint_type {
                AuthEndpointType::Login => {
                    // Test username enumeration via timing
                    let (vulns, tests) = self
                        .test_username_enumeration(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;

                    // Test password verification timing
                    let (vulns, tests) = self
                        .test_password_timing(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;
                }
                AuthEndpointType::TokenVerification | AuthEndpointType::OtpVerification => {
                    // Test token validation timing
                    let (vulns, tests) = self
                        .test_token_timing(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;
                }
                AuthEndpointType::ApiAuthentication => {
                    // Test API key validation timing
                    let (vulns, tests) = self
                        .test_api_key_timing(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;
                }
                AuthEndpointType::PasswordReset => {
                    // Test email enumeration via timing
                    let (vulns, tests) = self
                        .test_email_enumeration(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;
                }
                AuthEndpointType::Register => {
                    // Test existing user detection via timing
                    let (vulns, tests) = self
                        .test_registration_timing(&endpoint, sample_count)
                        .await?;
                    vulnerabilities.extend(vulns);
                    tests_run += tests;
                }
            }
        }

        // Test JWT timing if JWT is detected
        if characteristics.has_jwt {
            let (vulns, tests) = self.test_jwt_timing(url, sample_count).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test cryptographic timing on API endpoints
        if characteristics.is_api || characteristics.has_oauth {
            let (vulns, tests) = self.test_hmac_timing(url, sample_count).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test database query timing on search/filter endpoints
        let (vulns, tests) = self.test_database_timing(url, &response.body, sample_count).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        info!(
            "[TimingAttack] Scan complete: {} vulnerabilities, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect authentication endpoints from page content
    async fn detect_auth_endpoints(&self, base_url: &str, html: &str) -> Vec<AuthEndpoint> {
        let mut endpoints = Vec::new();
        let html_lower = html.to_lowercase();

        // Pattern to find forms
        let form_regex = Regex::new(
            r#"<form[^>]*action=["']([^"']+)["'][^>]*>([\s\S]*?)</form>"#
        ).unwrap();

        for cap in form_regex.captures_iter(html) {
            let action = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let form_content = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let form_content_lower = form_content.to_lowercase();

            let action_lower = action.to_lowercase();
            let resolved_url = self.resolve_url(action, base_url);

            // Detect login forms
            if self.is_login_form(&action_lower, &form_content_lower) {
                let (username_field, password_field) = self.extract_credential_fields(form_content);
                endpoints.push(AuthEndpoint {
                    url: resolved_url,
                    endpoint_type: AuthEndpointType::Login,
                    method: "POST".to_string(),
                    username_field,
                    password_field,
                    token_field: None,
                });
            }
            // Detect registration forms
            else if self.is_registration_form(&action_lower, &form_content_lower) {
                let (username_field, password_field) = self.extract_credential_fields(form_content);
                endpoints.push(AuthEndpoint {
                    url: resolved_url,
                    endpoint_type: AuthEndpointType::Register,
                    method: "POST".to_string(),
                    username_field,
                    password_field,
                    token_field: None,
                });
            }
            // Detect password reset forms
            else if self.is_password_reset_form(&action_lower, &form_content_lower) {
                endpoints.push(AuthEndpoint {
                    url: resolved_url,
                    endpoint_type: AuthEndpointType::PasswordReset,
                    method: "POST".to_string(),
                    username_field: self.extract_email_field(form_content),
                    password_field: None,
                    token_field: None,
                });
            }
            // Detect OTP/token verification forms
            else if self.is_token_verification_form(&action_lower, &form_content_lower) {
                endpoints.push(AuthEndpoint {
                    url: resolved_url,
                    endpoint_type: AuthEndpointType::OtpVerification,
                    method: "POST".to_string(),
                    username_field: None,
                    password_field: None,
                    token_field: self.extract_token_field(form_content),
                });
            }
        }

        // Look for API endpoints in JavaScript
        let api_patterns = vec![
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?login)['\"]"#, AuthEndpointType::Login),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?signin)['\"]"#, AuthEndpointType::Login),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?authenticate)['\"]"#, AuthEndpointType::Login),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?register)['\"]"#, AuthEndpointType::Register),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?signup)['\"]"#, AuthEndpointType::Register),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?forgot-password)['\"]"#, AuthEndpointType::PasswordReset),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?reset-password)['\"]"#, AuthEndpointType::PasswordReset),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?verify)['\"]"#, AuthEndpointType::TokenVerification),
            (r#"['"](/api/(?:v\d+/)?(?:auth/)?token)['\"]"#, AuthEndpointType::ApiAuthentication),
        ];

        for (pattern, endpoint_type) in api_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    if let Some(path) = cap.get(1) {
                        let url = self.resolve_url(path.as_str(), base_url);
                        if !endpoints.iter().any(|e| e.url == url) {
                            endpoints.push(AuthEndpoint {
                                url,
                                endpoint_type: endpoint_type.clone(),
                                method: "POST".to_string(),
                                username_field: Some("email".to_string()),
                                password_field: Some("password".to_string()),
                                token_field: None,
                            });
                        }
                    }
                }
            }
        }

        endpoints
    }

    /// Test username enumeration via timing analysis
    async fn test_username_enumeration(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing username enumeration on {}", endpoint.url);

        let username_field = endpoint.username_field.as_deref().unwrap_or("email");
        let password_field = endpoint.password_field.as_deref().unwrap_or("password");

        // Test with likely valid username patterns
        let valid_usernames = vec![
            "admin", "user", "test", "administrator", "root",
            "admin@test.com", "user@test.com", "test@test.com",
        ];

        // Test with random/invalid usernames
        let invalid_usernames: Vec<String> = (0..valid_usernames.len())
            .map(|_| Self::generate_random_string(24))
            .collect();

        // Collect timing samples for valid-looking usernames
        let mut valid_times = Vec::new();
        for username in &valid_usernames {
            let timing = self
                .measure_auth_timing(
                    &endpoint.url,
                    &endpoint.method,
                    username_field,
                    username,
                    password_field,
                    "wrongpassword123",
                    sample_count / valid_usernames.len() + 1,
                )
                .await?;
            valid_times.extend(timing);
        }

        // Collect timing samples for random usernames
        let mut invalid_times = Vec::new();
        for username in &invalid_usernames {
            let timing = self
                .measure_auth_timing(
                    &endpoint.url,
                    &endpoint.method,
                    username_field,
                    username,
                    password_field,
                    "wrongpassword123",
                    sample_count / invalid_usernames.len() + 1,
                )
                .await?;
            invalid_times.extend(timing);
        }

        // Statistical analysis
        if let (Some(valid_stats), Some(invalid_stats)) = (
            TimingStatistics::from_samples(&valid_times),
            TimingStatistics::from_samples(&invalid_times),
        ) {
            let comparison = TimingComparison::from_stats(valid_stats.clone(), invalid_stats.clone());

            if comparison.is_significant {
                info!(
                    "[TimingAttack] Username enumeration timing leak detected: {:.2}ms difference",
                    comparison.leak_magnitude_ms
                );

                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::UsernameEnumeration,
                    &comparison,
                    &format!(
                        "Valid usernames responded {:.2}ms {} than invalid usernames",
                        comparison.leak_magnitude_ms,
                        if valid_stats.mean_ms > invalid_stats.mean_ms { "slower" } else { "faster" }
                    ),
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test password verification timing
    async fn test_password_timing(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing password verification timing on {}", endpoint.url);

        let username_field = endpoint.username_field.as_deref().unwrap_or("email");
        let password_field = endpoint.password_field.as_deref().unwrap_or("password");
        let test_username = "timing-test-user@bountyy-scanner.invalid";

        // Test with short passwords (early exit detection)
        let short_passwords: Vec<String> = (0..5).map(|_| Self::generate_random_string(2)).collect();

        // Test with long passwords (full bcrypt computation)
        let long_passwords: Vec<String> = (0..5).map(|_| Self::generate_random_string(72)).collect();

        // Collect timing for short passwords
        let mut short_times = Vec::new();
        for password in &short_passwords {
            let timing = self
                .measure_auth_timing(
                    &endpoint.url,
                    &endpoint.method,
                    username_field,
                    test_username,
                    password_field,
                    password,
                    sample_count / short_passwords.len() + 1,
                )
                .await?;
            short_times.extend(timing);
        }

        // Collect timing for long passwords
        let mut long_times = Vec::new();
        for password in &long_passwords {
            let timing = self
                .measure_auth_timing(
                    &endpoint.url,
                    &endpoint.method,
                    username_field,
                    test_username,
                    password_field,
                    password,
                    sample_count / long_passwords.len() + 1,
                )
                .await?;
            long_times.extend(timing);
        }

        // Statistical analysis
        if let (Some(short_stats), Some(long_stats)) = (
            TimingStatistics::from_samples(&short_times),
            TimingStatistics::from_samples(&long_times),
        ) {
            let comparison = TimingComparison::from_stats(short_stats.clone(), long_stats.clone());

            if comparison.is_significant {
                info!(
                    "[TimingAttack] Password verification timing leak detected: {:.2}ms difference",
                    comparison.leak_magnitude_ms
                );

                // Determine if this suggests early exit or bcrypt timing
                let description = if long_stats.mean_ms > short_stats.mean_ms {
                    format!(
                        "Longer passwords take {:.2}ms more to process, suggesting bcrypt/scrypt timing leak",
                        comparison.leak_magnitude_ms
                    )
                } else {
                    format!(
                        "Short passwords process {:.2}ms faster, suggesting early exit on validation",
                        comparison.leak_magnitude_ms
                    )
                };

                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::PasswordVerification,
                    &comparison,
                    &description,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test token validation timing
    async fn test_token_timing(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 3;

        info!("[TimingAttack] Testing token validation timing on {}", endpoint.url);

        let token_field = endpoint.token_field.as_deref().unwrap_or("token");

        // Test with various token formats
        let short_tokens: Vec<String> = (0..5).map(|_| Self::generate_random_string(6)).collect();
        let correct_format_tokens: Vec<String> = (0..5)
            .map(|_| Self::generate_random_string(32))
            .collect();
        let long_tokens: Vec<String> = (0..5).map(|_| Self::generate_random_string(128)).collect();

        let mut short_times = Vec::new();
        let mut correct_times = Vec::new();
        let mut long_times = Vec::new();

        for token in &short_tokens {
            let timing = self
                .measure_token_timing(&endpoint.url, token_field, token, sample_count / 5)
                .await?;
            short_times.extend(timing);
        }

        for token in &correct_format_tokens {
            let timing = self
                .measure_token_timing(&endpoint.url, token_field, token, sample_count / 5)
                .await?;
            correct_times.extend(timing);
        }

        for token in &long_tokens {
            let timing = self
                .measure_token_timing(&endpoint.url, token_field, token, sample_count / 5)
                .await?;
            long_times.extend(timing);
        }

        // Compare short vs correct format
        if let (Some(short_stats), Some(correct_stats)) = (
            TimingStatistics::from_samples(&short_times),
            TimingStatistics::from_samples(&correct_times),
        ) {
            let comparison = TimingComparison::from_stats(short_stats, correct_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::TokenValidation,
                    &comparison,
                    "Token length affects validation timing, enabling token format discovery",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test API key validation timing
    async fn test_api_key_timing(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing API key validation timing on {}", endpoint.url);

        // Test with different API key formats
        let invalid_keys: Vec<String> = (0..sample_count)
            .map(|_| Self::generate_random_string(32))
            .collect();

        // Keys with correct prefix pattern (if detectable)
        let prefix_keys: Vec<String> = (0..sample_count)
            .map(|_| format!("sk_{}", Self::generate_random_string(28)))
            .collect();

        let mut invalid_times = Vec::new();
        let mut prefix_times = Vec::new();

        for key in &invalid_keys {
            let timing = self.measure_api_key_timing(&endpoint.url, key).await?;
            invalid_times.extend(timing);
        }

        for key in &prefix_keys {
            let timing = self.measure_api_key_timing(&endpoint.url, key).await?;
            prefix_times.extend(timing);
        }

        if let (Some(invalid_stats), Some(prefix_stats)) = (
            TimingStatistics::from_samples(&invalid_times),
            TimingStatistics::from_samples(&prefix_times),
        ) {
            let comparison = TimingComparison::from_stats(invalid_stats, prefix_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::ApiKeyValidation,
                    &comparison,
                    "API key format validation exhibits timing differences",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test email enumeration via timing on password reset
    async fn test_email_enumeration(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing email enumeration on password reset: {}", endpoint.url);

        let email_field = endpoint.username_field.as_deref().unwrap_or("email");

        // Common email patterns that might exist
        let common_emails = vec![
            "admin@test.com",
            "user@test.com",
            "info@test.com",
            "support@test.com",
            "contact@test.com",
        ];

        // Random emails that shouldn't exist
        let random_emails: Vec<String> = (0..5)
            .map(|_| format!("{}@bountyy-scanner.invalid", Self::generate_random_string(24)))
            .collect();

        let mut common_times = Vec::new();
        let mut random_times = Vec::new();

        for email in &common_emails {
            let timing = self
                .measure_form_timing(&endpoint.url, vec![(email_field.to_string(), email.to_string())], sample_count / 5)
                .await?;
            common_times.extend(timing);
        }

        for email in &random_emails {
            let timing = self
                .measure_form_timing(&endpoint.url, vec![(email_field.to_string(), email.to_string())], sample_count / 5)
                .await?;
            random_times.extend(timing);
        }

        if let (Some(common_stats), Some(random_stats)) = (
            TimingStatistics::from_samples(&common_times),
            TimingStatistics::from_samples(&random_times),
        ) {
            let comparison = TimingComparison::from_stats(common_stats, random_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::UsernameEnumeration,
                    &comparison,
                    "Password reset timing reveals whether email exists in system",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test registration endpoint for existing user detection
    async fn test_registration_timing(
        &self,
        endpoint: &AuthEndpoint,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing registration timing on {}", endpoint.url);

        let username_field = endpoint.username_field.as_deref().unwrap_or("email");
        let password_field = endpoint.password_field.as_deref().unwrap_or("password");

        // Common usernames that might exist
        let common_users = vec!["admin", "user", "test", "administrator"];

        // Random usernames that shouldn't exist
        let random_users: Vec<String> = (0..common_users.len())
            .map(|_| Self::generate_random_string(24))
            .collect();

        let mut common_times = Vec::new();
        let mut random_times = Vec::new();

        let password = "TestPass123!";

        for username in &common_users {
            let timing = self
                .measure_form_timing(
                    &endpoint.url,
                    vec![
                        (username_field.to_string(), username.to_string()),
                        (password_field.to_string(), password.to_string()),
                    ],
                    sample_count / common_users.len() + 1,
                )
                .await?;
            common_times.extend(timing);
        }

        for username in &random_users {
            let timing = self
                .measure_form_timing(
                    &endpoint.url,
                    vec![
                        (username_field.to_string(), username.to_string()),
                        (password_field.to_string(), password.to_string()),
                    ],
                    sample_count / random_users.len() + 1,
                )
                .await?;
            random_times.extend(timing);
        }

        if let (Some(common_stats), Some(random_stats)) = (
            TimingStatistics::from_samples(&common_times),
            TimingStatistics::from_samples(&random_times),
        ) {
            let comparison = TimingComparison::from_stats(common_stats, random_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    &endpoint.url,
                    TimingAttackType::UsernameEnumeration,
                    &comparison,
                    "Registration timing reveals whether username/email already exists",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JWT signature verification timing
    async fn test_jwt_timing(
        &self,
        url: &str,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing JWT verification timing");

        // Generate JWTs with different signature lengths
        let short_sig_jwts: Vec<String> = (0..sample_count / 2)
            .map(|_| self.generate_fake_jwt(32))
            .collect();

        let correct_sig_jwts: Vec<String> = (0..sample_count / 2)
            .map(|_| self.generate_fake_jwt(86))
            .collect();

        let mut short_times = Vec::new();
        let mut correct_times = Vec::new();

        for jwt in &short_sig_jwts {
            let timing = self.measure_jwt_timing(url, jwt).await?;
            short_times.extend(timing);
        }

        for jwt in &correct_sig_jwts {
            let timing = self.measure_jwt_timing(url, jwt).await?;
            correct_times.extend(timing);
        }

        if let (Some(short_stats), Some(correct_stats)) = (
            TimingStatistics::from_samples(&short_times),
            TimingStatistics::from_samples(&correct_times),
        ) {
            let comparison = TimingComparison::from_stats(short_stats, correct_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    TimingAttackType::JwtValidation,
                    &comparison,
                    "JWT signature verification exhibits timing differences based on signature format",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test HMAC signature verification timing
    async fn test_hmac_timing(
        &self,
        url: &str,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = sample_count * 2;

        info!("[TimingAttack] Testing HMAC verification timing");

        // Test signature headers
        let signatures_with_correct_prefix: Vec<String> = (0..sample_count / 2)
            .map(|_| format!("sha256={}", Self::generate_hex_string(64)))
            .collect();

        let random_signatures: Vec<String> = (0..sample_count / 2)
            .map(|_| Self::generate_hex_string(64))
            .collect();

        let mut prefix_times = Vec::new();
        let mut random_times = Vec::new();

        for sig in &signatures_with_correct_prefix {
            let timing = self.measure_signature_timing(url, sig).await?;
            prefix_times.extend(timing);
        }

        for sig in &random_signatures {
            let timing = self.measure_signature_timing(url, sig).await?;
            random_times.extend(timing);
        }

        if let (Some(prefix_stats), Some(random_stats)) = (
            TimingStatistics::from_samples(&prefix_times),
            TimingStatistics::from_samples(&random_times),
        ) {
            let comparison = TimingComparison::from_stats(prefix_stats, random_stats);

            if comparison.is_significant {
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    TimingAttackType::HmacVerification,
                    &comparison,
                    "HMAC signature verification timing varies by signature format, enabling byte-by-byte attacks",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test database query timing
    async fn test_database_timing(
        &self,
        url: &str,
        html: &str,
        sample_count: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Find search/filter endpoints
        let search_endpoints = self.find_search_endpoints(url, html);

        for endpoint in search_endpoints {
            tests_run += sample_count * 2;

            // Test LIKE vs exact match timing
            let like_queries: Vec<String> = vec![
                "a%".to_string(),
                "%a".to_string(),
                "%test%".to_string(),
            ];

            let exact_queries: Vec<String> = vec![
                "exact_value".to_string(),
                "specific_term".to_string(),
                "concrete".to_string(),
            ];

            let mut like_times = Vec::new();
            let mut exact_times = Vec::new();

            for query in &like_queries {
                let timing = self
                    .measure_search_timing(&endpoint, query, sample_count / 3 + 1)
                    .await?;
                like_times.extend(timing);
            }

            for query in &exact_queries {
                let timing = self
                    .measure_search_timing(&endpoint, query, sample_count / 3 + 1)
                    .await?;
                exact_times.extend(timing);
            }

            if let (Some(like_stats), Some(exact_stats)) = (
                TimingStatistics::from_samples(&like_times),
                TimingStatistics::from_samples(&exact_times),
            ) {
                let comparison = TimingComparison::from_stats(like_stats.clone(), exact_stats.clone());

                // Database timing typically shows larger differences
                if comparison.is_significant && comparison.leak_magnitude_ms > 20.0 {
                    vulnerabilities.push(self.create_vulnerability(
                        &endpoint,
                        TimingAttackType::DatabaseQuery,
                        &comparison,
                        &format!(
                            "Database query timing differs by {:.2}ms between LIKE and exact queries, enabling blind data extraction",
                            comparison.leak_magnitude_ms
                        ),
                    ));
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // ==================== TIMING MEASUREMENT HELPERS ====================

    /// Measure authentication endpoint timing
    async fn measure_auth_timing(
        &self,
        url: &str,
        method: &str,
        username_field: &str,
        username: &str,
        password_field: &str,
        password: &str,
        samples: usize,
    ) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let body = format!(
            "{}={}&{}={}",
            urlencoding::encode(username_field),
            urlencoding::encode(username),
            urlencoding::encode(password_field),
            urlencoding::encode(password)
        );

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.http_client.post(url, body.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            // Small delay between requests
            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure token validation timing
    async fn measure_token_timing(
        &self,
        url: &str,
        token_field: &str,
        token: &str,
        samples: usize,
    ) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let body = format!(
            "{}={}",
            urlencoding::encode(token_field),
            urlencoding::encode(token)
        );

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.http_client.post(url, body.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure API key validation timing
    async fn measure_api_key_timing(&self, url: &str, api_key: &str) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", api_key)),
            ("X-API-Key".to_string(), api_key.to_string()),
        ];

        for _ in 0..3 {
            let start = Instant::now();
            let _ = self.http_client.get_with_headers(url, headers.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure form submission timing
    async fn measure_form_timing(
        &self,
        url: &str,
        fields: Vec<(String, String)>,
        samples: usize,
    ) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.http_client.post(url, body.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure JWT verification timing
    async fn measure_jwt_timing(&self, url: &str, jwt: &str) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let headers = vec![("Authorization".to_string(), format!("Bearer {}", jwt))];

        for _ in 0..3 {
            let start = Instant::now();
            let _ = self.http_client.get_with_headers(url, headers.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure signature verification timing
    async fn measure_signature_timing(&self, url: &str, signature: &str) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let headers = vec![
            ("X-Hub-Signature-256".to_string(), signature.to_string()),
            ("X-Signature".to_string(), signature.to_string()),
        ];

        for _ in 0..3 {
            let start = Instant::now();
            let _ = self.http_client.post_with_headers(url, "{}", headers.clone()).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    /// Measure search endpoint timing
    async fn measure_search_timing(
        &self,
        url: &str,
        query: &str,
        samples: usize,
    ) -> Result<Vec<f64>> {
        let mut timings = Vec::new();
        let search_url = format!("{}?q={}", url, urlencoding::encode(query));

        for _ in 0..samples {
            let start = Instant::now();
            let _ = self.http_client.get(&search_url).await;
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            timings.push(elapsed);

            sleep(Duration::from_millis(50)).await;
        }

        Ok(timings)
    }

    // ==================== HELPER FUNCTIONS ====================

    fn is_login_form(&self, action: &str, content: &str) -> bool {
        let login_indicators = [
            "login", "signin", "sign-in", "sign_in", "authenticate", "auth",
            "kirjaudu", "anmelden", "connexion", "accedi",
        ];

        for indicator in &login_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        let has_username = content.contains("email") || content.contains("username") || content.contains("user");
        let has_password = content.contains("password") || content.contains("type=\"password\"");
        let has_confirm = content.contains("confirm") || content.contains("repeat");

        has_username && has_password && !has_confirm
    }

    fn is_registration_form(&self, action: &str, content: &str) -> bool {
        let register_indicators = [
            "register", "signup", "sign-up", "sign_up", "create-account",
            "rekisteröidy", "registrieren", "inscription",
        ];

        for indicator in &register_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        let has_email = content.contains("email");
        let has_password = content.contains("password");
        let has_confirm = content.contains("confirm") || content.contains("repeat") || content.contains("retype");

        has_email && has_password && has_confirm
    }

    fn is_password_reset_form(&self, action: &str, content: &str) -> bool {
        let reset_indicators = [
            "password-reset", "password_reset", "forgot", "reset-password",
            "recover", "unohdin",
        ];

        for indicator in &reset_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        content.contains("email") && (content.contains("reset") || content.contains("forgot"))
    }

    fn is_token_verification_form(&self, action: &str, content: &str) -> bool {
        let token_indicators = [
            "verify", "verification", "otp", "2fa", "mfa", "code",
            "vahvistus", "bestätigung",
        ];

        for indicator in &token_indicators {
            if action.contains(indicator) {
                return true;
            }
        }

        content.contains("code") || content.contains("otp") ||
            content.contains("maxlength=\"6\"") || content.contains("maxlength=\"4\"")
    }

    fn extract_credential_fields(&self, form_content: &str) -> (Option<String>, Option<String>) {
        let input_regex = Regex::new(
            r#"<input[^>]*name=["']([^"']+)["'][^>]*type=["']([^"']+)["']"#
        ).unwrap();

        let mut username_field = None;
        let mut password_field = None;

        for cap in input_regex.captures_iter(form_content) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let input_type = cap.get(2).map(|m| m.as_str()).unwrap_or("");

            if input_type == "password" {
                password_field = Some(name.to_string());
            } else if input_type == "email" || input_type == "text" {
                if name.contains("email") || name.contains("user") || name.contains("login") {
                    username_field = Some(name.to_string());
                }
            }
        }

        // Try alternative pattern
        if username_field.is_none() || password_field.is_none() {
            let alt_regex = Regex::new(
                r#"<input[^>]*type=["']([^"']+)["'][^>]*name=["']([^"']+)["']"#
            ).unwrap();

            for cap in alt_regex.captures_iter(form_content) {
                let input_type = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let name = cap.get(2).map(|m| m.as_str()).unwrap_or("");

                if input_type == "password" && password_field.is_none() {
                    password_field = Some(name.to_string());
                } else if (input_type == "email" || input_type == "text") && username_field.is_none() {
                    if name.contains("email") || name.contains("user") || name.contains("login") {
                        username_field = Some(name.to_string());
                    }
                }
            }
        }

        (username_field, password_field)
    }

    fn extract_email_field(&self, form_content: &str) -> Option<String> {
        let input_regex = Regex::new(
            r#"<input[^>]*name=["']([^"']+)["'][^>]*"#
        ).unwrap();

        for cap in input_regex.captures_iter(form_content) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if name.contains("email") || name.contains("mail") {
                return Some(name.to_string());
            }
        }

        Some("email".to_string())
    }

    fn extract_token_field(&self, form_content: &str) -> Option<String> {
        let input_regex = Regex::new(
            r#"<input[^>]*name=["']([^"']+)["'][^>]*"#
        ).unwrap();

        for cap in input_regex.captures_iter(form_content) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if name.contains("code") || name.contains("otp") || name.contains("token") {
                return Some(name.to_string());
            }
        }

        Some("code".to_string())
    }

    fn find_search_endpoints(&self, base_url: &str, html: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        let html_lower = html.to_lowercase();

        // Look for search forms
        let search_indicators = [
            "search", "query", "find", "filter", "lookup",
            "haku", "suche", "recherche", "cerca",
        ];

        for indicator in &search_indicators {
            if html_lower.contains(indicator) {
                endpoints.push(format!("{}/search", base_url.trim_end_matches('/')));
                endpoints.push(format!("{}/api/search", base_url.trim_end_matches('/')));
                break;
            }
        }

        // Check for autocomplete endpoints
        if html_lower.contains("autocomplete") || html_lower.contains("suggest") {
            endpoints.push(format!("{}/api/autocomplete", base_url.trim_end_matches('/')));
            endpoints.push(format!("{}/api/suggest", base_url.trim_end_matches('/')));
        }

        endpoints
    }

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

        if path.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_url) {
                let host = parsed.host_str().unwrap_or("localhost");
                let scheme = parsed.scheme();
                return format!("{}://{}{}", scheme, host, path);
            }
        }

        format!("{}/{}", base_url.trim_end_matches('/'), path)
    }

    fn generate_random_string(len: usize) -> String {
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

    fn generate_hex_string(len: usize) -> String {
        let mut rng = rand::rng();
        (0..len)
            .map(|_| {
                let idx = rng.random_range(0..16);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    }

    fn generate_fake_jwt(&self, sig_len: usize) -> String {
        // Generate a fake JWT with specified signature length
        let header = base64_url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload = base64_url_encode(b"{\"sub\":\"test\",\"iat\":1234567890}");
        let signature = Self::generate_random_string(sig_len);
        format!("{}.{}.{}", header, payload, signature)
    }

    fn generate_uuid() -> String {
        let mut rng = rand::rng();
        format!(
            "timing_{:08x}{:04x}{:04x}{:04x}{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u64>() & 0xffffffffffff
        )
    }

    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: TimingAttackType,
        comparison: &TimingComparison,
        description: &str,
    ) -> Vulnerability {
        let severity = match attack_type {
            TimingAttackType::UsernameEnumeration => Severity::Low,
            TimingAttackType::PasswordVerification => Severity::Medium,
            TimingAttackType::TokenValidation => Severity::Medium,
            TimingAttackType::JwtValidation => Severity::Medium,
            TimingAttackType::HmacVerification => Severity::Medium,
            TimingAttackType::ApiKeyValidation => Severity::Low,
            TimingAttackType::DatabaseQuery => Severity::Medium,
            TimingAttackType::CryptographicOperation => Severity::Medium,
        };

        let cvss = match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            _ => 2.0,
        };

        let remediation = match attack_type {
            TimingAttackType::UsernameEnumeration | TimingAttackType::PasswordVerification => {
                "1. Use constant-time comparison functions for credential validation\n\
                 2. Always perform full password hash computation, even for non-existent users\n\
                 3. Add random timing jitter to response times (50-200ms range)\n\
                 4. Use identical error messages for all authentication failures\n\
                 5. Implement rate limiting to reduce timing attack effectiveness\n\
                 6. Consider using CAPTCHA for repeated failed attempts\n\
                 7. Log and monitor for timing attack patterns"
            }
            TimingAttackType::TokenValidation | TimingAttackType::JwtValidation => {
                "1. Use constant-time comparison for token/signature validation\n\
                 2. Validate token format before cryptographic operations\n\
                 3. Add random timing jitter to mask processing time\n\
                 4. Use constant-time string comparison (e.g., hmac.compare_digest in Python)\n\
                 5. Consider using platform-provided timing-safe comparison functions\n\
                 6. Implement token rate limiting"
            }
            TimingAttackType::HmacVerification => {
                "1. CRITICAL: Use constant-time comparison for HMAC verification\n\
                 2. Use crypto library's timing-safe compare function\n\
                 3. Never implement manual byte-by-byte comparison\n\
                 4. Examples: crypto.timingSafeEqual (Node.js), hmac.compare_digest (Python)\n\
                 5. Validate signature format before comparison\n\
                 6. Add artificial delay to normalize response times"
            }
            TimingAttackType::ApiKeyValidation => {
                "1. Use constant-time string comparison for API key validation\n\
                 2. Hash API keys before storage and comparison\n\
                 3. Validate key format before database lookup\n\
                 4. Add response time normalization\n\
                 5. Implement key rotation policies"
            }
            TimingAttackType::DatabaseQuery => {
                "1. Use parameterized queries with consistent execution plans\n\
                 2. Add query result caching to normalize timing\n\
                 3. Implement response time padding\n\
                 4. Use database connection pooling\n\
                 5. Consider adding artificial delays for sensitive queries\n\
                 6. Monitor for timing-based data extraction attempts"
            }
            TimingAttackType::CryptographicOperation => {
                "1. Use constant-time cryptographic implementations\n\
                 2. Avoid branching based on secret data\n\
                 3. Use platform-provided crypto libraries\n\
                 4. Add timing jitter to mask operation duration\n\
                 5. Consider using hardware security modules (HSM)"
            }
        };

        let evidence = format!(
            "Timing Analysis Results:\n\
             ========================\n\
             Group A (Test): Mean={:.2}ms, StdDev={:.2}ms, Samples={}\n\
             Group B (Control): Mean={:.2}ms, StdDev={:.2}ms, Samples={}\n\
             \n\
             Statistical Analysis:\n\
             - Mean Difference: {:.2}ms\n\
             - T-Statistic: {:.4}\n\
             - Significance Threshold: {} standard deviations\n\
             - Result: {} significant timing difference\n\
             \n\
             Attack Implications:\n\
             {}",
            comparison.group_a.mean_ms,
            comparison.group_a.std_dev_ms,
            comparison.group_a.sample_count,
            comparison.group_b.mean_ms,
            comparison.group_b.std_dev_ms,
            comparison.group_b.sample_count,
            comparison.mean_diff_ms,
            comparison.t_statistic,
            SIGNIFICANCE_THRESHOLD,
            if comparison.is_significant { "DETECTED" } else { "No" },
            description
        );

        Vulnerability {
            id: Self::generate_uuid(),
            vuln_type: format!("Timing Attack - {}", attack_type.as_str()),
            severity,
            confidence: if comparison.t_statistic > 3.0 {
                Confidence::High
            } else if comparison.t_statistic > 2.0 {
                Confidence::Medium
            } else {
                Confidence::Low
            },
            category: "Side Channel".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: format!(
                "Timing difference: {:.2}ms (t={:.2})",
                comparison.mean_diff_ms, comparison.t_statistic
            ),
            description: format!(
                "{} timing side-channel detected. {}",
                attack_type.as_str(),
                description
            ),
            evidence: Some(evidence),
            cwe: attack_type.cwe().to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Base64 URL-safe encoding (no padding)
fn base64_url_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_statistics() {
        let samples = vec![100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.5, 101.5, 99.5];
        let stats = TimingStatistics::from_samples(&samples).unwrap();

        assert!(stats.mean_ms > 99.0 && stats.mean_ms < 102.0);
        assert!(stats.std_dev_ms < 5.0);
        assert_eq!(stats.sample_count, 10);
    }

    #[test]
    fn test_timing_statistics_outlier_removal() {
        let samples = vec![100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 500.0, 5.0];
        let stats = TimingStatistics::from_samples(&samples).unwrap();

        // Outliers should be removed
        assert!(stats.mean_ms > 95.0 && stats.mean_ms < 105.0);
    }

    #[test]
    fn test_timing_comparison_significant() {
        let samples_a = vec![150.0, 155.0, 148.0, 152.0, 151.0, 149.0, 153.0, 147.0, 154.0, 150.0];
        let samples_b = vec![100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.5, 101.5, 99.5];

        let stats_a = TimingStatistics::from_samples(&samples_a).unwrap();
        let stats_b = TimingStatistics::from_samples(&samples_b).unwrap();

        let comparison = TimingComparison::from_stats(stats_a, stats_b);

        assert!(comparison.is_significant);
        assert!(comparison.mean_diff_ms > 45.0);
    }

    #[test]
    fn test_timing_comparison_not_significant() {
        let samples_a = vec![100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.5, 101.5, 99.5];
        let samples_b = vec![101.0, 99.0, 102.0, 100.0, 98.0, 101.5, 100.5, 99.5, 102.5, 100.0];

        let stats_a = TimingStatistics::from_samples(&samples_a).unwrap();
        let stats_b = TimingStatistics::from_samples(&samples_b).unwrap();

        let comparison = TimingComparison::from_stats(stats_a, stats_b);

        assert!(!comparison.is_significant);
    }

    #[test]
    fn test_random_string_generation() {
        let s1 = TimingAttackScanner::generate_random_string(32);
        let s2 = TimingAttackScanner::generate_random_string(32);

        assert_eq!(s1.len(), 32);
        assert_eq!(s2.len(), 32);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_hex_string_generation() {
        let hex = TimingAttackScanner::generate_hex_string(64);

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_timing_attack_type_cwe() {
        assert_eq!(TimingAttackType::UsernameEnumeration.cwe(), "CWE-208");
        assert_eq!(TimingAttackType::DatabaseQuery.cwe(), "CWE-203");
    }
}
