// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Cognito configuration extracted from JavaScript
#[derive(Debug, Clone)]
pub struct CognitoConfig {
    pub region: String,
    pub user_pool_id: String,
    pub client_id: String,
    pub source: String,
}

/// Result of user enumeration attempt
#[derive(Debug)]
enum EnumResult {
    /// User exists and has verified contact (partial info returned)
    ExistsWithContact { destination: String, medium: String },
    /// User exists but has no verified contact method
    ExistsNoContact,
    /// User does not exist
    NotFound,
    /// Rate limited or other error
    Error(String),
}

pub struct CognitoEnumScanner {
    http_client: Arc<HttpClient>,
}

impl CognitoEnumScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for Cognito user enumeration vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        self.scan_with_endpoints(url, config, &[]).await
    }

    /// Scan for Cognito user enumeration vulnerabilities with additional intercepted endpoints
    pub async fn scan_with_endpoints(
        &self,
        url: &str,
        config: &ScanConfig,
        additional_urls: &[String],
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!("[Cognito] Scanning for AWS Cognito user enumeration vulnerabilities");

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;
        let mut found_client_ids: HashSet<String> = HashSet::new();

        // First, check additional URLs for Cognito params (e.g., intercepted form endpoints)
        // These often contain the real Cognito auth URL with client_id
        for additional_url in additional_urls {
            if let Some(cognito_config) = self.extract_cognito_from_url(additional_url) {
                if !cognito_config.client_id.is_empty()
                    && !found_client_ids.contains(&cognito_config.client_id)
                {
                    info!(
                        "[Cognito] Found Cognito config from intercepted URL: client_id={}...",
                        &cognito_config.client_id[..cognito_config.client_id.len().min(8)]
                    );
                    found_client_ids.insert(cognito_config.client_id.clone());
                    let (vulns, tests) = self
                        .test_user_enumeration(url, &cognito_config, config)
                        .await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests;
                }
            }
        }

        // Then extract Cognito configs from the main URL and its JavaScript
        let mut configs = self.extract_cognito_configs(url).await?;

        // If we found configs with empty client_id (e.g., from CSP header), try to find client_id from additional URLs
        for cognito_config in &mut configs {
            if cognito_config.client_id.is_empty() {
                // Look through additional URLs for a client_id
                for additional_url in additional_urls {
                    if let Some(url_config) = self.extract_cognito_from_url(additional_url) {
                        if !url_config.client_id.is_empty() {
                            info!(
                                "[Cognito] Found client_id from redirect URL for region {}",
                                cognito_config.region
                            );
                            cognito_config.client_id = url_config.client_id.clone();
                            // Prefer the region from the URL if available
                            if !url_config.region.is_empty() {
                                cognito_config.region = url_config.region;
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Filter out configs with empty client_id - we can't test without it
        configs.retain(|c| !c.client_id.is_empty() && !found_client_ids.contains(&c.client_id));

        if configs.is_empty() && all_vulnerabilities.is_empty() {
            debug!("[Cognito] No usable Cognito configurations found (need client_id)");
            return Ok((all_vulnerabilities, total_tests));
        }

        info!(
            "[Cognito] Found {} Cognito configuration(s) with valid client_id",
            configs.len()
        );

        // Test each configuration for user enumeration
        for cognito_config in &configs {
            found_client_ids.insert(cognito_config.client_id.clone());
            let (vulns, tests) = self
                .test_user_enumeration(url, cognito_config, config)
                .await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;
        }

        info!(
            "[Cognito] Completed {} tests, found {} vulnerabilities",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Extract Cognito configurations from JavaScript files
    async fn extract_cognito_configs(&self, url: &str) -> Result<Vec<CognitoConfig>> {
        let mut configs = Vec::new();

        // Fetch the main page
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok(configs),
        };

        // Check if the original URL contains Cognito params
        if let Some(cognito_config) = self.extract_cognito_from_url(url) {
            info!("[Cognito] Detected Cognito OAuth2 flow from URL parameters");
            configs.push(cognito_config);
        }

        // Check CSP header for Cognito endpoints (common pattern for SPAs using Cognito)
        // CSP often includes: connect-src 'self' https://cognito-idp.eu-west-1.amazonaws.com
        if let Some(cognito_config) = self.extract_cognito_from_headers(&response.headers) {
            info!("[Cognito] Detected Cognito from CSP/security headers");
            configs.push(cognito_config);
        }

        // Check if this is a Cognito hosted UI page
        if let Some(cognito_config) = self.detect_cognito_hosted_ui(url, &response.body) {
            info!("[Cognito] Detected Cognito hosted UI page");
            configs.push(cognito_config);
        }

        // Also look for Cognito URLs embedded in the page body (redirects, links, etc.)
        if let Some(cognito_config) = self.extract_cognito_from_body_urls(&response.body) {
            info!("[Cognito] Found Cognito OAuth2 URL in page body");
            configs.push(cognito_config);
        }

        // Extract from main page and linked JS files
        let mut js_contents = vec![response.body.clone()];

        // Find JS file links
        let script_pattern = Regex::new(r#"<script[^>]+src=["']([^"']+\.js[^"']*)["']"#)?;
        for cap in script_pattern.captures_iter(&response.body) {
            if let Some(js_path) = cap.get(1) {
                let js_url = self.resolve_url(url, js_path.as_str());
                if let Ok(js_resp) = self.http_client.get(&js_url).await {
                    js_contents.push(js_resp.body);
                }
            }
        }

        // Extract Cognito configs from all content
        for content in &js_contents {
            configs.extend(self.parse_cognito_config(content, url));
        }

        // Deduplicate by client_id
        let mut seen_clients = HashSet::new();
        configs.retain(|c| seen_clients.insert(c.client_id.clone()));

        Ok(configs)
    }

    /// Parse Cognito configuration from JavaScript content
    fn parse_cognito_config(&self, content: &str, source: &str) -> Vec<CognitoConfig> {
        let mut configs = Vec::new();

        // Pattern 1: User Pool ID (eu-west-1_XXXXXXXX format)
        let pool_pattern =
            Regex::new(r#"['"]((?:eu|us|ap|sa|ca|me|af)-[a-z]+-[0-9]+_[A-Za-z0-9]+)['"]"#).unwrap();

        // Pattern 2: Client ID (26 alphanumeric characters)
        let client_pattern = Regex::new(r#"['"]([\da-z]{26})['"]"#).unwrap();

        // Pattern 3: Cognito endpoint pattern
        let endpoint_pattern = Regex::new(r#"cognito-idp\.([\w-]+)\.amazonaws\.com"#).unwrap();

        // Extract all potential pool IDs
        let mut pool_ids: Vec<(String, String)> = Vec::new(); // (pool_id, region)
        for cap in pool_pattern.captures_iter(content) {
            if let Some(pool_id) = cap.get(1) {
                let pool_str = pool_id.as_str();
                // Extract region from pool ID (format: region_poolId)
                if let Some(underscore_pos) = pool_str.find('_') {
                    let region = &pool_str[..underscore_pos];
                    pool_ids.push((pool_str.to_string(), region.to_string()));
                }
            }
        }

        // Also check for explicit region in endpoint
        for cap in endpoint_pattern.captures_iter(content) {
            if let Some(region) = cap.get(1) {
                // Look for nearby pool ID
                for (pool_id, _) in &mut pool_ids {
                    if pool_id.starts_with(region.as_str()) {
                        // Already has correct region
                    }
                }
            }
        }

        // Extract all potential client IDs
        let mut client_ids: Vec<String> = Vec::new();
        for cap in client_pattern.captures_iter(content) {
            if let Some(client_id) = cap.get(1) {
                let client_str = client_id.as_str();
                // Validate it's likely a Cognito client ID (26 chars, lowercase alphanumeric)
                if client_str.len() == 26
                    && client_str
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    client_ids.push(client_str.to_string());
                }
            }
        }

        // Also look for explicit Cognito configuration objects
        let config_patterns = [
            r#"(?:userPoolId|UserPoolId|user_pool_id)\s*[:=]\s*['"]([\w-]+_[\w]+)['"]"#,
            r#"(?:clientId|ClientId|client_id|userPoolWebClientId)\s*[:=]\s*['"]([a-z0-9]{26})['"]"#,
        ];

        for pattern in config_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(value) = cap.get(1) {
                        let val = value.as_str();
                        if val.contains('_') && val.len() > 10 {
                            // Likely pool ID
                            if let Some(underscore_pos) = val.find('_') {
                                let region = &val[..underscore_pos];
                                if !pool_ids.iter().any(|(p, _)| p == val) {
                                    pool_ids.push((val.to_string(), region.to_string()));
                                }
                            }
                        } else if val.len() == 26 {
                            // Likely client ID
                            if !client_ids.contains(&val.to_string()) {
                                client_ids.push(val.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Create configs by pairing pool IDs with client IDs
        // If we have both, create a config
        for (pool_id, region) in &pool_ids {
            for client_id in &client_ids {
                configs.push(CognitoConfig {
                    region: region.clone(),
                    user_pool_id: pool_id.clone(),
                    client_id: client_id.clone(),
                    source: source.to_string(),
                });
            }
        }

        // If we only have client ID, try to infer region or use common ones
        if pool_ids.is_empty() && !client_ids.is_empty() {
            for client_id in &client_ids {
                // Check if there's a region hint nearby
                let regions = ["eu-west-1", "us-east-1", "eu-central-1", "ap-northeast-1"];
                for region in regions {
                    if content.contains(region) {
                        configs.push(CognitoConfig {
                            region: region.to_string(),
                            user_pool_id: String::new(), // Will need to discover
                            client_id: client_id.clone(),
                            source: source.to_string(),
                        });
                        break;
                    }
                }
            }
        }

        configs
    }

    /// Test for user enumeration vulnerability
    async fn test_user_enumeration(
        &self,
        url: &str,
        config: &CognitoConfig,
        _scan_config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let endpoint = format!("https://cognito-idp.{}.amazonaws.com/", config.region);

        info!(
            "[Cognito] Testing user pool in region {} with client {}",
            config.region,
            &config.client_id[..8.min(config.client_id.len())] // Only show first 8 chars
        );

        // Test 1: Check if SignUp is open (critical if should be restricted)
        info!("[Cognito] Testing SignUp endpoint for open registration");
        let (signup_vulns, signup_tests) = self
            .test_open_signup(&endpoint, &config.client_id, url)
            .await?;
        vulnerabilities.extend(signup_vulns);
        tests_run += signup_tests;

        // Test 2: Check for InitiateAuth enumeration
        info!("[Cognito] Testing InitiateAuth for user enumeration");
        let (auth_vulns, auth_tests) = self
            .test_auth_enumeration(&endpoint, &config.client_id, url)
            .await?;
        vulnerabilities.extend(auth_vulns);
        tests_run += auth_tests;

        // Test 3: Check ForgotPassword for user enumeration
        info!("[Cognito] Testing ForgotPassword for user enumeration");
        let (forgot_vulns, forgot_tests) = self
            .test_forgot_password_enumeration(&endpoint, &config.client_id, url)
            .await?;
        vulnerabilities.extend(forgot_vulns);
        tests_run += forgot_tests;

        // Test with a small set of common usernames to find actual users
        let test_usernames = self.get_test_usernames();
        let mut found_users = Vec::new();

        info!(
            "[Cognito] Testing {} common usernames for enumeration",
            test_usernames.len().min(10)
        );
        for username in test_usernames.iter().take(10) {
            tests_run += 1;

            match self
                .check_user_exists(&endpoint, &config.client_id, username)
                .await
            {
                EnumResult::ExistsWithContact {
                    destination,
                    medium,
                } => {
                    found_users.push(format!("{} ({})", username, medium));
                    info!("[Cognito] Found user: {} -> {}", username, destination);
                }
                EnumResult::ExistsNoContact => {
                    found_users.push(format!("{} (no verified contact)", username));
                    info!("[Cognito] Found user without contact: {}", username);
                }
                EnumResult::NotFound => {
                    // User doesn't exist - this is expected
                    debug!("[Cognito] User not found: {}", username);
                }
                EnumResult::Error(e) => {
                    if e.contains("TooManyRequestsException") || e.contains("rate") {
                        warn!("[Cognito] Rate limited, stopping enumeration");
                        break;
                    }
                    debug!("[Cognito] Error checking {}: {}", username, e);
                }
            }

            // Small delay to avoid rate limiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // If we found actual users, report as high severity with user list
        if !found_users.is_empty() {
            info!(
                "[Cognito] Found {} users via enumeration",
                found_users.len()
            );
            vulnerabilities.push(Vulnerability {
                id: format!("cognito-users-found-{}", uuid::Uuid::new_v4()),
                vuln_type: "AWS Cognito Users Enumerated".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Authentication".to_string(),
                url: url.to_string(),
                parameter: Some("Username".to_string()),
                payload: "X-Amz-Target: AWSCognitoIdentityProviderService.ForgotPassword"
                    .to_string(),
                description:
                    "Valid user accounts were discovered through AWS Cognito user enumeration. \
                     Attackers can use this information for targeted phishing, credential \
                     stuffing, or social engineering attacks against these specific users."
                        .to_string(),
                evidence: Some(format!(
                    "Found {} valid user accounts via Cognito ForgotPassword API:\n\
                     Region: {}\n\
                     Client ID: {}...\n\n\
                     Discovered users:\n{}",
                    found_users.len(),
                    config.region,
                    &config.client_id[..config.client_id.len().min(12)],
                    found_users
                        .iter()
                        .map(|u| format!("  - {}", u))
                        .collect::<Vec<_>>()
                        .join("\n")
                )),
                cwe: "CWE-204".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation:
                    "1. Enable 'Prevent user existence errors' in Cognito User Pool settings\n\
                     2. Review the discovered accounts for potential compromise\n\
                     3. Implement rate limiting and CAPTCHA on forgot password\n\
                     4. Monitor for credential stuffing attempts on these accounts\n\
                     5. Consider notifying affected users of potential exposure"
                        .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        // Also report the exposed Cognito configuration as informational
        if !config.user_pool_id.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: format!("cognito-config-{}", uuid::Uuid::new_v4()),
                vuln_type: "AWS Cognito Configuration Exposed".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: String::new(),
                description:
                    "AWS Cognito configuration was found exposed in client-side JavaScript. \
                     While this is common for SPAs, ensure proper security settings are enabled \
                     to prevent user enumeration and abuse."
                        .to_string(),
                evidence: Some(format!(
                    "AWS Cognito User Pool configuration found in JavaScript.\n\
                     Region: {}\n\
                     Pool ID: {}...\n\
                     Client ID: {}...",
                    config.region,
                    if config.user_pool_id.len() > 15 {
                        &config.user_pool_id[..15]
                    } else {
                        &config.user_pool_id
                    },
                    &config.client_id[..12]
                )),
                cwe: "CWE-200".to_string(),
                cvss: 2.0,
                verified: true,
                false_positive: false,
                remediation: "1. Ensure 'Prevent user existence errors' is enabled\n\
                     2. Implement proper rate limiting\n\
                     3. Use CloudFront or WAF to add additional protection\n\
                     4. Monitor for suspicious authentication patterns"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test if SignUp is open (critical vulnerability if pool should be restricted)
    async fn test_open_signup(
        &self,
        endpoint: &str,
        client_id: &str,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        // Use a clearly fake test email that won't exist
        let test_email = format!("cognito-test-{}@test.invalid", uuid::Uuid::new_v4());
        let test_password = "TestPass123!@#";

        let body = format!(
            r#"{{"ClientId":"{}","Username":"{}","Password":"{}"}}"#,
            client_id, test_email, test_password
        );

        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            (
                "X-Amz-Target".to_string(),
                "AWSCognitoIdentityProviderService.SignUp".to_string(),
            ),
        ];

        match self
            .http_client
            .post_with_headers(endpoint, &body, headers)
            .await
        {
            Ok(response) => {
                let resp_body = &response.body;
                info!(
                    "[Cognito] SignUp response: status={}, body_len={}",
                    response.status_code,
                    resp_body.len()
                );

                // If SignUp succeeds or asks for confirmation, registration is open
                if resp_body.contains("UserSub")
                    || resp_body.contains("CodeDeliveryDetails")
                    || resp_body.contains("UserConfirmed")
                {
                    vulnerabilities.push(Vulnerability {
                        id: format!("cognito-signup-{}", uuid::Uuid::new_v4()),
                        vuln_type: "AWS Cognito Open Registration".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: url.to_string(),
                        parameter: Some("SignUp".to_string()),
                        payload: "X-Amz-Target: AWSCognitoIdentityProviderService.SignUp"
                            .to_string(),
                        description:
                            "AWS Cognito User Pool allows unrestricted public registration. \
                             An attacker can create arbitrary accounts, potentially gaining \
                             unauthorized access to protected resources or using accounts \
                             for abuse. This is critical if the pool should be invite-only."
                                .to_string(),
                        evidence: Some(
                            "Cognito User Pool allows public registration via SignUp API.\n\
                             Anyone can create an account without invitation.\n\
                             Response indicates successful account creation."
                                .to_string(),
                        ),
                        cwe: "CWE-287".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "1. Disable self-service sign-up in Cognito User Pool settings\n\
                             2. Use AdminCreateUser API for controlled user creation\n\
                             3. Implement pre-sign-up Lambda trigger for validation\n\
                             4. Configure allowed sign-up attributes carefully\n\
                             5. Enable email/phone verification"
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }

                // Check for password policy disclosure
                if resp_body.contains("InvalidPasswordException") {
                    // Password policy is being disclosed
                    vulnerabilities.push(Vulnerability {
                        id: format!("cognito-pwpolicy-{}", uuid::Uuid::new_v4()),
                        vuln_type: "AWS Cognito Password Policy Disclosure".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::Medium,
                        category: "Information Disclosure".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: String::new(),
                        description:
                            "The Cognito User Pool reveals password policy requirements in error messages.".to_string(),
                        evidence: Some(
                            "Cognito returns password policy requirements in error messages.\n\
                             This information helps attackers craft valid passwords.".to_string()
                        ),
                        cwe: "CWE-200".to_string(),
                        cvss: 2.0,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Consider using generic error messages that don't reveal password requirements.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }

                // NotAuthorizedException with "SignUp is disabled" is good (not vulnerable)
                if resp_body.contains("SignUp is disabled") {
                    info!("[Cognito] SignUp is properly disabled");
                } else if resp_body.contains("NotAuthorizedException") {
                    info!("[Cognito] SignUp returned NotAuthorizedException");
                } else {
                    // Log unexpected response for debugging
                    info!(
                        "[Cognito] SignUp unexpected response: {}",
                        &resp_body[..resp_body.len().min(200)]
                    );
                }
            }
            Err(e) => {
                warn!("[Cognito] SignUp test failed: {}", e);
            }
        }

        Ok((vulnerabilities, 1))
    }

    /// Test for InitiateAuth user enumeration
    async fn test_auth_enumeration(
        &self,
        endpoint: &str,
        client_id: &str,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        // Test with a definitely non-existent user
        let fake_user = format!("nonexistent-test-{}", uuid::Uuid::new_v4());
        let body = format!(
            r#"{{"AuthFlow":"USER_PASSWORD_AUTH","ClientId":"{}","AuthParameters":{{"USERNAME":"{}","PASSWORD":"wrongpassword"}}}}"#,
            client_id, fake_user
        );

        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            (
                "X-Amz-Target".to_string(),
                "AWSCognitoIdentityProviderService.InitiateAuth".to_string(),
            ),
        ];

        match self
            .http_client
            .post_with_headers(endpoint, &body, headers)
            .await
        {
            Ok(response) => {
                let resp_body = &response.body;
                info!(
                    "[Cognito] InitiateAuth response: status={}, body_len={}",
                    response.status_code,
                    resp_body.len()
                );

                // If response explicitly says "User does not exist", enumeration is possible
                if resp_body.contains("UserNotFoundException")
                    || resp_body.contains("User does not exist")
                    || resp_body.contains("user does not exist")
                {
                    info!("[Cognito] User enumeration vulnerability detected via InitiateAuth");
                    vulnerabilities.push(Vulnerability {
                        id: format!("cognito-auth-enum-{}", uuid::Uuid::new_v4()),
                        vuln_type: "AWS Cognito Auth User Enumeration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: url.to_string(),
                        parameter: Some("USERNAME".to_string()),
                        payload: "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth".to_string(),
                        description:
                            "AWS Cognito InitiateAuth API reveals whether a username exists. \
                             Attackers can enumerate valid usernames for targeted attacks.".to_string(),
                        evidence: Some(
                            "Cognito reveals user existence through InitiateAuth API.\n\
                             Non-existent users return 'UserNotFoundException'.\n\
                             Existing users return 'NotAuthorizedException' for wrong password.".to_string()
                        ),
                        cwe: "CWE-204".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "1. Enable 'Prevent user existence errors' in Cognito settings\n\
                             2. This will return generic 'NotAuthorizedException' for all auth failures\n\
                             3. Implement account lockout and rate limiting\n\
                             4. Monitor for enumeration attempts".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }
            }
            Err(e) => {
                debug!("[Cognito] InitiateAuth test failed: {}", e);
            }
        }

        Ok((vulnerabilities, 1))
    }

    /// Test for ForgotPassword user enumeration by comparing responses for existing vs non-existing users
    async fn test_forgot_password_enumeration(
        &self,
        endpoint: &str,
        client_id: &str,
        url: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        // Test with a definitely non-existent user
        let fake_user = format!("nonexistent-test-user-{}", uuid::Uuid::new_v4());
        let body = format!(
            r#"{{"ClientId":"{}","Username":"{}"}}"#,
            client_id, fake_user
        );

        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            (
                "X-Amz-Target".to_string(),
                "AWSCognitoIdentityProviderService.ForgotPassword".to_string(),
            ),
        ];

        match self
            .http_client
            .post_with_headers(endpoint, &body, headers)
            .await
        {
            Ok(response) => {
                let resp_body = &response.body;
                info!(
                    "[Cognito] ForgotPassword response: status={}, body_len={}",
                    response.status_code,
                    resp_body.len()
                );

                // If response explicitly says "User does not exist", enumeration is possible
                // A secure configuration would return a generic message like "If this user exists..."
                if resp_body.contains("UserNotFoundException")
                    || resp_body.contains("User does not exist")
                    || resp_body.contains("user does not exist")
                {
                    info!("[Cognito] User enumeration vulnerability detected via ForgotPassword");
                    vulnerabilities.push(Vulnerability {
                        id: format!("cognito-forgot-enum-{}", uuid::Uuid::new_v4()),
                        vuln_type: "AWS Cognito ForgotPassword User Enumeration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Authentication".to_string(),
                        url: url.to_string(),
                        parameter: Some("Username".to_string()),
                        payload: "X-Amz-Target: AWSCognitoIdentityProviderService.ForgotPassword".to_string(),
                        description:
                            "AWS Cognito ForgotPassword API reveals whether a username exists. \
                             When 'Prevent user existence errors' is disabled, attackers can \
                             enumerate valid usernames by analyzing API responses.".to_string(),
                        evidence: Some(format!(
                            "Cognito reveals user existence through ForgotPassword API.\n\
                             Test: Sent ForgotPassword request for non-existent user\n\
                             Response: UserNotFoundException returned\n\
                             A secure configuration returns 'If this user exists...' for all users."
                        )),
                        cwe: "CWE-204".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "1. Enable 'Prevent user existence errors' in Cognito User Pool settings\n\
                             2. Go to AWS Console > Cognito > User Pools > [Pool] > Sign-in experience\n\
                             3. Under 'User existence errors', enable prevention\n\
                             4. This returns generic messages for all forgot password requests\n\
                             5. Add rate limiting via Lambda triggers or WAF".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                } else if resp_body.contains("NotAuthorizedException") {
                    // This is the expected secure response when enumeration prevention is enabled
                    info!("[Cognito] ForgotPassword returns generic error - enumeration prevention may be enabled");
                } else if resp_body.contains("InvalidParameterException") {
                    debug!("[Cognito] InvalidParameterException - may indicate user pool configuration issue");
                } else {
                    // Log unexpected response for debugging
                    info!(
                        "[Cognito] ForgotPassword unexpected response: {}",
                        &resp_body[..resp_body.len().min(200)]
                    );
                }
            }
            Err(e) => {
                warn!("[Cognito] ForgotPassword test failed: {}", e);
            }
        }

        Ok((vulnerabilities, 1))
    }

    /// Check if a user exists via ForgotPassword API
    async fn check_user_exists(
        &self,
        endpoint: &str,
        client_id: &str,
        username: &str,
    ) -> EnumResult {
        let body = format!(
            r#"{{"ClientId":"{}","Username":"{}"}}"#,
            client_id, username
        );

        let headers = vec![
            (
                "Content-Type".to_string(),
                "application/x-amz-json-1.1".to_string(),
            ),
            (
                "X-Amz-Target".to_string(),
                "AWSCognitoIdentityProviderService.ForgotPassword".to_string(),
            ),
        ];

        match self
            .http_client
            .post_with_headers(endpoint, &body, headers)
            .await
        {
            Ok(response) => {
                let body = &response.body;

                // Check for successful response (user exists with verified contact)
                if body.contains("CodeDeliveryDetails") {
                    // Extract destination (partial email/phone)
                    let destination = self
                        .extract_json_field(body, "Destination")
                        .unwrap_or_else(|| "[redacted]".to_string());
                    let medium = self
                        .extract_json_field(body, "DeliveryMedium")
                        .unwrap_or_else(|| "unknown".to_string());
                    return EnumResult::ExistsWithContact {
                        destination,
                        medium,
                    };
                }

                // User exists but has no verified email/phone
                if body.contains("InvalidParameterException")
                    && (body.contains("no registered/verified")
                        || body.contains("Cannot reset password"))
                {
                    return EnumResult::ExistsNoContact;
                }

                // User doesn't exist
                if body.contains("UserNotFoundException") {
                    return EnumResult::NotFound;
                }

                // Rate limited
                if body.contains("TooManyRequestsException") {
                    return EnumResult::Error("Rate limited".to_string());
                }

                // Limit exceeded
                if body.contains("LimitExceededException") {
                    return EnumResult::Error("Limit exceeded".to_string());
                }

                // Other error
                EnumResult::Error(format!(
                    "Unknown response: {}",
                    &body[..body.len().min(100)]
                ))
            }
            Err(e) => EnumResult::Error(e.to_string()),
        }
    }

    /// Extract a field from JSON response
    fn extract_json_field(&self, json: &str, field: &str) -> Option<String> {
        let pattern = format!(r#""{}"\s*:\s*"([^"]+)""#, field);
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(cap) = re.captures(json) {
                return cap.get(1).map(|m| m.as_str().to_string());
            }
        }
        None
    }

    /// Get list of common test usernames for enumeration detection
    fn get_test_usernames(&self) -> Vec<String> {
        let mut usernames = Vec::new();

        // System/admin accounts
        let system = [
            "admin",
            "administrator",
            "root",
            "test",
            "user",
            "support",
            "info",
            "contact",
            "helpdesk",
            "it",
            "security",
            "noreply",
            "system",
            "service",
            "api",
            "bot",
            "backup",
            "dev",
            "ops",
            "hr",
            "finance",
            "sales",
            "marketing",
            "webmaster",
            "postmaster",
            "guest",
            "demo",
            "training",
            "staff",
            "employee",
        ];
        usernames.extend(system.iter().map(|s| s.to_string()));

        // Finnish names (common)
        let finnish = [
            "matti", "mikko", "jukka", "juha", "timo", "antti", "kari", "pekka", "markku", "jari",
            "petri", "heikki", "seppo", "ville", "sami", "tommi", "tuomas", "lauri", "teemu",
            "aki", "anna", "maria", "liisa", "päivi", "sari", "tiina", "minna", "kirsi", "anne",
            "johanna", "hanna", "katja", "marika", "sanna", "laura", "elina", "jenni", "riikka",
            "piia", "nina",
        ];
        usernames.extend(finnish.iter().map(|s| s.to_string()));

        // Swedish names (common)
        let swedish = [
            "johan",
            "erik",
            "lars",
            "anders",
            "peter",
            "mikael",
            "karl",
            "stefan",
            "thomas",
            "jan",
            "marcus",
            "fredrik",
            "daniel",
            "mattias",
            "niklas",
            "henrik",
            "jonas",
            "christian",
            "alexander",
            "oscar",
            "david",
            "patrik",
            "magnus",
            "martin",
            "andreas",
            "emma",
            "anna",
            "maria",
            "sara",
            "linda",
            "jenny",
            "jessica",
            "sandra",
            "johanna",
            "elin",
            "sofia",
            "ida",
            "amanda",
            "lisa",
        ];
        usernames.extend(swedish.iter().map(|s| s.to_string()));

        // American/English names (common)
        let american = [
            "john",
            "james",
            "robert",
            "michael",
            "william",
            "david",
            "richard",
            "joseph",
            "thomas",
            "charles",
            "christopher",
            "daniel",
            "matthew",
            "anthony",
            "mark",
            "steven",
            "paul",
            "andrew",
            "brian",
            "mary",
            "patricia",
            "jennifer",
            "linda",
            "elizabeth",
            "barbara",
            "susan",
            "jessica",
            "sarah",
            "karen",
            "lisa",
            "nancy",
            "betty",
            "margaret",
            "sandra",
            "ashley",
            "emily",
            "donna",
            "michelle",
        ];
        usernames.extend(american.iter().map(|s| s.to_string()));

        // German names (common)
        let german = [
            "hans",
            "peter",
            "michael",
            "thomas",
            "andreas",
            "stefan",
            "christian",
            "martin",
            "markus",
            "daniel",
            "sebastian",
            "tobias",
            "julia",
            "anna",
            "laura",
            "lena",
            "sarah",
            "lisa",
            "marie",
            "katharina",
            "sophie",
            "maria",
            "claudia",
            "andrea",
            "nicole",
        ];
        usernames.extend(german.iter().map(|s| s.to_string()));

        // Common email patterns (will be adapted per-target)
        let patterns = [
            "info",
            "contact",
            "support",
            "admin",
            "sales",
            "marketing",
            "hello",
            "office",
            "mail",
            "team",
            "help",
            "service",
        ];
        usernames.extend(patterns.iter().map(|s| s.to_string()));

        usernames
    }

    /// Extract Cognito configuration from URLs found in body content
    ///
    /// Looks for URLs in the page body that contain Cognito OAuth2 parameters
    fn extract_cognito_from_body_urls(&self, body: &str) -> Option<CognitoConfig> {
        // Look for URLs with client_id and identity_provider=COGNITO
        let url_pattern =
            Regex::new(r#"(?:href|action|src|url)[=:]["']?([^"'\s>]+client_id=[^"'\s>]+)"#).ok()?;

        for cap in url_pattern.captures_iter(body) {
            if let Some(url_match) = cap.get(1) {
                let potential_url = url_match.as_str();

                // URL decode if needed
                let decoded =
                    urlencoding::decode(potential_url).unwrap_or_else(|_| potential_url.into());

                if let Some(config) = self.extract_cognito_from_url(&decoded) {
                    return Some(config);
                }
            }
        }

        // Also look for client_id and identity_provider in query strings or JavaScript
        if body.contains("identity_provider") && body.to_lowercase().contains("cognito") {
            // Try to find client_id pattern
            let client_pattern = Regex::new(r#"client_id[=:]["']?([a-z0-9]{20,32})"#).ok()?;
            if let Some(cap) = client_pattern.captures(body) {
                if let Some(client_id) = cap.get(1) {
                    // Try to find region
                    let region = if body.contains("eu-west-1") {
                        "eu-west-1"
                    } else if body.contains("us-east-1") {
                        "us-east-1"
                    } else if body.contains("eu-central-1") {
                        "eu-central-1"
                    } else {
                        "eu-west-1"
                    };

                    return Some(CognitoConfig {
                        region: region.to_string(),
                        user_pool_id: String::new(),
                        client_id: client_id.as_str().to_string(),
                        source: "body_extraction".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Extract Cognito configuration from URL parameters
    ///
    /// Cognito OAuth2/OIDC flows often include client_id and identity_provider=COGNITO
    /// Example: https://auth.example.com/login?client_id=1v1l3r2qvgohl8r2h572mqt966&identity_provider=COGNITO
    fn extract_cognito_from_url(&self, url: &str) -> Option<CognitoConfig> {
        let parsed = url::Url::parse(url).ok()?;

        let mut client_id: Option<String> = None;
        let mut is_cognito = false;
        let mut region: Option<String> = None;

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "client_id" => {
                    // Cognito client IDs are typically 26 lowercase alphanumeric chars
                    let val = value.to_string();
                    if val.len() >= 20
                        && val.len() <= 32
                        && val.chars().all(|c| c.is_ascii_alphanumeric())
                    {
                        client_id = Some(val);
                    }
                }
                "identity_provider" if value.to_uppercase() == "COGNITO" => {
                    is_cognito = true;
                }
                _ => {}
            }
        }

        // Check host for region hints
        let host = parsed.host_str().unwrap_or("");
        if host.contains("auth.") {
            // Try to extract region from subdomain pattern
            // Pattern: auth.idm.vrprod.io or something.auth.eu-west-1.amazoncognito.com
            let region_pattern = Regex::new(r"auth\.([\w-]+)\.amazoncognito\.com").ok();
            if let Some(re) = region_pattern {
                if let Some(caps) = re.captures(host) {
                    if let Some(r) = caps.get(1) {
                        region = Some(r.as_str().to_string());
                    }
                }
            }
        }

        // If we have a client_id and either identity_provider=COGNITO or it looks like a Cognito auth URL
        if client_id.is_some() && (is_cognito || host.contains("auth.") || host.contains("cognito"))
        {
            return Some(CognitoConfig {
                region: region.unwrap_or_else(|| "eu-west-1".to_string()),
                user_pool_id: String::new(),
                client_id: client_id.unwrap_or_default(),
                source: url.to_string(),
            });
        }

        None
    }

    /// Detect if the page is a Cognito hosted UI login page
    ///
    /// Cognito hosted UI pages typically have:
    /// - Domain patterns like *.auth.*.amazoncognito.com or custom domains
    /// - Specific form structures and JavaScript references
    /// - CSRF tokens and Cognito-specific meta tags
    /// - URL parameters containing client_id and identity_provider=COGNITO
    fn detect_cognito_hosted_ui(&self, url: &str, body: &str) -> Option<CognitoConfig> {
        // First check if URL contains Cognito OAuth2 parameters
        // Pattern: client_id=XXXX...&identity_provider=COGNITO
        if let Some(config) = self.extract_cognito_from_url(url) {
            info!("[Cognito] Detected Cognito OAuth2 flow from URL parameters");
            return Some(config);
        }

        // Patterns that indicate a Cognito hosted UI page
        let cognito_indicators = [
            // Cognito hosted UI specific patterns
            "cognito-idp",
            "amazoncognito.com",
            "CognitoUserPool",
            "aws-amplify",
            "AWSCognito",
            "aws_cognito",
            // Cognito login form patterns
            r#"name="username""#,
            r#"name="password""#,
            "forgotPassword",
            "cognitoUser",
            // Cognito hosted UI specific JavaScript
            "amazon-cognito-identity",
            "cognito-auth",
            "_csrf",
            // Common Cognito hosted UI page indicators
            "Sign in with your",
            "Forgot your password",
            // Identity provider indicator
            "identity_provider",
            "COGNITO",
        ];

        let body_lower = body.to_lowercase();
        let indicator_count = cognito_indicators
            .iter()
            .filter(|pattern| body_lower.contains(&pattern.to_lowercase()))
            .count();

        // Need at least 2 indicators to consider it a Cognito page
        if indicator_count < 2 {
            return None;
        }

        debug!(
            "[Cognito] Found {} Cognito indicators on page",
            indicator_count
        );

        // Try to extract region and client ID from the page
        // Look for cognito-idp endpoint in the page
        let endpoint_pattern = Regex::new(r#"cognito-idp\.([\w-]+)\.amazonaws\.com"#).ok()?;
        let region = endpoint_pattern
            .captures(body)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        // Look for user pool ID in the page
        let pool_pattern =
            Regex::new(r#"['"]((?:eu|us|ap|sa|ca|me|af)-[a-z]+-[0-9]+_[A-Za-z0-9]+)['"]"#).ok()?;
        let pool_id = pool_pattern
            .captures(body)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        // Look for client ID (26 char alphanumeric)
        let client_pattern = Regex::new(r#"['"]([\da-z]{26})['"]"#).ok()?;
        let client_id = client_pattern
            .captures(body)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        // Try to extract from URL if it's a Cognito hosted domain
        // Pattern: https://something.auth.region.amazoncognito.com
        let url_pattern =
            Regex::new(r#"https?://[^/]+\.auth\.([\w-]+)\.amazoncognito\.com"#).ok()?;
        let url_region = url_pattern
            .captures(url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string());

        // Also check for custom domain pattern that redirects to Cognito
        // Look in meta tags or form actions
        let redirect_pattern =
            Regex::new(r#"(?:action|href|redirect)[^"']*["']([^"']*cognito[^"']*)["']"#).ok()?;
        let has_cognito_redirect = redirect_pattern.is_match(body);

        // Determine the best region
        let final_region = region
            .or(url_region)
            .or_else(|| {
                // Try to extract from pool_id
                pool_id
                    .as_ref()
                    .and_then(|pid| pid.find('_').map(|pos| pid[..pos].to_string()))
            })
            .unwrap_or_else(|| "eu-west-1".to_string()); // Default to eu-west-1

        // If we have either a client_id or indicators suggest Cognito
        if client_id.is_some() || (indicator_count >= 3 && has_cognito_redirect) {
            info!(
                "[Cognito] Detected Cognito hosted UI - region: {}, has_client_id: {}",
                final_region,
                client_id.is_some()
            );

            return Some(CognitoConfig {
                region: final_region,
                user_pool_id: pool_id.unwrap_or_default(),
                client_id: client_id.unwrap_or_default(),
                source: url.to_string(),
            });
        }

        None
    }

    /// Extract Cognito configuration from HTTP headers (CSP, etc.)
    ///
    /// SPAs using Cognito often have CSP headers that include the Cognito endpoint:
    /// Content-Security-Policy: connect-src 'self' https://cognito-idp.eu-west-1.amazonaws.com
    fn extract_cognito_from_headers(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Option<CognitoConfig> {
        // Look for Cognito endpoints in various security headers
        let header_keys = [
            "content-security-policy",
            "content-security-policy-report-only",
        ];

        for key in &header_keys {
            if let Some(header_value) = headers.get(*key) {
                // Look for cognito-idp.REGION.amazonaws.com pattern
                let cognito_pattern = Regex::new(r"cognito-idp\.([\w-]+)\.amazonaws\.com").ok()?;

                if let Some(cap) = cognito_pattern.captures(header_value) {
                    if let Some(region_match) = cap.get(1) {
                        let region = region_match.as_str().to_string();

                        info!("[Cognito] Found Cognito region {} in CSP header", region);

                        // We have the region but need to discover client_id
                        // This indicates Cognito is in use, so we should look harder for client_id
                        // Return a partial config that can be used for further discovery
                        return Some(CognitoConfig {
                            region,
                            user_pool_id: String::new(),
                            client_id: String::new(), // Will be discovered via headless browser
                            source: "csp_header".to_string(),
                        });
                    }
                }
            }
        }

        None
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, base: &str, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }

        if let Ok(base_url) = url::Url::parse(base) {
            if path.starts_with('/') {
                return format!("{}{}", base_url.origin().ascii_serialization(), path);
            } else {
                // Relative path
                if let Ok(resolved) = base_url.join(path) {
                    return resolved.to_string();
                }
            }
        }

        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cognito_pool_id_pattern() {
        // Test with synthetic pool ID format (region_id)
        let content = r#"userPoolId: "us-east-1_TestPool123""#;
        let pool_pattern =
            Regex::new(r#"['"]((?:eu|us|ap|sa|ca|me|af)-[a-z]+-[0-9]+_[A-Za-z0-9]+)['"]"#).unwrap();
        assert!(pool_pattern.is_match(content));
    }

    #[test]
    fn test_parse_cognito_client_id_pattern() {
        // Test with synthetic 26-char client ID
        let content = r#"clientId: "abcdefghij1234567890abcdef""#;
        let client_pattern = Regex::new(r#"['"]([\da-z]{26})['"]"#).unwrap();
        assert!(client_pattern.is_match(content));
    }
}
