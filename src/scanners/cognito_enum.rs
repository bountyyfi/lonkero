// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - AWS Cognito User Enumeration Scanner
 *
 * Detects AWS Cognito User Pool configurations in JavaScript and tests
 * for user enumeration vulnerabilities via the ForgotPassword API.
 *
 * Cognito user pools may leak user existence through:
 * - Different responses for existing vs non-existing users
 * - CodeDeliveryDetails revealing partial email/phone
 * - InvalidParameterException indicating user exists but has no verified contact
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

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
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
        }

        info!("[Cognito] Scanning for AWS Cognito user enumeration vulnerabilities");

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // First, extract Cognito configs from JavaScript
        let configs = self.extract_cognito_configs(url).await?;

        if configs.is_empty() {
            debug!("[Cognito] No Cognito configurations found");
            return Ok((all_vulnerabilities, 0));
        }

        info!("[Cognito] Found {} Cognito configuration(s)", configs.len());

        // Test each configuration for user enumeration
        for cognito_config in &configs {
            let (vulns, tests) = self.test_user_enumeration(url, cognito_config, config).await?;
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
        let pool_pattern = Regex::new(r#"['"]((?:eu|us|ap|sa|ca|me|af)-[a-z]+-[0-9]+_[A-Za-z0-9]+)['"]"#).unwrap();

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
                if client_str.len() == 26 && client_str.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
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
        let (signup_vulns, signup_tests) = self.test_open_signup(&endpoint, &config.client_id, url).await?;
        vulnerabilities.extend(signup_vulns);
        tests_run += signup_tests;

        // Test 2: Check for InitiateAuth enumeration
        let (auth_vulns, auth_tests) = self.test_auth_enumeration(&endpoint, &config.client_id, url).await?;
        vulnerabilities.extend(auth_vulns);
        tests_run += auth_tests;

        // Test with a small set of common usernames to detect enumeration
        let test_usernames = self.get_test_usernames();
        let mut found_users = Vec::new();
        let mut enumerable = false;

        for username in test_usernames.iter().take(10) {
            tests_run += 1;

            match self.check_user_exists(&endpoint, &config.client_id, username).await {
                EnumResult::ExistsWithContact { destination, medium } => {
                    enumerable = true;
                    found_users.push(format!("{} ({})", username, medium));
                    debug!("[Cognito] User exists: {} -> {}", username, destination);
                }
                EnumResult::ExistsNoContact => {
                    enumerable = true;
                    found_users.push(format!("{} (no verified contact)", username));
                    debug!("[Cognito] User exists without contact: {}", username);
                }
                EnumResult::NotFound => {
                    // User doesn't exist - this is expected for most test usernames
                    // The difference in response indicates enumeration is possible
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

        // If we found any users or detected different responses, report vulnerability
        if enumerable {
            vulnerabilities.push(Vulnerability {
                vuln_type: "AWS Cognito User Enumeration".to_string(),
                severity: Severity::Medium,
                url: url.to_string(),
                evidence: format!(
                    "Cognito User Pool allows user enumeration via ForgotPassword API.\n\
                     Region: {}\n\
                     Client ID: {}...\n\
                     Found {} potential users during limited test.\n\
                     The API returns different responses for existing vs non-existing users.",
                    config.region,
                    &config.client_id[..12],
                    found_users.len()
                ),
                payload: format!("X-Amz-Target: AWSCognitoIdentityProviderService.ForgotPassword"),
                remediation:
                    "1. Enable 'Prevent user existence errors' in Cognito User Pool settings\n\
                     2. Configure custom messages that don't reveal user existence\n\
                     3. Implement rate limiting and CAPTCHA on the forgot password flow\n\
                     4. Monitor for enumeration attempts in CloudWatch logs\n\
                     5. Consider using alias attributes to hide usernames".to_string(),
                description:
                    "AWS Cognito User Pool is vulnerable to user enumeration. \
                     An attacker can determine valid usernames by analyzing responses \
                     from the ForgotPassword API. This information can be used for \
                     targeted phishing, credential stuffing, or brute force attacks.".to_string(),
                cwe: "CWE-204".to_string(),
                cvss: 5.3,
                parameter: "Username".to_string(),
                confidence: Confidence::High,
                request: None,
                response: None,
            });
        }

        // Also report the exposed Cognito configuration as informational
        if !config.user_pool_id.is_empty() {
            vulnerabilities.push(Vulnerability {
                vuln_type: "AWS Cognito Configuration Exposed".to_string(),
                severity: Severity::Low,
                url: url.to_string(),
                evidence: format!(
                    "AWS Cognito User Pool configuration found in JavaScript.\n\
                     Region: {}\n\
                     Pool ID: {}...\n\
                     Client ID: {}...",
                    config.region,
                    if config.user_pool_id.len() > 15 { &config.user_pool_id[..15] } else { &config.user_pool_id },
                    &config.client_id[..12]
                ),
                payload: String::new(),
                remediation:
                    "1. Ensure 'Prevent user existence errors' is enabled\n\
                     2. Implement proper rate limiting\n\
                     3. Use CloudFront or WAF to add additional protection\n\
                     4. Monitor for suspicious authentication patterns".to_string(),
                description:
                    "AWS Cognito configuration was found exposed in client-side JavaScript. \
                     While this is common for SPAs, ensure proper security settings are enabled \
                     to prevent user enumeration and abuse.".to_string(),
                cwe: "CWE-200".to_string(),
                cvss: 2.0,
                parameter: String::new(),
                confidence: Confidence::High,
                request: None,
                response: None,
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
            ("Content-Type".to_string(), "application/x-amz-json-1.1".to_string()),
            ("X-Amz-Target".to_string(), "AWSCognitoIdentityProviderService.SignUp".to_string()),
        ];

        debug!("[Cognito] Testing SignUp endpoint");

        match self.http_client.post_with_headers(endpoint, &body, headers).await {
            Ok(response) => {
                let resp_body = &response.body;

                // If SignUp succeeds or asks for confirmation, registration is open
                if resp_body.contains("UserSub") ||
                   resp_body.contains("CodeDeliveryDetails") ||
                   resp_body.contains("UserConfirmed") {
                    vulnerabilities.push(Vulnerability {
                        vuln_type: "AWS Cognito Open Registration".to_string(),
                        severity: Severity::High,
                        url: url.to_string(),
                        evidence: format!(
                            "Cognito User Pool allows public registration via SignUp API.\n\
                             Anyone can create an account without invitation.\n\
                             Response indicates successful account creation."
                        ),
                        payload: "X-Amz-Target: AWSCognitoIdentityProviderService.SignUp".to_string(),
                        remediation:
                            "1. Disable self-service sign-up in Cognito User Pool settings\n\
                             2. Use AdminCreateUser API for controlled user creation\n\
                             3. Implement pre-sign-up Lambda trigger for validation\n\
                             4. Configure allowed sign-up attributes carefully\n\
                             5. Enable email/phone verification".to_string(),
                        description:
                            "AWS Cognito User Pool allows unrestricted public registration. \
                             An attacker can create arbitrary accounts, potentially gaining \
                             unauthorized access to protected resources or using accounts \
                             for abuse. This is critical if the pool should be invite-only.".to_string(),
                        cwe: "CWE-287".to_string(),
                        cvss: 7.5,
                        parameter: "SignUp".to_string(),
                        confidence: Confidence::High,
                        request: None,
                        response: None,
                    });
                }

                // Check for password policy disclosure
                if resp_body.contains("InvalidPasswordException") {
                    // Password policy is being disclosed
                    vulnerabilities.push(Vulnerability {
                        vuln_type: "AWS Cognito Password Policy Disclosure".to_string(),
                        severity: Severity::Low,
                        url: url.to_string(),
                        evidence: format!(
                            "Cognito returns password policy requirements in error messages.\n\
                             This information helps attackers craft valid passwords."
                        ),
                        payload: String::new(),
                        remediation:
                            "Consider using generic error messages that don't reveal password requirements.".to_string(),
                        description:
                            "The Cognito User Pool reveals password policy requirements in error messages.".to_string(),
                        cwe: "CWE-200".to_string(),
                        cvss: 2.0,
                        parameter: String::new(),
                        confidence: Confidence::Medium,
                        request: None,
                        response: None,
                    });
                }

                // NotAuthorizedException with "SignUp is disabled" is good (not vulnerable)
                if resp_body.contains("SignUp is disabled") || resp_body.contains("NotAuthorizedException") {
                    debug!("[Cognito] SignUp is properly disabled");
                }
            }
            Err(e) => {
                debug!("[Cognito] SignUp test failed: {}", e);
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
            ("Content-Type".to_string(), "application/x-amz-json-1.1".to_string()),
            ("X-Amz-Target".to_string(), "AWSCognitoIdentityProviderService.InitiateAuth".to_string()),
        ];

        debug!("[Cognito] Testing InitiateAuth for user enumeration");

        match self.http_client.post_with_headers(endpoint, &body, headers).await {
            Ok(response) => {
                let resp_body = &response.body;

                // If response explicitly says "User does not exist", enumeration is possible
                if resp_body.contains("UserNotFoundException") ||
                   resp_body.contains("User does not exist") {
                    vulnerabilities.push(Vulnerability {
                        vuln_type: "AWS Cognito Auth User Enumeration".to_string(),
                        severity: Severity::Medium,
                        url: url.to_string(),
                        evidence: format!(
                            "Cognito reveals user existence through InitiateAuth API.\n\
                             Non-existent users return 'UserNotFoundException'.\n\
                             Existing users return 'NotAuthorizedException' for wrong password."
                        ),
                        payload: "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth".to_string(),
                        remediation:
                            "1. Enable 'Prevent user existence errors' in Cognito settings\n\
                             2. This will return generic 'NotAuthorizedException' for all auth failures\n\
                             3. Implement account lockout and rate limiting\n\
                             4. Monitor for enumeration attempts".to_string(),
                        description:
                            "AWS Cognito InitiateAuth API reveals whether a username exists. \
                             Attackers can enumerate valid usernames for targeted attacks.".to_string(),
                        cwe: "CWE-204".to_string(),
                        cvss: 5.3,
                        parameter: "USERNAME".to_string(),
                        confidence: Confidence::High,
                        request: None,
                        response: None,
                    });
                }
            }
            Err(e) => {
                debug!("[Cognito] InitiateAuth test failed: {}", e);
            }
        }

        Ok((vulnerabilities, 1))
    }

    /// Check if a user exists via ForgotPassword API
    async fn check_user_exists(&self, endpoint: &str, client_id: &str, username: &str) -> EnumResult {
        let body = format!(
            r#"{{"ClientId":"{}","Username":"{}"}}"#,
            client_id, username
        );

        let headers = vec![
            ("Content-Type".to_string(), "application/x-amz-json-1.1".to_string()),
            ("X-Amz-Target".to_string(), "AWSCognitoIdentityProviderService.ForgotPassword".to_string()),
        ];

        match self.http_client.post_with_headers(endpoint, &body, headers).await {
            Ok(response) => {
                let body = &response.body;

                // Check for successful response (user exists with verified contact)
                if body.contains("CodeDeliveryDetails") {
                    // Extract destination (partial email/phone)
                    let destination = self.extract_json_field(body, "Destination")
                        .unwrap_or_else(|| "[redacted]".to_string());
                    let medium = self.extract_json_field(body, "DeliveryMedium")
                        .unwrap_or_else(|| "unknown".to_string());
                    return EnumResult::ExistsWithContact { destination, medium };
                }

                // User exists but has no verified email/phone
                if body.contains("InvalidParameterException") &&
                   (body.contains("no registered/verified") || body.contains("Cannot reset password")) {
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
                EnumResult::Error(format!("Unknown response: {}", &body[..body.len().min(100)]))
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
            "admin", "administrator", "root", "test", "user", "support",
            "info", "contact", "helpdesk", "it", "security", "noreply",
            "system", "service", "api", "bot", "backup", "dev", "ops",
            "hr", "finance", "sales", "marketing", "webmaster", "postmaster",
            "guest", "demo", "training", "staff", "employee",
        ];
        usernames.extend(system.iter().map(|s| s.to_string()));

        // Finnish names (common)
        let finnish = [
            "matti", "mikko", "jukka", "juha", "timo", "antti", "kari",
            "pekka", "markku", "jari", "petri", "heikki", "seppo", "ville",
            "sami", "tommi", "tuomas", "lauri", "teemu", "aki",
            "anna", "maria", "liisa", "päivi", "sari", "tiina", "minna",
            "kirsi", "anne", "johanna", "hanna", "katja", "marika", "sanna",
            "laura", "elina", "jenni", "riikka", "piia", "nina",
        ];
        usernames.extend(finnish.iter().map(|s| s.to_string()));

        // Swedish names (common)
        let swedish = [
            "johan", "erik", "lars", "anders", "peter", "mikael", "karl",
            "stefan", "thomas", "jan", "marcus", "fredrik", "daniel",
            "mattias", "niklas", "henrik", "jonas", "christian", "alexander",
            "oscar", "david", "patrik", "magnus", "martin", "andreas",
            "emma", "anna", "maria", "sara", "linda", "jenny", "jessica",
            "sandra", "johanna", "elin", "sofia", "ida", "amanda", "lisa",
        ];
        usernames.extend(swedish.iter().map(|s| s.to_string()));

        // American/English names (common)
        let american = [
            "john", "james", "robert", "michael", "william", "david",
            "richard", "joseph", "thomas", "charles", "christopher", "daniel",
            "matthew", "anthony", "mark", "steven", "paul", "andrew", "brian",
            "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara",
            "susan", "jessica", "sarah", "karen", "lisa", "nancy", "betty",
            "margaret", "sandra", "ashley", "emily", "donna", "michelle",
        ];
        usernames.extend(american.iter().map(|s| s.to_string()));

        // German names (common)
        let german = [
            "hans", "peter", "michael", "thomas", "andreas", "stefan",
            "christian", "martin", "markus", "daniel", "sebastian", "tobias",
            "julia", "anna", "laura", "lena", "sarah", "lisa", "marie",
            "katharina", "sophie", "maria", "claudia", "andrea", "nicole",
        ];
        usernames.extend(german.iter().map(|s| s.to_string()));

        // Common email patterns (will be adapted per-target)
        let patterns = [
            "info", "contact", "support", "admin", "sales", "marketing",
            "hello", "office", "mail", "team", "help", "service",
        ];
        usernames.extend(patterns.iter().map(|s| s.to_string()));

        usernames
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
        let pool_pattern = Regex::new(r#"['"]((?:eu|us|ap|sa|ca|me|af)-[a-z]+-[0-9]+_[A-Za-z0-9]+)['"]"#).unwrap();
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
