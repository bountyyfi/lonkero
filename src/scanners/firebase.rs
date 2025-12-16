// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Firebase Security Scanner
 * Tests for Firebase authentication vulnerabilities
 *
 * Detects:
 * - Email enumeration via Firebase Authentication API
 * - Exposed Firebase API keys
 * - Missing email enumeration protection
 * - Firebase configuration exposure
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct FirebaseScanner {
    http_client: Arc<HttpClient>,
}

/// Firebase API key detection result
#[derive(Clone)]
struct FirebaseConfig {
    api_key: String,
    project_id: Option<String>,
    found_in: String,
}

/// Common Firebase paths to test (70+ paths from hackday)
const COMMON_PATHS: &[&str] = &[
    "/users.json",
    "/user.json",
    "/accounts.json",
    "/admin.json",
    "/admins.json",
    "/config.json",
    "/configuration.json",
    "/settings.json",
    "/data.json",
    "/public.json",
    "/private.json",
    "/secret.json",
    "/secrets.json",
    "/api.json",
    "/keys.json",
    "/tokens.json",
    "/auth.json",
    "/authentication.json",
    "/credentials.json",
    "/passwords.json",
    "/messages.json",
    "/chat.json",
    "/chats.json",
    "/posts.json",
    "/comments.json",
    "/orders.json",
    "/transactions.json",
    "/payments.json",
    "/billing.json",
    "/customers.json",
    "/profiles.json",
    "/members.json",
    "/logs.json",
    "/debug.json",
    "/test.json",
    "/dev.json",
    "/staging.json",
    "/prod.json",
    "/backup.json",
    "/dump.json",
    "/export.json",
    "/internal.json",
    "/system.json",
    "/api_keys.json",
    "/firebase.json",
    "/analytics.json",
    "/notifications.json",
    "/sessions.json",
    "/temp.json",
    "/uploads.json",
    "/documents.json",
    "/metadata.json",
    "/version.json",
];

/// Common Firestore collections
const FIRESTORE_COLLECTIONS: &[&str] = &[
    "users",
    "customers",
    "orders",
    "accounts",
    "config",
    "settings",
    "admin",
    "messages",
    "posts",
    "products",
];

/// Common Storage prefixes
const STORAGE_PREFIXES: &[&str] = &[
    "uploads/",
    "images/",
    "files/",
    "documents/",
    "public/",
    "media/",
    "assets/",
];

impl FirebaseScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for Firebase vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Scanning for Firebase vulnerabilities");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Step 1a: Check if URL itself is a Firebase URL
        let direct_project_id = self.detect_direct_firebase_url(url);

        // Step 1b: Detect Firebase API keys and project IDs from page content
        tests_run += 1;
        let mut firebase_configs = self.detect_firebase_config(url).await;

        // Get project ID (prioritize direct URL detection, then configs)
        let project_id = direct_project_id.or_else(|| {
            firebase_configs
                .iter()
                .find(|c| c.project_id.is_some())
                .and_then(|c| c.project_id.clone())
        });

        // If we have a direct Firebase URL but no configs, create a placeholder
        if let Some(ref pid) = direct_project_id {
            if firebase_configs.is_empty() {
                info!("Direct Firebase URL detected: {}", url);
                firebase_configs.push(FirebaseConfig {
                    api_key: String::new(), // No API key from URL alone
                    project_id: Some(pid.clone()),
                    found_in: "Direct Firebase URL".to_string(),
                });
            }
        }

        if firebase_configs.is_empty() && project_id.is_none() {
            debug!("No Firebase API keys, project IDs, or Firebase URLs detected");
            return Ok((Vec::new(), tests_run));
        }

        info!("Found {} Firebase configuration(s)", firebase_configs.len());

        // Step 2: Test Realtime Database (doesn't need API key)
        if let Some(ref project_id_val) = project_id {
            info!("Testing Firebase Realtime Database for project: {}", project_id_val);

            let (rtdb_vulns, rtdb_tests) = self.test_realtime_database(project_id_val, url).await;
            vulnerabilities.extend(rtdb_vulns);
            tests_run += rtdb_tests;
        }

        // Step 3: Test Firestore (doesn't need API key initially)
        if let Some(ref project_id_val) = project_id {
            info!("Testing Firestore for project: {}", project_id_val);

            let (firestore_vulns, firestore_tests) = self.test_firestore(project_id_val, url).await;
            vulnerabilities.extend(firestore_vulns);
            tests_run += firestore_tests;
        }

        // Step 4: Test Firebase Storage (doesn't need API key initially)
        if let Some(ref project_id_val) = project_id {
            info!("Testing Firebase Storage for project: {}", project_id_val);

            let (storage_vulns, storage_tests) = self.test_storage(project_id_val, url).await;
            vulnerabilities.extend(storage_vulns);
            tests_run += storage_tests;
        }

        // Step 5: Test Firebase config discovery
        if let Some(ref project_id_val) = project_id {
            info!("Testing Firebase config discovery");

            let (config_vulns, config_tests) = self.test_config_discovery(project_id_val, url).await;
            vulnerabilities.extend(config_vulns);
            tests_run += config_tests;
        }

        // Step 6: Test Remote Config
        if let Some(ref project_id_val) = project_id {
            let (remote_config_vulns, remote_config_tests) = self.test_remote_config(project_id_val, url).await;
            vulnerabilities.extend(remote_config_vulns);
            tests_run += remote_config_tests;
        }

        // Step 7: Test Cloud Functions
        if let Some(ref project_id_val) = project_id {
            info!("Testing Cloud Functions for project: {}", project_id_val);

            let (functions_vulns, functions_tests) = self.test_cloud_functions(project_id_val, url).await;
            vulnerabilities.extend(functions_vulns);
            tests_run += functions_tests;
        }

        // Step 8: API key tests (only if we have valid API keys)
        for firebase_config in &firebase_configs {
            // Validate API key first
            if !self.validate_api_key(&firebase_config.api_key).await {
                debug!("API key {}... is invalid, skipping API key tests", &firebase_config.api_key[..15]);
                continue;
            }

            info!("Valid Firebase API key detected, testing authentication vulnerabilities");

            // Test email enumeration
            tests_run += 1;
            if let Some(vuln) = self.test_email_enumeration(firebase_config, url).await {
                vulnerabilities.push(vuln);
            }

            // Test anonymous signup
            tests_run += 1;
            if let Some(vuln) = self.test_anonymous_signup(firebase_config, url).await {
                vulnerabilities.push(vuln);
            }

            // Test password reset enumeration
            tests_run += 1;
            if let Some(vuln) = self.test_password_reset_enum(firebase_config, url).await {
                vulnerabilities.push(vuln);
            }

            // Test Google API key (Maps, Translation)
            tests_run += 1;
            if let Some(vuln) = self.test_google_api_key(firebase_config, url).await {
                vulnerabilities.push(vuln);
            }

            // Only test one valid API key to avoid excessive requests
            break;
        }

        // Fast mode: stop after finding vulnerabilities
        if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
            return Ok((vulnerabilities, tests_run));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect Firebase API keys in page content and JavaScript
    async fn detect_firebase_config(&self, url: &str) -> Vec<FirebaseConfig> {
        let mut configs = Vec::new();

        // Get the main page
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return configs,
        };

        // Pattern 1: Firebase API key (AIza...)
        let api_key_pattern = Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).unwrap();

        // Pattern 2: Firebase config object
        let config_pattern = Regex::new(
            r#"(?i)apiKey["']?\s*:\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?"#
        ).unwrap();

        // Pattern 3: Project ID
        let project_pattern = Regex::new(
            r#"(?i)projectId["']?\s*:\s*["']?([a-z0-9\-]+)["']?"#
        ).unwrap();

        let body = &response.body;

        // Extract API keys
        for cap in api_key_pattern.captures_iter(body) {
            let api_key = cap[0].to_string();

            // Try to find associated project ID
            let project_id = project_pattern
                .captures(body)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            debug!("Found Firebase API key in page content");

            configs.push(FirebaseConfig {
                api_key,
                project_id,
                found_in: "page content".to_string(),
            });
        }

        // Also check for API keys in config objects
        for cap in config_pattern.captures_iter(body) {
            let api_key = cap[1].to_string();

            // Avoid duplicates
            if !configs.iter().any(|c| c.api_key == api_key) {
                let project_id = project_pattern
                    .captures(body)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());

                debug!("Found Firebase API key in config object");

                configs.push(FirebaseConfig {
                    api_key,
                    project_id,
                    found_in: "Firebase config".to_string(),
                });
            }
        }

        // Try to fetch JavaScript files and search for Firebase config
        if configs.is_empty() {
            // Look for script tags
            let script_pattern = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();

            for cap in script_pattern.captures_iter(body) {
                if let Some(script_url) = cap.get(1) {
                    let script_url_str = script_url.as_str();

                    // Skip external CDN scripts
                    if script_url_str.contains("firebase") && !script_url_str.starts_with("http") {
                        // Construct full URL
                        let full_url = if script_url_str.starts_with('/') {
                            format!("{}{}", self.get_base_url(url), script_url_str)
                        } else {
                            format!("{}/{}", url.trim_end_matches('/'), script_url_str)
                        };

                        if let Ok(js_response) = self.http_client.get(&full_url).await {
                            // Search for Firebase config in JavaScript
                            for cap in config_pattern.captures_iter(&js_response.body) {
                                let api_key = cap[1].to_string();

                                if !configs.iter().any(|c| c.api_key == api_key) {
                                    let project_id = project_pattern
                                        .captures(&js_response.body)
                                        .and_then(|c| c.get(1))
                                        .map(|m| m.as_str().to_string());

                                    debug!("Found Firebase API key in JavaScript file: {}", script_url_str);

                                    configs.push(FirebaseConfig {
                                        api_key,
                                        project_id,
                                        found_in: format!("JavaScript: {}", script_url_str),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        configs
    }

    /// Detect if URL is a direct Firebase URL
    fn detect_direct_firebase_url(&self, url: &str) -> Option<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                // Check for Firebase Realtime Database: PROJECT.firebaseio.com
                if host.ends_with(".firebaseio.com") {
                    let parts: Vec<&str> = host.split('.').collect();
                    if parts.len() >= 3 {
                        return Some(parts[0].to_string());
                    }
                }

                // Check for Firebase Hosting: PROJECT.web.app or PROJECT.firebaseapp.com
                if host.ends_with(".web.app") || host.ends_with(".firebaseapp.com") {
                    let parts: Vec<&str> = host.split('.').collect();
                    if parts.len() >= 2 {
                        return Some(parts[0].to_string());
                    }
                }

                // Check for Firestore: firestore.googleapis.com (extract from path)
                if host == "firestore.googleapis.com" {
                    let path = parsed.path();
                    if path.contains("/projects/") {
                        if let Some(start) = path.find("/projects/") {
                            let after = &path[start + 10..];
                            if let Some(end) = after.find('/') {
                                return Some(after[..end].to_string());
                            }
                        }
                    }
                }

                // Check for Firebase Storage: firebasestorage.googleapis.com
                if host == "firebasestorage.googleapis.com" {
                    let path = parsed.path();
                    if path.contains("/b/") {
                        if let Some(start) = path.find("/b/") {
                            let after = &path[start + 3..];
                            if let Some(end) = after.find(".appspot.com") {
                                return Some(after[..end].to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Test Firebase config discovery endpoints
    async fn test_config_discovery(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let config_urls = vec![
            format!("https://{}.web.app/__/firebase/init.json", project_id),
            format!("https://{}.firebaseapp.com/__/firebase/init.json", project_id),
            format!("https://{}.firebaseio.com/.settings/rules.json", project_id),
        ];

        for config_url in config_urls {
            tests_run += 1;
            if let Ok(response) = self.http_client.get(&config_url).await {
                if response.status_code == 200 && !response.body.is_empty() {
                    let is_config = response.body.contains("\"apiKey\"") ||
                                   response.body.contains("\"projectId\"") ||
                                   response.body.contains("\"rules\"");

                    if is_config {
                        info!("Firebase configuration exposed at: {}", config_url);

                        vulnerabilities.push(Vulnerability {
                            id: format!("firebase_config_{}", Self::generate_id()),
                            vuln_type: "Firebase Configuration Disclosure".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: url.to_string(),
                            parameter: None,
                            payload: config_url.clone(),
                            description: format!(
                                "Firebase configuration is publicly accessible at {}. \
                                This may expose API keys, project details, or security rules.",
                                config_url
                            ),
                            evidence: Some(format!(
                                "URL: {}\nStatus: {}\nConfiguration found",
                                config_url, response.status_code
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Remove publicly accessible configuration files\n\
                                          2. Use environment variables for sensitive config\n\
                                          3. Implement authentication for config endpoints\n\
                                          4. Review Firebase security rules".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test Firebase Remote Config
    async fn test_remote_config(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let remote_config_url = format!(
            "https://firebaseremoteconfig.googleapis.com/v1/projects/{}/remoteConfig",
            project_id
        );

        tests_run += 1;
        if let Ok(response) = self.http_client.get(&remote_config_url).await {
            if response.status_code == 200 && response.body.contains("\"parameters\"") {
                info!("Firebase Remote Config is publicly accessible");

                vulnerabilities.push(Vulnerability {
                    id: format!("firebase_remote_config_{}", Self::generate_id()),
                    vuln_type: "Firebase Remote Config - Public Access".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Access Control".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: remote_config_url.clone(),
                    description: format!(
                        "Firebase Remote Config for project '{}' is publicly accessible.",
                        project_id
                    ),
                    evidence: Some(format!(
                        "URL: {}\nStatus: {}\nConfig parameters exposed",
                        remote_config_url, response.status_code
                    )),
                    cwe: "CWE-732".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Restrict Remote Config API access\n\
                                  2. Require authentication for config retrieval\n\
                                  3. Review Remote Config permissions\n\
                                  4. Use IAM policies to limit access".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test password reset for email enumeration
    async fn test_password_reset_enum(&self, config: &FirebaseConfig, url: &str) -> Option<Vulnerability> {
        let endpoint = format!(
            "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={}",
            config.api_key
        );

        let test_email = format!("nonexistent-test-{}@example.invalid",
            uuid::Uuid::new_v4().to_string());

        let payload = json!({
            "requestType": "PASSWORD_RESET",
            "email": test_email
        });

        match self.make_firebase_request(&endpoint, &payload).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();

                // Check if response reveals whether email exists
                if body_lower.contains("user_not_found") ||
                   body_lower.contains("email not found") ||
                   (response.status_code == 400 && body_lower.contains("\"error\"")) {
                    info!("Password reset endpoint allows email enumeration");

                    return Some(Vulnerability {
                        id: format!("firebase_password_enum_{}", Self::generate_id()),
                        vuln_type: "Firebase Password Reset Email Enumeration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: url.to_string(),
                        parameter: Some("email".to_string()),
                        payload: test_email,
                        description: "Firebase password reset endpoint reveals whether an email is registered. \
                                      Error messages differ for existing vs non-existing accounts.".to_string(),
                        evidence: Some(format!(
                            "Endpoint: {}\nResponse reveals account existence through error messages",
                            endpoint
                        )),
                        cwe: "CWE-204".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Return generic error messages for password reset\n\
                                      2. Enable email enumeration protection in Firebase Console\n\
                                      3. Use same response for existing and non-existing accounts\n\
                                      4. Implement rate limiting on password reset requests".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Err(_) => {}
        }

        None
    }

    /// Test if Google API key works with Maps/Translation APIs
    async fn test_google_api_key(&self, config: &FirebaseConfig, url: &str) -> Option<Vulnerability> {
        let mut exposed_apis = Vec::new();

        // Test Maps API
        let maps_url = format!(
            "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=100x100&key={}",
            config.api_key
        );

        if let Ok(response) = self.http_client.get(&maps_url).await {
            if response.status_code == 200 && response.body.len() > 1000 {
                exposed_apis.push("Google Maps API");
            }
        }

        // Test Translation API
        let translation_url = format!(
            "https://translation.googleapis.com/language/translate/v2?key={}&q=test&target=fi",
            config.api_key
        );

        if let Ok(response) = self.http_client.get(&translation_url).await {
            if response.status_code == 200 && response.body.contains("\"translatedText\"") {
                exposed_apis.push("Google Translation API");
            }
        }

        if !exposed_apis.is_empty() {
            info!("Firebase API key works with: {}", exposed_apis.join(", "));

            return Some(Vulnerability {
                id: format!("firebase_api_abuse_{}", Self::generate_id()),
                vuln_type: "Firebase API Key - Google Services Accessible".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "Configuration".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: format!("API Key: {}...", &config.api_key[..20]),
                description: format!(
                    "Firebase API key can be used to access Google services: {}. \
                    This may result in quota abuse and unexpected billing.",
                    exposed_apis.join(", ")
                ),
                evidence: Some(format!(
                    "Accessible APIs: {}\n\
                    API key should be restricted to specific services and domains.",
                    exposed_apis.join(", ")
                )),
                cwe: "CWE-284".to_string(),
                cvss: 7.5,
                verified: true,
                false_positive: false,
                remediation: "1. Restrict API key to specific APIs in Google Cloud Console\n\
                              2. Add HTTP referrer restrictions\n\
                              3. Add IP address restrictions for server keys\n\
                              4. Regenerate compromised keys\n\
                              5. Monitor API usage for abuse\n\
                              6. Set usage quotas to prevent billing surprises".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        None
    }

    /// Test Firebase Authentication API for email enumeration vulnerability
    async fn test_email_enumeration(
        &self,
        config: &FirebaseConfig,
        url: &str,
    ) -> Option<Vulnerability> {
        info!("Testing Firebase email enumeration with API key: {}...", &config.api_key[..20]);

        // Firebase Identity Toolkit endpoint
        let endpoint = format!(
            "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={}",
            config.api_key
        );

        // Test with a non-existent email (highly unlikely to exist)
        let test_email_nonexistent = format!("nonexistent-test-{}@example.invalid",
            uuid::Uuid::new_v4().to_string());

        let payload = json!({
            "identifier": test_email_nonexistent,
            "continueUri": "http://localhost"
        });

        let response_nonexistent = match self.make_firebase_request(&endpoint, &payload).await {
            Ok(r) => r,
            Err(e) => {
                debug!("Firebase request failed: {}", e);
                return None;
            }
        };

        // Check if the response contains "registered" field
        if let Ok(json_response) = serde_json::from_str::<Value>(&response_nonexistent.body) {
            // Check for email enumeration vulnerability
            if let Some(registered) = json_response.get("registered") {
                if registered.is_boolean() {
                    let is_registered = registered.as_bool().unwrap_or(false);

                    info!(
                        "Firebase email enumeration CONFIRMED: API returns registered={} for test email",
                        is_registered
                    );

                    let evidence = format!(
                        "Firebase API key: {}...\n\
                        Endpoint: POST {}\n\
                        Test email: {}\n\
                        Response contains 'registered' field: {}\n\
                        \n\
                        The API response reveals whether an email is registered:\n\
                        {}\n\
                        \n\
                        This allows attackers to:\n\
                        1. Enumerate valid user emails\n\
                        2. Build targeted phishing lists\n\
                        3. Verify customer relationships\n\
                        4. Prepare credential stuffing attacks",
                        &config.api_key[..20],
                        endpoint,
                        test_email_nonexistent,
                        registered,
                        serde_json::to_string_pretty(&json_response).unwrap_or_default()
                    );

                    let description = if let Some(project_id) = &config.project_id {
                        format!(
                            "Firebase Authentication API (project: {}) allows email enumeration. \
                            The createAuthUri endpoint returns a 'registered' boolean field that \
                            reveals whether an email address is registered with the service. \
                            This enables attackers to enumerate valid user accounts.",
                            project_id
                        )
                    } else {
                        "Firebase Authentication API allows email enumeration. \
                        The createAuthUri endpoint returns a 'registered' boolean field that \
                        reveals whether an email address is registered with the service. \
                        This enables attackers to enumerate valid user accounts.".to_string()
                    };

                    return Some(Vulnerability {
                        id: format!("firebase_enum_{}", Self::generate_id()),
                        vuln_type: "Firebase Email Enumeration".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: url.to_string(),
                        parameter: Some("Firebase API".to_string()),
                        payload: format!("API Key: {}...", &config.api_key[..20]),
                        description,
                        evidence: Some(evidence),
                        cwe: "CWE-204".to_string(), // Observable Response Discrepancy
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. CRITICAL: Enable email enumeration protection in Firebase Console:\n\
                                      - Go to Firebase Console → Authentication → Settings\n\
                                      - Navigate to 'User Actions' section\n\
                                      - Enable 'Email enumeration protection'\n\
                                      \n\
                                      2. Implement rate limiting on authentication endpoints\n\
                                      3. Add CAPTCHA for password reset and login attempts\n\
                                      4. Monitor for enumeration attempts (multiple createAuthUri calls)\n\
                                      5. Consider using anonymous authentication flows\n\
                                      6. Implement account lockout after multiple failed attempts\n\
                                      \n\
                                      Reference: https://cloud.google.com/identity-platform/docs/admin/email-enumeration-protection".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        // Check for error responses that might indicate API key validity
        if response_nonexistent.status_code == 400 {
            // API key works but might have different response format
            debug!("Firebase API key is valid but response format differs");
        } else if response_nonexistent.status_code == 401 || response_nonexistent.status_code == 403 {
            debug!("Firebase API key appears to be invalid or restricted");
        }

        None
    }

    /// Make a POST request to Firebase API
    async fn make_firebase_request(&self, endpoint: &str, payload: &Value) -> Result<HttpResponse> {
        let payload_str = serde_json::to_string(payload)?;

        // Use POST method with JSON body
        let response = self.http_client.post(endpoint, payload_str).await?;

        Ok(response)
    }

    /// Extract base URL from a full URL
    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("localhost");
            let scheme = parsed.scheme();

            if let Some(port) = parsed.port() {
                format!("{}://{}:{}", scheme, host, port)
            } else {
                format!("{}://{}", scheme, host)
            }
        } else {
            url.to_string()
        }
    }

    /// Validate Firebase API key by making a test request
    async fn validate_api_key(&self, api_key: &str) -> bool {
        let endpoint = format!(
            "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={}",
            api_key
        );

        let test_payload = json!({
            "identifier": "test@example.invalid",
            "continueUri": "http://localhost"
        });

        match self.make_firebase_request(&endpoint, &test_payload).await {
            Ok(response) => {
                // 200 = valid key, 400 with JSON = valid key with error
                // 401/403 = invalid key
                response.status_code == 200 || (response.status_code == 400 && response.body.contains("\"error\""))
            }
            Err(_) => false,
        }
    }

    /// Test Firebase Realtime Database for open access
    async fn test_realtime_database(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let rtdb_url = format!("https://{}.firebaseio.com", project_id);

        // Test 1: Root read access
        tests_run += 1;
        let root_url = format!("{}/.json", rtdb_url);
        if let Ok(response) = self.http_client.get(&root_url).await {
            if response.status_code == 200 && !response.body.is_empty() && response.body != "null" {
                info!("Firebase Realtime Database root is publicly readable!");

                vulnerabilities.push(Vulnerability {
                    id: format!("firebase_rtdb_read_{}", Self::generate_id()),
                    vuln_type: "Firebase Realtime Database - Public Read Access".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Access Control".to_string(),
                    url: url.to_string(),
                    parameter: Some("Firebase RTDB".to_string()),
                    payload: root_url.clone(),
                    description: format!(
                        "Firebase Realtime Database for project '{}' is publicly readable. \
                        Anyone can read all data without authentication.",
                        project_id
                    ),
                    evidence: Some(format!(
                        "URL: {}\nStatus: {}\nData accessible: {} bytes\n\nSample:\n{}",
                        root_url,
                        response.status_code,
                        response.body.len(),
                        if response.body.len() > 500 {
                            format!("{}... [truncated]", &response.body[..500])
                        } else {
                            response.body.clone()
                        }
                    )),
                    cwe: "CWE-732".to_string(),
                    cvss: 9.1,
                    verified: true,
                    false_positive: false,
                    remediation: "1. CRITICAL: Fix Firebase Realtime Database security rules immediately\n\
                                  2. Go to Firebase Console → Realtime Database → Rules\n\
                                  3. Replace permissive rules with:\n\
                                  {\n\
                                    \"rules\": {\n\
                                      \".read\": \"auth != null\",\n\
                                      \".write\": \"auth != null\"\n\
                                    }\n\
                                  }\n\
                                  4. Test rules before deploying\n\
                                  5. Implement granular path-based rules\n\
                                  6. Audit existing data for exposed sensitive information".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Test 2: Rules disclosure
        tests_run += 1;
        let rules_url = format!("{}/.settings/rules.json", rtdb_url);
        if let Ok(response) = self.http_client.get(&rules_url).await {
            if response.status_code == 200 && !response.body.is_empty() && response.body != "null" {
                info!("Firebase Realtime Database rules are publicly accessible!");

                vulnerabilities.push(Vulnerability {
                    id: format!("firebase_rules_{}", Self::generate_id()),
                    vuln_type: "Firebase Realtime Database - Rules Disclosure".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: url.to_string(),
                    parameter: Some("Rules".to_string()),
                    payload: rules_url.clone(),
                    description: format!(
                        "Firebase Realtime Database security rules for project '{}' are publicly accessible. \
                        This reveals the security model and may help attackers identify weaknesses.",
                        project_id
                    ),
                    evidence: Some(format!(
                        "URL: {}\nStatus: {}\nRules: {}",
                        rules_url, response.status_code,
                        if response.body.len() > 200 {
                            format!("{}... [truncated]", &response.body[..200])
                        } else {
                            response.body.clone()
                        }
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Restrict access to /.settings/rules.json\n\
                                  2. Review Firebase security rules\n\
                                  3. Follow principle of least privilege in rules\n\
                                  4. Use Firebase Console to manage rules securely".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Test 3: Common sensitive paths
        for path in COMMON_PATHS.iter().take(15) {  // Test 15 paths
            tests_run += 1;
            let test_url = format!("{}{}", rtdb_url, path);

            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && !response.body.is_empty() && response.body != "null" {
                    info!("Firebase RTDB path accessible: {}", path);

                    vulnerabilities.push(Vulnerability {
                        id: format!("firebase_rtdb_path_{}", Self::generate_id()),
                        vuln_type: "Firebase Realtime Database - Sensitive Path Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Access Control".to_string(),
                        url: url.to_string(),
                        parameter: Some(format!("Path: {}", path)),
                        payload: test_url.clone(),
                        description: format!(
                            "Firebase Realtime Database path '{}' is publicly accessible for project '{}'.",
                            path, project_id
                        ),
                        evidence: Some(format!(
                            "URL: {}\nStatus: {}\nData: {} bytes",
                            test_url, response.status_code, response.body.len()
                        )),
                        cwe: "CWE-732".to_string(),
                        cvss: 8.2,
                        verified: true,
                        false_positive: false,
                        remediation: "Fix Firebase Realtime Database security rules. See Firebase documentation.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });

                    // Only report first sensitive path to avoid spam
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test Firestore for open access
    async fn test_firestore(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let firestore_base = format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/(default)/documents",
            project_id
        );

        // Test common collections
        for collection in FIRESTORE_COLLECTIONS.iter().take(5) {  // Limit requests
            tests_run += 1;
            let collection_url = format!("{}/{}", firestore_base, collection);

            if let Ok(response) = self.http_client.get(&collection_url).await {
                if response.status_code == 200 && response.body.contains("\"documents\"") {
                    info!("Firestore collection '{}' is publicly readable", collection);

                    vulnerabilities.push(Vulnerability {
                        id: format!("firebase_firestore_{}", Self::generate_id()),
                        vuln_type: "Firestore - Public Collection Access".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Access Control".to_string(),
                        url: url.to_string(),
                        parameter: Some(format!("Collection: {}", collection)),
                        payload: collection_url.clone(),
                        description: format!(
                            "Firestore collection '{}' in project '{}' is publicly accessible.",
                            collection, project_id
                        ),
                        evidence: Some(format!(
                            "URL: {}\nStatus: {}\nDocuments found",
                            collection_url, response.status_code
                        )),
                        cwe: "CWE-732".to_string(),
                        cvss: 9.1,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Fix Firestore security rules\n\
                                      2. Go to Firebase Console → Firestore → Rules\n\
                                      3. Implement authentication-based rules\n\
                                      4. Never use 'allow read, write: if true;'".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });

                    // Only report first accessible collection
                    break;
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test Firebase Storage for public access
    async fn test_storage(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let storage_bucket = format!("{}.appspot.com", project_id);
        let storage_url = format!(
            "https://firebasestorage.googleapis.com/v0/b/{}/o",
            storage_bucket
        );

        // Test root bucket list
        tests_run += 1;
        if let Ok(response) = self.http_client.get(&storage_url).await {
            if response.status_code == 200 && response.body.contains("\"items\"") {
                info!("Firebase Storage bucket is publicly listable");

                vulnerabilities.push(Vulnerability {
                    id: format!("firebase_storage_{}", Self::generate_id()),
                    vuln_type: "Firebase Storage - Public Bucket Listing".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Access Control".to_string(),
                    url: url.to_string(),
                    parameter: Some("Firebase Storage".to_string()),
                    payload: storage_url.clone(),
                    description: format!(
                        "Firebase Storage bucket for project '{}' allows public file listing.",
                        project_id
                    ),
                    evidence: Some(format!(
                        "URL: {}\nStatus: {}\nBucket: {}",
                        storage_url, response.status_code, storage_bucket
                    )),
                    cwe: "CWE-732".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Fix Firebase Storage security rules\n\
                                  2. Go to Firebase Console → Storage → Rules\n\
                                  3. Restrict read access to authenticated users\n\
                                  4. Never use 'allow read: if true;'".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test Cloud Functions discovery
    async fn test_cloud_functions(&self, project_id: &str, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let regions = vec!["us-central1", "europe-west1"];

        for region in regions {
            tests_run += 1;
            let functions_url = format!(
                "https://{}-{}.cloudfunctions.net/",
                region, project_id
            );

            if let Ok(response) = self.http_client.get(&functions_url).await {
                if response.status_code != 404 {
                    debug!("Cloud Functions region {} accessible", region);

                    // This is informational, not necessarily a vulnerability
                    // Only report if we find actual exposed functions
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test anonymous signup capability
    async fn test_anonymous_signup(&self, config: &FirebaseConfig, url: &str) -> Option<Vulnerability> {
        let endpoint = format!(
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={}",
            config.api_key
        );

        let payload = json!({
            "returnSecureToken": true
        });

        match self.make_firebase_request(&endpoint, &payload).await {
            Ok(response) => {
                if response.status_code == 200 && response.body.contains("\"idToken\"") {
                    info!("Firebase allows anonymous signups");

                    return Some(Vulnerability {
                        id: format!("firebase_anon_{}", Self::generate_id()),
                        vuln_type: "Firebase - Anonymous Authentication Enabled".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "Configuration".to_string(),
                        url: url.to_string(),
                        parameter: Some("Firebase Auth".to_string()),
                        payload: "Anonymous signup enabled".to_string(),
                        description: format!(
                            "Firebase Authentication allows anonymous user creation for project '{:?}'. \
                            While not always a vulnerability, this could allow abuse if not properly rate-limited.",
                            config.project_id
                        ),
                        evidence: Some("Successfully created anonymous user account".to_string()),
                        cwe: "CWE-306".to_string(),
                        cvss: 3.7,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Review if anonymous authentication is needed\n\
                                      2. If not needed, disable in Firebase Console → Authentication\n\
                                      3. If needed, implement rate limiting and abuse prevention\n\
                                      4. Monitor for anomalous signup patterns".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Err(_) => {}
        }

        None
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use rand::Rng;
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

// UUID generation
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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

    #[test]
    fn test_firebase_api_key_pattern() {
        let pattern = Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).unwrap();

        // Valid Firebase API key
        assert!(pattern.is_match("AIzaSyB0sQji446z_60MwtHZAEGPfuHNVqYVJp0"));

        // Invalid patterns
        assert!(!pattern.is_match("AIza123")); // Too short
        assert!(!pattern.is_match("AIZA1234567890123456789012345678901234")); // Wrong prefix
    }

    #[test]
    fn test_firebase_config_extraction() {
        let html = r#"
        <script>
        var firebaseConfig = {
            apiKey: "AIzaSyB0sQji446z_60MwtHZAEGPfuHNVqYVJp0",
            authDomain: "test-project.firebaseapp.com",
            projectId: "test-project"
        };
        </script>
        "#;

        let api_key_pattern = Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).unwrap();
        assert!(api_key_pattern.is_match(html));

        let project_pattern = Regex::new(r#"(?i)projectId["']?\s*:\s*["']?([a-z0-9\-]+)["']?"#).unwrap();
        let cap = project_pattern.captures(html).unwrap();
        assert_eq!(cap.get(1).unwrap().as_str(), "test-project");
    }
}
