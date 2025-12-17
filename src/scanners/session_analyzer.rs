// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Advanced Session Security Analyzer
//!
//! Deep analysis of session management including:
//! - Session tracking across login/action/logout flow
//! - Logout invalidation testing
//! - Session ID entropy measurement
//! - Session fixation testing
//! - Concurrent session handling

use crate::auth_context::{AuthSession, Authenticator, LoginCredentials};
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Session Analyzer for deep session security testing
pub struct SessionAnalyzer {
    http_client: Arc<HttpClient>,
}

impl SessionAnalyzer {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Full session security analysis
    pub async fn analyze(
        &self,
        url: &str,
        credentials: Option<&LoginCredentials>,
        existing_session: Option<&AuthSession>,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[Session] Starting deep session analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // 1. Collect multiple session IDs to measure entropy
        tests_run += 1;
        if let Some(entropy_vulns) = self.test_session_entropy(url).await? {
            vulnerabilities.extend(entropy_vulns);
        }

        // 2. Test session fixation
        tests_run += 1;
        if let Some(creds) = credentials {
            if let Some(fixation_vulns) = self.test_session_fixation(url, creds).await? {
                vulnerabilities.extend(fixation_vulns);
            }
        }

        // 3. Test logout invalidation
        tests_run += 1;
        if let Some(session) = existing_session {
            if let Some(logout_vulns) = self.test_logout_invalidation(url, session).await? {
                vulnerabilities.extend(logout_vulns);
            }
        }

        // 4. Test concurrent sessions
        tests_run += 1;
        if let Some(creds) = credentials {
            if let Some(concurrent_vulns) = self.test_concurrent_sessions(url, creds).await? {
                vulnerabilities.extend(concurrent_vulns);
            }
        }

        // 5. Test session timeout
        tests_run += 1;
        if let Some(session) = existing_session {
            if let Some(timeout_vulns) = self.test_session_timeout_config(url, session).await? {
                vulnerabilities.extend(timeout_vulns);
            }
        }

        info!("[Session] Analysis complete: {} tests, {} vulnerabilities", tests_run, vulnerabilities.len());
        Ok((vulnerabilities, tests_run))
    }

    /// Measure session ID entropy by collecting multiple samples
    async fn test_session_entropy(&self, url: &str) -> Result<Option<Vec<Vulnerability>>> {
        info!("[Session] Testing session ID entropy");

        let mut session_ids: Vec<String> = Vec::new();

        // Collect 10 session IDs
        for _ in 0..10 {
            if let Ok(response) = self.http_client.get(url).await {
                // Extract session cookies
                for (key, value) in &response.headers {
                    if key.to_lowercase() == "set-cookie" {
                        if let Some(session_id) = Self::extract_session_id(value) {
                            session_ids.push(session_id);
                        }
                    }
                }
            }
            // Small delay between requests
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if session_ids.len() < 5 {
            debug!("[Session] Not enough session IDs collected for entropy analysis");
            return Ok(None);
        }

        // Analyze entropy
        let analysis = Self::analyze_entropy(&session_ids);

        let mut vulnerabilities = Vec::new();

        // Check for low entropy
        if analysis.estimated_entropy < 64.0 {
            vulnerabilities.push(Vulnerability {
                id: format!("SESSION-ENTROPY-{}", uuid::Uuid::new_v4()),
                name: "Low Session ID Entropy".to_string(),
                description: format!(
                    "Session IDs have low entropy (~{:.1} bits). Recommended: 128+ bits. \
                    Sample length: {} chars, character set size: {}",
                    analysis.estimated_entropy,
                    analysis.avg_length,
                    analysis.charset_size
                ),
                severity: if analysis.estimated_entropy < 32.0 { Severity::Critical } else { Severity::High },
                confidence: Confidence::High,
                url: url.to_string(),
                parameter: Some("Session ID".to_string()),
                evidence: format!(
                    "Collected {} unique sessions. Avg length: {}, Estimated entropy: {:.1} bits",
                    analysis.unique_count,
                    analysis.avg_length,
                    analysis.estimated_entropy
                ),
                remediation: "Use cryptographically secure random number generator with at least 128 bits of entropy".to_string(),
                cwe_id: Some("CWE-330".to_string()),
                cvss_score: Some(7.5),
                references: vec!["https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length".to_string()],
                request: None,
                response: None,
                found_at: chrono::Utc::now(),
            });
        }

        // Check for sequential patterns
        if analysis.has_sequential_pattern {
            vulnerabilities.push(Vulnerability {
                id: format!("SESSION-SEQUENTIAL-{}", uuid::Uuid::new_v4()),
                name: "Predictable Session ID Pattern".to_string(),
                description: "Session IDs appear to follow a sequential or predictable pattern".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Medium,
                url: url.to_string(),
                parameter: Some("Session ID".to_string()),
                evidence: "Sequential numeric components detected in session IDs".to_string(),
                remediation: "Use truly random session IDs without sequential components".to_string(),
                cwe_id: Some("CWE-330".to_string()),
                cvss_score: Some(9.1),
                references: vec![],
                request: None,
                response: None,
                found_at: chrono::Utc::now(),
            });
        }

        Ok(if vulnerabilities.is_empty() { None } else { Some(vulnerabilities) })
    }

    /// Test if session is regenerated after login (session fixation)
    async fn test_session_fixation(&self, url: &str, credentials: &LoginCredentials) -> Result<Option<Vec<Vulnerability>>> {
        info!("[Session] Testing session fixation");

        // Step 1: Get a session before login
        let pre_login_response = self.http_client.get(url).await?;
        let pre_login_session = Self::extract_all_session_cookies(&pre_login_response.headers);

        if pre_login_session.is_empty() {
            debug!("[Session] No pre-login session found");
            return Ok(None);
        }

        // Step 2: Login with the pre-existing session
        let authenticator = Authenticator::new(30);
        let session = authenticator.login(url, credentials).await?;

        if !session.is_authenticated {
            debug!("[Session] Login failed, can't test session fixation");
            return Ok(None);
        }

        // Step 3: Compare sessions
        let post_login_session: HashSet<String> = session.cookies.values().cloned().collect();
        let pre_login_set: HashSet<String> = pre_login_session.into_iter().collect();

        // Check if any pre-login session IDs survived login
        let unchanged: Vec<_> = pre_login_set.intersection(&post_login_session).collect();

        if !unchanged.is_empty() {
            return Ok(Some(vec![Vulnerability {
                id: format!("SESSION-FIXATION-{}", uuid::Uuid::new_v4()),
                name: "Session Fixation Vulnerability".to_string(),
                description: "Session ID is not regenerated after successful authentication, allowing session fixation attacks".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                url: url.to_string(),
                parameter: Some("Session ID".to_string()),
                evidence: format!("{} session values remained unchanged after login", unchanged.len()),
                remediation: "Regenerate session ID after successful authentication and privilege level changes".to_string(),
                cwe_id: Some("CWE-384".to_string()),
                cvss_score: Some(8.1),
                references: vec!["https://owasp.org/www-community/attacks/Session_fixation".to_string()],
                request: None,
                response: None,
                found_at: chrono::Utc::now(),
            }]));
        }

        Ok(None)
    }

    /// Test if session is actually invalidated after logout
    async fn test_logout_invalidation(&self, url: &str, session: &AuthSession) -> Result<Option<Vec<Vulnerability>>> {
        info!("[Session] Testing logout invalidation");

        // Step 1: Verify session works
        let pre_logout = self.http_client.get_authenticated(url, session).await?;
        if pre_logout.status_code == 401 || pre_logout.status_code == 403 {
            debug!("[Session] Session not working, can't test logout");
            return Ok(None);
        }

        // Step 2: Find and hit logout endpoint
        let logout_urls = vec![
            format!("{}/logout", url.trim_end_matches('/')),
            format!("{}/signout", url.trim_end_matches('/')),
            format!("{}/api/logout", url.trim_end_matches('/')),
            format!("{}/api/auth/logout", url.trim_end_matches('/')),
            format!("{}/auth/logout", url.trim_end_matches('/')),
        ];

        let mut logged_out = false;
        for logout_url in &logout_urls {
            // Try GET and POST
            if let Ok(_) = self.http_client.get_authenticated(logout_url, session).await {
                logged_out = true;
                break;
            }
            if let Ok(_) = self.http_client.post_authenticated(logout_url, "", session).await {
                logged_out = true;
                break;
            }
        }

        if !logged_out {
            debug!("[Session] Couldn't find logout endpoint");
            return Ok(None);
        }

        // Step 3: Wait a moment then try using the old session
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let post_logout = self.http_client.get_authenticated(url, session).await?;

        // If we can still access protected resources, session wasn't invalidated
        if post_logout.status_code != 401 && post_logout.status_code != 403 {
            // Check for auth indicators in response
            let body_lower = post_logout.body.to_lowercase();
            if body_lower.contains("dashboard") ||
               body_lower.contains("profile") ||
               body_lower.contains("welcome") ||
               body_lower.contains("\"authenticated\":true") {
                return Ok(Some(vec![Vulnerability {
                    id: format!("SESSION-LOGOUT-{}", uuid::Uuid::new_v4()),
                    name: "Session Not Invalidated After Logout".to_string(),
                    description: "Session token remains valid after logout, allowing continued access".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    url: url.to_string(),
                    parameter: Some("Session ID".to_string()),
                    evidence: format!("Session still accessible after logout (status: {})", post_logout.status_code),
                    remediation: "Invalidate session server-side on logout. Don't rely only on cookie deletion.".to_string(),
                    cwe_id: Some("CWE-613".to_string()),
                    cvss_score: Some(6.5),
                    references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality".to_string()],
                    request: None,
                    response: None,
                    found_at: chrono::Utc::now(),
                }]));
            }
        }

        Ok(None)
    }

    /// Test concurrent session handling
    async fn test_concurrent_sessions(&self, url: &str, credentials: &LoginCredentials) -> Result<Option<Vec<Vulnerability>>> {
        info!("[Session] Testing concurrent sessions");

        let authenticator = Authenticator::new(30);

        // Login twice to create concurrent sessions
        let session1 = authenticator.login(url, credentials).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let session2 = authenticator.login(url, credentials).await?;

        if !session1.is_authenticated || !session2.is_authenticated {
            debug!("[Session] Couldn't create concurrent sessions");
            return Ok(None);
        }

        // Check if session1 is still valid after session2 login
        let response1 = self.http_client.get_authenticated(url, &session1).await?;
        let response2 = self.http_client.get_authenticated(url, &session2).await?;

        // Both sessions still work - might be intentional, but worth noting
        if response1.status_code != 401 && response2.status_code != 401 {
            // This is informational - concurrent sessions are sometimes allowed
            debug!("[Session] Concurrent sessions allowed (may be by design)");
        }

        Ok(None)
    }

    /// Test session timeout configuration
    async fn test_session_timeout_config(&self, url: &str, session: &AuthSession) -> Result<Option<Vec<Vulnerability>>> {
        info!("[Session] Analyzing session timeout configuration");

        let mut vulnerabilities = Vec::new();

        // Check for session cookies without expiration (session cookies)
        for (name, _) in &session.cookies {
            let name_lower = name.to_lowercase();
            if name_lower.contains("session") || name_lower.contains("auth") || name_lower.contains("token") {
                // Session cookies that persist indefinitely are a risk
                // Can't directly check cookie attributes from our extraction, but we can note the finding
            }
        }

        // Check for very long-lived JWT tokens in session
        if let Some(jwt_str) = session.find_jwt() {
            if let Some(jwt) = crate::scanners::jwt_analyzer::DecodedJwt::decode(&jwt_str) {
                if let Some(exp) = jwt.payload.get("exp").and_then(|v| v.as_i64()) {
                    let now = chrono::Utc::now().timestamp();
                    let hours_until_exp = (exp - now) / 3600;

                    if hours_until_exp > 24 * 7 { // More than a week
                        vulnerabilities.push(Vulnerability {
                            id: format!("SESSION-LONGLIVED-{}", uuid::Uuid::new_v4()),
                            name: "Excessively Long Session Lifetime".to_string(),
                            description: format!("Session/token expires in {} hours ({} days)", hours_until_exp, hours_until_exp / 24),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            url: url.to_string(),
                            parameter: Some("Session timeout".to_string()),
                            evidence: format!("Token expires in {} days", hours_until_exp / 24),
                            remediation: "Implement shorter session timeouts (4-8 hours for sensitive apps)".to_string(),
                            cwe_id: Some("CWE-613".to_string()),
                            cvss_score: Some(4.3),
                            references: vec![],
                            request: None,
                            response: None,
                            found_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        Ok(if vulnerabilities.is_empty() { None } else { Some(vulnerabilities) })
    }

    // Helper functions

    fn extract_session_id(cookie_header: &str) -> Option<String> {
        // Parse cookie header and extract session-like values
        let session_names = ["session", "sess", "sid", "phpsessid", "jsessionid", "aspsessionid", "connect.sid"];

        for part in cookie_header.split(';') {
            let trimmed = part.trim();
            if let Some(eq_pos) = trimmed.find('=') {
                let name = trimmed[..eq_pos].to_lowercase();
                let value = trimmed[eq_pos + 1..].to_string();

                for session_name in &session_names {
                    if name.contains(session_name) {
                        return Some(value);
                    }
                }
            }
        }
        None
    }

    fn extract_all_session_cookies(headers: &std::collections::HashMap<String, String>) -> Vec<String> {
        let mut sessions = Vec::new();
        for (key, value) in headers {
            if key.to_lowercase() == "set-cookie" {
                if let Some(session) = Self::extract_session_id(value) {
                    sessions.push(session);
                }
            }
        }
        sessions
    }

    fn analyze_entropy(session_ids: &[String]) -> EntropyAnalysis {
        let unique: HashSet<_> = session_ids.iter().collect();

        let avg_length = session_ids.iter().map(|s| s.len()).sum::<usize>() / session_ids.len().max(1);

        // Count unique characters used across all session IDs
        let all_chars: HashSet<char> = session_ids.iter().flat_map(|s| s.chars()).collect();
        let charset_size = all_chars.len();

        // Estimate entropy: log2(charset^length)
        let estimated_entropy = (avg_length as f64) * (charset_size as f64).log2();

        // Check for sequential patterns
        let has_sequential_pattern = Self::detect_sequential_pattern(session_ids);

        EntropyAnalysis {
            unique_count: unique.len(),
            avg_length,
            charset_size,
            estimated_entropy,
            has_sequential_pattern,
        }
    }

    fn detect_sequential_pattern(session_ids: &[String]) -> bool {
        if session_ids.len() < 3 {
            return false;
        }

        // Extract numeric portions and check for incrementing
        let numbers: Vec<Option<i64>> = session_ids.iter()
            .map(|s| {
                let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                digits.parse().ok()
            })
            .collect();

        // Check if numbers are incrementing
        let valid_numbers: Vec<i64> = numbers.into_iter().flatten().collect();
        if valid_numbers.len() >= 3 {
            let mut increments = true;
            for window in valid_numbers.windows(2) {
                if window[1] <= window[0] || window[1] - window[0] > 100 {
                    increments = false;
                    break;
                }
            }
            return increments;
        }

        false
    }
}

struct EntropyAnalysis {
    unique_count: usize,
    avg_length: usize,
    charset_size: usize,
    estimated_entropy: f64,
    has_sequential_pattern: bool,
}
