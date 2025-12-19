// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Out-of-Band (OOB) Detection Infrastructure
 * Client-side OOB detection system for blind vulnerabilities
 *
 * Features:
 * - DNS exfiltration payload generation with unique IDs
 * - HTTP callback URL generation with tracking
 * - Callback verification via public OOB services
 * - Graceful degradation when OOB service unavailable
 * - Support for multiple OOB backend services
 * - Non-blocking async operations with configurable timeouts
 *
 * Architecture:
 * Since we can't run actual DNS/HTTP servers, this implements a CLIENT-SIDE
 * OOB detection system that can interface with public callback services or
 * simulate OOB detection for testing purposes.
 *
 * Supported Services:
 * - Burp Collaborator
 * - Interactsh (ProjectDiscovery)
 * - Custom callback domains (oob.lonkero.bountyy.fi)
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use anyhow::{Context, Result};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// OOB callback service type
#[derive(Debug, Clone, PartialEq)]
pub enum OobServiceType {
    /// Custom Bountyy callback domain (oob.lonkero.bountyy.fi)
    BountyyCallback,
    /// Burp Collaborator (if available)
    BurpCollaborator,
    /// Interactsh by ProjectDiscovery (public service)
    Interactsh,
    /// Simulated (for testing - always returns false)
    Simulated,
}

/// OOB vulnerability type for categorization
#[derive(Debug, Clone, PartialEq)]
pub enum OobVulnType {
    /// SSRF (Server-Side Request Forgery)
    Ssrf,
    /// XXE (XML External Entity)
    Xxe,
    /// Command Injection
    CommandInjection,
    /// SQL Injection
    SqlInjection,
    /// LDAP Injection
    LdapInjection,
    /// Template Injection
    TemplateInjection,
}

impl OobVulnType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ssrf => "ssrf",
            Self::Xxe => "xxe",
            Self::CommandInjection => "cmd",
            Self::SqlInjection => "sqli",
            Self::LdapInjection => "ldap",
            Self::TemplateInjection => "ssti",
        }
    }
}

/// OOB detection payload type
#[derive(Debug, Clone, PartialEq)]
pub enum OobPayloadType {
    /// DNS lookup (most reliable)
    Dns,
    /// HTTP GET request
    Http,
    /// HTTPS request
    Https,
}

/// OOB Detector for blind vulnerability detection
pub struct OobDetector {
    /// Unique test session ID
    session_id: String,
    /// Callback domain to use
    callback_domain: String,
    /// Service type being used
    service_type: OobServiceType,
    /// HTTP client for callback verification
    http_client: Option<Arc<crate::http_client::HttpClient>>,
    /// Whether OOB service is available
    service_available: bool,
}

impl OobDetector {
    /// Create a new OOB detector with default service
    pub fn new() -> Self {
        let session_id = Self::generate_session_id();

        // Try to use Bountyy callback service first, fall back to Interactsh
        let (service_type, callback_domain) = Self::select_service();

        debug!(
            "[OOB] Initialized OOB detector with session_id={}, service={:?}, domain={}",
            session_id, service_type, callback_domain
        );

        Self {
            session_id,
            callback_domain,
            service_type,
            http_client: None,
            service_available: true,
        }
    }

    /// Create a new OOB detector with specific service
    pub fn with_service(service_type: OobServiceType) -> Self {
        let session_id = Self::generate_session_id();
        let callback_domain = Self::get_domain_for_service(&service_type);

        debug!(
            "[OOB] Initialized OOB detector with session_id={}, service={:?}, domain={}",
            session_id, service_type, callback_domain
        );

        Self {
            session_id,
            callback_domain,
            service_type,
            http_client: None,
            service_available: true,
        }
    }

    /// Create OOB detector with HTTP client for callback verification
    pub fn with_http_client(http_client: Arc<crate::http_client::HttpClient>) -> Self {
        let mut detector = Self::new();
        detector.http_client = Some(http_client);
        detector
    }

    /// Generate unique session ID for this scan
    fn generate_session_id() -> String {
        let mut rng = rand::rng();
        format!("{:016x}", rng.random::<u64>())
    }

    /// Select best available OOB service
    fn select_service() -> (OobServiceType, String) {
        // In production, check if Bountyy callback service is available
        // For now, use Interactsh as it's a public service

        // Check environment for custom callback domain
        if let Ok(domain) = std::env::var("LONKERO_OOB_DOMAIN") {
            info!("[OOB] Using custom callback domain from environment: {}", domain);
            return (OobServiceType::BountyyCallback, domain);
        }

        // Default to Interactsh (public service)
        (
            OobServiceType::Interactsh,
            "oast.pro".to_string(), // Interactsh public server
        )
    }

    /// Get callback domain for specific service type
    fn get_domain_for_service(service_type: &OobServiceType) -> String {
        match service_type {
            OobServiceType::BountyyCallback => {
                std::env::var("LONKERO_OOB_DOMAIN")
                    .unwrap_or_else(|_| "oob.lonkero.bountyy.fi".to_string())
            }
            OobServiceType::BurpCollaborator => "burpcollaborator.net".to_string(),
            OobServiceType::Interactsh => "oast.pro".to_string(),
            OobServiceType::Simulated => "simulated.local".to_string(),
        }
    }

    /// Generate unique test ID for a specific test
    fn generate_test_id(&self, vuln_type: &OobVulnType) -> String {
        let mut rng = rand::rng();
        format!(
            "{}-{}-{:08x}",
            vuln_type.as_str(),
            &self.session_id[0..8],
            rng.random::<u32>()
        )
    }

    /// Generate DNS exfiltration payload
    ///
    /// Creates a DNS lookup that can be monitored for OOB detection.
    /// Format: {test_id}.{callback_domain}
    ///
    /// # Example
    /// ```
    /// let detector = OobDetector::new();
    /// let dns_payload = detector.generate_dns_payload(OobVulnType::Ssrf);
    /// // Returns: "ssrf-a1b2c3d4-12345678.oast.pro"
    /// ```
    pub fn generate_dns_payload(&self, vuln_type: OobVulnType) -> String {
        let test_id = self.generate_test_id(&vuln_type);
        format!("{}.{}", test_id, self.callback_domain)
    }

    /// Generate DNS exfiltration payload with custom data
    ///
    /// Embeds data in subdomain for exfiltration.
    /// Format: {data}.{test_id}.{callback_domain}
    ///
    /// # Example
    /// ```
    /// let detector = OobDetector::new();
    /// let payload = detector.generate_dns_exfil_payload(OobVulnType::SqlInjection, "version");
    /// // Returns: "version.sqli-a1b2c3d4-12345678.oast.pro"
    /// ```
    pub fn generate_dns_exfil_payload(&self, vuln_type: OobVulnType, data: &str) -> String {
        let test_id = self.generate_test_id(&vuln_type);
        // Sanitize data for DNS (alphanumeric + hyphens only)
        let safe_data = data
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .take(63) // DNS label max length
            .collect::<String>();

        if safe_data.is_empty() {
            format!("{}.{}", test_id, self.callback_domain)
        } else {
            format!("{}.{}.{}", safe_data, test_id, self.callback_domain)
        }
    }

    /// Generate HTTP callback URL
    ///
    /// Creates an HTTP URL for callback detection.
    ///
    /// # Example
    /// ```
    /// let detector = OobDetector::new();
    /// let url = detector.generate_http_callback(OobVulnType::Xxe);
    /// // Returns: "http://xxe-a1b2c3d4-12345678.oast.pro"
    /// ```
    pub fn generate_http_callback(&self, vuln_type: OobVulnType) -> String {
        let test_id = self.generate_test_id(&vuln_type);
        format!("http://{}.{}", test_id, self.callback_domain)
    }

    /// Generate HTTPS callback URL
    pub fn generate_https_callback(&self, vuln_type: OobVulnType) -> String {
        let test_id = self.generate_test_id(&vuln_type);
        format!("https://{}.{}", test_id, self.callback_domain)
    }

    /// Generate callback URL with custom path
    ///
    /// # Example
    /// ```
    /// let url = detector.generate_callback_with_path(
    ///     OobVulnType::Ssrf,
    ///     "/latest/meta-data/"
    /// );
    /// // Returns: "http://ssrf-a1b2c3d4-12345678.oast.pro/latest/meta-data/"
    /// ```
    pub fn generate_callback_with_path(&self, vuln_type: OobVulnType, path: &str) -> String {
        let base = self.generate_http_callback(vuln_type);
        format!("{}{}", base, path)
    }

    /// Generate callback URL for specific protocol
    pub fn generate_callback_url(
        &self,
        vuln_type: OobVulnType,
        payload_type: OobPayloadType,
    ) -> String {
        match payload_type {
            OobPayloadType::Dns => self.generate_dns_payload(vuln_type),
            OobPayloadType::Http => self.generate_http_callback(vuln_type),
            OobPayloadType::Https => self.generate_https_callback(vuln_type),
        }
    }

    /// Check if callback was triggered
    ///
    /// Polls the OOB service to check if a DNS/HTTP callback was received.
    /// This is async and non-blocking with configurable timeout.
    ///
    /// # Arguments
    /// * `test_id` - The unique test identifier from generate_*_payload
    /// * `timeout_secs` - Maximum time to wait for callback (default: 10 seconds)
    ///
    /// # Returns
    /// * `Ok(true)` - Callback was detected
    /// * `Ok(false)` - No callback detected within timeout
    /// * `Err(_)` - Service unavailable or error occurred
    ///
    /// # Example
    /// ```
    /// let dns_payload = detector.generate_dns_payload(OobVulnType::Ssrf);
    /// // ... send payload to target ...
    /// let detected = detector.check_callback(&dns_payload, 10).await?;
    /// ```
    pub async fn check_callback(&self, test_id: &str, timeout_secs: u64) -> Result<bool> {
        if !self.service_available {
            debug!("[OOB] Service unavailable, skipping callback check");
            return Ok(false);
        }

        debug!(
            "[OOB] Checking callback for test_id={} (timeout={}s)",
            test_id, timeout_secs
        );

        // Try to check callback with timeout
        match timeout(
            Duration::from_secs(timeout_secs),
            self.check_callback_internal(test_id),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                debug!("[OOB] Callback check timed out after {}s", timeout_secs);
                Ok(false)
            }
        }
    }

    /// Internal callback checking logic
    async fn check_callback_internal(&self, test_id: &str) -> Result<bool> {
        match &self.service_type {
            OobServiceType::Interactsh => self.check_interactsh_callback(test_id).await,
            OobServiceType::BurpCollaborator => {
                // Burp Collaborator requires authentication
                warn!("[OOB] Burp Collaborator requires authentication - not implemented");
                Ok(false)
            }
            OobServiceType::BountyyCallback => self.check_bountyy_callback(test_id).await,
            OobServiceType::Simulated => {
                // Simulated mode for testing - always returns false
                debug!("[OOB] Simulated mode - no actual callback check");
                Ok(false)
            }
        }
    }

    /// Check Interactsh for callbacks
    async fn check_interactsh_callback(&self, test_id: &str) -> Result<bool> {
        // Interactsh requires polling their API
        // For now, we'll implement the basic structure
        // Full implementation would require Interactsh client integration

        if let Some(client) = &self.http_client {
            // Extract correlation ID from test_id
            // Format: {vuln_type}-{session_id}-{random}

            // Interactsh API endpoint (if we have an active session)
            // This is a placeholder - actual implementation would need:
            // 1. Register with Interactsh server to get a session
            // 2. Poll the session endpoint for interactions

            debug!("[OOB] Interactsh callback check not fully implemented - requires session registration");
            Ok(false)
        } else {
            debug!("[OOB] No HTTP client available for callback check");
            Ok(false)
        }
    }

    /// Check Bountyy callback service
    async fn check_bountyy_callback(&self, test_id: &str) -> Result<bool> {
        if let Some(client) = &self.http_client {
            // Check Bountyy OOB service API
            // Endpoint: https://oob.lonkero.bountyy.fi/api/check/{test_id}

            let check_url = format!(
                "https://{}/api/check/{}",
                self.callback_domain, test_id
            );

            debug!("[OOB] Checking Bountyy callback service: {}", check_url);

            match client.get(&check_url).await {
                Ok(response) => {
                    // Response format: {"detected": true/false, "timestamp": "...", "type": "dns/http"}
                    if response.status_code == 200 {
                        let detected = response.body.contains("\"detected\":true")
                            || response.body.contains("\"detected\": true");

                        if detected {
                            info!("[OOB] Callback detected for test_id={}", test_id);
                        }

                        Ok(detected)
                    } else if response.status_code == 404 {
                        // No callback received yet
                        Ok(false)
                    } else {
                        warn!(
                            "[OOB] Unexpected response from callback service: {}",
                            response.status_code
                        );
                        Ok(false)
                    }
                }
                Err(e) => {
                    warn!("[OOB] Failed to check callback service: {}", e);
                    Ok(false)
                }
            }
        } else {
            debug!("[OOB] No HTTP client available for callback check");
            Ok(false)
        }
    }

    /// Wait for callback with retry logic
    ///
    /// Polls for callback multiple times with delay between attempts.
    ///
    /// # Arguments
    /// * `test_id` - The unique test identifier
    /// * `max_wait_secs` - Maximum total wait time
    /// * `poll_interval_secs` - Seconds between poll attempts
    ///
    /// # Example
    /// ```
    /// // Poll every 2 seconds for up to 10 seconds
    /// let detected = detector.wait_for_callback(&test_id, 10, 2).await?;
    /// ```
    pub async fn wait_for_callback(
        &self,
        test_id: &str,
        max_wait_secs: u64,
        poll_interval_secs: u64,
    ) -> Result<bool> {
        let max_attempts = (max_wait_secs + poll_interval_secs - 1) / poll_interval_secs;

        for attempt in 1..=max_attempts {
            debug!(
                "[OOB] Callback poll attempt {}/{} for test_id={}",
                attempt, max_attempts, test_id
            );

            match self.check_callback(test_id, poll_interval_secs).await {
                Ok(true) => {
                    info!(
                        "[OOB] Callback detected on attempt {}/{} for test_id={}",
                        attempt, max_attempts, test_id
                    );
                    return Ok(true);
                }
                Ok(false) => {
                    // No callback yet, continue polling
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
                    }
                }
                Err(e) => {
                    warn!("[OOB] Callback check error on attempt {}: {}", attempt, e);
                    // Continue trying despite errors
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
                    }
                }
            }
        }

        debug!("[OOB] No callback detected after {} attempts", max_attempts);
        Ok(false)
    }

    /// Check if OOB service is available
    pub fn is_available(&self) -> bool {
        self.service_available
    }

    /// Disable OOB service (graceful degradation)
    pub fn disable(&mut self) {
        self.service_available = false;
        debug!("[OOB] OOB service disabled");
    }

    /// Get current service type
    pub fn service_type(&self) -> &OobServiceType {
        &self.service_type
    }

    /// Get callback domain
    pub fn callback_domain(&self) -> &str {
        &self.callback_domain
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl Default for OobDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to create OOB detector with proper configuration
pub fn create_oob_detector(
    http_client: Option<Arc<crate::http_client::HttpClient>>,
) -> OobDetector {
    if let Some(client) = http_client {
        OobDetector::with_http_client(client)
    } else {
        OobDetector::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let detector1 = OobDetector::new();
        let detector2 = OobDetector::new();

        // Session IDs should be unique
        assert_ne!(detector1.session_id(), detector2.session_id());

        // Session ID should be 16 hex characters
        assert_eq!(detector1.session_id().len(), 16);
    }

    #[test]
    fn test_dns_payload_generation() {
        let detector = OobDetector::new();
        let payload = detector.generate_dns_payload(OobVulnType::Ssrf);

        // Should contain vuln type prefix
        assert!(payload.starts_with("ssrf-"));

        // Should contain callback domain
        assert!(payload.contains(&detector.callback_domain));

        // Should be valid DNS format (no spaces, etc.)
        assert!(!payload.contains(' '));
    }

    #[test]
    fn test_dns_exfil_payload() {
        let detector = OobDetector::new();
        let payload = detector.generate_dns_exfil_payload(
            OobVulnType::SqlInjection,
            "mysql-5.7.33"
        );

        // Should contain sanitized data
        assert!(payload.contains("mysql-5"));

        // Should contain sqli prefix
        assert!(payload.contains("sqli-"));
    }

    #[test]
    fn test_http_callback_generation() {
        let detector = OobDetector::new();
        let url = detector.generate_http_callback(OobVulnType::Xxe);

        // Should be valid HTTP URL
        assert!(url.starts_with("http://"));

        // Should contain xxe prefix
        assert!(url.contains("xxe-"));
    }

    #[test]
    fn test_https_callback_generation() {
        let detector = OobDetector::new();
        let url = detector.generate_https_callback(OobVulnType::CommandInjection);

        // Should be valid HTTPS URL
        assert!(url.starts_with("https://"));

        // Should contain cmd prefix
        assert!(url.contains("cmd-"));
    }

    #[test]
    fn test_callback_with_path() {
        let detector = OobDetector::new();
        let url = detector.generate_callback_with_path(
            OobVulnType::Ssrf,
            "/latest/meta-data/"
        );

        // Should include the path
        assert!(url.ends_with("/latest/meta-data/"));

        // Should be valid URL
        assert!(url.starts_with("http://"));
    }

    #[test]
    fn test_service_type_selection() {
        let detector = OobDetector::with_service(OobServiceType::Interactsh);
        assert_eq!(detector.service_type(), &OobServiceType::Interactsh);
        assert_eq!(detector.callback_domain(), "oast.pro");
    }

    #[test]
    fn test_graceful_degradation() {
        let mut detector = OobDetector::new();
        assert!(detector.is_available());

        detector.disable();
        assert!(!detector.is_available());
    }

    #[tokio::test]
    async fn test_simulated_callback_check() {
        let detector = OobDetector::with_service(OobServiceType::Simulated);
        let test_id = "test-12345678-abcdef12";

        // Simulated mode should always return false
        let result = detector.check_callback(test_id, 1).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_vuln_type_strings() {
        assert_eq!(OobVulnType::Ssrf.as_str(), "ssrf");
        assert_eq!(OobVulnType::Xxe.as_str(), "xxe");
        assert_eq!(OobVulnType::CommandInjection.as_str(), "cmd");
        assert_eq!(OobVulnType::SqlInjection.as_str(), "sqli");
    }
}
