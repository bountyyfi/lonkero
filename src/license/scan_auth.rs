// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Server-side scan authorization management
//!
//! This module manages the authorization state for scans, tracking
//! which modules the server has authorized and which were actually used.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Denied module information from server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeniedModule {
    /// Module ID that was denied
    pub module: String,
    /// Reason for denial (e.g., "Requires Professional+ license")
    pub reason: String,
}

/// Extended authorization response with module information
#[derive(Debug, Clone, Deserialize)]
pub struct ModuleAuthorizeResponse {
    /// Whether the scan is authorized
    pub authorized: bool,
    /// Scan token for subsequent signing
    pub scan_token: Option<String>,
    /// Token expiration timestamp
    pub token_expires_at: Option<String>,
    /// Maximum targets allowed
    pub max_targets: Option<u32>,
    /// License type
    pub license_type: Option<String>,
    /// Modules the server authorized
    pub authorized_modules: Option<Vec<String>>,
    /// Modules denied with reasons
    pub denied_modules: Option<Vec<DeniedModule>>,
    /// Error message if not authorized
    pub error: Option<String>,
    /// Ban reason if user is banned
    pub ban_reason: Option<String>,
}

/// Manages server-authorized modules for the current scan
///
/// This struct is thread-safe and can be shared across async tasks.
/// It tracks:
/// - Which modules the server authorized
/// - Which modules have actually been used during the scan
/// - License type and target limits
pub struct ScanAuthorization {
    /// The scan token from the server
    scan_token: String,
    /// Set of module IDs authorized by the server
    authorized_modules: HashSet<String>,
    /// Modules that have been used during scanning (for sign request)
    modules_used: Arc<RwLock<Vec<String>>>,
    /// Maximum number of targets allowed
    max_targets: u32,
    /// License type (Personal, Professional, Team, Enterprise)
    license_type: String,
    /// Token expiration timestamp
    expires_at: String,
}

impl ScanAuthorization {
    /// Create a new ScanAuthorization from a server response
    ///
    /// # Arguments
    /// * `response` - The authorization response from the server
    ///
    /// # Returns
    /// * `Ok(ScanAuthorization)` - Successfully created authorization
    /// * `Err(String)` - Authorization failed (check error message)
    pub fn new(response: ModuleAuthorizeResponse) -> Result<Self, String> {
        // Check if authorized
        if !response.authorized {
            let error = response.error.unwrap_or_else(|| "Authorization failed".to_string());
            return Err(error);
        }

        // Check for ban
        if let Some(ban_reason) = response.ban_reason {
            return Err(format!("BANNED: {}", ban_reason));
        }

        // Extract scan token
        let scan_token = response.scan_token
            .ok_or_else(|| "No scan token in response".to_string())?;

        // Extract expiration
        let expires_at = response.token_expires_at
            .ok_or_else(|| "No token expiration in response".to_string())?;

        // Build authorized modules set
        let authorized_modules: HashSet<String> = response
            .authorized_modules
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Log denied modules summary (individual denials at debug level)
        if let Some(denied) = &response.denied_modules {
            if !denied.is_empty() {
                debug!("[Auth] {} modules denied (requires license upgrade)", denied.len());
                for d in denied {
                    debug!("[Auth] Module '{}' denied: {}", d.module, d.reason);
                }
            }
        }

        let max_targets = response.max_targets.unwrap_or(10);
        let license_type = response.license_type.unwrap_or_else(|| "Personal".to_string());

        info!(
            "[Auth] Authorized: {} modules, license={}, max_targets={}",
            authorized_modules.len(),
            license_type,
            max_targets
        );

        Ok(Self {
            scan_token,
            authorized_modules,
            modules_used: Arc::new(RwLock::new(Vec::new())),
            max_targets,
            license_type,
            expires_at,
        })
    }

    /// Check if a module is authorized by the server
    ///
    /// # Arguments
    /// * `module_id` - The module ID to check (from crate::modules::ids)
    ///
    /// # Returns
    /// * `true` if the module is authorized
    /// * `false` if the module was not authorized by the server
    pub fn is_module_authorized(&self, module_id: &str) -> bool {
        let authorized = self.authorized_modules.contains(module_id);
        if !authorized {
            debug!("[Auth] Module '{}' not authorized", module_id);
        }
        authorized
    }

    /// Record that a module was used during the scan
    ///
    /// This should be called when a scanner starts running.
    /// The list of used modules is sent to the server during signing
    /// for validation.
    ///
    /// # Arguments
    /// * `module_id` - The module ID that was used
    pub async fn record_module_used(&self, module_id: &str) {
        let mut used = self.modules_used.write().await;
        if !used.contains(&module_id.to_string()) {
            debug!("[Auth] Recording module usage: {}", module_id);
            used.push(module_id.to_string());
        }
    }

    /// Get the scan token for signing requests
    pub fn scan_token(&self) -> &str {
        &self.scan_token
    }

    /// Get the list of modules that were actually used
    ///
    /// This is sent to the server during signing to validate
    /// that only authorized modules were used.
    pub async fn get_modules_used(&self) -> Vec<String> {
        self.modules_used.read().await.clone()
    }

    /// Get the maximum number of targets allowed
    pub fn max_targets(&self) -> u32 {
        self.max_targets
    }

    /// Get the license type
    pub fn license_type(&self) -> &str {
        &self.license_type
    }

    /// Get the token expiration timestamp
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    /// Check if the authorization token is still valid
    pub fn is_valid(&self) -> bool {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            let now = chrono::Utc::now();
            return now < expires;
        }
        false
    }

    /// Get the set of all authorized modules
    pub fn authorized_modules(&self) -> &HashSet<String> {
        &self.authorized_modules
    }

    /// Check if there are any denied modules
    pub fn has_denied_modules(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|m| !self.authorized_modules.contains(*m))
            .cloned()
            .collect()
    }
}

/// Helper function to check if a module ID corresponds to a free module
pub fn is_free_module(module_id: &str) -> bool {
    matches!(
        module_id,
        "port_scanner"
            | "http_headers"
            | "ssl_checker"
            | "dns_enum"
            | "security_headers"
            | "cors_basic"
            | "clickjacking"
            | "info_disclosure_basic"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_free_module() {
        assert!(is_free_module("port_scanner"));
        assert!(is_free_module("http_headers"));
        assert!(!is_free_module("sqli_scanner"));
        assert!(!is_free_module("wordpress_scanner"));
    }

    #[tokio::test]
    async fn test_scan_authorization() {
        let response = ModuleAuthorizeResponse {
            authorized: true,
            scan_token: Some("test_token".to_string()),
            token_expires_at: Some(
                (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            ),
            max_targets: Some(100),
            license_type: Some("Professional".to_string()),
            authorized_modules: Some(vec![
                "sqli_scanner".to_string(),
                "xss_scanner".to_string(),
            ]),
            denied_modules: None,
            error: None,
            ban_reason: None,
        };

        let auth = ScanAuthorization::new(response).unwrap();

        assert!(auth.is_valid());
        assert!(auth.is_module_authorized("sqli_scanner"));
        assert!(auth.is_module_authorized("xss_scanner"));
        assert!(!auth.is_module_authorized("wordpress_scanner"));

        auth.record_module_used("sqli_scanner").await;
        let used = auth.get_modules_used().await;
        assert_eq!(used, vec!["sqli_scanner"]);
    }

    #[test]
    fn test_authorization_denied() {
        let response = ModuleAuthorizeResponse {
            authorized: false,
            scan_token: None,
            token_expires_at: None,
            max_targets: None,
            license_type: None,
            authorized_modules: None,
            denied_modules: None,
            error: Some("License expired".to_string()),
            ban_reason: None,
        };

        let result = ScanAuthorization::new(response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("License expired"));
    }

    #[test]
    fn test_authorization_banned() {
        let response = ModuleAuthorizeResponse {
            authorized: false,
            scan_token: None,
            token_expires_at: None,
            max_targets: None,
            license_type: None,
            authorized_modules: None,
            denied_modules: None,
            error: None,
            ban_reason: Some("Terms of service violation".to_string()),
        };

        let result = ScanAuthorization::new(response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BANNED"));
    }
}
