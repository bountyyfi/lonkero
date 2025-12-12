// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.
// License verification and killswitch module.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};

/// Bountyy license server endpoint
const LICENSE_SERVER: &str = "https://lonkero.bountyy.fi/api/v1";

/// Global killswitch state
static KILLSWITCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static KILLSWITCH_CHECKED: AtomicBool = AtomicBool::new(false);

/// Global license status cache
static GLOBAL_LICENSE: OnceLock<LicenseStatus> = OnceLock::new();

/// Check if killswitch is active
#[inline]
pub fn is_killswitch_active() -> bool {
    KILLSWITCH_ACTIVE.load(Ordering::SeqCst)
}

/// License types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseType {
    Personal,
    Professional,
    Team,
    Enterprise,
}

impl std::fmt::Display for LicenseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseType::Personal => write!(f, "Personal"),
            LicenseType::Professional => write!(f, "Professional"),
            LicenseType::Team => write!(f, "Team"),
            LicenseType::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// License status returned from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub valid: bool,
    pub license_type: Option<LicenseType>,
    pub licensee: Option<String>,
    pub organization: Option<String>,
    pub expires_at: Option<String>,
    pub features: Vec<String>,
    pub max_targets: Option<u32>,
    pub killswitch_active: bool,
    pub killswitch_reason: Option<String>,
    pub message: Option<String>,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        // DEFAULT: Full access, non-commercial
        Self {
            valid: true,
            license_type: Some(LicenseType::Personal),
            licensee: None,
            organization: None,
            expires_at: None,
            features: vec![
                "all_scanners".to_string(),
                "all_outputs".to_string(),
                "subdomain_enum".to_string(),
                "crawler".to_string(),
                "cloud_scanning".to_string(),
                "api_fuzzing".to_string(),
            ],
            max_targets: Some(100),
            killswitch_active: false,
            killswitch_reason: None,
            message: Some("Non-commercial use. For commercial licensing: https://bountyy.fi/license".to_string()),
        }
    }
}

/// Killswitch response from server
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KillswitchResponse {
    pub active: bool,
    pub reason: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub revoked_keys: Vec<String>,
}

/// License manager
pub struct LicenseManager {
    license_key: Option<String>,
    http_client: reqwest::Client,
    hardware_id: Option<String>,
}

impl LicenseManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            license_key: None,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Lonkero/1.0.0")
                .build()?,
            hardware_id: Self::get_hardware_id(),
        })
    }

    /// Get hardware fingerprint
    fn get_hardware_id() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = fs::read_to_string("/etc/machine-id") {
                let mut hasher = Sha256::new();
                hasher.update(id.trim().as_bytes());
                return Some(hex::encode(hasher.finalize())[..16].to_string());
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("ioreg")
                .args(["-rd1", "-c", "IOPlatformExpertDevice"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Some(uuid_line) = output_str.lines().find(|l| l.contains("IOPlatformUUID")) {
                    let mut hasher = Sha256::new();
                    hasher.update(uuid_line.as_bytes());
                    return Some(hex::encode(hasher.finalize())[..16].to_string());
                }
            }
        }

        None
    }

    pub fn load_license(&mut self) -> Result<Option<String>> {
        // Check environment variable
        if let Ok(key) = std::env::var("LONKERO_LICENSE_KEY") {
            self.license_key = Some(key.clone());
            return Ok(Some(key));
        }

        // Check config file
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lonkero");
        let license_file = config_dir.join("license.key");

        if license_file.exists() {
            if let Ok(content) = fs::read_to_string(&license_file) {
                let key = content.trim().to_string();
                if !key.is_empty() {
                    self.license_key = Some(key.clone());
                    return Ok(Some(key));
                }
            }
        }

        Ok(None)
    }

    pub fn set_license_key(&mut self, key: String) {
        self.license_key = Some(key);
    }

    pub fn save_license(&self, key: &str) -> Result<()> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lonkero");

        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        fs::write(config_dir.join("license.key"), key)?;
        info!("License key saved");
        Ok(())
    }

    /// Validate license - checks server for killswitch, defaults to full access
    pub async fn validate(&self) -> Result<LicenseStatus> {
        // Try to check with server
        match self.check_server().await {
            Ok(status) => {
                // Server responded - use its response
                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(status.killswitch_active, Ordering::SeqCst);

                if status.killswitch_active {
                    error!("KILLSWITCH ACTIVE: {}", status.killswitch_reason.as_deref().unwrap_or("Unknown"));
                }

                Ok(status)
            }
            Err(e) => {
                // Server unreachable - FAIL OPEN (allow full access)
                // This is intentional: we don't want to block users if our server is down
                debug!("License server unreachable: {}. Allowing full access.", e);
                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(false, Ordering::SeqCst);

                Ok(LicenseStatus::default())
            }
        }
    }

    /// Check with license server
    async fn check_server(&self) -> Result<LicenseStatus> {
        let url = format!("{}/validate", LICENSE_SERVER);

        let mut request = self.http_client
            .post(&url)
            .header("X-Product", "lonkero")
            .header("X-Version", "1.0.0");

        if let Some(ref hw_id) = self.hardware_id {
            request = request.header("X-Hardware-ID", hw_id);
        }

        let body = serde_json::json!({
            "license_key": self.license_key,
            "hardware_id": self.hardware_id,
            "product": "lonkero",
            "version": "1.0.0"
        });

        let response = request.json(&body).send().await?;

        if response.status().is_success() {
            let status: LicenseStatus = response.json().await?;
            Ok(status)
        } else if response.status().as_u16() == 403 {
            // Explicitly blocked
            let status: LicenseStatus = response.json().await.unwrap_or_else(|_| LicenseStatus {
                valid: false,
                killswitch_active: true,
                killswitch_reason: Some("Access denied".to_string()),
                ..Default::default()
            });
            Ok(status)
        } else {
            Err(anyhow!("Server returned: {}", response.status()))
        }
    }

    pub fn allows_commercial_use(&self) -> bool {
        if let Some(ref _key) = self.license_key {
            // If they have a license key, assume commercial
            return true;
        }
        false
    }
}

/// Verify license before scan - main entry point
pub async fn verify_license_for_scan(
    license_key: Option<&str>,
    _target_count: usize,
    is_commercial: bool,
) -> Result<LicenseStatus> {
    let mut manager = LicenseManager::new()?;
    manager.load_license()?;

    if let Some(key) = license_key {
        manager.set_license_key(key.to_string());
    }

    let status = manager.validate().await?;

    // Store globally
    let _ = GLOBAL_LICENSE.set(status.clone());

    // Check killswitch
    if status.killswitch_active {
        return Err(anyhow!(
            "Scanner disabled: {}",
            status.killswitch_reason.clone().unwrap_or_else(|| "Contact support@bountyy.fi".to_string())
        ));
    }

    // Warn about commercial use without license
    if is_commercial && !manager.allows_commercial_use() {
        warn!("========================================================");
        warn!("NOTE: Commercial use requires a license from Bountyy Oy");
        warn!("      Visit: https://bountyy.fi/license");
        warn!("========================================================");
    }

    Ok(status)
}

/// Get global license status
pub fn get_global_license() -> Option<&'static LicenseStatus> {
    GLOBAL_LICENSE.get()
}

/// Print license info
pub fn print_license_info(status: &LicenseStatus) {
    if let Some(lt) = status.license_type {
        info!("License: {} Edition", lt);
    }

    if let Some(ref licensee) = status.licensee {
        info!("Licensed to: {}", licensee);
    }

    if let Some(ref org) = status.organization {
        info!("Organization: {}", org);
    }

    if let Some(ref msg) = status.message {
        debug!("{}", msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_license_has_full_access() {
        let status = LicenseStatus::default();
        assert!(status.valid);
        assert!(!status.killswitch_active);
        assert!(status.features.contains(&"all_scanners".to_string()));
        assert_eq!(status.max_targets, Some(100));
    }

    #[test]
    fn test_license_type_display() {
        assert_eq!(format!("{}", LicenseType::Personal), "Personal");
        assert_eq!(format!("{}", LicenseType::Enterprise), "Enterprise");
    }
}
