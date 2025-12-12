// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.
// License verification and killswitch module.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};

/// Bountyy license server endpoint
const LICENSE_SERVER: &str = "https://lonkero.bountyy.fi/api/v1";

/// Global killswitch state
static KILLSWITCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static KILLSWITCH_CHECKED: AtomicBool = AtomicBool::new(false);

/// Global license status cache
static GLOBAL_LICENSE: OnceLock<LicenseStatus> = OnceLock::new();

// ============================================================================
// Anti-tampering: Integrity verification system
// These values are checked by distributed verifiers throughout the codebase
// ============================================================================

/// Internal validation token - set during license check, verified elsewhere
static VALIDATION_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Scan counter - tracks scans performed, used for integrity verification
static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Module integrity marker - must match expected value
const INTEGRITY_MARKER: u64 = 0x4C4F4E4B45524F; // "LONKERO" in hex

/// Generate validation token from license status
fn generate_token(status: &LicenseStatus) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", status.license_type).as_bytes());
    hasher.update(status.licensee.as_deref().unwrap_or("").as_bytes());
    hasher.update(&status.max_targets.unwrap_or(0).to_le_bytes());
    hasher.update(&INTEGRITY_MARKER.to_le_bytes());
    let hash = hasher.finalize();
    u64::from_le_bytes(hash[0..8].try_into().unwrap())
}

/// Verify the current validation state - called by distributed checks
#[inline]
pub fn verify_rt_state() -> bool {
    let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
    let checked = KILLSWITCH_CHECKED.load(Ordering::SeqCst);
    // Token must be non-zero if we've checked, and killswitch must not be active
    (token != 0 || !checked) && !KILLSWITCH_ACTIVE.load(Ordering::SeqCst)
}

/// Get current integrity marker for verification
#[inline]
pub fn get_integrity_marker() -> u64 {
    INTEGRITY_MARKER ^ VALIDATION_TOKEN.load(Ordering::SeqCst)
}

/// Increment scan counter - must be called for each scan
#[inline]
pub fn increment_scan_counter() -> u64 {
    SCAN_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Get scan counter value
#[inline]
pub fn get_scan_counter() -> u64 {
    SCAN_COUNTER.load(Ordering::SeqCst)
}

/// Verify scan is authorized - combines multiple checks
pub fn verify_scan_authorized() -> bool {
    // Check 1: Killswitch not active
    if is_killswitch_active() {
        return false;
    }

    // Check 2: License was validated (token set)
    if KILLSWITCH_CHECKED.load(Ordering::SeqCst) {
        let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
        if token == 0 {
            return false;
        }
    }

    // Check 3: Global license exists and is valid
    if let Some(license) = get_global_license() {
        if !license.valid || license.killswitch_active {
            return false;
        }
    }

    true
}

/// Get license signature for embedding in results
pub fn get_license_signature() -> String {
    if let Some(license) = get_global_license() {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", license.license_type).as_bytes());
        hasher.update(license.licensee.as_deref().unwrap_or("unlicensed").as_bytes());
        hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());
        let hash = hasher.finalize();
        format!("LKR-{}", hex::encode(&hash[0..8]))
    } else {
        "LKR-UNVALIDATED".to_string()
    }
}

/// Check if killswitch is active
#[inline]
pub fn is_killswitch_active() -> bool {
    KILLSWITCH_ACTIVE.load(Ordering::SeqCst)
}

// ============================================================================
// Feature gating - certain features require paid licenses
// ============================================================================

/// Premium features that require paid license
const PREMIUM_FEATURES: &[&str] = &[
    "cloud_scanning",
    "api_fuzzing",
    "container_scanning",
    "ssti_advanced",
    "team_sharing",
    "custom_integrations",
    "priority_support",
];

/// Check if a premium feature is available for the current license
pub fn is_feature_available(feature: &str) -> bool {
    // Always allow basic features
    if !PREMIUM_FEATURES.contains(&feature) {
        return true;
    }

    // Check license status
    if let Some(license) = get_global_license() {
        // Enterprise and Team get all features
        if let Some(license_type) = license.license_type {
            match license_type {
                LicenseType::Enterprise | LicenseType::Team => return true,
                LicenseType::Professional => {
                    // Professional gets most features except team/enterprise-only
                    let enterprise_only = &["team_sharing", "custom_integrations", "dedicated_support"];
                    return !enterprise_only.contains(&feature);
                }
                LicenseType::Personal => {
                    // Personal/Free gets limited premium features
                    // Check if explicitly granted in features list
                    return license.features.iter().any(|f| f == feature);
                }
            }
        }
    }

    // If no license, check token validity (anti-tampering)
    // This ensures removing license check doesn't grant access
    let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
    if token == 0 && KILLSWITCH_CHECKED.load(Ordering::SeqCst) {
        return false;
    }

    // Default to deny for premium features if license status unknown
    false
}

/// Check if license allows commercial use
pub fn allows_commercial_use() -> bool {
    if let Some(license) = get_global_license() {
        match license.license_type {
            Some(LicenseType::Enterprise) | Some(LicenseType::Team) | Some(LicenseType::Professional) => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Get max allowed targets for current license
pub fn get_max_targets() -> usize {
    if let Some(license) = get_global_license() {
        license.max_targets.unwrap_or(100) as usize
    } else {
        100 // Default free limit
    }
}

/// License types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseType {
    #[serde(alias = "Personal")]
    Personal,
    #[serde(alias = "Professional")]
    Professional,
    #[serde(alias = "Team")]
    Team,
    #[serde(alias = "Enterprise")]
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
    #[serde(default)]
    pub valid: bool,
    pub license_type: Option<LicenseType>,
    pub licensee: Option<String>,
    pub organization: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    pub max_targets: Option<u32>,
    #[serde(default)]
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
        debug!("Starting license validation...");

        // Try to check with server
        match self.check_server().await {
            Ok(status) => {
                // Server responded - use its response
                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(status.killswitch_active, Ordering::SeqCst);

                // Set validation token for integrity verification
                let token = generate_token(&status);
                VALIDATION_TOKEN.store(token, Ordering::SeqCst);

                if status.killswitch_active {
                    error!("KILLSWITCH ACTIVE: {}", status.killswitch_reason.as_deref().unwrap_or("Unknown"));
                    // Clear token on killswitch
                    VALIDATION_TOKEN.store(0, Ordering::SeqCst);
                }

                Ok(status)
            }
            Err(e) => {
                // Server unreachable - FAIL OPEN (allow full access)
                // This is intentional: we don't want to block users if our server is down
                warn!("License server error: {}. Falling back to free license.", e);
                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(false, Ordering::SeqCst);

                // Generate token for default license
                let default_status = LicenseStatus::default();
                let token = generate_token(&default_status);
                VALIDATION_TOKEN.store(token, Ordering::SeqCst);

                Ok(default_status)
            }
        }
    }

    /// Check with license server
    async fn check_server(&self) -> Result<LicenseStatus> {
        let url = format!("{}/validate", LICENSE_SERVER);

        debug!("Validating license with server: {}", url);
        debug!("License key present: {}", self.license_key.is_some());

        let mut request = self.http_client
            .post(&url)
            .header("X-Product", "lonkero")
            .header("X-Version", env!("CARGO_PKG_VERSION"));

        if let Some(ref hw_id) = self.hardware_id {
            request = request.header("X-Hardware-ID", hw_id);
        }

        let body = serde_json::json!({
            "license_key": self.license_key,
            "hardware_id": self.hardware_id,
            "product": "lonkero",
            "version": env!("CARGO_PKG_VERSION")
        });

        let response = request.json(&body).send().await?;
        let status_code = response.status();
        debug!("License server response status: {}", status_code);

        if status_code.is_success() {
            // Get raw text first for debugging
            let text = response.text().await?;
            debug!("License server response: {}", text);

            // Parse the response
            match serde_json::from_str::<LicenseStatus>(&text) {
                Ok(status) => {
                    info!("License validated: type={:?}, licensee={:?}",
                          status.license_type, status.licensee);
                    Ok(status)
                }
                Err(e) => {
                    warn!("Failed to parse license response: {}. Response was: {}", e, text);
                    Err(anyhow!("Failed to parse license response: {}", e))
                }
            }
        } else if status_code.as_u16() == 403 {
            // Explicitly blocked
            let text = response.text().await.unwrap_or_default();
            warn!("License blocked (403): {}", text);
            let status: LicenseStatus = serde_json::from_str(&text).unwrap_or_else(|_| LicenseStatus {
                valid: false,
                killswitch_active: true,
                killswitch_reason: Some("Access denied".to_string()),
                ..Default::default()
            });
            Ok(status)
        } else {
            let text = response.text().await.unwrap_or_default();
            warn!("License server error {}: {}", status_code, text);
            Err(anyhow!("Server returned: {} - {}", status_code, text))
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
        match lt {
            LicenseType::Personal => info!("License: Free Non-Commercial Edition"),
            _ => info!("License: {} Edition", lt),
        }
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
