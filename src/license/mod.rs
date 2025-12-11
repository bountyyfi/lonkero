// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.
// License verification and killswitch module.
//
// ANTI-TAMPERING NOTICE:
// This module contains critical license enforcement code.
// Tampering with or removing this code violates the license agreement
// and may result in legal action. The scanner's core functionality
// depends on valid license status - removing checks will break scanning.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};

/// Bountyy license server endpoint
const LICENSE_SERVER: &str = "https://license.bountyy.fi/api/v1";

/// Killswitch check endpoint
const KILLSWITCH_ENDPOINT: &str = "https://license.bountyy.fi/api/v1/killswitch";

/// Payload decryption endpoint (payloads are encrypted, need license to decrypt)
const PAYLOAD_SERVER: &str = "https://license.bountyy.fi/api/v1/payloads";

/// Grace period for offline use (days)
const OFFLINE_GRACE_DAYS: i64 = 7;

/// Cache duration for license validation (hours)
const LICENSE_CACHE_HOURS: i64 = 24;

/// Global license state - checked throughout the codebase
static LICENSE_VALID: AtomicBool = AtomicBool::new(false);
static LICENSE_CHECKED: AtomicBool = AtomicBool::new(false);
static SCAN_COUNT: AtomicU64 = AtomicU64::new(0);
static MAX_SCANS_ALLOWED: AtomicU64 = AtomicU64::new(1);
static KILLSWITCH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Global license status cache
static GLOBAL_LICENSE: OnceLock<LicenseStatus> = OnceLock::new();

/// Check if license is valid (called from scanner modules)
#[inline]
pub fn is_license_valid() -> bool {
    // Must have been checked first
    if !LICENSE_CHECKED.load(Ordering::SeqCst) {
        return false;
    }
    // Killswitch overrides everything
    if KILLSWITCH_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    LICENSE_VALID.load(Ordering::SeqCst)
}

/// Check if killswitch is active (called from scanner modules)
#[inline]
pub fn is_killswitch_active() -> bool {
    KILLSWITCH_ACTIVE.load(Ordering::SeqCst)
}

/// Increment scan counter and check limits
#[inline]
pub fn increment_scan_count() -> bool {
    let current = SCAN_COUNT.fetch_add(1, Ordering::SeqCst);
    let max = MAX_SCANS_ALLOWED.load(Ordering::SeqCst);
    current < max
}

/// Get current scan count
#[inline]
pub fn get_scan_count() -> u64 {
    SCAN_COUNT.load(Ordering::SeqCst)
}

/// Verify license inline - for embedding in scanner code
/// Returns a "verification token" that scanners use to validate results
#[inline]
pub fn get_verification_token() -> u64 {
    if !is_license_valid() {
        return 0;
    }
    // Generate a token based on license state
    let token = LICENSE_VALID.load(Ordering::SeqCst) as u64 * 0x5F3759DF
        + SCAN_COUNT.load(Ordering::SeqCst);
    token ^ 0xDEADBEEF
}

/// Validate verification token - scanners check this
#[inline]
pub fn validate_token(token: u64) -> bool {
    let expected = get_verification_token();
    // Allow some tolerance for race conditions
    token == expected || token == expected.wrapping_sub(1) || token == expected.wrapping_add(1)
}

/// License types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseType {
    /// Personal/non-commercial use (free, limited features)
    Personal,
    /// Professional license (single user)
    Professional,
    /// Team license (up to 10 users)
    Team,
    /// Enterprise license (unlimited users)
    Enterprise,
    /// Trial license (30 days)
    Trial,
}

impl std::fmt::Display for LicenseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseType::Personal => write!(f, "Personal"),
            LicenseType::Professional => write!(f, "Professional"),
            LicenseType::Team => write!(f, "Team"),
            LicenseType::Enterprise => write!(f, "Enterprise"),
            LicenseType::Trial => write!(f, "Trial"),
        }
    }
}

/// License status returned from validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseStatus {
    pub valid: bool,
    pub license_type: Option<LicenseType>,
    pub licensee: Option<String>,
    pub organization: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub features: Vec<String>,
    pub max_targets: Option<u32>,
    pub killswitch_active: bool,
    pub killswitch_reason: Option<String>,
    pub message: Option<String>,
}

impl Default for LicenseStatus {
    fn default() -> Self {
        Self {
            valid: false,
            license_type: None,
            licensee: None,
            organization: None,
            expires_at: None,
            features: vec![],
            max_targets: Some(1),
            killswitch_active: false,
            killswitch_reason: None,
            message: None,
        }
    }
}

/// License key structure (decoded)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseKey {
    /// License version
    pub version: u8,
    /// License type
    pub license_type: LicenseType,
    /// Licensee email or identifier
    pub licensee: String,
    /// Organization name (for team/enterprise)
    pub organization: Option<String>,
    /// Issue date
    pub issued_at: DateTime<Utc>,
    /// Expiration date
    pub expires_at: DateTime<Utc>,
    /// Maximum targets allowed per scan
    pub max_targets: u32,
    /// Enabled features
    pub features: Vec<String>,
    /// Hardware fingerprint (optional binding)
    pub hardware_id: Option<String>,
    /// Cryptographic signature
    pub signature: String,
}

/// Cached license validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseCache {
    pub status: LicenseStatus,
    pub validated_at: DateTime<Utc>,
    pub license_key_hash: String,
}

/// Killswitch response from server
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KillswitchResponse {
    pub active: bool,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub revoked_keys: Vec<String>,
}

/// License manager handles all license operations
pub struct LicenseManager {
    /// Current license key (if any)
    license_key: Option<String>,
    /// Cached validation result
    cache: Option<LicenseCache>,
    /// HTTP client for license server communication
    http_client: reqwest::Client,
    /// Path to license file
    license_file_path: PathBuf,
    /// Path to cache file
    cache_file_path: PathBuf,
}

impl LicenseManager {
    /// Create a new license manager
    pub fn new() -> Result<Self> {
        let config_dir = Self::get_config_dir()?;

        Ok(Self {
            license_key: None,
            cache: None,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Lonkero/1.0.0")
                .build()?,
            license_file_path: config_dir.join("license.key"),
            cache_file_path: config_dir.join(".license_cache"),
        })
    }

    /// Get configuration directory
    fn get_config_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lonkero");

        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        Ok(config_dir)
    }

    /// Load license from environment, file, or CLI argument
    pub fn load_license(&mut self) -> Result<Option<String>> {
        // Priority: CLI arg > Environment variable > License file

        // Check environment variable
        if let Ok(key) = std::env::var("LONKERO_LICENSE_KEY") {
            debug!("License key loaded from environment variable");
            self.license_key = Some(key.clone());
            return Ok(Some(key));
        }

        // Check license file
        if self.license_file_path.exists() {
            match fs::read_to_string(&self.license_file_path) {
                Ok(content) => {
                    let key = content.trim().to_string();
                    if !key.is_empty() {
                        debug!("License key loaded from file: {:?}", self.license_file_path);
                        self.license_key = Some(key.clone());
                        return Ok(Some(key));
                    }
                }
                Err(e) => {
                    warn!("Failed to read license file: {}", e);
                }
            }
        }

        // Load cache for offline validation
        self.load_cache();

        Ok(None)
    }

    /// Set license key directly (from CLI argument)
    pub fn set_license_key(&mut self, key: String) {
        self.license_key = Some(key);
    }

    /// Save license key to file
    pub fn save_license(&self, key: &str) -> Result<()> {
        fs::write(&self.license_file_path, key)?;
        info!("License key saved to {:?}", self.license_file_path);
        Ok(())
    }

    /// Load cached validation result
    fn load_cache(&mut self) {
        if self.cache_file_path.exists() {
            if let Ok(content) = fs::read_to_string(&self.cache_file_path) {
                if let Ok(cache) = serde_json::from_str::<LicenseCache>(&content) {
                    self.cache = Some(cache);
                    debug!("License cache loaded");
                }
            }
        }
    }

    /// Save validation result to cache
    fn save_cache(&self, status: &LicenseStatus, key_hash: &str) -> Result<()> {
        let cache = LicenseCache {
            status: status.clone(),
            validated_at: Utc::now(),
            license_key_hash: key_hash.to_string(),
        };

        let content = serde_json::to_string(&cache)?;
        fs::write(&self.cache_file_path, content)?;
        debug!("License cache saved");
        Ok(())
    }

    /// Hash a license key for cache comparison
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validate the current license
    pub async fn validate(&mut self) -> Result<LicenseStatus> {
        // First, check global killswitch (even without license)
        if let Err(e) = self.check_killswitch().await {
            warn!("Killswitch check failed: {}", e);
            // Continue - we'll use cached data or offline mode
        }

        let key = match &self.license_key {
            Some(k) => k.clone(),
            None => {
                // No license - check if we have a valid cache for offline use
                if let Some(ref cache) = self.cache {
                    let age = Utc::now() - cache.validated_at;
                    if age < Duration::days(OFFLINE_GRACE_DAYS) && cache.status.valid {
                        info!("Using cached license (offline mode, {} days remaining)",
                              OFFLINE_GRACE_DAYS - age.num_days());
                        return Ok(cache.status.clone());
                    }
                }

                // No license, return personal/unlicensed status
                return Ok(LicenseStatus {
                    valid: true,
                    license_type: Some(LicenseType::Personal),
                    message: Some("Running in personal/non-commercial mode. For commercial use, please obtain a license at https://bountyy.fi/license".to_string()),
                    max_targets: Some(1),
                    features: vec!["basic_scanning".to_string()],
                    ..Default::default()
                });
            }
        };

        let key_hash = Self::hash_key(&key);

        // Check cache validity
        if let Some(ref cache) = self.cache {
            if cache.license_key_hash == key_hash {
                let age = Utc::now() - cache.validated_at;
                if age < Duration::hours(LICENSE_CACHE_HOURS) && cache.status.valid {
                    debug!("Using cached license validation");
                    return Ok(cache.status.clone());
                }
            }
        }

        // Validate online
        match self.validate_online(&key).await {
            Ok(status) => {
                // Save to cache
                let _ = self.save_cache(&status, &key_hash);
                Ok(status)
            }
            Err(e) => {
                warn!("Online validation failed: {}. Trying offline validation.", e);

                // Try offline validation with signature check
                self.validate_offline(&key)
            }
        }
    }

    /// Validate license online against Bountyy server
    async fn validate_online(&self, key: &str) -> Result<LicenseStatus> {
        let url = format!("{}/validate", LICENSE_SERVER);

        let response = self.http_client
            .post(&url)
            .json(&serde_json::json!({
                "license_key": key,
                "product": "lonkero",
                "version": "1.0.0",
                "hardware_id": self.get_hardware_id(),
            }))
            .send()
            .await?;

        if response.status().is_success() {
            let status: LicenseStatus = response.json().await?;

            if status.killswitch_active {
                return Err(anyhow!(
                    "License has been revoked: {}",
                    status.killswitch_reason.unwrap_or_else(|| "Contact support@bountyy.fi".to_string())
                ));
            }

            Ok(status)
        } else if response.status().as_u16() == 403 {
            // License revoked or invalid
            let error: serde_json::Value = response.json().await.unwrap_or_default();
            Err(anyhow!(
                "License invalid or revoked: {}",
                error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error")
            ))
        } else {
            Err(anyhow!("License server returned status: {}", response.status()))
        }
    }

    /// Validate license offline using embedded signature verification
    fn validate_offline(&self, key: &str) -> Result<LicenseStatus> {
        // Decode and verify the license key structure
        let decoded = self.decode_license_key(key)?;

        // Check expiration
        if decoded.expires_at < Utc::now() {
            return Err(anyhow!(
                "License expired on {}. Please renew at https://bountyy.fi/license",
                decoded.expires_at.format("%Y-%m-%d")
            ));
        }

        // Verify signature (simplified - in production use proper asymmetric crypto)
        if !self.verify_signature(&decoded) {
            return Err(anyhow!("Invalid license signature. Please contact support@bountyy.fi"));
        }

        Ok(LicenseStatus {
            valid: true,
            license_type: Some(decoded.license_type),
            licensee: Some(decoded.licensee),
            organization: decoded.organization,
            expires_at: Some(decoded.expires_at),
            features: decoded.features,
            max_targets: Some(decoded.max_targets),
            killswitch_active: false,
            killswitch_reason: None,
            message: Some("License validated offline".to_string()),
        })
    }

    /// Decode a license key from base64
    fn decode_license_key(&self, key: &str) -> Result<LicenseKey> {
        // License format: LONKERO-XXXX-XXXX-XXXX-XXXX
        // The key is base64 encoded JSON
        let clean_key = key
            .replace("LONKERO-", "")
            .replace("-", "");

        let decoded = BASE64.decode(&clean_key)
            .map_err(|_| anyhow!("Invalid license key format"))?;

        let license: LicenseKey = serde_json::from_slice(&decoded)
            .map_err(|_| anyhow!("Invalid license key structure"))?;

        Ok(license)
    }

    /// Verify license signature (simplified version)
    fn verify_signature(&self, license: &LicenseKey) -> bool {
        // In production, this would use ed25519 or RSA signature verification
        // with Bountyy's public key embedded in the binary

        // Create the signing payload
        let payload = format!(
            "{}:{}:{}:{}:{}",
            license.version,
            license.licensee,
            license.license_type as u8,
            license.issued_at.timestamp(),
            license.expires_at.timestamp()
        );

        // For now, we use a simple HMAC check
        // In production, replace with proper asymmetric signature verification
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hasher.update(b"bountyy-signing-key-v1"); // Would be asymmetric in production
        let expected = hex::encode(hasher.finalize());

        license.signature.starts_with(&expected[..16])
    }

    /// Check global killswitch status
    async fn check_killswitch(&self) -> Result<()> {
        let response = self.http_client
            .get(KILLSWITCH_ENDPOINT)
            .header("X-Product", "lonkero")
            .header("X-Version", "1.0.0")
            .send()
            .await?;

        if response.status().is_success() {
            let ks: KillswitchResponse = response.json().await?;

            if ks.active {
                error!("KILLSWITCH ACTIVATED: {}", ks.reason.unwrap_or_default());
                return Err(anyhow!(
                    "Lonkero has been remotely disabled. Reason: {}. {}",
                    ks.reason.unwrap_or_else(|| "Security measure".to_string()),
                    ks.message.unwrap_or_else(|| "Contact support@bountyy.fi for assistance".to_string())
                ));
            }

            // Check if current license is in revoked list
            if let Some(ref key) = self.license_key {
                let key_hash = Self::hash_key(key);
                if ks.revoked_keys.contains(&key_hash) {
                    return Err(anyhow!(
                        "Your license has been revoked. This may be due to detected misuse. Contact support@bountyy.fi"
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get hardware fingerprint for license binding
    fn get_hardware_id(&self) -> Option<String> {
        // Generate a hardware fingerprint based on machine characteristics
        // This helps prevent license sharing

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

    /// Check if a specific feature is enabled
    pub fn has_feature(&self, feature: &str) -> bool {
        if let Some(ref cache) = self.cache {
            return cache.status.features.contains(&feature.to_string());
        }
        false
    }

    /// Get maximum allowed targets
    pub fn max_targets(&self) -> u32 {
        if let Some(ref cache) = self.cache {
            return cache.status.max_targets.unwrap_or(1);
        }
        1
    }

    /// Check if commercial use is allowed
    pub fn allows_commercial_use(&self) -> bool {
        if let Some(ref cache) = self.cache {
            if let Some(lt) = cache.status.license_type {
                return matches!(lt, LicenseType::Professional | LicenseType::Team | LicenseType::Enterprise);
            }
        }
        false
    }
}

/// Verify license before running a scan
/// This is the main entry point called from CLI
pub async fn verify_license_for_scan(
    license_key: Option<&str>,
    target_count: usize,
    is_commercial: bool,
) -> Result<LicenseStatus> {
    let mut manager = LicenseManager::new()?;

    // Load license
    manager.load_license()?;

    // Override with CLI argument if provided
    if let Some(key) = license_key {
        manager.set_license_key(key.to_string());
    }

    // Validate
    let status = manager.validate().await?;

    // Set global license state - this is checked by scanner modules
    LICENSE_CHECKED.store(true, Ordering::SeqCst);
    LICENSE_VALID.store(status.valid, Ordering::SeqCst);
    KILLSWITCH_ACTIVE.store(status.killswitch_active, Ordering::SeqCst);

    if let Some(max) = status.max_targets {
        MAX_SCANS_ALLOWED.store(max as u64 * 1000, Ordering::SeqCst); // Allow 1000 tests per target
    }

    // Store globally for scanner access
    let _ = GLOBAL_LICENSE.set(status.clone());

    // Check killswitch
    if status.killswitch_active {
        return Err(anyhow!(
            "This software has been disabled. Reason: {}",
            status.killswitch_reason.clone().unwrap_or_else(|| "Unknown".to_string())
        ));
    }

    // Check target count
    if let Some(max) = status.max_targets {
        if target_count as u32 > max {
            return Err(anyhow!(
                "Your license allows scanning {} target(s), but you specified {}. Upgrade at https://bountyy.fi/license",
                max,
                target_count
            ));
        }
    }

    // Check commercial use
    if is_commercial && !manager.allows_commercial_use() {
        warn!("========================================================");
        warn!("WARNING: Commercial use requires a valid license!");
        warn!("========================================================");
        warn!("");
        warn!("You are using Lonkero for commercial purposes without a");
        warn!("valid commercial license. This is a violation of the");
        warn!("Lonkero Source-Available License.");
        warn!("");
        warn!("To obtain a commercial license, please visit:");
        warn!("  https://bountyy.fi/license");
        warn!("");
        warn!("Or contact us at: info@bountyy.fi");
        warn!("");
        warn!("Continuing scan in 10 seconds...");
        warn!("========================================================");

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }

    Ok(status)
}

/// Check license during scan execution - call this from scanner modules
/// Returns Ok if license is valid, Err if scanner should stop
pub fn check_license_during_scan() -> Result<()> {
    // Quick atomic checks first (fast path)
    if KILLSWITCH_ACTIVE.load(Ordering::SeqCst) {
        return Err(anyhow!("Scanner disabled by remote killswitch"));
    }

    if !LICENSE_CHECKED.load(Ordering::SeqCst) {
        return Err(anyhow!("License not verified - run verification first"));
    }

    // Increment scan counter and check limits
    if !increment_scan_count() {
        return Err(anyhow!(
            "Scan limit reached for your license. Upgrade at https://bountyy.fi/license"
        ));
    }

    Ok(())
}

/// Get the global license status (for scanner modules)
pub fn get_global_license() -> Option<&'static LicenseStatus> {
    GLOBAL_LICENSE.get()
}

/// Periodic license revalidation (call every N minutes during long scans)
pub async fn revalidate_license() -> Result<()> {
    let mut manager = LicenseManager::new()?;
    manager.load_license()?;

    // Force online check
    let status = manager.validate().await?;

    // Update global state
    LICENSE_VALID.store(status.valid, Ordering::SeqCst);
    KILLSWITCH_ACTIVE.store(status.killswitch_active, Ordering::SeqCst);

    if status.killswitch_active {
        error!("KILLSWITCH ACTIVATED DURING SCAN");
        return Err(anyhow!("Scanner disabled by remote killswitch"));
    }

    Ok(())
}

/// Print license information
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

    if let Some(expires) = status.expires_at {
        let days_left = (expires - Utc::now()).num_days();
        if days_left < 30 {
            warn!("License expires in {} days ({})", days_left, expires.format("%Y-%m-%d"));
        } else {
            info!("License valid until: {}", expires.format("%Y-%m-%d"));
        }
    }

    if let Some(ref msg) = status.message {
        info!("{}", msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_type_display() {
        assert_eq!(format!("{}", LicenseType::Personal), "Personal");
        assert_eq!(format!("{}", LicenseType::Enterprise), "Enterprise");
    }

    #[test]
    fn test_hash_key() {
        let hash = LicenseManager::hash_key("test-key");
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
    }

    #[tokio::test]
    async fn test_license_manager_new() {
        let manager = LicenseManager::new();
        assert!(manager.is_ok());
    }
}
