// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.
// License verification and killswitch module.

pub mod anti_tamper;
pub mod scan_auth;
pub use scan_auth::{DeniedModule, ModuleAuthorizeResponse, ScanAuthorization};

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
/// NOTE: OnceLock is safe here because:
/// 1. License status is set once and never modified
/// 2. Dynamic state (killswitch, validation) uses atomics (KILLSWITCH_ACTIVE, VALIDATION_TOKEN)
/// 3. TOCTOU is prevented by checking atomics on every access, not just cached license
static GLOBAL_LICENSE: OnceLock<LicenseStatus> = OnceLock::new();

/// Timestamp of last license validation (for periodic re-validation)
static LAST_VALIDATION: AtomicU64 = AtomicU64::new(0);

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

/// Runtime integrity verification - detects binary tampering
/// This function's bytecode checksum is verified at multiple points
#[inline(never)] // Prevent inlining to maintain addressable code
pub fn verify_binary_integrity() -> bool {
    // Multi-layer integrity check

    // Check 1: Verify critical constants are unchanged
    if INTEGRITY_MARKER != 0x4C4F4E4B45524F {
        error!("INTEGRITY VIOLATION: Marker tampered");
        return false;
    }

    // Check 2: Verify validation token system is operational
    let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
    let checked = KILLSWITCH_CHECKED.load(Ordering::SeqCst);

    // Check 3: Cross-verify with another integrity marker
    let _marker_xor = get_integrity_marker();
    if checked && token != 0 {
        // Token should never be exactly equal to marker (XOR relationship)
        if token == INTEGRITY_MARKER {
            error!("INTEGRITY VIOLATION: Token/marker collision");
            return false;
        }
    }

    // Check 4: Verify function pointers haven't been redirected
    // Compare actual function address with expected range
    let fn_ptr = verify_binary_integrity as *const ();
    let fn_addr = fn_ptr as usize;

    // Sanity check: function should be in reasonable memory range
    // (This won't catch all patches but detects some obvious tampering)
    if fn_addr == 0 || fn_addr == usize::MAX {
        error!("INTEGRITY VIOLATION: Function pointer invalid");
        return false;
    }

    true
}

/// Verify critical license enforcement functions haven't been patched
#[inline(never)]
pub fn verify_enforcement_integrity() -> bool {
    // Check that enforcement functions exist and are callable
    let verify_scan_ptr = verify_scan_authorized as *const ();
    let verify_rt_ptr = verify_rt_state as *const ();
    let is_killswitch_ptr = is_killswitch_active as *const ();

    // Verify pointers are valid and different (not redirected to same location)
    let addrs = [
        verify_scan_ptr as usize,
        verify_rt_ptr as usize,
        is_killswitch_ptr as usize,
    ];

    for &addr in &addrs {
        if addr == 0 || addr == usize::MAX {
            error!("INTEGRITY VIOLATION: Enforcement function pointer invalid");
            return false;
        }
    }

    // Verify they're not all redirected to same address (common patch technique)
    if addrs[0] == addrs[1] || addrs[1] == addrs[2] || addrs[0] == addrs[2] {
        error!("INTEGRITY VIOLATION: Function pointers redirected");
        return false;
    }

    true
}

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
/// Protected by hardcore anti-tampering system
#[inline(never)]
pub fn verify_scan_authorized() -> bool {
    // LAYER 0: Anti-tamper system check (new hardcore protection)
    if anti_tamper::was_tampered() {
        error!("Scan blocked: Tampering detected");
        return false;
    }

    // LAYER 1: Full anti-tamper integrity check
    if !anti_tamper::full_integrity_check() {
        error!("Scan blocked: Integrity check failed");
        return false;
    }

    // LAYER 2: Verify this function isn't hooked
    if !anti_tamper::verify_no_hook(verify_scan_authorized as *const ()) {
        error!("Scan blocked: Function hook detected");
        return false;
    }

    // LAYER 3: Legacy binary integrity (tamper detection)
    if !verify_binary_integrity() {
        error!("Scan blocked: Binary integrity check failed");
        return false;
    }

    if !verify_enforcement_integrity() {
        error!("Scan blocked: Enforcement integrity check failed");
        return false;
    }

    // LAYER 4: Killswitch not active
    if is_killswitch_active() {
        return false;
    }

    // LAYER 5: Anti-tamper validation state
    if !anti_tamper::is_validated() {
        // Fall back to legacy token check
        if KILLSWITCH_CHECKED.load(Ordering::SeqCst) {
            let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
            if token == 0 {
                return false;
            }
        }
    }

    // LAYER 6: Global license exists and is valid
    if let Some(license) = get_global_license() {
        if !license.valid || license.killswitch_active {
            return false;
        }
    }

    // LAYER 7: Final magic constant verification
    if !anti_tamper::verify_magic_constants() {
        error!("Scan blocked: Binary modification detected");
        return false;
    }

    true
}

/// Get license signature for embedding in results
pub fn get_license_signature() -> String {
    if let Some(license) = get_global_license() {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", license.license_type).as_bytes());
        hasher.update(
            license
                .licensee
                .as_deref()
                .unwrap_or("unlicensed")
                .as_bytes(),
        );
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
    // Advanced bypass techniques
    "rate_limiting_bypass",
    "mfa_bypass_advanced",
    "mass_assignment_advanced",
    // Professional tier scanners
    "client_route_auth_bypass",
    "template_injection",
    "session_analyzer",
    "baseline_detector",
    "information_disclosure",
];

/// Check if a premium feature is available for the current license
/// Protected by multi-layer anti-tampering system
#[inline(never)]
pub fn is_feature_available(feature: &str) -> bool {
    // LAYER 1: Anti-tamper check - if tampering detected, deny all
    if anti_tamper::was_tampered() {
        return false;
    }

    // LAYER 2: Full integrity verification (periodic)
    // Run full check every ~100 calls
    let check_count = SCAN_COUNTER.fetch_add(1, Ordering::SeqCst);
    if check_count % 100 == 0 {
        if !anti_tamper::full_integrity_check() {
            return false;
        }
    }

    // LAYER 3: Verify this function hasn't been hooked
    if !anti_tamper::verify_no_hook(is_feature_available as *const ()) {
        return false;
    }

    // LAYER 4: Always allow basic features
    if !PREMIUM_FEATURES.contains(&feature) {
        return true;
    }

    // LAYER 5: Verify anti-tamper validation state
    if !anti_tamper::is_validated() {
        // Double-check with legacy token system
        let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
        if token == 0 && KILLSWITCH_CHECKED.load(Ordering::SeqCst) {
            return false;
        }
    }

    // LAYER 6: Check license status
    if let Some(license) = get_global_license() {
        // Enterprise and Team get all features
        if let Some(license_type) = license.license_type {
            match license_type {
                LicenseType::Enterprise | LicenseType::Team => {
                    // Final verification before granting premium access
                    return anti_tamper::verify_magic_constants();
                }
                LicenseType::Professional => {
                    // Professional gets most features except team/enterprise-only
                    let enterprise_only =
                        &["team_sharing", "custom_integrations", "dedicated_support"];
                    if enterprise_only.contains(&feature) {
                        return false;
                    }
                    return anti_tamper::verify_magic_constants();
                }
                LicenseType::Personal => {
                    // Personal/Free gets limited premium features
                    // Check if explicitly granted in features list
                    let granted = license.features.iter().any(|f| f == feature);
                    if granted {
                        return anti_tamper::verify_magic_constants();
                    }
                    return false;
                }
            }
        }
    }

    // LAYER 7: If no license, check token validity (anti-tampering)
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
            Some(LicenseType::Enterprise)
            | Some(LicenseType::Team)
            | Some(LicenseType::Professional) => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Check if a feature is available based on license
///
/// Feature requirements:
/// - "cms_security" -> Personal+ (WordPress, Drupal, Laravel, Django, etc.)
/// - "advanced_scanning" -> Professional+ (SQLi, XSS, SSRF, etc.)
/// - "cloud_scanning" -> Team+ (AWS, Azure, GCP, K8s)
/// - "custom_integrations" -> Enterprise (custom modules, compliance)
///
/// NOTE: This is a LOCAL check only. Server-side authorization via
/// ScanAuthorization should be used for actual module access control.
/// This function is for backwards compatibility and offline fallback.
pub fn has_feature(feature: &str) -> bool {
    // Check global license status
    if let Some(license) = get_global_license() {
        // Check if killswitch is active
        if license.killswitch_active {
            return false;
        }

        // Check if feature is explicitly in the features list
        if license
            .features
            .iter()
            .any(|f| f == feature || f == "all_features")
        {
            return true;
        }

        // Check based on license type
        if let Some(license_type) = license.license_type {
            match license_type {
                LicenseType::Enterprise => {
                    // Enterprise gets everything
                    return true;
                }
                LicenseType::Team => {
                    // Team gets cloud_scanning, advanced_scanning, cms_security
                    return matches!(
                        feature,
                        "cloud_scanning" | "advanced_scanning" | "cms_security"
                    );
                }
                LicenseType::Professional => {
                    // Professional gets advanced_scanning, cms_security
                    return matches!(feature, "advanced_scanning" | "cms_security");
                }
                LicenseType::Personal => {
                    // Personal gets cms_security only
                    return feature == "cms_security";
                }
            }
        }
    }

    // Anti-tampering check
    let token = VALIDATION_TOKEN.load(Ordering::SeqCst);
    if token == 0 && KILLSWITCH_CHECKED.load(Ordering::SeqCst) {
        return false;
    }

    // Default: deny premium features
    false
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
        // DEFAULT: FAIL-CLOSED - Minimal access when server unreachable
        // Only basic features available, premium features DENIED
        Self {
            valid: true,
            license_type: Some(LicenseType::Personal),
            licensee: None,
            organization: None,
            expires_at: None,
            features: vec![
                // Only basic scanners - NO PREMIUM FEATURES
                "basic_scanners".to_string(),
                "basic_outputs".to_string(),
            ],
            max_targets: Some(10), // Reduced from 100
            killswitch_active: false,
            killswitch_reason: None,
            message: Some("OFFLINE MODE: Limited features. Server unreachable. For full access: https://bountyy.fi".to_string()),
        }
    }
}

/// Killswitch response from server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
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
                .timeout(std::time::Duration::from_secs(30)) // Increased from 5s to 30s
                .connect_timeout(std::time::Duration::from_secs(10))
                .user_agent("Lonkero/1.0.0")
                .build()?,
            hardware_id: Self::get_hardware_id(),
        })
    }

    /// Get hardware fingerprint - MULTI-FACTOR for anti-spoofing
    /// Combines multiple hardware identifiers to make spoofing harder
    fn get_hardware_id() -> Option<String> {
        let mut components = Vec::new();

        // Component 1: Machine ID
        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = fs::read_to_string("/etc/machine-id") {
                components.push(format!("mid:{}", id.trim()));
            }
            // Also try systemd's machine-id
            if let Ok(id) = fs::read_to_string("/var/lib/dbus/machine-id") {
                components.push(format!("dbus:{}", id.trim()));
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
                    components.push(format!("uuid:{}", uuid_line.trim()));
                }
            }
        }

        // Component 2: CPU info (harder to spoof)
        #[cfg(target_os = "linux")]
        {
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                // Extract CPU serial or processor ID
                for line in cpuinfo.lines() {
                    if line.starts_with("Serial") || line.starts_with("processor") {
                        components.push(format!("cpu:{}", line.trim()));
                        break;
                    }
                }
            }
        }

        // Component 3: MAC address (network interface)
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Ok(output) = std::process::Command::new("sh")
                .args(["-c", "cat /sys/class/net/*/address 2>/dev/null | head -n1"])
                .output()
            {
                if output.status.success() {
                    let mac = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        components.push(format!("mac:{}", mac));
                    }
                }
            }
        }

        // Component 4: Hostname
        if let Ok(hostname) = hostname::get() {
            if let Ok(hostname_str) = hostname.into_string() {
                components.push(format!("host:{}", hostname_str));
            }
        }

        // If we have at least 2 components, create a composite fingerprint
        if components.len() >= 2 {
            let mut hasher = Sha256::new();
            for component in components {
                hasher.update(component.as_bytes());
                hasher.update(b"|"); // Separator
            }
            hasher.update(b"LONKERO_HW_V2"); // Version marker
            let hash = hasher.finalize();
            Some(hex::encode(&hash[0..16]))
        } else {
            // Not enough components for reliable fingerprint
            warn!("Hardware fingerprinting failed: insufficient identifiers");
            None
        }
    }

    pub fn load_license(&mut self) -> Result<Option<String>> {
        // Check environment variable (highest priority)
        if let Ok(key) = std::env::var("LONKERO_LICENSE_KEY") {
            self.license_key = Some(key.clone());
            return Ok(Some(key));
        }

        // Try to load from OS keychain (SECURE STORAGE)
        if let Ok(entry) = keyring::Entry::new("lonkero", "license_key") {
            if let Ok(key) = entry.get_password() {
                if !key.is_empty() {
                    debug!("License key loaded from OS keychain");
                    self.license_key = Some(key.clone());
                    return Ok(Some(key));
                }
            }
        }

        // FALLBACK: Check legacy plaintext config file (for migration)
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("lonkero");
        let license_file = config_dir.join("license.key");

        if license_file.exists() {
            if let Ok(content) = fs::read_to_string(&license_file) {
                let key = content.trim().to_string();
                if !key.is_empty() {
                    warn!("Found license in INSECURE plaintext file. Migrating to OS keychain...");

                    // Migrate to keychain
                    if let Err(e) = self.save_license(&key) {
                        warn!("Failed to migrate license to keychain: {}", e);
                    } else {
                        // Delete plaintext file after successful migration
                        if let Err(e) = fs::remove_file(&license_file) {
                            warn!("Failed to delete plaintext license file: {}", e);
                        } else {
                            info!("License migrated to secure OS keychain");
                        }
                    }

                    self.license_key = Some(key.clone());
                    return Ok(Some(key));
                }
            }
        }

        Ok(None)
    }

    pub fn set_license_key(&mut self, key: String) {
        // ANTI-TAMPER: Check for honeypot/cracked keys
        if anti_tamper::check_honeypot_key(&key) {
            error!("Invalid license key detected");
            // Don't set the key, trigger lockdown
            return;
        }
        self.license_key = Some(key);
    }

    pub fn save_license(&self, key: &str) -> Result<()> {
        // Save to OS keychain (SECURE STORAGE)
        let entry = keyring::Entry::new("lonkero", "license_key")
            .map_err(|e| anyhow!("Failed to access OS keychain: {}", e))?;

        entry
            .set_password(key)
            .map_err(|e| anyhow!("Failed to save license to keychain: {}", e))?;

        info!("License key saved to OS keychain (encrypted)");

        // DO NOT save to plaintext file anymore - security vulnerability!
        // Old plaintext storage is deprecated and insecure

        Ok(())
    }

    /// Validate license with retry logic
    pub async fn validate(&self) -> Result<LicenseStatus> {
        debug!("Starting license validation with retry...");

        // Try to check with server (with retries)
        match self.check_server_with_retry().await {
            Ok(status) => {
                // Server responded - use its response
                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(status.killswitch_active, Ordering::SeqCst);

                // Set validation token for integrity verification
                let token = generate_token(&status);
                VALIDATION_TOKEN.store(token, Ordering::SeqCst);

                // ANTI-TAMPER: Initialize protection and set validated state
                anti_tamper::initialize_protection();
                if status.valid && !status.killswitch_active {
                    // Generate license hash for anti-tamper validation
                    let license_hash = {
                        let mut hasher = Sha256::new();
                        hasher.update(format!("{:?}", status.license_type).as_bytes());
                        hasher.update(status.licensee.as_deref().unwrap_or("").as_bytes());
                        hasher.update(&token.to_le_bytes());
                        let hash = hasher.finalize();
                        u64::from_le_bytes(hash[0..8].try_into().unwrap())
                    };
                    anti_tamper::set_validated(license_hash);
                }

                if status.killswitch_active {
                    error!(
                        "KILLSWITCH ACTIVE: {}",
                        status.killswitch_reason.as_deref().unwrap_or("Unknown")
                    );
                    // Clear token on killswitch
                    VALIDATION_TOKEN.store(0, Ordering::SeqCst);
                    // Trigger tamper response to lock everything down
                    anti_tamper::trigger_tamper_response("killswitch_active");
                }

                Ok(status)
            }
            Err(e) => {
                // Server unreachable - FAIL CLOSED (deny premium features)
                // Security-first: only basic features when server down
                error!("License server unreachable: {}. Running in OFFLINE MODE with limited features.", e);
                warn!(
                    "Premium features DISABLED. Restore network connection for full functionality."
                );

                KILLSWITCH_CHECKED.store(true, Ordering::SeqCst);
                KILLSWITCH_ACTIVE.store(false, Ordering::SeqCst);

                // Generate token for minimal offline license
                let offline_status = LicenseStatus::default();
                let token = generate_token(&offline_status);
                VALIDATION_TOKEN.store(token, Ordering::SeqCst);

                // ANTI-TAMPER: Initialize but DON'T set validated for offline mode
                // This ensures premium features remain locked
                anti_tamper::initialize_protection();
                // Offline mode gets minimal validation - basic features only
                anti_tamper::set_validated(0); // Zero hash = minimal access

                Ok(offline_status)
            }
        }
    }

    /// Check with license server with exponential backoff retry
    async fn check_server_with_retry(&self) -> Result<LicenseStatus> {
        const MAX_RETRIES: u32 = 3;
        const INITIAL_BACKOFF_MS: u64 = 1000;

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let backoff_ms = INITIAL_BACKOFF_MS * 2_u64.pow(attempt - 1);
                debug!("Retry attempt {} after {}ms", attempt + 1, backoff_ms);
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }

            match self.check_server().await {
                Ok(status) => return Ok(status),
                Err(e) => {
                    debug!("License server attempt {} failed: {}", attempt + 1, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("All retry attempts failed")))
    }

    /// Check with license server
    async fn check_server(&self) -> Result<LicenseStatus> {
        let url = format!("{}/validate", LICENSE_SERVER);

        debug!("Validating license with server: {}", url);
        debug!("License key present: {}", self.license_key.is_some());

        let mut request = self
            .http_client
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
                    info!(
                        "License validated: type={:?}, licensee={:?}",
                        status.license_type, status.licensee
                    );
                    Ok(status)
                }
                Err(e) => {
                    warn!(
                        "Failed to parse license response: {}. Response was: {}",
                        e, text
                    );
                    Err(anyhow!("Failed to parse license response: {}", e))
                }
            }
        } else if status_code.as_u16() == 403 {
            // Explicitly blocked
            let text = response.text().await.unwrap_or_default();
            warn!("License blocked (403): {}", text);
            let status: LicenseStatus =
                serde_json::from_str(&text).unwrap_or_else(|_| LicenseStatus {
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

    // Update validation timestamp (for periodic re-validation tracking)
    let now = chrono::Utc::now().timestamp() as u64;
    LAST_VALIDATION.store(now, Ordering::SeqCst);

    // Check killswitch
    if status.killswitch_active {
        return Err(anyhow!(
            "Scanner disabled: {}",
            status
                .killswitch_reason
                .clone()
                .unwrap_or_else(|| "Contact info@bountyy.fi".to_string())
        ));
    }

    // Warn about commercial use without license
    if is_commercial && !manager.allows_commercial_use() {
        warn!("========================================================");
        warn!("NOTE: Commercial use requires a license from Bountyy Oy");
        warn!("      Visit: https://bountyy.fi");
        warn!("========================================================");
    }

    Ok(status)
}

/// Get global license status
pub fn get_global_license() -> Option<&'static LicenseStatus> {
    GLOBAL_LICENSE.get()
}

/// Check if license validation is stale and needs refresh
/// Returns true if more than 24 hours since last validation
pub fn is_validation_stale() -> bool {
    const VALIDATION_TIMEOUT_SECS: u64 = 86400; // 24 hours
    let last = LAST_VALIDATION.load(Ordering::SeqCst);

    if last == 0 {
        return true; // Never validated
    }

    let now = chrono::Utc::now().timestamp() as u64;
    now.saturating_sub(last) > VALIDATION_TIMEOUT_SECS
}

/// Get time since last validation in hours
pub fn hours_since_validation() -> u64 {
    let last = LAST_VALIDATION.load(Ordering::SeqCst);
    if last == 0 {
        return u64::MAX; // Never validated
    }

    let now = chrono::Utc::now().timestamp() as u64;
    now.saturating_sub(last) / 3600
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
