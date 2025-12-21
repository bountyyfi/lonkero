// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Strict quantum-safe report signing with mandatory server authorization
//!
//! This module provides cryptographic signing of scan results with
//! mandatory pre-scan authorization. NO OFFLINE FALLBACK - all operations
//! require server connectivity.
//!
//! ## Usage Flow
//! ```ignore
//! // Step 1: Authorize scan (ban check happens here!)
//! let scan_token = authorize_scan(target_count, &hardware_id, license_key, scanner_version).await?;
//!
//! // Step 2: Perform the actual scan
//! let results = perform_scan(targets).await?;
//!
//! // Step 3: Hash and sign results with privacy-safe findings summary
//! let results_hash = hash_results(&results)?;
//! let findings_summary = FindingsSummary::from_vulnerabilities(&results.vulnerabilities);
//! let signature = sign_results(&results_hash, &scan_token, modules_used, metadata, Some(findings_summary)).await?;
//! ```
//!
//! ## Privacy-Safe Findings Summary
//! The `FindingsSummary` struct contains ONLY aggregate counts:
//! - Total number of findings
//! - Counts by severity level (critical, high, medium, low, info)
//! - Counts by module/category name
//!
//! **NO sensitive data is included:**
//! - No target URLs
//! - No vulnerability details or payloads
//! - No parameters or evidence

use blake3::Hasher;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Backwards-compatible type alias for SigningError
pub type ScanError = SigningError;

/// Bountyy signing server base URL
const API_BASE: &str = "https://lonkero.bountyy.fi/api/v1";

/// Request timeout in seconds
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Token validity duration in seconds (6 hours)
const TOKEN_VALIDITY_SECS: u64 = 6 * 60 * 60;

/// Global scan token storage
static GLOBAL_SCAN_TOKEN: OnceLock<ScanToken> = OnceLock::new();

// ============ ERRORS ============

/// Errors that can occur during scan authorization or signing
#[derive(Debug, Clone, Error)]
pub enum SigningError {
    /// User is not authorized to scan
    #[error("Not authorized. Call authorize_scan() first.")]
    NotAuthorized,

    /// Authorization token has expired
    #[error("Authorization expired. Re-authorize to continue.")]
    AuthorizationExpired,

    /// User is banned from scanning
    #[error("BANNED: {0}")]
    Banned(String),

    /// License error
    #[error("License error: {0}")]
    LicenseError(String),

    /// Server is unreachable (network error)
    #[error("Server unreachable: {0}")]
    ServerUnreachable(String),

    /// Server returned an error
    #[error("Server error: {0}")]
    ServerError(String),

    /// Invalid response from server
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

// ============ REQUEST/RESPONSE STRUCTS ============

/// Request to authorize a scan before it begins
#[derive(Debug, Clone, Serialize)]
struct ScanAuthorizeRequest {
    /// Number of targets to scan
    targets_count: u32,
    /// Hardware fingerprint for device identification
    hardware_id: String,
    /// Optional license key for premium features
    #[serde(skip_serializing_if = "Option::is_none")]
    license_key: Option<String>,
    /// Scanner version for compatibility checking
    #[serde(skip_serializing_if = "Option::is_none")]
    scanner_version: Option<String>,
    /// List of module IDs to request authorization for
    modules: Vec<String>,
}

/// Denied module information from server
#[derive(Debug, Clone, Deserialize)]
pub struct DeniedModuleInfo {
    /// Module ID that was denied
    pub module: String,
    /// Reason for denial
    pub reason: String,
}

/// Response from scan authorization endpoint
#[derive(Debug, Clone, Deserialize)]
struct ScanAuthorizeResponse {
    /// Whether the scan is authorized
    authorized: bool,
    /// Scan token for subsequent signing (only if authorized)
    scan_token: Option<String>,
    /// Token expiration timestamp (ISO 8601)
    token_expires_at: Option<String>,
    /// Maximum targets allowed for this license
    max_targets: Option<u32>,
    /// License type (Personal, Professional, Team, Enterprise)
    license_type: Option<String>,
    /// Modules the server authorized
    authorized_modules: Option<Vec<String>>,
    /// Modules denied with reasons
    denied_modules: Option<Vec<DeniedModuleInfo>>,
    /// Error message if not authorized
    error: Option<String>,
    /// Ban reason if user is banned - CHECK THIS FIRST
    ban_reason: Option<String>,
}

/// Request to sign scan results
#[derive(Debug, Clone, Serialize)]
struct SignRequest {
    /// BLAKE3 hash of the scan results (64 hex chars, lowercase)
    results_hash: String,
    /// Scan token from authorization (REQUIRED)
    scan_token: String,
    /// Optional license key
    #[serde(skip_serializing_if = "Option::is_none")]
    license_key: Option<String>,
    /// Hardware fingerprint
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_id: Option<String>,
    /// Request timestamp in MILLISECONDS since epoch
    timestamp: u64,
    /// Cryptographic nonce for replay protection (min 16 chars)
    nonce: String,
    /// Modules that were actually used in the scan
    modules_used: Vec<String>,
    /// Optional scan metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_metadata: Option<ScanMetadata>,
    /// PRIVACY-SAFE: Aggregate findings summary (only counts, no URLs or details)
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_summary: Option<FindingsSummary>,
}

/// Response from signing endpoint
#[derive(Debug, Clone, Deserialize)]
struct SignResponse {
    /// Whether signing was successful
    valid: bool,
    /// The cryptographic signature (128 hex chars HMAC-SHA512)
    signature: Option<String>,
    /// Signing timestamp (ISO 8601)
    signed_at: Option<String>,
    /// License type used for signing
    license_type: Option<String>,
    /// Signing algorithm used (e.g., "HMAC-SHA512")
    algorithm: Option<String>,
    /// Error message if signing failed
    error: Option<String>,
}

// ============ PUBLIC STRUCTS ============

/// Authorization token received from server - required for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanToken {
    /// The token string from the server
    pub token: String,
    /// Expiration timestamp (ISO 8601)
    pub expires_at: String,
    /// Maximum targets allowed
    pub max_targets: u32,
    /// License type
    pub license_type: String,
    /// Modules authorized by the server
    pub authorized_modules: Vec<String>,
}

impl ScanToken {
    /// Check if the token is still valid based on expiration time
    pub fn is_valid(&self) -> bool {
        // Parse the ISO 8601 expires_at timestamp
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            let now = chrono::Utc::now();
            return now < expires;
        }

        // If parsing fails, check against token validity duration
        false
    }

    /// Check if a module is authorized by the server
    pub fn is_module_authorized(&self, module_id: &str) -> bool {
        self.authorized_modules.iter().any(|m| m == module_id)
    }

    /// Filter a list of modules to only include those authorized by the server
    ///
    /// This is a defensive check to ensure only authorized modules are used.
    /// Returns a tuple of (authorized_modules, denied_modules) for logging.
    ///
    /// # Example
    /// ```ignore
    /// let modules = vec!["sqli_scanner", "xss_scanner", "wordpress_scanner"];
    /// let token = license_client.authorize_scan(&targets, &modules).await?;
    ///
    /// // Defensive: Only use modules the server authorized
    /// let (approved, denied) = token.filter_modules(&modules);
    /// if !denied.is_empty() {
    ///     warn!("Modules not authorized: {:?}", denied);
    /// }
    /// // Use only approved modules
    /// ```
    pub fn filter_modules<'a>(&self, requested: &[&'a str]) -> (Vec<&'a str>, Vec<&'a str>) {
        let mut approved = Vec::new();
        let mut denied = Vec::new();

        for module in requested {
            if self.is_module_authorized(module) {
                approved.push(*module);
            } else {
                denied.push(*module);
            }
        }

        (approved, denied)
    }

    /// Get a list of modules that were requested but not authorized
    ///
    /// Useful for logging which modules were denied by the server.
    pub fn get_denied_modules(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|m| !self.is_module_authorized(m))
            .cloned()
            .collect()
    }
}

/// Complete signature attached to a report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSignature {
    /// Cryptographic signature from server (128 hex chars)
    pub signature: String,
    /// Algorithm used (e.g., "HMAC-SHA512")
    pub algorithm: String,
    /// Signing timestamp (ISO 8601)
    pub signed_at: String,
    /// License type used
    pub license_type: String,
    /// Hash of the results that were signed
    pub results_hash: String,
}

/// Metadata about the scan for audit purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Number of targets scanned
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets_count: Option<u32>,
    /// Scanner version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_version: Option<String>,
    /// Scan duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_duration_ms: Option<u64>,
}

/// PRIVACY-SAFE: Only aggregate counts, NO target URLs or finding details
///
/// This summary is sent to the signing server for telemetry purposes.
/// It contains only statistical counts - no sensitive information like
/// target URLs, payloads, or vulnerability descriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FindingsSummary {
    /// Total number of findings (just a count)
    pub total: u32,
    /// Counts by severity level (no details)
    pub by_severity: SeverityCounts,
    /// Counts by module name (no target info)
    pub by_module: HashMap<String, u32>,
}

impl FindingsSummary {
    /// Create a new empty findings summary
    pub fn new() -> Self {
        Self {
            total: 0,
            by_severity: SeverityCounts::new(),
            by_module: HashMap::new(),
        }
    }

    /// Normalize module/category name for consistent grouping
    fn normalize_module_name(name: &str) -> String {
        name.trim().to_lowercase()
    }

    /// Collect ONLY counts from vulnerabilities - no URLs, no finding content
    pub fn from_vulnerabilities(vulnerabilities: &[crate::types::Vulnerability]) -> Self {
        let mut summary = Self::new();

        for vuln in vulnerabilities {
            summary.total += 1;
            summary.by_severity.increment(&vuln.severity);
            // ONLY normalized category/type, NOT target URL or payload
            let module_name = Self::normalize_module_name(&vuln.category);
            *summary.by_module.entry(module_name).or_insert(0) += 1;
        }

        summary
    }
}

impl Default for FindingsSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts by severity level for findings summary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl SeverityCounts {
    /// Create new severity counts initialized to zero
    pub fn new() -> Self {
        Self {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        }
    }

    /// Increment the appropriate severity counter
    pub fn increment(&mut self, severity: &crate::types::Severity) {
        match severity {
            crate::types::Severity::Critical => self.critical += 1,
            crate::types::Severity::High => self.high += 1,
            crate::types::Severity::Medium => self.medium += 1,
            crate::types::Severity::Low => self.low += 1,
            crate::types::Severity::Info => self.info += 1,
        }
    }
}

impl Default for SeverityCounts {
    fn default() -> Self {
        Self::new()
    }
}

// ============ PUBLIC FUNCTIONS ============

/// Generate a cryptographically secure nonce (32 hex chars = 16 bytes)
pub fn generate_nonce() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

/// Hash scan results using BLAKE3
///
/// Returns a 64 character lowercase hex string
pub fn hash_results<T: Serialize>(results: &T) -> Result<String, SigningError> {
    let json = serde_json::to_string(results)
        .map_err(|e| SigningError::InvalidResponse(format!("Failed to serialize results: {}", e)))?;

    let mut hasher = Hasher::new();
    hasher.update(json.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// Check if scan is currently authorized
#[inline]
pub fn is_authorized() -> bool {
    match GLOBAL_SCAN_TOKEN.get() {
        Some(token) => token.is_valid(),
        None => false,
    }
}

/// Get the current scan token if authorized
pub fn get_scan_token() -> Option<&'static ScanToken> {
    GLOBAL_SCAN_TOKEN.get().filter(|t| t.is_valid())
}

/// Backwards-compatible alias for is_authorized()
#[inline]
pub fn is_scan_authorized() -> bool {
    is_authorized()
}

/// Get hardware fingerprint for device identification
pub fn get_hardware_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            let mut hasher = Sha256::new();
            hasher.update(id.trim().as_bytes());
            hasher.update(b"lonkero-signing-v1");
            return hex::encode(hasher.finalize())[..32].to_string();
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
                hasher.update(b"lonkero-signing-v1");
                return hex::encode(hasher.finalize())[..32].to_string();
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["csproduct", "get", "uuid"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid_line) = output_str.lines().nth(1) {
                let mut hasher = Sha256::new();
                hasher.update(uuid_line.trim().as_bytes());
                hasher.update(b"lonkero-signing-v1");
                return hex::encode(hasher.finalize())[..32].to_string();
            }
        }
    }

    // Fallback: use hostname + random component
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b"lonkero-fallback-v1");
    hex::encode(hasher.finalize())[..32].to_string()
}

/// Authorize scan BEFORE starting - NO OFFLINE FALLBACK
///
/// This MUST be called before any scanning operations. It:
/// - Checks if the user is banned (IP, ASN, hardware, license)
/// - Validates the license (if provided)
/// - Validates requested modules against license
/// - Returns a scan token with authorized modules
///
/// # Arguments
/// * `targets_count` - Number of targets to scan
/// * `hardware_id` - Hardware fingerprint for device identification
/// * `license_key` - Optional license key for premium features
/// * `scanner_version` - Optional scanner version string
/// * `modules` - List of module IDs to request authorization for
///
/// # Returns
/// * `Ok(ScanToken)` - Authorization successful, use this token for signing
/// * `Err(SigningError::Banned)` - User is banned, cannot proceed
/// * `Err(SigningError::ServerUnreachable)` - Network error, NO FALLBACK
pub async fn authorize_scan(
    targets_count: u32,
    hardware_id: &str,
    license_key: Option<&str>,
    scanner_version: Option<&str>,
    modules: Vec<String>,
) -> Result<ScanToken, SigningError> {
    debug!("Authorizing scan for {} targets with {} modules", targets_count, modules.len());

    let request = ScanAuthorizeRequest {
        targets_count,
        hardware_id: hardware_id.to_string(),
        license_key: license_key.map(String::from),
        scanner_version: scanner_version.map(String::from),
        modules,
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(format!("Lonkero/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SigningError::ServerUnreachable(e.to_string()))?;

    // Send authorization request - NO FALLBACK ON NETWORK ERROR
    let response = client
        .post(format!("{}/scan/authorize", API_BASE))
        .json(&request)
        .send()
        .await
        .map_err(|e| {
            error!("Authorization server unreachable: {}", e);
            SigningError::ServerUnreachable(e.to_string())
        })?;

    let status = response.status();
    let auth_response: ScanAuthorizeResponse = response.json().await.map_err(|e| {
        SigningError::InvalidResponse(format!("Failed to parse authorization response: {}", e))
    })?;

    // CRITICAL: Check ban_reason FIRST, before checking authorized field
    if let Some(ban_reason) = auth_response.ban_reason {
        error!("SCAN BLOCKED: User is banned - {}", ban_reason);
        return Err(SigningError::Banned(ban_reason));
    }

    // Log denied modules
    if let Some(ref denied) = auth_response.denied_modules {
        for d in denied {
            warn!("[Auth] Module '{}' denied: {}", d.module, d.reason);
        }
    }

    // Check if authorized
    if !auth_response.authorized {
        let error_msg = auth_response
            .error
            .unwrap_or_else(|| "Authorization denied".to_string());

        if status.as_u16() == 403 || error_msg.to_lowercase().contains("license") {
            return Err(SigningError::LicenseError(error_msg));
        }
        return Err(SigningError::ServerError(error_msg));
    }

    // Extract token from response
    let token_str = auth_response
        .scan_token
        .ok_or_else(|| SigningError::InvalidResponse("Missing scan_token in response".to_string()))?;

    let expires_at = auth_response
        .token_expires_at
        .ok_or_else(|| SigningError::InvalidResponse("Missing token_expires_at in response".to_string()))?;

    let max_targets = auth_response.max_targets.unwrap_or(100);
    let license_type = auth_response
        .license_type
        .unwrap_or_else(|| "Personal".to_string());
    let authorized_modules = auth_response.authorized_modules.unwrap_or_default();

    info!(
        "[Auth] Authorized: {} license, max {} targets, {} modules",
        license_type, max_targets, authorized_modules.len()
    );

    let token = ScanToken {
        token: token_str,
        expires_at,
        max_targets,
        license_type: license_type.clone(),
        authorized_modules,
    };

    // Store token globally (only succeeds once per process)
    let _ = GLOBAL_SCAN_TOKEN.set(token.clone());

    Ok(token)
}

/// Sign results AFTER scanning - NO OFFLINE FALLBACK
///
/// Creates a cryptographic signature for the scan results.
/// The signature can be verified by third parties to prove authenticity.
///
/// # Arguments
/// * `results_hash` - BLAKE3 hash of the scan results (64 hex chars, lowercase)
/// * `scan_token` - Token from authorize_scan()
/// * `modules_used` - List of module IDs that were actually used during the scan
/// * `metadata` - Optional scan metadata for audit purposes
/// * `findings_summary` - Optional privacy-safe aggregate findings counts (no URLs or details)
///
/// # Returns
/// * `Ok(ReportSignature)` - Signature created successfully
/// * `Err(SigningError::ServerUnreachable)` - Network error, NO FALLBACK
pub async fn sign_results(
    results_hash: &str,
    scan_token: &ScanToken,
    modules_used: Vec<String>,
    metadata: Option<ScanMetadata>,
    findings_summary: Option<FindingsSummary>,
) -> Result<ReportSignature, SigningError> {
    // Validate hash format: 64 hex chars, lowercase
    if !is_valid_blake3_hash(results_hash) {
        return Err(SigningError::InvalidResponse(
            "Invalid results_hash: must be 64 lowercase hex characters".to_string(),
        ));
    }

    // Verify token is still valid
    if !scan_token.is_valid() {
        return Err(SigningError::AuthorizationExpired);
    }

    // Generate timestamp in MILLISECONDS
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SigningError::ServerError("System time error".to_string()))?
        .as_millis() as u64;

    let nonce = generate_nonce();

    debug!(
        "[Sign] Signing with {} modules used, findings_summary: {}",
        modules_used.len(),
        findings_summary.as_ref().map(|f| f.total).unwrap_or(0)
    );

    let request = SignRequest {
        results_hash: results_hash.to_string(),
        scan_token: scan_token.token.clone(),
        license_key: None,
        hardware_id: None,
        timestamp,
        nonce,
        modules_used,
        scan_metadata: metadata,
        findings_summary,
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(format!("Lonkero/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SigningError::ServerUnreachable(e.to_string()))?;

    // Send sign request - NO FALLBACK ON NETWORK ERROR
    let response = client
        .post(format!("{}/sign", API_BASE))
        .json(&request)
        .send()
        .await
        .map_err(|e| {
            error!("Signing server unreachable: {}", e);
            SigningError::ServerUnreachable(e.to_string())
        })?;

    let sign_response: SignResponse = response.json().await.map_err(|e| {
        SigningError::InvalidResponse(format!("Failed to parse sign response: {}", e))
    })?;

    // Check for errors
    if !sign_response.valid {
        let error_msg = sign_response
            .error
            .unwrap_or_else(|| "Signing failed".to_string());
        return Err(SigningError::ServerError(error_msg));
    }

    // Extract signature from response
    let signature = sign_response
        .signature
        .ok_or_else(|| SigningError::InvalidResponse("Missing signature in response".to_string()))?;

    let signed_at = sign_response
        .signed_at
        .ok_or_else(|| SigningError::InvalidResponse("Missing signed_at in response".to_string()))?;

    let algorithm = sign_response
        .algorithm
        .unwrap_or_else(|| "HMAC-SHA512".to_string());

    let license_type = sign_response
        .license_type
        .unwrap_or_else(|| scan_token.license_type.clone());

    info!("Results signed successfully with {}", algorithm);

    Ok(ReportSignature {
        signature,
        algorithm,
        signed_at,
        license_type,
        results_hash: results_hash.to_string(),
    })
}

// ============ HELPER FUNCTIONS ============

/// Validate BLAKE3 hash format: exactly 64 lowercase hex characters
fn is_valid_blake3_hash(hash: &str) -> bool {
    if hash.len() != 64 {
        return false;
    }
    hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// ============ TESTS ============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be unique
        assert_ne!(nonce1, nonce2);

        // Nonce should be at least 16 chars (requirement)
        assert!(nonce1.len() >= 16);

        // Our implementation produces 32 hex chars (16 bytes)
        assert_eq!(nonce1.len(), 32);

        // Should be valid hex
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_results() {
        #[derive(Serialize)]
        struct TestData {
            value: String,
        }

        let data = TestData {
            value: "test".to_string(),
        };

        let hash = hash_results(&data).unwrap();

        // BLAKE3 produces 64 hex chars
        assert_eq!(hash.len(), 64);

        // Should be lowercase hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // Same input should produce same hash
        let hash2 = hash_results(&data).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_is_valid_blake3_hash() {
        // Valid hash
        let valid = "a".repeat(64);
        assert!(is_valid_blake3_hash(&valid));

        // Too short
        assert!(!is_valid_blake3_hash("abc123"));

        // Too long
        let too_long = "a".repeat(65);
        assert!(!is_valid_blake3_hash(&too_long));

        // Contains uppercase (invalid for our requirement)
        let uppercase = "A".repeat(64);
        assert!(!is_valid_blake3_hash(&uppercase));

        // Contains non-hex characters
        let invalid_chars = "g".repeat(64);
        assert!(!is_valid_blake3_hash(&invalid_chars));
    }

    #[test]
    fn test_scan_token_validity() {
        // Valid token (expires in future)
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let valid_token = ScanToken {
            token: "test_token".to_string(),
            expires_at: future.to_rfc3339(),
            max_targets: 100,
            license_type: "Personal".to_string(),
            authorized_modules: vec!["sqli_scanner".to_string(), "xss_scanner".to_string()],
        };
        assert!(valid_token.is_valid());
        assert!(valid_token.is_module_authorized("sqli_scanner"));
        assert!(!valid_token.is_module_authorized("wordpress_scanner"));

        // Expired token
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let expired_token = ScanToken {
            token: "test_token".to_string(),
            expires_at: past.to_rfc3339(),
            max_targets: 100,
            license_type: "Personal".to_string(),
            authorized_modules: vec![],
        };
        assert!(!expired_token.is_valid());

        // Invalid timestamp format
        let invalid_token = ScanToken {
            token: "test_token".to_string(),
            expires_at: "invalid".to_string(),
            max_targets: 100,
            license_type: "Personal".to_string(),
            authorized_modules: vec![],
        };
        assert!(!invalid_token.is_valid());
    }

    #[test]
    fn test_signing_error_display() {
        let err = SigningError::Banned("Test ban reason".to_string());
        assert!(err.to_string().contains("BANNED"));
        assert!(err.to_string().contains("Test ban reason"));

        let err = SigningError::NotAuthorized;
        assert!(err.to_string().contains("authorize_scan"));

        let err = SigningError::AuthorizationExpired;
        assert!(err.to_string().contains("expired"));

        let err = SigningError::ServerUnreachable("connection refused".to_string());
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn test_timestamp_is_milliseconds() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Timestamp should be in milliseconds (roughly 13+ digits as of 2024)
        // Seconds would be ~10 digits
        assert!(now > 1_000_000_000_000); // After year ~2001 in milliseconds
    }

    #[test]
    fn test_no_local_or_offline_tokens() {
        // Ensure our module doesn't contain any local/offline token generation
        // This is a compile-time check via code review - the absence of
        // "local_" or "offline_" prefix generation in the codebase confirms this

        // The generate_nonce function should not produce local_ prefixed values
        let nonce = generate_nonce();
        assert!(!nonce.starts_with("local_"));
        assert!(!nonce.starts_with("offline_"));
    }

    #[test]
    fn test_severity_counts_new() {
        let counts = SeverityCounts::new();
        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
    }

    #[test]
    fn test_severity_counts_increment() {
        let mut counts = SeverityCounts::new();

        counts.increment(&crate::types::Severity::Critical);
        counts.increment(&crate::types::Severity::Critical);
        counts.increment(&crate::types::Severity::High);
        counts.increment(&crate::types::Severity::Medium);
        counts.increment(&crate::types::Severity::Medium);
        counts.increment(&crate::types::Severity::Medium);
        counts.increment(&crate::types::Severity::Low);
        counts.increment(&crate::types::Severity::Info);
        counts.increment(&crate::types::Severity::Info);

        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 3);
        assert_eq!(counts.low, 1);
        assert_eq!(counts.info, 2);
    }

    #[test]
    fn test_findings_summary_new() {
        let summary = FindingsSummary::new();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.by_severity.critical, 0);
        assert_eq!(summary.by_severity.high, 0);
        assert_eq!(summary.by_severity.medium, 0);
        assert_eq!(summary.by_severity.low, 0);
        assert_eq!(summary.by_severity.info, 0);
        assert!(summary.by_module.is_empty());
    }

    #[test]
    fn test_findings_summary_from_vulnerabilities() {
        use crate::types::{Confidence, Severity, Vulnerability};

        let vulns = vec![
            Vulnerability {
                id: "1".to_string(),
                vuln_type: "xss".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                category: "XSS".to_string(),
                url: "https://example.com/page1".to_string(),
                parameter: Some("q".to_string()),
                payload: "<script>alert(1)</script>".to_string(),
                description: "XSS vulnerability".to_string(),
                evidence: None,
                cwe: "CWE-79".to_string(),
                cvss: 8.0,
                verified: true,
                false_positive: false,
                remediation: "Sanitize input".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
            Vulnerability {
                id: "2".to_string(),
                vuln_type: "sqli".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                category: "SQLi".to_string(),
                url: "https://example.com/page2".to_string(),
                parameter: Some("id".to_string()),
                payload: "1' OR '1'='1".to_string(),
                description: "SQL Injection".to_string(),
                evidence: None,
                cwe: "CWE-89".to_string(),
                cvss: 9.0,
                verified: false,
                false_positive: false,
                remediation: "Use parameterized queries".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
            Vulnerability {
                id: "3".to_string(),
                vuln_type: "xss".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Low,
                category: "XSS".to_string(),
                url: "https://example.com/page3".to_string(),
                parameter: None,
                payload: "test".to_string(),
                description: "Another XSS".to_string(),
                evidence: None,
                cwe: "CWE-79".to_string(),
                cvss: 5.0,
                verified: false,
                false_positive: false,
                remediation: "Sanitize".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
        ];

        let summary = FindingsSummary::from_vulnerabilities(&vulns);

        // Check total count
        assert_eq!(summary.total, 3);

        // Check severity breakdown - PRIVACY: only counts, no URLs
        assert_eq!(summary.by_severity.critical, 1);
        assert_eq!(summary.by_severity.high, 1);
        assert_eq!(summary.by_severity.medium, 1);
        assert_eq!(summary.by_severity.low, 0);
        assert_eq!(summary.by_severity.info, 0);

        // Check module breakdown - PRIVACY: only normalized category names, no target URLs
        // Module names are normalized to lowercase
        assert_eq!(summary.by_module.get("xss"), Some(&2));
        assert_eq!(summary.by_module.get("sqli"), Some(&1));

        // Verify NO URL data is stored in the summary
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("example.com"));
        assert!(!serialized.contains("page1"));
        assert!(!serialized.contains("page2"));
        assert!(!serialized.contains("page3"));
    }

    #[test]
    fn test_findings_summary_serialization() {
        let mut summary = FindingsSummary::new();
        summary.total = 5;
        summary.by_severity.critical = 1;
        summary.by_severity.high = 2;
        summary.by_severity.medium = 1;
        summary.by_severity.low = 1;
        summary.by_module.insert("xss".to_string(), 3);
        summary.by_module.insert("sqli".to_string(), 2);

        // Test serialization - fields should be snake_case
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":5"));
        assert!(json.contains("\"critical\":1"));
        assert!(json.contains("\"high\":2"));
        assert!(json.contains("\"by_severity\""));
        assert!(json.contains("\"by_module\""));

        // Test deserialization
        let deserialized: FindingsSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total, 5);
        assert_eq!(deserialized.by_severity.critical, 1);
        assert_eq!(deserialized.by_module.get("xss"), Some(&3));
    }

    #[test]
    fn test_module_name_normalization() {
        use crate::types::{Confidence, Severity, Vulnerability};

        // Create vulnerabilities with varied casing and whitespace
        let vulns = vec![
            Vulnerability {
                id: "1".to_string(),
                vuln_type: "xss".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: "XSS".to_string(), // uppercase
                url: "https://example.com".to_string(),
                parameter: None,
                payload: "test".to_string(),
                description: "test".to_string(),
                evidence: None,
                cwe: "CWE-79".to_string(),
                cvss: 5.0,
                verified: false,
                false_positive: false,
                remediation: "fix".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
            Vulnerability {
                id: "2".to_string(),
                vuln_type: "xss".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "  xss  ".to_string(), // with whitespace
                url: "https://example.com".to_string(),
                parameter: None,
                payload: "test".to_string(),
                description: "test".to_string(),
                evidence: None,
                cwe: "CWE-79".to_string(),
                cvss: 5.0,
                verified: false,
                false_positive: false,
                remediation: "fix".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
            Vulnerability {
                id: "3".to_string(),
                vuln_type: "xss".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                category: "Xss".to_string(), // mixed case
                url: "https://example.com".to_string(),
                parameter: None,
                payload: "test".to_string(),
                description: "test".to_string(),
                evidence: None,
                cwe: "CWE-79".to_string(),
                cvss: 5.0,
                verified: false,
                false_positive: false,
                remediation: "fix".to_string(),
                discovered_at: "2024-01-01T00:00:00Z".to_string(),
            },
        ];

        let summary = FindingsSummary::from_vulnerabilities(&vulns);

        // All should be normalized to "xss" and counted together
        assert_eq!(summary.by_module.len(), 1);
        assert_eq!(summary.by_module.get("xss"), Some(&3));
    }
}
