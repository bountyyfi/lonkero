// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GDPR Privacy Compliance Module
 * Ensures all ML operations comply with GDPR and data protection regulations
 *
 * GDPR Compliance Guarantees:
 * ==========================
 *
 * 1. DATA MINIMIZATION (Article 5(1)(c)):
 *    - Only anonymized features are extracted
 *    - No raw request/response data is stored
 *    - No URLs, hostnames, or IP addresses in training data
 *    - All identifiers are hashed or replaced with patterns
 *
 * 2. PURPOSE LIMITATION (Article 5(1)(b)):
 *    - Data used only for improving vulnerability detection
 *    - No secondary uses, no profiling, no targeting
 *
 * 3. STORAGE LIMITATION (Article 5(1)(e)):
 *    - Automatic data retention with configurable expiry
 *    - Default: 90 days for training data
 *    - User can delete all data at any time
 *
 * 4. DATA SUBJECT RIGHTS:
 *    - Right to erasure: delete_all_data()
 *    - Right to access: export_personal_data()
 *    - Right to opt-out: disable_ml()
 *
 * 5. FEDERATED LEARNING PRIVACY:
 *    - Only model WEIGHTS are shared (not training data)
 *    - Differential privacy noise applied before sharing
 *    - Cannot reconstruct individual findings from weights
 *    - Anonymous client IDs (not linked to user identity)
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// GDPR Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprCompliance {
    /// User has been informed about data collection
    pub informed_consent: bool,
    /// User has explicitly opted in to federated learning
    pub federated_opt_in: bool,
    /// Date of consent
    pub consent_date: Option<DateTime<Utc>>,
    /// Data retention policy
    pub retention_policy: DataRetentionPolicy,
    /// Last data cleanup timestamp
    pub last_cleanup: Option<DateTime<Utc>>,
}

impl Default for GdprCompliance {
    fn default() -> Self {
        Self {
            informed_consent: false,
            federated_opt_in: false,
            consent_date: None,
            retention_policy: DataRetentionPolicy::default(),
            last_cleanup: None,
        }
    }
}

/// Data retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRetentionPolicy {
    /// Maximum days to keep training data
    pub max_age_days: u32,
    /// Maximum number of training examples to store
    pub max_examples: usize,
    /// Whether to auto-delete expired data
    pub auto_cleanup: bool,
}

impl Default for DataRetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: 90,  // GDPR recommends minimal retention
            max_examples: 10000,
            auto_cleanup: true,
        }
    }
}

/// Privacy manager for GDPR-compliant ML operations
pub struct PrivacyManager {
    /// Path to privacy settings
    settings_path: PathBuf,
    /// Current compliance status
    compliance: GdprCompliance,
    /// Data directory for ML storage
    data_dir: PathBuf,
}

impl PrivacyManager {
    /// Create new privacy manager
    pub fn new() -> Result<Self> {
        let data_dir = Self::get_data_dir()?;
        fs::create_dir_all(&data_dir)?;

        let settings_path = data_dir.join("privacy_settings.json");
        let compliance = Self::load_or_create_settings(&settings_path)?;

        let mut manager = Self {
            settings_path,
            compliance,
            data_dir,
        };

        // Run auto-cleanup if enabled
        if manager.compliance.retention_policy.auto_cleanup {
            manager.cleanup_expired_data()?;
        }

        Ok(manager)
    }

    /// Get data directory
    fn get_data_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Could not determine home directory")?;
        Ok(home.join(".lonkero"))
    }

    /// Load or create privacy settings
    fn load_or_create_settings(path: &PathBuf) -> Result<GdprCompliance> {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(GdprCompliance::default())
        }
    }

    /// Save privacy settings
    fn save_settings(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.compliance)?;
        fs::write(&self.settings_path, json)?;
        Ok(())
    }

    /// Record user consent for ML features
    /// This MUST be called before any data collection
    pub fn record_consent(&mut self, federated_opt_in: bool) -> Result<()> {
        self.compliance.informed_consent = true;
        self.compliance.federated_opt_in = federated_opt_in;
        self.compliance.consent_date = Some(Utc::now());
        self.save_settings()?;

        info!("GDPR consent recorded: informed={}, federated={}",
              self.compliance.informed_consent,
              self.compliance.federated_opt_in);

        Ok(())
    }

    /// Withdraw consent and delete all data (Right to be forgotten)
    pub fn withdraw_consent(&mut self) -> Result<()> {
        warn!("User withdrawing consent - deleting all ML data");

        self.delete_all_data()?;

        self.compliance = GdprCompliance::default();
        self.save_settings()?;

        info!("Consent withdrawn and all data deleted");
        Ok(())
    }

    /// Check if ML features are allowed
    pub fn is_ml_allowed(&self) -> bool {
        self.compliance.informed_consent
    }

    /// Check if federated learning is allowed
    pub fn is_federated_allowed(&self) -> bool {
        self.compliance.informed_consent && self.compliance.federated_opt_in
    }

    /// Delete all ML-related data (Right to erasure - Article 17)
    pub fn delete_all_data(&self) -> Result<()> {
        let paths = [
            self.data_dir.join("training_data"),
            self.data_dir.join("models"),
            self.data_dir.join("federated"),
        ];

        for path in &paths {
            if path.exists() {
                fs::remove_dir_all(path)
                    .context(format!("Failed to delete {}", path.display()))?;
                debug!("Deleted: {}", path.display());
            }
        }

        info!("All ML data deleted (GDPR Article 17 - Right to erasure)");
        Ok(())
    }

    /// Export all personal data (Right to access - Article 15)
    pub fn export_personal_data(&self) -> Result<PersonalDataExport> {
        let training_data = self.data_dir.join("training_data");
        let federated = self.data_dir.join("federated");

        let mut export = PersonalDataExport {
            export_date: Utc::now(),
            consent_info: self.compliance.clone(),
            training_examples: Vec::new(),
            client_id: None,
            pending_contributions: 0,
        };

        // Export training data files
        if training_data.exists() {
            for entry in fs::read_dir(&training_data)? {
                let entry = entry?;
                if entry.path().extension().map(|e| e == "jsonl").unwrap_or(false) {
                    let content = fs::read_to_string(entry.path())?;
                    for line in content.lines() {
                        if !line.trim().is_empty() {
                            export.training_examples.push(line.to_string());
                        }
                    }
                }
            }
        }

        // Export federated client ID
        let client_id_path = federated.join("client_id");
        if client_id_path.exists() {
            export.client_id = Some(fs::read_to_string(client_id_path)?);
        }

        // Count pending contributions
        let pending_dir = federated.join("pending");
        if pending_dir.exists() {
            export.pending_contributions = fs::read_dir(&pending_dir)?.count();
        }

        info!("Exported personal data (GDPR Article 15 - Right to access)");
        Ok(export)
    }

    /// Update retention policy
    pub fn set_retention_policy(&mut self, policy: DataRetentionPolicy) -> Result<()> {
        self.compliance.retention_policy = policy;
        self.save_settings()?;

        // Run cleanup with new policy
        if self.compliance.retention_policy.auto_cleanup {
            self.cleanup_expired_data()?;
        }

        Ok(())
    }

    /// Clean up expired data according to retention policy
    pub fn cleanup_expired_data(&mut self) -> Result<CleanupResult> {
        let max_age = Duration::days(self.compliance.retention_policy.max_age_days as i64);
        let cutoff = Utc::now() - max_age;

        let mut result = CleanupResult::default();

        // Cleanup training data
        let training_paths = [
            self.data_dir.join("training_data/confirmed_vulns.jsonl"),
            self.data_dir.join("training_data/false_positives.jsonl"),
            self.data_dir.join("training_data/unverified.jsonl"),
        ];

        for path in &training_paths {
            if path.exists() {
                result.files_processed += 1;
                let cleaned = self.cleanup_jsonl_file(path, cutoff)?;
                result.records_deleted += cleaned;
            }
        }

        // Cleanup pending federated contributions
        let pending_dir = self.data_dir.join("federated/pending");
        if pending_dir.exists() {
            for entry in fs::read_dir(&pending_dir)? {
                let entry = entry?;
                let metadata = entry.metadata()?;
                if let Ok(modified) = metadata.modified() {
                    let modified: DateTime<Utc> = modified.into();
                    if modified < cutoff {
                        fs::remove_file(entry.path())?;
                        result.records_deleted += 1;
                    }
                }
            }
        }

        self.compliance.last_cleanup = Some(Utc::now());
        self.save_settings()?;

        if result.records_deleted > 0 {
            info!("GDPR cleanup: deleted {} expired records from {} files",
                  result.records_deleted, result.files_processed);
        }

        Ok(result)
    }

    /// Clean up a JSONL file, removing entries older than cutoff
    fn cleanup_jsonl_file(&self, path: &PathBuf, cutoff: DateTime<Utc>) -> Result<usize> {
        let content = fs::read_to_string(path)?;
        let mut kept = Vec::new();
        let mut deleted = 0;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Parse to check timestamp
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(timestamp) = json.get("collected_at")
                    .and_then(|v| v.as_str())
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                {
                    if timestamp.with_timezone(&Utc) >= cutoff {
                        kept.push(line.to_string());
                        continue;
                    }
                }
            }
            deleted += 1;
        }

        // Rewrite file with only kept records
        fs::write(path, kept.join("\n") + "\n")?;

        Ok(deleted)
    }

    /// Anonymize a value for GDPR compliance
    /// Used to ensure no personal data in training examples
    pub fn anonymize_value(value: &str) -> String {
        // Hash emails
        if value.contains('@') {
            return "{email}".to_string();
        }

        // Hash IP addresses
        if Self::is_ip_address(value) {
            return "{ip}".to_string();
        }

        // Hash hostnames
        if Self::looks_like_hostname(value) {
            return "{host}".to_string();
        }

        // Hash long numeric IDs
        if value.chars().all(|c| c.is_ascii_digit()) && value.len() > 6 {
            return "{id}".to_string();
        }

        // Hash UUIDs
        if Self::is_uuid(value) {
            return "{uuid}".to_string();
        }

        value.to_string()
    }

    fn is_ip_address(value: &str) -> bool {
        // IPv4
        if value.parse::<std::net::Ipv4Addr>().is_ok() {
            return true;
        }
        // IPv6
        if value.parse::<std::net::Ipv6Addr>().is_ok() {
            return true;
        }
        false
    }

    fn looks_like_hostname(value: &str) -> bool {
        value.contains('.') &&
        !value.starts_with('/') &&
        value.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    }

    fn is_uuid(value: &str) -> bool {
        let parts: Vec<&str> = value.split('-').collect();
        parts.len() == 5 &&
        parts[0].len() == 8 &&
        parts[1].len() == 4 &&
        parts[2].len() == 4 &&
        parts[3].len() == 4 &&
        parts[4].len() == 12 &&
        parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
    }

    /// Get privacy status summary
    pub fn get_status(&self) -> PrivacyStatus {
        PrivacyStatus {
            ml_enabled: self.is_ml_allowed(),
            federated_enabled: self.is_federated_allowed(),
            consent_date: self.compliance.consent_date,
            retention_days: self.compliance.retention_policy.max_age_days,
            last_cleanup: self.compliance.last_cleanup,
            data_dir: self.data_dir.clone(),
        }
    }
}

impl Default for PrivacyManager {
    fn default() -> Self {
        Self::new().expect("Failed to create privacy manager")
    }
}

/// Exported personal data structure
#[derive(Debug, Serialize)]
pub struct PersonalDataExport {
    pub export_date: DateTime<Utc>,
    pub consent_info: GdprCompliance,
    pub training_examples: Vec<String>,
    pub client_id: Option<String>,
    pub pending_contributions: usize,
}

/// Cleanup result
#[derive(Debug, Default)]
pub struct CleanupResult {
    pub files_processed: usize,
    pub records_deleted: usize,
}

/// Privacy status summary
#[derive(Debug)]
pub struct PrivacyStatus {
    pub ml_enabled: bool,
    pub federated_enabled: bool,
    pub consent_date: Option<DateTime<Utc>>,
    pub retention_days: u32,
    pub last_cleanup: Option<DateTime<Utc>>,
    pub data_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_email() {
        assert_eq!(PrivacyManager::anonymize_value("user@example.com"), "{email}");
    }

    #[test]
    fn test_anonymize_ip() {
        assert_eq!(PrivacyManager::anonymize_value("192.168.1.1"), "{ip}");
        assert_eq!(PrivacyManager::anonymize_value("::1"), "{ip}");
    }

    #[test]
    fn test_anonymize_uuid() {
        assert_eq!(
            PrivacyManager::anonymize_value("550e8400-e29b-41d4-a716-446655440000"),
            "{uuid}"
        );
    }

    #[test]
    fn test_anonymize_long_id() {
        assert_eq!(PrivacyManager::anonymize_value("123456789"), "{id}");
    }

    #[test]
    fn test_preserve_short_values() {
        assert_eq!(PrivacyManager::anonymize_value("GET"), "GET");
        assert_eq!(PrivacyManager::anonymize_value("200"), "200");
    }
}
