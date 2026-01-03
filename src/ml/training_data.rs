// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Training Data Collection
 * Collects and stores user-verified vulnerability data for ML training
 *
 * Data is stored locally in ~/.lonkero/training_data/
 * No raw vulnerability data is ever transmitted - only model weights
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::types::{Confidence, Severity, Vulnerability};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tracing::{debug, info};

/// User verification status for a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// User confirmed this is a true positive
    Confirmed,
    /// User marked this as a false positive
    FalsePositive,
    /// Not yet verified
    Unverified,
}

/// A training example derived from a vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    /// Unique ID for this example
    pub id: String,
    /// Vulnerability type (e.g., "SQL Injection", "XSS")
    pub vuln_type: String,
    /// URL pattern (anonymized - e.g., "/api/users/{id}")
    pub url_pattern: String,
    /// HTTP method used
    pub http_method: String,
    /// Response status code
    pub status_code: u16,
    /// Response length
    pub response_length: usize,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Content-Type of response
    pub content_type: Option<String>,
    /// Whether payload was reflected in response
    pub payload_reflected: bool,
    /// Whether response contained error patterns
    pub has_error_patterns: bool,
    /// Whether response differed from baseline
    pub differs_from_baseline: bool,
    /// Scanner's original severity
    pub severity: Severity,
    /// Scanner's original confidence
    pub confidence: Confidence,
    /// User verification status
    pub verification: VerificationStatus,
    /// Timestamp when collected
    pub collected_at: DateTime<Utc>,
    /// Timestamp when verified (if applicable)
    pub verified_at: Option<DateTime<Utc>>,
    /// Additional feature flags
    pub features: Vec<f32>,
}

impl TrainingExample {
    /// Create from pre-extracted features (GDPR-compliant - no raw data)
    pub fn from_features(vuln: &Vulnerability, features: &super::VulnFeatures) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: vuln.vuln_type.clone(),
            url_pattern: Self::anonymize_url(&vuln.url),
            http_method: "GET".to_string(),
            status_code: features.status_code,
            response_length: features.response_length,
            response_time_ms: features.response_time_ms,
            content_type: if features.has_json {
                Some("application/json".to_string())
            } else if features.has_html {
                Some("text/html".to_string())
            } else if features.has_xml {
                Some("application/xml".to_string())
            } else {
                None
            },
            payload_reflected: features.payload_reflected,
            has_error_patterns: features.has_sql_error || features.has_stack_trace,
            differs_from_baseline: features.differs_from_baseline,
            severity: vuln.severity.clone(),
            confidence: vuln.confidence.clone(),
            verification: VerificationStatus::Unverified,
            collected_at: Utc::now(),
            verified_at: None,
            features: features.to_vector(),
        }
    }

    /// Create from a vulnerability and response metadata
    pub fn from_vulnerability(
        vuln: &Vulnerability,
        status_code: u16,
        response_length: usize,
        response_time_ms: u64,
        content_type: Option<String>,
        payload_reflected: bool,
        has_error_patterns: bool,
        differs_from_baseline: bool,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vuln_type: vuln.vuln_type.clone(),
            url_pattern: Self::anonymize_url(&vuln.url),
            http_method: "GET".to_string(), // Default, can be overridden
            status_code,
            response_length,
            response_time_ms,
            content_type,
            payload_reflected,
            has_error_patterns,
            differs_from_baseline,
            severity: vuln.severity.clone(),
            confidence: vuln.confidence.clone(),
            verification: VerificationStatus::Unverified,
            collected_at: Utc::now(),
            verified_at: None,
            features: Vec::new(),
        }
    }

    /// Anonymize URL to remove sensitive data but keep structure
    /// e.g., "https://example.com/api/users/12345" -> "/api/users/{id}"
    fn anonymize_url(url: &str) -> String {
        // Parse URL and extract path
        let path = url::Url::parse(url)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| url.to_string());

        // Replace numeric IDs with {id}
        let id_pattern = regex::Regex::new(r"/\d+").unwrap();
        let anonymized = id_pattern.replace_all(&path, "/{id}");

        // Replace UUIDs with {uuid}
        let uuid_pattern =
            regex::Regex::new(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                .unwrap();
        let anonymized = uuid_pattern.replace_all(&anonymized, "/{uuid}");

        // Replace email-like patterns
        let email_pattern = regex::Regex::new(r"[^/]+@[^/]+\.[^/]+").unwrap();
        let anonymized = email_pattern.replace_all(&anonymized, "{email}");

        anonymized.to_string()
    }

    /// Convert to feature vector for ML training
    pub fn to_feature_vector(&self) -> Vec<f32> {
        let mut features = vec![
            self.status_code as f32 / 600.0,            // Normalize to 0-1
            (self.response_length as f32).ln() / 20.0,  // Log-scale normalize
            (self.response_time_ms as f32).ln() / 10.0, // Log-scale normalize
            if self.payload_reflected { 1.0 } else { 0.0 },
            if self.has_error_patterns { 1.0 } else { 0.0 },
            if self.differs_from_baseline { 1.0 } else { 0.0 },
            self.severity_to_float(),
            self.confidence_to_float(),
        ];

        // Add vuln type one-hot encoding (top 20 types)
        features.extend(self.vuln_type_encoding());

        features
    }

    fn severity_to_float(&self) -> f32 {
        match self.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.75,
            Severity::Medium => 0.5,
            Severity::Low => 0.25,
            Severity::Info => 0.0,
        }
    }

    fn confidence_to_float(&self) -> f32 {
        match self.confidence {
            Confidence::High => 1.0,
            Confidence::Medium => 0.5,
            Confidence::Low => 0.25,
        }
    }

    fn vuln_type_encoding(&self) -> Vec<f32> {
        // Top 20 vulnerability types for one-hot encoding
        let vuln_types = [
            "SQL Injection",
            "XSS",
            "CSRF",
            "SSRF",
            "XXE",
            "Command Injection",
            "Path Traversal",
            "IDOR",
            "Auth Bypass",
            "JWT",
            "NoSQL Injection",
            "CORS",
            "Open Redirect",
            "File Upload",
            "Deserialization",
            "SSTI",
            "Prototype Pollution",
            "Race Condition",
            "BOLA",
            "Information Disclosure",
        ];

        vuln_types
            .iter()
            .map(|vt| {
                if self.vuln_type.to_uppercase().contains(&vt.to_uppercase()) {
                    1.0
                } else {
                    0.0
                }
            })
            .collect()
    }

    /// Get label for supervised learning (1.0 = true positive, 0.0 = false positive)
    pub fn get_label(&self) -> Option<f32> {
        match self.verification {
            VerificationStatus::Confirmed => Some(1.0),
            VerificationStatus::FalsePositive => Some(0.0),
            VerificationStatus::Unverified => None,
        }
    }
}

/// Training data collector - manages local storage of training examples
pub struct TrainingDataCollector {
    /// Path to training data directory
    data_dir: PathBuf,
    /// Path to confirmed vulnerabilities file
    confirmed_file: PathBuf,
    /// Path to false positives file
    fp_file: PathBuf,
    /// Path to unverified findings file
    unverified_file: PathBuf,
}

impl TrainingDataCollector {
    /// Create new collector with default paths
    pub fn new() -> Result<Self> {
        let data_dir = Self::get_data_dir()?;
        fs::create_dir_all(&data_dir).context("Failed to create training data directory")?;

        Ok(Self {
            confirmed_file: data_dir.join("confirmed_vulns.jsonl"),
            fp_file: data_dir.join("false_positives.jsonl"),
            unverified_file: data_dir.join("unverified.jsonl"),
            data_dir,
        })
    }

    /// Get the training data directory path
    fn get_data_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".lonkero").join("training_data"))
    }

    /// Record a new training example (initially unverified)
    pub fn record_example(&self, example: &TrainingExample) -> Result<()> {
        self.append_to_file(&self.unverified_file, example)?;
        debug!(
            "Recorded training example: {} - {}",
            example.id, example.vuln_type
        );
        Ok(())
    }

    /// Mark an example as confirmed true positive
    pub fn confirm_vulnerability(&self, vuln_id: &str) -> Result<bool> {
        self.move_and_update_verification(
            vuln_id,
            VerificationStatus::Confirmed,
            &self.confirmed_file,
        )
    }

    /// Mark an example as false positive
    pub fn mark_false_positive(&self, vuln_id: &str) -> Result<bool> {
        self.move_and_update_verification(vuln_id, VerificationStatus::FalsePositive, &self.fp_file)
    }

    /// Move example from unverified to target file with updated status
    fn move_and_update_verification(
        &self,
        vuln_id: &str,
        status: VerificationStatus,
        target_file: &PathBuf,
    ) -> Result<bool> {
        // Read all unverified examples
        let examples = self.read_file(&self.unverified_file)?;

        // Find and update the matching example
        let mut found = false;
        let mut remaining = Vec::new();

        for mut example in examples {
            if example.id == vuln_id {
                example.verification = status;
                example.verified_at = Some(Utc::now());
                self.append_to_file(target_file, &example)?;
                found = true;
                info!("Marked vulnerability {} as {:?}", vuln_id, status);
            } else {
                remaining.push(example);
            }
        }

        // Rewrite unverified file without the moved example
        if found {
            self.write_file(&self.unverified_file, &remaining)?;
        }

        Ok(found)
    }

    /// Append an example to a JSONL file
    fn append_to_file(&self, path: &PathBuf, example: &TrainingExample) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .context("Failed to open training data file")?;

        let json = serde_json::to_string(example)?;
        writeln!(file, "{}", json)?;
        Ok(())
    }

    /// Read all examples from a JSONL file
    fn read_file(&self, path: &PathBuf) -> Result<Vec<TrainingExample>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut examples = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                match serde_json::from_str(&line) {
                    Ok(example) => examples.push(example),
                    Err(e) => debug!("Skipping malformed line: {}", e),
                }
            }
        }

        Ok(examples)
    }

    /// Write examples to a file (overwrites)
    fn write_file(&self, path: &PathBuf, examples: &[TrainingExample]) -> Result<()> {
        let mut file = File::create(path)?;
        for example in examples {
            let json = serde_json::to_string(example)?;
            writeln!(file, "{}", json)?;
        }
        Ok(())
    }

    /// Get all confirmed true positives
    pub fn get_confirmed(&self) -> Result<Vec<TrainingExample>> {
        self.read_file(&self.confirmed_file)
    }

    /// Get all false positives
    pub fn get_false_positives(&self) -> Result<Vec<TrainingExample>> {
        self.read_file(&self.fp_file)
    }

    /// Get all unverified examples
    pub fn get_unverified(&self) -> Result<Vec<TrainingExample>> {
        self.read_file(&self.unverified_file)
    }

    /// Get all verified examples (for training)
    pub fn get_training_data(&self) -> Result<Vec<TrainingExample>> {
        let mut data = self.get_confirmed()?;
        data.extend(self.get_false_positives()?);
        Ok(data)
    }

    /// Get training statistics
    pub fn get_stats(&self) -> Result<TrainingStats> {
        Ok(TrainingStats {
            confirmed_count: self.get_confirmed()?.len(),
            false_positive_count: self.get_false_positives()?.len(),
            unverified_count: self.get_unverified()?.len(),
            data_dir: self.data_dir.clone(),
        })
    }

    /// Export training data for federated learning (anonymized features only)
    pub fn export_for_federated(&self) -> Result<FederatedTrainingData> {
        let examples = self.get_training_data()?;

        let features: Vec<Vec<f32>> = examples.iter().map(|e| e.to_feature_vector()).collect();

        let labels: Vec<f32> = examples.iter().filter_map(|e| e.get_label()).collect();

        Ok(FederatedTrainingData {
            features,
            labels,
            example_count: examples.len(),
        })
    }
}

impl Default for TrainingDataCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create training data collector")
    }
}

/// Statistics about collected training data
#[derive(Debug, Default)]
pub struct TrainingStats {
    pub confirmed_count: usize,
    pub false_positive_count: usize,
    pub unverified_count: usize,
    #[allow(dead_code)]
    pub data_dir: PathBuf,
}

impl TrainingStats {
    pub fn total_verified(&self) -> usize {
        self.confirmed_count + self.false_positive_count
    }

    pub fn is_ready_for_training(&self) -> bool {
        // Need at least 50 examples of each class
        self.confirmed_count >= 50 && self.false_positive_count >= 50
    }
}

/// Anonymized training data for federated learning
#[derive(Debug, Serialize, Deserialize)]
pub struct FederatedTrainingData {
    pub features: Vec<Vec<f32>>,
    pub labels: Vec<f32>,
    pub example_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_anonymization() {
        assert_eq!(
            TrainingExample::anonymize_url("https://example.com/api/users/12345"),
            "/api/users/{id}"
        );

        assert_eq!(
            TrainingExample::anonymize_url(
                "https://example.com/api/items/550e8400-e29b-41d4-a716-446655440000"
            ),
            "/api/items/{uuid}"
        );
    }

    #[test]
    fn test_feature_vector_length() {
        let example = TrainingExample {
            id: "test".to_string(),
            vuln_type: "SQL Injection".to_string(),
            url_pattern: "/api/test".to_string(),
            http_method: "GET".to_string(),
            status_code: 200,
            response_length: 1000,
            response_time_ms: 100,
            content_type: Some("text/html".to_string()),
            payload_reflected: true,
            has_error_patterns: false,
            differs_from_baseline: true,
            severity: Severity::High,
            confidence: Confidence::High,
            verification: VerificationStatus::Confirmed,
            collected_at: Utc::now(),
            verified_at: None,
            features: Vec::new(),
        };

        let features = example.to_feature_vector();
        assert_eq!(features.len(), 28); // 8 base features + 20 vuln type one-hot
    }
}
