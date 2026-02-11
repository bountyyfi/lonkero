// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Model Distribution Client
 * One-way model distribution: download detection model from server
 *
 * How it works:
 * 1. Server trains and aggregates the detection model
 * 2. CLI downloads the latest model (requires valid license)
 * 3. Model weights are applied locally for vulnerability scoring
 * 4. Downloaded model is cached locally for offline use
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Model weights used for vulnerability scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelWeights {
    /// Unique identifier for this model version
    pub model_id: String,
    /// Version number for compatibility checking
    pub version: u32,
    /// The actual weight parameters (feature_name -> weight value)
    pub weights: HashMap<String, f64>,
    /// Bias term for the model
    pub bias: f64,
    /// Number of training examples this model was trained on
    pub training_count: usize,
    /// Timestamp when these weights were generated
    pub timestamp: i64,
    /// Hash of the training data schema (for compatibility)
    pub schema_hash: String,
}

impl ModelWeights {
    /// Create new weights from a trained model
    pub fn new(weights: HashMap<String, f64>, bias: f64, training_count: usize) -> Self {
        Self {
            model_id: uuid::Uuid::new_v4().to_string(),
            version: 1,
            weights,
            bias,
            training_count,
            timestamp: chrono::Utc::now().timestamp(),
            schema_hash: Self::compute_schema_hash(),
        }
    }

    /// Compute schema hash to ensure weight compatibility
    fn compute_schema_hash() -> String {
        // Feature names in order - must match between clients
        let features = [
            "status_code",
            "response_length",
            "response_time",
            "payload_reflected",
            "has_error_patterns",
            "differs_from_baseline",
            "severity",
            "confidence",
            // Vuln type one-hot (20 types)
            "sql_injection",
            "xss",
            "csrf",
            "ssrf",
            "xxe",
            "command_injection",
            "path_traversal",
            "idor",
            "auth_bypass",
            "jwt",
            "nosql_injection",
            "cors",
            "open_redirect",
            "file_upload",
            "deserialization",
            "ssti",
            "prototype_pollution",
            "race_condition",
            "bola",
            "info_disclosure",
        ];

        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        features.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Check if these weights are compatible with current schema
    pub fn is_compatible(&self) -> bool {
        self.schema_hash == Self::compute_schema_hash()
    }
}

/// Aggregated model from the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedModel {
    /// Global model version
    pub global_version: u32,
    /// Aggregated weights
    pub weights: ModelWeights,
    /// Number of contributors to this aggregation
    pub contributor_count: usize,
    /// Total training examples across all contributors
    pub total_training_examples: usize,
    /// Server signature
    pub server_signature: String,
}

/// Detection model category information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCategory {
    pub name: String,
    pub feature_count: usize,
    pub description: Option<String>,
}

/// Model distribution client (download-only, no contribution)
pub struct FederatedClient {
    /// API endpoint for model server
    server_url: String,
    /// Latest fetched global model
    global_model: Option<AggregatedModel>,
    /// License key for authenticated model downloads
    license_key: Option<String>,
}

impl FederatedClient {
    /// Create new model distribution client
    pub fn new() -> Result<Self> {
        let data_dir = Self::get_data_dir()?;
        fs::create_dir_all(&data_dir)?;

        Ok(Self {
            server_url: "https://lonkero.bountyy.fi/api/federated/v1".to_string(),
            global_model: None,
            license_key: None,
        })
    }

    /// Set the license key for authenticated model downloads
    pub fn set_license_key(&mut self, key: String) {
        self.license_key = Some(key);
    }

    /// Load license key from all available sources: env var > OS keychain > legacy config file.
    /// This ensures enterprise users who activated via `lonkero license activate` can download
    /// detection models without needing to set the LONKERO_LICENSE_KEY env var.
    pub fn load_license_key(&mut self) {
        // 1. Environment variable (highest priority)
        if let Ok(key) = std::env::var("LONKERO_LICENSE_KEY") {
            if !key.is_empty() {
                self.license_key = Some(key);
                return;
            }
        }

        // 2. OS keychain (secure storage, set by `lonkero license activate`)
        if let Ok(entry) = keyring::Entry::new("lonkero", "license_key") {
            if let Ok(key) = entry.get_password() {
                if !key.is_empty() {
                    debug!("ML: License key loaded from OS keychain");
                    self.license_key = Some(key);
                    return;
                }
            }
        }

        // 3. Legacy plaintext config file (fallback for migration)
        if let Some(config_dir) = dirs::config_dir() {
            let license_file = config_dir.join("lonkero").join("license.key");
            if license_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&license_file) {
                    let key = content.trim().to_string();
                    if !key.is_empty() {
                        debug!("ML: License key loaded from legacy config file");
                        self.license_key = Some(key);
                    }
                }
            }
        }
    }

    /// Get data directory
    fn get_data_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".lonkero").join("federated"))
    }

    /// Fetch latest global model from server (publicly available to all users)
    pub async fn fetch_global_model(&mut self) -> Result<Option<AggregatedModel>> {
        info!("Fetching detection model from server...");

        let client = reqwest::Client::new();
        let request = client
            .get(format!("{}/model/latest", self.server_url))
            .timeout(std::time::Duration::from_secs(30));

        // ML models are now publicly available - no license required
        // This enables all users to benefit from ML-enhanced vulnerability detection

        let response = request.send().await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let model: AggregatedModel = resp.json().await?;
                info!(
                    "Fetched detection model v{} ({} contributors, {} examples)",
                    model.global_version, model.contributor_count, model.total_training_examples
                );

                // Verify compatibility
                if !model.weights.is_compatible() {
                    warn!("Detection model has incompatible schema, skipping");
                    return Ok(None);
                }

                self.global_model = Some(model.clone());
                self.save_global_model(&model)?;
                Ok(Some(model))
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                // This shouldn't happen since models are public, but handle it gracefully
                warn!("Model download returned 401 - server configuration issue");
                warn!("Please contact support at info@bountyy.fi");
                // Try loading cached model as fallback
                Ok(self.load_cached_global_model()?)
            }
            Ok(resp) => {
                debug!("No detection model available: {}", resp.status());
                // Try loading cached model
                Ok(self.load_cached_global_model()?)
            }
            Err(e) => {
                debug!("Could not reach server: {}", e);
                // Try loading cached model
                Ok(self.load_cached_global_model()?)
            }
        }
    }

    /// Fetch available detection categories (public, no auth required)
    pub async fn fetch_categories(&self) -> Result<Vec<ModelCategory>> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/model/categories", self.server_url))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let categories: Vec<ModelCategory> = resp.json().await?;
                info!("Fetched {} detection categories", categories.len());
                Ok(categories)
            }
            Ok(resp) => {
                debug!("Could not fetch categories: {}", resp.status());
                Ok(Vec::new())
            }
            Err(e) => {
                debug!("Could not reach server for categories: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Get the current global model (if any)
    pub fn get_model(&self) -> Option<&AggregatedModel> {
        self.global_model.as_ref()
    }

    /// Save global model to cache
    fn save_global_model(&self, model: &AggregatedModel) -> Result<()> {
        let path = Self::get_data_dir()?.join("global_model.json");
        let json = serde_json::to_string_pretty(model)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load cached global model
    fn load_cached_global_model(&self) -> Result<Option<AggregatedModel>> {
        let path = Self::get_data_dir()?.join("global_model.json");
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let model: AggregatedModel = serde_json::from_str(&content)?;
            debug!("Loaded cached detection model v{}", model.global_version);
            Ok(Some(model))
        } else {
            Ok(None)
        }
    }

    /// Load cached model from disk without network. Fast path for scan start.
    /// This is a static method - no client instance needed.
    pub fn load_cached_model() -> Result<AggregatedModel> {
        let path = Self::get_data_dir()?.join("global_model.json");
        let content = fs::read_to_string(&path)
            .context("No cached model found at ~/.lonkero/federated/global_model.json")?;
        let model: AggregatedModel = serde_json::from_str(&content)
            .context("Failed to parse cached model")?;
        info!("Loaded cached detection model v{}", model.global_version);
        Ok(model)
    }

    /// Fetch model and cache it. Convenience method for auto-download.
    pub async fn fetch_and_cache_model(&mut self) -> Result<AggregatedModel> {
        match self.fetch_global_model().await? {
            Some(model) => Ok(model),
            None => Err(anyhow::anyhow!("No model available from server")),
        }
    }

    /// Get client statistics
    pub fn get_stats(&self) -> FederatedStats {
        FederatedStats {
            has_global_model: self.global_model.is_some(),
            global_version: self.global_model.as_ref().map(|m| m.global_version),
            global_contributors: self.global_model.as_ref().map(|m| m.contributor_count),
        }
    }
}

impl Default for FederatedClient {
    fn default() -> Self {
        Self::new().expect("Failed to create model distribution client")
    }
}

/// Model distribution statistics
#[derive(Debug)]
pub struct FederatedStats {
    pub has_global_model: bool,
    pub global_version: Option<u32>,
    pub global_contributors: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_compatibility() {
        let weights = ModelWeights::new(HashMap::new(), 0.0, 50);
        assert!(weights.is_compatible());
    }

    #[test]
    fn test_model_weights_creation() {
        let weights = ModelWeights::new(
            [("feature1".to_string(), 0.8)].into_iter().collect(),
            -0.42,
            100,
        );
        assert_eq!(weights.bias, -0.42);
        assert_eq!(weights.training_count, 100);
        assert!(weights.weights.contains_key("feature1"));
    }

    #[test]
    fn test_federated_client_creation() {
        let client = FederatedClient::new();
        assert!(client.is_ok());
        let client = client.unwrap();
        assert!(client.global_model.is_none());
        assert!(client.license_key.is_none());
    }

    #[test]
    fn test_set_license_key() {
        let mut client = FederatedClient::new().unwrap();
        client.set_license_key("test-key-123".to_string());
        assert_eq!(client.license_key.as_deref(), Some("test-key-123"));
    }

    #[test]
    fn test_stats_no_model() {
        let client = FederatedClient::new().unwrap();
        let stats = client.get_stats();
        assert!(!stats.has_global_model);
        assert!(stats.global_version.is_none());
        assert!(stats.global_contributors.is_none());
    }
}
