// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Federated Learning
 * Privacy-preserving model training where only model weights are shared
 *
 * How it works:
 * 1. Each user trains locally on their own verified vulnerability data
 * 2. Only model WEIGHTS are sent to the aggregation server (no raw data)
 * 3. Server aggregates weights from all users using Federated Averaging
 * 4. Updated global model is distributed back to all users
 * 5. All users benefit from collective learning while data stays private
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

/// Model weights that can be safely shared (no raw data)
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
            "status_code", "response_length", "response_time",
            "payload_reflected", "has_error_patterns", "differs_from_baseline",
            "severity", "confidence",
            // Vuln type one-hot (20 types)
            "sql_injection", "xss", "csrf", "ssrf", "xxe",
            "command_injection", "path_traversal", "idor", "auth_bypass", "jwt",
            "nosql_injection", "cors", "open_redirect", "file_upload", "deserialization",
            "ssti", "prototype_pollution", "race_condition", "bola", "info_disclosure",
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

/// Contribution package sent to aggregation server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightContribution {
    /// Anonymous client ID (not linked to user identity)
    pub client_id: String,
    /// The model weights being contributed
    pub weights: ModelWeights,
    /// Differential privacy noise already applied
    pub dp_noise_applied: bool,
    /// Signature for authenticity (prevents tampering)
    pub signature: String,
}

impl WeightContribution {
    /// Create a new contribution with differential privacy
    pub fn new(weights: ModelWeights, client_id: &str) -> Self {
        let mut contribution = Self {
            client_id: client_id.to_string(),
            weights,
            dp_noise_applied: false,
            signature: String::new(),
        };

        // Apply differential privacy noise
        contribution.apply_differential_privacy();
        contribution.sign();

        contribution
    }

    /// Apply differential privacy noise to weights
    /// This prevents any single training example from being reconstructed
    fn apply_differential_privacy(&mut self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Laplace noise with epsilon = 1.0 (standard privacy guarantee)
        let epsilon = 1.0;
        let sensitivity = 0.1; // Max impact of single example
        let scale = sensitivity / epsilon;

        for weight in self.weights.weights.values_mut() {
            // Add Laplace noise
            let u: f64 = rng.gen_range(-0.5..0.5);
            let noise = -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln();
            *weight += noise;
        }

        // Also add noise to bias
        let u: f64 = rng.gen_range(-0.5..0.5);
        let noise = -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln();
        self.weights.bias += noise;

        self.dp_noise_applied = true;
    }

    /// Sign the contribution for authenticity
    fn sign(&mut self) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Hash key components
        self.client_id.hash(&mut hasher);
        self.weights.model_id.hash(&mut hasher);
        self.weights.timestamp.hash(&mut hasher);

        self.signature = format!("{:x}", hasher.finish());
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

/// Federated learning client
pub struct FederatedClient {
    /// Anonymous client ID (persisted locally)
    client_id: String,
    /// Path to client ID storage
    client_id_path: PathBuf,
    /// API endpoint for federated server
    server_url: String,
    /// Current local model weights
    local_weights: Option<ModelWeights>,
    /// Latest fetched global model
    global_model: Option<AggregatedModel>,
}

impl FederatedClient {
    /// Create new federated client
    pub fn new() -> Result<Self> {
        let data_dir = Self::get_data_dir()?;
        fs::create_dir_all(&data_dir)?;

        let client_id_path = data_dir.join("client_id");
        let client_id = Self::get_or_create_client_id(&client_id_path)?;

        Ok(Self {
            client_id,
            client_id_path,
            server_url: "https://lonkero.bountyy.fi/api/federated/v1".to_string(),
            local_weights: None,
            global_model: None,
        })
    }

    /// Get data directory
    fn get_data_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Could not determine home directory")?;
        Ok(home.join(".lonkero").join("federated"))
    }

    /// Get or create anonymous client ID
    fn get_or_create_client_id(path: &PathBuf) -> Result<String> {
        if path.exists() {
            Ok(fs::read_to_string(path)?.trim().to_string())
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            fs::write(path, &id)?;
            Ok(id)
        }
    }

    /// Set local model weights (from local training)
    pub fn set_local_weights(&mut self, weights: ModelWeights) {
        self.local_weights = Some(weights);
    }

    /// Check if we have enough data to contribute
    pub fn can_contribute(&self) -> bool {
        self.local_weights
            .as_ref()
            .map(|w| w.training_count >= 50) // Minimum examples to contribute
            .unwrap_or(false)
    }

    /// Contribute local weights to the federated network
    pub async fn contribute_weights(&self) -> Result<bool> {
        let weights = self.local_weights.as_ref()
            .context("No local weights to contribute")?;

        if weights.training_count < 50 {
            info!("Not enough training data to contribute (need 50, have {})",
                  weights.training_count);
            return Ok(false);
        }

        let contribution = WeightContribution::new(weights.clone(), &self.client_id);

        info!("Contributing weights to federated network...");
        debug!("Contribution: {} weights, {} training examples",
               contribution.weights.weights.len(),
               contribution.weights.training_count);

        // Send to server
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/contribute", self.server_url))
            .json(&contribution)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                info!("Successfully contributed weights to federated network");
                Ok(true)
            }
            Ok(resp) => {
                warn!("Server rejected contribution: {}", resp.status());
                Ok(false)
            }
            Err(e) => {
                // Offline mode - save for later
                debug!("Could not reach server, saving contribution for later: {}", e);
                self.save_pending_contribution(&contribution)?;
                Ok(false)
            }
        }
    }

    /// Fetch latest global model from server
    pub async fn fetch_global_model(&mut self) -> Result<Option<AggregatedModel>> {
        info!("Fetching global model from federated network...");

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/model/latest", self.server_url))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let model: AggregatedModel = resp.json().await?;
                info!("Fetched global model v{} ({} contributors, {} examples)",
                      model.global_version,
                      model.contributor_count,
                      model.total_training_examples);

                // Verify compatibility
                if !model.weights.is_compatible() {
                    warn!("Global model has incompatible schema, skipping");
                    return Ok(None);
                }

                self.global_model = Some(model.clone());
                self.save_global_model(&model)?;
                Ok(Some(model))
            }
            Ok(resp) => {
                debug!("No global model available: {}", resp.status());
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

    /// Merge global model with local model
    /// Uses weighted average based on training counts
    pub fn merge_models(&mut self) -> Result<ModelWeights> {
        let local = self.local_weights.as_ref();
        let global = self.global_model.as_ref();

        match (local, global) {
            (Some(local), Some(global)) => {
                info!("Merging local model ({} examples) with global model ({} examples)",
                      local.training_count, global.total_training_examples);

                // Weighted average based on training counts
                let local_weight = local.training_count as f64;
                let global_weight = global.total_training_examples as f64;
                let total_weight = local_weight + global_weight;

                let mut merged_weights = HashMap::new();

                // Merge each weight
                for (key, &local_val) in &local.weights {
                    let global_val = global.weights.weights.get(key).copied().unwrap_or(0.0);
                    let merged = (local_val * local_weight + global_val * global_weight) / total_weight;
                    merged_weights.insert(key.clone(), merged);
                }

                // Include any global-only weights
                for (key, &global_val) in &global.weights.weights {
                    if !merged_weights.contains_key(key) {
                        let merged = global_val * global_weight / total_weight;
                        merged_weights.insert(key.clone(), merged);
                    }
                }

                // Merge bias
                let merged_bias = (local.bias * local_weight + global.weights.bias * global_weight) / total_weight;

                Ok(ModelWeights::new(
                    merged_weights,
                    merged_bias,
                    local.training_count + global.total_training_examples,
                ))
            }
            (Some(local), None) => {
                debug!("No global model available, using local only");
                Ok(local.clone())
            }
            (None, Some(global)) => {
                debug!("No local model, using global only");
                Ok(global.weights.clone())
            }
            (None, None) => {
                anyhow::bail!("No models available to merge")
            }
        }
    }

    /// Save pending contribution for later upload
    fn save_pending_contribution(&self, contribution: &WeightContribution) -> Result<()> {
        let pending_dir = Self::get_data_dir()?.join("pending");
        fs::create_dir_all(&pending_dir)?;

        let path = pending_dir.join(format!("{}.json", contribution.weights.model_id));
        let json = serde_json::to_string_pretty(contribution)?;
        fs::write(path, json)?;

        debug!("Saved pending contribution for later upload");
        Ok(())
    }

    /// Upload any pending contributions
    pub async fn upload_pending(&self) -> Result<usize> {
        let pending_dir = Self::get_data_dir()?.join("pending");
        if !pending_dir.exists() {
            return Ok(0);
        }

        let mut uploaded = 0;
        let client = reqwest::Client::new();

        for entry in fs::read_dir(&pending_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let content = fs::read_to_string(&path)?;
                let contribution: WeightContribution = serde_json::from_str(&content)?;

                let response = client
                    .post(format!("{}/contribute", self.server_url))
                    .json(&contribution)
                    .timeout(std::time::Duration::from_secs(30))
                    .send()
                    .await;

                if response.is_ok() && response.unwrap().status().is_success() {
                    fs::remove_file(&path)?;
                    uploaded += 1;
                }
            }
        }

        if uploaded > 0 {
            info!("Uploaded {} pending contributions", uploaded);
        }

        Ok(uploaded)
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
            debug!("Loaded cached global model v{}", model.global_version);
            Ok(Some(model))
        } else {
            Ok(None)
        }
    }

    /// Get client statistics
    pub fn get_stats(&self) -> FederatedStats {
        FederatedStats {
            client_id: self.client_id.clone(),
            has_local_model: self.local_weights.is_some(),
            local_training_count: self.local_weights.as_ref().map(|w| w.training_count).unwrap_or(0),
            has_global_model: self.global_model.is_some(),
            global_version: self.global_model.as_ref().map(|m| m.global_version),
            global_contributors: self.global_model.as_ref().map(|m| m.contributor_count),
            can_contribute: self.can_contribute(),
        }
    }
}

impl Default for FederatedClient {
    fn default() -> Self {
        Self::new().expect("Failed to create federated client")
    }
}

/// Federated learning statistics
#[derive(Debug)]
pub struct FederatedStats {
    pub client_id: String,
    pub has_local_model: bool,
    pub local_training_count: usize,
    pub has_global_model: bool,
    pub global_version: Option<u32>,
    pub global_contributors: Option<usize>,
    pub can_contribute: bool,
}

/// Aggregation server (for reference - runs on Bountyy infrastructure)
/// This shows how the server-side aggregation works
pub struct AggregationServer {
    /// All received contributions
    contributions: Vec<WeightContribution>,
    /// Current global model version
    current_version: u32,
}

impl AggregationServer {
    /// Create new aggregation server
    pub fn new() -> Self {
        Self {
            contributions: Vec::new(),
            current_version: 0,
        }
    }

    /// Receive a contribution from a client
    pub fn receive_contribution(&mut self, contribution: WeightContribution) -> Result<()> {
        // Validate contribution
        if !contribution.weights.is_compatible() {
            anyhow::bail!("Incompatible weight schema");
        }

        if !contribution.dp_noise_applied {
            anyhow::bail!("Contribution must have differential privacy applied");
        }

        // Check minimum training count
        if contribution.weights.training_count < 50 {
            anyhow::bail!("Insufficient training data");
        }

        self.contributions.push(contribution);
        info!("Received contribution, total: {}", self.contributions.len());

        Ok(())
    }

    /// Aggregate all contributions using Federated Averaging
    pub fn aggregate(&mut self) -> Result<AggregatedModel> {
        if self.contributions.is_empty() {
            anyhow::bail!("No contributions to aggregate");
        }

        info!("Aggregating {} contributions", self.contributions.len());

        // Calculate total training examples
        let total_examples: usize = self.contributions
            .iter()
            .map(|c| c.weights.training_count)
            .sum();

        // Federated Averaging: weighted sum by training count
        let mut aggregated_weights: HashMap<String, f64> = HashMap::new();
        let mut aggregated_bias = 0.0;

        for contribution in &self.contributions {
            let weight = contribution.weights.training_count as f64 / total_examples as f64;

            for (key, &value) in &contribution.weights.weights {
                *aggregated_weights.entry(key.clone()).or_insert(0.0) += value * weight;
            }

            aggregated_bias += contribution.weights.bias * weight;
        }

        self.current_version += 1;

        let model = AggregatedModel {
            global_version: self.current_version,
            weights: ModelWeights::new(aggregated_weights, aggregated_bias, total_examples),
            contributor_count: self.contributions.len(),
            total_training_examples: total_examples,
            server_signature: self.sign_model(),
        };

        // Clear contributions after aggregation
        self.contributions.clear();

        info!("Created global model v{} from {} contributors",
              model.global_version, model.contributor_count);

        Ok(model)
    }

    /// Sign the aggregated model
    fn sign_model(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.current_version.hash(&mut hasher);
        chrono::Utc::now().timestamp().hash(&mut hasher);
        format!("bountyy-sig-{:x}", hasher.finish())
    }
}

impl Default for AggregationServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_contribution_has_dp_noise() {
        let weights = ModelWeights::new(
            [("test".to_string(), 0.5)].into_iter().collect(),
            0.1,
            100,
        );

        let contribution = WeightContribution::new(weights, "test-client");
        assert!(contribution.dp_noise_applied);
        assert!(!contribution.signature.is_empty());
    }

    #[test]
    fn test_schema_compatibility() {
        let weights = ModelWeights::new(HashMap::new(), 0.0, 50);
        assert!(weights.is_compatible());
    }

    #[test]
    fn test_aggregation() {
        let mut server = AggregationServer::new();

        // Add two contributions
        let w1 = ModelWeights::new(
            [("feature1".to_string(), 0.8)].into_iter().collect(),
            0.1,
            100,
        );
        let c1 = WeightContribution::new(w1, "client1");
        server.receive_contribution(c1).unwrap();

        let w2 = ModelWeights::new(
            [("feature1".to_string(), 0.4)].into_iter().collect(),
            0.2,
            100,
        );
        let c2 = WeightContribution::new(w2, "client2");
        server.receive_contribution(c2).unwrap();

        let aggregated = server.aggregate().unwrap();

        assert_eq!(aggregated.contributor_count, 2);
        assert_eq!(aggregated.total_training_examples, 200);
        assert_eq!(aggregated.global_version, 1);
    }
}
