// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - False Positive Classifier
 * ML-based classification to reduce false positives
 *
 * Uses a simple but effective logistic regression model that can be:
 * 1. Trained locally on user-verified findings
 * 2. Improved via federated learning without sharing raw data
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use super::features::VulnFeatures;
use super::training_data::TrainingDataCollector;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use tracing::{debug, info};

/// Prediction result from the classifier
#[derive(Debug, Clone)]
pub struct Prediction {
    /// Probability that this is a true positive (0.0 - 1.0)
    pub true_positive_probability: f32,
    /// Confidence in the prediction
    pub confidence: f32,
    /// Whether this is likely a false positive
    pub likely_false_positive: bool,
    /// Explanation of key factors
    pub explanation: Vec<String>,
}

/// Logistic regression weights for the classifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelWeights {
    /// Feature weights
    pub weights: Vec<f32>,
    /// Bias term
    pub bias: f32,
    /// Number of training examples used
    pub training_examples: usize,
    /// Model version
    pub version: u32,
    /// Feature names for interpretability
    pub feature_names: Vec<String>,
}

impl ModelWeights {
    /// Create initial weights (before training)
    pub fn initial(num_features: usize) -> Self {
        Self {
            weights: vec![0.0; num_features],
            bias: 0.0,
            training_examples: 0,
            version: 1,
            feature_names: VulnFeatures::feature_names()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Sigmoid activation function
    fn sigmoid(x: f32) -> f32 {
        1.0 / (1.0 + (-x).exp())
    }

    /// Predict probability given features
    pub fn predict(&self, features: &[f32]) -> f32 {
        if features.len() != self.weights.len() {
            return 0.5; // Unknown - return neutral
        }

        let z: f32 = self.weights.iter()
            .zip(features.iter())
            .map(|(w, f)| w * f)
            .sum::<f32>() + self.bias;

        Self::sigmoid(z)
    }

    /// Get top contributing features for interpretability
    pub fn top_features(&self, features: &[f32], top_k: usize) -> Vec<(String, f32)> {
        let mut contributions: Vec<(String, f32)> = self.weights.iter()
            .zip(features.iter())
            .zip(self.feature_names.iter())
            .map(|((w, f), name)| (name.clone(), w * f))
            .collect();

        contributions.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
        contributions.truncate(top_k);
        contributions
    }
}

/// False Positive Classifier using logistic regression
pub struct FalsePositiveClassifier {
    /// Model weights
    weights: ModelWeights,
    /// Model file path
    model_path: PathBuf,
    /// Learning rate for training
    learning_rate: f32,
    /// Training data collector
    data_collector: TrainingDataCollector,
}

impl FalsePositiveClassifier {
    /// Create new classifier, loading existing model if available
    pub fn new() -> Result<Self> {
        let model_path = Self::get_model_path()?;
        let weights = Self::load_or_create_model(&model_path)?;
        let data_collector = TrainingDataCollector::new()?;

        Ok(Self {
            weights,
            model_path,
            learning_rate: 0.01,
            data_collector,
        })
    }

    /// Get path to saved model
    fn get_model_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .context("Could not determine home directory")?;
        let dir = home.join(".lonkero").join("models");
        fs::create_dir_all(&dir)?;
        Ok(dir.join("fp_classifier.json"))
    }

    /// Load existing model or create new one
    fn load_or_create_model(path: &PathBuf) -> Result<ModelWeights> {
        if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let weights: ModelWeights = serde_json::from_reader(reader)?;
            info!("Loaded FP classifier model (v{}, {} examples)",
                weights.version, weights.training_examples);
            Ok(weights)
        } else {
            let num_features = VulnFeatures::feature_names().len();
            info!("Created new FP classifier with {} features", num_features);
            Ok(ModelWeights::initial(num_features))
        }
    }

    /// Save model to disk
    pub fn save_model(&self) -> Result<()> {
        let file = File::create(&self.model_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.weights)?;
        info!("Saved FP classifier model to {:?}", self.model_path);
        Ok(())
    }

    /// Predict whether a finding is a false positive
    pub fn predict(&self, features: &VulnFeatures) -> Prediction {
        let feature_vec = features.to_vector();
        let prob = self.weights.predict(&feature_vec);

        // Get confidence based on distance from 0.5
        let confidence = (prob - 0.5).abs() * 2.0;

        // Get explanations from top features
        let top = self.weights.top_features(&feature_vec, 3);
        let explanation: Vec<String> = top.iter()
            .map(|(name, contrib)| {
                if *contrib > 0.0 {
                    format!("{} indicates true positive", name)
                } else {
                    format!("{} indicates false positive", name)
                }
            })
            .collect();

        Prediction {
            true_positive_probability: prob,
            confidence,
            likely_false_positive: prob < 0.5,
            explanation,
        }
    }

    /// Train the model on collected data
    pub fn train(&mut self, epochs: usize) -> Result<TrainingResult> {
        let data = self.data_collector.get_training_data()?;

        if data.len() < 10 {
            return Ok(TrainingResult {
                success: false,
                message: format!(
                    "Not enough training data. Have {} examples, need at least 10.",
                    data.len()
                ),
                accuracy: 0.0,
                examples_used: data.len(),
            });
        }

        // Prepare feature matrix and labels
        let features: Vec<Vec<f32>> = data.iter()
            .map(|e| e.to_feature_vector())
            .collect();

        let labels: Vec<f32> = data.iter()
            .filter_map(|e| e.get_label())
            .collect();

        if features.len() != labels.len() {
            return Ok(TrainingResult {
                success: false,
                message: "Mismatch between features and labels".to_string(),
                accuracy: 0.0,
                examples_used: 0,
            });
        }

        info!("Training on {} examples for {} epochs", features.len(), epochs);

        // Gradient descent training
        for epoch in 0..epochs {
            let mut total_loss = 0.0;

            for (feature_vec, &label) in features.iter().zip(labels.iter()) {
                // Forward pass
                let prediction = self.weights.predict(feature_vec);

                // Compute loss (binary cross-entropy)
                let loss = -(label * prediction.ln() + (1.0 - label) * (1.0 - prediction).ln());
                total_loss += loss;

                // Backward pass - update weights
                let error = prediction - label;
                for (i, &f) in feature_vec.iter().enumerate() {
                    self.weights.weights[i] -= self.learning_rate * error * f;
                }
                self.weights.bias -= self.learning_rate * error;
            }

            if epoch % 100 == 0 {
                debug!("Epoch {}: avg loss = {:.4}", epoch, total_loss / features.len() as f32);
            }
        }

        // Calculate final accuracy
        let mut correct = 0;
        for (feature_vec, &label) in features.iter().zip(labels.iter()) {
            let pred = self.weights.predict(feature_vec);
            let pred_class = if pred > 0.5 { 1.0 } else { 0.0 };
            if (pred_class - label).abs() < 0.001 {
                correct += 1;
            }
        }
        let accuracy = correct as f32 / features.len() as f32;

        // Update model metadata
        self.weights.training_examples = features.len();
        self.weights.version += 1;

        // Save the trained model
        self.save_model()?;

        info!(
            "Training complete: accuracy = {:.2}% on {} examples",
            accuracy * 100.0,
            features.len()
        );

        Ok(TrainingResult {
            success: true,
            message: format!("Model trained successfully (v{})", self.weights.version),
            accuracy,
            examples_used: features.len(),
        })
    }

    /// Get current model weights (for federated learning)
    pub fn get_weights(&self) -> &ModelWeights {
        &self.weights
    }

    /// Update model with federated weights
    pub fn update_from_federated(&mut self, federated_weights: ModelWeights) -> Result<()> {
        // Validate dimensions match
        if federated_weights.weights.len() != self.weights.weights.len() {
            anyhow::bail!("Federated weights dimension mismatch");
        }

        // Merge with local model (weighted average favoring local)
        let local_weight = 0.7;
        let federated_weight = 0.3;

        for (_i, (local, federated)) in self.weights.weights.iter_mut()
            .zip(federated_weights.weights.iter())
            .enumerate()
        {
            *local = *local * local_weight + federated * federated_weight;
        }

        self.weights.bias = self.weights.bias * local_weight +
            federated_weights.bias * federated_weight;

        self.weights.version += 1;
        self.save_model()?;

        info!("Updated model with federated weights (v{})", self.weights.version);
        Ok(())
    }

    /// Get training statistics
    pub fn get_stats(&self) -> Result<ClassifierStats> {
        let data_stats = self.data_collector.get_stats()?;
        Ok(ClassifierStats {
            model_version: self.weights.version,
            model_training_examples: self.weights.training_examples,
            local_confirmed: data_stats.confirmed_count,
            local_false_positives: data_stats.false_positive_count,
            local_unverified: data_stats.unverified_count,
            model_path: self.model_path.clone(),
        })
    }
}

impl Default for FalsePositiveClassifier {
    fn default() -> Self {
        Self::new().expect("Failed to create FP classifier")
    }
}

/// Result of training operation
#[derive(Debug)]
pub struct TrainingResult {
    pub success: bool,
    pub message: String,
    pub accuracy: f32,
    pub examples_used: usize,
}

/// Statistics about the classifier
#[derive(Debug)]
pub struct ClassifierStats {
    pub model_version: u32,
    pub model_training_examples: usize,
    pub local_confirmed: usize,
    pub local_false_positives: usize,
    pub local_unverified: usize,
    pub model_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid() {
        assert!((ModelWeights::sigmoid(0.0) - 0.5).abs() < 0.001);
        assert!(ModelWeights::sigmoid(10.0) > 0.99);
        assert!(ModelWeights::sigmoid(-10.0) < 0.01);
    }

    #[test]
    fn test_initial_weights_neutral() {
        let weights = ModelWeights::initial(10);
        let features = vec![1.0; 10];
        let pred = weights.predict(&features);
        // With all zero weights, should predict 0.5
        assert!((pred - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_prediction_structure() {
        let features = VulnFeatures {
            status_code: 200,
            response_length: 1000,
            response_time_ms: 100,
            has_html: true,
            has_json: false,
            has_xml: false,
            has_javascript: false,
            has_sql_error: true,
            has_stack_trace: false,
            has_debug_info: false,
            has_path_disclosure: false,
            payload_reflected: true,
            reflection_count: 1,
            reflection_in_attribute: false,
            reflection_in_script: false,
            reflection_encoded: false,
            differs_from_baseline: true,
            timing_anomaly: false,
            status_changed: false,
            length_changed_significantly: false,
            is_api_endpoint: false,
            has_auth_headers: false,
            has_session_cookie: false,
        };

        // Just verify it doesn't panic with initial weights
        let weights = ModelWeights::initial(features.to_vector().len());
        let pred = weights.predict(&features.to_vector());
        assert!(pred >= 0.0 && pred <= 1.0);
    }
}
