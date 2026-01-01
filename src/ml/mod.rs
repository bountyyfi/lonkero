// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Machine Learning Module
 * Federated learning for vulnerability detection with privacy-preserving model training
 *
 * Features:
 * - Local training data collection (no data leaves machine)
 * - False positive classifier
 * - Vulnerability prediction
 * - Federated model weight aggregation
 * - Smart payload selection
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

pub mod training_data;
pub mod fp_classifier;
pub mod federated;
pub mod features;
pub mod auto_learning;
pub mod privacy;
pub mod integration;

pub use training_data::{TrainingDataCollector, TrainingExample, VerificationStatus};
pub use fp_classifier::{FalsePositiveClassifier, Prediction};
pub use federated::{FederatedClient, ModelWeights, AggregationServer};
pub use features::{FeatureExtractor, VulnFeatures};
pub use auto_learning::{AutoLearner, AutoVerification, LearningStats};
pub use privacy::{PrivacyManager, GdprCompliance, DataRetentionPolicy};
pub use integration::{MlPipeline, MlPipelineStats, MlIntegration};
