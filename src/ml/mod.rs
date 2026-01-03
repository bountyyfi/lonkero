// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

pub mod auto_learning;
pub mod features;
pub mod federated;
pub mod fp_classifier;
pub mod integration;
pub mod privacy;
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

pub use auto_learning::{AutoLearner, AutoVerification, LearningStats};
pub use features::{FeatureExtractor, VulnFeatures};
pub use federated::{AggregationServer, FederatedClient, ModelWeights};
pub use fp_classifier::{FalsePositiveClassifier, Prediction};
pub use integration::{MlIntegration, MlPipeline, MlPipelineStats};
pub use privacy::{DataRetentionPolicy, GdprCompliance, PrivacyManager};
pub use training_data::{TrainingDataCollector, TrainingExample, VerificationStatus};
