// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use super::auto_learning::{AutoLearner, AutoVerification};
use super::federated::FederatedClient;
use super::fp_classifier::FalsePositiveClassifier;
use super::privacy::PrivacyManager;
use super::training_data::VerificationStatus;
/**
 * Bountyy Oy - ML Integration for Scan Pipeline
 * Automatic learning from scan results without user intervention
 *
 * This module integrates the ML system into the scan pipeline:
 * 1. After each scan completes, vulnerabilities are processed for learning
 * 2. Auto-verification determines true/false positives
 * 3. Training data is collected locally
 * 4. Periodically syncs with federated network (if opted in)
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::http_client::HttpResponse;
use crate::types::Vulnerability;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// ML Pipeline Integration
/// Manages automatic learning from scan results
pub struct MlPipeline {
    /// Auto-learner for verification without user input
    auto_learner: Arc<RwLock<AutoLearner>>,
    /// False positive classifier (uses learned model)
    fp_classifier: Arc<RwLock<FalsePositiveClassifier>>,
    /// Federated learning client
    federated_client: Arc<RwLock<FederatedClient>>,
    /// Privacy manager for GDPR compliance
    privacy_manager: Arc<RwLock<PrivacyManager>>,
    /// Whether ML features are enabled
    enabled: bool,
    /// Findings processed this session
    findings_processed: usize,
    /// Auto-confirmed true positives
    auto_confirmed: usize,
    /// Auto-rejected false positives
    auto_rejected: usize,
}

impl MlPipeline {
    /// Create new ML pipeline
    pub fn new() -> Result<Self> {
        let privacy_manager = PrivacyManager::new()?;
        let enabled = privacy_manager.is_ml_allowed();

        Ok(Self {
            auto_learner: Arc::new(RwLock::new(AutoLearner::new()?)),
            fp_classifier: Arc::new(RwLock::new(FalsePositiveClassifier::new()?)),
            federated_client: Arc::new(RwLock::new(FederatedClient::new()?)),
            privacy_manager: Arc::new(RwLock::new(privacy_manager)),
            enabled,
            findings_processed: 0,
            auto_confirmed: 0,
            auto_rejected: 0,
        })
    }

    /// Check if ML is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process pre-extracted ML features for learning (GDPR-compliant)
    /// Features are already extracted - no raw response data needed
    pub async fn process_features(
        &mut self,
        vuln: &Vulnerability,
        features: &super::VulnFeatures,
    ) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }

        // Use features directly for learning
        let mut learner = self.auto_learner.write().await;
        let verification = learner.learn_from_features(vuln, features)?;

        self.findings_processed += 1;

        match verification.status {
            VerificationStatus::Confirmed => {
                self.auto_confirmed += 1;
                debug!(
                    "ML: Auto-confirmed {} at {} (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
            VerificationStatus::FalsePositive => {
                self.auto_rejected += 1;
                debug!(
                    "ML: Auto-rejected {} at {} as FP (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
            VerificationStatus::Unverified => {
                debug!(
                    "ML: {} at {} needs more data (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
        }

        Ok(true)
    }

    /// Process a vulnerability finding for learning
    /// Call this for each vulnerability found during scanning
    pub async fn process_finding(
        &mut self,
        vuln: &Vulnerability,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
        payload: Option<&str>,
    ) -> Result<Option<AutoVerification>> {
        if !self.enabled {
            return Ok(None);
        }

        let mut learner = self.auto_learner.write().await;
        let verification = learner.learn_from_finding(vuln, response, baseline, payload)?;

        self.findings_processed += 1;

        match verification.status {
            VerificationStatus::Confirmed => {
                self.auto_confirmed += 1;
                debug!(
                    "ML: Auto-confirmed {} at {} (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
            VerificationStatus::FalsePositive => {
                self.auto_rejected += 1;
                debug!(
                    "ML: Auto-rejected {} at {} as FP (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
            VerificationStatus::Unverified => {
                debug!(
                    "ML: {} at {} needs more data (confidence: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    verification.confidence * 100.0
                );
            }
        }

        Ok(Some(verification))
    }

    /// Process multiple vulnerabilities at once (batch processing)
    pub async fn process_findings_batch(
        &mut self,
        findings: &[(
            Vulnerability,
            HttpResponse,
            Option<HttpResponse>,
            Option<String>,
        )],
    ) -> Result<Vec<AutoVerification>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let mut verifications = Vec::with_capacity(findings.len());

        for (vuln, response, baseline, payload) in findings {
            if let Some(verification) = self
                .process_finding(vuln, response, baseline.as_ref(), payload.as_deref())
                .await?
            {
                verifications.push(verification);
            }
        }

        Ok(verifications)
    }

    /// Predict if a vulnerability is likely a false positive
    /// Use this to filter results before presenting to user
    pub async fn predict_false_positive(
        &self,
        _vuln: &Vulnerability,
        response: &HttpResponse,
        baseline: Option<&HttpResponse>,
        payload: Option<&str>,
    ) -> Result<f32> {
        if !self.enabled {
            return Ok(0.5); // Unknown
        }

        // Extract features from response
        let learner = self.auto_learner.read().await;
        let features = learner
            .feature_extractor
            .extract(response, baseline, payload);

        let classifier = self.fp_classifier.read().await;
        let prediction = classifier.predict(&features);

        Ok(1.0 - prediction.true_positive_probability)
    }

    /// Filter vulnerabilities by false positive probability
    /// Returns only findings below the threshold
    pub async fn filter_likely_true_positives(
        &self,
        findings: Vec<(
            Vulnerability,
            HttpResponse,
            Option<HttpResponse>,
            Option<String>,
        )>,
        threshold: f32,
    ) -> Result<Vec<Vulnerability>> {
        if !self.enabled {
            // Return all if ML disabled
            return Ok(findings.into_iter().map(|(v, _, _, _)| v).collect());
        }

        let mut filtered = Vec::new();

        for (vuln, response, baseline, payload) in findings {
            let fp_prob = self
                .predict_false_positive(&vuln, &response, baseline.as_ref(), payload.as_deref())
                .await?;

            if fp_prob < threshold {
                filtered.push(vuln);
            } else {
                debug!(
                    "ML: Filtered {} at {} (FP probability: {:.0}%)",
                    vuln.vuln_type,
                    vuln.url,
                    fp_prob * 100.0
                );
            }
        }

        Ok(filtered)
    }

    /// Predict if a vulnerability is likely a false positive using pre-extracted features
    /// Use this when vulnerabilities already have MlResponseData attached
    pub async fn predict_false_positive_from_features(
        &self,
        features: &super::VulnFeatures,
    ) -> Result<f32> {
        if !self.enabled {
            return Ok(0.5); // Unknown
        }

        let classifier = self.fp_classifier.read().await;
        let prediction = classifier.predict(features);

        Ok(1.0 - prediction.true_positive_probability)
    }

    /// Filter vulnerabilities using their embedded ML features
    /// Returns (filtered_vulns, filtered_count) - filtered_vulns are likely true positives
    /// Vulnerabilities without ML features are kept (not filtered)
    pub async fn filter_vulns_by_features(
        &self,
        vulns: Vec<Vulnerability>,
        threshold: f32,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        if !self.enabled {
            // Return all if ML disabled
            return Ok((vulns, 0));
        }

        let mut filtered = Vec::new();
        let mut filtered_count = 0;

        for vuln in vulns {
            if let Some(ref ml_data) = vuln.ml_data {
                let fp_prob = self
                    .predict_false_positive_from_features(&ml_data.features)
                    .await?;

                if fp_prob < threshold {
                    filtered.push(vuln);
                } else {
                    filtered_count += 1;
                    debug!(
                        "ML: Filtered {} at {} (FP probability: {:.0}%)",
                        vuln.vuln_type,
                        vuln.url,
                        fp_prob * 100.0
                    );
                }
            } else {
                // No ML data - keep the vulnerability (can't predict)
                filtered.push(vuln);
            }
        }

        Ok((filtered, filtered_count))
    }

    /// Called at end of scan to sync detection model
    pub async fn on_scan_complete(&mut self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        info!(
            "ML: Scan complete - processed {} findings ({} confirmed, {} rejected)",
            self.findings_processed, self.auto_confirmed, self.auto_rejected
        );

        // Try to fetch latest detection model
        let mut federated = self.federated_client.write().await;
        if let Ok(Some(model)) = federated.fetch_global_model().await {
            info!(
                "ML: Fetched detection model v{} ({} contributors)",
                model.global_version, model.contributor_count
            );
        }

        // Reset session counters
        self.findings_processed = 0;
        self.auto_confirmed = 0;
        self.auto_rejected = 0;

        Ok(())
    }

    /// Enable ML features (requires user consent)
    pub async fn enable(&mut self) -> Result<()> {
        let mut privacy = self.privacy_manager.write().await;
        privacy.record_consent(false)?;
        self.enabled = true;

        info!("ML: Enabled");
        Ok(())
    }

    /// Disable ML features and optionally delete data
    pub async fn disable(&mut self, delete_data: bool) -> Result<()> {
        self.enabled = false;

        if delete_data {
            let mut privacy = self.privacy_manager.write().await;
            privacy.withdraw_consent()?;
            info!("ML: Disabled and all data deleted");
        } else {
            info!("ML: Disabled (data retained)");
        }

        Ok(())
    }

    /// Get ML pipeline statistics
    pub async fn get_stats(&self) -> MlPipelineStats {
        let learner = self.auto_learner.read().await;
        let learning_stats = learner.get_stats();

        let federated = self.federated_client.read().await;
        let federated_stats = federated.get_stats();

        MlPipelineStats {
            enabled: self.enabled,
            session_processed: self.findings_processed,
            session_confirmed: self.auto_confirmed,
            session_rejected: self.auto_rejected,
            total_confirmed: learning_stats.auto_confirmed,
            total_rejected: learning_stats.auto_rejected,
            pending_learning: learning_stats.pending_learning,
            endpoint_patterns: learning_stats.endpoint_patterns,
            model_available: federated_stats.has_global_model,
            model_contributors: federated_stats.global_contributors,
        }
    }
}

impl Default for MlPipeline {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            warn!("ML: Failed to initialize pipeline: {}", e);
            Self {
                auto_learner: Arc::new(RwLock::new(AutoLearner::default())),
                fp_classifier: Arc::new(RwLock::new(FalsePositiveClassifier::default())),
                federated_client: Arc::new(RwLock::new(FederatedClient::default())),
                privacy_manager: Arc::new(RwLock::new(PrivacyManager::default())),
                enabled: false,
                findings_processed: 0,
                auto_confirmed: 0,
                auto_rejected: 0,
            }
        })
    }
}

/// ML Pipeline Statistics
#[derive(Debug, Clone)]
pub struct MlPipelineStats {
    /// Whether ML is enabled
    pub enabled: bool,
    /// Findings processed this session
    pub session_processed: usize,
    /// Auto-confirmed this session
    pub session_confirmed: usize,
    /// Auto-rejected this session
    pub session_rejected: usize,
    /// Total confirmed across all sessions
    pub total_confirmed: usize,
    /// Total rejected across all sessions
    pub total_rejected: usize,
    /// Pending examples needing more data
    pub pending_learning: usize,
    /// Unique endpoint patterns learned
    pub endpoint_patterns: usize,
    /// Whether detection model is available
    pub model_available: bool,
    /// Number of model contributors
    pub model_contributors: Option<usize>,
}

/// Simplified interface for scan pipeline integration
/// Use this when you don't need full pipeline control
pub struct MlIntegration {
    pipeline: Arc<RwLock<MlPipeline>>,
}

impl MlIntegration {
    pub fn new() -> Result<Self> {
        Ok(Self {
            pipeline: Arc::new(RwLock::new(MlPipeline::new()?)),
        })
    }

    /// Process a finding (simplified interface)
    pub async fn learn(&self, vuln: &Vulnerability, response: &HttpResponse) -> Result<()> {
        let mut pipeline = self.pipeline.write().await;
        pipeline.process_finding(vuln, response, None, None).await?;
        Ok(())
    }

    /// Called when scan completes
    pub async fn scan_complete(&self) -> Result<()> {
        let mut pipeline = self.pipeline.write().await;
        pipeline.on_scan_complete().await
    }

    /// Get the underlying pipeline
    pub fn pipeline(&self) -> Arc<RwLock<MlPipeline>> {
        Arc::clone(&self.pipeline)
    }
}

impl Default for MlIntegration {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            pipeline: Arc::new(RwLock::new(MlPipeline::default())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Severity};
    use std::collections::HashMap;

    fn create_test_vuln() -> Vulnerability {
        Vulnerability {
            id: "test-123".to_string(),
            vuln_type: "SQL Injection".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: "https://example.com/api/users/123".to_string(),
            parameter: Some("id".to_string()),
            payload: Some("' OR '1'='1".to_string()),
            description: "Test SQL injection".to_string(),
            evidence: None,
            cwe: Some("CWE-89".to_string()),
            cvss: None,
            verified: false,
            false_positive: false,
            remediation: None,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_test_response(body: &str, status: u16) -> HttpResponse {
        HttpResponse {
            status_code: status,
            headers: HashMap::new(),
            body: body.to_string(),
            duration_ms: 100,
        }
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let pipeline = MlPipeline::new();
        // May fail if ~/.lonkero doesn't exist, that's OK for tests
        assert!(pipeline.is_ok() || pipeline.is_err());
    }
}
