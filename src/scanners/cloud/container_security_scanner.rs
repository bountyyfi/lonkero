// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Container Security Scanner
 * Enhanced container image scanning for ECR, ACR, and GCR
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::cloud::error_handling::{CloudError, RetryConfig, retry_with_backoff};
use crate::cloud::optimizations::{CloudMetadataCache, PerformanceMetrics};
use crate::types::{Confidence, Severity, Vulnerability};
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Container security finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerFindingType {
    VulnerableBaseImage,
    OutdatedBaseImage,
    InsecureImageConfig,
    MissingImageSigning,
    PrivilegedContainer,
    RootUser,
    ExposedSecrets,
    InsecureRegistry,
}

/// Container image vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerVulnerability {
    pub vulnerability_id: String,
    pub severity: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

pub struct CloudContainerSecurityScanner {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
}

impl CloudContainerSecurityScanner {
    pub fn new() -> Self {
        let cache = Arc::new(CloudMetadataCache::new(
            Duration::from_secs(300),
            1000,
        ));

        Self {
            cache,
            retry_config: RetryConfig::default(),
        }
    }

    /// Scan AWS ECR repositories and images
    pub async fn scan_aws_ecr(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS ECR Security Scanning");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS ECR security scanning");

        let client = aws_sdk_ecr::Client::new(aws_config);

        // List all repositories
        metrics.record_api_call();
        let repositories = retry_with_backoff(
            || async {
                client
                    .describe_repositories()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe repositories: {}", e)))
            },
            self.retry_config.clone(),
            "describe_repositories",
        )
        .await?;

        if let Some(repos_list) = repositories.repositories {
            for repo in repos_list {
                let repo_name = repo.repository_name().unwrap_or("unknown");

                // Check repository configuration
                let repo_vulns = self.check_ecr_repository_config(&repo, repo_name);
                vulnerabilities.extend(repo_vulns);

                // List images in repository
                metrics.record_api_call();
                let images = client
                    .list_images()
                    .repository_name(repo_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list images: {}", e)))?;

                if let Some(image_ids) = images.image_ids {
                    for image_id in image_ids {
                        // Get image scan findings
                        if let Some(image_tag) = image_id.image_tag() {
                            metrics.record_api_call();
                            let scan_findings = client
                                .describe_image_scan_findings()
                                .repository_name(repo_name)
                                .image_id(image_id.clone())
                                .send()
                                .await;

                            if let Ok(findings) = scan_findings {
                                if let Some(scan_result) = findings.image_scan_findings() {
                                    let image_vulns = self.process_ecr_scan_findings(
                                        scan_result,
                                        repo_name,
                                        image_tag,
                                    );
                                    vulnerabilities.extend(image_vulns);
                                }
                            }
                        }
                    }
                }
            }
        }

        metrics.report();
        info!("AWS ECR security scanning completed. Found {} issues", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    fn check_ecr_repository_config(
        &self,
        repo: &aws_sdk_ecr::types::Repository,
        repo_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if image scanning is enabled
        if let Some(scan_config) = repo.image_scanning_configuration() {
            if !scan_config.scan_on_push() {
                vulnerabilities.push(self.create_vulnerability(
                    "ECR Image Scanning Not Enabled",
                    Severity::Medium,
                    Confidence::High,
                    format!("ECR repository '{}' does not have scan-on-push enabled", repo_name),
                    format!("Repository: {}, Scan on Push: false", repo_name),
                    "Enable scan-on-push to automatically scan images for vulnerabilities",
                    "CWE-1188",
                    5.0,
                ));
            }
        }

        // Check if lifecycle policy is configured
        // Note: This would require a separate API call to get_lifecycle_policy
        // For now, this is a reminder to implement

        vulnerabilities
    }

    fn process_ecr_scan_findings(
        &self,
        scan_result: &aws_sdk_ecr::types::ImageScanFindings,
        repo_name: &str,
        image_tag: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let findings = scan_result.findings();
        for finding in findings {
            let severity = finding.severity().map(|s| format!("{:?}", s)).unwrap_or("UNKNOWN".to_string());
            let name = finding.name().unwrap_or("unknown");
            let description = finding.description().unwrap_or("No description");

            let vuln_severity = match severity.as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                _ => Severity::Low,
            };

            let cvss = match severity.as_str() {
                "CRITICAL" => 9.0,
                "HIGH" => 7.5,
                "MEDIUM" => 5.0,
                _ => 3.0,
            };

            vulnerabilities.push(self.create_vulnerability(
                &format!("ECR Image Vulnerability: {}", name),
                vuln_severity,
                Confidence::High,
                format!(
                    "Container image '{}:{}' has {} vulnerability: {}",
                    repo_name, image_tag, severity, name
                ),
                format!("Repository: {}, Tag: {}, CVE: {}, Description: {}",
                       repo_name, image_tag, name, description),
                "Update the base image or package to a version without the vulnerability",
                "CWE-1104",
                cvss,
            ));
        }

        vulnerabilities
    }

    /// Scan Azure Container Registry
    pub async fn scan_azure_acr(&self) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting Azure ACR security scanning");

        // Note: Placeholder for Azure ACR scanning
        // In production, you would:
        // 1. List all registries
        // 2. List images in each registry
        // 3. Get vulnerability scan results
        // 4. Check registry configuration (admin user, public access, etc.)

        warn!("Azure ACR scanning requires Azure credentials configuration");

        Ok(vec![])
    }

    /// Scan Google Container Registry
    pub async fn scan_gcp_gcr(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting GCP GCR security scanning for project: {}", project_id);

        // Note: Placeholder for GCP GCR scanning
        // In production, you would:
        // 1. List all container images
        // 2. Get vulnerability scan results from Container Analysis API
        // 3. Check for binary authorization policies
        // 4. Verify image signing

        warn!("GCP GCR scanning requires GCP credentials configuration");

        Ok(vec![])
    }

    /// Check for common container misconfigurations
    pub fn check_container_config(&self, config: &serde_json::Value) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if container runs as root
        if let Some(user) = config.get("User") {
            if user.as_str() == Some("root") || user.as_str() == Some("0") {
                vulnerabilities.push(self.create_vulnerability(
                    "Container Running as Root",
                    Severity::High,
                    Confidence::High,
                    "Container is configured to run as root user".to_string(),
                    "User: root".to_string(),
                    "Configure container to run as non-root user",
                    "CWE-250",
                    7.0,
                ));
            }
        }

        // Check for privileged mode
        if let Some(privileged) = config.get("Privileged") {
            if privileged.as_bool() == Some(true) {
                vulnerabilities.push(self.create_vulnerability(
                    "Privileged Container",
                    Severity::Critical,
                    Confidence::High,
                    "Container is running in privileged mode".to_string(),
                    "Privileged: true".to_string(),
                    "Remove privileged flag unless absolutely necessary. Use specific capabilities instead.",
                    "CWE-250",
                    9.0,
                ));
            }
        }

        // Check for exposed secrets in environment variables
        if let Some(env) = config.get("Env").and_then(|e| e.as_array()) {
            for env_var in env {
                if let Some(env_str) = env_var.as_str() {
                    if env_str.to_lowercase().contains("password")
                        || env_str.to_lowercase().contains("secret")
                        || env_str.to_lowercase().contains("api_key")
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            "Potential Secret in Environment Variable",
                            Severity::High,
                            Confidence::Medium,
                            format!("Container has potential secret in environment: {}", env_str),
                            format!("Environment: {}", env_str),
                            "Use secrets management (AWS Secrets Manager, K8s Secrets, etc.) instead of environment variables",
                            "CWE-798",
                            7.5,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    fn create_vulnerability(
        &self,
        vuln_type: &str,
        severity: Severity,
        confidence: Confidence,
        description: String,
        evidence: String,
        remediation: &str,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("container_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud Container Security".to_string(),
            url: "N/A".to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description,
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for CloudContainerSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }
    }

    impl std::fmt::Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut rng = rand::rng();
            write!(
                f,
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}
