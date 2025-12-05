// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Compliance Scanner
 * CIS Benchmarks implementation for AWS, Azure, and GCP
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

/// Compliance framework types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    CisAwsFoundations14,
    CisAzureFoundations14,
    CisGcpFoundations13,
    PciDss,
    HipaaCompliance,
    GdprCompliance,
    Soc2,
}

/// Compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub framework: ComplianceFramework,
    pub severity: String,
    pub automated: bool,
}

/// Compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    pub control: ComplianceControl,
    pub status: ComplianceStatus,
    pub findings: Vec<String>,
    pub evidence: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    NotApplicable,
    ManualReview,
}

pub struct CloudComplianceScanner {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
}

impl CloudComplianceScanner {
    pub fn new() -> Self {
        let cache = Arc::new(CloudMetadataCache::new(
            Duration::from_secs(600),
            1000,
        ));

        Self {
            cache,
            retry_config: RetryConfig::default(),
        }
    }

    /// Run CIS AWS Foundations Benchmark v1.4
    pub async fn scan_cis_aws_foundations(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("CIS AWS Foundations Benchmark");
        let mut vulnerabilities = Vec::new();

        info!("Starting CIS AWS Foundations Benchmark v1.4 scan");

        // CIS 1.1 - Avoid the use of the "root" account
        let root_findings = self.check_root_account_usage(aws_config, &mut metrics).await?;
        vulnerabilities.extend(root_findings);

        // CIS 1.2 - Ensure MFA is enabled for all IAM users with a console password
        let mfa_findings = self.check_iam_mfa(aws_config, &mut metrics).await?;
        vulnerabilities.extend(mfa_findings);

        // CIS 1.3 - Ensure credentials unused for 90 days or greater are disabled
        let inactive_findings = self.check_inactive_credentials(aws_config, &mut metrics).await?;
        vulnerabilities.extend(inactive_findings);

        // CIS 1.4 - Ensure access keys are rotated every 90 days or less
        let key_rotation_findings = self.check_access_key_rotation(aws_config, &mut metrics).await?;
        vulnerabilities.extend(key_rotation_findings);

        // CIS 2.1 - Ensure CloudTrail is enabled in all regions
        let cloudtrail_findings = self.check_cloudtrail_enabled(aws_config, &mut metrics).await?;
        vulnerabilities.extend(cloudtrail_findings);

        // CIS 2.3 - Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
        let s3_public_findings = self.check_cloudtrail_s3_public(aws_config, &mut metrics).await?;
        vulnerabilities.extend(s3_public_findings);

        // CIS 3.1 - Ensure a log metric filter and alarm exist for unauthorized API calls
        let api_alarm_findings = self.check_cloudwatch_alarms(aws_config, &mut metrics).await?;
        vulnerabilities.extend(api_alarm_findings);

        // CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
        let ssh_findings = self.check_ssh_unrestricted(aws_config, &mut metrics).await?;
        vulnerabilities.extend(ssh_findings);

        // CIS 4.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
        let rdp_findings = self.check_rdp_unrestricted(aws_config, &mut metrics).await?;
        vulnerabilities.extend(rdp_findings);

        metrics.report();
        info!("CIS AWS Foundations Benchmark completed. Found {} issues", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    async fn check_root_account_usage(
        &self,
        _aws_config: &aws_config::SdkConfig,
        _metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        // Note: This requires CloudTrail logs analysis
        // For production, you would query CloudTrail for root account activity

        Ok(vulnerabilities)
    }

    async fn check_iam_mfa(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let users = retry_with_backoff(
            || async {
                client
                    .list_users()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list users: {}", e)))
            },
            self.retry_config.clone(),
            "list_users",
        )
        .await?;

        for user in users.users() {
            let user_name = user.user_name();

            // Check if user has console access
            metrics.record_api_call();
            let login_profile = client
                .get_login_profile()
                .user_name(user_name)
                .send()
                .await;

            if login_profile.is_ok() {
                // User has console access, check MFA
                metrics.record_api_call();
                let mfa_devices = client
                    .list_mfa_devices()
                    .user_name(user_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list MFA devices: {}", e)))?;

                if mfa_devices.mfa_devices().is_empty() {
                    vulnerabilities.push(self.create_vulnerability(
                        "CIS 1.2 - IAM User Without MFA",
                        Severity::High,
                        Confidence::High,
                        format!("IAM user '{}' has console access but no MFA enabled", user_name),
                        format!("User: {}, Console Access: Yes, MFA: No", user_name),
                        "Enable MFA for all IAM users with console access",
                        "CIS AWS Foundations Benchmark v1.4 - Control 1.2",
                        7.5,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_inactive_credentials(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let users = client
            .list_users()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to list users: {}", e)))?;

        for user in users.users() {
            let user_name = user.user_name();

            // Check password last used
            if let Some(password_last_used) = user.password_last_used() {
                let password_date = chrono::DateTime::from_timestamp(password_last_used.secs(), 0).unwrap_or_else(|| chrono::Utc::now());
                let days_since_use = (chrono::Utc::now() - password_date).num_days();
                if days_since_use > 90 {
                    vulnerabilities.push(self.create_vulnerability(
                        "CIS 1.3 - Inactive IAM Credentials",
                        Severity::Medium,
                        Confidence::High,
                        format!("IAM user '{}' credentials unused for {} days", user_name, days_since_use),
                        format!("User: {}, Days Inactive: {}", user_name, days_since_use),
                        "Disable or remove credentials that have been inactive for 90 days or more",
                        "CIS AWS Foundations Benchmark v1.4 - Control 1.3",
                        5.0,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_access_key_rotation(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let users = client
            .list_users()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to list users: {}", e)))?;

        for user in users.users() {
            let user_name = user.user_name();

            metrics.record_api_call();
            let access_keys = client
                .list_access_keys()
                .user_name(user_name)
                .send()
                .await
                .map_err(|e| CloudError::ApiError(format!("Failed to list access keys: {}", e)))?;

            for key in access_keys.access_key_metadata() {
                if let Some(create_date) = key.create_date() {
                    let create_date_dt = chrono::DateTime::from_timestamp(create_date.secs(), 0).unwrap_or_else(|| chrono::Utc::now());
                    let days_old = (chrono::Utc::now() - create_date_dt).num_days();
                    if days_old > 90 {
                        vulnerabilities.push(self.create_vulnerability(
                            "CIS 1.4 - Access Key Not Rotated",
                            Severity::Medium,
                            Confidence::High,
                            format!("Access key for user '{}' is {} days old and should be rotated", user_name, days_old),
                            format!("User: {}, Key ID: {}, Age: {} days", user_name, key.access_key_id().unwrap_or("unknown"), days_old),
                            "Rotate access keys every 90 days or less",
                            "CIS AWS Foundations Benchmark v1.4 - Control 1.4",
                            5.5,
                        ));
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_cloudtrail_enabled(
        &self,
        _aws_config: &aws_config::SdkConfig,
        _metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        // Note: This requires CloudTrail API access
        // For production implementation
        Ok(vec![])
    }

    async fn check_cloudtrail_s3_public(
        &self,
        _aws_config: &aws_config::SdkConfig,
        _metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        // Note: This requires S3 bucket policy analysis
        // For production implementation
        Ok(vec![])
    }

    async fn check_cloudwatch_alarms(
        &self,
        _aws_config: &aws_config::SdkConfig,
        _metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        // Note: This requires CloudWatch API access
        // For production implementation
        Ok(vec![])
    }

    async fn check_ssh_unrestricted(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let sg_result = client
            .describe_security_groups()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to describe security groups: {}", e)))?;

        if let Some(security_groups) = sg_result.security_groups {
            for sg in security_groups {
                for permission in sg.ip_permissions() {
                    let from_port = permission.from_port().unwrap_or(0);
                    let to_port = permission.to_port().unwrap_or(65535);

                    if from_port <= 22 && to_port >= 22 {
                        for ip_range in permission.ip_ranges() {
                            if ip_range.cidr_ip() == Some("0.0.0.0/0") {
                                vulnerabilities.push(self.create_vulnerability(
                                    "CIS 4.1 - SSH Port Open to Internet",
                                    Severity::Critical,
                                    Confidence::High,
                                    format!("Security group '{}' allows SSH (port 22) from 0.0.0.0/0",
                                           sg.group_name().unwrap_or("unknown")),
                                    format!("Security Group: {} ({})",
                                           sg.group_name().unwrap_or("unknown"),
                                           sg.group_id().unwrap_or("unknown")),
                                    "Restrict SSH access to specific IP addresses or use a bastion host",
                                    "CIS AWS Foundations Benchmark v1.4 - Control 4.1",
                                    9.8,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_rdp_unrestricted(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let sg_result = client
            .describe_security_groups()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to describe security groups: {}", e)))?;

        if let Some(security_groups) = sg_result.security_groups {
            for sg in security_groups {
                for permission in sg.ip_permissions() {
                    let from_port = permission.from_port().unwrap_or(0);
                    let to_port = permission.to_port().unwrap_or(65535);

                    if from_port <= 3389 && to_port >= 3389 {
                        for ip_range in permission.ip_ranges() {
                            if ip_range.cidr_ip() == Some("0.0.0.0/0") {
                                vulnerabilities.push(self.create_vulnerability(
                                    "CIS 4.2 - RDP Port Open to Internet",
                                    Severity::Critical,
                                    Confidence::High,
                                    format!("Security group '{}' allows RDP (port 3389) from 0.0.0.0/0",
                                           sg.group_name().unwrap_or("unknown")),
                                    format!("Security Group: {} ({})",
                                           sg.group_name().unwrap_or("unknown"),
                                           sg.group_id().unwrap_or("unknown")),
                                    "Restrict RDP access to specific IP addresses or use a bastion host",
                                    "CIS AWS Foundations Benchmark v1.4 - Control 4.2",
                                    9.8,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Run CIS Azure Foundations Benchmark v1.4
    pub async fn scan_cis_azure_foundations(&self) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting CIS Azure Foundations Benchmark v1.4 scan");

        // Note: Placeholder for Azure compliance checks
        warn!("Azure compliance scanning requires Azure credentials configuration");

        Ok(vec![])
    }

    /// Run CIS GCP Foundations Benchmark v1.3
    pub async fn scan_cis_gcp_foundations(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting CIS GCP Foundations Benchmark v1.3 scan for project: {}", project_id);

        // Note: Placeholder for GCP compliance checks
        warn!("GCP compliance scanning requires GCP credentials configuration");

        Ok(vec![])
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
            id: format!("compliance_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud Compliance".to_string(),
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

impl Default for CloudComplianceScanner {
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
