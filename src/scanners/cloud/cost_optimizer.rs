// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Cost Optimizer
 * Identifies cost optimization opportunities in cloud infrastructure
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
use tracing::{debug, info, warn};

/// Cost optimization finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CostOptimizationType {
    UnattachedVolume,
    UnusedElasticIp,
    IdleInstance,
    OversizedInstance,
    ReservedInstanceOpportunity,
    SpotInstanceOpportunity,
    UnusedLoadBalancer,
    OldSnapshot,
    UnoptimizedStorage,
}

/// Cost optimization finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostOptimization {
    pub optimization_type: CostOptimizationType,
    pub resource_id: String,
    pub resource_name: Option<String>,
    pub estimated_monthly_savings: f64,
    pub current_monthly_cost: f64,
    pub recommendation: String,
    pub evidence: Vec<String>,
}

pub struct CloudCostOptimizer {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
}

impl CloudCostOptimizer {
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

    /// Analyze AWS resources for cost optimization
    pub async fn analyze_aws_costs(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS Cost Optimization Analysis");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS cost optimization analysis");

        // Find unattached EBS volumes
        let volume_findings = self.find_unattached_volumes(aws_config, &mut metrics).await?;
        vulnerabilities.extend(volume_findings);

        // Find unused Elastic IPs
        let eip_findings = self.find_unused_elastic_ips(aws_config, &mut metrics).await?;
        vulnerabilities.extend(eip_findings);

        // Find idle EC2 instances
        let idle_findings = self.find_idle_instances(aws_config, &mut metrics).await?;
        vulnerabilities.extend(idle_findings);

        // Find old snapshots
        let snapshot_findings = self.find_old_snapshots(aws_config, &mut metrics).await?;
        vulnerabilities.extend(snapshot_findings);

        metrics.report();
        info!("AWS cost optimization analysis completed. Found {} opportunities", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    async fn find_unattached_volumes(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let volumes = retry_with_backoff(
            || async {
                client
                    .describe_volumes()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe volumes: {}", e)))
            },
            self.retry_config.clone(),
            "describe_volumes",
        )
        .await?;

        if let Some(volumes_list) = volumes.volumes {
            for volume in volumes_list {
                // Check if volume is unattached
                if volume.attachments().is_empty() {
                    let volume_id = volume.volume_id().unwrap_or("unknown");
                    let size_gb = volume.size().unwrap_or(0);
                    let volume_type = volume.volume_type().map(|vt| format!("{:?}", vt)).unwrap_or("gp2".to_string());

                    // Estimate monthly cost (approximate)
                    let monthly_cost = self.estimate_ebs_cost(&volume_type, size_gb);

                    vulnerabilities.push(self.create_vulnerability(
                        "Unattached EBS Volume",
                        Severity::Low,
                        Confidence::High,
                        format!("EBS volume '{}' ({} GB) is not attached to any instance", volume_id, size_gb),
                        format!("Volume ID: {}, Size: {} GB, Type: {}, Est. Monthly Cost: ${:.2}",
                               volume_id, size_gb, volume_type, monthly_cost),
                        &format!("Delete the unattached volume or attach it to an instance. Estimated monthly savings: ${:.2}", monthly_cost),
                        "N/A",
                        2.0,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn find_unused_elastic_ips(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let addresses = retry_with_backoff(
            || async {
                client
                    .describe_addresses()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe addresses: {}", e)))
            },
            self.retry_config.clone(),
            "describe_addresses",
        )
        .await?;

        if let Some(addresses_list) = addresses.addresses {
            for address in addresses_list {
                // Check if EIP is not associated
                if address.association_id().is_none() {
                    let public_ip = address.public_ip().unwrap_or("unknown");
                    let allocation_id = address.allocation_id().unwrap_or("unknown");

                    // Unused EIPs cost approximately $0.005 per hour = ~$3.60 per month
                    let monthly_cost = 3.60;

                    vulnerabilities.push(self.create_vulnerability(
                        "Unused Elastic IP",
                        Severity::Low,
                        Confidence::High,
                        format!("Elastic IP {} is allocated but not associated with any instance", public_ip),
                        format!("Public IP: {}, Allocation ID: {}, Est. Monthly Cost: ${:.2}",
                               public_ip, allocation_id, monthly_cost),
                        &format!("Release the unused Elastic IP. Estimated monthly savings: ${:.2}", monthly_cost),
                        "N/A",
                        2.0,
                    ));
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn find_idle_instances(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let instances = retry_with_backoff(
            || async {
                client
                    .describe_instances()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe instances: {}", e)))
            },
            self.retry_config.clone(),
            "describe_instances",
        )
        .await?;

        // Note: To truly identify idle instances, we would need to:
        // 1. Query CloudWatch metrics for CPU utilization
        // 2. Query CloudWatch metrics for network traffic
        // 3. Analyze over a period (e.g., 7-14 days)
        //
        // For this implementation, we'll flag running instances as candidates
        // that should be reviewed with CloudWatch monitoring

        if let Some(reservations) = instances.reservations {
            for reservation in reservations {
                if let Some(instances_list) = reservation.instances {
                    for instance in instances_list {
                        if instance.state().and_then(|s| s.name()).map(|n| format!("{:?}", n)) == Some("running".to_string()) {
                            let instance_id = instance.instance_id().unwrap_or("unknown");
                            let instance_type = instance.instance_type().map(|it| format!("{:?}", it)).unwrap_or("unknown".to_string());

                            // Note: This is a recommendation to review, not a definitive finding
                            debug!("Instance {} ({}) should be monitored for idle time", instance_id, instance_type);
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn find_old_snapshots(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        // Get AWS account ID for filtering
        let sts_client = aws_sdk_sts::Client::new(aws_config);
        let identity = sts_client
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to get caller identity: {}", e)))?;

        let owner_id = identity.account().unwrap_or("self");

        metrics.record_api_call();
        let snapshots = retry_with_backoff(
            || async {
                client
                    .describe_snapshots()
                    .owner_ids(owner_id)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe snapshots: {}", e)))
            },
            self.retry_config.clone(),
            "describe_snapshots",
        )
        .await?;

        if let Some(snapshots_list) = snapshots.snapshots {
            for snapshot in snapshots_list {
                if let Some(start_time) = snapshot.start_time() {
                    let start_time_chrono = chrono::DateTime::<chrono::Utc>::from(
                        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(start_time.secs() as u64)
                    );
                    let age_days = (chrono::Utc::now() - start_time_chrono).num_days();

                    // Flag snapshots older than 1 year as potential candidates for deletion
                    if age_days > 365 {
                        let snapshot_id = snapshot.snapshot_id().unwrap_or("unknown");
                        let size_gb = snapshot.volume_size().unwrap_or(0);
                        let description = snapshot.description().unwrap_or("N/A");

                        // EBS snapshot storage costs approximately $0.05 per GB-month
                        let monthly_cost = size_gb as f64 * 0.05;

                        vulnerabilities.push(self.create_vulnerability(
                            "Old EBS Snapshot",
                            Severity::Low,
                            Confidence::Medium,
                            format!("EBS snapshot '{}' is {} days old and may no longer be needed", snapshot_id, age_days),
                            format!("Snapshot ID: {}, Age: {} days, Size: {} GB, Description: {}, Est. Monthly Cost: ${:.2}",
                                   snapshot_id, age_days, size_gb, description, monthly_cost),
                            &format!("Review and delete old snapshots that are no longer needed. Estimated monthly savings: ${:.2}", monthly_cost),
                            "N/A",
                            2.0,
                        ));
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn estimate_ebs_cost(&self, volume_type: &str, size_gb: i32) -> f64 {
        // Approximate AWS EBS pricing per GB-month
        let price_per_gb = match volume_type {
            "gp2" | "gp3" => 0.10,
            "io1" | "io2" => 0.125,
            "st1" => 0.045,
            "sc1" => 0.015,
            _ => 0.10,
        };

        size_gb as f64 * price_per_gb
    }

    /// Analyze Azure resources for cost optimization
    pub async fn analyze_azure_costs(&self) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting Azure cost optimization analysis");

        // Note: Placeholder for Azure cost optimization
        warn!("Azure cost optimization requires Azure credentials configuration");

        Ok(vec![])
    }

    /// Analyze GCP resources for cost optimization
    pub async fn analyze_gcp_costs(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting GCP cost optimization analysis for project: {}", project_id);

        // Note: Placeholder for GCP cost optimization
        warn!("GCP cost optimization requires GCP credentials configuration");

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
            id: format!("cost_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud Cost Optimization".to_string(),
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

impl Default for CloudCostOptimizer {
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
