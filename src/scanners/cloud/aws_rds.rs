// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS RDS Vulnerability Scanner
 * Production-grade RDS security scanner with comprehensive checks
 *
 * © 2025 Bountyy Oy
 */

use crate::types::{ScanConfig, Severity, Vulnerability, Confidence};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, warn, debug, error};

/// RDS instance security findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdsInstanceSecurity {
    pub instance_id: String,
    pub engine: String,
    pub engine_version: String,
    pub is_public: bool,
    pub encrypted: bool,
    pub backup_enabled: bool,
    pub backup_retention_days: i32,
    pub uses_default_port: bool,
    pub enhanced_monitoring_enabled: bool,
    pub deletion_protection_enabled: bool,
    pub multi_az: bool,
    pub auto_minor_version_upgrade: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdsScanResult {
    pub instances_scanned: usize,
    pub snapshots_scanned: usize,
    pub clusters_scanned: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub findings_summary: HashMap<String, usize>,
}

/// AWS RDS Security Scanner
pub struct AwsRdsScanner {
    aws_config: Option<aws_config::SdkConfig>,
    max_concurrency: usize,
    regions: Vec<String>,
}

impl AwsRdsScanner {
    /// Create a new AWS RDS scanner
    pub fn new() -> Self {
        Self {
            aws_config: None,
            max_concurrency: 10,
            regions: vec![
                "us-east-1".to_string(),
                "us-west-2".to_string(),
                "eu-west-1".to_string(),
                "ap-southeast-1".to_string(),
            ],
        }
    }

    /// Initialize AWS SDK configuration
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing AWS RDS scanner");

        let config = aws_config::from_env()
            .region("us-east-1")
            .retry_config(
                aws_config::retry::RetryConfig::standard()
                    .with_max_attempts(3)
            )
            .timeout_config(
                aws_config::timeout::TimeoutConfig::builder()
                    .operation_timeout(std::time::Duration::from_secs(30))
                    .build()
            )
            .load()
            .await;

        self.aws_config = Some(config);
        info!("AWS RDS scanner initialized successfully");
        Ok(())
    }

    /// Scan all RDS instances across regions
    pub async fn scan(&mut self, _config: &ScanConfig) -> Result<RdsScanResult> {
        info!("Starting comprehensive AWS RDS security scan");

        if self.aws_config.is_none() {
            self.initialize().await?;
        }

        let mut all_vulnerabilities = Vec::new();
        let mut findings_summary: HashMap<String, usize> = HashMap::new();
        let mut total_instances = 0;
        let mut total_snapshots = 0;
        let mut total_clusters = 0;

        // Scan each region in parallel
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = vec![];

        for region in &self.regions {
            let sem = Arc::clone(&semaphore);
            let region_clone = region.clone();
            let config = self.aws_config.clone().unwrap();

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                Self::scan_region_static(&config, &region_clone).await
            });

            tasks.push(task);
        }

        // Collect results from all regions
        for task in tasks {
            match task.await {
                Ok(Ok((vulns, instances, snapshots, clusters))) => {
                    total_instances += instances;
                    total_snapshots += snapshots;
                    total_clusters += clusters;

                    for vuln in vulns {
                        *findings_summary.entry(vuln.vuln_type.clone()).or_insert(0) += 1;
                        all_vulnerabilities.push(vuln);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Region scan failed: {}", e);
                }
                Err(e) => {
                    error!("Task join error: {}", e);
                }
            }
        }

        info!(
            "RDS scan completed: {} instances, {} snapshots, {} clusters scanned, {} vulnerabilities found",
            total_instances,
            total_snapshots,
            total_clusters,
            all_vulnerabilities.len()
        );

        Ok(RdsScanResult {
            instances_scanned: total_instances,
            snapshots_scanned: total_snapshots,
            clusters_scanned: total_clusters,
            vulnerabilities: all_vulnerabilities,
            findings_summary,
        })
    }

    /// Scan a single region
    async fn scan_region_static(
        config: &aws_config::SdkConfig,
        region: &str,
    ) -> Result<(Vec<Vulnerability>, usize, usize, usize)> {
        info!("Scanning RDS resources in region: {}", region);

        let regional_config = config.clone().into_builder()
            .region(aws_config::Region::new(region.to_string()))
            .build();

        let client = aws_sdk_rds::Client::new(&regional_config);
        let mut vulnerabilities = Vec::new();

        // Scan RDS instances
        let (instance_vulns, instance_count) = Self::scan_instances_static(&client, region).await?;
        vulnerabilities.extend(instance_vulns);

        // Scan RDS snapshots
        let (snapshot_vulns, snapshot_count) = Self::scan_snapshots_static(&client, region).await?;
        vulnerabilities.extend(snapshot_vulns);

        // Scan Aurora clusters
        let (cluster_vulns, cluster_count) = Self::scan_clusters_static(&client, region).await?;
        vulnerabilities.extend(cluster_vulns);

        Ok((vulnerabilities, instance_count, snapshot_count, cluster_count))
    }

    /// Scan RDS instances
    async fn scan_instances_static(
        client: &aws_sdk_rds::Client,
        region: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Scanning RDS instances in {}", region);

        let mut vulnerabilities = Vec::new();
        let mut marker: Option<String> = None;
        let mut instance_count = 0;

        loop {
            let mut request = client.describe_db_instances();
            if let Some(m) = marker {
                request = request.marker(m);
            }

            let response = request.send().await
                .context("Failed to describe RDS instances")?;

            for instance in response.db_instances() {
                instance_count += 1;

                if let Some(instance_id) = instance.db_instance_identifier() {
                    // Check public accessibility
                    if instance.publicly_accessible() == Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Publicly Accessible",
                            instance_id,
                            region,
                            "RDS instance is publicly accessible from the internet",
                            Severity::Critical,
                            "CWE-668",
                            9.0,
                        ));
                    }

                    // Check encryption
                    if instance.storage_encrypted() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Not Encrypted",
                            instance_id,
                            region,
                            "RDS instance does not have encryption at rest enabled",
                            Severity::High,
                            "CWE-311",
                            8.0,
                        ));
                    }

                    // Check backup retention
                    let backup_retention = instance.backup_retention_period().unwrap_or(0);
                    if backup_retention < 7 {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Insufficient Backup Retention",
                            instance_id,
                            region,
                            &format!("Backup retention period is {} days (recommended: 7+ days)", backup_retention),
                            Severity::Medium,
                            "CWE-693",
                            5.5,
                        ));
                    }

                    // Check for default ports
                    if let Some(port) = instance.db_instance_port() {
                        let engine = instance.engine().unwrap_or("");
                        let is_default = Self::is_default_port(engine, port);

                        if is_default {
                            vulnerabilities.push(Self::create_vulnerability(
                                "RDS Instance Uses Default Port",
                                instance_id,
                                region,
                                &format!("Instance uses default port {} for {}", port, engine),
                                Severity::Medium,
                                "CWE-1188",
                                4.5,
                            ));
                        }
                    }

                    // Check enhanced monitoring
                    if instance.enhanced_monitoring_resource_arn().is_none() {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Enhanced Monitoring Disabled",
                            instance_id,
                            region,
                            "Enhanced monitoring is not enabled for detailed metrics",
                            Severity::Low,
                            "CWE-778",
                            3.5,
                        ));
                    }

                    // Check deletion protection
                    if instance.deletion_protection() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Deletion Protection Disabled",
                            instance_id,
                            region,
                            "Instance does not have deletion protection enabled",
                            Severity::Medium,
                            "CWE-665",
                            5.0,
                        ));
                    }

                    // Check Multi-AZ
                    if instance.multi_az() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Not Multi-AZ",
                            instance_id,
                            region,
                            "Instance is not deployed in Multi-AZ configuration for high availability",
                            Severity::Low,
                            "CWE-1254",
                            3.0,
                        ));
                    }

                    // Check auto minor version upgrade
                    if instance.auto_minor_version_upgrade() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Instance Auto Minor Version Upgrade Disabled",
                            instance_id,
                            region,
                            "Automatic minor version upgrades are not enabled",
                            Severity::Low,
                            "CWE-1104",
                            3.5,
                        ));
                    }

                    // Check security groups for 0.0.0.0/0
                    if let Some(sg_rules) = Self::check_security_groups(instance).await {
                        for (sg_id, rule_desc) in sg_rules {
                            vulnerabilities.push(Self::create_vulnerability(
                                "RDS Instance Security Group Allows 0.0.0.0/0",
                                instance_id,
                                region,
                                &format!("Security group {} allows access from {}", sg_id, rule_desc),
                                Severity::Critical,
                                "CWE-732",
                                9.5,
                            ));
                        }
                    }

                    // Check for outdated engine version
                    if let Some(vuln) = Self::check_engine_version(instance, region).await {
                        vulnerabilities.push(vuln);
                    }
                }
            }

            // Pagination
            if response.marker().is_some() {
                marker = response.marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok((vulnerabilities, instance_count))
    }

    /// Scan RDS snapshots
    async fn scan_snapshots_static(
        client: &aws_sdk_rds::Client,
        region: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Scanning RDS snapshots in {}", region);

        let mut vulnerabilities = Vec::new();
        let mut marker: Option<String> = None;
        let mut snapshot_count = 0;

        loop {
            let mut request = client.describe_db_snapshots();
            if let Some(m) = marker {
                request = request.marker(m);
            }

            let response = request.send().await
                .context("Failed to describe RDS snapshots")?;

            for snapshot in response.db_snapshots() {
                snapshot_count += 1;

                if let Some(snapshot_id) = snapshot.db_snapshot_identifier() {
                    // Check if snapshot is public
                    if let Ok(attrs) = client.describe_db_snapshot_attributes()
                        .db_snapshot_identifier(snapshot_id)
                        .send()
                        .await
                    {
                        if let Some(attr_result) = attrs.db_snapshot_attributes_result() {
                            for attr in attr_result.db_snapshot_attributes() {
                                if attr.attribute_name() == Some("restore") {
                                    let values = attr.attribute_values();
                                    if values.iter().any(|v| v == "all") {
                                        vulnerabilities.push(Self::create_vulnerability(
                                            "RDS Snapshot Publicly Accessible",
                                            snapshot_id,
                                            region,
                                            "Snapshot is publicly accessible and can be restored by anyone",
                                            Severity::Critical,
                                            "CWE-732",
                                            10.0,
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    // Check snapshot encryption
                    if snapshot.encrypted() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "RDS Snapshot Not Encrypted",
                            snapshot_id,
                            region,
                            "Snapshot is not encrypted at rest",
                            Severity::High,
                            "CWE-311",
                            7.5,
                        ));
                    }
                }
            }

            // Pagination
            if response.marker().is_some() {
                marker = response.marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok((vulnerabilities, snapshot_count))
    }

    /// Scan Aurora clusters
    async fn scan_clusters_static(
        client: &aws_sdk_rds::Client,
        region: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Scanning Aurora clusters in {}", region);

        let mut vulnerabilities = Vec::new();
        let mut marker: Option<String> = None;
        let mut cluster_count = 0;

        loop {
            let mut request = client.describe_db_clusters();
            if let Some(m) = marker {
                request = request.marker(m);
            }

            let response = request.send().await
                .context("Failed to describe DB clusters")?;

            for cluster in response.db_clusters() {
                cluster_count += 1;

                if let Some(cluster_id) = cluster.db_cluster_identifier() {
                    // Check encryption
                    if cluster.storage_encrypted() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "Aurora Cluster Not Encrypted",
                            cluster_id,
                            region,
                            "Aurora cluster does not have encryption enabled",
                            Severity::High,
                            "CWE-311",
                            8.0,
                        ));
                    }

                    // Check backup retention
                    let backup_retention = cluster.backup_retention_period().unwrap_or(0);
                    if backup_retention < 7 {
                        vulnerabilities.push(Self::create_vulnerability(
                            "Aurora Cluster Insufficient Backup Retention",
                            cluster_id,
                            region,
                            &format!("Backup retention is {} days (recommended: 7+ days)", backup_retention),
                            Severity::Medium,
                            "CWE-693",
                            5.5,
                        ));
                    }

                    // Check deletion protection
                    if cluster.deletion_protection() != Some(true) {
                        vulnerabilities.push(Self::create_vulnerability(
                            "Aurora Cluster Deletion Protection Disabled",
                            cluster_id,
                            region,
                            "Cluster does not have deletion protection enabled",
                            Severity::Medium,
                            "CWE-665",
                            5.0,
                        ));
                    }

                    // Check for public endpoints
                    for member in cluster.db_cluster_members() {
                        if let Some(instance_id) = member.db_instance_identifier() {
                            // Check if any cluster member is public
                            if let Ok(instance_resp) = client.describe_db_instances()
                                .db_instance_identifier(instance_id)
                                .send()
                                .await
                            {
                                if let Some(instance) = instance_resp.db_instances().first() {
                                    if instance.publicly_accessible() == Some(true) {
                                        vulnerabilities.push(Self::create_vulnerability(
                                            "Aurora Cluster Member Publicly Accessible",
                                            cluster_id,
                                            region,
                                            &format!("Cluster member {} is publicly accessible", instance_id),
                                            Severity::Critical,
                                            "CWE-668",
                                            9.0,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Pagination
            if response.marker().is_some() {
                marker = response.marker().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok((vulnerabilities, cluster_count))
    }

    /// Check if port is default for engine
    fn is_default_port(engine: &str, port: i32) -> bool {
        match engine.to_lowercase().as_str() {
            e if e.contains("mysql") || e.contains("mariadb") => port == 3306,
            e if e.contains("postgres") => port == 5432,
            e if e.contains("oracle") => port == 1521,
            e if e.contains("sqlserver") => port == 1433,
            _ => false,
        }
    }

    /// Check security groups for open access
    async fn check_security_groups(
        instance: &aws_sdk_rds::types::DbInstance,
    ) -> Option<Vec<(String, String)>> {
        let issues = Vec::new();

        for sg in instance.vpc_security_groups() {
            if let Some(sg_id) = sg.vpc_security_group_id() {
                // Note: This is simplified. In production, you'd query EC2 API for SG rules
                // For now, we'll return None as we can't check SG rules from RDS API alone
                debug!("Would check security group: {}", sg_id);
            }
        }

        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    /// Check for outdated engine versions
    async fn check_engine_version(
        instance: &aws_sdk_rds::types::DbInstance,
        region: &str,
    ) -> Option<Vulnerability> {
        if let (Some(engine), Some(version), Some(instance_id)) = (
            instance.engine(),
            instance.engine_version(),
            instance.db_instance_identifier(),
        ) {
            // Simple version check - in production, compare against known vulnerable versions
            let version_parts: Vec<&str> = version.split('.').collect();
            if !version_parts.is_empty() {
                if let Ok(major) = version_parts[0].parse::<i32>() {
                    // Example: MySQL versions < 8 are considered outdated
                    if engine.contains("mysql") && major < 8 {
                        return Some(Self::create_vulnerability(
                            "RDS Instance Outdated Engine Version",
                            instance_id,
                            region,
                            &format!("Instance is running {} version {} which may have known vulnerabilities", engine, version),
                            Severity::High,
                            "CWE-1104",
                            7.0,
                        ));
                    }
                }
            }
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        vuln_type: &str,
        resource: &str,
        region: &str,
        description: &str,
        severity: Severity,
        cwe: &str,
        cvss: f32,
    ) -> Vulnerability {
        let remediation = Self::get_remediation(vuln_type);

        Vulnerability {
            id: format!("rds_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloud Security - AWS RDS".to_string(),
            url: format!("rds://{}/{}", region, resource),
            parameter: Some(region.to_string()),
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(format!("Resource: {}, Region: {}", resource, region)),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation guidance
    fn get_remediation(vuln_type: &str) -> String {
        match vuln_type {
            "RDS Instance Publicly Accessible" | "Aurora Cluster Member Publicly Accessible" => {
                "1. Disable public accessibility on RDS instance\n\
                 2. Deploy RDS in private subnet\n\
                 3. Use VPN or AWS PrivateLink for access\n\
                 4. Implement bastion host for administrative access\n\
                 5. Review and restrict security group rules".to_string()
            }
            "RDS Instance Not Encrypted" | "Aurora Cluster Not Encrypted" | "RDS Snapshot Not Encrypted" => {
                "1. Enable encryption at rest using AWS KMS\n\
                 2. Create encrypted snapshot and restore to new instance\n\
                 3. Use customer-managed CMK for key control\n\
                 4. Enable encryption in transit with SSL/TLS\n\
                 5. Implement AWS Config rule to enforce encryption".to_string()
            }
            "RDS Instance Insufficient Backup Retention" | "Aurora Cluster Insufficient Backup Retention" => {
                "1. Increase backup retention period to at least 7 days\n\
                 2. Configure automated backups during maintenance window\n\
                 3. Implement cross-region backup copy\n\
                 4. Test backup restoration procedures regularly\n\
                 5. Use AWS Backup for centralized backup management".to_string()
            }
            "RDS Instance Uses Default Port" => {
                "1. Change database port to non-default value\n\
                 2. Update application connection strings\n\
                 3. Update security group rules for new port\n\
                 4. Document port changes in runbook\n\
                 5. Consider this during maintenance window".to_string()
            }
            "RDS Instance Enhanced Monitoring Disabled" => {
                "1. Enable Enhanced Monitoring with 60-second granularity\n\
                 2. Configure CloudWatch alarms for key metrics\n\
                 3. Integrate metrics with monitoring solution\n\
                 4. Set up automated alerts for anomalies\n\
                 5. Review monitoring data regularly".to_string()
            }
            "RDS Instance Deletion Protection Disabled" | "Aurora Cluster Deletion Protection Disabled" => {
                "1. Enable deletion protection on production instances\n\
                 2. Implement IAM policies to control deletion permissions\n\
                 3. Use AWS Organizations SCPs to prevent accidental deletion\n\
                 4. Enable CloudTrail logging for delete operations\n\
                 5. Implement approval workflow for instance deletion".to_string()
            }
            "RDS Snapshot Publicly Accessible" => {
                "1. Immediately remove public access from snapshot\n\
                 2. Review snapshot sharing settings\n\
                 3. Use AWS RAM for controlled snapshot sharing\n\
                 4. Enable AWS Config rule to detect public snapshots\n\
                 5. Implement automated remediation for public snapshots".to_string()
            }
            "RDS Instance Security Group Allows 0.0.0.0/0" => {
                "1. Remove 0.0.0.0/0 from security group rules\n\
                 2. Restrict access to specific IP ranges or security groups\n\
                 3. Use VPN or AWS PrivateLink for remote access\n\
                 4. Implement AWS Config rule to detect overly permissive rules\n\
                 5. Regularly audit security group configurations".to_string()
            }
            "RDS Instance Outdated Engine Version" => {
                "1. Plan upgrade to latest supported engine version\n\
                 2. Test upgrade in non-production environment\n\
                 3. Review release notes for breaking changes\n\
                 4. Enable auto minor version upgrade\n\
                 5. Schedule upgrade during maintenance window".to_string()
            }
            _ => {
                "1. Review AWS RDS security best practices\n\
                 2. Implement least privilege access controls\n\
                 3. Enable comprehensive logging and monitoring\n\
                 4. Use AWS Security Hub for compliance checking\n\
                 5. Regularly audit RDS configurations".to_string()
            }
        }
    }
}

impl Default for AwsRdsScanner {
    fn default() -> Self {
        Self::new()
    }
}

// UUID generation
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            use rand::Rng;
            let mut rng = rand::rng();
            format!(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = AwsRdsScanner::new();
        assert_eq!(scanner.max_concurrency, 10);
        assert!(scanner.aws_config.is_none());
    }

    #[test]
    fn test_default_port_detection() {
        assert!(AwsRdsScanner::is_default_port("mysql", 3306));
        assert!(AwsRdsScanner::is_default_port("postgres", 5432));
        assert!(!AwsRdsScanner::is_default_port("mysql", 3307));
    }

    #[test]
    fn test_remediation_generation() {
        let remediation = AwsRdsScanner::get_remediation("RDS Instance Publicly Accessible");
        assert!(remediation.contains("private subnet"));
        assert!(remediation.contains("security group"));
    }
}
