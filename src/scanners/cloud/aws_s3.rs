// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS S3 Vulnerability Scanner
 * Production-grade S3 security scanner with comprehensive checks
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

/// S3 bucket configuration and security findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BucketSecurity {
    pub bucket_name: String,
    pub region: String,
    pub is_public: bool,
    pub has_encryption: bool,
    pub encryption_type: Option<String>,
    pub versioning_enabled: bool,
    pub mfa_delete_enabled: bool,
    pub logging_enabled: bool,
    pub replication_enabled: bool,
    pub lifecycle_configured: bool,
    pub public_acl_blocked: bool,
    pub public_policy_blocked: bool,
    pub restrict_public_buckets: bool,
    pub ignore_public_acls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3ObjectPermissions {
    pub key: String,
    pub is_public: bool,
    pub acl: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3ScanResult {
    pub buckets_scanned: usize,
    pub vulnerabilities: Vec<Vulnerability>,
    pub findings_summary: HashMap<String, usize>,
}

/// AWS S3 Security Scanner
pub struct AwsS3Scanner {
    aws_config: Option<aws_config::SdkConfig>,
    max_concurrency: usize,
    regions: Vec<String>,
}

impl AwsS3Scanner {
    /// Create a new AWS S3 scanner
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
        info!("Initializing AWS S3 scanner");

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
        info!("AWS S3 scanner initialized successfully");
        Ok(())
    }

    /// Scan all S3 buckets for vulnerabilities
    pub async fn scan(&mut self, _config: &ScanConfig) -> Result<S3ScanResult> {
        info!("Starting comprehensive AWS S3 security scan");

        if self.aws_config.is_none() {
            self.initialize().await?;
        }

        let config = self.aws_config.as_ref().unwrap();
        let client = aws_sdk_s3::Client::new(config);

        let mut all_vulnerabilities = Vec::new();
        let mut findings_summary: HashMap<String, usize> = HashMap::new();

        // List all S3 buckets
        let buckets = self.list_all_buckets(&client).await?;
        info!("Found {} S3 buckets to scan", buckets.len());

        // Scan buckets with controlled concurrency
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = vec![];

        for bucket_name in buckets {
            let sem = Arc::clone(&semaphore);
            let client_clone = client.clone();
            let bucket = bucket_name.clone();

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                Self::scan_bucket_static(&client_clone, &bucket).await
            });

            tasks.push(task);
        }

        // Collect results
        let mut buckets_scanned = 0;
        for task in tasks {
            match task.await {
                Ok(Ok(vulns)) => {
                    buckets_scanned += 1;
                    for vuln in vulns {
                        // Update summary
                        *findings_summary.entry(vuln.vuln_type.clone()).or_insert(0) += 1;
                        all_vulnerabilities.push(vuln);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Bucket scan failed: {}", e);
                }
                Err(e) => {
                    error!("Task join error: {}", e);
                }
            }
        }

        info!(
            "S3 scan completed: {} buckets scanned, {} vulnerabilities found",
            buckets_scanned,
            all_vulnerabilities.len()
        );

        Ok(S3ScanResult {
            buckets_scanned,
            vulnerabilities: all_vulnerabilities,
            findings_summary,
        })
    }

    /// List all S3 buckets
    async fn list_all_buckets(&self, client: &aws_sdk_s3::Client) -> Result<Vec<String>> {
        debug!("Listing all S3 buckets");

        let response = client.list_buckets()
            .send()
            .await
            .context("Failed to list S3 buckets")?;

        let buckets = response.buckets()
            .iter()
            .filter_map(|b| b.name().map(|n| n.to_string()))
            .collect();

        Ok(buckets)
    }

    /// Scan a single bucket for vulnerabilities (static version for async tasks)
    async fn scan_bucket_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
    ) -> Result<Vec<Vulnerability>> {
        debug!("Scanning bucket: {}", bucket_name);

        let mut vulnerabilities = Vec::new();

        // Get bucket location
        let region = match Self::get_bucket_region_static(client, bucket_name).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to get region for bucket {}: {}", bucket_name, e);
                "unknown".to_string()
            }
        };

        // Check public access
        if let Some(vuln) = Self::check_public_access_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check bucket ACL
        if let Some(vuln) = Self::check_bucket_acl_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check bucket policy
        if let Some(vuln) = Self::check_bucket_policy_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check encryption
        if let Some(vuln) = Self::check_encryption_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check versioning
        if let Some(vuln) = Self::check_versioning_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check logging
        if let Some(vuln) = Self::check_logging_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check MFA delete
        if let Some(vuln) = Self::check_mfa_delete_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check replication
        if let Some(vuln) = Self::check_replication_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check public access block
        if let Some(vuln) = Self::check_public_access_block_static(client, bucket_name, &region).await {
            vulnerabilities.push(vuln);
        }

        // Check object-level permissions (sample)
        if let Some(vulns) = Self::check_object_permissions_static(client, bucket_name, &region).await {
            vulnerabilities.extend(vulns);
        }

        Ok(vulnerabilities)
    }

    /// Get bucket region
    async fn get_bucket_region_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
    ) -> Result<String> {
        let response = client.get_bucket_location()
            .bucket(bucket_name)
            .send()
            .await?;

        let region = response.location_constraint()
            .map(|lc| lc.as_str().to_string())
            .unwrap_or_else(|| "us-east-1".to_string());

        Ok(region)
    }

    /// Check if bucket has public access
    async fn check_public_access_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_acl().bucket(bucket_name).send().await {
            Ok(response) => {
                let is_public = response.grants()
                    .iter()
                    .any(|grant| {
                        grant.grantee()
                            .and_then(|g| g.uri())
                            .map(|uri| uri.contains("AllUsers") || uri.contains("AuthenticatedUsers"))
                            .unwrap_or(false)
                    });

                if is_public {
                    Some(Self::create_vulnerability(
                        "S3 Bucket Publicly Accessible",
                        bucket_name,
                        region,
                        "Bucket has public read or write access via ACL",
                        Severity::Critical,
                        "CWE-732",
                        9.5,
                    ))
                } else {
                    None
                }
            }
            Err(e) => {
                debug!("Failed to check ACL for {}: {}", bucket_name, e);
                None
            }
        }
    }

    /// Check bucket ACL for overly permissive grants
    async fn check_bucket_acl_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_acl().bucket(bucket_name).send().await {
            Ok(response) => {
                let risky_grants = response.grants()
                    .iter()
                    .filter(|grant| {
                        grant.grantee()
                            .and_then(|g| g.uri())
                            .map(|uri| uri.contains("AllUsers"))
                            .unwrap_or(false)
                    })
                    .count();

                if risky_grants > 0 {
                    Some(Self::create_vulnerability(
                        "S3 Bucket ACL Too Permissive",
                        bucket_name,
                        region,
                        &format!("Bucket has {} grants to AllUsers or AuthenticatedUsers", risky_grants),
                        Severity::High,
                        "CWE-732",
                        8.5,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check bucket policy for public access
    async fn check_bucket_policy_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_policy().bucket(bucket_name).send().await {
            Ok(response) => {
                if let Some(policy) = response.policy() {
                    // Check if policy allows public access
                    let is_public = policy.contains("\"Principal\":\"*\"") ||
                                   policy.contains("\"Principal\":{\"AWS\":\"*\"}");

                    if is_public {
                        Some(Self::create_vulnerability(
                            "S3 Bucket Policy Allows Public Access",
                            bucket_name,
                            region,
                            "Bucket policy grants access to all principals (*)",
                            Severity::Critical,
                            "CWE-732",
                            9.0,
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check bucket encryption
    async fn check_encryption_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_encryption().bucket(bucket_name).send().await {
            Ok(_) => None, // Encryption is configured
            Err(_) => {
                Some(Self::create_vulnerability(
                    "S3 Bucket Not Encrypted",
                    bucket_name,
                    region,
                    "Bucket does not have default encryption enabled (AES-256 or KMS)",
                    Severity::High,
                    "CWE-311",
                    7.5,
                ))
            }
        }
    }

    /// Check bucket versioning
    async fn check_versioning_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_versioning().bucket(bucket_name).send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_none() || status.unwrap().as_str() != "Enabled" {
                    Some(Self::create_vulnerability(
                        "S3 Bucket Versioning Disabled",
                        bucket_name,
                        region,
                        "Bucket does not have versioning enabled for data protection",
                        Severity::Medium,
                        "CWE-693",
                        5.5,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check bucket logging
    async fn check_logging_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_logging().bucket(bucket_name).send().await {
            Ok(response) => {
                if response.logging_enabled().is_none() {
                    Some(Self::create_vulnerability(
                        "S3 Bucket Access Logging Disabled",
                        bucket_name,
                        region,
                        "Bucket does not have access logging enabled for audit trail",
                        Severity::Medium,
                        "CWE-778",
                        4.5,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check MFA delete protection
    async fn check_mfa_delete_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_versioning().bucket(bucket_name).send().await {
            Ok(response) => {
                let mfa_delete = response.mfa_delete();
                if mfa_delete.is_none() || mfa_delete.unwrap().as_str() != "Enabled" {
                    Some(Self::create_vulnerability(
                        "S3 Bucket MFA Delete Not Enabled",
                        bucket_name,
                        region,
                        "Bucket does not require MFA for object deletion",
                        Severity::Medium,
                        "CWE-306",
                        5.0,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check cross-region replication
    async fn check_replication_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_bucket_replication().bucket(bucket_name).send().await {
            Ok(_) => None, // Replication is configured
            Err(_) => {
                Some(Self::create_vulnerability(
                    "S3 Bucket Replication Not Configured",
                    bucket_name,
                    region,
                    "Bucket does not have cross-region replication for disaster recovery",
                    Severity::Low,
                    "CWE-693",
                    3.5,
                ))
            }
        }
    }

    /// Check public access block settings
    async fn check_public_access_block_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vulnerability> {
        match client.get_public_access_block().bucket(bucket_name).send().await {
            Ok(response) => {
                let config = response.public_access_block_configuration();
                if config.is_none() {
                    return Some(Self::create_vulnerability(
                        "S3 Public Access Block Not Configured",
                        bucket_name,
                        region,
                        "Bucket does not have public access block settings configured",
                        Severity::High,
                        "CWE-732",
                        7.0,
                    ));
                }

                let cfg = config.unwrap();
                let all_enabled = cfg.block_public_acls() == Some(true) &&
                                 cfg.block_public_policy() == Some(true) &&
                                 cfg.ignore_public_acls() == Some(true) &&
                                 cfg.restrict_public_buckets() == Some(true);

                if !all_enabled {
                    Some(Self::create_vulnerability(
                        "S3 Public Access Block Incomplete",
                        bucket_name,
                        region,
                        "Not all public access block settings are enabled",
                        Severity::High,
                        "CWE-732",
                        6.5,
                    ))
                } else {
                    None
                }
            }
            Err(_) => {
                Some(Self::create_vulnerability(
                    "S3 Public Access Block Not Configured",
                    bucket_name,
                    region,
                    "Bucket does not have public access block settings",
                    Severity::High,
                    "CWE-732",
                    7.0,
                ))
            }
        }
    }

    /// Check object-level permissions (sample check)
    async fn check_object_permissions_static(
        client: &aws_sdk_s3::Client,
        bucket_name: &str,
        region: &str,
    ) -> Option<Vec<Vulnerability>> {
        // List up to 10 objects to check
        match client.list_objects_v2()
            .bucket(bucket_name)
            .max_keys(10)
            .send()
            .await
        {
            Ok(response) => {
                let mut vulnerabilities = Vec::new();

                for object in response.contents().iter().take(5) {
                    if let Some(key) = object.key() {
                        // Check object ACL
                        if let Ok(acl_response) = client.get_object_acl()
                            .bucket(bucket_name)
                            .key(key)
                            .send()
                            .await
                        {
                            let is_public = acl_response.grants()
                                .iter()
                                .any(|grant| {
                                    grant.grantee()
                                        .and_then(|g| g.uri())
                                        .map(|uri| uri.contains("AllUsers"))
                                        .unwrap_or(false)
                                });

                            if is_public {
                                vulnerabilities.push(Self::create_vulnerability(
                                    "S3 Object Publicly Accessible",
                                    &format!("{}/{}", bucket_name, key),
                                    region,
                                    &format!("Object '{}' has public read access", key),
                                    Severity::High,
                                    "CWE-732",
                                    8.0,
                                ));
                            }
                        }
                    }
                }

                if !vulnerabilities.is_empty() {
                    Some(vulnerabilities)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
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
            id: format!("s3_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloud Security - AWS S3".to_string(),
            url: format!("s3://{}", resource),
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

    /// Get remediation guidance for vulnerability type
    fn get_remediation(vuln_type: &str) -> String {
        match vuln_type {
            "S3 Bucket Publicly Accessible" | "S3 Bucket ACL Too Permissive" => {
                "1. Remove public access from bucket ACL\n\
                 2. Enable S3 Block Public Access at account and bucket level\n\
                 3. Use bucket policies with least privilege principle\n\
                 4. Implement CloudFront with OAI for public content delivery\n\
                 5. Regularly audit bucket permissions using AWS Access Analyzer".to_string()
            }
            "S3 Bucket Policy Allows Public Access" => {
                "1. Review and restrict bucket policy to specific principals\n\
                 2. Remove wildcard (*) principals from policy statements\n\
                 3. Use IAM roles and policies for access control\n\
                 4. Enable S3 Block Public Access settings\n\
                 5. Use AWS Policy Simulator to test policies".to_string()
            }
            "S3 Bucket Not Encrypted" => {
                "1. Enable default encryption with AES-256 or AWS KMS\n\
                 2. Use KMS CMK for additional key control and audit\n\
                 3. Enforce encryption in bucket policy (deny unencrypted uploads)\n\
                 4. Enable bucket key to reduce KMS costs\n\
                 5. Monitor encryption status using AWS Config".to_string()
            }
            "S3 Bucket Versioning Disabled" => {
                "1. Enable versioning on the bucket\n\
                 2. Configure lifecycle policies to manage old versions\n\
                 3. Enable MFA Delete for additional protection\n\
                 4. Use object lock for compliance requirements\n\
                 5. Monitor versioning status with AWS Config".to_string()
            }
            "S3 Bucket Access Logging Disabled" => {
                "1. Enable S3 server access logging\n\
                 2. Store logs in a separate, restricted bucket\n\
                 3. Configure lifecycle policy for log retention\n\
                 4. Enable CloudTrail for S3 data events\n\
                 5. Integrate logs with SIEM or monitoring solution".to_string()
            }
            "S3 Bucket MFA Delete Not Enabled" => {
                "1. Enable MFA Delete on versioned buckets\n\
                 2. Require MFA for root account operations\n\
                 3. Document MFA procedures for bucket operations\n\
                 4. Use object lock as additional protection layer\n\
                 5. Regularly review deletion logs".to_string()
            }
            "S3 Public Access Block Not Configured" | "S3 Public Access Block Incomplete" => {
                "1. Enable all S3 Block Public Access settings\n\
                 2. Apply block public access at account level\n\
                 3. Regularly audit public access settings\n\
                 4. Use AWS Organizations SCPs to enforce settings\n\
                 5. Monitor changes using AWS Config rules".to_string()
            }
            "S3 Object Publicly Accessible" => {
                "1. Remove public ACL from object\n\
                 2. Enable Block Public Access at bucket level\n\
                 3. Review and restrict object-level permissions\n\
                 4. Use pre-signed URLs for temporary access\n\
                 5. Implement CloudFront for content delivery".to_string()
            }
            _ => {
                "1. Review AWS S3 security best practices\n\
                 2. Implement least privilege access controls\n\
                 3. Enable comprehensive logging and monitoring\n\
                 4. Use AWS Security Hub for security posture management\n\
                 5. Regularly audit S3 configurations using AWS Config".to_string()
            }
        }
    }
}

impl Default for AwsS3Scanner {
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
        let scanner = AwsS3Scanner::new();
        assert_eq!(scanner.max_concurrency, 10);
        assert!(scanner.aws_config.is_none());
    }

    #[test]
    fn test_remediation_generation() {
        let remediation = AwsS3Scanner::get_remediation("S3 Bucket Publicly Accessible");
        assert!(remediation.contains("Block Public Access"));
        assert!(remediation.contains("least privilege"));
    }
}
