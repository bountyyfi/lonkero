// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Security Scanners
 * Multi-cloud security vulnerability detection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

// AWS Scanners
pub mod aws_s3;
pub mod aws_ec2;
pub mod aws_rds;
pub mod aws_lambda;

// Azure Scanners
pub mod azure_storage;
pub mod azure_containers;
pub mod azure_aks;
pub mod azure_vm;

// GCP Scanners
pub mod gcp_compute;
pub mod gcp_storage;

// Cloudflare Scanners
pub mod cloudflare_dns;
pub mod cloudflare_waf;
pub mod cloudflare_workers;

// GitLab Scanners
pub mod gitlab_code;
pub mod gitlab_cicd;
pub mod gitlab_registry;

// Compliance (Legacy)
pub mod compliance;

// Enhanced Cloud Security Scanners
pub mod iam_analyzer;
pub mod network_analyzer;
pub mod compliance_scanner;
pub mod cost_optimizer;
pub mod secrets_scanner;
pub mod container_security_scanner;
pub mod api_gateway_security_scanner;

// AWS Exports
pub use aws_s3::AwsS3Scanner;
pub use aws_ec2::AwsEc2Scanner;
pub use aws_rds::AwsRdsScanner;
pub use aws_lambda::AwsLambdaScanner;

// Azure Exports
pub use azure_storage::AzureStorageScanner;
pub use azure_containers::AzureContainerScanner;
pub use azure_aks::AzureAksScanner;
pub use azure_vm::AzureVmScanner;

// GCP Exports
pub use gcp_compute::GcpComputeScanner;
pub use gcp_storage::GcpStorageScanner;

// Cloudflare Exports
pub use cloudflare_dns::CloudflareDnsScanner;
pub use cloudflare_waf::CloudflareWafScanner;
pub use cloudflare_workers::CloudflareWorkersScanner;

// GitLab Exports
pub use gitlab_code::GitLabCodeScanner;
pub use gitlab_cicd::GitLabCICDScanner;
pub use gitlab_registry::GitLabRegistryScanner;

// Compliance Exports (Legacy)
pub use compliance::CloudComplianceEngine;

// Enhanced Cloud Security Exports
pub use iam_analyzer::CloudIamAnalyzer;
pub use network_analyzer::CloudNetworkAnalyzer;
pub use compliance_scanner::CloudComplianceScanner;
pub use cost_optimizer::CloudCostOptimizer;
pub use secrets_scanner::CloudSecretsScanner;
pub use container_security_scanner::CloudContainerSecurityScanner;
pub use api_gateway_security_scanner::CloudApiGatewaySecurityScanner;
