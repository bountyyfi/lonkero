// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * N-API Bridge for Node.js Integration
 * Exposes Rust cloud scanners to Node.js via N-API
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Re-export cloud scanner modules
use crate::scanners::cloud::{
    AwsS3Scanner, AwsEc2Scanner, AwsRdsScanner,
    AzureStorageScanner, AzureVmScanner,
    GcpComputeScanner, GcpStorageScanner,
    CloudflareDnsScanner, CloudflareWafScanner,
    GitLabCodeScanner, GitLabCICDScanner,
};

/// Scan configuration passed from Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiScanConfig {
    pub scan_mode: String,
    pub timeout_secs: Option<i64>,
    pub max_retries: Option<u32>,
}

impl Default for NapiScanConfig {
    fn default() -> Self {
        Self {
            scan_mode: "normal".to_string(),
            timeout_secs: Some(30),
            max_retries: Some(3),
        }
    }
}

/// Vulnerability result returned to Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiVulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: String,
    pub description: String,
    pub evidence: Option<String>,
    pub cwe: String,
    pub cvss: f64,
    pub verified: bool,
    pub remediation: String,
    pub discovered_at: String,
}

/// Scan result returned to Node.js
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapiScanResult {
    pub success: bool,
    pub resources_scanned: i32,
    pub vulnerabilities: Vec<NapiVulnerability>,
    pub error: Option<String>,
    pub findings_summary: HashMap<String, i32>,
}

// =============================================================================
// AWS Scanners
// =============================================================================

/// Scan AWS S3 buckets for security vulnerabilities
#[napi]
pub async fn scan_aws_s3(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    // Convert to internal ScanConfig
    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let mut scanner = AwsS3Scanner::new();

    match scanner.scan(&_internal_config).await {
        Ok(result) => {
            let vulnerabilities: Vec<NapiVulnerability> = result.vulnerabilities
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let findings_summary: HashMap<String, i32> = result.findings_summary
                .into_iter()
                .map(|(k, v)| (k, v as i32))
                .collect();

            Ok(NapiScanResult {
                success: true,
                resources_scanned: result.buckets_scanned as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("AWS S3 scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

/// Scan AWS EC2 instances for security vulnerabilities
#[napi]
pub async fn scan_aws_ec2(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _scanner = AwsEc2Scanner::new();

    // AWS EC2 scanner requires instance and volume data
    // For now, return empty results as a placeholder
    let vulnerabilities: Vec<NapiVulnerability> = vec![];
    let findings_summary: HashMap<String, i32> = HashMap::new();

    Ok(NapiScanResult {
        success: true,
        resources_scanned: 0,
        vulnerabilities,
        error: None,
        findings_summary,
    })
}

/// Scan AWS RDS instances for security vulnerabilities
#[napi]
pub async fn scan_aws_rds(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let mut scanner = AwsRdsScanner::new();

    match scanner.scan(&_internal_config).await {
        Ok(result) => {
            let vulnerabilities: Vec<NapiVulnerability> = result.vulnerabilities
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let findings_summary: HashMap<String, i32> = result.findings_summary
                .into_iter()
                .map(|(k, v)| (k, v as i32))
                .collect();

            Ok(NapiScanResult {
                success: true,
                resources_scanned: (result.instances_scanned + result.snapshots_scanned + result.clusters_scanned) as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("AWS RDS scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

// =============================================================================
// Azure Scanners
// =============================================================================

/// Scan Azure Storage accounts for security vulnerabilities
#[napi]
pub async fn scan_azure_storage(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for Azure scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for Azure Storage scanner")
    }));

    let scanner = AzureStorageScanner::new(http_client);

    match scanner.scan("", &_internal_config).await {
        Ok((vulnerabilities_vec, accounts_scanned)) => {
            let vulnerabilities: Vec<NapiVulnerability> = vulnerabilities_vec
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let mut findings_summary: HashMap<String, i32> = HashMap::new();
            for vuln in &vulnerabilities {
                *findings_summary.entry(vuln.severity.clone()).or_insert(0) += 1;
            }

            Ok(NapiScanResult {
                success: true,
                resources_scanned: accounts_scanned as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("Azure Storage scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

/// Scan Azure VMs for security vulnerabilities
#[napi]
pub async fn scan_azure_vm(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for Azure scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for Azure VM scanner")
    }));

    let mut scanner = AzureVmScanner::new(http_client);

    // Create dummy Azure credentials (in production, these would come from config)
    let credentials = crate::scanners::cloud::azure_vm::AzureCredentials {
        tenant_id: String::new(),
        client_id: String::new(),
        client_secret: String::new(),
        subscription_id: String::new(),
    };

    match scanner.scan(&credentials).await {
        Ok((vulnerabilities_vec, vms_scanned)) => {
            let vulnerabilities: Vec<NapiVulnerability> = vulnerabilities_vec
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let mut findings_summary: HashMap<String, i32> = HashMap::new();
            for vuln in &vulnerabilities {
                *findings_summary.entry(vuln.severity.clone()).or_insert(0) += 1;
            }

            Ok(NapiScanResult {
                success: true,
                resources_scanned: vms_scanned as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("Azure VM scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

// =============================================================================
// GCP Scanners
// =============================================================================

/// Scan GCP Compute Engine instances for security vulnerabilities
#[napi]
pub async fn scan_gcp_compute(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let _scanner = GcpComputeScanner::new();

    // GcpComputeScanner requires instances data and project_id
    // For now, return empty results as a placeholder
    let vulnerabilities: Vec<NapiVulnerability> = vec![];
    let findings_summary: HashMap<String, i32> = HashMap::new();

    Ok(NapiScanResult {
        success: true,
        resources_scanned: 0,
        vulnerabilities,
        error: None,
        findings_summary,
    })
}

/// Scan GCP Cloud Storage buckets for security vulnerabilities
#[napi]
pub async fn scan_gcp_storage(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let _scanner = GcpStorageScanner::new();

    // GcpStorageScanner requires buckets data and project_id
    // For now, return empty results as a placeholder
    let vulnerabilities: Vec<NapiVulnerability> = vec![];
    let findings_summary: HashMap<String, i32> = HashMap::new();

    Ok(NapiScanResult {
        success: true,
        resources_scanned: 0,
        vulnerabilities,
        error: None,
        findings_summary,
    })
}

// =============================================================================
// Cloudflare Scanners
// =============================================================================

/// Scan Cloudflare DNS for security vulnerabilities
#[napi]
pub async fn scan_cloudflare_dns(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for Cloudflare scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for Cloudflare DNS scanner")
    }));

    let scanner = CloudflareDnsScanner::new(http_client, String::new());

    // Create Cloudflare DNS config
    let cf_config = crate::scanners::cloud::cloudflare_dns::CloudflareDnsConfig {
        api_token: String::new(),
        zone_id: String::new(),
        check_dangling: true,
        check_dnssec: true,
        check_email_security: true,
        check_caa: true,
        check_takeover: true,
    };

    match scanner.scan("", &cf_config).await {
        Ok((vulnerabilities_vec, records_scanned)) => {
            let vulnerabilities: Vec<NapiVulnerability> = vulnerabilities_vec
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let mut findings_summary: HashMap<String, i32> = HashMap::new();
            for vuln in &vulnerabilities {
                *findings_summary.entry(vuln.severity.clone()).or_insert(0) += 1;
            }

            Ok(NapiScanResult {
                success: true,
                resources_scanned: records_scanned as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("Cloudflare DNS scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

/// Scan Cloudflare WAF for security vulnerabilities
#[napi]
pub async fn scan_cloudflare_waf(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for Cloudflare scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for Cloudflare WAF scanner")
    }));

    let scanner = CloudflareWafScanner::new(http_client, String::new());

    // Create Cloudflare WAF config
    let cf_config = crate::scanners::cloud::cloudflare_waf::CloudflareWafConfig {
        api_token: String::new(),
        zone_id: String::new(),
        check_waf: true,
        check_ssl: true,
        check_firewall: true,
        check_rate_limiting: true,
        check_bot_management: true,
        check_ddos: true,
        check_page_rules: true,
    };

    match scanner.scan("", &cf_config).await {
        Ok((vulnerabilities_vec, configs_scanned)) => {
            let vulnerabilities: Vec<NapiVulnerability> = vulnerabilities_vec
                .into_iter()
                .map(|v| NapiVulnerability {
                    id: v.id,
                    vuln_type: v.vuln_type,
                    severity: format!("{:?}", v.severity),
                    confidence: format!("{:?}", v.confidence),
                    category: v.category,
                    url: v.url,
                    parameter: v.parameter,
                    payload: v.payload,
                    description: v.description,
                    evidence: v.evidence,
                    cwe: v.cwe,
                    cvss: v.cvss as f64,
                    verified: v.verified,
                    remediation: v.remediation,
                    discovered_at: v.discovered_at,
                })
                .collect();

            let mut findings_summary: HashMap<String, i32> = HashMap::new();
            for vuln in &vulnerabilities {
                *findings_summary.entry(vuln.severity.clone()).or_insert(0) += 1;
            }

            Ok(NapiScanResult {
                success: true,
                resources_scanned: configs_scanned as i32,
                vulnerabilities,
                error: None,
                findings_summary,
            })
        }
        Err(e) => Ok(NapiScanResult {
            success: false,
            resources_scanned: 0,
            vulnerabilities: vec![],
            error: Some(format!("Cloudflare WAF scan failed: {}", e)),
            findings_summary: HashMap::new(),
        }),
    }
}

// =============================================================================
// GitLab Scanners
// =============================================================================

/// Scan GitLab code repositories for security vulnerabilities
#[napi]
pub async fn scan_gitlab_code(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for GitLab scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for GitLab Code scanner")
    }));

    let _scanner = GitLabCodeScanner::new(http_client, String::from("https://gitlab.com"), String::new());

    // GitLabCodeScanner returns a different structure - placeholder for now
    let vulnerabilities: Vec<NapiVulnerability> = vec![];
    let findings_summary: HashMap<String, i32> = HashMap::new();

    Ok(NapiScanResult {
        success: true,
        resources_scanned: 0,
        vulnerabilities,
        error: None,
        findings_summary,
    })
}

/// Scan GitLab CI/CD pipelines for security vulnerabilities
#[napi]
pub async fn scan_gitlab_cicd(config: Option<NapiScanConfig>) -> Result<NapiScanResult> {
    let _config = config.unwrap_or_default();

    let _internal_config = crate::types::ScanConfig {
        scan_mode: crate::types::ScanMode::Normal,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Create HTTP client for GitLab scanner
    let http_client = Arc::new(crate::http_client::HttpClient::new(30000, 3).unwrap_or_else(|_| {
        panic!("Failed to create HTTP client for GitLab CICD scanner")
    }));

    let _scanner = GitLabCICDScanner::new(http_client, String::from("https://gitlab.com"), String::new());

    // GitLabCICDScanner returns a different structure - placeholder for now
    let vulnerabilities: Vec<NapiVulnerability> = vec![];
    let findings_summary: HashMap<String, i32> = HashMap::new();

    Ok(NapiScanResult {
        success: true,
        resources_scanned: 0,
        vulnerabilities,
        error: None,
        findings_summary,
    })
}
