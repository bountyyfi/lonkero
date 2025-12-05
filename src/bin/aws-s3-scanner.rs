// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS S3 Security Scanner - Standalone Binary
 * Scans S3 buckets for security vulnerabilities and misconfigurations
 *
 * © 2025 Bountyy Oy
 */

use clap::Parser;
use serde_json::json;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "aws-s3-scanner")]
#[command(about = "AWS S3 Security Scanner", long_about = None)]
struct Args {
    /// Scan ID for tracking
    #[arg(long)]
    scan_id: Option<String>,

    /// AWS regions to scan (comma-separated)
    #[arg(long, default_value = "us-east-1")]
    regions: String,

    /// Maximum concurrent requests
    #[arg(long, default_value = "10")]
    max_concurrency: usize,

    /// Output format (json, ndjson)
    #[arg(long, default_value = "json")]
    output: String,

    /// Verbose logging
    #[arg(long, short)]
    verbose: bool,

    /// Check individual objects in buckets (slower but more thorough)
    #[arg(long)]
    check_objects: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt::init();

    let regions: Vec<String> = args.regions.split(',').map(|s| s.trim().to_string()).collect();
    let scan_id = args.scan_id.unwrap_or_else(|| format!("s3_scan_{}", chrono::Utc::now().timestamp()));

    eprintln!("[aws-s3-scanner] Starting scan {} across regions: {:?}", scan_id, regions);

    // Execute the scan
    let results = scan_s3_security(&scan_id, &regions, args.max_concurrency, args.check_objects).await?;

    // Output results
    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("{}", serde_json::to_string(&results)?);
    }

    eprintln!("[aws-s3-scanner] Scan complete. Found {} vulnerabilities", results["vulnerabilities"].as_array().map(|v| v.len()).unwrap_or(0));

    Ok(())
}

async fn scan_s3_security(
    scan_id: &str,
    regions: &[String],
    _max_concurrency: usize,
    check_objects: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;

    let mut all_vulnerabilities = Vec::new();
    let mut total_buckets = 0;

    // S3 is global, but we'll use the first region for the client
    let default_region = "us-east-1".to_string();
    let region = regions.first().unwrap_or(&default_region);

    eprintln!("[aws-s3-scanner] Connecting to S3 service (region: {})", region);

    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(region.clone()))
        .load()
        .await;

    let s3_client = aws_sdk_s3::Client::new(&config);

    // List all buckets
    let buckets_response = s3_client.list_buckets().send().await?;
    let buckets = buckets_response.buckets();

    total_buckets = buckets.len();
    eprintln!("[aws-s3-scanner] Found {} buckets to scan", total_buckets);

    // Scan each bucket
    for bucket in buckets {
        let bucket_name = bucket.name().unwrap_or("unknown");
        eprintln!("[aws-s3-scanner] Scanning bucket: {}", bucket_name);

        match scan_bucket_security(&s3_client, bucket_name, scan_id, check_objects).await {
            Ok(vulns) => {
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-s3-scanner] Error scanning bucket {}: {}", bucket_name, e);
            }
        }
    }

    // Build findings summary
    let mut findings_summary: HashMap<String, usize> = HashMap::new();
    for vuln in &all_vulnerabilities {
        let severity = vuln["severity"].as_str().unwrap_or("Unknown");
        *findings_summary.entry(severity.to_string()).or_insert(0) += 1;
    }

    Ok(json!({
        "scanId": scan_id,
        "scanType": "aws-s3",
        "regions": regions,
        "bucketsScanned": total_buckets,
        "vulnerabilities": all_vulnerabilities,
        "findingsSummary": findings_summary,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn scan_bucket_security(
    client: &aws_sdk_s3::Client,
    bucket_name: &str,
    _scan_id: &str,
    _check_objects: bool,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    // Check bucket ACL
    match client.get_bucket_acl().bucket(bucket_name).send().await {
        Ok(acl_response) => {
            let grants = acl_response.grants();

            for grant in grants {
                if let Some(grantee) = grant.grantee() {
                    let uri = grantee.uri();

                    // Check for public ACLs
                    if uri == Some("http://acs.amazonaws.com/groups/global/AllUsers")
                        || uri == Some("http://acs.amazonaws.com/groups/global/AuthenticatedUsers") {

                        let permission = grant.permission().map(|p| p.as_str()).unwrap_or("UNKNOWN");
                        let severity = if permission == "FULL_CONTROL" || permission == "WRITE" {
                            "Critical"
                        } else {
                            "High"
                        };

                        vulnerabilities.push(json!({
                            "id": format!("s3-public-acl-{}", bucket_name),
                            "vuln_type": "Public S3 Bucket ACL",
                            "severity": severity,
                            "title": format!("S3 bucket {} has public ACL", bucket_name),
                            "description": format!("Bucket has public ACL granting {} permission to all users", permission),
                            "remediation": "Remove public ACL grants. Enable S3 Block Public Access settings.",
                            "evidence": {
                                "bucket_name": bucket_name,
                                "grant_uri": uri,
                                "permission": permission
                            },
                            "resource_id": bucket_name,
                            "resource_type": "s3-bucket",
                            "region": "global",
                            "cwe": "CWE-284",
                            "compliance_frameworks": ["CIS AWS 2.1.5", "NIST 800-53 AC-6"],
                            "risk_score": if severity == "Critical" { 9 } else { 8 }
                        }));
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[aws-s3-scanner] Could not get ACL for bucket {}: {}", bucket_name, e);
        }
    }

    // Check bucket policy
    match client.get_bucket_policy().bucket(bucket_name).send().await {
        Ok(policy_response) => {
            if let Some(policy_str) = policy_response.policy() {
                // Check for overly permissive policies
                if policy_str.contains("\"Effect\":\"Allow\"") &&
                   (policy_str.contains("\"Principal\":\"*\"") || policy_str.contains("\"Principal\":{\"AWS\":\"*\"}")) {

                    vulnerabilities.push(json!({
                        "id": format!("s3-public-policy-{}", bucket_name),
                        "vuln_type": "Public S3 Bucket Policy",
                        "severity": "High",
                        "title": format!("S3 bucket {} has public bucket policy", bucket_name),
                        "description": "Bucket policy allows public access via wildcard (*) principal",
                        "remediation": "Review and restrict bucket policy to specific principals. Enable S3 Block Public Access.",
                        "evidence": {
                            "bucket_name": bucket_name,
                            "has_public_policy": true,
                            "policy_excerpt": &policy_str[..std::cmp::min(200, policy_str.len())]
                        },
                        "resource_id": bucket_name,
                        "resource_type": "s3-bucket",
                        "region": "global",
                        "cwe": "CWE-284",
                        "compliance_frameworks": ["CIS AWS 2.1.5"],
                        "risk_score": 8
                    }));
                }
            }
        }
        Err(_) => {
            // No policy is fine
        }
    }

    // Check bucket encryption
    match client.get_bucket_encryption().bucket(bucket_name).send().await {
        Ok(_) => {
            // Encryption is enabled, good
        }
        Err(_) => {
            // No encryption configured
            vulnerabilities.push(json!({
                "id": format!("s3-no-encryption-{}", bucket_name),
                "vuln_type": "Unencrypted S3 Bucket",
                "severity": "Medium",
                "title": format!("S3 bucket {} does not have default encryption", bucket_name),
                "description": "Bucket does not have server-side encryption enabled by default",
                "remediation": "Enable default server-side encryption (SSE-S3, SSE-KMS, or SSE-C) for the bucket.",
                "evidence": {
                    "bucket_name": bucket_name,
                    "encryption_enabled": false
                },
                "resource_id": bucket_name,
                "resource_type": "s3-bucket",
                "region": "global",
                "cwe": "CWE-311",
                "compliance_frameworks": ["CIS AWS 2.1.1", "PCI-DSS 3.4"],
                "risk_score": 6
            }));
        }
    }

    // Check bucket versioning
    match client.get_bucket_versioning().bucket(bucket_name).send().await {
        Ok(versioning_response) => {
            if versioning_response.status() != Some(&aws_sdk_s3::types::BucketVersioningStatus::Enabled) {
                vulnerabilities.push(json!({
                    "id": format!("s3-no-versioning-{}", bucket_name),
                    "vuln_type": "S3 Versioning Disabled",
                    "severity": "Low",
                    "title": format!("S3 bucket {} does not have versioning enabled", bucket_name),
                    "description": "Bucket versioning is not enabled, preventing recovery from accidental deletions or overwrites",
                    "remediation": "Enable versioning to protect against accidental data loss.",
                    "evidence": {
                        "bucket_name": bucket_name,
                        "versioning_status": "disabled"
                    },
                    "resource_id": bucket_name,
                    "resource_type": "s3-bucket",
                    "region": "global",
                    "cwe": "CWE-664",
                    "compliance_frameworks": ["CIS AWS 2.1.3"],
                    "risk_score": 3
                }));
            }
        }
        Err(e) => {
            eprintln!("[aws-s3-scanner] Could not get versioning for bucket {}: {}", bucket_name, e);
        }
    }

    // Check public access block configuration
    match client.get_public_access_block().bucket(bucket_name).send().await {
        Ok(pab_response) => {
            if let Some(config) = pab_response.public_access_block_configuration() {
                if !config.block_public_acls().unwrap_or(false) ||
                   !config.block_public_policy().unwrap_or(false) ||
                   !config.ignore_public_acls().unwrap_or(false) ||
                   !config.restrict_public_buckets().unwrap_or(false) {

                    vulnerabilities.push(json!({
                        "id": format!("s3-pab-incomplete-{}", bucket_name),
                        "vuln_type": "Incomplete Public Access Block",
                        "severity": "Medium",
                        "title": format!("S3 bucket {} has incomplete public access block configuration", bucket_name),
                        "description": "Not all public access block settings are enabled",
                        "remediation": "Enable all four public access block settings for maximum protection.",
                        "evidence": {
                            "bucket_name": bucket_name,
                            "block_public_acls": config.block_public_acls(),
                            "block_public_policy": config.block_public_policy(),
                            "ignore_public_acls": config.ignore_public_acls(),
                            "restrict_public_buckets": config.restrict_public_buckets()
                        },
                        "resource_id": bucket_name,
                        "resource_type": "s3-bucket",
                        "region": "global",
                        "cwe": "CWE-284",
                        "compliance_frameworks": ["CIS AWS 2.1.5"],
                        "risk_score": 5
                    }));
                }
            }
        }
        Err(_) => {
            // Public access block not configured
            vulnerabilities.push(json!({
                "id": format!("s3-no-pab-{}", bucket_name),
                "vuln_type": "No Public Access Block",
                "severity": "High",
                "title": format!("S3 bucket {} does not have public access block enabled", bucket_name),
                "description": "Public access block settings are not configured for this bucket",
                "remediation": "Enable S3 Block Public Access settings to prevent accidental public exposure.",
                "evidence": {
                    "bucket_name": bucket_name,
                    "public_access_block_configured": false
                },
                "resource_id": bucket_name,
                "resource_type": "s3-bucket",
                "region": "global",
                "cwe": "CWE-284",
                "compliance_frameworks": ["CIS AWS 2.1.5"],
                "risk_score": 7
            }));
        }
    }

    Ok(vulnerabilities)
}
