// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS EC2 Security Scanner - Standalone Binary
 * Scans EC2 instances for security vulnerabilities and misconfigurations
 *
 * © 2025 Bountyy Oy
 */

use clap::Parser;
use serde_json::json;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "aws-ec2-scanner")]
#[command(about = "AWS EC2 Security Scanner", long_about = None)]
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

    /// Instance types to scan (comma-separated, optional)
    #[arg(long)]
    instance_types: Option<String>,
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
    let scan_id = args.scan_id.unwrap_or_else(|| format!("ec2_scan_{}", chrono::Utc::now().timestamp()));

    eprintln!("[aws-ec2-scanner] Starting scan {} across regions: {:?}", scan_id, regions);

    // Execute the scan
    let results = scan_ec2_security(&scan_id, &regions, args.max_concurrency).await?;

    // Output results
    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("{}", serde_json::to_string(&results)?);
    }

    eprintln!("[aws-ec2-scanner] Scan complete. Found {} vulnerabilities", results["vulnerabilities"].as_array().map(|v| v.len()).unwrap_or(0));

    Ok(())
}

async fn scan_ec2_security(
    scan_id: &str,
    regions: &[String],
    _max_concurrency: usize,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;

    let mut all_vulnerabilities = Vec::new();
    let mut total_instances = 0;
    let mut total_security_groups = 0;
    let mut total_volumes = 0;

    // Scan each region
    for region in regions {
        eprintln!("[aws-ec2-scanner] Scanning region: {}", region);

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let ec2_client = aws_sdk_ec2::Client::new(&config);

        // Scan EC2 instances
        match scan_ec2_instances(&ec2_client, region, scan_id).await {
            Ok((instances, vulns)) => {
                total_instances += instances;
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-ec2-scanner] Error scanning instances in {}: {}", region, e);
            }
        }

        // Scan security groups
        match scan_security_groups(&ec2_client, region, scan_id).await {
            Ok((sgs, vulns)) => {
                total_security_groups += sgs;
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-ec2-scanner] Error scanning security groups in {}: {}", region, e);
            }
        }

        // Scan EBS volumes
        match scan_ebs_volumes(&ec2_client, region, scan_id).await {
            Ok((vols, vulns)) => {
                total_volumes += vols;
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-ec2-scanner] Error scanning EBS volumes in {}: {}", region, e);
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
        "scanType": "aws-ec2",
        "regions": regions,
        "instancesScanned": total_instances,
        "securityGroupsScanned": total_security_groups,
        "volumesScanned": total_volumes,
        "vulnerabilities": all_vulnerabilities,
        "findingsSummary": findings_summary,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn scan_ec2_instances(
    client: &aws_sdk_ec2::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_instances().send().await?;
    let reservations = response.reservations();

    let mut instance_count = 0;

    for reservation in reservations {
        for instance in reservation.instances() {
            instance_count += 1;

            let instance_id = instance.instance_id().unwrap_or("unknown");
            let public_ip = instance.public_ip_address();

            // Check for IMDSv1 usage (insecure metadata service)
            if let Some(metadata_options) = instance.metadata_options() {
                if metadata_options.http_tokens() == Some(&aws_sdk_ec2::types::HttpTokensState::Optional) {
                    vulnerabilities.push(json!({
                        "id": format!("ec2-imdsv1-{}", instance_id),
                        "vuln_type": "IMDSv1 Enabled",
                        "severity": "Medium",
                        "title": format!("EC2 instance {} uses IMDSv1", instance_id),
                        "description": "Instance Metadata Service v1 (IMDSv1) is enabled, which is vulnerable to SSRF attacks. IMDSv2 should be required.",
                        "remediation": "Require IMDSv2 by setting HttpTokens to 'required' in instance metadata options.",
                        "evidence": {
                            "instance_id": instance_id,
                            "http_tokens": "optional",
                            "public_ip": public_ip,
                        },
                        "resource_id": instance_id,
                        "resource_type": "ec2-instance",
                        "region": region,
                        "cwe": "CWE-918",
                        "compliance_frameworks": ["CIS AWS 5.6"],
                        "risk_score": 6
                    }));
                }
            }

            // Check for publicly accessible instances without proper monitoring
            if public_ip.is_some() {
                let monitoring_enabled = instance.monitoring()
                    .and_then(|m| m.state())
                    .map(|s| s == &aws_sdk_ec2::types::MonitoringState::Enabled)
                    .unwrap_or(false);
                if !monitoring_enabled {
                    vulnerabilities.push(json!({
                        "id": format!("ec2-no-monitoring-{}", instance_id),
                        "vuln_type": "Missing Detailed Monitoring",
                        "severity": "Low",
                        "title": format!("Public EC2 instance {} lacks detailed monitoring", instance_id),
                        "description": "Publicly accessible EC2 instance does not have detailed monitoring enabled.",
                        "remediation": "Enable detailed monitoring for better visibility into instance metrics.",
                        "evidence": {
                            "instance_id": instance_id,
                            "public_ip": public_ip,
                            "monitoring": "disabled"
                        },
                        "resource_id": instance_id,
                        "resource_type": "ec2-instance",
                        "region": region,
                        "cwe": "CWE-778",
                        "compliance_frameworks": ["CIS AWS 5.3"],
                        "risk_score": 3
                    }));
                }
            }
        }
    }

    Ok((instance_count, vulnerabilities))
}

async fn scan_security_groups(
    client: &aws_sdk_ec2::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_security_groups().send().await?;
    let security_groups = response.security_groups();

    for sg in security_groups {
        let sg_id = sg.group_id().unwrap_or("unknown");
        let sg_name = sg.group_name().unwrap_or("unknown");

        // Check for overly permissive ingress rules
        for rule in sg.ip_permissions() {
            let from_port = rule.from_port().unwrap_or(0);
            let to_port = rule.to_port().unwrap_or(0);

            for ip_range in rule.ip_ranges() {
                let cidr = ip_range.cidr_ip().unwrap_or("");

                // Check for 0.0.0.0/0 (unrestricted access)
                if cidr == "0.0.0.0/0" {
                    let severity = if from_port == 22 || from_port == 3389 {
                        "Critical" // SSH or RDP
                    } else if to_port == 0 || (to_port - from_port > 1000) {
                        "High" // Wide port range
                    } else {
                        "Medium"
                    };

                    let protocol = rule.ip_protocol().unwrap_or("-1");
                    let service = match from_port {
                        22 => "SSH",
                        3389 => "RDP",
                        80 => "HTTP",
                        443 => "HTTPS",
                        3306 => "MySQL",
                        5432 => "PostgreSQL",
                        _ => "Unknown"
                    };

                    vulnerabilities.push(json!({
                        "id": format!("sg-open-{}-{}", sg_id, from_port),
                        "vuln_type": "Unrestricted Security Group",
                        "severity": severity,
                        "title": format!("Security group {} allows unrestricted {} access", sg_name, service),
                        "description": format!("Security group allows {} access (port {}-{}) from 0.0.0.0/0", service, from_port, to_port),
                        "remediation": "Restrict access to specific IP addresses or ranges. Use AWS Systems Manager Session Manager for administrative access.",
                        "evidence": {
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": cidr
                        },
                        "resource_id": sg_id,
                        "resource_type": "security-group",
                        "region": region,
                        "cwe": "CWE-16",
                        "compliance_frameworks": ["CIS AWS 5.2", "PCI-DSS 1.2.1"],
                        "risk_score": if severity == "Critical" { 9 } else if severity == "High" { 7 } else { 5 }
                    }));
                }
            }
        }
    }

    Ok((security_groups.len(), vulnerabilities))
}

async fn scan_ebs_volumes(
    client: &aws_sdk_ec2::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_volumes().send().await?;
    let volumes = response.volumes();

    for volume in volumes {
        let volume_id = volume.volume_id().unwrap_or("unknown");
        let encrypted = volume.encrypted().unwrap_or(false);

        // Check for unencrypted volumes
        if !encrypted {
            vulnerabilities.push(json!({
                "id": format!("ebs-unencrypted-{}", volume_id),
                "vuln_type": "Unencrypted EBS Volume",
                "severity": "High",
                "title": format!("EBS volume {} is not encrypted", volume_id),
                "description": "EBS volume does not have encryption enabled, risking data exposure if volume is compromised.",
                "remediation": "Enable encryption for EBS volumes. Create encrypted snapshot and restore to new encrypted volume.",
                "evidence": {
                    "volume_id": volume_id,
                    "encrypted": false,
                    "size": volume.size(),
                    "volume_type": volume.volume_type().map(|t| t.as_str())
                },
                "resource_id": volume_id,
                "resource_type": "ebs-volume",
                "region": region,
                "cwe": "CWE-311",
                "compliance_frameworks": ["CIS AWS 2.2.1", "HIPAA", "PCI-DSS 3.4"],
                "risk_score": 7
            }));
        }
    }

    Ok((volumes.len(), vulnerabilities))
}
