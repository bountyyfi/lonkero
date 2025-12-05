// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS RDS Security Scanner - Standalone Binary
 * Scans RDS instances for security vulnerabilities and misconfigurations
 *
 * © 2025 Bountyy Oy
 */

use clap::Parser;
use serde_json::json;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "aws-rds-scanner")]
#[command(about = "AWS RDS Security Scanner", long_about = None)]
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

    /// Check RDS snapshots
    #[arg(long)]
    check_snapshots: bool,
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
    let scan_id = args.scan_id.unwrap_or_else(|| format!("rds_scan_{}", chrono::Utc::now().timestamp()));

    eprintln!("[aws-rds-scanner] Starting scan {} across regions: {:?}", scan_id, regions);

    // Execute the scan
    let results = scan_rds_security(&scan_id, &regions, args.max_concurrency, args.check_snapshots).await?;

    // Output results
    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        println!("{}", serde_json::to_string(&results)?);
    }

    eprintln!("[aws-rds-scanner] Scan complete. Found {} vulnerabilities", results["vulnerabilities"].as_array().map(|v| v.len()).unwrap_or(0));

    Ok(())
}

async fn scan_rds_security(
    scan_id: &str,
    regions: &[String],
    _max_concurrency: usize,
    check_snapshots: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;

    let mut all_vulnerabilities = Vec::new();
    let mut total_instances = 0;
    let mut total_clusters = 0;
    let mut total_snapshots = 0;

    // Scan each region
    for region in regions {
        eprintln!("[aws-rds-scanner] Scanning region: {}", region);

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let rds_client = aws_sdk_rds::Client::new(&config);

        // Scan RDS instances
        match scan_rds_instances(&rds_client, region, scan_id).await {
            Ok((instances, vulns)) => {
                total_instances += instances;
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-rds-scanner] Error scanning instances in {}: {}", region, e);
            }
        }

        // Scan RDS clusters
        match scan_rds_clusters(&rds_client, region, scan_id).await {
            Ok((clusters, vulns)) => {
                total_clusters += clusters;
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => {
                eprintln!("[aws-rds-scanner] Error scanning clusters in {}: {}", region, e);
            }
        }

        // Scan RDS snapshots if requested
        if check_snapshots {
            match scan_rds_snapshots(&rds_client, region, scan_id).await {
                Ok((snapshots, vulns)) => {
                    total_snapshots += snapshots;
                    all_vulnerabilities.extend(vulns);
                }
                Err(e) => {
                    eprintln!("[aws-rds-scanner] Error scanning snapshots in {}: {}", region, e);
                }
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
        "scanType": "aws-rds",
        "regions": regions,
        "instancesScanned": total_instances,
        "clustersScanned": total_clusters,
        "snapshotsScanned": total_snapshots,
        "vulnerabilities": all_vulnerabilities,
        "findingsSummary": findings_summary,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn scan_rds_instances(
    client: &aws_sdk_rds::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_db_instances().send().await?;
    let instances = response.db_instances();

    for instance in instances {
        let instance_id = instance.db_instance_identifier().unwrap_or("unknown");
        let engine = instance.engine().unwrap_or("unknown");
        let publicly_accessible = instance.publicly_accessible().unwrap_or(false);
        let encrypted = instance.storage_encrypted().unwrap_or(false);

        // Check for publicly accessible databases
        if publicly_accessible {
            vulnerabilities.push(json!({
                "id": format!("rds-public-{}", instance_id),
                "vuln_type": "Publicly Accessible RDS",
                "severity": "Critical",
                "title": format!("RDS instance {} is publicly accessible", instance_id),
                "description": "Database instance is accessible from the internet, exposing it to potential attacks.",
                "remediation": "Disable public accessibility. Place RDS instances in private subnets and use VPN or bastion hosts for access.",
                "evidence": {
                    "instance_id": instance_id,
                    "engine": engine,
                    "publicly_accessible": true,
                    "endpoint": instance.endpoint().and_then(|e| e.address())
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-16",
                "compliance_frameworks": ["CIS AWS 2.3.3", "PCI-DSS 1.2.1"],
                "risk_score": 9
            }));
        }

        // Check for unencrypted databases
        if !encrypted {
            vulnerabilities.push(json!({
                "id": format!("rds-unencrypted-{}", instance_id),
                "vuln_type": "Unencrypted RDS Instance",
                "severity": "High",
                "title": format!("RDS instance {} is not encrypted", instance_id),
                "description": "Database instance does not have encryption enabled, risking data exposure.",
                "remediation": "Enable encryption for RDS instances. Create encrypted snapshot and restore to new encrypted instance.",
                "evidence": {
                    "instance_id": instance_id,
                    "engine": engine,
                    "encrypted": false
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-311",
                "compliance_frameworks": ["CIS AWS 2.3.1", "HIPAA", "PCI-DSS 3.4"],
                "risk_score": 7
            }));
        }

        // Check for disabled automated backups
        let backup_retention = instance.backup_retention_period().unwrap_or(0);
        if backup_retention == 0 {
            vulnerabilities.push(json!({
                "id": format!("rds-no-backup-{}", instance_id),
                "vuln_type": "Disabled Automated Backups",
                "severity": "Medium",
                "title": format!("RDS instance {} has automated backups disabled", instance_id),
                "description": "Automated backups are disabled, preventing recovery from data loss.",
                "remediation": "Enable automated backups with appropriate retention period (7-35 days recommended).",
                "evidence": {
                    "instance_id": instance_id,
                    "backup_retention_period": backup_retention
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-664",
                "compliance_frameworks": ["CIS AWS 2.3.2"],
                "risk_score": 5
            }));
        } else if backup_retention < 7 {
            vulnerabilities.push(json!({
                "id": format!("rds-short-backup-{}", instance_id),
                "vuln_type": "Short Backup Retention",
                "severity": "Low",
                "title": format!("RDS instance {} has short backup retention period", instance_id),
                "description": format!("Backup retention is only {} days. Recommended minimum is 7 days.", backup_retention),
                "remediation": "Increase backup retention period to at least 7 days.",
                "evidence": {
                    "instance_id": instance_id,
                    "backup_retention_period": backup_retention
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-664",
                "compliance_frameworks": ["CIS AWS 2.3.2"],
                "risk_score": 3
            }));
        }

        // Check for disabled deletion protection
        if !instance.deletion_protection().unwrap_or(false) {
            vulnerabilities.push(json!({
                "id": format!("rds-no-delete-protection-{}", instance_id),
                "vuln_type": "Deletion Protection Disabled",
                "severity": "Medium",
                "title": format!("RDS instance {} has deletion protection disabled", instance_id),
                "description": "Deletion protection is disabled, allowing accidental deletion of the database.",
                "remediation": "Enable deletion protection to prevent accidental instance deletion.",
                "evidence": {
                    "instance_id": instance_id,
                    "deletion_protection": false
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-664",
                "compliance_frameworks": ["AWS Best Practices"],
                "risk_score": 4
            }));
        }

        // Check if instance uses default port
        let default_ports: HashMap<&str, i32> = [
            ("mysql", 3306),
            ("postgres", 5432),
            ("mariadb", 3306),
            ("oracle", 1521),
            ("sqlserver", 1433),
        ].iter().cloned().collect();

        if let Some(endpoint) = instance.endpoint() {
            if let Some(port) = endpoint.port() {
                if let Some(&default_port) = default_ports.get(engine) {
                    if port == default_port {
                        vulnerabilities.push(json!({
                            "id": format!("rds-default-port-{}", instance_id),
                            "vuln_type": "Default Database Port",
                            "severity": "Low",
                            "title": format!("RDS instance {} uses default {} port", instance_id, engine),
                            "description": format!("Instance uses default port {} which is commonly targeted by attackers.", port),
                            "remediation": "Consider using a non-default port to reduce automated attacks.",
                            "evidence": {
                                "instance_id": instance_id,
                                "engine": engine,
                                "port": port,
                                "default_port": default_port
                            },
                            "resource_id": instance_id,
                            "resource_type": "rds-instance",
                            "region": region,
                            "cwe": "CWE-1188",
                            "compliance_frameworks": [],
                            "risk_score": 2
                        }));
                    }
                }
            }
        }

        // Check for disabled enhanced monitoring
        if instance.monitoring_interval().unwrap_or(0) == 0 {
            vulnerabilities.push(json!({
                "id": format!("rds-no-enhanced-monitoring-{}", instance_id),
                "vuln_type": "Enhanced Monitoring Disabled",
                "severity": "Info",
                "title": format!("RDS instance {} has enhanced monitoring disabled", instance_id),
                "description": "Enhanced monitoring is disabled, limiting visibility into database performance.",
                "remediation": "Enable enhanced monitoring for better performance insights and troubleshooting.",
                "evidence": {
                    "instance_id": instance_id,
                    "monitoring_interval": 0
                },
                "resource_id": instance_id,
                "resource_type": "rds-instance",
                "region": region,
                "cwe": "CWE-778",
                "compliance_frameworks": [],
                "risk_score": 1
            }));
        }
    }

    Ok((instances.len(), vulnerabilities))
}

async fn scan_rds_clusters(
    client: &aws_sdk_rds::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_db_clusters().send().await?;
    let clusters = response.db_clusters();

    for cluster in clusters {
        let cluster_id = cluster.db_cluster_identifier().unwrap_or("unknown");
        let encrypted = cluster.storage_encrypted().unwrap_or(false);

        // Check for unencrypted clusters
        if !encrypted {
            vulnerabilities.push(json!({
                "id": format!("rds-cluster-unencrypted-{}", cluster_id),
                "vuln_type": "Unencrypted RDS Cluster",
                "severity": "High",
                "title": format!("RDS cluster {} is not encrypted", cluster_id),
                "description": "Database cluster does not have encryption enabled.",
                "remediation": "Enable encryption for RDS clusters. Migrate to encrypted cluster.",
                "evidence": {
                    "cluster_id": cluster_id,
                    "engine": cluster.engine(),
                    "encrypted": false
                },
                "resource_id": cluster_id,
                "resource_type": "rds-cluster",
                "region": region,
                "cwe": "CWE-311",
                "compliance_frameworks": ["CIS AWS 2.3.1"],
                "risk_score": 7
            }));
        }

        // Check backup retention
        let backup_retention = cluster.backup_retention_period().unwrap_or(0);
        if backup_retention == 0 {
            vulnerabilities.push(json!({
                "id": format!("rds-cluster-no-backup-{}", cluster_id),
                "vuln_type": "Disabled Cluster Backups",
                "severity": "Medium",
                "title": format!("RDS cluster {} has backups disabled", cluster_id),
                "description": "Automated backups are disabled for the cluster.",
                "remediation": "Enable automated backups with appropriate retention period.",
                "evidence": {
                    "cluster_id": cluster_id,
                    "backup_retention_period": backup_retention
                },
                "resource_id": cluster_id,
                "resource_type": "rds-cluster",
                "region": region,
                "cwe": "CWE-664",
                "compliance_frameworks": ["CIS AWS 2.3.2"],
                "risk_score": 5
            }));
        }
    }

    Ok((clusters.len(), vulnerabilities))
}

async fn scan_rds_snapshots(
    client: &aws_sdk_rds::Client,
    region: &str,
    _scan_id: &str,
) -> Result<(usize, Vec<serde_json::Value>), Box<dyn std::error::Error>> {
    let mut vulnerabilities = Vec::new();

    let response = client.describe_db_snapshots().send().await?;
    let snapshots = response.db_snapshots();

    for snapshot in snapshots {
        let snapshot_id = snapshot.db_snapshot_identifier().unwrap_or("unknown");
        let encrypted = snapshot.encrypted().unwrap_or(false);

        // Check for unencrypted snapshots
        if !encrypted {
            vulnerabilities.push(json!({
                "id": format!("rds-snapshot-unencrypted-{}", snapshot_id),
                "vuln_type": "Unencrypted RDS Snapshot",
                "severity": "High",
                "title": format!("RDS snapshot {} is not encrypted", snapshot_id),
                "description": "Database snapshot is not encrypted, risking data exposure if shared or accessed.",
                "remediation": "Use encrypted RDS instances to ensure snapshots are also encrypted.",
                "evidence": {
                    "snapshot_id": snapshot_id,
                    "encrypted": false,
                    "db_instance_id": snapshot.db_instance_identifier()
                },
                "resource_id": snapshot_id,
                "resource_type": "rds-snapshot",
                "region": region,
                "cwe": "CWE-311",
                "compliance_frameworks": ["CIS AWS 2.3.1"],
                "risk_score": 7
            }));
        }

        // Check for public snapshots
        match client
            .describe_db_snapshot_attributes()
            .db_snapshot_identifier(snapshot_id)
            .send()
            .await
        {
            Ok(attrs_response) => {
                if let Some(attrs) = attrs_response.db_snapshot_attributes_result() {
                    for attr in attrs.db_snapshot_attributes() {
                        if attr.attribute_name() == Some("restore") {
                            let values = attr.attribute_values();
                            {
                                if values.iter().any(|v| v == "all") {
                                    vulnerabilities.push(json!({
                                        "id": format!("rds-snapshot-public-{}", snapshot_id),
                                        "vuln_type": "Public RDS Snapshot",
                                        "severity": "Critical",
                                        "title": format!("RDS snapshot {} is publicly accessible", snapshot_id),
                                        "description": "Snapshot is shared with all AWS accounts, exposing database data.",
                                        "remediation": "Remove public restore permissions from the snapshot immediately.",
                                        "evidence": {
                                            "snapshot_id": snapshot_id,
                                            "restore_permission": "all"
                                        },
                                        "resource_id": snapshot_id,
                                        "resource_type": "rds-snapshot",
                                        "region": region,
                                        "cwe": "CWE-284",
                                        "compliance_frameworks": ["CIS AWS 2.3.3"],
                                        "risk_score": 10
                                    }));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[aws-rds-scanner] Could not get snapshot attributes for {}: {}", snapshot_id, e);
            }
        }
    }

    Ok((snapshots.len(), vulnerabilities))
}
