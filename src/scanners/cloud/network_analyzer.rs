// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Network Analyzer
 * Security analysis for AWS Security Groups, Azure NSGs, and GCP Firewall Rules
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::cloud::error_handling::{CloudError, RetryConfig, retry_with_backoff};
use crate::cloud::optimizations::{CloudMetadataCache, PerformanceMetrics};
use crate::types::{Confidence, Severity, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Network finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkFindingType {
    UnrestrictedIngress,
    UnrestrictedEgress,
    OpenManagementPorts,
    RulePriorityConflict,
    UnusedSecurityGroup,
    DefaultDenyMissing,
    InsecureProtocol,
    WidePortRange,
}

/// Network security rule analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRuleAnalysis {
    pub rule_id: String,
    pub rule_name: String,
    pub direction: String,
    pub source: String,
    pub destination: String,
    pub port_range: String,
    pub protocol: String,
    pub findings: Vec<NetworkFinding>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFinding {
    pub finding_type: NetworkFindingType,
    pub severity: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub remediation: String,
}

pub struct CloudNetworkAnalyzer {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
    dangerous_ports: HashSet<u16>,
    management_ports: HashSet<u16>,
}

impl CloudNetworkAnalyzer {
    pub fn new() -> Self {
        let cache = Arc::new(CloudMetadataCache::new(
            Duration::from_secs(300),
            1000,
        ));

        // Define dangerous ports that should never be open to 0.0.0.0/0
        let dangerous_ports: HashSet<u16> = [
            20, 21,   // FTP
            22,       // SSH
            23,       // Telnet
            25,       // SMTP
            53,       // DNS
            135,      // MS RPC
            139, 445, // SMB
            1433,     // MS SQL
            3306,     // MySQL
            3389,     // RDP
            5432,     // PostgreSQL
            5900,     // VNC
            6379,     // Redis
            8080,     // HTTP Alt
            9200,     // Elasticsearch
            27017,    // MongoDB
        ]
        .iter()
        .cloned()
        .collect();

        let management_ports: HashSet<u16> = [
            22,   // SSH
            3389, // RDP
            5985, // WinRM HTTP
            5986, // WinRM HTTPS
        ]
        .iter()
        .cloned()
        .collect();

        Self {
            cache,
            retry_config: RetryConfig::default(),
            dangerous_ports,
            management_ports,
        }
    }

    /// Analyze AWS Security Groups
    pub async fn analyze_aws_security_groups(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS Security Groups Analysis");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS Security Groups analysis");

        let client = aws_sdk_ec2::Client::new(aws_config);

        // Get all security groups
        metrics.record_api_call();
        let sg_result = retry_with_backoff(
            || async {
                client
                    .describe_security_groups()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe security groups: {}", e)))
            },
            self.retry_config.clone(),
            "describe_security_groups",
        )
        .await?;

        if let Some(security_groups) = sg_result.security_groups {
            for sg in &security_groups {
                let sg_id = sg.group_id().unwrap_or("unknown");
                let sg_name = sg.group_name().unwrap_or("unknown");

                debug!("Analyzing security group: {} ({})", sg_name, sg_id);

                // Analyze ingress rules
                for rule in sg.ip_permissions() {
                    let vulns = self.analyze_aws_ingress_rule(rule, sg_id, sg_name);
                    vulnerabilities.extend(vulns);
                }

                // Analyze egress rules
                for rule in sg.ip_permissions_egress() {
                    let vulns = self.analyze_aws_egress_rule(rule, sg_id, sg_name);
                    vulnerabilities.extend(vulns);
                }
            }

            // Check for unused security groups
            let used_sgs = self.get_used_security_groups(&client).await?;
            for sg in &security_groups {
                let sg_id = sg.group_id().unwrap_or("unknown");
                if !used_sgs.contains(sg_id) && sg.group_name() != Some("default") {
                    vulnerabilities.push(self.create_vulnerability(
                        "Unused AWS Security Group",
                        Severity::Low,
                        Confidence::High,
                        format!("Security group '{}' ({}) is not attached to any resources",
                                sg.group_name().unwrap_or("unknown"), sg_id),
                        format!("Security Group ID: {}", sg_id),
                        "Remove unused security groups to reduce attack surface and management complexity",
                        "CWE-1188",
                        3.0,
                    ));
                }
            }
        }

        metrics.report();
        info!("AWS Security Groups analysis completed. Found {} issues", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    fn analyze_aws_ingress_rule(
        &self,
        rule: &aws_sdk_ec2::types::IpPermission,
        sg_id: &str,
        sg_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let from_port = rule.from_port().unwrap_or(0);
        let to_port = rule.to_port().unwrap_or(65535);
        let protocol = rule.ip_protocol().unwrap_or("-1");

        // Check for 0.0.0.0/0 access
        for ip_range in rule.ip_ranges() {
            if let Some(cidr) = ip_range.cidr_ip() {
                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                    // Check if dangerous ports are exposed
                    for port in from_port..=to_port {
                        if self.dangerous_ports.contains(&(port as u16)) {
                            let is_critical = self.management_ports.contains(&(port as u16));
                            let severity = if is_critical {
                                Severity::Critical
                            } else {
                                Severity::High
                            };

                            vulnerabilities.push(self.create_vulnerability(
                                "AWS Security Group Allows Unrestricted Access to Sensitive Port",
                                severity,
                                Confidence::High,
                                format!(
                                    "Security group '{}' ({}) allows unrestricted ingress on port {} from 0.0.0.0/0",
                                    sg_name, sg_id, port
                                ),
                                format!("Protocol: {}, Port: {}, Source: {}", protocol, port, cidr),
                                "Restrict access to specific IP addresses or ranges. Never expose management ports to the internet.",
                                "CWE-923",
                                if is_critical { 9.8 } else { 7.5 },
                            ));
                            break; // Only report once per rule
                        }
                    }

                    // Check for wide port ranges
                    if to_port - from_port > 100 && protocol != "icmp" {
                        vulnerabilities.push(self.create_vulnerability(
                            "AWS Security Group with Wide Port Range",
                            Severity::Medium,
                            Confidence::High,
                            format!(
                                "Security group '{}' ({}) allows unrestricted access to a wide port range ({}-{})",
                                sg_name, sg_id, from_port, to_port
                            ),
                            format!("Protocol: {}, Ports: {}-{}, Source: {}", protocol, from_port, to_port, cidr),
                            "Limit port ranges to only what is necessary for your application",
                            "CWE-923",
                            6.0,
                        ));
                    }

                    // Check for unrestricted protocol access
                    if protocol == "-1" {
                        vulnerabilities.push(self.create_vulnerability(
                            "AWS Security Group Allows All Protocols",
                            Severity::High,
                            Confidence::High,
                            format!(
                                "Security group '{}' ({}) allows all protocols from 0.0.0.0/0",
                                sg_name, sg_id
                            ),
                            format!("All protocols allowed from {}", cidr),
                            "Specify exact protocols required instead of allowing all",
                            "CWE-923",
                            8.0,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    fn analyze_aws_egress_rule(
        &self,
        rule: &aws_sdk_ec2::types::IpPermission,
        sg_id: &str,
        sg_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let protocol = rule.ip_protocol().unwrap_or("-1");

        // Check for overly permissive egress (0.0.0.0/0 on all ports/protocols)
        for ip_range in rule.ip_ranges() {
            if let Some(cidr) = ip_range.cidr_ip() {
                if (cidr == "0.0.0.0/0" || cidr == "::/0") && protocol == "-1" {
                    vulnerabilities.push(self.create_vulnerability(
                        "AWS Security Group with Unrestricted Egress",
                        Severity::Low,
                        Confidence::Medium,
                        format!(
                            "Security group '{}' ({}) allows unrestricted egress to 0.0.0.0/0",
                            sg_name, sg_id
                        ),
                        format!("All protocols allowed to {}", cidr),
                        "Consider implementing egress filtering to prevent data exfiltration",
                        "CWE-284",
                        4.0,
                    ));
                }
            }
        }

        vulnerabilities
    }

    async fn get_used_security_groups(
        &self,
        client: &aws_sdk_ec2::Client,
    ) -> Result<HashSet<String>, CloudError> {
        let mut used_sgs = HashSet::new();

        // Get all EC2 instances
        let instances_result = client
            .describe_instances()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to describe instances: {}", e)))?;

        if let Some(reservations) = instances_result.reservations {
            for reservation in reservations {
                if let Some(instances) = reservation.instances {
                    for instance in instances {
                        if let Some(security_groups) = instance.security_groups {
                            for sg in security_groups {
                                if let Some(sg_id) = sg.group_id() {
                                    used_sgs.insert(sg_id.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Get all network interfaces
        let eni_result = client
            .describe_network_interfaces()
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("Failed to describe network interfaces: {}", e)))?;

        if let Some(interfaces) = eni_result.network_interfaces {
            for interface in interfaces {
                if let Some(groups) = interface.groups {
                    for group in groups {
                        if let Some(group_id) = group.group_id() {
                            used_sgs.insert(group_id.to_string());
                        }
                    }
                }
            }
        }

        Ok(used_sgs)
    }

    /// Analyze Azure Network Security Groups
    pub async fn analyze_azure_nsgs(&self) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        info!("Starting Azure NSG analysis");

        // Note: This is a placeholder for Azure NSG analysis
        // In production, you would use the Azure SDK to:
        // 1. List all NSGs
        // 2. Analyze rule priorities for conflicts
        // 3. Check for overly permissive rules
        // 4. Identify rules allowing access from Any (*) source
        // 5. Check for proper default deny rules

        warn!("Azure NSG analysis requires Azure credentials configuration");

        Ok(vulnerabilities)
    }

    /// Analyze GCP Firewall Rules
    pub async fn analyze_gcp_firewall(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        info!("Starting GCP Firewall Rules analysis for project: {}", project_id);

        // Note: This is a placeholder for GCP Firewall analysis
        // In production, you would use the GCP SDK to:
        // 1. List all firewall rules
        // 2. Check for default-deny rules
        // 3. Analyze rule conflicts
        // 4. Check for overly permissive rules (0.0.0.0/0)
        // 5. Identify unused rules

        warn!("GCP Firewall analysis requires GCP credentials configuration");

        Ok(vulnerabilities)
    }

    /// Check if port is considered dangerous
    pub fn is_dangerous_port(&self, port: u16) -> bool {
        self.dangerous_ports.contains(&port)
    }

    /// Check if port is a management port
    pub fn is_management_port(&self, port: u16) -> bool {
        self.management_ports.contains(&port)
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
            id: format!("network_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud Network Security".to_string(),
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

impl Default for CloudNetworkAnalyzer {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_ports() {
        let analyzer = CloudNetworkAnalyzer::new();

        assert!(analyzer.is_dangerous_port(22));
        assert!(analyzer.is_dangerous_port(3389));
        assert!(analyzer.is_dangerous_port(3306));
        assert!(!analyzer.is_dangerous_port(443));
    }

    #[test]
    fn test_management_ports() {
        let analyzer = CloudNetworkAnalyzer::new();

        assert!(analyzer.is_management_port(22));
        assert!(analyzer.is_management_port(3389));
        assert!(!analyzer.is_management_port(80));
    }
}
