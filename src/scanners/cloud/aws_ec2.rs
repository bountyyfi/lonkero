// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * AWS EC2 Security Scanner
 * Scans EC2 instances for security vulnerabilities and misconfigurations
 *
 * © 2025 Bountyy Oy
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2Instance {
    pub instance_id: String,
    pub instance_type: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub vpc_id: String,
    pub subnet_id: String,
    pub security_groups: Vec<SecurityGroup>,
    pub image_id: String,
    pub launch_time: String,
    pub metadata_options: Option<MetadataOptions>,
    pub monitoring_state: String,
    pub tags: HashMap<String, String>,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroup {
    pub group_id: String,
    pub group_name: String,
    pub ingress_rules: Vec<SecurityGroupRule>,
    pub egress_rules: Vec<SecurityGroupRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupRule {
    pub protocol: String,
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    pub cidr_blocks: Vec<String>,
    pub ipv6_cidr_blocks: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataOptions {
    pub http_tokens: String, // "optional" (IMDSv1) or "required" (IMDSv2)
    pub http_put_response_hop_limit: i32,
    pub http_endpoint: String, // "enabled" or "disabled"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbsVolume {
    pub volume_id: String,
    pub size: i32,
    pub volume_type: String,
    pub encrypted: bool,
    pub kms_key_id: Option<String>,
    pub state: String,
    pub availability_zone: String,
    pub attachments: Vec<VolumeAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeAttachment {
    pub instance_id: String,
    pub device: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudVulnerability {
    pub id: String,
    pub vuln_type: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub evidence: serde_json::Value,
    pub cwe: String,
    pub compliance_frameworks: Vec<String>,
    pub resource_id: String,
    pub resource_type: String,
    pub region: String,
    pub risk_score: i32,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl ToString for Severity {
    fn to_string(&self) -> String {
        match self {
            Severity::Critical => "CRITICAL".to_string(),
            Severity::High => "HIGH".to_string(),
            Severity::Medium => "MEDIUM".to_string(),
            Severity::Low => "LOW".to_string(),
            Severity::Info => "INFO".to_string(),
        }
    }
}

pub struct AwsEc2Scanner;

impl AwsEc2Scanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan EC2 instances for security vulnerabilities
    pub fn scan_instances(&self, instances: &[Ec2Instance], volumes: &[EbsVolume]) -> Vec<CloudVulnerability> {
        let mut vulnerabilities = Vec::new();

        for instance in instances {
            // Check for public instances with open security groups
            vulnerabilities.extend(self.check_public_instance_with_open_sg(instance));

            // Check for IMDSv1 usage
            vulnerabilities.extend(self.check_imdsv1_enabled(instance));

            // Check for missing Systems Manager
            vulnerabilities.extend(self.check_ssm_agent(instance));

            // Check for public IP exposure
            vulnerabilities.extend(self.check_public_ip_exposure(instance));

            // Check security group misconfigurations
            vulnerabilities.extend(self.check_security_group_misconfigurations(instance));

            // Check for missing required tags
            vulnerabilities.extend(self.check_missing_tags(instance));

            // Check for monitoring disabled
            vulnerabilities.extend(self.check_monitoring_disabled(instance));

            // Check for old AMI
            vulnerabilities.extend(self.check_outdated_ami(instance));
        }

        // Check for unencrypted EBS volumes
        for volume in volumes {
            vulnerabilities.extend(self.check_unencrypted_volume(volume));
        }

        vulnerabilities
    }

    /// Check for public EC2 instances with overly permissive security groups
    fn check_public_instance_with_open_sg(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        if instance.public_ip.is_none() {
            return vulns;
        }

        for sg in &instance.security_groups {
            for rule in &sg.ingress_rules {
                if rule.cidr_blocks.contains(&"0.0.0.0/0".to_string()) {
                    vulns.push(CloudVulnerability {
                        id: format!("aws-ec2-public-{}", uuid::Uuid::new_v4()),
                        vuln_type: "Public EC2 Instance with Open Security Group".to_string(),
                        severity: Severity::High,
                        title: format!("EC2 instance {} has public access with open security group", instance.instance_id),
                        description: format!(
                            "EC2 instance {} has a public IP address and security group {} allows unrestricted access from 0.0.0.0/0 on port {}",
                            instance.instance_id,
                            sg.group_name,
                            rule.from_port.map(|p| p.to_string()).unwrap_or_else(|| "ALL".to_string())
                        ),
                        remediation: "Restrict security group rules to specific IP ranges. Use VPN or bastion hosts for remote access. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP access.".to_string(),
                        evidence: serde_json::json!({
                            "instance_id": instance.instance_id,
                            "public_ip": instance.public_ip,
                            "security_group": sg.group_name,
                            "security_group_id": sg.group_id,
                            "rule": {
                                "protocol": rule.protocol,
                                "from_port": rule.from_port,
                                "to_port": rule.to_port,
                                "cidr_blocks": rule.cidr_blocks
                            }
                        }),
                        cwe: "CWE-284".to_string(),
                        compliance_frameworks: vec!["CIS".to_string(), "NIST".to_string(), "PCI-DSS".to_string()],
                        resource_id: instance.instance_id.clone(),
                        resource_type: "ec2:instance".to_string(),
                        region: instance.region.clone(),
                        risk_score: 75,
                        discovered_at: Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        vulns
    }

    /// Check for IMDSv1 enabled (should use IMDSv2)
    fn check_imdsv1_enabled(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        if let Some(metadata_options) = &instance.metadata_options {
            if metadata_options.http_tokens == "optional" {
                vulns.push(CloudVulnerability {
                    id: format!("aws-ec2-imdsv1-{}", uuid::Uuid::new_v4()),
                    vuln_type: "IMDSv1 Enabled".to_string(),
                    severity: Severity::Medium,
                    title: format!("EC2 instance {} has IMDSv1 enabled", instance.instance_id),
                    description: format!(
                        "EC2 instance {} is configured to allow IMDSv1 (Instance Metadata Service v1), which is vulnerable to SSRF attacks. IMDSv2 should be required.",
                        instance.instance_id
                    ),
                    remediation: "Configure the instance to require IMDSv2 by setting HttpTokens to 'required'. Use: aws ec2 modify-instance-metadata-options --instance-id {} --http-tokens required --http-endpoint enabled".to_string(),
                    evidence: serde_json::json!({
                        "instance_id": instance.instance_id,
                        "http_tokens": metadata_options.http_tokens,
                        "http_endpoint": metadata_options.http_endpoint,
                        "http_put_response_hop_limit": metadata_options.http_put_response_hop_limit
                    }),
                    cwe: "CWE-918".to_string(),
                    compliance_frameworks: vec!["CIS".to_string(), "AWS".to_string()],
                    resource_id: instance.instance_id.clone(),
                    resource_type: "ec2:instance".to_string(),
                    region: instance.region.clone(),
                    risk_score: 60,
                    discovered_at: Utc::now().to_rfc3339(),
                });
            }
        }

        vulns
    }

    /// Check for missing AWS Systems Manager agent
    fn check_ssm_agent(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        // Check if instance has SSM tag or role
        let has_ssm_tag = instance.tags.get("SSMManaged").map(|v| v == "true").unwrap_or(false);

        if !has_ssm_tag && instance.state == "running" {
            vulns.push(CloudVulnerability {
                id: format!("aws-ec2-no-ssm-{}", uuid::Uuid::new_v4()),
                vuln_type: "Missing AWS Systems Manager".to_string(),
                severity: Severity::Low,
                title: format!("EC2 instance {} is not managed by AWS Systems Manager", instance.instance_id),
                description: format!(
                    "EC2 instance {} does not appear to be managed by AWS Systems Manager (SSM), which provides secure remote access, patch management, and configuration management.",
                    instance.instance_id
                ),
                remediation: "Install the SSM agent on the instance and attach an IAM role with the AmazonSSMManagedInstanceCore policy. This enables secure access without SSH keys and automated patch management.".to_string(),
                evidence: serde_json::json!({
                    "instance_id": instance.instance_id,
                    "tags": instance.tags
                }),
                cwe: "CWE-1188".to_string(),
                compliance_frameworks: vec!["AWS".to_string()],
                resource_id: instance.instance_id.clone(),
                resource_type: "ec2:instance".to_string(),
                region: instance.region.clone(),
                risk_score: 30,
                discovered_at: Utc::now().to_rfc3339(),
            });
        }

        vulns
    }

    /// Check for public IP address exposure
    fn check_public_ip_exposure(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        if let Some(public_ip) = &instance.public_ip {
            if instance.state == "running" {
                vulns.push(CloudVulnerability {
                    id: format!("aws-ec2-public-ip-{}", uuid::Uuid::new_v4()),
                    vuln_type: "EC2 Instance with Public IP".to_string(),
                    severity: Severity::Info,
                    title: format!("EC2 instance {} has a public IP address", instance.instance_id),
                    description: format!(
                        "EC2 instance {} is assigned a public IP address ({}). Consider whether this instance needs to be publicly accessible or if it should be placed in a private subnet behind a load balancer or NAT gateway.",
                        instance.instance_id, public_ip
                    ),
                    remediation: "Review if public access is necessary. If not, move the instance to a private subnet. Use a load balancer, API Gateway, or CloudFront for public-facing services. Use VPN or Direct Connect for administrative access.".to_string(),
                    evidence: serde_json::json!({
                        "instance_id": instance.instance_id,
                        "public_ip": public_ip,
                        "vpc_id": instance.vpc_id,
                        "subnet_id": instance.subnet_id
                    }),
                    cwe: "CWE-668".to_string(),
                    compliance_frameworks: vec!["CIS".to_string()],
                    resource_id: instance.instance_id.clone(),
                    resource_type: "ec2:instance".to_string(),
                    region: instance.region.clone(),
                    risk_score: 20,
                    discovered_at: Utc::now().to_rfc3339(),
                });
            }
        }

        vulns
    }

    /// Check for security group misconfigurations
    fn check_security_group_misconfigurations(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        // Define sensitive ports
        let sensitive_ports = vec![
            (22, "SSH"),
            (3389, "RDP"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (27017, "MongoDB"),
            (6379, "Redis"),
            (9200, "Elasticsearch"),
            (5984, "CouchDB"),
            (1433, "SQL Server"),
            (1521, "Oracle"),
        ];

        for sg in &instance.security_groups {
            for rule in &sg.ingress_rules {
                // Check for unrestricted access to sensitive ports
                if rule.cidr_blocks.contains(&"0.0.0.0/0".to_string()) ||
                   rule.ipv6_cidr_blocks.contains(&"::/0".to_string()) {

                    for (port, service) in &sensitive_ports {
                        let from_port = rule.from_port.unwrap_or(0);
                        let to_port = rule.to_port.unwrap_or(65535);

                        if from_port <= *port && *port <= to_port {
                            vulns.push(CloudVulnerability {
                                id: format!("aws-ec2-open-port-{}", uuid::Uuid::new_v4()),
                                vuln_type: format!("Unrestricted {} Access", service),
                                severity: if *port == 22 || *port == 3389 { Severity::Critical } else { Severity::High },
                                title: format!("EC2 instance {} allows unrestricted {} access", instance.instance_id, service),
                                description: format!(
                                    "Security group {} attached to EC2 instance {} allows unrestricted access from 0.0.0.0/0 to port {} ({}). This is a significant security risk.",
                                    sg.group_name, instance.instance_id, port, service
                                ),
                                remediation: format!(
                                    "Restrict access to port {} in security group {}. Allow access only from specific IP addresses or security groups. For {} access, use VPN, bastion hosts, or AWS Systems Manager Session Manager.",
                                    port, sg.group_id, service
                                ),
                                evidence: serde_json::json!({
                                    "instance_id": instance.instance_id,
                                    "security_group": sg.group_name,
                                    "security_group_id": sg.group_id,
                                    "port": port,
                                    "service": service,
                                    "rule": {
                                        "protocol": rule.protocol,
                                        "from_port": rule.from_port,
                                        "to_port": rule.to_port,
                                        "cidr_blocks": rule.cidr_blocks,
                                        "ipv6_cidr_blocks": rule.ipv6_cidr_blocks
                                    }
                                }),
                                cwe: "CWE-284".to_string(),
                                compliance_frameworks: vec!["CIS".to_string(), "NIST".to_string(), "PCI-DSS".to_string()],
                                resource_id: instance.instance_id.clone(),
                                resource_type: "ec2:instance".to_string(),
                                region: instance.region.clone(),
                                risk_score: if *port == 22 || *port == 3389 { 90 } else { 80 },
                                discovered_at: Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }
        }

        vulns
    }

    /// Check for missing required tags
    fn check_missing_tags(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        // Define required tags
        let required_tags = vec!["Environment", "Owner", "CostCenter", "Name"];
        let mut missing_tags = Vec::new();

        for tag in &required_tags {
            if !instance.tags.contains_key(*tag) {
                missing_tags.push(tag.to_string());
            }
        }

        if !missing_tags.is_empty() {
            vulns.push(CloudVulnerability {
                id: format!("aws-ec2-missing-tags-{}", uuid::Uuid::new_v4()),
                vuln_type: "Missing Required Tags".to_string(),
                severity: Severity::Low,
                title: format!("EC2 instance {} is missing required tags", instance.instance_id),
                description: format!(
                    "EC2 instance {} is missing the following required tags: {}. Proper tagging is essential for cost allocation, access control, and resource management.",
                    instance.instance_id,
                    missing_tags.join(", ")
                ),
                remediation: format!(
                    "Add the following tags to the instance: {}. Use tag policies to enforce tagging standards across your organization.",
                    missing_tags.join(", ")
                ),
                evidence: serde_json::json!({
                    "instance_id": instance.instance_id,
                    "missing_tags": missing_tags,
                    "current_tags": instance.tags
                }),
                cwe: "CWE-1188".to_string(),
                compliance_frameworks: vec!["AWS".to_string()],
                resource_id: instance.instance_id.clone(),
                resource_type: "ec2:instance".to_string(),
                region: instance.region.clone(),
                risk_score: 15,
                discovered_at: Utc::now().to_rfc3339(),
            });
        }

        vulns
    }

    /// Check for monitoring disabled
    fn check_monitoring_disabled(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        if instance.monitoring_state != "enabled" && instance.state == "running" {
            vulns.push(CloudVulnerability {
                id: format!("aws-ec2-no-monitoring-{}", uuid::Uuid::new_v4()),
                vuln_type: "Detailed Monitoring Disabled".to_string(),
                severity: Severity::Low,
                title: format!("EC2 instance {} has detailed monitoring disabled", instance.instance_id),
                description: format!(
                    "EC2 instance {} does not have detailed CloudWatch monitoring enabled. Detailed monitoring provides 1-minute metrics instead of 5-minute metrics for better visibility.",
                    instance.instance_id
                ),
                remediation: "Enable detailed monitoring for the instance. Use: aws ec2 monitor-instances --instance-ids {}".to_string(),
                evidence: serde_json::json!({
                    "instance_id": instance.instance_id,
                    "monitoring_state": instance.monitoring_state
                }),
                cwe: "CWE-778".to_string(),
                compliance_frameworks: vec!["AWS".to_string()],
                resource_id: instance.instance_id.clone(),
                resource_type: "ec2:instance".to_string(),
                region: instance.region.clone(),
                risk_score: 10,
                discovered_at: Utc::now().to_rfc3339(),
            });
        }

        vulns
    }

    /// Check for outdated AMI
    fn check_outdated_ami(&self, instance: &Ec2Instance) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        // Check if launch time is older than 90 days
        if let Ok(launch_time) = chrono::DateTime::parse_from_rfc3339(&instance.launch_time) {
            let launch_time_utc = launch_time.with_timezone(&Utc);
            let age_days = (Utc::now().timestamp() - launch_time_utc.timestamp()) / 86400;

            if age_days > 90 && instance.state == "running" {
                vulns.push(CloudVulnerability {
                    id: format!("aws-ec2-old-ami-{}", uuid::Uuid::new_v4()),
                    vuln_type: "Outdated EC2 Instance".to_string(),
                    severity: Severity::Medium,
                    title: format!("EC2 instance {} is running for {} days", instance.instance_id, age_days),
                    description: format!(
                        "EC2 instance {} was launched {} days ago using AMI {}. Long-running instances may be running outdated software with known vulnerabilities. Consider using immutable infrastructure patterns.",
                        instance.instance_id, age_days, instance.image_id
                    ),
                    remediation: "Review and update the instance. Use AWS Systems Manager Patch Manager for automated patching. Consider using Auto Scaling Groups with Launch Templates to automate instance replacement with updated AMIs.".to_string(),
                    evidence: serde_json::json!({
                        "instance_id": instance.instance_id,
                        "image_id": instance.image_id,
                        "launch_time": instance.launch_time,
                        "age_days": age_days
                    }),
                    cwe: "CWE-1329".to_string(),
                    compliance_frameworks: vec!["CIS".to_string(), "AWS".to_string()],
                    resource_id: instance.instance_id.clone(),
                    resource_type: "ec2:instance".to_string(),
                    region: instance.region.clone(),
                    risk_score: 50,
                    discovered_at: Utc::now().to_rfc3339(),
                });
            }
        }

        vulns
    }

    /// Check for unencrypted EBS volumes
    fn check_unencrypted_volume(&self, volume: &EbsVolume) -> Vec<CloudVulnerability> {
        let mut vulns = Vec::new();

        if !volume.encrypted && volume.state != "deleting" && volume.state != "deleted" {
            let severity = if volume.attachments.is_empty() {
                Severity::Low
            } else {
                Severity::High
            };

            vulns.push(CloudVulnerability {
                id: format!("aws-ebs-unencrypted-{}", uuid::Uuid::new_v4()),
                vuln_type: "Unencrypted EBS Volume".to_string(),
                severity,
                title: format!("EBS volume {} is not encrypted", volume.volume_id),
                description: format!(
                    "EBS volume {} ({} GB, {}) is not encrypted. Unencrypted volumes may expose sensitive data if snapshots are shared or if physical storage media is compromised.",
                    volume.volume_id, volume.size, volume.volume_type
                ),
                remediation: "Enable encryption for all new EBS volumes by default. For existing volumes, create an encrypted snapshot and restore to a new encrypted volume. Use AWS KMS for encryption key management.".to_string(),
                evidence: serde_json::json!({
                    "volume_id": volume.volume_id,
                    "size_gb": volume.size,
                    "volume_type": volume.volume_type,
                    "encrypted": volume.encrypted,
                    "state": volume.state,
                    "attachments": volume.attachments,
                    "availability_zone": volume.availability_zone
                }),
                cwe: "CWE-311".to_string(),
                compliance_frameworks: vec!["CIS".to_string(), "PCI-DSS".to_string(), "HIPAA".to_string()],
                resource_id: volume.volume_id.clone(),
                resource_type: "ec2:volume".to_string(),
                region: volume.availability_zone.clone(),
                risk_score: if volume.attachments.is_empty() { 40 } else { 70 },
                discovered_at: Utc::now().to_rfc3339(),
            });
        }

        vulns
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
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

    fn create_test_instance() -> Ec2Instance {
        Ec2Instance {
            instance_id: "i-1234567890abcdef0".to_string(),
            instance_type: "t3.micro".to_string(),
            state: "running".to_string(),
            public_ip: Some("54.123.456.789".to_string()),
            private_ip: Some("10.0.1.100".to_string()),
            vpc_id: "vpc-12345678".to_string(),
            subnet_id: "subnet-12345678".to_string(),
            security_groups: vec![],
            image_id: "ami-12345678".to_string(),
            launch_time: "2024-01-01T00:00:00Z".to_string(),
            metadata_options: Some(MetadataOptions {
                http_tokens: "optional".to_string(),
                http_put_response_hop_limit: 1,
                http_endpoint: "enabled".to_string(),
            }),
            monitoring_state: "disabled".to_string(),
            tags: HashMap::new(),
            region: "us-east-1".to_string(),
        }
    }

    #[test]
    fn test_imdsv1_detection() {
        let scanner = AwsEc2Scanner::new();
        let instance = create_test_instance();
        let vulns = scanner.check_imdsv1_enabled(&instance);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].vuln_type, "IMDSv1 Enabled");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_unencrypted_volume_detection() {
        let scanner = AwsEc2Scanner::new();
        let volume = EbsVolume {
            volume_id: "vol-12345678".to_string(),
            size: 100,
            volume_type: "gp3".to_string(),
            encrypted: false,
            kms_key_id: None,
            state: "in-use".to_string(),
            availability_zone: "us-east-1a".to_string(),
            attachments: vec![VolumeAttachment {
                instance_id: "i-12345678".to_string(),
                device: "/dev/sda1".to_string(),
                state: "attached".to_string(),
            }],
        };

        let vulns = scanner.check_unencrypted_volume(&volume);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].vuln_type, "Unencrypted EBS Volume");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_open_ssh_port_detection() {
        let scanner = AwsEc2Scanner::new();
        let mut instance = create_test_instance();
        instance.security_groups = vec![SecurityGroup {
            group_id: "sg-12345678".to_string(),
            group_name: "default".to_string(),
            ingress_rules: vec![SecurityGroupRule {
                protocol: "tcp".to_string(),
                from_port: Some(22),
                to_port: Some(22),
                cidr_blocks: vec!["0.0.0.0/0".to_string()],
                ipv6_cidr_blocks: vec![],
                description: Some("SSH access".to_string()),
            }],
            egress_rules: vec![],
        }];

        let vulns = scanner.check_security_group_misconfigurations(&instance);

        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].severity, Severity::Critical);
    }
}
