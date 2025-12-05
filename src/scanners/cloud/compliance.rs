// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Cloud Compliance Engine
 * CIS Benchmark validation for AWS, Azure, and GCP
 *
 * Validates:
 * - CIS AWS Foundations Benchmark
 * - CIS Azure Foundations Benchmark
 * - CIS GCP Foundations Benchmark
 *
 * © 2025 Bountyy Oy
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    CisAws,
    CisAzure,
    CisGcp,
    Soc2,
    Iso27001,
    Nist,
    PciDss,
    Hipaa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Passed,
    Failed,
    Warning,
    Manual,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub severity: Severity,
    pub automated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub status: ComplianceStatus,
    pub severity: Severity,
    pub findings: Vec<ComplianceFinding>,
    pub remediation: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub resource_id: String,
    pub resource_type: String,
    pub description: String,
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub total_controls: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub manual: usize,
    pub not_applicable: usize,
    pub compliance_score: f64,
    pub results: Vec<ComplianceResult>,
}

pub struct CloudComplianceEngine {
    framework: ComplianceFramework,
    controls: Vec<ComplianceControl>,
}

impl CloudComplianceEngine {
    pub fn new(framework: ComplianceFramework) -> Self {
        let controls = match &framework {
            ComplianceFramework::CisAws => Self::load_cis_aws_controls(),
            ComplianceFramework::CisAzure => Self::load_cis_azure_controls(),
            ComplianceFramework::CisGcp => Self::load_cis_gcp_controls(),
            ComplianceFramework::Soc2 => Self::load_soc2_controls(),
            ComplianceFramework::Iso27001 => Self::load_iso27001_controls(),
            ComplianceFramework::Nist => Self::load_nist_controls(),
            ComplianceFramework::PciDss => Self::load_pci_dss_controls(),
            ComplianceFramework::Hipaa => Self::load_hipaa_controls(),
        };

        info!("Loaded {} controls for {:?}", controls.len(), framework);

        Self { framework, controls }
    }

    /// Validate compliance against framework
    pub fn validate(&self, cloud_config: &CloudConfiguration) -> ComplianceReport {
        info!("Validating compliance against {:?}", self.framework);

        let mut results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut manual = 0;
        let mut not_applicable = 0;

        for control in &self.controls {
            let result = self.validate_control(control, cloud_config);

            match result.status {
                ComplianceStatus::Passed => passed += 1,
                ComplianceStatus::Failed => failed += 1,
                ComplianceStatus::Warning => warnings += 1,
                ComplianceStatus::Manual => manual += 1,
                ComplianceStatus::NotApplicable => not_applicable += 1,
            }

            results.push(result);
        }

        let total_controls = self.controls.len();
        let compliance_score = if total_controls > 0 {
            (passed as f64 / (total_controls - manual - not_applicable) as f64) * 100.0
        } else {
            0.0
        };

        ComplianceReport {
            framework: self.framework.clone(),
            total_controls,
            passed,
            failed,
            warnings,
            manual,
            not_applicable,
            compliance_score,
            results,
        }
    }

    /// Validate individual control
    fn validate_control(
        &self,
        control: &ComplianceControl,
        config: &CloudConfiguration,
    ) -> ComplianceResult {
        debug!("Validating control: {}", control.id);

        let (status, findings) = match self.framework {
            ComplianceFramework::CisAws => self.validate_cis_aws_control(control, config),
            ComplianceFramework::CisAzure => self.validate_cis_azure_control(control, config),
            ComplianceFramework::CisGcp => self.validate_cis_gcp_control(control, config),
            _ => (ComplianceStatus::Manual, Vec::new()),
        };

        let score = match status {
            ComplianceStatus::Passed => 100.0,
            ComplianceStatus::Failed => 0.0,
            ComplianceStatus::Warning => 50.0,
            _ => 0.0,
        };

        ComplianceResult {
            control_id: control.id.clone(),
            framework: self.framework.clone(),
            status,
            severity: control.severity.clone(),
            findings,
            remediation: self.get_remediation(&control.id),
            score,
        }
    }

    /// Validate CIS AWS control
    fn validate_cis_aws_control(
        &self,
        control: &ComplianceControl,
        config: &CloudConfiguration,
    ) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        match control.id.as_str() {
            "2.1" => self.check_cloudtrail_enabled(config),
            "2.2" => self.check_cloudtrail_log_validation(config),
            "3.1" => self.check_vpc_flow_logging(config),
            "4.1" => self.check_security_group_ssh(config),
            "4.2" => self.check_security_group_rdp(config),
            "5.1" => self.check_s3_logging(config),
            _ => (ComplianceStatus::Manual, Vec::new()),
        }
    }

    /// Validate CIS Azure control
    fn validate_cis_azure_control(
        &self,
        control: &ComplianceControl,
        config: &CloudConfiguration,
    ) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        match control.id.as_str() {
            "1.1" => self.check_azure_mfa(config),
            "2.1" => self.check_azure_defender(config),
            "3.1" => self.check_azure_storage_keys(config),
            "4.1" => self.check_azure_sql_encryption(config),
            "6.1" => self.check_azure_rdp_restriction(config),
            _ => (ComplianceStatus::Manual, Vec::new()),
        }
    }

    /// Validate CIS GCP control
    fn validate_cis_gcp_control(
        &self,
        control: &ComplianceControl,
        config: &CloudConfiguration,
    ) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        match control.id.as_str() {
            "1.1" => self.check_gcp_corporate_login(config),
            "2.1" => self.check_gcp_audit_logging(config),
            "3.1" => self.check_gcp_default_network(config),
            "4.1" => self.check_gcp_default_service_account(config),
            "5.1" => self.check_gcp_storage_public_access(config),
            _ => (ComplianceStatus::Manual, Vec::new()),
        }
    }

    // AWS Compliance Checks

    fn check_cloudtrail_enabled(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.cloudtrail_trails
            .iter()
            .filter(|t| !t.is_multi_region || !t.enabled)
            .map(|t| ComplianceFinding {
                resource_id: t.name.clone(),
                resource_type: "CloudTrail".to_string(),
                description: "CloudTrail not enabled in all regions".to_string(),
                evidence: HashMap::from([
                    ("enabled".to_string(), t.enabled.to_string()),
                    ("multi_region".to_string(), t.is_multi_region.to_string()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_cloudtrail_log_validation(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.cloudtrail_trails
            .iter()
            .filter(|t| !t.log_file_validation_enabled)
            .map(|t| ComplianceFinding {
                resource_id: t.name.clone(),
                resource_type: "CloudTrail".to_string(),
                description: "CloudTrail log file validation not enabled".to_string(),
                evidence: HashMap::from([
                    ("log_validation".to_string(), t.log_file_validation_enabled.to_string()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_vpc_flow_logging(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.vpcs
            .iter()
            .filter(|v| !v.flow_logs_enabled)
            .map(|v| ComplianceFinding {
                resource_id: v.vpc_id.clone(),
                resource_type: "VPC".to_string(),
                description: "VPC flow logging not enabled".to_string(),
                evidence: HashMap::from([
                    ("flow_logs".to_string(), v.flow_logs_enabled.to_string()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_security_group_ssh(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.security_groups
            .iter()
            .filter(|sg| {
                sg.ingress_rules.iter().any(|rule| {
                    rule.port == 22 && rule.source == "0.0.0.0/0"
                })
            })
            .map(|sg| ComplianceFinding {
                resource_id: sg.group_id.clone(),
                resource_type: "SecurityGroup".to_string(),
                description: "Security group allows SSH from 0.0.0.0/0".to_string(),
                evidence: HashMap::from([
                    ("group_name".to_string(), sg.group_name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_security_group_rdp(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.security_groups
            .iter()
            .filter(|sg| {
                sg.ingress_rules.iter().any(|rule| {
                    rule.port == 3389 && rule.source == "0.0.0.0/0"
                })
            })
            .map(|sg| ComplianceFinding {
                resource_id: sg.group_id.clone(),
                resource_type: "SecurityGroup".to_string(),
                description: "Security group allows RDP from 0.0.0.0/0".to_string(),
                evidence: HashMap::from([
                    ("group_name".to_string(), sg.group_name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_s3_logging(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.s3_buckets
            .iter()
            .filter(|b| !b.logging_enabled)
            .map(|b| ComplianceFinding {
                resource_id: b.name.clone(),
                resource_type: "S3Bucket".to_string(),
                description: "S3 bucket access logging not enabled".to_string(),
                evidence: HashMap::from([
                    ("logging".to_string(), b.logging_enabled.to_string()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    // Azure Compliance Checks

    fn check_azure_mfa(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.azure_users
            .iter()
            .filter(|u| u.is_admin && !u.mfa_enabled)
            .map(|u| ComplianceFinding {
                resource_id: u.user_id.clone(),
                resource_type: "AzureUser".to_string(),
                description: "MFA not enabled for privileged user".to_string(),
                evidence: HashMap::from([
                    ("username".to_string(), u.username.clone()),
                    ("is_admin".to_string(), u.is_admin.to_string()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_azure_defender(&self, _config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        // This would require Azure Security Center API check
        (ComplianceStatus::Manual, Vec::new())
    }

    fn check_azure_storage_keys(&self, _config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        // This would require checking key rotation policies
        (ComplianceStatus::Manual, Vec::new())
    }

    fn check_azure_sql_encryption(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.azure_sql_databases
            .iter()
            .filter(|db| !db.encryption_enabled)
            .map(|db| ComplianceFinding {
                resource_id: db.database_id.clone(),
                resource_type: "AzureSqlDatabase".to_string(),
                description: "SQL database encryption not enabled".to_string(),
                evidence: HashMap::from([
                    ("database_name".to_string(), db.name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_azure_rdp_restriction(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.azure_nsgs
            .iter()
            .filter(|nsg| {
                nsg.rules.iter().any(|rule| {
                    rule.destination_port == 3389 && rule.source_address == "*"
                })
            })
            .map(|nsg| ComplianceFinding {
                resource_id: nsg.nsg_id.clone(),
                resource_type: "NetworkSecurityGroup".to_string(),
                description: "RDP access not restricted from Internet".to_string(),
                evidence: HashMap::from([
                    ("nsg_name".to_string(), nsg.name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    // GCP Compliance Checks

    fn check_gcp_corporate_login(&self, _config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        // This requires checking identity provider configuration
        (ComplianceStatus::Manual, Vec::new())
    }

    fn check_gcp_audit_logging(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.gcp_projects
            .iter()
            .filter(|p| !p.audit_logging_enabled)
            .map(|p| ComplianceFinding {
                resource_id: p.project_id.clone(),
                resource_type: "GcpProject".to_string(),
                description: "Cloud audit logging not configured".to_string(),
                evidence: HashMap::from([
                    ("project_name".to_string(), p.name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_gcp_default_network(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.gcp_networks
            .iter()
            .filter(|n| n.name == "default")
            .map(|n| ComplianceFinding {
                resource_id: n.network_id.clone(),
                resource_type: "GcpNetwork".to_string(),
                description: "Default network exists in project".to_string(),
                evidence: HashMap::from([
                    ("network_name".to_string(), n.name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_gcp_default_service_account(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.gcp_instances
            .iter()
            .filter(|i| i.uses_default_service_account)
            .map(|i| ComplianceFinding {
                resource_id: i.instance_id.clone(),
                resource_type: "GcpInstance".to_string(),
                description: "Instance uses default service account".to_string(),
                evidence: HashMap::from([
                    ("instance_name".to_string(), i.name.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    fn check_gcp_storage_public_access(&self, config: &CloudConfiguration) -> (ComplianceStatus, Vec<ComplianceFinding>) {
        let findings = config.gcp_buckets
            .iter()
            .filter(|b| b.public_access_prevention == "inherited")
            .map(|b| ComplianceFinding {
                resource_id: b.name.clone(),
                resource_type: "GcpBucket".to_string(),
                description: "Storage bucket may be publicly accessible".to_string(),
                evidence: HashMap::from([
                    ("public_access_prevention".to_string(), b.public_access_prevention.clone()),
                ]),
            })
            .collect::<Vec<_>>();

        let status = if findings.is_empty() {
            ComplianceStatus::Passed
        } else {
            ComplianceStatus::Failed
        };

        (status, findings)
    }

    /// Get remediation guidance
    fn get_remediation(&self, control_id: &str) -> String {
        match control_id {
            "2.1" => "Enable CloudTrail in all regions and configure it to log management and data events.".to_string(),
            "2.2" => "Enable log file validation for all CloudTrail trails to detect log tampering.".to_string(),
            "3.1" => "Enable VPC Flow Logs for all VPCs to capture network traffic information.".to_string(),
            "4.1" => "Remove security group rules that allow SSH (port 22) access from 0.0.0.0/0.".to_string(),
            "4.2" => "Remove security group rules that allow RDP (port 3389) access from 0.0.0.0/0.".to_string(),
            "5.1" => "Enable access logging for all S3 buckets to track requests.".to_string(),
            _ => "Refer to CIS Benchmark documentation for remediation steps.".to_string(),
        }
    }

    /// Load CIS AWS controls
    fn load_cis_aws_controls() -> Vec<ComplianceControl> {
        vec![
            ComplianceControl {
                id: "2.1".to_string(),
                title: "Ensure CloudTrail is enabled in all regions".to_string(),
                description: "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you.".to_string(),
                category: "Logging".to_string(),
                severity: Severity::High,
                automated: true,
            },
            ComplianceControl {
                id: "2.2".to_string(),
                title: "Ensure CloudTrail log file validation is enabled".to_string(),
                description: "CloudTrail log file validation creates a digitally signed digest file.".to_string(),
                category: "Logging".to_string(),
                severity: Severity::Medium,
                automated: true,
            },
            ComplianceControl {
                id: "3.1".to_string(),
                title: "Ensure VPC flow logging is enabled in all VPCs".to_string(),
                description: "VPC Flow Logs is a feature that enables you to capture information about IP traffic.".to_string(),
                category: "Networking".to_string(),
                severity: Severity::High,
                automated: true,
            },
            ComplianceControl {
                id: "4.1".to_string(),
                title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22".to_string(),
                description: "Security groups provide stateful filtering of ingress/egress network traffic.".to_string(),
                category: "Networking".to_string(),
                severity: Severity::Critical,
                automated: true,
            },
            ComplianceControl {
                id: "4.2".to_string(),
                title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389".to_string(),
                description: "Security groups provide stateful filtering of ingress/egress network traffic.".to_string(),
                category: "Networking".to_string(),
                severity: Severity::Critical,
                automated: true,
            },
            ComplianceControl {
                id: "5.1".to_string(),
                title: "Ensure S3 bucket access logging is enabled".to_string(),
                description: "S3 Bucket Access Logging generates a log that contains access records for requests.".to_string(),
                category: "Storage".to_string(),
                severity: Severity::Medium,
                automated: true,
            },
        ]
    }

    /// Load CIS Azure controls
    fn load_cis_azure_controls() -> Vec<ComplianceControl> {
        vec![
            ComplianceControl {
                id: "1.1".to_string(),
                title: "Ensure MFA is enabled for all privileged users".to_string(),
                description: "Multi-factor authentication requires an individual to present a minimum of two credentials.".to_string(),
                category: "Identity and Access Management".to_string(),
                severity: Severity::Critical,
                automated: true,
            },
            ComplianceControl {
                id: "2.1".to_string(),
                title: "Ensure Azure Defender is set to On".to_string(),
                description: "Azure Defender provides threat detection and protection for workloads.".to_string(),
                category: "Security Center".to_string(),
                severity: Severity::High,
                automated: false,
            },
            ComplianceControl {
                id: "4.1".to_string(),
                title: "Ensure Azure SQL Database encryption is enabled".to_string(),
                description: "Enable Transparent Data Encryption on all SQL databases.".to_string(),
                category: "SQL Services".to_string(),
                severity: Severity::High,
                automated: true,
            },
        ]
    }

    /// Load CIS GCP controls
    fn load_cis_gcp_controls() -> Vec<ComplianceControl> {
        vec![
            ComplianceControl {
                id: "2.1".to_string(),
                title: "Ensure Cloud Audit Logging is configured properly".to_string(),
                description: "Cloud Audit Logs maintains audit trails of all activity in GCP.".to_string(),
                category: "Logging and Monitoring".to_string(),
                severity: Severity::High,
                automated: true,
            },
            ComplianceControl {
                id: "3.1".to_string(),
                title: "Ensure default network does not exist in project".to_string(),
                description: "The default network has a preconfigured network configuration.".to_string(),
                category: "Networking".to_string(),
                severity: Severity::Medium,
                automated: true,
            },
            ComplianceControl {
                id: "5.1".to_string(),
                title: "Ensure Cloud Storage bucket is not publicly accessible".to_string(),
                description: "Allowing public access to Cloud Storage can expose sensitive data.".to_string(),
                category: "Storage".to_string(),
                severity: Severity::Critical,
                automated: true,
            },
        ]
    }

    fn load_soc2_controls() -> Vec<ComplianceControl> {
        vec![]
    }

    fn load_iso27001_controls() -> Vec<ComplianceControl> {
        vec![]
    }

    fn load_nist_controls() -> Vec<ComplianceControl> {
        vec![]
    }

    fn load_pci_dss_controls() -> Vec<ComplianceControl> {
        vec![]
    }

    fn load_hipaa_controls() -> Vec<ComplianceControl> {
        vec![]
    }
}

// Supporting data structures for cloud configuration

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudConfiguration {
    pub cloudtrail_trails: Vec<CloudTrailTrail>,
    pub vpcs: Vec<Vpc>,
    pub security_groups: Vec<SecurityGroup>,
    pub s3_buckets: Vec<S3Bucket>,
    pub azure_users: Vec<AzureUser>,
    pub azure_sql_databases: Vec<AzureSqlDatabase>,
    pub azure_nsgs: Vec<AzureNsg>,
    pub gcp_projects: Vec<GcpProject>,
    pub gcp_networks: Vec<GcpNetwork>,
    pub gcp_instances: Vec<GcpInstance>,
    pub gcp_buckets: Vec<GcpBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailTrail {
    pub name: String,
    pub enabled: bool,
    pub is_multi_region: bool,
    pub log_file_validation_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vpc {
    pub vpc_id: String,
    pub flow_logs_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroup {
    pub group_id: String,
    pub group_name: String,
    pub ingress_rules: Vec<IngressRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    pub port: u16,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Bucket {
    pub name: String,
    pub logging_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureUser {
    pub user_id: String,
    pub username: String,
    pub is_admin: bool,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureSqlDatabase {
    pub database_id: String,
    pub name: String,
    pub encryption_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureNsg {
    pub nsg_id: String,
    pub name: String,
    pub rules: Vec<AzureNsgRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureNsgRule {
    pub destination_port: u16,
    pub source_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpProject {
    pub project_id: String,
    pub name: String,
    pub audit_logging_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpNetwork {
    pub network_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpInstance {
    pub instance_id: String,
    pub name: String,
    pub uses_default_service_account: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpBucket {
    pub name: String,
    pub public_access_prevention: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cis_aws_validation() {
        let engine = CloudComplianceEngine::new(ComplianceFramework::CisAws);
        let config = CloudConfiguration::default();
        let report = engine.validate(&config);

        assert_eq!(report.framework, ComplianceFramework::CisAws);
        assert!(report.total_controls > 0);
    }

    #[test]
    fn test_cloudtrail_check() {
        let engine = CloudComplianceEngine::new(ComplianceFramework::CisAws);
        let mut config = CloudConfiguration::default();

        config.cloudtrail_trails.push(CloudTrailTrail {
            name: "test-trail".to_string(),
            enabled: true,
            is_multi_region: true,
            log_file_validation_enabled: true,
        });

        let (status, findings) = engine.check_cloudtrail_enabled(&config);
        assert!(matches!(status, ComplianceStatus::Passed));
        assert_eq!(findings.len(), 0);
    }
}
