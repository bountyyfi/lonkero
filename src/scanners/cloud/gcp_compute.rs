// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GCP Compute Engine Scanner
 * Production-grade GCE vulnerability scanner
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;
use reqwest::Client;
use tracing::{debug, info};

/// GCP Compute Engine vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GceVulnerability {
    pub id: String,
    pub severity: VulnerabilitySeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub resource_type: String,
    pub resource_name: String,
    pub resource_id: String,
    pub project_id: String,
    pub zone: Option<String>,
    pub region: Option<String>,
    pub remediation: String,
    pub compliance: Vec<String>,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// GCP Compute Engine instance details
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GceInstance {
    pub name: String,
    pub id: String,
    pub zone: String,
    pub machine_type: String,
    pub status: String,
    pub network_interfaces: Vec<NetworkInterface>,
    pub service_accounts: Option<Vec<ServiceAccount>>,
    pub metadata: Option<Metadata>,
    pub tags: Option<Tags>,
    pub labels: Option<HashMap<String, String>>,
    pub disks: Option<Vec<Disk>>,
    pub shielded_instance_config: Option<ShieldedInstanceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub network: String,
    pub network_ip: String,
    pub access_configs: Option<Vec<AccessConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessConfig {
    pub name: String,
    pub nat_ip: Option<String>,
    #[serde(rename = "type")]
    pub access_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccount {
    pub email: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub items: Option<Vec<MetadataItem>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetadataItem {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tags {
    pub items: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    pub device_name: String,
    pub source: String,
    pub boot: Option<bool>,
    pub auto_delete: Option<bool>,
    pub disk_encryption_key: Option<DiskEncryptionKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskEncryptionKey {
    pub kms_key_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedInstanceConfig {
    pub enable_secure_boot: Option<bool>,
    pub enable_vtpm: Option<bool>,
    pub enable_integrity_monitoring: Option<bool>,
}

/// Firewall rule details
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    pub name: String,
    pub description: Option<String>,
    pub network: String,
    pub priority: Option<u32>,
    pub direction: String,
    pub source_ranges: Option<Vec<String>>,
    pub destination_ranges: Option<Vec<String>>,
    pub allowed: Option<Vec<FirewallAllowed>>,
    pub denied: Option<Vec<FirewallDenied>>,
    pub source_tags: Option<Vec<String>>,
    pub target_tags: Option<Vec<String>>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallAllowed {
    #[serde(rename = "IPProtocol")]
    pub ip_protocol: String,
    pub ports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallDenied {
    #[serde(rename = "IPProtocol")]
    pub ip_protocol: String,
    pub ports: Option<Vec<String>>,
}

/// GCP Compute Engine Scanner
pub struct GcpComputeScanner {
    client: Client,
    access_token: Option<String>,
}

impl GcpComputeScanner {
    /// Create a new GCP Compute Engine scanner
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            access_token: None,
        }
    }

    /// Set access token for authentication
    pub fn with_access_token(mut self, token: String) -> Self {
        self.access_token = Some(token);
        self
    }

    /// Scan GCE instances for vulnerabilities
    pub async fn scan_instances(
        &self,
        project_id: &str,
        instances: &[GceInstance],
    ) -> Result<Vec<GceVulnerability>> {
        info!("Starting GCE instance scan for project {}", project_id);

        let mut vulnerabilities = Vec::new();

        for instance in instances {
            // Check for instances with external IPs
            if let Some(vuln) = self.check_external_ip(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for default service account
            if let Some(vuln) = self.check_default_service_account(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for Shielded VM configuration
            if let Some(vuln) = self.check_shielded_vm(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for serial port access
            if let Some(vuln) = self.check_serial_port_access(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for OS Login
            if let Some(vuln) = self.check_os_login(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for legacy metadata API
            if let Some(vuln) = self.check_legacy_metadata_api(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for monitoring agent
            if let Some(vuln) = self.check_monitoring_agent(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for default VPC
            if let Some(vuln) = self.check_default_vpc(project_id, instance) {
                vulnerabilities.push(vuln);
            }

            // Check for disk encryption
            if let Some(vulns) = self.check_disk_encryption(project_id, instance) {
                vulnerabilities.extend(vulns);
            }
        }

        info!("GCE instance scan completed: {} vulnerabilities found", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Scan firewall rules for vulnerabilities
    pub async fn scan_firewall_rules(
        &self,
        project_id: &str,
        rules: &[FirewallRule],
    ) -> Result<Vec<GceVulnerability>> {
        info!("Starting firewall rules scan for project {}", project_id);

        let mut vulnerabilities = Vec::new();

        for rule in rules {
            // Check for overly permissive rules (0.0.0.0/0)
            if let Some(vuln) = self.check_overly_permissive_firewall(project_id, rule) {
                vulnerabilities.push(vuln);
            }
        }

        info!("Firewall rules scan completed: {} vulnerabilities found", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Check for instances with external IPs
    fn check_external_ip(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        for interface in &instance.network_interfaces {
            if let Some(access_configs) = &interface.access_configs {
                if !access_configs.is_empty() {
                    for config in access_configs {
                        if config.nat_ip.is_some() {
                            debug!("Instance {} has external IP", instance.name);

                            return Some(GceVulnerability {
                                id: format!("gce-external-ip-{}", instance.id),
                                severity: VulnerabilitySeverity::Medium,
                                category: "Network Security".to_string(),
                                title: "GCE Instance with External IP".to_string(),
                                description: format!(
                                    "Instance '{}' has an external IP address ({}), which exposes it to the internet. \
                                    Consider using Cloud NAT or VPN for outbound connectivity instead.",
                                    instance.name,
                                    config.nat_ip.as_ref().unwrap_or(&"unknown".to_string())
                                ),
                                resource_type: "compute.googleapis.com/Instance".to_string(),
                                resource_name: instance.name.clone(),
                                resource_id: instance.id.clone(),
                                project_id: project_id.to_string(),
                                zone: Some(instance.zone.clone()),
                                region: None,
                                remediation: "Remove external IP and use Cloud NAT, Identity-Aware Proxy (IAP), or VPN for access. \
                                    Use private IP addresses and internal load balancers where possible.".to_string(),
                                compliance: vec!["CIS GCP 3.2".to_string(), "NIST 800-53 AC-4".to_string()],
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    /// Check for instances using default service account
    fn check_default_service_account(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        if let Some(service_accounts) = &instance.service_accounts {
            for sa in service_accounts {
                if sa.email.contains("-compute@developer.gserviceaccount.com") {
                    debug!("Instance {} uses default service account", instance.name);

                    // Check for overly broad scopes
                    let has_broad_scopes = sa.scopes.iter().any(|scope| {
                        scope.contains("cloud-platform") || scope.contains("compute")
                    });

                    let severity = if has_broad_scopes {
                        VulnerabilitySeverity::High
                    } else {
                        VulnerabilitySeverity::Medium
                    };

                    return Some(GceVulnerability {
                        id: format!("gce-default-sa-{}", instance.id),
                        severity,
                        category: "IAM & Permissions".to_string(),
                        title: "GCE Instance Using Default Service Account".to_string(),
                        description: format!(
                            "Instance '{}' is using the default Compute Engine service account ({}). \
                            The default service account has the Project Editor role, which is overly permissive.",
                            instance.name, sa.email
                        ),
                        resource_type: "compute.googleapis.com/Instance".to_string(),
                        resource_name: instance.name.clone(),
                        resource_id: instance.id.clone(),
                        project_id: project_id.to_string(),
                        zone: Some(instance.zone.clone()),
                        region: None,
                        remediation: "Create a custom service account with minimal required permissions. \
                            Use the principle of least privilege and assign only necessary IAM roles.".to_string(),
                        compliance: vec!["CIS GCP 4.1".to_string(), "NIST 800-53 AC-6".to_string()],
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }
        None
    }

    /// Check for Shielded VM configuration
    fn check_shielded_vm(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        let shielded = instance.shielded_instance_config.as_ref();

        let is_secure_boot_disabled = shielded.map_or(true, |s| !s.enable_secure_boot.unwrap_or(false));
        let is_vtpm_disabled = shielded.map_or(true, |s| !s.enable_vtpm.unwrap_or(false));
        let is_integrity_disabled = shielded.map_or(true, |s| !s.enable_integrity_monitoring.unwrap_or(false));

        if is_secure_boot_disabled || is_vtpm_disabled || is_integrity_disabled {
            debug!("Instance {} has incomplete Shielded VM configuration", instance.name);

            let mut missing = Vec::new();
            if is_secure_boot_disabled {
                missing.push("Secure Boot");
            }
            if is_vtpm_disabled {
                missing.push("vTPM");
            }
            if is_integrity_disabled {
                missing.push("Integrity Monitoring");
            }

            return Some(GceVulnerability {
                id: format!("gce-shielded-vm-{}", instance.id),
                severity: VulnerabilitySeverity::Medium,
                category: "Compute Security".to_string(),
                title: "GCE Instance Without Complete Shielded VM Configuration".to_string(),
                description: format!(
                    "Instance '{}' does not have all Shielded VM features enabled. Missing: {}. \
                    Shielded VM provides verifiable integrity and helps protect against rootkits and bootkits.",
                    instance.name,
                    missing.join(", ")
                ),
                resource_type: "compute.googleapis.com/Instance".to_string(),
                resource_name: instance.name.clone(),
                resource_id: instance.id.clone(),
                project_id: project_id.to_string(),
                zone: Some(instance.zone.clone()),
                region: None,
                remediation: "Enable all Shielded VM features: Secure Boot, vTPM, and Integrity Monitoring. \
                    Use Shielded VM images for new instances.".to_string(),
                compliance: vec!["CIS GCP 4.8".to_string(), "PCI DSS 2.2".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check for serial port access enabled
    fn check_serial_port_access(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        if let Some(metadata) = &instance.metadata {
            if let Some(items) = &metadata.items {
                for item in items {
                    if item.key == "serial-port-enable" {
                        if let Some(value) = &item.value {
                            if value == "1" || value.to_lowercase() == "true" {
                                debug!("Instance {} has serial port access enabled", instance.name);

                                return Some(GceVulnerability {
                                    id: format!("gce-serial-port-{}", instance.id),
                                    severity: VulnerabilitySeverity::High,
                                    category: "Access Control".to_string(),
                                    title: "GCE Instance with Serial Port Access Enabled".to_string(),
                                    description: format!(
                                        "Instance '{}' has interactive serial console access enabled. \
                                        This can bypass network-based access controls and logging.",
                                        instance.name
                                    ),
                                    resource_type: "compute.googleapis.com/Instance".to_string(),
                                    resource_name: instance.name.clone(),
                                    resource_id: instance.id.clone(),
                                    project_id: project_id.to_string(),
                                    zone: Some(instance.zone.clone()),
                                    region: None,
                                    remediation: "Disable serial port access unless specifically required. \
                                        Use SSH or other secure remote access methods instead.".to_string(),
                                    compliance: vec!["CIS GCP 4.5".to_string()],
                                    discovered_at: chrono::Utc::now().to_rfc3339(),
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check for OS Login enabled
    fn check_os_login(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        let mut os_login_enabled = false;

        if let Some(metadata) = &instance.metadata {
            if let Some(items) = &metadata.items {
                for item in items {
                    if item.key == "enable-oslogin" {
                        if let Some(value) = &item.value {
                            if value == "TRUE" || value.to_lowercase() == "true" {
                                os_login_enabled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !os_login_enabled {
            debug!("Instance {} does not have OS Login enabled", instance.name);

            return Some(GceVulnerability {
                id: format!("gce-os-login-{}", instance.id),
                severity: VulnerabilitySeverity::Medium,
                category: "Access Control".to_string(),
                title: "GCE Instance Without OS Login".to_string(),
                description: format!(
                    "Instance '{}' does not have OS Login enabled. \
                    OS Login provides centralized SSH key management and IAM-based access control.",
                    instance.name
                ),
                resource_type: "compute.googleapis.com/Instance".to_string(),
                resource_name: instance.name.clone(),
                resource_id: instance.id.clone(),
                project_id: project_id.to_string(),
                zone: Some(instance.zone.clone()),
                region: None,
                remediation: "Enable OS Login at the project or instance level. \
                    Remove individual SSH keys from instance metadata and use IAM for access control.".to_string(),
                compliance: vec!["CIS GCP 4.3".to_string(), "NIST 800-53 IA-2".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check for legacy metadata API enabled
    fn check_legacy_metadata_api(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        let mut legacy_api_disabled = false;

        if let Some(metadata) = &instance.metadata {
            if let Some(items) = &metadata.items {
                for item in items {
                    if item.key == "metadata-flavor" {
                        if let Some(value) = &item.value {
                            if value == "Google" {
                                legacy_api_disabled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if !legacy_api_disabled {
            debug!("Instance {} may have legacy metadata API v1beta1 enabled", instance.name);

            return Some(GceVulnerability {
                id: format!("gce-legacy-metadata-{}", instance.id),
                severity: VulnerabilitySeverity::Low,
                category: "Configuration".to_string(),
                title: "GCE Instance with Legacy Metadata API".to_string(),
                description: format!(
                    "Instance '{}' may be using the legacy metadata API v1beta1. \
                    The legacy API has security limitations compared to the v1 API.",
                    instance.name
                ),
                resource_type: "compute.googleapis.com/Instance".to_string(),
                resource_name: instance.name.clone(),
                resource_id: instance.id.clone(),
                project_id: project_id.to_string(),
                zone: Some(instance.zone.clone()),
                region: None,
                remediation: "Configure applications to use the v1 metadata API endpoint. \
                    Add 'Metadata-Flavor: Google' header to metadata requests.".to_string(),
                compliance: vec!["CIS GCP 4.6".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check for monitoring agent
    fn check_monitoring_agent(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        // This is a best-effort check based on labels or metadata
        let has_monitoring = if let Some(labels) = &instance.labels {
            labels.contains_key("monitoring-enabled") || labels.contains_key("ops-agent")
        } else {
            false
        };

        if !has_monitoring {
            debug!("Instance {} may not have monitoring agent installed", instance.name);

            return Some(GceVulnerability {
                id: format!("gce-no-monitoring-{}", instance.id),
                severity: VulnerabilitySeverity::Low,
                category: "Monitoring".to_string(),
                title: "GCE Instance Without Monitoring Agent".to_string(),
                description: format!(
                    "Instance '{}' may not have the Cloud Monitoring (Ops) agent installed. \
                    The agent is required for detailed system metrics and logging.",
                    instance.name
                ),
                resource_type: "compute.googleapis.com/Instance".to_string(),
                resource_name: instance.name.clone(),
                resource_id: instance.id.clone(),
                project_id: project_id.to_string(),
                zone: Some(instance.zone.clone()),
                region: None,
                remediation: "Install the Ops Agent (recommended) or legacy monitoring/logging agents. \
                    Configure log collection and metrics monitoring.".to_string(),
                compliance: vec!["CIS GCP 2.9".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check for default VPC usage
    fn check_default_vpc(&self, project_id: &str, instance: &GceInstance) -> Option<GceVulnerability> {
        for interface in &instance.network_interfaces {
            if interface.network.contains("/default") {
                debug!("Instance {} is in default VPC", instance.name);

                return Some(GceVulnerability {
                    id: format!("gce-default-vpc-{}", instance.id),
                    severity: VulnerabilitySeverity::Low,
                    category: "Network Security".to_string(),
                    title: "GCE Instance in Default VPC".to_string(),
                    description: format!(
                        "Instance '{}' is deployed in the default VPC network. \
                        The default VPC has default firewall rules that may be overly permissive.",
                        instance.name
                    ),
                    resource_type: "compute.googleapis.com/Instance".to_string(),
                    resource_name: instance.name.clone(),
                    resource_id: instance.id.clone(),
                    project_id: project_id.to_string(),
                    zone: Some(instance.zone.clone()),
                    region: None,
                    remediation: "Create custom VPC networks with custom firewall rules. \
                        Use separate VPCs for different environments (dev, staging, production).".to_string(),
                    compliance: vec!["CIS GCP 3.1".to_string()],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
        None
    }

    /// Check for disk encryption with CMEK
    fn check_disk_encryption(&self, project_id: &str, instance: &GceInstance) -> Option<Vec<GceVulnerability>> {
        let mut vulnerabilities = Vec::new();

        if let Some(disks) = &instance.disks {
            for disk in disks {
                let has_cmek = disk.disk_encryption_key.as_ref()
                    .and_then(|key| key.kms_key_name.as_ref())
                    .is_some();

                if !has_cmek {
                    debug!("Disk {} on instance {} not encrypted with CMEK", disk.device_name, instance.name);

                    vulnerabilities.push(GceVulnerability {
                        id: format!("gce-disk-no-cmek-{}-{}", instance.id, disk.device_name),
                        severity: VulnerabilitySeverity::Medium,
                        category: "Encryption".to_string(),
                        title: "GCE Disk Without Customer-Managed Encryption Key (CMEK)".to_string(),
                        description: format!(
                            "Disk '{}' on instance '{}' is not encrypted with a customer-managed encryption key (CMEK). \
                            While Google encrypts all data at rest, using CMEK provides additional control over encryption keys.",
                            disk.device_name, instance.name
                        ),
                        resource_type: "compute.googleapis.com/Disk".to_string(),
                        resource_name: disk.device_name.clone(),
                        resource_id: disk.source.clone(),
                        project_id: project_id.to_string(),
                        zone: Some(instance.zone.clone()),
                        region: None,
                        remediation: "Enable CMEK encryption for persistent disks using Cloud KMS keys. \
                            Implement key rotation policies and access controls for encryption keys.".to_string(),
                        compliance: vec!["CIS GCP 4.7".to_string(), "NIST 800-53 SC-28".to_string()],
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        if vulnerabilities.is_empty() {
            None
        } else {
            Some(vulnerabilities)
        }
    }

    /// Check for overly permissive firewall rules
    fn check_overly_permissive_firewall(&self, project_id: &str, rule: &FirewallRule) -> Option<GceVulnerability> {
        if rule.disabled == Some(true) {
            return None;
        }

        if let Some(source_ranges) = &rule.source_ranges {
            if source_ranges.iter().any(|range| range == "0.0.0.0/0") {
                if let Some(allowed) = &rule.allowed {
                    // Check for commonly exposed services
                    let mut exposed_services = Vec::new();

                    for allow in allowed {
                        if let Some(ports) = &allow.ports {
                            for port in ports {
                                let port_num = port.split('-').next().unwrap_or(port);
                                match port_num {
                                    "22" => exposed_services.push("SSH (22)"),
                                    "3389" => exposed_services.push("RDP (3389)"),
                                    "1433" => exposed_services.push("MSSQL (1433)"),
                                    "3306" => exposed_services.push("MySQL (3306)"),
                                    "5432" => exposed_services.push("PostgreSQL (5432)"),
                                    "27017" => exposed_services.push("MongoDB (27017)"),
                                    "6379" => exposed_services.push("Redis (6379)"),
                                    _ => {}
                                }
                            }
                        }
                    }

                    if !exposed_services.is_empty() {
                        let severity = if exposed_services.iter().any(|s| s.contains("SSH") || s.contains("RDP")) {
                            VulnerabilitySeverity::Critical
                        } else {
                            VulnerabilitySeverity::High
                        };

                        debug!("Firewall rule {} allows 0.0.0.0/0 access to {}", rule.name, exposed_services.join(", "));

                        return Some(GceVulnerability {
                            id: format!("gce-fw-public-{}", rule.name),
                            severity,
                            category: "Network Security".to_string(),
                            title: "Overly Permissive Firewall Rule".to_string(),
                            description: format!(
                                "Firewall rule '{}' allows unrestricted access (0.0.0.0/0) to sensitive services: {}. \
                                This exposes these services to the entire internet.",
                                rule.name,
                                exposed_services.join(", ")
                            ),
                            resource_type: "compute.googleapis.com/Firewall".to_string(),
                            resource_name: rule.name.clone(),
                            resource_id: rule.name.clone(),
                            project_id: project_id.to_string(),
                            zone: None,
                            region: None,
                            remediation: "Restrict firewall rules to specific IP ranges or use Identity-Aware Proxy (IAP) for access. \
                                Apply the principle of least privilege to network access.".to_string(),
                            compliance: vec![
                                "CIS GCP 3.6".to_string(),
                                "CIS GCP 3.7".to_string(),
                                "PCI DSS 1.3".to_string()
                            ],
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    } else {
                        // Generic warning for 0.0.0.0/0 access
                        debug!("Firewall rule {} allows 0.0.0.0/0 access", rule.name);

                        return Some(GceVulnerability {
                            id: format!("gce-fw-public-generic-{}", rule.name),
                            severity: VulnerabilitySeverity::Medium,
                            category: "Network Security".to_string(),
                            title: "Firewall Rule Allows Public Access".to_string(),
                            description: format!(
                                "Firewall rule '{}' allows unrestricted access from the internet (0.0.0.0/0). \
                                Review the rule to ensure this is intentional.",
                                rule.name
                            ),
                            resource_type: "compute.googleapis.com/Firewall".to_string(),
                            resource_name: rule.name.clone(),
                            resource_id: rule.name.clone(),
                            project_id: project_id.to_string(),
                            zone: None,
                            region: None,
                            remediation: "Review and restrict the source IP ranges to only necessary networks. \
                                Use Cloud Armor or VPC Service Controls for additional protection.".to_string(),
                            compliance: vec!["CIS GCP 3.6".to_string()],
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        None
    }
}

impl Default for GcpComputeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_external_ip() {
        let scanner = GcpComputeScanner::new();
        let instance = GceInstance {
            name: "test-instance".to_string(),
            id: "123456".to_string(),
            zone: "us-central1-a".to_string(),
            machine_type: "n1-standard-1".to_string(),
            status: "RUNNING".to_string(),
            network_interfaces: vec![NetworkInterface {
                network: "default".to_string(),
                network_ip: "10.0.0.1".to_string(),
                access_configs: Some(vec![AccessConfig {
                    name: "External NAT".to_string(),
                    nat_ip: Some("35.1.2.3".to_string()),
                    access_type: "ONE_TO_ONE_NAT".to_string(),
                }]),
            }],
            service_accounts: None,
            metadata: None,
            tags: None,
            labels: None,
            disks: None,
            shielded_instance_config: None,
        };

        let vuln = scanner.check_external_ip("test-project", &instance);
        assert!(vuln.is_some());

        let vuln = vuln.unwrap();
        assert_eq!(vuln.severity as i32, VulnerabilitySeverity::Medium as i32);
        assert!(vuln.title.contains("External IP"));
    }

    #[test]
    fn test_check_default_service_account() {
        let scanner = GcpComputeScanner::new();
        let instance = GceInstance {
            name: "test-instance".to_string(),
            id: "123456".to_string(),
            zone: "us-central1-a".to_string(),
            machine_type: "n1-standard-1".to_string(),
            status: "RUNNING".to_string(),
            network_interfaces: vec![],
            service_accounts: Some(vec![ServiceAccount {
                email: "123456-compute@developer.gserviceaccount.com".to_string(),
                scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
            }]),
            metadata: None,
            tags: None,
            labels: None,
            disks: None,
            shielded_instance_config: None,
        };

        let vuln = scanner.check_default_service_account("test-project", &instance);
        assert!(vuln.is_some());

        let vuln = vuln.unwrap();
        assert_eq!(vuln.severity as i32, VulnerabilitySeverity::High as i32);
    }
}
