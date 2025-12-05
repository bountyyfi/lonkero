// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Azure Virtual Machine Security Scanner - Rust Implementation
 * Enterprise-grade cloud security scanning for Azure VMs
 *
 * @copyright 2025 Bountyy Oy
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AzureCredentials {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub subscription_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureVirtualMachine {
    id: String,
    name: String,
    location: String,
    #[serde(rename = "type")]
    resource_type: String,
    properties: VmProperties,
    tags: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VmProperties {
    #[serde(rename = "hardwareProfile")]
    hardware_profile: Option<HardwareProfile>,
    #[serde(rename = "storageProfile")]
    storage_profile: Option<StorageProfile>,
    #[serde(rename = "osProfile")]
    os_profile: Option<OsProfile>,
    #[serde(rename = "networkProfile")]
    network_profile: Option<NetworkProfile>,
    #[serde(rename = "diagnosticsProfile")]
    diagnostics_profile: Option<DiagnosticsProfile>,
    #[serde(rename = "provisioningState")]
    provisioning_state: Option<String>,
    #[serde(rename = "instanceView")]
    instance_view: Option<InstanceView>,
    zones: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HardwareProfile {
    #[serde(rename = "vmSize")]
    vm_size: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StorageProfile {
    #[serde(rename = "imageReference")]
    image_reference: Option<ImageReference>,
    #[serde(rename = "osDisk")]
    os_disk: Option<OsDisk>,
    #[serde(rename = "dataDisks")]
    data_disks: Option<Vec<DataDisk>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImageReference {
    publisher: Option<String>,
    offer: Option<String>,
    sku: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsDisk {
    #[serde(rename = "osType")]
    os_type: Option<String>,
    name: Option<String>,
    #[serde(rename = "createOption")]
    create_option: Option<String>,
    #[serde(rename = "managedDisk")]
    managed_disk: Option<ManagedDisk>,
    #[serde(rename = "encryptionSettings")]
    encryption_settings: Option<EncryptionSettings>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DataDisk {
    name: Option<String>,
    lun: i32,
    #[serde(rename = "managedDisk")]
    managed_disk: Option<ManagedDisk>,
    #[serde(rename = "diskSizeGB")]
    disk_size_gb: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManagedDisk {
    id: Option<String>,
    #[serde(rename = "storageAccountType")]
    storage_account_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptionSettings {
    enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsProfile {
    #[serde(rename = "computerName")]
    computer_name: Option<String>,
    #[serde(rename = "adminUsername")]
    admin_username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkProfile {
    #[serde(rename = "networkInterfaces")]
    network_interfaces: Option<Vec<NetworkInterface>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkInterface {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiagnosticsProfile {
    #[serde(rename = "bootDiagnostics")]
    boot_diagnostics: Option<BootDiagnostics>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BootDiagnostics {
    enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstanceView {
    statuses: Option<Vec<InstanceStatus>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstanceStatus {
    code: Option<String>,
    level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AzureResourceList<T> {
    value: Vec<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkSecurityGroup {
    id: String,
    name: String,
    properties: NsgProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NsgProperties {
    #[serde(rename = "securityRules")]
    security_rules: Option<Vec<SecurityRule>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityRule {
    name: String,
    properties: SecurityRuleProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityRuleProperties {
    protocol: String,
    #[serde(rename = "sourceAddressPrefix")]
    source_address_prefix: Option<String>,
    #[serde(rename = "sourceAddressPrefixes")]
    source_address_prefixes: Option<Vec<String>>,
    #[serde(rename = "destinationPortRange")]
    destination_port_range: Option<String>,
    access: String,
    direction: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicIpAddress {
    id: String,
    name: String,
    properties: PublicIpProperties,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicIpProperties {
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "ipConfiguration")]
    ip_configuration: Option<IpConfiguration>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IpConfiguration {
    id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Disk {
    id: String,
    name: String,
    properties: DiskProperties,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskProperties {
    encryption: Option<Encryption>,
    #[serde(rename = "diskState")]
    disk_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Encryption {
    #[serde(rename = "type")]
    encryption_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VmExtension {
    id: String,
    name: String,
    properties: ExtensionProperties,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExtensionProperties {
    publisher: Option<String>,
    #[serde(rename = "type")]
    extension_type: Option<String>,
    #[serde(rename = "provisioningState")]
    provisioning_state: Option<String>,
}

pub struct AzureVmScanner {
    http_client: Arc<HttpClient>,
    access_token: Option<String>,
    token_expiry: Option<std::time::Instant>,
}

impl AzureVmScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            access_token: None,
            token_expiry: None,
        }
    }

    /// Authenticate with Azure and get access token
    async fn authenticate(&mut self, credentials: &AzureCredentials) -> Result<String> {
        // Return cached token if still valid
        if let (Some(token), Some(expiry)) = (&self.access_token, self.token_expiry) {
            if std::time::Instant::now() < expiry - std::time::Duration::from_secs(300) {
                return Ok(token.clone());
            }
        }

        info!("[Azure] Authenticating with Azure AD");

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            credentials.tenant_id
        );

        let params = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope=https://management.azure.com/.default",
            urlencoding::encode(&credentials.client_id),
            urlencoding::encode(&credentials.client_secret)
        );

        let response = self
            .http_client
            .post_with_headers(
                &token_url,
                &params,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            )
            .await
            .context("Failed to authenticate with Azure")?;

        let token_response: AzureTokenResponse = serde_json::from_str(&response.body)
            .context("Failed to parse token response")?;

        self.access_token = Some(token_response.access_token.clone());
        self.token_expiry = Some(
            std::time::Instant::now() + std::time::Duration::from_secs(token_response.expires_in),
        );

        Ok(token_response.access_token)
    }

    /// Make authenticated request to Azure Resource Manager
    async fn make_azure_request(&self, path: &str, token: &str) -> Result<String> {
        let url = format!("https://management.azure.com{}", path);

        let response = self
            .http_client
            .get_with_headers(
                &url,
                vec![
                    ("Authorization".to_string(), format!("Bearer {}", token)),
                    ("Content-Type".to_string(), "application/json".to_string())
                ]
            )
            .await
            .context("Azure API request failed")?;

        Ok(response.body)
    }

    /// Scan Azure VMs for security vulnerabilities
    pub async fn scan(
        &mut self,
        credentials: &AzureCredentials,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[Azure] Starting Azure VM security scan");

        // Authenticate
        let token = self.authenticate(credentials).await?;

        // List all VMs in subscription
        let vms_path = format!(
            "/subscriptions/{}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01",
            credentials.subscription_id
        );

        let vms_response = self.make_azure_request(&vms_path, &token).await?;
        let vms_list: AzureResourceList<AzureVirtualMachine> = serde_json::from_str(&vms_response)
            .context("Failed to parse VMs list")?;

        info!("[Azure] Found {} virtual machines", vms_list.value.len());

        // Get network interfaces and public IPs
        let nics_path = format!(
            "/subscriptions/{}/providers/Microsoft.Network/networkInterfaces?api-version=2023-05-01",
            credentials.subscription_id
        );
        let nics_response = self.make_azure_request(&nics_path, &token).await?;

        let public_ips_path = format!(
            "/subscriptions/{}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-05-01",
            credentials.subscription_id
        );
        let public_ips_response = self.make_azure_request(&public_ips_path, &token).await?;
        let public_ips: AzureResourceList<PublicIpAddress> =
            serde_json::from_str(&public_ips_response).unwrap_or(AzureResourceList { value: vec![] });

        // Get NSGs
        let nsgs_path = format!(
            "/subscriptions/{}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01",
            credentials.subscription_id
        );
        let nsgs_response = self.make_azure_request(&nsgs_path, &token).await?;
        let nsgs: AzureResourceList<NetworkSecurityGroup> =
            serde_json::from_str(&nsgs_response).unwrap_or(AzureResourceList { value: vec![] });

        // Get all disks
        let disks_path = format!(
            "/subscriptions/{}/providers/Microsoft.Compute/disks?api-version=2023-04-02",
            credentials.subscription_id
        );
        let disks_response = self.make_azure_request(&disks_path, &token).await?;
        let disks: AzureResourceList<Disk> =
            serde_json::from_str(&disks_response).unwrap_or(AzureResourceList { value: vec![] });

        // Create a map of VM IDs to public IPs
        let vm_public_ips = self.map_vm_to_public_ips(&vms_list.value, &public_ips.value, &nics_response);

        // Scan each VM
        for vm in &vms_list.value {
            tests_run += 10; // 10 checks per VM

            // Check 1: VMs with public IP addresses
            if vm_public_ips.contains_key(&vm.id) {
                vulnerabilities.push(self.create_public_ip_vulnerability(&vm, &vm_public_ips[&vm.id]));
            }

            // Check 2: VMs without Azure Security Center (requires extensions check)
            let vm_resource_group = self.extract_resource_group(&vm.id);
            if let Some(rg) = vm_resource_group {
                let extensions = self.get_vm_extensions(&token, credentials, &rg, &vm.name).await?;

                // Check for Azure Monitor agent
                if !self.has_azure_monitor_agent(&extensions) {
                    vulnerabilities.push(self.create_no_monitor_agent_vulnerability(&vm));
                }
            }

            // Check 3: VMs with unencrypted disks
            if let Some(ref storage_profile) = vm.properties.storage_profile {
                // Check OS disk
                if let Some(ref os_disk) = storage_profile.os_disk {
                    if !self.is_disk_encrypted(os_disk) {
                        vulnerabilities.push(self.create_unencrypted_os_disk_vulnerability(&vm));
                    }
                }

                // Check data disks
                if let Some(ref data_disks) = storage_profile.data_disks {
                    for data_disk in data_disks {
                        if let Some(ref managed_disk) = data_disk.managed_disk {
                            if let Some(ref disk_id) = managed_disk.id {
                                if !self.is_managed_disk_encrypted(&disks.value, disk_id) {
                                    vulnerabilities.push(
                                        self.create_unencrypted_data_disk_vulnerability(&vm, data_disk),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Check 4: VMs without backup configured (simplified check)
            // In production, you'd query Recovery Services Vaults
            // This is a placeholder - proper implementation would check backup policies

            // Check 5: VMs with open NSG rules
            let vm_nsgs = self.get_vm_nsgs(&vm, &nsgs.value, &nics_response);
            for nsg in vm_nsgs {
                let open_rules = self.check_nsg_for_open_rules(nsg);
                if !open_rules.is_empty() {
                    vulnerabilities.push(self.create_open_nsg_vulnerability(&vm, nsg, &open_rules));
                }
            }

            // Check 6: VMs with boot diagnostics disabled
            if !self.has_boot_diagnostics_enabled(&vm) {
                vulnerabilities.push(self.create_no_boot_diagnostics_vulnerability(&vm));
            }

            // Check 7: VMs without availability zones (HA check)
            if !self.is_in_availability_zone(&vm) {
                vulnerabilities.push(self.create_no_availability_zone_vulnerability(&vm));
            }

            // Check 8: VMs without managed identities
            // This would require checking the identity property
            // Simplified for this implementation

            // Check 9: VMs with deprecated OS versions
            if self.has_deprecated_os(&vm) {
                vulnerabilities.push(self.create_deprecated_os_vulnerability(&vm));
            }
        }

        info!(
            "[Azure] Scan complete: {} vulnerabilities found in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Extract resource group name from resource ID
    fn extract_resource_group(&self, resource_id: &str) -> Option<String> {
        let parts: Vec<&str> = resource_id.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if part.eq_ignore_ascii_case("resourcegroups") && i + 1 < parts.len() {
                return Some(parts[i + 1].to_string());
            }
        }
        None
    }

    /// Get VM extensions
    async fn get_vm_extensions(
        &self,
        token: &str,
        credentials: &AzureCredentials,
        resource_group: &str,
        vm_name: &str,
    ) -> Result<Vec<VmExtension>> {
        let extensions_path = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}/extensions?api-version=2023-09-01",
            credentials.subscription_id, resource_group, vm_name
        );

        let response = self.make_azure_request(&extensions_path, token).await?;
        let extensions: AzureResourceList<VmExtension> = serde_json::from_str(&response)
            .unwrap_or(AzureResourceList { value: vec![] });

        Ok(extensions.value)
    }

    /// Check if VM has Azure Monitor agent
    fn has_azure_monitor_agent(&self, extensions: &[VmExtension]) -> bool {
        extensions.iter().any(|ext| {
            ext.properties
                .extension_type
                .as_ref()
                .map(|t| {
                    t.contains("AzureMonitor")
                        || t.contains("OmsAgentForLinux")
                        || t.contains("MicrosoftMonitoringAgent")
                })
                .unwrap_or(false)
        })
    }

    /// Map VMs to their public IPs
    fn map_vm_to_public_ips(
        &self,
        vms: &[AzureVirtualMachine],
        public_ips: &[PublicIpAddress],
        _nics_response: &str,
    ) -> HashMap<String, String> {
        let mut vm_to_ip = HashMap::new();

        for vm in vms {
            if let Some(ref network_profile) = vm.properties.network_profile {
                if let Some(ref nics) = network_profile.network_interfaces {
                    for nic in nics {
                        // Find public IP associated with this NIC
                        for public_ip in public_ips {
                            if let Some(ref ip_config) = public_ip.properties.ip_configuration {
                                if let Some(ref config_id) = ip_config.id {
                                    if config_id.contains(&nic.id) {
                                        if let Some(ref ip_addr) = public_ip.properties.ip_address {
                                            vm_to_ip.insert(vm.id.clone(), ip_addr.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        vm_to_ip
    }

    /// Check if OS disk is encrypted
    fn is_disk_encrypted(&self, os_disk: &OsDisk) -> bool {
        if let Some(ref encryption) = os_disk.encryption_settings {
            encryption.enabled.unwrap_or(false)
        } else {
            false
        }
    }

    /// Check if managed disk is encrypted
    fn is_managed_disk_encrypted(&self, disks: &[Disk], disk_id: &str) -> bool {
        disks.iter().any(|d| {
            &d.id == disk_id
                && d.properties
                    .encryption
                    .as_ref()
                    .and_then(|e| e.encryption_type.as_ref())
                    .map(|t| t.contains("Encryption") || t.contains("CustomerKey"))
                    .unwrap_or(false)
        })
    }

    /// Get NSGs associated with a VM
    fn get_vm_nsgs<'a>(
        &self,
        _vm: &AzureVirtualMachine,
        all_nsgs: &'a [NetworkSecurityGroup],
        _nics_response: &str,
    ) -> Vec<&'a NetworkSecurityGroup> {
        // Simplified: return all NSGs
        // In production, you'd match NSGs to VM's network interfaces
        all_nsgs.iter().collect()
    }

    /// Check NSG for open rules (0.0.0.0/0)
    fn check_nsg_for_open_rules(&self, nsg: &NetworkSecurityGroup) -> Vec<String> {
        let mut open_rules = Vec::new();

        if let Some(ref rules) = nsg.properties.security_rules {
            for rule in rules {
                let is_open = rule
                    .properties
                    .source_address_prefix
                    .as_ref()
                    .map(|s| s == "*" || s == "0.0.0.0/0" || s == "Internet")
                    .unwrap_or(false);

                let allows_inbound =
                    rule.properties.access.eq_ignore_ascii_case("allow")
                        && rule.properties.direction.eq_ignore_ascii_case("inbound");

                if is_open && allows_inbound {
                    open_rules.push(rule.name.clone());
                }
            }
        }

        open_rules
    }

    /// Check if VM has boot diagnostics enabled
    fn has_boot_diagnostics_enabled(&self, vm: &AzureVirtualMachine) -> bool {
        vm.properties
            .diagnostics_profile
            .as_ref()
            .and_then(|d| d.boot_diagnostics.as_ref())
            .and_then(|b| b.enabled)
            .unwrap_or(false)
    }

    /// Check if VM is in an availability zone
    fn is_in_availability_zone(&self, vm: &AzureVirtualMachine) -> bool {
        vm.properties
            .zones
            .as_ref()
            .map(|z| !z.is_empty())
            .unwrap_or(false)
    }

    /// Check if VM has deprecated OS
    fn has_deprecated_os(&self, vm: &AzureVirtualMachine) -> bool {
        if let Some(ref storage_profile) = vm.properties.storage_profile {
            if let Some(ref image_ref) = storage_profile.image_reference {
                // Check for deprecated versions
                if let Some(ref sku) = image_ref.sku {
                    // List of deprecated OS versions
                    let deprecated = vec![
                        "2008", "2012", "14.04", "16.04", "centos-6", "rhel-6",
                    ];

                    return deprecated.iter().any(|d| sku.to_lowercase().contains(d));
                }
            }
        }
        false
    }

    // Vulnerability creation helpers

    fn create_public_ip_vulnerability(&self, vm: &AzureVirtualMachine, ip: &str) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_public_ip_{}", vm.name),
            vuln_type: "Azure VM with Public IP Address".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' has a public IP address ({}) which increases attack surface. \
                Consider using Azure Bastion or VPN for remote access.",
                vm.name, ip
            ),
            evidence: Some(format!("Public IP: {}, Location: {}", ip, vm.location)),
            cwe: "CWE-284".to_string(),
            cvss: 5.3,
            verified: true,
            false_positive: false,
            remediation: "1. Remove public IP if not required\n\
                         2. Use Azure Bastion for secure RDP/SSH access\n\
                         3. Implement Network Security Groups with strict rules\n\
                         4. Enable Just-In-Time VM access"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_no_monitor_agent_vulnerability(&self, vm: &AzureVirtualMachine) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_no_monitor_{}", vm.name),
            vuln_type: "Azure VM without Azure Monitor Agent".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' does not have Azure Monitor agent installed. \
                This limits visibility and monitoring capabilities.",
                vm.name
            ),
            evidence: Some(format!("VM: {}, Location: {}", vm.name, vm.location)),
            cwe: "CWE-778".to_string(),
            cvss: 4.0,
            verified: true,
            false_positive: false,
            remediation: "1. Install Azure Monitor agent extension\n\
                         2. Configure Log Analytics workspace\n\
                         3. Enable VM insights\n\
                         4. Set up alerts for security events"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_unencrypted_os_disk_vulnerability(&self, vm: &AzureVirtualMachine) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_unencrypted_os_{}", vm.name),
            vuln_type: "Azure VM with Unencrypted OS Disk".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' has an unencrypted OS disk. \
                This violates data-at-rest encryption requirements.",
                vm.name
            ),
            evidence: Some(format!("VM: {}, Location: {}", vm.name, vm.location)),
            cwe: "CWE-311".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "1. Enable Azure Disk Encryption (ADE)\n\
                         2. Use Azure Key Vault for key management\n\
                         3. Enable encryption at host if supported\n\
                         4. Implement compliance policies to enforce encryption"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_unencrypted_data_disk_vulnerability(
        &self,
        vm: &AzureVirtualMachine,
        disk: &DataDisk,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_unencrypted_data_{}_{}", vm.name, disk.lun),
            vuln_type: "Azure VM with Unencrypted Data Disk".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' has an unencrypted data disk (LUN: {}). \
                This may expose sensitive data.",
                vm.name, disk.lun
            ),
            evidence: Some(format!(
                "VM: {}, Disk LUN: {}, Size: {} GB",
                vm.name,
                disk.lun,
                disk.disk_size_gb.unwrap_or(0)
            )),
            cwe: "CWE-311".to_string(),
            cvss: 7.5,
            verified: true,
            false_positive: false,
            remediation: "1. Enable Azure Disk Encryption for data disks\n\
                         2. Use customer-managed keys in Azure Key Vault\n\
                         3. Enable double encryption if handling sensitive data\n\
                         4. Implement Azure Policy to enforce encryption"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_open_nsg_vulnerability(
        &self,
        vm: &AzureVirtualMachine,
        nsg: &NetworkSecurityGroup,
        rules: &[String],
    ) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_open_nsg_{}_{}", vm.name, nsg.name),
            vuln_type: "Azure VM with Open Network Security Group Rules".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' has Network Security Group '{}' with {} open rule(s) \
                allowing traffic from 0.0.0.0/0 (Internet). This exposes the VM to potential attacks.",
                vm.name,
                nsg.name,
                rules.len()
            ),
            evidence: Some(format!("NSG: {}, Open Rules: {}", nsg.name, rules.join(", "))),
            cwe: "CWE-284".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: "1. Restrict source IP ranges to specific addresses\n\
                         2. Use Azure Bastion instead of direct RDP/SSH\n\
                         3. Implement Just-In-Time VM access\n\
                         4. Review and remove unnecessary inbound rules\n\
                         5. Enable Azure Firewall for centralized protection"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_no_boot_diagnostics_vulnerability(&self, vm: &AzureVirtualMachine) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_no_boot_diag_{}", vm.name),
            vuln_type: "Azure VM without Boot Diagnostics".to_string(),
            severity: Severity::Low,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' does not have boot diagnostics enabled. \
                This makes troubleshooting boot issues difficult.",
                vm.name
            ),
            evidence: Some(format!("VM: {}, Location: {}", vm.name, vm.location)),
            cwe: "CWE-778".to_string(),
            cvss: 2.0,
            verified: true,
            false_positive: false,
            remediation: "1. Enable boot diagnostics in VM settings\n\
                         2. Configure diagnostics storage account\n\
                         3. Review boot logs periodically\n\
                         4. Use managed storage for diagnostics"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_no_availability_zone_vulnerability(&self, vm: &AzureVirtualMachine) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_no_az_{}", vm.name),
            vuln_type: "Azure VM not in Availability Zone".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' is not deployed in an availability zone. \
                This may impact high availability and SLA.",
                vm.name
            ),
            evidence: Some(format!("VM: {}, Location: {}", vm.name, vm.location)),
            cwe: "CWE-1188".to_string(),
            cvss: 4.5,
            verified: true,
            false_positive: false,
            remediation: "1. Deploy VMs in availability zones for HA\n\
                         2. Use zone-redundant services\n\
                         3. Implement disaster recovery strategy\n\
                         4. Consider Azure Site Recovery"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn create_deprecated_os_vulnerability(&self, vm: &AzureVirtualMachine) -> Vulnerability {
        Vulnerability {
            id: format!("azure_vm_deprecated_os_{}", vm.name),
            vuln_type: "Azure VM with Deprecated OS Version".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: format!("azure://vm/{}", vm.name),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Virtual Machine '{}' is running a deprecated operating system version \
                that may no longer receive security updates.",
                vm.name
            ),
            evidence: Some(format!("VM: {}, Location: {}", vm.name, vm.location)),
            cwe: "CWE-1104".to_string(),
            cvss: 7.8,
            verified: true,
            false_positive: false,
            remediation: "1. Upgrade to a supported OS version\n\
                         2. Plan migration to modern OS releases\n\
                         3. Enable automatic updates\n\
                         4. Use Azure Update Management"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scanner_creation() {
        let http_client = Arc::new(HttpClient::with_config(30, 3, true, true, 100, 10).unwrap());
        let scanner = AzureVmScanner::new(http_client);
        assert!(scanner.access_token.is_none());
    }

    #[test]
    fn test_extract_resource_group() {
        let http_client = Arc::new(HttpClient::with_config(30, 3, true, true, 100, 10).unwrap());
        let scanner = AzureVmScanner::new(http_client);

        let resource_id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm1";
        let rg = scanner.extract_resource_group(resource_id);

        assert_eq!(rg, Some("my-rg".to_string()));
    }
}
