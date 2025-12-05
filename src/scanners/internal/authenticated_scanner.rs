// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Authenticated Scanner for Internal Networks
 * Performs authenticated vulnerability and configuration scanning
 *
 * Features:
 * - SSH credential scanning
 * - Windows credential scanning (WMI, PowerShell)
 * - Database credential scanning
 * - API key-based scanning
 * - LDAP/Active Directory integration
 * - Patch level detection
 * - Configuration compliance
 *
 * © 2025 Bountyy Oy
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Credential types for authenticated scanning
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanCredential {
    SshKey {
        username: String,
        private_key: String,
        port: Option<u16>,
    },
    SshPassword {
        username: String,
        password: String,
        port: Option<u16>,
    },
    WindowsPassword {
        username: String,
        password: String,
        domain: Option<String>,
    },
    ApiKey {
        key: String,
        header_name: Option<String>,
    },
    Certificate {
        cert_path: String,
        key_path: String,
    },
    Token {
        token: String,
        token_type: String,
    },
}

// Security: Custom Debug implementation that masks sensitive data
impl std::fmt::Debug for ScanCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanCredential::SshKey { username, port, .. } => {
                f.debug_struct("SshKey")
                    .field("username", username)
                    .field("private_key", &"[REDACTED]")
                    .field("port", port)
                    .finish()
            }
            ScanCredential::SshPassword { username, port, .. } => {
                f.debug_struct("SshPassword")
                    .field("username", username)
                    .field("password", &"[REDACTED]")
                    .field("port", port)
                    .finish()
            }
            ScanCredential::WindowsPassword { username, domain, .. } => {
                f.debug_struct("WindowsPassword")
                    .field("username", username)
                    .field("password", &"[REDACTED]")
                    .field("domain", domain)
                    .finish()
            }
            ScanCredential::ApiKey { header_name, .. } => {
                f.debug_struct("ApiKey")
                    .field("key", &"[REDACTED]")
                    .field("header_name", header_name)
                    .finish()
            }
            ScanCredential::Certificate { cert_path, key_path } => {
                f.debug_struct("Certificate")
                    .field("cert_path", cert_path)
                    .field("key_path", key_path)
                    .finish()
            }
            ScanCredential::Token { token_type, .. } => {
                f.debug_struct("Token")
                    .field("token", &"[REDACTED]")
                    .field("token_type", token_type)
                    .finish()
            }
        }
    }
}

// Security: Safe display for logging (never exposes secrets)
impl std::fmt::Display for ScanCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanCredential::SshKey { username, port, .. } => {
                write!(f, "SSH key for {}@{}", username, port.unwrap_or(22))
            }
            ScanCredential::SshPassword { username, port, .. } => {
                write!(f, "SSH password for {}@{}", username, port.unwrap_or(22))
            }
            ScanCredential::WindowsPassword { username, domain, .. } => {
                if let Some(d) = domain {
                    write!(f, "Windows password for {}\\{}", d, username)
                } else {
                    write!(f, "Windows password for {}", username)
                }
            }
            ScanCredential::ApiKey { header_name, .. } => {
                write!(f, "API key ({})", header_name.as_deref().unwrap_or("default"))
            }
            ScanCredential::Certificate { cert_path, .. } => {
                write!(f, "Certificate ({})", cert_path)
            }
            ScanCredential::Token { token_type, .. } => {
                write!(f, "{} token", token_type)
            }
        }
    }
}

/// Patch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub installed: bool,
    pub install_date: Option<String>,
    pub description: Option<String>,
}

/// Configuration item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationItem {
    pub category: String,
    pub key: String,
    pub value: serde_json::Value,
    pub compliant: bool,
    pub recommendation: Option<String>,
}

/// Authenticated scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedScanResult {
    pub authenticated: bool,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub os_build: Option<String>,

    // Patches
    pub patches_installed: Vec<PatchInfo>,
    pub patches_missing: Vec<PatchInfo>,
    pub last_patch_date: Option<String>,

    // Configuration
    pub configurations: Vec<ConfigurationItem>,
    pub misconfigurations: Vec<ConfigurationItem>,

    // Access control
    pub local_admins: Vec<String>,
    pub sudo_users: Vec<String>,
    pub privileged_accounts: Vec<String>,

    // Active Directory
    pub ad_domain: Option<String>,
    pub ad_groups: Vec<String>,
    pub ad_policies: serde_json::Value,

    // Services
    pub services: Vec<ServiceInfo>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub status: String,
    pub version: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub cve: Option<String>,
    pub description: String,
}

/// Authenticated scanner
pub struct AuthenticatedScanner {
    timeout: Duration,
}

impl AuthenticatedScanner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(300),
        }
    }

    /// Scan target with credentials
    pub async fn scan(
        &self,
        target: &str,
        credentials: &[ScanCredential],
    ) -> Result<AuthenticatedScanResult> {
        info!("Starting authenticated scan for {}", target);

        // Try each credential until one works
        for credential in credentials {
            match self.try_credential(target, credential).await {
                Ok(result) => {
                    // Security: Use Display trait instead of Debug to avoid logging secrets
                    info!("Successfully authenticated to {} with {}", target, credential);
                    return Ok(result);
                }
                Err(e) => {
                    warn!("Failed to authenticate with credential: {}", e);
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!("Failed to authenticate with any provided credentials"))
    }

    /// Try scanning with a specific credential
    async fn try_credential(
        &self,
        target: &str,
        credential: &ScanCredential,
    ) -> Result<AuthenticatedScanResult> {
        match credential {
            ScanCredential::SshKey { username, private_key, port } => {
                self.scan_ssh_key(target, username, private_key, *port).await
            }
            ScanCredential::SshPassword { username, password, port } => {
                self.scan_ssh_password(target, username, password, *port).await
            }
            ScanCredential::WindowsPassword { username, password, domain } => {
                self.scan_windows(target, username, password, domain.as_deref()).await
            }
            _ => {
                Err(anyhow::anyhow!("Credential type not yet implemented"))
            }
        }
    }

    /// Scan via SSH with key
    async fn scan_ssh_key(
        &self,
        target: &str,
        username: &str,
        private_key: &str,
        port: Option<u16>,
    ) -> Result<AuthenticatedScanResult> {
        let port = port.unwrap_or(22);

        info!("Scanning {} via SSH (key auth) as {}", target, username);

        // Write private key to temporary file
        let key_file = self.write_temp_key(private_key)?;

        // Test connection
        let test_cmd = format!(
            "ssh -i {} -p {} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {}@{} 'echo connected'",
            key_file.display(),
            port,
            username,
            target
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(&test_cmd)
            .output()
            .context("Failed to execute SSH command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("SSH connection failed"));
        }

        // Gather system information
        let result = self.gather_ssh_info(target, username, &key_file.to_string_lossy(), port).await?;

        // Clean up key file
        let _ = std::fs::remove_file(key_file);

        Ok(result)
    }

    /// Scan via SSH with password
    async fn scan_ssh_password(
        &self,
        target: &str,
        username: &str,
        password: &str,
        port: Option<u16>,
    ) -> Result<AuthenticatedScanResult> {
        let port = port.unwrap_or(22);

        info!("Scanning {} via SSH (password auth) as {}", target, username);

        // Use sshpass for password authentication
        let test_cmd = format!(
            "sshpass -p '{}' ssh -p {} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {}@{} 'echo connected'",
            password,
            port,
            username,
            target
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(&test_cmd)
            .output()
            .context("Failed to execute SSH command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("SSH connection failed"));
        }

        // Gather system information using password
        self.gather_ssh_info_password(target, username, password, port).await
    }

    /// Scan Windows system via WMI/PowerShell
    async fn scan_windows(
        &self,
        target: &str,
        username: &str,
        password: &str,
        domain: Option<&str>,
    ) -> Result<AuthenticatedScanResult> {
        info!("Scanning Windows system {} as {}", target, username);

        let full_username = if let Some(d) = domain {
            format!("{}\\{}", d, username)
        } else {
            username.to_string()
        };

        // Use PowerShell remoting or WMI
        let result = self.scan_windows_wmi(target, &full_username, password).await?;

        Ok(result)
    }

    /// Gather information via SSH
    async fn gather_ssh_info(
        &self,
        target: &str,
        username: &str,
        key_file: &str,
        port: u16,
    ) -> Result<AuthenticatedScanResult> {
        let ssh_base = format!(
            "ssh -i {} -p {} -o StrictHostKeyChecking=no {}@{}",
            key_file, port, username, target
        );

        // Get hostname
        let hostname = self.ssh_exec(&ssh_base, "hostname").await?;

        // Get OS info
        let os_info = self.ssh_exec(&ssh_base, "uname -a && cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null").await?;

        // Get installed packages (Debian/Ubuntu)
        let packages = self.ssh_exec(&ssh_base, "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null").await.unwrap_or_default();

        // Get sudo users
        let sudo_users = self.ssh_exec(&ssh_base, "getent group sudo 2>/dev/null | cut -d: -f4").await.unwrap_or_default();

        // Get running services
        let services = self.ssh_exec(&ssh_base, "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null").await.unwrap_or_default();

        // Parse and structure the results
        let (os_type, os_version) = self.parse_os_info(&os_info);

        Ok(AuthenticatedScanResult {
            authenticated: true,
            hostname: hostname.trim().to_string(),
            os_type,
            os_version,
            os_build: None,
            patches_installed: self.parse_packages(&packages),
            patches_missing: Vec::new(), // Would need to check against CVE database
            last_patch_date: None,
            configurations: Vec::new(),
            misconfigurations: Vec::new(),
            local_admins: Vec::new(),
            sudo_users: sudo_users.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            privileged_accounts: Vec::new(),
            ad_domain: None,
            ad_groups: Vec::new(),
            ad_policies: serde_json::json!({}),
            services: self.parse_services(&services),
            vulnerabilities: Vec::new(),
        })
    }

    /// Gather information via SSH with password
    async fn gather_ssh_info_password(
        &self,
        target: &str,
        username: &str,
        password: &str,
        port: u16,
    ) -> Result<AuthenticatedScanResult> {
        let ssh_base = format!(
            "sshpass -p '{}' ssh -p {} -o StrictHostKeyChecking=no {}@{}",
            password, port, username, target
        );

        // Get hostname
        let hostname = self.ssh_exec(&ssh_base, "hostname").await?;

        // Get OS info
        let os_info = self.ssh_exec(&ssh_base, "uname -a && cat /etc/os-release").await?;

        let (os_type, os_version) = self.parse_os_info(&os_info);

        Ok(AuthenticatedScanResult {
            authenticated: true,
            hostname: hostname.trim().to_string(),
            os_type,
            os_version,
            os_build: None,
            patches_installed: Vec::new(),
            patches_missing: Vec::new(),
            last_patch_date: None,
            configurations: Vec::new(),
            misconfigurations: Vec::new(),
            local_admins: Vec::new(),
            sudo_users: Vec::new(),
            privileged_accounts: Vec::new(),
            ad_domain: None,
            ad_groups: Vec::new(),
            ad_policies: serde_json::json!({}),
            services: Vec::new(),
            vulnerabilities: Vec::new(),
        })
    }

    /// Scan Windows via WMI
    async fn scan_windows_wmi(
        &self,
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<AuthenticatedScanResult> {
        // Use wmic or PowerShell remoting
        // This is a placeholder - actual implementation would use Windows Management Instrumentation

        info!("Scanning Windows system via WMI: {}", target);

        // Get computer name
        let hostname_cmd = format!(
            "wmic /node:{} /user:{} /password:{} computersystem get name",
            target, username, password
        );

        let hostname = self.exec_command(&hostname_cmd).await.unwrap_or_else(|_| target.to_string());

        // Get OS info
        let os_cmd = format!(
            "wmic /node:{} /user:{} /password:{} os get Caption,Version",
            target, username, password
        );

        let os_info = self.exec_command(&os_cmd).await.unwrap_or_default();

        // Get installed updates
        let updates_cmd = format!(
            "wmic /node:{} /user:{} /password:{} qfe list",
            target, username, password
        );

        let updates = self.exec_command(&updates_cmd).await.unwrap_or_default();

        // Get local administrators
        let admins_cmd = format!(
            "wmic /node:{} /user:{} /password:{} group where name='Administrators' get",
            target, username, password
        );

        let admins = self.exec_command(&admins_cmd).await.unwrap_or_default();

        Ok(AuthenticatedScanResult {
            authenticated: true,
            hostname: hostname.trim().to_string(),
            os_type: "windows".to_string(),
            os_version: os_info.trim().to_string(),
            os_build: None,
            patches_installed: self.parse_windows_updates(&updates),
            patches_missing: Vec::new(),
            last_patch_date: None,
            configurations: Vec::new(),
            misconfigurations: Vec::new(),
            local_admins: self.parse_windows_admins(&admins),
            sudo_users: Vec::new(),
            privileged_accounts: Vec::new(),
            ad_domain: None,
            ad_groups: Vec::new(),
            ad_policies: serde_json::json!({}),
            services: Vec::new(),
            vulnerabilities: Vec::new(),
        })
    }

    /// Execute SSH command
    async fn ssh_exec(&self, ssh_base: &str, command: &str) -> Result<String> {
        let full_command = format!("{} '{}'", ssh_base, command);

        let output = Command::new("sh")
            .arg("-c")
            .arg(&full_command)
            .output()
            .context("Failed to execute SSH command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Command failed: {}", stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Execute generic command
    async fn exec_command(&self, command: &str) -> Result<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .context("Failed to execute command")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Write temporary SSH key file
    fn write_temp_key(&self, key_content: &str) -> Result<std::path::PathBuf> {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join(format!("ssh_key_{}", uuid::Uuid::new_v4()));

        let mut file = std::fs::File::create(&key_path)
            .context("Failed to create temporary key file")?;

        file.write_all(key_content.as_bytes())
            .context("Failed to write key content")?;

        // Set permissions to 600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&key_path, perms)?;
        }

        Ok(key_path)
    }

    /// Parse OS information
    fn parse_os_info(&self, os_info: &str) -> (String, String) {
        let os_type = if os_info.contains("Ubuntu") {
            "ubuntu"
        } else if os_info.contains("Debian") {
            "debian"
        } else if os_info.contains("CentOS") || os_info.contains("Red Hat") {
            "rhel"
        } else if os_info.contains("Linux") {
            "linux"
        } else {
            "unknown"
        };

        let os_version = os_info
            .lines()
            .find(|line| line.contains("VERSION=") || line.contains("PRETTY_NAME="))
            .and_then(|line| line.split('=').nth(1))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".to_string());

        (os_type.to_string(), os_version)
    }

    /// Parse installed packages
    fn parse_packages(&self, packages: &str) -> Vec<PatchInfo> {
        packages
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(100) // Limit to first 100 packages
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                PatchInfo {
                    id: parts.get(1).unwrap_or(&"unknown").to_string(),
                    name: parts.get(1).unwrap_or(&"unknown").to_string(),
                    severity: "info".to_string(),
                    installed: true,
                    install_date: None,
                    description: None,
                }
            })
            .collect()
    }

    /// Parse Windows updates
    fn parse_windows_updates(&self, updates: &str) -> Vec<PatchInfo> {
        updates
            .lines()
            .filter(|line| !line.trim().is_empty() && line.contains("KB"))
            .map(|line| {
                PatchInfo {
                    id: line.trim().to_string(),
                    name: line.trim().to_string(),
                    severity: "info".to_string(),
                    installed: true,
                    install_date: None,
                    description: None,
                }
            })
            .collect()
    }

    /// Parse Windows administrators
    fn parse_windows_admins(&self, admins: &str) -> Vec<String> {
        admins
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect()
    }

    /// Parse running services
    fn parse_services(&self, services: &str) -> Vec<ServiceInfo> {
        services
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(50) // Limit to first 50 services
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                ServiceInfo {
                    name: parts.get(0).unwrap_or(&"unknown").to_string(),
                    status: "running".to_string(),
                    version: None,
                    port: None,
                }
            })
            .collect()
    }
}

impl Default for AuthenticatedScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_os_info() {
        let scanner = AuthenticatedScanner::new();
        let os_info = "Linux ubuntu 5.15.0-56-generic\nNAME=\"Ubuntu\"\nVERSION=\"22.04.1 LTS\"";
        let (os_type, os_version) = scanner.parse_os_info(os_info);
        assert_eq!(os_type, "ubuntu");
        assert!(os_version.contains("22.04") || os_version.contains("Ubuntu"));
    }
}
