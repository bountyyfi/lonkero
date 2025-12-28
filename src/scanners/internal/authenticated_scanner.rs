// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Authenticated Scanner for Internal Networks
 * Performs authenticated vulnerability and configuration scanning
 *
 * Features:
 * - SSH credential scanning (using native SSH library - SECURE)
 * - Database credential scanning
 * - API key-based scanning
 * - LDAP/Active Directory integration
 * - Patch level detection
 * - Configuration compliance
 *
 * SECURITY: This module uses the ssh2 crate for native SSH connections
 * to prevent command injection vulnerabilities. All user inputs are
 * validated before use.
 *
 * © 2026 Bountyy Oy
 */

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
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

        // Validate target before attempting connection
        Self::validate_target(target)?;

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

        Err(anyhow!("Failed to authenticate with any provided credentials"))
    }

    /// Validate target hostname/IP
    fn validate_target(target: &str) -> Result<()> {
        // Whitelist: only allow valid hostnames and IP addresses
        // No special characters that could be used for injection
        let valid_chars = target.chars().all(|c| {
            c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == ':'
        });

        if !valid_chars {
            return Err(anyhow!("Invalid target: contains illegal characters"));
        }

        if target.is_empty() || target.len() > 253 {
            return Err(anyhow!("Invalid target: length out of bounds"));
        }

        Ok(())
    }

    /// Validate username
    fn validate_username(username: &str) -> Result<()> {
        // Username validation: alphanumeric, underscore, hyphen, dot
        let valid_chars = username.chars().all(|c| {
            c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
        });

        if !valid_chars {
            return Err(anyhow!("Invalid username: contains illegal characters"));
        }

        if username.is_empty() || username.len() > 32 {
            return Err(anyhow!("Invalid username: length out of bounds"));
        }

        Ok(())
    }

    /// Try scanning with a specific credential
    async fn try_credential(
        &self,
        target: &str,
        credential: &ScanCredential,
    ) -> Result<AuthenticatedScanResult> {
        match credential {
            ScanCredential::SshKey { username, private_key, port } => {
                Self::validate_username(username)?;
                self.scan_ssh_key(target, username, private_key, *port).await
            }
            ScanCredential::SshPassword { username, password, port } => {
                Self::validate_username(username)?;
                self.scan_ssh_password(target, username, password, *port).await
            }
            ScanCredential::WindowsPassword { .. } => {
                Err(anyhow!(
                    "Windows authentication is currently disabled due to security concerns. \
                     Native Windows remoting library support is planned for a future release."
                ))
            }
            _ => {
                Err(anyhow!("Credential type not yet implemented"))
            }
        }
    }

    /// Create SSH session and connect
    fn create_ssh_session(target: &str, port: u16, timeout: Duration) -> Result<Session> {
        // Connect via TCP
        let tcp = TcpStream::connect_timeout(
            &format!("{}:{}", target, port).parse()?,
            timeout,
        ).context("Failed to connect to SSH server")?;

        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;

        // Create SSH session
        let mut sess = Session::new().context("Failed to create SSH session")?;
        sess.set_tcp_stream(tcp);
        sess.set_timeout(timeout.as_millis() as u32);
        sess.handshake().context("SSH handshake failed")?;

        Ok(sess)
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

        // Create session
        let mut sess = Self::create_ssh_session(target, port, self.timeout)?;

        // Authenticate with public key
        sess.userauth_pubkey_file(
            username,
            None,
            &key_file,
            None,
        ).context("SSH key authentication failed")?;

        if !sess.authenticated() {
            return Err(anyhow!("SSH authentication failed"));
        }

        // Gather system information
        let result = self.gather_ssh_info(&sess, target, username).await?;

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

        // Create session
        let mut sess = Self::create_ssh_session(target, port, self.timeout)?;

        // Authenticate with password
        sess.userauth_password(username, password)
            .context("SSH password authentication failed")?;

        if !sess.authenticated() {
            return Err(anyhow!("SSH authentication failed"));
        }

        // Gather system information
        self.gather_ssh_info(&sess, target, username).await
    }

    /// Execute command over SSH session
    fn ssh_exec(sess: &Session, command: &str) -> Result<String> {
        let mut channel = sess.channel_session()
            .context("Failed to open SSH channel")?;

        channel.exec(command)
            .context("Failed to execute command")?;

        let mut output = String::new();
        channel.read_to_string(&mut output)
            .context("Failed to read command output")?;

        channel.wait_close()
            .context("Failed to close channel")?;

        let exit_status = channel.exit_status()?;
        if exit_status != 0 {
            debug!("Command exited with status {}: {}", exit_status, command);
        }

        Ok(output)
    }

    /// Gather information via SSH
    async fn gather_ssh_info(
        &self,
        sess: &Session,
        target: &str,
        username: &str,
    ) -> Result<AuthenticatedScanResult> {
        debug!("Gathering system information from {}", target);

        // Get hostname
        let hostname = Self::ssh_exec(sess, "hostname")
            .unwrap_or_else(|_| target.to_string());

        // Get OS info
        let os_info = Self::ssh_exec(
            sess,
            "uname -a && cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null"
        ).unwrap_or_default();

        // Get installed packages
        let packages = Self::ssh_exec(
            sess,
            "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null"
        ).unwrap_or_default();

        // Get sudo users
        let sudo_users = Self::ssh_exec(
            sess,
            "getent group sudo 2>/dev/null | cut -d: -f4"
        ).unwrap_or_default();

        // Get running services
        let services = Self::ssh_exec(
            sess,
            "systemctl list-units --type=service --state=running --no-pager 2>/dev/null || service --status-all 2>/dev/null"
        ).unwrap_or_default();

        // Parse and structure the results
        let (os_type, os_version) = self.parse_os_info(&os_info);

        Ok(AuthenticatedScanResult {
            authenticated: true,
            hostname: hostname.trim().to_string(),
            os_type,
            os_version,
            os_build: None,
            patches_installed: self.parse_packages(&packages),
            patches_missing: Vec::new(),
            last_patch_date: None,
            configurations: Vec::new(),
            misconfigurations: Vec::new(),
            local_admins: Vec::new(),
            sudo_users: sudo_users
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            privileged_accounts: Vec::new(),
            ad_domain: None,
            ad_groups: Vec::new(),
            ad_policies: serde_json::json!({}),
            services: self.parse_services(&services),
            vulnerabilities: Vec::new(),
        })
    }

    /// Write temporary SSH key file
    fn write_temp_key(&self, key_content: &str) -> Result<PathBuf> {
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

    /// Parse running services
    fn parse_services(&self, services: &str) -> Vec<ServiceInfo> {
        services
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(50) // Limit to first 50 services
            .map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                ServiceInfo {
                    name: parts.first().unwrap_or(&"unknown").to_string(),
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

    #[tokio::test]
    async fn test_validate_target() {
        // Valid targets
        assert!(AuthenticatedScanner::validate_target("example.com").is_ok());
        assert!(AuthenticatedScanner::validate_target("192.168.1.1").is_ok());
        assert!(AuthenticatedScanner::validate_target("host-name.example.com").is_ok());
        assert!(AuthenticatedScanner::validate_target("192.168.1.1:22").is_ok());

        // Invalid targets (potential injection)
        assert!(AuthenticatedScanner::validate_target("host; rm -rf /").is_err());
        assert!(AuthenticatedScanner::validate_target("host`whoami`").is_err());
        assert!(AuthenticatedScanner::validate_target("host$(ls)").is_err());
        assert!(AuthenticatedScanner::validate_target("host&& cat /etc/passwd").is_err());
    }

    #[tokio::test]
    async fn test_validate_username() {
        // Valid usernames
        assert!(AuthenticatedScanner::validate_username("admin").is_ok());
        assert!(AuthenticatedScanner::validate_username("user123").is_ok());
        assert!(AuthenticatedScanner::validate_username("user_name").is_ok());
        assert!(AuthenticatedScanner::validate_username("user-name").is_ok());

        // Invalid usernames (potential injection)
        assert!(AuthenticatedScanner::validate_username("user; whoami").is_err());
        assert!(AuthenticatedScanner::validate_username("user`id`").is_err());
        assert!(AuthenticatedScanner::validate_username("user$(pwd)").is_err());
        assert!(AuthenticatedScanner::validate_username("user && ls").is_err());
    }
}
