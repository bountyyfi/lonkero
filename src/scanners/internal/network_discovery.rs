// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Network Discovery Scanner
 * Discovers and maps internal network assets
 *
 * Features:
 * - ARP scanning for local network
 * - ICMP ping sweeps
 * - TCP SYN scanning for host discovery
 * - Service enumeration
 * - OS fingerprinting
 * - Network topology mapping
 *
 * © 2025 Bountyy Oy
 */

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Network discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiscoveryResult {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub os_detected: Option<String>,
    pub os_version: Option<String>,
    pub os_accuracy: Option<u8>,
    pub open_ports: Vec<PortInfo>,
    pub services: Vec<ServiceInfo>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub is_alive: bool,
    pub response_time_ms: Option<u64>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub subnet_mask: Option<String>,
}

/// Network discovery options
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryOptions {
    #[serde(default = "default_true")]
    pub ping_scan: bool,

    #[serde(default = "default_true")]
    pub port_scan: bool,

    #[serde(default = "default_false")]
    pub os_detection: bool,

    #[serde(default = "default_false")]
    pub service_detection: bool,

    #[serde(default = "default_false")]
    pub aggressive: bool,

    #[serde(default)]
    pub port_range: Option<String>,

    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_timeout() -> u64 { 30 }

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            ping_scan: true,
            port_scan: true,
            os_detection: false,
            service_detection: false,
            aggressive: false,
            port_range: None,
            timeout_secs: 30,
        }
    }
}

/// Network discovery scanner
pub struct NetworkDiscoveryScanner {
    timeout: Duration,
}

impl NetworkDiscoveryScanner {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    /// Discover single host
    pub async fn discover_host(
        &self,
        target: &str,
        options: &DiscoveryOptions,
    ) -> Result<NetworkDiscoveryResult> {
        info!("Discovering host: {}", target);

        let start_time = std::time::Instant::now();

        // Check if host is alive
        let is_alive = if options.ping_scan {
            self.ping_host(target).await?
        } else {
            true // Assume alive if ping scan disabled
        };

        if !is_alive {
            return Ok(NetworkDiscoveryResult {
                ip_address: target.to_string(),
                hostname: None,
                mac_address: None,
                os_detected: None,
                os_version: None,
                os_accuracy: None,
                open_ports: Vec::new(),
                services: Vec::new(),
                network_interfaces: Vec::new(),
                is_alive: false,
                response_time_ms: None,
                last_seen: chrono::Utc::now(),
            });
        }

        let response_time = start_time.elapsed().as_millis() as u64;

        // Get hostname
        let hostname = self.resolve_hostname(target).await.ok();

        // Get MAC address (only works on local network)
        let mac_address = self.get_mac_address(target).await.ok();

        // Port scanning
        let open_ports = if options.port_scan {
            self.scan_ports(target, options).await?
        } else {
            Vec::new()
        };

        // Service detection
        let services = if options.service_detection && !open_ports.is_empty() {
            self.detect_services(target, &open_ports).await?
        } else {
            Vec::new()
        };

        // OS detection
        let (os_detected, os_version, os_accuracy) = if options.os_detection && !open_ports.is_empty() {
            self.detect_os(target).await?
        } else {
            (None, None, None)
        };

        Ok(NetworkDiscoveryResult {
            ip_address: target.to_string(),
            hostname,
            mac_address,
            os_detected,
            os_version,
            os_accuracy,
            open_ports,
            services,
            network_interfaces: Vec::new(),
            is_alive,
            response_time_ms: Some(response_time),
            last_seen: chrono::Utc::now(),
        })
    }

    /// Discover network range
    pub async fn discover_range(
        &self,
        cidr: &str,
        options: &DiscoveryOptions,
    ) -> Result<Vec<NetworkDiscoveryResult>> {
        info!("Discovering network range: {}", cidr);

        let targets = self.expand_cidr(cidr)?;
        let mut results = Vec::new();

        info!("Scanning {} hosts in range {}", targets.len(), cidr);

        // Scan hosts in parallel (with concurrency limit)
        let semaphore = Arc::new(tokio::sync::Semaphore::new(50));
        let mut tasks = Vec::new();

        for target in targets {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let target_clone = target.clone();
            let options_clone = options.clone();
            let scanner = Self::new();

            tasks.push(tokio::spawn(async move {
                let result = scanner.discover_host(&target_clone, &options_clone).await;
                drop(permit);
                result
            }));
        }

        // Collect results
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => {
                    if result.is_alive {
                        results.push(result);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Discovery failed: {}", e);
                }
                Err(e) => {
                    warn!("Task failed: {}", e);
                }
            }
        }

        info!("Discovered {} alive hosts", results.len());

        Ok(results)
    }

    /// Ping host to check if alive
    async fn ping_host(&self, target: &str) -> Result<bool> {
        debug!("Pinging host: {}", target);

        let output = Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("2")
            .arg(target)
            .output()
            .context("Failed to execute ping command")?;

        Ok(output.status.success())
    }

    /// Resolve hostname via reverse DNS
    async fn resolve_hostname(&self, ip: &str) -> Result<String> {
        debug!("Resolving hostname for: {}", ip);

        let output = Command::new("host")
            .arg(ip)
            .output()
            .context("Failed to execute host command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to resolve hostname"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse hostname from output
        let hostname = output_str
            .lines()
            .find(|line| line.contains("domain name pointer"))
            .and_then(|line| line.split_whitespace().last())
            .map(|h| h.trim_end_matches('.').to_string())
            .ok_or_else(|| anyhow::anyhow!("No hostname found"))?;

        Ok(hostname)
    }

    /// Get MAC address (ARP)
    async fn get_mac_address(&self, ip: &str) -> Result<String> {
        debug!("Getting MAC address for: {}", ip);

        // Ping first to populate ARP cache
        let _ = self.ping_host(ip).await;

        // Check ARP cache
        let output = Command::new("arp")
            .arg("-n")
            .arg(ip)
            .output()
            .context("Failed to execute arp command")?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse MAC address
        let mac = output_str
            .lines()
            .find(|line| line.contains(ip))
            .and_then(|line| {
                line.split_whitespace()
                    .find(|part| part.contains(':') && part.matches(':').count() == 5)
            })
            .map(|m| m.to_string())
            .ok_or_else(|| anyhow::anyhow!("No MAC address found"))?;

        Ok(mac)
    }

    /// Scan ports
    async fn scan_ports(
        &self,
        target: &str,
        options: &DiscoveryOptions,
    ) -> Result<Vec<PortInfo>> {
        debug!("Scanning ports on: {}", target);

        // Use nmap for comprehensive port scanning
        let mut nmap_args = vec![
            "-Pn", // Skip host discovery
            "-T4", // Aggressive timing
        ];

        // Port range
        if let Some(ref port_range) = options.port_range {
            nmap_args.push("-p");
            nmap_args.push(port_range);
        } else {
            nmap_args.push("--top-ports");
            nmap_args.push("1000");
        }

        // Service version detection
        if options.service_detection {
            nmap_args.push("-sV");
        }

        // Aggressive scan
        if options.aggressive {
            nmap_args.push("-A");
        }

        nmap_args.push(target);

        let output = Command::new("nmap")
            .args(&nmap_args)
            .output()
            .context("Failed to execute nmap command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Nmap scan failed"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let ports = self.parse_nmap_ports(&output_str);

        Ok(ports)
    }

    /// Detect services on open ports
    async fn detect_services(
        &self,
        target: &str,
        ports: &[PortInfo],
    ) -> Result<Vec<ServiceInfo>> {
        debug!("Detecting services on: {}", target);

        let mut services = Vec::new();

        for port_info in ports {
            if let Some(ref service) = port_info.service {
                services.push(ServiceInfo {
                    name: service.clone(),
                    port: port_info.port,
                    protocol: port_info.protocol.clone(),
                    version: port_info.version.clone(),
                    banner: None,
                });
            }
        }

        Ok(services)
    }

    /// Detect operating system
    async fn detect_os(&self, target: &str) -> Result<(Option<String>, Option<String>, Option<u8>)> {
        debug!("Detecting OS for: {}", target);

        let output = Command::new("nmap")
            .arg("-O")
            .arg("-Pn")
            .arg(target)
            .output()
            .context("Failed to execute nmap OS detection")?;

        if !output.status.success() {
            return Ok((None, None, None));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let (os_name, os_version, accuracy) = self.parse_nmap_os(&output_str);

        Ok((os_name, os_version, accuracy))
    }

    /// Parse nmap port scan output
    fn parse_nmap_ports(&self, output: &str) -> Vec<PortInfo> {
        let mut ports = Vec::new();

        for line in output.lines() {
            if line.contains("/tcp") || line.contains("/udp") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let port_proto = parts[0];
                let port_parts: Vec<&str> = port_proto.split('/').collect();

                if port_parts.len() < 2 {
                    continue;
                }

                let port = port_parts[0].parse::<u16>().ok();
                let protocol = port_parts[1];
                let state = parts.get(1).unwrap_or(&"unknown");
                let service = parts.get(2).map(|s| s.to_string());

                if let Some(port_num) = port {
                    ports.push(PortInfo {
                        port: port_num,
                        protocol: protocol.to_string(),
                        state: state.to_string(),
                        service,
                        version: None,
                    });
                }
            }
        }

        ports
    }

    /// Parse nmap OS detection output
    fn parse_nmap_os(&self, output: &str) -> (Option<String>, Option<String>, Option<u8>) {
        let mut os_name = None;
        let mut os_version = None;
        let mut accuracy = None;

        for line in output.lines() {
            if line.contains("OS details:") {
                os_name = line.split("OS details:").nth(1).map(|s| s.trim().to_string());
            } else if line.contains("Running:") {
                os_version = line.split("Running:").nth(1).map(|s| s.trim().to_string());
            } else if line.contains("Aggressive OS guesses:") {
                let parts: Vec<&str> = line.split('(').collect();
                if parts.len() >= 2 {
                    let percent = parts[1].split('%').next();
                    accuracy = percent.and_then(|p| p.parse::<u8>().ok());
                }
            }
        }

        (os_name, os_version, accuracy)
    }

    /// Expand CIDR notation to IP list
    fn expand_cidr(&self, cidr: &str) -> Result<Vec<String>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR notation: {}", cidr));
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .context("Invalid IP address in CIDR")?;

        let prefix_len: u8 = parts[1]
            .parse()
            .context("Invalid prefix length in CIDR")?;

        if prefix_len > 32 {
            return Err(anyhow::anyhow!("Invalid prefix length: {}", prefix_len));
        }

        let ip_int = u32::from(ip);
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let network = ip_int & mask;
        let broadcast = network | !mask;

        let mut ips = Vec::new();

        // Skip network and broadcast addresses
        for i in (network + 1)..broadcast {
            ips.push(Ipv4Addr::from(i).to_string());
        }

        Ok(ips)
    }

    /// Perform ARP scan on local network
    pub async fn arp_scan(&self, interface: &str) -> Result<Vec<NetworkDiscoveryResult>> {
        info!("Performing ARP scan on interface: {}", interface);

        let output = Command::new("arp-scan")
            .arg("--interface")
            .arg(interface)
            .arg("--localnet")
            .output()
            .context("Failed to execute arp-scan command")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("ARP scan failed"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let results = self.parse_arp_scan(&output_str);

        Ok(results)
    }

    /// Parse arp-scan output
    fn parse_arp_scan(&self, output: &str) -> Vec<NetworkDiscoveryResult> {
        let mut results = Vec::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Check if first part looks like an IP
                if parts[0].contains('.') {
                    results.push(NetworkDiscoveryResult {
                        ip_address: parts[0].to_string(),
                        hostname: None,
                        mac_address: Some(parts[1].to_string()),
                        os_detected: None,
                        os_version: None,
                        os_accuracy: None,
                        open_ports: Vec::new(),
                        services: Vec::new(),
                        network_interfaces: Vec::new(),
                        is_alive: true,
                        response_time_ms: None,
                        last_seen: chrono::Utc::now(),
                    });
                }
            }
        }

        results
    }
}

impl Default for NetworkDiscoveryScanner {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_cidr() {
        let scanner = NetworkDiscoveryScanner::new();
        let ips = scanner.expand_cidr("192.168.1.0/29").unwrap();
        assert_eq!(ips.len(), 6); // Network has 8 addresses, minus network and broadcast
    }

    #[test]
    fn test_parse_nmap_ports() {
        let scanner = NetworkDiscoveryScanner::new();
        let output = "22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n";
        let ports = scanner.parse_nmap_ports(output);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].service, Some("ssh".to_string()));
    }
}
