// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

// External Port Scanner
// Production-grade TCP/UDP port scanning with service detection
// © 2026 Bountyy Oy

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    pub scan_technique: ScanTechnique,
    pub timeout_ms: u64,
    pub max_rate: u32,  // Packets per second
    pub stealth_mode: bool,
    pub randomize_ports: bool,
    pub banner_grab: bool,
    pub service_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanTechnique {
    Syn,        // SYN scan (requires raw sockets/privileges)
    Connect,    // TCP Connect scan
    Udp,        // UDP scan
    Null,       // NULL scan
    Fin,        // FIN scan
    Xmas,       // XMAS scan
    Ack,        // ACK scan
    Window,     // Window scan
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
    pub vulnerabilities: Vec<String>,
    pub scan_technique: String,
    pub response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanSummary {
    pub target: String,
    pub scan_duration_seconds: u64,
    pub ports_scanned: u32,
    pub open_ports: Vec<PortScanResult>,
    pub filtered_ports: Vec<u16>,
    pub closed_ports_count: u32,
    pub uncommon_ports: Vec<PortScanResult>,
    pub common_services: Vec<String>,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            scan_technique: ScanTechnique::Connect,
            timeout_ms: 3000,
            max_rate: 1000,
            stealth_mode: false,
            randomize_ports: true,
            banner_grab: true,
            service_detection: true,
        }
    }
}

pub struct ExternalPortScanner {
    config: PortScanConfig,
}

impl ExternalPortScanner {
    pub fn new(config: PortScanConfig) -> Self {
        Self { config }
    }

    /// Scan a range of ports on a target
    pub async fn scan_ports(
        &self,
        target: &str,
        port_range: (u16, u16),
    ) -> Result<PortScanSummary> {
        let start_time = std::time::Instant::now();

        // Parse target to IP address
        let ip_addr = self.resolve_target(target).await?;

        info!(
            "Starting port scan on {} ({}): ports {}-{}",
            target, ip_addr, port_range.0, port_range.1
        );

        // Generate port list
        let mut ports: Vec<u16> = (port_range.0..=port_range.1).collect();

        if self.config.randomize_ports {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            ports.shuffle(&mut rng);
        }

        let total_ports = ports.len() as u32;

        // Scan ports with rate limiting
        let mut open_ports = Vec::new();
        let mut filtered_ports = Vec::new();
        let mut closed_count = 0;

        let rate_limiter = self.create_rate_limiter();
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        for port in ports {
            // Rate limiting
            rate_limiter.until_ready().await;

            match self.scan_single_port(ip_addr, port, timeout_duration).await {
                Ok(result) => {
                    match result.state {
                        PortState::Open => {
                            info!("Port {} is OPEN: {:?}", port, result.service);
                            open_ports.push(result);
                        }
                        PortState::Filtered | PortState::OpenFiltered => {
                            filtered_ports.push(port);
                        }
                        _ => {
                            closed_count += 1;
                        }
                    }
                }
                Err(e) => {
                    debug!("Error scanning port {}: {}", port, e);
                    closed_count += 1;
                }
            }
        }

        // Identify uncommon ports
        let uncommon_ports = self.identify_uncommon_ports(&open_ports);
        let common_services = self.extract_common_services(&open_ports);

        let scan_duration = start_time.elapsed().as_secs();

        Ok(PortScanSummary {
            target: target.to_string(),
            scan_duration_seconds: scan_duration,
            ports_scanned: total_ports,
            open_ports,
            filtered_ports,
            closed_ports_count: closed_count,
            uncommon_ports,
            common_services,
        })
    }

    /// Scan a single port
    async fn scan_single_port(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<PortScanResult> {
        let start_time = std::time::Instant::now();

        match self.config.scan_technique {
            ScanTechnique::Connect => {
                self.tcp_connect_scan(ip, port, timeout_duration).await
            }
            ScanTechnique::Udp => {
                self.udp_scan(ip, port, timeout_duration).await
            }
            _ => {
                // For advanced techniques, fall back to connect scan
                warn!("Advanced scan techniques require raw socket privileges, using TCP Connect scan");
                self.tcp_connect_scan(ip, port, timeout_duration).await
            }
        }.map(|mut result| {
            result.response_time_ms = start_time.elapsed().as_millis() as u64;
            result
        })
    }

    /// TCP Connect scan
    async fn tcp_connect_scan(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<PortScanResult> {
        let socket_addr = SocketAddr::new(ip, port);

        match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(stream)) => {
                let service = self.identify_service(port);
                let mut banner = None;
                let mut service_version = None;

                // Banner grabbing
                if self.config.banner_grab {
                    match self.grab_banner(stream).await {
                        Ok(b) => {
                            banner = Some(b.clone());
                            if self.config.service_detection {
                                service_version = self.parse_service_version(&b, &service);
                            }
                        }
                        Err(e) => {
                            debug!("Banner grab failed for port {}: {}", port, e);
                        }
                    }
                }

                Ok(PortScanResult {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service: Some(service.clone()),
                    service_version: service_version.clone(),
                    banner,
                    cpe: self.generate_cpe(&service, &service_version),
                    vulnerabilities: Vec::new(),
                    scan_technique: "connect".to_string(),
                    response_time_ms: 0, // Set by caller
                })
            }
            Ok(Err(_)) => {
                Ok(PortScanResult {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Closed,
                    service: None,
                    service_version: None,
                    banner: None,
                    cpe: None,
                    vulnerabilities: Vec::new(),
                    scan_technique: "connect".to_string(),
                    response_time_ms: 0,
                })
            }
            Err(_) => {
                // Timeout - likely filtered
                Ok(PortScanResult {
                    port,
                    protocol: "tcp".to_string(),
                    state: PortState::Filtered,
                    service: None,
                    service_version: None,
                    banner: None,
                    cpe: None,
                    vulnerabilities: Vec::new(),
                    scan_technique: "connect".to_string(),
                    response_time_ms: timeout_duration.as_millis() as u64,
                })
            }
        }
    }

    /// UDP scan
    async fn udp_scan(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_duration: Duration,
    ) -> Result<PortScanResult> {
        let local_addr: SocketAddr = if ip.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(local_addr).await?;
        let remote_addr = SocketAddr::new(ip, port);

        // Send empty UDP packet
        socket.send_to(&[], remote_addr).await?;

        let mut buf = vec![0u8; 1024];

        match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                let response = String::from_utf8_lossy(&buf[..len]).to_string();
                let service = self.identify_service(port);

                Ok(PortScanResult {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::Open,
                    service: Some(service),
                    service_version: None,
                    banner: Some(response),
                    cpe: None,
                    vulnerabilities: Vec::new(),
                    scan_technique: "udp".to_string(),
                    response_time_ms: 0,
                })
            }
            _ => {
                // No response - could be open or filtered
                Ok(PortScanResult {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::OpenFiltered,
                    service: None,
                    service_version: None,
                    banner: None,
                    cpe: None,
                    vulnerabilities: Vec::new(),
                    scan_technique: "udp".to_string(),
                    response_time_ms: 0,
                })
            }
        }
    }

    /// Grab banner from TCP connection
    async fn grab_banner(&self, mut stream: TcpStream) -> Result<String> {
        let mut buffer = vec![0u8; 4096];

        // Try to read without sending data first (for services that send banner immediately)
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                return Ok(String::from_utf8_lossy(&buffer[..n]).trim().to_string());
            }
            _ => {}
        }

        // Send generic HTTP request for web servers
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;

        match timeout(Duration::from_millis(2000), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                Ok(String::from_utf8_lossy(&buffer[..n]).trim().to_string())
            }
            _ => Ok(String::new()),
        }
    }

    /// Identify service by port number
    fn identify_service(&self, port: u16) -> String {
        match port {
            20 | 21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            5900 => "VNC",
            6379 => "Redis",
            8080 => "HTTP-Proxy",
            8443 => "HTTPS-Alt",
            9200 => "Elasticsearch",
            27017 => "MongoDB",
            _ => "Unknown",
        }
        .to_string()
    }

    /// Parse service version from banner
    fn parse_service_version(&self, banner: &str, _service: &str) -> Option<String> {
        // Simple version extraction (can be enhanced with regex patterns)
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("apache") {
            if let Some(idx) = banner.find("Apache/") {
                let version_str = &banner[idx + 7..];
                if let Some(space_idx) = version_str.find(' ') {
                    return Some(version_str[..space_idx].to_string());
                }
            }
        }

        if banner_lower.contains("nginx") {
            if let Some(idx) = banner.find("nginx/") {
                let version_str = &banner[idx + 6..];
                if let Some(space_idx) = version_str.find(' ') {
                    return Some(version_str[..space_idx].to_string());
                }
            }
        }

        if banner_lower.contains("openssh") {
            if let Some(idx) = banner.find("OpenSSH_") {
                let version_str = &banner[idx + 8..];
                if let Some(space_idx) = version_str.find(' ') {
                    return Some(version_str[..space_idx].to_string());
                }
            }
        }

        None
    }

    /// Generate CPE (Common Platform Enumeration) identifier
    fn generate_cpe(&self, service: &str, version: &Option<String>) -> Option<String> {
        if let Some(ver) = version {
            let cpe = match service.to_lowercase().as_str() {
                "apache" => format!("cpe:/a:apache:http_server:{}", ver),
                "nginx" => format!("cpe:/a:nginx:nginx:{}", ver),
                "openssh" => format!("cpe:/a:openbsd:openssh:{}", ver),
                _ => return None,
            };
            Some(cpe)
        } else {
            None
        }
    }

    /// Identify uncommon ports (non-standard services)
    fn identify_uncommon_ports(&self, open_ports: &[PortScanResult]) -> Vec<PortScanResult> {
        let common_ports: Vec<u16> = vec![
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443,
        ];

        open_ports
            .iter()
            .filter(|p| !common_ports.contains(&p.port))
            .cloned()
            .collect()
    }

    /// Extract list of common services found
    fn extract_common_services(&self, open_ports: &[PortScanResult]) -> Vec<String> {
        open_ports
            .iter()
            .filter_map(|p| p.service.clone())
            .filter(|s| s != "Unknown")
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Resolve target hostname to IP address
    async fn resolve_target(&self, target: &str) -> Result<IpAddr> {
        use hickory_resolver::TokioResolver;
        use hickory_resolver::name_server::TokioConnectionProvider;

        // Try parsing as IP first
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Resolve hostname
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .context("Failed to create resolver")?
            .build();

        let response = resolver
            .lookup_ip(target)
            .await
            .context("Failed to resolve hostname")?;

        response
            .iter()
            .next()
            .context("No IP addresses found for hostname")
    }

    /// Create rate limiter
    fn create_rate_limiter(&self) -> governor::RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    > {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let rate = NonZeroU32::new(self.config.max_rate).unwrap_or(NonZeroU32::new(1000).unwrap());
        let quota = Quota::per_second(rate);
        RateLimiter::direct(quota)
    }

    /// Scan common ports only (top 1000)
    pub async fn scan_common_ports(&self, target: &str) -> Result<PortScanSummary> {
        let common_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306,
            3389, 5900, 8080, 8443,
        ];

        let ip_addr = self.resolve_target(target).await?;
        let start_time = std::time::Instant::now();

        info!("Starting common ports scan on {} ({})", target, ip_addr);

        let mut open_ports = Vec::new();
        let mut filtered_ports = Vec::new();
        let mut closed_count = 0;

        let rate_limiter = self.create_rate_limiter();
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        for port in common_ports.iter() {
            rate_limiter.until_ready().await;

            match self.scan_single_port(ip_addr, *port, timeout_duration).await {
                Ok(result) => match result.state {
                    PortState::Open => {
                        open_ports.push(result);
                    }
                    PortState::Filtered | PortState::OpenFiltered => {
                        filtered_ports.push(*port);
                    }
                    _ => {
                        closed_count += 1;
                    }
                },
                Err(_) => {
                    closed_count += 1;
                }
            }
        }

        let uncommon_ports = self.identify_uncommon_ports(&open_ports);
        let common_services = self.extract_common_services(&open_ports);

        Ok(PortScanSummary {
            target: target.to_string(),
            scan_duration_seconds: start_time.elapsed().as_secs(),
            ports_scanned: common_ports.len() as u32,
            open_ports,
            filtered_ports,
            closed_ports_count: closed_count,
            uncommon_ports,
            common_services,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_scanner_creation() {
        let config = PortScanConfig::default();
        let scanner = ExternalPortScanner::new(config);
        assert_eq!(scanner.config.scan_technique, ScanTechnique::Connect);
    }

    #[test]
    fn test_service_identification() {
        let config = PortScanConfig::default();
        let scanner = ExternalPortScanner::new(config);

        assert_eq!(scanner.identify_service(22), "SSH");
        assert_eq!(scanner.identify_service(80), "HTTP");
        assert_eq!(scanner.identify_service(443), "HTTPS");
        assert_eq!(scanner.identify_service(99999), "Unknown");
    }
}
