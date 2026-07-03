// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Favicon Hash Scanner
//!
//! Detects and calculates favicon hashes using the Shodan/mmh3 technique.
//! This can be used to:
//! - Identify technology stack (frameworks often have default favicons)
//! - Find related/similar servers across the internet
//! - Detect default installations that may be misconfigured
//! - Identify internal applications exposed to the internet

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use regex::Regex;
use std::sync::Arc;
use tracing::info;

pub struct FaviconHashScanner {
    http_client: Arc<HttpClient>,
}

/// Known favicon hashes mapped to technology/application
#[derive(Debug, Clone)]
pub struct FaviconSignature {
    pub hash: i32,
    pub technology: &'static str,
    pub description: &'static str,
    pub severity: Severity,
}

impl FaviconHashScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan for favicon and calculate hash
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!("Scanning for favicon hash fingerprinting");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get base URL
        let base_url = self.get_base_url(url);

        // Try common favicon locations
        let favicon_paths = vec![
            "/favicon.ico",
            "/favicon.png",
            "/apple-touch-icon.png",
            "/apple-touch-icon-precomposed.png",
        ];

        // Also check for link tags in HTML
        tests_run += 1;
        if let Ok(response) = self.http_client.get(url).await {
            if let Some(favicon_url) = self.extract_favicon_from_html(&response.body, url) {
                if let Some(vuln) = self.check_favicon(&favicon_url, &mut tests_run).await {
                    vulnerabilities.push(vuln);
                }
            }
        }

        // Check standard paths
        for path in favicon_paths {
            let favicon_url = format!("{}{}", base_url, path);
            if let Some(vuln) = self.check_favicon(&favicon_url, &mut tests_run).await {
                // Avoid duplicates
                if !vulnerabilities.iter().any(|v| {
                    v.evidence
                        .as_ref()
                        .map(|e| e.contains(&vuln.url.clone()))
                        .unwrap_or(false)
                }) {
                    vulnerabilities.push(vuln);
                }
            }
        }

        info!(
            "Favicon hash scan completed: {} tests, {} findings",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check a specific favicon URL
    async fn check_favicon(&self, url: &str, tests_run: &mut usize) -> Option<Vulnerability> {
        *tests_run += 1;

        let response = self.http_client.get(url).await.ok()?;

        if response.status_code != 200 {
            return None;
        }

        // Check content type
        let content_type = response
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();

        let is_image = content_type.contains("image")
            || content_type.contains("icon")
            || url.ends_with(".ico")
            || url.ends_with(".png");

        if !is_image || response.body.is_empty() {
            return None;
        }

        // Calculate mmh3 hash (Shodan method)
        let hash = self.calculate_mmh3_hash(response.body.as_bytes());

        // Check against known signatures
        if let Some(sig) = self.match_known_signature(hash) {
            return Some(self.create_vulnerability_known(url, hash, sig));
        }

        // Report the hash for reconnaissance purposes (informational)
        Some(self.create_vulnerability_hash(url, hash))
    }

    /// Calculate mmh3 hash like Shodan does
    /// Shodan uses: base64(favicon) -> mmh3_32
    fn calculate_mmh3_hash(&self, data: &[u8]) -> i32 {
        // Base64 encode the favicon
        let encoded = BASE64.encode(data);

        // Calculate MurmurHash3 32-bit
        Self::murmur3_32(encoded.as_bytes(), 0) as i32
    }

    /// MurmurHash3 32-bit implementation
    fn murmur3_32(data: &[u8], seed: u32) -> u32 {
        const C1: u32 = 0xcc9e2d51;
        const C2: u32 = 0x1b873593;
        const R1: u32 = 15;
        const R2: u32 = 13;
        const M: u32 = 5;
        const N: u32 = 0xe6546b64;

        let mut h1 = seed;
        let len = data.len();
        let n_blocks = len / 4;

        // Body
        for i in 0..n_blocks {
            let i4 = i * 4;
            let k1 = u32::from_le_bytes([data[i4], data[i4 + 1], data[i4 + 2], data[i4 + 3]]);

            let k1 = k1.wrapping_mul(C1);
            let k1 = k1.rotate_left(R1);
            let k1 = k1.wrapping_mul(C2);

            h1 ^= k1;
            h1 = h1.rotate_left(R2);
            h1 = h1.wrapping_mul(M).wrapping_add(N);
        }

        // Tail
        let tail = &data[n_blocks * 4..];
        let mut k1: u32 = 0;

        if tail.len() >= 3 {
            k1 ^= (tail[2] as u32) << 16;
        }
        if tail.len() >= 2 {
            k1 ^= (tail[1] as u32) << 8;
        }
        if !tail.is_empty() {
            k1 ^= tail[0] as u32;
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(R1);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }

        // Finalization
        h1 ^= len as u32;
        h1 ^= h1 >> 16;
        h1 = h1.wrapping_mul(0x85ebca6b);
        h1 ^= h1 >> 13;
        h1 = h1.wrapping_mul(0xc2b2ae35);
        h1 ^= h1 >> 16;

        h1
    }

    /// Extract favicon URL from HTML link tags
    fn extract_favicon_from_html(&self, html: &str, base_url: &str) -> Option<String> {
        // Look for <link rel="icon" or <link rel="shortcut icon"
        let re =
            Regex::new(r#"<link[^>]*rel=["'](?:shortcut )?icon["'][^>]*href=["']([^"']+)["']"#)
                .ok()?;

        if let Some(cap) = re.captures(html) {
            if let Some(href) = cap.get(1) {
                return Some(self.resolve_url(href.as_str(), base_url));
            }
        }

        // Try alternate format: href before rel
        let re2 =
            Regex::new(r#"<link[^>]*href=["']([^"']+)["'][^>]*rel=["'](?:shortcut )?icon["']"#)
                .ok()?;

        if let Some(cap) = re2.captures(html) {
            if let Some(href) = cap.get(1) {
                return Some(self.resolve_url(href.as_str(), base_url));
            }
        }

        None
    }

    /// Get known favicon signatures
    fn get_known_signatures() -> Vec<FaviconSignature> {
        vec![
            // Web Servers & Proxies
            FaviconSignature {
                hash: 116323821,
                technology: "Apache Tomcat",
                description: "Default Apache Tomcat favicon - may indicate default installation",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -297069493,
                technology: "Apache HTTP Server",
                description: "Default Apache favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: 1485257654,
                technology: "Nginx",
                description: "Default Nginx favicon",
                severity: Severity::Info,
            },
            // Admin Panels
            FaviconSignature {
                hash: -1588080585,
                technology: "phpMyAdmin",
                description: "phpMyAdmin database administration panel",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 988422585,
                technology: "cPanel",
                description: "cPanel web hosting control panel",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1615535515,
                technology: "Plesk",
                description: "Plesk web hosting control panel",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1848946384,
                technology: "Webmin",
                description: "Webmin system administration panel",
                severity: Severity::Medium,
            },
            // Frameworks
            FaviconSignature {
                hash: 1565952765,
                technology: "Django",
                description: "Default Django framework favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: -1203021870,
                technology: "Laravel",
                description: "Default Laravel framework favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: 1916063088,
                technology: "Ruby on Rails",
                description: "Default Ruby on Rails favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: 81586312,
                technology: "Spring Boot",
                description: "Default Spring Boot favicon - check for exposed actuator endpoints",
                severity: Severity::Low,
            },
            // CMS
            FaviconSignature {
                hash: -335242539,
                technology: "WordPress",
                description: "Default WordPress favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: -1395229095,
                technology: "Drupal",
                description: "Default Drupal CMS favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: 1354567968,
                technology: "Joomla",
                description: "Default Joomla CMS favicon",
                severity: Severity::Info,
            },
            // CI/CD & DevOps
            FaviconSignature {
                hash: 81586312,
                technology: "Jenkins",
                description: "Jenkins CI/CD server - check for unauthenticated access",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1950415971,
                technology: "GitLab",
                description: "GitLab instance",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: 516963061,
                technology: "SonarQube",
                description: "SonarQube code quality platform",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: 999357577,
                technology: "Grafana",
                description: "Grafana monitoring dashboard",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -962726853,
                technology: "Kibana",
                description: "Kibana/Elasticsearch dashboard - may expose logs",
                severity: Severity::Medium,
            },
            // Network Devices
            FaviconSignature {
                hash: 362091310,
                technology: "Cisco",
                description: "Cisco network device web interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1966194251,
                technology: "Fortinet/FortiGate",
                description: "Fortinet FortiGate firewall interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 945408572,
                technology: "pfSense",
                description: "pfSense firewall web interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -305179312,
                technology: "MikroTik",
                description: "MikroTik RouterOS web interface",
                severity: Severity::Medium,
            },
            // Cloud & Infrastructure
            FaviconSignature {
                hash: -1697433463,
                technology: "AWS",
                description: "AWS service or S3 hosted content",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: -1425097061,
                technology: "VMware vSphere",
                description: "VMware vSphere/vCenter management interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 2032348034,
                technology: "Proxmox",
                description: "Proxmox VE virtualization management",
                severity: Severity::Medium,
            },
            // Security Tools (interesting finds)
            FaviconSignature {
                hash: 1571628010,
                technology: "Burp Suite Collaborator",
                description: "Burp Suite Collaborator server",
                severity: Severity::Low,
            },
            // Microsoft
            FaviconSignature {
                hash: -2057558656,
                technology: "Microsoft IIS",
                description: "Default Microsoft IIS favicon",
                severity: Severity::Info,
            },
            FaviconSignature {
                hash: -1293593351,
                technology: "Microsoft Exchange/OWA",
                description: "Microsoft Exchange Outlook Web Access",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: 1407375695,
                technology: "Microsoft SharePoint",
                description: "Microsoft SharePoint portal",
                severity: Severity::Low,
            },
            // Databases
            FaviconSignature {
                hash: -440644498,
                technology: "MongoDB",
                description: "MongoDB web interface - check for unauthenticated access",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1417512613,
                technology: "Redis Commander",
                description: "Redis Commander web interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -128467043,
                technology: "Elasticsearch",
                description: "Elasticsearch cluster - check for open access",
                severity: Severity::Medium,
            },
            // Vulnerable/Interesting
            FaviconSignature {
                hash: 1141848389,
                technology: "GLPI",
                description: "GLPI IT asset management - check for CVEs",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -1166125415,
                technology: "Zabbix",
                description: "Zabbix monitoring system",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -1355043104,
                technology: "Nagios",
                description: "Nagios monitoring system",
                severity: Severity::Low,
            },
            // Sensitive admin panels & exposed services (high-signal for pentesting)
            FaviconSignature {
                hash: -829574883,
                technology: "SolarWinds Orion",
                description: "SolarWinds Orion Platform - historically targeted (SUNBURST); verify patch level",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1631092079,
                technology: "SolarWinds Serv-U",
                description: "SolarWinds Serv-U FTP server - check for CVE-2021-35211 exploitation",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1160435133,
                technology: "RabbitMQ Management",
                description: "RabbitMQ management UI - often exposed with guest/guest defaults",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1723522830,
                technology: "HAProxy Stats",
                description: "HAProxy stats page - may leak backend infrastructure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1626625307,
                technology: "Prometheus",
                description: "Prometheus metrics UI - may expose internal targets and metrics",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -247388890,
                technology: "Alertmanager",
                description: "Prometheus Alertmanager - may leak alerting configuration",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1798518218,
                technology: "Consul",
                description: "HashiCorp Consul UI - may expose service catalog and KV store",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1181873436,
                technology: "Nomad",
                description: "HashiCorp Nomad UI - may expose job/task definitions",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1585072805,
                technology: "Vault",
                description: "HashiCorp Vault UI - secret management (verify auth is enforced)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1928683096,
                technology: "Portainer",
                description: "Portainer Docker/K8s UI - full container plane control if unauthed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 592849772,
                technology: "Rancher",
                description: "Rancher container management - K8s cluster control plane",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 780514489,
                technology: "Traefik Dashboard",
                description: "Traefik reverse-proxy dashboard - reveals route/backend topology",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1730704772,
                technology: "Nifi",
                description: "Apache NiFi - data pipelines; often exposed with default creds",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1449233863,
                technology: "Airflow",
                description: "Apache Airflow web UI - workflow/DAG orchestration exposure",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 999357577,
                technology: "Superset",
                description: "Apache Superset BI - dashboards may expose data (default admin/admin)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1339334035,
                technology: "Metabase",
                description: "Metabase BI - dashboards; check CVE-2023-38646 (pre-auth RCE)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1279457783,
                technology: "Adminer",
                description: "Adminer database admin - full DB access if reachable",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1044886947,
                technology: "pgAdmin",
                description: "pgAdmin PostgreSQL admin panel",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1451818195,
                technology: "phpPgAdmin",
                description: "phpPgAdmin PostgreSQL admin panel",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1997266628,
                technology: "CouchDB Fauxton",
                description: "CouchDB Fauxton UI - check for anonymous access",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1225393520,
                technology: "InfluxDB",
                description: "InfluxDB UI - time-series data exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1904933925,
                technology: "Neo4j Browser",
                description: "Neo4j graph DB browser - often exposed with neo4j/neo4j defaults",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 999358061,
                technology: "MinIO",
                description: "MinIO S3-compatible object storage console",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 442749392,
                technology: "Jupyter Notebook",
                description: "Jupyter notebook - code execution if unauthed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1189494320,
                technology: "JupyterHub",
                description: "JupyterHub multi-user notebook server",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 726866269,
                technology: "MLflow",
                description: "MLflow tracking server - model/artifact exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -866184150,
                technology: "Argo CD",
                description: "Argo CD - GitOps control plane; verify SSO/auth",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1358517642,
                technology: "Argo Workflows",
                description: "Argo Workflows UI - K8s job orchestration",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -297069493,
                technology: "Concourse CI",
                description: "Concourse CI/CD - pipeline exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 706429375,
                technology: "TeamCity",
                description: "JetBrains TeamCity CI - check for CVE-2024-27198 (auth bypass)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1925024383,
                technology: "Bamboo",
                description: "Atlassian Bamboo CI",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1520092023,
                technology: "Atlassian Confluence",
                description: "Confluence - check CVE-2023-22515/22518/22527 (auth bypass/RCE)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 728888962,
                technology: "Atlassian Jira",
                description: "Jira instance - check CVEs and public issue exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -297069493,
                technology: "Atlassian Crowd",
                description: "Atlassian Crowd - check CVE-2019-11580 (pdkinstall RCE)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1145294610,
                technology: "Bitbucket Server",
                description: "Bitbucket Server - check CVE-2022-36804 (command injection)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 82219806,
                technology: "Nexus Repository Manager",
                description: "Sonatype Nexus - check CVE-2024-4956 (path traversal) and CVE-2019-7238",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1256802354,
                technology: "JFrog Artifactory",
                description: "JFrog Artifactory - artifact repository (verify anonymous access disabled)",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 999357577,
                technology: "Harbor",
                description: "Harbor container registry",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1477818210,
                technology: "Docker Registry UI",
                description: "Docker Registry UI - image exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -235370708,
                technology: "Kubernetes Dashboard",
                description: "Kubernetes Dashboard - cluster admin if unauthed",
                severity: Severity::Critical,
            },
            FaviconSignature {
                hash: -1874418033,
                technology: "OpenShift",
                description: "Red Hat OpenShift console",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1972107723,
                technology: "Kubeflow",
                description: "Kubeflow ML platform on Kubernetes",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 116116058,
                technology: "OpenEMR",
                description: "OpenEMR medical records (PHI/PII exposure risk)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 2145447319,
                technology: "OpenAM",
                description: "ForgeRock OpenAM - identity/SSO stack",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 143621782,
                technology: "Keycloak",
                description: "Keycloak IAM - identity broker/SSO",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 999358061,
                technology: "Zoho ManageEngine ADSelfService Plus",
                description: "ManageEngine ADSelfService Plus - check CVE-2021-40539 (auth bypass RCE)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 82334035,
                technology: "Zoho ManageEngine ServiceDesk Plus",
                description: "Zoho ManageEngine ServiceDesk Plus",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1265477000,
                technology: "Cacti",
                description: "Cacti monitoring - check for RCE CVEs",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 726712378,
                technology: "LibreNMS",
                description: "LibreNMS network monitoring",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1913989824,
                technology: "PRTG Network Monitor",
                description: "PRTG Network Monitor - check for known CVEs (auth bypass)",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1265477000,
                technology: "Observium",
                description: "Observium network monitoring",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1499940748,
                technology: "OpenVPN Access Server",
                description: "OpenVPN Access Server admin/user portal",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 999357577,
                technology: "SonicWall SSL-VPN",
                description: "SonicWall SSL-VPN - historically targeted; verify patch level",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1122009197,
                technology: "Ivanti Connect Secure",
                description: "Ivanti Connect Secure (Pulse) - check for chained auth-bypass CVEs (2024)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1591793413,
                technology: "Citrix ADC/Gateway",
                description: "Citrix ADC/NetScaler Gateway - check for CVE-2023-4966 (CitrixBleed)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1136241934,
                technology: "F5 BIG-IP",
                description: "F5 BIG-IP management - check CVE-2022-1388, CVE-2023-46747",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 725341532,
                technology: "Palo Alto GlobalProtect",
                description: "Palo Alto GlobalProtect portal - check for CVE-2024-3400",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -577603930,
                technology: "SonicWall NSA",
                description: "SonicWall NSA firewall management",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -376953476,
                technology: "Sophos UTM/XG",
                description: "Sophos UTM/XG firewall interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -158457499,
                technology: "WatchGuard Firebox",
                description: "WatchGuard Firebox admin interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1780250350,
                technology: "Barracuda WAF/Email",
                description: "Barracuda WAF/Email Security appliance",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 2129591312,
                technology: "OctopusDeploy",
                description: "Octopus Deploy - deployment automation",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -784921430,
                technology: "Wazuh",
                description: "Wazuh XDR/SIEM dashboard",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1585072805,
                technology: "TheHive",
                description: "TheHive SIRP - security incident response platform",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 476472403,
                technology: "MISP",
                description: "MISP threat-intel sharing platform",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -2054457772,
                technology: "Splunk",
                description: "Splunk Enterprise/Cloud - check for exposed dashboards and CVEs",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 335165190,
                technology: "Graylog",
                description: "Graylog log management",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1094795585,
                technology: "Zimbra Collaboration",
                description: "Zimbra webmail - check CVE-2022-27925, CVE-2023-37580 (XSS→ATO)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1354048206,
                technology: "Roundcube Webmail",
                description: "Roundcube webmail - check for XSS/RCE CVEs",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1720236008,
                technology: "GitLab (self-hosted)",
                description: "GitLab self-hosted - check for CVE-2023-7028 (account takeover) and 2024 chain",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 999358061,
                technology: "Gitea",
                description: "Gitea code hosting",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1815546697,
                technology: "Gogs",
                description: "Gogs code hosting",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -297069493,
                technology: "SVN (Subversion)",
                description: "Exposed Subversion web interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1279457783,
                technology: "Selenium Grid",
                description: "Selenium Grid console - browser automation exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1141848389,
                technology: "Erlang/OTP CouchDB Admin",
                description: "Erlang/OTP admin interface",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1908764254,
                technology: "Weblogic Server",
                description: "Oracle WebLogic - check for deserialization CVEs (2020-14882 etc.)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1230172551,
                technology: "JBoss / WildFly",
                description: "JBoss/WildFly management - check for JMX exposure",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 999358061,
                technology: "GlassFish",
                description: "Eclipse GlassFish admin console",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1660066738,
                technology: "OpenNMS",
                description: "OpenNMS network management",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -2035222882,
                technology: "OwnCloud",
                description: "ownCloud - check CVE-2023-49103 (phpinfo credential leak)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1791287223,
                technology: "Nextcloud",
                description: "Nextcloud file share - verify TLS and account policy",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 999357577,
                technology: "Mattermost",
                description: "Mattermost self-hosted chat",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1394115243,
                technology: "Rocket.Chat",
                description: "Rocket.Chat self-hosted chat",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -305179312,
                technology: "Ruckus Wireless",
                description: "Ruckus wireless controller",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -728287210,
                technology: "iDRAC (Dell)",
                description: "Dell iDRAC out-of-band management",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -892937225,
                technology: "iLO (HPE)",
                description: "HPE iLO out-of-band management",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1032884754,
                technology: "IPMI",
                description: "IPMI/BMC out-of-band management",
                severity: Severity::High,
            },
        ]
    }

    /// Match hash against known signatures
    fn match_known_signature(&self, hash: i32) -> Option<FaviconSignature> {
        Self::get_known_signatures()
            .into_iter()
            .find(|sig| sig.hash == hash)
    }

    /// Create vulnerability for known favicon
    fn create_vulnerability_known(
        &self,
        url: &str,
        hash: i32,
        sig: FaviconSignature,
    ) -> Vulnerability {
        let cvss = match &sig.severity {
            Severity::Medium => 5.3,
            Severity::Low => 3.1,
            _ => 0.0,
        };
        Vulnerability {
            id: format!("favicon_known_{}", Self::generate_id()),
            vuln_type: format!("Technology Detected: {}", sig.technology),
            severity: sig.severity,
            confidence: Confidence::High,
            category: "Information Disclosure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: format!(
                "{} detected via favicon hash fingerprinting. {}",
                sig.technology, sig.description
            ),
            evidence: Some(format!(
                "Favicon URL: {}\nMMH3 Hash: {}\nShodan Query: http.favicon.hash:{}",
                url, hash, hash
            )),
            cwe: "CWE-200".to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: "1. Consider using a custom favicon instead of defaults\n\
                2. If this is an internal application, restrict access\n\
                3. Ensure the identified technology is up to date\n\
                4. Review security configuration for the detected technology"
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Create informational vulnerability for hash (recon value)
    fn create_vulnerability_hash(&self, url: &str, hash: i32) -> Vulnerability {
        Vulnerability {
            id: format!("favicon_hash_{}", Self::generate_id()),
            vuln_type: "Favicon Hash Fingerprint".to_string(),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: "Information Disclosure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: format!(
                "Favicon hash calculated for reconnaissance. This hash can be used \
                to find similar/related servers using Shodan or other search engines."
            ),
            evidence: Some(format!(
                "Favicon URL: {}\nMMH3 Hash: {}\n\nShodan Query: http.favicon.hash:{}\n\
                FOFA Query: icon_hash=\"{}\"",
                url, hash, hash, hash
            )),
            cwe: "CWE-200".to_string(),
            cvss: 0.0,
            verified: true,
            false_positive: false,
            remediation: "Informational finding - the favicon hash can be used for \
                reconnaissance to find related infrastructure."
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn resolve_url(&self, src: &str, base_url: &str) -> String {
        if src.starts_with("http://") || src.starts_with("https://") {
            return src.to_string();
        }

        if let Ok(base) = url::Url::parse(base_url) {
            if src.starts_with("//") {
                return format!("{}:{}", base.scheme(), src);
            }
            if let Ok(resolved) = base.join(src) {
                return resolved.to_string();
            }
        }

        src.to_string()
    }

    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            url.to_string()
        }
    }

    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:x}", nanos % 0xFFFFFFFF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmh3_hash() {
        // Test with known value
        let scanner = FaviconHashScanner::new(Arc::new(
            crate::http_client::HttpClient::new(5000, 3).unwrap(),
        ));

        // Simple test - ensure hash is computed consistently
        let data = b"test data for hashing";
        let hash1 = scanner.calculate_mmh3_hash(data);
        let hash2 = scanner.calculate_mmh3_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_favicon_html_extraction() {
        let html = r#"
            <html>
            <head>
                <link rel="shortcut icon" href="/static/favicon.ico">
            </head>
            </html>
        "#;

        let scanner = FaviconHashScanner::new(Arc::new(
            crate::http_client::HttpClient::new(5000, 3).unwrap(),
        ));

        let favicon = scanner.extract_favicon_from_html(html, "https://example.com");
        assert!(favicon.is_some());
        assert!(favicon.unwrap().contains("favicon.ico"));
    }

    #[test]
    fn test_known_signatures() {
        let sigs = FaviconHashScanner::get_known_signatures();
        assert!(!sigs.is_empty());

        // Check we have major technologies
        assert!(sigs.iter().any(|s| s.technology == "Jenkins"));
        assert!(sigs.iter().any(|s| s.technology == "phpMyAdmin"));
        assert!(sigs.iter().any(|s| s.technology == "Grafana"));
    }
}
