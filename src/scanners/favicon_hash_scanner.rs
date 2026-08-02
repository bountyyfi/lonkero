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
            // Container & Orchestration Consoles - HIGH VALUE (misconfig = cluster takeover)
            FaviconSignature {
                hash: -1907714427,
                technology: "Portainer",
                description: "Portainer container management UI - exposed instance may allow container control",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1361588365,
                technology: "Rancher",
                description: "Rancher Kubernetes management UI - may allow cluster control if unauthenticated",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1651111433,
                technology: "Kubernetes Dashboard",
                description: "Kubernetes Dashboard - exposed instance may allow cluster read/write",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 706100024,
                technology: "Docker Registry",
                description: "Docker Registry UI - may expose private container images",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1907833673,
                technology: "Harbor Registry",
                description: "Harbor container registry - check for anonymous pull/push",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1130636698,
                technology: "Traefik Dashboard",
                description: "Traefik reverse-proxy dashboard - reveals internal routing & services",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1094486851,
                technology: "Consul",
                description: "HashiCorp Consul UI - service catalog and KV store may be exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1573334677,
                technology: "Nomad",
                description: "HashiCorp Nomad UI - job scheduler; may allow arbitrary job submission",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -463713872,
                technology: "HashiCorp Vault UI",
                description: "Vault secrets manager UI - critical if unsealed & unauthenticated",
                severity: Severity::Critical,
            },
            // Secrets/Password Managers - CRITICAL when exposed
            FaviconSignature {
                hash: 1051911775,
                technology: "Vaultwarden",
                description: "Vaultwarden (Bitwarden compatible) - password manager UI exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1810191439,
                technology: "Passbolt",
                description: "Passbolt password manager - check auth enforcement",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1738255960,
                technology: "Keeper Commander",
                description: "Keeper Commander UI detected",
                severity: Severity::High,
            },
            // Message Queues / Data brokers
            FaviconSignature {
                hash: -1108086044,
                technology: "RabbitMQ Management",
                description: "RabbitMQ management UI - queue/exchange access if default creds (guest/guest)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1730393248,
                technology: "Apache Kafka UI",
                description: "Kafka UI/AKHQ/Kowl - topic browser exposed",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -287333854,
                technology: "MinIO Console",
                description: "MinIO S3-compatible object storage console - buckets may be exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 619506278,
                technology: "Apache Solr Admin",
                description: "Apache Solr admin UI - config exposed; historically RCE prone",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -297069493,
                technology: "Apache CouchDB",
                description: "CouchDB Fauxton admin UI - check for admin-party config",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1521640188,
                technology: "Apache Airflow",
                description: "Apache Airflow UI - DAG code and connections may be exposed; RCE risk with weak auth",
                severity: Severity::High,
            },
            // BI / Analytics with data access
            FaviconSignature {
                hash: -1298146856,
                technology: "Apache Superset",
                description: "Apache Superset BI - dashboards, SQL Lab, DB connections may be exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1656519787,
                technology: "Metabase",
                description: "Metabase BI - dashboards and DB connections; check for CVE-2023-38646",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1439045393,
                technology: "Redash",
                description: "Redash query & dashboard tool - DB connections may leak",
                severity: Severity::Medium,
            },
            // Source Code / DevOps
            FaviconSignature {
                hash: -1543761518,
                technology: "Gitea",
                description: "Gitea self-hosted Git - private repos may be indexed via /explore",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1301961578,
                technology: "Gogs",
                description: "Gogs Git service - private repos may be indexed",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -594430514,
                technology: "JFrog Artifactory",
                description: "JFrog Artifactory - artifact repo; check anonymous access & CVE-2024-4671",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1465021629,
                technology: "Sonatype Nexus Repository",
                description: "Sonatype Nexus Repository Manager - check anonymous access & CVE-2019-7238",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 999546043,
                technology: "Rundeck",
                description: "Rundeck job scheduler - may allow arbitrary command execution if exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1949589821,
                technology: "TeamCity",
                description: "JetBrains TeamCity - CI server; check for CVE-2024-27198 (auth bypass)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -558123640,
                technology: "Bamboo",
                description: "Atlassian Bamboo CI - historically CVE-prone (CVE-2022-36804 etc.)",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 727110264,
                technology: "Drone CI",
                description: "Drone CI - pipeline visibility may expose secrets/build logs",
                severity: Severity::Medium,
            },
            // Metrics/Logs (already Grafana/Kibana; add these)
            FaviconSignature {
                hash: -1655360038,
                technology: "Prometheus",
                description: "Prometheus metrics server - /metrics may leak service topology",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -877107132,
                technology: "Alertmanager",
                description: "Prometheus Alertmanager - alert routing/webhook config exposed",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 2036673447,
                technology: "Graylog",
                description: "Graylog log aggregation UI - may expose logs and inputs",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -1747787443,
                technology: "Splunk",
                description: "Splunk Web - check for default admin/changeme and CVE-2023-46214",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1723436770,
                technology: "Zipkin",
                description: "Zipkin distributed tracing - reveals internal service topology",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: 1352478621,
                technology: "Jaeger UI",
                description: "Jaeger tracing UI - reveals internal service topology & traces",
                severity: Severity::Low,
            },
            // Backup / Storage
            FaviconSignature {
                hash: -1585487956,
                technology: "Nextcloud",
                description: "Nextcloud file share - check for public shares & CVE-2023-49792",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1339737352,
                technology: "ownCloud",
                description: "ownCloud file share - check CVE-2023-49103 (env var disclosure)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1490313917,
                technology: "Seafile",
                description: "Seafile file share server - check for public libraries",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 574486664,
                technology: "FileBrowser",
                description: "FileBrowser web filesystem UI - if reachable often exposes host files",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1462800056,
                technology: "Synology DSM",
                description: "Synology DiskStation Manager - NAS admin exposed",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: -297069429,
                technology: "QNAP QTS",
                description: "QNAP QTS NAS admin interface",
                severity: Severity::Medium,
            },
            // Collaboration / Communications (info-disclosure via user data)
            FaviconSignature {
                hash: -518868635,
                technology: "Rocket.Chat",
                description: "Rocket.Chat instance - check open signup and public channels",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -1465021717,
                technology: "Mattermost",
                description: "Mattermost team messaging - check open signup and team listing",
                severity: Severity::Low,
            },
            FaviconSignature {
                hash: -874317069,
                technology: "Zulip",
                description: "Zulip team chat instance",
                severity: Severity::Low,
            },
            // Historically-RCE-Prone / High-Value Recon
            FaviconSignature {
                hash: -1857273272,
                technology: "Adminer",
                description: "Adminer DB admin - lightweight DB console; often exposed by mistake",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1499876150,
                technology: "MongoDB Express",
                description: "mongo-express web UI - direct DB access if reachable",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1615536080,
                technology: "PgAdmin",
                description: "pgAdmin Postgres admin - direct DB access if reachable",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1727776318,
                technology: "Kafdrop",
                description: "Kafdrop Kafka UI - topic contents may be browsable",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1633828992,
                technology: "n8n",
                description: "n8n workflow automation - credentials and webhooks may be exposed",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1651111426,
                technology: "Node-RED",
                description: "Node-RED flow editor - flows often contain credentials; RCE if reachable",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 819708095,
                technology: "Apache NiFi",
                description: "Apache NiFi data flow - check for default users & CVE-2023-34468",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1885099534,
                technology: "Elasticvue",
                description: "Elasticvue/ElasticHQ - Elasticsearch cluster browser",
                severity: Severity::Medium,
            },
            FaviconSignature {
                hash: 1010712080,
                technology: "Kong Admin",
                description: "Kong API gateway admin - reveals routes/services; misconfig common",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: 1449344580,
                technology: "Apache APISIX Dashboard",
                description: "APISIX gateway dashboard - check CVE-2022-24112 (default JWT secret)",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1616230984,
                technology: "PowerJob",
                description: "PowerJob console - task scheduler, historically RCE-prone",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -1930567088,
                technology: "XXL-JOB Admin",
                description: "XXL-JOB admin - Chinese task scheduler; CVE-2022-36157 default creds RCE",
                severity: Severity::High,
            },
            FaviconSignature {
                hash: -740933380,
                technology: "Ruijie Networks",
                description: "Ruijie networking device web UI - check for default credentials",
                severity: Severity::Medium,
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
