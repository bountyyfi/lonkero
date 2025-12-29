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
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
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
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
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
                if !vulnerabilities.iter().any(|v| v.evidence.as_ref().map(|e| e.contains(&vuln.url.clone())).unwrap_or(false)) {
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
        let content_type = response.headers
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
            let k1 = u32::from_le_bytes([
                data[i4],
                data[i4 + 1],
                data[i4 + 2],
                data[i4 + 3],
            ]);

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
        let re = Regex::new(r#"<link[^>]*rel=["'](?:shortcut )?icon["'][^>]*href=["']([^"']+)["']"#).ok()?;

        if let Some(cap) = re.captures(html) {
            if let Some(href) = cap.get(1) {
                return Some(self.resolve_url(href.as_str(), base_url));
            }
        }

        // Try alternate format: href before rel
        let re2 = Regex::new(r#"<link[^>]*href=["']([^"']+)["'][^>]*rel=["'](?:shortcut )?icon["']"#).ok()?;

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
        ]
    }

    /// Match hash against known signatures
    fn match_known_signature(&self, hash: i32) -> Option<FaviconSignature> {
        Self::get_known_signatures()
            .into_iter()
            .find(|sig| sig.hash == hash)
    }

    /// Create vulnerability for known favicon
    fn create_vulnerability_known(&self, url: &str, hash: i32, sig: FaviconSignature) -> Vulnerability {
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
                4. Review security configuration for the detected technology".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
                reconnaissance to find related infrastructure.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
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
            crate::http_client::HttpClient::new(5000, 3).unwrap()
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
            crate::http_client::HttpClient::new(5000, 3).unwrap()
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
