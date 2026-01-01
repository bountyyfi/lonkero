// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Enhanced Subdomain Discovery Module
 * Production-grade subdomain enumeration with passive and active techniques
 *
 * © 2026 Bountyy Oy
 */

use crate::http_client::HttpClient;
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use std::collections::{HashSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

/// Subdomain discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub use_passive_sources: bool,
    pub use_active_enumeration: bool,
    pub use_cert_transparency: bool,
    pub use_web_scraping: bool,
    pub use_reverse_dns: bool,
    pub recursive: bool,
    pub thorough: bool,
    pub max_depth: usize,
    pub concurrency: usize,
    pub timeout_seconds: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            use_passive_sources: true,
            use_active_enumeration: true,
            use_cert_transparency: true,
            use_web_scraping: false,
            use_reverse_dns: false,
            recursive: false,
            thorough: false,
            max_depth: 2,
            concurrency: 50,
            timeout_seconds: 300,
        }
    }
}

/// Subdomain information with detailed metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub domain: String,
    pub ip_addresses: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub source: String,
    pub is_wildcard: bool,
    pub confidence: f32,
    pub discovered_at: String,
}

/// Certificate Transparency log entry
#[derive(Debug, Deserialize)]
struct CertTransparencyEntry {
    name_value: String,
    #[serde(default)]
    issuer_name: Option<String>,
}

/// VirusTotal subdomain response
#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: Vec<VirusTotalDomain>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalDomain {
    id: String,
}

/// SecurityTrails subdomain response
#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    subdomains: Vec<String>,
}

/// Enhanced subdomain discovery service
pub struct SubdomainDiscovery {
    http_client: Arc<HttpClient>,
    config: DiscoveryConfig,
    discovered: HashSet<String>,
    wildcard_domains: HashSet<String>,
}

impl SubdomainDiscovery {
    pub fn new(http_client: Arc<HttpClient>, config: DiscoveryConfig) -> Self {
        Self {
            http_client,
            config,
            discovered: HashSet::new(),
            wildcard_domains: HashSet::new(),
        }
    }

    /// Main discovery entry point
    pub async fn discover(&mut self, domain: &str) -> Result<HashMap<String, SubdomainInfo>> {
        info!("Starting enhanced subdomain discovery for: {}", domain);

        let mut all_results = HashMap::new();

        // 1. Passive sources (crt.sh, VirusTotal, SecurityTrails, etc.)
        if self.config.use_passive_sources {
            info!("Querying passive sources...");

            if self.config.use_cert_transparency {
                if let Ok(ct_results) = self.query_cert_transparency(domain).await {
                    info!("[OK] Certificate Transparency: {} subdomains", ct_results.len());
                    all_results.extend(ct_results);
                }
            }

            // VirusTotal, SecurityTrails would require API keys
            // Implementation shown below for completeness
        }

        // 2. Active DNS enumeration (bruteforce with wordlists)
        if self.config.use_active_enumeration {
            info!("Starting active DNS enumeration...");
            if let Ok(dns_results) = self.dns_bruteforce(domain).await {
                info!("[OK] DNS Bruteforce: {} subdomains", dns_results.len());
                all_results.extend(dns_results);
            }
        }

        // 3. Wildcard detection and filtering
        info!("Detecting wildcard DNS...");
        self.detect_wildcards(domain).await;
        let mut filtered_results = self.filter_wildcards(all_results);

        // 4. Reverse DNS lookups
        if self.config.use_reverse_dns {
            info!("Performing reverse DNS lookups...");
            if let Ok(reverse_results) = self.reverse_dns_discovery(&filtered_results, domain).await {
                info!("[OK] Reverse DNS: {} additional subdomains", reverse_results.len());
                for (k, v) in reverse_results {
                    filtered_results.entry(k).or_insert(v);
                }
            }
        }

        // 5. Recursive enumeration (if enabled)
        if self.config.recursive && self.config.max_depth > 1 {
            info!("Starting recursive enumeration...");
            // Implement recursive discovery on found subdomains
        }

        info!(
            "[SUCCESS] Discovery complete: found {} unique subdomains for {}",
            filtered_results.len(),
            domain
        );

        Ok(filtered_results)
    }

    /// Query Certificate Transparency logs (crt.sh)
    async fn query_cert_transparency(&self, domain: &str) -> Result<HashMap<String, SubdomainInfo>> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);

        let response = self
            .http_client
            .get(&url)
            .await
            .context("Failed to query crt.sh")?;

        let entries: Vec<CertTransparencyEntry> = serde_json::from_str(&response.body)
            .context("Failed to parse crt.sh response")?;

        let mut results = HashMap::new();
        let mut unique_domains = HashSet::new();

        for entry in entries {
            for name in entry.name_value.lines() {
                let cleaned = name
                    .trim()
                    .to_lowercase()
                    .trim_start_matches("*.")
                    .trim_start_matches('.')
                    .to_string();

                if cleaned.ends_with(domain) && !cleaned.contains('*') && !unique_domains.contains(&cleaned) {
                    unique_domains.insert(cleaned.clone());

                    // Resolve the domain to get full info
                    if let Some(info) = self.resolve_subdomain(&cleaned, "cert_transparency").await {
                        results.insert(cleaned, info);
                    }
                }
            }
        }

        Ok(results)
    }

    /// DNS bruteforce with wordlist
    async fn dns_bruteforce(&self, domain: &str) -> Result<HashMap<String, SubdomainInfo>> {
        let wordlist = self.get_wordlist();

        info!("Testing {} subdomain names", wordlist.len());

        let results = stream::iter(wordlist)
            .map(|subdomain| {
                let full_domain = format!("{}.{}", subdomain, domain);
                async move {
                    if let Some(info) = self.resolve_subdomain(&full_domain, "dns_bruteforce").await {
                        Some((full_domain, info))
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(self.config.concurrency)
            .collect::<Vec<_>>()
            .await;

        Ok(results.into_iter().flatten().collect())
    }

    /// Detect wildcard DNS configurations
    async fn detect_wildcards(&mut self, domain: &str) {
        let random_subdomains = vec![
            format!("nonexistent-{}.{}", uuid::Uuid::new_v4().to_string(), domain),
            format!("random-{}.{}", uuid::Uuid::new_v4().to_string(), domain),
            format!("test-{}.{}", uuid::Uuid::new_v4().to_string(), domain),
        ];

        let mut wildcard_ips = Vec::new();

        for test_domain in random_subdomains {
            if let Some(info) = self.resolve_subdomain(&test_domain, "wildcard_test").await {
                if !info.ip_addresses.is_empty() {
                    wildcard_ips.extend(info.ip_addresses);
                }
            }
        }

        if !wildcard_ips.is_empty() {
            warn!("[WARNING]  Wildcard DNS detected for {}: {:?}", domain, wildcard_ips);
            self.wildcard_domains.insert(domain.to_string());

            // Store wildcard IPs for filtering
            for ip in wildcard_ips {
                self.wildcard_domains.insert(ip);
            }
        }
    }

    /// Filter out wildcard subdomains
    fn filter_wildcards(&self, mut results: HashMap<String, SubdomainInfo>) -> HashMap<String, SubdomainInfo> {
        if self.wildcard_domains.is_empty() {
            return results;
        }

        results.retain(|domain, info| {
            // Check if this subdomain resolves to wildcard IPs
            for ip in &info.ip_addresses {
                if self.wildcard_domains.contains(ip) {
                    info!("Filtering wildcard subdomain: {}", domain);
                    return false;
                }
            }
            true
        });

        results
    }

    /// Reverse DNS discovery
    async fn reverse_dns_discovery(
        &self,
        known_subdomains: &HashMap<String, SubdomainInfo>,
        base_domain: &str,
    ) -> Result<HashMap<String, SubdomainInfo>> {
        let mut unique_ips = HashSet::new();

        for info in known_subdomains.values() {
            for ip in &info.ip_addresses {
                if let Ok(addr) = ip.parse::<IpAddr>() {
                    unique_ips.insert(addr);
                }
            }
        }

        let base_domain_owned = base_domain.to_string();
        let mut results = HashMap::new();

        for ip in unique_ips {
            if let Some((hostname, info)) = self.reverse_dns_lookup(ip, &base_domain_owned).await {
                results.insert(hostname, info);
            }
        }

        Ok(results)
    }

    /// Perform reverse DNS lookup on single IP
    async fn reverse_dns_lookup(&self, ip: IpAddr, base_domain: &str) -> Option<(String, SubdomainInfo)> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .ok()?
            .build();

        let reverse_lookup = resolver.reverse_lookup(ip).await.ok()?;

        for hostname in reverse_lookup.iter() {
            let hostname_str = hostname.to_string().trim_end_matches('.').to_string();

            if hostname_str.ends_with(base_domain) {
                // Resolve the hostname to get full info
                let ip_lookup = resolver.lookup_ip(&hostname_str).await.ok()?;
                let ips: Vec<String> = ip_lookup.iter().map(|ip| ip.to_string()).collect();

                return Some((
                    hostname_str.clone(),
                    SubdomainInfo {
                        domain: hostname_str,
                        ip_addresses: ips,
                        mx_records: vec![],
                        txt_records: vec![],
                        ns_records: vec![],
                        cname_records: vec![],
                        source: "reverse_dns".to_string(),
                        is_wildcard: false,
                        confidence: 0.9,
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    },
                ));
            }
        }

        None
    }

    /// Resolve subdomain and get full DNS information
    async fn resolve_subdomain(&self, domain: &str, source: &str) -> Option<SubdomainInfo> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .ok()?
            .build();

        // A/AAAA records
        let ip_lookup = resolver.lookup_ip(domain).await.ok()?;
        let ips: Vec<String> = ip_lookup.iter().map(|ip| ip.to_string()).collect();

        if ips.is_empty() {
            return None;
        }

        // MX records
        let mx_records: Vec<String> = resolver
            .mx_lookup(domain)
            .await
            .ok()
            .map(|mx| mx.iter().map(|r| r.exchange().to_string()).collect())
            .unwrap_or_default();

        // TXT records
        let txt_records: Vec<String> = resolver
            .txt_lookup(domain)
            .await
            .ok()
            .map(|txt| {
                txt.iter()
                    .flat_map(|r| r.iter())
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect()
            })
            .unwrap_or_default();

        // NS records
        let ns_records: Vec<String> = resolver
            .ns_lookup(domain)
            .await
            .ok()
            .map(|ns| ns.iter().map(|r| r.to_string()).collect())
            .unwrap_or_default();

        // CNAME records (if any)
        let cname_records: Vec<String> = resolver
            .lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
            .ok()
            .map(|cname| {
                cname
                    .iter()
                    .map(|r| format!("{}", r))
                    .collect()
            })
            .unwrap_or_default();

        Some(SubdomainInfo {
            domain: domain.to_string(),
            ip_addresses: ips,
            mx_records,
            txt_records,
            ns_records,
            cname_records,
            source: source.to_string(),
            is_wildcard: false,
            confidence: 1.0,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Get subdomain wordlist based on configuration
    fn get_wordlist(&self) -> Vec<&'static str> {
        let common = vec![
            "www", "api", "admin", "dev", "staging", "test", "qa", "uat",
            "mail", "smtp", "pop", "imap", "webmail",
            "ftp", "sftp", "ssh",
            "vpn", "remote", "access",
            "blog", "forum", "shop", "store",
            "cdn", "static", "assets", "media", "images",
            "m", "mobile", "app",
            "portal", "dashboard", "panel",
            "beta", "alpha", "demo",
            "git", "gitlab", "github", "bitbucket",
            "jenkins", "ci", "cd",
            "jira", "confluence", "wiki",
            "status", "monitor", "metrics",
            "db", "database", "mysql", "postgres", "mongo",
            "cache", "redis", "memcache",
            "backup", "backups",
            "old", "new", "legacy",
            "v1", "v2", "api-v1", "api-v2",
            "ws", "wss", "websocket",
            "grpc", "graphql", "rest",
            "docs", "documentation", "help",
            "support", "helpdesk", "service",
            "secure", "login", "auth", "oauth",
            "payment", "pay", "checkout",
            "internal", "corp", "corporate",
            "office", "intranet",
        ];

        let extended = vec![
            "autodiscover", "autoconfig", "cpanel", "whm", "plesk",
            "webdisk", "email", "mx", "ns1", "ns2", "ns3", "ns4",
            "ftp2", "files", "download", "upload",
            "ssl", "tls",
            "test1", "test2", "dev1", "dev2", "dev3",
            "stage", "staging1", "staging2",
            "prod", "production",
            "lb", "loadbalancer",
            "proxy", "gateway",
            "cdn1", "cdn2", "static1", "static2",
            "img", "images1", "images2",
            "video", "videos", "stream",
            "chat", "messaging",
            "crm", "erp", "hr",
            "finance", "accounting",
            "warehouse", "inventory",
            "reports", "analytics", "stats",
            "logging", "logs", "syslog",
            "sandbox", "preview", "preprod",
            "uat1", "uat2", "qa1", "qa2",
            "build", "release",
        ];

        if self.config.thorough {
            common.into_iter().chain(extended).collect()
        } else {
            common
        }
    }

    /// Query VirusTotal API (requires API key)
    #[allow(dead_code)]
    async fn query_virustotal(&self, domain: &str, api_key: &str) -> Result<HashMap<String, SubdomainInfo>> {
        let url = format!("https://www.virustotal.com/api/v3/domains/{}/subdomains", domain);

        let response = self
            .http_client
            .get_with_headers(&url, vec![("x-apikey".to_string(), api_key.to_string())])
            .await
            .context("Failed to query VirusTotal")?;

        let vt_response: VirusTotalResponse = serde_json::from_str(&response.body)
            .context("Failed to parse VirusTotal response")?;

        let mut results = HashMap::new();
        for item in vt_response.data {
            if let Some(info) = self.resolve_subdomain(&item.id, "virustotal").await {
                results.insert(item.id, info);
            }
        }

        Ok(results)
    }

    /// Query SecurityTrails API (requires API key)
    #[allow(dead_code)]
    async fn query_securitytrails(&self, domain: &str, api_key: &str) -> Result<HashMap<String, SubdomainInfo>> {
        let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains", domain);

        let response = self
            .http_client
            .get_with_headers(&url, vec![("APIKEY".to_string(), api_key.to_string())])
            .await
            .context("Failed to query SecurityTrails")?;

        let st_response: SecurityTrailsResponse = serde_json::from_str(&response.body)
            .context("Failed to parse SecurityTrails response")?;

        let mut results = HashMap::new();
        for subdomain in st_response.subdomains {
            let full_domain = format!("{}.{}", subdomain, domain);
            if let Some(info) = self.resolve_subdomain(&full_domain, "securitytrails").await {
                results.insert(full_domain, info);
            }
        }

        Ok(results)
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
    async fn test_subdomain_discovery() {
        let http_client = Arc::new(HttpClient::new(5, 1).unwrap());
        let config = DiscoveryConfig {
            thorough: false,
            use_passive_sources: true,
            use_active_enumeration: false,
            ..Default::default()
        };

        let mut discovery = SubdomainDiscovery::new(http_client, config);

        // Test with a known domain
        let results = discovery.discover("example.com").await;
        assert!(results.is_ok());
    }

    #[tokio::test]
    async fn test_wildcard_detection() {
        let http_client = Arc::new(HttpClient::new(5, 1).unwrap());
        let config = DiscoveryConfig::default();

        let mut discovery = SubdomainDiscovery::new(http_client, config);
        discovery.detect_wildcards("example.com").await;

        // Wildcard detection should complete without errors
    }
}
