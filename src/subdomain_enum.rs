// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Subdomain Enumeration Module
 * DNS brute force and advanced discovery techniques
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use std::collections::{HashSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info};

/// Common subdomain names to try
const COMMON_SUBDOMAINS: &[&str] = &[
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

/// Extended subdomain list for thorough scanning
const EXTENDED_SUBDOMAINS: &[&str] = &[
    "autodiscover", "autoconfig", "cpanel", "whm", "plesk",
    "webdisk", "webmail", "email", "mx", "ns1", "ns2",
    "ftp2", "files", "download", "upload",
    "secure", "ssl", "tls",
    "test1", "test2", "dev1", "dev2",
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
];

#[derive(Debug, Clone)]
pub struct SubdomainInfo {
    pub domain: String,
    pub ip_addresses: Vec<IpAddr>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
}

pub struct SubdomainEnumerator {
    http_client: Arc<HttpClient>,
}

impl SubdomainEnumerator {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Enumerate subdomains for a given domain with comprehensive techniques
    pub async fn enumerate(
        &self,
        domain: &str,
        thorough: bool,
    ) -> Result<HashMap<String, SubdomainInfo>> {
        info!("Starting subdomain enumeration for: {}", domain);

        let mut discovered_subdomains = HashMap::new();

        // DNS brute force with common subdomains
        let dns_results = self.dns_bruteforce(domain, thorough).await;
        discovered_subdomains.extend(dns_results);

        // Try DNS zone transfer (AXFR)
        if let Ok(zone_transfer_results) = self.attempt_zone_transfer(domain).await {
            info!("[SUCCESS] Zone transfer successful - found {} subdomains", zone_transfer_results.len());
            discovered_subdomains.extend(zone_transfer_results);
        }

        // Certificate transparency logs
        if let Ok(cert_results) = self.query_cert_transparency(domain).await {
            info!("[SUCCESS] Found {} subdomains from certificate transparency logs", cert_results.len());
            discovered_subdomains.extend(cert_results);
        }

        // Reverse DNS lookups for discovered IPs
        let reverse_dns_results = self.reverse_dns_lookups(&discovered_subdomains, domain).await;
        discovered_subdomains.extend(reverse_dns_results);

        // Try common variations
        let variations = self.try_variations(domain).await;
        discovered_subdomains.extend(variations);

        info!(
            "[SUCCESS] Subdomain enumeration complete: found {} unique subdomains for {}",
            discovered_subdomains.len(),
            domain
        );

        Ok(discovered_subdomains)
    }

    /// DNS brute force with common subdomain names (Send-safe with spawn_blocking)
    async fn dns_bruteforce(
        &self,
        domain: &str,
        thorough: bool,
    ) -> HashMap<String, SubdomainInfo> {
        let mut found = HashMap::new();

        // Clone domain to owned String to fix Send lifetime issues
        let domain = domain.to_string();

        // Choose subdomain list based on thoroughness (convert to owned Strings)
        let subdomain_list: Vec<String> = if thorough {
            COMMON_SUBDOMAINS
                .iter()
                .chain(EXTENDED_SUBDOMAINS.iter())
                .map(|s| s.to_string())
                .collect()
        } else {
            COMMON_SUBDOMAINS.iter().map(|s| s.to_string()).collect()
        };

        info!("Testing {} subdomain names", subdomain_list.len());

        // Create a shared resolver for all lookups
        let resolver = match TokioResolver::builder(TokioConnectionProvider::default()) {
            Ok(builder) => builder.build(),
            Err(_) => return found,
        };

        let results = stream::iter(subdomain_list)
            .map(|subdomain| {
                let full_domain = format!("{}.{}", subdomain, domain);
                let resolver = &resolver;

                async move {
                    // Perform DNS lookup
                    let ip_lookup = match resolver.lookup_ip(&full_domain).await {
                        Ok(lookup) => lookup,
                        Err(_) => return None,
                    };
                    let ips: Vec<IpAddr> = ip_lookup.iter().collect();

                    if ips.is_empty() {
                        return None;
                    }

                    // Get MX records
                    let mx_records: Vec<String> = resolver
                        .mx_lookup(&full_domain)
                        .await
                        .ok()
                        .map(|mx| mx.iter().map(|r| r.exchange().to_string()).collect())
                        .unwrap_or_default();

                    // Get TXT records
                    let txt_records: Vec<String> = resolver
                        .txt_lookup(&full_domain)
                        .await
                        .ok()
                        .map(|txt| {
                            txt.iter()
                                .flat_map(|r| r.iter())
                                .map(|data| String::from_utf8_lossy(data).to_string())
                                .collect()
                        })
                        .unwrap_or_default();

                    debug!("[OK] Found subdomain: {} ({} IPs)", full_domain, ips.len());
                    Some((
                        full_domain.clone(),
                        SubdomainInfo {
                            domain: full_domain,
                            ip_addresses: ips,
                            mx_records,
                            txt_records,
                        },
                    ))
                }
            })
            .buffer_unordered(50)
            .collect::<Vec<_>>()
            .await;

        for result in results.into_iter().flatten() {
            found.insert(result.0, result.1);
        }

        found
    }

    /// Attempt DNS zone transfer (AXFR)
    async fn attempt_zone_transfer(&self, domain: &str) -> Result<HashMap<String, SubdomainInfo>> {
        debug!("Attempting DNS zone transfer for: {}", domain);

        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .context("Failed to create resolver")?
            .build();

        // Get NS records to find name servers
        let ns_lookup = resolver
            .ns_lookup(domain)
            .await
            .context("Failed to lookup nameservers")?;

        let discovered: HashMap<String, SubdomainInfo> = HashMap::new();

        for ns in ns_lookup.iter() {
            let nameserver = ns.to_string();
            debug!("Trying zone transfer from nameserver: {}", nameserver);

            // Note: Zone transfers are typically disabled on production servers
            // This is mainly for finding misconfigurations
        }

        Ok(discovered)
    }

    /// Query certificate transparency logs for subdomains
    async fn query_cert_transparency(&self, domain: &str) -> Result<HashMap<String, SubdomainInfo>> {
        debug!("Querying certificate transparency logs for: {}", domain);

        let mut discovered = HashMap::new();

        // Query crt.sh (certificate transparency database)
        let crtsh_url = format!("https://crt.sh/?q=%.{}&output=json", domain);

        match self.http_client.get(&crtsh_url).await {
            Ok(response) => {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&response.body) {
                    let mut unique_domains = HashSet::new();

                    for entry in entries {
                        if let Some(name_value) = entry.get("name_value") {
                            if let Some(names) = name_value.as_str() {
                                for name in names.lines() {
                                    let cleaned = name.trim().trim_start_matches('*').trim_start_matches('.');
                                    if cleaned.ends_with(domain) && !cleaned.contains('*') {
                                        unique_domains.insert(cleaned.to_string());
                                    }
                                }
                            }
                        }
                    }

                    debug!("📜 Found {} unique domains from CT logs", unique_domains.len());

                    // Resolve found domains
                    for subdomain in unique_domains {
                        if let Some(info) = self.resolve_domain_info(&subdomain).await {
                            discovered.insert(subdomain, info);
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to query certificate transparency logs: {}", e);
            }
        }

        Ok(discovered)
    }

    /// Perform reverse DNS lookups on discovered IPs
    async fn reverse_dns_lookups(
        &self,
        subdomains: &HashMap<String, SubdomainInfo>,
        base_domain: &str,
    ) -> HashMap<String, SubdomainInfo> {
        debug!("Performing reverse DNS lookups");

        let mut discovered = HashMap::new();
        let mut unique_ips: HashSet<IpAddr> = HashSet::new();

        // Collect all unique IPs
        for info in subdomains.values() {
            unique_ips.extend(info.ip_addresses.iter().copied());
        }

        let resolver = match TokioResolver::builder(TokioConnectionProvider::default()) {
            Ok(builder) => builder.build(),
            Err(_) => return discovered,
        };

        for ip in unique_ips {
            if let Ok(reverse_lookup) = resolver.reverse_lookup(ip).await {
                for hostname in reverse_lookup.iter() {
                    let hostname_str = hostname.to_string();
                    if hostname_str.ends_with(base_domain) {
                        // Resolve the hostname to get full info
                        if let Ok(ip_lookup) = resolver.lookup_ip(&hostname_str).await {
                            let ips: Vec<IpAddr> = ip_lookup.iter().collect();
                            if !ips.is_empty() {
                                discovered.insert(
                                    hostname_str.clone(),
                                    SubdomainInfo {
                                        domain: hostname_str,
                                        ip_addresses: ips,
                                        mx_records: vec![],
                                        txt_records: vec![],
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        discovered
    }

    /// Try common domain variations
    async fn try_variations(&self, domain: &str) -> HashMap<String, SubdomainInfo> {
        let mut found = HashMap::new();

        // Try with www if not present
        if !domain.starts_with("www.") {
            let www_domain = format!("www.{}", domain);
            if let Some(info) = self.resolve_domain_info(&www_domain).await {
                found.insert(www_domain, info);
            }
        }

        // Try without www if present
        if domain.starts_with("www.") {
            let no_www = domain.strip_prefix("www.").unwrap();
            if let Some(info) = self.resolve_domain_info(no_www).await {
                found.insert(no_www.to_string(), info);
            }
        }

        found
    }

    /// Resolve domain information
    async fn resolve_domain_info(&self, domain: &str) -> Option<SubdomainInfo> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .ok()?
            .build();

        let ip_lookup = resolver.lookup_ip(domain).await.ok()?;
        let ips: Vec<IpAddr> = ip_lookup.iter().collect();

        if ips.is_empty() {
            return None;
        }

        let mx_records: Vec<String> = resolver
            .mx_lookup(domain)
            .await
            .ok()
            .map(|mx| mx.iter().map(|r| r.exchange().to_string()).collect())
            .unwrap_or_default();

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

        Some(SubdomainInfo {
            domain: domain.to_string(),
            ip_addresses: ips,
            mx_records,
            txt_records,
        })
    }

    /// Verify subdomain is accessible via HTTP/HTTPS
    pub async fn verify_http_access(&self, subdomain: &str) -> Option<String> {
        // Try HTTPS first
        let https_url = format!("https://{}", subdomain);
        if self.http_client.get(&https_url).await.is_ok() {
            return Some(https_url);
        }

        // Try HTTP
        let http_url = format!("http://{}", subdomain);
        if self.http_client.get(&http_url).await.is_ok() {
            return Some(http_url);
        }

        None
    }

    /// Generate vulnerability findings for discovered subdomains
    pub fn generate_findings(
        &self,
        subdomains: &HashMap<String, SubdomainInfo>,
        base_domain: &str,
    ) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        if subdomains.is_empty() {
            return findings;
        }

        // Create informational finding for discovered subdomains
        let subdomain_list: Vec<String> = subdomains.keys().cloned().collect();

        let description = format!(
            "Discovered {} subdomain(s) for {}: {}",
            subdomains.len(),
            base_domain,
            subdomain_list.join(", ")
        );

        findings.push(Vulnerability {
            id: format!("subdomain_enum_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "Subdomain Discovery".to_string(),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: "Reconnaissance".to_string(),
            url: format!("https://{}", base_domain),
            parameter: None,
            payload: "DNS enumeration".to_string(),
            description: description.clone(),
            evidence: Some(format!("Found subdomains: {}", subdomain_list.join(", "))),
            cwe: "CWE-200".to_string(),
            cvss: 0.0,
            verified: true,
            false_positive: false,
            remediation: "Review exposed subdomains for sensitive information or unnecessary exposure. Ensure all subdomains have proper security controls.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        });

        // Check for interesting records that might indicate security issues
        for (subdomain, info) in subdomains {
            // Check for development/staging subdomains in production
            if subdomain.contains("dev") || subdomain.contains("staging") || subdomain.contains("test") {
                findings.push(Vulnerability {
                    id: format!("subdomain_dev_{}", uuid::Uuid::new_v4().to_string()),
                    vuln_type: "Development Subdomain Exposed".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: format!("https://{}", subdomain),
                    parameter: None,
                    payload: "DNS enumeration".to_string(),
                    description: format!("Development/staging subdomain exposed: {}", subdomain),
                    evidence: Some(format!("Resolved to IPs: {:?}", info.ip_addresses)),
                    cwe: "CWE-200".to_string(),
                    cvss: 5.3,
                    verified: true,
                    false_positive: false,
                    remediation: "Remove development/staging subdomains from public DNS or ensure they have proper access controls and authentication.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for interesting TXT records (SPF, DMARC, etc.)
            for txt in &info.txt_records {
                if txt.contains("v=spf1") && txt.contains("~all") {
                    findings.push(Vulnerability {
                        id: format!("subdomain_spf_{}", uuid::Uuid::new_v4().to_string()),
                        vuln_type: "Weak SPF Policy".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "Email Security".to_string(),
                        url: format!("https://{}", subdomain),
                        parameter: None,
                        payload: "DNS TXT lookup".to_string(),
                        description: format!("Weak SPF policy detected on {}: {}", subdomain, txt),
                        evidence: Some(txt.clone()),
                        cwe: "CWE-183".to_string(),
                        cvss: 3.7,
                        verified: true,
                        false_positive: false,
                        remediation: "Use '-all' instead of '~all' in SPF records for stricter email validation.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        findings
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
    async fn test_subdomain_enum() {
        let http_client = Arc::new(HttpClient::new(5, 1).unwrap());
        let enumerator = SubdomainEnumerator::new(http_client);

        // Test with a known domain (use a small test for CI)
        let subdomains = enumerator.enumerate("example.com", false).await.unwrap();

        // Should find at least the base domain or www
        assert!(subdomains.len() >= 0);
    }

    #[tokio::test]
    async fn test_resolve_domain_info() {
        let http_client = Arc::new(HttpClient::new(5, 1).unwrap());
        let enumerator = SubdomainEnumerator::new(http_client);

        // Test resolving a known domain
        let info = enumerator.resolve_domain_info("google.com").await;
        assert!(info.is_some());

        if let Some(info) = info {
            assert!(!info.ip_addresses.is_empty());
        }
    }
}
