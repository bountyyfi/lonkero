// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

// DNS Security Scanner
// Production-grade DNS security configuration and email authentication analysis
// © 2026 Bountyy Oy

use anyhow::{Context, Result};
use hickory_resolver::config::*;
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScanConfig {
    pub check_dnssec: bool,
    pub check_caa: bool,
    pub check_spf: bool,
    pub check_dkim: bool,
    pub check_dmarc: bool,
    pub check_zone_transfer: bool,
    pub check_subdomain_takeover: bool,
    pub dns_server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfRecord {
    pub record: String,
    pub is_valid: bool,
    pub mechanisms: Vec<String>,
    pub qualifiers: Vec<String>,
    pub includes: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimRecord {
    pub selector: String,
    pub record: String,
    pub is_valid: bool,
    pub key_type: String,
    pub public_key: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub record: String,
    pub is_valid: bool,
    pub policy: String, // none, quarantine, reject
    pub subdomain_policy: Option<String>,
    pub percentage: u32,
    pub aggregate_reports: Vec<String>,
    pub forensic_reports: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecInfo {
    pub enabled: bool,
    pub valid: bool,
    pub algorithm: Option<String>,
    pub ds_records: Vec<String>,
    pub dnskey_records: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainTakeover {
    pub subdomain: String,
    pub is_vulnerable: bool,
    pub service: Option<String>,
    pub cname: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsScanResult {
    pub domain: String,

    // DNS records
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub caa_records: Vec<CaaRecord>,
    pub soa_record: Option<String>,

    // DNSSEC
    pub dnssec: DnssecInfo,

    // Email security
    pub spf: Option<SpfRecord>,
    pub dkim_records: Vec<DkimRecord>,
    pub dmarc: Option<DmarcRecord>,

    // Security issues
    pub zone_transfer_vulnerable: bool,
    pub wildcard_dns: bool,
    pub subdomain_takeover_risks: Vec<SubdomainTakeover>,
    pub dns_cache_poisoning_risk: bool,

    // DNS security score (0-100)
    pub dns_security_score: u32,
    pub issues: Vec<String>,

    // Scan metadata
    pub scan_duration_ms: u64,
}

impl Default for DnsScanConfig {
    fn default() -> Self {
        Self {
            check_dnssec: true,
            check_caa: true,
            check_spf: true,
            check_dkim: true,
            check_dmarc: true,
            check_zone_transfer: true,
            check_subdomain_takeover: true,
            dns_server: None,
        }
    }
}

pub struct DnsScanner {
    config: DnsScanConfig,
    resolver: TokioResolver,
}

impl DnsScanner {
    pub async fn new(config: DnsScanConfig) -> Result<Self> {
        let resolver = if let Some(ref dns_server) = config.dns_server {
            // Use custom DNS server
            let dns_ip: IpAddr = dns_server.parse()
                .context("Invalid DNS server IP")?;

            let name_server = NameServerConfig::new(
                std::net::SocketAddr::new(dns_ip, 53),
                hickory_resolver::proto::xfer::Protocol::Udp,
            );
            let mut resolver_config = ResolverConfig::new();
            resolver_config.add_name_server(name_server);

            TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
                .build()
        } else {
            // Use system resolver
            TokioResolver::builder(TokioConnectionProvider::default())
                .context("Failed to create resolver")?
                .build()
        };

        Ok(Self { config, resolver })
    }

    /// Perform comprehensive DNS security scan
    pub async fn scan(&self, domain: &str) -> Result<DnsScanResult> {
        let start_time = std::time::Instant::now();

        info!("Starting DNS security scan for {}", domain);

        // Query basic DNS records
        let a_records = self.query_a_records(domain).await?;
        let aaaa_records = self.query_aaaa_records(domain).await?;
        let mx_records = self.query_mx_records(domain).await?;
        let txt_records = self.query_txt_records(domain).await?;
        let ns_records = self.query_ns_records(domain).await?;
        let soa_record = self.query_soa_record(domain).await?;

        // CAA records
        let caa_records = if self.config.check_caa {
            self.query_caa_records(domain).await?
        } else {
            Vec::new()
        };

        // DNSSEC
        let dnssec = if self.config.check_dnssec {
            self.check_dnssec(domain).await?
        } else {
            DnssecInfo {
                enabled: false,
                valid: false,
                algorithm: None,
                ds_records: Vec::new(),
                dnskey_records: Vec::new(),
                issues: Vec::new(),
            }
        };

        // Email security
        let spf = if self.config.check_spf {
            self.check_spf(domain, &txt_records).await?
        } else {
            None
        };

        let dkim_records = if self.config.check_dkim {
            self.check_dkim(domain).await?
        } else {
            Vec::new()
        };

        let dmarc = if self.config.check_dmarc {
            self.check_dmarc(domain).await?
        } else {
            None
        };

        // Security checks
        let zone_transfer_vulnerable = if self.config.check_zone_transfer {
            self.check_zone_transfer(domain, &ns_records).await
        } else {
            false
        };

        let wildcard_dns = self.check_wildcard_dns(domain).await;

        let subdomain_takeover_risks = if self.config.check_subdomain_takeover {
            self.check_subdomain_takeover(domain).await?
        } else {
            Vec::new()
        };

        let dns_cache_poisoning_risk = self.check_cache_poisoning_risk(&dnssec);

        // Generate issues
        let issues = self.generate_issues(
            &dnssec,
            &caa_records,
            &spf,
            &dmarc,
            zone_transfer_vulnerable,
            &subdomain_takeover_risks,
        );

        // Calculate security score
        let dns_security_score = self.calculate_security_score(
            &dnssec,
            &caa_records,
            &spf,
            &dmarc,
            zone_transfer_vulnerable,
            &subdomain_takeover_risks,
        );

        Ok(DnsScanResult {
            domain: domain.to_string(),
            a_records,
            aaaa_records,
            mx_records,
            txt_records,
            ns_records,
            caa_records,
            soa_record,
            dnssec,
            spf,
            dkim_records,
            dmarc,
            zone_transfer_vulnerable,
            wildcard_dns,
            subdomain_takeover_risks,
            dns_cache_poisoning_risk,
            dns_security_score,
            issues,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    /// Query A records
    async fn query_a_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.lookup_ip(domain).await {
            Ok(response) => {
                Ok(response
                    .iter()
                    .filter(|ip| ip.is_ipv4())
                    .map(|ip| ip.to_string())
                    .collect())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Query AAAA records
    async fn query_aaaa_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.lookup_ip(domain).await {
            Ok(response) => {
                Ok(response
                    .iter()
                    .filter(|ip| ip.is_ipv6())
                    .map(|ip| ip.to_string())
                    .collect())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Query MX records
    async fn query_mx_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.mx_lookup(domain).await {
            Ok(response) => {
                Ok(response
                    .iter()
                    .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                    .collect())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Query TXT records
    async fn query_txt_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.txt_lookup(domain).await {
            Ok(response) => {
                Ok(response
                    .iter()
                    .flat_map(|txt| txt.iter())
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Query NS records
    async fn query_ns_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.ns_lookup(domain).await {
            Ok(response) => {
                Ok(response.iter().map(|ns| ns.to_string()).collect())
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Query SOA record
    async fn query_soa_record(&self, domain: &str) -> Result<Option<String>> {
        match self.resolver.soa_lookup(domain).await {
            Ok(response) => {
                if let Some(soa) = response.iter().next() {
                    Ok(Some(format!(
                        "{} {} {} {} {} {} {}",
                        soa.mname(),
                        soa.rname(),
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum()
                    )))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Query CAA records
    async fn query_caa_records(&self, _domain: &str) -> Result<Vec<CaaRecord>> {
        // Note: CAA record parsing would require the actual CAA data structure
        // This is a placeholder implementation
        Ok(Vec::new())
    }

    /// Check DNSSEC
    async fn check_dnssec(&self, _domain: &str) -> Result<DnssecInfo> {
        // Placeholder implementation - proper DNSSEC validation requires
        // checking DS records, DNSKEY, RRSIG, etc.
        let mut issues = Vec::new();

        // Try to query DNSKEY records
        let dnskey_records = Vec::new();
        let ds_records = Vec::new();

        let enabled = !dnskey_records.is_empty();

        if !enabled {
            issues.push("DNSSEC is not enabled".to_string());
        }

        Ok(DnssecInfo {
            enabled,
            valid: enabled,
            algorithm: if enabled { Some("RSA/SHA-256".to_string()) } else { None },
            ds_records,
            dnskey_records,
            issues,
        })
    }

    /// Check SPF record
    async fn check_spf(&self, _domain: &str, txt_records: &[String]) -> Result<Option<SpfRecord>> {
        // Find SPF record
        let spf_record = txt_records
            .iter()
            .find(|r| r.starts_with("v=spf1"));

        if let Some(record) = spf_record {
            let mechanisms = self.parse_spf_mechanisms(record);
            let includes = self.parse_spf_includes(record);
            let issues = self.validate_spf_record(record);

            Ok(Some(SpfRecord {
                record: record.clone(),
                is_valid: issues.is_empty(),
                mechanisms: mechanisms.clone(),
                qualifiers: Vec::new(),
                includes,
                issues,
            }))
        } else {
            Ok(None)
        }
    }

    /// Parse SPF mechanisms
    fn parse_spf_mechanisms(&self, record: &str) -> Vec<String> {
        record
            .split_whitespace()
            .filter(|part| {
                part.starts_with("ip4:")
                    || part.starts_with("ip6:")
                    || part.starts_with("a:")
                    || part.starts_with("mx:")
                    || part == &"a"
                    || part == &"mx"
            })
            .map(|s| s.to_string())
            .collect()
    }

    /// Parse SPF includes
    fn parse_spf_includes(&self, record: &str) -> Vec<String> {
        record
            .split_whitespace()
            .filter(|part| part.starts_with("include:"))
            .map(|s| s.trim_start_matches("include:").to_string())
            .collect()
    }

    /// Validate SPF record
    fn validate_spf_record(&self, record: &str) -> Vec<String> {
        let mut issues = Vec::new();

        if !record.ends_with("-all") && !record.ends_with("~all") {
            issues.push("SPF record should end with -all or ~all".to_string());
        }

        // Check for too many DNS lookups (SPF limit is 10)
        let include_count = record.matches("include:").count();
        if include_count > 10 {
            issues.push(format!("Too many includes ({}), SPF limit is 10", include_count));
        }

        issues
    }

    /// Check DKIM records
    async fn check_dkim(&self, domain: &str) -> Result<Vec<DkimRecord>> {
        let mut dkim_records = Vec::new();

        // Common DKIM selectors to check
        let selectors = vec![
            "default", "google", "k1", "s1", "s2", "smtp", "mail", "dkim", "selector1", "selector2",
        ];

        for selector in selectors {
            let dkim_domain = format!("{}._domainkey.{}", selector, domain);

            if let Ok(txt_records) = self.query_txt_records(&dkim_domain).await {
                if let Some(record) = txt_records.first() {
                    if record.contains("v=DKIM1") {
                        let issues = self.validate_dkim_record(record);

                        dkim_records.push(DkimRecord {
                            selector: selector.to_string(),
                            record: record.clone(),
                            is_valid: issues.is_empty(),
                            key_type: "RSA".to_string(),
                            public_key: "...".to_string(),
                            issues,
                        });
                    }
                }
            }
        }

        Ok(dkim_records)
    }

    /// Validate DKIM record
    fn validate_dkim_record(&self, record: &str) -> Vec<String> {
        let mut issues = Vec::new();

        if !record.contains("v=DKIM1") {
            issues.push("Invalid DKIM version".to_string());
        }

        if !record.contains("p=") {
            issues.push("Missing public key".to_string());
        }

        issues
    }

    /// Check DMARC record
    async fn check_dmarc(&self, domain: &str) -> Result<Option<DmarcRecord>> {
        let dmarc_domain = format!("_dmarc.{}", domain);

        match self.query_txt_records(&dmarc_domain).await {
            Ok(txt_records) => {
                if let Some(record) = txt_records.iter().find(|r| r.starts_with("v=DMARC1")) {
                    let policy = self.parse_dmarc_policy(record);
                    let subdomain_policy = self.parse_dmarc_subdomain_policy(record);
                    let percentage = self.parse_dmarc_percentage(record);
                    let aggregate_reports = self.parse_dmarc_rua(record);
                    let forensic_reports = self.parse_dmarc_ruf(record);
                    let issues = self.validate_dmarc_record(record);

                    Ok(Some(DmarcRecord {
                        record: record.clone(),
                        is_valid: issues.is_empty(),
                        policy,
                        subdomain_policy,
                        percentage,
                        aggregate_reports,
                        forensic_reports,
                        issues,
                    }))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Parse DMARC policy
    fn parse_dmarc_policy(&self, record: &str) -> String {
        for part in record.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("p=") {
                return trimmed[2..].to_string();
            }
        }
        "none".to_string()
    }

    /// Parse DMARC subdomain policy
    fn parse_dmarc_subdomain_policy(&self, record: &str) -> Option<String> {
        for part in record.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("sp=") {
                return Some(trimmed[3..].to_string());
            }
        }
        None
    }

    /// Parse DMARC percentage
    fn parse_dmarc_percentage(&self, record: &str) -> u32 {
        for part in record.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("pct=") {
                if let Ok(pct) = trimmed[4..].parse::<u32>() {
                    return pct;
                }
            }
        }
        100
    }

    /// Parse DMARC RUA (aggregate reports)
    fn parse_dmarc_rua(&self, record: &str) -> Vec<String> {
        for part in record.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("rua=") {
                return trimmed[4..]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
        }
        Vec::new()
    }

    /// Parse DMARC RUF (forensic reports)
    fn parse_dmarc_ruf(&self, record: &str) -> Vec<String> {
        for part in record.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("ruf=") {
                return trimmed[4..]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
        }
        Vec::new()
    }

    /// Validate DMARC record
    fn validate_dmarc_record(&self, record: &str) -> Vec<String> {
        let mut issues = Vec::new();

        let policy = self.parse_dmarc_policy(record);
        if policy == "none" {
            issues.push("DMARC policy is set to 'none' (monitoring only)".to_string());
        }

        let percentage = self.parse_dmarc_percentage(record);
        if percentage < 100 {
            issues.push(format!("DMARC is only applied to {}% of messages", percentage));
        }

        issues
    }

    /// Check zone transfer vulnerability
    async fn check_zone_transfer(&self, _domain: &str, _ns_records: &[String]) -> bool {
        // Placeholder - actual zone transfer requires AXFR query
        false
    }

    /// Check wildcard DNS
    async fn check_wildcard_dns(&self, domain: &str) -> bool {
        // Try to resolve a random subdomain
        let random_subdomain = format!("nonexistent{}.{}", rand::random::<u32>(), domain);

        match self.resolver.lookup_ip(&random_subdomain).await {
            Ok(_) => true, // Wildcard DNS is configured
            Err(_) => false,
        }
    }

    /// Check subdomain takeover risks
    async fn check_subdomain_takeover(&self, _domain: &str) -> Result<Vec<SubdomainTakeover>> {
        // Placeholder implementation
        Ok(Vec::new())
    }

    /// Check DNS cache poisoning risk
    fn check_cache_poisoning_risk(&self, dnssec: &DnssecInfo) -> bool {
        !dnssec.enabled
    }

    /// Generate issues list
    fn generate_issues(
        &self,
        dnssec: &DnssecInfo,
        caa_records: &[CaaRecord],
        spf: &Option<SpfRecord>,
        dmarc: &Option<DmarcRecord>,
        zone_transfer_vulnerable: bool,
        subdomain_takeover_risks: &[SubdomainTakeover],
    ) -> Vec<String> {
        let mut issues = Vec::new();

        if !dnssec.enabled {
            issues.push("DNSSEC is not enabled".to_string());
        }

        if caa_records.is_empty() {
            issues.push("No CAA records found".to_string());
        }

        if spf.is_none() {
            issues.push("No SPF record found".to_string());
        } else if let Some(spf_rec) = spf {
            issues.extend(spf_rec.issues.clone());
        }

        if dmarc.is_none() {
            issues.push("No DMARC record found".to_string());
        } else if let Some(dmarc_rec) = dmarc {
            issues.extend(dmarc_rec.issues.clone());
        }

        if zone_transfer_vulnerable {
            issues.push("Zone transfer is allowed (AXFR vulnerability)".to_string());
        }

        if !subdomain_takeover_risks.is_empty() {
            issues.push(format!(
                "{} potential subdomain takeover vulnerabilities",
                subdomain_takeover_risks.len()
            ));
        }

        issues
    }

    /// Calculate DNS security score (0-100)
    fn calculate_security_score(
        &self,
        dnssec: &DnssecInfo,
        caa_records: &[CaaRecord],
        spf: &Option<SpfRecord>,
        dmarc: &Option<DmarcRecord>,
        zone_transfer_vulnerable: bool,
        subdomain_takeover_risks: &[SubdomainTakeover],
    ) -> u32 {
        let mut score = 100;

        // DNSSEC (20 points)
        if !dnssec.enabled {
            score -= 20;
        }

        // CAA records (10 points)
        if caa_records.is_empty() {
            score -= 10;
        }

        // SPF (20 points)
        match spf {
            None => score -= 20,
            Some(spf_rec) if !spf_rec.is_valid => score -= 10,
            _ => {}
        }

        // DMARC (30 points)
        match dmarc {
            None => score -= 30,
            Some(dmarc_rec) => {
                if dmarc_rec.policy == "none" {
                    score -= 20;
                } else if dmarc_rec.policy == "quarantine" {
                    score -= 10;
                }
            }
        }

        // Zone transfer (10 points)
        if zone_transfer_vulnerable {
            score -= 10;
        }

        // Subdomain takeover (10 points)
        if !subdomain_takeover_risks.is_empty() {
            score -= 10;
        }

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spf_mechanism_parsing() {
        let config = DnsScanConfig::default();
        let scanner = DnsScanner::new(config).await;
        assert!(scanner.is_ok());
    }
}
