// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloudflare DNS Security Scanner
 * Comprehensive DNS security scanning for Cloudflare zones
 *
 * Detects:
 * - Dangling DNS records (pointing to non-existent resources)
 * - DNSSEC not enabled
 * - CAA records missing or misconfigured
 * - SPF, DKIM, DMARC records missing
 * - Wildcard DNS records
 * - DNS records with short TTLs (cache poisoning risk)
 * - DNS tunneling detection
 * - Subdomain takeover vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize)]
struct CloudflareApiResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize, Clone)]
struct DnsRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DnssecSettings {
    status: String,
    #[serde(default)]
    flags: Option<u16>,
    #[serde(default)]
    algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CloudflareDnsConfig {
    pub api_token: String,
    pub zone_id: String,
    pub check_dangling: bool,
    pub check_dnssec: bool,
    pub check_email_security: bool,
    pub check_caa: bool,
    pub check_takeover: bool,
}

pub struct CloudflareDnsScanner {
    http_client: Arc<HttpClient>,
    api_token: String,
}

impl CloudflareDnsScanner {
    pub fn new(http_client: Arc<HttpClient>, api_token: String) -> Self {
        Self {
            http_client,
            api_token,
        }
    }

    /// Main scan function for Cloudflare DNS security
    pub async fn scan(
        &self,
        zone_id: &str,
        config: &CloudflareDnsConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting Cloudflare DNS security scan for zone: {}", zone_id);

        // Fetch all DNS records
        let dns_records = match self.fetch_dns_records(zone_id).await {
            Ok(records) => records,
            Err(e) => {
                warn!("Failed to fetch DNS records: {}", e);
                return Ok((vulnerabilities, 0));
            }
        };

        info!("Found {} DNS records", dns_records.len());

        // Check DNSSEC
        if config.check_dnssec {
            let (vulns, tests) = self.check_dnssec(zone_id).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check for dangling DNS records
        if config.check_dangling {
            let (vulns, tests) = self.check_dangling_records(&dns_records).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check email security records
        if config.check_email_security {
            let (vulns, tests) = self.check_email_security_records(&dns_records).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check CAA records
        if config.check_caa {
            let (vulns, tests) = self.check_caa_records(&dns_records).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check wildcard DNS
        let (vulns, tests) = self.check_wildcard_records(&dns_records).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Check short TTLs
        let (vulns, tests) = self.check_short_ttls(&dns_records).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Check subdomain takeover
        if config.check_takeover {
            let (vulns, tests) = self.check_subdomain_takeover(&dns_records).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Check DNS tunneling indicators
        let (vulns, tests) = self.check_dns_tunneling(&dns_records).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        info!(
            "Cloudflare DNS scan completed: {} vulnerabilities found, {} tests run",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Fetch DNS records from Cloudflare API
    async fn fetch_dns_records(&self, zone_id: &str) -> anyhow::Result<Vec<DnsRecord>> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?per_page=100",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        let response = self.http_client.get_with_headers(&url, headers).await?;

        let api_response: CloudflareApiResponse<Vec<DnsRecord>> =
            serde_json::from_str(&response.body)?;

        if !api_response.success {
            let errors = api_response
                .errors
                .iter()
                .map(|e| e.message.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow::anyhow!("Cloudflare API error: {}", errors));
        }

        Ok(api_response.result.unwrap_or_default())
    }

    /// Check DNSSEC configuration
    async fn check_dnssec(&self, zone_id: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking DNSSEC configuration");

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dnssec",
            zone_id
        );

        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {}", self.api_token)),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];

        match self.http_client.get_with_headers(&url, headers).await {
            Ok(response) => {
                let api_response: CloudflareApiResponse<DnssecSettings> =
                    serde_json::from_str(&response.body)?;

                if let Some(dnssec) = api_response.result {
                    if dnssec.status != "active" {
                        vulnerabilities.push(self.create_vulnerability(
                            zone_id,
                            "DNSSEC Not Enabled",
                            "",
                            &format!("DNSSEC status is '{}' instead of 'active'", dnssec.status),
                            "Zone is vulnerable to DNS spoofing and cache poisoning attacks",
                            Severity::High,
                            "CWE-350",
                            7.5,
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to check DNSSEC: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for dangling DNS records
    async fn check_dangling_records(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking for dangling DNS records");

        // Known dangling record patterns
        let dangling_patterns = vec![
            // AWS
            (r".*\.elb\.amazonaws\.com$", "AWS ELB"),
            (r".*\.s3\.amazonaws\.com$", "AWS S3"),
            (r".*\.s3-website.*\.amazonaws\.com$", "AWS S3 Website"),
            (r".*\.cloudfront\.net$", "AWS CloudFront"),
            // Azure
            (r".*\.azurewebsites\.net$", "Azure Web Apps"),
            (r".*\.cloudapp\.azure\.com$", "Azure Cloud Services"),
            (r".*\.blob\.core\.windows\.net$", "Azure Blob Storage"),
            // Google Cloud
            (r".*\.appspot\.com$", "Google App Engine"),
            (r".*\.googleplex\.com$", "Google Cloud"),
            // Heroku
            (r".*\.herokuapp\.com$", "Heroku"),
            // GitHub Pages
            (r".*\.github\.io$", "GitHub Pages"),
            // Vercel
            (r".*\.vercel\.app$", "Vercel"),
            // Netlify
            (r".*\.netlify\.app$", "Netlify"),
        ];

        for record in records {
            if record.record_type == "CNAME" || record.record_type == "A" {
                tests_run += 1;

                for (pattern, service) in &dangling_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(&record.content) {
                            // Try to resolve the target
                            if let Err(_) = self.verify_dns_target(&record.content).await {
                                vulnerabilities.push(self.create_vulnerability(
                                    &record.name,
                                    "Dangling DNS Record",
                                    &record.content,
                                    &format!(
                                        "DNS record '{}' points to non-existent {} resource '{}'",
                                        record.name, service, record.content
                                    ),
                                    &format!("Potential subdomain takeover via {}", service),
                                    Severity::High,
                                    "CWE-346",
                                    8.1,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Verify DNS target exists
    async fn verify_dns_target(&self, target: &str) -> anyhow::Result<()> {
        let url = format!("https://{}", target);

        match self.http_client.get(&url).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if it's a real DNS resolution failure vs other errors
                if e.to_string().contains("dns") || e.to_string().contains("resolve") {
                    Err(anyhow::anyhow!("DNS target does not exist"))
                } else {
                    Ok(()) // Exists but returned error (that's fine)
                }
            }
        }
    }

    /// Check email security records (SPF, DKIM, DMARC)
    async fn check_email_security_records(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Checking email security records");

        // Check for SPF record
        let has_spf = records.iter().any(|r| {
            r.record_type == "TXT" && r.content.starts_with("v=spf1")
        });

        if !has_spf {
            vulnerabilities.push(self.create_vulnerability(
                "domain",
                "Missing SPF Record",
                "",
                "No SPF record found for the domain",
                "Domain is vulnerable to email spoofing attacks",
                Severity::Medium,
                "CWE-346",
                5.3,
            ));
        } else {
            // Validate SPF record
            if let Some(spf_record) = records.iter().find(|r| {
                r.record_type == "TXT" && r.content.starts_with("v=spf1")
            }) {
                if !spf_record.content.contains("~all") && !spf_record.content.contains("-all") {
                    vulnerabilities.push(self.create_vulnerability(
                        "domain",
                        "Weak SPF Configuration",
                        &spf_record.content,
                        "SPF record does not end with ~all or -all",
                        "SPF policy is too permissive, allowing unauthorized senders",
                        Severity::Medium,
                        "CWE-346",
                        5.3,
                    ));
                }
            }
        }

        // Check for DMARC record
        let has_dmarc = records.iter().any(|r| {
            r.name.starts_with("_dmarc") && r.record_type == "TXT" && r.content.starts_with("v=DMARC1")
        });

        if !has_dmarc {
            vulnerabilities.push(self.create_vulnerability(
                "domain",
                "Missing DMARC Record",
                "",
                "No DMARC record found for the domain",
                "Domain lacks email authentication policy enforcement",
                Severity::Medium,
                "CWE-346",
                5.3,
            ));
        } else {
            // Validate DMARC record
            if let Some(dmarc_record) = records.iter().find(|r| {
                r.name.starts_with("_dmarc") && r.record_type == "TXT"
            }) {
                if dmarc_record.content.contains("p=none") {
                    vulnerabilities.push(self.create_vulnerability(
                        "domain",
                        "Weak DMARC Policy",
                        &dmarc_record.content,
                        "DMARC policy is set to 'none' which only monitors",
                        "DMARC policy does not reject or quarantine unauthorized emails",
                        Severity::Low,
                        "CWE-346",
                        3.7,
                    ));
                }
            }
        }

        // Check for DKIM selector (common selectors)
        let common_selectors = vec!["default".to_string(), "google".to_string(), "k1".to_string(), "selector1".to_string(), "selector2".to_string(), "dkim".to_string()];
        let has_dkim = common_selectors.iter().any(|selector| {
            records.iter().any(|r| {
                r.name.contains(&format!("{}._domainkey", selector)) && r.record_type == "TXT"
            })
        });

        if !has_dkim {
            vulnerabilities.push(self.create_vulnerability(
                "domain",
                "Missing DKIM Record",
                "",
                "No DKIM record found with common selectors",
                "Domain may not be using DKIM email authentication",
                Severity::Low,
                "CWE-346",
                3.7,
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check CAA records
    async fn check_caa_records(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Checking CAA records");

        let has_caa = records.iter().any(|r| r.record_type == "CAA");

        if !has_caa {
            vulnerabilities.push(self.create_vulnerability(
                "domain",
                "Missing CAA Record",
                "",
                "No CAA records found for the domain",
                "Domain is vulnerable to unauthorized SSL/TLS certificate issuance",
                Severity::Medium,
                "CWE-295",
                5.3,
            ));
        } else {
            // Validate CAA records
            let caa_records: Vec<&DnsRecord> = records
                .iter()
                .filter(|r| r.record_type == "CAA")
                .collect();

            let has_issue_or_issuewild = caa_records.iter().any(|r| {
                r.content.contains("issue") || r.content.contains("issuewild")
            });

            if !has_issue_or_issuewild {
                vulnerabilities.push(self.create_vulnerability(
                    "domain",
                    "Misconfigured CAA Record",
                    "",
                    "CAA records exist but don't specify 'issue' or 'issuewild' properties",
                    "CAA configuration does not restrict certificate issuance",
                    Severity::Medium,
                    "CWE-295",
                    5.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for wildcard DNS records
    async fn check_wildcard_records(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking for wildcard DNS records");

        for record in records {
            tests_run += 1;
            if record.name.starts_with("*.") || record.name.contains(".*.") {
                vulnerabilities.push(self.create_vulnerability(
                    &record.name,
                    "Wildcard DNS Record",
                    &record.content,
                    &format!("Wildcard DNS record found: {} -> {}", record.name, record.content),
                    "Wildcard records can increase attack surface and enable subdomain enumeration",
                    Severity::Low,
                    "CWE-200",
                    3.7,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for short TTL values (cache poisoning risk)
    async fn check_short_ttls(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking for short TTL values");

        const MIN_SAFE_TTL: u32 = 300; // 5 minutes

        for record in records {
            tests_run += 1;
            if record.ttl > 0 && record.ttl < MIN_SAFE_TTL {
                vulnerabilities.push(self.create_vulnerability(
                    &record.name,
                    "Short DNS TTL",
                    &format!("TTL: {} seconds", record.ttl),
                    &format!(
                        "DNS record '{}' has very short TTL of {} seconds",
                        record.name, record.ttl
                    ),
                    "Short TTL values can facilitate DNS cache poisoning attacks",
                    Severity::Low,
                    "CWE-350",
                    3.7,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for subdomain takeover vulnerabilities
    async fn check_subdomain_takeover(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking for subdomain takeover vulnerabilities");

        // Subdomain takeover fingerprints
        let takeover_signatures = vec![
            ("There isn't a GitHub Pages site here", "GitHub Pages", "Create a repository with the subdomain name"),
            ("NoSuchBucket", "AWS S3", "Create an S3 bucket with the same name"),
            ("No such app", "Heroku", "Create a Heroku app with the subdomain name"),
            ("404 File not found", "Netlify", "Claim the subdomain in Netlify"),
            ("The specified bucket does not exist", "AWS S3", "Create the missing S3 bucket"),
            ("404: Not Found", "Vercel", "Add the domain to your Vercel project"),
        ];

        for record in records {
            if record.record_type == "CNAME" || record.record_type == "A" {
                tests_run += 1;

                let url = format!("https://{}", record.name);

                match self.http_client.get(&url).await {
                    Ok(response) => {
                        for (signature, service, exploit) in &takeover_signatures {
                            if response.body.contains(signature) {
                                vulnerabilities.push(self.create_vulnerability(
                                    &record.name,
                                    "Subdomain Takeover Vulnerability",
                                    &record.content,
                                    &format!(
                                        "Subdomain '{}' points to unclaimed {} resource",
                                        record.name, service
                                    ),
                                    &format!(
                                        "Attackers can {} and control the subdomain",
                                        exploit.to_lowercase()
                                    ),
                                    Severity::Critical,
                                    "CWE-346",
                                    8.1,
                                ));
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        // DNS resolution failure might indicate dangling record
                        // Already handled in check_dangling_records
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Check for DNS tunneling indicators
    async fn check_dns_tunneling(
        &self,
        records: &[DnsRecord],
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Checking for DNS tunneling indicators");

        // Look for suspicious patterns that might indicate DNS tunneling
        let mut subdomain_counts: HashMap<String, usize> = HashMap::new();

        for record in records {
            tests_run += 1;

            // Count subdomains per parent domain
            if let Some(parent) = self.extract_parent_domain(&record.name) {
                *subdomain_counts.entry(parent.clone()).or_insert(0) += 1;

                // Check for unusually long subdomain names (potential base64 encoded data)
                let parts: Vec<&str> = record.name.split('.').collect();
                for part in &parts[..parts.len().saturating_sub(2)] {
                    if part.len() > 50 {
                        vulnerabilities.push(self.create_vulnerability(
                            &record.name,
                            "Suspicious DNS Pattern - Potential Tunneling",
                            part,
                            &format!("Unusually long subdomain label ({} chars) detected", part.len()),
                            "May indicate DNS tunneling or data exfiltration attempts",
                            Severity::Medium,
                            "CWE-506",
                            6.5,
                        ));
                    }
                }
            }
        }

        // Check for excessive number of subdomains
        for (domain, count) in subdomain_counts {
            if count > 100 {
                vulnerabilities.push(self.create_vulnerability(
                    &domain,
                    "Excessive Subdomains",
                    &format!("{} subdomains", count),
                    &format!("Domain '{}' has {} subdomains", domain, count),
                    "Large number of subdomains may indicate DNS tunneling or malicious activity",
                    Severity::Medium,
                    "CWE-506",
                    5.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Extract parent domain from FQDN
    fn extract_parent_domain(&self, fqdn: &str) -> Option<String> {
        let parts: Vec<&str> = fqdn.split('.').collect();
        if parts.len() >= 2 {
            Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
        } else {
            None
        }
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cf_dns_{}", self.generate_uuid()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloudflare DNS Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn generate_uuid(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!(
            "{:08x}{:04x}{:04x}{:04x}{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u64>() & 0xffffffffffff
        )
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "DNSSEC Not Enabled" => {
                "1. Enable DNSSEC in Cloudflare dashboard (DNS > Settings > DNSSEC)\n\
                 2. Add DS records to your domain registrar\n\
                 3. Verify DNSSEC is properly configured using online validators\n\
                 4. Monitor DNSSEC status regularly\n\
                 5. Ensure key rotation is configured".to_string()
            }
            "Dangling DNS Record" | "Subdomain Takeover Vulnerability" => {
                "1. Remove DNS records pointing to deleted/non-existent resources\n\
                 2. Audit all CNAME records pointing to third-party services\n\
                 3. Implement automated monitoring for subdomain takeovers\n\
                 4. Use Cloudflare's subdomain protection features\n\
                 5. Maintain inventory of all external services and their DNS records".to_string()
            }
            "Missing SPF Record" | "Weak SPF Configuration" => {
                "1. Create SPF record: v=spf1 include:_spf.mx.cloudflare.net ~all\n\
                 2. Include all authorized mail servers in SPF record\n\
                 3. End SPF record with -all or ~all for strict policy\n\
                 4. Keep SPF record under 10 DNS lookups\n\
                 5. Test SPF configuration using online validators".to_string()
            }
            "Missing DMARC Record" | "Weak DMARC Policy" => {
                "1. Create DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\n\
                 2. Start with p=none to monitor, then move to p=quarantine or p=reject\n\
                 3. Configure rua and ruf for aggregate and forensic reports\n\
                 4. Review DMARC reports regularly\n\
                 5. Gradually increase policy strictness".to_string()
            }
            "Missing CAA Record" | "Misconfigured CAA Record" => {
                "1. Add CAA record to authorize specific CAs: issue 'letsencrypt.org'\n\
                 2. Use issuewild for wildcard certificates if needed\n\
                 3. Add iodef for violation notifications\n\
                 4. Review and update CAA records when changing CAs\n\
                 5. Test CAA configuration with online tools".to_string()
            }
            "Wildcard DNS Record" => {
                "1. Review necessity of wildcard DNS records\n\
                 2. Replace wildcards with specific subdomains where possible\n\
                 3. Use Cloudflare's WAF to protect wildcard domains\n\
                 4. Enable rate limiting on wildcard domains\n\
                 5. Monitor wildcard domain usage for anomalies".to_string()
            }
            "Short DNS TTL" => {
                "1. Increase TTL to at least 300 seconds (5 minutes)\n\
                 2. Use longer TTLs (3600-86400s) for stable records\n\
                 3. Only use short TTLs during planned DNS changes\n\
                 4. Restore normal TTLs after DNS migrations\n\
                 5. Monitor DNS query patterns for abuse".to_string()
            }
            "Suspicious DNS Pattern - Potential Tunneling" | "Excessive Subdomains" => {
                "1. Investigate unusual subdomain patterns immediately\n\
                 2. Implement DNS query logging and monitoring\n\
                 3. Use Cloudflare's DNS firewall to block suspicious queries\n\
                 4. Set up alerts for unusual DNS activity\n\
                 5. Review and remove unnecessary DNS records\n\
                 6. Consider implementing NXDOMAIN rate limiting".to_string()
            }
            _ => "Review and remediate according to Cloudflare and DNS security best practices".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_parent_domain() {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let scanner = CloudflareDnsScanner::new(http_client, "test_token".to_string());

        assert_eq!(
            scanner.extract_parent_domain("subdomain.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            scanner.extract_parent_domain("deep.subdomain.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(scanner.extract_parent_domain("example.com"), Some("example.com".to_string()));
    }
}
