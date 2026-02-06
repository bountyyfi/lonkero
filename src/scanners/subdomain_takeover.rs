// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Subdomain takeover service fingerprint
#[derive(Debug, Clone)]
struct ServiceFingerprint {
    /// Service/provider name
    name: &'static str,
    /// CNAME patterns that indicate this service
    cname_patterns: &'static [&'static str],
    /// HTTP response body patterns indicating vulnerability
    http_signatures: &'static [&'static str],
    /// HTTP headers that confirm the service
    header_patterns: &'static [(&'static str, &'static str)],
    /// Whether an NXDOMAIN response indicates vulnerability
    nxdomain_vulnerable: bool,
    /// Base severity when vulnerable
    severity: Severity,
    /// CVSS score
    cvss: f32,
    /// Whether takeover is confirmed exploitable
    confirmed_exploitable: bool,
    /// Remediation advice
    remediation: &'static str,
}

/// All supported service fingerprints
const SERVICE_FINGERPRINTS: &[ServiceFingerprint] = &[
    // AWS S3
    ServiceFingerprint {
        name: "AWS S3",
        cname_patterns: &[".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"],
        http_signatures: &[
            "NoSuchBucket",
            "The specified bucket does not exist",
            "BucketNotFound",
        ],
        header_patterns: &[("x-amz-request-id", ""), ("server", "AmazonS3")],
        nxdomain_vulnerable: false,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the DNS CNAME record pointing to the non-existent S3 bucket, or recreate the bucket with the same name to claim it before an attacker does.",
    },
    // AWS CloudFront
    ServiceFingerprint {
        name: "AWS CloudFront",
        cname_patterns: &[".cloudfront.net"],
        http_signatures: &[
            "The request could not be satisfied",
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        header_patterns: &[("server", "CloudFront"), ("x-amz-cf-pop", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.5,
        confirmed_exploitable: true,
        remediation: "Remove the DNS CNAME record pointing to CloudFront, or configure a new CloudFront distribution with this alternate domain name.",
    },
    // Azure Web Apps
    ServiceFingerprint {
        name: "Azure Web Apps",
        cname_patterns: &[".azurewebsites.net", ".azure-mobile.net"],
        http_signatures: &[
            "404 Web Site not found",
            "Azure Error",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to Azure, or create a new Azure Web App with the matching hostname.",
    },
    // Azure Cloud Apps
    ServiceFingerprint {
        name: "Azure Cloud Apps",
        cname_patterns: &[".cloudapp.azure.com", ".cloudapp.net"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::Critical,
        cvss: 9.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or claim the Azure Cloud Service resource.",
    },
    // Azure Traffic Manager
    ServiceFingerprint {
        name: "Azure Traffic Manager",
        cname_patterns: &[".trafficmanager.net"],
        http_signatures: &[],
        header_patterns: &[],
        nxdomain_vulnerable: true,
        severity: Severity::High,
        cvss: 8.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or create a new Traffic Manager profile with the matching DNS name.",
    },
    // GitHub Pages
    ServiceFingerprint {
        name: "GitHub Pages",
        cname_patterns: &[".github.io", "github.map.fastly.net"],
        http_signatures: &[
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        header_patterns: &[("server", "GitHub.com")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to GitHub Pages, or configure a GitHub repository with this custom domain.",
    },
    // Heroku
    ServiceFingerprint {
        name: "Heroku",
        cname_patterns: &[".herokuapp.com", ".herokucdn.com", ".herokudns.com"],
        http_signatures: &[
            "No such app",
            "herokucdn.com/error-pages/",
            "There's nothing here, yet",
        ],
        header_patterns: &[("server", "Cowboy")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record pointing to Heroku, or create a new Heroku app with the matching domain configuration.",
    },
    // Shopify
    ServiceFingerprint {
        name: "Shopify",
        cname_patterns: &[".myshopify.com", "shops.myshopify.com"],
        http_signatures: &[
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        header_patterns: &[("x-shopify-stage", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Shopify store's settings.",
    },
    // Fastly
    ServiceFingerprint {
        name: "Fastly",
        cname_patterns: &[".fastly.net", ".fastlylb.net", ".map.fastly.net"],
        http_signatures: &[
            "Fastly error: unknown domain",
            "Fastly error:",
        ],
        header_patterns: &[("server", "Varnish"), ("via", "varnish")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Fastly service.",
    },
    // Pantheon
    ServiceFingerprint {
        name: "Pantheon",
        cname_patterns: &[".pantheonsite.io", ".pantheon.io"],
        http_signatures: &[
            "The gods are wise, but do not know of the site",
            "404 Unknown Site",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Pantheon.",
    },
    // Tumblr
    ServiceFingerprint {
        name: "Tumblr",
        cname_patterns: &[".tumblr.com", "domains.tumblr.com"],
        http_signatures: &[
            "There's nothing here",
            "Whatever you were looking for doesn't currently exist",
        ],
        header_patterns: &[("x-tumblr-user", "")],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain on a Tumblr blog.",
    },
    // Zendesk
    ServiceFingerprint {
        name: "Zendesk",
        cname_patterns: &[".zendesk.com", "zendesk.com"],
        http_signatures: &[
            "Help Center Closed",
            "This help center no longer exists",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Zendesk.",
    },
    // Netlify
    ServiceFingerprint {
        name: "Netlify",
        cname_patterns: &[".netlify.app", ".netlify.com", ".bitballoon.com"],
        http_signatures: &[
            "Not Found - Request ID:",
            "Page Not Found",
        ],
        header_patterns: &[("server", "Netlify")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain on a Netlify site.",
    },
    // Ghost
    ServiceFingerprint {
        name: "Ghost",
        cname_patterns: &[".ghost.io", ".ghost.org"],
        http_signatures: &[
            "The thing you were looking for is no longer here",
            "Ghost site not found",
        ],
        header_patterns: &[("x-powered-by", "Ghost")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Ghost.",
    },
    // Surge.sh
    ServiceFingerprint {
        name: "Surge.sh",
        cname_patterns: &[".surge.sh", "na-west1.surge.sh"],
        http_signatures: &[
            "project not found",
        ],
        header_patterns: &[("server", "SurgeSH")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or deploy a project to Surge.sh with this domain.",
    },
    // Bitbucket
    ServiceFingerprint {
        name: "Bitbucket",
        cname_patterns: &[".bitbucket.io", ".bitbucket.org"],
        http_signatures: &[
            "Repository not found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure Bitbucket Cloud repository to use this domain.",
    },
    // Cargo (crates.io documentation)
    ServiceFingerprint {
        name: "Cargo/crates.io",
        cname_patterns: &[".crates.io", ".docs.rs"],
        http_signatures: &[
            "404: This page could not be found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: false,
        remediation: "Remove the CNAME record pointing to Cargo/crates.io.",
    },
    // Fly.io
    ServiceFingerprint {
        name: "Fly.io",
        cname_patterns: &[".fly.dev", ".fly.io"],
        http_signatures: &[
            "404 Not Found",
        ],
        header_patterns: &[("server", "Fly/"), ("fly-request-id", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Fly.io application.",
    },
    // Vercel
    ServiceFingerprint {
        name: "Vercel",
        cname_patterns: &[".vercel.app", ".now.sh", ".vercel.com"],
        http_signatures: &[
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found",
        ],
        header_patterns: &[("server", "Vercel"), ("x-vercel-id", "")],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in a Vercel project.",
    },
    // WordPress.com
    ServiceFingerprint {
        name: "WordPress.com",
        cname_patterns: &[".wordpress.com", "lb.wordpress.com"],
        http_signatures: &[
            "Do you want to register",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in WordPress.com.",
    },
    // Tilda
    ServiceFingerprint {
        name: "Tilda",
        cname_patterns: &[".tilda.ws", ".tildacdn.com"],
        http_signatures: &[
            "Please renew your subscription",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Tilda.",
    },
    // Agile CRM
    ServiceFingerprint {
        name: "Agile CRM",
        cname_patterns: &[".agilecrm.com"],
        http_signatures: &[
            "Sorry, this page is no longer available",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Agile CRM.",
    },
    // UserVoice
    ServiceFingerprint {
        name: "UserVoice",
        cname_patterns: &[".uservoice.com"],
        http_signatures: &[
            "This UserVoice subdomain is currently available",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::High,
        cvss: 8.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in UserVoice.",
    },
    // Cargo Collective
    ServiceFingerprint {
        name: "Cargo Collective",
        cname_patterns: &[".cargocollective.com", "subdomain.cargocollective.com"],
        http_signatures: &[
            "404 Not Found",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 6.5,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Cargo Collective.",
    },
    // Help Scout
    ServiceFingerprint {
        name: "Help Scout",
        cname_patterns: &[".helpscoutdocs.com", "secure.helpscout.net"],
        http_signatures: &[
            "No settings were found for this company",
        ],
        header_patterns: &[],
        nxdomain_vulnerable: false,
        severity: Severity::Medium,
        cvss: 7.0,
        confirmed_exploitable: true,
        remediation: "Remove the CNAME record or configure the domain in Help Scout.",
    },
];

/// DNS resolution result for a subdomain
#[derive(Debug, Clone)]
struct DnsResult {
    subdomain: String,
    cname_records: Vec<String>,
    a_records: Vec<String>,
    is_nxdomain: bool,
    matched_service: Option<String>,
}

/// Subdomain takeover scanner
pub struct SubdomainTakeoverScanner {
    http_client: Arc<HttpClient>,
}

impl SubdomainTakeoverScanner {
    /// Create a new subdomain takeover scanner
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a target URL for subdomain takeover vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!("[SubdomainTakeover] Starting scan for: {}", url);

        let vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response for context awareness
        tests_run += 1;
        let _baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(e) => {
                debug!("[SubdomainTakeover] Failed to get baseline: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Extract domain from URL
        let domain = match self.extract_domain(url) {
            Some(d) => d,
            None => {
                info!("[SubdomainTakeover] Could not extract domain from URL");
                return Ok((vulnerabilities, tests_run));
            }
        };

        info!("[SubdomainTakeover] Scanning domain: {}", domain);

        // Check if subdomain enumeration is enabled or if we should enumerate
        let subdomains = if config.enum_subdomains || config.subdomain_extended() {
            // Use comprehensive subdomain enumeration
            self.enumerate_subdomains(&domain, config.subdomain_extended())
                .await
        } else {
            // Just check the main domain and www
            vec![domain.clone(), format!("www.{}", domain)]
        };

        if subdomains.is_empty() {
            info!("[SubdomainTakeover] No subdomains to check");
            return Ok((vulnerabilities, tests_run));
        }

        info!(
            "[SubdomainTakeover] Checking {} subdomains for takeover vulnerabilities",
            subdomains.len()
        );

        // DNS resolver setup
        let resolver = match self.create_resolver().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[SubdomainTakeover] Failed to create DNS resolver: {}", e);
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Scan all subdomains in parallel
        let tests_completed = Arc::new(AtomicUsize::new(0));
        let vulns = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(resolver);

        // High concurrency for DNS lookups
        let concurrent_requests = 50;

        stream::iter(subdomains)
            .for_each_concurrent(concurrent_requests, |subdomain| {
                let resolver = Arc::clone(&resolver);
                let client = Arc::clone(&self.http_client);
                let tests_completed = Arc::clone(&tests_completed);
                let vulns = Arc::clone(&vulns);

                async move {
                    // DNS resolution
                    tests_completed.fetch_add(1, Ordering::Relaxed);

                    let dns_result = Self::resolve_subdomain(&resolver, &subdomain).await;

                    if let Some(result) = dns_result {
                        // Check for NXDOMAIN vulnerabilities
                        if result.is_nxdomain {
                            if let Some(vuln) = Self::check_nxdomain_vulnerability(&result).await {
                                let mut v = vulns.lock().await;
                                v.push(vuln);
                                return;
                            }
                        }

                        // Check for CNAME-based vulnerabilities
                        if !result.cname_records.is_empty() {
                            for cname in &result.cname_records {
                                if let Some(fingerprint) = Self::match_cname_to_service(cname) {
                                    // HTTP verification
                                    tests_completed.fetch_add(1, Ordering::Relaxed);

                                    if let Some(vuln) = Self::verify_http_vulnerability(
                                        &client,
                                        &result.subdomain,
                                        cname,
                                        fingerprint,
                                    )
                                    .await
                                    {
                                        info!(
                                            "[ALERT] Subdomain takeover found: {} -> {} ({})",
                                            result.subdomain, cname, fingerprint.name
                                        );
                                        let mut v = vulns.lock().await;
                                        v.push(vuln);
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .await;

        // Extract results
        let final_vulns = match Arc::try_unwrap(vulns) {
            Ok(mutex) => mutex.into_inner(),
            Err(arc) => {
                let guard = arc.lock().await;
                guard.clone()
            }
        };

        tests_run += tests_completed.load(Ordering::Relaxed);

        info!(
            "[SUCCESS] [SubdomainTakeover] Completed {} tests, found {} vulnerabilities",
            tests_run,
            final_vulns.len()
        );

        Ok((final_vulns, tests_run))
    }

    /// Extract the domain from a URL
    fn extract_domain(&self, url: &str) -> Option<String> {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
    }

    /// Create a DNS resolver
    async fn create_resolver(&self) -> Result<TokioResolver> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .map_err(|e| anyhow::anyhow!("Failed to create resolver: {}", e))?
            .build();
        Ok(resolver)
    }

    /// Enumerate subdomains for a domain
    async fn enumerate_subdomains(&self, domain: &str, thorough: bool) -> Vec<String> {
        let mut subdomains = Vec::new();

        // Common subdomain prefixes
        let common_prefixes = vec![
            "www",
            "api",
            "admin",
            "dev",
            "staging",
            "test",
            "qa",
            "uat",
            "mail",
            "smtp",
            "ftp",
            "vpn",
            "remote",
            "blog",
            "shop",
            "store",
            "cdn",
            "static",
            "assets",
            "media",
            "m",
            "mobile",
            "app",
            "portal",
            "dashboard",
            "panel",
            "beta",
            "alpha",
            "demo",
            "git",
            "gitlab",
            "jenkins",
            "ci",
            "jira",
            "confluence",
            "wiki",
            "status",
            "monitor",
            "db",
            "mysql",
            "postgres",
            "redis",
            "backup",
            "old",
            "new",
            "legacy",
            "v1",
            "v2",
            "ws",
            "graphql",
            "docs",
            "help",
            "support",
            "secure",
            "login",
            "auth",
            "oauth",
            "payment",
            "internal",
            "corp",
            "intranet",
        ];

        // Extended prefixes for thorough scanning
        let extended_prefixes = vec![
            "autodiscover",
            "autoconfig",
            "cpanel",
            "whm",
            "plesk",
            "webdisk",
            "webmail",
            "email",
            "mx",
            "ns1",
            "ns2",
            "ftp2",
            "files",
            "download",
            "upload",
            "ssl",
            "tls",
            "test1",
            "test2",
            "dev1",
            "dev2",
            "stage",
            "staging1",
            "staging2",
            "prod",
            "production",
            "lb",
            "loadbalancer",
            "proxy",
            "gateway",
            "cdn1",
            "cdn2",
            "static1",
            "static2",
            "img",
            "images",
            "video",
            "stream",
            "chat",
            "crm",
            "erp",
            "hr",
            "finance",
            "reports",
            "analytics",
            "stats",
            "logging",
            "logs",
        ];

        let prefixes: Vec<&str> = if thorough {
            common_prefixes
                .iter()
                .chain(extended_prefixes.iter())
                .cloned()
                .collect()
        } else {
            common_prefixes
        };

        // Generate subdomains
        for prefix in prefixes {
            subdomains.push(format!("{}.{}", prefix, domain));
        }

        // Add the base domain
        subdomains.push(domain.to_string());

        subdomains
    }

    /// Resolve a subdomain's DNS records
    async fn resolve_subdomain(resolver: &TokioResolver, subdomain: &str) -> Option<DnsResult> {
        let mut result = DnsResult {
            subdomain: subdomain.to_string(),
            cname_records: Vec::new(),
            a_records: Vec::new(),
            is_nxdomain: false,
            matched_service: None,
        };

        // Query CNAME records
        match resolver
            .lookup(subdomain, hickory_resolver::proto::rr::RecordType::CNAME)
            .await
        {
            Ok(response) => {
                for record in response.iter() {
                    if let Some(cname) = record.as_cname() {
                        result.cname_records.push(cname.0.to_string());
                    }
                }
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("nxdomain") || error_str.contains("no name") {
                    result.is_nxdomain = true;
                }
            }
        }

        // Query A records
        match resolver.lookup_ip(subdomain).await {
            Ok(response) => {
                for ip in response.iter() {
                    result.a_records.push(ip.to_string());
                }
            }
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("nxdomain") || error_str.contains("no name") {
                    result.is_nxdomain = true;
                }
            }
        }

        // Only return if we have results or NXDOMAIN
        if result.is_nxdomain || !result.cname_records.is_empty() || !result.a_records.is_empty() {
            Some(result)
        } else {
            None
        }
    }

    /// Match a CNAME record to a known vulnerable service
    fn match_cname_to_service(cname: &str) -> Option<&'static ServiceFingerprint> {
        let cname_lower = cname.to_lowercase();

        for fingerprint in SERVICE_FINGERPRINTS {
            for pattern in fingerprint.cname_patterns {
                if cname_lower.contains(pattern) {
                    return Some(fingerprint);
                }
            }
        }

        None
    }

    /// Check for NXDOMAIN-based vulnerabilities
    async fn check_nxdomain_vulnerability(dns_result: &DnsResult) -> Option<Vulnerability> {
        // Check if any known service is vulnerable to NXDOMAIN takeover
        for cname in &dns_result.cname_records {
            if let Some(fingerprint) = Self::match_cname_to_service(cname) {
                if fingerprint.nxdomain_vulnerable {
                    return Some(Self::create_vulnerability(
                        &dns_result.subdomain,
                        cname,
                        fingerprint,
                        "NXDOMAIN response indicates the underlying service has been decommissioned",
                        Confidence::High,
                    ));
                }
            }
        }

        None
    }

    /// Verify vulnerability via HTTP response
    async fn verify_http_vulnerability(
        client: &HttpClient,
        subdomain: &str,
        cname: &str,
        fingerprint: &'static ServiceFingerprint,
    ) -> Option<Vulnerability> {
        // Try both HTTP and HTTPS
        for scheme in &["https", "http"] {
            let url = format!("{}://{}", scheme, subdomain);

            match client.get(&url).await {
                Ok(response) => {
                    // Check HTTP signatures
                    let body_lower = response.body.to_lowercase();

                    for signature in fingerprint.http_signatures {
                        if body_lower.contains(&signature.to_lowercase()) {
                            let evidence = format!(
                                "HTTP response contains takeover signature: '{}'. CNAME: {} -> {}",
                                signature, subdomain, cname
                            );

                            return Some(Self::create_vulnerability(
                                subdomain,
                                cname,
                                fingerprint,
                                &evidence,
                                Confidence::High,
                            ));
                        }
                    }

                    // Check header patterns
                    for (header_name, expected_value) in fingerprint.header_patterns {
                        if let Some(header_value) = response.header(header_name) {
                            if expected_value.is_empty() || header_value.contains(expected_value) {
                                // Header matches - do additional body check for Fly.io
                                if fingerprint.name == "Fly.io" {
                                    // Fly.io needs specific 404 pattern
                                    if body_lower.contains("404 not found")
                                        && !body_lower.contains("your app")
                                    {
                                        let evidence = format!(
                                            "Fly.io 404 response with fly-request-id header. CNAME: {} -> {}",
                                            subdomain, cname
                                        );
                                        return Some(Self::create_vulnerability(
                                            subdomain,
                                            cname,
                                            fingerprint,
                                            &evidence,
                                            Confidence::Medium,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("[SubdomainTakeover] HTTP request failed for {}: {}", url, e);
                    // Connection errors to known services might also indicate vulnerability
                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("connection refused")
                        || error_str.contains("no route to host")
                    {
                        // Could indicate the service is down/decommissioned
                        debug!(
                            "[SubdomainTakeover] Connection error may indicate vulnerability: {}",
                            subdomain
                        );
                    }
                }
            }
        }

        None
    }

    /// Create a vulnerability report
    fn create_vulnerability(
        subdomain: &str,
        cname: &str,
        fingerprint: &'static ServiceFingerprint,
        evidence: &str,
        confidence: Confidence,
    ) -> Vulnerability {
        let description = format!(
            "Subdomain {} is vulnerable to takeover. The CNAME record points to {} ({}) \
            which appears to be unclaimed or decommissioned. An attacker could register this \
            resource on the {} platform and serve malicious content on your domain, potentially \
            enabling phishing attacks, cookie theft, and reputation damage.",
            subdomain, cname, fingerprint.name, fingerprint.name
        );

        let remediation = format!(
            "IMMEDIATE ACTION REQUIRED:\n\n\
            1. **Primary Fix**: {}\n\n\
            2. **Verify the Fix**:\n\
               - After making DNS changes, wait for TTL expiration (check current TTL)\n\
               - Verify with: `dig {} CNAME +short`\n\
               - Confirm the CNAME no longer points to {}\n\n\
            3. **Prevent Future Occurrences**:\n\
               - Implement a process to review DNS records when decommissioning services\n\
               - Use DNS monitoring to detect dangling records\n\
               - Document all external service dependencies\n\n\
            4. **If Already Exploited**:\n\
               - Check if attacker has claimed the resource\n\
               - Review access logs for suspicious activity\n\
               - Consider notifying affected users if cookies/sessions were at risk\n\n\
            References:\n\
            - OWASP: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover\n\
            - CWE-284: https://cwe.mitre.org/data/definitions/284.html",
            fingerprint.remediation,
            subdomain,
            fingerprint.name
        );

        Vulnerability {
            id: format!("subdomain_takeover_{:x}", rand::random::<u32>()),
            vuln_type: format!("Subdomain Takeover - {}", fingerprint.name),
            severity: fingerprint.severity.clone(),
            confidence,
            category: "DNS Security".to_string(),
            url: format!("https://{}", subdomain),
            parameter: Some("CNAME".to_string()),
            payload: cname.to_string(),
            description,
            evidence: Some(evidence.to_string()),
            cwe: "CWE-284".to_string(), // Improper Access Control
            cvss: fingerprint.cvss,
            verified: fingerprint.confirmed_exploitable,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

/// Scan a target for subdomain takeover vulnerabilities
/// Convenience function for use by the scanner registry
pub async fn scan_subdomain_takeover(
    http_client: Arc<HttpClient>,
    url: &str,
    config: &ScanConfig,
) -> Result<(Vec<Vulnerability>, usize)> {
    let scanner = SubdomainTakeoverScanner::new(http_client);
    scanner.scan(url, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cname_matching() {
        // Test AWS S3
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("mybucket.s3.amazonaws.com").is_some()
        );

        // Test GitHub Pages
        assert!(SubdomainTakeoverScanner::match_cname_to_service("myorg.github.io").is_some());

        // Test Azure
        assert!(
            SubdomainTakeoverScanner::match_cname_to_service("myapp.azurewebsites.net").is_some()
        );

        // Test Heroku
        assert!(SubdomainTakeoverScanner::match_cname_to_service("myapp.herokuapp.com").is_some());

        // Test unknown service
        assert!(SubdomainTakeoverScanner::match_cname_to_service("unknown.example.com").is_none());
    }

    #[test]
    fn test_fingerprint_coverage() {
        // Ensure we have all the required services
        let service_names: Vec<&str> = SERVICE_FINGERPRINTS.iter().map(|f| f.name).collect();

        assert!(service_names.contains(&"AWS S3"));
        assert!(service_names.contains(&"AWS CloudFront"));
        assert!(service_names.contains(&"Azure Web Apps"));
        assert!(service_names.contains(&"GitHub Pages"));
        assert!(service_names.contains(&"Heroku"));
        assert!(service_names.contains(&"Shopify"));
        assert!(service_names.contains(&"Fastly"));
        assert!(service_names.contains(&"Pantheon"));
        assert!(service_names.contains(&"Tumblr"));
        assert!(service_names.contains(&"Zendesk"));
        assert!(service_names.contains(&"Netlify"));
        assert!(service_names.contains(&"Ghost"));
        assert!(service_names.contains(&"Surge.sh"));
        assert!(service_names.contains(&"Bitbucket"));
        assert!(service_names.contains(&"Fly.io"));
        assert!(service_names.contains(&"Vercel"));
    }

    #[test]
    fn test_severity_levels() {
        for fingerprint in SERVICE_FINGERPRINTS {
            // All services should have High or Critical severity
            assert!(
                matches!(
                    fingerprint.severity,
                    Severity::High | Severity::Critical | Severity::Medium
                ),
                "Service {} has unexpected severity",
                fingerprint.name
            );

            // CVSS should be reasonable
            assert!(
                fingerprint.cvss >= 6.0 && fingerprint.cvss <= 10.0,
                "Service {} has unreasonable CVSS score",
                fingerprint.name
            );
        }
    }
}
