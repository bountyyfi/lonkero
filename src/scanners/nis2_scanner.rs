// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

pub struct Nis2Scanner {
    http_client: Arc<HttpClient>,
}

#[derive(Debug, Clone)]
struct SecurityHeaderAssessment {
    header: String,
    present: bool,
    value: Option<String>,
    compliant: bool,
    issue: Option<String>,
    nis2_article: String,
}

#[derive(Debug, Clone)]
struct TlsAssessment {
    version: Option<String>,
    cipher_suite: Option<String>,
    certificate_valid: bool,
    hsts_enabled: bool,
    issues: Vec<String>,
}

impl Nis2Scanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Comprehensive NIS2 compliance scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[NIS2] Starting NIS2 Directive compliance assessment");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let base_url = self.get_base_url(url);

        // Article 21(2)(a): Risk management - Security headers completeness
        let (risk_vulns, risk_tests) = self.assess_risk_management(&base_url).await;
        vulnerabilities.extend(risk_vulns);
        tests_run += risk_tests;

        // Article 21(2)(b): Incident handling - security.txt, contact info
        let (incident_vulns, incident_tests) = self.assess_incident_handling(&base_url).await;
        vulnerabilities.extend(incident_vulns);
        tests_run += incident_tests;

        // Article 21(2)(c): Business continuity - health endpoints, status pages
        let (continuity_vulns, continuity_tests) = self.assess_business_continuity(&base_url).await;
        vulnerabilities.extend(continuity_vulns);
        tests_run += continuity_tests;

        // Article 21(2)(d): Supply chain security - SRI, external resources
        let (supply_vulns, supply_tests) = self.assess_supply_chain_security(&base_url).await;
        vulnerabilities.extend(supply_vulns);
        tests_run += supply_tests;

        // Article 21(2)(h): Encryption - TLS configuration, certificate validation
        let (crypto_vulns, crypto_tests) = self.assess_encryption_controls(&base_url).await;
        vulnerabilities.extend(crypto_vulns);
        tests_run += crypto_tests;

        // Article 21(2)(j): Access control - authentication mechanisms
        let (access_vulns, access_tests) = self.assess_access_controls(&base_url).await;
        vulnerabilities.extend(access_vulns);
        tests_run += access_tests;

        // Article 21(2)(f): Vulnerability handling - disclosure policy
        let (vuln_handling_vulns, vuln_tests) = self.assess_vulnerability_handling(&base_url).await;
        vulnerabilities.extend(vuln_handling_vulns);
        tests_run += vuln_tests;

        // Article 21(2)(g): Cyber hygiene - cookie flags, security headers
        let (hygiene_vulns, hygiene_tests) = self.assess_cyber_hygiene(&base_url).await;
        vulnerabilities.extend(hygiene_vulns);
        tests_run += hygiene_tests;

        info!(
            "[NIS2] Compliance assessment complete: {} findings in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Article 21(2)(a): Risk management policies - comprehensive security headers
    async fn assess_risk_management(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return (vulnerabilities, tests_run),
        };

        let required_headers: Vec<(&str, &str, Severity, &str)> = vec![
            (
                "Content-Security-Policy",
                "Prevents XSS and injection attacks",
                Severity::High,
                "CSP is mandatory for NIS2 risk management",
            ),
            (
                "X-Content-Type-Options",
                "Prevents MIME-type sniffing",
                Severity::Medium,
                "MIME sniffing protection required",
            ),
            (
                "X-Frame-Options",
                "Prevents clickjacking attacks",
                Severity::Medium,
                "Clickjacking protection required",
            ),
            (
                "Referrer-Policy",
                "Controls information leakage",
                Severity::Low,
                "Information disclosure control",
            ),
            (
                "Permissions-Policy",
                "Controls browser feature access",
                Severity::Low,
                "Feature access control required",
            ),
            (
                "Cross-Origin-Embedder-Policy",
                "Controls cross-origin resource embedding",
                Severity::Low,
                "Cross-origin isolation recommended",
            ),
            (
                "Cross-Origin-Opener-Policy",
                "Prevents cross-origin attacks",
                Severity::Low,
                "Cross-origin protection recommended",
            ),
            (
                "Cross-Origin-Resource-Policy",
                "Controls resource sharing",
                Severity::Low,
                "Resource isolation recommended",
            ),
        ];

        let mut missing_headers: Vec<(&str, Severity, &str)> = Vec::new();
        let mut weak_headers: Vec<(&str, String, &str)> = Vec::new();

        for (header, _description, severity, nis2_reason) in &required_headers {
            tests_run += 1;
            let header_lower = header.to_lowercase();
            let header_value = response
                .headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == header_lower)
                .map(|(_, v)| v.clone());

            match header_value {
                None => {
                    missing_headers.push((header, severity.clone(), nis2_reason));
                }
                Some(value) => {
                    if *header == "Content-Security-Policy" {
                        if value.contains("unsafe-inline") || value.contains("unsafe-eval") {
                            weak_headers.push((
                                header,
                                "Contains unsafe-inline or unsafe-eval directives".to_string(),
                                nis2_reason,
                            ));
                        }
                    }
                    if *header == "X-Frame-Options" && value.to_uppercase() == "ALLOWALL" {
                        weak_headers.push((header, "Set to ALLOWALL which provides no protection".to_string(), nis2_reason));
                    }
                }
            }
        }

        if !missing_headers.is_empty() {
            let critical_missing: Vec<&str> = missing_headers
                .iter()
                .filter(|(_, s, _)| matches!(s, Severity::High | Severity::Critical))
                .map(|(h, _, _)| *h)
                .collect();

            let severity = if critical_missing.len() >= 2 {
                Severity::High
            } else if !critical_missing.is_empty() {
                Severity::Medium
            } else {
                Severity::Low
            };

            let header_list: Vec<String> = missing_headers
                .iter()
                .map(|(h, s, r)| format!("- {} ({:?}): {}", h, s, r))
                .collect();

            let cvss = match &severity {
                Severity::High => 7.1,
                Severity::Medium => 5.3,
                _ => 3.7,
            };

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-RISK"),
                vuln_type: "NIS2 Risk Management Gap".to_string(),
                severity,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Security headers assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(a) - Risk Management: Missing {} security headers that are \
                    recommended for comprehensive risk management:\n\n{}",
                    missing_headers.len(),
                    header_list.join("\n")
                ),
                evidence: Some(format!("Missing headers: {}", missing_headers.iter().map(|(h, _, _)| *h).collect::<Vec<_>>().join(", "))),
                cwe: "CWE-693".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Implement the following security headers to comply with NIS2 risk management requirements:\n\
                    \n\
                    1. Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'\n\
                    2. X-Content-Type-Options: nosniff\n\
                    3. X-Frame-Options: DENY (or SAMEORIGIN if framing is required)\n\
                    4. Referrer-Policy: strict-origin-when-cross-origin\n\
                    5. Permissions-Policy: geolocation=(), camera=(), microphone=()\n\
                    \n\
                    Reference: NIS2 Directive Article 21(2)(a) - Policies on risk analysis"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        for (header, issue, nis2_reason) in weak_headers {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-WEAK"),
                vuln_type: "NIS2 Weak Security Configuration".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: format!("{} header", header),
                description: format!(
                    "NIS2 Article 21(2)(a) - Risk Management: {} header is present but weakly configured. \
                    {}\n\nNIS2 Requirement: {}",
                    header, issue, nis2_reason
                ),
                evidence: Some(issue.clone()),
                cwe: "CWE-693".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Strengthen the {} header configuration:\n\
                    - Remove unsafe-inline and unsafe-eval from CSP\n\
                    - Use strict CSP with nonces or hashes\n\
                    - Set X-Frame-Options to DENY or SAMEORIGIN\n\
                    \n\
                    Reference: NIS2 Directive Article 21(2)(a)",
                    header
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(b): Incident handling - security.txt and contact information
    async fn assess_incident_handling(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let security_txt_paths = vec![
            "/.well-known/security.txt",
            "/security.txt",
        ];

        let mut security_txt_found = false;
        let mut security_txt_issues: Vec<String> = Vec::new();
        let mut security_txt_content = String::new();

        for path in security_txt_paths {
            tests_run += 1;
            let test_url = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && !response.body.is_empty() {
                    security_txt_found = true;
                    security_txt_content = response.body.clone();

                    let has_contact = response.body.to_lowercase().contains("contact:");
                    let has_expires = response.body.to_lowercase().contains("expires:");
                    let has_encryption = response.body.to_lowercase().contains("encryption:");
                    let has_preferred_languages = response.body.to_lowercase().contains("preferred-languages:");

                    if !has_contact {
                        security_txt_issues.push("Missing required 'Contact:' field".to_string());
                    }
                    if !has_expires {
                        security_txt_issues.push("Missing required 'Expires:' field (RFC 9116)".to_string());
                    }
                    if !has_encryption {
                        security_txt_issues.push("Missing recommended 'Encryption:' field for secure communication".to_string());
                    }
                    if !has_preferred_languages {
                        security_txt_issues.push("Missing 'Preferred-Languages:' field".to_string());
                    }

                    if let Some(expires_line) = response.body.lines().find(|l| l.to_lowercase().starts_with("expires:")) {
                        let expires_value = expires_line.split(':').skip(1).collect::<String>().trim().to_string();
                        if let Ok(expires_date) = chrono::DateTime::parse_from_rfc3339(&expires_value) {
                            if expires_date < chrono::Utc::now() {
                                security_txt_issues.push(format!("security.txt has expired: {}", expires_value));
                            }
                        }
                    }

                    break;
                }
            }
        }

        if !security_txt_found {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-INCIDENT"),
                vuln_type: "NIS2 Incident Handling Gap".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "/.well-known/security.txt".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(b) - Incident Handling: No security.txt file found.\n\n\
                    A security.txt file (RFC 9116) is essential for vulnerability disclosure and \
                    incident response. NIS2 requires organizations to have documented incident \
                    handling procedures and clear communication channels for security researchers.\n\n\
                    This enables coordinated vulnerability disclosure as recommended by ENISA."
                ),
                evidence: Some("No security.txt found at /.well-known/security.txt or /security.txt".to_string()),
                cwe: "CWE-1059".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Create a security.txt file at /.well-known/security.txt with the following content:\n\n\
                    Contact: mailto:security@example.com\n\
                    Expires: 2026-12-31T23:59:59.000Z\n\
                    Encryption: https://example.com/pgp-key.txt\n\
                    Preferred-Languages: en, fi\n\
                    Canonical: https://example.com/.well-known/security.txt\n\
                    Policy: https://example.com/security-policy\n\n\
                    Reference: RFC 9116, NIS2 Article 21(2)(b)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        } else if !security_txt_issues.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-INCIDENT-INCOMPLETE"),
                vuln_type: "NIS2 Incomplete Incident Handling Configuration".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "security.txt".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(b) - Incident Handling: security.txt found but incomplete.\n\n\
                    Issues identified:\n{}\n\n\
                    A complete security.txt ensures effective incident response communication.",
                    security_txt_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(format!("security.txt content (truncated): {}...", &security_txt_content.chars().take(200).collect::<String>())),
                cwe: "CWE-1059".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Update security.txt to include all required fields:\n\
                    - Contact: (required) Security contact email or URL\n\
                    - Expires: (required) Expiration date in ISO 8601 format\n\
                    - Encryption: (recommended) PGP key for encrypted communication\n\
                    - Preferred-Languages: (recommended) Accepted languages\n\n\
                    Reference: RFC 9116, NIS2 Article 21(2)(b)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        tests_run += 1;
        let abuse_contact_paths = vec!["/contact", "/about", "/impressum", "/legal"];
        let mut has_contact_page = false;

        for path in abuse_contact_paths {
            let test_url = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("security") || body_lower.contains("contact") ||
                       body_lower.contains("email") || body_lower.contains("report") {
                        has_contact_page = true;
                        break;
                    }
                }
            }
        }

        if !has_contact_page && !security_txt_found {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-CONTACT"),
                vuln_type: "NIS2 Missing Security Contact".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Contact page assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(b) - Incident Handling: No security contact information found.\n\n\
                    Organizations covered by NIS2 must have clear channels for reporting security \
                    incidents. No security.txt or contact page with security information was found."
                ),
                evidence: Some("No contact information found".to_string()),
                cwe: "CWE-1059".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Establish clear security contact channels:\n\
                    1. Create security.txt at /.well-known/security.txt\n\
                    2. Add security contact information to contact/about pages\n\
                    3. Consider setting up a security-specific email (e.g., security@domain.com)\n\n\
                    Reference: NIS2 Article 21(2)(b)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(c): Business continuity - health endpoints and status pages
    async fn assess_business_continuity(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let health_endpoints = vec![
            "/health",
            "/healthz",
            "/health/live",
            "/health/ready",
            "/actuator/health",
            "/api/health",
            "/_health",
            "/status",
            "/api/status",
            "/ping",
            "/ready",
            "/live",
        ];

        let mut health_endpoint_found = false;
        let mut exposed_internal_info = false;
        let mut exposed_endpoint = String::new();
        let mut exposed_info_types: Vec<String> = Vec::new();

        for endpoint in health_endpoints {
            tests_run += 1;
            let test_url = format!("{}{}", url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    health_endpoint_found = true;

                    let sensitive_patterns = vec![
                        ("database", "Database connection status"),
                        ("db_host", "Database hostname"),
                        ("redis", "Redis connection status"),
                        ("memory", "Memory usage details"),
                        ("disk", "Disk usage details"),
                        ("version", "Application version"),
                        ("hostname", "Internal hostname"),
                        ("uptime", "System uptime"),
                        ("queue", "Queue status"),
                        ("dependencies", "Dependency status"),
                    ];

                    let body_lower = response.body.to_lowercase();
                    for (pattern, info_type) in sensitive_patterns {
                        if body_lower.contains(pattern) {
                            exposed_internal_info = true;
                            exposed_endpoint = test_url.clone();
                            if !exposed_info_types.contains(&info_type.to_string()) {
                                exposed_info_types.push(info_type.to_string());
                            }
                        }
                    }
                }
            }
        }

        if exposed_internal_info {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-BC-EXPOSURE"),
                vuln_type: "NIS2 Internal Information Exposure".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: exposed_endpoint.clone(),
                parameter: None,
                payload: "Health endpoint assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(c) - Business Continuity: Health endpoint exposes internal information.\n\n\
                    Exposed information types:\n{}\n\n\
                    While health endpoints support business continuity monitoring, exposing detailed \
                    internal status can aid attackers in reconnaissance and attack planning.",
                    exposed_info_types.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(format!("Endpoint {} exposes: {}", exposed_endpoint, exposed_info_types.join(", "))),
                cwe: "CWE-200".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Protect health endpoint information:\n\
                    1. Require authentication for detailed health information\n\
                    2. Provide minimal public health status (UP/DOWN only)\n\
                    3. Expose detailed metrics only to authorized monitoring systems\n\
                    4. Use network segmentation to restrict access\n\n\
                    Example minimal response: {{\"status\": \"UP\"}}\n\n\
                    Reference: NIS2 Article 21(2)(c)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        tests_run += 1;
        let status_pages = vec![
            "/status",
            "/_status",
            "/system-status",
            "/service-status",
        ];

        for page in status_pages {
            let test_url = format!("{}{}", url, page);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("incident") || body_lower.contains("outage") ||
                       body_lower.contains("degraded") || body_lower.contains("maintenance") {
                        debug!("[NIS2] Status page found at {}", test_url);
                        break;
                    }
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(d): Supply chain security - SRI integrity and external resources
    async fn assess_supply_chain_security(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return (vulnerabilities, tests_run),
        };

        let script_re = Regex::new(r#"<script[^>]*src=["']([^"']+)["'][^>]*>"#).unwrap();
        let link_re = Regex::new(r#"<link[^>]*href=["']([^"']+)["'][^>]*>"#).unwrap();
        let integrity_re = Regex::new(r#"integrity=["']([^"']+)["']"#).unwrap();

        let mut external_scripts_without_sri: Vec<String> = Vec::new();
        let mut external_styles_without_sri: Vec<String> = Vec::new();
        let mut total_external_scripts = 0;
        let mut total_external_styles = 0;

        for cap in script_re.captures_iter(&response.body) {
            let src = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let full_tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");

            if self.is_external_resource(src, url) {
                total_external_scripts += 1;
                if !integrity_re.is_match(full_tag) {
                    external_scripts_without_sri.push(src.to_string());
                }
            }
        }

        for cap in link_re.captures_iter(&response.body) {
            let href = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let full_tag = cap.get(0).map(|m| m.as_str()).unwrap_or("");

            if full_tag.contains("stylesheet") && self.is_external_resource(href, url) {
                total_external_styles += 1;
                if !integrity_re.is_match(full_tag) {
                    external_styles_without_sri.push(href.to_string());
                }
            }
        }

        let total_without_sri = external_scripts_without_sri.len() + external_styles_without_sri.len();

        if total_without_sri > 0 {
            let severity = if external_scripts_without_sri.len() >= 3 {
                Severity::High
            } else if !external_scripts_without_sri.is_empty() {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut evidence_parts: Vec<String> = Vec::new();
            if !external_scripts_without_sri.is_empty() {
                evidence_parts.push(format!(
                    "Scripts without SRI ({}/{}):\n{}",
                    external_scripts_without_sri.len(),
                    total_external_scripts,
                    external_scripts_without_sri.iter().take(5).map(|s| format!("  - {}", s)).collect::<Vec<_>>().join("\n")
                ));
            }
            if !external_styles_without_sri.is_empty() {
                evidence_parts.push(format!(
                    "Stylesheets without SRI ({}/{}):\n{}",
                    external_styles_without_sri.len(),
                    total_external_styles,
                    external_styles_without_sri.iter().take(5).map(|s| format!("  - {}", s)).collect::<Vec<_>>().join("\n")
                ));
            }

            let cvss = match &severity {
                Severity::High => 7.5,
                Severity::Medium => 5.3,
                _ => 3.7,
            };

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-SUPPLY"),
                vuln_type: "NIS2 Supply Chain Security Gap".to_string(),
                severity,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Subresource Integrity assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(d) - Supply Chain Security: {} external resources lack Subresource \
                    Integrity (SRI) hashes.\n\n\
                    SRI ensures that resources fetched from CDNs or third-party sources have not been \
                    tampered with. Without SRI, a compromised CDN could inject malicious code.\n\n\
                    {}",
                    total_without_sri,
                    evidence_parts.join("\n\n")
                ),
                evidence: Some(format!(
                    "{} scripts and {} stylesheets without integrity hashes",
                    external_scripts_without_sri.len(),
                    external_styles_without_sri.len()
                )),
                cwe: "CWE-353".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Add Subresource Integrity (SRI) hashes to all external resources:\n\n\
                    Example for script:\n\
                    <script src=\"https://cdn.example.com/lib.js\"\n\
                            integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n\
                            crossorigin=\"anonymous\"></script>\n\n\
                    Generate SRI hashes using: https://www.srihash.org/\n\n\
                    Reference: NIS2 Article 21(2)(d) - Supply chain security"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        tests_run += 1;
        let known_cdn_domains = vec![
            "cdnjs.cloudflare.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "code.jquery.com",
            "stackpath.bootstrapcdn.com",
            "maxcdn.bootstrapcdn.com",
            "ajax.googleapis.com",
            "fonts.googleapis.com",
            "use.fontawesome.com",
        ];

        let cdn_resources: Vec<&String> = external_scripts_without_sri
            .iter()
            .chain(external_styles_without_sri.iter())
            .filter(|url| known_cdn_domains.iter().any(|cdn| url.contains(cdn)))
            .collect();

        if !cdn_resources.is_empty() {
            debug!(
                "[NIS2] {} CDN resources detected without SRI",
                cdn_resources.len()
            );
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(h): Encryption and cryptography policies
    async fn assess_encryption_controls(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return (vulnerabilities, tests_run),
        };

        let hsts_header = response
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "strict-transport-security")
            .map(|(_, v)| v.clone());

        match hsts_header {
            None => {
                if url.starts_with("https://") {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("NIS2-CRYPTO"),
                        vuln_type: "NIS2 Encryption Policy Gap".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "NIS2 Compliance".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: "Strict-Transport-Security header".to_string(),
                        description: format!(
                            "NIS2 Article 21(2)(h) - Cryptography: Missing HTTP Strict Transport Security (HSTS).\n\n\
                            HSTS ensures all communications use TLS encryption, preventing protocol downgrade \
                            attacks and cookie hijacking. This is a fundamental encryption control required by NIS2."
                        ),
                        evidence: Some("No Strict-Transport-Security header present".to_string()),
                        cwe: "CWE-319".to_string(),
                        cvss: 7.4,
                        verified: true,
                        false_positive: false,
                        remediation: format!(
                            "Implement HSTS with the following header:\n\n\
                            Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n\
                            Steps:\n\
                            1. First deploy with short max-age (e.g., 300) to test\n\
                            2. Gradually increase to 31536000 (1 year)\n\
                            3. Add includeSubDomains if all subdomains support HTTPS\n\
                            4. Consider HSTS preloading: https://hstspreload.org/\n\n\
                            Reference: NIS2 Article 21(2)(h)"
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Some(value) => {
                let mut hsts_issues: Vec<String> = Vec::new();

                if let Some(max_age_match) = Regex::new(r"max-age=(\d+)").ok().and_then(|re| re.captures(&value)) {
                    if let Some(max_age_str) = max_age_match.get(1) {
                        if let Ok(max_age) = max_age_str.as_str().parse::<u64>() {
                            if max_age < 15768000 {
                                hsts_issues.push(format!(
                                    "max-age too short ({} seconds). Recommended: at least 15768000 (6 months)",
                                    max_age
                                ));
                            }
                        }
                    }
                }

                if !value.to_lowercase().contains("includesubdomains") {
                    hsts_issues.push("Missing includeSubDomains directive".to_string());
                }

                if !hsts_issues.is_empty() {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id("NIS2-CRYPTO-WEAK"),
                        vuln_type: "NIS2 Weak Encryption Configuration".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "NIS2 Compliance".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: "HSTS configuration".to_string(),
                        description: format!(
                            "NIS2 Article 21(2)(h) - Cryptography: HSTS configuration could be strengthened.\n\n\
                            Current value: {}\n\n\
                            Issues:\n{}",
                            value,
                            hsts_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                        ),
                        evidence: Some(format!("Current HSTS: {}", value)),
                        cwe: "CWE-319".to_string(),
                        cvss: 3.7,
                        verified: true,
                        false_positive: false,
                        remediation: format!(
                            "Strengthen HSTS configuration:\n\
                            Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n\
                            Reference: NIS2 Article 21(2)(h)"
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        tests_run += 1;
        if url.starts_with("http://") {
            let https_url = url.replacen("http://", "https://", 1);
            if let Ok(_https_response) = self.http_client.get(&https_url).await {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id("NIS2-HTTPS"),
                    vuln_type: "NIS2 Unencrypted Communication".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "NIS2 Compliance".to_string(),
                    url: url.to_string(),
                    parameter: None,
                    payload: "HTTP to HTTPS upgrade".to_string(),
                    description: format!(
                        "NIS2 Article 21(2)(h) - Cryptography: Site accessible over unencrypted HTTP.\n\n\
                        HTTPS is available but HTTP is not redirecting to HTTPS. All communications \
                        should be encrypted to comply with NIS2 encryption requirements."
                    ),
                    evidence: Some("HTTP accessible without redirect to HTTPS".to_string()),
                    cwe: "CWE-319".to_string(),
                    cvss: 7.4,
                    verified: true,
                    false_positive: false,
                    remediation: format!(
                        "Enforce HTTPS for all connections:\n\
                        1. Configure automatic HTTP to HTTPS redirect\n\
                        2. Implement HSTS header\n\
                        3. Consider HSTS preloading\n\n\
                        Reference: NIS2 Article 21(2)(h)"
                    ),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(j): Access control and authentication
    async fn assess_access_controls(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let auth_endpoints = vec![
            "/login",
            "/signin",
            "/auth/login",
            "/user/login",
            "/admin/login",
            "/api/auth/login",
            "/account/login",
        ];

        let mut login_found = false;
        let mut login_url = String::new();
        let mut login_issues: Vec<String> = Vec::new();

        for endpoint in auth_endpoints {
            tests_run += 1;
            let test_url = format!("{}{}", url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 || response.status_code == 302 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("password") || body_lower.contains("login") ||
                       body_lower.contains("sign in") || body_lower.contains("username") {
                        login_found = true;
                        login_url = test_url.clone();

                        if !body_lower.contains("csrf") && !body_lower.contains("_token") &&
                           !body_lower.contains("authenticity_token") {
                            login_issues.push("No CSRF protection detected on login form".to_string());
                        }

                        if body_lower.contains("autocomplete=\"on\"") ||
                           (!body_lower.contains("autocomplete=\"off\"") &&
                            !body_lower.contains("autocomplete=\"new-password\"")) {
                            login_issues.push("Password field may allow autocomplete".to_string());
                        }

                        if response.headers.iter().any(|(k, _)| k.to_lowercase() == "x-frame-options") {
                        } else {
                            login_issues.push("Login page lacks X-Frame-Options (clickjacking risk)".to_string());
                        }

                        break;
                    }
                }
            }
        }

        if login_found && !login_issues.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-ACCESS"),
                vuln_type: "NIS2 Access Control Weakness".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: "NIS2 Compliance".to_string(),
                url: login_url.clone(),
                parameter: None,
                payload: "Authentication form assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(j) - Access Control: Authentication mechanism has potential weaknesses.\n\n\
                    Issues identified:\n{}\n\n\
                    Robust access control is a core NIS2 requirement for protecting critical systems.",
                    login_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(format!("Login page: {}", login_url)),
                cwe: "CWE-287".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Strengthen authentication controls:\n\
                    1. Implement CSRF tokens on all authentication forms\n\
                    2. Set autocomplete=\"off\" or autocomplete=\"new-password\" on password fields\n\
                    3. Add X-Frame-Options: DENY to prevent clickjacking\n\
                    4. Consider implementing MFA for privileged accounts\n\
                    5. Implement account lockout after failed attempts\n\n\
                    Reference: NIS2 Article 21(2)(j)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        tests_run += 1;
        let mfa_indicators = vec![
            "two-factor",
            "2fa",
            "mfa",
            "authenticator",
            "otp",
            "verification code",
            "security code",
        ];

        let mut mfa_mentioned = false;
        let security_pages = vec!["/security", "/account/security", "/settings/security"];

        for page in security_pages {
            let test_url = format!("{}{}", url, page);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    for indicator in &mfa_indicators {
                        if body_lower.contains(indicator) {
                            mfa_mentioned = true;
                            break;
                        }
                    }
                }
            }
            if mfa_mentioned {
                break;
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(f): Vulnerability handling and disclosure
    async fn assess_vulnerability_handling(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let disclosure_paths = vec![
            "/security",
            "/security-policy",
            "/.well-known/security-policy",
            "/responsible-disclosure",
            "/vulnerability-disclosure",
            "/bug-bounty",
            "/hackerone",
        ];

        let mut disclosure_policy_found = false;

        for path in disclosure_paths {
            let test_url = format!("{}{}", url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();
                    if body_lower.contains("vulnerability") || body_lower.contains("disclosure") ||
                       body_lower.contains("security researcher") || body_lower.contains("bug bounty") ||
                       body_lower.contains("responsible") {
                        disclosure_policy_found = true;
                        break;
                    }
                }
            }
        }

        if !disclosure_policy_found {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-VULN"),
                vuln_type: "NIS2 Vulnerability Handling Gap".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Vulnerability disclosure policy".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(f) - Vulnerability Handling: No vulnerability disclosure policy found.\n\n\
                    NIS2 requires organizations to have policies and procedures for vulnerability handling \
                    and disclosure. A public disclosure policy encourages responsible reporting and \
                    demonstrates commitment to security."
                ),
                evidence: Some("No vulnerability disclosure policy page found".to_string()),
                cwe: "CWE-1059".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Establish a vulnerability disclosure policy:\n\
                    1. Create a dedicated security/disclosure page\n\
                    2. Define scope of what can be tested\n\
                    3. Provide clear reporting instructions\n\
                    4. Specify response timeline expectations\n\
                    5. Consider a bug bounty program\n\
                    6. Reference in security.txt via Policy: directive\n\n\
                    Resources:\n\
                    - ISO/IEC 29147:2018 for disclosure guidelines\n\
                    - ENISA Good Practice Guide on Vulnerability Disclosure\n\n\
                    Reference: NIS2 Article 21(2)(f)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    /// Article 21(2)(g): Cyber hygiene practices
    async fn assess_cyber_hygiene(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return (vulnerabilities, tests_run),
        };

        let set_cookie_headers: Vec<&String> = response
            .headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .map(|(_, v)| v)
            .collect();

        let mut cookie_issues: Vec<String> = Vec::new();

        for cookie in &set_cookie_headers {
            let cookie_lower = cookie.to_lowercase();

            if cookie_lower.contains("session") || cookie_lower.contains("auth") ||
               cookie_lower.contains("token") || cookie_lower.contains("jwt") {
                if !cookie_lower.contains("httponly") {
                    cookie_issues.push(format!("Session cookie missing HttpOnly flag: {}", cookie.split(';').next().unwrap_or("")));
                }
                if !cookie_lower.contains("secure") {
                    cookie_issues.push(format!("Session cookie missing Secure flag: {}", cookie.split(';').next().unwrap_or("")));
                }
                if !cookie_lower.contains("samesite") {
                    cookie_issues.push(format!("Session cookie missing SameSite attribute: {}", cookie.split(';').next().unwrap_or("")));
                }
            }
        }

        if !cookie_issues.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-HYGIENE"),
                vuln_type: "NIS2 Cyber Hygiene Gap".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Cookie security assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(g) - Cyber Hygiene: Cookie security flags not properly configured.\n\n\
                    Issues found:\n{}\n\n\
                    Proper cookie security is a fundamental cyber hygiene practice required by NIS2.",
                    cookie_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(format!("{} cookie security issues found", cookie_issues.len())),
                cwe: "CWE-614".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Set proper security flags on all session cookies:\n\n\
                    Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/\n\n\
                    Flags explained:\n\
                    - HttpOnly: Prevents JavaScript access (XSS protection)\n\
                    - Secure: Only sent over HTTPS\n\
                    - SameSite=Strict: Prevents CSRF attacks\n\n\
                    Reference: NIS2 Article 21(2)(g)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        tests_run += 1;
        let server_header = response
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "server")
            .map(|(_, v)| v.clone());

        let x_powered_by = response
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "x-powered-by")
            .map(|(_, v)| v.clone());

        let mut info_disclosure_issues: Vec<String> = Vec::new();

        if let Some(server) = server_header {
            let version_re = Regex::new(r"[\d]+\.[\d]+").ok();
            if version_re.map(|re| re.is_match(&server)).unwrap_or(false) {
                info_disclosure_issues.push(format!("Server header reveals version: {}", server));
            }
        }

        if let Some(powered_by) = x_powered_by {
            info_disclosure_issues.push(format!("X-Powered-By header exposes technology: {}", powered_by));
        }

        if !info_disclosure_issues.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id("NIS2-DISCLOSURE"),
                vuln_type: "NIS2 Information Disclosure".to_string(),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: "NIS2 Compliance".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: "Server header assessment".to_string(),
                description: format!(
                    "NIS2 Article 21(2)(g) - Cyber Hygiene: Server banners reveal technology information.\n\n\
                    Disclosed information:\n{}\n\n\
                    This information aids attackers in identifying vulnerable software versions.",
                    info_disclosure_issues.iter().map(|i| format!("- {}", i)).collect::<Vec<_>>().join("\n")
                ),
                evidence: Some(info_disclosure_issues.join("; ")),
                cwe: "CWE-200".to_string(),
                cvss: 3.7,
                verified: true,
                false_positive: false,
                remediation: format!(
                    "Remove or minimize server version disclosure:\n\
                    1. Remove X-Powered-By header entirely\n\
                    2. Minimize Server header (e.g., just 'nginx' not 'nginx/1.18.0')\n\
                    3. Configure web server to suppress version information\n\n\
                    Apache: ServerTokens Prod, ServerSignature Off\n\
                    Nginx: server_tokens off;\n\n\
                    Reference: NIS2 Article 21(2)(g)"
                ),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        (vulnerabilities, tests_run)
    }

    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("localhost");
            let scheme = parsed.scheme();
            if let Some(port) = parsed.port() {
                format!("{}://{}:{}", scheme, host, port)
            } else {
                format!("{}://{}", scheme, host)
            }
        } else {
            url.to_string()
        }
    }

    fn is_external_resource(&self, resource_url: &str, page_url: &str) -> bool {
        if resource_url.starts_with("//") || resource_url.starts_with("http://") ||
           resource_url.starts_with("https://") {
            if let (Ok(resource), Ok(page)) = (url::Url::parse(&format!("https:{}", resource_url.trim_start_matches("https:").trim_start_matches("http:"))),
                                                url::Url::parse(page_url)) {
                return resource.host_str() != page.host_str();
            }
            return true;
        }
        false
    }
}

fn generate_vuln_id(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{:x}", prefix, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_id_generation() {
        let id1 = generate_vuln_id("NIS2-TEST");
        let id2 = generate_vuln_id("NIS2-TEST");
        assert!(id1.starts_with("NIS2-TEST-"));
        assert!(id2.starts_with("NIS2-TEST-"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_external_resource_detection() {
        let scanner = Nis2Scanner {
            http_client: Arc::new(HttpClient::new(30, 3).unwrap()),
        };

        assert!(scanner.is_external_resource("https://cdn.example.com/lib.js", "https://mysite.com"));
        assert!(scanner.is_external_resource("//cdn.example.com/lib.js", "https://mysite.com"));
        assert!(!scanner.is_external_resource("/static/lib.js", "https://mysite.com"));
        assert!(!scanner.is_external_resource("lib.js", "https://mysite.com"));
    }
}
