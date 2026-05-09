// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct JoomlaScanner {
    http_client: Arc<HttpClient>,
    known_vulnerabilities: HashMap<String, Vec<JoomlaVulnerability>>,
}

#[derive(Clone)]
struct JoomlaVulnerability {
    name: String,
    #[allow(dead_code)]
    vulnerable_version: String,
    #[allow(dead_code)]
    cve: Option<String>,
    severity: Severity,
    description: String,
}

#[derive(Debug, Clone)]
struct JoomlaVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl JoomlaScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_vulnerabilities: Self::build_vulnerability_db(),
        }
    }

    fn build_vulnerability_db() -> HashMap<String, Vec<JoomlaVulnerability>> {
        let mut db = HashMap::new();
        let vulnerabilities = vec![
            JoomlaVulnerability {
                name: "com_jce".to_string(),
                vulnerable_version: "2.6.38".to_string(),
                cve: Some("CVE-2020-35936".to_string()),
                severity: Severity::Critical,
                description: "JCE Editor file upload bypass RCE".to_string(),
            },
            JoomlaVulnerability {
                name: "com_fabrik".to_string(),
                vulnerable_version: "3.10".to_string(),
                cve: None,
                severity: Severity::Critical,
                description: "Fabrik file upload arbitrary file write".to_string(),
            },
        ];
        for vuln in vulnerabilities {
            db.entry(vuln.name.clone())
                .or_insert_with(Vec::new)
                .push(vuln);
        }
        db
    }

    pub async fn scan(
        &self,
        target: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let (is_joomla, version) = self.detect_joomla(target).await?;
        tests += 1;

        if !is_joomla {
            debug!("Target does not appear to be a Joomla installation");
            return Ok((vulnerabilities, tests));
        }

        info!("Detected Joomla installation at {}", target);
        if let Some(ref v) = version {
            info!("Joomla version: {}.{}.{}", v.major, v.minor, v.patch);
        }

        let (version_vulns, t) = self.check_version_vulnerabilities(target, &version).await?;
        vulnerabilities.extend(version_vulns);
        tests += t;

        let (admin_vulns, t) = self.check_admin_exposure(target).await?;
        vulnerabilities.extend(admin_vulns);
        tests += t;

        let (config_vulns, t) = self.check_config_exposure(target).await?;
        vulnerabilities.extend(config_vulns);
        tests += t;

        let (api_vulns, t) = self.check_api_exposure(target).await?;
        vulnerabilities.extend(api_vulns);
        tests += t;

        let (ext_vulns, t) = self.check_extension_vulnerabilities(target).await?;
        vulnerabilities.extend(ext_vulns);
        tests += t;

        let (install_vulns, t) = self.check_installation_files(target).await?;
        vulnerabilities.extend(install_vulns);
        tests += t;

        Ok((vulnerabilities, tests))
    }

    async fn detect_joomla(&self, target: &str) -> Result<(bool, Option<JoomlaVersion>)> {
        let mut version: Option<JoomlaVersion> = None;

        let detection_urls = vec![
            format!("{}/administrator/manifests/files/joomla.xml", target),
            format!("{}/language/en-GB/en-GB.xml", target),
        ];

        for url in &detection_urls {
            if let Ok(response) = self.http_client.get(url).await {
                if response.status_code == 200 {
                    if url.ends_with(".xml") {
                        if let Some(v) = self.extract_version_from_xml(&response.body) {
                            version = Some(v);
                        }
                    }
                    return Ok((true, version));
                }
            }
        }

        // Check main page for Joomla generator meta tag - this is the most reliable indicator.
        // Previously matched `body.contains("joomla")` alone which matches any page
        // that mentions Joomla in text (blog posts, docs, comparisons).
        // Now require the Joomla generator meta tag or Joomla-specific HTML patterns.
        if let Ok(response) = self.http_client.get(target).await {
            if response.status_code == 200 {
                let body_lower = response.body.to_lowercase();
                let has_joomla_meta = body_lower.contains("content=\"joomla")
                    || body_lower.contains("generator\" content=\"joomla");
                let has_joomla_structure = body_lower.contains("/media/jui/")
                    || body_lower.contains("/media/system/")
                        && body_lower.contains("joomla");

                if has_joomla_meta || has_joomla_structure {
                    let version_regex = Regex::new(
                        r#"generator"[^>]*content="Joomla!\s*(\d+)\.(\d+)(?:\.(\d+))?"#,
                    )
                    .ok();
                    if let Some(re) = version_regex {
                        if let Some(caps) = re.captures(&response.body) {
                            let major = caps
                                .get(1)
                                .and_then(|m| m.as_str().parse().ok())
                                .unwrap_or(0);
                            let minor = caps
                                .get(2)
                                .and_then(|m| m.as_str().parse().ok())
                                .unwrap_or(0);
                            let patch = caps
                                .get(3)
                                .and_then(|m| m.as_str().parse().ok())
                                .unwrap_or(0);
                            version = Some(JoomlaVersion {
                                major,
                                minor,
                                patch,
                            });
                        }
                    }
                    return Ok((true, version));
                }
            }
        }

        Ok((false, None))
    }

    fn extract_version_from_xml(&self, content: &str) -> Option<JoomlaVersion> {
        let version_regex = Regex::new(r"<version>(\d+)\.(\d+)(?:\.(\d+))?</version>").ok()?;
        if let Some(caps) = version_regex.captures(content) {
            let major = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let minor = caps
                .get(2)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let patch = caps
                .get(3)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            return Some(JoomlaVersion {
                major,
                minor,
                patch,
            });
        }
        None
    }

    async fn check_version_vulnerabilities(
        &self,
        target: &str,
        version: &Option<JoomlaVersion>,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests = 1;

        if let Some(v) = version {
            // Check CVE-2023-23752 (Joomla 4.0.0 - 4.2.7)
            if v.major == 4 && (v.minor < 2 || (v.minor == 2 && v.patch <= 7)) {
                let api_url = format!("{}/api/index.php/v1/config/application?public=true", target);
                if let Ok(response) = self.http_client.get(&api_url).await {
                    if response.status_code == 200 && response.body.contains("dbtype") {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "CMS Security".to_string(),
                            url: api_url,
                            parameter: None,
                            payload: "CVE-2023-23752".to_string(),
                            description:
                                "CVE-2023-23752: Joomla REST API exposes database credentials"
                                    .to_string(),
                            evidence: Some(
                                "Database configuration accessible without authentication"
                                    .to_string(),
                            ),
                            cwe: "CWE-284".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Upgrade to Joomla 4.2.8 or later".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
            }

            // Check CVE-2017-8917 (Joomla 3.7.0)
            if v.major == 3 && v.minor == 7 && v.patch == 0 {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: "SQL Injection".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "CMS Security".to_string(),
                    url: target.to_string(),
                    parameter: Some("list[fullordering]".to_string()),
                    payload: "CVE-2017-8917".to_string(),
                    description: "CVE-2017-8917: Joomla 3.7.0 com_fields SQL injection".to_string(),
                    evidence: Some(format!(
                        "Detected vulnerable version {}.{}.{}",
                        v.major, v.minor, v.patch
                    )),
                    cwe: "CWE-89".to_string(),
                    cvss: 9.8,
                    verified: false,
                    false_positive: false,
                    remediation: "Upgrade to Joomla 3.7.1 or later".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_admin_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests = 1;

        let url = format!("{}/administrator/", target);
        if let Ok(response) = self.http_client.get(&url).await {
            if response.status_code == 200 && response.body.contains("mod-login") {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: "Information Disclosure".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: "CMS Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: String::new(),
                    description: "Joomla administrator panel is publicly accessible".to_string(),
                    evidence: Some("Admin login form detected".to_string()),
                    cwe: "CWE-200".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation:
                        "Restrict access to administrator panel using .htaccess or firewall"
                            .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_config_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // Each entry is (path, signatures, severity, label).
        //
        // Signatures are intentionally Joomla-specific PHP property names or
        // INI keys. A 200-OK SPA shell cannot match these by accident because
        // they only appear in real configuration / log files.
        let config_targets: &[(&str, &[&str], Severity, &str)] = &[
            // Backup variants of configuration.php (the database master config)
            (
                "/configuration.php~",
                &["public $host", "public $user", "public $password", "public $db", "public $secret"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.php.bak",
                &["public $host", "public $user", "public $password", "public $db", "public $secret"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.php.old",
                &["public $host", "public $user", "public $password", "public $db"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.php.save",
                &["public $host", "public $user", "public $password", "public $db"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.php.swp",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla vim swap file",
            ),
            (
                "/configuration.bak.php",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.php_bak",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla configuration backup",
            ),
            (
                "/configuration.txt",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla configuration as text",
            ),
            // Per-environment configuration files used by some setups
            (
                "/configuration.dev.php",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla dev configuration",
            ),
            (
                "/configuration.local.php",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla local configuration",
            ),
            (
                "/configuration.staging.php",
                &["public $host", "public $password"],
                Severity::Critical,
                "Joomla staging configuration",
            ),
            // .htaccess / htpasswd backups - common admin-protection bypass surface
            (
                "/.htaccess.bak",
                &["RewriteEngine", "RewriteRule", "<IfModule mod_rewrite"],
                Severity::Medium,
                ".htaccess backup",
            ),
            (
                "/.htaccess.txt",
                &["RewriteEngine", "RewriteRule"],
                Severity::Medium,
                ".htaccess as text",
            ),
            (
                "/htaccess.txt",
                &["RewriteEngine", "RewriteRule", "## Joomla"],
                Severity::Low,
                "Default Joomla htaccess template",
            ),
            (
                "/administrator/.htpasswd",
                &[":$apr1$", ":$2y$", ":$1$"],
                Severity::Critical,
                "Admin htpasswd file",
            ),
            // Debug / error logs - Joomla writes SQL queries, file paths and
            // stack traces here. PHP error log can include passed credentials.
            (
                "/administrator/logs/error.php",
                &["#<?php die('Forbidden.');", "#Date:", "#Software:"],
                Severity::High,
                "Joomla error log",
            ),
            (
                "/administrator/logs/error_log",
                &["PHP Notice", "PHP Warning", "PHP Fatal error", "JDatabaseException"],
                Severity::High,
                "Joomla error log",
            ),
            (
                "/administrator/logs/everything.php",
                &["#<?php die('Forbidden.');", "#Date:"],
                Severity::High,
                "Joomla full log",
            ),
            (
                "/logs/error.php",
                &["#<?php die('Forbidden.');", "#Date:"],
                Severity::High,
                "Joomla error log",
            ),
            (
                "/logs/everything.php",
                &["#<?php die('Forbidden.');", "#Date:"],
                Severity::High,
                "Joomla full log",
            ),
            (
                "/error_log",
                &["PHP Notice", "PHP Warning", "PHP Fatal error"],
                Severity::Medium,
                "PHP error log",
            ),
            // Database / migration dumps left in webroot
            (
                "/database.sql",
                &["INSERT INTO `jos_", "INSERT INTO `#__", "CREATE TABLE `jos_", "CREATE TABLE `#__"],
                Severity::Critical,
                "Database SQL dump",
            ),
            (
                "/backup.sql",
                &["INSERT INTO `jos_", "INSERT INTO `#__", "CREATE TABLE `#__"],
                Severity::Critical,
                "Database SQL dump",
            ),
            (
                "/dump.sql",
                &["INSERT INTO `jos_", "INSERT INTO `#__"],
                Severity::Critical,
                "Database SQL dump",
            ),
            (
                "/site.sql",
                &["INSERT INTO `#__", "CREATE TABLE `#__"],
                Severity::Critical,
                "Database SQL dump",
            ),
            // Akeeba Backup leftovers - kickstart.php is itself a serious risk
            (
                "/administrator/components/com_akeeba/backup/",
                &["Index of /", "<title>Index of"],
                Severity::Critical,
                "Akeeba backup directory listing",
            ),
            (
                "/kickstart.php",
                &["Akeeba Kickstart", "akeebabackup.com"],
                Severity::Critical,
                "Akeeba Kickstart restore script",
            ),
            (
                "/restore.php",
                &["Akeeba", "encapsulation"],
                Severity::Critical,
                "Akeeba restore script",
            ),
            // Information disclosure files
            (
                "/README.txt",
                &["Joomla! is free software", "1- What is this?"],
                Severity::Info,
                "Joomla README (version recon)",
            ),
            (
                "/CHANGELOG.php",
                &["Joomla", "<?php\ndefined('_JEXEC')"],
                Severity::Info,
                "Joomla CHANGELOG",
            ),
            (
                "/administrator/manifests/files/joomla.xml",
                &["<extension", "<version>"],
                Severity::Info,
                "Joomla version manifest",
            ),
            (
                "/language/en-GB/en-GB.xml",
                &["<metadata>", "<version>"],
                Severity::Info,
                "Joomla language manifest",
            ),
            // .env / build/CI artifacts
            (
                "/.env",
                &["DB_HOST=", "DB_PASSWORD=", "APP_KEY="],
                Severity::Critical,
                ".env file",
            ),
            (
                "/.env.local",
                &["DB_HOST=", "DB_PASSWORD="],
                Severity::Critical,
                ".env.local file",
            ),
            (
                "/.git/config",
                &["[core]", "[remote \"origin\"]"],
                Severity::High,
                ".git config",
            ),
            (
                "/.git/HEAD",
                &["ref: refs/heads/"],
                Severity::High,
                ".git HEAD",
            ),
        ];

        for (path, signatures, severity, label) in config_targets {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }
                let hits = signatures
                    .iter()
                    .filter(|s| response.body.contains(*s))
                    .count();
                // Require >=2 distinct signature hits (or the only signature
                // when there's just one) to keep this strictly false-positive-free.
                let validated = if signatures.len() == 1 {
                    hits == 1
                } else {
                    hits >= 2
                };
                if !validated {
                    continue;
                }

                let cvss = match severity {
                    Severity::Critical => 9.1,
                    Severity::High => 7.5,
                    Severity::Medium => 5.3,
                    Severity::Low => 3.7,
                    _ => 2.0,
                };

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: "Information Disclosure".to_string(),
                    severity: severity.clone(),
                    confidence: Confidence::High,
                    category: "CMS Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: format!("{} exposed: {}", label, path),
                    evidence: Some(format!(
                        "{} matched {} signature hit(s)",
                        path, hits
                    )),
                    cwe: "CWE-538".to_string(),
                    cvss,
                    verified: true,
                    false_positive: false,
                    remediation:
                        "Remove backup, log, dump and CI artifact files from web-accessible directories. Block /.git, /.env, /administrator/logs and *.sql at the web server."
                            .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_api_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let api_endpoints = vec![
            "/api/index.php/v1/config/application",
            "/api/index.php/v1/users",
        ];

        for endpoint in api_endpoints {
            let url = format!("{}{}", target, endpoint);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    if endpoint.contains("config") && response.body.contains("dbtype") {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "CMS Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: "Joomla REST API exposes application configuration"
                                .to_string(),
                            evidence: Some(
                                "Database configuration exposed without authentication".to_string(),
                            ),
                            cwe: "CWE-284".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "Restrict API access and upgrade to patched Joomla version"
                                    .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    } else if endpoint.contains("users") && response.body.contains("email") {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "User Enumeration".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "CMS Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: "Joomla REST API exposes user information".to_string(),
                            evidence: Some("User details including emails accessible".to_string()),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Restrict API access with proper authentication"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_extension_vulnerabilities(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let extensions = vec![
            ("com_jce", "/administrator/components/com_jce/"),
            ("com_fabrik", "/components/com_fabrik/"),
        ];

        for (ext_name, ext_path) in extensions {
            let url = format!("{}{}", target, ext_path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                // Only report if extension is ACCESSIBLE (200), not just blocked (403).
                // A 403 means the server is blocking access, which is PROTECTION, not vulnerability.
                // Reporting on 403 creates false positives for properly secured extensions.
                if response.status_code == 200 {
                    if let Some(vulns) = self.known_vulnerabilities.get(ext_name) {
                        for vuln in vulns {
                            vulnerabilities.push(Vulnerability {
                                id: generate_vuln_id(),
                                vuln_type: format!("{} Vulnerability", vuln.description),
                                severity: vuln.severity.clone(),
                                confidence: Confidence::Medium,
                                category: "CMS Security".to_string(),
                                url: url.clone(),
                                parameter: None,
                                payload: ext_name.to_string(),
                                description: format!(
                                    "Potentially vulnerable Joomla extension: {} - {}",
                                    ext_name, vuln.description
                                ),
                                evidence: Some(format!("Extension {} detected", ext_name)),
                                cwe: "CWE-1035".to_string(),
                                cvss: 7.5,
                                verified: false,
                                false_positive: false,
                                remediation: format!("Update {} to the latest version", ext_name),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_installation_files(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests = 1;

        let url = format!("{}/installation/", target);
        if let Ok(response) = self.http_client.get(&url).await {
            if response.status_code == 200 && response.body.contains("install") {
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: "Security Misconfiguration".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "CMS Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: "/installation/".to_string(),
                    description:
                        "Joomla installation directory accessible - site may be reinstallable"
                            .to_string(),
                    evidence: Some("Installation wizard accessible".to_string()),
                    cwe: "CWE-284".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "Remove the installation directory after setup".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }
}

fn generate_vuln_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("JOOMLA-{:x}", timestamp)
}
