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

        let (akeeba_vulns, t) = self.check_akeeba_and_sensitive_files(target).await?;
        vulnerabilities.extend(akeeba_vulns);
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

        // Every common backup / swap-file / pre-deploy variant of
        // configuration.php. A hit on any of these leaks the full database
        // credentials + secret keys; no known benign web app shares this
        // exact set of `$host` / `$db` / `$password` PHP-variable names.
        let config_paths = vec![
            "/configuration.php~",
            "/configuration.php.bak",
            "/configuration.php.old",
            "/configuration.php.save",
            "/configuration.php.swp",
            "/configuration.php.swo",
            "/configuration.php.orig",
            "/configuration.php.dist",
            "/configuration.php-dist",
            "/configuration.php.txt",
            "/configuration.php.1",
            "/configuration.php.2",
            "/configuration.php.new",
            "/configuration.php.tmp",
            "/configuration.php.inc",
            "/configuration.php_bak",
            "/configuration.bak.php",
            "/configuration.old.php",
            "/configuration.backup",
            "/configuration.inc",
            "/configuration.inc.php",
            "/.configuration.php.swp",
            "/.configuration.php.un~",
            "/configuration.json",
            // Common editor-specific backup locations
            "/configuration.php~1~",
            "/#configuration.php#",
            // Linux distro deploy helpers sometimes place a copy here
            "/backup/configuration.php",
            "/backups/configuration.php",
            "/old/configuration.php",
            "/bak/configuration.php",
            "/tmp/configuration.php",
        ];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200
                    && (response.body.contains("$host")
                        || response.body.contains("$db")
                        || response.body.contains("$password"))
                {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "CMS Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!("Joomla configuration backup file exposed: {}", path),
                        evidence: Some(
                            "Configuration file contains database credentials".to_string(),
                        ),
                        cwe: "CWE-538".to_string(),
                        cvss: 9.1,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Remove backup configuration files from web-accessible directories"
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_api_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // Joomla 4.x REST API endpoints that historically leak data without auth
        // when the `public=true` flag (CVE-2023-23752) or over-permissive ACLs
        // are left in place. Each hit below is matched against an endpoint-
        // specific JSON anchor before being reported.
        let api_endpoints = vec![
            "/api/index.php/v1/config/application",
            "/api/index.php/v1/config/application?public=true",
            "/api/index.php/v1/config/site",
            "/api/index.php/v1/config/databaseconfiguration",
            "/api/index.php/v1/users",
            "/api/index.php/v1/users?public=true",
            "/api/index.php/v1/users/1",
            "/api/index.php/v1/content/articles",
            "/api/index.php/v1/content/articles?public=true",
            "/api/index.php/v1/content/categories",
            "/api/index.php/v1/menus",
            "/api/index.php/v1/menus/site",
            "/api/index.php/v1/menus/administrator",
            "/api/index.php/v1/templates/site",
            "/api/index.php/v1/templates/administrator",
            "/api/index.php/v1/extensions",
            "/api/index.php/v1/extensions?public=true",
            "/api/index.php/v1/plugins",
            "/api/index.php/v1/modules/site",
            "/api/index.php/v1/modules/administrator",
            "/api/index.php/v1/languages",
            "/api/index.php/v1/usergroups",
            "/api/index.php/v1/viewlevels",
            "/api/index.php/v1/fields",
            "/api/index.php/v1/privacy/requests",
            "/api/index.php/v1/messages",
            "/api/index.php/v1/banners",
            "/api/index.php/v1/contacts",
            "/api/index.php/v1/newsfeeds",
            "/api/index.php/v1/redirects",
            "/api/index.php/v1/tags",
            "/api/index.php/v1/media/adapters",
            "/api/index.php/v1/media/files",
        ];

        for endpoint in api_endpoints {
            let url = format!("{}{}", target, endpoint);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }
                let body = &response.body;

                // Every Joomla 4.x REST response is wrapped in an outer envelope
                // containing "data" and either "type" or "links". Require that
                // envelope so random 200 OK HTML pages cannot flag.
                let is_joomla_api_envelope = body.contains("\"data\":")
                    && (body.contains("\"type\":") || body.contains("\"links\":"));

                if endpoint.contains("config") && body.contains("dbtype") {
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
                } else if endpoint.contains("users") && body.contains("email") {
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
                } else if is_joomla_api_envelope
                    && (endpoint.contains("/extensions")
                        || endpoint.contains("/plugins")
                        || endpoint.contains("/modules")
                        || endpoint.contains("/templates"))
                {
                    // Enumerating installed components + versions hands an
                    // attacker a ready-made shopping list of known-vulnerable
                    // extensions to exploit.
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "CMS Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: endpoint.to_string(),
                        description:
                            "Joomla REST API exposes installed extensions/plugins/modules/templates"
                                .to_string(),
                        evidence: Some(
                            "Extension inventory accessible without authentication - aids targeted exploitation"
                                .to_string(),
                        ),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Restrict API access with authentication and remove the `public=true` allowance"
                                .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
                } else if is_joomla_api_envelope && endpoint.contains("/privacy/requests") {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "CMS Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: endpoint.to_string(),
                        description:
                            "Joomla Privacy (GDPR) requests exposed - reveals subject access / erasure requests"
                                .to_string(),
                        evidence: Some(
                            "GDPR privacy requests accessible without authentication".to_string(),
                        ),
                        cwe: "CWE-200".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "Restrict the privacy API to authenticated Super Users only".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
                } else if is_joomla_api_envelope && endpoint.contains("/messages") {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "CMS Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: endpoint.to_string(),
                        description:
                            "Joomla private messaging inbox accessible via REST API".to_string(),
                        evidence: Some("Private messages accessible without auth".to_string()),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "Restrict /api/index.php/v1/messages to authenticated users"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
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

    /// Check for Akeeba Backup leftovers and other high-signal Joomla files
    /// that commonly ship with production deployments.
    ///
    /// Every path below is matched against a file-specific content anchor,
    /// so a 200-OK SPA index fallback can never trigger a finding.
    async fn check_akeeba_and_sensitive_files(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // (path, vuln_id, required substrings, severity, cvss, description, remediation)
        let checks: &[(&str, &str, &[&str], Severity, f32, &str, &str)] = &[
            // Akeeba Backup - most common Joomla backup extension.
            // kickstart.php is the restoration script. If present it means a
            // `.jpa` archive restore is available to anyone on the internet.
            (
                "/kickstart.php",
                "JOOMLA_AKEEBA_KICKSTART_EXPOSED",
                &["Akeeba", "kickstart"],
                Severity::Critical,
                9.8,
                "Akeeba Kickstart restore script exposed - anyone can trigger a full site restore from a leftover .jpa archive",
                "Delete kickstart.php immediately; Akeeba requires this file only during restore and it must not remain on production",
            ),
            // Standard Akeeba output folder — often world-readable + directory-listed.
            (
                "/administrator/components/com_akeeba/backup/",
                "JOOMLA_AKEEBA_BACKUP_DIR_LISTING",
                &["Index of", ".jpa"],
                Severity::Critical,
                9.1,
                "Akeeba Backup output directory has directory listing enabled and shows .jpa archives (full site + DB backups)",
                "Disable directory listing (e.g. add `Options -Indexes` to .htaccess) and move backups out of the web root",
            ),
            (
                "/administrator/components/com_akeeba/backup/",
                "JOOMLA_AKEEBA_BACKUP_DIR_LISTING",
                &["Index of", ".jps"],
                Severity::Critical,
                9.1,
                "Akeeba Backup output directory has directory listing enabled and shows .jps archives (encrypted but still downloadable)",
                "Disable directory listing and move backups out of the web root",
            ),
            // Joomla update / discovery logs commonly contain host/user info.
            (
                "/administrator/logs/error.php",
                "JOOMLA_ERROR_LOG_EXPOSED",
                &["PHP Fatal", "Stack trace"],
                Severity::Medium,
                5.3,
                "Joomla error log publicly accessible - can leak file paths and stack traces",
                "Block /administrator/logs/ via .htaccess or move logs outside web root",
            ),
            (
                "/logs/error.php",
                "JOOMLA_ERROR_LOG_EXPOSED",
                &["PHP Fatal", "Stack trace"],
                Severity::Medium,
                5.3,
                "Joomla log directory publicly accessible",
                "Block /logs/ via .htaccess or move logs outside web root",
            ),
            // Default debug / phpinfo that sometimes slips through.
            (
                "/administrator/index.php?option=com_config&view=component&component=com_debug",
                "JOOMLA_DEBUG_ENABLED",
                &["Debug Information", "Joomla"],
                Severity::Medium,
                5.3,
                "Joomla debug panel appears enabled",
                "Disable debug mode in production (Global Configuration → System → Debug System = No)",
            ),
            // htaccess backup - reveals security rules to bypass.
            (
                "/.htaccess.bak",
                "JOOMLA_HTACCESS_BACKUP_EXPOSED",
                &["RewriteEngine", "RewriteRule"],
                Severity::Medium,
                5.3,
                "Joomla .htaccess backup exposed - reveals rewrite and security rules",
                "Remove .htaccess.bak from the web root",
            ),
            (
                "/htaccess.txt",
                "JOOMLA_HTACCESS_TEMPLATE_READABLE",
                &["RewriteEngine", "RewriteRule", "Joomla"],
                Severity::Info,
                2.0,
                "Joomla shipped htaccess.txt template is readable (low impact, confirms Joomla)",
                "Optional - most deployments leave this for rename-to-.htaccess; can be removed once .htaccess is in place",
            ),
            // Composer artefacts — expose dependency versions for targeted exploits.
            (
                "/composer.json",
                "JOOMLA_COMPOSER_JSON_EXPOSED",
                &["\"require\"", "joomla"],
                Severity::Low,
                3.7,
                "composer.json exposed - reveals dependency versions for CVE targeting",
                "Deny access to composer.{json,lock} at the reverse proxy",
            ),
            (
                "/composer.lock",
                "JOOMLA_COMPOSER_LOCK_EXPOSED",
                &["\"packages\"", "\"name\":"],
                Severity::Low,
                3.7,
                "composer.lock exposed - reveals pinned dependency versions",
                "Deny access to composer.{json,lock} at the reverse proxy",
            ),
            // README / manifest leftovers that confirm Joomla version.
            (
                "/README.txt",
                "JOOMLA_README_EXPOSED",
                &["Joomla", "installation"],
                Severity::Info,
                2.0,
                "Joomla README.txt exposed - confirms Joomla install",
                "Remove README.txt from production web root",
            ),
            // language/en-GB/en-GB.xml is the canonical version oracle.
            (
                "/language/en-GB/en-GB.xml",
                "JOOMLA_LANGUAGE_MANIFEST_EXPOSED",
                &["<metadata>", "Joomla"],
                Severity::Low,
                3.7,
                "Joomla language manifest exposed - precise version disclosure",
                "Block /language/**/*.xml at the reverse proxy",
            ),
            // Installation lock residue — presence strongly suggests reinstallable state.
            (
                "/installation/index.php",
                "JOOMLA_INSTALL_INDEX_EXPOSED",
                &["Joomla", "installation"],
                Severity::Critical,
                9.8,
                "Joomla installer entry point still present - site may be reinstallable",
                "Delete the entire /installation/ directory after setup",
            ),
            // Convertforms / common backup tool collateral.
            (
                "/administrator/backups/",
                "JOOMLA_BACKUPS_DIR_LISTING",
                &["Index of"],
                Severity::High,
                7.5,
                "Joomla backups directory has directory listing enabled",
                "Disable directory listing and move backups outside web root",
            ),
            (
                "/backups/",
                "JOOMLA_BACKUPS_DIR_LISTING",
                &["Index of", ".sql"],
                Severity::Critical,
                9.1,
                "/backups/ has directory listing and contains SQL dumps",
                "Disable directory listing and move SQL dumps outside web root",
            ),
            // Joomla .xml manifest per extension - useful version fingerprint.
            (
                "/administrator/manifests/files/joomla.xml",
                "JOOMLA_CORE_MANIFEST_EXPOSED",
                &["<extension", "joomla"],
                Severity::Low,
                3.7,
                "Core Joomla manifest exposed - exact version disclosure",
                "Block /administrator/manifests/ at the reverse proxy",
            ),
        ];

        for (path, vuln_id, markers, severity, cvss, description, remediation) in checks {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.len() < 20 {
                    continue;
                }
                let body_lower = response.body.to_lowercase();
                let all_match = markers
                    .iter()
                    .all(|m| body_lower.contains(&m.to_lowercase()));
                if !all_match {
                    continue;
                }

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: vuln_id.to_string(),
                    severity: severity.clone(),
                    confidence: Confidence::High,
                    category: "CMS Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: description.to_string(),
                    evidence: Some(format!(
                        "{} returned 200 OK and contains all of: [{}]",
                        path,
                        markers.join(", ")
                    )),
                    cwe: "CWE-200".to_string(),
                    cvss: *cvss,
                    verified: true,
                    false_positive: false,
                    remediation: remediation.to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
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
