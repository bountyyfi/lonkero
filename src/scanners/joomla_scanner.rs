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

        // Joomla's primary secrets live in configuration.php at the docroot. When
        // editors or deploy scripts leave a backup/swap copy behind it serves the
        // file as text/plain (PHP no longer parses it), exposing the database
        // credentials, the secret site salt, the mail SMTP password, and the
        // FTP password if FTP layer is enabled. Every variant below has been
        // seen in the wild on production Joomla installs.
        let config_paths = vec![
            "/configuration.php~",
            "/configuration.php.bak",
            "/configuration.php.old",
            "/configuration.php.save",
            "/configuration.php.swp",
            "/configuration.php.swo",
            "/.configuration.php.swp",
            "/configuration.php.orig",
            "/configuration.php.txt",
            "/configuration.php.backup",
            "/configuration.php~1~",
            "/configuration.bak.php",
            "/configuration.old.php",
            "/configuration.php-dist",
            "/configuration.php.dist",
            "/configuration.php.disabled",
            "/configuration.php.copy",
            "/configuration.php.original",
            "/configuration.php.new",
            // Less common but uniquely Joomla — editor backup conventions.
            "/configuration.php#",
            "/#configuration.php#",
            "/configuration.inc.php.bak",
            // Installer remnants — created by Joomla itself and routinely left
            // on disk after upgrades.
            "/installation/configuration.php-dist",
            "/installation/configuration.php.dist",
            "/installation/sql/mysql/joomla.sql",
            "/installation/sql/postgresql/joomla.sql",
            // CLI deploy artefacts
            "/configuration.php_dist",
            "/configuration_dist.php",
            // Joomla front-end accessible profile / template config
            "/templates/system/error.php.bak",
        ];

        for path in config_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }
                let body = &response.body;

                // Require Joomla-configuration-specific markers. The two PHP
                // class names below are present in every shipped Joomla
                // installation since 1.5 and absent from generic PHP files,
                // so a 200 OK from an unrelated server cannot match.
                let is_joomla_config_php = (body.contains("JConfig")
                    || body.contains("class JConfig"))
                    && (body.contains("$host") || body.contains("public $host"))
                    && (body.contains("$db") || body.contains("public $db"));

                // configuration.php-dist ships with placeholders rather than
                // real values, so accept the JConfig class alone.
                let is_dist_template = (path.ends_with("-dist") || path.ends_with(".dist"))
                    && body.contains("class JConfig")
                    && body.contains("$secret");

                // Joomla installation SQL dump — the schema is uniquely
                // identifiable by the prefixed table list.
                let is_install_sql = path.ends_with(".sql")
                    && body.contains("CREATE TABLE")
                    && (body.contains("`#__users`") || body.contains("#__extensions"));

                if is_joomla_config_php || is_dist_template || is_install_sql {
                    let (description, evidence, severity, cvss) = if is_install_sql {
                        (
                            format!("Joomla installer SQL schema dump exposed: {}", path),
                            "SQL schema reveals Joomla version-specific tables and default user setup".to_string(),
                            Severity::Medium,
                            5.3,
                        )
                    } else if is_dist_template {
                        (
                            format!("Joomla configuration template (dist) exposed: {}", path),
                            "configuration.php-dist reveals expected secrets layout; if found, the real configuration.php variants likely leak too".to_string(),
                            Severity::Low,
                            3.7,
                        )
                    } else {
                        (
                            format!("Joomla configuration backup file exposed: {}", path),
                            "Backup of configuration.php — contains DB host/user/password, $secret site salt, and SMTP password".to_string(),
                            Severity::Critical,
                            9.1,
                        )
                    };

                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "CMS Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description,
                        evidence: Some(evidence),
                        cwe: "CWE-538".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation:
                            "1. Delete configuration.* backup/swap/dist files from the docroot.\n\
                             2. Block editor backups in nginx/Apache: deny .bak .swp .old .orig .save .dist suffixes.\n\
                             3. Rotate database credentials, $secret salt, and any SMTP/FTP passwords that appeared in the leaked file — assume they are public.\n\
                             4. Remove the /installation/ directory after setup; its sql/ subtree also leaks schema and default credentials."
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

        // Joomla 4+ exposes a JSON-API tree under /api/index.php/v1. Many sites
        // forget to add an API Key (Joomla token) requirement when first
        // enabling the API plugin — in that case every endpoint below returns
        // its data anonymously. We probe the high-signal ones; each match has
        // a unique JSON field name we verify against in the matching block
        // below to avoid claiming a hit on a 200-OK JSON catch-all route.
        let api_endpoints = vec![
            "/api/index.php/v1/config/application",
            "/api/index.php/v1/config/site",
            "/api/index.php/v1/config/databaseserver",
            "/api/index.php/v1/users",
            "/api/index.php/v1/users?filter[state]=0",
            "/api/index.php/v1/extensions",
            "/api/index.php/v1/plugins",
            "/api/index.php/v1/modules",
            "/api/index.php/v1/templates/styles/site",
            "/api/index.php/v1/templates/styles/administrator",
            "/api/index.php/v1/messages",
            "/api/index.php/v1/privacy/requests",
            "/api/index.php/v1/redirects",
            "/api/index.php/v1/banners",
            "/api/index.php/v1/contacts",
            "/api/index.php/v1/newsfeeds",
            "/api/index.php/v1/tags",
            "/api/index.php/v1/menus/site",
            "/api/index.php/v1/menus/administrator",
            "/api/index.php/v1/content/articles",
            "/api/index.php/v1/content/categories",
            "/api/index.php/v1/fields",
            "/api/index.php/v1/fields/groups",
            // Legacy 3.x com_api / com_jsonapi style endpoints
            "/index.php?option=com_api&format=raw",
            "/index.php?option=com_users&view=registration&format=raw",
        ];

        for endpoint in api_endpoints {
            let url = format!("{}{}", target, endpoint);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }

                let body = &response.body;

                // Every Joomla 4 API response wraps its payload in a
                // {"links":..., "data":[{"type":"...","id":..."}, ...]}
                // envelope. We require this structure on /v1/* endpoints so a
                // generic JSON catch-all cannot match.
                let is_joomla_api_envelope = endpoint.contains("/api/index.php/v1")
                    && body.contains("\"links\"")
                    && body.contains("\"data\"")
                    && (body.contains("\"type\":") || body.contains("\"id\":"));

                // (endpoint substring → (vuln_type, severity, cvss, description, evidence_pattern))
                // evidence_pattern is a substring whose presence inside the
                // body confirms the endpoint really returned its sensitive
                // payload (vs. an empty 200 placeholder route).
                let classification: Option<(&str, Severity, f32, &str, &[&str])> =
                    if endpoint.contains("/v1/config/application") {
                        Some((
                            "Information Disclosure",
                            Severity::Critical,
                            9.1,
                            "Joomla REST API exposes application configuration — DB host/user/password and $secret site salt",
                            &["\"dbtype\"", "\"host\"", "\"user\"", "\"secret\""][..],
                        ))
                    } else if endpoint.contains("/v1/config/databaseserver") {
                        Some((
                            "Information Disclosure",
                            Severity::Critical,
                            9.1,
                            "Joomla REST API leaks the database server configuration object",
                            &["\"dbtype\"", "\"host\""][..],
                        ))
                    } else if endpoint.contains("/v1/config/site") {
                        Some((
                            "Information Disclosure",
                            Severity::High,
                            7.5,
                            "Joomla REST API leaks site configuration — captures SMTP credentials, FTP password if set, $secret salt",
                            &["\"mailfrom\"", "\"smtphost\"", "\"secret\""][..],
                        ))
                    } else if endpoint.contains("/v1/users") {
                        Some((
                            "User Enumeration",
                            Severity::High,
                            7.5,
                            "Joomla REST API exposes user list including emails and account state — feeds password spraying and reset-token replay",
                            &["\"email\"", "\"username\""][..],
                        ))
                    } else if endpoint.contains("/v1/extensions") || endpoint.contains("/v1/plugins") {
                        Some((
                            "Information Disclosure",
                            Severity::Medium,
                            5.3,
                            "Joomla REST API enumerates installed extensions/plugins with version info — pre-flight for CVE targeting",
                            &["\"manifest_cache\"", "\"extension_id\"", "\"element\""][..],
                        ))
                    } else if endpoint.contains("/v1/modules") {
                        Some((
                            "Information Disclosure",
                            Severity::Medium,
                            5.3,
                            "Joomla REST API enumerates published modules and their parameters",
                            &["\"module\"", "\"position\""][..],
                        ))
                    } else if endpoint.contains("/v1/templates/styles") {
                        Some((
                            "Information Disclosure",
                            Severity::Low,
                            3.7,
                            "Joomla REST API exposes template styles and parameters",
                            &["\"template\"", "\"params\""][..],
                        ))
                    } else if endpoint.contains("/v1/privacy/requests") {
                        Some((
                            "Sensitive Data Exposure",
                            Severity::High,
                            7.5,
                            "Joomla REST API exposes GDPR privacy requests — emails of subjects, request types, statuses",
                            &["\"request_type\"", "\"requested_at\""][..],
                        ))
                    } else if endpoint.contains("/v1/messages") {
                        Some((
                            "Information Disclosure",
                            Severity::High,
                            7.5,
                            "Joomla REST API exposes private user-to-user messages",
                            &["\"subject\"", "\"message\""][..],
                        ))
                    } else if endpoint.contains("/v1/redirects") {
                        Some((
                            "Information Disclosure",
                            Severity::Low,
                            3.7,
                            "Joomla REST API exposes URL redirect rules — reveals internal paths and removed endpoints",
                            &["\"old_url\"", "\"new_url\""][..],
                        ))
                    } else if endpoint.contains("/v1/banners") || endpoint.contains("/v1/contacts")
                        || endpoint.contains("/v1/newsfeeds") || endpoint.contains("/v1/tags")
                        || endpoint.contains("/v1/menus") || endpoint.contains("/v1/content")
                        || endpoint.contains("/v1/fields")
                    {
                        Some((
                            "Information Disclosure",
                            Severity::Low,
                            3.7,
                            "Joomla REST API exposes site content collections — full enumeration possible",
                            &["\"data\""][..],
                        ))
                    } else if endpoint.contains("com_api") {
                        // Legacy 3.x: a 200 OK with the com_api JSON envelope.
                        if body.contains("\"version\"") && body.contains("\"name\"") {
                            Some((
                                "Information Disclosure",
                                Severity::Medium,
                                5.3,
                                "Legacy Joomla 3.x com_api JSON endpoint reachable without authentication",
                                &["\"version\""][..],
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                if let Some((vtype, severity, cvss, desc, markers)) = classification {
                    // Require both the Joomla v1 envelope AND endpoint-specific
                    // content keys, OR (for legacy /index.php?option=com_api)
                    // the legacy-specific markers above.
                    let body_confirms = markers.iter().any(|m| body.contains(m));
                    let envelope_ok = if endpoint.contains("com_api") {
                        true
                    } else {
                        is_joomla_api_envelope
                    };

                    if envelope_ok && body_confirms {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: vtype.to_string(),
                            severity,
                            confidence: Confidence::High,
                            category: "CMS Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: desc.to_string(),
                            evidence: Some(format!(
                                "Endpoint accessible without authentication. Matched markers: {:?}",
                                markers
                            )),
                            cwe: "CWE-284".to_string(),
                            cvss,
                            verified: true,
                            false_positive: false,
                            remediation:
                                "1. Require an API token (Joomla Bearer token) for every /api/index.php/v1 route via the Web Services component permissions.\n\
                                 2. Disable the JSON-API plugin entirely if the site does not use it.\n\
                                 3. If any /v1/config/* route was reachable, rotate the database password and $secret salt — they are now public.\n\
                                 4. Upgrade to the latest Joomla 4.x/5.x patch; CVE-2023-23752 and similar bugs make these paths reachable without a token even when ACLs are present."
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
