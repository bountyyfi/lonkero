// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Advanced Drupal Security Scanner
 * Comprehensive Drupal vulnerability detection
 *
 * REQUIRES: Personal license or higher
 *
 * Detects:
 * - Drupalgeddon vulnerabilities (SA-CORE-2014-005, SA-CORE-2018-002, SA-CORE-2018-004)
 * - User enumeration (via user paths, password reset, JSON API)
 * - Version disclosure (CHANGELOG.txt, README.txt, core files)
 * - Module/theme vulnerabilities
 * - Configuration exposure (settings.php backups)
 * - Update.php/install.php exposure
 * - Cron.php without cron key
 * - REST/JSON API exposure
 * - PHP filter module enabled
 * - Views/Services module vulnerabilities
 * - File upload bypasses
 * - Private file access
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Personal Edition and above
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct DrupalSecurityScanner {
    http_client: Arc<HttpClient>,
    known_vulnerable_modules: HashMap<String, Vec<ModuleVulnerability>>,
}

#[derive(Clone)]
struct ModuleVulnerability {
    name: String,
    vulnerable_version: String,
    sa_id: Option<String>,
    cve: Option<String>,
    severity: Severity,
    description: String,
}

#[derive(Debug, Clone)]
struct DrupalVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl DrupalSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            known_vulnerable_modules: Self::build_vulnerable_modules_db(),
        }
    }

    /// Build database of known vulnerable modules
    fn build_vulnerable_modules_db() -> HashMap<String, Vec<ModuleVulnerability>> {
        let mut db = HashMap::new();

        let vulnerabilities = vec![
            // Core Drupalgeddon vulnerabilities
            ModuleVulnerability {
                name: "drupal_core".to_string(),
                vulnerable_version: "7.31".to_string(),
                sa_id: Some("SA-CORE-2014-005".to_string()),
                cve: Some("CVE-2014-3704".to_string()),
                severity: Severity::Critical,
                description: "Drupalgeddon - SQL injection allowing arbitrary PHP execution".to_string(),
            },
            ModuleVulnerability {
                name: "drupal_core".to_string(),
                vulnerable_version: "8.5.0".to_string(),
                sa_id: Some("SA-CORE-2018-002".to_string()),
                cve: Some("CVE-2018-7600".to_string()),
                severity: Severity::Critical,
                description: "Drupalgeddon2 - Remote code execution via Form API".to_string(),
            },
            ModuleVulnerability {
                name: "drupal_core".to_string(),
                vulnerable_version: "8.5.3".to_string(),
                sa_id: Some("SA-CORE-2018-004".to_string()),
                cve: Some("CVE-2018-7602".to_string()),
                severity: Severity::Critical,
                description: "Drupalgeddon3 - Remote code execution".to_string(),
            },
            // Contributed modules
            ModuleVulnerability {
                name: "ctools".to_string(),
                vulnerable_version: "7.x-1.14".to_string(),
                sa_id: Some("SA-CONTRIB-2018-012".to_string()),
                cve: None,
                severity: Severity::High,
                description: "Object injection vulnerability".to_string(),
            },
            ModuleVulnerability {
                name: "views".to_string(),
                vulnerable_version: "7.x-3.20".to_string(),
                sa_id: Some("SA-CONTRIB-2017-020".to_string()),
                cve: None,
                severity: Severity::High,
                description: "SQL injection in Views module".to_string(),
            },
            ModuleVulnerability {
                name: "services".to_string(),
                vulnerable_version: "7.x-3.19".to_string(),
                sa_id: Some("SA-CONTRIB-2016-011".to_string()),
                cve: None,
                severity: Severity::Critical,
                description: "Remote code execution via PHP object injection".to_string(),
            },
            ModuleVulnerability {
                name: "restws".to_string(),
                vulnerable_version: "7.x-2.6".to_string(),
                sa_id: Some("SA-CONTRIB-2016-040".to_string()),
                cve: Some("CVE-2016-6211".to_string()),
                severity: Severity::Critical,
                description: "Remote code execution".to_string(),
            },
            ModuleVulnerability {
                name: "webform".to_string(),
                vulnerable_version: "7.x-4.15".to_string(),
                sa_id: Some("SA-CONTRIB-2017-063".to_string()),
                cve: None,
                severity: Severity::High,
                description: "Access bypass vulnerability".to_string(),
            },
            ModuleVulnerability {
                name: "paragraphs".to_string(),
                vulnerable_version: "8.x-1.11".to_string(),
                sa_id: Some("SA-CONTRIB-2019-066".to_string()),
                cve: None,
                severity: Severity::High,
                description: "Access bypass - unpublished content access".to_string(),
            },
            ModuleVulnerability {
                name: "link".to_string(),
                vulnerable_version: "7.x-1.6".to_string(),
                sa_id: Some("SA-CONTRIB-2018-027".to_string()),
                cve: None,
                severity: Severity::Medium,
                description: "Cross-site scripting vulnerability".to_string(),
            },
            ModuleVulnerability {
                name: "token".to_string(),
                vulnerable_version: "7.x-1.7".to_string(),
                sa_id: Some("SA-CONTRIB-2018-014".to_string()),
                cve: None,
                severity: Severity::Medium,
                description: "Information disclosure".to_string(),
            },
            ModuleVulnerability {
                name: "media".to_string(),
                vulnerable_version: "7.x-2.21".to_string(),
                sa_id: Some("SA-CONTRIB-2018-066".to_string()),
                cve: None,
                severity: Severity::High,
                description: "Remote code execution via file upload".to_string(),
            },
            ModuleVulnerability {
                name: "entity".to_string(),
                vulnerable_version: "7.x-1.9".to_string(),
                sa_id: Some("SA-CONTRIB-2019-007".to_string()),
                cve: None,
                severity: Severity::High,
                description: "Access bypass vulnerability".to_string(),
            },
            ModuleVulnerability {
                name: "colorbox".to_string(),
                vulnerable_version: "7.x-2.13".to_string(),
                sa_id: Some("SA-CONTRIB-2017-033".to_string()),
                cve: None,
                severity: Severity::Medium,
                description: "Cross-site scripting".to_string(),
            },
            ModuleVulnerability {
                name: "rules".to_string(),
                vulnerable_version: "7.x-2.11".to_string(),
                sa_id: Some("SA-CONTRIB-2019-012".to_string()),
                cve: None,
                severity: Severity::High,
                description: "PHP object injection".to_string(),
            },
            ModuleVulnerability {
                name: "captcha".to_string(),
                vulnerable_version: "7.x-1.5".to_string(),
                sa_id: Some("SA-CONTRIB-2017-012".to_string()),
                cve: None,
                severity: Severity::Medium,
                description: "CAPTCHA bypass vulnerability".to_string(),
            },
        ];

        for vuln in vulnerabilities {
            db.entry(vuln.name.clone())
                .or_insert_with(Vec::new)
                .push(vuln);
        }

        db
    }

    /// Scan Drupal site for security issues
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[Drupal] Advanced Drupal security scan starting");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, detect if this is a Drupal site and get version
        tests_run += 1;
        let drupal_info = self.detect_drupal(url).await;

        if drupal_info.is_none() {
            debug!("Not a Drupal site, skipping Drupal-specific tests");
            return Ok((vulnerabilities, tests_run));
        }

        let (is_drupal, version) = drupal_info.unwrap();
        if !is_drupal {
            return Ok((vulnerabilities, tests_run));
        }

        info!("[Drupal] Drupal detected (version: {:?}), running comprehensive scan", version);

        // Test 1: Drupalgeddon vulnerabilities (based on version)
        tests_run += 1;
        let drupalgeddon_vulns = self.test_drupalgeddon(url, &version).await;
        vulnerabilities.extend(drupalgeddon_vulns);

        // Test 2: User enumeration
        tests_run += 1;
        let user_enum_vulns = self.test_user_enumeration(url, &version).await;
        vulnerabilities.extend(user_enum_vulns);

        // Test 3: Version disclosure
        tests_run += 1;
        let version_vulns = self.test_version_disclosure(url).await;
        vulnerabilities.extend(version_vulns);

        // Test 4: Configuration file exposure
        tests_run += 1;
        let config_vulns = self.test_config_exposure(url).await;
        vulnerabilities.extend(config_vulns);

        // Test 5: Admin paths exposure
        tests_run += 1;
        let admin_vulns = self.test_admin_exposure(url).await;
        vulnerabilities.extend(admin_vulns);

        // Test 6: Update.php / Install.php exposure
        tests_run += 1;
        let install_vulns = self.test_installation_exposure(url).await;
        vulnerabilities.extend(install_vulns);

        // Test 7: Cron.php exposure
        tests_run += 1;
        let cron_vulns = self.test_cron_exposure(url).await;
        vulnerabilities.extend(cron_vulns);

        // Test 8: REST/JSON API exposure
        tests_run += 1;
        let api_vulns = self.test_api_exposure(url, &version).await;
        vulnerabilities.extend(api_vulns);

        // Test 9: Module vulnerabilities
        tests_run += 1;
        let module_vulns = self.test_module_vulnerabilities(url, &version).await;
        vulnerabilities.extend(module_vulns);

        // Test 10: Directory listing
        tests_run += 1;
        let listing_vulns = self.test_directory_listing(url).await;
        vulnerabilities.extend(listing_vulns);

        // Test 11: Backup file exposure
        tests_run += 1;
        let backup_vulns = self.test_backup_exposure(url).await;
        vulnerabilities.extend(backup_vulns);

        // Test 12: Private files access
        tests_run += 1;
        let private_vulns = self.test_private_files(url).await;
        vulnerabilities.extend(private_vulns);

        // Test 13: Status report access
        tests_run += 1;
        let status_vulns = self.test_status_report_access(url).await;
        vulnerabilities.extend(status_vulns);

        // Deep scans (not in fast mode)
        if config.scan_mode.as_str() != "fast" {
            // Test 14: PHP filter module detection
            tests_run += 1;
            let php_vulns = self.test_php_filter_module(url).await;
            vulnerabilities.extend(php_vulns);

            // Test 15: Form API testing (Drupalgeddon2 variants)
            tests_run += 1;
            let form_vulns = self.test_form_api_vulnerabilities(url, &version).await;
            vulnerabilities.extend(form_vulns);
        }

        info!(
            "[Drupal] Scan complete: {} vulnerabilities found in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if site is Drupal and get version
    async fn detect_drupal(&self, url: &str) -> Option<(bool, Option<DrupalVersion>)> {
        let base_url = self.get_base_url(url);
        let mut version: Option<DrupalVersion> = None;

        // Check for Drupal indicators in main page
        if let Ok(response) = self.http_client.get(url).await {
            let drupal_indicators = vec![
                "Drupal",
                "drupal.js",
                "drupal.css",
                "/sites/default/",
                "/sites/all/",
                "Drupal.settings",
                "drupal-link-system",
            ];

            let is_drupal = drupal_indicators.iter().any(|i| response.body.contains(i));

            // Check generator meta tag
            if let Some(re) = Regex::new(r#"<meta[^>]*generator[^>]*Drupal\s*(\d+)"#).ok() {
                if let Some(cap) = re.captures(&response.body) {
                    if let Some(major) = cap.get(1) {
                        version = Some(DrupalVersion {
                            major: major.as_str().parse().unwrap_or(0),
                            minor: 0,
                            patch: 0,
                        });
                    }
                }
            }

            if is_drupal || version.is_some() {
                return Some((true, version));
            }

            // Check X-Generator header
            if let Some(generator) = response.headers.get("x-generator") {
                if generator.to_lowercase().contains("drupal") {
                    let version_re = Regex::new(r#"Drupal\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?"#).ok();
                    if let Some(re) = version_re {
                        if let Some(cap) = re.captures(generator) {
                            version = Some(DrupalVersion {
                                major: cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                                minor: cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                                patch: cap.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                            });
                        }
                    }
                    return Some((true, version));
                }
            }
        }

        // Try CHANGELOG.txt for version detection
        let changelog_url = format!("{}/CHANGELOG.txt", base_url);
        if let Ok(response) = self.http_client.get(&changelog_url).await {
            if response.status_code == 200 && response.body.contains("Drupal") {
                let version_re = Regex::new(r#"Drupal\s*(\d+)\.(\d+)(?:\.(\d+))?"#).ok();
                if let Some(re) = version_re {
                    if let Some(cap) = re.captures(&response.body) {
                        version = Some(DrupalVersion {
                            major: cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                            minor: cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                            patch: cap.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
                        });
                    }
                }
                return Some((true, version));
            }
        }

        // Try user/login path
        let login_url = format!("{}/user/login", base_url);
        if let Ok(response) = self.http_client.get(&login_url).await {
            if response.status_code == 200 &&
               (response.body.contains("drupal") || response.body.contains("Drupal")) {
                return Some((true, version));
            }
        }

        None
    }

    /// Test for Drupalgeddon vulnerabilities
    async fn test_drupalgeddon(&self, url: &str, version: &Option<DrupalVersion>) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        if let Some(ver) = version {
            // Check for Drupalgeddon (SA-CORE-2014-005) - Drupal 7 < 7.32
            if ver.major == 7 && ver.minor < 32 {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_drupalgeddon1_{}", Self::generate_id()),
                    vuln_type: "Drupalgeddon (SA-CORE-2014-005)".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Remote Code Execution".to_string(),
                    url: base_url.clone(),
                    parameter: None,
                    payload: "SQL injection in form API".to_string(),
                    description: format!(
                        "Drupal version {}.{}.{} is vulnerable to Drupalgeddon (CVE-2014-3704).\n\
                        This SQL injection vulnerability allows unauthenticated attackers to \
                        execute arbitrary PHP code on the server.\n\n\
                        This is one of the most critical Drupal vulnerabilities ever discovered.",
                        ver.major, ver.minor, ver.patch
                    ),
                    evidence: Some(format!("Drupal version {}.{}.{} detected", ver.major, ver.minor, ver.patch)),
                    cwe: "CWE-89".to_string(),
                    cvss: 10.0,
                    verified: true,
                    false_positive: false,
                    remediation: "CRITICAL: Update Drupal core to version 7.32 or later IMMEDIATELY.\n\
                                  1. Backup your database and files\n\
                                  2. Update Drupal core: drush up drupal\n\
                                  3. Check for signs of compromise\n\
                                  4. Review user accounts for unauthorized additions\n\
                                  Reference: https://www.drupal.org/SA-CORE-2014-005".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for Drupalgeddon2 (SA-CORE-2018-002) - Drupal 7 < 7.58, 8 < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1
            let drupalgeddon2_vulnerable = match ver.major {
                7 => ver.minor < 58,
                8 => {
                    (ver.minor < 3) ||
                    (ver.minor == 3 && ver.patch < 9) ||
                    (ver.minor == 4 && ver.patch < 6) ||
                    (ver.minor == 5 && ver.patch < 1)
                }
                _ => false,
            };

            if drupalgeddon2_vulnerable {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_drupalgeddon2_{}", Self::generate_id()),
                    vuln_type: "Drupalgeddon2 (SA-CORE-2018-002)".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Remote Code Execution".to_string(),
                    url: base_url.clone(),
                    parameter: None,
                    payload: "Form API RCE".to_string(),
                    description: format!(
                        "Drupal version {}.{}.{} is vulnerable to Drupalgeddon2 (CVE-2018-7600).\n\
                        This vulnerability allows unauthenticated remote code execution via the \
                        Form API by exploiting the render array system.\n\n\
                        Exploit code is publicly available and actively exploited in the wild.",
                        ver.major, ver.minor, ver.patch
                    ),
                    evidence: Some(format!("Drupal version {}.{}.{} detected", ver.major, ver.minor, ver.patch)),
                    cwe: "CWE-94".to_string(),
                    cvss: 10.0,
                    verified: true,
                    false_positive: false,
                    remediation: "CRITICAL: Update Drupal core IMMEDIATELY.\n\
                                  Drupal 7: Update to 7.58 or later\n\
                                  Drupal 8.3.x: Update to 8.3.9\n\
                                  Drupal 8.4.x: Update to 8.4.6\n\
                                  Drupal 8.5.x: Update to 8.5.1 or later\n\
                                  Reference: https://www.drupal.org/SA-CORE-2018-002".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for Drupalgeddon3 (SA-CORE-2018-004) - Drupal 7 < 7.59, 8 < 8.4.8, 8.5.x < 8.5.3
            let drupalgeddon3_vulnerable = match ver.major {
                7 => ver.minor < 59,
                8 => {
                    (ver.minor < 4) ||
                    (ver.minor == 4 && ver.patch < 8) ||
                    (ver.minor == 5 && ver.patch < 3)
                }
                _ => false,
            };

            if drupalgeddon3_vulnerable && !drupalgeddon2_vulnerable {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_drupalgeddon3_{}", Self::generate_id()),
                    vuln_type: "Drupalgeddon3 (SA-CORE-2018-004)".to_string(),
                    severity: Severity::Critical,
                    confidence: Confidence::High,
                    category: "Remote Code Execution".to_string(),
                    url: base_url.clone(),
                    parameter: None,
                    payload: "Authenticated RCE".to_string(),
                    description: format!(
                        "Drupal version {}.{}.{} is vulnerable to Drupalgeddon3 (CVE-2018-7602).\n\
                        This vulnerability allows authenticated users with the ability to delete \
                        content to execute arbitrary code.",
                        ver.major, ver.minor, ver.patch
                    ),
                    evidence: Some(format!("Drupal version {}.{}.{} detected", ver.major, ver.minor, ver.patch)),
                    cwe: "CWE-94".to_string(),
                    cvss: 9.0,
                    verified: true,
                    false_positive: false,
                    remediation: "Update Drupal core immediately.\n\
                                  Drupal 7: Update to 7.59 or later\n\
                                  Drupal 8.4.x: Update to 8.4.8\n\
                                  Drupal 8.5.x: Update to 8.5.3 or later\n\
                                  Reference: https://www.drupal.org/SA-CORE-2018-004".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        vulnerabilities
    }

    /// Test user enumeration
    async fn test_user_enumeration(&self, url: &str, version: &Option<DrupalVersion>) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);
        let mut found_users = Vec::new();

        // Test user/N paths (Drupal 7 style)
        for i in 1..=10 {
            let user_url = format!("{}/user/{}", base_url, i);
            if let Ok(response) = self.http_client.get(&user_url).await {
                if response.status_code == 200 {
                    // Extract username from page
                    let title_re = Regex::new(r#"<title>([^|<]+)"#).ok();
                    if let Some(re) = title_re {
                        if let Some(cap) = re.captures(&response.body) {
                            if let Some(name) = cap.get(1) {
                                let username = name.as_str().trim().to_string();
                                if !username.is_empty() && !found_users.contains(&username) {
                                    found_users.push(username);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Test JSON API user enumeration (Drupal 8+)
        if version.as_ref().map(|v| v.major >= 8).unwrap_or(true) {
            let json_endpoints = vec![
                "/jsonapi/user/user",
                "/api/user",
                "/?_format=json&_path=/user",
            ];

            for endpoint in json_endpoints {
                let test_url = format!("{}{}", base_url, endpoint);
                if let Ok(response) = self.http_client.get(&test_url).await {
                    if response.status_code == 200 && response.body.contains("\"name\"") {
                        let name_re = Regex::new(r#""name"\s*:\s*"([^"]+)""#).ok();
                        if let Some(re) = name_re {
                            for cap in re.captures_iter(&response.body) {
                                if let Some(name) = cap.get(1) {
                                    let username = name.as_str().to_string();
                                    if !found_users.contains(&username) {
                                        found_users.push(username);
                                    }
                                }
                            }
                        }

                        vulnerabilities.push(Vulnerability {
                            id: format!("drupal_jsonapi_users_{}", Self::generate_id()),
                            vuln_type: "Drupal JSON API User Enumeration".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url,
                            parameter: None,
                            payload: endpoint.to_string(),
                            description: "Drupal JSON API exposes user information. \
                                This allows attackers to enumerate usernames for targeted attacks.".to_string(),
                            evidence: Some(format!(
                                "JSON API returns user data. Preview: {}...",
                                &response.body.chars().take(300).collect::<String>()
                            )),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Disable JSON API for anonymous users\n\
                                          2. Configure permissions to restrict user endpoint access\n\
                                          3. Use the JSON:API Extras module for fine-grained control".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        // Test password reset user enumeration
        let reset_url = format!("{}/user/password", base_url);
        if let Ok(response) = self.http_client.get(&reset_url).await {
            if response.status_code == 200 {
                // Try to submit password reset for a known user
                let test_users = vec!["admin", "root", "administrator", "webmaster"];
                for test_user in test_users {
                    let form_data = format!("name={}&form_id=user_pass", test_user);
                    if let Ok(reset_response) = self.http_client.post(&reset_url, form_data).await {
                        // Different error messages can indicate if user exists
                        if reset_response.body.contains("Further instructions") ||
                           reset_response.body.contains("sent to") ||
                           (reset_response.status_code == 302 && !reset_response.body.contains("not recognized")) {
                            found_users.push(test_user.to_string());
                        }
                    }
                }
            }
        }

        if !found_users.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: format!("drupal_user_enum_{}", Self::generate_id()),
                vuln_type: "Drupal User Enumeration".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: format!("{}/user/1", base_url),
                parameter: None,
                payload: "/user/N".to_string(),
                description: format!(
                    "Drupal allows user enumeration. {} usernames discovered: {}",
                    found_users.len(),
                    found_users.join(", ")
                ),
                evidence: Some(format!("Enumerated users: {}", found_users.join(", "))),
                cwe: "CWE-200".to_string(),
                cvss: 5.3,
                verified: true,
                false_positive: false,
                remediation: "1. Install and configure the Username Enumeration Prevention module\n\
                              2. Configure permissions to restrict user profile access\n\
                              3. Use the Rabbit Hole module to control access to user pages".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        vulnerabilities
    }

    /// Test version disclosure
    async fn test_version_disclosure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let version_files = vec![
            ("/CHANGELOG.txt", "Changelog - version history"),
            ("/core/CHANGELOG.txt", "Drupal 8+ core changelog"),
            ("/INSTALL.txt", "Installation instructions"),
            ("/core/INSTALL.txt", "Drupal 8+ install file"),
            ("/README.txt", "Readme file"),
            ("/core/README.txt", "Drupal 8+ readme"),
            ("/UPGRADE.txt", "Upgrade instructions"),
            ("/LICENSE.txt", "License file"),
            ("/MAINTAINERS.txt", "Maintainers list"),
        ];

        for (file, description) in version_files {
            let test_url = format!("{}{}", base_url, file);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.contains("Drupal") {
                    // Extract version if present
                    let version_re = Regex::new(r#"Drupal\s*(\d+\.\d+(?:\.\d+)?)"#).ok();
                    let version = version_re.and_then(|re| {
                        re.captures(&response.body)
                            .and_then(|cap| cap.get(1).map(|v| v.as_str().to_string()))
                    });

                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_version_file_{}", Self::generate_id()),
                        vuln_type: "Drupal Version Disclosure via File".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: "Information Disclosure".to_string(),
                        url: test_url,
                        parameter: None,
                        payload: file.to_string(),
                        description: format!(
                            "Drupal {} exposed: {}\n{}",
                            description,
                            file,
                            version.as_ref().map(|v| format!("Detected version: {}", v)).unwrap_or_default()
                        ),
                        evidence: Some(format!(
                            "File content preview: {}...",
                            &response.body.chars().take(300).collect::<String>()
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 3.7,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove or restrict access to version disclosure files:\n\
                                      Add to .htaccess:\n\
                                      <FilesMatch \"\\.(txt|md)$\">\n\
                                        Order Allow,Deny\n\
                                        Deny from all\n\
                                      </FilesMatch>".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break; // Found one, no need to continue
                }
            }
        }

        vulnerabilities
    }

    /// Test configuration file exposure
    async fn test_config_exposure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let config_files = vec![
            "/sites/default/settings.php",
            "/sites/default/settings.php.bak",
            "/sites/default/settings.php.old",
            "/sites/default/settings.php~",
            "/sites/default/settings.local.php",
            "/sites/default/services.yml",
            "/sites/default/default.settings.php",
            "/.env",
            "/.env.local",
        ];

        for file in config_files {
            let test_url = format!("{}{}", base_url, file);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let has_sensitive = response.body.contains("database") ||
                                        response.body.contains("password") ||
                                        response.body.contains("DB_") ||
                                        response.body.contains("$databases") ||
                                        response.body.contains("hash_salt");

                    if has_sensitive {
                        vulnerabilities.push(Vulnerability {
                            id: format!("drupal_config_exposed_{}", Self::generate_id()),
                            vuln_type: "Drupal Configuration File Exposed".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Sensitive Data Exposure".to_string(),
                            url: test_url,
                            parameter: None,
                            payload: file.to_string(),
                            description: format!(
                                "Drupal configuration file exposed: {}\n\
                                This file may contain database credentials, hash salt, \
                                and other sensitive configuration values.",
                                file
                            ),
                            evidence: Some("Configuration file contains sensitive settings".to_string()),
                            cwe: "CWE-200".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Change all exposed credentials immediately!\n\
                                          2. Remove backup configuration files\n\
                                          3. Ensure settings.php is not publicly accessible\n\
                                          4. Regenerate hash_salt\n\
                                          5. Check for signs of compromise".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test admin paths exposure
    async fn test_admin_exposure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let admin_paths = vec![
            "/admin",
            "/admin/config",
            "/admin/structure",
            "/admin/people",
            "/admin/modules",
            "/admin/reports/status",
            "/admin/reports/dblog",
        ];

        for path in admin_paths {
            let test_url = format!("{}{}", base_url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let has_admin_content = response.body.contains("Administration") ||
                                            response.body.contains("admin-menu") ||
                                            response.body.contains("system-admin") ||
                                            response.body.contains("toolbar-menu");

                    if has_admin_content {
                        vulnerabilities.push(Vulnerability {
                            id: format!("drupal_admin_access_{}", Self::generate_id()),
                            vuln_type: "Drupal Admin Area Accessible".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Access Control".to_string(),
                            url: test_url,
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "Drupal admin area is accessible without authentication: {}\n\
                                This indicates a severe misconfiguration or compromised site.",
                                path
                            ),
                            evidence: Some("Admin interface content detected".to_string()),
                            cwe: "CWE-284".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. CRITICAL: Review and fix user permissions immediately\n\
                                          2. Check for unauthorized admin accounts\n\
                                          3. Review recent changes to the site\n\
                                          4. Check for signs of compromise\n\
                                          5. Ensure anonymous user role has no admin permissions".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test installation/update file exposure
    async fn test_installation_exposure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Test install.php
        let install_url = format!("{}/install.php", base_url);
        if let Ok(response) = self.http_client.get(&install_url).await {
            if response.status_code == 200 {
                let is_installer = response.body.contains("Install Drupal") ||
                                   response.body.contains("installation") ||
                                   response.body.contains("Choose language");

                if is_installer {
                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_install_exposed_{}", Self::generate_id()),
                        vuln_type: "Drupal Installation Script Accessible".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Misconfiguration".to_string(),
                        url: install_url,
                        parameter: None,
                        payload: "/install.php".to_string(),
                        description: "Drupal installation script is accessible. \
                            While Drupal prevents reinstallation if already configured, \
                            this script should be removed or protected.".to_string(),
                        evidence: Some("Installation script responds with installer page".to_string()),
                        cwe: "CWE-16".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Remove install.php after installation\n\
                                      2. Or block access via .htaccess:\n\
                                      <Files install.php>\n\
                                        Order Allow,Deny\n\
                                        Deny from all\n\
                                      </Files>".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        // Test update.php
        let update_url = format!("{}/update.php", base_url);
        if let Ok(response) = self.http_client.get(&update_url).await {
            if response.status_code == 200 && response.body.contains("update") {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_update_exposed_{}", Self::generate_id()),
                    vuln_type: "Drupal Update Script Accessible".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Misconfiguration".to_string(),
                    url: update_url,
                    parameter: None,
                    payload: "/update.php".to_string(),
                    description: "Drupal update.php script is accessible. \
                        This script should be protected to prevent unauthorized database updates.".to_string(),
                    evidence: Some("Update script accessible".to_string()),
                    cwe: "CWE-16".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Set $settings['update_free_access'] = FALSE in settings.php\n\
                                  2. Block access via .htaccess when not needed".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        vulnerabilities
    }

    /// Test cron.php exposure
    async fn test_cron_exposure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Test cron.php without key
        let cron_url = format!("{}/cron.php", base_url);
        if let Ok(response) = self.http_client.get(&cron_url).await {
            if response.status_code == 200 {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_cron_exposed_{}", Self::generate_id()),
                    vuln_type: "Drupal Cron Accessible Without Key".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: "Misconfiguration".to_string(),
                    url: cron_url,
                    parameter: None,
                    payload: "/cron.php".to_string(),
                    description: "Drupal cron.php is accessible without cron key. \
                        This can be used to trigger cron tasks externally or for DoS attacks.".to_string(),
                    evidence: Some("Cron script accessible without authentication".to_string()),
                    cwe: "CWE-16".to_string(),
                    cvss: 3.7,
                    verified: true,
                    false_positive: false,
                    remediation: "Configure cron key in settings.php and update cron URL:\n\
                                  $settings['cron_key'] = 'YOUR_SECRET_KEY';\n\
                                  Then use: /cron/YOUR_SECRET_KEY".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        vulnerabilities
    }

    /// Test REST/JSON API exposure
    async fn test_api_exposure(&self, url: &str, _version: &Option<DrupalVersion>) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let api_endpoints = vec![
            ("/jsonapi", "JSON:API"),
            ("/rest", "REST API"),
            ("/api", "API endpoint"),
            ("/services", "Services module"),
            ("/?_format=json", "Format parameter"),
            ("/?_format=hal_json", "HAL+JSON format"),
        ];

        for (endpoint, name) in api_endpoints {
            let test_url = format!("{}{}", base_url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.contains("\"data\"") ||
                    response.body.contains("\"links\"") ||
                    response.body.contains("\"jsonapi\"") ||
                    response.body.contains("services")) {

                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_api_exposed_{}", Self::generate_id()),
                        vuln_type: format!("Drupal {} Exposed", name),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        category: "API Security".to_string(),
                        url: test_url,
                        parameter: None,
                        payload: endpoint.to_string(),
                        description: format!(
                            "Drupal {} is publicly accessible.\n\
                            This may expose sensitive data or functionality depending on configuration.",
                            name
                        ),
                        evidence: Some(format!(
                            "API response preview: {}...",
                            &response.body.chars().take(300).collect::<String>()
                        )),
                        cwe: "CWE-200".to_string(),
                        cvss: 5.3,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Review API permissions and restrict anonymous access\n\
                                      2. Configure JSON:API resource types carefully\n\
                                      3. Use authentication for sensitive endpoints\n\
                                      4. Consider disabling unused API modules".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        vulnerabilities
    }

    /// Test for vulnerable modules
    async fn test_module_vulnerabilities(&self, url: &str, version: &Option<DrupalVersion>) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Common module paths to check
        let modules_base = if version.as_ref().map(|v| v.major >= 8).unwrap_or(false) {
            vec!["/modules/contrib/", "/modules/"]
        } else {
            vec!["/sites/all/modules/", "/sites/default/modules/"]
        };

        for (module_name, vulns) in &self.known_vulnerable_modules {
            for base in &modules_base {
                let info_path = format!("{}{}{}/{}.info", base_url, base, module_name, module_name);
                let info_yml_path = format!("{}{}{}/{}.info.yml", base_url, base, module_name, module_name);

                for path in [info_path, info_yml_path] {
                    if let Ok(response) = self.http_client.get(&path).await {
                        if response.status_code == 200 {
                            // Extract version
                            let version_re = Regex::new(r#"version\s*[=:]\s*["']?([^"'\n]+)"#).ok();
                            let module_version = version_re.and_then(|re| {
                                re.captures(&response.body)
                                    .and_then(|cap| cap.get(1).map(|v| v.as_str().to_string()))
                            });

                            if let Some(ver) = module_version {
                                for vuln in vulns {
                                    if Self::is_version_vulnerable(&ver, &vuln.vulnerable_version) {
                                        vulnerabilities.push(Vulnerability {
                                            id: format!("drupal_module_vuln_{}", Self::generate_id()),
                                            vuln_type: format!("Vulnerable Drupal Module: {}", module_name),
                                            severity: vuln.severity.clone(),
                                            confidence: Confidence::High,
                                            category: "Known Vulnerability".to_string(),
                                            url: path.clone(),
                                            parameter: None,
                                            payload: module_name.clone(),
                                            description: format!(
                                                "Vulnerable module detected: {} version {}\n\n\
                                                Vulnerability: {}\n\
                                                SA ID: {}\n\
                                                CVE: {}",
                                                module_name, ver,
                                                vuln.description,
                                                vuln.sa_id.as_ref().unwrap_or(&"N/A".to_string()),
                                                vuln.cve.as_ref().unwrap_or(&"N/A".to_string())
                                            ),
                                            evidence: Some(format!("Module {} version {} detected", module_name, ver)),
                                            cwe: "CWE-1035".to_string(),
                                            cvss: match vuln.severity {
                                                Severity::Critical => 9.8,
                                                Severity::High => 7.5,
                                                Severity::Medium => 5.3,
                                                _ => 3.7,
                                            },
                                            verified: true,
                                            false_positive: false,
                                            remediation: format!(
                                                "Update {} module to the latest version:\n\
                                                drush up {}\n\
                                                Reference: https://www.drupal.org/project/{}",
                                                module_name, module_name, module_name
                                            ),
                                            discovered_at: chrono::Utc::now().to_rfc3339(),
                                        });
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test directory listing
    async fn test_directory_listing(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let directories = vec![
            "/sites/default/files/",
            "/sites/all/modules/",
            "/sites/all/themes/",
            "/modules/",
            "/themes/",
            "/profiles/",
        ];

        for dir in directories {
            let test_url = format!("{}{}", base_url, dir);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let has_listing = response.body.contains("Index of") ||
                                      response.body.contains("Parent Directory");

                    if has_listing {
                        vulnerabilities.push(Vulnerability {
                            id: format!("drupal_dir_listing_{}", Self::generate_id()),
                            vuln_type: "Drupal Directory Listing Enabled".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Information Disclosure".to_string(),
                            url: test_url,
                            parameter: None,
                            payload: dir.to_string(),
                            description: format!("Directory listing enabled at: {}", dir),
                            evidence: Some("Directory index visible".to_string()),
                            cwe: "CWE-548".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Add to .htaccess: Options -Indexes".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Test backup file exposure
    async fn test_backup_exposure(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let backup_patterns = vec![
            "/backup.sql",
            "/database.sql",
            "/drupal.sql",
            "/sites/default/files/backup.sql",
            "/sites/default/files/backup/",
        ];

        for pattern in backup_patterns {
            let test_url = format!("{}{}", base_url, pattern);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 &&
                   (response.body.contains("CREATE TABLE") ||
                    response.body.contains("INSERT INTO") ||
                    response.body.contains("Index of")) {

                    let severity = if response.body.contains("CREATE TABLE") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_backup_{}", Self::generate_id()),
                        vuln_type: "Drupal Database Backup Exposed".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Sensitive Data Exposure".to_string(),
                        url: test_url,
                        parameter: None,
                        payload: pattern.to_string(),
                        description: "Database backup or backup directory exposed publicly.".to_string(),
                        evidence: Some("Backup file/directory accessible".to_string()),
                        cwe: "CWE-200".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Remove backup files immediately\n\
                                      2. Change all credentials\n\
                                      3. Never store backups in web-accessible directories".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        vulnerabilities
    }

    /// Test private files access
    async fn test_private_files(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let private_paths = vec![
            "/sites/default/files/private/",
            "/system/files/",
            "/private/",
        ];

        for path in private_paths {
            let test_url = format!("{}{}", base_url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 && response.body.contains("Index of") {
                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_private_files_{}", Self::generate_id()),
                        vuln_type: "Drupal Private Files Directory Exposed".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Access Control".to_string(),
                        url: test_url,
                        parameter: None,
                        payload: path.to_string(),
                        description: "Private files directory is publicly accessible with directory listing.".to_string(),
                        evidence: Some("Private directory listing visible".to_string()),
                        cwe: "CWE-284".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Move private files outside web root\n\
                                      2. Configure file system path in admin/config/media/file-system\n\
                                      3. Disable directory listing".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// Test status report access
    async fn test_status_report_access(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        let status_url = format!("{}/admin/reports/status", base_url);
        if let Ok(response) = self.http_client.get(&status_url).await {
            if response.status_code == 200 && response.body.contains("Status report") {
                vulnerabilities.push(Vulnerability {
                    id: format!("drupal_status_report_{}", Self::generate_id()),
                    vuln_type: "Drupal Status Report Publicly Accessible".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Information Disclosure".to_string(),
                    url: status_url,
                    parameter: None,
                    payload: "/admin/reports/status".to_string(),
                    description: "Drupal status report page is publicly accessible. \
                        This page reveals detailed system information including PHP version, \
                        database info, and security issues.".to_string(),
                    evidence: Some("Status report page accessible without authentication".to_string()),
                    cwe: "CWE-200".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Review and fix permissions for administrator role. \
                        Status report should only be accessible to authenticated admins.".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        vulnerabilities
    }

    /// Test PHP filter module
    async fn test_php_filter_module(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Check for PHP filter module presence
        let php_filter_paths = vec![
            "/modules/php/",
            "/core/modules/php/",
            "/sites/all/modules/php/",
        ];

        for path in php_filter_paths {
            let test_url = format!("{}{}", base_url, path);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 || response.status_code == 403 {
                    vulnerabilities.push(Vulnerability {
                        id: format!("drupal_php_filter_{}", Self::generate_id()),
                        vuln_type: "Drupal PHP Filter Module Detected".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "Dangerous Configuration".to_string(),
                        url: test_url,
                        parameter: None,
                        payload: path.to_string(),
                        description: "PHP Filter module appears to be present. \
                            This module allows PHP code execution in content and is highly dangerous. \
                            It should never be enabled in production.".to_string(),
                        evidence: Some("PHP filter module directory detected".to_string()),
                        cwe: "CWE-94".to_string(),
                        cvss: 8.1,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Disable and uninstall PHP Filter module immediately\n\
                                      2. Remove the module files from the server\n\
                                      3. Audit content for embedded PHP code\n\
                                      4. Use safer alternatives like Twig templates".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                    break;
                }
            }
        }

        vulnerabilities
    }

    /// Test Form API vulnerabilities
    async fn test_form_api_vulnerabilities(&self, url: &str, version: &Option<DrupalVersion>) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Test Drupalgeddon2 style payloads (non-destructive test)
        if version.as_ref().map(|v| v.major >= 8).unwrap_or(true) {
            let test_paths = vec![
                "/user/register",
                "/user/password",
                "/contact",
            ];

            for path in test_paths {
                let test_url = format!("{}{}", base_url, path);
                if let Ok(response) = self.http_client.get(&test_url).await {
                    if response.status_code == 200 && response.body.contains("form") {
                        // Check for unprotected form elements
                        if response.body.contains("mail[#post_render]") ||
                           response.body.contains("account[mail]") ||
                           response.body.contains("#lazy_builder") {
                            vulnerabilities.push(Vulnerability {
                                id: format!("drupal_form_api_{}", Self::generate_id()),
                                vuln_type: "Potentially Vulnerable Form API Usage".to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Low,
                                category: "Code Quality".to_string(),
                                url: test_url,
                                parameter: None,
                                payload: path.to_string(),
                                description: "Form contains render elements that may be vulnerable \
                                    to Drupalgeddon2-style attacks if not properly sanitized.".to_string(),
                                evidence: Some("Suspicious form elements detected".to_string()),
                                cwe: "CWE-94".to_string(),
                                cvss: 5.3,
                                verified: false,
                                false_positive: false,
                                remediation: "Update Drupal core to the latest version and review form implementations.".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Helper: Get base URL
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

    /// Helper: Check if version is vulnerable
    fn is_version_vulnerable(current: &str, vulnerable: &str) -> bool {
        // Simple version comparison - in production would use semver
        let parse_version = |v: &str| -> Vec<u32> {
            v.split(|c: char| !c.is_numeric())
                .filter_map(|s| s.parse().ok())
                .collect()
        };

        let current_parts = parse_version(current);
        let vuln_parts = parse_version(vulnerable);

        for (c, v) in current_parts.iter().zip(vuln_parts.iter()) {
            if c < v {
                return true;
            }
            if c > v {
                return false;
            }
        }

        current_parts.len() <= vuln_parts.len()
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(DrupalSecurityScanner::is_version_vulnerable("7.31", "7.32"));
        assert!(DrupalSecurityScanner::is_version_vulnerable("8.4.5", "8.4.6"));
        assert!(!DrupalSecurityScanner::is_version_vulnerable("7.58", "7.32"));
    }
}
