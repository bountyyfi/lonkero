// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct RailsScanner {
    http_client: Arc<HttpClient>,
}

impl RailsScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(
        &self,
        target: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let is_rails = self.detect_rails(target).await?;
        tests += 1;

        if !is_rails {
            debug!("Target does not appear to be a Rails application");
            return Ok((vulnerabilities, tests));
        }

        info!("Detected Rails application at {}", target);

        let (debug_vulns, t) = self.check_debug_mode(target).await?;
        vulnerabilities.extend(debug_vulns);
        tests += t;

        let (env_vulns, t) = self.check_environment_exposure(target).await?;
        vulnerabilities.extend(env_vulns);
        tests += t;

        let (log_vulns, t) = self.check_log_exposure(target).await?;
        vulnerabilities.extend(log_vulns);
        tests += t;

        let (session_vulns, t) = self.check_session_security(target).await?;
        vulnerabilities.extend(session_vulns);
        tests += t;

        let (asset_vulns, t) = self.check_asset_exposure(target).await?;
        vulnerabilities.extend(asset_vulns);
        tests += t;

        let (key_vulns, t) = self.check_master_key_exposure(target).await?;
        vulnerabilities.extend(key_vulns);
        tests += t;

        let (dashboard_vulns, t) = self.check_admin_dashboards(target).await?;
        vulnerabilities.extend(dashboard_vulns);
        tests += t;

        Ok((vulnerabilities, tests))
    }

    async fn detect_rails(&self, target: &str) -> Result<bool> {
        if let Ok(response) = self.http_client.get(target).await {
            if response.headers.contains_key("x-runtime") {
                return Ok(true);
            }
            if response.body.contains("csrf-param") && response.body.contains("csrf-token") {
                return Ok(true);
            }
            if response.body.contains("turbolinks") || response.body.contains("turbo-frame") {
                return Ok(true);
            }
            if response.body.contains("data-remote=\"true\"") || response.body.contains("rails-ujs")
            {
                return Ok(true);
            }
        }

        let rails_paths = vec!["/rails/info/properties", "/rails/info/routes"];
        for path in rails_paths {
            let url = format!("{}{}", target, path);
            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn check_debug_mode(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let debug_paths = vec![
            ("/rails/info/properties", "Rails Info"),
            ("/rails/info/routes", "Rails Routes"),
            ("/__better_errors", "Better Errors"),
        ];

        for (path, name) in debug_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "{} endpoint exposed - development mode likely enabled in production",
                            name
                        ),
                        evidence: Some(format!("Debug endpoint {} accessible", path)),
                        cwe: "CWE-215".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "Disable development mode in production environment"
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

    async fn check_environment_exposure(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let env_paths = vec![
            "/.env",
            "/.env.production",
            "/.env.local",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/storage.yml",
            "/config/cable.yml",
            "/config/newrelic.yml",
            "/config/initializers/secret_token.rb",
        ];

        for path in env_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                // A served Rails SPA returns its index.html with status 200 for
                // unknown paths. Skip HTML responses so we only flag the raw
                // config file actually being served.
                let looks_like_html = {
                    let head = response.body.get(..512).unwrap_or(&response.body);
                    let lower = head.to_lowercase();
                    lower.contains("<!doctype html") || lower.contains("<html")
                };
                if response.status_code == 200 && !looks_like_html {
                    let sensitive_patterns = vec![
                        "SECRET_KEY",
                        "secret_key_base",
                        "DATABASE_URL",
                        "password:",
                        "adapter:",
                        "access_key_id",
                        "secret_access_key",
                        "license_key",
                    ];
                    for pattern in &sensitive_patterns {
                        if response
                            .body
                            .to_lowercase()
                            .contains(&pattern.to_lowercase())
                        {
                            vulnerabilities.push(Vulnerability {
                                id: generate_vuln_id(),
                                vuln_type: "Information Disclosure".to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                category: "Framework Security".to_string(),
                                url: url.clone(),
                                parameter: None,
                                payload: path.to_string(),
                                description: format!(
                                    "Rails environment/configuration file exposed: {}",
                                    path
                                ),
                                evidence: Some(format!("Sensitive pattern found: {}", pattern)),
                                cwe: "CWE-538".to_string(),
                                cvss: 9.1,
                                verified: true,
                                false_positive: false,
                                remediation: "Remove configuration files from web root".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_log_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let log_paths = vec![
            "/log/development.log",
            "/log/production.log",
            "/log/staging.log",
            "/log/puma.log",
        ];

        for path in log_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 && response.body.len() > 100 {
                    if response.body.contains("Started") || response.body.contains("Processing by")
                    {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!("Rails log file exposed: {}", path),
                            evidence: Some("Log file contains request/response data".to_string()),
                            cwe: "CWE-532".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Remove log files from web-accessible directories"
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

    async fn check_session_security(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests = 1;

        if let Ok(response) = self.http_client.get(target).await {
            if let Some(cookie) = response.headers.get("set-cookie") {
                let cookie_lower = cookie.to_lowercase();
                if cookie_lower.contains("_session") {
                    let mut issues = Vec::new();
                    if !cookie_lower.contains("httponly") {
                        issues.push("Missing HttpOnly flag");
                    }
                    if !cookie_lower.contains("secure") && target.starts_with("https") {
                        issues.push("Missing Secure flag on HTTPS");
                    }
                    if !issues.is_empty() {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Insecure Session Configuration".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: target.to_string(),
                            parameter: Some("session cookie".to_string()),
                            payload: String::new(),
                            description: format!("Rails session cookie security issues: {}", issues.join(", ")),
                            evidence: Some(cookie.to_string()),
                            cwe: "CWE-614".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Configure session cookies with Secure, HttpOnly, and SameSite attributes".to_string(),
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

    async fn check_asset_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let asset_paths = vec![
            ("/assets/application.js.map", "source map"),
            ("/.git/config", "git config"),
        ];

        for (path, desc) in asset_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    if path.contains(".map") && response.body.contains("sourceContent") {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: format!(
                                "JavaScript {} exposed - reveals original source code",
                                desc
                            ),
                            evidence: Some("Source map file accessible".to_string()),
                            cwe: "CWE-200".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Remove source maps from production".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                        });
                    } else if path.contains(".git") && response.body.contains("[core]") {
                        vulnerabilities.push(Vulnerability {
                            id: generate_vuln_id(),
                            vuln_type: "Information Disclosure".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            category: "Framework Security".to_string(),
                            url: url.clone(),
                            parameter: None,
                            payload: path.to_string(),
                            description: "Git repository exposed - source code may be downloadable"
                                .to_string(),
                            evidence: Some("Git config file accessible".to_string()),
                            cwe: "CWE-538".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Remove .git directory from web root".to_string(),
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

    /// Probe for an exposed Rails `master.key` / per-environment credentials key.
    ///
    /// These files hold the 32-character hex key that decrypts
    /// `config/credentials.yml.enc` (which contains `secret_key_base`, DB and
    /// third-party credentials). A leaked key is a full secret compromise.
    ///
    /// The key is `SecureRandom.hex(16)`, so a real file is exactly 32 lowercase
    /// hex characters and nothing else. Requiring that exact shape means a false
    /// positive is effectively impossible — an HTML page or JSON error never
    /// matches.
    async fn check_master_key_exposure(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let key_paths = vec![
            "/config/master.key",
            "/config/credentials/production.key",
            "/config/credentials/staging.key",
            "/config/credentials/development.key",
        ];

        for path in key_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 {
                    continue;
                }
                let body = response.body.trim();
                let is_master_key =
                    body.len() == 32 && body.bytes().all(|b| b.is_ascii_hexdigit());
                if is_master_key {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Sensitive Credential Exposure".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Rails credentials key exposed: {}. This 32-char key decrypts \
                             config/credentials.yml.enc, revealing secret_key_base, database \
                             and third-party credentials.",
                            path
                        ),
                        evidence: Some(
                            "Response body is a bare 32-character hex master key".to_string(),
                        ),
                        cwe: "CWE-798".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove the key file from the web root, rotate the key and \
                                      all secrets it protected, and serve credentials via \
                                      RAILS_MASTER_KEY environment variable instead."
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

    /// Probe for unauthenticated mountable admin/operations dashboards that are
    /// commonly mounted in `config/routes.rb` without an auth constraint.
    ///
    /// Each is confirmed by two tool-specific markers in the response body so a
    /// generic 200 page cannot trigger a finding. These dashboards leak job
    /// arguments (often containing PII/tokens), query data and feature state,
    /// and frequently allow destructive actions.
    async fn check_admin_dashboards(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // (path, tool, marker_a, marker_b, severity, cvss)
        let dashboards = vec![
            (
                "/sidekiq",
                "Sidekiq",
                "Sidekiq",
                "Processed",
                Severity::High,
                7.5_f32,
            ),
            (
                "/pghero",
                "PgHero",
                "PgHero",
                "Queries",
                Severity::High,
                7.5,
            ),
            (
                "/flipper",
                "Flipper",
                "Flipper",
                "Features",
                Severity::Medium,
                5.3,
            ),
        ];

        for (path, tool, marker_a, marker_b, severity, cvss) in dashboards {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200
                    && response.body.contains(marker_a)
                    && response.body.contains(marker_b)
                {
                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Exposed Administrative Dashboard".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "{} dashboard mounted without authentication at {}. Exposes \
                             operational data and may allow destructive actions to anonymous users.",
                            tool, path
                        ),
                        evidence: Some(format!(
                            "Response contains '{}' and '{}'",
                            marker_a, marker_b
                        )),
                        cwe: "CWE-862".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation: format!(
                            "Wrap the {} mount in an authentication constraint in \
                             config/routes.rb (e.g. authenticate :user, ->(u) {{ u.admin? }}).",
                            tool
                        ),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_confidence: None,
                        ml_data: None,
                    });
                }
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
    format!("RAILS-{:x}", timestamp)
}
