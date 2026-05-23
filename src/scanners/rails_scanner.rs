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

        // (path, friendly name, content markers). A marker must appear in the
        // body to confirm the genuine Rails debug page, so an SPA / catch-all
        // route returning 200 for every path cannot produce a false positive.
        let debug_paths = vec![
            (
                "/rails/info/properties",
                "Rails Info",
                vec!["rails version", "ruby version"],
            ),
            (
                "/rails/info/routes",
                "Rails Routes",
                vec!["controller#action", "http verb"],
            ),
            (
                "/__better_errors",
                "Better Errors",
                vec![
                    "better errors",
                    "bettererrors",
                    "no errors have been recorded",
                ],
            ),
        ];

        for (path, name, markers) in debug_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                let body_l = response.body.to_lowercase();
                if response.status_code == 200 && markers.iter().any(|m| body_l.contains(*m)) {
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

        // config/master.key decrypts config/credentials.yml.enc, exposing
        // secret_key_base, database credentials and every stored third-party
        // secret. The file is exactly a 32-character hex string, so matching
        // that exact shape makes a false positive practically impossible.
        tests += 1;
        let master_key_url = format!("{}/config/master.key", target);
        if let Ok(response) = self.http_client.get(&master_key_url).await {
            if response.status_code == 200 {
                let trimmed = response.body.trim();
                if trimmed.len() == 32 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                    vulnerabilities.push(self.disclosure_vuln(
                        &master_key_url,
                        "/config/master.key",
                        Severity::Critical,
                        9.8,
                        "Rails master key (config/master.key) exposed - decrypts \
                         config/credentials.yml.enc, revealing secret_key_base, database \
                         credentials and all stored third-party secrets"
                            .to_string(),
                        "32-character hex master key returned".to_string(),
                        "CWE-798",
                    ));
                }
            }
        }

        // config/credentials.yml.enc is the encrypted secret store; its content
        // is three base64 segments joined by "--" (MessageEncryptor format).
        // Combined with an exposed master key it yields full compromise.
        tests += 1;
        let creds_url = format!("{}/config/credentials.yml.enc", target);
        if let Ok(response) = self.http_client.get(&creds_url).await {
            if response.status_code == 200 {
                let trimmed = response.body.trim();
                let parts: Vec<&str> = trimmed.split("--").collect();
                let is_creds = parts.len() == 3
                    && trimmed.len() > 50
                    && !trimmed.contains('<')
                    && parts.iter().all(|p| {
                        !p.is_empty()
                            && p.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
                            })
                    });
                if is_creds {
                    vulnerabilities.push(self.disclosure_vuln(
                        &creds_url,
                        "/config/credentials.yml.enc",
                        Severity::High,
                        7.5,
                        "Rails encrypted credentials (config/credentials.yml.enc) exposed - \
                         decryptable to the full secret store if config/master.key or \
                         RAILS_MASTER_KEY is also obtained"
                            .to_string(),
                        "MessageEncryptor base64 ciphertext returned".to_string(),
                        "CWE-200",
                    ));
                }
            }
        }

        // Plaintext config / secret files, confirmed by a sensitive pattern and
        // guarded against SPA catch-all HTML responses.
        let env_paths = vec![
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/storage.yml",
            "/config/initializers/secret_token.rb",
            "/.env",
            "/.env.production",
            "/.env.development",
        ];

        let sensitive_patterns = vec![
            "secret_key_base",
            "secret_token",
            "secret_key",
            "database_url",
            "password:",
            "adapter:",
            "access_key_id",
            "secret_access_key",
            "aws_secret",
            "private_key",
        ];

        for path in env_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    let body_l = response.body.to_lowercase();
                    // Skip SPA / catch-all HTML responses.
                    if body_l.contains("<html") || body_l.contains("<!doctype") {
                        continue;
                    }
                    if let Some(pattern) =
                        sensitive_patterns.iter().copied().find(|p| body_l.contains(*p))
                    {
                        vulnerabilities.push(self.disclosure_vuln(
                            &url,
                            path,
                            Severity::Critical,
                            9.1,
                            format!("Rails environment/configuration file exposed: {}", path),
                            format!("Sensitive pattern found: {}", pattern),
                            "CWE-538",
                        ));
                    }
                }
            }
        }

        Ok((vulnerabilities, tests))
    }

    #[allow(clippy::too_many_arguments)]
    fn disclosure_vuln(
        &self,
        url: &str,
        path: &str,
        severity: Severity,
        cvss: f32,
        description: String,
        evidence: String,
        cwe: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: generate_vuln_id(),
            vuln_type: "Information Disclosure".to_string(),
            severity,
            confidence: Confidence::High,
            category: "Framework Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: path.to_string(),
            description,
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation:
                "Remove sensitive files from web-accessible paths, block them at the web server, \
                 and rotate any exposed secrets"
                    .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_confidence: None,
            ml_data: None,
        }
    }

    async fn check_log_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let log_paths = vec!["/log/development.log", "/log/production.log"];

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
}

fn generate_vuln_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("RAILS-{:x}", timestamp)
}
