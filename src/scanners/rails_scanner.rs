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

        let (admin_vulns, t) = self.check_admin_panels(target).await?;
        vulnerabilities.extend(admin_vulns);
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

        // (path, label, content_signatures, severity)
        //
        // Every path requires at least one signature in the response body to be
        // reported. Signatures are picked so a coincidental 200 with unrelated
        // content (a SPA shell, a 404-rewritten HTML page, etc.) cannot match.
        let env_paths: &[(&str, &str, &[&str], Severity)] = &[
            // --- Dotenv-style files: full credential leak ---
            (
                "/.env",
                "Rails .env file exposed",
                &[
                    "DATABASE_URL=",
                    "SECRET_KEY_BASE=",
                    "RAILS_MASTER_KEY=",
                    "AWS_ACCESS_KEY_ID=",
                    "AWS_SECRET_ACCESS_KEY=",
                    "STRIPE_SECRET_KEY=",
                    "REDIS_URL=",
                ],
                Severity::Critical,
            ),
            (
                "/.env.production",
                ".env.production exposed",
                &["DATABASE_URL=", "SECRET_KEY_BASE=", "RAILS_MASTER_KEY="],
                Severity::Critical,
            ),
            (
                "/.env.development",
                ".env.development exposed",
                &["DATABASE_URL=", "SECRET_KEY_BASE="],
                Severity::High,
            ),
            (
                "/.env.local",
                ".env.local exposed",
                &["DATABASE_URL=", "SECRET_KEY_BASE="],
                Severity::Critical,
            ),
            // --- Database connections ---
            (
                "/config/database.yml",
                "Rails database.yml exposed",
                &["adapter:", "database:", "username:", "password:", "host:"],
                Severity::Critical,
            ),
            (
                "/config/database.yml.example",
                "Rails database.yml.example template exposed",
                &["adapter:", "database:", "username:"],
                Severity::Low,
            ),
            // --- Pre-Rails 5.2 secrets (plaintext) ---
            (
                "/config/secrets.yml",
                "Rails secrets.yml exposed (pre-5.2 plaintext secret_key_base)",
                &["secret_key_base:", "secret_key_base ="],
                Severity::Critical,
            ),
            // --- Rails 5.2+ credentials (encrypted) — the .key file decrypts the .yml.enc ---
            (
                "/config/master.key",
                "Rails master.key exposed — decrypts credentials.yml.enc",
                // master.key is a 32-byte hex string; require the file to actually look like one
                // (length and hex-only). We additionally accept the literal banner present in
                // some template repos.
                &[],
                Severity::Critical,
            ),
            (
                "/config/credentials.yml.enc",
                "Rails encrypted credentials file exposed",
                // First 32 chars are the IV in hex, separated from ciphertext by '--'
                &["--"],
                Severity::High,
            ),
            (
                "/config/credentials/production.key",
                "Rails per-env production.key exposed — decrypts production.yml.enc",
                &[],
                Severity::Critical,
            ),
            (
                "/config/credentials/production.yml.enc",
                "Rails per-env production credentials exposed",
                &["--"],
                Severity::High,
            ),
            (
                "/config/credentials/staging.key",
                "Rails per-env staging.key exposed",
                &[],
                Severity::Critical,
            ),
            (
                "/config/credentials/staging.yml.enc",
                "Rails per-env staging credentials exposed",
                &["--"],
                Severity::High,
            ),
            // --- Other Rails config files ---
            (
                "/config/storage.yml",
                "Rails storage.yml exposed (Active Storage cloud credentials)",
                &["service:", "access_key_id:", "secret_access_key:", "bucket:", "amazon", "google", "azure"],
                Severity::Critical,
            ),
            (
                "/config/cable.yml",
                "Rails cable.yml exposed",
                &["adapter:", "url:", "channel_prefix:"],
                Severity::Medium,
            ),
            (
                "/config/redis.yml",
                "Rails redis.yml exposed",
                &["url:", "redis://"],
                Severity::High,
            ),
            (
                "/config/sidekiq.yml",
                "Rails sidekiq.yml exposed",
                &["queues:", "concurrency:"],
                Severity::Low,
            ),
            (
                "/config/newrelic.yml",
                "New Relic license key exposed via newrelic.yml",
                &["license_key:"],
                Severity::High,
            ),
            // --- Schema / structure dumps (leak full DB layout) ---
            (
                "/db/schema.rb",
                "Rails db/schema.rb exposed — full DB schema disclosure",
                &["ActiveRecord::Schema", "create_table"],
                Severity::Medium,
            ),
            (
                "/db/structure.sql",
                "Rails db/structure.sql exposed — full DB schema (SQL dump)",
                &["CREATE TABLE", "CREATE SCHEMA", "PostgreSQL database dump"],
                Severity::Medium,
            ),
            (
                "/db/seeds.rb",
                "Rails db/seeds.rb exposed",
                &["Model.create", ".create!(", "User.create"],
                Severity::Low,
            ),
            // --- Dependency manifests ---
            (
                "/Gemfile",
                "Rails Gemfile exposed",
                &["source 'https://rubygems.org'", "gem 'rails'", "gem \"rails\""],
                Severity::Low,
            ),
            (
                "/Gemfile.lock",
                "Rails Gemfile.lock exposed — exact gem versions for CVE lookup",
                &["GEM\n", "BUNDLED WITH", "DEPENDENCIES"],
                Severity::Low,
            ),
            // --- Deploy / process manifests ---
            (
                "/Procfile",
                "Procfile exposed",
                &["web:", "worker:", "release:"],
                Severity::Low,
            ),
            (
                "/Rakefile",
                "Rakefile exposed",
                &["Rails.application.load_tasks", "require_relative"],
                Severity::Info,
            ),
            (
                "/config.ru",
                "Rack config.ru exposed",
                &["Rails.application", "run ", "require_relative"],
                Severity::Low,
            ),
            (
                "/config/environment.rb",
                "Rails environment.rb exposed",
                &["Rails.application.initialize!", "require_relative \"application\""],
                Severity::Low,
            ),
            (
                "/config/application.rb",
                "Rails application.rb exposed",
                &["class Application < Rails::Application", "module ", "config.load_defaults"],
                Severity::Low,
            ),
            (
                "/config/routes.rb",
                "Rails routes.rb exposed — full route map",
                &["Rails.application.routes.draw", "resources :", "get ", "post "],
                Severity::Medium,
            ),
            (
                "/config/initializers/secret_token.rb",
                "Legacy secret_token initializer exposed (Rails 3.x)",
                &["secret_token", "config.secret_token"],
                Severity::Critical,
            ),
            (
                "/config/initializers/devise.rb",
                "Devise initializer exposed",
                &["Devise.setup", "config.secret_key"],
                Severity::High,
            ),
        ];

        for (path, label, signatures, severity) in env_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            let response = match self.http_client.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if response.status_code != 200 || response.body.len() < 8 {
                continue;
            }

            // master.key / per-env *.key files have no banner — validate by shape.
            // Real master.key is exactly 32 lowercase hex chars (optionally followed
            // by a trailing newline). Anything else is a SPA shell or HTML 200.
            let body_trim = response.body.trim();
            let key_file = path.ends_with(".key");
            let has_signature = if key_file {
                let len_ok = matches!(body_trim.len(), 32 | 33 | 64 | 65);
                len_ok
                    && body_trim
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || c == '\n' || c == '\r')
            } else if signatures.is_empty() {
                false
            } else {
                signatures.iter().any(|s| response.body.contains(s))
            };

            if !has_signature {
                continue;
            }

            // HTML pages with an embedded fragment that happens to contain "adapter:"
            // are easy to filter: real YAML / .env / Ruby files don't start with
            // a doctype or an html tag.
            let looks_like_html = {
                let head: String = response.body.chars().take(64).collect();
                let head_lower = head.to_lowercase();
                head_lower.starts_with("<!doctype html")
                    || head_lower.starts_with("<html")
                    || head_lower.starts_with("<head")
            };
            if looks_like_html && !key_file {
                continue;
            }

            let cvss = match severity {
                Severity::Critical => 9.8,
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
                category: "Framework Security".to_string(),
                url: url.clone(),
                parameter: None,
                payload: path.to_string(),
                description: label.to_string(),
                evidence: Some(format!(
                    "Path: {}\nStatus: 200\nResponse matched a content signature unique to this file type.",
                    path
                )),
                cwe: "CWE-538".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: "1. Remove config and secret files from the public web root\n\
                              2. Rotate any credentials present in the exposed file immediately\n\
                              3. Ensure the web server denies serving dotfiles and the config/, db/, and tmp/ directories\n\
                              4. Use Rails credentials (encrypted) instead of plaintext secrets.yml\n\
                              5. Store production secrets in a secret manager (AWS Secrets Manager, Vault, Doppler) rather than committing them"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests))
    }

    async fn check_admin_panels(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // Background-job dashboards routinely mounted in Rails apps. When
        // unauthenticated they leak job arguments (often containing PII or tokens)
        // and let attackers enqueue arbitrary jobs.
        //
        // (path, label, content_signatures, severity)
        let panels: &[(&str, &str, &[&str], Severity)] = &[
            (
                "/sidekiq",
                "Sidekiq dashboard exposed",
                &["Sidekiq", "sidekiq.css", "sidekiq.js", "data-sidekiq-version"],
                Severity::High,
            ),
            (
                "/sidekiq/dashboard",
                "Sidekiq dashboard exposed",
                &["Sidekiq", "sidekiq.css", "sidekiq.js"],
                Severity::High,
            ),
            (
                "/sidekiq/busy",
                "Sidekiq workers page exposed",
                &["Sidekiq", "Busy", "Processed"],
                Severity::High,
            ),
            (
                "/sidekiq/queues",
                "Sidekiq queues page exposed",
                &["Sidekiq", "Queues", "Latency"],
                Severity::High,
            ),
            (
                "/sidekiq/retries",
                "Sidekiq retries page exposed",
                &["Sidekiq", "Retries"],
                Severity::High,
            ),
            (
                "/sidekiq/scheduled",
                "Sidekiq scheduled jobs exposed",
                &["Sidekiq", "Scheduled"],
                Severity::High,
            ),
            (
                "/sidekiq/dead",
                "Sidekiq dead set exposed",
                &["Sidekiq", "Dead"],
                Severity::High,
            ),
            (
                "/resque",
                "Resque web UI exposed",
                &["Resque", "resque/style.css", "resque.js"],
                Severity::High,
            ),
            (
                "/resque/overview",
                "Resque overview exposed",
                &["Resque", "Overview"],
                Severity::High,
            ),
            (
                "/admin/sidekiq",
                "Sidekiq dashboard mounted under /admin",
                &["Sidekiq", "sidekiq.css"],
                Severity::High,
            ),
            (
                "/admin/resque",
                "Resque mounted under /admin",
                &["Resque", "resque/style.css"],
                Severity::High,
            ),
            // RailsAdmin / ActiveAdmin: full DB editor
            (
                "/admin",
                "RailsAdmin/ActiveAdmin panel reachable",
                &[
                    "rails_admin",
                    "RailsAdmin",
                    "ActiveAdmin",
                    "active_admin.css",
                    "Sign in as administrator",
                ],
                Severity::High,
            ),
            (
                "/rails_admin",
                "RailsAdmin panel reachable",
                &["rails_admin", "RailsAdmin"],
                Severity::High,
            ),
            (
                "/admin/dashboard",
                "Admin dashboard reachable",
                &["RailsAdmin", "ActiveAdmin", "rails_admin", "active_admin"],
                Severity::High,
            ),
            // LetterOpener / MailCatcher / MailHog in dev mode
            (
                "/letter_opener",
                "letter_opener dev mailer UI exposed",
                &["Letter Opener", "letter_opener"],
                Severity::High,
            ),
            // Flipper feature flag UI
            (
                "/flipper",
                "Flipper UI exposed — feature flags toggleable",
                &["Flipper", "flipper.css"],
                Severity::Medium,
            ),
            // PgHero (Postgres dashboard)
            (
                "/pghero",
                "PgHero dashboard exposed — DB stats and slow queries",
                &["PgHero", "pghero.css"],
                Severity::High,
            ),
            // Blazer (SQL analytics)
            (
                "/blazer",
                "Blazer SQL analytics UI exposed",
                &["Blazer", "blazer.css"],
                Severity::High,
            ),
        ];

        for (path, label, signatures, severity) in panels {
            let url = format!("{}{}", target, path);
            tests += 1;

            let response = match self.http_client.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // 200 = reachable without auth. 401/403 with the signature = the
            // dashboard is mounted but protected (still useful recon, downgraded).
            let body_has_sig = signatures.iter().any(|s| response.body.contains(s));
            if !body_has_sig {
                continue;
            }

            let (effective_severity, cvss) = match response.status_code {
                200 => {
                    let cvss = match severity {
                        Severity::Critical => 9.1,
                        Severity::High => 7.5,
                        Severity::Medium => 5.3,
                        _ => 3.7,
                    };
                    (severity.clone(), cvss)
                }
                401 | 403 => (Severity::Info, 2.0),
                _ => continue,
            };

            vulnerabilities.push(Vulnerability {
                id: generate_vuln_id(),
                vuln_type: "Information Disclosure".to_string(),
                severity: effective_severity,
                confidence: Confidence::High,
                category: "Framework Security".to_string(),
                url: url.clone(),
                parameter: None,
                payload: path.to_string(),
                description: label.to_string(),
                evidence: Some(format!(
                    "Path: {}\nStatus: {}\nResponse contains the dashboard's own asset/markup signature.",
                    path, response.status_code
                )),
                cwe: "CWE-284".to_string(),
                cvss,
                verified: true,
                false_positive: false,
                remediation: "1. Mount admin/job dashboards inside an authenticated routes block\n\
                              2. Use Rack::Auth::Basic or Devise constraints in routes.rb (e.g. constraints: lambda { |r| r.session[:admin] })\n\
                              3. Disable letter_opener and other dev-only middleware in production\n\
                              4. Restrict by IP at the reverse proxy where possible"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
            });
        }

        Ok((vulnerabilities, tests))
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
