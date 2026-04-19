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

        let (dashboard_vulns, t) = self.check_admin_dashboards(target).await?;
        vulnerabilities.extend(dashboard_vulns);
        tests += t;

        Ok((vulnerabilities, tests))
    }

    /// Check common Rails admin/operational dashboards that frequently ship without auth.
    /// Each probe requires a specific content signature to avoid SPA catch-all 200 noise.
    async fn check_admin_dashboards(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // (path, name, description, signatures)
        let dashboards: Vec<(&str, &str, &str, &[&str])> = vec![
            ("/sidekiq", "Sidekiq Web", "Background job queue UI - exposes job arguments often containing PII/secrets", &["Sidekiq", "Busy", "Retries", "Scheduled"]),
            ("/sidekiq/queues", "Sidekiq Queues", "Exposes in-flight job data", &["Sidekiq", "queue"]),
            ("/sidekiq/dashboard", "Sidekiq Dashboard", "Sidekiq stats dashboard", &["Sidekiq"]),
            ("/resque", "Resque Web", "Resque job dashboard", &["Resque", "Failed"]),
            ("/delayed_job", "Delayed Job", "Delayed Job UI", &["Delayed::Job"]),
            ("/good_job", "GoodJob", "Active Job GoodJob dashboard", &["GoodJob", "good_job"]),
            ("/solid_queue", "Solid Queue", "Rails 8 Solid Queue UI", &["Solid Queue", "SolidQueue"]),
            ("/mission_control/jobs", "Mission Control Jobs", "Rails Active Job dashboard", &["Mission Control", "mission_control"]),
            ("/pghero", "PgHero", "PostgreSQL performance dashboard - exposes query data", &["PgHero", "Long Running"]),
            ("/blazer", "Blazer", "SQL query/reporting dashboard - direct DB access", &["Blazer", "Queries"]),
            ("/flipper", "Flipper UI", "Feature flag admin - can toggle production features", &["Flipper", "flipper"]),
            ("/ahoy", "Ahoy Captain", "Analytics admin - exposes user events/PII", &["Ahoy", "ahoy_"]),
            ("/chartkick", "Chartkick", "Chartkick admin", &["chartkick"]),
            ("/rails_admin", "RailsAdmin", "RailsAdmin CRUD dashboard - direct model access", &["RailsAdmin", "rails_admin"]),
            ("/admin", "ActiveAdmin", "ActiveAdmin CRUD dashboard", &["ActiveAdmin", "active_admin"]),
            ("/avo", "Avo Admin", "Avo admin dashboard", &["avo-", "Avo."]),
            ("/letter_opener", "Letter Opener", "Dev email capture - may expose user emails", &["letter_opener", "Letter Opener"]),
            ("/maildev", "MailDev", "Dev mail catcher", &["MailDev", "maildev"]),
            ("/mailcatcher", "MailCatcher", "SMTP dev trap", &["MailCatcher", "mailcatcher"]),
            ("/exception_track", "Exception Track", "Exception tracker dashboard with stack traces", &["ExceptionTrack"]),
            ("/errbit", "Errbit", "Self-hosted error tracker", &["Errbit"]),
            ("/whenever", "Whenever", "Whenever cron dashboard", &["whenever"]),
            ("/cable", "Action Cable", "WebSocket mount point", &["Action Cable"]),
        ];

        for (path, name, desc, sigs) in dashboards {
            let url = format!("{}{}", target.trim_end_matches('/'), path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                // Auth-protected dashboards (401/403/302) are fine; only report 200 w/ signature.
                if response.status_code != 200 {
                    continue;
                }
                if !sigs.iter().any(|s| response.body.contains(s)) {
                    continue;
                }

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: format!("Unauthenticated Rails Dashboard: {}", name),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: "Framework Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: format!(
                        "{} appears accessible without authentication at {}. {}",
                        name, path, desc
                    ),
                    evidence: Some(format!(
                        "Matched dashboard signature at {} ({} bytes)",
                        path,
                        response.body.len()
                    )),
                    cwe: "CWE-306".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: format!(
                        "Require authentication to mount {}:\n\
                         - constraint with authenticate :admin do\n\
                         - or wrap mount in Devise/HTTP Basic in config/routes.rb\n\
                         - remove from production entirely if not needed",
                        name
                    ),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
            }
        }

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

        // (path, friendly-name, required-signature-substring)
        // Each probe requires a specific content marker to avoid false positives from
        // SPA catch-all 200 responses.
        let debug_paths: Vec<(&str, &str, &[&str])> = vec![
            ("/rails/info/properties", "Rails Info", &["Ruby version", "Rails version"]),
            ("/rails/info/routes", "Rails Routes", &["Helper", "HTTP Verb", "Path"]),
            ("/rails/info", "Rails Info Index", &["Properties", "Routes"]),
            ("/__better_errors", "Better Errors", &["BetterErrors", "better_errors"]),
            ("/rails/conductor/action_mailbox/inbound_emails", "Action Mailbox Conductor", &["Action Mailbox", "inbound_emails"]),
            ("/rails/conductor/action_mailbox/inbound_emails/new", "Action Mailbox New Email", &["Action Mailbox"]),
            ("/rails/mailers", "Rails Mailers Preview", &["Mailer", "mailer_previews"]),
            ("/rails/action_mailbox/ingresses/relay/inbound_emails", "Action Mailbox Relay Ingress", &["Action Mailbox"]),
            ("/rails/active_storage/blobs", "Active Storage Blobs", &["active_storage"]),
        ];

        for (path, name, sigs) in debug_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200
                    && sigs.iter().any(|s| response.body.contains(s))
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

        // (path, required-signature-substrings, is-critical-credential-material)
        // Each path must exhibit one of its signatures to be reported, which avoids
        // reporting SPA catch-all 200 HTML responses as leaked configuration.
        let env_paths: Vec<(&str, &[&str], bool)> = vec![
            // Classic .env variants - Rails apps using dotenv-rails, figaro
            ("/.env", &["SECRET_KEY", "DATABASE_URL", "RAILS_MASTER_KEY", "DEVISE_", "STRIPE_", "AWS_ACCESS"], true),
            ("/.env.production", &["SECRET_KEY", "DATABASE_URL", "RAILS_MASTER_KEY", "AWS_ACCESS"], true),
            ("/.env.staging", &["SECRET_KEY", "DATABASE_URL", "RAILS_MASTER_KEY"], true),
            ("/.env.development", &["SECRET_KEY", "DATABASE_URL"], true),
            ("/.env.local", &["SECRET_KEY", "DATABASE_URL"], true),
            // Rails-specific credential material (full compromise)
            ("/config/master.key", &[], true), // strict hex-32 check below
            ("/config/credentials/production.key", &[], true),
            ("/config/credentials/staging.key", &[], true),
            ("/config/credentials/development.key", &[], true),
            // Rails 5.2+ encrypted credentials - by themselves useless, but evidence of misconfig
            ("/config/credentials.yml.enc", &[], false),
            ("/config/credentials/production.yml.enc", &[], false),
            ("/config/credentials/staging.yml.enc", &[], false),
            ("/config/secrets.yml.enc", &[], false),
            // Classic yml configs
            ("/config/database.yml", &["adapter:", "username:", "password:", "database:"], true),
            ("/config/secrets.yml", &["secret_key_base:", "production:", "development:"], true),
            ("/config/application.yml", &["production:", "secret", "api_key"], true),
            ("/config/cable.yml", &["adapter:", "redis"], false),
            ("/config/storage.yml", &["service:", "amazon", "google", "azure"], false),
            ("/config/newrelic.yml", &["license_key:"], true),
            ("/config/puma.rb", &["workers ", "threads ", "bind ", "port"], false),
            ("/config/unicorn.rb", &["worker_processes", "timeout", "listen "], false),
            ("/config/sidekiq.yml", &[":queues:", ":concurrency:"], false),
            ("/config/environments/production.rb", &["Rails.application.configure", "config.cache_classes"], false),
            // Dependency + build manifests
            ("/Gemfile", &["source \"", "source '", "gem \"", "gem '"], false),
            ("/Gemfile.lock", &["GEM", "PLATFORMS", "DEPENDENCIES"], false),
            ("/Rakefile", &["Rails.application.load_tasks", "require_relative"], false),
            ("/Procfile", &["web:", "worker:"], false),
            ("/.ruby-version", &[], false), // strict version string check below
            ("/.rbenv-gemsets", &[], false),
            // Database schema / seeds - reveal full schema
            ("/db/schema.rb", &["ActiveRecord::Schema", "create_table"], false),
            ("/db/structure.sql", &["CREATE TABLE", "SET statement_timeout"], false),
            ("/db/seeds.rb", &["User.create", "seeds", "Rails"], false),
            // Deploy configs occasionally shipped
            ("/config/deploy.rb", &["set :application", "role :"], false),
            ("/config/deploy/production.rb", &["server ", "role "], false),
            ("/.github/workflows/deploy.yml", &["uses: actions/checkout", "run:"], false),
            // CI tokens / SSH - rarely shipped but devastating
            ("/.bundle/config", &["BUNDLE_GEMS__", "BUNDLE_RUBYGEMS__"], true),
        ];

        for (path, sigs, is_critical) in &env_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.is_empty() {
                    continue;
                }

                // Skip SPA catch-all HTML responses for file types that are never HTML.
                let body_trim = response.body.trim();
                let looks_like_html = body_trim.starts_with('<')
                    && (body_trim.contains("<html") || body_trim.contains("<!DOCTYPE"));
                if looks_like_html {
                    continue;
                }

                let matched = match *path {
                    // master.key / *.key: exactly 32 lowercase hex chars
                    "/config/master.key"
                    | "/config/credentials/production.key"
                    | "/config/credentials/staging.key"
                    | "/config/credentials/development.key" => {
                        let trimmed = body_trim;
                        trimmed.len() == 32
                            && trimmed.bytes().all(|b| b.is_ascii_hexdigit() && (b.is_ascii_digit() || b.is_ascii_lowercase()))
                    }
                    // Encrypted credentials: base64-ish "<iv>--<payload>--<auth>" pattern
                    "/config/credentials.yml.enc"
                    | "/config/credentials/production.yml.enc"
                    | "/config/credentials/staging.yml.enc"
                    | "/config/secrets.yml.enc" => {
                        body_trim.matches("--").count() == 2
                            && body_trim.len() > 32
                            && body_trim.len() < 16384
                            && body_trim.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'\n' || b == b'\r')
                    }
                    "/.ruby-version" => {
                        let t = body_trim;
                        t.len() < 32
                            && (t.starts_with(|c: char| c == 'r' || c.is_ascii_digit()))
                            && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'p')
                    }
                    "/.rbenv-gemsets" => {
                        let t = body_trim;
                        !t.is_empty() && t.len() < 256 && !t.contains('<') && !t.contains('{')
                    }
                    _ => sigs.iter().any(|s| response.body.contains(s)),
                };

                if matched {
                    let severity = if *is_critical {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    let cvss = if *is_critical { 9.1 } else { 7.5 };

                    vulnerabilities.push(Vulnerability {
                        id: generate_vuln_id(),
                        vuln_type: "Information Disclosure".to_string(),
                        severity,
                        confidence: Confidence::High,
                        category: "Framework Security".to_string(),
                        url: url.clone(),
                        parameter: None,
                        payload: path.to_string(),
                        description: format!(
                            "Rails environment/configuration file exposed: {}",
                            path
                        ),
                        evidence: Some(format!(
                            "Matched content signature for {} ({} bytes)",
                            path,
                            response.body.len()
                        )),
                        cwe: "CWE-538".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove configuration files from web root; block dotfiles and /config at the web server; rotate any exposed credential/key material.".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
                    });
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
            "/log/test.log",
            "/log/sidekiq.log",
            "/log/unicorn.log",
            "/log/puma.log",
            "/log/delayed_job.log",
            "/log/cron_log.log",
            "/log/rails.log",
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
            ("/assets/application.css.map", "source map"),
            ("/packs/js/application.js.map", "source map"),
            ("/packs/js/runtime.js.map", "source map"),
            ("/.git/config", "git config"),
            ("/.git/HEAD", "git config"),
            ("/.git/index", "git config"),
            ("/.svn/entries", "svn config"),
            ("/.hg/hgrc", "mercurial config"),
        ];

        for (path, desc) in asset_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code == 200 {
                    // Source map: must include the sourceContent field of the source map schema
                    let is_source_map =
                        path.contains(".map") && response.body.contains("sourceContent");

                    // Git: validate per-path content to avoid HTML SPA false positives.
                    let body = &response.body;
                    let is_git_config = path.ends_with("/.git/config") && body.contains("[core]");
                    let is_git_head = path.ends_with("/.git/HEAD")
                        && (body.trim_start().starts_with("ref: refs/")
                            || (body.trim().len() == 40
                                && body.trim().bytes().all(|b| b.is_ascii_hexdigit())));
                    let is_git_index = path.ends_with("/.git/index")
                        && body.as_bytes().len() >= 12
                        && &body.as_bytes()[..4] == b"DIRC";
                    let is_svn = path.ends_with("/.svn/entries")
                        && (body.trim_start().starts_with("svn:")
                            || body.contains("dir\n")
                            || body.trim_start().starts_with(|c: char| c.is_ascii_digit()));
                    let is_hg = path.ends_with("/.hg/hgrc") && body.contains("[paths]");

                    let is_scm = is_git_config || is_git_head || is_git_index || is_svn || is_hg;

                    if is_source_map {
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
                    } else if is_scm {
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
                                "Source control metadata exposed ({}) - source code may be downloadable",
                                desc
                            ),
                            evidence: Some(format!("SCM artifact accessible at {}", path)),
                            cwe: "CWE-538".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Remove SCM metadata (.git/.svn/.hg) from web root"
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
}

fn generate_vuln_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("RAILS-{:x}", timestamp)
}
