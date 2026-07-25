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

        let (admin_vulns, t) = self.check_admin_dashboards(target).await?;
        vulnerabilities.extend(admin_vulns);
        tests += t;

        let (creds_vulns, t) = self.check_credentials_exposure(target).await?;
        vulnerabilities.extend(creds_vulns);
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

        // All of these are dev-only Rails routes; any 200 in production is a
        // production-mode misconfiguration (config.consider_all_requests_local
        // or Rails.env.development? left true). Body-based verification below.
        let debug_paths = vec![
            ("/rails/info/properties", "Rails Info"),
            ("/rails/info/routes", "Rails Routes"),
            ("/rails/info", "Rails Info Root"),
            ("/rails/info/notes", "Rails Notes"),
            ("/__better_errors", "Better Errors"),
            ("/__web_console", "Rails Web Console"),
            ("/rails/mailers", "Action Mailer Preview"),
            ("/rails/db", "rails-db plugin"),
            ("/rails/conductor", "Action Mailbox Conductor"),
            ("/rails/conductor/action_mailbox/inbound_emails", "Action Mailbox Emails"),
            ("/rails/active_storage/blobs/", "ActiveStorage Blob Listing"),
            ("/rails/active_storage/direct_uploads", "ActiveStorage Direct Upload"),
            ("/letter_opener", "letter_opener dev inbox"),
        ];

        for (path, name) in debug_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.len() < 40 {
                    continue;
                }
                // Body must contain a signature specific to the dev tool - otherwise a
                // catch-all SPA index at 200 would false-fire against every path.
                let body = &response.body;
                let matches = match path {
                    "/rails/info/properties" | "/rails/info" => {
                        body.contains("Rails::Info") || body.contains("Rails version")
                    }
                    "/rails/info/routes" => {
                        body.contains("Routes")
                            && (body.contains("Helper") || body.contains("Path / Url"))
                    }
                    "/rails/info/notes" => body.contains("Notes") && body.contains("annotations"),
                    "/__better_errors" => {
                        body.contains("BetterErrors") || body.contains("better_errors")
                    }
                    "/__web_console" => body.contains("web_console") || body.contains("WebConsole"),
                    "/rails/mailers" => {
                        body.contains("Mailer previews")
                            || body.contains("ActionMailer::Preview")
                            || body.contains("<h1>Mailer previews</h1>")
                    }
                    "/rails/db" => body.contains("rails-db") || body.contains("Database console"),
                    p if p.starts_with("/rails/conductor") => {
                        body.contains("Action Mailbox") || body.contains("ActionMailbox")
                    }
                    p if p.starts_with("/rails/active_storage") => {
                        body.contains("ActiveStorage")
                            || body.contains("blob")
                            || response
                                .headers
                                .get("content-type")
                                .map(|v| v.contains("json"))
                                .unwrap_or(false)
                    }
                    "/letter_opener" => {
                        body.contains("letter_opener") || body.contains("Letter Opener")
                    }
                    _ => false,
                };
                if !matches {
                    continue;
                }
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
                        "{} endpoint exposed - development-only Rails route reachable in production",
                        name
                    ),
                    evidence: Some(format!("Debug endpoint {} returned signature body", path)),
                    cwe: "CWE-215".to_string(),
                    cvss: 7.5,
                    verified: true,
                    false_positive: false,
                    remediation: "Disable development mode in production environment; ensure \
                        Rails.env is 'production' and web_console/better_errors are in the :development \
                        group only."
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
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

        // Rails / Sinatra / Padrino config files historically leaked via web root
        // when config/ is symlinked or the app is served from the project root.
        let env_paths = vec![
            "/.env",
            "/.env.development",
            "/.env.production",
            "/.env.staging",
            "/.env.local",
            "/.env.local.production",
            "/config/database.yml",
            "/config/database.yml.bak",
            "/config/database.yml.example",
            "/config/database.yml.sample",
            "/config/secrets.yml",
            "/config/secrets.yml.bak",
            "/config/application.yml",
            "/config/settings.yml",
            "/config/settings/development.yml",
            "/config/settings/production.yml",
            "/config/settings/staging.yml",
            "/config/redis.yml",
            "/config/sidekiq.yml",
            "/config/cable.yml",
            "/config/storage.yml",
            "/config/newrelic.yml",
            "/config/mongoid.yml",
            "/config/puma.rb",
            "/config/unicorn.rb",
            "/config/environments/production.rb",
            "/config/environments/development.rb",
            "/config/environments/staging.rb",
            "/config/initializers/devise.rb",
            "/config/initializers/omniauth.rb",
            "/config/initializers/secret_token.rb",
            "/config/initializers/session_store.rb",
            "/config/initializers/carrierwave.rb",
            "/Gemfile",
            "/Gemfile.lock",
            "/config.ru",
            "/Rakefile",
        ];

        for path in env_paths {
            let url = format!("{}{}", target, path);
            tests += 1;

            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.is_empty() {
                    continue;
                }
                // Reject default HTML shells / SPA fallbacks served at 200.
                let body_lower = response.body.to_lowercase();
                if body_lower.contains("<!doctype html")
                    || body_lower.contains("<html")
                    || body_lower.contains("<head")
                {
                    continue;
                }
                // Path-shape-aware sensitivity patterns. A hit here means the file
                // is actually the target format, not a random 200 with a matching
                // buzzword. Every branch requires structural content of the file.
                let matched_pattern: Option<&str> = if path.ends_with(".env")
                    || path.contains(".env.")
                {
                    // dotenv: KEY=VALUE with credential-y keys.
                    if body_lower.contains("secret_key_base=")
                        || body_lower.contains("database_url=")
                        || body_lower.contains("rails_master_key=")
                        || body_lower.contains("rack_env=")
                        || body_lower.contains("secret_token=")
                        || body_lower.contains("aws_access_key_id=")
                        || body_lower.contains("aws_secret_access_key=")
                    {
                        Some("dotenv credentials")
                    } else {
                        None
                    }
                } else if path.contains("database.yml") {
                    if body_lower.contains("adapter:")
                        && (body_lower.contains("username:") || body_lower.contains("password:"))
                    {
                        Some("database.yml with credentials")
                    } else {
                        None
                    }
                } else if path.contains("secrets.yml") {
                    if body_lower.contains("secret_key_base:") || body_lower.contains("secret_token:") {
                        Some("secrets.yml with secret_key_base")
                    } else {
                        None
                    }
                } else if path.contains("application.yml") || path.contains("settings.yml")
                    || path.contains("settings/")
                {
                    if (body_lower.contains("secret") || body_lower.contains("token")
                        || body_lower.contains("password"))
                        && (body_lower.contains(":") || body_lower.contains("="))
                    {
                        Some("application settings with secrets")
                    } else {
                        None
                    }
                } else if path.contains("sidekiq.yml") {
                    if body_lower.contains(":queues:") || body_lower.contains(":concurrency:") {
                        Some("Sidekiq config")
                    } else {
                        None
                    }
                } else if path.contains("cable.yml") {
                    if body_lower.contains("adapter:") && body_lower.contains("redis") {
                        Some("Action Cable Redis URL")
                    } else {
                        None
                    }
                } else if path.contains("storage.yml") {
                    if body_lower.contains("service:") {
                        Some("ActiveStorage service config")
                    } else {
                        None
                    }
                } else if path.contains("newrelic.yml") {
                    if body_lower.contains("license_key:") {
                        Some("New Relic license key")
                    } else {
                        None
                    }
                } else if path.contains("mongoid.yml") {
                    if body_lower.contains("clients:") && body_lower.contains("uri:") {
                        Some("Mongoid MongoDB URI")
                    } else {
                        None
                    }
                } else if path.contains("puma.rb") {
                    if body_lower.contains("workers") || body_lower.contains("bind ") {
                        Some("Puma server config")
                    } else {
                        None
                    }
                } else if path.contains("unicorn.rb") {
                    if body_lower.contains("worker_processes") || body_lower.contains("preload_app") {
                        Some("Unicorn server config")
                    } else {
                        None
                    }
                } else if path.contains("/environments/") {
                    if body_lower.contains("rails.application.configure") {
                        Some("Rails environment file")
                    } else {
                        None
                    }
                } else if path.contains("/initializers/") {
                    if body_lower.contains("devise.setup")
                        || body_lower.contains("omniauth::builder")
                        || body_lower.contains("secret_key_base")
                        || body_lower.contains("rails.application.config.session_store")
                        || body_lower.contains("carrierwave.configure")
                    {
                        Some("Rails initializer with secrets")
                    } else {
                        None
                    }
                } else if path == "/Gemfile" || path == "/Gemfile.lock" {
                    if body_lower.contains("source ") && body_lower.contains("gem ") {
                        Some("Gemfile / lockfile")
                    } else if body_lower.contains("gem_version") || body_lower.contains("dependencies") {
                        Some("Gemfile.lock")
                    } else {
                        None
                    }
                } else if path == "/config.ru" {
                    if body_lower.contains("run rails.application") || body_lower.contains("require_relative") {
                        Some("Rack config.ru")
                    } else {
                        None
                    }
                } else if path == "/Rakefile" {
                    if body_lower.contains("rails.application.load_tasks") {
                        Some("Rakefile")
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(pattern) = matched_pattern {
                    // Info files (Gemfile, Rakefile, config.ru) are lower severity
                    // than files containing actual credentials.
                    let (severity, cvss) = match pattern {
                        "Gemfile / lockfile" | "Gemfile.lock" | "Rack config.ru" | "Rakefile"
                        | "Puma server config" | "Unicorn server config" | "Rails environment file"
                        | "Sidekiq config" | "ActiveStorage service config" => {
                            (Severity::Medium, 5.3)
                        }
                        _ => (Severity::Critical, 9.1),
                    };
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
                        evidence: Some(format!("Matched signature: {}", pattern)),
                        cwe: "CWE-538".to_string(),
                        cvss,
                        verified: true,
                        false_positive: false,
                        remediation: "Remove configuration files from web root. Rails serves \
                            static assets from /public only - config/, Gemfile, config.ru \
                            should not be reachable. Rotate any credentials that appeared."
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

    async fn check_log_exposure(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // Rails writes to log/<env>.log by default and many hosts leave the
        // rotated *.log.<N> around. Body signature ("Started GET"/"Processing by")
        // enforced below so a 200 SPA fallback cannot false-fire.
        let log_paths = vec![
            "/log/development.log",
            "/log/production.log",
            "/log/staging.log",
            "/log/test.log",
            "/log/sidekiq.log",
            "/log/puma.log",
            "/log/puma.stdout.log",
            "/log/puma.stderr.log",
            "/log/unicorn.log",
            "/log/delayed_job.log",
            "/log/scheduler.log",
            "/log/production.log.1",
            "/log/production.log.2",
            "/log/development.log.old",
            "/log/production.log.gz",
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
            ("/assets/application-debug.js.map", "debug source map"),
            ("/packs/js/application.js.map", "webpacker source map"),
            ("/vite/assets/application.js.map", "vite_ruby source map"),
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

    /// Detect commonly-mounted admin dashboards that Rails apps mount at fixed
    /// paths (Sidekiq Web UI, Resque, GoodJob, PgHero, etc.). Every one of these
    /// is verified by a UI-specific string in the body - a generic 200 cannot
    /// match. Detection is high-impact because these dashboards often expose
    /// production queue contents, DB stats, or admin actions when auth is missing.
    async fn check_admin_dashboards(&self, target: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        let dashboards: &[(&str, &str, &[&str], Severity, f64, &str)] = &[
            (
                "/sidekiq",
                "Sidekiq Web",
                &["Sidekiq", "Retries", "Scheduled", "Dead"],
                Severity::Critical,
                9.1,
                "Sidekiq Web UI is exposed without authentication - allows job manipulation and queue enumeration",
            ),
            (
                "/sidekiq/stats",
                "Sidekiq stats",
                &["\"sidekiq\":", "\"processed\":", "\"failed\":"],
                Severity::High,
                7.5,
                "Sidekiq stats JSON is exposed without authentication",
            ),
            (
                "/admin/sidekiq",
                "Sidekiq (admin/)",
                &["Sidekiq"],
                Severity::Critical,
                9.1,
                "Sidekiq mounted under /admin without authentication",
            ),
            (
                "/resque",
                "Resque Web",
                &["Resque", "Workers", "Queues"],
                Severity::Critical,
                9.1,
                "Resque Web UI is exposed without authentication",
            ),
            (
                "/good_job",
                "GoodJob dashboard",
                &["GoodJob", "Jobs"],
                Severity::Critical,
                9.1,
                "GoodJob dashboard is exposed without authentication",
            ),
            (
                "/mission_control",
                "Mission Control - Jobs",
                &["Mission Control", "mission_control", "Queues", "Jobs"],
                Severity::Critical,
                9.1,
                "Mission Control - Jobs dashboard exposed without authentication",
            ),
            (
                "/delayed_job",
                "Delayed::Job Web",
                &["Delayed", "queue", "handler"],
                Severity::Critical,
                9.1,
                "Delayed::Job Web UI is exposed without authentication",
            ),
            (
                "/que",
                "Que Web",
                &["Que", "Jobs", "queue"],
                Severity::High,
                8.2,
                "Que Web UI is exposed without authentication",
            ),
            (
                "/pghero",
                "PgHero",
                &["PgHero", "Space", "Long Running Queries"],
                Severity::High,
                8.2,
                "PgHero database dashboard is exposed - reveals DB schema and query metrics",
            ),
            (
                "/rails_performance",
                "Rails Performance dashboard",
                &["rails_performance", "Rails Performance"],
                Severity::High,
                7.5,
                "Rails Performance dashboard is exposed",
            ),
            (
                "/blazer",
                "Blazer",
                &["Blazer", "Queries", "Dashboards"],
                Severity::Critical,
                9.1,
                "Blazer SQL query tool is exposed - allows arbitrary DB queries",
            ),
            (
                "/flipper",
                "Flipper UI",
                &["Flipper", "feature", "gate"],
                Severity::High,
                7.5,
                "Flipper feature-flag UI exposed - attackers can toggle feature gates",
            ),
            (
                "/audits",
                "Audits1984 / audited",
                &["Audit", "audited"],
                Severity::Medium,
                5.3,
                "Audit log dashboard exposed",
            ),
            (
                "/exception_track",
                "exception_track",
                &["exception_track"],
                Severity::Medium,
                5.3,
                "Exception tracking dashboard exposed",
            ),
        ];

        for (path, name, signatures, severity, cvss, description) in dashboards {
            let url = format!("{}{}", target, path);
            tests += 1;
            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.len() < 40 {
                    continue;
                }
                let hit = signatures.iter().any(|s| response.body.contains(*s));
                if !hit {
                    continue;
                }
                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: format!("Exposed Rails Admin Dashboard: {}", name),
                    severity: severity.clone(),
                    confidence: Confidence::High,
                    category: "Framework Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: description.to_string(),
                    evidence: Some(format!("Response contains {} signature", name)),
                    cwe: "CWE-306".to_string(),
                    cvss: *cvss as f32,
                    verified: true,
                    false_positive: false,
                    remediation: "Protect the dashboard mount point with authentication. Rails \
                        constraints support `constraints AdminConstraint.new` or basic HTTP auth via \
                        `Rack::Auth::Basic`. Better: keep queue/DB dashboards on an internal-only \
                        network."
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_confidence: None,
                    ml_data: None,
                });
            }
        }

        Ok((vulnerabilities, tests))
    }

    /// Detect Rails encrypted-credentials artifacts served over the web. A
    /// `config/master.key` leak is game-over: it decrypts every credential in
    /// `credentials.yml.enc` (DB passwords, JWT secrets, API tokens, etc.).
    /// Detection is body-shape-based: master.key is a single 32-byte hex line,
    /// credentials files contain the Rails ActiveSupport::MessageEncryptor
    /// format (colon-separated base64 blocks).
    async fn check_credentials_exposure(
        &self,
        target: &str,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests = 0;

        // (path, description, kind_marker)
        // "kind_marker": "master_key" or "enc_file"
        let paths: &[(&str, &str, &str)] = &[
            (
                "/config/master.key",
                "Rails master key",
                "master_key",
            ),
            ("/config/credentials.yml.enc", "Rails credentials (default)", "enc_file"),
            (
                "/config/credentials/production.yml.enc",
                "Rails credentials (production)",
                "enc_file",
            ),
            (
                "/config/credentials/staging.yml.enc",
                "Rails credentials (staging)",
                "enc_file",
            ),
            (
                "/config/credentials/development.yml.enc",
                "Rails credentials (development)",
                "enc_file",
            ),
            (
                "/config/credentials/production.key",
                "Rails per-env production key",
                "master_key",
            ),
            (
                "/config/credentials/staging.key",
                "Rails per-env staging key",
                "master_key",
            ),
            (
                "/config/credentials/development.key",
                "Rails per-env development key",
                "master_key",
            ),
        ];

        for (path, description, kind) in paths {
            let url = format!("{}{}", target, path);
            tests += 1;
            if let Ok(response) = self.http_client.get(&url).await {
                if response.status_code != 200 || response.body.is_empty() {
                    continue;
                }
                let body = response.body.trim();
                let body_lower = body.to_lowercase();
                // Reject HTML shells masquerading as 200.
                if body_lower.contains("<!doctype html")
                    || body_lower.contains("<html")
                    || body_lower.contains("<head")
                {
                    continue;
                }

                let is_hit = match *kind {
                    "master_key" => {
                        // master.key is a single 32-char hex line; be strict.
                        let one_line = body.lines().count() <= 2;
                        let candidate = body.lines().next().unwrap_or("").trim();
                        one_line
                            && candidate.len() >= 24
                            && candidate.len() <= 128
                            && candidate.chars().all(|c| c.is_ascii_hexdigit())
                    }
                    "enc_file" => {
                        // Rails encrypted credentials: two colon-separated base64 blocks
                        // followed by --<iv>--<auth-tag>. Reject empty / HTML / plain.
                        let looks_encrypted = body.contains("--")
                            && body
                                .chars()
                                .filter(|c| {
                                    c.is_ascii_alphanumeric()
                                        || *c == '+'
                                        || *c == '/'
                                        || *c == '='
                                        || *c == '-'
                                        || *c == '_'
                                })
                                .count()
                                > 60;
                        looks_encrypted && !body_lower.contains("html")
                    }
                    _ => false,
                };

                if !is_hit {
                    continue;
                }

                let (severity, cvss, remediation) = if *kind == "master_key" {
                    (
                        Severity::Critical,
                        9.8,
                        "GAME OVER: rotate the Rails master key IMMEDIATELY. Re-encrypt the \
                         credentials file (`rails credentials:edit`) with a new key. Anyone who \
                         downloaded the key can decrypt every DB password, JWT signing secret, \
                         and API token in the credentials file. Assume every secret is \
                         compromised until rotated.",
                    )
                } else {
                    (
                        Severity::Medium,
                        5.3,
                        "Rails encrypted credentials file exposed. Content is safe as long as \
                         config/master.key has never been leaked - verify the master key was \
                         never committed to git or served over HTTP. If either happened, treat \
                         all credentials as compromised and rotate.",
                    )
                };

                vulnerabilities.push(Vulnerability {
                    id: generate_vuln_id(),
                    vuln_type: format!("Exposed {}", description),
                    severity,
                    confidence: Confidence::High,
                    category: "Framework Security".to_string(),
                    url: url.clone(),
                    parameter: None,
                    payload: path.to_string(),
                    description: format!("{} accessible over HTTP at {}", description, path),
                    evidence: Some(format!(
                        "File matches {} signature",
                        if *kind == "master_key" {
                            "single hex-line"
                        } else {
                            "Rails encrypted-credentials"
                        }
                    )),
                    cwe: "CWE-798".to_string(),
                    cvss: cvss as f32,
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
}

fn generate_vuln_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("RAILS-{:x}", timestamp)
}
