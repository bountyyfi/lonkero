// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for sensitive data exposure (files, credentials, configuration)
pub struct SensitiveDataScanner {
    http_client: Arc<HttpClient>,
}

impl SensitiveDataScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Run sensitive data exposure scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting sensitive data exposure scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Parse base URL
        let url_obj = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                info!("Failed to parse URL: {}", e);
                return Ok((all_vulnerabilities, 0));
            }
        };

        let base_url = format!(
            "{}://{}",
            url_obj.scheme(),
            url_obj.host_str().unwrap_or("")
        );

        // Test sensitive file paths
        let sensitive_paths = self.get_sensitive_paths();

        for path in &sensitive_paths {
            total_tests += 1;
            let test_url = format!("{}{}", base_url, path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_sensitive_file(
                        &response.body,
                        response.status_code,
                        path,
                        &test_url,
                    ) {
                        all_vulnerabilities.push(vuln);
                    }
                }
                Err(_) => {
                    // File not accessible, continue
                }
            }
        }

        // Check main response for exposed credentials
        total_tests += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                let cred_vulns = self.scan_for_credentials(&response.body, url);
                all_vulnerabilities.extend(cred_vulns);
            }
            Err(_) => {
                // Continue
            }
        }

        info!(
            "Sensitive data exposure scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Get list of sensitive paths to test
    fn get_sensitive_paths(&self) -> Vec<&'static str> {
        vec![
            // Environment and config files
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.stage",
            "/.env.staging",
            "/.env.prod",
            "/.env.dev",
            "/.env.test",
            "/.env.backup",
            "/.env.bak",
            "/.env.old",
            "/.env.save",
            "/.env.sample",
            "/.env.example",
            "/.env.default",
            "/.env.live",
            "/.env.private",
            "/config.php",
            "/configuration.php",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/wp-config.php~",
            "/wp-config.php.swp",
            "/wp-config-sample.php",
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/settings.json",
            "/settings.yml",
            "/web.config",
            "/web.config.bak",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/appsettings.Production.json",
            "/application.properties",
            "/application.yml",
            "/application.yaml",
            "/application-prod.properties",
            "/application-dev.properties",
            "/bootstrap.properties",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/app.yml",
            "/config/config.yml",
            "/config/application.yml",
            // Rails master key / encrypted credentials
            "/config/master.key",
            "/config/credentials.yml.enc",
            "/config/credentials/production.key",
            "/config/credentials/production.yml.enc",
            "/config/credentials/development.key",
            "/config/credentials/staging.key",
            // Django
            "/settings.py",
            "/local_settings.py",
            "/app/settings.py",
            "/config/settings.py",
            "/settings/production.py",
            "/settings/local.py",
            // Magento
            "/app/etc/local.xml",
            "/app/etc/env.php",
            "/app/etc/config.php",
            // Drupal
            "/sites/default/settings.php",
            "/sites/default/settings.local.php",
            "/sites/default/default.settings.php",
            "/sites/default/files/private/",
            // Joomla
            "/configuration.php.bak",
            "/configuration.php~",
            "/configuration.php.save",
            // Git files
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.git/logs/HEAD",
            "/.git/refs/heads/master",
            "/.git/refs/heads/main",
            "/.git/info/exclude",
            "/.git/description",
            "/.git/packed-refs",
            "/.git/COMMIT_EDITMSG",
            "/.git/ORIG_HEAD",
            "/.git/FETCH_HEAD",
            "/.gitignore",
            "/.gitconfig",
            "/.gitmodules",
            "/.gitattributes",
            // Subversion / Mercurial / Bazaar
            "/.svn/entries",
            "/.svn/wc.db",
            "/.svn/format",
            "/.svn/all-wcprops",
            "/CVS/Entries",
            "/CVS/Root",
            "/.hg/hgrc",
            "/.hg/store/00manifest.i",
            "/.bzr/README",
            "/.bzr/checkout/conflicts",
            // Package manager files
            "/package.json",
            "/package-lock.json",
            "/composer.json",
            "/composer.lock",
            "/yarn.lock",
            "/pnpm-lock.yaml",
            "/Gemfile",
            "/Gemfile.lock",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            "/poetry.lock",
            "/pyproject.toml",
            "/go.mod",
            "/go.sum",
            "/Cargo.toml",
            "/Cargo.lock",
            "/auth.json", // Composer auth tokens
            "/.npmrc",
            "/.yarnrc",
            "/.yarnrc.yml",
            "/.pypirc",
            // Database dumps (high value)
            "/backup.sql",
            "/backup.sql.gz",
            "/backup.sql.zip",
            "/backup.sql.tar.gz",
            "/dump.sql",
            "/dump.sql.gz",
            "/database.sql",
            "/database.sql.gz",
            "/db.sql",
            "/db.sql.gz",
            "/mysql.sql",
            "/mysqldump.sql",
            "/postgres.sql",
            "/pgdump.sql",
            "/data.sql",
            "/prod.sql",
            "/production.sql",
            "/prod_backup.sql",
            "/production_backup.sql",
            "/users.sql",
            "/customers.sql",
            "/clients.sql",
            "/orders.sql",
            "/accounts.sql",
            "/site.sql",
            "/site_backup.sql",
            "/latest.sql",
            "/db_backup.sql",
            "/database_backup.sql",
            "/dump.rdb", // Redis persistent snapshot
            "/mongodump.tar",
            "/mongodump.tar.gz",
            // Terraform / IaC state (contains ALL plaintext secrets)
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/terraform.tfvars",
            "/terraform.tfvars.json",
            "/secret.tfvars",
            "/secrets.tfvars",
            "/prod.tfvars",
            "/production.tfvars",
            "/.terraform/terraform.tfstate",
            "/.terraformrc",
            // Debug and info files
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/debug.php",
            "/_debug",
            "/debug",
            "/phpinfo",
            "/pinfo.php",
            "/i.php",
            "/_profiler",     // Symfony profiler
            "/_profiler/phpinfo",
            "/elmah.axd",     // ASP.NET error log
            "/trace.axd",     // ASP.NET tracing
            "/server-status", // Apache mod_status
            // Log files
            "/logs/error.log",
            "/logs/access.log",
            "/logs/debug.log",
            "/logs/app.log",
            "/logs/application.log",
            "/logs/production.log",
            "/log/error.log",
            "/log/production.log",
            "/log/development.log",
            "/error.log",
            "/access.log",
            "/error_log",
            "/debug.log",
            "/app.log",
            "/laravel.log",
            "/storage/logs/laravel.log",
            "/nohup.out",
            "/log.txt",
            // API documentation
            "/api/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/swagger.json",
            "/swagger.yaml",
            "/swagger-ui",
            "/swagger-ui/index.html",
            "/swagger/v1/swagger.json",
            "/swagger/v2/swagger.json",
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/graphql",
            "/graphiql",
            "/v1/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api/v1/swagger",
            "/api/v2/swagger",
            "/api/docs",
            "/api/schema",
            "/redoc",
            // Server status
            "/server-info",
            "/status",
            "/health",
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/configprops",
            // Cloud credentials & SDK configs
            "/.aws/credentials",
            "/.aws/config",
            "/.boto",
            "/.s3cfg",
            "/s3cfg",
            "/credentials.csv",      // AWS root/IAM credentials export
            "/credentials.json",     // GCP / Firebase service account
            "/service-account.json",
            "/serviceaccount.json",
            "/gcp-key.json",
            "/gcloud-key.json",
            "/firebase-adminsdk.json",
            "/.gcloudignore",
            "/.docker/config.json",
            "/.dockercfg",
            "/.kube/config",
            "/kubeconfig",
            "/azure.json",
            "/azureProfile.json",
            "/publishsettings",
            "/WebDeploy.publishsettings",
            // Private keys and certificates
            "/id_rsa",
            "/id_dsa",
            "/id_ecdsa",
            "/id_ed25519",
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519",
            "/.ssh/authorized_keys",
            "/.ssh/known_hosts",
            "/.ssh/config",
            "/authorized_keys",
            "/server.key",
            "/server.pem",
            "/private.key",
            "/private.pem",
            "/privkey.pem",
            "/cert.pem",
            "/certificate.pem",
            "/key.pem",
            "/client.key",
            "/client.pem",
            "/ca.key",
            "/ca.pem",
            "/ssl.key",
            "/ssl.pem",
            // Secret store files
            "/secrets.yml",
            "/secrets.yaml",
            "/secrets.json",
            "/secrets.env",
            "/vault.json",
            "/credentials.yml",
            "/credentials.yaml",
            // IDE / editor config (often contains DB + SSH creds)
            "/.vscode/sftp.json",
            "/.vscode/settings.json",
            "/.vscode/launch.json",
            "/.idea/workspace.xml",
            "/.idea/dataSources.xml",
            "/.idea/dataSources.local.xml",
            "/.idea/webServers.xml",
            "/.idea/deployment.xml",
            "/.idea/WebServers.xml",
            "/sftp-config.json",
            "/ftpsync.settings",
            "/nbproject/project.properties",
            "/nbproject/private/private.properties",
            // CI/CD configs
            "/.travis.yml",
            "/.circleci/config.yml",
            "/.gitlab-ci.yml",
            "/bitbucket-pipelines.yml",
            "/azure-pipelines.yml",
            "/Jenkinsfile",
            "/jenkins.xml",
            "/.drone.yml",
            "/buildspec.yml",
            "/codemagic.yaml",
            // Container / orchestration
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/docker-compose.prod.yml",
            "/docker-compose.production.yml",
            "/docker-compose.dev.yml",
            "/.dockerignore",
            // Shell history / dotfiles leaking credentials
            "/.bash_history",
            "/.zsh_history",
            "/.sh_history",
            "/.mysql_history",
            "/.psql_history",
            "/.irb_history",
            "/.node_repl_history",
            "/.rediscli_history",
            "/.history",
            "/.pgpass",
            "/.my.cnf",
            "/.netrc",
            "/.netlify/state.json",
            // Core dumps / heap dumps
            "/core",
            "/core.dump",
            "/heapdump",
            "/heapdump.hprof",
            "/dump.hprof",
            "/java_pid.hprof",
            // ASP.NET, Java, PHP specific
            "/appsettings.json.bak",
            "/appsettings.json.old",
            "/Web.config.bak",
            "/Web.config.old",
            "/WEB-INF/web.xml",
            "/WEB-INF/classes/",
            "/META-INF/MANIFEST.MF",
            "/META-INF/context.xml",
            "/.phpunit.result.cache",
            // Other sensitive files
            "/.DS_Store",
            "/robots.txt",
            "/.well-known/security.txt",
            "/sitemap.xml",
            "/admin/config",
            "/.htaccess",
            "/.htpasswd",
            "/passwd",
            "/.passwd",
            "/users.txt",
            "/password.txt",
            "/passwords.txt",
            "/secret.txt",
            "/secrets.txt",
            "/todo.txt",
            "/TODO",
            "/CHANGELOG",
            "/CHANGELOG.md",
            "/CHANGELOG.txt",
            "/VERSION",
            "/version.txt",
            "/.well-known/openid-configuration",
            // Archive backups (fast enum)
            "/backup.zip",
            "/backup.tar.gz",
            "/backup.tar",
            "/backup.rar",
            "/backup.7z",
            "/site.zip",
            "/site.tar.gz",
            "/site.tar",
            "/www.zip",
            "/www.tar.gz",
            "/html.zip",
            "/public_html.zip",
            "/public_html.tar.gz",
            "/web.zip",
            "/wwwroot.zip",
            "/release.zip",
            "/source.zip",
            "/src.zip",
            "/app.zip",
            "/app.tar.gz",
        ]
    }

    /// Analyze response for sensitive file exposure
    fn analyze_sensitive_file(
        &self,
        body: &str,
        status_code: u16,
        path: &str,
        url: &str,
    ) -> Option<Vulnerability> {
        if status_code != 200 || body.is_empty() {
            return None;
        }

        let body_lower = body.to_lowercase();
        let path_lower = path.to_lowercase();

        // Reject HTML error pages / SPA shells served as 200
        // These tend to be the most common source of false positives.
        if Self::looks_like_generic_html(&body_lower) {
            return None;
        }

        // Private SSH/PEM key blocks - extremely high confidence, critical impact
        if Self::contains_private_key_block(body) {
            return Some(self.create_vulnerability(
                "Private Key Exposed",
                url,
                &self.truncate_evidence(body, 200),
                Severity::Critical,
                "CWE-321",
                9.8,
                "Rotate the exposed private key immediately. Never store private keys in web-accessible locations.",
            ));
        }

        // AWS credentials file (~/.aws/credentials)
        if path_lower.ends_with("/.aws/credentials") || path_lower == "/.aws/credentials"
            || path_lower.ends_with("/credentials.csv") {
            if (body.contains("aws_access_key_id") && body.contains("aws_secret_access_key"))
                || body.contains("AKIA")
                || (body_lower.contains("access key id") && body_lower.contains("secret access key"))
            {
                return Some(self.create_vulnerability(
                    "AWS Credentials File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Rotate all AWS credentials immediately. Delete the exposed file. Use IAM roles instead of long-lived keys.",
                ));
            }
        }

        // AWS SDK config file
        if path_lower.ends_with("/.aws/config") {
            if body.contains("[profile") || body.contains("[default]")
                || body_lower.contains("region") && body_lower.contains("output") {
                return Some(self.create_vulnerability(
                    "AWS Config File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    7.5,
                    "Remove .aws/config from web root. Check for accompanying credentials exposure.",
                ));
            }
        }

        // Kubernetes kubeconfig
        if path_lower.ends_with("/.kube/config") || path_lower.ends_with("/kubeconfig") {
            if (body_lower.contains("apiversion") && body_lower.contains("kind: config"))
                || (body.contains("clusters:") && body.contains("contexts:") && body.contains("users:"))
                || body.contains("client-certificate-data")
                || body.contains("client-key-data")
                || body.contains("certificate-authority-data")
            {
                return Some(self.create_vulnerability(
                    "Kubernetes kubeconfig Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Rotate cluster credentials immediately. Remove kubeconfig from web root. Use short-lived tokens.",
                ));
            }
        }

        // Docker config (contains registry auth tokens)
        if path_lower.ends_with("/.docker/config.json") || path_lower.ends_with("/.dockercfg") {
            if body.contains("\"auths\"") || body.contains("\"auth\":") || body.contains("\"credsStore\"") {
                return Some(self.create_vulnerability(
                    "Docker Registry Credentials Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Rotate registry credentials immediately. Remove Docker config from web root.",
                ));
            }
        }

        // GCP / Firebase service account JSON
        if path_lower.ends_with(".json")
            && (body.contains("\"type\": \"service_account\"")
                || body.contains("\"type\":\"service_account\"")
                || (body.contains("\"private_key\"") && body.contains("-----BEGIN PRIVATE KEY-----")))
        {
            return Some(self.create_vulnerability(
                "GCP/Firebase Service Account Key Exposed",
                url,
                &self.truncate_evidence(body, 200),
                Severity::Critical,
                "CWE-798",
                9.8,
                "Revoke the service account key immediately in the GCP console. Rotate and store securely.",
            ));
        }

        // Terraform state file - contains ALL plaintext secrets (passwords, tokens, private keys)
        if path_lower.ends_with(".tfstate") || path_lower.ends_with(".tfstate.backup") {
            if (body.contains("\"terraform_version\"") && body.contains("\"resources\""))
                || body.contains("\"serial\":")
                || body.contains("\"lineage\"")
            {
                return Some(self.create_vulnerability(
                    "Terraform State File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.8,
                    "Terraform state stores all resource attributes in plaintext including passwords, tokens, and private keys. \
                    Assume every secret referenced by this state is compromised. Migrate state to a remote backend (S3/GCS/Terraform Cloud) \
                    with encryption and access controls. Rotate all secrets.",
                ));
            }
        }

        // Terraform variables file
        if path_lower.ends_with(".tfvars") || path_lower.ends_with(".tfvars.json") {
            let cred_keywords = ["password", "secret", "token", "api_key", "access_key", "private_key"];
            if cred_keywords.iter().any(|k| body_lower.contains(k))
                && (body.contains("=") || body.contains(":"))
            {
                return Some(self.create_vulnerability(
                    "Terraform Variables File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Remove .tfvars files from web root. These often contain plaintext secrets. Rotate any exposed credentials.",
                ));
            }
        }

        // Rails master key (single 32-char hex/base32)
        if path_lower.ends_with("/config/master.key") || path_lower.ends_with("/master.key")
            || path_lower.contains("/credentials/") && path_lower.ends_with(".key") {
            let trimmed = body.trim();
            // Rails master keys are 32-character hex
            if trimmed.len() >= 24 && trimmed.len() <= 128
                && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '\n' || c == '\r')
            {
                return Some(self.create_vulnerability(
                    "Rails Master Key Exposed",
                    url,
                    "Rails master.key contents detected",
                    Severity::Critical,
                    "CWE-321",
                    9.8,
                    "Rotate the Rails master key and re-encrypt credentials.yml.enc. Never commit master.key to the web root.",
                ));
            }
        }

        // Rails encrypted credentials file - still worth flagging as exposure
        if path_lower.ends_with("credentials.yml.enc") {
            // Rails credentials files start with a specific binary-ish signature
            if body.len() > 20 && !body_lower.contains("<html") {
                return Some(self.create_vulnerability(
                    "Rails Encrypted Credentials File Exposed",
                    url,
                    &self.truncate_evidence(body, 100),
                    Severity::Medium,
                    "CWE-200",
                    5.3,
                    "Remove credentials.yml.enc from web root. If master.key is also leaked, all credentials are compromised.",
                ));
            }
        }

        // .htpasswd file exposure (contains bcrypt/MD5 hashed user passwords)
        if path_lower.ends_with("/.htpasswd") {
            // Format: username:$2y$... or username:$apr1$...
            if body.contains(":$2")
                || body.contains(":$apr1$")
                || body.contains(":{SHA}")
                || body.contains(":$1$")
                || body.contains(":$6$")
            {
                return Some(self.create_vulnerability(
                    ".htpasswd File Exposed",
                    url,
                    &self.truncate_evidence(body, 150),
                    Severity::Critical,
                    "CWE-522",
                    9.1,
                    "Remove .htpasswd from web root. Password hashes can be cracked offline. Rotate all passwords and move the file outside DocumentRoot.",
                ));
            }
        }

        // .netrc / .pgpass / .my.cnf files
        if path_lower.ends_with("/.netrc") {
            if body.contains("machine ") && (body.contains("login ") || body.contains("password ")) {
                return Some(self.create_vulnerability(
                    ".netrc File Exposed",
                    url,
                    &self.truncate_evidence(body, 150),
                    Severity::Critical,
                    "CWE-522",
                    9.1,
                    "Rotate all credentials stored in the .netrc file. Remove from web root.",
                ));
            }
        }

        if path_lower.ends_with("/.pgpass") {
            // Format: hostname:port:database:username:password
            let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).collect();
            if lines.iter().any(|l| l.matches(':').count() >= 4) {
                return Some(self.create_vulnerability(
                    "PostgreSQL .pgpass File Exposed",
                    url,
                    "PostgreSQL credentials file format detected",
                    Severity::Critical,
                    "CWE-522",
                    9.1,
                    "Rotate all PostgreSQL passwords listed. Remove .pgpass from web root.",
                ));
            }
        }

        if path_lower.ends_with("/.my.cnf") {
            if (body.contains("[client]") || body.contains("[mysql]") || body.contains("[mysqldump]"))
                && (body_lower.contains("password") || body_lower.contains("user"))
            {
                return Some(self.create_vulnerability(
                    "MySQL Client Config (.my.cnf) Exposed",
                    url,
                    &self.truncate_evidence(body, 150),
                    Severity::Critical,
                    "CWE-522",
                    9.1,
                    "Rotate MySQL credentials. Remove .my.cnf from web root.",
                ));
            }
        }

        // Shell history files
        if path_lower.ends_with("/.bash_history")
            || path_lower.ends_with("/.zsh_history")
            || path_lower.ends_with("/.sh_history")
            || path_lower.ends_with("/.mysql_history")
            || path_lower.ends_with("/.psql_history")
        {
            let shell_indicators = ["cd ", "ls ", "sudo ", "ssh ", "mysql ", "psql ", "curl ", "wget ", "export ", "git ", "vi ", "nano "];
            let hit = shell_indicators.iter().filter(|i| body.contains(*i)).count();
            if hit >= 2 || body.contains("-u root") || body.contains("--password") {
                return Some(self.create_vulnerability(
                    "Shell History File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-532",
                    7.5,
                    "Shell history commonly contains passwords, tokens, and sensitive commands. Remove from web root and rotate any exposed credentials.",
                ));
            }
        }

        // ELMAH (ASP.NET) error log
        if path_lower.ends_with("/elmah.axd") || path_lower.contains("/elmah.axd") {
            if body.contains("ELMAH") || body.contains("Error Log") || body.contains("All Errors") {
                return Some(self.create_vulnerability(
                    "ELMAH Error Log Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    7.5,
                    "ELMAH exposes full stack traces, query strings, cookies, and server variables. Protect elmah.axd with authentication or remove from production.",
                ));
            }
        }

        // ASP.NET trace.axd
        if path_lower.ends_with("/trace.axd") {
            if body.contains("Application Trace") || body.contains("Request Details") || body.contains("Trace Information") {
                return Some(self.create_vulnerability(
                    "ASP.NET trace.axd Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    7.5,
                    "trace.axd exposes request/session details. Disable tracing in production web.config.",
                ));
            }
        }

        // Spring Boot Actuator heapdump / env (binary or JSON)
        if path_lower.contains("/actuator/heapdump") || path_lower.ends_with("/heapdump") {
            // Heap dumps are binary with HPROF magic header, or can be small error pages when disabled
            let bytes = body.as_bytes();
            if bytes.len() > 100
                && (body.starts_with("JAVA PROFILE") || (bytes.len() >= 4 && &bytes[..4] == b"\x4a\x41\x56\x41"))
            {
                return Some(self.create_vulnerability(
                    "Spring Boot Heap Dump Exposed",
                    url,
                    "HPROF heap dump data served",
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Heap dumps contain every string and object in JVM memory including passwords and tokens. Secure /actuator endpoints with authentication.",
                ));
            }
        }

        if path_lower.contains("/actuator/env") || path_lower == "/env" {
            if body.contains("\"propertySources\"") || body.contains("\"activeProfiles\"")
                || body.contains("systemEnvironment") {
                return Some(self.create_vulnerability(
                    "Spring Boot Actuator /env Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    8.2,
                    "Actuator /env endpoint exposes environment variables and property sources including database URLs and secrets. Protect actuator endpoints.",
                ));
            }
        }

        // IDE config leaking datasources / SSH targets
        if path_lower.ends_with("/.idea/datasources.xml") || path_lower.ends_with("/.idea/datasources.local.xml") {
            if body.contains("<DataSource") || body.contains("jdbc:") || body.contains("<datasource") {
                return Some(self.create_vulnerability(
                    "JetBrains IDE Data Source Configuration Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    7.5,
                    "dataSources.xml exposes database connection strings. Add .idea/ to .gitignore and remove from web root.",
                ));
            }
        }

        if path_lower.ends_with("/.vscode/sftp.json") || path_lower.ends_with("/sftp-config.json") {
            if body.contains("\"host\"") && (body.contains("\"password\"") || body.contains("\"privateKeyPath\"") || body.contains("\"username\"")) {
                return Some(self.create_vulnerability(
                    "Editor SFTP Configuration Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-522",
                    9.1,
                    "SFTP config leaks server hosts, usernames, and often passwords or key paths. Rotate credentials and remove from web root.",
                ));
            }
        }

        // Drupal settings.php
        if path_lower.ends_with("/sites/default/settings.php")
            || path_lower.ends_with("/sites/default/settings.local.php")
        {
            if body.contains("$databases") || body.contains("$settings['hash_salt']")
                || body.contains("'driver' =>") {
                return Some(self.create_vulnerability(
                    "Drupal settings.php Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Drupal settings.php contains database credentials and hash salt. Rotate credentials and secure the file.",
                ));
            }
        }

        // Magento local.xml / env.php
        if path_lower.ends_with("/app/etc/local.xml") {
            if body.contains("<username>") && body.contains("<password>") && body.contains("<dbname>") {
                return Some(self.create_vulnerability(
                    "Magento local.xml Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Magento local.xml exposes database credentials and crypt key. Rotate credentials immediately.",
                ));
            }
        }

        if path_lower.ends_with("/app/etc/env.php") {
            if body.contains("<?php") && body.contains("'db'") && body.contains("'connection'") {
                return Some(self.create_vulnerability(
                    "Magento 2 env.php Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Magento 2 env.php exposes encryption key, database credentials and cache configuration. Rotate all secrets.",
                ));
            }
        }

        // Django settings
        if path_lower.ends_with("/settings.py") || path_lower.ends_with("/local_settings.py")
            || path_lower.ends_with("/settings/production.py") || path_lower.ends_with("/settings/local.py")
        {
            if body.contains("SECRET_KEY") && body.contains("=")
                && (body.contains("DATABASES") || body.contains("INSTALLED_APPS"))
            {
                return Some(self.create_vulnerability(
                    "Django settings.py Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Django settings.py exposes SECRET_KEY and database credentials. Rotate SECRET_KEY (invalidates sessions) and DB passwords.",
                ));
            }
        }

        // appsettings.json (ASP.NET Core)
        if path_lower.ends_with("/appsettings.json")
            || path_lower.ends_with("/appsettings.development.json")
            || path_lower.ends_with("/appsettings.production.json")
        {
            if (body.contains("\"ConnectionStrings\"") || body.contains("\"ConnectionString\""))
                && body.contains("Password")
            {
                return Some(self.create_vulnerability(
                    "ASP.NET Core appsettings.json Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "appsettings.json exposes connection strings with credentials. Use User Secrets or Azure Key Vault in production.",
                ));
            }
        }

        // WEB-INF/web.xml
        if path_lower.contains("/web-inf/web.xml") {
            if body.contains("<web-app") || body.contains("<servlet>") || body.contains("<filter>") {
                return Some(self.create_vulnerability(
                    "Java WEB-INF/web.xml Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-200",
                    7.5,
                    "web.xml exposes servlet mappings, filters, and often context parameters with credentials. Block /WEB-INF/ at the web server layer.",
                ));
            }
        }

        // npmrc / composer auth.json
        if path_lower.ends_with("/.npmrc") {
            if body.contains("_authToken") || body.contains("//registry.npmjs.org/:_auth")
                || body.contains("//npm.pkg.github.com/:_authToken")
            {
                return Some(self.create_vulnerability(
                    ".npmrc With Auth Token Exposed",
                    url,
                    &self.truncate_evidence(body, 150),
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "The .npmrc contains an npm/GitHub package registry auth token. Revoke the token and remove the file from the web root.",
                ));
            }
        }

        if path_lower.ends_with("/auth.json") {
            if body.contains("\"http-basic\"") || body.contains("\"github-oauth\"")
                || body.contains("\"gitlab-token\"") || body.contains("\"bearer\"")
            {
                return Some(self.create_vulnerability(
                    "Composer auth.json Exposed",
                    url,
                    &self.truncate_evidence(body, 150),
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Composer auth.json contains package registry credentials. Revoke tokens and remove from web root.",
                ));
            }
        }

        // Redis RDB snapshot - binary signature
        if path_lower.ends_with("/dump.rdb") {
            if body.starts_with("REDIS") {
                return Some(self.create_vulnerability(
                    "Redis RDB Snapshot Exposed",
                    url,
                    "Redis database snapshot file served",
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "dump.rdb contains the full Redis dataset including session data and cached credentials. Remove from web root.",
                ));
            }
        }

        // .env file exposure
        if path.contains(".env") {
            let env_patterns = [
                "db_password=",
                "api_key=",
                "secret_key=",
                "app_secret=",
                "aws_secret_access_key=",
                "aws_access_key_id=",
                "app_key=",
                "database_url=",
                "jwt_secret=",
                "stripe_secret=",
                "mail_password=",
                "redis_password=",
                "pusher_app_secret=",
                "mailgun_secret=",
            ];
            if env_patterns.iter().any(|p| body_lower.contains(p)) {
                return Some(self.create_vulnerability(
                    "Environment File Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-215",
                    9.8,
                    "Remove .env files from web root. Use server-side environment variables. Add .env to .gitignore.",
                ));
            }
        }

        // Git repository exposure
        if path.contains(".git") {
            if body.contains("[core]")
                || body.contains("repositoryformatversion")
                || body.contains("ref: refs/")
            {
                return Some(self.create_vulnerability(
                    "Git Repository Files Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::High,
                    "CWE-540",
                    7.5,
                    "Remove .git directory from web root. Add server configuration to deny access to .git folders.",
                ));
            }
        }

        // Configuration files - use specific config file extensions/names, not bare "config"
        let is_config_file = path.ends_with(".conf")
            || path.ends_with(".cfg")
            || path.ends_with(".ini")
            || path.ends_with(".yaml")
            || path.ends_with(".yml")
            || path.contains("wp-config.php")
            || path.contains("web.config")
            || path.contains("application.properties")
            || path.contains("settings.py");
        if is_config_file {
            // Require credential assignment patterns, not just the word "password"
            let cred_patterns = [
                "password=",
                "password:",
                "password\":",
                "db_password",
                "db_user=",
                "db_host=",
                "db_name=",
                "secret_key=",
                "secret_key:",
            ];
            if cred_patterns.iter().any(|p| body_lower.contains(p)) {
                return Some(self.create_vulnerability(
                    "Configuration File with Credentials Exposed",
                    url,
                    &self.truncate_evidence(body, 200),
                    Severity::Critical,
                    "CWE-200",
                    9.1,
                    "Remove configuration files from web root. Store outside document root. Use environment variables.",
                ));
            }
        }

        // SQL dumps
        if path.contains(".sql") {
            if body.contains("INSERT INTO")
                || body.contains("CREATE TABLE")
                || body.contains("DROP TABLE")
            {
                return Some(self.create_vulnerability(
                    "Database Dump File Exposed",
                    url,
                    "SQL dump contains database structure and data",
                    Severity::Critical,
                    "CWE-538",
                    8.8,
                    "Remove SQL dump files from web root. Store backups securely outside public access.",
                ));
            }
        }

        // phpinfo exposure
        if path.contains("phpinfo") || path.contains("info.php") {
            if body.contains("PHP Version")
                || body.contains("phpinfo()")
                || body.contains("php.ini")
            {
                return Some(self.create_vulnerability(
                    "PHPInfo Page Exposed",
                    url,
                    "PHPInfo reveals server configuration and environment variables",
                    Severity::Medium,
                    "CWE-200",
                    5.3,
                    "Remove phpinfo() files from production. Disable in production environments.",
                ));
            }
        }

        // API documentation
        if path.contains("swagger") || path.contains("api-docs") || path.contains("openapi") {
            if body_lower.contains("swagger")
                || body_lower.contains("openapi")
                || body_lower.contains("\"paths\"")
            {
                return Some(self.create_vulnerability(
                    "API Documentation Exposed",
                    url,
                    "API documentation reveals endpoints and schema",
                    Severity::Medium,
                    "CWE-200",
                    5.3,
                    "Restrict access to API documentation in production. Require authentication.",
                ));
            }
        }

        // Log files - use word boundary check to avoid matching /blog, /catalog, /dialog, etc.
        let path_lower = path.to_lowercase();
        let is_log_path = path_lower.ends_with(".log")
            || path_lower.ends_with("/log")
            || path_lower.contains("/log/")
            || path_lower.contains("/logs/")
            || path_lower.contains("access.log")
            || path_lower.contains("error.log");
        if is_log_path {
            if (body.contains("ERROR") && body.contains("["))  // Log format: [ERROR] or [2024-01-01]
                || body.contains("Stack trace")
                || (body.contains("Exception") && body.contains(" at "))
            {
                return Some(self.create_vulnerability(
                    "Log File Exposed",
                    url,
                    "Log file may contain sensitive error information",
                    Severity::Medium,
                    "CWE-532",
                    5.3,
                    "Remove log files from web root. Configure logging to secure location. Disable directory listing.",
                ));
            }
        }

        // Server status pages
        if path.contains("server-status") || path.contains("server-info") {
            if body_lower.contains("apache")
                || body_lower.contains("server version")
                || body_lower.contains("uptime")
            {
                return Some(self.create_vulnerability(
                    "Server Status Page Exposed",
                    url,
                    "Server status reveals configuration and active connections",
                    Severity::Low,
                    "CWE-200",
                    3.7,
                    "Restrict access to server status pages. Require authentication or disable entirely.",
                ));
            }
        }

        // Package manager files (informational)
        if path.contains("package.json") || path.contains("composer.json") {
            if body_lower.contains("dependencies") || body_lower.contains("\"name\"") {
                return Some(self.create_vulnerability(
                    "Package Manager File Exposed",
                    url,
                    "Package file reveals dependencies and versions",
                    Severity::Info,
                    "CWE-200",
                    2.0,
                    "Consider restricting access to package manager files to prevent version enumeration.",
                ));
            }
        }

        None
    }

    /// Scan response body for exposed credentials
    fn scan_for_credentials(&self, body: &str, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // AWS Access Keys
        if let Some(matches) = self.regex_scan(body, r"AKIA[0-9A-Z]{16}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "AWS Access Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.5,
                    "Rotate AWS credentials immediately. Remove from client-side code. Use IAM roles.",
                ));
            }
        }

        // Stripe Secret Keys
        if let Some(matches) = self.regex_scan(body, r"sk_live_[a-zA-Z0-9]{24,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Stripe Secret Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.5,
                    "Rotate Stripe secret key immediately. Never expose secret keys client-side.",
                ));
            }
        }

        // Google API Keys
        if let Some(matches) = self.regex_scan(body, r"AIza[0-9A-Za-z\-_]{35}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Google API Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    7.5,
                    "Rotate Google API key. Implement API key restrictions (IP, referrer, API limits).",
                ));
            }
        }

        // GitHub Tokens
        if let Some(matches) = self.regex_scan(body, r"ghp_[a-zA-Z0-9]{36}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "GitHub Personal Access Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.0,
                    "Revoke GitHub token immediately. Use GitHub Apps or OAuth for authentication.",
                ));
            }
        }

        // Slack Tokens
        if let Some(matches) = self.regex_scan(body, r"xox[baprs]-[a-zA-Z0-9\-]{10,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Slack Token Exposed in Response",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    8.0,
                    "Revoke Slack token immediately. Rotate credentials. Use environment variables.",
                ));
            }
        }

        // GitHub App / Server / User / Refresh tokens
        if let Some(matches) = self.regex_scan(body, r"gh[suor]_[A-Za-z0-9_]{36,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "GitHub Token Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the GitHub token immediately. Check audit logs for abuse.",
                ));
            }
        }

        // GitLab PAT
        if let Some(matches) = self.regex_scan(body, r"glpat-[a-zA-Z0-9_\-]{20}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "GitLab Personal Access Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the GitLab PAT immediately.",
                ));
            }
        }

        // OpenAI API key
        if let Some(matches) = self.regex_scan(body, r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "OpenAI API Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the OpenAI API key immediately. OpenAI keys enable billing abuse.",
                ));
            }
        }

        // Anthropic API key
        if let Some(matches) = self.regex_scan(body, r"sk-ant-api[a-zA-Z0-9_\-]{32,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Anthropic API Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the Anthropic API key immediately.",
                ));
            }
        }

        // Stripe publishable+secret pair (secret is higher impact - already covered)
        if let Some(matches) = self.regex_scan(body, r"rk_live_[a-zA-Z0-9]{24,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Stripe Restricted Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Rotate the Stripe restricted key. Scoped API keys still allow real operations.",
                ));
            }
        }

        // Twilio Account SID + Auth token patterns (pair indicates real leak)
        if body.contains("AC") {
            if let Some(matches) = self.regex_scan(body, r"AC[a-f0-9]{32}") {
                // Only report if a plausible auth token is in the same response
                let has_auth_token = self
                    .regex_scan(body, r#"(?i)auth[_-]?token['"\s:=]{1,6}[a-f0-9]{32}"#)
                    .is_some();
                if has_auth_token {
                    for evidence in matches.into_iter().take(2) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Twilio Account SID + Auth Token Exposed",
                            url,
                            &evidence,
                            Severity::Critical,
                            "CWE-798",
                            9.1,
                            "Rotate the Twilio auth token immediately - attackers can send SMS/voice and incur charges.",
                        ));
                    }
                }
            }
        }

        // SendGrid API key
        if let Some(matches) = self.regex_scan(body, r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}")
        {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "SendGrid API Key Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the SendGrid API key. Attackers can send mail from your domain.",
                ));
            }
        }

        // Square access / OAuth secret
        if let Some(matches) = self.regex_scan(body, r"sq0(?:atp|csp)-[a-zA-Z0-9_\-]{22,43}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Square Token Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the Square token immediately.",
                ));
            }
        }

        // Shopify tokens
        if let Some(matches) = self.regex_scan(body, r"shp(?:at|pa|ss|ca)_[a-fA-F0-9]{32}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Shopify Token Exposed in Response",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the Shopify token; attackers can read or modify store data.",
                ));
            }
        }

        // HashiCorp Vault service token
        if let Some(matches) = self.regex_scan(body, r"hvs\.[A-Za-z0-9_\-]{24,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "HashiCorp Vault Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Revoke the Vault token immediately and audit accessed paths.",
                ));
            }
        }

        // Doppler API key
        if let Some(matches) = self.regex_scan(body, r"dp\.pt\.[A-Za-z0-9]{43}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Doppler API Key Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Revoke the Doppler service token - it provides access to all your secrets.",
                ));
            }
        }

        // Supabase service-role key (JWT with role=service_role)
        if let Some(matches) = self.regex_scan(body, r"sbp_[a-fA-F0-9]{40}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Supabase Service Key Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Rotate the Supabase service_role key - it bypasses Row-Level Security.",
                ));
            }
        }

        // Netlify Personal Access Token
        if let Some(matches) = self.regex_scan(body, r"nfp_[a-zA-Z0-9]{40}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Netlify Personal Access Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the Netlify token.",
                ));
            }
        }

        // Docker Hub personal access token
        if let Some(matches) = self.regex_scan(body, r"dckr_pat_[a-zA-Z0-9_\-]{27}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Docker Hub Access Token Exposed",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    8.2,
                    "Revoke the Docker Hub token and inspect push/pull logs.",
                ));
            }
        }

        // NPM token
        if let Some(matches) = self.regex_scan(body, r"npm_[A-Za-z0-9]{36}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "NPM Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the NPM automation/publish token.",
                ));
            }
        }

        // PyPI token
        if let Some(matches) = self.regex_scan(body, r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{40,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "PyPI API Token Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Revoke the PyPI API token - attackers can push malicious releases.",
                ));
            }
        }

        // MongoDB Atlas connection string with credentials
        if let Some(matches) = self.regex_scan(
            body,
            r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9.-]+\.mongodb\.net",
        ) {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "MongoDB Atlas Connection String Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.8,
                    "Rotate MongoDB Atlas DB user password and restrict source IPs.",
                ));
            }
        }

        // Generic "connection URL with embedded credentials"
        // Strictly require scheme + user + pass + @ + host.TLD
        if let Some(matches) = self.regex_scan(
            body,
            r#"(?:postgres(?:ql)?|mysql|redis|amqps?|mongodb(?:\+srv)?)://[A-Za-z0-9_][A-Za-z0-9_\-]*:[^@\s'"<>]+@[A-Za-z0-9][A-Za-z0-9.\-]+"#,
        ) {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Database Connection String With Credentials Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Rotate the database password. Never expose connection strings client-side.",
                ));
            }
        }

        // Google OAuth client secret format
        if let Some(matches) = self.regex_scan(body, r"GOCSPX-[a-zA-Z0-9_\-]{28}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Google OAuth Client Secret Exposed",
                    url,
                    &evidence,
                    Severity::Critical,
                    "CWE-798",
                    9.1,
                    "Rotate the Google OAuth client secret. Enable authorized origin/redirect restrictions.",
                ));
            }
        }

        // Firebase Cloud Messaging server key
        if let Some(matches) = self.regex_scan(body, r"AAAA[A-Za-z0-9_\-]{7}:APA91[A-Za-z0-9_\-]{134,}") {
            for evidence in matches.into_iter().take(2) {
                vulnerabilities.push(self.create_vulnerability(
                    "Firebase Cloud Messaging Server Key Exposed",
                    url,
                    &evidence,
                    Severity::High,
                    "CWE-798",
                    8.2,
                    "Rotate the FCM legacy server key; use HTTP v1 API with short-lived OAuth tokens.",
                ));
            }
        }

        // Private key block served in HTML/JSON response (not a file)
        if Self::contains_private_key_block(body) {
            vulnerabilities.push(self.create_vulnerability(
                "Private Key Block Exposed in Response",
                url,
                "PEM/OpenSSH private key material served in response body",
                Severity::Critical,
                "CWE-321",
                9.8,
                "Rotate the key pair immediately. Audit where the private key was reachable from and remove it from any public surface.",
            ));
        }

        vulnerabilities
    }

    /// Detect whether a body is an HTML error/SPA shell rather than the requested file.
    /// Heuristic: contains standard HTML and is not one of the signature-based file types we
    /// already positively identify. This reduces false positives from 200 OK default pages.
    fn looks_like_generic_html(body_lower: &str) -> bool {
        let html_hits = [
            "<!doctype html",
            "<html",
            "<head",
            "<body",
        ];
        let hit_count = html_hits.iter().filter(|p| body_lower.contains(*p)).count();
        if hit_count < 2 {
            return false;
        }
        // Only treat as generic HTML if there's no structured machine data markers
        // that could appear in sensitive files (e.g., JSON service accounts embedded
        // on pages are extremely rare but possible).
        !(body_lower.contains("\"private_key\"")
            || body_lower.contains("-----begin")
            || body_lower.contains("\"terraform_version\"")
            || body_lower.contains("aws_access_key_id")
            || body_lower.contains("<datasource"))
    }

    /// Detect PEM-encoded private key blocks. Extremely specific - these never appear in
    /// legitimate HTML responses.
    fn contains_private_key_block(body: &str) -> bool {
        body.contains("-----BEGIN RSA PRIVATE KEY-----")
            || body.contains("-----BEGIN DSA PRIVATE KEY-----")
            || body.contains("-----BEGIN EC PRIVATE KEY-----")
            || body.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
            || body.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
            || body.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || (body.contains("-----BEGIN PRIVATE KEY-----")
                && body.contains("-----END PRIVATE KEY-----"))
    }

    /// Perform regex scan and return matches
    fn regex_scan(&self, content: &str, pattern: &str) -> Option<Vec<String>> {
        let regex = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let matches: Vec<String> = regex
            .find_iter(content)
            .map(|m| {
                let matched = m.as_str();
                if matched.len() > 40 {
                    format!("{}...", &matched[..40])
                } else {
                    matched.to_string()
                }
            })
            .collect();

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Truncate evidence to specified length
    fn truncate_evidence(&self, text: &str, max_len: usize) -> String {
        if text.len() > max_len {
            format!("{}...", &text[..max_len])
        } else {
            text.to_string()
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f32,
        remediation: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("sensdata_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Sensitive Data Exposure".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> SensitiveDataScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        SensitiveDataScanner::new(client)
    }

    #[test]
    fn test_analyze_env_file() {
        let scanner = create_test_scanner();

        let body = "DB_PASSWORD=secret123\nAPI_KEY=abc123\nSECRET=xyz789";
        let vuln = scanner.analyze_sensitive_file(body, 200, "/.env", "https://example.com/.env");

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.vuln_type.contains("Environment File"));
    }

    #[test]
    fn test_analyze_git_config() {
        let scanner = create_test_scanner();

        let body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/.git/config",
            "https://example.com/.git/config",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert!(v.vuln_type.contains("Git Repository"));
    }

    #[test]
    fn test_analyze_sql_dump() {
        let scanner = create_test_scanner();

        let body = "CREATE TABLE users (id INT, name VARCHAR(255));\nINSERT INTO users VALUES (1, 'admin');";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/backup.sql",
            "https://example.com/backup.sql",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert_eq!(v.severity, Severity::Critical);
        assert!(v.vuln_type.contains("Database Dump"));
    }

    #[test]
    fn test_analyze_phpinfo() {
        let scanner = create_test_scanner();

        let body = "PHP Version 7.4.3\nSystem => Linux\nphp.ini => /etc/php/7.4/php.ini";
        let vuln = scanner.analyze_sensitive_file(
            body,
            200,
            "/phpinfo.php",
            "https://example.com/phpinfo.php",
        );

        assert!(vuln.is_some());
        let v = vuln.unwrap();
        assert!(v.vuln_type.contains("PHPInfo"));
    }

    #[test]
    fn test_regex_scan_aws_key() {
        let scanner = create_test_scanner();

        let body = r#"{"aws_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let matches = scanner.regex_scan(body, r"AKIA[0-9A-Z]{16}");

        assert!(matches.is_some());
        let m = matches.unwrap();
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_scan_for_credentials() {
        let scanner = create_test_scanner();

        let body = r#"{"stripe_key": "sk_test_FAKE_KEY_FOR_TESTING_ONLY"}"#;
        let vulns = scanner.scan_for_credentials(body, "https://example.com");

        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Stripe")));
    }

    #[test]
    fn test_get_sensitive_paths() {
        let scanner = create_test_scanner();
        let paths = scanner.get_sensitive_paths();

        assert!(paths.len() > 70);
        assert!(paths.contains(&"/.env"));
        assert!(paths.contains(&"/.git/config"));
        assert!(paths.contains(&"/phpinfo.php"));
        assert!(paths.contains(&"/backup.sql"));
    }
}
