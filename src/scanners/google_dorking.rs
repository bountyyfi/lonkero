// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Google Dorking Scanner
 * Generates Google dork queries to discover sensitive information
 *
 * This module generates search queries that can be used in Google
 * to find potentially sensitive resources, exposed files, and
 * vulnerable endpoints for a target domain.
 *
 * NOTE: This does not perform automated Google searches (which would
 * violate Google's Terms of Service). It generates queries for manual use.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::collections::HashMap;
use tracing::info;

/// Represents a Google Dork query with metadata
#[derive(Debug, Clone)]
pub struct GoogleDork {
    /// Category of the dork (e.g., "API Endpoints", "Sensitive Files")
    pub category: String,
    /// The actual dork query string
    pub query: String,
    /// Description of what this dork looks for
    pub description: String,
    /// Potential security impact
    pub impact: String,
}

/// Result of Google Dorking scan
#[derive(Debug, Clone)]
pub struct GoogleDorkingResults {
    /// Target domain
    pub domain: String,
    /// List of generated dork queries
    pub dorks: Vec<GoogleDork>,
    /// Dorks organized by category
    pub by_category: HashMap<String, Vec<GoogleDork>>,
}

pub struct GoogleDorkingScanner;

impl GoogleDorkingScanner {
    pub fn new() -> Self {
        Self
    }

    /// Generate Google dork queries for a domain
    pub fn generate_dorks(&self, domain: &str) -> GoogleDorkingResults {
        info!("Generating Google dorks for domain: {}", domain);

        let mut dorks = Vec::new();
        let clean_domain = domain
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        // PHP Extension with Parameters
        dorks.push(GoogleDork {
            category: "PHP Extensions".to_string(),
            query: format!("site:{} ext:php inurl:?", clean_domain),
            description: "Find PHP files with query parameters".to_string(),
            impact: "May expose PHP endpoints accepting user input, potential injection points"
                .to_string(),
        });

        // API Endpoints
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} inurl:api | site:{}/rest | site:{}/v1 | site:{}/v2 | site:{}/v3",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Discover API endpoints".to_string(),
            impact: "API endpoints may expose sensitive data or functionality".to_string(),
        });

        // Juicy Extensions (sensitive file types)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:\"{}\" ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json",
                clean_domain
            ),
            description: "Find sensitive file extensions".to_string(),
            impact: "May expose configuration files, credentials, backups, or version control data".to_string(),
        });

        // High % Inurl Keywords
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:{}",
                clean_domain
            ),
            description: "Find sensitive URL paths".to_string(),
            impact: "May reveal administrative interfaces, configuration endpoints, or backup files".to_string(),
        });

        // Server Errors
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "inurl:\"error\" | intitle:\"exception\" | intitle:\"failure\" | intitle:\"server at\" | inurl:exception | \"database error\" | \"SQL syntax\" | \"undefined index\" | \"unhandled exception\" | \"stack trace\" site:{}",
                clean_domain
            ),
            description: "Find error pages and stack traces".to_string(),
            impact: "Error messages may leak sensitive information about the application stack".to_string(),
        });

        // XSS Prone Parameters
        dorks.push(GoogleDork {
            category: "XSS Prone Parameters".to_string(),
            query: format!(
                "inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters commonly vulnerable to XSS".to_string(),
            impact: "Search and display parameters often lack proper output encoding".to_string(),
        });

        // Open Redirect Prone Parameters
        dorks.push(GoogleDork {
            category: "Open Redirect Parameters".to_string(),
            query: format!(
                "inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http site:{}",
                clean_domain
            ),
            description: "Find parameters prone to open redirect".to_string(),
            impact: "May allow attackers to redirect users to malicious sites".to_string(),
        });

        // SQLi Prone Parameters
        dorks.push(GoogleDork {
            category: "SQLi Prone Parameters".to_string(),
            query: format!(
                "inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters commonly vulnerable to SQL injection".to_string(),
            impact: "ID and category parameters often directly interact with databases".to_string(),
        });

        // SSRF Prone Parameters
        dorks.push(GoogleDork {
            category: "SSRF Prone Parameters".to_string(),
            query: format!(
                "inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters prone to SSRF".to_string(),
            impact: "URL-accepting parameters may allow server-side request forgery".to_string(),
        });

        // LFI Prone Parameters
        dorks.push(GoogleDork {
            category: "LFI Prone Parameters".to_string(),
            query: format!(
                "inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters prone to Local File Inclusion".to_string(),
            impact: "File path parameters may allow reading arbitrary files".to_string(),
        });

        // RCE Prone Parameters
        dorks.push(GoogleDork {
            category: "RCE Prone Parameters".to_string(),
            query: format!(
                "inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters prone to Remote Code Execution".to_string(),
            impact: "Command execution parameters are critical security risks".to_string(),
        });

        // File Upload Endpoints
        dorks.push(GoogleDork {
            category: "File Upload".to_string(),
            query: format!(
                "site:{} intext:\"choose file\" | intext:\"select file\" | intext:\"upload PDF\"",
                clean_domain
            ),
            description: "Find file upload functionality".to_string(),
            impact: "File upload features may allow arbitrary file uploads".to_string(),
        });

        // API Documentation
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer | inurl:redoc | inurl:openapi | intitle:\"Swagger UI\" site:\"{}\"",
                clean_domain
            ),
            description: "Find exposed API documentation".to_string(),
            impact: "API docs reveal endpoints, parameters, and authentication methods".to_string(),
        });

        // Login Pages
        dorks.push(GoogleDork {
            category: "Login Pages".to_string(),
            query: format!(
                "inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:{}",
                clean_domain
            ),
            description: "Find login and authentication pages".to_string(),
            impact: "Login pages are targets for credential attacks".to_string(),
        });

        // Test Environments
        dorks.push(GoogleDork {
            category: "Test Environments".to_string(),
            query: format!(
                "inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:{}",
                clean_domain
            ),
            description: "Find development and test environments".to_string(),
            impact: "Non-production environments often have weaker security".to_string(),
        });

        // Sensitive Documents
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:{} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx intext:\"confidential\" | intext:\"Not for Public Release\" | intext:\"internal use only\" | intext:\"do not distribute\"",
                clean_domain
            ),
            description: "Find confidential documents".to_string(),
            impact: "May expose sensitive business documents and data".to_string(),
        });

        // Sensitive Parameters (PII)
        dorks.push(GoogleDork {
            category: "PII Parameters".to_string(),
            query: format!(
                "inurl:email= | inurl:phone= | inurl:name= | inurl:user= inurl:& site:{}",
                clean_domain
            ),
            description: "Find parameters handling personal information".to_string(),
            impact: "PII parameters may be vulnerable to enumeration or injection".to_string(),
        });

        // Adobe Experience Manager (AEM)
        dorks.push(GoogleDork {
            category: "AEM Paths".to_string(),
            query: format!(
                "inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:{}",
                clean_domain
            ),
            description: "Find Adobe Experience Manager paths".to_string(),
            impact: "AEM misconfigurations can expose admin interfaces and content".to_string(),
        });

        // Disclosed XSS and Open Redirects (OpenBugBounty)
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "site:openbugbounty.org inurl:reports intext:\"{}\"",
                clean_domain
            ),
            description: "Find disclosed vulnerabilities on OpenBugBounty".to_string(),
            impact: "Previously reported vulnerabilities may still be unpatched".to_string(),
        });

        // Google Groups
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:groups.google.com \"{}\"", clean_domain),
            description: "Find mentions in Google Groups".to_string(),
            impact: "May reveal internal discussions, credentials, or configurations".to_string(),
        });

        // Code Leaks - Pastebin
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:pastebin.com \"{}\"", clean_domain),
            description: "Find code snippets on Pastebin".to_string(),
            impact: "May expose credentials, API keys, or internal code".to_string(),
        });

        // Code Leaks - JSFiddle
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:jsfiddle.net \"{}\"", clean_domain),
            description: "Find code snippets on JSFiddle".to_string(),
            impact: "May expose frontend code with hardcoded credentials".to_string(),
        });

        // Code Leaks - CodeBeautify
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:codebeautify.org \"{}\"", clean_domain),
            description: "Find code snippets on CodeBeautify".to_string(),
            impact: "May expose formatted code with sensitive data".to_string(),
        });

        // Code Leaks - CodePen
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:codepen.io \"{}\"", clean_domain),
            description: "Find code snippets on CodePen".to_string(),
            impact: "May expose frontend code with API endpoints".to_string(),
        });

        // Cloud Storage - AWS S3
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:s3.amazonaws.com \"{}\"", clean_domain),
            description: "Find AWS S3 buckets".to_string(),
            impact: "Misconfigured S3 buckets may expose sensitive data".to_string(),
        });

        // Cloud Storage - Azure Blob
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:blob.core.windows.net \"{}\"", clean_domain),
            description: "Find Azure Blob storage".to_string(),
            impact: "Misconfigured blob storage may expose sensitive data".to_string(),
        });

        // Cloud Storage - Google Cloud
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:googleapis.com \"{}\"", clean_domain),
            description: "Find Google Cloud Storage".to_string(),
            impact: "May expose GCS buckets or API responses".to_string(),
        });

        // Cloud Storage - Google Drive
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:drive.google.com \"{}\"", clean_domain),
            description: "Find Google Drive files".to_string(),
            impact: "Shared Drive files may contain sensitive information".to_string(),
        });

        // Cloud Storage - Azure DevOps
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:dev.azure.com \"{}\"", clean_domain),
            description: "Find Azure DevOps resources".to_string(),
            impact: "May expose repositories, pipelines, or configurations".to_string(),
        });

        // Cloud Storage - OneDrive
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:onedrive.live.com \"{}\"", clean_domain),
            description: "Find OneDrive files".to_string(),
            impact: "Shared OneDrive files may contain sensitive data".to_string(),
        });

        // Cloud Storage - DigitalOcean Spaces
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:digitaloceanspaces.com \"{}\"", clean_domain),
            description: "Find DigitalOcean Spaces".to_string(),
            impact: "Misconfigured Spaces may expose sensitive files".to_string(),
        });

        // Cloud Storage - SharePoint
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:sharepoint.com \"{}\"", clean_domain),
            description: "Find SharePoint resources".to_string(),
            impact: "May expose internal documents and files".to_string(),
        });

        // Cloud Storage - S3 External
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:s3-external-1.amazonaws.com \"{}\"", clean_domain),
            description: "Find S3 external buckets".to_string(),
            impact: "Additional S3 bucket configurations".to_string(),
        });

        // Cloud Storage - S3 Dualstack
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.dualstack.us-east-1.amazonaws.com \"{}\"",
                clean_domain
            ),
            description: "Find S3 dualstack buckets".to_string(),
            impact: "IPv6-enabled S3 buckets".to_string(),
        });

        // Cloud Storage - Dropbox
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:dropbox.com/s \"{}\"", clean_domain),
            description: "Find Dropbox shared links".to_string(),
            impact: "Shared Dropbox files may contain sensitive data".to_string(),
        });

        // Cloud Storage - Google Docs
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!("site:docs.google.com inurl:\"/d/\" \"{}\"", clean_domain),
            description: "Find Google Docs".to_string(),
            impact: "Shared documents may contain sensitive information".to_string(),
        });

        // JFrog Artifactory
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!("site:jfrog.io \"{}\"", clean_domain),
            description: "Find JFrog Artifactory resources".to_string(),
            impact: "May expose build artifacts or internal packages".to_string(),
        });

        // Firebase
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!("site:firebaseio.com \"{}\"", clean_domain),
            description: "Find Firebase databases".to_string(),
            impact: "Misconfigured Firebase may expose data without authentication".to_string(),
        });

        // Security.txt with Bounty
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: "site:*/security.txt \"bounty\"".to_string(),
            description: "Find security.txt files mentioning bug bounty".to_string(),
            impact: "Identifies targets with bug bounty programs".to_string(),
        });

        // GitHub Code Search
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:github.com \"{}\"", clean_domain),
            description: "Find GitHub repositories mentioning the domain".to_string(),
            impact: "May expose source code, credentials, or internal tools".to_string(),
        });

        // GitLab Code Search
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:gitlab.com \"{}\"", clean_domain),
            description: "Find GitLab repositories mentioning the domain".to_string(),
            impact: "May expose source code or configurations".to_string(),
        });

        // Trello Boards
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:trello.com \"{}\"", clean_domain),
            description: "Find Trello boards".to_string(),
            impact: "Public Trello boards may expose project details and credentials".to_string(),
        });

        // ==============================================================
        // Sensitive-information dorks (high-impact, low-noise).
        //
        // Each dork below either scopes to the target domain (site:{})
        // or joins the domain into a text query, so results are always
        // relevant to the target. The queries look for narrowly-defined
        // sensitive artefacts — dotfiles, backups, environment files,
        // dumps, cloud credentials, VCS leaks — not fuzzy keywords.
        // ==============================================================

        // Version control leaks — exposed .git / .svn / .hg directories
        dorks.push(GoogleDork {
            category: "Version Control Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs\" | inurl:\".gitignore\" | inurl:\".svn/entries\" | inurl:\".hg/store\")",
                clean_domain
            ),
            description: "Find exposed .git/.svn/.hg metadata".to_string(),
            impact: "A readable .git directory allows full source-code reconstruction and often leaks credentials from commit history.".to_string(),
        });

        // Environment / dotenv files
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.staging\" | inurl:\".env.dev\" | inurl:\".env.bak\" | inurl:\"env.js\") -github",
                clean_domain
            ),
            description: "Find exposed .env / dotenv files".to_string(),
            impact: "Dotenv files typically contain database credentials, API keys, cloud provider secrets, and third-party service tokens.".to_string(),
        });

        // Cloud credentials on disk
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".aws/config\" | inurl:\"gcloud/credentials\" | inurl:\"application_default_credentials.json\" | inurl:\".s3cfg\" | inurl:\".boto\" | inurl:\"docker/config.json\")",
                clean_domain
            ),
            description: "Find leaked AWS / GCP / Docker credential files".to_string(),
            impact: "These files grant full programmatic access to cloud providers or private container registries.".to_string(),
        });

        // Kubernetes / container platform manifests
        dorks.push(GoogleDork {
            category: "Kubernetes / Container Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\".kube/config\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.override.yml\" | inurl:\"helm/values.yaml\" | inurl:\"tiller-secret\" | inurl:\"secrets.yaml\" | inurl:\"secret.yaml\") ext:yaml | ext:yml | ext:json | ext:conf",
                clean_domain
            ),
            description: "Find Kubernetes / Docker / Helm secrets".to_string(),
            impact: "Kubeconfig files grant cluster-admin access; docker-compose and helm values commonly contain plaintext DB/API secrets.".to_string(),
        });

        // Private key material
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:p12 | ext:pfx | ext:asc | ext:jks | ext:keystore | ext:crt) (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\" | intext:\"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find exposed private cryptographic keys".to_string(),
            impact: "Private keys enable SSH access, TLS impersonation, JWT signing forgery, or PGP identity theft.".to_string(),
        });

        // Database dumps and SQL exports
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dbf | ext:mdb | ext:sqlite | ext:sqlitedb | ext:db | ext:sql.gz | ext:sql.bz2 | ext:dump) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"MySQL dump\" | intext:\"pg_dump\" | intext:\"phpMyAdmin\")",
                clean_domain
            ),
            description: "Find exposed database dumps / SQL exports".to_string(),
            impact: "Full database exports commonly contain user PII, password hashes, session tokens, and internal business data.".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:back | ext:old | ext:orig | ext:tmp | ext:swp | ext:save | ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z) inurl:(backup | dump | archive | export)",
                clean_domain
            ),
            description: "Find server-side backup archives".to_string(),
            impact: "Web-accessible backups often contain application source, configuration secrets, and full database exports.".to_string(),
        });

        // OS/editor artefacts (metadata leaks)
        dorks.push(GoogleDork {
            category: "OS / Editor Metadata".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\".vscode/settings.json\" | inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources.xml\" | inurl:\".idea/webServers.xml\")",
                clean_domain
            ),
            description: "Find leaked editor / OS metadata files".to_string(),
            impact: ".DS_Store and IDE workspace files enumerate the site's directory structure; JetBrains dataSources.xml also leaks DB hostnames and users.".to_string(),
        });

        // Web-server / framework configuration
        dorks.push(GoogleDork {
            category: "Server Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"web.config\" | inurl:\"nginx.conf\" | inurl:\"httpd.conf\" | inurl:\".htpasswd\" | inurl:\".htaccess\" | inurl:\"php.ini\" | inurl:\"wp-config.php.bak\" | inurl:\"config.php.bak\" | inurl:\"settings.py.bak\" | inurl:\"local_settings.py\" | inurl:\"application.yml\" | inurl:\"application.properties\")",
                clean_domain
            ),
            description: "Find exposed server / framework configuration files".to_string(),
            impact: "Server configs frequently expose DB connection strings, HMAC secrets, mail credentials, and internal endpoints.".to_string(),
        });

        // Application log files
        dorks.push(GoogleDork {
            category: "Application Logs".to_string(),
            query: format!(
                "site:{} (inurl:\"error.log\" | inurl:\"access.log\" | inurl:\"debug.log\" | inurl:\"application.log\" | inurl:\"laravel.log\" | inurl:\"npm-debug.log\" | inurl:\"yarn-error.log\" | inurl:\"catalina.out\" | inurl:\"gunicorn.log\") ext:log",
                clean_domain
            ),
            description: "Find publicly accessible application log files".to_string(),
            impact: "Log files can contain stack traces, session tokens, PII, and full request bodies — a common exfiltration point.".to_string(),
        });

        // CI / CD configuration
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".gitlab-ci.yml\" | inurl:\".travis.yml\" | inurl:\".circleci/config.yml\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"Jenkinsfile\" | inurl:\"buildspec.yml\" | inurl:\"azure-pipelines.yml\" | inurl:\".github/workflows\")",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline configuration".to_string(),
            impact: "Pipeline configs often reference secret names and leak internal registry hosts, S3 buckets, and deploy targets.".to_string(),
        });

        // Package manager metadata
        dorks.push(GoogleDork {
            category: "Package Manager Metadata".to_string(),
            query: format!(
                "site:{} (inurl:\"composer.lock\" | inurl:\"package-lock.json\" | inurl:\"yarn.lock\" | inurl:\"Pipfile.lock\" | inurl:\"poetry.lock\" | inurl:\"Cargo.lock\" | inurl:\"go.sum\" | inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\".gem/credentials\")",
                clean_domain
            ),
            description: "Find package-manager credentials and lock files".to_string(),
            impact: "npmrc/pypirc/gem-credentials contain publish tokens; lock files fingerprint every dependency version for CVE mapping.".to_string(),
        });

        // Monitoring / observability dashboards
        dorks.push(GoogleDork {
            category: "Exposed Monitoring".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" | intitle:\"Kibana\" | intitle:\"Prometheus\" | intitle:\"Alertmanager\" | intitle:\"Consul UI\" | intitle:\"Nomad\" | intitle:\"Airflow\" | intitle:\"MinIO Browser\" | intitle:\"RabbitMQ Management\" | intitle:\"Traefik\" | intitle:\"Kong Manager\")",
                clean_domain
            ),
            description: "Find exposed observability / cluster dashboards".to_string(),
            impact: "Unauthenticated Grafana/Kibana/Prometheus reveal metrics topology; Consul/Nomad may allow full cluster control.".to_string(),
        });

        // Admin / management panels
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"pgAdmin\" | intitle:\"Adminer\" | intitle:\"cPanel\" | intitle:\"Plesk\" | intitle:\"DirectAdmin\" | intitle:\"Webmin\" | intitle:\"Portainer\" | intitle:\"Jenkins Dashboard\" | intitle:\"phpPgAdmin\" | intitle:\"phpRedisAdmin\")",
                clean_domain
            ),
            description: "Find exposed database / server admin panels".to_string(),
            impact: "Any of these panels behind weak or default credentials leads directly to full database/host compromise.".to_string(),
        });

        // Debug / diagnostic endpoints
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/debug/pprof\" | inurl:\"/debug/vars\" | inurl:\"/metrics\" | inurl:\"phpinfo.php\" | inurl:\"/server-status\" | inurl:\"/server-info\" | inurl:\"trace.axd\" | inurl:\"elmah.axd\")",
                clean_domain
            ),
            description: "Find exposed debug / introspection endpoints".to_string(),
            impact: "Spring Actuator env, Go pprof heap dumps, elmah.axd, and phpinfo leak secrets, memory contents, and full server state.".to_string(),
        });

        // Directory listings
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} (intitle:\"Index of /\" | intitle:\"Directory Listing For\" | intitle:\"Directory listing for\") -inurl:(html|htm|php|asp|aspx|jsp)",
                clean_domain
            ),
            description: "Find open directory listings".to_string(),
            impact: "Autoindex-enabled paths let attackers enumerate every file the web server can serve.".to_string(),
        });

        // Cloud metadata proxies exposed
        dorks.push(GoogleDork {
            category: "Cloud Metadata Proxies".to_string(),
            query: format!(
                "site:{} (inurl:\"latest/meta-data\" | inurl:\"latest/user-data\" | inurl:\"computeMetadata/v1\" | inurl:\"metadata/instance\")",
                clean_domain
            ),
            description: "Find endpoints proxying cloud instance metadata".to_string(),
            impact: "Access to instance metadata (EC2 IMDS, GCE, Azure IMDS) yields the machine's cloud role credentials.".to_string(),
        });

        // SaaS project artefacts exposed publicly
        dorks.push(GoogleDork {
            category: "SaaS Project Artefacts".to_string(),
            query: format!(
                "site:{} (inurl:\"postman_collection.json\" | inurl:\"insomnia_export\" | inurl:\"har\" | ext:har) intext:\"authorization\"",
                clean_domain
            ),
            description: "Find leaked Postman / Insomnia / HAR captures".to_string(),
            impact: "Exported API collections and HAR files nearly always contain live bearer tokens, cookies, and API keys.".to_string(),
        });

        // Sensitive corporate documents
        dorks.push(GoogleDork {
            category: "Confidential Corporate Docs".to_string(),
            query: format!(
                "site:{} (ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:csv) (intext:\"confidential\" | intext:\"internal use only\" | intext:\"not for distribution\" | intext:\"proprietary\" | intext:\"classification: restricted\")",
                clean_domain
            ),
            description: "Find explicitly-marked confidential documents".to_string(),
            impact: "Documents watermarked confidential/internal often contain contracts, roadmaps, security assessments, or personnel data.".to_string(),
        });

        // Personally identifiable information (PII) in indexed files
        dorks.push(GoogleDork {
            category: "PII in Documents".to_string(),
            query: format!(
                "site:{} (ext:xlsx | ext:xls | ext:csv | ext:txt | ext:pdf) (intext:\"SSN\" | intext:\"Social Security\" | intext:\"passport\" | intext:\"date of birth\" | intext:\"cardholder\" | intext:\"IBAN\" | intext:\"routing number\")",
                clean_domain
            ),
            description: "Find documents containing typical PII markers".to_string(),
            impact: "PII exposure triggers regulatory obligations (GDPR/HIPAA/PCI) and immediate breach-notification duty.".to_string(),
        });

        // Invoices / receipts / financial exports
        dorks.push(GoogleDork {
            category: "Financial Documents".to_string(),
            query: format!(
                "site:{} (inurl:invoice | inurl:receipt | inurl:statement | inurl:payslip | inurl:paystub | inurl:tax) (ext:pdf | ext:xlsx | ext:xls | ext:csv)",
                clean_domain
            ),
            description: "Find leaked invoices, receipts, payslips".to_string(),
            impact: "Financial exports leak client lists, revenue, employee compensation, and payment identifiers.".to_string(),
        });

        // Third-party secret leaks about this domain
        dorks.push(GoogleDork {
            category: "Public Code Repos Referencing Domain".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitlab.com/-/snippets | site:bitbucket.org/snippets) \"{}\"",
                clean_domain
            ),
            description: "Search public gists / snippets for the domain".to_string(),
            impact: "Ad-hoc snippets are a common leak surface for hard-coded credentials and internal endpoints.".to_string(),
        });

        // Search across public wikis / paste hubs beyond Pastebin
        dorks.push(GoogleDork {
            category: "Paste Sites".to_string(),
            query: format!(
                "(site:ghostbin.com | site:paste.ee | site:hastebin.com | site:justpaste.it | site:controlc.com | site:paste.debian.net | site:dpaste.com | site:pastie.io | site:rentry.co) \"{}\"",
                clean_domain
            ),
            description: "Find domain references across common paste sites".to_string(),
            impact: "Pasted debug output, logs, and support conversations regularly leak tokens or session cookies.".to_string(),
        });

        // WordPress-specific exposures
        dorks.push(GoogleDork {
            category: "WordPress Exposures".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php\" | inurl:\"wp-config.php.bak\" | inurl:\"wp-config.old\" | inurl:\"wp-content/debug.log\" | inurl:\"wp-content/uploads/dump.sql\" | inurl:\"wp-admin/admin-ajax.php?action=\")",
                clean_domain
            ),
            description: "Find exposed WordPress secrets and debug output".to_string(),
            impact: "wp-config.php holds the DB credentials, secret keys, and auth salts — full site takeover once obtained.".to_string(),
        });

        // Drupal / Joomla / other CMS config exposures
        dorks.push(GoogleDork {
            category: "CMS Config Exposures".to_string(),
            query: format!(
                "site:{} (inurl:\"sites/default/settings.php\" | inurl:\"sites/default/settings.local.php\" | inurl:\"configuration.php\" | inurl:\"CHANGELOG.txt\" | inurl:\"MAINTAINERS.txt\") (inurl:drupal | inurl:joomla | inurl:magento | inurl:typo3)",
                clean_domain
            ),
            description: "Find exposed non-WordPress CMS configuration".to_string(),
            impact: "Drupal/Joomla/Magento settings files contain DB credentials, cookie salts, and cron tokens.".to_string(),
        });

        // Salesforce / SharePoint public objects
        dorks.push(GoogleDork {
            category: "Enterprise SaaS Exposures".to_string(),
            query: format!(
                "(site:force.com | site:salesforce.com | site:my.salesforce.com | site:sharepoint.com | site:atlassian.net | site:zendesk.com) \"{}\"",
                clean_domain
            ),
            description: "Find enterprise-SaaS objects that reference the domain".to_string(),
            impact: "Improperly-scoped Salesforce/Sharepoint/Atlassian shares are a common breach path for internal data.".to_string(),
        });

        // API keys pasted alongside the domain
        dorks.push(GoogleDork {
            category: "API Key Leaks (Cross-site)".to_string(),
            query: format!(
                "\"{}\" (\"AKIA\" | \"AIza\" | \"ghp_\" | \"glpat-\" | \"sk_live_\" | \"xoxb-\" | \"xoxp-\" | \"SG.\" | \"npm_\" | \"dckr_pat_\" | \"pypi-\" | \"sk-ant-\")",
                clean_domain
            ),
            description: "Search anywhere on the web for prefixed provider tokens next to this domain".to_string(),
            impact: "Vendor-prefixed tokens (AWS AKIA, Slack xoxb, Stripe sk_live) are near-zero-false-positive credential markers.".to_string(),
        });

        // Have I Been Pwned domain awareness
        dorks.push(GoogleDork {
            category: "Breach Data".to_string(),
            query: format!(
                "(site:dehashed.com | site:leakcheck.io | site:snusbase.com | site:haveibeenpwned.com | site:intelx.io) \"{}\"",
                clean_domain
            ),
            description: "Find breach-database mentions of the target domain".to_string(),
            impact: "Public references to breach dumps indicate leaked employee credentials still valid for reuse.".to_string(),
        });

        // Build categories map
        let mut by_category: HashMap<String, Vec<GoogleDork>> = HashMap::new();
        for dork in &dorks {
            by_category
                .entry(dork.category.clone())
                .or_default()
                .push(dork.clone());
        }

        GoogleDorkingResults {
            domain: clean_domain.to_string(),
            dorks,
            by_category,
        }
    }

    /// Scan target and return results (for compatibility with scan engine)
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize, GoogleDorkingResults)> {
        // Extract domain from URL
        let domain = extract_domain(url);
        let results = self.generate_dorks(&domain);

        // Create an informational "vulnerability" to include in reports
        let vuln = Vulnerability {
            id: format!("google_dorking_{}", generate_uuid()),
            vuln_type: "GOOGLE_DORKS_GENERATED".to_string(),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: "Reconnaissance".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description: format!(
                "Generated {} Google dork queries for {} across {} categories",
                results.dorks.len(),
                domain,
                results.by_category.len()
            ),
            evidence: Some(format!(
                "Categories: {}",
                results.by_category.keys().cloned().collect::<Vec<_>>().join(", ")
            )),
            cwe: "CWE-200".to_string(),
            cvss: 0.0,
            verified: true,
            false_positive: false,
            remediation: "Review generated dorks manually in Google Search to find exposed resources. \
                Remediate any findings by removing sensitive files, securing endpoints, or implementing \
                proper access controls.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        };

        Ok((vec![vuln], results.dorks.len(), results))
    }

    /// Format dorks for display
    pub fn format_dorks_for_display(results: &GoogleDorkingResults) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n╔══════════════════════════════════════════════════════════════════╗\n"
        ));
        output.push_str(&format!("║  GOOGLE DORKS FOR: {:<46} ║\n", results.domain));
        output.push_str(&format!("║  Total Dorks: {:<51} ║\n", results.dorks.len()));
        output.push_str(&format!(
            "╚══════════════════════════════════════════════════════════════════╝\n\n"
        ));

        let categories: Vec<&String> = {
            let mut cats: Vec<_> = results.by_category.keys().collect();
            cats.sort();
            cats
        };

        for category in categories {
            if let Some(dorks) = results.by_category.get(category) {
                output.push_str(&format!("┌─ {} ({} dorks)\n", category, dorks.len()));
                output.push_str("│\n");

                for dork in dorks {
                    output.push_str(&format!("│  📝 {}\n", dork.description));
                    output.push_str(&format!("│  🔍 {}\n", dork.query));
                    output.push_str(&format!("│  ⚠️  Impact: {}\n", dork.impact));
                    output.push_str("│\n");
                }
                output.push_str(
                    "└────────────────────────────────────────────────────────────────────\n\n",
                );
            }
        }

        output
    }

    /// Format dorks as JSON for output files
    pub fn format_dorks_as_json(results: &GoogleDorkingResults) -> serde_json::Value {
        let dorks_json: Vec<serde_json::Value> = results
            .dorks
            .iter()
            .map(|d| {
                serde_json::json!({
                    "category": d.category,
                    "query": d.query,
                    "description": d.description,
                    "impact": d.impact
                })
            })
            .collect();

        serde_json::json!({
            "domain": results.domain,
            "total_dorks": results.dorks.len(),
            "categories": results.by_category.keys().collect::<Vec<_>>(),
            "dorks": dorks_json
        })
    }
}

impl Default for GoogleDorkingScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract domain from URL
fn extract_domain(url: &str) -> String {
    let url = url.trim();
    let without_scheme = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Get the domain part (before any path)
    if let Some(slash_pos) = without_scheme.find('/') {
        without_scheme[..slash_pos].to_string()
    } else {
        without_scheme.to_string()
    }
}

/// Generate a simple UUID
fn generate_uuid() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rng.random::<u32>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u16>(),
        rng.random::<u64>() & 0xffffffffffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com"), "example.com");
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(extract_domain("http://sub.example.com"), "sub.example.com");
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_generate_dorks() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        assert!(!results.dorks.is_empty());
        assert!(!results.by_category.is_empty());
        assert_eq!(results.domain, "example.com");
    }

    #[test]
    fn test_dorks_contain_domain() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("test.example.org");

        // Most dorks should contain the domain
        let dorks_with_domain = results
            .dorks
            .iter()
            .filter(|d| d.query.contains("test.example.org") || d.query.contains("example"))
            .count();

        assert!(dorks_with_domain > results.dorks.len() / 2);
    }

    #[test]
    fn test_categories_exist() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        // Check some expected categories exist
        assert!(results.by_category.contains_key("API Endpoints"));
        assert!(results.by_category.contains_key("Sensitive Files"));
        assert!(results.by_category.contains_key("Cloud Storage"));
    }

    #[test]
    fn test_format_for_display() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");
        let output = GoogleDorkingScanner::format_dorks_for_display(&results);

        assert!(output.contains("example.com"));
        assert!(output.contains("GOOGLE DORKS"));
    }

    #[test]
    fn test_format_as_json() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");
        let json = GoogleDorkingScanner::format_dorks_as_json(&results);

        assert!(json.get("domain").is_some());
        assert!(json.get("dorks").is_some());
        assert!(json.get("total_dorks").is_some());
    }
}
