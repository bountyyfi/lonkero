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

        // .env files (indexed by mistake)
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (intitle:\"index of\" | ext:env | ext:envrc) (\"DB_PASSWORD\" | \"APP_KEY\" | \"AWS_SECRET_ACCESS_KEY\" | \"SECRET_KEY_BASE\" | \"STRIPE_SECRET\")",
                clean_domain
            ),
            description: "Find indexed .env files with credentials".to_string(),
            impact: "Directly exposes database passwords, cloud secrets, API keys, and app signing keys".to_string(),
        });

        // Rails master.key / credentials.yml.enc
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:config/master.key | inurl:config/credentials.yml.enc)",
                clean_domain
            ),
            description: "Find Rails master.key or encrypted credentials".to_string(),
            impact: "master.key decrypts credentials.yml.enc — full Rails secret material".to_string(),
        });

        // Terraform state / tfvars
        dorks.push(GoogleDork {
            category: "IaC Secrets".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:terraform.tfstate | inurl:terraform.tfstate.backup)",
                clean_domain
            ),
            description: "Find exposed Terraform state / tfvars".to_string(),
            impact: "Terraform state files contain plaintext secrets, resource IDs, and infra topology".to_string(),
        });

        // Kubernetes / Helm exposures
        dorks.push(GoogleDork {
            category: "Kubernetes / Container".to_string(),
            query: format!(
                "site:{} (inurl:kubeconfig | inurl:.kube/config | inurl:values.yaml | inurl:charts | ext:yaml intext:\"apiVersion\" intext:\"kind: Secret\")",
                clean_domain
            ),
            description: "Find Kubernetes kubeconfig, Helm values, or leaked K8s Secret manifests".to_string(),
            impact: "kubeconfig grants cluster admin access; K8s Secret YAML leaks base64-encoded credentials".to_string(),
        });

        // Docker registry / configs
        dorks.push(GoogleDork {
            category: "Kubernetes / Container".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:.dockercfg | inurl:.docker/config.json | inurl:Dockerfile intext:\"ENV\")",
                clean_domain
            ),
            description: "Find Docker compose files, registry credentials, and Dockerfiles with ENV secrets".to_string(),
            impact: "docker-compose files and .dockercfg often embed registry credentials and DB passwords".to_string(),
        });

        // Cloud credential files
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:.aws/config | inurl:credentials.csv intext:\"AWS_ACCESS_KEY\" | inurl:aws_access_key_id)",
                clean_domain
            ),
            description: "Find exposed AWS credential material".to_string(),
            impact: "AWS credential files grant direct programmatic access to the account".to_string(),
        });

        // GCP service account JSON
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} ext:json (\"type\":\"service_account\" | \"private_key\":\"-----BEGIN PRIVATE KEY-----\")",
                clean_domain
            ),
            description: "Find exposed GCP service account JSON keys".to_string(),
            impact: "GCP service account key files grant persistent programmatic access to the project".to_string(),
        });

        // Private keys (SSH, PGP, PEM)
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:pfx | ext:p12) intext:\"BEGIN PRIVATE KEY\" | intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\"",
                clean_domain
            ),
            description: "Find exposed private key material".to_string(),
            impact: "Private keys enable authentication as the owning identity (SSH, TLS, code signing, PGP)".to_string(),
        });

        // SSH authorized_keys and known_hosts
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (inurl:.ssh/authorized_keys | inurl:.ssh/known_hosts | inurl:.ssh/id_rsa | inurl:.ssh/id_ed25519)",
                clean_domain
            ),
            description: "Find leaked SSH directory contents".to_string(),
            impact: "authorized_keys reveals persistent trust; leaked id_rsa/id_ed25519 grants shell access".to_string(),
        });

        // Database backups / dumps
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:sqlitedb | ext:db | ext:mdb | ext:bak) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intitle:\"index of\")",
                clean_domain
            ),
            description: "Find database dumps and backup files".to_string(),
            impact: "Database dumps disclose entire user tables, hashed passwords, and PII in bulk".to_string(),
        });

        // WordPress config / secret files
        dorks.push(GoogleDork {
            category: "WordPress Exposures".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.old | inurl:wp-config.txt | inurl:wp-config.php~ | inurl:.wp-config.php.swp | inurl:wp-content/debug.log)",
                clean_domain
            ),
            description: "Find WordPress config leftovers and debug logs".to_string(),
            impact: "wp-config backups contain DB credentials and auth salts; debug.log leaks internal state".to_string(),
        });

        // WordPress uploads directory listing
        dorks.push(GoogleDork {
            category: "WordPress Exposures".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (inurl:wp-content/uploads | inurl:wp-content/backup | inurl:wp-content/plugins)",
                clean_domain
            ),
            description: "Find WordPress uploads/backups with directory listing".to_string(),
            impact: "Directory listings expose customer uploads, plugin backups, and staging artifacts".to_string(),
        });

        // Jenkins / CI dashboards
        dorks.push(GoogleDork {
            category: "CI / Build Systems".to_string(),
            query: format!(
                "site:{} (inurl:jenkins | inurl:/job/ | inurl:/computer/ | inurl:script | inurl:manage | intitle:\"Dashboard [Jenkins]\" | intitle:\"Manage Jenkins\")",
                clean_domain
            ),
            description: "Find exposed Jenkins dashboards".to_string(),
            impact: "Jenkins with anonymous access exposes build logs, credentials, and often a Script Console (RCE)".to_string(),
        });

        // GitLab / Gitea self-hosted
        dorks.push(GoogleDork {
            category: "CI / Build Systems".to_string(),
            query: format!(
                "site:{} (intitle:\"Sign in \\u00b7 GitLab\" | intitle:\"GitLab\" inurl:/users/sign_in | intitle:\"Gitea\" inurl:explore)",
                clean_domain
            ),
            description: "Find self-hosted GitLab/Gitea instances".to_string(),
            impact: "Self-hosted git servers often expose registration, weak passwords, and public projects with secrets".to_string(),
        });

        // Kibana / Elasticsearch / Grafana panels
        dorks.push(GoogleDork {
            category: "Observability Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | intitle:\"Grafana\" | inurl:/app/kibana | inurl:/goto/ inurl:kibana | inurl:/d/ | inurl:/dashboards/f/)",
                clean_domain
            ),
            description: "Find exposed Kibana / Grafana dashboards".to_string(),
            impact: "Kibana/Grafana with anonymous view exposes production log data, metrics, and PII".to_string(),
        });

        // Prometheus / Alertmanager
        dorks.push(GoogleDork {
            category: "Observability Panels".to_string(),
            query: format!(
                "site:{} (inurl:/metrics intext:\"# HELP\" | inurl:/prometheus | inurl:/alertmanager | inurl:/graph intitle:\"Prometheus\")",
                clean_domain
            ),
            description: "Find exposed Prometheus / Alertmanager".to_string(),
            impact: "/metrics leaks internal endpoints and load; open Alertmanager can be silenced by attackers".to_string(),
        });

        // phpMyAdmin / Adminer
        dorks.push(GoogleDork {
            category: "Database Panels".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin/index.php | intitle:\"phpMyAdmin\" inurl:index.php | inurl:/adminer.php | intitle:\"Adminer\")",
                clean_domain
            ),
            description: "Find exposed phpMyAdmin / Adminer".to_string(),
            impact: "Web-facing DB admin panels are direct paths to database compromise via weak/default creds".to_string(),
        });

        // Actuator / debug endpoints
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/health | inurl:/env)",
                clean_domain
            ),
            description: "Find Spring Boot Actuator or generic /env endpoints".to_string(),
            impact: "/actuator/env leaks properties and secrets; heapdump enables full memory extraction".to_string(),
        });

        // phpinfo() dumps
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | inurl:test.php intext:\"PHP Version\" | intitle:\"phpinfo()\")",
                clean_domain
            ),
            description: "Find phpinfo() dumps".to_string(),
            impact: "phpinfo reveals full server configuration, env vars, loaded modules, and file paths".to_string(),
        });

        // Laravel / Symfony debug pages
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Whoops! There was an error\" | intext:\"Illuminate\\\\\" intext:\"Stack trace\" | intitle:\"Symfony Exception\" | intext:\"_profiler\")",
                clean_domain
            ),
            description: "Find Laravel Whoops! / Symfony profiler surfaces".to_string(),
            impact: "Debug pages leak source paths, env, DB config, and stack traces with parameter values".to_string(),
        });

        // Django DEBUG=True
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"DisallowedHost\" | intext:\"You're seeing this error because you have DEBUG = True\" | intext:\"Traceback (most recent call last):\" inurl:django)",
                clean_domain
            ),
            description: "Find Django running with DEBUG=True".to_string(),
            impact: "Django DEBUG pages disclose settings, SECRET_KEY-adjacent env, DB config, and full tracebacks".to_string(),
        });

        // Backup / archive files
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp | ext:swo | ext:tmp | ext:tar.gz | ext:tgz | ext:zip | ext:7z | ext:rar) (inurl:backup | inurl:old | inurl:archive | intitle:\"index of\")",
                clean_domain
            ),
            description: "Find backup / archive leftovers".to_string(),
            impact: "Backup files frequently contain full source, .env, and DB dumps left after migrations".to_string(),
        });

        // Version control exposure
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.git/index | inurl:.svn/entries | inurl:.svn/wc.db | inurl:.hg/hgrc | inurl:.bzr/checkout)",
                clean_domain
            ),
            description: "Find exposed .git / .svn / .hg metadata".to_string(),
            impact: "Exposed VCS metadata enables full source tree reconstruction (git-dumper) and history recovery".to_string(),
        });

        // .DS_Store / .idea / .vscode leftovers
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.DS_Store | inurl:.idea/workspace.xml | inurl:.idea/dataSources.xml | inurl:.vscode/sftp.json | inurl:.vscode/settings.json)",
                clean_domain
            ),
            description: "Find IDE / OS metadata leftovers".to_string(),
            impact: ".DS_Store reveals filenames; JetBrains dataSources.xml exposes DB connection strings; SFTP configs leak deploy creds".to_string(),
        });

        // Log files
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log intext:\"password\" | ext:log intext:\"Authorization\" | ext:log intext:\"stacktrace\" | inurl:laravel.log | inurl:storage/logs/ | inurl:var/log/)",
                clean_domain
            ),
            description: "Find application log files".to_string(),
            impact: "Application logs frequently contain Authorization headers, cleartext PII, and stack traces".to_string(),
        });

        // Slack / Discord / Teams webhook URLs
        dorks.push(GoogleDork {
            category: "Chat Webhooks".to_string(),
            query: format!(
                "site:{} (\"hooks.slack.com/services/\" | \"discord.com/api/webhooks/\" | \"outlook.office.com/webhook/\")",
                clean_domain
            ),
            description: "Find leaked Slack / Discord / Teams webhook URLs".to_string(),
            impact: "Webhook URLs allow anyone to post as your integration, seed phishing, or trigger alerts".to_string(),
        });

        // JWT tokens in URLs/pages
        dorks.push(GoogleDork {
            category: "Tokens in Pages".to_string(),
            query: format!(
                "site:{} (intext:\"eyJhbGciOi\" | intext:\"Bearer eyJ\" | inurl:access_token=eyJ | inurl:id_token=eyJ)",
                clean_domain
            ),
            description: "Find JWTs indexed in URLs or page text".to_string(),
            impact: "JWTs in URLs are logged to referrers/proxies and enable session hijack until expiry".to_string(),
        });

        // Vendor-prefixed API keys
        dorks.push(GoogleDork {
            category: "Tokens in Pages".to_string(),
            query: format!(
                "site:{} (\"AIza\" | \"AKIA\" | \"ASIA\" | \"ghp_\" | \"gho_\" | \"ghu_\" | \"ghs_\" | \"github_pat_\" | \"glpat-\" | \"xoxb-\" | \"xoxp-\" | \"xoxa-\" | \"sk_live_\" | \"rk_live_\" | \"SG.\" | \"sk-ant-\" | \"sk-proj-\" | \"npm_\" | \"pypi-\")",
                clean_domain
            ),
            description: "Find indexed vendor-prefixed API keys".to_string(),
            impact: "Vendor-prefixed tokens are always active credentials — validate quickly and revoke on match".to_string(),
        });

        // ELMAH / trace.axd (ASP.NET)
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:elmah.axd | inurl:trace.axd | inurl:elmah/detail)",
                clean_domain
            ),
            description: "Find ASP.NET ELMAH and trace.axd endpoints".to_string(),
            impact: "elmah.axd exposes full request/error history including cookies, sessions, and stack traces".to_string(),
        });

        // WEB-INF / META-INF (Java)
        dorks.push(GoogleDork {
            category: "Web App Metadata".to_string(),
            query: format!(
                "site:{} (inurl:WEB-INF/web.xml | inurl:WEB-INF/classes | inurl:META-INF/MANIFEST.MF | inurl:META-INF/context.xml)",
                clean_domain
            ),
            description: "Find exposed WEB-INF / META-INF resources".to_string(),
            impact: "web.xml/context.xml leak servlet mappings, DB credentials, and internal endpoints".to_string(),
        });

        // Coldfusion / Tomcat manager
        dorks.push(GoogleDork {
            category: "Application Servers".to_string(),
            query: format!(
                "site:{} (inurl:/manager/html intitle:\"Tomcat\" | inurl:/host-manager/html | inurl:/CFIDE/administrator | inurl:/CFIDE/adminapi | intitle:\"JBoss Management Console\")",
                clean_domain
            ),
            description: "Find exposed Tomcat Manager, ColdFusion admin, JBoss console".to_string(),
            impact: "App-server management consoles allow WAR/EAR deploy — direct path to RCE".to_string(),
        });

        // Kubernetes Dashboard / Rancher
        dorks.push(GoogleDork {
            category: "Kubernetes / Container".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/#!/login intext:Kubeconfig | inurl:/dashboard/#/login intext:Kubernetes | intitle:\"Rancher\" inurl:/dashboard | inurl:/v3/settings)",
                clean_domain
            ),
            description: "Find exposed Kubernetes Dashboard / Rancher".to_string(),
            impact: "K8s Dashboard/Rancher exposure with skip-auth or weak creds grants full cluster control".to_string(),
        });

        // Sentry / issue trackers with exposed events
        dorks.push(GoogleDork {
            category: "Observability Panels".to_string(),
            query: format!(
                "site:{} (inurl:/organizations/ inurl:/issues/ intext:\"Sentry\" | inurl:/events/ intext:\"Sentry\" | inurl:.ingest.sentry.io)",
                clean_domain
            ),
            description: "Find Sentry issues/events indexed publicly or DSN leaks".to_string(),
            impact: "Public Sentry issues leak stack traces, PII from crash context; leaked DSN enables event forgery".to_string(),
        });

        // GraphQL introspection surface
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql intitle:\"GraphiQL\" | inurl:/graphiql | inurl:/playground | inurl:/altair | inurl:__graphql)",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds / IDEs".to_string(),
            impact: "Enabled GraphQL IDEs in production imply introspection is on — full schema disclosure".to_string(),
        });

        // Directory listings (generic high-value)
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (parent directory | \"Last modified\") (backup | dump | config | conf | private | secret | keys | ssh | vpn | admin | logs)",
                clean_domain
            ),
            description: "Find open directory listings on sensitive folders".to_string(),
            impact: "Enumerable listings on sensitive folders instantly reveal filenames of secrets, dumps, and keys".to_string(),
        });

        // Firebase realtime dumps
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" (users | auth | secret | admin | config | payment)",
                clean_domain
            ),
            description: "Find Firebase RTDB references correlated to sensitive collections".to_string(),
            impact: "Publicly-readable Firebase RTDB nodes with sensitive names typically expose full JSON on GET".to_string(),
        });

        // Postman / Insomnia public collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:elements.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find Postman published API collections mentioning the domain".to_string(),
            impact: "Public Postman collections leak internal endpoints, headers, and often long-lived API tokens in examples".to_string(),
        });

        // Confluence / SharePoint indexed sensitive terms
        dorks.push(GoogleDork {
            category: "Wiki / Collaboration".to_string(),
            query: format!(
                "site:{} (inurl:/wiki/spaces | inurl:/display/ inurl:/pages/ | inurl:atlassian) (password | secret | credentials | \"internal only\" | confidential)",
                clean_domain
            ),
            description: "Find Confluence/Atlassian pages with sensitive keywords".to_string(),
            impact: "Anonymous-readable Confluence pages routinely leak SOPs, credentials, and internal runbooks".to_string(),
        });

        // Public S3 index pages
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (\"s3.amazonaws.com\" | \"s3-website\") (intitle:\"index of\" | \"ListBucketResult\")",
                clean_domain
            ),
            description: "Find publicly listable S3 buckets referencing the domain".to_string(),
            impact: "Listable S3 buckets enumerate every key — inventory of every leaked asset".to_string(),
        });

        // Server-Sent Events / webhook receivers
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/webhook | inurl:/hooks | inurl:/callback | inurl:/incoming) inurl:token= | inurl:secret= | inurl:signature=",
                clean_domain
            ),
            description: "Find webhook receivers with tokens/signatures in the URL".to_string(),
            impact: "Webhook URLs with embedded tokens are logged to referrers/proxies and enable replay".to_string(),
        });

        // Robots / sitemap leaking sensitive paths
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:robots.txt Disallow: /admin | inurl:robots.txt Disallow: /api | inurl:robots.txt Disallow: /backup | inurl:sitemap.xml)",
                clean_domain
            ),
            description: "Find robots.txt / sitemap advertising sensitive paths".to_string(),
            impact: "Disallow: entries and sitemap URLs are direct disclosure of paths the operator wanted hidden".to_string(),
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
