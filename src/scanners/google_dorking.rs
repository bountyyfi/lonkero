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

        // -------------------------------------------------------------------
        // High-signal sensitive-data dorks.
        //
        // Everything below targets a specific indexed artifact — a named file, a
        // provider-branded response fragment, or a login-page title — so a hit
        // requires the exact artifact to be indexed by Google against the target
        // domain. That is what keeps false positives near zero: we're not
        // searching for the word "password" on a marketing page.
        // -------------------------------------------------------------------

        // Exposed .env / dotenv leakage – matches the literal line prefixes emitted
        // by files-cache indexers when a .env is left web-accessible.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:env OR inurl:.env) (intext:DB_PASSWORD OR intext:AWS_ACCESS_KEY_ID OR intext:SECRET_KEY OR intext:APP_KEY OR intext:JWT_SECRET)",
                clean_domain
            ),
            description: "Find exposed .env files containing production credentials".to_string(),
            impact: "Exposed .env files leak database, AWS, JWT, and framework secrets — typically full compromise".to_string(),
        });

        // Backup files that Google fingerprints via directory-listing output —
        // requires an actual index page, so 0 FP on production sites.
        dorks.push(GoogleDork {
            category: "Exposed Backups".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (ext:bak OR ext:backup OR ext:old OR ext:sql OR ext:tar.gz OR ext:zip OR ext:tgz OR ext:dump)",
                clean_domain
            ),
            description: "Find open directory listings containing backup archives".to_string(),
            impact: "Backup archives frequently contain source, DB dumps, and secret material".to_string(),
        });

        // Database dumps – phpMyAdmin / mysqldump signature lines that only ever
        // appear inside real SQL exports.
        dorks.push(GoogleDork {
            category: "Exposed Backups".to_string(),
            query: format!(
                "site:{} (ext:sql OR ext:dump OR ext:sqlite) (intext:\"-- phpMyAdmin SQL Dump\" OR intext:\"-- Server version\" OR intext:\"CREATE TABLE\" OR intext:\"DROP TABLE IF EXISTS\")",
                clean_domain
            ),
            description: "Find indexed SQL / database dumps".to_string(),
            impact: "Database exports leak schema, rows, and often credentials in hashed form".to_string(),
        });

        // Version control artefacts — .git/config always contains the string
        // "[core]" followed by "repositoryformatversion", which is unique to git.
        dorks.push(GoogleDork {
            category: "Version Control".to_string(),
            query: format!(
                "site:{} (inurl:.git/config OR inurl:.svn/entries OR inurl:.hg/store) (intext:\"repositoryformatversion\" OR intext:\"dir-prop-base\")",
                clean_domain
            ),
            description: "Find exposed .git / .svn / .hg metadata".to_string(),
            impact: "Full source-tree reconstruction with git-dumper and equivalents".to_string(),
        });

        // Spring Boot Actuator exposure – env/heapdump/mappings endpoints render
        // provider-branded JSON that Google indexes verbatim.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env OR inurl:/actuator/heapdump OR inurl:/actuator/mappings OR inurl:/actuator/configprops OR inurl:/actuator/beans OR inurl:/env.json)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator sensitive endpoints".to_string(),
            impact: "Actuator env/heapdump exposes secrets, mapped routes, and dependency versions".to_string(),
        });

        // Kibana / Elasticsearch consoles – indexed when the app renders its
        // splash page publicly.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" OR intext:\"Elasticsearch cluster\" OR inurl:/_cat/indices OR inurl:/_cluster/health OR inurl:/_search)",
                clean_domain
            ),
            description: "Find exposed Kibana / Elasticsearch endpoints".to_string(),
            impact: "Cluster metadata, indices, and often full document read via `/_search`".to_string(),
        });

        // Prometheus / Grafana / Alertmanager exposed dashboards – the app title
        // is stable and specific.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series Collection and Processing Server\" OR intitle:\"Grafana\" OR intitle:\"Alertmanager\")",
                clean_domain
            ),
            description: "Find exposed observability dashboards".to_string(),
            impact: "Metrics leak infra shape and service names; Grafana anonymous mode exposes dashboards including internal charts".to_string(),
        });

        // Jenkins / TeamCity / Bamboo — build servers with distinctive titles.
        dorks.push(GoogleDork {
            category: "Exposed CI/CD".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" OR intitle:\"Projects | TeamCity\" OR intitle:\"Bamboo\" OR inurl:/manage/configureSecurity OR inurl:/script)",
                clean_domain
            ),
            description: "Find exposed Jenkins, TeamCity, or Bamboo build servers".to_string(),
            impact: "Script Console (Jenkins) = RCE as the build user; jobs/artifacts leak source and secrets".to_string(),
        });

        // Argo CD / Portainer / Rancher / Kubernetes dashboard — the ops
        // consoles that get accidentally proxied to the public internet.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Argo CD\" OR intitle:\"Portainer\" OR intitle:\"Rancher\" OR intitle:\"Kubernetes Dashboard\" OR inurl:/api/v1/namespaces)",
                clean_domain
            ),
            description: "Find exposed cluster / container management consoles".to_string(),
            impact: "Unauthenticated cluster access typically means full cluster takeover".to_string(),
        });

        // Vault UI — very stable title, deployment usually assumes internal-only.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Vault - HashiCorp\" OR inurl:/v1/sys/health OR inurl:/ui/vault)",
                clean_domain
            ),
            description: "Find exposed HashiCorp Vault UIs / health probes".to_string(),
            impact: "Reveals seal state and namespace layout; misconfigured auth grants secret access".to_string(),
        });

        // Airflow / Nifi / JupyterHub / Airbyte / Superset — data-platform
        // consoles that ship with weak defaults.
        dorks.push(GoogleDork {
            category: "Exposed Data Platforms".to_string(),
            query: format!(
                "site:{} (intitle:\"Airflow - DAGs\" OR intitle:\"NiFi Flow\" OR intitle:\"JupyterHub\" OR intitle:\"Airbyte\" OR intitle:\"Apache Superset\")",
                clean_domain
            ),
            description: "Find exposed data-platform consoles".to_string(),
            impact: "Airflow variables/connections and NiFi process groups routinely embed credentials; notebook RCE possible".to_string(),
        });

        // Adminer / phpMyAdmin — the login pages have very stable titles.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" \"Welcome to phpMyAdmin\" OR intitle:\"Login - Adminer\" OR inurl:/adminer.php OR inurl:/phpmyadmin/)",
                clean_domain
            ),
            description: "Find exposed database web UIs".to_string(),
            impact: "Direct login target for the database; brute-force + credential-reuse candidates".to_string(),
        });

        // WordPress debug.log — literal file emitted by WP_DEBUG_LOG=true.
        dorks.push(GoogleDork {
            category: "Exposed Logs".to_string(),
            query: format!(
                "site:{} (inurl:wp-content/debug.log OR inurl:error_log OR inurl:laravel.log OR inurl:app.log OR inurl:npm-debug.log)",
                clean_domain
            ),
            description: "Find exposed application debug logs".to_string(),
            impact: "Stack traces leak file paths, query strings, and sometimes credentials".to_string(),
        });

        // AWS credentials files – .aws/credentials is the canonical filename;
        // config values only ever appear inside it.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials OR inurl:credentials.csv) (intext:aws_access_key_id OR intext:aws_secret_access_key)",
                clean_domain
            ),
            description: "Find exposed AWS credentials files".to_string(),
            impact: "IAM key pair leak — attacker inherits the associated role".to_string(),
        });

        // GCP service-account JSON – `\"type\": \"service_account\"` is unique.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:json intext:\"\\\"type\\\": \\\"service_account\\\"\" intext:\"private_key\"",
                clean_domain
            ),
            description: "Find exposed GCP service-account key files".to_string(),
            impact: "Full impersonation of the service account, often with broad IAM roles".to_string(),
        });

        // SSH private keys — the PEM header is unique and never legitimately
        // appears on a public web page.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" OR intext:\"-----BEGIN RSA PRIVATE KEY-----\" OR intext:\"-----BEGIN EC PRIVATE KEY-----\" OR intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\") (ext:key OR ext:pem OR ext:txt)",
                clean_domain
            ),
            description: "Find exposed SSH / PEM / PGP private keys".to_string(),
            impact: "Direct shell or signing access depending on the key type".to_string(),
        });

        // WordPress wp-config.php exposures – the file rarely renders except
        // when the interpreter is broken, but when it does the DB creds leak.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php OR inurl:wp-config.php.bak OR inurl:wp-config.txt) (intext:DB_PASSWORD OR intext:AUTH_KEY)",
                clean_domain
            ),
            description: "Find leaked WordPress wp-config.php".to_string(),
            impact: "DB credentials + auth salts — full WordPress compromise".to_string(),
        });

        // Web.config / appsettings.json exposures — ASP.NET secret material.
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:web.config OR inurl:appsettings.json OR inurl:appsettings.Production.json) (intext:\"ConnectionStrings\" OR intext:\"machineKey\")",
                clean_domain
            ),
            description: "Find ASP.NET secrets in web.config / appsettings.json".to_string(),
            impact: "DB connection strings + machineKey enables ViewState-based RCE and DB access".to_string(),
        });

        // Public S3 listings — the XML `ListBucketResult` root element is a
        // sure sign the bucket allows anonymous LIST.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com intext:\"<ListBucketResult\" \"{}\"",
                clean_domain
            ),
            description: "Find publicly listable AWS S3 buckets".to_string(),
            impact: "Anonymous LIST means every object name — often downloadable — is enumerable".to_string(),
        });

        // OpenAPI / Swagger raw JSON – the top-level `\"swagger\":` /
        // `\"openapi\":` fields are stable across all specs.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} ext:json (intext:\"\\\"swagger\\\":\" OR intext:\"\\\"openapi\\\":\") intext:\"paths\"",
                clean_domain
            ),
            description: "Find raw OpenAPI / Swagger JSON specifications".to_string(),
            impact: "Maps every endpoint, parameter, and auth scheme — huge attack-surface uplift".to_string(),
        });

        // GraphQL introspection dumps — SDL always contains `type Query {`.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:graphql OR inurl:playground OR inurl:altair) (intext:\"type Query\" OR intext:\"__schema\")",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds / SDL dumps".to_string(),
            impact: "Full schema leak enables field-level enumeration and IDOR discovery".to_string(),
        });

        // Postman / Insomnia collection exports – top-level metadata fields are
        // unique to the exported format.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} ext:json (intext:\"\\\"_postman_id\\\":\" OR intext:\"\\\"info\\\": {{ \\\"schema\\\":\") intext:\"request\"",
                clean_domain
            ),
            description: "Find leaked Postman / Insomnia collection exports".to_string(),
            impact: "Collections frequently carry hard-coded bearer tokens, cookies, and internal hosts".to_string(),
        });

        // Trufflehog / gitleaks reports left in artifact directories – both tools
        // emit distinctive strings in their output.
        dorks.push(GoogleDork {
            category: "Security Reports".to_string(),
            query: format!(
                "site:{} (intext:\"gitleaks report\" OR intext:\"trufflehog\" OR intext:\"Semgrep results\" OR intext:\"nuclei-templates\")",
                clean_domain
            ),
            description: "Find leaked internal security-scan reports".to_string(),
            impact: "Report body typically lists exact secret values and vulnerable paths — often unpatched".to_string(),
        });

        // Sourcemap indexes — `.js.map` files are indexed alongside the source
        // bundles they belong to.
        dorks.push(GoogleDork {
            category: "Source Disclosure".to_string(),
            query: format!(
                "site:{} ext:map (intext:\"sourceRoot\" OR intext:\"sourcesContent\")",
                clean_domain
            ),
            description: "Find exposed JavaScript source maps".to_string(),
            impact: "Full de-minified frontend source, including embedded secrets and internal routing".to_string(),
        });

        // Docker Compose / Kubernetes manifests – top-level version + service
        // keys are unique to the format.
        dorks.push(GoogleDork {
            category: "Infrastructure Disclosure".to_string(),
            query: format!(
                "site:{} (ext:yml OR ext:yaml) (intext:\"apiVersion:\" OR intext:\"docker-compose\" OR intext:\"kind: Secret\" OR intext:\"kind: ConfigMap\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Compose manifests".to_string(),
            impact: "`kind: Secret` bodies contain base64-encoded live secrets; ConfigMaps leak service topology".to_string(),
        });

        // Terraform state files — `\"terraform_version\"` is a stable top-level
        // key that never appears outside a state file.
        dorks.push(GoogleDork {
            category: "Infrastructure Disclosure".to_string(),
            query: format!(
                "site:{} (ext:tfstate OR inurl:terraform.tfstate) intext:\"\\\"terraform_version\\\":\"",
                clean_domain
            ),
            description: "Find exposed Terraform state files".to_string(),
            impact: "State files carry the plaintext of every provider-managed secret — DB passwords, tokens, private keys".to_string(),
        });

        // Composer / npm lockfiles with private registry URLs — reveals
        // internal package servers.
        dorks.push(GoogleDork {
            category: "Infrastructure Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:package-lock.json OR inurl:composer.lock OR inurl:yarn.lock) (intext:\"artifactory\" OR intext:\"nexus\" OR intext:\"myget.org\")",
                clean_domain
            ),
            description: "Find lockfiles referencing internal package registries".to_string(),
            impact: "Reveals internal Artifactory/Nexus hosts — pivot targets for dependency confusion".to_string(),
        });

        // Search-history / paste-site cache of the domain's Slack messages —
        // groups.google archives are where old Slack invites and support
        // discussions leak.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:pastebin.com OR site:ghostbin.com OR site:paste.ee OR site:hastebin.com \"{}\" (intext:password OR intext:api_key OR intext:token)",
                clean_domain
            ),
            description: "Find leaked internal content on paste sites".to_string(),
            impact: "Leaked chat/config snippets frequently contain live credentials".to_string(),
        });

        // Bitbucket / GitLab / Gitea public repos referencing the domain – the
        // `site:` filter narrows to code-hosting hits.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:github.com OR site:gitlab.com OR site:bitbucket.org OR site:gitea.com OR site:codeberg.org) \"{}\" (intext:password OR intext:secret OR intext:api_key OR intext:BEGIN)",
                clean_domain
            ),
            description: "Find public repos referencing the domain that contain likely secrets".to_string(),
            impact: "Historical commits routinely leak credentials that are still live".to_string(),
        });

        // BuildKite / CircleCI / GitHub Actions logs that got indexed – the
        // action UI titles are stable.
        dorks.push(GoogleDork {
            category: "CI/CD Logs".to_string(),
            query: format!(
                "site:{} (intitle:\"Buildkite\" OR intitle:\"CircleCI\" OR inurl:/workflows/ OR inurl:/pipelines/)",
                clean_domain
            ),
            description: "Find exposed CI job / workflow pages".to_string(),
            impact: "Failed-job stacktraces frequently include tokens echoed to stderr".to_string(),
        });

        // FTP directory listings — VSFTPD/Pure-FTPd emit distinctive banners.
        dorks.push(GoogleDork {
            category: "Exposed File Servers".to_string(),
            query: format!(
                "site:{} (intitle:\"index of /\" OR intitle:\"FTP root at\" OR intext:\"To parent directory\") -html -htm",
                clean_domain
            ),
            description: "Find exposed FTP/directory listings".to_string(),
            impact: "Anonymous file listings enable enumeration of backups, uploads, logs".to_string(),
        });

        // Employee document leaks – `intext:\"internal use only\"` combined with
        // a large document extension surfaces confidential PDFs / decks.
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:{} (ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx) (intext:\"internal use only\" OR intext:\"confidential\" OR intext:\"do not distribute\" OR intext:\"restricted\") -template",
                clean_domain
            ),
            description: "Find indexed confidential documents".to_string(),
            impact: "Business-sensitive docs — customer lists, contracts, roadmaps".to_string(),
        });

        // Email / SMS leaks via publicly-indexed mailhog / mailtrap frontends.
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"MailHog\" OR intitle:\"Mailtrap\" OR intitle:\"Papercut\" OR inurl:/mailhog OR inurl:/inbox)",
                clean_domain
            ),
            description: "Find exposed developer mail catchers".to_string(),
            impact: "Full read of dev/staging password-reset flows — allows account takeover of real accounts if envs share DBs".to_string(),
        });

        // MinIO public console / anonymous buckets.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Console\" OR inurl:/minio/ OR inurl:/api/v1/buckets)",
                clean_domain
            ),
            description: "Find exposed MinIO consoles".to_string(),
            impact: "MinIO defaults commonly leave `minioadmin:minioadmin` credentials in place".to_string(),
        });

        // Firebase realtime DB open reads — `.json?shallow=true` returns actual
        // data on misconfigured databases.
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" (inurl:.json OR inurl:shallow=true)",
                clean_domain
            ),
            description: "Find Firebase Realtime DB paths exposed with .json read".to_string(),
            impact: "Anonymous JSON exports of the entire database on misconfigured Firebase rules".to_string(),
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
