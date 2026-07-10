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

        // ================================================================
        // Backup Files — high-yield, low-noise
        // ================================================================

        // Database dumps (SQL, PostgreSQL, MongoDB export)
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} ext:sql | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb | ext:bak | ext:dump intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\"",
                clean_domain
            ),
            description: "Find exposed database dump files".to_string(),
            impact: "Database dumps expose entire tables, including credentials and PII".to_string(),
        });

        // Compressed backups on webroot
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z | ext:bz2 | ext:war | ext:jar inurl:backup | inurl:bak | inurl:old | inurl:dump | inurl:archive",
                clean_domain
            ),
            description: "Find compressed backup archives on the web root".to_string(),
            impact: "Backup archives often contain full source code, database dumps, and .env files".to_string(),
        });

        // Editor swap and temporary files
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} inurl:.swp | inurl:.swo | inurl:.orig | inurl:.tmp | inurl:.save | inurl:.bak | inurl:~ | inurl:.old | inurl:.copy",
                clean_domain
            ),
            description: "Find editor swap files and stray backups".to_string(),
            impact: "Swap files often contain full source of the edited script including secrets".to_string(),
        });

        // ================================================================
        // Version Control Exposure — direct source-code disclosure
        // ================================================================

        dorks.push(GoogleDork {
            category: "Version Control".to_string(),
            query: format!(
                "site:{} inurl:\".git/\" | inurl:\".git/HEAD\" | inurl:\".git/config\" | inurl:\".git/logs\" | inurl:\".gitignore\" -github.com -gitlab.com",
                clean_domain
            ),
            description: "Find exposed .git directories".to_string(),
            impact: "Exposed .git allows full source-code and history extraction via git-dumper".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Version Control".to_string(),
            query: format!(
                "site:{} inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/\" | inurl:\".bzr/\" | inurl:\"CVS/Root\" | inurl:\"CVS/Entries\"",
                clean_domain
            ),
            description: "Find SVN, Mercurial, Bazaar, or CVS metadata".to_string(),
            impact: "VCS metadata leaks structure, commit history, and often credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Version Control".to_string(),
            query: format!(
                "site:{} inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\"desktop.ini\"",
                clean_domain
            ),
            description: "Find OS-generated directory metadata files".to_string(),
            impact: ".DS_Store enumerates hidden files/paths that are otherwise unlinked".to_string(),
        });

        // ================================================================
        // Environment / Config Files
        // ================================================================

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.dev\" | inurl:\".env.backup\" intext:\"DB_PASSWORD\" | intext:\"APP_KEY\" | intext:\"SECRET\" | intext:\"AWS_\"",
                clean_domain
            ),
            description: "Find .env files with credential markers".to_string(),
            impact: "Env files typically hold DB passwords, cloud keys, and app secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} ext:yml | ext:yaml | ext:toml | ext:properties inurl:config | inurl:secret | inurl:credential intext:\"password:\" | intext:\"secret:\" | intext:\"apikey\" | intext:\"api_key\"",
                clean_domain
            ),
            description: "Find YAML/TOML/properties configuration files with credentials".to_string(),
            impact: "Framework config files commonly contain database and third-party credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.old\" | inurl:\"wp-config.txt\" | inurl:\"wp-config.php.save\" | inurl:\"wp-config.php.swp\"",
                clean_domain
            ),
            description: "Find WordPress wp-config.php backup copies".to_string(),
            impact: "wp-config backups leak DB credentials and WordPress secret keys".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} inurl:\"application.properties\" | inurl:\"application.yml\" | inurl:\"application.yaml\" | inurl:\"application-prod.yml\" | inurl:\"bootstrap.yml\"",
                clean_domain
            ),
            description: "Find Spring Boot application properties".to_string(),
            impact: "application.properties often carries spring.datasource.password and JWT secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} inurl:\"web.config\" | inurl:\"Web.config.bak\" | inurl:\"appsettings.json\" | inurl:\"appsettings.Production.json\" | inurl:\"connectionStrings.config\"",
                clean_domain
            ),
            description: "Find ASP.NET/IIS configuration files".to_string(),
            impact: "web.config and appsettings.json hold DB connection strings and machineKey".to_string(),
        });

        // ================================================================
        // Log Files — leaked internal state
        // ================================================================

        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} ext:log intext:\"password\" | intext:\"passwd\" | intext:\"secret\" | intext:\"token\" | intext:\"authorization: bearer\" | intext:\"session_id\"",
                clean_domain
            ),
            description: "Find log files containing credentials or session data".to_string(),
            impact: "Logs commonly contain leaked passwords, tokens, and PII in request bodies".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} inurl:\"error_log\" | inurl:\"access_log\" | inurl:\"debug.log\" | inurl:\"laravel.log\" | inurl:\"npm-debug.log\" | inurl:\"yarn-error.log\" | inurl:\"php_errors.log\"",
                clean_domain
            ),
            description: "Find framework and server log files".to_string(),
            impact: "Application logs reveal stack traces, request bodies, and internal paths".to_string(),
        });

        // ================================================================
        // CI/CD, Build & Deploy Configs
        // ================================================================

        dorks.push(GoogleDork {
            category: "CI/CD Config".to_string(),
            query: format!(
                "site:{} inurl:\".gitlab-ci.yml\" | inurl:\".github/workflows/\" | inurl:\".circleci/config.yml\" | inurl:\"Jenkinsfile\" | inurl:\".drone.yml\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"azure-pipelines.yml\"",
                clean_domain
            ),
            description: "Find CI/CD pipeline definitions on the web root".to_string(),
            impact: "Pipeline files reveal secrets names, deploy targets, and internal infrastructure".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CI/CD Config".to_string(),
            query: format!(
                "site:{} inurl:\"Dockerfile\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.override.yml\" | inurl:\".dockercfg\" | inurl:\"config.json\" intext:\"auths\"",
                clean_domain
            ),
            description: "Find Dockerfiles and compose files served over HTTP".to_string(),
            impact: "Compose files carry environment variables including secrets and image registries".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CI/CD Config".to_string(),
            query: format!(
                "site:{} inurl:\"terraform.tfstate\" | inurl:\".terraform/\" | inurl:\"ansible.cfg\" | inurl:\"hosts.ini\" | inurl:\"vault-password\" | inurl:\"vault_pass\"",
                clean_domain
            ),
            description: "Find IaC state and configuration files".to_string(),
            impact: "Terraform state stores AWS/GCP keys and RDS passwords in plaintext".to_string(),
        });

        // ================================================================
        // Exposed Admin Panels & Database UIs
        // ================================================================

        dorks.push(GoogleDork {
            category: "Database Interfaces".to_string(),
            query: format!(
                "site:{} inurl:\"phpmyadmin\" | inurl:\"pma\" | inurl:\"adminer.php\" | inurl:\"phppgadmin\" | inurl:\"sqlbuddy\" | inurl:\"myadmin\" intitle:\"phpMyAdmin\" | intitle:\"Adminer\"",
                clean_domain
            ),
            description: "Find exposed database administration interfaces".to_string(),
            impact: "phpMyAdmin/Adminer exposure often leads to full DB takeover via weak creds".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Interfaces".to_string(),
            query: format!(
                "site:{} intitle:\"Kibana\" | intitle:\"Elasticsearch\" | inurl:\"/_cat/indices\" | inurl:\"/_cluster/health\" | inurl:\"/app/kibana\"",
                clean_domain
            ),
            description: "Find exposed Elasticsearch and Kibana instances".to_string(),
            impact: "Open Elasticsearch/Kibana typically exposes indexed logs and PII".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Interfaces".to_string(),
            query: format!(
                "site:{} intitle:\"MongoDB Ops Manager\" | intitle:\"couchdb\" | inurl:\"/_utils/\" | inurl:\"/rest/mongo\" | inurl:\"neo4j/browser\"",
                clean_domain
            ),
            description: "Find NoSQL admin interfaces".to_string(),
            impact: "Exposed NoSQL admin UIs allow full data access without authentication".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Interfaces".to_string(),
            query: format!(
                "site:{} intitle:\"Redis Commander\" | intitle:\"RedisInsight\" | inurl:\"/redis-commander\"",
                clean_domain
            ),
            description: "Find Redis admin interfaces".to_string(),
            impact: "Redis Commander exposes cached sessions, secrets, and queue payloads".to_string(),
        });

        // ================================================================
        // Observability / Monitoring — session token & PII leak surfaces
        // ================================================================

        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Grafana\" | inurl:\"/grafana/login\" | inurl:\"/d/\" intext:\"grafana\"",
                clean_domain
            ),
            description: "Find Grafana dashboards".to_string(),
            impact: "Public Grafana dashboards leak internal metrics, hostnames, and sometimes tokens".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Prometheus\" inurl:\"/graph\" | inurl:\"/targets\" | inurl:\"/metrics\" | inurl:\"/api/v1/query\"",
                clean_domain
            ),
            description: "Find Prometheus servers and metric endpoints".to_string(),
            impact: "Prometheus /metrics endpoints leak internal service topology and tokens".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Jaeger UI\" | intitle:\"Zipkin\" | intitle:\"SigNoz\" | inurl:\"/jaeger\" | inurl:\"/zipkin\"",
                clean_domain
            ),
            description: "Find distributed tracing UIs".to_string(),
            impact: "Tracing UIs commonly expose full request bodies including auth headers".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"phpinfo()\" | intext:\"PHP Version\" intext:\"Loaded Configuration File\" ext:php",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo leaks server environment, filesystem layout, module versions, and $_SERVER data".to_string(),
        });

        // ================================================================
        // Secrets Management & Internal Tools
        // ================================================================

        dorks.push(GoogleDork {
            category: "Secrets Management".to_string(),
            query: format!(
                "site:{} intitle:\"Vault UI\" | inurl:\"/ui/vault\" | inurl:\"/v1/sys/health\" | inurl:\"/v1/auth/token\"",
                clean_domain
            ),
            description: "Find HashiCorp Vault instances".to_string(),
            impact: "Reachable Vault control planes are high-value targets for lateral movement".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets Management".to_string(),
            query: format!(
                "site:{} intitle:\"Consul by HashiCorp\" | inurl:\"/v1/kv/\" | inurl:\"/ui/dc1/\" | inurl:\"/consul/api\"",
                clean_domain
            ),
            description: "Find HashiCorp Consul UIs and KV stores".to_string(),
            impact: "Consul KV frequently stores service credentials in plaintext".to_string(),
        });

        // ================================================================
        // Container & Orchestration
        // ================================================================

        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "site:{} inurl:\"/v2/_catalog\" | inurl:\"/v2/\" intext:\"repositories\" | inurl:\"/api/v2.0/projects\" intitle:\"Harbor\"",
                clean_domain
            ),
            description: "Find open Docker registries and Harbor projects".to_string(),
            impact: "Open registries let attackers pull private images and read layer metadata".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "site:{} intitle:\"Kubernetes Dashboard\" | inurl:\"/api/v1/namespaces\" | inurl:\"/api/v1/pods\" | inurl:\"/#/workloads\"",
                clean_domain
            ),
            description: "Find exposed Kubernetes dashboards and API surfaces".to_string(),
            impact: "Reachable K8s API and dashboards can lead to cluster takeover".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "site:{} intitle:\"Portainer\" | inurl:\"/#!/portainer\" | inurl:\"/api/endpoints\" intitle:\"Rancher\"",
                clean_domain
            ),
            description: "Find Portainer and Rancher management UIs".to_string(),
            impact: "Container management UIs allow arbitrary code execution on all managed nodes".to_string(),
        });

        // ================================================================
        // Documentation, Wikis & Collaboration
        // ================================================================

        dorks.push(GoogleDork {
            category: "Collaboration".to_string(),
            query: format!(
                "site:atlassian.net \"{}\" | site:*.atlassian.net \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find public Confluence/Jira pages referencing the target".to_string(),
            impact: "Public Confluence pages routinely leak runbooks, credentials, and architecture details".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Collaboration".to_string(),
            query: format!(
                "site:notion.so \"{}\" | site:notion.site \"{}\" | site:airtable.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Notion and Airtable pages".to_string(),
            impact: "Public Notion pages often contain onboarding docs with test credentials and API keys".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Collaboration".to_string(),
            query: format!(
                "site:miro.com \"{}\" | site:figma.com \"{}\" | site:lucidchart.com \"{}\" | site:draw.io \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find public whiteboards and diagrams".to_string(),
            impact: "Architecture diagrams and whiteboards expose internal topology and service names".to_string(),
        });

        // ================================================================
        // Additional Cloud Storage Providers
        // ================================================================

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\" | site:storage.cloud.google.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Google Cloud Storage buckets".to_string(),
            impact: "Public GCS objects often include user uploads, backups, and CI artifacts".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:*.r2.cloudflarestorage.com \"{}\" | site:r2.dev \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Cloudflare R2 buckets".to_string(),
            impact: "Misconfigured R2 buckets expose user assets and backups".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.wasabisys.com \"{}\" | site:*.wasabisys.com \"{}\" | site:*.backblazeb2.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Wasabi and Backblaze B2 buckets".to_string(),
            impact: "Alternative S3-compatible providers hosting production backups".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:*.oss-cn-hangzhou.aliyuncs.com \"{}\" | site:*.aliyuncs.com \"{}\" | site:*.hicloud.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Alibaba Cloud OSS and Huawei OBS buckets".to_string(),
            impact: "APAC cloud storage misconfigurations are frequently overlooked".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:*.file.core.windows.net \"{}\" | site:*.dfs.core.windows.net \"{}\" | site:*.table.core.windows.net \"{}\" | site:*.queue.core.windows.net \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find Azure File, Data Lake, Table, and Queue storage".to_string(),
            impact: "Azure Files and ADLS Gen2 often carry the same misconfigurations as Blob".to_string(),
        });

        // ================================================================
        // Static Site & Serverless Hosting (leaked internal deploys)
        // ================================================================

        dorks.push(GoogleDork {
            category: "Static Hosting".to_string(),
            query: format!(
                "site:*.netlify.app \"{}\" | site:*.vercel.app \"{}\" | site:*.pages.dev \"{}\" | site:*.github.io \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find preview/staging deploys on static hosting platforms".to_string(),
            impact: "Preview URLs frequently expose staging envs with production credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Static Hosting".to_string(),
            query: format!(
                "site:*.web.app \"{}\" | site:*.firebaseapp.com \"{}\" | site:*.surge.sh \"{}\" | site:*.onrender.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find Firebase Hosting, Surge, and Render deployments".to_string(),
            impact: "Additional serverless hosting platforms with staging assets".to_string(),
        });

        // ================================================================
        // API / Testing Tool Public Assets
        // ================================================================

        dorks.push(GoogleDork {
            category: "API Tooling".to_string(),
            query: format!(
                "site:documenter.getpostman.com \"{}\" | site:postman.com \"{}\" intext:\"workspace\"",
                clean_domain, clean_domain
            ),
            description: "Find public Postman collections and workspaces".to_string(),
            impact: "Public Postman collections often contain live API keys and internal endpoints".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Tooling".to_string(),
            query: format!(
                "site:{} inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/playground\" | inurl:\"/altair\" intitle:\"GraphQL\" | intitle:\"GraphiQL\" | intitle:\"Playground\"",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds".to_string(),
            impact: "GraphQL playgrounds with introspection enabled fully expose the schema".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Tooling".to_string(),
            query: format!(
                "site:{} inurl:\"swagger.json\" | inurl:\"swagger.yaml\" | inurl:\"openapi.json\" | inurl:\"openapi.yaml\" | inurl:\"api-docs.json\" | inurl:\"v3/api-docs\"",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger specifications".to_string(),
            impact: "Full spec files enumerate every internal endpoint and its parameters".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Tooling".to_string(),
            query: format!(
                "site:*.stoplight.io \"{}\" | site:*.readme.io \"{}\" | site:swaggerhub.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find hosted API documentation portals".to_string(),
            impact: "Hosted API portals commonly leak beta endpoints and undocumented auth methods".to_string(),
        });

        // ================================================================
        // Framework-Specific Debug / Panel Signatures
        // ================================================================

        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} intext:\"Whoops! There was an error.\" | intext:\"Ignition — Laravel debugger\" | intext:\"Symfony Profiler\" intitle:\"debug\"",
                clean_domain
            ),
            description: "Find Laravel/Symfony debug pages".to_string(),
            impact: "Ignition and Symfony Profiler leak env vars, DB queries, and enable RCE in some versions".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} intext:\"Werkzeug\" intext:\"Traceback\" | intitle:\"Django DEBUG=True\" | intext:\"You're seeing this error because you have DEBUG = True\"",
                clean_domain
            ),
            description: "Find Python framework debug consoles".to_string(),
            impact: "Werkzeug/Django debug consoles allow arbitrary code execution".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} intext:\"Rails.application.config\" intext:\"exception\" | intext:\"NoMethodError in\" | intext:\"ActionController::RoutingError\"",
                clean_domain
            ),
            description: "Find Rails development-mode error pages".to_string(),
            impact: "Rails dev errors expose source snippets, gems, and request environment".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\"",
                clean_domain
            ),
            description: "Find Spring Boot Actuator endpoints".to_string(),
            impact: "/actuator/env leaks all config; /heapdump downloads live memory including secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} inurl:\"/server-status\" | inurl:\"/server-info\" | intitle:\"Apache Status\"",
                clean_domain
            ),
            description: "Find Apache mod_status/mod_info exposure".to_string(),
            impact: "/server-status shows live request URIs and clients — a real-time session sniffer".to_string(),
        });

        // ================================================================
        // Directory Listings — passive enumeration
        // ================================================================

        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" intext:\"Parent Directory\" -html",
                clean_domain
            ),
            description: "Find Apache/nginx open directory indexes".to_string(),
            impact: "Directory indexes reveal every static file including backups and configs".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /admin\" | intitle:\"Index of /backup\" | intitle:\"Index of /uploads\" | intitle:\"Index of /db\" | intitle:\"Index of /config\"",
                clean_domain
            ),
            description: "Find directory indexes in juicy paths".to_string(),
            impact: "Indexes of sensitive directories directly enumerate high-value files".to_string(),
        });

        // ================================================================
        // Package Manager & Dependency Metadata
        // ================================================================

        dorks.push(GoogleDork {
            category: "Package Metadata".to_string(),
            query: format!(
                "site:{} inurl:\"package.json\" | inurl:\"package-lock.json\" | inurl:\"yarn.lock\" | inurl:\"pnpm-lock.yaml\" | inurl:\".npmrc\" | inurl:\".yarnrc\"",
                clean_domain
            ),
            description: "Find npm/yarn/pnpm package manifests on the web root".to_string(),
            impact: "package.json and .npmrc frequently leak internal registry URLs and auth tokens".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Package Metadata".to_string(),
            query: format!(
                "site:{} inurl:\"composer.json\" | inurl:\"composer.lock\" | inurl:\".composer/auth.json\" | inurl:\"auth.json\"",
                clean_domain
            ),
            description: "Find PHP Composer manifests on the web root".to_string(),
            impact: "Composer auth.json contains credentials for private Packagist/Satis repositories".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Package Metadata".to_string(),
            query: format!(
                "site:{} inurl:\"Gemfile\" | inurl:\"Gemfile.lock\" | inurl:\"requirements.txt\" | inurl:\"Pipfile\" | inurl:\"Pipfile.lock\" | inurl:\"pyproject.toml\" | inurl:\"go.mod\" | inurl:\"go.sum\"",
                clean_domain
            ),
            description: "Find dependency manifests for Ruby, Python, and Go".to_string(),
            impact: "Manifests enumerate every dependency and version — an SCA cheat sheet for attackers".to_string(),
        });

        // ================================================================
        // Password / Credential Text Leaks
        // ================================================================

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\"",
                clean_domain
            ),
            description: "Find PEM-armored private keys served over HTTP".to_string(),
            impact: "Private keys grant SSH, TLS, or PGP identity impersonation".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} intext:\"aws_access_key_id\" | intext:\"aws_secret_access_key\" | intext:\"AWS_SESSION_TOKEN\" ext:txt | ext:log | ext:json | ext:yml | ext:yaml",
                clean_domain
            ),
            description: "Find AWS credential markers in text files".to_string(),
            impact: "Explicit aws_access_key_id lines almost always accompany a live secret".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} intext:\"htpasswd\" | intext:\"htaccess\" ext:txt | ext:log | intext:\"$apr1$\" | intext:\"$2y$\" | intext:\"$1$\"",
                clean_domain
            ),
            description: "Find htpasswd hashes leaked in text".to_string(),
            impact: "htpasswd hashes are typically bcrypt/APR1 and often crack quickly".to_string(),
        });

        // ================================================================
        // Additional Paste / Snippet / Code Sites
        // ================================================================

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" | site:bitbucket.org/snippets \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find code gists and snippets".to_string(),
            impact: "Employee gists frequently contain sample requests with real bearer tokens".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:paste.ee \"{}\" | site:hastebin.com \"{}\" | site:ghostbin.com \"{}\" | site:rentry.co \"{}\" | site:controlc.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find snippets on alternative paste services".to_string(),
            impact: "Non-Pastebin services get less scanning attention and often host older leaks".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:replit.com \"{}\" | site:glitch.com \"{}\" | site:stackblitz.com \"{}\" | site:runkit.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find live-coding sandboxes referencing the target".to_string(),
            impact: "Sandbox projects run production APIs with hard-coded credentials committed in-file".to_string(),
        });

        // ================================================================
        // Support & Ticketing (leaked customer PII / internal tickets)
        // ================================================================

        dorks.push(GoogleDork {
            category: "Support Portals".to_string(),
            query: format!(
                "site:*.zendesk.com \"{}\" | site:*.freshdesk.com \"{}\" | site:*.helpscoutdocs.com \"{}\" | site:*.gitter.im \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find public support portals and community chats".to_string(),
            impact: "Support forums may leak ticket contents, customer PII, and internal handling notes".to_string(),
        });

        // ================================================================
        // Miscellaneous High-Value Signatures
        // ================================================================

        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:\"sitemap.xml\" | inurl:\"sitemap_index.xml\" | inurl:\"robots.txt\" intext:\"Disallow: /admin\" | intext:\"Disallow: /api\" | intext:\"Disallow: /private\"",
                clean_domain
            ),
            description: "Find robots.txt/sitemaps disallowing sensitive paths".to_string(),
            impact: "Disallow entries advertise the exact paths worth attacking".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:\"crossdomain.xml\" | inurl:\"clientaccesspolicy.xml\"",
                clean_domain
            ),
            description: "Find Flash/Silverlight cross-domain policies".to_string(),
            impact: "Wildcard policies allow cross-origin requests that bypass SOP".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:\"phpunit.xml\" | inurl:\"karma.conf.js\" | inurl:\"jest.config.js\" | inurl:\"cypress.json\" | inurl:\"playwright.config\"",
                clean_domain
            ),
            description: "Find test framework configuration files".to_string(),
            impact: "Test configs often reveal internal test endpoints and fixture credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:\".vscode/sftp.json\" | inurl:\".vscode/settings.json\" | inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources.xml\"",
                clean_domain
            ),
            description: "Find IDE workspace and remote-editing configs".to_string(),
            impact: "sftp.json and dataSources.xml store production SFTP/DB passwords".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:\".well-known/openid-configuration\" | inurl:\".well-known/oauth-authorization-server\" | inurl:\".well-known/jwks.json\"",
                clean_domain
            ),
            description: "Find OIDC / OAuth discovery documents".to_string(),
            impact: "Discovery docs enumerate every auth endpoint, scope, and supported grant type".to_string(),
        });

        // Public bug-tracker mentions (broader than OpenBugBounty)
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "site:hackerone.com \"{}\" | site:bugcrowd.com \"{}\" | site:huntr.dev \"{}\" | site:intigriti.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find bug bounty program listings for the domain".to_string(),
            impact: "Confirms in-scope assets and reward tiers; disclosed reports may reveal live bugs".to_string(),
        });

        // Historical exposure via archive
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" inurl:api | inurl:admin | inurl:internal | inurl:key",
                clean_domain
            ),
            description: "Find archived snapshots of sensitive endpoints".to_string(),
            impact: "The Wayback Machine often preserves endpoints and files that have since been removed".to_string(),
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
        // Newly added high-signal categories
        assert!(results.by_category.contains_key("Backup Files"));
        assert!(results.by_category.contains_key("Version Control"));
        assert!(results.by_category.contains_key("Environment Files"));
        assert!(results.by_category.contains_key("CI/CD Config"));
        assert!(results.by_category.contains_key("Database Interfaces"));
        assert!(results.by_category.contains_key("Debug Interfaces"));
        assert!(results.by_category.contains_key("Directory Listing"));
        assert!(results.by_category.contains_key("Credential Leaks"));
    }

    #[test]
    fn test_new_dorks_reference_domain() {
        // Guard against a category-scoped regression where a new dork forgets
        // the site: filter and would search the whole web.
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        let referencing = results
            .dorks
            .iter()
            .filter(|d| d.query.contains("example.com"))
            .count();
        // Overwhelming majority of dorks must scope to the target domain.
        assert!(referencing * 10 > results.dorks.len() * 8);
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
