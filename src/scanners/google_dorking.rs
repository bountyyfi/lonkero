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

        // ─── Additional high-impact sensitive-recon dorks ─────────────────
        // These dorks are intentionally narrow: each combines a well-known
        // filename / endpoint with a domain or content marker so a hit is
        // strongly indicative of a real exposure rather than an unrelated page.

        // Environment / dotfile leaks
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD\" | intext:\"AWS_SECRET\" | intext:\"SECRET_KEY\" | intext:\"DATABASE_URL\")",
                clean_domain
            ),
            description: ".env / dotenv leaks containing credentials".to_string(),
            impact: "Exposed .env files routinely contain DB passwords, AWS keys, JWT secrets — direct account compromise".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.dev\")",
                clean_domain
            ),
            description: "Common .env file locations".to_string(),
            impact: "Direct disclosure of application secrets and credentials".to_string(),
        });

        // Version control directories accidentally deployed
        dorks.push(GoogleDork {
            category: "Version Control Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/index\" | inurl:\".gitignore\")",
                clean_domain
            ),
            description: "Exposed .git directory artifacts".to_string(),
            impact: "Full source-tree reconstruction via git-dumper; reveals secrets across history".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Version Control Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\".bzr/\" | inurl:\"CVS/Root\")",
                clean_domain
            ),
            description: "Other VCS metadata leaks".to_string(),
            impact: "Source-tree reconstruction from SVN / Mercurial / Bazaar / CVS metadata".to_string(),
        });

        // Build / IaC / dependency manifests with secrets
        dorks.push(GoogleDork {
            category: "Build & IaC Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\"Dockerfile\" | inurl:\".dockercfg\" | inurl:\".docker/config.json\")",
                clean_domain
            ),
            description: "Docker / Compose configs publicly accessible".to_string(),
            impact: "Reveals services, network layout, registry credentials and embedded env vars".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Build & IaC Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"terraform.tfstate\" | inurl:\".terraform/\" | inurl:\"main.tf\" | inurl:\"variables.tf\")",
                clean_domain
            ),
            description: "Terraform state / configuration exposure".to_string(),
            impact: "tfstate files contain plaintext secrets (DB passwords, tokens, keys) and full infrastructure inventory".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Build & IaC Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"ansible.cfg\" | inurl:\"hosts.ini\" | inurl:\"vault.yml\" | inurl:\"group_vars\" | inurl:\"host_vars\")",
                clean_domain
            ),
            description: "Ansible inventory / vault files".to_string(),
            impact: "Inventory files reveal hostnames and credentials; vault.yml is encrypted but its existence proves the workflow".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Build & IaC Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\".kube/config\" | inurl:\"helm-values.yaml\")",
                clean_domain
            ),
            description: "Kubernetes / Helm configuration leaks".to_string(),
            impact: "kubeconfig grants direct cluster access; Helm values often hold registry creds and secrets".to_string(),
        });

        // CI/CD secrets in published configs
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" | inurl:\".gitlab-ci.yml\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"Jenkinsfile\" | inurl:\"azure-pipelines.yml\" | inurl:\".circleci/config.yml\" | inurl:\".travis.yml\")",
                clean_domain
            ),
            description: "CI/CD pipeline definitions".to_string(),
            impact: "Pipeline files reveal deploy targets, secret names, build matrices — secrets leak when echoed in inline scripts".to_string(),
        });

        // Database dumps & backups
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:db | ext:sqlite | ext:sqlite3 | ext:mdb | ext:bak | ext:backup) intext:\"INSERT INTO\"",
                clean_domain
            ),
            description: "SQL dumps and database backups".to_string(),
            impact: "Wholesale data disclosure including PII, password hashes, business records".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (intext:\"-- MySQL dump\" | intext:\"-- PostgreSQL database dump\" | intext:\"-- phpMyAdmin SQL Dump\")",
                clean_domain
            ),
            description: "Identifiable DB-dump banners".to_string(),
            impact: "Confirmed full or partial database export".to_string(),
        });

        // Log files with sensitive content
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} ext:log (intext:\"password\" | intext:\"passwd\" | intext:\"authorization: bearer\" | intext:\"secret\" | intext:\"apikey\")",
                clean_domain
            ),
            description: "Log files containing credential strings".to_string(),
            impact: "Logs frequently capture Authorization headers, query-string passwords and reset tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (inurl:\"error.log\" | inurl:\"debug.log\" | inurl:\"access.log\" | inurl:\"laravel.log\" | inurl:\"production.log\" | inurl:\"npm-debug.log\")",
                clean_domain
            ),
            description: "Common log filenames".to_string(),
            impact: "Stack traces and request logs reveal infrastructure detail and tokens".to_string(),
        });

        // Backup / archive artefacts
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:7z | ext:rar) (intext:\"backup\" | inurl:backup | inurl:bak)",
                clean_domain
            ),
            description: "Backup archives in web roots".to_string(),
            impact: "Archives commonly contain full source, configs and database dumps".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:old | ext:orig | ext:save | ext:swp | ext:swo | ext:tmp | ext:~)",
                clean_domain
            ),
            description: "Editor / backup file extensions".to_string(),
            impact: "Recovers prior versions of configuration or source files".to_string(),
        });

        // Configuration files specific to high-value services
        dorks.push(GoogleDork {
            category: "Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\"web.config\" | inurl:\"applicationhost.config\" | inurl:\"appsettings.json\" | inurl:\"appsettings.Production.json\" | inurl:\"connectionStrings.config\")",
                clean_domain
            ),
            description: "ASP.NET / IIS configuration".to_string(),
            impact: "Contains database connection strings, machine keys and identity provider secrets".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php\" | inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php.old\" | inurl:\"wp-config.txt\")",
                clean_domain
            ),
            description: "WordPress wp-config exposure".to_string(),
            impact: "Plaintext DB credentials, AUTH_KEY, SECURE_AUTH_KEY etc. — full WP compromise".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\"settings.py\" | inurl:\"local_settings.py\" | inurl:\"production.py\")",
                clean_domain
            ),
            description: "Django settings files".to_string(),
            impact: "Reveals SECRET_KEY, DB credentials, ALLOWED_HOSTS and SMTP creds".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\"config.yml\" | inurl:\"config.yaml\" | inurl:\"application.yml\" | inurl:\"application.properties\" | inurl:\"bootstrap.yml\")",
                clean_domain
            ),
            description: "Spring Boot / generic YAML configuration".to_string(),
            impact: "Database, OAuth, mail and management endpoints with embedded credentials".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\"phpinfo.php\" | intitle:\"phpinfo()\" | intext:\"PHP Version\" intext:\"Configuration File\")",
                clean_domain
            ),
            description: "phpinfo() pages".to_string(),
            impact: "Reveals modules, paths, environment variables and internal IPs — major recon win".to_string(),
        });

        // Spring Boot Actuator exposure (frequent prod misconfig)
        dorks.push(GoogleDork {
            category: "Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/loggers\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\")",
                clean_domain
            ),
            description: "Spring Boot Actuator endpoints".to_string(),
            impact: "/env discloses secrets; /heapdump returns memory image (passwords, tokens); /loggers and /jolokia enable RCE in some setups".to_string(),
        });

        // Cloud metadata / SSRF-marker pages (recon, not exploitation)
        dorks.push(GoogleDork {
            category: "Cloud Metadata".to_string(),
            query: format!(
                "site:{} (intext:\"ami-id\" intext:\"instance-id\" | intext:\"169.254.169.254\")",
                clean_domain
            ),
            description: "Mirrored cloud instance metadata".to_string(),
            impact: "Indicates SSRF chain leaking IMDS — IAM credential theft window".to_string(),
        });

        // Public S3 / blob index listings
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "intitle:\"Index of\" (\"{}\" | site:s3.amazonaws.com \"{}\")",
                clean_domain, clean_domain
            ),
            description: "Open S3 listings or bucket directory indexes".to_string(),
            impact: "Listable buckets allow enumeration of objects; misconfigurations often allow read of any object".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Google Cloud Storage public buckets".to_string(),
            impact: "Public GCS buckets often hold backups and exported data".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:wasabisys.com | site:linodeobjects.com | site:r2.dev | site:backblazeb2.com) \"{}\"",
                clean_domain
            ),
            description: "Alt-cloud object storage (Wasabi, Linode, R2, Backblaze)".to_string(),
            impact: "Mirrors of S3-style misconfigurations on alternative providers".to_string(),
        });

        // Exposed directory listings
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (intext:\"Last modified\" | intext:\"Parent Directory\")",
                clean_domain
            ),
            description: "Apache / Nginx auto-indexed directories".to_string(),
            impact: "Browseable directories often expose backups, source and internal files".to_string(),
        });

        // Private key / certificate leaks
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:p12 | ext:pfx | ext:jks | ext:keystore | ext:asc) (intext:\"BEGIN PRIVATE KEY\" | intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\")",
                clean_domain
            ),
            description: "Private keys / keystores".to_string(),
            impact: "Direct disclosure of TLS, SSH or signing keys — full impersonation".to_string(),
        });

        // Mail server / mbox leaks
        dorks.push(GoogleDork {
            category: "Communication Leaks".to_string(),
            query: format!(
                "site:{} (ext:eml | ext:mbox | ext:msg | inurl:\"mail/\" intext:\"From:\")",
                clean_domain
            ),
            description: "Exported email files".to_string(),
            impact: "Internal correspondence frequently contains credentials and PII".to_string(),
        });

        // Wikis / pastes / knowledge bases referencing the domain
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitlab.com/-/snippets | site:notion.site | site:hackmd.io | site:hastebin.com | site:rentry.co) \"{}\"",
                clean_domain
            ),
            description: "Snippets and shared notes mentioning the domain".to_string(),
            impact: "Public gists / pastes / Notion sites frequently leak internal credentials and runbooks".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:web.archive.org | site:archive.ph) \"{}\" (intext:\"password\" | intext:\"api_key\" | intext:\"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Archived snapshots holding now-removed secrets".to_string(),
            impact: "Wayback / archive.ph captures secrets that were later patched on the live site".to_string(),
        });

        // Vendor / SaaS misconfigurations (high-impact public exposures)
        dorks.push(GoogleDork {
            category: "SaaS Exposure".to_string(),
            query: format!(
                "site:atlassian.net (inurl:\"/jira/\" | inurl:\"/wiki/\") \"{}\"",
                clean_domain
            ),
            description: "Public Atlassian Cloud spaces / projects".to_string(),
            impact: "Anonymous access to Jira/Confluence often discloses tickets and pages".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Exposure".to_string(),
            query: format!(
                "site:lucid.app \"{}\" | site:miro.com \"{}\" | site:figma.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Whiteboard / design tools with sharable links".to_string(),
            impact: "Architecture diagrams and design exports often include credentials and internal URLs".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Exposure".to_string(),
            query: format!(
                "(site:postman.com | site:apidocs.io | site:apilist.fun) \"{}\"",
                clean_domain
            ),
            description: "Public Postman workspaces / API doc mirrors".to_string(),
            impact: "Public Postman collections frequently embed Authorization headers with live tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Exposure".to_string(),
            query: format!(
                "(site:repl.it | site:replit.com | site:codesandbox.io | site:stackblitz.com) \"{}\"",
                clean_domain
            ),
            description: "Online IDE projects mentioning the domain".to_string(),
            impact: "Sandboxes often forget to scrub real API keys before publishing".to_string(),
        });

        // Bug bounty / disclosure surfaces
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "(site:hackerone.com | site:bugcrowd.com | site:intigriti.com | site:yeswehack.com) \"{}\"",
                clean_domain
            ),
            description: "Disclosed bounty reports referencing the domain".to_string(),
            impact: "Resolved or duplicate reports may still describe still-present misconfigurations".to_string(),
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
