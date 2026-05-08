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

        // ──────────────────────────────────────────────────────────────────
        // High-impact additions — every query below is anchored to either
        // `site:<domain>` or a vendor-specific host so a hit corresponds to a
        // real exposure rather than an incidental keyword match.
        // ──────────────────────────────────────────────────────────────────

        // Version Control Exposure — finding any of these on a live host is a
        // critical source-leak: full repo history → recoverable secrets.
        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/config\" | inurl:\"/.git/HEAD\" | inurl:\"/.git/index\" | inurl:\"/.git/logs/HEAD\")",
                clean_domain
            ),
            description: "Exposed .git directory metadata".to_string(),
            impact: "Allows full repository reconstruction including secrets in git history".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.svn/entries\" | inurl:\"/.svn/wc.db\" | inurl:\"/.hg/store\" | inurl:\"/.bzr/\" | inurl:\"/CVS/Entries\")",
                clean_domain
            ),
            description: "Exposed SVN, Mercurial, Bazaar, or CVS metadata".to_string(),
            impact: "Allows source code reconstruction and credential discovery".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.gitignore\" | inurl:\"/.gitattributes\" | inurl:\"/.gitmodules\" | inurl:\"/.gitlab-ci.yml\")",
                clean_domain
            ),
            description: "Exposed git metadata files".to_string(),
            impact: "Reveals repository structure, CI config, submodule URLs".to_string(),
        });

        // CI/CD Configuration — pipeline files frequently disclose secret
        // names, registries, internal hosts, deployment endpoints.
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" | inurl:\".gitlab-ci.yml\" | inurl:\"Jenkinsfile\" | inurl:\".travis.yml\" | inurl:\".circleci/config\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"azure-pipelines.yml\")",
                clean_domain
            ),
            description: "Exposed CI/CD pipeline definitions".to_string(),
            impact: "Reveals build secrets references, deployment targets, registry credentials".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".dockerignore\" | inurl:\"Dockerfile\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\".npmrc\" | inurl:\".yarnrc\" | inurl:\".pypirc\")",
                clean_domain
            ),
            description: "Exposed package manager and container build configs".to_string(),
            impact: "Auth tokens and registry credentials are commonly stored in these files".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"composer.json\" | inurl:\"composer.lock\" | inurl:\"package-lock.json\" | inurl:\"yarn.lock\" | inurl:\"Gemfile.lock\" | inurl:\"poetry.lock\")",
                clean_domain
            ),
            description: "Exposed dependency lockfiles".to_string(),
            impact: "Reveals exact dependency versions for targeted CVE exploitation".to_string(),
        });

        // Environment & Configuration Files — `.env`, framework configs, IIS
        // web.config, etc. These are the single highest-yield credential
        // source on misconfigured static servers.
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (ext:env | inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.development\" | inurl:\".env.staging\" | inurl:\".env.backup\")",
                clean_domain
            ),
            description: "Exposed dotenv files".to_string(),
            impact: "Almost always contains DB credentials, API keys, JWT secrets, OAuth secrets".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\"web.config\" | inurl:\"appsettings.json\" | inurl:\"appsettings.Production.json\" | inurl:\"appsettings.Development.json\")",
                clean_domain
            ),
            description: "Exposed ASP.NET / .NET Core configuration files".to_string(),
            impact: "Connection strings, IdentityServer keys, machine keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\"application.properties\" | inurl:\"application.yml\" | inurl:\"application.yaml\" | inurl:\"application-prod.yml\" | inurl:\"bootstrap.yml\" | inurl:\"bootstrap.properties\")",
                clean_domain
            ),
            description: "Exposed Spring Boot configuration".to_string(),
            impact: "Database URLs, datasource passwords, OAuth client secrets, encryption keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\"settings.py\" | inurl:\"local_settings.py\" | inurl:\"config.py\" | inurl:\"secrets.py\" | inurl:\"wp-config.php\" | inurl:\"configuration.php\" | inurl:\"local.xml\")",
                clean_domain
            ),
            description: "Exposed framework configuration files (Django/Flask/WordPress/Joomla/Magento)".to_string(),
            impact: "SECRET_KEY, DB credentials, salt values, API tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\"sftp-config.json\" | inurl:\"ftpconfig\" | inurl:\".ftpconfig\" | inurl:\"deployment-config.json\" | inurl:\".remote-sync.json\")",
                clean_domain
            ),
            description: "Exposed editor/IDE deployment configs".to_string(),
            impact: "Often contain plaintext FTP/SFTP credentials and internal hostnames".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\"/.idea/dataSources.xml\" | inurl:\"/.idea/workspace.xml\" | inurl:\"/.vscode/settings.json\" | inurl:\"/.vscode/sftp.json\")",
                clean_domain
            ),
            description: "Exposed JetBrains/VSCode project configs".to_string(),
            impact: "Database connection strings and SFTP credentials are stored here".to_string(),
        });

        // Backup Files — high-value because backups frequently retain
        // credentials that have since been removed from live config.
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:tmp | ext:swp | ext:swo)",
                clean_domain
            ),
            description: "Files with backup-style extensions".to_string(),
            impact: "Backup files often retain old credentials and source code".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (inurl:\".php.bak\" | inurl:\".php~\" | inurl:\".php.old\" | inurl:\".php.swp\" | inurl:\".php.save\" | inurl:\".php.orig\" | inurl:\".inc.bak\")",
                clean_domain
            ),
            description: "Backup copies of PHP source files".to_string(),
            impact: "Server returns plaintext source instead of executing — full code disclosure".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z) (inurl:backup | inurl:dump | inurl:export | inurl:archive)",
                clean_domain
            ),
            description: "Compressed archives of backups or exports".to_string(),
            impact: "Full source code or database snapshots".to_string(),
        });

        // Database Dumps — direct, immediate impact.
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb | ext:dbf) (inurl:dump | inurl:backup | inurl:export | inurl:db | inurl:database)",
                clean_domain
            ),
            description: "Database dump or SQLite/Access database files".to_string(),
            impact: "Full database contents including user records and password hashes".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (intext:\"-- MySQL dump\" | intext:\"-- PostgreSQL database dump\" | intext:\"DUMP OF TABLE\" | intext:\"INSERT INTO\" filetype:sql)",
                clean_domain
            ),
            description: "Indexed contents of SQL dump files".to_string(),
            impact: "Indexed SQL dump indicates a public database snapshot — typically yields credentials".to_string(),
        });

        // Log Files — error/access logs commonly contain session tokens,
        // bearer tokens in URL params, stack traces with file paths.
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:\"/logs/\" | inurl:error.log | inurl:access.log | inurl:debug.log | inurl:application.log | inurl:wp-content/debug.log)",
                clean_domain
            ),
            description: "Exposed application/server logs".to_string(),
            impact: "Logs frequently leak session tokens, query parameters with secrets, internal paths".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (intext:\"PHP Fatal error\" | intext:\"PHP Warning\" | intext:\"PHP Notice\" | intext:\"Traceback (most recent call last)\" | intext:\"at java.lang\")",
                clean_domain
            ),
            description: "Indexed runtime stack traces".to_string(),
            impact: "Reveals filesystem paths, framework versions, sometimes session/DB info".to_string(),
        });

        // Spring Boot Actuator — unauthenticated `/env`, `/heapdump`,
        // `/trace` endpoints are top-tier credential leaks. Heap dump alone
        // is RCE-class because it contains every secret in process memory.
        dorks.push(GoogleDork {
            category: "Spring Boot Actuator".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/beans\" | inurl:\"/actuator/trace\" | inurl:\"/actuator/httptrace\")",
                clean_domain
            ),
            description: "Exposed Spring Boot Actuator administrative endpoints".to_string(),
            impact: "Exposes env vars (secrets), heap (in-memory creds), routing — frequently RCE-class".to_string(),
        });

        // Server Status / Info Pages — Apache server-status, PHP info, etc.
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:\"/server-status\" | inurl:\"/server-info\" | inurl:\"/status?full\" | inurl:\"/nginx_status\" | inurl:\"/haproxy?stats\")",
                clean_domain
            ),
            description: "Exposed Apache/Nginx/HAProxy status pages".to_string(),
            impact: "Reveals client IPs, internal request URIs (often with tokens), server config".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | inurl:test.php | inurl:_phpinfo.php | intitle:\"phpinfo()\")",
                clean_domain
            ),
            description: "Exposed phpinfo() output".to_string(),
            impact: "Discloses environment variables, file system paths, PHP/server config, loaded modules".to_string(),
        });

        // Framework Debug Pages — Laravel Ignition, Django Debug, Werkzeug
        // debugger, Symfony profiler. Werkzeug debugger is unauthenticated RCE.
        dorks.push(GoogleDork {
            category: "Framework Debug".to_string(),
            query: format!(
                "site:{} (intitle:\"Whoops! There was an error\" | intext:\"Ignition\" | intext:\"Laravel Ignition\")",
                clean_domain
            ),
            description: "Laravel debug error page (Ignition)".to_string(),
            impact: "CVE-2021-3129 territory: env disclosure and historical RCE chains".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Framework Debug".to_string(),
            query: format!(
                "site:{} (intitle:\"Werkzeug Debugger\" | intext:\"console-pin\" | intext:\"The debugger caught an exception in your WSGI application\")",
                clean_domain
            ),
            description: "Werkzeug interactive debugger".to_string(),
            impact: "Interactive Python REPL on the server — pre-auth RCE if exposed".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Framework Debug".to_string(),
            query: format!(
                "site:{} (intext:\"Django Debug\" | intitle:\"DisallowedHost\" | intext:\"DEBUG = True\" | intext:\"You're seeing this error because you have DEBUG = True\")",
                clean_domain
            ),
            description: "Django debug page".to_string(),
            impact: "Discloses settings, installed apps, request data including session cookies".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Framework Debug".to_string(),
            query: format!(
                "site:{} (inurl:\"/_profiler/\" | inurl:\"_profiler/phpinfo\" | inurl:\"/_profiler/empty/search/results\" | intitle:\"Symfony Profiler\")",
                clean_domain
            ),
            description: "Symfony profiler exposed".to_string(),
            impact: "Reveals request/response, session data, DB queries, configuration".to_string(),
        });

        // Crypto / Key Material — private keys, certificates, keystores.
        dorks.push(GoogleDork {
            category: "Cryptographic Material".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:p12 | ext:pfx | ext:jks | ext:keystore | ext:asc) -intext:\"PUBLIC KEY\"",
                clean_domain
            ),
            description: "Exposed key/keystore files (excluding obvious public keys)".to_string(),
            impact: "TLS, code-signing, JWT, or SSH private key material".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cryptographic Material".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN EC PRIVATE KEY-----\" | intext:\"-----BEGIN DSA PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\")",
                clean_domain
            ),
            description: "Indexed PEM-armored private keys".to_string(),
            impact: "Direct disclosure of private keys is always a critical finding".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cryptographic Material".to_string(),
            query: format!(
                "site:{} (inurl:id_rsa | inurl:id_dsa | inurl:id_ecdsa | inurl:id_ed25519 | inurl:authorized_keys | inurl:known_hosts | inurl:.ssh/config)",
                clean_domain
            ),
            description: "Exposed SSH key files".to_string(),
            impact: "Direct lateral movement into infrastructure".to_string(),
        });

        // Tokens / API keys leaked in URL parameters — search results
        // commonly preserve them; also useful for content-only matches.
        dorks.push(GoogleDork {
            category: "Tokens in URLs".to_string(),
            query: format!(
                "site:{} (inurl:token= | inurl:access_token= | inurl:api_key= | inurl:apikey= | inurl:auth_token= | inurl:session= | inurl:sessionid= | inurl:auth=)",
                clean_domain
            ),
            description: "Tokens passed in URL query strings".to_string(),
            impact: "URL-borne tokens leak via referer, browser history, server logs, and search indexes".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Tokens in URLs".to_string(),
            query: format!(
                "site:{} (inurl:password= | inurl:passwd= | inurl:pwd= | inurl:secret= | inurl:client_secret=)",
                clean_domain
            ),
            description: "Credentials in URL query strings".to_string(),
            impact: "Plaintext credentials embedded in URLs".to_string(),
        });

        // DB / Admin Web Interfaces — phpMyAdmin, Adminer, etc.
        dorks.push(GoogleDork {
            category: "Database Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin | inurl:pma | inurl:myadmin | inurl:adminer.php | inurl:adminer | inurl:phppgadmin | inurl:dbadmin | inurl:mongo-express | inurl:rockmongo)",
                clean_domain
            ),
            description: "Exposed database administration interfaces".to_string(),
            impact: "Direct database management interface access from the internet".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"phpPgAdmin\" | intitle:\"RockMongo\" | intitle:\"Mongo Express\")",
                clean_domain
            ),
            description: "Database admin interfaces by page title".to_string(),
            impact: "Direct database management access — frequently default-credential vulnerable".to_string(),
        });

        // GraphQL / API Console exposure
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:graphql | inurl:graphiql | inurl:playground | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\" | intitle:\"Apollo Studio\")",
                clean_domain
            ),
            description: "Exposed GraphQL playgrounds and consoles".to_string(),
            impact: "Schema introspection, query execution against production data".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:swagger.yaml | inurl:openapi.json | inurl:openapi.yaml | inurl:api-docs.json | inurl:v2/api-docs | inurl:v3/api-docs)",
                clean_domain
            ),
            description: "Raw OpenAPI/Swagger schema documents".to_string(),
            impact: "Full API surface enumeration including internal/admin endpoints".to_string(),
        });

        // CMS-specific sensitive paths
        dorks.push(GoogleDork {
            category: "CMS Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php~ | inurl:wp-config.php.old | inurl:wp-config.php.save | inurl:wp-config.txt)",
                clean_domain
            ),
            description: "Backup copies of wp-config.php".to_string(),
            impact: "Plaintext WordPress DB credentials and authentication salts".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CMS Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/wp-content/uploads/\" ext:sql | inurl:\"/wp-content/backup\" | inurl:\"/wp-content/uploads/backup\" | inurl:\"/wp-content/debug.log\")",
                clean_domain
            ),
            description: "WordPress backup and debug artifacts".to_string(),
            impact: "DB dumps and debug logs exposing site internals".to_string(),
        });

        // .htaccess / .htpasswd
        dorks.push(GoogleDork {
            category: "Server Config".to_string(),
            query: format!(
                "site:{} (inurl:\"/.htpasswd\" | inurl:\"/.htaccess\" | inurl:web.config ext:config | inurl:nginx.conf | inurl:my.cnf)",
                clean_domain
            ),
            description: "Exposed web server configuration".to_string(),
            impact: "Reveals auth files, rewrite rules, internal paths, sometimes plaintext password hashes".to_string(),
        });

        // Open directory listings
        dorks.push(GoogleDork {
            category: "Open Directory".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (intext:\"backup\" | intext:\".env\" | intext:\".sql\" | intext:\".bak\" | intext:\"private\" | intext:\"keys\" | intext:\"secrets\")",
                clean_domain
            ),
            description: "Apache/Nginx autoindex directory listings with sensitive contents".to_string(),
            impact: "Unintentional exposure of arbitrary file trees".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Open Directory".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (\"parent directory\" | \"last modified\")",
                clean_domain
            ),
            description: "Generic directory listing pages".to_string(),
            impact: "Directory listing enabled — enumerate for sensitive files".to_string(),
        });

        // Source Maps and built artifacts (search-only; module-level scanner
        // probes paths directly, but indexed source maps surface fast here).
        dorks.push(GoogleDork {
            category: "Source Maps".to_string(),
            query: format!(
                "site:{} (ext:map | inurl:.js.map | inurl:.css.map | inurl:.mjs.map)",
                clean_domain
            ),
            description: "Indexed JavaScript/CSS source maps".to_string(),
            impact: "Source maps reconstruct original source — credentials and business logic disclosure".to_string(),
        });

        // GitHub leaks containing the target domain — focused on credential
        // patterns rather than generic mentions.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com \"{}\" (filename:.env | filename:.npmrc | filename:.pypirc | filename:credentials | filename:config.json | filename:secrets.yml)",
                clean_domain
            ),
            description: "GitHub results combining target with sensitive filenames".to_string(),
            impact: "High signal: a hit usually means a real leaked secret in public code".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com \"{}\" (extension:pem | extension:ppk | extension:keystore | extension:jks | extension:p12)",
                clean_domain
            ),
            description: "Key/keystore files referencing the target domain on GitHub".to_string(),
            impact: "Private key material associated with the target".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:gist.github.com \"{}\"",
                clean_domain
            ),
            description: "Public gists mentioning the target domain".to_string(),
            impact: "Gists are the most common accidental secret-leak vector for individual developers".to_string(),
        });

        // Paste sites beyond Pastebin
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:rentry.co | site:ghostbin.com | site:controlc.com | site:paste.ee | site:hastebin.com | site:dpaste.com | site:0bin.net) \"{}\"",
                clean_domain
            ),
            description: "Mentions of the target across alternative paste sites".to_string(),
            impact: "Off-Pastebin paste sites are routinely used to evade detection".to_string(),
        });

        // Postman public workspaces / collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Postman public workspaces, collections, and documenters".to_string(),
            impact: "Often expose API endpoints, request samples with auth, and environment vars".to_string(),
        });

        // Insomnia / Bruno / Thunder Client share links
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:insomnia.rest | site:hoppscotch.io) \"{}\"",
                clean_domain
            ),
            description: "Shared collections in alternative API clients".to_string(),
            impact: "Same exposure profile as Postman — full API specs with auth examples".to_string(),
        });

        // Wayback Machine — historical exposures often persist after takedown.
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (inurl:.env | inurl:.git | inurl:wp-config | inurl:backup | inurl:dump)",
                clean_domain
            ),
            description: "Archived snapshots of sensitive paths".to_string(),
            impact: "Even if removed from production, archive.org may retain the leaked content".to_string(),
        });

        // Public S3 / GCS / Azure listing pages indexed in Google
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net) intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Indexed bucket-listing pages for the target".to_string(),
            impact: "Confirms a public-listed bucket — direct enumeration of contained objects".to_string(),
        });

        // Cloudfront / generic cloud distribution backends
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:cloudfront.net | site:objects.dreamhost.com | site:r2.cloudflarestorage.com | site:wasabisys.com | site:linodeobjects.com) \"{}\"",
                clean_domain
            ),
            description: "Alternative object storage and CDN providers".to_string(),
            impact: "Equivalent S3-style misconfiguration risks beyond AWS/GCP/Azure".to_string(),
        });

        // Internal hostname patterns (subdomain enumeration via search)
        dorks.push(GoogleDork {
            category: "Internal Hosts".to_string(),
            query: format!(
                "site:*.{} -site:www.{} (inurl:admin | inurl:internal | inurl:vpn | inurl:portal | inurl:dashboard | inurl:jenkins | inurl:gitlab | inurl:jira | inurl:confluence)",
                clean_domain, clean_domain
            ),
            description: "Subdomains hosting internal-style applications".to_string(),
            impact: "Internal applications exposed externally are frequent compromise paths".to_string(),
        });

        // Email / PII leaks from indexed pages
        dorks.push(GoogleDork {
            category: "PII Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"@{}\" ext:pdf | intext:\"@{}\" ext:csv | intext:\"@{}\" ext:xlsx | intext:\"@{}\" ext:txt)",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Indexed documents containing corporate email addresses".to_string(),
            impact: "Indexed PII document exposure — feeds phishing and compliance findings".to_string(),
        });

        // CVE / version disclosure via README / changelog
        dorks.push(GoogleDork {
            category: "Version Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:CHANGELOG | inurl:CHANGES | inurl:VERSION | inurl:RELEASE | inurl:README | inurl:HISTORY)",
                clean_domain
            ),
            description: "Indexed changelog/version files".to_string(),
            impact: "Pinpoints exact deployed version for targeted CVE matching".to_string(),
        });

        // Coverage / test reports — sometimes contain code paths and secrets
        dorks.push(GoogleDork {
            category: "Build Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"/coverage/\" | inurl:lcov.html | inurl:lcov-report | inurl:\"/test-results/\" | inurl:junit.xml | inurl:mochawesome.html)",
                clean_domain
            ),
            description: "Exposed coverage and test reports".to_string(),
            impact: "Reveals source paths, function names, internal logic, sometimes test fixtures with secrets".to_string(),
        });

        // Sentry / error reporting public dashboards or hosted exception pages
        dorks.push(GoogleDork {
            category: "Error Tracking".to_string(),
            query: format!(
                "(site:sentry.io | site:bugsnag.com | site:rollbar.com | site:airbrake.io) \"{}\"",
                clean_domain
            ),
            description: "Mentions of the target on error-tracking platforms".to_string(),
            impact: "Public dashboards leak exception traces with file paths, request bodies, sometimes tokens".to_string(),
        });

        // Generic open file shares
        dorks.push(GoogleDork {
            category: "Open File Shares".to_string(),
            query: format!(
                "(site:transfer.sh | site:wetransfer.com | site:file.io | site:anonfiles.com | site:mega.nz) \"{}\"",
                clean_domain
            ),
            description: "Anonymous file-share services referencing the target".to_string(),
            impact: "Used to exfiltrate dumps and credentials outside corporate channels".to_string(),
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
