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

        // Atlassian Confluence (public spaces)
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:atlassian.net inurl:/wiki/spaces \"{}\"",
                clean_domain
            ),
            description: "Find public Confluence spaces mentioning the domain".to_string(),
            impact: "Public Confluence pages may expose runbooks, credentials, or architecture diagrams".to_string(),
        });

        // Atlassian Jira (public service desk / portal)
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:atlassian.net inurl:/servicedesk | inurl:/jira \"{}\"",
                clean_domain
            ),
            description: "Find public Jira service desks or portals".to_string(),
            impact: "Public Jira tickets may expose internal email addresses, ticket templates, or workflows".to_string(),
        });

        // Notion public pages
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:notion.site \"{}\"", clean_domain),
            description: "Find public Notion pages".to_string(),
            impact: "Public Notion docs may leak SOPs, onboarding guides, or shared credentials".to_string(),
        });

        // Asana
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:asana.com \"{}\"", clean_domain),
            description: "Find public Asana tasks or projects".to_string(),
            impact: "Public Asana boards may expose internal project details".to_string(),
        });

        // Monday.com
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:monday.com \"{}\"", clean_domain),
            description: "Find public Monday.com boards".to_string(),
            impact: "Public Monday.com boards may expose internal project data".to_string(),
        });

        // Postman public workspaces / collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com (inurl:/workspace | inurl:/collection) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces or collections".to_string(),
            impact: "Public Postman collections frequently contain API tokens, bearer tokens, and internal API surface".to_string(),
        });

        // SwaggerHub public APIs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!("site:app.swaggerhub.com \"{}\"", clean_domain),
            description: "Find published OpenAPI specs on SwaggerHub".to_string(),
            impact: "Published OpenAPI specs disclose every endpoint, parameter, auth scheme, and example payload".to_string(),
        });

        // RapidAPI / ReadMe / Stoplight public API docs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:rapidapi.com | site:readme.io | site:stoplight.io \"{}\"",
                clean_domain
            ),
            description: "Find hosted API documentation on RapidAPI/ReadMe/Stoplight".to_string(),
            impact: "Hosted docs reveal full API surface and authentication requirements".to_string(),
        });

        // Bitbucket Cloud snippets/repos
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:bitbucket.org \"{}\"", clean_domain),
            description: "Find Bitbucket repositories or snippets mentioning the domain".to_string(),
            impact: "Public Bitbucket repos may expose internal source code, configs, or credentials".to_string(),
        });

        // GitHub Gist
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists mentioning the domain".to_string(),
            impact: "Gists are frequently used to share secrets and configs; common source of leaked API keys".to_string(),
        });

        // GitHub Code Search - credentials near domain
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" (password | passwd | secret | token | api_key | api-key | apikey | bearer | aws_access | private_key)",
                clean_domain
            ),
            description: "GitHub repos mentioning the domain alongside credential keywords".to_string(),
            impact: "High-signal dork for finding hardcoded secrets bound to the target".to_string(),
        });

        // GitHub - .env / config files referencing the domain
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" (filename:.env | filename:config.json | filename:settings.py | filename:application.yml | filename:web.config)",
                clean_domain
            ),
            description: "GitHub config/env files referencing the domain".to_string(),
            impact: "Dotenv and framework config files often contain database URLs, API keys, and secrets".to_string(),
        });

        // GitLab snippets
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gitlab.com/snippets | site:gitlab.com/-/snippets \"{}\"", clean_domain),
            description: "Find GitLab snippets mentioning the domain".to_string(),
            impact: "Snippets are commonly used for quick sharing and may expose credentials".to_string(),
        });

        // SourceGraph public search
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:sourcegraph.com \"{}\"", clean_domain),
            description: "Find code on Sourcegraph mentioning the domain".to_string(),
            impact: "Sourcegraph indexes many public repos and may surface secrets".to_string(),
        });

        // Hastebin / Ghostbin / 0bin / dpaste
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:hastebin.com | site:ghostbin.com | site:dpaste.com | site:dpaste.org | site:paste.ee | site:paste.ofcode.org | site:rentry.co) \"{}\"",
                clean_domain
            ),
            description: "Find pastes on additional paste services".to_string(),
            impact: "Alternative paste sites frequently host leaked credentials and tokens".to_string(),
        });

        // ControlC / Paste.ee / Justpaste.it
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:controlc.com | site:justpaste.it | site:pastes.io | site:textbin.net) \"{}\"",
                clean_domain
            ),
            description: "Find pastes on lesser-known paste services".to_string(),
            impact: "Lesser-known paste sites are often used to evade scanning and leak sensitive data".to_string(),
        });

        // Glitch / Replit / CodeSandbox / StackBlitz hosted apps
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:glitch.com | site:replit.com | site:codesandbox.io | site:stackblitz.com) \"{}\"",
                clean_domain
            ),
            description: "Find hosted code on online IDEs".to_string(),
            impact: "Online sandboxes often contain embedded API keys, OAuth client IDs, and tokens".to_string(),
        });

        // .git directory exposure
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:/.git/refs)",
                clean_domain
            ),
            description: "Find exposed .git directories".to_string(),
            impact: "Exposed .git allows full repository clone, leaking source code and historical secrets".to_string(),
        });

        // .svn / .hg / .bzr exposure
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.svn/entries | inurl:.svn/wc.db | inurl:.hg/store | inurl:.bzr/branch)",
                clean_domain
            ),
            description: "Find exposed SVN/Mercurial/Bazaar metadata".to_string(),
            impact: "Exposed VCS metadata permits source code reconstruction".to_string(),
        });

        // .DS_Store / Thumbs.db (directory listing leak)
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.DS_Store | inurl:Thumbs.db | inurl:desktop.ini)",
                clean_domain
            ),
            description: "Find OS-generated metadata files".to_string(),
            impact: ".DS_Store and Thumbs.db enumerate directory contents and filenames".to_string(),
        });

        // Database dumps & backups (file extensions)
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:dmp | ext:mdb | ext:sqlite | ext:sqlite3 | ext:db | ext:bak | ext:gz | ext:tar | ext:tgz | ext:7z | ext:rar | ext:zip)",
                clean_domain
            ),
            description: "Find database dumps and archive backups".to_string(),
            impact: "SQL dumps and archives often contain entire database snapshots and PII".to_string(),
        });

        // Environment / config dotfiles
        dorks.push(GoogleDork {
            category: "Configuration Files".to_string(),
            query: format!(
                "site:{} (ext:env | ext:ini | ext:yml | ext:yaml | ext:toml | ext:properties | ext:cfg | ext:conf | ext:config)",
                clean_domain
            ),
            description: "Find environment and configuration files".to_string(),
            impact: "Configuration files routinely contain API keys, DB credentials, and service tokens".to_string(),
        });

        // Private key material
        dorks.push(GoogleDork {
            category: "Credentials".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:pfx | ext:p12 | ext:jks | ext:keystore | ext:asc | ext:gpg)",
                clean_domain
            ),
            description: "Find exposed private keys, keystores, or PGP material".to_string(),
            impact: "Private keys give direct access to TLS, SSH, signing, and encryption material".to_string(),
        });

        // BEGIN PRIVATE KEY in indexed content
        dorks.push(GoogleDork {
            category: "Credentials".to_string(),
            query: format!(
                "site:{} (\"BEGIN RSA PRIVATE KEY\" | \"BEGIN OPENSSH PRIVATE KEY\" | \"BEGIN EC PRIVATE KEY\" | \"BEGIN PGP PRIVATE KEY BLOCK\")",
                clean_domain
            ),
            description: "Find indexed pages containing PEM-armored private keys".to_string(),
            impact: "Indexed private keys are immediately usable by an attacker".to_string(),
        });

        // .htpasswd / .htaccess
        dorks.push(GoogleDork {
            category: "Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.htpasswd | inurl:.htaccess | inurl:.netrc | inurl:.pgpass | inurl:.my.cnf)",
                clean_domain
            ),
            description: "Find exposed Apache/Unix credential files".to_string(),
            impact: ".htpasswd contains password hashes; .netrc/.my.cnf/.pgpass contain plaintext credentials".to_string(),
        });

        // WordPress wp-config.php variants
        dorks.push(GoogleDork {
            category: "Configuration Files".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php~ | inurl:wp-config.old | inurl:wp-config.txt)",
                clean_domain
            ),
            description: "Find WordPress wp-config backup variants".to_string(),
            impact: "wp-config backups contain database credentials and authentication keys/salts".to_string(),
        });

        // Log files (server-side error/access logs)
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:error_log | inurl:access_log | inurl:debug.log | inurl:laravel.log | inurl:catalina.out | inurl:sftp-config.json)",
                clean_domain
            ),
            description: "Find exposed log files".to_string(),
            impact: "Logs may contain session tokens, stack traces, internal endpoints, and PII".to_string(),
        });

        // Spring Boot Actuator endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/loggers | inurl:/actuator/threaddump | inurl:/actuator/health | inurl:/actuator/info)",
                clean_domain
            ),
            description: "Find Spring Boot Actuator endpoints".to_string(),
            impact: "/actuator/env and /heapdump leak credentials and full process memory; /configprops leaks injected secrets".to_string(),
        });

        // Prometheus / metrics endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/metrics | inurl:/prometheus | inurl:/server-status | inurl:/server-info | inurl:/nginx_status | inurl:/stub_status)",
                clean_domain
            ),
            description: "Find exposed metrics / status endpoints".to_string(),
            impact: "Metrics endpoints disclose internal hostnames, deployment topology, and traffic patterns".to_string(),
        });

        // Trace / debug endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:trace.axd | inurl:elmah.axd | inurl:/_profiler | inurl:/debug/vars | inurl:/_debugbar | inurl:phpinfo.php | inurl:test.php inurl:phpinfo)",
                clean_domain
            ),
            description: "Find debug/trace/profiling endpoints".to_string(),
            impact: "Debug endpoints leak request data, env vars, DB queries, and routing info".to_string(),
        });

        // .well-known / OAuth discovery / SAML metadata
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:.well-known/openid-configuration | inurl:.well-known/oauth-authorization-server | inurl:saml/metadata | inurl:FederationMetadata.xml)",
                clean_domain
            ),
            description: "Find OIDC discovery and SAML metadata endpoints".to_string(),
            impact: "Discovery docs and SAML metadata reveal IdP topology, signing keys, and supported flows for auth attacks".to_string(),
        });

        // Kubernetes / container orchestration
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/api/v1/namespaces | inurl:/healthz | inurl:/readyz | inurl:/livez | inurl:/kubelet | inurl:/swaggerapi)",
                clean_domain
            ),
            description: "Find Kubernetes API or kubelet endpoints".to_string(),
            impact: "Exposed K8s APIs can lead to cluster compromise and secret extraction".to_string(),
        });

        // ServiceNow public knowledge / catalog
        dorks.push(GoogleDork {
            category: "SaaS Leakage".to_string(),
            query: format!(
                "site:service-now.com \"{}\"",
                clean_domain
            ),
            description: "Find ServiceNow tenants referencing the domain".to_string(),
            impact: "Public ServiceNow tables may expose tickets, user info, or catalog items".to_string(),
        });

        // Salesforce sites & communities
        dorks.push(GoogleDork {
            category: "SaaS Leakage".to_string(),
            query: format!(
                "(site:force.com | site:my.salesforce.com | site:lightning.force.com | site:my.site.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Salesforce Experience/Community sites".to_string(),
            impact: "Misconfigured Salesforce Communities historically expose every record via guest profiles".to_string(),
        });

        // HubSpot hosted pages
        dorks.push(GoogleDork {
            category: "SaaS Leakage".to_string(),
            query: format!("site:hubspot.com | site:hs-sites.com \"{}\"", clean_domain),
            description: "Find HubSpot landing pages".to_string(),
            impact: "HubSpot pages may expose marketing forms with weak validation".to_string(),
        });

        // Smartsheet / Airtable shared bases
        dorks.push(GoogleDork {
            category: "SaaS Leakage".to_string(),
            query: format!(
                "(site:smartsheet.com | site:airtable.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Smartsheet/Airtable bases".to_string(),
            impact: "Shared Smartsheet/Airtable views frequently expose PII, customer lists, and internal data".to_string(),
        });

        // Slack archives
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:slack.com/archives | site:files.slack.com) \"{}\"",
                clean_domain
            ),
            description: "Find Slack archives or attachments referencing the domain".to_string(),
            impact: "Slack file shares may expose internal conversations and uploaded credentials".to_string(),
        });

        // Discord
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:discord.com \"{}\"", clean_domain),
            description: "Find Discord references to the domain".to_string(),
            impact: "Discord servers may discuss internal apps or vulnerabilities".to_string(),
        });

        // Telegram public channels
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:t.me \"{}\"", clean_domain),
            description: "Find Telegram channels referencing the domain".to_string(),
            impact: "Telegram channels often leak credentials, dumps, or internal discussions".to_string(),
        });

        // Stack Overflow questions with internal details
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:serverfault.com | site:superuser.com) \"{}\"",
                clean_domain
            ),
            description: "Find Q&A posts referencing the domain".to_string(),
            impact: "Developers often paste configs/stack traces with secrets when asking questions".to_string(),
        });

        // Wayback Machine archived sensitive endpoints
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (\".env\" | \"config.json\" | \"swagger\" | \"actuator\" | \"phpinfo\")",
                clean_domain
            ),
            description: "Find sensitive endpoints archived on the Wayback Machine".to_string(),
            impact: "Wayback often retains snapshots of pages now hidden or removed".to_string(),
        });

        // Box / WeTransfer / Dropbox business shares
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:app.box.com/s | site:we.tl | site:wetransfer.com/downloads | site:transfer.sh) \"{}\"",
                clean_domain
            ),
            description: "Find Box / WeTransfer / transfer.sh shared file links".to_string(),
            impact: "File-share links often grant unauthenticated access to internal documents".to_string(),
        });

        // Google Cloud Storage / Firebase hosted apps
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com | site:web.app | site:firebaseapp.com) \"{}\"",
                clean_domain
            ),
            description: "Find GCS objects or Firebase Hosting apps referencing the domain".to_string(),
            impact: "Misconfigured GCS buckets and Firebase apps may expose data and config".to_string(),
        });

        // Backblaze B2 / Cloudflare R2 / Wasabi
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:backblazeb2.com | site:r2.dev | site:s3.wasabisys.com | site:storage.yandexcloud.net | site:objectstorage.oraclecloud.com) \"{}\"",
                clean_domain
            ),
            description: "Find non-AWS S3-compatible object storage referencing the domain".to_string(),
            impact: "Alternative object storage often has weaker default access controls".to_string(),
        });

        // Email archive lists / Mailman / Pipermail
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(inurl:/pipermail | inurl:/mailman/listinfo | inurl:/mail-archive) \"{}\"",
                clean_domain
            ),
            description: "Find public mailing list archives mentioning the domain".to_string(),
            impact: "List archives may leak internal email addresses and discussions".to_string(),
        });

        // WebDAV exposure
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/webdav | inurl:/dav | intext:\"DAV: 1\")",
                clean_domain
            ),
            description: "Find WebDAV-enabled endpoints".to_string(),
            impact: "WebDAV often allows authenticated or anonymous file upload/overwrite".to_string(),
        });

        // Open directory listing
        dorks.push(GoogleDork {
            category: "Sensitive Endpoints".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (\"backup\" | \"upload\" | \"private\" | \"config\" | \"db\" | \"sql\" | \"log\")",
                clean_domain
            ),
            description: "Find open directory listings for sensitive folder names".to_string(),
            impact: "Open directory listings enable trivial enumeration of every file in the folder".to_string(),
        });

        // CI/CD platform leakage
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "(site:travis-ci.org | site:travis-ci.com | site:app.circleci.com | site:dev.azure.com | site:teamcity.com) \"{}\"",
                clean_domain
            ),
            description: "Find CI/CD build pages referencing the domain".to_string(),
            impact: "CI build logs frequently leak secrets via accidental echo or env dumps".to_string(),
        });

        // GitHub Actions logs (public)
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:github.com inurl:/actions/runs \"{}\"",
                clean_domain
            ),
            description: "Find public GitHub Actions runs referencing the domain".to_string(),
            impact: "Action logs may show env vars, masked-too-late secrets, and internal hostnames".to_string(),
        });

        // Package registries with private-looking names
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:npmjs.com | site:pypi.org | site:rubygems.org) \"{}\"",
                clean_domain
            ),
            description: "Find published packages referencing the domain (possible dependency confusion targets)".to_string(),
            impact: "Identifies internal-looking package names useful for dependency confusion attacks".to_string(),
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
