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

        // Exposed environment files (.env, dump.sql, config files)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD\" | intext:\"AWS_SECRET_ACCESS_KEY\" | intext:\"DATABASE_URL=\" | intext:\"SECRET_KEY_BASE\" | intext:\"RAILS_MASTER_KEY\" | intext:\"DJANGO_SECRET_KEY\")",
                clean_domain
            ),
            description: "Find leaked .env-style configuration values referencing the target".to_string(),
            impact: "Direct credential exposure - immediate critical risk".to_string(),
        });

        // Wayback / archive snapshots (often retain removed sensitive content)
        dorks.push(GoogleDork {
            category: "Historical Snapshots".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (inurl:.env | inurl:config | inurl:backup | inurl:.git)",
                clean_domain
            ),
            description: "Find archived snapshots of sensitive endpoints".to_string(),
            impact: "Historical copies may still leak credentials removed from the live site".to_string(),
        });

        // Stack Overflow code snippets (devs commonly paste configs)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:stackoverflow.com \"{}\"", clean_domain),
            description: "Find Stack Overflow questions/answers referencing the domain".to_string(),
            impact: "Questions often contain redacted-but-recoverable internal URLs, errors, configs".to_string(),
        });

        // Postman public workspaces (frequent credential leak channel)
        dorks.push(GoogleDork {
            category: "API Exposure".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman collections, workspaces, and API documentation".to_string(),
            impact: "Public Postman workspaces routinely leak Bearer tokens, API keys, and internal endpoints".to_string(),
        });

        // SwaggerHub / Apiary / Bump public API definitions
        dorks.push(GoogleDork {
            category: "API Exposure".to_string(),
            query: format!(
                "(site:app.swaggerhub.com | site:apiary.io | site:bump.sh | site:stoplight.io) \"{}\"",
                clean_domain
            ),
            description: "Find publicly hosted OpenAPI/Swagger definitions".to_string(),
            impact: "Reveals undocumented endpoints, parameters, and authentication models".to_string(),
        });

        // Hashnode / Medium / Dev.to leaks (engineers blog about internals)
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:medium.com | site:dev.to | site:hashnode.com) \"{}\" (intext:\"internal\" | intext:\"production\" | intext:\"staging\")",
                clean_domain
            ),
            description: "Find blog posts mentioning internal architecture".to_string(),
            impact: "Engineering blogs often reveal stack details, auth flows, and business logic".to_string(),
        });

        // npm / PyPI / RubyGems package leaks
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:npmjs.com | site:pypi.org | site:rubygems.org) \"{}\"",
                clean_domain
            ),
            description: "Find packages published referencing the target".to_string(),
            impact: "Internal packages mistakenly published to public registries are a supply-chain risk".to_string(),
        });

        // Docker Hub leaks (build artifacts often contain secrets)
        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!("site:hub.docker.com \"{}\"", clean_domain),
            description: "Find public Docker images referencing the domain".to_string(),
            impact: "Public images often ship with environment variables, source code, or build secrets".to_string(),
        });

        // Open S3 listing pages (`<ListBucketResult>`)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Find publicly listable S3 buckets".to_string(),
            impact: "Listing-enabled buckets allow enumeration of all stored objects".to_string(),
        });

        // Azure Storage public containers
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:blob.core.windows.net inurl:\"?restype=container&comp=list\" \"{}\"",
                clean_domain
            ),
            description: "Find Azure Blob containers with public listing".to_string(),
            impact: "Container-level listing enumerates all blobs, often including backups".to_string(),
        });

        // Open directory listings on the target itself
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (intext:\"parent directory\" | intext:\"backup\" | intext:\".sql\" | intext:\".bak\" | intext:\".env\")",
                clean_domain
            ),
            description: "Find auto-indexed directories exposing files".to_string(),
            impact: "Directory listings expose backup, configuration, and database dump files".to_string(),
        });

        // Exposed Git / SVN metadata
        dorks.push(GoogleDork {
            category: "Source Control Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".git/HEAD\" | inurl:\".git/config\" | inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\".bzr/branch-format\")",
                clean_domain
            ),
            description: "Find exposed VCS metadata".to_string(),
            impact: "Public .git/.svn directories allow full source code reconstruction".to_string(),
        });

        // Database backups / dumps
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:dmp | ext:db | ext:sqlite | ext:sqlite3 | ext:mdb)",
                clean_domain
            ),
            description: "Find database dump files".to_string(),
            impact: "DB dumps typically contain user credentials, PII, and internal data".to_string(),
        });

        // Exposed log files with potentially sensitive content
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:logs | inurl:logfile) (intext:\"password\" | intext:\"token\" | intext:\"authorization\" | intext:\"exception\")",
                clean_domain
            ),
            description: "Find log files containing credentials or stack traces".to_string(),
            impact: "Production logs frequently leak tokens, passwords, and stack-trace internals".to_string(),
        });

        // Backup file extensions (configs, source, archives)
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:save | ext:swp | ext:swo | ext:orig | ext:tmp | ext:~ | ext:rar | ext:zip | ext:tar | ext:tar.gz | ext:tgz)",
                clean_domain
            ),
            description: "Find backup and archive files".to_string(),
            impact: "Backup files often contain unredacted source code and configuration".to_string(),
        });

        // Server status / mod_status pages
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:server-status | inurl:server-info | inurl:status?full | intitle:\"Apache Status\" | intitle:\"Server Status for\")",
                clean_domain
            ),
            description: "Find exposed Apache/nginx status pages".to_string(),
            impact: "Status pages leak internal IPs, request URIs, and process information".to_string(),
        });

        // Spring Boot Actuator endpoints (env, heapdump, beans)
        dorks.push(GoogleDork {
            category: "Actuator Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/beans | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/threaddump)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator /env and /heapdump leak credentials; /jolokia can lead to RCE".to_string(),
        });

        // Drupal / WordPress / Joomla admin & install endpoints
        dorks.push(GoogleDork {
            category: "CMS Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/wp-admin | inurl:/wp-config.php | inurl:/xmlrpc.php | inurl:/user/login | inurl:/?q=admin | inurl:/administrator/index.php | inurl:/install.php | inurl:/CHANGELOG.txt)",
                clean_domain
            ),
            description: "Find CMS administrative and install endpoints".to_string(),
            impact: "Exposed install scripts and admin panels are direct compromise vectors".to_string(),
        });

        // Jenkins / Hudson / TeamCity / Bamboo unauth views
        dorks.push(GoogleDork {
            category: "CI/CD Exposure".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | intitle:\"Hudson\" | intitle:\"TeamCity\" | intitle:\"Bamboo\" | inurl:/job/ | inurl:/script | inurl:/scriptText)",
                clean_domain
            ),
            description: "Find unauthenticated CI dashboards and script consoles".to_string(),
            impact: "Open Jenkins script consoles equal RCE on the build host".to_string(),
        });

        // Mail server / webmail access
        dorks.push(GoogleDork {
            category: "Webmail Access".to_string(),
            query: format!(
                "site:{} (intitle:\"Outlook Web App\" | intitle:\"Roundcube Webmail\" | intitle:\"Zimbra Web Client Sign In\" | intitle:\"SquirrelMail\" | inurl:/owa/ | inurl:/ecp/ | inurl:/webmail)",
                clean_domain
            ),
            description: "Find webmail / Exchange / Zimbra portals".to_string(),
            impact: "Mail portals are common credential-stuffing and CVE targets".to_string(),
        });

        // VPN / SSL-VPN / RDP gateway portals
        dorks.push(GoogleDork {
            category: "Remote Access Portals".to_string(),
            query: format!(
                "site:{} (intitle:\"FortiGate SSL VPN Portal\" | intitle:\"Pulse Connect Secure\" | intitle:\"Citrix Gateway\" | intitle:\"GlobalProtect Portal\" | intitle:\"Remote Desktop Web Connection\" | inurl:/dana-na/ | inurl:/remote/login | inurl:/+CSCOE+/ | inurl:/global-protect/)",
                clean_domain
            ),
            description: "Find SSL-VPN and remote-access portals".to_string(),
            impact: "VPN appliances are top-tier targets - many have authentication-bypass CVEs".to_string(),
        });

        // GraphQL exposed endpoints / playgrounds
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/altair | inurl:/playground | inurl:/api/graphql)",
                clean_domain
            ),
            description: "Find GraphQL endpoints and playgrounds".to_string(),
            impact: "Exposed playgrounds usually mean enabled introspection - full schema disclosure".to_string(),
        });

        // Internal training / corporate LMS / wikis
        dorks.push(GoogleDork {
            category: "Internal Knowledge".to_string(),
            query: format!(
                "site:{} (inurl:/confluence | inurl:/wiki | inurl:/tableau | inurl:/sharepoint | intitle:\"Confluence\")",
                clean_domain
            ),
            description: "Find internal wikis and BI dashboards".to_string(),
            impact: "Open Confluence/wikis routinely expose runbooks and credentials".to_string(),
        });

        // AWS / GCP / Azure metadata leaks in error pages
        dorks.push(GoogleDork {
            category: "Cloud Metadata Leak".to_string(),
            query: format!(
                "site:{} (intext:\"AccessKeyId\" | intext:\"AccountId\" | intext:\"InstanceProfileArn\" | intext:\"SecretAccessKey\" | intext:\"169.254.169.254\")",
                clean_domain
            ),
            description: "Find pages leaking IMDS / cloud metadata".to_string(),
            impact: "IMDS leaks of temporary credentials lead directly to AWS account compromise".to_string(),
        });

        // Common breach paste sites (search by user accounts)
        dorks.push(GoogleDork {
            category: "Breach Mentions".to_string(),
            query: format!(
                "(site:ghostbin.com | site:rentry.co | site:paste.ee | site:gist.github.com | site:0bin.net) \"{}\"",
                clean_domain
            ),
            description: "Find paste-site mentions across more obscure platforms".to_string(),
            impact: "Pastes often contain credential dumps and internal URLs".to_string(),
        });

        // .DS_Store / Thumbs.db metadata files
        dorks.push(GoogleDork {
            category: "Metadata Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\".idea/\" | inurl:\".vscode/\" | inurl:\".project\" | inurl:\".classpath\")",
                clean_domain
            ),
            description: "Find IDE/OS metadata files exposing internal file structure".to_string(),
            impact: ".DS_Store and IDE metadata leak full server-side directory structure".to_string(),
        });

        // CI/CD config files exposed
        dorks.push(GoogleDork {
            category: "CI Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".gitlab-ci.yml\" | inurl:\".github/workflows\" | inurl:\".circleci/config.yml\" | inurl:\"Jenkinsfile\" | inurl:\"buildspec.yml\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.override.yml\")",
                clean_domain
            ),
            description: "Find CI/CD pipeline configurations".to_string(),
            impact: "Pipeline files routinely leak secrets, deploy targets, and infrastructure layout".to_string(),
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
