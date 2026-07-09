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

        // ---------------------------------------------------------------
        // Additional high-impact sensitive-data dorks
        // ---------------------------------------------------------------

        // Postman public workspaces — regularly leak API keys, bearer tokens,
        // internal hostnames, and full request/response history.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:postman.com \"{}\" (inurl:workspace | inurl:collection | inurl:documenter)",
                clean_domain
            ),
            description: "Find Postman workspaces, collections, and documenters mentioning the domain".to_string(),
            impact: "Public Postman assets frequently expose live API keys, bearer tokens, cookies, and internal endpoints in saved examples".to_string(),
        });

        // GitHub Gists — the classic dumping ground for one-off scripts with creds.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists mentioning the domain".to_string(),
            impact: "Gists are a common source of leaked credentials, .env dumps, and private scripts".to_string(),
        });

        // Public GitHub Actions workflow logs — often contain masked-but-echoed secrets.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com inurl:/actions/runs \"{}\"",
                clean_domain
            ),
            description: "Find public GitHub Actions runs referencing the domain".to_string(),
            impact: "Workflow logs may echo secrets, deploy tokens, or internal URLs".to_string(),
        });

        // Public S3 index listings scoped to the target.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "intitle:\"index of\" (site:s3.amazonaws.com | site:s3-website.amazonaws.com | site:storage.googleapis.com) \"{}\"",
                clean_domain
            ),
            description: "Find directory listings on cloud object storage referencing the domain".to_string(),
            impact: "Public bucket listings often expose backups, database dumps, and .env files".to_string(),
        });

        // Firebase Realtime Database — .json endpoint returns raw data when world-readable.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:firebaseio.com inurl:\".json\" \"{}\"",
                clean_domain
            ),
            description: "Find Firebase Realtime Database .json endpoints tied to the domain".to_string(),
            impact: "World-readable Firebase RTDB nodes dump full user/PII/token records with a single GET".to_string(),
        });

        // GCS bucket signed / raw links.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Find Google Cloud Storage objects referenced with the domain".to_string(),
            impact: "Publicly listed GCS objects may expose backups, exports, or PII documents".to_string(),
        });

        // Wasabi / Backblaze / Cloudflare R2 buckets — often forgotten in migrations.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.wasabisys.com | site:f000.backblazeb2.com | site:r2.dev | site:r2.cloudflarestorage.com) \"{}\"",
                clean_domain
            ),
            description: "Find objects on secondary S3-compatible providers (Wasabi, Backblaze B2, Cloudflare R2)".to_string(),
            impact: "Non-AWS buckets are frequently overlooked in cloud-security reviews and remain world-readable".to_string(),
        });

        // Firebase Storage — googleusercontent + firebasestorage host public objects with tokens in URL.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:firebasestorage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Find Firebase Storage objects referenced with the domain".to_string(),
            impact: "Firebase Storage URLs carry access tokens that grant read for the object's lifetime".to_string(),
        });

        // Exposed .git / .svn / .hg / .env at the webroot — the classic misconfig.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/config\" | inurl:\"/.svn/entries\" | inurl:\"/.hg/hgrc\" | inurl:\"/.env\" | inurl:\"/.aws/credentials\")",
                clean_domain
            ),
            description: "Find VCS metadata and dotfile credentials exposed at the webroot".to_string(),
            impact: "A single readable .git/config or .env commonly leads to full source disclosure or cloud takeover".to_string(),
        });

        // Backup archive extensions that ship database dumps and source snapshots.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} ext:sql | ext:dump | ext:sql.gz | ext:tar.gz | ext:tgz | ext:7z | ext:rar | ext:zip | ext:mdb | ext:mdf | ext:bak intitle:\"index of\"",
                clean_domain
            ),
            description: "Find publicly exposed archive/database dump files".to_string(),
            impact: "SQL/backup archives typically contain full PII sets and hashed or plaintext credentials".to_string(),
        });

        // WordPress diagnostic and installer files.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/wp-config.php.bak\" | inurl:\"/wp-config.php~\" | inurl:\"/wp-config.txt\" | inurl:\"/wp-content/debug.log\" | inurl:\"/wp-admin/install.php\")",
                clean_domain
            ),
            description: "Find WordPress backup and installer files".to_string(),
            impact: "wp-config backups contain DB credentials and secret keys; debug.log leaks stack traces and query text".to_string(),
        });

        // Laravel / Symfony / Django debug pages that ship secrets in the response.
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops! There was an error.\" | intext:\"Whoops, looks like something went wrong.\" | intext:\"DEBUG = True\" | intext:\"Symfony Profiler\" | inurl:\"/_profiler\" | inurl:\"/debug/default/view\")",
                clean_domain
            ),
            description: "Find framework debug pages (Laravel Whoops, Django DEBUG, Symfony Profiler, Yii debug)".to_string(),
            impact: "Debug pages routinely expose APP_KEY, database DSNs, environment variables, and full request context".to_string(),
        });

        // Exposed Spring Boot actuator endpoints.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/health\" | inurl:\"/actuator/loggers\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator endpoints leak env vars, memory dumps, route tables, and log configuration; heapdump gives credentials and sessions".to_string(),
        });

        // Prometheus / Grafana / Kibana / Jaeger public instances.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series Collection\" | intitle:\"Grafana\" | intitle:\"Kibana\" | intitle:\"Jaeger UI\")",
                clean_domain
            ),
            description: "Find exposed monitoring dashboards".to_string(),
            impact: "Open dashboards leak metrics, trace payloads, request bodies, and application internals".to_string(),
        });

        // Cloud IaaS console/dashboard links exposed via short URLs.
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "(site:console.aws.amazon.com | site:portal.azure.com | site:console.cloud.google.com) \"{}\"",
                clean_domain
            ),
            description: "Find cloud-console links referencing the domain".to_string(),
            impact: "Console links in public docs/support tickets can reveal account IDs, regions, and resource names".to_string(),
        });

        // Exposed environment/config files as plain text in doc / support portals.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY\" | intext:\"aws_secret_access_key\" | intext:\"AWS_SECRET_ACCESS_KEY\")",
                clean_domain
            ),
            description: "Find private keys and cloud secrets embedded in indexed pages".to_string(),
            impact: "Any hit on this dork is generally a Critical secret disclosure".to_string(),
        });

        // OAuth / JWT tokens accidentally indexed in docs, notebooks, or bug trackers.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"eyJhbGciOi\" | intext:\"Bearer eyJ\" | intext:\"xoxb-\" | intext:\"xoxp-\" | intext:\"ghp_\" | intext:\"gho_\" | intext:\"github_pat_\")",
                clean_domain
            ),
            description: "Find pages containing common token prefixes (JWT, Slack, GitHub PAT)".to_string(),
            impact: "Indexed tokens are almost always live and grant the linked account's privileges".to_string(),
        });

        // Notion / Coda / Airtable / Confluence / Miro / Figma public assets.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:notion.site | site:notion.so | site:coda.io | site:airtable.com | site:atlassian.net | site:miro.com | site:figma.com) \"{}\"",
                clean_domain
            ),
            description: "Find internal knowledge-base and collaboration content mentioning the domain".to_string(),
            impact: "Employees routinely publish runbooks, on-call docs, and credentials in \"unlisted\" workspaces that Google still indexes".to_string(),
        });

        // Public Confluence spaces on the target's own instance.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:{} (inurl:\"/wiki/spaces\" | inurl:\"/display/\" | inurl:\"/pages/viewpage.action\")",
                clean_domain
            ),
            description: "Find public Confluence spaces hosted on the target".to_string(),
            impact: "Confluence pages routinely expose SOPs, deploy runbooks, VPN details, and admin credentials".to_string(),
        });

        // SharePoint and OneDrive listings for the target.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:sharepoint.com | site:onedrive.live.com | site:my.sharepoint.com) \"{}\"",
                clean_domain
            ),
            description: "Find SharePoint / OneDrive content referencing the domain".to_string(),
            impact: "\"Anyone with the link\" SharePoint documents often contain internal reports and PII".to_string(),
        });

        // Slack workspaces / archives / search indexes.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:*.slack.com | site:archive.org inurl:slack) \"{}\"",
                clean_domain
            ),
            description: "Find Slack workspace URLs or archived content".to_string(),
            impact: "Leaked Slack URLs can lead to open-invite links, exported channel dumps, and integration tokens".to_string(),
        });

        // Public Google Colab notebooks — often contain hardcoded API keys for demos.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:colab.research.google.com \"{}\"", clean_domain),
            description: "Find shared Colab notebooks mentioning the domain".to_string(),
            impact: "Colab notebooks routinely embed cloud creds, dataset URLs, and internal endpoints".to_string(),
        });

        // Sentry / Bugsnag / Rollbar public issue trackers.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:sentry.io | site:app.bugsnag.com | site:rollbar.com) \"{}\"",
                clean_domain
            ),
            description: "Find public error-tracking dashboards for the domain".to_string(),
            impact: "Public error trackers surface stack traces, request payloads, session IDs, and PII".to_string(),
        });

        // Public CI/CD run outputs — CircleCI, Travis, Semaphore, Drone.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:app.circleci.com | site:travis-ci.org | site:travis-ci.com | site:app.wercker.com | site:cloud.drone.io) \"{}\"",
                clean_domain
            ),
            description: "Find public CI/CD build logs referencing the domain".to_string(),
            impact: "CI logs frequently expose secrets, deploy keys, artifact URLs, and internal hostnames".to_string(),
        });

        // Docker Hub / registry pages that expose internal image names.
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:hub.docker.com | site:quay.io) \"{}\"",
                clean_domain
            ),
            description: "Find public container images referencing the domain".to_string(),
            impact: "Public images often contain baked-in secrets, private code, and configuration".to_string(),
        });

        // npm / PyPI / RubyGems package pages tied to the domain (typosquat / abandoned).
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:npmjs.com/package | site:pypi.org/project | site:rubygems.org/gems) \"{}\"",
                clean_domain
            ),
            description: "Find published packages linked to the domain".to_string(),
            impact: "Abandoned or typo-squatted packages tied to the target can enable supply-chain attacks".to_string(),
        });

        // Public code search across Sourcegraph / grep.app.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:sourcegraph.com | site:grep.app | site:search.marginalia.nu) \"{}\"",
                clean_domain
            ),
            description: "Find code-search hits for the domain".to_string(),
            impact: "Broad code-search engines can turn up leaked source, config, and hard-coded secrets missed by GitHub search".to_string(),
        });

        // Exposed phpinfo() pages.
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" | intext:\"PHP Version\" intext:\"System\" intext:\"Configuration File (php.ini) Path\")",
                clean_domain
            ),
            description: "Find phpinfo() pages".to_string(),
            impact: "phpinfo output leaks server paths, env vars, module versions, and PHP internals used to plan follow-on attacks".to_string(),
        });

        // WSDL / SOAP / gRPC descriptors.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:asmx | inurl:\"?wsdl\" | inurl:\"?singleWsdl\" | inurl:\".proto\")",
                clean_domain
            ),
            description: "Find SOAP/gRPC service descriptors".to_string(),
            impact: "WSDL and .proto files enumerate methods, message types, and internal operations that bypass UI-level authorization".to_string(),
        });

        // GraphQL exploration endpoints commonly left on.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/altair\" | inurl:\"/voyager\" | intitle:\"GraphiQL\" | intitle:\"GraphQL Playground\")",
                clean_domain
            ),
            description: "Find exposed GraphQL playground / voyager UIs".to_string(),
            impact: "Playgrounds allow interactive schema introspection and query execution without authentication in many misconfigurations".to_string(),
        });

        // .DS_Store files reveal directory structure.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!("site:{} (inurl:\"/.DS_Store\" | inurl:\"Thumbs.db\")", clean_domain),
            description: "Find OS-level metadata files".to_string(),
            impact: ".DS_Store enumerates directory contents (including hidden files) and often reveals internal filenames".to_string(),
        });

        // Symfony / Rails / Node.js secrets.yml, credentials.yml.enc, .env.production
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\"/config/secrets.yml\" | inurl:\"/config/master.key\" | inurl:\"/config/credentials\" | inurl:\".env.production\" | inurl:\".env.local\" | inurl:\".env.development\")",
                clean_domain
            ),
            description: "Find framework-specific secret files".to_string(),
            impact: "Ruby master.key, Rails credentials, and Node .env.* files unlock every downstream secret".to_string(),
        });

        // Public Bitrix, Kentico, Sitecore admin/config paths.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/bitrix/admin\" | inurl:\"/CMSPages\" | inurl:\"/sitecore/login\" | inurl:\"/umbraco\")",
                clean_domain
            ),
            description: "Find enterprise CMS admin surfaces".to_string(),
            impact: "Bitrix/Sitecore/Umbraco panels have a long history of RCEs and default credentials".to_string(),
        });

        // Exposed developer tooling for debugging.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/debug/pprof\" | inurl:\"/rails/info/routes\" | inurl:\"/rails/info/properties\" | inurl:\"/telescope\" | inurl:\"/horizon\")",
                clean_domain
            ),
            description: "Find exposed pprof, Rails info, and Laravel Telescope/Horizon dashboards".to_string(),
            impact: "These dashboards leak profiling data, routes, queued jobs, and often full request payloads with tokens".to_string(),
        });

        // Public Elasticsearch/OpenSearch /_cat and /_cluster endpoints.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/_cat/indices\" | inurl:\"/_cluster/state\" | inurl:\"/_cluster/health\" | inurl:\"/_search\")",
                clean_domain
            ),
            description: "Find exposed Elasticsearch / OpenSearch endpoints".to_string(),
            impact: "Open ES/OS clusters allow direct data exfiltration of every indexed document".to_string(),
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
