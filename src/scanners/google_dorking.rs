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

        // Atlassian Confluence (cloud and self-hosted) wikis and Jira tickets
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:atlassian.net \"{}\" | site:jira.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find publicly indexed Atlassian Confluence pages and Jira tickets"
                .to_string(),
            impact: "Public Confluence pages and Jira tickets routinely leak credentials, internal architecture, customer data, and reproduction steps for unpatched issues."
                .to_string(),
        });

        // Notion shared workspaces
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:notion.site \"{}\" | site:notion.so \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find publicly shared Notion pages referencing the domain".to_string(),
            impact: "Public Notion workspaces often contain runbooks, on-call rotations, internal docs, and embedded secrets.".to_string(),
        });

        // Postman public collections and workspaces
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com \"{}\" | site:documenter.getpostman.com \"{}\" | site:explore.postman.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find published Postman collections, workspaces, and documenter pages."
                .to_string(),
            impact: "Public Postman collections commonly embed API keys, bearer tokens, and full unauthenticated request examples for production endpoints.".to_string(),
        });

        // SwaggerHub published API specs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!("site:app.swaggerhub.com \"{}\"", clean_domain),
            description: "Find SwaggerHub-published OpenAPI specifications".to_string(),
            impact: "Public OpenAPI specs reveal full endpoint inventory, authentication schemes, and request shapes for the API.".to_string(),
        });

        // ReadMe.io developer hubs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!("site:readme.io \"{}\"", clean_domain),
            description: "Find developer documentation hosted on ReadMe.io".to_string(),
            impact: "ReadMe.io hubs often expose private API references that were intended for partner-only access.".to_string(),
        });

        // Stack Overflow exposures (questions sometimes paste real tokens)
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:stackoverflow.com \"{}\" (\"api_key\" OR \"apikey\" OR \"bearer\" OR \"x-api-key\" OR \"authorization:\")",
                clean_domain
            ),
            description: "Find StackOverflow questions mentioning the domain alongside auth tokens"
                .to_string(),
            impact: "Developers regularly paste real production tokens, cookies, and bearer headers into StackOverflow questions when troubleshooting.".to_string(),
        });

        // Reddit mentions (often discloses incidents and internal tooling)
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:reddit.com \"{}\"", clean_domain),
            description: "Find Reddit discussions mentioning the domain".to_string(),
            impact: "Reddit posts (especially r/sysadmin, r/devops, r/cscareerquestions) frequently leak internal tooling, incident details, and screenshots of dashboards."
                .to_string(),
        });

        // GitHub Gists - extremely common credential-leak surface
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists referencing the domain".to_string(),
            impact: "Gists are routinely used as a quick paste target by developers and frequently contain secrets, internal URLs, and database dumps.".to_string(),
        });

        // GitHub raw content (often indexed individually)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:raw.githubusercontent.com \"{}\" (BEGIN | API_KEY | password | token | secret)",
                clean_domain
            ),
            description: "Find raw GitHub file content mentioning the domain near credential keywords"
                .to_string(),
            impact: "Direct raw.githubusercontent.com hits combined with credential keywords are high-signal for accidentally committed secrets.".to_string(),
        });

        // BitBucket Snippets and repositories
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:bitbucket.org \"{}\" | site:bitbucket.io \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find BitBucket repositories and snippets".to_string(),
            impact: "BitBucket Snippets are the equivalent of GitHub Gists and often contain credentials and internal scripts.".to_string(),
        });

        // SourceGraph public code search
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:sourcegraph.com \"{}\"", clean_domain),
            description: "Find code search results referencing the domain on Sourcegraph.com"
                .to_string(),
            impact: "Sourcegraph indexes far more repositories than appear on GitHub search; hits often point at archived or fork-only secret leaks."
                .to_string(),
        });

        // Linear and Asana public boards
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:linear.app \"{}\" | site:asana.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Linear or Asana public project pages".to_string(),
            impact: "Public project trackers expose engineering priorities, vulnerability tickets, and customer escalations."
                .to_string(),
        });

        // Hugging Face spaces (frequently leak API keys via Gradio apps)
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:huggingface.co \"{}\"", clean_domain),
            description: "Find Hugging Face Spaces or models referencing the domain".to_string(),
            impact: "Hugging Face Spaces often embed credentials in `app.py` or `.env` files and proxy requests to internal APIs.".to_string(),
        });

        // Docker Hub - leaked internal images
        dorks.push(GoogleDork {
            category: "Container Images".to_string(),
            query: format!("site:hub.docker.com \"{}\"", clean_domain),
            description: "Find Docker Hub images referencing the domain".to_string(),
            impact: "Internal Docker images pushed to a public namespace expose source code, baked-in secrets, and environment configuration."
                .to_string(),
        });

        // Quay.io container registry
        dorks.push(GoogleDork {
            category: "Container Images".to_string(),
            query: format!("site:quay.io \"{}\"", clean_domain),
            description: "Find Quay.io container images referencing the domain".to_string(),
            impact: "Public Quay.io images frequently contain proprietary application code and embedded credentials.".to_string(),
        });

        // npm and PyPI - typosquat or company-namespace packages
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "site:npmjs.com \"{}\" | site:pypi.org \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find npm or PyPI packages referencing the domain".to_string(),
            impact: "Internal packages accidentally published publicly typically contain source code, build configuration, and registry credentials."
                .to_string(),
        });

        // Wayback Machine - historical snapshots of removed files
        dorks.push(GoogleDork {
            category: "Historical Data".to_string(),
            query: format!("site:web.archive.org \"{}\"", clean_domain),
            description: "Find Wayback Machine snapshots of the domain".to_string(),
            impact: "Removed pages, leaked file listings, and old admin endpoints often remain accessible via the Wayback Machine.".to_string(),
        });

        // Censys / Shodan historical mentions
        dorks.push(GoogleDork {
            category: "Asset Intelligence".to_string(),
            query: format!(
                "site:censys.io \"{}\" | site:shodan.io \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Censys and Shodan host pages for the domain".to_string(),
            impact: "Search-engine asset databases enumerate IPs, certificates, exposed services, and banner-disclosed software versions for the target."
                .to_string(),
        });

        // CRT.sh certificate transparency
        dorks.push(GoogleDork {
            category: "Asset Intelligence".to_string(),
            query: format!("site:crt.sh \"{}\"", clean_domain),
            description: "Find certificate transparency log entries".to_string(),
            impact: "Certificate transparency exposes every subdomain ever issued a TLS certificate, often including internal/staging hostnames.".to_string(),
        });

        // VirusTotal historical relationships
        dorks.push(GoogleDork {
            category: "Asset Intelligence".to_string(),
            query: format!("site:virustotal.com \"{}\"", clean_domain),
            description: "Find VirusTotal entries referencing the domain".to_string(),
            impact: "VirusTotal aggregates passive DNS, observed URLs, and file submissions related to the domain — a rich recon corpus."
                .to_string(),
        });

        // Cloud bucket listings indexed by Google
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(intitle:\"Index of\" | intitle:\"Bucket loot\") (\"{}\" OR \"backup\" OR \".sql\" OR \".env\" OR \"credentials\") site:storage.googleapis.com | site:s3.amazonaws.com",
                clean_domain
            ),
            description: "Find publicly listed cloud-bucket index pages".to_string(),
            impact: "Directory listings on S3/GCS buckets are a high-signal indicator of full bucket read access and frequently expose database dumps, backups, and `.env` files."
                .to_string(),
        });

        // Git-history exposure on the live site
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.git/HEAD | inurl:.git/config | inurl:.svn/entries | inurl:.hg/store | inurl:.DS_Store)",
                clean_domain
            ),
            description: "Find exposed VCS metadata that allows full source-tree reconstruction"
                .to_string(),
            impact: "Exposed `.git/`, `.svn/`, or `.hg/` directories let an attacker reconstruct the entire source code and configuration history of the application.".to_string(),
        });

        // Environment files served by web roots
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.bak | inurl:web.config | inurl:appsettings.json | inurl:application.yml | inurl:application.properties)",
                clean_domain
            ),
            description: "Find dotenv and framework-configuration files served from the web root"
                .to_string(),
            impact: "These files almost universally contain database credentials, API keys, signing secrets, and full infrastructure configuration.".to_string(),
        });

        // CI/CD artifacts and pipeline configs
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.github/workflows | inurl:.gitlab-ci.yml | inurl:bitbucket-pipelines.yml | inurl:Jenkinsfile | inurl:azure-pipelines.yml | inurl:buildspec.yml)",
                clean_domain
            ),
            description: "Find CI/CD pipeline definitions exposed via the web root".to_string(),
            impact: "Pipeline files reveal the build, test, deploy chain and often reference (or embed) registry credentials, signing keys, and deploy tokens.".to_string(),
        });

        // Database dumps and SQL artifacts
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:rdb | ext:bson | inurl:dump.sql | inurl:backup.sql | inurl:database.sql)",
                clean_domain
            ),
            description: "Find database dumps and backup artifacts indexed on the target"
                .to_string(),
            impact: "Indexed `.sql`/`.dump`/`.rdb` files typically contain complete database snapshots including PII, password hashes, and session data.".to_string(),
        });

        // Private/internal key material
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:p12 | ext:pfx | ext:jks | ext:keystore | inurl:id_rsa | inurl:id_ed25519)",
                clean_domain
            ),
            description: "Find private-key material exposed under the target domain".to_string(),
            impact: "Exposed private keys allow TLS impersonation, signing forgery (JWT, S/MIME), and direct host access via SSH.".to_string(),
        });

        // Heap dumps and core files
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:hprof | ext:phd | ext:dmp | inurl:heapdump | inurl:threaddump | inurl:core.)",
                clean_domain
            ),
            description: "Find application heap/core dumps".to_string(),
            impact: "Heap and core dumps contain in-memory secrets (session tokens, decrypted DB credentials, encryption keys) at the time of capture.".to_string(),
        });

        // Spring Boot Actuator and similar internal management endpoints
        dorks.push(GoogleDork {
            category: "Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/loggers | inurl:/actuator/configprops | inurl:/actuator/beans | inurl:/actuator/mappings)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Unauthenticated Actuator endpoints expose environment variables, in-memory secrets, full configuration, and heap dumps — often a direct path to credential theft."
                .to_string(),
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
