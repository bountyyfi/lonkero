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

        // --- Exposed configuration & secret files (high-signal) ---
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:/.env intext:\"DB_PASSWORD\" | intext:\"APP_KEY=\" | intext:\"AWS_SECRET\" | intext:\"SECRET_KEY_BASE\"",
                clean_domain
            ),
            description: "Discover exposed .env files (Laravel/Rails/Node)".to_string(),
            impact: "CRITICAL: .env files typically contain database credentials, API keys, encryption keys and mail credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"/.git/config\" | inurl:\"/.git/HEAD\" | inurl:\"/.git/index\"",
                clean_domain
            ),
            description: "Discover exposed .git directories".to_string(),
            impact: "CRITICAL: Exposed .git enables full source-code disclosure and secret extraction.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"config.php\" intext:\"DB_PASSWORD\" | inurl:\"wp-config.php\" | inurl:\"configuration.php\" intext:\"$password\"",
                clean_domain
            ),
            description: "Discover PHP configuration files with credentials".to_string(),
            impact: "CRITICAL: WordPress/Joomla/generic PHP configs often ship DB credentials in plain text.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} filetype:properties intext:\"password=\" | filetype:properties intext:\"jdbc.\" | filetype:properties intext:\"spring.datasource\"",
                clean_domain
            ),
            description: "Discover exposed Java .properties files".to_string(),
            impact: "HIGH: Spring / Java application property files can leak datasource URLs and credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} filetype:yml intext:\"password:\" | filetype:yaml intext:\"private_key:\" | filetype:yml intext:\"secret_key_base\" | filetype:yaml intext:\"aws_access_key_id\"",
                clean_domain
            ),
            description: "Discover exposed YAML configuration files".to_string(),
            impact: "HIGH: application.yml / secrets.yml frequently embed API keys, DB URIs and signing secrets.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} filetype:xml intext:\"password\" | filetype:xml intext:\"web.xml\" | filetype:xml intext:\"jdbc\"",
                clean_domain
            ),
            description: "Discover exposed XML deployment descriptors".to_string(),
            impact: "web.xml / persistence.xml frequently expose datasource credentials and internal JNDI paths.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} filetype:json intext:\"aws_access_key_id\" | intext:\"aws_secret_access_key\" | intext:\"private_key\" | intext:\"service_account\"",
                clean_domain
            ),
            description: "Discover exposed JSON credential files".to_string(),
            impact: "CRITICAL: GCP service-account JSON and AWS credential files enable full cloud-account compromise.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\".DS_Store\" | inurl:\".idea/workspace.xml\" | inurl:\".vscode/settings.json\" | inurl:\"Thumbs.db\"",
                clean_domain
            ),
            description: "Discover exposed IDE / OS metadata files".to_string(),
            impact: ".DS_Store and IDE metadata enumerate internal directory structure; JetBrains workspaces often reveal server paths.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\".htpasswd\" | inurl:\".netrc\" | inurl:\".pgpass\" | inurl:\".my.cnf\" | inurl:\".npmrc\"",
                clean_domain
            ),
            description: "Discover exposed shell/user credential files".to_string(),
            impact: "CRITICAL: These files contain credentials for HTTP basic auth, mail, DB, npm publishing.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"docker-compose.yml\" | inurl:\"Dockerfile\" | inurl:\".dockerignore\"",
                clean_domain
            ),
            description: "Discover exposed Docker/Compose files".to_string(),
            impact: "docker-compose files often embed root passwords, registry credentials, and internal service hostnames.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\".terraform\" | filetype:tfstate | filetype:tfvars",
                clean_domain
            ),
            description: "Discover exposed Terraform state / tfvars".to_string(),
            impact: "CRITICAL: Terraform state files include secrets in plaintext and full infra topology.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"kubeconfig\" | inurl:\"kubectl.kubeconfig\" | filetype:yaml intext:\"kind: Secret\"",
                clean_domain
            ),
            description: "Discover exposed Kubernetes kubeconfig / Secret manifests".to_string(),
            impact: "CRITICAL: kubeconfig enables cluster-wide command execution; Secret manifests embed base64-encoded credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"id_rsa\" | inurl:\"id_ed25519\" | inurl:\"authorized_keys\" | filetype:pem intext:\"PRIVATE KEY\"",
                clean_domain
            ),
            description: "Discover exposed SSH / PEM private keys".to_string(),
            impact: "CRITICAL: SSH private keys and authorized_keys enable direct shell access.".to_string(),
        });

        // --- Backups & database dumps ---
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} ext:sql | ext:dbf | ext:mdb | ext:sqlite | ext:sqlitedb | ext:sqlite3 intext:\"INSERT INTO\" | intext:\"CREATE TABLE\"",
                clean_domain
            ),
            description: "Discover exposed SQL / database files".to_string(),
            impact: "CRITICAL: Full database dumps can expose all user records, hashes, and business data.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} ext:bak | ext:backup | ext:bkp | ext:swp | ext:save | ext:old | ext:orig | ext:temp | ext:tmp",
                clean_domain
            ),
            description: "Discover exposed backup files".to_string(),
            impact: "Backup files often expose source code and configuration frozen at a leak-worthy point in time.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z intitle:\"index of\"",
                clean_domain
            ),
            description: "Discover exposed archives on open directory listings".to_string(),
            impact: "Archive files on open indexes commonly contain full site backups.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} inurl:\"dump.sql\" | inurl:\"backup.sql\" | inurl:\"database.sql\" | inurl:\"db.sql\" | inurl:\"mysqldump\"",
                clean_domain
            ),
            description: "Discover exposed database dump names".to_string(),
            impact: "CRITICAL: Named database dumps regularly expose full production data.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} inurl:\"heapdump\" | filetype:hprof | inurl:\"core.\" | inurl:\"crashdump\"",
                clean_domain
            ),
            description: "Discover exposed heap / core dumps".to_string(),
            impact: "HIGH: Heap/core dumps leak in-memory credentials, tokens, and PII.".to_string(),
        });

        // --- Directory listings ---
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" | intitle:\"index of /backup\" | intitle:\"index of /db\" | intitle:\"index of /uploads\" | intitle:\"index of /admin\"",
                clean_domain
            ),
            description: "Discover exposed Apache/Nginx directory listings".to_string(),
            impact: "Open index pages routinely expose backups, uploads, and internal artifacts.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" \"parent directory\" ( \".env\" | \"config\" | \"backup\" | \"private\" | \"secret\" )",
                clean_domain
            ),
            description: "Discover directory listings containing high-value filenames".to_string(),
            impact: "Directly points to reachable sensitive files.".to_string(),
        });

        // --- Actuator / management / diagnostic endpoints ---
        dorks.push(GoogleDork {
            category: "Actuator / Debug".to_string(),
            query: format!(
                "site:{} inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/beans\"",
                clean_domain
            ),
            description: "Discover exposed Spring Boot Actuator endpoints".to_string(),
            impact: "CRITICAL: /env leaks secrets; /heapdump leaks in-memory credentials; /mappings enumerates full API surface.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Actuator / Debug".to_string(),
            query: format!(
                "site:{} inurl:\"trace.axd\" | inurl:\"elmah.axd\" | inurl:\"errorlog.axd\" | inurl:\"handler.aspx\"",
                clean_domain
            ),
            description: "Discover exposed ASP.NET diagnostic handlers".to_string(),
            impact: "HIGH: elmah/trace.axd leak full request logs (cookies, tokens) unauthenticated by default.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Actuator / Debug".to_string(),
            query: format!(
                "site:{} inurl:\"/_ah/api/explorer\" | inurl:\"/_ah/stats\" | inurl:\"/_ah/logs\"",
                clean_domain
            ),
            description: "Discover exposed Google App Engine admin endpoints".to_string(),
            impact: "App Engine internal endpoints can leak deployment info and logs.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Actuator / Debug".to_string(),
            query: format!(
                "site:{} inurl:\"/manager/html\" | inurl:\"/host-manager\" | inurl:\"/jmx-console\" | inurl:\"/web-console\"",
                clean_domain
            ),
            description: "Discover exposed Tomcat / JBoss admin consoles".to_string(),
            impact: "CRITICAL: Default-credentialled Tomcat/JBoss admin allows WAR deploy = RCE.".to_string(),
        });

        // --- CI/CD & source ecosystem leaks ---
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" site:travis-ci.com | site:travis-ci.org intext:\"env\" intext:\"SECRET\"",
                clean_domain
            ),
            description: "Discover exposed Travis CI build logs".to_string(),
            impact: "Public Travis logs frequently leak build-time secrets.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" site:circleci.com/gh | site:circleci.com/bb",
                clean_domain
            ),
            description: "Discover public CircleCI project pages".to_string(),
            impact: "Public CircleCI orgs expose build history and sometimes artifacts.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" site:github.com filename:.env | filename:credentials | filename:.pgpass | filename:.htpasswd | filename:.dockercfg",
                clean_domain
            ),
            description: "GitHub code search - config/credential filenames referencing target".to_string(),
            impact: "Public repos with target-matching credential filenames commonly leak live keys.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" site:github.com ( \"api_key\" | \"apikey\" | \"secret_key\" | \"access_key\" | \"BEGIN RSA PRIVATE KEY\" )",
                clean_domain
            ),
            description: "GitHub code search - inline secrets referencing target".to_string(),
            impact: "Locates leaked keys tied to the target org across public repos.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" site:gitlab.com ( \"private_token\" | \"api_key\" | \"CI_JOB_TOKEN\" )",
                clean_domain
            ),
            description: "GitLab code search - token leaks referencing target".to_string(),
            impact: "GitLab CI job tokens can grant repo/pipeline access.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:bitbucket.org/snippets | site:snippets.gitlab.com | site:gist.github.com )",
                clean_domain
            ),
            description: "Discover public snippets referencing target".to_string(),
            impact: "Snippets commonly host \"quick tests\" containing live credentials.".to_string(),
        });

        // --- Public SaaS knowledge / collaboration leaks ---
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:notion.site | site:notion.so | site:www.notion.so )",
                clean_domain
            ),
            description: "Discover public Notion pages referencing target".to_string(),
            impact: "Notion pages set public often expose internal docs, runbooks, and credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" site:atlassian.net ( inurl:/wiki | inurl:/jira )",
                clean_domain
            ),
            description: "Discover public Atlassian Confluence / Jira spaces".to_string(),
            impact: "Public Confluence pages leak architecture diagrams and credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:coda.io | site:miro.com | site:app.diagrams.net )",
                clean_domain
            ),
            description: "Discover public Coda / Miro / draw.io documents".to_string(),
            impact: "Publicly shared design docs often expose systems architecture.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:airtable.com | site:public.tableau.com )",
                clean_domain
            ),
            description: "Discover exposed Airtable / Tableau workbooks".to_string(),
            impact: "Public data workbooks often leak customer data or KPI dashboards.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:linear.app/team | site:linear.app/document )",
                clean_domain
            ),
            description: "Discover public Linear team pages".to_string(),
            impact: "Public Linear docs may expose roadmap / security context.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:postman.co | site:documenter.getpostman.com | site:postman.com/workspaces )",
                clean_domain
            ),
            description: "Discover public Postman workspaces / collections".to_string(),
            impact: "Public Postman collections often contain valid API keys and admin endpoints.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:loom.com/share | site:vimeo.com )",
                clean_domain
            ),
            description: "Discover public Loom / Vimeo screen recordings".to_string(),
            impact: "Publicly-shared screen recordings routinely capture credentials mid-workflow.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "SaaS Leaks".to_string(),
            query: format!(
                "\"{}\" ( site:pastebin.com | site:ghostbin.co | site:hastebin.com | site:controlc.com | site:paste.ee )",
                clean_domain
            ),
            description: "Discover expanded paste-site mentions of target".to_string(),
            impact: "Paste sites are the most common leak destination for stolen credentials and dumps.".to_string(),
        });

        // --- Firebase / cloud realtime DB ---
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" ( site:firebaseio.com | site:firebasestorage.googleapis.com )",
                clean_domain
            ),
            description: "Firebase RTDB / Storage buckets referencing target".to_string(),
            impact: "Misconfigured Firebase rules commonly expose full DB read/write.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" site:appspot.com",
                clean_domain
            ),
            description: "Google App Engine deployments referencing target".to_string(),
            impact: "AppSpot staging deployments frequently lack production auth.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" ( site:elasticbeanstalk.com | site:cloudfront.net | site:execute-api.amazonaws.com )",
                clean_domain
            ),
            description: "AWS-hosted assets referencing target".to_string(),
            impact: "Direct execute-api / EB URLs bypass WAF/CDN and often expose staging APIs.".to_string(),
        });

        // --- Webhooks & DSNs leaked in public content ---
        dorks.push(GoogleDork {
            category: "Webhook Leaks".to_string(),
            query: format!(
                "\"{}\" ( \"hooks.slack.com/services/\" | \"discord.com/api/webhooks\" | \"outlook.office.com/webhook\" )",
                clean_domain
            ),
            description: "Discover leaked chat webhooks referencing target".to_string(),
            impact: "Chat webhooks allow attacker-controlled phishing messages into internal channels.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Webhook Leaks".to_string(),
            query: format!(
                "\"{}\" \"@sentry.io/\" | \"ingest.sentry.io\"",
                clean_domain
            ),
            description: "Discover leaked Sentry DSNs referencing target".to_string(),
            impact: "Sentry DSN exposure can enable event forging and (rarely) org-level access.".to_string(),
        });

        // --- Log / error / stack-trace disclosures ---
        dorks.push(GoogleDork {
            category: "Log Disclosure".to_string(),
            query: format!(
                "site:{} filetype:log ( intext:\"password\" | intext:\"authorization\" | intext:\"stack trace\" | intext:\"caused by\" )",
                clean_domain
            ),
            description: "Discover exposed application log files".to_string(),
            impact: "Log files routinely contain full auth headers, session cookies, and PII.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Log Disclosure".to_string(),
            query: format!(
                "site:{} inurl:\"debug=true\" | inurl:\"whoops\" | intext:\"Whoops! There was an error\" | intext:\"Werkzeug Debugger\" | intext:\"Symfony Profiler\"",
                clean_domain
            ),
            description: "Discover debug-mode enabled applications".to_string(),
            impact: "CRITICAL: Werkzeug/Symfony debug consoles offer RCE; Whoops leaks source and env.".to_string(),
        });

        // --- Third-party sensitive-doc surfaces ---
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:{} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx intext:\"internal\" | intext:\"restricted\" | intext:\"confidential\" | intext:\"NDA\"",
                clean_domain
            ),
            description: "Discover published documents marked as internal/restricted".to_string(),
            impact: "Marked-internal documents on public webroot are almost always misuploaded.".to_string(),
        });

        // --- Auth & identity provider misconfigs ---
        dorks.push(GoogleDork {
            category: "Auth Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\".well-known/openid-configuration\" | inurl:\".well-known/oauth-authorization-server\" | inurl:\"/oauth/authorize\"",
                clean_domain
            ),
            description: "Discover exposed OIDC / OAuth2 discovery endpoints".to_string(),
            impact: "OIDC discovery documents enable client enumeration and often expose non-production issuers.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Auth Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"/saml/metadata\" | inurl:\"/adfs/ls/\" | inurl:\"/simplesaml/\"",
                clean_domain
            ),
            description: "Discover exposed SAML metadata / ADFS / SimpleSAMLphp endpoints".to_string(),
            impact: "SAML metadata identifies IdP relationships and may leak signing certificates.".to_string(),
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
