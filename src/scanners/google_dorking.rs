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

        // ------------------------------------------------------------------
        // Exposed environment / configuration files
        //
        // Anchored on `intext:` strings that only appear inside live config
        // files, so a hit on Google's index is a real exposure — not a code
        // sample or documentation page.
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Exposed Env Files".to_string(),
            query: format!(
                "site:{} ext:env | ext:envrc | inurl:.env intext:DB_PASSWORD | intext:APP_KEY | intext:SECRET_KEY | intext:AWS_SECRET_ACCESS_KEY",
                clean_domain
            ),
            description: "Find indexed .env files containing live secrets".to_string(),
            impact: "Indexed .env files almost always contain DB credentials, signing keys, and cloud access keys.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Env Files".to_string(),
            query: format!(
                "site:{} (inurl:\".env.local\" | inurl:\".env.prod\" | inurl:\".env.production\" | inurl:\".env.development\" | inurl:\".env.backup\" | inurl:\".env.bak\" | inurl:\".env.example\" intext:SECRET)",
                clean_domain
            ),
            description: "Find environment-specific dotfiles served by the web root".to_string(),
            impact: "Production/local env files frequently differ from .env.example and contain real credentials.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php | inurl:wp-config.php.bak | inurl:wp-config.txt | inurl:wp-config.old) intext:DB_PASSWORD",
                clean_domain
            ),
            description: "WordPress config exposures with live DB credentials".to_string(),
            impact: "wp-config.php contains DB user/pass and WordPress auth/nonce salts — full site takeover.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:web.config | inurl:appsettings.json | inurl:appsettings.Production.json | inurl:appsettings.Development.json) intext:ConnectionString",
                clean_domain
            ),
            description: ".NET application config with connection strings".to_string(),
            impact: "appsettings/web.config typically carry DB connection strings and signing keys.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:application.yml | inurl:application.properties | inurl:application-prod.yml | inurl:bootstrap.yml) intext:password | intext:datasource.url",
                clean_domain
            ),
            description: "Spring Boot configuration files exposed".to_string(),
            impact: "application.yml/properties leak DB JDBC URLs with credentials, Redis hosts, JWT secrets.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:database.yml | inurl:secrets.yml | inurl:credentials.yml.enc | inurl:master.key) intext:password",
                clean_domain
            ),
            description: "Rails configuration files exposed".to_string(),
            impact: "Rails database.yml + master.key allows full decryption of credentials.yml.enc.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:settings.py intext:SECRET_KEY | inurl:local_settings.py intext:DATABASES)",
                clean_domain
            ),
            description: "Django settings files exposed".to_string(),
            impact: "settings.py exposes SECRET_KEY (signs session cookies, password reset tokens) and DB config.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.prod.yml | inurl:docker-compose.override.yml) intext:environment | intext:PASSWORD",
                clean_domain
            ),
            description: "docker-compose with embedded credentials".to_string(),
            impact: "Compose files leak service credentials, registry tokens, and internal hostnames.".to_string(),
        });

        // ------------------------------------------------------------------
        // Exposed source-control directories
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Exposed Source Control".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/config\" | inurl:\"/.git/HEAD\" | inurl:\"/.git/logs/HEAD\" | inurl:\"/.gitignore\" intext:\".env\")",
                clean_domain
            ),
            description: "Indexed .git/ metadata indicates a fully reconstructable repo".to_string(),
            impact: "Exposed .git/ allows full source-code reconstruction (git-dumper) including history/secrets.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Source Control".to_string(),
            query: format!(
                "site:{} (inurl:\"/.svn/entries\" | inurl:\"/.svn/wc.db\" | inurl:\"/.hg/store\" | inurl:\"/.bzr/branch-format\" | inurl:CVS/Entries)",
                clean_domain
            ),
            description: "Indexed SVN/Mercurial/Bazaar/CVS metadata".to_string(),
            impact: "Same impact as exposed .git/ — repo reconstructable from metadata.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Source Control".to_string(),
            query: format!(
                "site:{} (inurl:\"/.DS_Store\" | inurl:\"Thumbs.db\")",
                clean_domain
            ),
            description: "Filesystem metadata leakage (directory listings)".to_string(),
            impact: "DS_Store/Thumbs.db enumerate hidden files in deployed directories.".to_string(),
        });

        // ------------------------------------------------------------------
        // Database dumps and backups
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"-- MySQL dump\" | intext:\"PostgreSQL database dump\"",
                clean_domain
            ),
            description: "Find SQL dumps containing actual table data".to_string(),
            impact: "Full database content disclosure including users, password hashes, and PII.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:dump | ext:dmp | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb | ext:ldif | ext:ldb | ext:bak intext:CREATE)",
                clean_domain
            ),
            description: "Binary database files left in web root".to_string(),
            impact: "SQLite/MDB/LDIF dumps can be downloaded and queried offline — bulk PII exposure.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z | ext:gz) (inurl:backup | inurl:bak | inurl:old | inurl:dump | inurl:archive | inurl:site)",
                clean_domain
            ),
            description: "Archive files in backup-style paths".to_string(),
            impact: "Web-root backup archives commonly leak full site source, configs, and DB exports.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (inurl:backup.zip | inurl:website.zip | inurl:site.zip | inurl:source.zip | inurl:src.zip | inurl:www.zip | inurl:html.zip | inurl:public.zip | inurl:wwwroot.zip)",
                clean_domain
            ),
            description: "Common 'whole site' backup filenames".to_string(),
            impact: "These exact filenames are routinely created by developers and forgotten in the web root.".to_string(),
        });

        // ------------------------------------------------------------------
        // Private key material exposed
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Private Keys / Certificates".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:asc) intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\"",
                clean_domain
            ),
            description: "PEM-armored private key material indexed by Google".to_string(),
            impact: "Exposed private keys = direct compromise (SSH, TLS, code-signing, GPG, JWT-RS256).".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Private Keys / Certificates".to_string(),
            query: format!(
                "site:{} (ext:pfx | ext:p12 | ext:jks | ext:keystore | ext:bks)",
                clean_domain
            ),
            description: "Binary keystore files (PKCS#12, Java KeyStore)".to_string(),
            impact: "Keystores often ship with weak/known passwords ('changeit', 'password') — full TLS key extraction.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Private Keys / Certificates".to_string(),
            query: format!(
                "site:{} (inurl:id_rsa | inurl:id_dsa | inurl:id_ed25519 | inurl:id_ecdsa | inurl:authorized_keys | inurl:known_hosts)",
                clean_domain
            ),
            description: "SSH key material at default filenames".to_string(),
            impact: "id_rsa exposure is immediate lateral movement; authorized_keys reveals trusted accesses.".to_string(),
        });

        // ------------------------------------------------------------------
        // Log files (often contain sessions, tokens, stack traces)
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | ext:txt | inurl:error_log | inurl:debug.log | inurl:access.log | inurl:laravel.log | inurl:storage/logs) intext:\"Authorization: Bearer\" | intext:Exception | intext:Traceback | intext:\"set-cookie:\"",
                clean_domain
            ),
            description: "Indexed log files leaking tokens, sessions, or stack traces".to_string(),
            impact: "Logs commonly include live Bearer tokens, session IDs, and queries with PII.".to_string(),
        });

        // ------------------------------------------------------------------
        // API specs / introspection (defines the entire attack surface)
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "API Specifications".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:swagger.yaml | inurl:openapi.json | inurl:openapi.yaml | inurl:api-docs.json | inurl:v3/api-docs)",
                clean_domain
            ),
            description: "Raw OpenAPI/Swagger specifications".to_string(),
            impact: "Spec files enumerate every endpoint, parameter, auth scheme — a complete attack-surface map.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Specifications".to_string(),
            query: format!(
                "site:{} (inurl:postman_collection.json | inurl:postman_environment.json | inurl:collection.json intext:\"_postman_id\")",
                clean_domain
            ),
            description: "Leaked Postman collections / environments".to_string(),
            impact: "Postman exports frequently contain working API keys and example PII payloads.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Specifications".to_string(),
            query: format!(
                "site:{} (inurl:graphql intext:\"__schema\" | inurl:playground | inurl:graphiql)",
                clean_domain
            ),
            description: "GraphQL playgrounds / introspection responses indexed".to_string(),
            impact: "Indexed introspection reveals types/fields including admin mutations.".to_string(),
        });

        // ------------------------------------------------------------------
        // Exposed CI / DevOps state
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Exposed CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:.travis.yml | inurl:.gitlab-ci.yml | inurl:bitbucket-pipelines.yml | inurl:.circleci/config.yml | inurl:Jenkinsfile | inurl:azure-pipelines.yml) intext:secret | intext:token | intext:AWS_",
                clean_domain
            ),
            description: "CI pipeline files referencing in-tree secrets".to_string(),
            impact: "Pipeline YAMLs frequently embed deploy keys, registry creds, or printf-leaked secrets.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:.terraform | inurl:terraform.tfstate | inurl:terraform.tfstate.backup | inurl:.tfvars)",
                clean_domain
            ),
            description: "Terraform state and variable files".to_string(),
            impact: "tfstate contains plaintext values for every resource including DB passwords and access keys.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:.npmrc intext:_authToken | inurl:.pypirc intext:password | inurl:.dockercfg | inurl:.docker/config.json intext:auth)",
                clean_domain
            ),
            description: "Package-registry auth files exposed".to_string(),
            impact: ".npmrc/.pypirc auth tokens enable malicious package publishing — supply-chain compromise.".to_string(),
        });

        // ------------------------------------------------------------------
        // Exposed admin / management consoles
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin | inurl:pma | inurl:dbadmin | inurl:adminer.php | inurl:websql | intitle:\"phpMyAdmin\")",
                clean_domain
            ),
            description: "Database admin UIs (phpMyAdmin / Adminer)".to_string(),
            impact: "Indexed login pages are credential-attack targets; misconfigured instances skip auth entirely.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/manager/html intitle:\"Tomcat\" | inurl:/host-manager/html | inurl:/jmx-console | inurl:/web-console)",
                clean_domain
            ),
            description: "Tomcat / JBoss management consoles".to_string(),
            impact: "Tomcat Manager with default tomcat/tomcat creds = RCE via WAR upload.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/mappings | inurl:/actuator/configprops | inurl:/actuator/loggers)",
                clean_domain
            ),
            description: "Spring Boot Actuator endpoints exposed".to_string(),
            impact: "/actuator/env leaks property values incl. secrets; /heapdump enables credential extraction from memory.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Jenkins\" inurl:/script | inurl:/manage | inurl:/asynchPeople | inurl:/jenkins intitle:Dashboard)",
                clean_domain
            ),
            description: "Jenkins script consoles / dashboards".to_string(),
            impact: "Jenkins /script with anonymous read = Groovy RCE; /asynchPeople enumerates users.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:/login | intitle:\"Kibana\" | intitle:\"Prometheus Time Series\" | intitle:\"Alertmanager\")",
                clean_domain
            ),
            description: "Observability stack consoles (Grafana / Kibana / Prometheus)".to_string(),
            impact: "Often unauthenticated reads — full log/metric exfiltration; CVE-2021-43798 etc. on older Grafana.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Apache Solr\" inurl:/admin | inurl:/solr/#/ | intitle:\"Elasticsearch\" inurl:_cat | inurl:_search?pretty)",
                clean_domain
            ),
            description: "Solr / Elasticsearch admin endpoints".to_string(),
            impact: "Unauthenticated _search returns documents; Solr admin has historic RCE (CVE-2019-17558).".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | inurl:/rabbitmq | intitle:\"Apache Airflow\" | inurl:/airflow | intitle:\"Argo CD\")",
                clean_domain
            ),
            description: "Message-broker / workflow consoles".to_string(),
            impact: "Default guest/guest credentials on RabbitMQ; Airflow connections often hold prod DB creds.".to_string(),
        });

        // ------------------------------------------------------------------
        // Cloud metadata / signed-URL leakage
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Cloud Credentials Leakage".to_string(),
            query: format!(
                "site:{} (intext:\"AKIA\" intext:\"aws_secret_access_key\" | intext:\"X-Amz-Signature=\" intext:\"X-Amz-Credential=\")",
                clean_domain
            ),
            description: "Pages or files containing AWS access keys or presigned URLs".to_string(),
            impact: "AKIA + secret = full IAM principal compromise; presigned URLs often grant write access.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Credentials Leakage".to_string(),
            query: format!(
                "site:{} intext:\"-----BEGIN PRIVATE KEY-----\" intext:\"service_account\" intext:\"client_email\" intext:\"private_key_id\"",
                clean_domain
            ),
            description: "GCP service-account JSON files indexed".to_string(),
            impact: "Service-account JSON is a passwordless GCP credential — full project access.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Credentials Leakage".to_string(),
            query: format!(
                "site:{} (intext:\"DefaultEndpointsProtocol=https;AccountName=\" intext:\"AccountKey=\")",
                clean_domain
            ),
            description: "Azure Storage account connection strings".to_string(),
            impact: "AccountKey is a master credential for the storage account — read/write/delete on all blobs.".to_string(),
        });

        // ------------------------------------------------------------------
        // Source-code paste / search engines
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Code Leaks (extended)".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" (password | api_key | secret | token | BEGIN | AKIA)",
                clean_domain
            ),
            description: "Gists referencing the target with credential indicators".to_string(),
            impact: "Public gists routinely contain real credentials checked in during debugging.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks (extended)".to_string(),
            query: format!(
                "site:searchcode.com \"{}\" | site:grep.app \"{}\" | site:publicwww.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Code search engines indexing references to the domain".to_string(),
            impact: "Wider net than GitHub — catches mirrors and self-hosted Gitea/Forgejo instances.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks (extended)".to_string(),
            query: format!(
                "site:scribd.com \"{}\" | site:slideshare.net \"{}\" | site:academia.edu \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Document-sharing platforms hosting internal materials".to_string(),
            impact: "Internal runbooks, architecture docs, and credentials end up on these sites.".to_string(),
        });

        // ------------------------------------------------------------------
        // PII / regulatory exposure
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "PII / Regulated Data".to_string(),
            query: format!(
                "site:{} (intext:\"SSN:\" | intext:\"Social Security Number\" | intext:\"date of birth\" intext:\"@\" | intext:\"passport\" intext:\"DOB\")",
                clean_domain
            ),
            description: "Pages referencing US PII identifiers".to_string(),
            impact: "Bulk PII exposure triggers regulatory notification (GDPR/CCPA/HIPAA).".to_string(),
        });

        dorks.push(GoogleDork {
            category: "PII / Regulated Data".to_string(),
            query: format!(
                "site:{} (intext:\"henkilötunnus\" | intext:\"personnummer\" | intext:\"CPR-nummer\" | intext:\"BSN\" | intext:\"DNI\" | intext:\"Personenkennziffer\")",
                clean_domain
            ),
            description: "European national identifier mentions".to_string(),
            impact: "EU national IDs are special-category PII under GDPR — high regulatory impact.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "PII / Regulated Data".to_string(),
            query: format!(
                "site:{} (filetype:xlsx | filetype:csv) (intext:email intext:password | intext:\"first name\" intext:\"last name\" intext:phone)",
                clean_domain
            ),
            description: "Spreadsheets containing user-record style columns".to_string(),
            impact: "Indexed CSV/XLSX with personal columns = direct PII breach.".to_string(),
        });

        // ------------------------------------------------------------------
        // Mail / SMTP / chat leaks
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "Communication Channel Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"mailto:\" intext:\"@{}\" inurl:/mailman | inurl:pipermail | inurl:listinfo)",
                clean_domain, clean_domain
            ),
            description: "Mailman archives exposing employee email and discussion".to_string(),
            impact: "Mailman/pipermail archives are a goldmine for org-mapping and credential leaks in replies.".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Communication Channel Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"phpinfo.php\" | inurl:\"info.php\" | inurl:\"test.php\" intitle:phpinfo() | intitle:\"PHP Version\")",
                clean_domain
            ),
            description: "phpinfo() pages exposing full environment".to_string(),
            impact: "phpinfo() leaks env vars (often with DB creds), filesystem paths, and module versions.".to_string(),
        });

        // ------------------------------------------------------------------
        // IoT / Industrial / Camera streams
        // ------------------------------------------------------------------
        dorks.push(GoogleDork {
            category: "IoT / Cameras".to_string(),
            query: format!(
                "site:{} (intitle:\"webcamXP\" | intitle:\"webcam 7\" | inurl:axis-cgi | inurl:/view/index.shtml | intitle:\"Live View / - AXIS\" | inurl:/control/userimage.html)",
                clean_domain
            ),
            description: "Indexed IP-camera control endpoints".to_string(),
            impact: "Unauthenticated camera feeds = privacy breach; AXIS CGI has historic auth bypasses.".to_string(),
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
