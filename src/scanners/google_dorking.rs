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

        // ============================================================
        // EXPANDED HIGH-IMPACT DORKS
        //
        // The dorks below are scoped narrowly enough that a hit is almost
        // certainly an actual exposure (specific filenames, vendor-unique
        // tokens, or "index of" listings of named secrets) rather than a
        // generic match a real site could trip without intent.
        // ============================================================

        // --- Pinpoint .env / secret-file disclosures ----------------------

        dorks.push(GoogleDork {
            category: "Secrets in Files".to_string(),
            query: format!(
                "site:{} ext:env \"DB_PASSWORD\" | \"SECRET_KEY\" | \"APP_KEY\" | \"AWS_SECRET_ACCESS_KEY\"",
                clean_domain
            ),
            description: "Find .env files containing live secrets".to_string(),
            impact: "Direct exposure of database, framework, or AWS credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Files".to_string(),
            query: format!(
                "site:{} (ext:yml | ext:yaml | ext:json | ext:xml) (\"password\" | \"passwd\" | \"secret\" | \"api_key\" | \"apikey\" | \"access_token\")",
                clean_domain
            ),
            description: "Find structured config files leaking credential fields".to_string(),
            impact: "Config files with embedded secrets often grant production access".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Files".to_string(),
            query: format!(
                "site:{} \"-----BEGIN RSA PRIVATE KEY-----\" | \"-----BEGIN OPENSSH PRIVATE KEY-----\" | \"-----BEGIN EC PRIVATE KEY-----\" | \"-----BEGIN PGP PRIVATE KEY BLOCK-----\"",
                clean_domain
            ),
            description: "Find indexed PEM-armored private keys".to_string(),
            impact: "Private keys allow full impersonation of services or operators".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Files".to_string(),
            query: format!(
                "site:{} \"aws_access_key_id\" \"aws_secret_access_key\"",
                clean_domain
            ),
            description: "Find AWS credential files".to_string(),
            impact: "Active AWS IAM credentials, frequently with broad permissions".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Files".to_string(),
            query: format!(
                "site:{} \"BEGIN CERTIFICATE\" ext:pem | ext:key | ext:crt",
                clean_domain
            ),
            description: "Find indexed TLS keys and certificate bundles".to_string(),
            impact: "Server private keys allow TLS impersonation and decryption".to_string(),
        });

        // --- "Index of" directory listings of named sensitive files ------

        dorks.push(GoogleDork {
            category: "Open Directories".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\".env\" | \".git\" | \".svn\" | \".ssh\")",
                clean_domain
            ),
            description: "Auto-indexed dirs containing VCS or dotfile leaks".to_string(),
            impact: "Walkable VCS / dotfile dirs expose full source trees and keys".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Open Directories".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\"wp-config.php\" | \"settings.php\" | \"configuration.php\" | \"local_settings.py\" | \"parameters.yml\")",
                clean_domain
            ),
            description: "Open directories listing framework config files".to_string(),
            impact: "Framework configs typically contain DB and admin credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Open Directories".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\"backup\" | \"backups\" | \"dump.sql\" | \"db.sql\" | \"database.sql\" | \"data.sql\")",
                clean_domain
            ),
            description: "Open directories listing database dumps".to_string(),
            impact: "Indexed SQL dumps disclose entire user, session, and PII tables".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Open Directories".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\"id_rsa\" | \"authorized_keys\" | \"known_hosts\" | \".pem\" | \".key\")",
                clean_domain
            ),
            description: "Open directories listing SSH/TLS key material".to_string(),
            impact: "Indexed key files grant direct authentication to backend services".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Open Directories".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\"terraform.tfstate\" | \".tfvars\" | \"docker-compose.yml\" | \"Dockerfile\" | \"serverless.yml\")",
                clean_domain
            ),
            description: "Indexed IaC / orchestrator manifests".to_string(),
            impact: "Tfstate and compose files commonly embed managed-service secrets".to_string(),
        });

        // --- Source-tree leaks ------------------------------------------

        dorks.push(GoogleDork {
            category: "Source Code Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\".git/HEAD\" | inurl:\".git/config\" | inurl:\".git/index\")",
                clean_domain
            ),
            description: "Direct hits on served `.git` repository metadata".to_string(),
            impact: "Allows full git history reconstruction (git-dumper)".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Source Code Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/wc.db\" | inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\"CVS/Entries\")",
                clean_domain
            ),
            description: "Non-git VCS metadata exposure".to_string(),
            impact: "Older repos still serve enough to reconstruct historical sources".to_string(),
        });

        // --- Spring Boot Actuator / Java diagnostic disclosures ---------

        dorks.push(GoogleDork {
            category: "Diagnostic Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/loggers\" | inurl:\"/actuator/httptrace\")",
                clean_domain
            ),
            description: "Spring Boot Actuator endpoints indexed by Google".to_string(),
            impact: "Env / heapdump / jolokia reach RCE on common Spring deployments".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Diagnostic Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"/jolokia\" | inurl:\"/manage/env\" | inurl:\"/manage/heapdump\")",
                clean_domain
            ),
            description: "Legacy Spring Boot 1.x / Jolokia management".to_string(),
            impact: "Pre-Actuator endpoints often left wide open behind reverse proxies".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Diagnostic Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"trace.axd\" | inurl:\"elmah.axd\" | inurl:\"glimpse.axd\" | inurl:\"_profiler\" | inurl:\"_debugbar\" | inurl:\"_ignition\" | inurl:\"telescope/\")",
                clean_domain
            ),
            description: "ASP.NET, Symfony, Laravel diagnostic surfaces".to_string(),
            impact: "Stack traces, env dumps, and query logs disclosed to anonymous users".to_string(),
        });

        // --- WordPress / Drupal / Joomla high-impact paths --------------

        dorks.push(GoogleDork {
            category: "CMS Sensitive".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php.bak\" | inurl:\"wp-config.old\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.php.save\")",
                clean_domain
            ),
            description: "WordPress config backups (DB creds + AUTH salts)".to_string(),
            impact: "Direct DB credentials and forgeable AUTH/NONCE salts".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CMS Sensitive".to_string(),
            query: format!(
                "site:{} inurl:\"/wp-json/wp/v2/users\"",
                clean_domain
            ),
            description: "WordPress user enumeration via REST API".to_string(),
            impact: "Username list for credential-stuffing or 2FA-less admin targeting".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CMS Sensitive".to_string(),
            query: format!(
                "site:{} (inurl:\"sites/default/files/private\" | inurl:\"sites/default/settings.php\")",
                clean_domain
            ),
            description: "Drupal private files / settings disclosure".to_string(),
            impact: "Drupal settings contain DB and hash-salt material".to_string(),
        });

        // --- Cloud storage (specific to misconfigured public objects) ---

        dorks.push(GoogleDork {
            category: "Cloud Storage Misconfig".to_string(),
            query: format!(
                "site:s3.amazonaws.com \"{}\" intitle:\"Index of\" | intitle:\"ListBucketResult\"",
                clean_domain
            ),
            description: "Public S3 buckets returning a directory listing".to_string(),
            impact: "Anonymous bucket listing enables full object enumeration".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage Misconfig".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Public GCS objects indexed by Google".to_string(),
            impact: "Direct GCS object reads when ACL is `allUsers:Reader`".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage Misconfig".to_string(),
            query: format!(
                "(site:r2.cloudflarestorage.com | site:r2.dev) \"{}\"",
                clean_domain
            ),
            description: "Cloudflare R2 buckets bound to the target".to_string(),
            impact: "Public R2 paths frequently host build artifacts and backups".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage Misconfig".to_string(),
            query: format!(
                "(site:b2-api.backblazeb2.com | site:b2.contabostorage.com | site:wasabisys.com) \"{}\"",
                clean_domain
            ),
            description: "Alt-cloud object stores (Backblaze B2, Wasabi, Contabo)".to_string(),
            impact: "Same data-leak class as S3, but rarely covered by scanners".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage Misconfig".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" \".json\"",
                clean_domain
            ),
            description: "Firebase Realtime Database paths".to_string(),
            impact: "RTDB with permissive rules exposes user data and tokens".to_string(),
        });

        // --- CI/CD log leaks (commonly indexed) -------------------------

        dorks.push(GoogleDork {
            category: "CI/CD Log Leaks".to_string(),
            query: format!(
                "(site:travis-ci.com | site:travis-ci.org | site:app.circleci.com | site:circleci.com) \"{}\"",
                clean_domain
            ),
            description: "Public CI build logs for the target".to_string(),
            impact: "Pre-2019 Travis builds and public CircleCI orgs leak env secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CI/CD Log Leaks".to_string(),
            query: format!(
                "site:buildkite.com \"{}\"",
                clean_domain
            ),
            description: "Public Buildkite build pages".to_string(),
            impact: "Job output often leaks tokens via debug echoes".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CI/CD Log Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" \"workflow_dispatch\" | \"setup-node\" | \"actions/checkout\"",
                clean_domain
            ),
            description: "GitHub Actions workflow files mentioning the target".to_string(),
            impact: "Workflows expose secret names, runners, and protected branches".to_string(),
        });

        // --- Postman / API platform leaks -------------------------------

        dorks.push(GoogleDork {
            category: "API Spec Leaks".to_string(),
            query: format!(
                "site:postman.com \"{}\"",
                clean_domain
            ),
            description: "Public Postman workspaces / collections referencing target".to_string(),
            impact: "Collections regularly include Authorization headers and bearer tokens"
                .to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Spec Leaks".to_string(),
            query: format!(
                "(site:rapidapi.com | site:apiary.io | site:swaggerhub.com) \"{}\"",
                clean_domain
            ),
            description: "API platforms hosting public specs for the target".to_string(),
            impact: "Disclose endpoints, parameters, and sometimes example creds".to_string(),
        });

        // --- Code paste / sandbox platforms (deep) ----------------------

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\"",
                clean_domain
            ),
            description: "GitHub gists referencing the target".to_string(),
            impact: "Gists routinely paste tokens, internal URLs, and DB creds".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:replit.com | site:repl.it | site:codesandbox.io | site:stackblitz.com | site:glitch.com | site:jsbin.com) \"{}\"",
                clean_domain
            ),
            description: "Online IDEs / sandboxes referencing the target".to_string(),
            impact: "Sandboxed projects often retain hardcoded creds from local dev".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:hastebin.com | site:ghostbin.com | site:ide.geeksforgeeks.org | site:paste.ee | site:dpaste.org | site:rentry.co) \"{}\"",
                clean_domain
            ),
            description: "Alt paste services mentioning the target".to_string(),
            impact: "Quick paste-and-share leak channel".to_string(),
        });

        // --- Internal docs / wikis exposed --------------------------------

        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "(site:atlassian.net | site:atlassian.com) \"{}\"",
                clean_domain
            ),
            description: "Atlassian (Jira / Confluence) hits".to_string(),
            impact: "Public confluence pages or public Jira projects often discuss bugs / creds"
                .to_string(),
        });

        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "site:notion.site \"{}\"",
                clean_domain
            ),
            description: "Public Notion pages referencing the target".to_string(),
            impact: "Shared runbooks and ops docs frequently linked unintentionally".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "(site:gitbook.io | site:gitbook.com | site:readme.io | site:readthedocs.io) \"{}\"",
                clean_domain
            ),
            description: "Hosted documentation platforms".to_string(),
            impact: "Disclose internal API endpoints and authentication models".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "(site:slack.com/archives | site:discord.com/channels | site:t.me) \"{}\"",
                clean_domain
            ),
            description: "Chat / community platforms referencing target".to_string(),
            impact: "Archived chats sometimes contain debug URLs and rotated creds".to_string(),
        });

        // --- Error message fingerprints (precise, low-FP) ----------------

        dorks.push(GoogleDork {
            category: "Stack Trace Disclosure".to_string(),
            query: format!(
                "site:{} (\"Whitelabel Error Page\" | \"at org.springframework\" | \"NoClassDefFoundError\" | \"java.lang.NullPointerException\")",
                clean_domain
            ),
            description: "Spring Boot default error pages or framework traces".to_string(),
            impact: "Reveals framework version and internal class paths".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Stack Trace Disclosure".to_string(),
            query: format!(
                "site:{} (\"Traceback (most recent call last)\" | \"Werkzeug Debugger\" | \"DEBUG = True\" | \"DisallowedHost\")",
                clean_domain
            ),
            description: "Python (Django / Flask) traceback exposure".to_string(),
            impact: "Werkzeug debugger PIN-bypass leads to RCE".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Stack Trace Disclosure".to_string(),
            query: format!(
                "site:{} (\"Fatal error: Uncaught\" | \"Call Stack\" inurl:.php | \"Whoops, looks like something went wrong.\")",
                clean_domain
            ),
            description: "PHP fatal traces / Laravel Whoops".to_string(),
            impact: "Path and class disclosure; Whoops often hits Ignition RCE".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Stack Trace Disclosure".to_string(),
            query: format!(
                "site:{} (\"Object reference not set to an instance of an object\" | \"Server Error in '/' Application\")",
                clean_domain
            ),
            description: "ASP.NET yellow-screen error".to_string(),
            impact: "Reveals .NET version and stack details".to_string(),
        });

        // --- Database admin tools exposed publicly -----------------------

        dorks.push(GoogleDork {
            category: "DB Admin Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"pgAdmin\" | intitle:\"RockMongo\" | intitle:\"MongoExpress\")",
                clean_domain
            ),
            description: "Web-based DB admin panels indexed publicly".to_string(),
            impact: "Default creds or session reuse → direct DB access".to_string(),
        });

        // --- Observability / search clusters left open -------------------

        dorks.push(GoogleDork {
            category: "Search/Logs Exposed".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | intitle:\"Welcome to Apache Solr\" | inurl:\"_cat/indices\" | inurl:\"/_cluster/health\")",
                clean_domain
            ),
            description: "Elasticsearch / Kibana / Solr cluster admin".to_string(),
            impact: "Open clusters typically expose user, log, and event indices".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Search/Logs Exposed".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:login | intitle:\"Welcome to Prometheus\" | inurl:\"/alertmanager\")",
                clean_domain
            ),
            description: "Grafana / Prometheus / Alertmanager dashboards".to_string(),
            impact: "Dashboards leak metric labels, hostnames, and sometimes credentials"
                .to_string(),
        });

        // --- DevOps panels / container orchestration --------------------

        dorks.push(GoogleDork {
            category: "DevOps Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Portainer\" | intitle:\"Rancher\" | intitle:\"Dashboard · Kubernetes\" | inurl:\"/api/v1/namespaces\")",
                clean_domain
            ),
            description: "Container orchestration UIs".to_string(),
            impact: "Direct cluster control — pod exec, secrets read, deployment rewrite"
                .to_string(),
        });

        dorks.push(GoogleDork {
            category: "DevOps Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Jenkins\" | intitle:\"GoCD\" | intitle:\"TeamCity\" | intitle:\"Argo CD\" | intitle:\"Concourse\" | intitle:\"Spinnaker\")",
                clean_domain
            ),
            description: "CI/CD control planes (UI side)".to_string(),
            impact: "Misconfigured anonymous read → secret variables & deploy abuse".to_string(),
        });

        // --- Webhook URL leaks (Slack/Discord/Teams) ---------------------

        dorks.push(GoogleDork {
            category: "Webhook Leaks".to_string(),
            query: format!(
                "site:{} \"hooks.slack.com/services/T\"",
                clean_domain
            ),
            description: "Slack incoming-webhook URLs referenced on target".to_string(),
            impact: "Anyone can post to the channel until rotated".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Webhook Leaks".to_string(),
            query: format!(
                "site:{} (\"discord.com/api/webhooks/\" | \"discordapp.com/api/webhooks/\")",
                clean_domain
            ),
            description: "Discord webhook URLs".to_string(),
            impact: "Equivalent to Slack: post-only abuse and message spoofing".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Webhook Leaks".to_string(),
            query: format!(
                "site:{} (\"outlook.office.com/webhook/\" | \"webhook.office.com\")",
                clean_domain
            ),
            description: "Microsoft Teams incoming-webhook URLs".to_string(),
            impact: "Post arbitrary messages into channels".to_string(),
        });

        // --- Recon: cert transparency, subdomain dorks -------------------

        dorks.push(GoogleDork {
            category: "Recon".to_string(),
            query: format!(
                "(site:crt.sh | site:censys.io | site:shodan.io | site:fofa.so | site:zoomeye.org) \"{}\"",
                clean_domain
            ),
            description: "Recon platforms with target intelligence".to_string(),
            impact: "Subdomains, certs, exposed services — full attack surface map".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Recon".to_string(),
            query: format!(
                "-www site:*.{}",
                clean_domain
            ),
            description: "Subdomain enumeration via Google".to_string(),
            impact: "Surfaces dev/staging/internal subdomains often more vulnerable".to_string(),
        });

        // --- ChatGPT/AI prompt + log files -------------------------------

        dorks.push(GoogleDork {
            category: "AI / LLM Leaks".to_string(),
            query: format!(
                "(site:huggingface.co | site:wandb.ai | site:share.hsforms.com) \"{}\"",
                clean_domain
            ),
            description: "AI/ML platforms hosting datasets or W&B runs".to_string(),
            impact: "Public datasets and training logs sometimes embed prompts with PII"
                .to_string(),
        });

        dorks.push(GoogleDork {
            category: "AI / LLM Leaks".to_string(),
            query: format!(
                "site:{} (\"sk-ant-\" | \"sk-proj-\" | \"sk-org-\" | \"AIza\" | \"hf_\")",
                clean_domain
            ),
            description: "Vendor-prefixed AI provider tokens".to_string(),
            impact: "Active OpenAI / Anthropic / Google / HuggingFace API keys".to_string(),
        });

        // --- JWT / token leaks in indexed content ------------------------

        dorks.push(GoogleDork {
            category: "Token Leaks".to_string(),
            query: format!(
                "site:{} \"eyJhbGciOi\"",
                clean_domain
            ),
            description: "Indexed JWTs (header `eyJhbGciOi` base64 prefix)".to_string(),
            impact: "Often live session or service tokens, valid for hours/days".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Token Leaks".to_string(),
            query: format!(
                "site:{} (\"ghp_\" | \"gho_\" | \"ghs_\" | \"ghu_\" | \"github_pat_\")",
                clean_domain
            ),
            description: "GitHub PAT / OAuth tokens indexed on the domain".to_string(),
            impact: "Repository read/write, often org-wide".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Token Leaks".to_string(),
            query: format!(
                "site:{} (\"xoxb-\" | \"xoxp-\" | \"xoxa-\" | \"xoxr-\" | \"xoxs-\")",
                clean_domain
            ),
            description: "Slack workspace tokens".to_string(),
            impact: "Read history, post messages, list users".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Token Leaks".to_string(),
            query: format!(
                "site:{} (\"sk_live_\" | \"rk_live_\" | \"pk_live_\")",
                clean_domain
            ),
            description: "Stripe live API keys".to_string(),
            impact: "Live payment-platform credentials".to_string(),
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
    fn test_high_impact_categories_exist() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        for expected in [
            "Secrets in Files",
            "Open Directories",
            "Source Code Disclosure",
            "Diagnostic Disclosure",
            "CMS Sensitive",
            "Cloud Storage Misconfig",
            "CI/CD Log Leaks",
            "API Spec Leaks",
            "Internal Docs",
            "Stack Trace Disclosure",
            "DB Admin Tools",
            "Search/Logs Exposed",
            "DevOps Panels",
            "Webhook Leaks",
            "Recon",
            "AI / LLM Leaks",
            "Token Leaks",
        ] {
            assert!(
                results.by_category.contains_key(expected),
                "expected category `{}` to be present",
                expected
            );
        }
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
