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
        // Version Control Exposure (exposed .git / .svn / .hg trees)
        // Extremely high impact: recoverable source, credentials in
        // history, and often deploy keys. Almost zero false positives —
        // these paths only exist when a working tree was published.
        // ============================================================

        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\"",
                clean_domain
            ),
            description: "Find exposed .git directory metadata files".to_string(),
            impact: "Full source code and commit history can be reconstructed with git-dumper; credentials frequently appear in history".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".svn/pristine\"",
                clean_domain
            ),
            description: "Find exposed Subversion working copy metadata".to_string(),
            impact: "wc.db and pristine/ let attackers reconstruct the working copy including deleted files".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} inurl:\".hg/store\" | inurl:\".hg/hgrc\" | inurl:\".bzr/README\"",
                clean_domain
            ),
            description: "Find exposed Mercurial or Bazaar repositories".to_string(),
            impact: "Full repository history and remote push URLs (often containing credentials) recoverable".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} intitle:\"Index of\" \".git\" | intitle:\"Index of\" \".svn\"",
                clean_domain
            ),
            description: "Directory listing exposing VCS metadata folders".to_string(),
            impact: "Auto-index of VCS folders allows full source disclosure via directory traversal".to_string(),
        });

        // ============================================================
        // Environment & Configuration File Exposure
        // Every dork here is anchored to filenames that only exist when
        // a real secret file is served — no generic \"help\" pages.
        // ============================================================

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} ext:env | ext:envrc intext:\"DB_PASSWORD\" | intext:\"SECRET_KEY\" | intext:\"AWS_ACCESS_KEY_ID\" | intext:\"STRIPE_SECRET\"",
                clean_domain
            ),
            description: "Find .env style files containing production secrets".to_string(),
            impact: "Direct disclosure of production credentials, cloud keys, and third-party API secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} intitle:\"Index of\" (\".env\" | \".env.production\" | \".env.local\" | \".env.prod\")",
                clean_domain
            ),
            description: "Directory listing exposing dotenv variants".to_string(),
            impact: "Environment-specific credentials (prod/staging) exposed via auto-index".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} inurl:\".aws/credentials\" | inurl:\"credentials\" intext:\"aws_secret_access_key\"",
                clean_domain
            ),
            description: "Find AWS credential files".to_string(),
            impact: "Full AWS account compromise via long-lived access keys".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} inurl:\"gcloud\" intext:\"private_key_id\" | inurl:\"service-account\" ext:json",
                clean_domain
            ),
            description: "Find GCP service account JSON keys".to_string(),
            impact: "GCP service account takeover with full project permissions".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} inurl:\"kubeconfig\" | inurl:\".kube/config\" intext:\"client-certificate-data\"",
                clean_domain
            ),
            description: "Find kubectl configuration exposing cluster credentials".to_string(),
            impact: "Full Kubernetes cluster access with embedded certificates".to_string(),
        });

        dorks.push(GoogleDork {
            category: "SSH Keys".to_string(),
            query: format!(
                "site:{} inurl:\"id_rsa\" | inurl:\"id_ed25519\" | inurl:\"authorized_keys\" | inurl:\"known_hosts\"",
                clean_domain
            ),
            description: "Find exposed SSH private keys and trust files".to_string(),
            impact: "Private key disclosure allows persistent lateral access to any server the key authorizes".to_string(),
        });

        dorks.push(GoogleDork {
            category: "SSH Keys".to_string(),
            query: format!(
                "site:{} intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN RSA PRIVATE KEY-----\"",
                clean_domain
            ),
            description: "Find PEM/OpenSSH private key blocks embedded in indexed pages".to_string(),
            impact: "Private key material recoverable from cached content even after removal".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Package Manager Credentials".to_string(),
            query: format!(
                "site:{} inurl:\".npmrc\" intext:\"_authToken\" | inurl:\".pypirc\" intext:\"password\" | inurl:\".cargo/credentials\"",
                clean_domain
            ),
            description: "Find package registry authentication files".to_string(),
            impact: "Supply-chain compromise vector: attacker publishes malicious versions of your packages".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Terraform State".to_string(),
            query: format!(
                "site:{} ext:tfstate | ext:tfvars intext:\"secret\" | intext:\"password\" | intext:\"api_key\"",
                clean_domain
            ),
            description: "Find Terraform state and variable files".to_string(),
            impact: "tfstate contains cloud resource IDs, IAM policies and often plain-text provider credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Container Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" intext:\"environment:\" intext:\"PASSWORD\"",
                clean_domain
            ),
            description: "Find docker-compose files with hardcoded environment secrets".to_string(),
            impact: "Direct disclosure of database, cache and message broker credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Container Configuration".to_string(),
            query: format!(
                "site:{} inurl:\".dockerconfigjson\" | inurl:\"config.json\" intext:\"auths\" intext:\"auth\"",
                clean_domain
            ),
            description: "Find Docker registry auth config exposing base64-encoded credentials".to_string(),
            impact: "Registry credentials allow pushing malicious images to trusted image tags".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Kubernetes Secrets".to_string(),
            query: format!(
                "site:{} intext:\"kind: Secret\" intext:\"apiVersion: v1\" intext:\"data:\"",
                clean_domain
            ),
            description: "Find Kubernetes Secret manifests with base64 data".to_string(),
            impact: "Base64-encoded secrets in manifests decode to plaintext credentials".to_string(),
        });

        // ============================================================
        // WordPress / CMS Sensitive File Exposure
        // ============================================================

        dorks.push(GoogleDork {
            category: "CMS Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.php.old\" | inurl:\"wp-config.txt\"",
                clean_domain
            ),
            description: "Find backup copies of wp-config.php served as text".to_string(),
            impact: "Backup extension bypasses PHP handler and leaks DB credentials plus AUTH_KEY secrets".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CMS Configuration".to_string(),
            query: format!(
                "site:{} inurl:\"configuration.php.bak\" | inurl:\"configuration.php~\" | inurl:\"settings.php.bak\" | inurl:\"local.php.bak\"",
                clean_domain
            ),
            description: "Backup copies of Joomla/Drupal configuration files".to_string(),
            impact: "Leaks DB credentials, salts and hash pepper values used across the CMS".to_string(),
        });

        dorks.push(GoogleDork {
            category: "CMS Sensitive Paths".to_string(),
            query: format!(
                "site:{} inurl:\"wp-content/debug.log\" | inurl:\"wp-content/uploads/backup\"",
                clean_domain
            ),
            description: "WordPress debug logs and backup uploads exposed".to_string(),
            impact: "Stack traces and full-site backup archives frequently contain secrets and PII".to_string(),
        });

        // ============================================================
        // Database Dumps & Backups (very high impact when returned)
        // ============================================================

        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql intext:\"CREATE TABLE\" | intext:\"INSERT INTO\" | intext:\"DROP TABLE\"",
                clean_domain
            ),
            description: "Find raw SQL dump files".to_string(),
            impact: "Full database contents including password hashes and PII".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:bak | ext:backup | ext:dump | ext:rdb | ext:bson intitle:\"Index of\"",
                clean_domain
            ),
            description: "Find database backup archives via directory index".to_string(),
            impact: "Downloadable full-DB snapshots (MySQL .bak, Redis .rdb, MongoDB .bson)".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:gz | ext:zip | ext:tar) intext:\"phpMyAdmin SQL Dump\" | intext:\"-- MySQL dump\"",
                clean_domain
            ),
            description: "Find phpMyAdmin/mysqldump exports".to_string(),
            impact: "Direct download of complete DB export, often with credentials and session tables".to_string(),
        });

        // ============================================================
        // Debug / Diagnostics Endpoints
        // These are always leaks when they resolve — the endpoints are
        // not user-facing content.
        // ============================================================

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/configprops\"",
                clean_domain
            ),
            description: "Spring Boot Actuator sensitive endpoints".to_string(),
            impact: "/env leaks all config including secrets; /heapdump exposes full JVM memory including session tokens and credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"_ignition/execute-solution\" | inurl:\"/telescope/requests\" | inurl:\"_debugbar\"",
                clean_domain
            ),
            description: "Laravel Ignition / Telescope / Debugbar exposure".to_string(),
            impact: "Ignition execute-solution led to CVE-2021-3129 RCE; Telescope logs every request incl. tokens".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"_profiler\" | inurl:\"_wdt\" intitle:\"Symfony Profiler\"",
                clean_domain
            ),
            description: "Symfony Web Profiler / Debug Toolbar exposed".to_string(),
            impact: "Profiler exposes DB queries, session data, environment and request/response internals".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} intitle:\"Werkzeug Debugger\" | intext:\"Werkzeug\" intext:\"traceback\"",
                clean_domain
            ),
            description: "Flask / Werkzeug interactive debugger exposed".to_string(),
            impact: "Interactive Python console in the browser — direct RCE if PIN is bypassable".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} intitle:\"Django\" intext:\"Traceback\" intext:\"Request Method\" intext:\"Request URL\"",
                clean_domain
            ),
            description: "Django DEBUG=True traceback pages".to_string(),
            impact: "Leaks settings, installed apps, source snippets and often SECRET_KEY / DB config".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"elmah.axd\" | inurl:\"trace.axd\" | inurl:\"errors.axd\"",
                clean_domain
            ),
            description: "ASP.NET ELMAH / trace.axd error logs".to_string(),
            impact: "Full application error log including request headers (cookies, Authorization) exposed to anyone".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} intitle:\"phpinfo()\" intext:\"PHP Version\" intext:\"System\" intext:\"Loaded Configuration File\"",
                clean_domain
            ),
            description: "phpinfo() output pages".to_string(),
            impact: "Reveals every server path, extension, and PHP env var — a launchpad for further attacks".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} inurl:\"/server-status\" | inurl:\"/server-info\" | inurl:\"/nginx_status\"",
                clean_domain
            ),
            description: "Apache mod_status / Nginx stub_status pages".to_string(),
            impact: "Real-time request logs expose live URLs and query strings including tokens in the last hits".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} intext:\"YAML Application Error\" intext:\"YAML::\" | intext:\"You are seeing this error because you have\"",
                clean_domain
            ),
            description: "Rails default error / info pages".to_string(),
            impact: "Reveals framework version, gem list and stack frames pointing at code paths".to_string(),
        });

        // ============================================================
        // Management UIs & Admin Consoles (discovery, not attack)
        // ============================================================

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" intext:\"Welcome to phpMyAdmin\") | (intitle:\"Adminer\" \"Login\")",
                clean_domain
            ),
            description: "Public phpMyAdmin / Adminer login pages".to_string(),
            impact: "DB admin surface exposed to the internet — targets for credential-stuffing and known CVEs".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} intitle:\"Kibana\" inurl:\"app/kibana\" | intitle:\"Grafana\" inurl:\"/login\"",
                clean_domain
            ),
            description: "Kibana / Grafana dashboards".to_string(),
            impact: "Often anonymous read; leaks log content, dashboards and internal service names".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} inurl:\"/graph\" inurl:\"/targets\" intext:\"prometheus\"",
                clean_domain
            ),
            description: "Prometheus expression browser / targets".to_string(),
            impact: "Reveals every internal scrape target and label set — full internal service inventory".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} intitle:\"Dashboard [Jenkins]\" | intitle:\"Sign in [Jenkins]\"",
                clean_domain
            ),
            description: "Jenkins CI dashboards".to_string(),
            impact: "Anonymous read of jobs/config; script console is remote code execution if authenticated".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} intitle:\"RabbitMQ Management\" | intitle:\"Argo CD\" | intitle:\"Airflow - DAGs\" | intitle:\"Portainer\"",
                clean_domain
            ),
            description: "Message-broker / CI / container management UIs".to_string(),
            impact: "Cluster-level operational control planes exposed — high blast radius if authenticated".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} inurl:\"v2/_catalog\" | inurl:\"/v2/\" intext:\"repositories\"",
                clean_domain
            ),
            description: "Docker Registry v2 API catalog".to_string(),
            impact: "Full image catalog exposure; unauthenticated pulls leak internal build content".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} intitle:\"Vault\" inurl:\"/ui/vault\" | intitle:\"Consul\" inurl:\"/ui/\"",
                clean_domain
            ),
            description: "HashiCorp Vault / Consul web UIs".to_string(),
            impact: "Secret management and service discovery UIs exposed to public internet".to_string(),
        });

        // ============================================================
        // Data-Store REST/HTTP Interfaces
        // ============================================================

        dorks.push(GoogleDork {
            category: "Exposed Data Stores".to_string(),
            query: format!(
                "site:{} inurl:\"_cat/indices\" | inurl:\"_cluster/health\" | inurl:\"_cat/nodes\"",
                clean_domain
            ),
            description: "Open Elasticsearch cluster endpoints".to_string(),
            impact: "Anonymous access to Elasticsearch indices — historical data exfiltration".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Data Stores".to_string(),
            query: format!(
                "site:{} inurl:\"solr/#/\" intitle:\"Solr Admin\" | inurl:\"/solr/admin/cores\"",
                clean_domain
            ),
            description: "Apache Solr admin UI / cores endpoint".to_string(),
            impact: "Historical RCE in Solr (CVE-2019-17558 etc.) and full index browsing".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Exposed Data Stores".to_string(),
            query: format!(
                "site:{} inurl:\"_utils\" intitle:\"CouchDB\" | inurl:\"/_all_dbs\"",
                clean_domain
            ),
            description: "CouchDB Fauxton UI / _all_dbs endpoint".to_string(),
            impact: "Anonymous DB listing; often paired with default admin party mode".to_string(),
        });

        // ============================================================
        // Secrets in Structured Text (JSON / YAML / logs)
        // ============================================================

        dorks.push(GoogleDork {
            category: "Secrets in Logs".to_string(),
            query: format!(
                "site:{} ext:log intext:\"Authorization: Bearer \" | intext:\"Authorization: Basic \" | intext:\"Cookie: session\"",
                clean_domain
            ),
            description: "Log files containing captured Authorization / session headers".to_string(),
            impact: "Direct account takeover via stolen bearer tokens / session cookies from ingested logs".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Logs".to_string(),
            query: format!(
                "site:{} ext:log (intext:\"password=\" | intext:\"api_key=\" | intext:\"apikey=\" | intext:\"secret=\")",
                clean_domain
            ),
            description: "Log files with secrets captured via GET query strings".to_string(),
            impact: "Credentials logged from query params — no rotation typically applied to log archives".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Text".to_string(),
            query: format!(
                "site:{} (ext:yml | ext:yaml | ext:json | ext:conf | ext:ini) intext:\"password:\" intext:\"host:\" intext:\"user:\"",
                clean_domain
            ),
            description: "Structured config files with clear-text credentials".to_string(),
            impact: "Application-level credentials for DBs, brokers and third-party APIs recoverable directly".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Text".to_string(),
            query: format!(
                "site:{} intext:\"hooks.slack.com/services/\"",
                clean_domain
            ),
            description: "Slack incoming webhook URLs indexed on the site".to_string(),
            impact: "Anyone can post to internal Slack channels — phishing and SSRF pivot vector".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Secrets in Text".to_string(),
            query: format!(
                "site:{} intext:\"discord.com/api/webhooks/\" | intext:\"discordapp.com/api/webhooks/\"",
                clean_domain
            ),
            description: "Discord webhook URLs indexed on the site".to_string(),
            impact: "Attacker can spoof messages in the target channel; sometimes used for CI notifications".to_string(),
        });

        // ============================================================
        // GraphQL / API Introspection & Playgrounds
        // ============================================================

        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/playground\") intext:\"__schema\" | intitle:\"GraphiQL\" | intitle:\"Playground\"",
                clean_domain
            ),
            description: "GraphQL endpoints with introspection enabled or interactive IDE exposed".to_string(),
            impact: "Full schema disclosure reveals every query, mutation and internal type — a full API map for the attacker".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Exposure".to_string(),
            query: format!(
                "site:{} inurl:\"swagger.json\" | inurl:\"openapi.json\" | inurl:\"api-docs\" ext:json",
                clean_domain
            ),
            description: "Machine-readable OpenAPI / Swagger specs".to_string(),
            impact: "Complete internal API surface handed to attackers including undocumented admin endpoints".to_string(),
        });

        // ============================================================
        // Backup / Editor Swap Files
        // ============================================================

        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} intitle:\"Index of\" (ext:swp | ext:swo | ext:swn | ext:bak | ext:orig | ext:save | ext:old | ext:tmp)",
                clean_domain
            ),
            description: "Directory listing with editor swap / backup files".to_string(),
            impact: "vim .swp / editor .bak files served as text bypass application handlers and reveal source".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} inurl:\".well-known/backup\" | inurl:\"backup.zip\" | inurl:\"site-backup\" | inurl:\"full-backup\"",
                clean_domain
            ),
            description: "Predictable public backup archive locations".to_string(),
            impact: "Full site archive (source + DB + secrets) downloadable in one request".to_string(),
        });

        // ============================================================
        // External Intelligence Sources
        // Broader than site:target — looks for leaks about the domain
        // published on third-party services.
        // ============================================================

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:documenter.getpostman.com | site:www.postman.com/collections | site:app.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Public Postman collections / documentation mentioning the domain".to_string(),
            impact: "Frequently contains staging URLs, bearer tokens and undocumented endpoints".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "site:notion.site \"{}\" | site:notion.so \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Public Notion pages referencing the domain".to_string(),
            impact: "Publicly shared runbooks and onboarding docs often reveal architecture and admin URLs".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:hub.docker.com | site:quay.io) \"{}\"",
                clean_domain
            ),
            description: "Public Docker images tagged with the organization / domain".to_string(),
            impact: "Image layers may embed baked-in secrets, private code, or old vulnerable dependencies".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:serverfault.com) \"{}\" (intext:\"stack trace\" | intext:\"error\" | intext:\"password\" | intext:\"connection string\")",
                clean_domain
            ),
            description: "Stack Overflow / Server Fault posts pasting internal logs with the domain".to_string(),
            impact: "Employees frequently paste production stack traces and connection strings into Q&A".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:gist.github.com | site:pastebin.com | site:ghostbin.com | site:hastebin.com | site:paste.ee | site:controlc.com) \"{}\"",
                clean_domain
            ),
            description: "Paste-site content mentioning the domain".to_string(),
            impact: "Broad coverage of leaked snippets, credentials and internal notes".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "site:github.com \"{}\" (filename:.env | filename:credentials | filename:config.php | filename:.npmrc | filename:.dockerconfigjson)",
                clean_domain
            ),
            description: "GitHub code search proxy — filenames known to hold secrets".to_string(),
            impact: "Public repositories with matching filenames are the highest-yield secret sources in bug bounties".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "site:gitlab.com \"{}\" (filename:.env | filename:credentials | filename:kubeconfig | filename:secrets.yaml)",
                clean_domain
            ),
            description: "GitLab code with high-value secret filenames".to_string(),
            impact: "Same yield as GitHub search but often under-monitored".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:hastebin.com | site:paste.ubuntu.com | site:0bin.net) \"{}\" (intext:\"BEGIN PRIVATE KEY\" | intext:\"BEGIN OPENSSH\" | intext:\"api_key\" | intext:\"password\")",
                clean_domain
            ),
            description: "Less-monitored paste services with credential-shaped content".to_string(),
            impact: "Older/niche paste sites still index into Google and rarely get scrubbed".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "(site:atlassian.net | site:jira.com | site:confluence.com) \"{}\" (intext:\"internal\" | intext:\"confidential\" | inurl:\"/wiki/spaces\")",
                clean_domain
            ),
            description: "Publicly visible Atlassian Confluence / Jira content".to_string(),
            impact: "Anonymous-read wikis expose runbooks, on-call rosters and network diagrams".to_string(),
        });

        dorks.push(GoogleDork {
            category: "External Intelligence".to_string(),
            query: format!(
                "site:sitesecrethub.com \"{}\" | site:huntr.dev \"{}\" | site:cvedetails.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Vulnerability trackers referencing the domain".to_string(),
            impact: "Known-vulnerable version disclosure aids exploit selection".to_string(),
        });

        // ============================================================
        // PII / Confidential Documents (targeted, less noisy)
        // ============================================================

        dorks.push(GoogleDork {
            category: "PII Documents".to_string(),
            query: format!(
                "site:{} (ext:pdf | ext:docx | ext:xlsx) (intext:\"passport number\" | intext:\"date of birth\" | intext:\"driver's license\" | intext:\"social security\")",
                clean_domain
            ),
            description: "Documents with PII identifier phrases".to_string(),
            impact: "Direct exposure of regulated personal data (GDPR / HIPAA / PCI adjacent)".to_string(),
        });

        dorks.push(GoogleDork {
            category: "PII Documents".to_string(),
            query: format!(
                "site:{} (ext:pdf | ext:xlsx | ext:csv) (intitle:\"payroll\" | intitle:\"salaries\" | intitle:\"employees\" | intitle:\"customers\") (intext:\"IBAN\" | intext:\"salary\" | intext:\"annual\")",
                clean_domain
            ),
            description: "Payroll / employee / customer lists exposed as documents".to_string(),
            impact: "High-impact HR and financial PII with clear regulatory reporting obligations".to_string(),
        });

        dorks.push(GoogleDork {
            category: "PII Documents".to_string(),
            query: format!(
                "site:{} intext:\"henkilötunnus\" | intext:\"personnummer\" | intext:\"CPF\" | intext:\"NIF\" (ext:pdf | ext:xlsx | ext:csv)",
                clean_domain
            ),
            description: "Regional PII identifiers (Finland / Sweden / Brazil / Spain)".to_string(),
            impact: "Country-specific national IDs are directly regulated PII with high breach reporting cost".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Confidential Documents".to_string(),
            query: format!(
                "site:{} (ext:pdf | ext:docx | ext:pptx) (intitle:\"NDA\" | intitle:\"MNDA\" | intitle:\"agreement\") (intext:\"non-disclosure\" | intext:\"confidential\")",
                clean_domain
            ),
            description: "NDAs and confidential agreements exposed publicly".to_string(),
            impact: "Client / partner names leaked; often paired with counterparty legal contact info".to_string(),
        });

        // ============================================================
        // Cloud Metadata / Localhost Endpoints Accidentally Indexed
        // ============================================================

        dorks.push(GoogleDork {
            category: "Cloud Metadata Leaks".to_string(),
            query: format!(
                "site:{} inurl:\"169.254.169.254\" | inurl:\"/latest/meta-data/\" | inurl:\"/computeMetadata/v1/\"",
                clean_domain
            ),
            description: "Cloud metadata service responses cached / proxied via the site".to_string(),
            impact: "Metadata responses often contain IAM role temporary credentials".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Metadata Leaks".to_string(),
            query: format!(
                "site:{} intext:\"AKIA\" | intext:\"ASIA\" | intext:\"AIza\" | intext:\"ya29.\" | intext:\"sk_live_\" | intext:\"rk_live_\"",
                clean_domain
            ),
            description: "Vendor-prefixed key literals in indexed pages".to_string(),
            impact: "Vendor prefixes (AWS AKIA/ASIA, Google AIza/ya29, Stripe sk_live) uniquely identify real credentials — near-zero FP".to_string(),
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
    fn test_sensitive_discovery_categories_present() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        // High-impact sensitive-data discovery categories added on top of
        // the historical parameter/error dorks. Each of these categories
        // corresponds to a finding class with near-zero false positives —
        // if a real result comes back, it is genuinely leaking.
        for category in &[
            "Version Control Exposure",
            "Environment Files",
            "Cloud Credentials",
            "SSH Keys",
            "Package Manager Credentials",
            "Terraform State",
            "Container Configuration",
            "Kubernetes Secrets",
            "CMS Configuration",
            "Database Dumps",
            "Debug Endpoints",
            "Admin Consoles",
            "Exposed Data Stores",
            "Secrets in Logs",
            "Secrets in Text",
            "GraphQL Exposure",
            "API Exposure",
            "Backup Files",
            "External Intelligence",
            "PII Documents",
            "Confidential Documents",
            "Cloud Metadata Leaks",
        ] {
            assert!(
                results.by_category.contains_key(*category),
                "expected sensitive-discovery category `{}` to be present",
                category
            );
        }
    }

    #[test]
    fn test_dork_corpus_grew() {
        // Guardrail against accidental deletions of the sensitive-discovery
        // corpus. The historical set was ~44 entries; the expansion adds
        // 40+ high-signal dorks focused on finding sensitive stuff.
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");
        assert!(
            results.dorks.len() >= 80,
            "expected at least 80 dork entries after expansion, got {}",
            results.dorks.len()
        );
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
