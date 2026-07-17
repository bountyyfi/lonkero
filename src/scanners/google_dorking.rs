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

        // === High-impact sensitive-file exposures (low FP, high value) ===

        // Exposed .env files - highest-signal secret leak on the web
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} inurl:.env intext:\"DB_PASSWORD\" | intext:\"AWS_SECRET\" | intext:\"API_KEY\" | intext:\"APP_SECRET\"",
                clean_domain
            ),
            description: "Find exposed .env files containing credentials".to_string(),
            impact: "CRITICAL: .env files typically contain database credentials, API keys, and framework secrets that grant full application compromise".to_string(),
        });

        // Exposed VCS metadata - .git and .svn directories
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".svn/entries\" | inurl:\".hg/store\"",
                clean_domain
            ),
            description: "Find exposed version control metadata".to_string(),
            impact: "CRITICAL: Exposed .git/.svn/.hg directories allow full source code reconstruction, revealing all historical secrets and business logic".to_string(),
        });

        // WordPress config backups - specific and high-value
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php.old\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.txt\" | inurl:\"wp-config.php.save\"",
                clean_domain
            ),
            description: "Find WordPress config backups served as text".to_string(),
            impact: "CRITICAL: wp-config backups reveal DB credentials, salts, and auth keys enabling full site takeover".to_string(),
        });

        // Framework config backups
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"settings.py.bak\" | inurl:\"local_settings.py\" | inurl:\"database.yml.bak\" | inurl:\"secrets.yml\" | inurl:\"application.yml.bak\" | inurl:\"appsettings.json.bak\")",
                clean_domain
            ),
            description: "Find framework configuration backups".to_string(),
            impact: "Django/Rails/Spring/ASP.NET config backups leak DB credentials, secret keys, and integration tokens".to_string(),
        });

        // Terraform state files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"terraform.tfstate\" | inurl:\".tfstate.backup\" | inurl:\"terraform.tfvars\")",
                clean_domain
            ),
            description: "Find Terraform state and variable files".to_string(),
            impact: "CRITICAL: tfstate stores cloud credentials, database passwords, and secret_key_base in cleartext; tfvars often contains provider tokens".to_string(),
        });

        // Ansible vault + inventory files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"group_vars\" | inurl:\"host_vars\" | inurl:\"ansible.cfg\" | filetype:yml intext:\"vault_password\")",
                clean_domain
            ),
            description: "Find Ansible inventory and vault references".to_string(),
            impact: "Ansible inventories expose internal hostnames; vaulted vars sometimes committed unencrypted or with password files nearby".to_string(),
        });

        // Docker/compose files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\".dockerignore\" | inurl:\"Dockerfile\") intext:\"password\" | intext:\"secret\" | intext:\"token\"",
                clean_domain
            ),
            description: "Find Docker compose files with embedded credentials".to_string(),
            impact: "docker-compose.yml often has hardcoded DB passwords, root passwords, and API tokens as environment variables".to_string(),
        });

        // Kubernetes secrets and configmaps
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"secret.yaml\" | inurl:\"secrets.yaml\" | intext:\"kind: Secret\" | intext:\"kubernetes.io/service-account-token\")",
                clean_domain
            ),
            description: "Find Kubernetes Secret manifests".to_string(),
            impact: "K8s Secrets are only base64-encoded; exposure = plaintext credential compromise".to_string(),
        });

        // Cloud credential files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".s3cfg\" | inurl:\".boto\" | inurl:\"gcloud/credentials.db\" | inurl:\".azure/credentials\")",
                clean_domain
            ),
            description: "Find cloud CLI credential files".to_string(),
            impact: "CRITICAL: ~/.aws/credentials, .s3cfg, and gcloud credential files grant direct cloud account access".to_string(),
        });

        // SSH private keys
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"id_rsa\" | inurl:\"id_dsa\" | inurl:\"id_ed25519\" | inurl:\"id_ecdsa\" | inurl:\".ssh/authorized_keys\" | intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find SSH private keys and authorized_keys".to_string(),
            impact: "CRITICAL: SSH private keys allow direct server access; authorized_keys reveals which keys have access".to_string(),
        });

        // Package manager credential files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\".m2/settings.xml\" | inurl:\".gem/credentials\" | inurl:\".cargo/credentials\" | inurl:\".dockercfg\" | inurl:\".docker/config.json\")",
                clean_domain
            ),
            description: "Find package manager authentication files".to_string(),
            impact: "Package manager creds allow attacker to publish malicious packages under the org's namespace (supply-chain risk)".to_string(),
        });

        // Database backups and dumps
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:bak | ext:tar.gz | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"password\" | intext:\"hash\")",
                clean_domain
            ),
            description: "Find exposed database backups and dumps".to_string(),
            impact: "Database dumps leak entire user tables, credential hashes, PII, and business data".to_string(),
        });

        // JSON credential/config files (Firebase, Google service account, etc.)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:json (intext:\"private_key_id\" | intext:\"client_email\" | intext:\"apiKey\" | intext:\"clientSecret\" | intext:\"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find exposed JSON credential files (GCP service account, Firebase)".to_string(),
            impact: "GCP service-account JSONs and Firebase configs grant direct cloud/backend access".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tgz | ext:tar.gz | ext:rar | ext:7z) (intext:\"backup\" | intext:\"dump\" | intitle:\"index of\")",
                clean_domain
            ),
            description: "Find backup archives".to_string(),
            impact: "Site/DB backup archives often contain full source, credentials, and user data".to_string(),
        });

        // macOS/Windows metadata leakage (reveals directory structure)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\"desktop.ini\")",
                clean_domain
            ),
            description: "Find OS metadata files exposing directory contents".to_string(),
            impact: ".DS_Store enumerates files/folders including hidden ones - useful for further discovery".to_string(),
        });

        // Directory listing
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (intext:\"backup\" | intext:\"dump\" | intext:\"config\" | intext:\"database\" | intext:\"private\" | intext:\"secret\" | intext:\".sql\" | intext:\".env\")",
                clean_domain
            ),
            description: "Find directory listings exposing sensitive files".to_string(),
            impact: "Open directory listings enable enumeration of every file, including hidden backups and dumps".to_string(),
        });

        // Log files with sensitive data
        dorks.push(GoogleDork {
            category: "Log Exposure".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:debug.log | inurl:error.log | inurl:access.log | inurl:laravel.log | inurl:storage/logs) intext:\"password\" | intext:\"token\" | intext:\"stacktrace\" | intext:\"Exception\"",
                clean_domain
            ),
            description: "Find exposed log files".to_string(),
            impact: "Application logs may contain session tokens, password reset URLs, PII, and stack traces revealing internal paths/versions".to_string(),
        });

        // API documentation files (raw specs)
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"swagger.json\" | inurl:\"swagger.yaml\" | inurl:\"openapi.json\" | inurl:\"openapi.yaml\" | inurl:\"api-docs.json\" | inurl:\"v2/api-docs\" | inurl:\"v3/api-docs\") | ext:wsdl",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger/WSDL specification files".to_string(),
            impact: "Full API specs reveal every endpoint including internal/admin routes, request schemas, and auth requirements - blueprint for targeted attacks".to_string(),
        });

        // GraphQL introspection endpoints
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/api/graphql\" | inurl:\"/v1/graphql\" | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints (often with introspection enabled)".to_string(),
            impact: "GraphQL introspection reveals full schema including internal mutations; production endpoints should disable it".to_string(),
        });

        // Robots and sitemap - reveal hidden paths
        dorks.push(GoogleDork {
            category: "Path Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:robots.txt intext:\"Disallow: /admin\" | intext:\"Disallow: /api\" | intext:\"Disallow: /private\" | intext:\"Disallow: /internal\")",
                clean_domain
            ),
            description: "Find robots.txt disclosing internal paths".to_string(),
            impact: "robots.txt Disallow entries advertise the exact paths admins want hidden - free enumeration".to_string(),
        });

        // WSDL/SOAP endpoints
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:asmx | inurl:?wsdl | inurl:\"WSDL\" | inurl:\"disco\")",
                clean_domain
            ),
            description: "Find SOAP web service descriptors".to_string(),
            impact: "WSDL/DISCO files expose SOAP operations, parameters, and internal type definitions".to_string(),
        });

        // Server status pages
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:server-status | inurl:server-info | inurl:nginx_status | inurl:php-info | inurl:phpinfo.php | inurl:info.php | inurl:test.php | inurl:_profiler)",
                clean_domain
            ),
            description: "Find exposed server status/info pages".to_string(),
            impact: "Apache server-status leaks live request URIs including tokens in querystrings; phpinfo exposes env vars, loaded modules, and server paths".to_string(),
        });

        // Spring Boot Actuator - hugely common finding
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/beans | inurl:/manage/env)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "CRITICAL: /actuator/env leaks all env vars including secrets; /heapdump enables memory scraping for creds/JWTs; /jolokia can lead to RCE".to_string(),
        });

        // Django debug
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (intext:\"You're seeing this error because you have DEBUG = True\" | intitle:\"DisallowedHost\" | intitle:\"Exception Value\" | intext:\"Django Version:\")",
                clean_domain
            ),
            description: "Find Django DEBUG=True error pages".to_string(),
            impact: "Django debug pages expose full stack traces, source snippets, DB queries, settings, and framework version".to_string(),
        });

        // Symfony/Laravel debug
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/_debugbar | inurl:/telescope | inurl:/_profiler | intitle:\"Whoops! There was an error\" | intext:\"Ignition\" intext:\"file\")",
                clean_domain
            ),
            description: "Find Laravel/Symfony debug panels".to_string(),
            impact: "Laravel Ignition (CVE-2021-3129) and Telescope can lead to RCE; debug panels expose environment and queries".to_string(),
        });

        // Postman workspaces/collections
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:postman.com \"{}\"", clean_domain),
            description: "Find public Postman workspaces/collections referencing the domain".to_string(),
            impact: "Public Postman collections often leak API keys, bearer tokens, and full request examples with production endpoints".to_string(),
        });

        // Grafana public dashboards
        dorks.push(GoogleDork {
            category: "Dashboard Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/grafana/d/ | inurl:/d/ intitle:\"Grafana\" | intitle:\"Grafana - Home\")",
                clean_domain
            ),
            description: "Find exposed Grafana dashboards".to_string(),
            impact: "Grafana dashboards may expose internal service metrics, error rates, and infrastructure topology".to_string(),
        });

        // Kibana/OpenSearch public dashboards
        dorks.push(GoogleDork {
            category: "Dashboard Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/app/kibana | inurl:/_plugin/kibana | intitle:\"Kibana\" | intitle:\"OpenSearch Dashboards\")",
                clean_domain
            ),
            description: "Find exposed Kibana/OpenSearch dashboards".to_string(),
            impact: "Kibana provides raw access to indexed logs, often containing tokens, PII, and internal errors".to_string(),
        });

        // Prometheus/Alertmanager
        dorks.push(GoogleDork {
            category: "Dashboard Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/api/v1/targets | inurl:/api/v1/alerts | inurl:/metrics intext:\"# HELP\" | intitle:\"Prometheus Time Series\")",
                clean_domain
            ),
            description: "Find exposed Prometheus/Alertmanager endpoints".to_string(),
            impact: "Prometheus /metrics exposes internal service labels, container names, IPs; /targets reveals full scrape topology".to_string(),
        });

        // Jenkins / CI script consoles
        dorks.push(GoogleDork {
            category: "CI/CD Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/jenkins | inurl:/script | inurl:/manage | intitle:\"Dashboard [Jenkins]\" | intitle:\"Jenkins\")",
                clean_domain
            ),
            description: "Find exposed Jenkins consoles".to_string(),
            impact: "Jenkins /script gives Groovy console = RCE as Jenkins user; unauth job configs leak credentials".to_string(),
        });

        // Firebase Realtime Database
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" | site:firebase-adminsdk.iam.gserviceaccount.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Firebase Realtime DB and admin service accounts".to_string(),
            impact: "Unauth Firebase RTDB (append .json to URL) can leak full DB contents; admin SDK creds grant total control".to_string(),
        });

        // SharePoint / OneDrive shared with tenant
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:sharepoint.com \"{}\" intext:\"anyone with the link\" | intext:\"guestaccess.aspx\"",
                clean_domain
            ),
            description: "Find publicly shared SharePoint documents".to_string(),
            impact: "\"Anyone with the link\" SharePoint documents indexed by Google leak confidential internal docs".to_string(),
        });

        // Slack workspace leaks in public archives
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "\"{}\" (site:snyk.io/vuln | site:app.snyk.io | site:pypi.org/project | site:npmjs.com/package)",
                clean_domain
            ),
            description: "Find domain references in package registries".to_string(),
            impact: "Public package pages may reveal internal package names or typo-squat opportunities".to_string(),
        });

        // Chatbot/AI leaks
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "\"{}\" (site:huggingface.co | site:kaggle.com/datasets | site:colab.research.google.com)",
                clean_domain
            ),
            description: "Find domain in ML/AI platforms".to_string(),
            impact: "Uploaded notebooks/datasets often include API keys or internal data snippets".to_string(),
        });

        // Public S3 bucket listings (via Google indexing)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:*.s3.amazonaws.com | site:*.s3-website*.amazonaws.com) intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Find publicly listable S3 buckets".to_string(),
            impact: "Listable S3 buckets enable enumeration of every object - a common source of major data breaches".to_string(),
        });

        // Wayback Machine - historical exposures often persist
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (inurl:.env | inurl:.git | inurl:config | inurl:swagger)",
                clean_domain
            ),
            description: "Find historical sensitive-path snapshots on Wayback Machine".to_string(),
            impact: "Historically exposed .env/.git/config files remain accessible via Wayback even after being fixed on the live site".to_string(),
        });

        // Certificate transparency + WHOIS-adjacent
        dorks.push(GoogleDork {
            category: "Reconnaissance".to_string(),
            query: format!(
                "(site:crt.sh | site:censys.io | site:shodan.io) \"{}\"",
                clean_domain
            ),
            description: "Find subdomains via certificate transparency and IoT search".to_string(),
            impact: "CT logs reveal every subdomain that has issued a TLS cert including internal/staging hosts".to_string(),
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
