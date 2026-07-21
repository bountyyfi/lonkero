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

        // ============================================================================
        // Sensitive information dorks — high-signal, low-false-positive queries the
        // pentester validates in Google/Bing/DuckDuckGo. Each query targets a
        // credential-shaped file, an accidentally-indexed console, or a public
        // artifact that has historically leaked keys.
        // ============================================================================

        // .env files — indexed environment files are one of the most common
        // sources of live production secrets.
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (ext:env | ext:envrc | inurl:\".env\") (intext:DB_PASSWORD | intext:SECRET_KEY | intext:API_KEY | intext:AWS_ACCESS_KEY)",
                clean_domain
            ),
            description: "Find indexed .env files with credentials".to_string(),
            impact: "Environment files typically contain live database and API credentials.".to_string(),
        });

        // Framework config files that ship secrets when checked in
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php | inurl:configuration.php | inurl:settings.py | inurl:web.config | inurl:appsettings.json) intext:password",
                clean_domain
            ),
            description: "Find framework config files leaking passwords".to_string(),
            impact: "CMS/app config files leak database and integration credentials.".to_string(),
        });

        // Private keys served over HTTP
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:p12 | ext:pfx | ext:jks | ext:keystore) (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find private keys served over HTTP".to_string(),
            impact: "PEM/PKCS12 keys enable impersonation, code signing, and infrastructure access.".to_string(),
        });

        // Docker/K8s manifests with baked-in secrets
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:kustomization.yaml | inurl:values.yaml) (intext:password | intext:secret | intext:token)",
                clean_domain
            ),
            description: "Find Docker/K8s manifests with embedded secrets".to_string(),
            impact: "Container/K8s manifests routinely embed database, registry, and cloud credentials.".to_string(),
        });

        // Terraform state / plan artifacts
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | ext:tfplan | inurl:terraform.tfstate)",
                clean_domain
            ),
            description: "Find Terraform state or vars files".to_string(),
            impact: "Terraform state stores every provider credential in plaintext.".to_string(),
        });

        // CI/CD workflow files with tokens
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.github/workflows | inurl:.gitlab-ci.yml | inurl:bitbucket-pipelines.yml | inurl:Jenkinsfile | inurl:azure-pipelines.yml) (intext:token | intext:secret | intext:password)",
                clean_domain
            ),
            description: "Find CI/CD pipeline definitions leaking tokens".to_string(),
            impact: "Pipelines often reference tokens by name and leak provider identifiers usable in phishing.".to_string(),
        });

        // Cloud provider credential file names
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:.aws/config | inurl:.boto | inurl:credentials.json | inurl:client_secret.json)",
                clean_domain
            ),
            description: "Find leaked cloud SDK credential files".to_string(),
            impact: "AWS/GCP/Azure SDK credential files expose long-lived access keys.".to_string(),
        });

        // SSH known_hosts / authorized_keys / private keys by name
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (inurl:id_rsa | inurl:id_dsa | inurl:id_ed25519 | inurl:id_ecdsa | inurl:authorized_keys | inurl:.ssh/config)",
                clean_domain
            ),
            description: "Find indexed SSH key material".to_string(),
            impact: "Any SSH private key served over HTTP is a full server-access credential.".to_string(),
        });

        // Password-manager and keychain exports
        dorks.push(GoogleDork {
            category: "Exposed Credentials".to_string(),
            query: format!(
                "site:{} (ext:kdbx | ext:kdb | ext:1pif | ext:agilekeychain | ext:opvault)",
                clean_domain
            ),
            description: "Find password-manager vault exports".to_string(),
            impact: "Vault files enable offline cracking of every stored credential.".to_string(),
        });

        // Database dumps and backups
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:mdb | ext:sqlite | ext:sqlitedb | ext:db | ext:bak) (intext:INSERT | intext:CREATE TABLE | intext:PRIVILEGES)",
                clean_domain
            ),
            description: "Find database dumps served over HTTP".to_string(),
            impact: "SQL dumps contain full user tables, password hashes, and business data.".to_string(),
        });

        // Miscellaneous backup archive extensions
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:7z | ext:rar) (inurl:backup | inurl:dump | inurl:archive | inurl:snapshot)",
                clean_domain
            ),
            description: "Find archive backups exposed on the site".to_string(),
            impact: "Backup archives frequently include full source trees, DB dumps, and secrets.".to_string(),
        });

        // .git metadata exposure (repos accidentally deployed)
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.git/index | inurl:.gitignore)",
                clean_domain
            ),
            description: "Find exposed .git repositories on the web root".to_string(),
            impact: "Exposed .git enables full source tree reconstruction, revealing history and secrets.".to_string(),
        });

        // Other VCS metadata
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.svn/entries | inurl:.svn/wc.db | inurl:.hg/hgrc | inurl:.bzr/branch/branch.conf | inurl:CVS/Entries)",
                clean_domain
            ),
            description: "Find exposed SVN/Hg/Bzr/CVS metadata".to_string(),
            impact: "Non-git VCS metadata also permits full source reconstruction.".to_string(),
        });

        // Idea/IDE project leaks including workspace secrets
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.idea/workspace.xml | inurl:.vscode/settings.json | inurl:.vscode/launch.json | inurl:.project | inurl:nbproject/private)",
                clean_domain
            ),
            description: "Find IDE workspace files with local paths and secrets".to_string(),
            impact: "IDE metadata leaks internal paths, DB URLs, and per-user tokens.".to_string(),
        });

        // Exposed .DS_Store enabling directory reconstruction
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} inurl:.DS_Store",
                clean_domain
            ),
            description: "Find .DS_Store files enabling directory listing recovery".to_string(),
            impact: "macOS metadata leaks the full local directory structure of the deploy source.".to_string(),
        });

        // Spring Boot Actuator exposure
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/beans)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator endpoints leak env, heap dumps, thread state, and often allow RCE via /jolokia.".to_string(),
        });

        // PHP info() and phpinfo pages
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | inurl:test.php | intitle:\"phpinfo()\" | intext:\"PHP Version\" intext:\"Loaded Configuration File\")",
                clean_domain
            ),
            description: "Find phpinfo() disclosure pages".to_string(),
            impact: "phpinfo leaks configuration, module list, environment variables, and internal paths.".to_string(),
        });

        // Rails / Django / Symfony debug interfaces
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/_profiler | inurl:/_debug | inurl:/debug/pprof | inurl:/rails/info | inurl:/__debug__ | inurl:django-admin | inurl:/_symfony/db) intitle:debug",
                clean_domain
            ),
            description: "Find framework debug/profiler pages".to_string(),
            impact: "Debug/profiler pages expose stack traces, request state, and sometimes DB schemas.".to_string(),
        });

        // Elasticsearch/Kibana/Grafana public installs
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | intitle:\"Grafana\" | inurl:/_cat/indices | inurl:/_cluster/health | inurl:/kibana | inurl:/grafana)",
                clean_domain
            ),
            description: "Find Kibana/Grafana or Elasticsearch endpoints".to_string(),
            impact: "Search/monitoring dashboards routinely ship without auth and expose logs and metrics.".to_string(),
        });

        // Jenkins / Bamboo / TeamCity public dashboards
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/manage | inurl:/script | inurl:/computer | intitle:\"Bamboo Dashboard\" | intitle:\"TeamCity\")",
                clean_domain
            ),
            description: "Find CI dashboards (Jenkins/Bamboo/TeamCity)".to_string(),
            impact: "CI dashboards frequently allow anonymous job execution or leak build logs with secrets.".to_string(),
        });

        // Container registries and package repos
        dorks.push(GoogleDork {
            category: "Admin/Debug Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/v2/_catalog | inurl:/artifactory | inurl:/nexus/repository | inurl:/harbor)",
                clean_domain
            ),
            description: "Find Docker registry/Artifactory/Nexus/Harbor interfaces".to_string(),
            impact: "Exposed registries let attackers pull private images or push malicious ones.".to_string(),
        });

        // Postman public workspaces (mentioning the target)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:postman.com \"{}\"",
                clean_domain
            ),
            description: "Find Postman public workspaces mentioning the domain".to_string(),
            impact: "Postman workspaces routinely embed tokens and cookies in saved requests.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:getpostman.com \"{}\"",
                clean_domain
            ),
            description: "Find getpostman.com collections mentioning the domain".to_string(),
            impact: "Legacy Postman collections may contain live Authorization headers.".to_string(),
        });

        // Public gist/paste search engines for source
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\"",
                clean_domain
            ),
            description: "Find GitHub Gists referencing the domain".to_string(),
            impact: "Gists frequently include tokens saved for personal testing.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gitter.im OR site:notion.so OR site:hackmd.io \"{}\"",
                clean_domain
            ),
            description: "Find internal-style chat/knowledge base leaks".to_string(),
            impact: "Notion, HackMD, and Gitter pages often preserve credentials from doc drafting.".to_string(),
        });

        // Wayback Machine — historical exposure that lingers after removal
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "site:web.archive.org \"{}\"",
                clean_domain
            ),
            description: "Find Wayback Machine snapshots of the domain".to_string(),
            impact: "Archived snapshots preserve pages deleted for containing secrets.".to_string(),
        });

        // JWT tokens accidentally rendered on public pages
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} intext:\"eyJhbGciOi\"",
                clean_domain
            ),
            description: "Find rendered JWT tokens".to_string(),
            impact: "JWTs pasted into pages/logs can be replayed if unexpired.".to_string(),
        });

        // Slack/Discord/Telegram webhook URLs on public pages
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"hooks.slack.com/services/\" | intext:\"discord.com/api/webhooks/\" | intext:\"discordapp.com/api/webhooks/\" | intext:\"api.telegram.org/bot\")",
                clean_domain
            ),
            description: "Find chat webhook URLs".to_string(),
            impact: "Webhook URLs enable arbitrary message posting and social-engineering leverage.".to_string(),
        });

        // Sentry DSNs published in HTML
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} intext:\"@sentry.io/\" intext:\"https://\"",
                clean_domain
            ),
            description: "Find Sentry DSNs embedded on pages".to_string(),
            impact: "Public DSNs allow event poisoning and reveal internal project structure.".to_string(),
        });

        // Google Maps / Firebase / Stripe publishable keys — recon value only
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"AIzaSy\" | intext:\"pk_live_\" | intext:\"apiKey: \\\"\")",
                clean_domain
            ),
            description: "Find Google/Firebase/Stripe front-end keys".to_string(),
            impact: "Google/Firebase keys often lack HTTP referer restrictions and enable quota abuse or data access.".to_string(),
        });

        // SharePoint / Confluence anonymously-accessible knowledge bases
        dorks.push(GoogleDork {
            category: "Internal Documents".to_string(),
            query: format!(
                "(site:atlassian.net | site:sharepoint.com | inurl:/wiki | inurl:/confluence) \"{}\"",
                clean_domain
            ),
            description: "Find anonymously-viewable Confluence/SharePoint pages".to_string(),
            impact: "Publicly-shared wiki pages routinely contain runbooks, onboarding secrets, and API keys.".to_string(),
        });

        // AWS Cognito hosted UI (unprotected pool discovery)
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:amazoncognito.com \"{}\"",
                clean_domain
            ),
            description: "Find AWS Cognito hosted-UI pools tied to the domain".to_string(),
            impact: "Cognito pools misconfigured for self-signup allow arbitrary account creation.".to_string(),
        });

        // Public Airtable / Notion / Google Sheets — internal data
        dorks.push(GoogleDork {
            category: "Internal Documents".to_string(),
            query: format!(
                "(site:airtable.com | site:notion.site | site:docs.google.com/spreadsheets) \"{}\"",
                clean_domain
            ),
            description: "Find public spreadsheets/knowledge bases mentioning the domain".to_string(),
            impact: "Public spreadsheets have leaked customer lists, KPIs, and API keys in production.".to_string(),
        });

        // Bug/incident write-ups referencing the domain
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "(site:hackerone.com | site:bugcrowd.com | site:huntr.dev | site:intigriti.com | site:medium.com | site:dev.to) \"{}\"",
                clean_domain
            ),
            description: "Find prior write-ups mentioning the domain".to_string(),
            impact: "Old write-ups reveal fixed and unfixed vulnerability classes for the target.".to_string(),
        });

        // Public issue trackers referencing internal URLs
        dorks.push(GoogleDork {
            category: "Internal Documents".to_string(),
            query: format!(
                "(site:github.com/issues | site:gitlab.com/-/issues | site:issues.jenkins.io | site:bugzilla.mozilla.org) \"{}\"",
                clean_domain
            ),
            description: "Find issue trackers referencing internal hostnames".to_string(),
            impact: "Public bug reports frequently paste stack traces containing internal URLs, DB hosts, and tokens.".to_string(),
        });

        // Backup file naming variations under commonly-served roots
        dorks.push(GoogleDork {
            category: "Data Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.bak | inurl:.old | inurl:.orig | inurl:.copy | inurl:.swp | inurl:.save | inurl:~)",
                clean_domain
            ),
            description: "Find editor/backup file leftovers".to_string(),
            impact: "Editor/backup file variants often serve unpatched application source.".to_string(),
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
