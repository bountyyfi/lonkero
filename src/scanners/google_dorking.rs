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

        // ====================================================================
        // High-impact sensitive-surface dorks (low false-positive, high signal).
        // Targets that, when indexed by Google, are almost always accidental
        // exposures rather than intentional public content.
        // ====================================================================

        // Spring Boot Actuator endpoints — /env and /heapdump alone are enough
        // to recover database passwords, JWT signing keys, and OAuth secrets.
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/loggers | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/beans)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env and /configprops leak DB passwords, JWT secrets and API keys; /heapdump lets an attacker carve credentials from process memory; /mappings and /beans map the internal API surface for follow-up attacks".to_string(),
        });

        // Legacy Spring 1.x / non-default actuator paths.
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/manage/env | inurl:/management/env | inurl:/admin/env | inurl:/jolokia/list | inurl:/hawtio)",
                clean_domain
            ),
            description: "Find legacy Spring management and Jolokia/Hawtio consoles".to_string(),
            impact: "Same secret-leak impact as modern actuator; Jolokia/Hawtio additionally allow JMX-based RCE on misconfigured JVMs".to_string(),
        });

        // .env variants — production deployments routinely commit these.
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:.env.production | inurl:.env.prod | inurl:.env.local | inurl:.env.development | inurl:.env.staging | inurl:.env.dist | inurl:.env.example | inurl:.env.backup | inurl:.env.bak)",
                clean_domain
            ),
            description: "Find leaked dotenv files".to_string(),
            impact: ".env files typically contain database credentials, third-party API keys, mail/SMTP passwords and signing secrets — single-file full compromise of an app's secrets".to_string(),
        });

        // Exposed VCS metadata directories — clone the repo without auth.
        dorks.push(GoogleDork {
            category: "Exposed Source Control".to_string(),
            query: format!(
                "site:{} (inurl:/.git/HEAD | inurl:/.git/config | inurl:/.git/index | inurl:/.svn/entries | inurl:/.svn/wc.db | inurl:/.hg/store | inurl:/.bzr/branch)",
                clean_domain
            ),
            description: "Find exposed .git / .svn / .hg / .bzr directories".to_string(),
            impact: "Allows reconstructing the full source tree (including deleted files, deploy keys and historical secrets) from the indexed metadata files".to_string(),
        });

        // Infrastructure-as-code state and var files — tfstate stores resolved
        // secrets in plaintext, tfvars typically defines provider credentials.
        dorks.push(GoogleDork {
            category: "Infrastructure-as-Code".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:terraform.tfstate | inurl:.terraform/terraform.tfstate | inurl:terragrunt.hcl | inurl:pulumi.yaml)",
                clean_domain
            ),
            description: "Find Terraform/Pulumi state and variable files".to_string(),
            impact: "tfstate captures every resource attribute including resolved cloud credentials, RDS passwords and TLS private keys in plaintext; tfvars often pins provider AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY".to_string(),
        });

        // Kubernetes config files.
        dorks.push(GoogleDork {
            category: "Infrastructure-as-Code".to_string(),
            query: format!(
                "site:{} (inurl:.kube/config | inurl:kubeconfig | ext:kubeconfig | inurl:admin.conf intext:\"apiVersion: v1\" | inurl:helm-charts inurl:values.yaml)",
                clean_domain
            ),
            description: "Find exposed kubeconfig and Helm values files".to_string(),
            impact: "A kubeconfig grants direct cluster API access (typically cluster-admin); Helm values.yaml frequently pins image-pull secrets, registry creds and DB passwords".to_string(),
        });

        // CI/CD configuration — pipelines are a common spot for hardcoded
        // credentials when developers don't yet trust the secret store.
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:.gitlab-ci.yml | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:.circleci/config.yml | inurl:.drone.yml | inurl:Jenkinsfile | inurl:.github/workflows)",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline definitions".to_string(),
            impact: "Pipeline files often contain hardcoded deploy tokens, registry credentials, signing keys, SSH private keys and references to internal services that map the build infrastructure".to_string(),
        });

        // Container build and compose files.
        dorks.push(GoogleDork {
            category: "Container Configuration".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:docker-compose.override.yml | inurl:Dockerfile.prod | inurl:.docker/config.json)",
                clean_domain
            ),
            description: "Find exposed Docker compose files and registry auth".to_string(),
            impact: "docker-compose files reveal service topology and frequently inline DB_PASSWORD / API_KEY environment values; .docker/config.json contains base64-encoded registry credentials".to_string(),
        });

        // Cloud-vendor credential and key files.
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:.aws/config | inurl:.boto | inurl:gcloud/credentials.db | inurl:azureProfile.json | inurl:.ssh/id_rsa | inurl:.ssh/authorized_keys)",
                clean_domain
            ),
            description: "Find leaked cloud CLI credentials and SSH keys".to_string(),
            impact: "Direct credential reuse: AWS/GCP/Azure CLI credential files give full account access at the IAM identity's permission level; id_rsa enables direct SSH compromise".to_string(),
        });

        // Database admin web UIs — when indexed by Google they're invariably
        // exposed to the public internet without IP allow-listing.
        dorks.push(GoogleDork {
            category: "Database Admin UIs".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin/index.php | inurl:adminer.php | inurl:pgadmin | inurl:rockmongo | inurl:mongo-express | inurl:cloudbeaver | inurl:dbgate | inurl:sqlbuddy)",
                clean_domain
            ),
            description: "Find publicly indexed database administration panels".to_string(),
            impact: "If reachable from Google, the admin UI is reachable from the internet — direct credential-stuffing / default-creds target, and an immediate path to data exfiltration on any compromise".to_string(),
        });

        // Backup archives — looking only at archive/dump file types.
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sql.gz | ext:dump | ext:dmp | ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z | ext:bak | ext:backup)",
                clean_domain
            ),
            description: "Find database dumps and archive backups".to_string(),
            impact: "Database dumps and archive backups commonly contain the full production schema, user records (including hashed and sometimes plaintext credentials) and embedded secrets".to_string(),
        });

        // Directory listings — Apache/nginx auto-index pages, usually
        // unintentional and a quick way into source / backups / logs.
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} (intitle:\"index of /\" \"parent directory\" | intitle:\"index of /backup\" | intitle:\"index of /logs\" | intitle:\"index of /uploads\" | intitle:\"index of /db\" | intitle:\"index of /sql\")",
                clean_domain
            ),
            description: "Find open Apache/nginx directory listings".to_string(),
            impact: "Auto-indexed directories expose every file in the path — frequently backups, logs, uploads or database dumps that were never meant to be enumerable".to_string(),
        });

        // Exposed log files — debug/error logs leak stack traces, session IDs
        // and occasionally credentials.
        dorks.push(GoogleDork {
            category: "Exposed Logs".to_string(),
            query: format!(
                "site:{} (ext:log inurl:debug | ext:log inurl:error | ext:log inurl:access | inurl:laravel.log | inurl:storage/logs | inurl:wp-content/debug.log | inurl:npm-debug.log)",
                clean_domain
            ),
            description: "Find exposed application and framework log files".to_string(),
            impact: "Application logs commonly contain session tokens, authorization headers, stack traces revealing internal paths, and queries with parameter values that include user PII".to_string(),
        });

        // Apache server-status / server-info — leaks live request data
        // including auth headers from other users.
        dorks.push(GoogleDork {
            category: "Server Status Pages".to_string(),
            query: format!(
                "site:{} (inurl:/server-status intitle:\"Apache Status\" | inurl:/server-info intitle:\"Server Information\" | inurl:/nginx_status)",
                clean_domain
            ),
            description: "Find exposed Apache/nginx server status pages".to_string(),
            impact: "server-status streams live request URIs across all virtual hosts — leaks session IDs and bearer tokens in query strings, and provides a continuously updated map of the application".to_string(),
        });

        // Web framework config files.
        dorks.push(GoogleDork {
            category: "Application Config Files".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.old | inurl:wp-config.txt | inurl:web.config inurl:.bak | ext:config intext:\"<connectionStrings\" | inurl:application.properties | inurl:application.yml inurl:src)",
                clean_domain
            ),
            description: "Find backup copies of framework config files".to_string(),
            impact: "wp-config.* backups and ASP.NET web.config.bak files are served as plaintext (not interpreted) — DB credentials and machine keys read directly; Spring application.properties commonly inlines DB and OAuth secrets".to_string(),
        });

        // Public GraphQL playgrounds / introspection UIs.
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/graphiql | inurl:/playground | inurl:/altair | inurl:/voyager | inurl:/graphql-explorer | intitle:\"GraphQL Playground\")",
                clean_domain
            ),
            description: "Find exposed GraphQL development UIs".to_string(),
            impact: "Playgrounds in production imply introspection is enabled — full schema disclosure including admin mutations, internal types and field-level authorization gaps for follow-up testing".to_string(),
        });

        // WSDL / SOAP / OpenAPI specs hosted publicly.
        dorks.push(GoogleDork {
            category: "API Definition Files".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:wadl | inurl:?wsdl | inurl:openapi.yaml | inurl:openapi.json | inurl:swagger.yaml | inurl:swagger.json | inurl:api-spec.yaml)",
                clean_domain
            ),
            description: "Find published WSDL/WADL/OpenAPI definitions".to_string(),
            impact: "Machine-readable API specs enumerate every operation, including internal-only admin endpoints, parameter types and authentication requirements — accelerates targeted testing against a full known interface".to_string(),
        });

        // Cloud object storage — vendors not yet covered.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:wasabisys.com | site:backblazeb2.com | site:linodeobjects.com | site:r2.dev | site:r2.cloudflarestorage.com | site:objectstorage.oraclecloud.com | site:fra1.digitaloceanspaces.com) \"{}\"",
                clean_domain
            ),
            description: "Find buckets on Wasabi, Backblaze B2, Linode, Cloudflare R2 and OCI".to_string(),
            impact: "Same misconfiguration class as S3 buckets, but commonly missed by S3-only tooling — public listing or direct object access on dev/staging/CI artifact buckets".to_string(),
        });

        // Public Notion / docs sharing — internal pages mistakenly marked public.
        dorks.push(GoogleDork {
            category: "Public Knowledge Bases".to_string(),
            query: format!(
                "(site:notion.so | site:notion.site | site:hackmd.io | site:hedgedoc.org | site:roamresearch.com | site:obsidian.md/publish) \"{}\"",
                clean_domain
            ),
            description: "Find public Notion / HackMD / wiki pages mentioning the domain".to_string(),
            impact: "Internal runbooks, onboarding docs, vendor credentials and architecture notes routinely end up on personal Notion pages with \"share to web\" still toggled on".to_string(),
        });

        // Public Postman collections / docs — frequently embed real auth tokens.
        dorks.push(GoogleDork {
            category: "Public Knowledge Bases".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:elements.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman collections and documentation".to_string(),
            impact: "Shared Postman collections regularly inline staging/prod bearer tokens, basic-auth credentials and full request examples against internal-only endpoints".to_string(),
        });

        // Online code sandboxes — where developers paste real config.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:codesandbox.io | site:replit.com | site:glitch.com | site:stackblitz.com | site:gist.github.com | site:gitlab.com/snippets | site:bitbucket.org/snippets) \"{}\"",
                clean_domain
            ),
            description: "Find code on sandbox/snippet platforms referencing the domain".to_string(),
            impact: "Developer scratch projects on these platforms frequently include real API tokens, signed JWTs and internal endpoint URLs as part of \"minimal reproductions\" or shared examples".to_string(),
        });

        // Self-hosted source forges.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:bitbucket.org | site:gitea.com | site:gitea.io | site:codeberg.org | site:gogs.io | site:forgejo.org | site:sourceforge.net) \"{}\"",
                clean_domain
            ),
            description: "Find references on alternative source-control platforms".to_string(),
            impact: "Bitbucket / Gitea / Codeberg mirrors are not deduplicated against GitHub searches — covers historical exports and forks that may still leak credentials removed from the canonical repo".to_string(),
        });

        // Public Sentry/error-tracking projects.
        dorks.push(GoogleDork {
            category: "Error Tracking".to_string(),
            query: format!(
                "(site:sentry.io | site:rollbar.com | site:bugsnag.com | site:airbrake.io) \"{}\"",
                clean_domain
            ),
            description: "Find publicly accessible error-tracking projects".to_string(),
            impact: "Public Sentry projects expose live exception streams that include request URLs, parameters, headers (often with auth) and stack traces revealing internal file paths and dependency versions".to_string(),
        });

        // Additional public paste services.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:hastebin.com | site:dpaste.org | site:dpaste.com | site:paste.ee | site:0bin.net | site:rentry.co | site:controlc.com | site:ide.geeksforgeeks.org) \"{}\"",
                clean_domain
            ),
            description: "Find pastes on alternative paste platforms".to_string(),
            impact: "These platforms are not covered by Pastebin-only tooling — developers and attackers alike use them to share configs, credentials and partial database dumps".to_string(),
        });

        // Issue trackers / project tools outside Atlassian.
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "(site:linear.app | site:youtrack.cloud | site:asana.com | site:monday.com | site:clickup.com | site:basecamp.com) \"{}\"",
                clean_domain
            ),
            description: "Find references in Linear/YouTrack/Asana/Monday/ClickUp".to_string(),
            impact: "Public-shared cards in these tools regularly contain reproduction steps for unfixed vulnerabilities, attached log snippets with PII, and links to internal staging environments".to_string(),
        });

        // Secrets-management UIs that should never be internet-reachable.
        dorks.push(GoogleDork {
            category: "Secrets Management".to_string(),
            query: format!(
                "site:{} (inurl:/v1/sys/health | inurl:/ui/vault | intitle:\"Vault\" inurl:8200 | inurl:/secrets-manager | inurl:/secret/data)",
                clean_domain
            ),
            description: "Find exposed HashiCorp Vault or secrets-manager UIs".to_string(),
            impact: "An internet-reachable Vault is a top-tier target — even unauthenticated, /sys/health and /sys/seal-status confirm an attack surface that, if misconfigured, holds every secret the org has chosen to centralize".to_string(),
        });

        // Mobile app source-map / bundle leaks (.map files).
        dorks.push(GoogleDork {
            category: "Source Map Exposure".to_string(),
            query: format!(
                "site:{} (ext:map inurl:.js.map | ext:map inurl:.css.map | inurl:_next/static inurl:.map | inurl:assets inurl:.map)",
                clean_domain
            ),
            description: "Find exposed JavaScript/CSS source map files".to_string(),
            impact: "Source maps reproduce the unminified frontend source — including comments, internal API endpoint URLs, feature-flag names and occasionally hardcoded staging tokens".to_string(),
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
