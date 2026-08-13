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
        // High-value sensitive-data dorks. Each block below targets a
        // specific class of exposure a real pentester wants to see first:
        // credentials in text form, cloud infrastructure state that gates
        // production, machine-to-machine config, and personally identifiable
        // data. Every query is anchored to `site:{domain}` (or to a public
        // paste/storage host cross-referenced with the domain) so nothing
        // becomes background noise.
        // ------------------------------------------------------------------

        // Environment files: .env, .env.local, .env.production - almost
        // always contain DB creds, API keys, and Django/Rails SECRET_KEY.
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (ext:env | ext:local | inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.development | inurl:.env.staging)",
                clean_domain
            ),
            description: "Find leaked .env dotfiles in any environment tier".to_string(),
            impact:
                "Direct exposure of DB credentials, framework secret keys, third-party API keys, and cloud tokens."
                    .to_string(),
        });

        // Docker / Kubernetes / Compose manifests referencing the target.
        dorks.push(GoogleDork {
            category: "Container Manifests".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:Dockerfile | inurl:kustomization.yaml | inurl:values.yaml | inurl:kubeconfig | ext:kubeconfig)",
                clean_domain
            ),
            description: "Docker/Kubernetes manifests exposed on the web root".to_string(),
            impact:
                "Reveals image tags, mounted secrets, service accounts, and internal network topology; kubeconfig files hand over the cluster."
                    .to_string(),
        });

        // Terraform state / plan output — full infrastructure map plus
        // resource-embedded secrets. State files never contain non-secret
        // data of value to search engines and are pure signal.
        dorks.push(GoogleDork {
            category: "IaC State".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfstate.backup | ext:tfvars | inurl:terraform.tfstate | inurl:.terraform)",
                clean_domain
            ),
            description: "Terraform state, backup, or tfvars files".to_string(),
            impact:
                "State files contain plaintext copies of every secret Terraform touches (DB passwords, IAM keys, private-key material)."
                    .to_string(),
        });

        // Ansible vault-encrypted files (still worth reporting: sometimes
        // stored alongside the decryption password) and plaintext playbooks.
        dorks.push(GoogleDork {
            category: "Configuration Management".to_string(),
            query: format!(
                "site:{} (ext:yml | ext:yaml) (inurl:playbook | inurl:vault | inurl:group_vars | inurl:host_vars | inurl:inventory)",
                clean_domain
            ),
            description: "Ansible playbooks, vaults, and inventory files".to_string(),
            impact:
                "Ansible vaults sometimes ship with their vault-password file next to them; plaintext playbooks contain SSH keys, sudo passwords, and target inventory."
                    .to_string(),
        });

        // CI/CD pipeline definitions — reveal build secrets, deploy
        // credentials, environment topology.
        dorks.push(GoogleDork {
            category: "CI/CD Pipelines".to_string(),
            query: format!(
                "site:{} (inurl:.gitlab-ci.yml | inurl:.travis.yml | inurl:.circleci/config.yml | inurl:Jenkinsfile | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:.github/workflows | inurl:buildkite | inurl:cloudbuild.yaml | inurl:drone.yml)",
                clean_domain
            ),
            description: "CI/CD pipeline manifests served over HTTP".to_string(),
            impact:
                "Pipeline files often contain deploy-user tokens, registry credentials, artifact-signing keys, and internal deploy endpoints."
                    .to_string(),
        });

        // Package-manager credential files.
        dorks.push(GoogleDork {
            category: "Package Manager Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.npmrc | inurl:.yarnrc | inurl:.pypirc | inurl:pip.conf | inurl:.gem/credentials | inurl:.m2/settings.xml | inurl:.gradle/gradle.properties | inurl:.cargo/credentials | inurl:nuget.config)",
                clean_domain
            ),
            description: "Package-registry authentication files".to_string(),
            impact:
                "npm/PyPI/Maven/RubyGems publish tokens enable supply-chain package hijacking, not just data theft."
                    .to_string(),
        });

        // Version-control internals directly served by the webroot.
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.git/logs/HEAD | inurl:.svn/entries | inurl:.hg/store | inurl:.bzr/branch | inurl:CVS/Root)",
                clean_domain
            ),
            description: "Exposed VCS metadata directories".to_string(),
            impact:
                "A reachable .git tree enables full repository reconstruction — code, credentials in history, and commit-author leakage."
                    .to_string(),
        });

        // IDE / editor drop files that mirror the workspace secrets.
        dorks.push(GoogleDork {
            category: "IDE Metadata".to_string(),
            query: format!(
                "site:{} (inurl:.idea/workspace.xml | inurl:.idea/dataSources.xml | inurl:.vscode/settings.json | inurl:.vscode/launch.json | inurl:sftp-config.json | inurl:.ftpconfig | inurl:nbproject/private)",
                clean_domain
            ),
            description: "Leaked IDE/editor project files".to_string(),
            impact:
                "JetBrains dataSources.xml stores DB DSNs; VS Code launch.json embeds env vars; SFTP configs carry SSH credentials verbatim."
                    .to_string(),
        });

        // Database dumps and backup archives.
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:bak | ext:mdf | ext:sqlitedb | ext:sqlite3 | ext:db3 | ext:pgsql) (INSERT INTO | CREATE TABLE | -- MySQL dump | -- PostgreSQL database dump)",
                clean_domain
            ),
            description: "SQL dump/backup files served publicly".to_string(),
            impact:
                "Dumps expose every row of the affected tables — customer PII, hashed credentials, session tokens with unlimited replay window."
                    .to_string(),
        });

        // Compressed backup archives commonly forgotten in the webroot.
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z | ext:gz | ext:bz2) (inurl:backup | inurl:bak | inurl:archive | inurl:dump | inurl:old)",
                clean_domain
            ),
            description: "Compressed backups matching backup/archive path hints".to_string(),
            impact:
                "Archive files reveal full source trees, database snapshots, or filesystem exports."
                    .to_string(),
        });

        // Cryptographic material — private keys and certificates.
        dorks.push(GoogleDork {
            category: "Cryptographic Keys".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:p12 | ext:pfx | ext:jks | ext:keystore | ext:asc | inurl:id_rsa | inurl:id_dsa | inurl:id_ecdsa | inurl:id_ed25519)",
                clean_domain
            ),
            description: "Private keys and certificate bundles".to_string(),
            impact:
                "Server private keys enable TLS impersonation and, when reused, direct root SSH; SSH private keys grant persistent access to whatever they were authorised for."
                    .to_string(),
        });

        // Cloud credentials on disk.
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:.aws/config | inurl:.docker/config.json | inurl:.kube/config | inurl:gcloud/credentials.db | inurl:application_default_credentials.json | inurl:azure/credentials)",
                clean_domain
            ),
            description: "Cloud CLI credential files".to_string(),
            impact:
                "Direct programmatic access to the customer's cloud tenant. AWS credentials commonly grant PowerUser or Admin; kubeconfigs give shell-in-pod."
                    .to_string(),
        });

        // Framework-secret leaks: Spring Boot Actuator, .env in Django,
        // WordPress wp-config.php back-ups.
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:actuator/env | inurl:actuator/heapdump | inurl:actuator/threaddump | inurl:actuator/configprops | inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.php.swp | inurl:local_settings.py | inurl:settings.py.bak)",
                clean_domain
            ),
            description: "Framework debug/config endpoints and back-up copies".to_string(),
            impact:
                "Spring Actuator /env leaks DB passwords and cloud tokens; heapdump enables in-memory credential extraction; wp-config back-ups hand over the WordPress DB user."
                    .to_string(),
        });

        // Storage service enumeration expanded beyond the S3-only list.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:*.r2.dev | site:*.r2.cloudflarestorage.com | site:*.storage.yandexcloud.net | site:*.wasabisys.com | site:*.backblazeb2.com | site:*.storage-download.googleapis.com | site:*.aliyuncs.com | site:*.oss-cn-hangzhou.aliyuncs.com | site:*.ovh.net | site:*.linodeobjects.com) \"{}\"",
                clean_domain
            ),
            description:
                "Object-storage buckets on non-AWS providers referenced by the domain".to_string(),
            impact:
                "Public buckets on Wasabi/Backblaze/Cloudflare R2/Alibaba OSS are often forgotten and rarely audited by CSPM tools."
                    .to_string(),
        });

        // Public paste sites with domain-tied leaks.
        dorks.push(GoogleDork {
            category: "Public Pastes".to_string(),
            query: format!(
                "(site:pastebin.com | site:ghostbin.com | site:hastebin.com | site:paste.ee | site:controlc.com | site:paste2.org | site:justpaste.it | site:0bin.net | site:privatebin.net | site:rentry.co) \"{}\" (password | api_key | token | secret | private_key | BEGIN RSA)",
                clean_domain
            ),
            description: "Paste-site leaks combining the domain and a credential keyword"
                .to_string(),
            impact: "Insiders and integrators drop debug output containing live secrets on paste sites; findings are typically actionable within minutes."
                .to_string(),
        });

        // Public code-sharing services indexing the domain — extends the
        // GitHub search with the Big Three code search UIs and Sourcegraph.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:github.com | site:gist.github.com | site:gitlab.com | site:bitbucket.org | site:sourcegraph.com | site:searchcode.com | site:grep.app) \"{}\" (password | api_key | apikey | authorization | Bearer | client_secret)",
                clean_domain
            ),
            description: "Public code hosting cross-referenced with credential keywords"
                .to_string(),
            impact: "Turns generic \"code mentions\" into actionable secret-leak candidates."
                .to_string(),
        });

        // Grafana / Kibana / open observability tooling that indexes the
        // domain and leaks queries, logs, and dashboards.
        dorks.push(GoogleDork {
            category: "Observability".to_string(),
            query: format!(
                "site:{} (inurl:grafana | inurl:kibana | inurl:app/kibana | inurl:_plugin/kibana | inurl:elasticsearch | inurl:_cat/indices | inurl:_all/_search | inurl:prometheus | inurl:alertmanager | inurl:jaeger | inurl:zipkin)",
                clean_domain
            ),
            description: "Unauthenticated dashboards and log-query UIs".to_string(),
            impact:
                "Elastic /_cat/indices reveals every index name; Grafana/Kibana with anonymous access exposes production query results and dashboards."
                    .to_string(),
        });

        // Internal admin dashboards commonly deployed alongside apps.
        dorks.push(GoogleDork {
            category: "Admin Dashboards".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin | inurl:adminer.php | inurl:mongo-express | inurl:redis-commander | inurl:rockmongo | inurl:mysqlworkbench | inurl:pgadmin | inurl:datagrip | inurl:opensearch-dashboards | inurl:solr/#/ | inurl:solr/admin | inurl:rabbitmq | inurl:kong/status | inurl:consul/ui | inurl:vault/ui | inurl:portainer | inurl:rancher | inurl:kubernetes-dashboard | inurl:traefik/dashboard)",
                clean_domain
            ),
            description: "Admin panels for databases, message brokers, and orchestrators".to_string(),
            impact:
                "Many of these ship with default credentials or an unauthenticated read view that leaks table names, queue contents, or cluster state."
                    .to_string(),
        });

        // Debug / trace endpoints — Django, Rails, Symfony, Flask.
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:__debug__ | inurl:_profiler | inurl:_wdt | inurl:debug_toolbar | inurl:__debug/ | inurl:rails/info | inurl:rails/info/routes | inurl:__profiler__ | inurl:/console | inurl:werkzeug | inurl:_debugbar | inurl:phpinfo.php | inurl:info.php | inurl:test.php | inurl:phptest.php)",
                clean_domain
            ),
            description: "Framework debug toolbars, /console, and phpinfo pages".to_string(),
            impact:
                "Debug toolbars expose SQL queries, session data, and environment; Werkzeug console is direct RCE; phpinfo enumerates modules and secrets."
                    .to_string(),
        });

        // Exposed configuration files by exact filename.
        dorks.push(GoogleDork {
            category: "Configuration Files".to_string(),
            query: format!(
                "site:{} (inurl:config.php | inurl:configuration.php | inurl:web.config | inurl:appsettings.json | inurl:appsettings.development.json | inurl:application.properties | inurl:application.yml | inurl:application-prod.yml | inurl:parameters.yml | inurl:parameters.yaml | inurl:secrets.yml | inurl:secrets.json | inurl:conf.d)",
                clean_domain
            ),
            description: "Named config files reachable from the webroot".to_string(),
            impact:
                "appsettings.Development.json, parameters.yml, and web.config routinely embed DB connection strings and IdentityServer secrets."
                    .to_string(),
        });

        // Payment / PCI data patterns.
        dorks.push(GoogleDork {
            category: "Payment Data".to_string(),
            query: format!(
                "site:{} (intext:\"cc_number\" | intext:\"credit_card\" | intext:\"cvv\" | intext:\"cardholder\" | intext:\"pan =\" | intext:\"stripe_customer\" | intext:\"paymentIntent\" | intext:\"iban\" | intext:\"swift/bic\") -inurl:policy -inurl:tos -inurl:legal",
                clean_domain
            ),
            description: "PCI/PII payment terms in indexed pages, minus policy pages".to_string(),
            impact:
                "Indexed order confirmations, receipts, or debug logs containing cardholder data are a direct PCI-DSS reportable breach."
                    .to_string(),
        });

        // Personal-data leakage patterns (SSN, national IDs, tax ids).
        dorks.push(GoogleDork {
            category: "Personal Data".to_string(),
            query: format!(
                "site:{} (intext:\"ssn\" | intext:\"social security\" | intext:\"national id\" | intext:\"passport number\" | intext:\"driver license\" | intext:\"tax id\" | intext:\"NIN\" | intext:\"date of birth\") (ext:pdf | ext:xls | ext:xlsx | ext:csv | ext:doc | ext:docx)",
                clean_domain
            ),
            description: "Documents mentioning national IDs or DOBs indexed under the domain"
                .to_string(),
            impact:
                "Regulator-notifiable PII leaks (GDPR / HIPAA / CCPA) with immediate legal exposure to the operator."
                    .to_string(),
        });

        // Federal / regulated file drops (email exports, patient records).
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:{} (ext:pst | ext:ost | ext:mbox | ext:eml | ext:msg | ext:vcf | ext:csv | ext:kdbx | ext:1pux | ext:agilekeychain)",
                clean_domain
            ),
            description: "Mailbox exports, address books, and password-vault databases"
                .to_string(),
            impact:
                "KeePass (.kdbx) and 1Password (.1pux) archives are offline-crackable once downloaded; mailbox exports leak internal correspondence in full."
                    .to_string(),
        });

        // OpenAPI / GraphQL schema surfaces reachable via search.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:openapi.json | inurl:swagger.json | inurl:swagger-ui | inurl:swagger/v1 | inurl:api-docs | inurl:v3/api-docs | inurl:graphql | inurl:graphiql | inurl:playground | inurl:altair | inurl:voyager)",
                clean_domain
            ),
            description: "Machine-readable API specs and interactive query UIs".to_string(),
            impact:
                "OpenAPI JSON reveals every endpoint, method, and parameter; GraphiQL/Altair enables live introspection and mutation attempts."
                    .to_string(),
        });

        // SSO / IdP metadata endpoints.
        dorks.push(GoogleDork {
            category: "Identity Providers".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/openid-configuration | inurl:/.well-known/jwks.json | inurl:saml/metadata | inurl:auth/realms | inurl:oauth/authorize | inurl:oauth/token | inurl:oidc/authorize | inurl:oidc/token | inurl:userinfo)",
                clean_domain
            ),
            description: "Public IdP metadata and OAuth/OIDC endpoints".to_string(),
            impact:
                "Enumerates SSO tenant, JWKS key ids, supported grants — feeds directly into JWT signing-key confusion, OAuth misconfiguration, and account-takeover chains."
                    .to_string(),
        });

        // Employee / directory enumeration from open sources.
        dorks.push(GoogleDork {
            category: "Employee OSINT".to_string(),
            query: format!(
                "(site:linkedin.com/in | site:linkedin.com/pub) \"at {}\" OR \"@{}\"",
                clean_domain, clean_domain
            ),
            description: "LinkedIn profiles asserting employment at the target".to_string(),
            impact:
                "Feeds phishing/spearphishing target selection, password-spraying username lists, and reset-question OSINT."
                    .to_string(),
        });

        // Ticketing systems that leak internal details when made public.
        dorks.push(GoogleDork {
            category: "Ticketing Systems".to_string(),
            query: format!(
                "(site:*.atlassian.net | site:*.zendesk.com | site:*.freshdesk.com | site:*.helpscoutdocs.com | site:*.helpjuice.com | site:support.{}) \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Public support tickets, wiki pages, and knowledge base articles"
                .to_string(),
            impact:
                "Public tickets frequently contain reproduction steps for still-open vulnerabilities and internal hostnames."
                    .to_string(),
        });

        // Cache / archive services that preserve deleted content.
        dorks.push(GoogleDork {
            category: "Cached Content".to_string(),
            query: format!(
                "(site:web.archive.org/web/*/{} | site:cachedview.com | site:webcache.googleusercontent.com) \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Archived copies preserving credentials or endpoints removed live"
                .to_string(),
            impact:
                "Wayback frequently retains .env, backup, and debug pages the operator has since taken down."
                    .to_string(),
        });

        // Kubernetes-exposed API surfaces sometimes indexed through
        // reverse-proxy misconfiguration.
        dorks.push(GoogleDork {
            category: "Kubernetes API".to_string(),
            query: format!(
                "site:{} (inurl:/api/v1/pods | inurl:/api/v1/namespaces | inurl:/api/v1/secrets | inurl:/healthz | inurl:/readyz | inurl:/livez | inurl:/openapi/v2 | inurl:/apis/apps/v1)",
                clean_domain
            ),
            description: "Kubernetes API endpoints reachable through the ingress".to_string(),
            impact:
                "An unauthenticated /api/v1/pods or /api/v1/secrets endpoint is a full cluster-secret disclosure."
                    .to_string(),
        });

        // Broker / queue admin endpoints (RabbitMQ, Kafka Connect, Nomad,
        // Consul, Vault).
        dorks.push(GoogleDork {
            category: "Broker Admin".to_string(),
            query: format!(
                "site:{} (inurl:/api/overview | inurl:/api/queues | inurl:/api/exchanges | inurl:/connectors | inurl:/v1/agent/self | inurl:/v1/catalog | inurl:/v1/kv | inurl:/v1/sys/health | inurl:/v1/sys/mounts)",
                clean_domain
            ),
            description: "RabbitMQ, Kafka Connect, Consul, Nomad, and Vault management APIs".to_string(),
            impact:
                "Consul /v1/kv and Vault /v1/sys/mounts leak the full secret hierarchy; RabbitMQ /api/queues exposes routing keys and message counts."
                    .to_string(),
        });

        // WSDL / SOAP / RPC surfaces.
        dorks.push(GoogleDork {
            category: "SOAP / RPC".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:asmx | inurl:?wsdl | inurl:services.wsdl | inurl:jsonrpc | inurl:xmlrpc.php | inurl:xmlrpc/mailinterface | inurl:rpc/api)",
                clean_domain
            ),
            description: "SOAP WSDL, ASMX, and JSON-RPC endpoints".to_string(),
            impact:
                "WSDL enumerates every SOAP operation; xmlrpc.php on WordPress historically enables credential-brute-forcing and SSRF (pingback.ping)."
                    .to_string(),
        });

        // WebDAV / file-serve misconfigurations.
        dorks.push(GoogleDork {
            category: "WebDAV / File Server".to_string(),
            query: format!(
                "site:{} (inurl:webdav | inurl:_dav | inurl:owncloud | inurl:nextcloud/apps/files | inurl:remote.php/webdav | intitle:\"Index of /\" | intitle:\"Directory listing for /\")",
                clean_domain
            ),
            description: "WebDAV shares, Nextcloud/ownCloud, and open directory listings"
                .to_string(),
            impact:
                "Open directory indexes let an attacker walk the filesystem; WebDAV shares often allow anonymous PUT."
                    .to_string(),
        });

        // Log files with domain-specific content.
        dorks.push(GoogleDork {
            category: "Application Logs".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:logs/ | inurl:log.txt | inurl:error.log | inurl:access.log | inurl:debug.log | inurl:laravel.log | inurl:storage/logs | inurl:npm-debug.log)",
                clean_domain
            ),
            description: "Application, framework, and web-server log files".to_string(),
            impact:
                "laravel.log and Django logs frequently include stack traces with request bodies, cookies, and bearer tokens."
                    .to_string(),
        });

        // Session storage / uploaded content directories.
        dorks.push(GoogleDork {
            category: "Session / Upload Directories".to_string(),
            query: format!(
                "site:{} (inurl:sess_ | inurl:phpsessid | inurl:/uploads/ | inurl:/upload/ | inurl:/tmp/ | inurl:/temp/ | inurl:/var/tmp/ | inurl:/pub/upload)",
                clean_domain
            ),
            description: "Publicly exposed session and upload directories".to_string(),
            impact:
                "PHP sess_ files are session hijacking primitives; /uploads/ often serves user-provided files without sanitisation."
                    .to_string(),
        });

        // Exposed Redis / Memcached HTTP-facing helpers.
        dorks.push(GoogleDork {
            category: "In-memory Stores".to_string(),
            query: format!(
                "site:{} (inurl:redis-commander | inurl:phpredmin | inurl:redis-web | inurl:memcache.php | inurl:memadmin)",
                clean_domain
            ),
            description: "HTTP UIs for Redis and Memcached".to_string(),
            impact:
                "Redis clients bound to public IPs and read from the internet reveal every cached auth token."
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
