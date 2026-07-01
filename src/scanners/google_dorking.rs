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

        // --- Additional high-signal sensitive-information dorks ---
        //
        // These target artefacts that, when reachable via Google's cache, almost
        // always indicate a real leak: dotfiles served by web root, DVCS metadata,
        // backup files, exposed dashboards, and credentials indexed in third-party
        // paste/notebook services. They are worded so any match implies impact
        // rather than a general search hit.

        // Exposed .env files (framework secrets, DB passwords, SMTP creds).
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} ext:env | ext:cfg | ext:conf | ext:ini | ext:yaml | ext:yml intext:\"DB_PASSWORD\" | intext:\"APP_KEY\" | intext:\"SECRET_KEY\" | intext:\"AWS_ACCESS\" | intext:\"AWS_SECRET\"",
                clean_domain
            ),
            description: "Find exposed .env / config files containing credentials".to_string(),
            impact: "Directly leaks database passwords, framework master keys, and cloud credentials — full application compromise.".to_string(),
        });

        // .git / .svn / .hg metadata.
        dorks.push(GoogleDork {
            category: "VCS Metadata Exposure".to_string(),
            query: format!(
                "site:{} inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/index\" | inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/store\"",
                clean_domain
            ),
            description: "Find exposed VCS metadata directories".to_string(),
            impact: "Full source-code recovery via git-dumper / svn-dumper — reveals credentials, business logic, and other vulns.".to_string(),
        });

        // Backup file extensions with real content.
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp | ext:swo | ext:tmp | ext:copy inurl:wp-config | inurl:config | inurl:settings | inurl:database",
                clean_domain
            ),
            description: "Find configuration backups (wp-config.bak, settings.old, etc.)".to_string(),
            impact: "Backup files are served as text and often contain the exact production secrets of their live counterparts.".to_string(),
        });

        // Database dumps and SQL exports.
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql | ext:dbf | ext:mdb | ext:sqlite | ext:sqlite3 | ext:db intext:INSERT | intext:CREATE | intext:\"-- MySQL dump\" | intext:\"PostgreSQL database dump\"",
                clean_domain
            ),
            description: "Find raw database dumps and SQL exports".to_string(),
            impact: "Dumps contain hashed passwords, PII, session tokens, and full table contents.".to_string(),
        });

        // WordPress configuration and debug files.
        dorks.push(GoogleDork {
            category: "WordPress Sensitive Files".to_string(),
            query: format!(
                "site:{} inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.php.save | inurl:wp-config.php~ | inurl:wp-config.txt | inurl:debug.log",
                clean_domain
            ),
            description: "Find wp-config backups and WordPress debug logs".to_string(),
            impact: "wp-config backups contain DB credentials, auth keys, and salts — instant site takeover.".to_string(),
        });

        // Terraform / IaC state files (often contain plaintext secrets).
        dorks.push(GoogleDork {
            category: "Infrastructure-as-Code Leaks".to_string(),
            query: format!(
                "site:{} inurl:terraform.tfstate | inurl:terraform.tfstate.backup | ext:tfvars | ext:tfstate | inurl:.terraform | inurl:ansible-vault",
                clean_domain
            ),
            description: "Find Terraform state files or Ansible vaults exposed".to_string(),
            impact: "State files serialise provider credentials, DB passwords, and private keys in plaintext.".to_string(),
        });

        // Docker / Kubernetes manifests.
        dorks.push(GoogleDork {
            category: "Container Config Leaks".to_string(),
            query: format!(
                "site:{} inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:Dockerfile | inurl:.dockercfg | inurl:.docker/config.json | inurl:kubeconfig | inurl:.kube/config",
                clean_domain
            ),
            description: "Find exposed Docker Compose files and Kubernetes kubeconfigs".to_string(),
            impact: "kubeconfig grants cluster-admin access; compose files reveal all service secrets.".to_string(),
        });

        // CI/CD artefacts.
        dorks.push(GoogleDork {
            category: "CI/CD Artifacts".to_string(),
            query: format!(
                "site:{} inurl:.gitlab-ci.yml | inurl:.github/workflows | inurl:Jenkinsfile | inurl:bitbucket-pipelines.yml | inurl:.circleci/config.yml | inurl:.travis.yml | inurl:azure-pipelines.yml",
                clean_domain
            ),
            description: "Find CI/CD pipeline definitions in webroot".to_string(),
            impact: "Pipeline files leak deploy tokens, registry credentials, and build-time env vars.".to_string(),
        });

        // SSH / TLS private keys.
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} ext:pem | ext:key | ext:ppk | ext:p12 | ext:pfx | ext:jks | ext:keystore intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\"",
                clean_domain
            ),
            description: "Find exposed private key material".to_string(),
            impact: "SSH / TLS / signing keys are directly usable for auth, MITM, and code-signing attacks.".to_string(),
        });

        // FTP client configs.
        dorks.push(GoogleDork {
            category: "FTP / Deploy Credentials".to_string(),
            query: format!(
                "site:{} inurl:sitemanager.xml | inurl:filezilla.xml | inurl:recentservers.xml | inurl:wcx_ftp.ini | inurl:.ftpconfig | inurl:ws_ftp.ini | inurl:deployment-config.json",
                clean_domain
            ),
            description: "Find FileZilla / WinSCP / VSCode deploy configs".to_string(),
            impact: "These files store host + username + (often base64/plain) password for SFTP/FTP servers.".to_string(),
        });

        // AWS credentials CSVs and profile files.
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} inurl:accessKeys.csv | inurl:credentials.csv | inurl:.aws/credentials | inurl:.aws/config | intext:\"aws_access_key_id\" intext:\"aws_secret_access_key\"",
                clean_domain
            ),
            description: "Find AWS credential exports".to_string(),
            impact: "IAM key pairs give direct API access to the AWS account (potentially root-equivalent).".to_string(),
        });

        // Google service-account JSON keys.
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} ext:json intext:\"type\" intext:\"service_account\" intext:\"private_key_id\"",
                clean_domain
            ),
            description: "Find Google Cloud service-account JSON key files".to_string(),
            impact: "GCP service-account keys grant full IAM-role access to the target project.".to_string(),
        });

        // Public Postman workspaces & collections leak endpoints + auth tokens.
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "site:postman.com \"{}\" | site:documenter.getpostman.com \"{}\" | site:web.postman.co \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Postman workspaces / collections referencing the target".to_string(),
            impact: "Public Postman collections routinely embed API keys, JWTs, and internal-only endpoints.".to_string(),
        });

        // Notion / Confluence / Airtable public shares.
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "site:notion.site \"{}\" | site:notion.so \"{}\" | site:airtable.com/shr \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Notion / Airtable pages referencing the domain".to_string(),
            impact: "Marketing/internal docs shared 'anyone with link' can expose credentials, roadmaps, and PII.".to_string(),
        });

        // Public Google Colab / Jupyter notebooks.
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "site:colab.research.google.com \"{}\" | site:nbviewer.org \"{}\" | site:kaggle.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Colab / nbviewer / Kaggle notebooks referencing the domain".to_string(),
            impact: "Data-science notebooks frequently paste production DB URIs, API keys, and PII samples.".to_string(),
        });

        // Public GitHub Gists — heavily indexed and full of leaked credentials.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" | site:gitlab.com/-/snippets \"{}\" | site:bitbucket.org/snippets \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find code snippets on Gist / GitLab snippets / Bitbucket snippets".to_string(),
            impact: "Snippet services are the #1 source of accidentally-public credentials by engineers.".to_string(),
        });

        // Slack invites and shared channels indexed by Google.
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "site:app.slack.com \"{}\" | site:slack.com/shared-invite \"{}\" | site:{}.slack.com",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Slack workspaces / open invite links".to_string(),
            impact: "Open Slack invites let attackers join the internal workspace and pivot to internal secrets.".to_string(),
        });

        // Exposed status / monitoring dashboards.
        dorks.push(GoogleDork {
            category: "Exposed Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Grafana\" | intitle:\"Kibana\" | intitle:\"Prometheus Time Series\" | intitle:\"Jaeger UI\" | intitle:\"Node Exporter\" | intitle:\"cAdvisor\"",
                clean_domain
            ),
            description: "Find exposed observability dashboards".to_string(),
            impact: "Unauthenticated Grafana/Kibana instances leak metrics, logs, and often auth headers of internal services.".to_string(),
        });

        // Exposed job schedulers and workflow orchestrators.
        dorks.push(GoogleDork {
            category: "Exposed Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Airflow\" | intitle:\"Argo Workflows\" | intitle:\"Prefect\" | intitle:\"Dagster\" | intitle:\"Luigi\" | intitle:\"Rundeck\"",
                clean_domain
            ),
            description: "Find exposed workflow orchestrator UIs".to_string(),
            impact: "Job schedulers with anonymous access allow arbitrary DAG upload = RCE on worker nodes.".to_string(),
        });

        // Actuator / Spring Boot management endpoints.
        dorks.push(GoogleDork {
            category: "Framework Endpoints".to_string(),
            query: format!(
                "site:{} inurl:actuator/env | inurl:actuator/heapdump | inurl:actuator/mappings | inurl:actuator/beans | inurl:actuator/threaddump | inurl:actuator/httptrace",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env dumps all secrets from application.properties; /heapdump leaks memory including tokens.".to_string(),
        });

        // Django / Flask / Rails debug pages.
        dorks.push(GoogleDork {
            category: "Framework Endpoints".to_string(),
            query: format!(
                "site:{} intitle:\"DEBUG = True\" | intitle:\"Werkzeug Debugger\" | intitle:\"Rails Web Console\" | intext:\"Traceback (most recent call last)\" | intext:\"in ?debug=1\"",
                clean_domain
            ),
            description: "Find production apps left in DEBUG mode".to_string(),
            impact: "Interactive debuggers (Werkzeug/Rails console) offer arbitrary Python/Ruby execution.".to_string(),
        });

        // Directory listings often leak sensitive files.
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" \"parent directory\" -intitle:\"error\"",
                clean_domain
            ),
            description: "Find open directory indexes".to_string(),
            impact: "Directory listings reveal backup files, .git dirs, and forgotten uploads that Google itself may not index.".to_string(),
        });

        // Object-storage buckets referenced by cloud CDN vendors — expanded coverage.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\" | site:{}.storage.googleapis.com | site:{}.s3.amazonaws.com | site:{}.s3.eu-west-1.amazonaws.com | site:{}.s3.us-west-2.amazonaws.com",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find object storage buckets referencing the domain".to_string(),
            impact: "Enumerates buckets whose name embeds the target — first step to bucket-permission testing.".to_string(),
        });

        // Cloudflare R2 / Backblaze B2 / Wasabi buckets.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:r2.cloudflarestorage.com \"{}\" | site:backblazeb2.com \"{}\" | site:wasabisys.com \"{}\" | site:linodeobjects.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find Cloudflare R2 / Backblaze B2 / Wasabi / Linode object storage".to_string(),
            impact: "Non-AWS object storage is often overlooked by internal security scans.".to_string(),
        });

        // phpinfo and info scripts.
        dorks.push(GoogleDork {
            category: "Info Disclosure".to_string(),
            query: format!(
                "site:{} intitle:\"phpinfo()\" | intitle:\"PHP Version\" intext:\"System\" intext:\"Build Date\" | inurl:phpinfo.php | inurl:info.php",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo leaks env vars, SAPI, doc root, credentials-in-env, and enabled extensions.".to_string(),
        });

        // Sentry / Rollbar / Bugsnag dashboards that were never restricted.
        dorks.push(GoogleDork {
            category: "Exposed Dashboards".to_string(),
            query: format!(
                "site:sentry.io \"{}\" | site:app.rollbar.com \"{}\" | site:app.bugsnag.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find error-tracker dashboards mentioning the domain".to_string(),
            impact: "Public error reports leak stack traces, request bodies, and sometimes session cookies.".to_string(),
        });

        // Package registry inspection — internal packages accidentally published public.
        dorks.push(GoogleDork {
            category: "Supply Chain".to_string(),
            query: format!(
                "site:npmjs.com \"{}\" | site:pypi.org \"{}\" | site:rubygems.org \"{}\" | site:packagist.org \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find company packages published to public registries".to_string(),
            impact: "Public registration of an internal-only package name enables dependency-confusion attacks.".to_string(),
        });

        // API keys inside JS bundles cached by search engines.
        dorks.push(GoogleDork {
            category: "Client-Side Secrets".to_string(),
            query: format!(
                "site:{} ext:js intext:\"api_key\" | intext:\"apiKey\" | intext:\"auth_token\" | intext:\"authToken\" | intext:\"AKIA\" | intext:\"sk_live_\"",
                clean_domain
            ),
            description: "Find API keys inside indexed JavaScript".to_string(),
            impact: "Bundled JS often ships live keys; Google's cache preserves them even after deploys rotate.".to_string(),
        });

        // .well-known / security disclosure indexes with high-value paths.
        dorks.push(GoogleDork {
            category: "Well-Known Endpoints".to_string(),
            query: format!(
                "site:{} inurl:/.well-known/security.txt | inurl:/.well-known/openid-configuration | inurl:/.well-known/oauth-authorization-server | inurl:/.well-known/apple-app-site-association | inurl:/.well-known/assetlinks.json",
                clean_domain
            ),
            description: "Enumerate .well-known metadata endpoints".to_string(),
            impact: "OpenID / OAuth metadata leaks issuer URLs, JWKS locations, and client-app associations useful for auth-abuse chains.".to_string(),
        });

        // robots.txt Disallow entries often point to sensitive paths.
        dorks.push(GoogleDork {
            category: "Well-Known Endpoints".to_string(),
            query: format!(
                "site:{} inurl:robots.txt intext:\"Disallow: /admin\" | intext:\"Disallow: /api\" | intext:\"Disallow: /backup\" | intext:\"Disallow: /private\"",
                clean_domain
            ),
            description: "Read robots.txt for sensitive-path breadcrumbs".to_string(),
            impact: "Admins routinely put unreleased admin/beta paths into Disallow, effectively advertising them.".to_string(),
        });

        // Password reset & MFA setup pages worth manual auditing.
        dorks.push(GoogleDork {
            category: "Auth Surfaces".to_string(),
            query: format!(
                "site:{} inurl:password/reset | inurl:reset-password | inurl:forgot-password | inurl:activate | inurl:register/verify | inurl:mfa/setup | inurl:2fa/setup",
                clean_domain
            ),
            description: "Find password reset / MFA setup flows".to_string(),
            impact: "Reset flows are prime targets for host-header poisoning, weak tokens, and account pre-hijack.".to_string(),
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
