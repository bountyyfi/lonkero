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
        // High-signal additions — sensitive-artifact discovery
        //
        // The dorks below target artifacts that, when returned, are
        // near-certain sensitive-info leaks: environment files, private
        // key material, database exports, IaC state, CI logs, and
        // wide-open cloud buckets. Each query is scoped to the target
        // domain (or the domain's public paste-trace) so noise from the
        // wider web does not dominate the results a pentester reviews.
        // ============================================================

        // Environment files — near-guaranteed credential leak when indexed
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (ext:env | inurl:.env) -inurl:\"env.js\" -inurl:\".env.example\"",
                clean_domain
            ),
            description: ".env files often committed alongside applications".to_string(),
            impact: "Environment files typically contain DB passwords, API keys, JWT secrets, and \
                third-party service credentials — direct account takeover risk".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD=\" | intext:\"AWS_SECRET_ACCESS_KEY=\" | intext:\"STRIPE_SECRET_KEY=\" | intext:\"JWT_SECRET=\")",
                clean_domain
            ),
            description: "Environment-variable assignments visible in indexed content".to_string(),
            impact: "The keys named are almost always live credentials, not placeholders".to_string(),
        });

        // Backup / archive files with the target's content
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp | ext:swo | ext:tmp | ext:temp | ext:copy | ext:~)",
                clean_domain
            ),
            description: "Editor and admin backups left on the web root".to_string(),
            impact: "Backups of source files reveal application logic, secrets, and pre-fix \
                versions of vulnerable code".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z | ext:war | ext:jar | ext:apk | ext:ipa)",
                clean_domain
            ),
            description: "Application archives / build artifacts exposed on public paths".to_string(),
            impact: "Full source code, application secrets, and internal deployment metadata \
                are typically bundled inside these archives".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (inurl:backup | inurl:dump | inurl:snapshot | inurl:export) (ext:sql | ext:db | ext:sqlite | ext:mdb | ext:tar | ext:gz | ext:zip)",
                clean_domain
            ),
            description: "Named backup directories with database or archive extensions".to_string(),
            impact: "Full database dumps expose PII, hashed credentials, and business data".to_string(),
        });

        // Version-control metadata accidentally deployed
        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/\" | inurl:\"/.git/HEAD\" | inurl:\"/.git/config\" | inurl:\"/.git/logs/\" | inurl:\"/.svn/\" | inurl:\"/.hg/\" | inurl:\"/.bzr/\")",
                clean_domain
            ),
            description: "Exposed VCS metadata directories".to_string(),
            impact: "Full source-code reconstruction via git-dumper and equivalent tools; \
                often includes secrets in commit history".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Version Control Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.gitignore\" | inurl:\"/.gitattributes\" | inurl:\"/.gitconfig\" | inurl:\"/.gitmodules\")",
                clean_domain
            ),
            description: "Repository configuration files exposed on the web root".to_string(),
            impact: "Reveals hidden paths and submodule sources worth investigating for leaks".to_string(),
        });

        // Database dumps — direct data exfiltration
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:mysql | ext:db | ext:sqlite | ext:sqlite3 | ext:bak intext:INSERT)",
                clean_domain
            ),
            description: "Raw database exports on the target".to_string(),
            impact: "Full user/PII/hashed-credential extraction; PCI/GDPR reportable".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (intext:\"-- MySQL dump\" | intext:\"-- PostgreSQL database dump\" | intext:\"BEGIN TRANSACTION;\" intext:\"INSERT INTO\")",
                clean_domain
            ),
            description: "Content-based detection of database dump preamble".to_string(),
            impact: "Confirms a real dump rather than a filename coincidence".to_string(),
        });

        // Log files & error traces with stack context
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log intext:\"password\" | ext:log intext:\"authorization\" | ext:log intext:\"secret\" | ext:log intext:\"api_key\")",
                clean_domain
            ),
            description: "Log files containing credential-like tokens".to_string(),
            impact: "Application logs often capture reset tokens, session IDs, and \
                bearer headers verbatim".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (inurl:debug.log | inurl:error.log | inurl:access.log | inurl:php_errors.log | inurl:laravel.log | inurl:storage/logs)",
                clean_domain
            ),
            description: "Well-known log filenames".to_string(),
            impact: "Reveals stack traces, DB queries with parameters, and internal paths".to_string(),
        });

        // Private key material
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:pfx | ext:p12 | ext:cer | ext:crt | ext:asc | ext:pgp)",
                clean_domain
            ),
            description: "Cryptographic key files exposed by extension".to_string(),
            impact: "Server private keys enable TLS impersonation and passive-decryption of \
                traffic against related infrastructure".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\")",
                clean_domain
            ),
            description: "PEM-armored private-key content on the target".to_string(),
            impact: "A PEM header on an indexed page is unambiguous key material".to_string(),
        });

        // CI/CD & DevOps configuration
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"/.github/workflows/\" | inurl:\".gitlab-ci.yml\" | inurl:\".travis.yml\" | inurl:\".circleci/config.yml\" | inurl:\"Jenkinsfile\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"azure-pipelines.yml\" | inurl:\"buildspec.yml\")",
                clean_domain
            ),
            description: "CI/CD pipeline configuration exposed".to_string(),
            impact: "Reveals build secrets references, deploy targets, and pipeline-injection \
                surface (self-hosted runners, cache-poisoning)".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/httptrace\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\")",
                clean_domain
            ),
            description: "Spring Boot Actuator sensitive endpoints".to_string(),
            impact: "/actuator/env leaks all env vars including cloud creds; \
                heapdump exports the process heap".to_string(),
        });

        // Infrastructure as Code / secrets managers
        dorks.push(GoogleDork {
            category: "IaC & Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"terraform.tfstate\" | inurl:\"terraform.tfstate.backup\" | inurl:\"*.tfvars\" | ext:tfstate | ext:tfvars)",
                clean_domain
            ),
            description: "Terraform state and variable files".to_string(),
            impact: "tfstate contains resolved provider credentials and infrastructure inventory \
                (RDS endpoints, S3 buckets, VPC layout) in plaintext".to_string(),
        });
        dorks.push(GoogleDork {
            category: "IaC & Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\".dockercfg\" | inurl:\".docker/config.json\" | inurl:\"Dockerfile\")",
                clean_domain
            ),
            description: "Container orchestration and registry config".to_string(),
            impact: "docker-compose files typically pin DB passwords and registry credentials \
                inline; .dockercfg holds base64 registry logins".to_string(),
        });
        dorks.push(GoogleDork {
            category: "IaC & Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"kube-config\" | inurl:\".kube/config\" | inurl:\"kubeconfig\" | inurl:\"kustomization.yaml\" | inurl:\"helm/values.yaml\")",
                clean_domain
            ),
            description: "Kubernetes admin credentials and manifests".to_string(),
            impact: "A leaked kubeconfig is direct cluster admin access when the API server is \
                Internet-reachable — full workload compromise".to_string(),
        });
        dorks.push(GoogleDork {
            category: "IaC & Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\".pip/pip.conf\" | inurl:\"nuget.config\" | inurl:\".gem/credentials\" | inurl:\".cargo/credentials\" | inurl:\"settings.xml\")",
                clean_domain
            ),
            description: "Package-manager credential files".to_string(),
            impact: "Registry publish tokens enable supply-chain attacks against downstream users".to_string(),
        });

        // Cloud service metadata & CLI credentials
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".aws/config\" | inurl:\".s3cfg\" | inurl:\".boto\" | inurl:\".azure/credentials\" | inurl:\".gcloud/credentials.db\" | inurl:credentials.csv)",
                clean_domain
            ),
            description: "Cloud CLI credential files".to_string(),
            impact: "Directly usable long-lived access keys for AWS/Azure/GCP".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (intext:\"aws_access_key_id\" intext:\"aws_secret_access_key\" | intext:\"AccountName=\" intext:\"AccountKey=\" | intext:\"\\\"type\\\": \\\"service_account\\\"\")",
                clean_domain
            ),
            description: "Cloud credential blobs by content signature".to_string(),
            impact: "Content-based hits are unambiguous: AWS credentials INI file, Azure \
                storage connection string, or GCP service-account JSON key".to_string(),
        });

        // Cloud bucket enumeration (open-listing UI on the target's brand)
        dorks.push(GoogleDork {
            category: "Cloud Buckets".to_string(),
            query: format!(
                "site:s3.amazonaws.com intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "S3 bucket with directory listing enabled containing brand".to_string(),
            impact: "Publicly listable S3 buckets typically expose customer data or internal artifacts".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Buckets".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Google Cloud Storage objects mentioning the brand".to_string(),
            impact: "Public GCS objects; enumerate the bucket listing for the full inventory".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Buckets".to_string(),
            query: format!(
                "site:*.blob.core.windows.net \"{}\"",
                clean_domain
            ),
            description: "Azure Blob storage containers referencing the brand".to_string(),
            impact: "Anonymous-read containers frequently contain customer PII".to_string(),
        });

        // Application-specific config leaks
        dorks.push(GoogleDork {
            category: "Application Configs".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php\" | inurl:\"wp-config.bak\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.old\" | inurl:\"wp-config.txt\")",
                clean_domain
            ),
            description: "WordPress database credential files (variants)".to_string(),
            impact: "Full DB credentials, auth-keys, and DB prefix — WordPress admin takeover".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Application Configs".to_string(),
            query: format!(
                "site:{} (inurl:\"configuration.php\" | inurl:\"config.inc.php\" | inurl:\"config.php.bak\" | inurl:\"database.yml\" | inurl:\"secrets.yml\" | inurl:\"application.yml\" | inurl:\"application.properties\" | inurl:\"appsettings.json\" | inurl:\"web.config\")",
                clean_domain
            ),
            description: "Framework configuration files (Joomla, Rails, Spring, .NET)".to_string(),
            impact: "Application-level credentials, third-party API keys, encryption master keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Application Configs".to_string(),
            query: format!(
                "site:{} (inurl:\"phpinfo.php\" | inurl:\"info.php\" | inurl:\"test.php\" | inurl:\"phpMyAdmin\" | inurl:\"pma\" | inurl:\"myadmin\")",
                clean_domain
            ),
            description: "phpinfo pages and DB admin panels".to_string(),
            impact: "phpinfo leaks the full server env; phpMyAdmin is a direct DB console".to_string(),
        });

        // Directory listing / file browsers
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of\" (intext:\"Parent Directory\" | intext:\"Last modified\")",
                clean_domain
            ),
            description: "Apache/nginx-style open directory listings".to_string(),
            impact: "Direct enumeration of files the site owner did not intend to expose".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} (intitle:\"Index of /admin\" | intitle:\"Index of /backup\" | intitle:\"Index of /config\" | intitle:\"Index of /uploads\" | intitle:\"Index of /database\" | intitle:\"Index of /logs\")",
                clean_domain
            ),
            description: "Open listings for privileged directory names".to_string(),
            impact: "High-signal hits on admin/backup/upload paths".to_string(),
        });

        // Editor / IDE metadata
        dorks.push(GoogleDork {
            category: "Editor Metadata".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\".idea\" | inurl:\".vscode\" | inurl:\"Thumbs.db\" | inurl:\".project\" | inurl:\".settings\")",
                clean_domain
            ),
            description: "Editor/IDE metadata deployed to web root".to_string(),
            impact: ".DS_Store enumerates full directory listings; JetBrains .idea leaks \
                run configs and remote-deploy paths".to_string(),
        });

        // Auth & SSO configuration
        dorks.push(GoogleDork {
            category: "Auth Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".well-known/openid-configuration\" | inurl:\".well-known/oauth-authorization-server\" | inurl:\".well-known/jwks.json\" | inurl:\"/oauth/authorize\" | inurl:\"/oidc/\")",
                clean_domain
            ),
            description: "OIDC / OAuth discovery documents".to_string(),
            impact: "Reveals auth-server metadata, JWKS keys, supported grants — recon for \
                token-forgery and open-redirect chains".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Auth Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"saml\" | inurl:\"metadata.xml\" | inurl:\"FederationMetadata.xml\" | inurl:\"Shibboleth.sso\")",
                clean_domain
            ),
            description: "SAML metadata endpoints".to_string(),
            impact: "Full IdP/SP trust configuration and signing keys — enables SAML forgery research".to_string(),
        });

        // Well-known + security metadata
        dorks.push(GoogleDork {
            category: "Well-Known Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\".well-known/security.txt\" | inurl:\"security.txt\" | inurl:\".well-known/change-password\" | inurl:\".well-known/dnt-policy.txt\" | inurl:\".well-known/assetlinks.json\" | inurl:\"apple-app-site-association\")",
                clean_domain
            ),
            description: "Well-known metadata surfaces".to_string(),
            impact: "assetlinks / AASA reveal deep-link handling and can be abused for \
                app-link hijacking; security.txt surfaces disclosure channel".to_string(),
        });

        // Third-party paste / snippet / gist leaks
        dorks.push(GoogleDork {
            category: "Paste Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:pastebin.com | site:paste.ee | site:hastebin.com | site:controlc.com | site:ghostbin.com) \"{}\"",
                clean_domain
            ),
            description: "Any paste service snippet mentioning the brand".to_string(),
            impact: "Public pastes are the single most common source of credential leaks".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Paste Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" (intext:\"api_key\" | intext:\"password\" | intext:\"secret\" | intext:\"token\")",
                clean_domain
            ),
            description: "Gists that mention the brand alongside credential-like keywords".to_string(),
            impact: "High-precision hit list for triage".to_string(),
        });

        // Third-party artifact repositories
        dorks.push(GoogleDork {
            category: "Artifact Repositories".to_string(),
            query: format!(
                "(site:hub.docker.com | site:quay.io | site:mcr.microsoft.com | site:ghcr.io) \"{}\"",
                clean_domain
            ),
            description: "Container-registry search for brand-tagged images".to_string(),
            impact: "Public images ship internal build artifacts, private-repo URLs, and \
                sometimes plaintext credentials in ENV / layers".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Artifact Repositories".to_string(),
            query: format!(
                "(site:hub.docker.com/r site:hub.docker.com/u) \"{}\"",
                clean_domain
            ),
            description: "Docker Hub user/repo pages mentioning the brand".to_string(),
            impact: "Enumerate company-owned or employee-owned images tied to the brand".to_string(),
        });

        // Application-specific admin interfaces
        dorks.push(GoogleDork {
            category: "Exposed Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" | intitle:\"Kibana\" | intitle:\"Jenkins\" | intitle:\"Elasticsearch\" | intitle:\"Prometheus\" | intitle:\"Node Exporter\" | intitle:\"cAdvisor\")",
                clean_domain
            ),
            description: "Web UIs of monitoring / observability tools".to_string(),
            impact: "Grafana/Kibana often expose full production dashboards & logs; \
                Jenkins may allow anonymous build triggering (RCE)".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"cPanel\" | intitle:\"Plesk\" | intitle:\"Webmin\" | intitle:\"DirectAdmin\" | intitle:\"ISPConfig\")",
                clean_domain
            ),
            description: "Database and hosting control panels".to_string(),
            impact: "Common credential-attack targets; frequent misconfiguration → root".to_string(),
        });

        // API-collection & schema leaks
        dorks.push(GoogleDork {
            category: "API Collections".to_string(),
            query: format!(
                "site:{} (ext:har | ext:postman_collection | ext:postman_environment | inurl:postman_collection | inurl:postman_environment)",
                clean_domain
            ),
            description: "Postman collections and HAR captures".to_string(),
            impact: "HAR files replay auth headers/cookies; Postman envs typically hold API keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Collections".to_string(),
            query: format!(
                "site:{} (inurl:\"openapi.json\" | inurl:\"swagger.json\" | inurl:\"api-docs\" | inurl:\"v3/api-docs\" | inurl:\"api/schema\") -inurl:swagger-ui",
                clean_domain
            ),
            description: "Raw OpenAPI/Swagger specs (not the UI)".to_string(),
            impact: "Full internal API map — feed straight into the API fuzzer".to_string(),
        });

        // Mobile app deep artifacts
        dorks.push(GoogleDork {
            category: "Mobile Artifacts".to_string(),
            query: format!(
                "site:{} (ext:apk | ext:ipa | ext:aab | ext:xap | inurl:\"apple-app-site-association\" | inurl:\".well-known/assetlinks.json\")",
                clean_domain
            ),
            description: "Mobile app builds and deep-link association files".to_string(),
            impact: "APK/IPA yields secrets baked into the mobile client; assetlinks reveals \
                app-link handlers that can be spoofed".to_string(),
        });

        // Robots / sitemap / feeds — free path enumeration
        dorks.push(GoogleDork {
            category: "Path Enumeration".to_string(),
            query: format!(
                "site:{} (inurl:robots.txt | inurl:sitemap.xml | inurl:sitemap_index.xml | inurl:humans.txt)",
                clean_domain
            ),
            description: "robots.txt / sitemap files".to_string(),
            impact: "robots.txt commonly discloses admin, staging, and internal paths the \
                owner tried to hide from search engines".to_string(),
        });

        // Session / cookie / token disclosure
        dorks.push(GoogleDork {
            category: "Session Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"PHPSESSID=\" | intext:\"JSESSIONID=\" | intext:\"session_id=\" | intext:\"csrf_token=\" | intext:\"XSRF-TOKEN=\" | intext:\"authenticity_token=\")",
                clean_domain
            ),
            description: "Session identifiers appearing in indexed content".to_string(),
            impact: "Session IDs indexed by Google are frequently still valid at review time".to_string(),
        });

        // Bug-tracker / issue leaks (public projects with the brand)
        dorks.push(GoogleDork {
            category: "Issue Trackers".to_string(),
            query: format!(
                "(site:issues.chromium.org | site:bugs.launchpad.net | site:bugzilla.mozilla.org | site:issuetracker.google.com | site:github.com/*/issues) \"{}\" (password | credential | token | leak | exposed)",
                clean_domain
            ),
            description: "Public bug-tracker mentions with credential-related keywords".to_string(),
            impact: "External researchers may have reported (and left evidence of) a leak".to_string(),
        });

        // SEC / regulatory / M&A footprint
        dorks.push(GoogleDork {
            category: "Regulatory Footprint".to_string(),
            query: format!(
                "(site:sec.gov | site:efts.sec.gov | site:companieshouse.gov.uk) \"{}\"",
                clean_domain
            ),
            description: "Regulatory filings that name the brand".to_string(),
            impact: "Reveals officers, subsidiaries, and acquired entities → wider attack surface".to_string(),
        });

        // Company-code repository search (source scraping)
        dorks.push(GoogleDork {
            category: "Source Search".to_string(),
            query: format!(
                "(site:sourcegraph.com | site:grep.app) \"{}\"",
                clean_domain
            ),
            description: "Public code search for brand-mentioning source".to_string(),
            impact: "Combine with credential regexes to find leaked secrets in indexed code".to_string(),
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
