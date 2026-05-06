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

        // -------------------------------------------------------------------
        // Exposed VCS metadata (high-impact, deterministic)
        // -------------------------------------------------------------------

        // Exposed .git directories
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:\".git/HEAD\" | inurl:\".git/config\" | inurl:\".git/index\" | inurl:\".git/logs/HEAD\")",
                clean_domain
            ),
            description: "Find indexed .git directory artifacts".to_string(),
            impact: "Exposed .git enables full source-code reconstruction and recovery of \
                hardcoded secrets from commit history".to_string(),
        });

        // Exposed .svn / .hg directories
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/store\" | inurl:\"_darcs/\")",
                clean_domain
            ),
            description: "Find indexed SVN/Mercurial/Darcs metadata".to_string(),
            impact: "Legacy VCS metadata leaks repository structure and historical source"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // Configuration / dotenv leaks (parameterised on the domain)
        // -------------------------------------------------------------------

        // Dotenv & runtime config files
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.dev\" | inurl:\"app.config\" | inurl:\"web.config\" | inurl:\"appsettings.json\" | inurl:\"application.properties\" | inurl:\"application.yml\" | inurl:\"application.yaml\")",
                clean_domain
            ),
            description: "Find exposed application configuration files".to_string(),
            impact: "Configuration files commonly contain database credentials, API keys, \
                signing secrets, SMTP passwords, and JWT secrets".to_string(),
        });

        // Cloud / infra config files
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".aws/config\" | inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\".dockercfg\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.override.yml\" | inurl:\"Dockerfile\" | inurl:\"kubeconfig\" | inurl:\".terraform/terraform.tfstate\" | inurl:\"terraform.tfstate\" | inurl:\"terraform.tfvars\")",
                clean_domain
            ),
            description: "Find exposed cloud, container, and IaC configuration".to_string(),
            impact: "Cloud configs and Terraform state files frequently embed long-lived \
                credentials, kubeconfig contexts, and full inventories of cloud resources"
                .to_string(),
        });

        // CI/CD config and pipeline definitions
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" | inurl:\".gitlab-ci.yml\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"Jenkinsfile\" | inurl:\".circleci/config.yml\" | inurl:\".travis.yml\" | inurl:\"azure-pipelines.yml\" | inurl:\"buildspec.yml\")",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline configuration".to_string(),
            impact: "Pipeline files reveal build secrets, deployment targets, and \
                self-hosted runner labels usable for further pivoting".to_string(),
        });

        // SSH / TLS / GPG key material
        dorks.push(GoogleDork {
            category: "Cryptographic Material".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:ppk | ext:key | ext:pfx | ext:p12 | ext:jks | ext:keystore | ext:asc | ext:gpg | ext:kdbx | ext:agilekeychain)",
                clean_domain
            ),
            description: "Find exposed cryptographic key material and password databases"
                .to_string(),
            impact: "Private keys, keystores, and KeePass/1Password databases provide direct \
                authentication bypass to TLS, code-signing, SSH, and identity systems"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // Backups, dumps, and archives
        // -------------------------------------------------------------------

        // Database dumps
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:mdb | ext:sqlite | ext:sqlite3 | ext:db | ext:bak | ext:dmp) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\" | intext:\"PRIVILEGES\" | intext:\"-- MySQL dump\" | intext:\"PostgreSQL database dump\")",
                clean_domain
            ),
            description: "Find exposed database dumps with structural/data markers".to_string(),
            impact: "Dumps directly expose user records, password hashes, and PII; the \
                content match makes findings actionable rather than guessing on extension"
                .to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Backups".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:7z | ext:rar | ext:gz | ext:bz2) (inurl:backup | inurl:bak | inurl:old | inurl:dump | inurl:export | inurl:archive)",
                clean_domain
            ),
            description: "Find archive files in backup-named paths".to_string(),
            impact: "Backup archives commonly mirror production code/config and bypass \
                ACLs that protect the live filesystem".to_string(),
        });

        // Editor / OS leftover files (Vim swap, Emacs autosave, macOS metadata)
        dorks.push(GoogleDork {
            category: "Backups".to_string(),
            query: format!(
                "site:{} (ext:swp | ext:swo | ext:save | ext:orig | ext:rej | inurl:.DS_Store | inurl:Thumbs.db | inurl:~)",
                clean_domain
            ),
            description: "Find editor/OS leftover artefacts indexed by search engines"
                .to_string(),
            impact: ".DS_Store enumerates directory listings; Vim swap files reveal \
                in-progress edits with credentials that were not yet sanitised".to_string(),
        });

        // -------------------------------------------------------------------
        // Logs and runtime artefacts
        // -------------------------------------------------------------------

        // Application/access logs with credential markers
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | ext:txt | ext:out) (intext:\"password=\" | intext:\"passwd=\" | intext:\"Authorization: Bearer\" | intext:\"Authorization: Basic\" | intext:\"client_secret=\" | intext:\"X-API-Key:\" | intext:\"set-cookie:\")",
                clean_domain
            ),
            description: "Find log files containing credential or auth-token markers"
                .to_string(),
            impact: "Logs that capture request bodies or headers commonly leak session \
                cookies, bearer tokens, and basic-auth strings — usable for direct account \
                takeover".to_string(),
        });

        // Stack traces with framework markers (high-fidelity, language-specific)
        dorks.push(GoogleDork {
            category: "Stack Traces".to_string(),
            query: format!(
                "site:{} (intext:\"Traceback (most recent call last)\" | intext:\"java.lang.NullPointerException at\" | intext:\"at System.Web.\" | intext:\"Whitelabel Error Page\" | intext:\"Symfony\\\\Component\" | intext:\"Whoops!\" | intext:\"You have an error in your SQL syntax\")",
                clean_domain
            ),
            description: "Find indexed stack traces from common frameworks".to_string(),
            impact: "Stack traces reveal framework versions, internal paths, and database \
                schema — directly fueling targeted exploit chains".to_string(),
        });

        // -------------------------------------------------------------------
        // Spring Boot Actuator (high-impact infrastructure exposure)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Actuator Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/configprops | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/beans | inurl:/actuator/loggers | inurl:/actuator/health)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env and /configprops leak full configuration including DB \
                credentials; /heapdump can be analysed offline for in-memory secrets and \
                session tokens".to_string(),
        });

        // -------------------------------------------------------------------
        // PHP / classic LAMP information disclosure
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "PHP Info Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | inurl:test.php | inurl:_phpinfo | intitle:\"phpinfo()\" intext:\"PHP Version\" intext:\"System\")",
                clean_domain
            ),
            description: "Find phpinfo() pages".to_string(),
            impact: "phpinfo() leaks the full PHP environment, loaded extensions, full \
                paths, and frequently the contents of $_SERVER and $_ENV".to_string(),
        });

        // Composer / package manifests with version disclosure
        dorks.push(GoogleDork {
            category: "Dependency Manifests".to_string(),
            query: format!(
                "site:{} (inurl:composer.json | inurl:composer.lock | inurl:package.json | inurl:package-lock.json | inurl:yarn.lock | inurl:pnpm-lock.yaml | inurl:Gemfile.lock | inurl:requirements.txt | inurl:Pipfile.lock | inurl:poetry.lock | inurl:go.mod | inurl:go.sum | inurl:Cargo.lock)",
                clean_domain
            ),
            description: "Find exposed package/dependency manifests".to_string(),
            impact: "Lockfiles reveal exact dependency versions, which directly enables \
                CVE matching and shows whether private/internal package registries are \
                configured (potential dependency-confusion targets)".to_string(),
        });

        // -------------------------------------------------------------------
        // GraphQL & gRPC endpoints
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "GraphQL Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/altair | inurl:/v1/graphql | inurl:/api/graphql | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find GraphQL endpoints and IDEs".to_string(),
            impact: "GraphQL endpoints with introspection enabled disclose the full schema; \
                exposed Playground/GraphiQL UIs are pre-authenticated query interfaces"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // Wordpress / Drupal / Joomla deeper paths
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "WordPress Internals".to_string(),
            query: format!(
                "site:{} (inurl:/wp-content/uploads | inurl:/wp-content/debug.log | inurl:/wp-content/backup | inurl:/wp-config.php.bak | inurl:/wp-config.php~ | inurl:/wp-content/plugins | inurl:/?author= | inurl:/wp-json/wp/v2/users)",
                clean_domain
            ),
            description: "Find WordPress sensitive paths and user-enumeration endpoints"
                .to_string(),
            impact: "wp-config backups expose DB credentials and salts; /wp-json/wp/v2/users \
                enumerates author accounts; plugin directory listings disclose vulnerable \
                versions".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Drupal Internals".to_string(),
            query: format!(
                "site:{} (inurl:/CHANGELOG.txt | inurl:/sites/default/files/php | inurl:/?q=admin | inurl:/?q=user | inurl:/install.php | inurl:/update.php | inurl:/sites/default/settings.php)",
                clean_domain
            ),
            description: "Find Drupal sensitive paths".to_string(),
            impact: "CHANGELOG.txt fingerprints exact Drupal version (Drupalgeddon \
                applicability); update.php exposes admin recovery path".to_string(),
        });

        // -------------------------------------------------------------------
        // Server-info / status / metrics endpoints
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Status / Metrics".to_string(),
            query: format!(
                "site:{} (inurl:/server-status | inurl:/server-info | inurl:/status | inurl:/metrics | inurl:/nginx_status | inurl:/haproxy?stats | inurl:/jolokia | inurl:/prometheus)",
                clean_domain
            ),
            description: "Find server status and metrics endpoints".to_string(),
            impact: "Apache mod_status reveals every active request URL and client IP in \
                real time; Prometheus/Jolokia expose internal service topology and JMX \
                operations".to_string(),
        });

        // -------------------------------------------------------------------
        // SOAP / WSDL / SOAP-style legacy services
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "SOAP/WSDL".to_string(),
            query: format!(
                "site:{} (inurl:?wsdl | ext:wsdl | inurl:asmx?wsdl | inurl:.svc?wsdl | inurl:Service?wsdl)",
                clean_domain
            ),
            description: "Find WSDL service descriptions".to_string(),
            impact: "WSDL files describe every operation, parameter, and authentication \
                expectation of legacy SOAP services — a complete attack surface map"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // Cloud bucket coverage (extra providers / formats)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com | site:firebasestorage.googleapis.com) \"{}\"",
                clean_domain
            ),
            description: "Find Google Cloud Storage and Firebase Storage exposures"
                .to_string(),
            impact: "Misconfigured GCS/Firebase Storage buckets routinely return directory \
                listings of user-uploaded content".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:wasabisys.com | site:backblazeb2.com | site:linodeobjects.com | site:r2.cloudflarestorage.com) \"{}\"",
                clean_domain
            ),
            description: "Find Wasabi / Backblaze B2 / Linode / Cloudflare R2 buckets"
                .to_string(),
            impact: "Non-AWS S3-compatible buckets are frequently overlooked in audits and \
                inherit the same public-by-default failure modes".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com (intitle:\"index of /\" | intitle:\"ListBucketResult\" | intext:\"<Key>\") \"{}\"",
                clean_domain
            ),
            description: "Find S3 buckets returning XML directory listings".to_string(),
            impact: "ListBucketResult XML confirms the bucket allows anonymous LIST — every \
                object key is enumerable and likely fetchable".to_string(),
        });

        // -------------------------------------------------------------------
        // Code-paste / leak sites (broader coverage)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitlab.com/snippets | site:bitbucket.org/snippets | site:hastebin.com | site:rentry.co | site:0bin.net | site:dpaste.org | site:ide.geeksforgeeks.org) \"{}\"",
                clean_domain
            ),
            description: "Find code on additional paste / snippet platforms".to_string(),
            impact: "Engineers routinely paste production fragments — including \
                credentials and internal hostnames — to gist, snippets, and ad-hoc \
                pastebins".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:stackexchange.com | site:serverfault.com) \"{}\" (intext:password | intext:secret | intext:token | intext:apikey | intext:api_key | intext:Authorization)",
                clean_domain
            ),
            description: "Find StackOverflow Q&A leaking credentials for the domain"
                .to_string(),
            impact: "Engineers troubleshooting in public sometimes paste real headers, \
                connection strings, or stack traces with embedded secrets".to_string(),
        });

        // -------------------------------------------------------------------
        // SaaS knowledge / collaboration platforms
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Knowledge Bases".to_string(),
            query: format!(
                "(site:notion.site | site:notion.so | site:coda.io | site:confluence.com | site:atlassian.net/wiki | site:guru.com | site:gitbook.io | site:gitbook.com) \"{}\"",
                clean_domain
            ),
            description: "Find publicly-shared Notion / Coda / Confluence / GitBook pages"
                .to_string(),
            impact: "\"Share to web\" toggles on knowledge bases routinely expose \
                onboarding docs, runbooks, and internal architecture diagrams".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Knowledge Bases".to_string(),
            query: format!(
                "(site:airtable.com/shr | site:airtable.com/app | site:miro.com | site:lucid.app | site:figma.com/file | site:figma.com/community/file) \"{}\"",
                clean_domain
            ),
            description: "Find shared Airtable bases, Miro/Lucid boards, and Figma files"
                .to_string(),
            impact: "Shared design and ops boards leak architecture diagrams, internal \
                APIs, and pre-release roadmap details".to_string(),
        });

        // -------------------------------------------------------------------
        // Bug-tracker public exposure
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Issue Trackers".to_string(),
            query: format!(
                "(site:linear.app | site:github.com/issues | site:asana.com | site:clickup.com | site:monday.com | site:jira.com) \"{}\"",
                clean_domain
            ),
            description: "Find publicly-visible issues on bug trackers".to_string(),
            impact: "Public issues frequently mention unpatched bugs, internal endpoints, \
                and reproduction steps usable as exploitation primitives".to_string(),
        });

        // -------------------------------------------------------------------
        // OAuth / SSO redirect & client metadata
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "OAuth / SSO".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/openid-configuration | inurl:/.well-known/oauth-authorization-server | inurl:/oauth2/.well-known | inurl:client_id= inurl:redirect_uri= inurl:response_type=)",
                clean_domain
            ),
            description: "Find OAuth/OIDC discovery endpoints and authorisation links"
                .to_string(),
            impact: "OIDC discovery enumerates issuer, JWKS, and supported flows; indexed \
                redirect_uri parameters are prime candidates for open-redirect / \
                token-theft chains".to_string(),
        });

        // SAML metadata
        dorks.push(GoogleDork {
            category: "OAuth / SSO".to_string(),
            query: format!(
                "site:{} (inurl:/saml/metadata | inurl:/Shibboleth.sso/Metadata | inurl:/saml2/idp/metadata | ext:xml intext:\"EntityDescriptor\" intext:\"urn:oasis:names:tc:SAML:2.0\")",
                clean_domain
            ),
            description: "Find SAML metadata documents".to_string(),
            impact: "SAML metadata reveals SP/IdP endpoints, signing certificates, and \
                supported NameID formats used to build assertion-injection payloads"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // OpenAPI / Swagger / Postman collections
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:openapi.json | inurl:openapi.yaml | inurl:swagger.json | inurl:swagger.yaml | inurl:v2/api-docs | inurl:v3/api-docs | (ext:json (intext:swagger | intext:openapi) intext:paths intext:components))",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger specifications".to_string(),
            impact: "The raw spec lists every endpoint, parameter, and security \
                requirement — including endpoints that have no UI but accept \
                authenticated requests".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com/collections | site:documenter.getpostman.com | site:run.pstmn.io) \"{}\"",
                clean_domain
            ),
            description: "Find published Postman collections / runners".to_string(),
            impact: "Public Postman collections frequently bundle production base URLs \
                and pre-set Authorization headers".to_string(),
        });

        // -------------------------------------------------------------------
        // Mobile artefacts (APK / IPA / source maps)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Mobile Artefacts".to_string(),
            query: format!(
                "site:{} (ext:apk | ext:ipa | ext:aab | ext:xapk | inurl:google-services.json | inurl:GoogleService-Info.plist | inurl:AndroidManifest.xml)",
                clean_domain
            ),
            description: "Find mobile application packages and config artefacts".to_string(),
            impact: "APK/IPA bundles can be statically reversed; google-services.json and \
                GoogleService-Info.plist contain Firebase API keys, project IDs, and \
                sender IDs".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Source Maps".to_string(),
            query: format!(
                "site:{} (ext:map intext:\"sourcesContent\" | inurl:.js.map | inurl:.css.map | inurl:.mjs.map)",
                clean_domain
            ),
            description: "Find exposed JavaScript / CSS source maps".to_string(),
            impact: "Source maps reconstruct minified bundles back to original source, \
                including comments, internal API URLs, and hardcoded staging credentials"
                .to_string(),
        });

        // -------------------------------------------------------------------
        // Email / messaging artefacts
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Email Artefacts".to_string(),
            query: format!(
                "site:{} (ext:eml | ext:msg | ext:mbox | ext:pst | ext:ost)",
                clean_domain
            ),
            description: "Find exported email files indexed by search".to_string(),
            impact: "EML/MSG/PST exports retain full headers, attachments, and reply \
                threads — often the original location of password-reset links and \
                onboarding credentials".to_string(),
        });

        // -------------------------------------------------------------------
        // Sensitive endpoints by name (auth/admin lookalikes)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/admin/ | inurl:/administrator/ | inurl:/manager/html | inurl:/console | inurl:/dashboard | inurl:/cpanel | inurl:/wp-admin | inurl:/typo3 | inurl:/umbraco | inurl:/sitecore/login | inurl:/Telerik.Web.UI.WebResource.axd)",
                clean_domain
            ),
            description: "Find admin / management interfaces".to_string(),
            impact: "Tomcat /manager, Sitecore login, and Umbraco panels are repeated \
                sources of pre-auth RCE when default credentials or known CVEs apply"
                .to_string(),
        });

        // CMS-specific Joomla
        dorks.push(GoogleDork {
            category: "Joomla Internals".to_string(),
            query: format!(
                "site:{} (inurl:/administrator/index.php | inurl:/components/com_ | inurl:/templates/system | inurl:/configuration.php~ | inurl:/configuration.php.bak)",
                clean_domain
            ),
            description: "Find Joomla admin and configuration backup paths".to_string(),
            impact: "configuration.php backups expose DB credentials and the secret \
                used for Joomla session signing".to_string(),
        });

        // -------------------------------------------------------------------
        // Specific high-value file content (intext-grounded, low-FP)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\" | intext:\"BEGIN ENCRYPTED PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find indexed PEM-armored private key blocks".to_string(),
            impact: "Any indexed private-key block is a critical, immediately-exploitable \
                exposure (TLS, SSH, code signing, GPG)".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"AKIA\" intext:\"AWS_SECRET_ACCESS_KEY\" | intext:\"aws_session_token\" | intext:\"DefaultEndpointsProtocol=https;AccountName\" | intext:\"AccountKey=\")",
                clean_domain
            ),
            description: "Find AWS / Azure credential markers in indexed content"
                .to_string(),
            impact: "Pairs of AKIA-prefixed keys with their secret are direct cloud-account \
                takeover; Azure connection strings provide full Storage access"
                .to_string(),
        });

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"xoxb-\" | intext:\"xoxp-\" | intext:\"xoxa-\" | intext:\"sk_live_\" | intext:\"rk_live_\" | intext:\"ghp_\" | intext:\"github_pat_\" | intext:\"glpat-\" | intext:\"npm_\" | intext:\"hf_\" | intext:\"sk-ant-\")",
                clean_domain
            ),
            description: "Find prefix-anchored, vendor-specific tokens".to_string(),
            impact: "Each prefix is a unique vendor signature — a hit is almost always a \
                live credential rather than a placeholder".to_string(),
        });

        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (inurl:authorized_keys | inurl:id_rsa | inurl:id_ed25519 | inurl:id_dsa | inurl:.ssh/known_hosts)",
                clean_domain
            ),
            description: "Find exposed SSH key material and known_hosts files".to_string(),
            impact: "Indexed SSH keys grant immediate shell access; known_hosts enumerates \
                jump hosts and internal infrastructure naming conventions".to_string(),
        });

        // -------------------------------------------------------------------
        // Internet-of-Things / printers (frequently forgotten on perimeter)
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Embedded Devices".to_string(),
            query: format!(
                "site:{} (intitle:\"Lexmark\" | intitle:\"HP LaserJet\" | intitle:\"Xerox\" | intitle:\"Canon\" | intitle:\"BROTHER\" | inurl:/hp/device | inurl:/printer | inurl:/ews/)",
                clean_domain
            ),
            description: "Find networked printers and embedded device interfaces"
                .to_string(),
            impact: "Printer interfaces leak address books, scanned-document caches, and \
                LDAP bind credentials configured for scan-to-email".to_string(),
        });

        // -------------------------------------------------------------------
        // Webhook-receiver / debug endpoints accidentally indexed
        // -------------------------------------------------------------------

        dorks.push(GoogleDork {
            category: "Webhook / Debug".to_string(),
            query: format!(
                "site:{} (inurl:/webhook | inurl:/hooks | inurl:/callback | inurl:/debug | inurl:/__debug__ | inurl:/_debug | inurl:/debugbar)",
                clean_domain
            ),
            description: "Find webhook receivers and debug toolbars".to_string(),
            impact: "Symfony/Laravel debugbar and Django debug pages disclose env vars, \
                routes, and SQL queries — often unauthenticated".to_string(),
        });

        // -------------------------------------------------------------------
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
