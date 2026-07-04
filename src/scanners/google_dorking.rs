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

        // Exposed .env / dotenv files
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (ext:env | inurl:.env) (intext:DB_PASSWORD | intext:SECRET_KEY | intext:APP_KEY | intext:AWS_SECRET)",
                clean_domain
            ),
            description: "Find exposed .env / dotenv files with credentials".to_string(),
            impact: "Directly leaks production DB, cloud, and app secrets — full compromise possible"
                .to_string(),
        });

        // Exposed .git repository files
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\" | inurl:\".gitignore\")",
                clean_domain
            ),
            description: "Find exposed .git directory or config metadata".to_string(),
            impact:
                "Exposed .git allows full repo reconstruction — source code, secrets, commit history"
                    .to_string(),
        });

        // Exposed CI/CD configuration
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".gitlab-ci.yml\" | inurl:\".github/workflows\" | inurl:\".circleci/config.yml\" | inurl:\".travis.yml\" | inurl:\"Jenkinsfile\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"azure-pipelines.yml\" | inurl:\"buildspec.yml\")",
                clean_domain
            ),
            description: "Find CI/CD pipeline configuration files".to_string(),
            impact:
                "Reveals build secrets, deploy keys, internal registry credentials, and infra topology"
                    .to_string(),
        });

        // Kubernetes / container manifests
        dorks.push(GoogleDork {
            category: "Infrastructure as Code".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\"deployment.yaml\" | inurl:\"docker-compose.yml\" | inurl:\".dockercfg\" | inurl:\"config.json\" intext:\"auths\") (intext:kind | intext:apiVersion | intext:image)",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Docker manifests and configs".to_string(),
            impact: "Reveals cluster topology, image registries, service accounts, and often embedded secrets"
                .to_string(),
        });

        // Terraform / Ansible / Chef state files
        dorks.push(GoogleDork {
            category: "Infrastructure as Code".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | ext:pkrvars.hcl | inurl:\"terraform.tfstate\" | inurl:\"ansible.cfg\" | inurl:\"hosts.ini\" | inurl:\"knife.rb\")",
                clean_domain
            ),
            description: "Find exposed Terraform state files or Ansible/Chef configuration".to_string(),
            impact:
                "State files contain resource IDs, cloud secrets, DB endpoints, and often plaintext passwords"
                    .to_string(),
        });

        // Backup / dump files
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:sql.gz | ext:sql.bz2 | ext:mdb | ext:accdb | ext:dbf | ext:sqlite | ext:sqlite3 | ext:db) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"phpMyAdmin\" | intext:\"pg_dump\" | intext:\"MySQL dump\")",
                clean_domain
            ),
            description: "Find exposed database dumps and backups".to_string(),
            impact: "Full database dumps typically contain PII, credentials, and business-critical data"
                .to_string(),
        });

        // Archive / backup extensions with sensitive names
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z) (inurl:backup | inurl:bak | inurl:dump | inurl:archive | inurl:snapshot | inurl:export)",
                clean_domain
            ),
            description: "Find archived backup files".to_string(),
            impact: "Archives frequently contain full site source, DB dumps, and credentials".to_string(),
        });

        // JWT / token leaks in content
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"eyJhbGciOi\" | intext:\"Bearer eyJ\" | intext:\"ssh-rsa AAAA\" | intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find JWTs, SSH keys, and PEM private keys leaked in indexed content".to_string(),
            impact: "Leaked keys/tokens grant direct authenticated access — treat as immediate incident"
                .to_string(),
        });

        // Exposed Postman collections and environments
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com | site:getpostman.com | site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find published Postman collections and workspaces referencing the domain".to_string(),
            impact:
                "Postman workspaces often embed API keys, bearer tokens, and internal endpoint documentation"
                    .to_string(),
        });

        // GraphQL endpoints and introspection
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/altair | inurl:/playground | inurl:/api/graphql | inurl:/v1/graphql | inurl:/query)",
                clean_domain
            ),
            description: "Find GraphQL endpoints, IDEs, and playgrounds".to_string(),
            impact: "Exposed GraphQL playgrounds usually allow full schema introspection and unauth queries"
                .to_string(),
        });

        // Exposed monitoring / metrics endpoints
        dorks.push(GoogleDork {
            category: "Monitoring & Telemetry".to_string(),
            query: format!(
                "site:{} (inurl:/metrics | inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/threaddump | inurl:/prometheus | inurl:/debug/vars | inurl:/debug/pprof | inurl:/_cat/indices)",
                clean_domain
            ),
            description: "Find exposed metrics, actuator, and profiling endpoints".to_string(),
            impact:
                "Spring actuator/env leaks secrets; heapdump/pprof leak in-memory secrets; ES /_cat leaks index data"
                    .to_string(),
        });

        // Log files with sensitive content
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | ext:txt inurl:log | inurl:error_log | inurl:access_log | inurl:debug.log | inurl:catalina.out) (intext:\"password\" | intext:\"token\" | intext:\"authorization\" | intext:\"stack trace\" | intext:\"exception\")",
                clean_domain
            ),
            description: "Find exposed application log files with credentials or traces".to_string(),
            impact: "Logs commonly leak session tokens, credentials in URLs, and internal stack traces"
                .to_string(),
        });

        // Exposed Jenkins / build servers
        dorks.push(GoogleDork {
            category: "Build Servers".to_string(),
            query: format!(
                "site:{} (inurl:\"/jenkins/\" | inurl:\"/hudson/\" | inurl:\"/job/\" | inurl:\"/computer/\" | inurl:\"script\" intitle:\"Jenkins\") (intitle:\"Dashboard\" | intitle:\"Jenkins\")",
                clean_domain
            ),
            description: "Find exposed Jenkins/Hudson interfaces".to_string(),
            impact: "Unauth Jenkins /script endpoints allow Groovy RCE; job configs contain secrets"
                .to_string(),
        });

        // GitHub secrets / dorks over external repos
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com \"{}\" (\"api_key\" | \"apikey\" | \"secret\" | \"password\" | \"credential\" | \"private_key\" | \"authorization\" | \"aws_access_key_id\" | \"aws_secret\")",
                clean_domain
            ),
            description: "Find GitHub commits/files mentioning the domain alongside credential keywords".to_string(),
            impact: "Public GitHub often contains leaked keys tied to the target — high impact if valid"
                .to_string(),
        });

        // Gitter / Slack / Discord history
        dorks.push(GoogleDork {
            category: "Chat & Collaboration".to_string(),
            query: format!(
                "(site:gitter.im | site:discord.com/channels | site:slack.com/archives | site:matrix.to) \"{}\"",
                clean_domain
            ),
            description: "Find chat archives mentioning the domain".to_string(),
            impact: "Public chat history may leak credentials, invite links, or internal discussions"
                .to_string(),
        });

        // Wayback Machine / archived sensitive URLs
        dorks.push(GoogleDork {
            category: "Historical Snapshots".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (inurl:admin | inurl:login | inurl:api | inurl:.env | inurl:.git)",
                clean_domain
            ),
            description: "Find archived snapshots of sensitive paths".to_string(),
            impact:
                "Archived versions of admin/API pages may reveal deprecated but still-live endpoints or credentials"
                    .to_string(),
        });

        // Exposed Jira / Confluence / SharePoint content
        dorks.push(GoogleDork {
            category: "Internal Wiki & Tickets".to_string(),
            query: format!(
                "(site:atlassian.net | site:atlassian.com | inurl:/wiki/spaces | inurl:/confluence | inurl:/jira) \"{}\"",
                clean_domain
            ),
            description: "Find public Atlassian/Confluence/Jira content".to_string(),
            impact:
                "Public spaces frequently expose runbooks, credentials, and internal architecture docs"
                    .to_string(),
        });

        // Exposed Kibana / Elasticsearch / OpenSearch
        dorks.push(GoogleDork {
            category: "Data Stores".to_string(),
            query: format!(
                "site:{} (inurl:/app/kibana | inurl:/_cat | inurl:/_cluster/health | inurl:/_search | inurl:/_all/_search | inurl:/_plugin/kibana)",
                clean_domain
            ),
            description: "Find exposed Kibana/Elasticsearch/OpenSearch endpoints".to_string(),
            impact: "Unauth ES clusters expose full document data — often PII and application logs"
                .to_string(),
        });

        // Cloud metadata references (often accidentally logged/indexed)
        dorks.push(GoogleDork {
            category: "Cloud Metadata Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"169.254.169.254\" | intext:\"metadata.google.internal\" | intext:\"metadata.azure.com\" | intext:\"instance-identity\" | intext:\"iam/security-credentials\")",
                clean_domain
            ),
            description: "Find pages referencing cloud metadata endpoints".to_string(),
            impact: "May indicate SSRF-fetched instance credentials leaked into responses or logs"
                .to_string(),
        });

        // Third-party pastebin variants
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:paste.ee | site:ghostbin.com | site:hastebin.com | site:controlc.com | site:justpaste.it | site:rentry.co | site:0bin.net) \"{}\"",
                clean_domain
            ),
            description: "Find code snippets on alternative paste services".to_string(),
            impact: "Alternative pastebin sites often bypass corporate DLP scanners".to_string(),
        });

        // Bitbucket / SourceForge / Codeberg
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:bitbucket.org | site:sourceforge.net | site:codeberg.org | site:gitea.com | site:gitea.io | site:launchpad.net) \"{}\"",
                clean_domain
            ),
            description: "Find code on alternative git hosts".to_string(),
            impact: "Alternative hosts are often overlooked in secret-scanning coverage".to_string(),
        });

        // Docker Hub images referencing the domain
        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "(site:hub.docker.com | site:quay.io | site:ghcr.io | site:gallery.ecr.aws) \"{}\"",
                clean_domain
            ),
            description: "Find public container images referencing the domain".to_string(),
            impact:
                "Public images frequently embed secrets in ENV/RUN layers; can be extracted from history"
                    .to_string(),
        });

        // npm / PyPI / RubyGems / Maven packages
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:npmjs.com/package | site:pypi.org/project | site:rubygems.org/gems | site:packagist.org | site:crates.io | site:search.maven.org) \"{}\"",
                clean_domain
            ),
            description: "Find public packages mentioning the domain".to_string(),
            impact: "Internal packages accidentally published may leak proprietary code or secrets".to_string(),
        });

        // Exposed WordPress config/backup
        dorks.push(GoogleDork {
            category: "CMS Backups".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php.old\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.txt\" | inurl:\"wp-content/uploads/backup\" | inurl:\".wp-config.php.swp\")",
                clean_domain
            ),
            description: "Find exposed WordPress config backups".to_string(),
            impact: "wp-config.php contains DB credentials, salt keys, and full site secret material"
                .to_string(),
        });

        // Server-status / server-info
        dorks.push(GoogleDork {
            category: "Server Info".to_string(),
            query: format!(
                "site:{} (inurl:/server-status | inurl:/server-info | inurl:/nginx_status | inurl:/haproxy?stats | inurl:/status?full | inurl:/httpd_status)",
                clean_domain
            ),
            description: "Find exposed Apache/Nginx/HAProxy status pages".to_string(),
            impact:
                "Status pages leak active URLs (with query strings and session IDs), request rates, and worker state"
                    .to_string(),
        });

        // Sitemap / robots hints at hidden paths
        dorks.push(GoogleDork {
            category: "Discovery Aids".to_string(),
            query: format!(
                "site:{} (inurl:sitemap.xml | inurl:sitemap_index.xml | inurl:robots.txt | inurl:humans.txt | inurl:security.txt)",
                clean_domain
            ),
            description: "Fetch sitemap/robots/security.txt to enumerate hidden paths".to_string(),
            impact: "robots.txt Disallow entries often point at admin/backup URLs left indexable elsewhere"
                .to_string(),
        });

        // Exposed IDE / editor artifacts
        dorks.push(GoogleDork {
            category: "IDE Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\".idea/\" | inurl:\".vscode/\" | inurl:\".project\" | inurl:\".classpath\" | inurl:\".settings/\" | inurl:\"nbproject/\" | inurl:\".netbeans/\" | inurl:\"composer.lock\" | inurl:\"package-lock.json\" | inurl:\"yarn.lock\" | inurl:\"Gemfile.lock\")",
                clean_domain
            ),
            description: "Find exposed IDE metadata and lockfiles".to_string(),
            impact: "IDE dirs may include local run configs with credentials; lockfiles reveal exact vulnerable deps"
                .to_string(),
        });

        // PHP info / debug pages
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:test.php | inurl:info.php | intitle:\"phpinfo()\" | intitle:\"PHP Version\" | intext:\"System => Linux\" intext:\"PHP Version\")",
                clean_domain
            ),
            description: "Find phpinfo() and PHP debug pages".to_string(),
            impact: "phpinfo leaks full env vars, loaded modules, filesystem paths, and often DB credentials"
                .to_string(),
        });

        // Django/Flask debug
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Werkzeug Debugger\" | intitle:\"DjangoDebugToolbar\" | intext:\"You're seeing this error because you have DEBUG = True\" | intext:\"Traceback (most recent call last)\" | intitle:\"Rails Application error\")",
                clean_domain
            ),
            description: "Find framework debug pages (Werkzeug/Django/Rails)".to_string(),
            impact: "Werkzeug debugger allows RCE; Django DEBUG leaks settings and DB config".to_string(),
        });

        // Open MinIO / S3-compatible bucket listings
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:{} | site:minio.{}) (intitle:\"MinIO Browser\" | intitle:\"Index of /\" | intext:\"ListBucketResult\" | intext:\"<Contents><Key>\")",
                clean_domain, clean_domain
            ),
            description: "Find open MinIO/S3-compatible bucket listings".to_string(),
            impact: "Directory listings expose object keys; may allow anonymous downloads of sensitive data"
                .to_string(),
        });

        // Firebase Realtime DB direct probes
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "(site:firebaseio.com | site:firebase.googleapis.com | site:appspot.com) \"{}\" (inurl:.json | intext:\"error\" | intext:\"permission_denied\")",
                clean_domain
            ),
            description: "Probe Firebase Realtime DB / GAE apps for the domain".to_string(),
            impact: "Adding .json to a Firebase URL returns full DB contents if rules are misconfigured"
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
