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

        // ----------------------------------------------------------------
        // High-impact sensitive-data dorks. Each query targets a specific
        // artifact class with very low false-positive rates: the search engine
        // index returns the exact resource type (env file, k8s manifest,
        // postman collection, etc.), not generic content. The operator must
        // still review hits manually, but a positive result almost always
        // represents a real disclosure.
        // ----------------------------------------------------------------

        // Exposed dotenv files — contain DB creds, API keys, SECRET_KEY
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD=\" | intext:\"AWS_SECRET_ACCESS_KEY=\" | intext:\"DATABASE_URL=postgres://\" | intext:\"SECRET_KEY_BASE=\") ext:env | ext:txt | inurl:.env",
                clean_domain
            ),
            description: "Find exposed .env files containing secrets".to_string(),
            impact: "Critical: .env files routinely leak DB credentials, signing keys, and cloud API tokens.".to_string(),
        });

        // Exposed .git directories
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | intitle:\"Index of\" intext:\".git/\")",
                clean_domain
            ),
            description: "Find exposed .git directories.".to_string(),
            impact: "Critical: a readable .git/ directory leaks complete source history including credentials in old commits.".to_string(),
        });

        // Exposed SVN / Mercurial / Bazaar repos
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\".bzr/branch\" | inurl:CVS/Entries)",
                clean_domain
            ),
            description: "Find exposed SVN/Mercurial/Bazaar/CVS metadata.".to_string(),
            impact: "High: legacy VCS metadata leaks source code and historical credentials.".to_string(),
        });

        // Editor / OS detritus
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:.DS_Store | inurl:Thumbs.db | inurl:.idea/workspace.xml | inurl:.vscode/settings.json | inurl:.project)",
                clean_domain
            ),
            description: "Find IDE / OS artifacts that map the filesystem.".to_string(),
            impact: "Medium: filesystem layout disclosure aids further exploitation.".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:bkp | ext:backup | ext:save | ext:old | ext:swp | ext:swo | ext:tmp | ext:temp | ext:orig | ext:original | ext:gz | ext:tgz | ext:tar | ext:zip | ext:7z | ext:rar | ext:sql | ext:dump) -intitle:\"index of\"",
                clean_domain
            ),
            description: "Find production backup archives indexed publicly.".to_string(),
            impact: "Critical: full filesystem or database dumps frequently include credentials and customer PII.".to_string(),
        });

        // Open directory listings (Apache / nginx autoindex)
        dorks.push(GoogleDork {
            category: "Open Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (\"Parent Directory\" | \"Last modified\")",
                clean_domain
            ),
            description: "Find directory autoindex pages.".to_string(),
            impact: "High: autoindex on production hosts exposes secondary files like backups, dumps, and config.".to_string(),
        });

        // Kubernetes / Helm / Docker manifests
        dorks.push(GoogleDork {
            category: "CI/CD & Infra Manifests".to_string(),
            query: format!(
                "site:{} (intext:\"apiVersion: v1\" intext:\"kind: Secret\" | intext:\"kind: Deployment\" intext:\"image:\" | filename:values.yaml \"image:\" \"tag:\" | filename:docker-compose.yml \"environment:\")",
                clean_domain
            ),
            description: "Find K8s, Helm, or Docker Compose manifests.".to_string(),
            impact: "High: manifests typically embed image tags, environment vars, and base64 Secret payloads.".to_string(),
        });

        // Terraform state / providers
        dorks.push(GoogleDork {
            category: "CI/CD & Infra Manifests".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:terraform.tfstate | filename:provider.tf | filename:backend.tf intext:\"access_key\")",
                clean_domain
            ),
            description: "Find Terraform state and tfvars files.".to_string(),
            impact: "Critical: .tfstate files contain provisioned resource IDs, IAM keys, and DB endpoints in plaintext.".to_string(),
        });

        // Ansible / Chef / Puppet
        dorks.push(GoogleDork {
            category: "CI/CD & Infra Manifests".to_string(),
            query: format!(
                "site:{} (filename:vault.yml | filename:hosts.ini intext:\"ansible_ssh_pass\" | filename:knife.rb | filename:hiera.yaml)",
                clean_domain
            ),
            description: "Find configuration management secrets files.".to_string(),
            impact: "Critical: vault and hiera files commonly hold SSH passwords, API keys, and root credentials.".to_string(),
        });

        // CI configuration
        dorks.push(GoogleDork {
            category: "CI/CD & Infra Manifests".to_string(),
            query: format!(
                "site:{} (filename:.travis.yml \"secure:\" | filename:.gitlab-ci.yml \"variables:\" | filename:circle.yml | filename:.github/workflows | filename:Jenkinsfile)",
                clean_domain
            ),
            description: "Find CI pipeline definitions.".to_string(),
            impact: "Medium: CI files can leak deploy targets, registry creds, and signing keys.".to_string(),
        });

        // Postman / Insomnia collections
        dorks.push(GoogleDork {
            category: "API Collections".to_string(),
            query: format!(
                "site:postman.com OR site:getpostman.com OR site:postman.co \"{}\" (collection | environment | workspace)",
                clean_domain
            ),
            description: "Find Postman collections / workspaces / environments referencing the target.".to_string(),
            impact: "High: leaked collections reveal authenticated endpoints and embedded API tokens.".to_string(),
        });

        // Stack traces & WSGI / ASP.NET / PHP debug pages
        dorks.push(GoogleDork {
            category: "Stack Traces & Debug Pages".to_string(),
            query: format!(
                "site:{} (\"DEBUG = True\" | \"Whoops! There was an error.\" | \"Werkzeug Debugger\" | \"Django Debug\" | \"Yellow Screen of Death\" | \"Symfony Profiler\" | intitle:\"Application Error\" \"Heroku\" | inurl:_profiler/phpinfo)",
                clean_domain
            ),
            description: "Find framework debug consoles and stack traces.".to_string(),
            impact: "Critical: an exposed Werkzeug / Django debugger gives RCE; Symfony profiler leaks env vars.".to_string(),
        });

        // phpinfo / server-status / actuator
        dorks.push(GoogleDork {
            category: "Stack Traces & Debug Pages".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" \"PHP Version\" | inurl:phpinfo.php | inurl:server-status \"Apache Server Status\" | inurl:server-info \"Server Information\" | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/health | inurl:/_stcore/health)",
                clean_domain
            ),
            description: "Find phpinfo, server-status, and Spring Boot actuator endpoints.".to_string(),
            impact: "Critical: phpinfo leaks env, paths, modules; /actuator/heapdump exposes memory.".to_string(),
        });

        // Logs (system/app)
        dorks.push(GoogleDork {
            category: "Exposed Logs".to_string(),
            query: format!(
                "site:{} (inurl:logs ext:log | inurl:debug.log | inurl:error.log | inurl:access.log | inurl:laravel.log | inurl:storage/logs)",
                clean_domain
            ),
            description: "Find application and webserver log files.".to_string(),
            impact: "High: app logs frequently contain session tokens, full request bodies, and stack traces.".to_string(),
        });

        // GraphQL endpoints (introspection candidates)
        dorks.push(GoogleDork {
            category: "GraphQL".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/api/graphql | inurl:/v1/graphql | intext:\"__schema\" \"queryType\")",
                clean_domain
            ),
            description: "Find GraphQL endpoints and exposed introspection.".to_string(),
            impact: "Medium-High: introspection-enabled endpoints map the entire schema, including admin operations.".to_string(),
        });

        // CMS / app-server admin consoles
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/wp-admin/ | inurl:/wp-login.php | inurl:/administrator/ | inurl:/user/login Drupal | inurl:/manager/html Tomcat | inurl:/jmx-console | inurl:/jolokia | inurl:/console/login.do WebLogic | inurl:/login.action Confluence | inurl:/secure/Dashboard.jspa Jira)",
                clean_domain
            ),
            description: "Find CMS / app-server admin entry points.".to_string(),
            impact: "High: admin consoles are first-class brute-force and exploit targets.".to_string(),
        });

        // Internal dashboards (Grafana / Kibana / Prometheus / RabbitMQ / Consul)
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" \"Welcome to Grafana\" | intitle:\"Kibana\" | inurl:/_plugin/kibana | inurl:/app/kibana | intitle:\"Prometheus Time Series\" | intitle:\"RabbitMQ Management\" | intitle:\"Consul by HashiCorp\" | intitle:\"Traefik\" \"dashboard\" | intitle:\"MinIO Console\")",
                clean_domain
            ),
            description: "Find unauthenticated observability and infra dashboards.".to_string(),
            impact: "Critical: open Grafana/Kibana commonly leak metrics, queries, and customer data; MinIO Console gives object-store access.".to_string(),
        });

        // CI / SCM dashboards
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/script Jenkins | intitle:\"GitLab\" inurl:/users/sign_in | intitle:\"Gitea\" | intitle:\"Sonatype Nexus\" | intitle:\"JFrog Artifactory\" | intitle:\"SonarQube\" | inurl:/sonar)",
                clean_domain
            ),
            description: "Find SCM, CI, and artifact-repository dashboards.".to_string(),
            impact: "High: Jenkins /script gives Groovy RCE; open Nexus/Artifactory leaks proprietary builds.".to_string(),
        });

        // Database admin tools
        dorks.push(GoogleDork {
            category: "Database Admin Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" \"Welcome to phpMyAdmin\" | intitle:\"Adminer\" \"Database\" | inurl:/pma/ | inurl:/phpmyadmin/ | intitle:\"pgAdmin\" | intitle:\"Mongo Express\" | intitle:\"Redis Commander\" | intitle:\"Mongo Express\" | inurl:/mongo-express)",
                clean_domain
            ),
            description: "Find DB admin web tools.".to_string(),
            impact: "Critical: phpMyAdmin / Adminer / Mongo Express on production is a direct database compromise vector.".to_string(),
        });

        // Mail logs / webmail
        dorks.push(GoogleDork {
            category: "Mail & Communications".to_string(),
            query: format!(
                "site:{} (intitle:\"Roundcube Webmail\" | intitle:\"Outlook Web App\" | inurl:/mail/inbox | inurl:/owa/auth | intitle:\"Zimbra Web Client\" | inurl:/horde/login.php | inurl:/squirrelmail)",
                clean_domain
            ),
            description: "Find webmail interfaces.".to_string(),
            impact: "High: webmail without MFA is a phishing-pivot foothold.".to_string(),
        });

        // SCM-hosted secrets via Google (target referenced in repo content)
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com OR site:gitlab.com OR site:bitbucket.org \"{}\" (\"BEGIN RSA PRIVATE KEY\" | \"BEGIN OPENSSH PRIVATE KEY\" | \"AKIA\" | \"AIza\" | \"xox[baprs]-\" | \"sk_live_\" | \"ghp_\" | \"hf_\" | \"sk-ant-\")",
                clean_domain
            ),
            description: "Find leaked credentials in public repos that mention the target domain.".to_string(),
            impact: "Critical: vendor-prefixed keys (AKIA, AIza, ghp_, sk_live_, sk-ant-) are essentially never false positives.".to_string(),
        });

        // Public Slack workspaces
        dorks.push(GoogleDork {
            category: "Mail & Communications".to_string(),
            query: format!(
                "site:slack.com \"{}\" (intext:\"join\" | intext:\"workspace\")",
                clean_domain
            ),
            description: "Find Slack workspaces or invite links referencing the target.".to_string(),
            impact: "Medium: open Slack invites can lead to internal channel disclosure.".to_string(),
        });

        // Confluence / Notion / wiki leaks
        dorks.push(GoogleDork {
            category: "Knowledge Bases".to_string(),
            query: format!(
                "(site:atlassian.net OR site:notion.so OR site:notion.site OR site:gitbook.io OR site:gitbook.com) \"{}\" (intext:\"password\" | intext:\"api key\" | intext:\"runbook\" | intext:\"on-call\")",
                clean_domain
            ),
            description: "Find publicly-shared Confluence/Notion/GitBook pages with operational secrets.".to_string(),
            impact: "Medium-High: runbooks and onboarding docs frequently contain credentials and architecture diagrams.".to_string(),
        });

        // Cached static maps (Mapbox / Google Maps tokens leaked in JS)
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:{} (intext:\"pk.eyJ\" Mapbox | intext:\"AIza\" \"&key=\" Maps | intext:\"sk-\" OpenAI | intext:\"sk-ant-\" Anthropic)",
                clean_domain
            ),
            description: "Find pages exposing third-party API keys in HTML/JS.".to_string(),
            impact: "High: Mapbox / Google Maps / OpenAI / Anthropic keys can be abused for billing fraud and data extraction.".to_string(),
        });

        // S3 bucket-listings (XML)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net \"{}\" intitle:\"ListBucketResult\"",
                clean_domain
            ),
            description: "Find listable cloud-storage buckets referencing the target.".to_string(),
            impact: "Critical: a listable bucket is one click from a full file enumeration.".to_string(),
        });

        // SQL files indexed
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} ext:sql (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DUMP\")",
                clean_domain
            ),
            description: "Find SQL dump files.".to_string(),
            impact: "Critical: SQL dumps contain hashed (or worse, plaintext) user records and full schema.".to_string(),
        });

        // SSH / OpenSSL key files
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN EC PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\")",
                clean_domain
            ),
            description: "Find PEM-armored private keys served on the target.".to_string(),
            impact: "Critical: any private key block on a web-served path is by definition a key compromise.".to_string(),
        });

        // .well-known leaks (security.txt mentions, change-password)
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "site:{} (inurl:.well-known/openid-configuration | inurl:.well-known/jwks.json | inurl:.well-known/oauth-authorization-server | inurl:.well-known/security.txt | inurl:.well-known/host-meta)",
                clean_domain
            ),
            description: "Find .well-known metadata endpoints.".to_string(),
            impact: "Low-Medium: enumerates IdP configuration, JWKS keys, and supported flows for follow-up attacks.".to_string(),
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
