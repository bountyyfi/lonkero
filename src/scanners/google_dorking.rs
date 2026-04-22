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

        // Exposed .env files (dotenv)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:env -inurl:example -inurl:sample",
                clean_domain
            ),
            description: "Find exposed .env dotenv files".to_string(),
            impact: "Dotenv files typically contain DB credentials, API keys, JWT secrets and AWS keys - direct key/credential compromise".to_string(),
        });

        // Exposed .git directory
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\")",
                clean_domain
            ),
            description: "Find exposed .git repository metadata".to_string(),
            impact: "Exposed .git directories allow reconstruction of full source code including committed secrets and history".to_string(),
        });

        // Exposed .svn / .hg repository metadata
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/store\")",
                clean_domain
            ),
            description: "Find exposed SVN or Mercurial repository metadata".to_string(),
            impact: "VCS metadata allows repo reconstruction and historical secret retrieval".to_string(),
        });

        // Spring Boot Actuator endpoints (unauthenticated)
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/beans\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator leaks env vars, heap dumps (containing secrets in memory), routes and JMX - often leads to RCE via /jolokia or /env POST".to_string(),
        });

        // Jenkins sensitive paths
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/script\" intitle:\"Script Console\" | inurl:\"/manage\" intitle:\"Jenkins\" | inurl:\"/credentials\" intitle:\"Jenkins\")",
                clean_domain
            ),
            description: "Find Jenkins Script Console and credentials store".to_string(),
            impact: "Jenkins Script Console is Groovy RCE; credentials store reveals all stored CI/CD secrets".to_string(),
        });

        // Kubernetes / Docker exposed APIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/api/v1/namespaces\" | inurl:\"/api/v1/pods\" | inurl:\"/v2/_catalog\" | inurl:\"/v1.40/containers/json\")",
                clean_domain
            ),
            description: "Find Kubernetes API / Docker registry / Docker Engine listings".to_string(),
            impact: "Unauthenticated Kubernetes or Docker APIs allow container takeover and cluster compromise".to_string(),
        });

        // Prometheus / Grafana metrics and dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/metrics\" intext:\"# HELP\" intext:\"# TYPE\" | inurl:\"/api/v1/status/config\")",
                clean_domain
            ),
            description: "Find exposed Prometheus metrics endpoints".to_string(),
            impact: "Exposed metrics leak internal hostnames, paths, credentials (in basic-auth URLs), and runtime info for further attacks".to_string(),
        });

        // Elasticsearch / Kibana
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/_cat/indices\" | inurl:\"/_cluster/health\" | inurl:\"/app/kibana\" | inurl:\"/_nodes\")",
                clean_domain
            ),
            description: "Find exposed Elasticsearch/Kibana endpoints".to_string(),
            impact: "Unauthenticated ES/Kibana exposes all indexed data, logs and allows data exfiltration".to_string(),
        });

        // phpinfo() disclosure
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} intitle:\"phpinfo()\" (intext:\"PHP Version\" | intext:\"System\" intext:\"Build Date\")",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo leaks full PHP config, extensions, env vars, document root, and server paths useful for pivoting".to_string(),
        });

        // Laravel debug / Ignition / Whoops
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops, looks like something went wrong\" | intext:\"Ignition\" intext:\"Laravel\")",
                clean_domain
            ),
            description: "Find Laravel debug / Ignition error pages".to_string(),
            impact: "Laravel debug mode leaks env vars and DB credentials; Ignition CVE-2021-3129 is unauthenticated RCE".to_string(),
        });

        // Django / Rails debug pages
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (intext:\"Django Version\" intext:\"DEBUG = True\" | intext:\"Web Console\" intext:\"Rails.root\")",
                clean_domain
            ),
            description: "Find Django DEBUG and Rails web-console debug pages".to_string(),
            impact: "Debug pages leak settings, traceback (including secrets) and Rails web-console is unauthenticated RCE".to_string(),
        });

        // WordPress debug.log / wp-config backups
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-content/debug.log\" | inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php.swp\" | inurl:\"wp-config.php~\")",
                clean_domain
            ),
            description: "Find WordPress debug logs and wp-config backups".to_string(),
            impact: "wp-config backups contain DB credentials and secret keys; debug.log leaks stack traces with user data".to_string(),
        });

        // Database dumps / backups
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:sqlite | ext:mdb) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE IF EXISTS\")",
                clean_domain
            ),
            description: "Find database dumps and backup files".to_string(),
            impact: "Database dumps expose the full dataset including hashed/plaintext passwords, PII, API tokens".to_string(),
        });

        // Directory listing exposure
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (\"parent directory\" | \"Last modified\") -intitle:\"htdocs\"",
                clean_domain
            ),
            description: "Find servers with directory listing enabled".to_string(),
            impact: "Directory listings expose filesystem layout, backups, and files not intended to be web-accessible".to_string(),
        });

        // .DS_Store / Thumbs.db
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\")",
                clean_domain
            ),
            description: "Find leaked macOS/Windows metadata files".to_string(),
            impact: ".DS_Store enumerates directory contents even when listing is disabled, revealing hidden filenames".to_string(),
        });

        // SSH/PGP private keys
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PGP PRIVATE KEY BLOCK\")",
                clean_domain
            ),
            description: "Find exposed SSH or PGP private keys".to_string(),
            impact: "Private keys are direct-use credentials: SSH access, code signing, encrypted data decryption".to_string(),
        });

        // Package manager credentials
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (filename:.npmrc intext:_authToken | filename:.pypirc intext:password | filename:.netrc intext:password)",
                clean_domain
            ),
            description: "Find package manager credential files".to_string(),
            impact: ".npmrc/.pypirc/.netrc expose registry tokens that allow package publish and supply chain attacks".to_string(),
        });

        // Jupyter Notebook exposed
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/tree\" intitle:\"Jupyter\" | inurl:\"/notebooks/\" ext:ipynb | inurl:\"/lab\" intitle:\"JupyterLab\")",
                clean_domain
            ),
            description: "Find exposed Jupyter notebooks".to_string(),
            impact: "Unauthenticated Jupyter is arbitrary code execution and file system access on the server".to_string(),
        });

        // GraphQL introspection / playground
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" intext:\"__schema\" | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find exposed GraphQL introspection or UI playgrounds".to_string(),
            impact: "Introspection reveals full schema (mutations, sensitive queries); playgrounds are attacker-friendly".to_string(),
        });

        // Docker / Kubernetes configuration files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (filename:docker-compose.yml intext:password | filename:kubeconfig | inurl:\".kube/config\")",
                clean_domain
            ),
            description: "Find exposed docker-compose and kubeconfig files".to_string(),
            impact: "kubeconfig provides cluster admin credentials; docker-compose often contains DB passwords and env".to_string(),
        });

        // Log files with credentials
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:log (intext:\"password=\" | intext:\"Authorization: Bearer\" | intext:\"api_key=\" | intext:\"X-Api-Key:\")",
                clean_domain
            ),
            description: "Find log files containing credentials".to_string(),
            impact: "Application logs often capture auth headers, passwords in POST bodies, and API keys in URLs".to_string(),
        });

        // CI/CD workflow files referencing secrets
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" | inurl:\".gitlab-ci.yml\" | inurl:\".circleci/config\" | inurl:\"bitbucket-pipelines.yml\")",
                clean_domain
            ),
            description: "Find CI/CD pipeline configuration files".to_string(),
            impact: "Pipeline files reference secret names, internal services, deployment targets - useful for supply-chain attack planning".to_string(),
        });

        // Next.js / Vite build artifacts and source maps
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"_next/static\" ext:map | inurl:\".vite/\" | ext:map intext:\"sourceRoot\" | ext:map intext:\"webpack://\")",
                clean_domain
            ),
            description: "Find exposed JavaScript source maps".to_string(),
            impact: "Source maps reconstruct original TypeScript/JSX source revealing internal routes, auth logic and embedded secrets".to_string(),
        });

        // WebDAV / frontpage
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"_vti_bin\" | inurl:\"_vti_pvt\" | inurl:\"webdav\" intitle:\"Index of /\")",
                clean_domain
            ),
            description: "Find FrontPage extensions and WebDAV endpoints".to_string(),
            impact: "WebDAV often permits PUT/MOVE leading to arbitrary file upload; FrontPage has historic auth bypasses".to_string(),
        });

        // Tomcat / JBoss / Weblogic admin consoles
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/manager/html\" intitle:\"Tomcat\" | inurl:\"/jmx-console\" | inurl:\"/web-console\" | inurl:\"/console/login\" intitle:\"WebLogic\")",
                clean_domain
            ),
            description: "Find Tomcat Manager / JBoss / WebLogic admin consoles".to_string(),
            impact: "Default-cred admin consoles lead directly to WAR deployment RCE (Tomcat) or server-side RCE (JBoss, WebLogic)".to_string(),
        });

        // Exposed environment-identifying debug/trace IDs
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (intext:\"trace_id\" intext:\"span_id\" | intitle:\"Traceback\" intext:\"File \\\"/\")",
                clean_domain
            ),
            description: "Find exposed Python tracebacks and distributed tracing artifacts".to_string(),
            impact: "Full tracebacks reveal absolute server paths, package versions and frequently leak secrets in local variables".to_string(),
        });

        // AWS/GCP/Azure SDK debug output
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"AKIA\" | intext:\"ASIA\" | intext:\"aws_secret_access_key\" | intext:\"AZURE_CLIENT_SECRET\" | intext:\"GOOGLE_APPLICATION_CREDENTIALS\")",
                clean_domain
            ),
            description: "Find exposed cloud provider credentials".to_string(),
            impact: "Static cloud credentials give direct account access; AKIA and ASIA prefixes are AWS access key identifiers".to_string(),
        });

        // Secrets in public error / staging deployments
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN CERTIFICATE-----\" ext:pem | ext:key | ext:p12 | ext:pfx)",
                clean_domain
            ),
            description: "Find exposed certificates and keystores".to_string(),
            impact: "PFX/P12 keystores often contain private keys for TLS or code signing; PEM files may include private material".to_string(),
        });

        // HashiCorp Vault / Consul / Nomad UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/v1/sys/health\" intext:\"initialized\" | inurl:\"/ui/vault\" | inurl:\"/v1/catalog/services\" intext:\"consul\")",
                clean_domain
            ),
            description: "Find exposed Vault, Consul, or Nomad endpoints".to_string(),
            impact: "Vault in dev mode or misconfigured Consul ACL exposes secrets engine; Consul catalog maps internal services".to_string(),
        });

        // RabbitMQ / Kafka admin UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/api/overview\" intext:\"rabbitmq_version\" | inurl:\"/kafka-manager\" | intitle:\"Kafka UI\")",
                clean_domain
            ),
            description: "Find RabbitMQ Management and Kafka UI endpoints".to_string(),
            impact: "Message broker admin UIs with default creds allow message replay, queue purging, and publishing to internal topics".to_string(),
        });

        // MongoDB / Couch / Redis web UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"mongo-express\" | inurl:\"/_utils/\" intitle:\"CouchDB\" | intitle:\"Redis Commander\")",
                clean_domain
            ),
            description: "Find exposed database management UIs".to_string(),
            impact: "mongo-express/Redis Commander/CouchDB Fauxton with no auth = full database read/write including dump and drop".to_string(),
        });

        // Paste / issue tracker with credentials for target
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:pastebin.com | site:ghostbin.com | site:rentry.co) \"{}\" (password | api_key | secret | token)",
                clean_domain
            ),
            description: "Find domain-specific credentials leaked on paste sites".to_string(),
            impact: "Leaked pastes often contain working credentials, API keys, or debug output referencing the target".to_string(),
        });

        // ChatGPT / AI exposed sessions referencing the domain
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:chat.openai.com/share \"{}\"", clean_domain),
            description: "Find shared ChatGPT conversations mentioning the domain".to_string(),
            impact: "Shared chat sessions frequently contain copy-pasted code, config files, and debug output with secrets".to_string(),
        });

        // Postman / public collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com/*/workspace | site:documenter.getpostman.com | site:www.postman.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces or documentation".to_string(),
            impact: "Public Postman collections often include example authorization tokens, staging URLs, and undocumented endpoints".to_string(),
        });

        // Firebase realtime / Firestore with domain scope
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "(site:firebaseio.com | site:firebasestorage.googleapis.com) \"{}\"",
                clean_domain
            ),
            description: "Find Firebase realtime databases or storage buckets for the domain".to_string(),
            impact: "Misconfigured rules allow unauthenticated read/write of user data and file upload".to_string(),
        });

        // Azure Blob storage findings (public SAS tokens)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:blob.core.windows.net \"{}\" (\"sv=\" intext:\"sig=\" | intext:\"sp=rwdl\")",
                clean_domain
            ),
            description: "Find leaked Azure Blob SAS tokens".to_string(),
            impact: "SAS tokens grant time-bound access to blobs; overly-scoped ones (sp=rwdl) allow data destruction".to_string(),
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
