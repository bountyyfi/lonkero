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

        // Spring Boot Actuator endpoints
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/health | inurl:/actuator/loggers | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator endpoints leak environment variables, heap dumps (with credentials), thread dumps, and may allow remote code execution via /actuator/jolokia or shutdown via /actuator/shutdown.".to_string(),
        });

        // Prometheus metrics endpoints
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/metrics | inurl:/prometheus) intext:\"# HELP\" intext:\"# TYPE\"",
                clean_domain
            ),
            description: "Find exposed Prometheus / metrics endpoints".to_string(),
            impact: "Metrics endpoints expose internal endpoint paths, hostnames, queue/database state, and request counts useful for reconnaissance.".to_string(),
        });

        // GraphQL introspection / endpoint exposure
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/__graphql | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints / playgrounds".to_string(),
            impact: "Exposed GraphQL playgrounds reveal full schema (queries, mutations, types) and enable introspection-driven attacks on hidden fields.".to_string(),
        });

        // Exposed .env files
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.staging\" | inurl:\".env.backup\") intext:\"DB_PASSWORD\" | intext:\"APP_KEY\" | intext:\"SECRET\"",
                clean_domain
            ),
            description: "Find publicly indexed .env files containing secrets".to_string(),
            impact: "CRITICAL - .env files typically contain database credentials, API keys, JWT secrets, and SMTP credentials, granting full backend compromise.".to_string(),
        });

        // Exposed .git directories
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs\" | inurl:\"/.git/\")",
                clean_domain
            ),
            description: "Find exposed .git directories".to_string(),
            impact: "Exposed .git directories allow downloading the entire repository (including history, credentials in earlier commits, and source code).".to_string(),
        });

        // Terraform state files
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:\"terraform.tfstate\" | inurl:\"terraform.tfvars\")",
                clean_domain
            ),
            description: "Find exposed Terraform state and variables".to_string(),
            impact: "Terraform state files contain plaintext infrastructure secrets: cloud credentials, database passwords, API tokens, and full infrastructure topology.".to_string(),
        });

        // Kubernetes / kubeconfig files
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\"/.kube/config\" | ext:yaml intext:\"apiVersion: v1\" intext:\"kind: Config\" intext:\"client-key-data\")",
                clean_domain
            ),
            description: "Find exposed kubeconfig files".to_string(),
            impact: "Kubeconfig files grant cluster-admin access, enabling full takeover of all workloads, secrets, and persistent volumes.".to_string(),
        });

        // Swagger / OpenAPI specs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"swagger.json\" | inurl:\"swagger.yaml\" | inurl:\"openapi.json\" | inurl:\"openapi.yaml\" | inurl:\"/v2/api-docs\" | inurl:\"/v3/api-docs\")",
                clean_domain
            ),
            description: "Find raw Swagger / OpenAPI specifications".to_string(),
            impact: "Raw API specs enumerate every endpoint, parameter, auth scheme, and response shape - dramatically expanding the testable attack surface.".to_string(),
        });

        // OAuth tokens leaked in URL parameters (search engine caches)
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"access_token=\" | inurl:\"id_token=\" | inurl:\"refresh_token=\" | inurl:\"client_secret=\")",
                clean_domain
            ),
            description: "Find OAuth tokens leaked in URLs".to_string(),
            impact: "OAuth tokens captured in Google's cache from referrer-leak bugs grant access until token expiration; refresh_token leaks may be persistent.".to_string(),
        });

        // JWT in URLs
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} inurl:\"eyJ\" inurl:\".\"",
                clean_domain
            ),
            description: "Find JWT tokens leaked in URLs".to_string(),
            impact: "JWTs in URLs are logged in proxies, CDNs and browser history - if still valid they yield direct session takeover.".to_string(),
        });

        // Database / Backup file exposure
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sql.gz | ext:sql.tar | ext:dump | ext:bak | ext:db | ext:sqlite | ext:mdb) intext:\"INSERT INTO\" | intext:\"CREATE TABLE\"",
                clean_domain
            ),
            description: "Find exposed database dumps and backups".to_string(),
            impact: "Database dumps expose user records, password hashes, session tokens, and PII - among the highest-impact data exposures.".to_string(),
        });

        // WordPress config backups
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php.old\" | inurl:\"wp-config.php.save\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.txt\")",
                clean_domain
            ),
            description: "Find exposed wp-config backup files".to_string(),
            impact: "wp-config backups contain DB credentials, AUTH_KEYs, and salts; full WordPress and database compromise possible.".to_string(),
        });

        // Jenkins exposed
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/jenkins/\" | inurl:\"/script\" | inurl:\"/manage\" | inurl:\"/credentials/\") intitle:\"Dashboard [Jenkins]\"",
                clean_domain
            ),
            description: "Find exposed Jenkins consoles".to_string(),
            impact: "Unauthenticated Jenkins consoles often allow Groovy script execution (RCE) and exfiltration of stored credentials.".to_string(),
        });

        // Kibana / Elasticsearch exposed
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | inurl:\"/app/kibana\" | inurl:\"/app/discover\" | inurl:\":9200\" | inurl:\":5601\")",
                clean_domain
            ),
            description: "Find exposed Kibana / Elasticsearch instances".to_string(),
            impact: "Open Kibana exposes indexed application logs which routinely contain authentication tokens, internal hostnames, PII and stack traces.".to_string(),
        });

        // Grafana exposed
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:\"/login\" | inurl:\"/dashboard/\" | inurl:\"/d/\" intext:\"Grafana\")",
                clean_domain
            ),
            description: "Find exposed Grafana instances".to_string(),
            impact: "Public Grafana dashboards leak internal infrastructure topology; CVEs (e.g. CVE-2021-43798) make older versions readable without auth.".to_string(),
        });

        // PHP info pages
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" | inurl:\"phpinfo.php\" | inurl:\"info.php\") intext:\"PHP Version\"",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo() reveals server paths, environment variables (often including secrets), loaded extensions, and exact PHP version for CVE matching.".to_string(),
        });

        // Shell / bash history files
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".bash_history\" | inurl:\".zsh_history\" | inurl:\".mysql_history\" | inurl:\".psql_history\")",
                clean_domain
            ),
            description: "Find exposed shell history files".to_string(),
            impact: "Shell history often contains typed credentials, SSH keys, mysql/psql connection strings with passwords, and curl commands with bearer tokens.".to_string(),
        });

        // Docker / container metadata
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/v2/_catalog\" | inurl:\"/v2/\" intext:\"repositories\" | inurl:\":2375\" | inurl:\":2376\")",
                clean_domain
            ),
            description: "Find exposed Docker registries / Docker daemons".to_string(),
            impact: "Exposed registries leak proprietary images; exposed Docker API daemons (2375) typically allow full host takeover.".to_string(),
        });

        // Postman / Workspace leaks
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:postman.com (inurl:workspace | inurl:collection | inurl:documentation) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces / collections referencing the domain".to_string(),
            impact: "Public Postman collections frequently include hardcoded API keys, bearer tokens, and undocumented internal endpoints.".to_string(),
        });

        // Bitbucket snippets
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:bitbucket.org/snippets | site:gist.github.com | site:gitlab.com/-/snippets) \"{}\"",
                clean_domain
            ),
            description: "Find public code snippets referencing the domain".to_string(),
            impact: "Snippets and gists are a common location for accidentally pasted credentials, internal URLs, and proof-of-concept exploits.".to_string(),
        });

        // Stack Overflow / Reddit leaks
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:serverfault.com | site:reddit.com) \"{}\" (password | token | apikey | \"connection string\" | secret)",
                clean_domain
            ),
            description: "Find Stack Overflow / Reddit posts leaking credentials".to_string(),
            impact: "Developers asking for help routinely paste redacted-but-still-valid credentials, configuration files, and stack traces.".to_string(),
        });

        // RabbitMQ / Solr / Vault management UIs
        dorks.push(GoogleDork {
            category: "Exposed Management Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | inurl:\"/solr/#/\" | intitle:\"Solr Admin\" | inurl:\"/ui/vault/\" | intitle:\"Vault\")",
                clean_domain
            ),
            description: "Find exposed broker / search / secrets-manager UIs".to_string(),
            impact: "RabbitMQ/Solr/Vault UIs without authentication enable queue inspection, index dumps, or full secret retrieval.".to_string(),
        });

        // Open S3 bucket listings
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:s3.*.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net) intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Find publicly listable cloud storage buckets".to_string(),
            impact: "Directory-listable buckets allow downloading every object in the bucket, frequently including backups, PII, and internal documents.".to_string(),
        });

        // .DS_Store / Thumbs.db (directory enumeration aids)
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\"desktop.ini\")",
                clean_domain
            ),
            description: "Find exposed OS metadata files".to_string(),
            impact: ".DS_Store / Thumbs.db files enumerate file and folder names that aren't otherwise indexed - a starting point for further discovery.".to_string(),
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
