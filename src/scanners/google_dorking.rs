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
        // Public collaboration / AI / paste sites — recent high-impact venues
        // for leaked credentials and internal documents. All queries scope to
        // a known site + the target domain so they cannot produce false hits.
        // ====================================================================

        // Notion public sites and pages — internal runbooks frequently leak here
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:notion.site OR site:notion.so \"{}\"", clean_domain),
            description: "Find publicly shared Notion pages mentioning the domain".to_string(),
            impact: "Public Notion pages routinely contain runbooks, API keys, and internal procedures".to_string(),
        });

        // ChatGPT shared conversations — engineers paste production data while debugging
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:chatgpt.com/share OR site:chat.openai.com/share \"{}\"", clean_domain),
            description: "Find ChatGPT shared conversations mentioning the domain".to_string(),
            impact: "Shared ChatGPT chats often contain pasted secrets, error logs, and internal code".to_string(),
        });

        // Claude shared artifacts
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:claude.site OR site:claude.ai/share \"{}\"", clean_domain),
            description: "Find shared Claude AI conversations or artifacts".to_string(),
            impact: "Shared Claude artifacts may contain pasted internal code, secrets, or queries".to_string(),
        });

        // Public Postman workspaces / collections / documenters
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com OR site:documenter.getpostman.com OR site:web.postman.co \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces, collections, and documenters".to_string(),
            impact: "Public Postman workspaces commonly leak production endpoints, examples, and pre-filled auth tokens".to_string(),
        });

        // Public OpenAPI hubs (Stoplight, ReadMe, SwaggerHub)
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:stoplight.io OR site:readme.com OR site:redocly.com OR site:swaggerhub.com \"{}\"",
                clean_domain
            ),
            description: "Find published API documentation portals referencing the domain".to_string(),
            impact: "Public API portals expose endpoint inventories, parameters, and authentication mechanics".to_string(),
        });

        // GitHub Gists — most common credential-leak surface after repos
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub gists referencing the domain".to_string(),
            impact: "Gists are a top source of leaked tokens, internal scripts, and SSH keys".to_string(),
        });

        // GitLab snippets
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gitlab.com/-/snippets OR inurl:/snippets/ \"{}\"", clean_domain),
            description: "Find GitLab snippets referencing the domain".to_string(),
            impact: "Public GitLab snippets often leak ad-hoc scripts and credentials".to_string(),
        });

        // Sourcegraph code search (cross-repo source code)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:sourcegraph.com \"{}\"", clean_domain),
            description: "Find indexed source code mentioning the domain".to_string(),
            impact: "Sourcegraph indexes public code across many forges and may surface secrets in commits".to_string(),
        });

        // Replit — public IDE projects, often with hardcoded keys
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:replit.com \"{}\"", clean_domain),
            description: "Find public Replit projects referencing the domain".to_string(),
            impact: "Replit projects routinely contain hardcoded API keys and database URLs in .env files".to_string(),
        });

        // CodeSandbox / StackBlitz
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:codesandbox.io OR site:stackblitz.com \"{}\"",
                clean_domain
            ),
            description: "Find browser-IDE sandboxes referencing the domain".to_string(),
            impact: "Public sandboxes often contain hardcoded API keys for prototyping".to_string(),
        });

        // Paste sites — broader than pastebin
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:hastebin.com OR site:dpaste.com OR site:paste.ee OR site:rentry.co OR site:justpaste.it OR site:controlc.com OR site:ideone.com \"{}\"",
                clean_domain
            ),
            description: "Find paste-site content referencing the domain".to_string(),
            impact: "Pastes commonly contain dumped credentials, leaked emails, and internal log fragments".to_string(),
        });

        // Public S3 indexes via Google
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com OR site:s3.us-east-1.amazonaws.com OR site:s3.us-west-2.amazonaws.com OR site:s3.eu-west-1.amazonaws.com intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Find directory-listed S3 buckets indexed by Google".to_string(),
            impact: "Listable S3 buckets often expose entire backup sets, logs, and PII dumps".to_string(),
        });

        // R2 / B2 / Wasabi / Linode object storage
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:r2.cloudflarestorage.com OR site:r2.dev OR site:backblazeb2.com OR site:wasabisys.com OR site:linodeobjects.com \"{}\"",
                clean_domain
            ),
            description: "Find non-AWS object storage buckets referencing the domain".to_string(),
            impact: "R2/B2/Wasabi buckets are often configured with public read for static assets and leak alongside it".to_string(),
        });

        // Apache Airflow exposed UIs
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"Airflow\" inurl:/admin OR inurl:/dags site:{}",
                clean_domain
            ),
            description: "Find exposed Apache Airflow UIs on the target domain".to_string(),
            impact: "Open Airflow UIs allow viewing and triggering DAGs, often with embedded connection credentials".to_string(),
        });

        // Argo CD / Argo Workflows
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"Argo CD\" OR intitle:\"Argo Workflows\" OR inurl:/argo/ OR inurl:/applications site:{}",
                clean_domain
            ),
            description: "Find exposed Argo CD or Argo Workflows interfaces".to_string(),
            impact: "Argo dashboards expose Kubernetes cluster contents, manifests, and sync state".to_string(),
        });

        // Kubernetes dashboards and kube-apiserver-style endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"Kubernetes Dashboard\" OR inurl:/api/v1/namespaces OR inurl:/#/workloads site:{}",
                clean_domain
            ),
            description: "Find exposed Kubernetes dashboards or kube-apiserver endpoints".to_string(),
            impact: "Exposed Kubernetes UIs and API servers grant cluster-wide visibility and sometimes control".to_string(),
        });

        // Apache Spark / Flink / Yarn cluster UIs
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"Spark Master\" OR intitle:\"Spark Jobs\" OR intitle:\"Apache Flink Dashboard\" OR intitle:\"All Applications\" inurl:cluster site:{}",
                clean_domain
            ),
            description: "Find exposed Spark/Flink/Yarn cluster UIs".to_string(),
            impact: "Big-data cluster UIs often allow job submission (RCE on cluster) and leak logs containing credentials".to_string(),
        });

        // RabbitMQ / Kafka / NATS / Pulsar admin UIs
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"RabbitMQ Management\" OR intitle:\"Kafka Manager\" OR inurl:/manage/main/overview site:{}",
                clean_domain
            ),
            description: "Find exposed message-broker admin UIs".to_string(),
            impact: "Broker admin UIs often allow message inspection, queue tampering, and reveal credentials".to_string(),
        });

        // Prometheus / Alertmanager (no auth by default)
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "inurl:/graph?g0.expr OR inurl:/alerts OR inurl:/targets intitle:\"Prometheus\" site:{}",
                clean_domain
            ),
            description: "Find exposed Prometheus / Alertmanager instances".to_string(),
            impact: "Prometheus exposes internal service inventory and PromQL query interface, often unauthenticated".to_string(),
        });

        // Public Grafana dashboards
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "inurl:/d/ inurl:orgId= intitle:\"Grafana\" site:{}",
                clean_domain
            ),
            description: "Find shared public Grafana dashboards".to_string(),
            impact: "Public Grafana dashboards leak internal metric names, hostnames, and sometimes raw log fields".to_string(),
        });

        // Spring Boot Actuator endpoints (extremely high impact)
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "inurl:/actuator/health OR inurl:/actuator/env OR inurl:/actuator/heapdump OR inurl:/actuator/loggers site:{}",
                clean_domain
            ),
            description: "Find Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator /env, /heapdump, /loggers expose environment variables, JVM heap (with secrets), and config".to_string(),
        });

        // Drupal /node?title patterns, /CHANGELOG.txt, Joomla configuration leak surfaces
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "inurl:/CHANGELOG.txt OR inurl:/web.config OR inurl:/.well-known/security.txt OR inurl:/.git/HEAD OR inurl:/.svn/entries site:{}",
                clean_domain
            ),
            description: "Find VCS metadata and configuration files".to_string(),
            impact: "Exposed .git/.svn directories allow full source tree reconstruction; web.config leaks connection strings".to_string(),
        });

        // Splunk / Kibana / Elastic Logstash dashboards
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "intitle:\"Splunk\" inurl:/en-US/account/login OR inurl:/app/kibana#/discover OR inurl:/_search?pretty site:{}",
                clean_domain
            ),
            description: "Find Splunk / Kibana / Elasticsearch endpoints".to_string(),
            impact: "Open log search interfaces frequently leak credentials, tokens, and PII appearing in log lines".to_string(),
        });

        // Sentry / Bugsnag / Rollbar — sometimes public projects
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:sentry.io OR site:bugsnag.com OR site:rollbar.com \"{}\"",
                clean_domain
            ),
            description: "Find publicly accessible error tracker projects".to_string(),
            impact: "Public error trackers expose stack traces with file paths, query parameters, and sometimes auth headers".to_string(),
        });

        // GitBook public spaces / Mintlify / Bookstack public docs
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:gitbook.io OR site:gitbook.com OR site:mintlify.app \"{}\"",
                clean_domain
            ),
            description: "Find public documentation hubs on GitBook / Mintlify".to_string(),
            impact: "Internal docs and runbooks are commonly accidentally published on these platforms".to_string(),
        });

        // Loom recordings — often contain dashboards with PII
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:loom.com \"{}\"", clean_domain),
            description: "Find shared Loom recordings mentioning the domain".to_string(),
            impact: "Loom recordings of internal dashboards reveal data layouts, customer records, and credentials on screen".to_string(),
        });

        // DocSend / Pitch.com / Canva shared decks
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:docsend.com OR site:pitch.com OR site:canva.com/design \"{}\"",
                clean_domain
            ),
            description: "Find publicly shared decks and design files".to_string(),
            impact: "Shared business decks frequently disclose roadmaps, partner names, and pricing".to_string(),
        });

        // Public Airtable / Coda / Confluence
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:airtable.com/shr OR site:coda.io OR inurl:/wiki/spaces site:atlassian.net \"{}\"",
                clean_domain
            ),
            description: "Find publicly shared Airtable / Coda / Confluence pages".to_string(),
            impact: "Shared collaboration tools often expose customer lists, contractor info, and credentials".to_string(),
        });

        // Public Snyk / Dependabot / OSS Index advisories — discloses CVE exposure
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "site:snyk.io/vuln OR site:github.com inurl:security/advisories \"{}\"",
                clean_domain
            ),
            description: "Find vulnerability advisories referencing the domain or its packages".to_string(),
            impact: "Advisories may pre-disclose unpatched CVEs in the target stack".to_string(),
        });

        // Bug bounty / vulnerability disclosure platforms
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "site:hackerone.com/reports OR site:huntr.dev OR site:bugcrowd.com/disclosures \"{}\"",
                clean_domain
            ),
            description: "Find disclosed bug bounty reports".to_string(),
            impact: "Disclosed reports may describe still-unpatched classes of issues on the target".to_string(),
        });

        // Public package registries containing internal package names
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "site:npmjs.com/package OR site:pypi.org/project OR site:rubygems.org/gems \"{}\"",
                clean_domain
            ),
            description: "Find internal packages accidentally published to public registries".to_string(),
            impact: "Internally-named packages on public registries enable dependency-confusion attacks".to_string(),
        });

        // Docker Hub / Quay / GHCR images referencing the org
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "site:hub.docker.com OR site:quay.io OR site:github.com/orgs inurl:packages \"{}\"",
                clean_domain
            ),
            description: "Find public Docker images and container packages".to_string(),
            impact: "Pushed images frequently contain embedded credentials, internal hostnames, and license files".to_string(),
        });

        // S3-style public Trello / Asana boards via Google
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:trello.com/b OR site:trello.com/c \"{}\" (password OR secret OR token OR key)",
                clean_domain
            ),
            description: "Find Trello boards mentioning credentials".to_string(),
            impact: "Public Trello cards historically leak production credentials in checklists and comments".to_string(),
        });

        // env-style files indexed by Google
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (filetype:env OR filetype:envrc OR filetype:tfstate OR filetype:tfvars OR filetype:pem OR filetype:ovpn OR filetype:rdp)",
                clean_domain
            ),
            description: "Find environment and IaC state files".to_string(),
            impact: ".env, .tfstate, .pem, .ovpn files contain database URLs, IAM credentials, and private keys".to_string(),
        });

        // GraphQL endpoints / GraphiQL UIs
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "inurl:/graphql OR inurl:/graphiql OR inurl:/playground OR inurl:/altair intitle:\"GraphiQL\" site:{}",
                clean_domain
            ),
            description: "Find GraphQL endpoints and exposed playgrounds".to_string(),
            impact: "Public GraphiQL/Playground reveals the full schema and enables introspection-driven testing".to_string(),
        });

        // Backup files indexed publicly
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql OR ext:sqlite OR ext:db OR ext:bak OR ext:backup OR ext:dump OR ext:tar.gz OR ext:zip) (intitle:\"index of\" OR inurl:backup)",
                clean_domain
            ),
            description: "Find database dumps and backup archives".to_string(),
            impact: "DB dumps and tarballs contain full schemas, rows, and often hashed credentials".to_string(),
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
