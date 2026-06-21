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

        // Notion shared sites - many companies leak internal handbooks here
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!("site:notion.site \"{}\"", clean_domain),
            description: "Find Notion shared pages mentioning the domain".to_string(),
            impact: "Public Notion pages frequently expose internal runbooks, onboarding docs, and credentials".to_string(),
        });

        // Loom unlisted recordings
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!("site:loom.com \"{}\"", clean_domain),
            description: "Find Loom recordings mentioning the domain".to_string(),
            impact: "Unlisted Loom videos can expose internal demos, admin walkthroughs, and screen recordings of sensitive UIs".to_string(),
        });

        // Figma community / shared files
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!("site:figma.com \"{}\"", clean_domain),
            description: "Find Figma files mentioning the domain".to_string(),
            impact: "Figma files often include real screenshots of admin panels and internal flows".to_string(),
        });

        // Miro public boards
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!("site:miro.com \"{}\"", clean_domain),
            description: "Find Miro boards mentioning the domain".to_string(),
            impact: "Public Miro boards can expose architecture diagrams and threat models".to_string(),
        });

        // Coda docs
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!("site:coda.io \"{}\"", clean_domain),
            description: "Find Coda docs mentioning the domain".to_string(),
            impact: "Public Coda docs frequently leak runbooks and credentials".to_string(),
        });

        // Postman Public Workspaces / collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com OR site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find Postman public workspaces / collections referencing the domain".to_string(),
            impact: "Public Postman collections frequently leak production tokens, internal endpoints, and example bodies".to_string(),
        });

        // Swagger Hub published APIs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!("site:app.swaggerhub.com \"{}\"", clean_domain),
            description: "Find SwaggerHub-published APIs for the domain".to_string(),
            impact: "Public SwaggerHub APIs disclose endpoint shapes and example payloads".to_string(),
        });

        // Raw OpenAPI / Swagger documents
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json OR inurl:swagger.yaml OR inurl:openapi.json OR inurl:openapi.yaml OR inurl:v2/api-docs OR inurl:v3/api-docs)",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger specs served by the target".to_string(),
            impact: "Raw API specs expose every endpoint and its schema, dramatically expanding attack surface".to_string(),
        });

        // GraphQL public explorers
        dorks.push(GoogleDork {
            category: "GraphQL".to_string(),
            query: format!(
                "site:{} (inurl:graphql OR inurl:graphiql OR inurl:playground OR intitle:\"GraphQL Playground\" OR intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints / explorers".to_string(),
            impact: "Open GraphQL Playground / GraphiQL frequently allow unauthenticated introspection of the full schema".to_string(),
        });

        // Spring Boot Actuator
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (inurl:/actuator OR inurl:/actuator/env OR inurl:/actuator/heapdump OR inurl:/actuator/loggers OR inurl:/actuator/gateway)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Unauthenticated Actuator endpoints leak env/secrets, heap dumps, and (via /gateway) allow SSRF".to_string(),
        });

        // Apache Airflow webserver
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Sign In - Airflow\" OR inurl:/airflow OR inurl:/admin/airflow)",
                clean_domain
            ),
            description: "Find exposed Apache Airflow web UI".to_string(),
            impact: "Open Airflow has multiple historic RCE CVEs and exposes DAG runtime / connection credentials".to_string(),
        });

        // Argo CD UI
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Argo CD\" OR inurl:/argocd OR inurl:/applications)",
                clean_domain
            ),
            description: "Find exposed Argo CD UI".to_string(),
            impact: "Open Argo CD allows attacker to deploy arbitrary manifests; multiple bypass CVEs".to_string(),
        });

        // Kubernetes dashboards / kubectl proxy
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" OR inurl:/api/v1/namespaces OR inurl:/#/login)",
                clean_domain
            ),
            description: "Find exposed Kubernetes Dashboard / API".to_string(),
            impact: "Open k8s dashboards are full cluster takeover".to_string(),
        });

        // Jenkins / Hudson
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" OR inurl:/script OR inurl:/computer)",
                clean_domain
            ),
            description: "Find exposed Jenkins instances".to_string(),
            impact: "Open Jenkins script consoles are RCE; build agents leak secrets".to_string(),
        });

        // Metabase BI
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Metabase\" OR inurl:/api/session/properties)",
                clean_domain
            ),
            description: "Find exposed Metabase instances".to_string(),
            impact: "Open Metabase exposes raw queries; CVE-2023-38646 allows pre-auth RCE on stale instances".to_string(),
        });

        // Elasticsearch / Kibana
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" OR inurl:/_cluster/health OR inurl:/_cat/indices)",
                clean_domain
            ),
            description: "Find exposed Elasticsearch / Kibana".to_string(),
            impact: "Open Elasticsearch leaks index data; open Kibana lets attackers run queries and stored XSS".to_string(),
        });

        // Jupyter notebooks
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Jupyter Notebook\" OR inurl:/tree OR inurl:/lab)",
                clean_domain
            ),
            description: "Find exposed Jupyter notebook servers".to_string(),
            impact: "Open Jupyter is RCE via terminal cell and frequently runs as root inside k8s pods".to_string(),
        });

        // Prometheus
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series\" OR inurl:/graph OR inurl:/targets)",
                clean_domain
            ),
            description: "Find exposed Prometheus".to_string(),
            impact: "Open Prometheus leaks internal hostnames, k8s topology, and target credentials in /targets metadata".to_string(),
        });

        // Grafana
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" OR inurl:/login intext:\"Grafana\")",
                clean_domain
            ),
            description: "Find exposed Grafana".to_string(),
            impact: "Anonymous Grafana orgs expose dashboards; CVE-2021-43798 LFI still found in the wild".to_string(),
        });

        // ENV files exposed
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD=\" OR intext:\"AWS_SECRET_ACCESS_KEY=\" OR intext:\"-----BEGIN PRIVATE KEY-----\")",
                clean_domain
            ),
            description: "Find indexed .env or PEM contents".to_string(),
            impact: "Indexed env/PEM contents are critical: usable production secrets exposed to crawlers".to_string(),
        });

        // Backups / dumps with credentials inside
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql OR ext:dump OR ext:gz OR ext:tar OR ext:7z OR ext:rar OR ext:bak) (intext:\"INSERT INTO\" OR intext:\"CREATE TABLE\" OR intext:\"password\")",
                clean_domain
            ),
            description: "Find indexed database dumps or backups".to_string(),
            impact: "Database dumps contain user records, password hashes, and sometimes plaintext secrets".to_string(),
        });

        // Exposed Git folder
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.git/config OR inurl:.git/HEAD OR inurl:.git/index)",
                clean_domain
            ),
            description: "Find exposed .git directory contents".to_string(),
            impact: "Exposed .git lets an attacker reconstruct full source code including history".to_string(),
        });

        // SVN / Mercurial
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.svn/entries OR inurl:.svn/wc.db OR inurl:.hg/store)",
                clean_domain
            ),
            description: "Find exposed SVN/Mercurial metadata".to_string(),
            impact: "SCM metadata enables source-code reconstruction".to_string(),
        });

        // DS_Store / Mac metadata
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!("site:{} (inurl:.DS_Store OR ext:DS_Store)", clean_domain),
            description: "Find exposed macOS .DS_Store files".to_string(),
            impact: ".DS_Store reveals full directory listing, often surfacing hidden files".to_string(),
        });

        // .well-known / Internal mappings
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.well-known/openid-configuration OR inurl:.well-known/oauth-authorization-server OR inurl:.well-known/security.txt)",
                clean_domain
            ),
            description: "Find indexed .well-known metadata documents".to_string(),
            impact: "OIDC/OAuth discovery docs reveal IdP, scopes, and token endpoints for further attack chaining".to_string(),
        });

        // SAML metadata
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:saml/metadata OR inurl:metadata.xml OR ext:xml intext:\"EntityDescriptor\")",
                clean_domain
            ),
            description: "Find indexed SAML metadata".to_string(),
            impact: "SAML metadata exposes signing certs and ACS URLs - useful for SSO attacks".to_string(),
        });

        // Atlassian Confluence / Jira indexed content
        dorks.push(GoogleDork {
            category: "Collaboration Leaks".to_string(),
            query: format!(
                "(site:atlassian.net OR site:jira.com OR site:confluence.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Atlassian (Jira/Confluence) pages mentioning the domain".to_string(),
            impact: "Public Jira/Confluence pages frequently leak runbooks, tickets, and internal architecture".to_string(),
        });

        // Stackoverflow / mailing-list disclosures
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:stackoverflow.com OR site:stackexchange.com) \"{}\" (token OR apikey OR password OR secret)",
                clean_domain
            ),
            description: "Find Stack Overflow questions where developers pasted the domain alongside credentials".to_string(),
            impact: "Developers often paste real tokens / config when asking for help".to_string(),
        });

        // GitHub Gists for the domain
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists mentioning the domain".to_string(),
            impact: "Gists frequently contain throwaway credentials and internal config snippets".to_string(),
        });

        // GitHub repos with explicit credential keywords - high-signal
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" (\"password\" OR \"apikey\" OR \"api_key\" OR \"AWS_SECRET_ACCESS_KEY\" OR \"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find GitHub source mentioning the domain alongside credential keywords".to_string(),
            impact: "High-signal credential-leak indicator; many tokens in GitHub are still live".to_string(),
        });

        // Replit / Glitch / CodeSandbox - frequent leak sources
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:replit.com OR site:glitch.com OR site:codesandbox.io OR site:stackblitz.com) \"{}\"",
                clean_domain
            ),
            description: "Find online IDE snippets mentioning the domain".to_string(),
            impact: "Online IDEs frequently store working sandboxes with real credentials".to_string(),
        });

        // Phpinfo & similar
        dorks.push(GoogleDork {
            category: "Misconfigured Tools".to_string(),
            query: format!(
                "site:{} (intitle:phpinfo() OR inurl:phpinfo.php OR inurl:test.php intext:\"PHP Extension\")",
                clean_domain
            ),
            description: "Find exposed phpinfo() output".to_string(),
            impact: "phpinfo leaks environment variables, loaded modules, and database creds in env".to_string(),
        });

        // Wayback / Archive.org leaks
        dorks.push(GoogleDork {
            category: "Historical Leaks".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (intext:apikey OR intext:password OR intext:token)",
                clean_domain
            ),
            description: "Find archived pages of the domain containing credential keywords".to_string(),
            impact: "Archived versions often retain credentials/configs that have been removed from live site".to_string(),
        });

        // LinkedIn employees - useful for spear-phish targeting
        dorks.push(GoogleDork {
            category: "Employee Reconnaissance".to_string(),
            query: format!(
                "site:linkedin.com/in \"{}\"",
                clean_domain.split('.').next().unwrap_or(clean_domain)
            ),
            description: "Find LinkedIn profiles claiming employment at the target organization".to_string(),
            impact: "Enumerates current employees - useful for social engineering and credential stuffing".to_string(),
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
