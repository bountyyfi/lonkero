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

        // -------- Exposed .env / dotenv files (highest-signal credential leak) --------
        dorks.push(GoogleDork {
            category: "Config Leaks".to_string(),
            query: format!(
                "site:{} intext:\"DB_PASSWORD\" | intext:\"APP_KEY=base64\" | intext:\"SECRET_KEY_BASE\" ext:env | ext:conf | ext:cfg | ext:local",
                clean_domain
            ),
            description: "Find exposed .env / dotenv files with credentials".to_string(),
            impact:
                "Directly discloses DB, API and framework secret keys — Critical if indexed"
                    .to_string(),
        });

        // -------- Actuator / Spring Boot management endpoints --------
        dorks.push(GoogleDork {
            category: "Actuator / Management".to_string(),
            query: format!(
                "site:{} inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/beans | inurl:/actuator/mappings | inurl:/actuator/health",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact:
                "Actuator env/heapdump routinely leaks environment vars, DB URIs, and full JVM \
                 heap dumps containing tokens and PII"
                    .to_string(),
        });

        // -------- Prometheus / metrics / debug endpoints --------
        dorks.push(GoogleDork {
            category: "Metrics / Debug".to_string(),
            query: format!(
                "site:{} inurl:/metrics | inurl:/prometheus | inurl:/debug/pprof | inurl:/debug/vars | inurl:/status | inurl:/varz",
                clean_domain
            ),
            description: "Find Prometheus / pprof / debug telemetry endpoints".to_string(),
            impact:
                "Metrics endpoints often reveal internal hostnames, versions, request URIs and \
                 stack traces; /debug/pprof enables Go heap/goroutine dumps"
                    .to_string(),
        });

        // -------- ELMAH / trace.axd / ASP.NET debug --------
        dorks.push(GoogleDork {
            category: "ASP.NET Debug".to_string(),
            query: format!(
                "site:{} inurl:elmah.axd | inurl:trace.axd | inurl:elmah/errors | inurl:elmah.aspx",
                clean_domain
            ),
            description: "Find ELMAH / trace.axd / ASP.NET error logs".to_string(),
            impact:
                "ELMAH and trace.axd expose full request bodies (incl. auth cookies, tokens) \
                 across all recent errors — often unauthenticated"
                    .to_string(),
        });

        // -------- phpinfo / server-status / server-info --------
        dorks.push(GoogleDork {
            category: "Server Info".to_string(),
            query: format!(
                "site:{} inurl:phpinfo.php | inurl:info.php | inurl:test.php intext:\"php.ini\" | inurl:server-status | inurl:server-info",
                clean_domain
            ),
            description: "Find phpinfo / Apache server-status pages".to_string(),
            impact:
                "phpinfo discloses env vars, module list, session paths; Apache server-status \
                 exposes recent request URIs and client IPs — commonly unauthenticated"
                    .to_string(),
        });

        // -------- Exposed .git / .svn / .hg / .bzr metadata --------
        dorks.push(GoogleDork {
            category: "VCS Metadata".to_string(),
            query: format!(
                "site:{} inurl:/.git/config | inurl:/.git/HEAD | inurl:/.svn/entries | inurl:/.hg/store | inurl:/.bzr/README",
                clean_domain
            ),
            description: "Find exposed VCS metadata directories".to_string(),
            impact:
                "Exposed .git allows full source disclosure and often reveals hardcoded secrets \
                 in commit history"
                    .to_string(),
        });

        // -------- Backup archives with domain reference --------
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} ext:zip | ext:tar | ext:tgz | ext:tar.gz | ext:rar | ext:7z | ext:gz | ext:bz2 intext:\"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find backup archives referencing the domain".to_string(),
            impact: "Backup archives frequently contain source, DB dumps and credentials"
                .to_string(),
        });

        // -------- SQL / DB dumps --------
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql | ext:dump | ext:sqlite | ext:sqlite3 | ext:mdb intext:\"INSERT INTO\" | intext:\"CREATE TABLE\"",
                clean_domain
            ),
            description: "Find raw SQL / SQLite / Access dumps".to_string(),
            impact: "Database dumps expose user data, credential hashes and business records"
                .to_string(),
        });

        // -------- Kubernetes / K8s dashboard / kubeconfig --------
        dorks.push(GoogleDork {
            category: "Kubernetes".to_string(),
            query: format!(
                "site:{} intitle:\"Kubernetes Dashboard\" | inurl:/api/v1/namespaces | inurl:/healthz | inurl:kubeconfig",
                clean_domain
            ),
            description: "Find exposed Kubernetes dashboards or API".to_string(),
            impact:
                "Unauthenticated Kubernetes dashboards / API allow full cluster takeover and \
                 secret extraction"
                    .to_string(),
        });

        // -------- Kibana / Elasticsearch --------
        dorks.push(GoogleDork {
            category: "Elasticsearch / Kibana".to_string(),
            query: format!(
                "site:{} intitle:\"Kibana\" | inurl:app/kibana | inurl:_cat/indices | inurl:_search | inurl:_cluster/health",
                clean_domain
            ),
            description: "Find exposed Kibana or Elasticsearch endpoints".to_string(),
            impact:
                "Public Elasticsearch clusters expose logs, PII and internal data; Kibana \
                 without SSO is direct read access"
                    .to_string(),
        });

        // -------- Grafana / Prometheus dashboards --------
        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} intitle:\"Grafana\" inurl:/login | inurl:/api/datasources | intitle:\"Prometheus Time Series Collection\"",
                clean_domain
            ),
            description: "Find exposed Grafana / Prometheus consoles".to_string(),
            impact:
                "Dashboards leak internal service topology; anonymous Grafana orgs commonly \
                 expose full metrics"
                    .to_string(),
        });

        // -------- Metabase / Redash / Superset (BI tools with data access) --------
        dorks.push(GoogleDork {
            category: "BI / Analytics".to_string(),
            query: format!(
                "site:{} intitle:\"Metabase\" | intitle:\"Redash\" | intitle:\"Apache Superset\" | inurl:/api/session/properties",
                clean_domain
            ),
            description: "Find exposed Metabase / Redash / Superset instances".to_string(),
            impact:
                "BI tools are backdoors into production DBs when auth is misconfigured (recent \
                 Metabase pre-auth RCEs, e.g. CVE-2023-38646)"
                    .to_string(),
        });

        // -------- Jenkins / TeamCity / Bamboo / GitLab CI --------
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} intitle:\"Dashboard [Jenkins]\" | inurl:/jenkins/script | intitle:\"TeamCity\" | intitle:\"Bamboo Dashboard\"",
                clean_domain
            ),
            description: "Find exposed CI/CD consoles".to_string(),
            impact:
                "Anonymous CI/CD dashboards expose build logs (often containing tokens) and \
                 sometimes a script console = RCE"
                    .to_string(),
        });

        // -------- Argo CD / ArgoCD --------
        dorks.push(GoogleDork {
            category: "GitOps".to_string(),
            query: format!(
                "site:{} intitle:\"Argo CD\" | inurl:/applications | inurl:/api/v1/applications",
                clean_domain
            ),
            description: "Find exposed Argo CD instances".to_string(),
            impact: "Argo CD without auth allows cluster manifest read/write, secret disclosure"
                .to_string(),
        });

        // -------- HashiCorp Vault / Consul / Nomad UIs --------
        dorks.push(GoogleDork {
            category: "HashiCorp".to_string(),
            query: format!(
                "site:{} intitle:\"Vault\" inurl:/ui | intitle:\"Consul\" | inurl:/v1/agent/self | intitle:\"Nomad\"",
                clean_domain
            ),
            description: "Find exposed Vault / Consul / Nomad UIs".to_string(),
            impact:
                "Public Consul KV or Nomad job configs frequently disclose secrets; unauth Vault \
                 UI is rare but critical"
                    .to_string(),
        });

        // -------- Airflow / Prefect / Dagster --------
        dorks.push(GoogleDork {
            category: "Workflow Orchestration".to_string(),
            query: format!(
                "site:{} intitle:\"Airflow\" inurl:/home | inurl:/admin/airflow | intitle:\"Prefect\"",
                clean_domain
            ),
            description: "Find exposed Airflow / Prefect consoles".to_string(),
            impact:
                "Airflow DAGs contain DB URIs, cloud creds and are executable — anonymous \
                 web UI = full pipeline compromise"
                    .to_string(),
        });

        // -------- Repository indexes (Nexus, Artifactory, npm, PyPI internal) --------
        dorks.push(GoogleDork {
            category: "Artifact Repositories".to_string(),
            query: format!(
                "site:{} intitle:\"Nexus Repository Manager\" | intitle:\"JFrog Artifactory\" | inurl:/service/rest/repository",
                clean_domain
            ),
            description: "Find exposed Nexus / Artifactory".to_string(),
            impact:
                "Internal artifact repos leak proprietary packages; anonymous deploy access \
                 enables supply-chain attacks"
                    .to_string(),
        });

        // -------- MinIO / S3 emulators --------
        dorks.push(GoogleDork {
            category: "Object Storage".to_string(),
            query: format!(
                "site:{} intitle:\"MinIO Console\" | inurl:/minio/health/live | inurl:?list-type=2",
                clean_domain
            ),
            description: "Find MinIO consoles and unauthenticated bucket listings".to_string(),
            impact: "Anonymous bucket listing discloses every object key — often includes PII"
                .to_string(),
        });

        // -------- Common CVE-worthy vendor portals --------
        dorks.push(GoogleDork {
            category: "Vendor Portals".to_string(),
            query: format!(
                "site:{} intitle:\"Citrix\" (\"NetScaler\" | \"Gateway\") | intitle:\"FortiGate\" | intitle:\"Pulse Connect Secure\" | intitle:\"GlobalProtect Portal\"",
                clean_domain
            ),
            description: "Find edge/VPN portals frequently targeted by chained CVEs".to_string(),
            impact:
                "Citrix/Fortinet/Pulse/PAN portals are prime targets for pre-auth exploits — \
                 confirms attack surface even if version is unknown"
                    .to_string(),
        });

        // -------- Exposed authentication / JWT / SAML metadata --------
        dorks.push(GoogleDork {
            category: "Auth Metadata".to_string(),
            query: format!(
                "site:{} inurl:/.well-known/openid-configuration | inurl:/.well-known/jwks.json | inurl:/saml/metadata | inurl:/FederationMetadata.xml",
                clean_domain
            ),
            description: "Find OIDC / JWKS / SAML metadata endpoints".to_string(),
            impact:
                "Reveals allowed algorithms, key IDs and issuer URLs — required intel for token \
                 forging or downgrade attacks"
                    .to_string(),
        });

        // -------- GraphQL introspection / schema --------
        dorks.push(GoogleDork {
            category: "GraphQL".to_string(),
            query: format!(
                "site:{} inurl:/graphql | inurl:/graphiql | inurl:/playground intext:\"__schema\"",
                clean_domain
            ),
            description: "Find GraphQL endpoints and introspection UIs".to_string(),
            impact:
                "Introspection reveals every type, field and mutation — accelerates BOLA / auth \
                 bypass discovery"
                    .to_string(),
        });

        // -------- Docker registry / Portainer / Rancher --------
        dorks.push(GoogleDork {
            category: "Container Management".to_string(),
            query: format!(
                "site:{} intitle:\"Portainer\" | intitle:\"Rancher\" | inurl:/v2/_catalog | intitle:\"Docker Registry\"",
                clean_domain
            ),
            description: "Find exposed container management UIs and Docker registries".to_string(),
            impact:
                "Anonymous Docker registry _catalog leaks image names and layers (often with \
                 baked-in secrets); Portainer/Rancher = container RCE"
                    .to_string(),
        });

        // -------- Wiki / knowledge bases (leak internal docs) --------
        dorks.push(GoogleDork {
            category: "Internal Wikis".to_string(),
            query: format!(
                "site:{} intitle:\"BookStack\" | intitle:\"XWiki\" | intitle:\"MediaWiki\" | intitle:\"DokuWiki\" | intitle:\"Outline\"",
                clean_domain
            ),
            description: "Find self-hosted wikis / knowledge bases".to_string(),
            impact:
                "Anonymous wiki access frequently exposes runbooks, credentials and internal \
                 architecture diagrams"
                    .to_string(),
        });

        // -------- Ticketing / helpdesk with attachments --------
        dorks.push(GoogleDork {
            category: "Helpdesk".to_string(),
            query: format!(
                "site:{} intitle:\"osTicket\" | intitle:\"Zammad\" | intitle:\"GLPI\" | intitle:\"OTRS\"",
                clean_domain
            ),
            description: "Find self-hosted helpdesk / ITSM tools".to_string(),
            impact:
                "Public ticket portals can expose customer PII and attachments (support tickets \
                 often contain passwords)"
                    .to_string(),
        });

        // -------- Mail interfaces (webmail, list archives) --------
        dorks.push(GoogleDork {
            category: "Mail".to_string(),
            query: format!(
                "site:{} intitle:\"Roundcube\" | intitle:\"Zimbra Web Client\" | inurl:/owa/auth | intitle:\"MailPile\" | inurl:pipermail",
                clean_domain
            ),
            description: "Find webmail portals / mailing list archives".to_string(),
            impact:
                "Webmail portals are credential-stuffing targets; public list archives leak \
                 internal email addresses and discussions"
                    .to_string(),
        });

        // -------- Storage indexes (Apache dir listing / IIS / nginx autoindex) --------
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (\"Last modified\" | \"Parent Directory\") -html -php",
                clean_domain
            ),
            description: "Find open directory listings".to_string(),
            impact:
                "Directory listings expose hidden files (backups, keys, logs) not linked from \
                 the site"
                    .to_string(),
        });

        // -------- WordPress / Drupal sensitive endpoints --------
        dorks.push(GoogleDork {
            category: "CMS Sensitive".to_string(),
            query: format!(
                "site:{} inurl:/wp-json/wp/v2/users | inurl:/wp-content/uploads intitle:\"index of\" | inurl:/xmlrpc.php | inurl:CHANGELOG.txt",
                clean_domain
            ),
            description: "Find CMS user enumeration / upload dirs / debug files".to_string(),
            impact:
                "wp-json user enumeration confirms admin usernames; open uploads dirs expose \
                 PII documents"
                    .to_string(),
        });

        // -------- macOS/Windows/IDE artefacts left on webroot --------
        dorks.push(GoogleDork {
            category: "Artefact Files".to_string(),
            query: format!(
                "site:{} inurl:/.DS_Store | inurl:/Thumbs.db | inurl:/desktop.ini | inurl:/.idea/workspace.xml | inurl:/.vscode/settings.json",
                clean_domain
            ),
            description: "Find OS / IDE artefact files".to_string(),
            impact:
                ".DS_Store reveals directory contents (filenames); IDE files may embed SSH \
                 hosts, DB creds and API endpoints"
                    .to_string(),
        });

        // -------- security.txt / responsible disclosure metadata --------
        dorks.push(GoogleDork {
            category: "Security Contact".to_string(),
            query: format!(
                "site:{} inurl:/.well-known/security.txt | inurl:/security.txt",
                clean_domain
            ),
            description: "Locate program's own security.txt".to_string(),
            impact:
                "Confirms responsible disclosure contact — required intel before submitting \
                 findings"
                    .to_string(),
        });

        // -------- CI logs / GitHub Actions runs indexed accidentally --------
        dorks.push(GoogleDork {
            category: "CI Logs".to_string(),
            query: format!(
                "site:github.com \"{}\" (\"##[error]\" | \"AWS_ACCESS_KEY\" | \"npm ERR\" | \"Authentication failed\")",
                clean_domain
            ),
            description: "Find GitHub Actions logs leaking secrets or errors".to_string(),
            impact:
                "Public workflow logs sometimes echo secrets that GitHub failed to mask; also \
                 reveal internal build steps"
                    .to_string(),
        });

        // -------- Postman / Insomnia / SwaggerHub public workspaces --------
        dorks.push(GoogleDork {
            category: "API Workspaces".to_string(),
            query: format!(
                "site:postman.com \"{}\" | site:documenter.getpostman.com \"{}\" | site:app.swaggerhub.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Postman / SwaggerHub workspaces mentioning the domain"
                .to_string(),
            impact:
                "Public collections frequently ship with baked-in Bearer tokens and internal \
                 endpoint URLs"
                    .to_string(),
        });

        // -------- Package registry indexes for internal names --------
        dorks.push(GoogleDork {
            category: "Package Namespaces".to_string(),
            query: format!(
                "site:npmjs.com \"{}\" | site:pypi.org \"{}\" | site:rubygems.org \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find internal package names published to public registries".to_string(),
            impact:
                "Reveals internal namespaces (enables dependency-confusion attacks) and may \
                 expose source"
                    .to_string(),
        });

        // -------- Static site config / build artefacts (CRA / Next / Vite) --------
        dorks.push(GoogleDork {
            category: "Build Artefacts".to_string(),
            query: format!(
                "site:{} inurl:/asset-manifest.json | inurl:/manifest.json | inurl:/_next/data | inurl:.map filetype:map",
                clean_domain
            ),
            description: "Find build manifests / source maps".to_string(),
            impact:
                "Source maps let attackers reconstruct un-minified code (often containing hidden \
                 admin routes and tokens)"
                    .to_string(),
        });

        // -------- Log files with domain reference --------
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} ext:log intext:\"password\" | intext:\"secret\" | intext:\"token\" | intext:\"authorization: bearer\"",
                clean_domain
            ),
            description: "Find publicly indexed log files with credentials".to_string(),
            impact: "Log files sometimes echo raw Authorization headers or DB passwords"
                .to_string(),
        });

        // -------- WebFinger / .well-known enumeration --------
        dorks.push(GoogleDork {
            category: "Well-Known".to_string(),
            query: format!(
                "site:{} inurl:/.well-known/ (\"apple-app-site-association\" | \"assetlinks.json\" | \"nodeinfo\" | \"webfinger\" | \"host-meta\")",
                clean_domain
            ),
            description: "Enumerate .well-known metadata".to_string(),
            impact:
                "AASA / assetlinks reveal linked mobile apps and universal-link routes — expands \
                 attack surface"
                    .to_string(),
        });

        // -------- Exposed cronjobs / systemd unit dumps --------
        dorks.push(GoogleDork {
            category: "System Config".to_string(),
            query: format!(
                "site:{} (inurl:crontab | inurl:cron.d | ext:service intext:\"[Unit]\" | intext:\"ExecStart=\")",
                clean_domain
            ),
            description: "Find system cron / systemd unit files".to_string(),
            impact:
                "Crontabs / unit files reveal scheduled scripts and their arguments (often with \
                 embedded creds)"
                    .to_string(),
        });

        // -------- SSRF-oracle URLs (metadata, imds) --------
        dorks.push(GoogleDork {
            category: "SSRF Signals".to_string(),
            query: format!(
                "site:{} intext:\"169.254.169.254\" | intext:\"metadata.google.internal\" | intext:\"instance-identity/document\"",
                clean_domain
            ),
            description:
                "Find pages referencing cloud metadata endpoints (proxies, docs, snippets)"
                    .to_string(),
            impact:
                "Content mentioning IMDS often indicates SSRF fetchers or documentation that \
                 leaks internal architecture"
                    .to_string(),
        });

        // -------- LDAP / AD dumps --------
        dorks.push(GoogleDork {
            category: "Directory Dumps".to_string(),
            query: format!(
                "site:{} ext:ldif | intext:\"dn: cn=\" | intext:\"objectClass: person\"",
                clean_domain
            ),
            description: "Find LDAP / Active Directory exports".to_string(),
            impact: "LDIF exports expose entire user directory including hashed passwords"
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
