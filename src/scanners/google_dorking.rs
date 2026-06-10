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
        // High-impact sensitive-data recon dorks.
        //
        // Each dork below is anchored on a vendor- or filename-specific
        // string (e.g. `DB_PASSWORD`, `.git/config`, `kind: Secret`) so the
        // operator can take the query straight to Google with a low chance
        // of having to wade through unrelated matches.
        // ----------------------------------------------------------------

        // Exposed .env files (Laravel / Symfony / Node / Rails)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.dev) intext:DB_PASSWORD | intext:APP_KEY | intext:AWS_SECRET",
                clean_domain
            ),
            description: "Find indexed .env files containing application secrets".to_string(),
            impact: "Full database credentials, app encryption keys, and cloud secrets — immediate full compromise.".to_string(),
        });

        // Exposed .git directory
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\")",
                clean_domain
            ),
            description: "Find publicly browsable .git directories".to_string(),
            impact: "Full source-code dump via git tree reconstruction; often includes historic secrets.".to_string(),
        });

        // Exposed wp-config backups
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.txt | inurl:wp-config.old | inurl:wp-config.php~ | inurl:wp-config.php.swp)",
                clean_domain
            ),
            description: "Find WordPress configuration backups served as text".to_string(),
            impact: "Direct disclosure of database credentials, AUTH_KEY / NONCE_KEY secrets, and salts.".to_string(),
        });

        // Database dumps
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:db | ext:sqlite | ext:dbf | ext:mdb) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\")",
                clean_domain
            ),
            description: "Find exposed database dumps containing raw INSERT/CREATE statements".to_string(),
            impact: "Whole-database data exfiltration including user records, hashes, and PII.".to_string(),
        });

        // Heap dumps / core dumps (JVM, Node, native)
        dorks.push(GoogleDork {
            category: "Memory Dumps".to_string(),
            query: format!(
                "site:{} (ext:hprof | ext:dmp | ext:dump | ext:core | inurl:heapdump | inurl:\"/actuator/heapdump\")",
                clean_domain
            ),
            description: "Find exposed JVM heap dumps and process core dumps".to_string(),
            impact: "Heap dumps contain in-memory secrets: JWT signing keys, DB passwords, session tokens.".to_string(),
        });

        // Spring Boot Actuator (very high impact when exposed)
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/configprops\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator management endpoints".to_string(),
            impact: "/env leaks env-var secrets; /heapdump enables full memory exfiltration; /mappings enumerates internal routes.".to_string(),
        });

        // Kubernetes / Helm / kubeconfig
        dorks.push(GoogleDork {
            category: "Kubernetes Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".kube/config\" | inurl:kubeconfig | (inurl:values.yaml intext:password) | (intext:\"kind: Secret\" intext:\"data:\"))",
                clean_domain
            ),
            description: "Find kubeconfig files, Helm values with passwords, and serialized Kubernetes Secrets".to_string(),
            impact: "Cluster-admin credentials, base64-encoded secrets, and full control-plane access.".to_string(),
        });

        // Terraform state files (contain plaintext secrets)
        dorks.push(GoogleDork {
            category: "Infrastructure as Code".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfstate.backup | ext:tfvars)",
                clean_domain
            ),
            description: "Find exposed Terraform state and variable files".to_string(),
            impact: "Plaintext provider credentials, DB passwords, and inventory of the entire cloud estate.".to_string(),
        });

        // CI / pipeline configuration with embedded secrets
        dorks.push(GoogleDork {
            category: "CI/CD Configuration".to_string(),
            query: format!(
                "site:{} (inurl:.gitlab-ci.yml | inurl:.travis.yml | inurl:.circleci/config.yml | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:Jenkinsfile)",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline definitions".to_string(),
            impact: "Reveals deployment topology, secret names, and occasionally inline tokens.".to_string(),
        });

        // Open directory listings (the original sensitive-finder)
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (intext:\"Parent Directory\" | intext:\"Last modified\")",
                clean_domain
            ),
            description: "Find Apache/nginx autoindex listings".to_string(),
            impact: "Browsable filesystem exposes backups, log files, and source archives.".to_string(),
        });

        // Apache/nginx server-status (mod_status)
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:server-status intitle:\"Apache Status\" | inurl:server-info intitle:\"Apache Server Information\" | inurl:nginx_status)",
                clean_domain
            ),
            description: "Find exposed mod_status / nginx stub_status pages".to_string(),
            impact: "Reveals every request URL processed by the server (incl. session tokens in query strings).".to_string(),
        });

        // phpinfo() pages
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | inurl:test.php intext:\"PHP Version\") intext:\"PHP Logo\"",
                clean_domain
            ),
            description: "Find exposed phpinfo() output".to_string(),
            impact: "Discloses full server filesystem layout, env vars, loaded extensions, INI paths — primary recon for chained RCE.".to_string(),
        });

        // Kibana / Elasticsearch console
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" inurl:app/kibana | inurl:_cat/indices | inurl:_search?q | intitle:\"Elasticsearch\" inurl:_cluster)",
                clean_domain
            ),
            description: "Find exposed Kibana dashboards and Elasticsearch APIs".to_string(),
            impact: "Direct query access to log/event indices that frequently contain PII and bearer tokens.".to_string(),
        });

        // Grafana login pages
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:login | intitle:\"Grafana\" inurl:/d/)",
                clean_domain
            ),
            description: "Find exposed Grafana instances".to_string(),
            impact: "Default `admin:admin` historically common; dashboards reveal architecture and metrics endpoints.".to_string(),
        });

        // Prometheus / Alertmanager
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series Collection and Processing Server\" | inurl:/graph?g0.expr | intitle:\"Alertmanager\")",
                clean_domain
            ),
            description: "Find exposed Prometheus and Alertmanager UIs".to_string(),
            impact: "Unauthenticated query of internal metrics + ability to silence production alerts.".to_string(),
        });

        // Kubernetes Dashboard
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:\"/api/v1/namespaces/kubernetes-dashboard\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes Dashboard installations".to_string(),
            impact: "Anonymous-bound dashboards historically allow full cluster-admin pod exec.".to_string(),
        });

        // Mongo Express, Redis Commander, pgAdmin, phpMyAdmin
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Mongo Express\" | intitle:\"Redis Commander\" | intitle:\"phpMyAdmin\" inurl:index.php | intitle:\"pgAdmin\" inurl:login)",
                clean_domain
            ),
            description: "Find exposed database admin web UIs".to_string(),
            impact: "Default credentials and weak auth on these tools = full database read/write.".to_string(),
        });

        // RabbitMQ / Kafka / Hadoop UI
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | intitle:\"Kafka Manager\" | intitle:\"Hadoop\" inurl:cluster | intitle:\"YARN ResourceManager\")",
                clean_domain
            ),
            description: "Find exposed message-broker and big-data cluster UIs".to_string(),
            impact: "Queue/topic enumeration, message peeking, and on Hadoop/YARN: pre-auth RCE via job submission.".to_string(),
        });

        // Jenkins (script console + build history)
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/script intitle:\"Script Console\" | inurl:/manage/script | intitle:\"Dashboard [Jenkins]\")",
                clean_domain
            ),
            description: "Find exposed Jenkins masters and Groovy script consoles".to_string(),
            impact: "Script Console = pre-auth Groovy RCE when anonymous read/admin is set.".to_string(),
        });

        // Spring Cloud / Eureka / Consul
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Eureka\" inurl:apps | inurl:/v1/agent/checks intext:\"Consul\" | inurl:/ui/dc1)",
                clean_domain
            ),
            description: "Find exposed Eureka registries and Consul UIs".to_string(),
            impact: "Internal service inventory + ability to manipulate discovery to hijack traffic.".to_string(),
        });

        // Hardcoded webhooks indexed in public pages
        dorks.push(GoogleDork {
            category: "Hardcoded Webhooks".to_string(),
            query: format!(
                "site:{} (intext:\"hooks.slack.com/services/\" | intext:\"discord.com/api/webhooks/\" | intext:\"discordapp.com/api/webhooks/\")",
                clean_domain
            ),
            description: "Find Slack/Discord webhook URLs in indexed pages".to_string(),
            impact: "Anyone can post arbitrary messages into internal channels — phishing pivot and reputation damage.".to_string(),
        });

        // Hardcoded high-value tokens / API keys
        dorks.push(GoogleDork {
            category: "Hardcoded Credentials".to_string(),
            query: format!(
                "site:{} (intext:\"sk_live_\" | intext:\"AKIA\" intext:\"SECRET\" | intext:\"AIza\" intext:\"key=\" | intext:\"ghp_\" | intext:\"glpat-\")",
                clean_domain
            ),
            description: "Find indexed pages containing live Stripe / AWS / Google / GitHub / GitLab tokens".to_string(),
            impact: "Each prefix is vendor-issued and uniquely identifies a live credential — direct take-over.".to_string(),
        });

        // JWT leaking through HTML / JS bundles
        dorks.push(GoogleDork {
            category: "Hardcoded Credentials".to_string(),
            query: format!(
                "site:{} intext:\"eyJhbGciOi\"",
                clean_domain
            ),
            description: "Find JWT tokens embedded in indexed HTML or JS".to_string(),
            impact: "JWTs often have long expiries; static service-account tokens grant ongoing API access.".to_string(),
        });

        // Cloud metadata reflected through SSRF-prone proxies
        dorks.push(GoogleDork {
            category: "Cloud Metadata Leakage".to_string(),
            query: format!(
                "site:{} (intext:\"ami-id\" intext:\"instance-id\" | intext:\"iam/security-credentials\" | intext:\"metadata.google.internal\")",
                clean_domain
            ),
            description: "Find cached responses that echo cloud instance metadata".to_string(),
            impact: "Indicates an SSRF-to-IMDS path that may already have leaked role credentials.".to_string(),
        });

        // Generic backup / temp file extensions
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:old | ext:backup | ext:save | ext:swp | ext:swo | ext:orig | ext:tmp | ext:~)",
                clean_domain
            ),
            description: "Find files served with backup/editor swap extensions".to_string(),
            impact: "Editor swaps and renamed backups frequently expose pre-deploy source with debug code and credentials.".to_string(),
        });

        // VS Code / JetBrains IDE config that leaks remotes, paths, debug ports
        dorks.push(GoogleDork {
            category: "IDE Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".vscode/settings.json\" | inurl:\".vscode/sftp.json\" | inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources.xml\")",
                clean_domain
            ),
            description: "Find exposed editor configuration files".to_string(),
            impact: "sftp.json contains deploy passwords; dataSources.xml contains DB connection strings.".to_string(),
        });

        // Composer / NPM / Pipfile lock disclosure (precise SCA-aware exploits)
        dorks.push(GoogleDork {
            category: "Dependency Files".to_string(),
            query: format!(
                "site:{} (inurl:composer.lock | inurl:package-lock.json | inurl:yarn.lock | inurl:Pipfile.lock | inurl:Gemfile.lock | inurl:go.sum)",
                clean_domain
            ),
            description: "Find dependency lock files served from web root".to_string(),
            impact: "Exact version manifest enables targeted CVE exploitation against known-vulnerable transitive deps.".to_string(),
        });

        // Mailing-list and code-review leaks of internal email/credentials
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:lists.openwall.net | site:seclists.org | site:marc.info) \"{}\"",
                clean_domain
            ),
            description: "Find domain references in public security mailing lists".to_string(),
            impact: "Past disclosures may reveal unpatched bugs, internal contacts, and architectural details.".to_string(),
        });

        // GitHub code-search variants (more specific than generic site:github.com)
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com \"{}\" (DB_PASSWORD | SECRET_KEY | API_KEY | private_key | password)",
                clean_domain
            ),
            description: "Find GitHub commits/files referencing the domain alongside secret-shaped tokens".to_string(),
            impact: "Catches contractors / interns committing creds tied to the target into public repos.".to_string(),
        });

        // SOAP/WSDL legacy interfaces
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (ext:wsdl | inurl:?wsdl | filetype:wsdl)",
                clean_domain
            ),
            description: "Find exposed SOAP/WSDL service definitions".to_string(),
            impact: "Full enumeration of legacy SOAP methods, often unauthenticated and XXE/XPath-injection prone.".to_string(),
        });

        // Atlassian Crowd / Confluence / Jira indexed admin/anonymous pages
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/wiki/people\" | inurl:\"/secure/Dashboard.jspa\" | inurl:\"/crowd/console\" | inurl:\"/plugins/servlet/oauth/users\")",
                clean_domain
            ),
            description: "Find anonymously accessible Atlassian admin/people pages".to_string(),
            impact: "User-directory enumeration feeds password-spray and reveals internal organisational structure.".to_string(),
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
