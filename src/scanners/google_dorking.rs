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
        // High-impact recon dorks (deterministic, narrow patterns)
        // Each query below is anchored by either a unique filename, a
        // product-specific page title, or a vendor-prefixed token so a
        // hit is almost always a real exposure rather than incidental
        // mention of the keyword.
        // ============================================================

        // .env file contents indexed in Google
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} ext:env \"DB_PASSWORD\" | \"APP_KEY\" | \"AWS_SECRET\" | \"SECRET_KEY\"",
                clean_domain
            ),
            description: "Find indexed .env files containing common secret variable names"
                .to_string(),
            impact: "Direct application credential exposure (DB, app key, cloud secrets)"
                .to_string(),
        });

        // Laravel .env signatures
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} intext:\"APP_KEY=base64:\" | intext:\"DB_CONNECTION=\" | intext:\"MAIL_USERNAME=\"",
                clean_domain
            ),
            description: "Find Laravel .env contents (APP_KEY/DB_CONNECTION)".to_string(),
            impact: "Laravel APP_KEY allows session/cookie forgery and full takeover".to_string(),
        });

        // Django settings.py exposure
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} intext:\"SECRET_KEY = \" intext:\"DJANGO_SETTINGS\" | intext:\"DATABASES = {{\"",
                clean_domain
            ),
            description: "Find indexed Django settings.py with SECRET_KEY".to_string(),
            impact: "Django SECRET_KEY allows session forgery and cryptographic compromise"
                .to_string(),
        });

        // wp-config backups (very high impact for WordPress)
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} inurl:wp-config (ext:bak | ext:old | ext:txt | ext:save | ext:swp | ext:orig | ext:php~)",
                clean_domain
            ),
            description: "Find leaked wp-config.php backup variants".to_string(),
            impact: "Full WordPress database credentials and auth keys".to_string(),
        });

        // .git index / fsmonitor exposure
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\")",
                clean_domain
            ),
            description: "Find exposed .git directory metadata".to_string(),
            impact: "Allows reconstruction of source tree via git-dumper".to_string(),
        });

        // .svn / .hg / CVS exposure
        dorks.push(GoogleDork {
            category: "Exposed Config Files".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/store\" | inurl:\"CVS/Entries\")",
                clean_domain
            ),
            description: "Find exposed SCM metadata other than git".to_string(),
            impact: "Source code disclosure via legacy VCS metadata".to_string(),
        });

        // Database dumps
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:dmp | ext:mdb | ext:sqlite | ext:db) intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\"",
                clean_domain
            ),
            description: "Find exposed SQL dump / database files".to_string(),
            impact: "Direct PII / credential disclosure from production data".to_string(),
        });

        // Spring Boot Actuator (Spring Boot 1 + 2/3 paths)
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/mappings | inurl:/actuator/health | inurl:/actuator/beans | inurl:/env | inurl:/heapdump)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env leaks credentials; /heapdump leaks live memory incl. tokens".to_string(),
        });

        // Prometheus / metrics endpoints
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/metrics intext:\"# HELP\" | inurl:/prometheus | inurl:/server-status | inurl:/server-info | inurl:/_status)",
                clean_domain
            ),
            description: "Find Prometheus-format metrics and Apache mod_status".to_string(),
            impact: "Reveals internal hosts, request URIs, and process state".to_string(),
        });

        // Kubernetes / container orchestration consoles
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:\"/api/v1/namespaces\" | inurl:\"/healthz\" intext:\"kube\" | intitle:\"Rancher\" | intitle:\"Portainer\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Rancher / Portainer consoles".to_string(),
            impact: "Cluster takeover via unauthenticated dashboard".to_string(),
        });

        // Jenkins exposure
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/script intext:\"Groovy\" | inurl:/jenkins/login | inurl:/manage)",
                clean_domain
            ),
            description: "Find exposed Jenkins instances and script console".to_string(),
            impact: "/script console is direct RCE on the CI host".to_string(),
        });

        // GitLab / CI exposure
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Sign in · GitLab\" | inurl:/-/profile/personal_access_tokens | intitle:\"Gitea\" | intitle:\"Forgejo\" | intitle:\"Sign in to Gogs\")",
                clean_domain
            ),
            description: "Find self-hosted Git platforms".to_string(),
            impact: "Often allow self-registration; private repos may be accessible".to_string(),
        });

        // Grafana / Kibana / Elasticsearch
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:/login | inurl:/app/kibana | inurl:/_cat/indices | inurl:/_cluster/health | intitle:\"Kibana\")",
                clean_domain
            ),
            description: "Find Grafana login pages and Elasticsearch/Kibana endpoints".to_string(),
            impact: "Often default creds (admin/admin); ES indices may leak data".to_string(),
        });

        // RabbitMQ / Kafka UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | inurl:/#/queues | intitle:\"Kafka UI\" | intitle:\"AKHQ\" | intitle:\"Conduktor\")",
                clean_domain
            ),
            description: "Find exposed broker management UIs".to_string(),
            impact: "Message queue contents may include PII, auth tokens, business events"
                .to_string(),
        });

        // Vault / Consul / Nomad UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"Vault\" inurl:/ui | intitle:\"Consul\" inurl:/ui | intitle:\"Nomad\" inurl:/ui | inurl:/v1/sys/health)",
                clean_domain
            ),
            description: "Find HashiCorp Vault/Consul/Nomad UIs".to_string(),
            impact: "Sealed Vaults still leak metadata; unsealed = full secret store".to_string(),
        });

        // phpMyAdmin / Adminer / pgAdmin
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" inurl:/index.php | intitle:\"Adminer\" inurl:/adminer | inurl:/phpmyadmin | inurl:/pgadmin4)",
                clean_domain
            ),
            description: "Find exposed DB admin UIs".to_string(),
            impact: "Brute-forceable login or known CVEs lead to DB access".to_string(),
        });

        // MinIO / Ceph / object-storage UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Console\" | intitle:\"MinIO Browser\" | inurl:/minio/login | intitle:\"Ceph Dashboard\")",
                clean_domain
            ),
            description: "Find self-hosted object storage consoles".to_string(),
            impact: "Default credentials (minioadmin/minioadmin) common in dev/staging"
                .to_string(),
        });

        // CI/CD secrets in GitHub Actions logs / artifacts
        dorks.push(GoogleDork {
            category: "Exposed Admin Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/runs intext:\"::add-mask::\" | inurl:/actions/runs | inurl:.github/workflows ext:yml)",
                clean_domain
            ),
            description: "Find exposed CI workflow logs and self-hosted workflow files"
                .to_string(),
            impact: "Workflow files reveal CI secrets-loading patterns; logs may unmask"
                .to_string(),
        });

        // GraphQL endpoints with introspection enabled
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (intitle:\"GraphQL Playground\" | intitle:\"Apollo Sandbox\" | intitle:\"GraphiQL\" | inurl:/graphql intext:\"__schema\")",
                clean_domain
            ),
            description: "Find GraphQL IDEs in production".to_string(),
            impact: "Introspection reveals full schema; often paired with broken authz"
                .to_string(),
        });

        // Backups and archives
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z) intext:\"backup\" | intext:\"dump\" | intext:\"export\"",
                clean_domain
            ),
            description: "Find indexed backup archives".to_string(),
            impact: "Backups commonly contain full source + DB + secrets".to_string(),
        });

        // Editor swap / IDE workspace leaks
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources\" | inurl:\".vscode/settings.json\" | inurl:\".vscode/launch.json\" | inurl:\".DS_Store\")",
                clean_domain
            ),
            description: "Find leaked IDE/editor metadata".to_string(),
            impact: "Reveals internal paths, DB connection strings, debug configurations"
                .to_string(),
        });

        // Docker / k8s manifests
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose ext:yml | inurl:Dockerfile | ext:yaml intext:\"apiVersion: v1\" intext:\"kind: Secret\" | inurl:values.yaml intext:\"password\")",
                clean_domain
            ),
            description: "Find exposed Docker/Kubernetes manifests".to_string(),
            impact: "K8s Secret manifests contain base64-encoded credentials".to_string(),
        });

        // CI configs with hardcoded secrets
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.gitlab-ci.yml | inurl:.travis.yml | inurl:.circleci/config.yml | inurl:Jenkinsfile | inurl:bitbucket-pipelines.yml) intext:\"token\" | intext:\"secret\" | intext:\"password\"",
                clean_domain
            ),
            description: "Find CI config files with embedded secrets".to_string(),
            impact: "Hardcoded tokens grant pipeline-level access to deploys".to_string(),
        });

        // SAML / OAuth metadata
        dorks.push(GoogleDork {
            category: "Auth Surface".to_string(),
            query: format!(
                "site:{} (inurl:/saml/metadata | inurl:FederationMetadata.xml | inurl:/.well-known/openid-configuration | inurl:/oauth2/authorize | inurl:/connect/authorize)",
                clean_domain
            ),
            description: "Find SAML/OIDC endpoints and metadata".to_string(),
            impact: "Discloses IdP trust, signing keys; useful for SSO attack surface mapping"
                .to_string(),
        });

        // Open password reset / token in URL (search engine cached)
        dorks.push(GoogleDork {
            category: "Auth Surface".to_string(),
            query: format!(
                "site:{} (inurl:reset_password_token= | inurl:reset-password?token= | inurl:?confirmation_token= | inurl:?invitation_token= | inurl:?api_key= | inurl:?access_token=)",
                clean_domain
            ),
            description: "Find leaked auth tokens in cached URLs".to_string(),
            impact: "Tokens in URLs are logged in referrer headers, browser history, search indexes"
                .to_string(),
        });

        // Postman / Insomnia public collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:postman-echo.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman collections referencing the target".to_string(),
            impact: "Collections frequently contain Bearer tokens and undocumented endpoints"
                .to_string(),
        });

        // Internal wikis / docs published by accident
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:notion.so | site:notion.site | site:confluence.atlassian.net | site:atlassian.net/wiki | site:gitbook.io | site:readme.io) \"{}\"",
                clean_domain
            ),
            description: "Find target references on public wiki/docs platforms".to_string(),
            impact: "Internal runbooks, onboarding docs, and architecture diagrams".to_string(),
        });

        // Stack Overflow / Reddit / forum leaks
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:stackexchange.com | site:reddit.com | site:dev.to) \"{}\" (\"api key\" | \"password\" | \"token\" | \"private\")",
                clean_domain
            ),
            description: "Find target mentions on Q&A/forums alongside credential keywords"
                .to_string(),
            impact: "Devs often paste real keys into questions; quickly redacted but cached"
                .to_string(),
        });

        // Replit / CodeSandbox / StackBlitz / Glitch
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:replit.com | site:codesandbox.io | site:stackblitz.com | site:glitch.com | site:repl.it) \"{}\"",
                clean_domain
            ),
            description: "Find target references in public IDE/sandbox projects".to_string(),
            impact: "Sandbox projects commonly hardcode API keys for quick demos".to_string(),
        });

        // Wayback Machine archived secrets
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (\"api_key\" | \"apikey\" | \"access_token\" | \"client_secret\" | \"-----BEGIN\")",
                clean_domain
            ),
            description: "Find archived snapshots that may still contain redacted secrets"
                .to_string(),
            impact: "Old snapshots often expose secrets that have not been rotated".to_string(),
        });

        // Pastes on alternative paste sites
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:ghostbin.com | site:dpaste.com | site:dpaste.org | site:hastebin.com | site:rentry.co | site:controlc.com | site:gist.github.com | site:gist.githubusercontent.com) \"{}\"",
                clean_domain
            ),
            description: "Find leaked snippets on paste services".to_string(),
            impact: "Pastes used to share log excerpts often contain secrets and PII".to_string(),
        });

        // Open AWS / GCP / Azure default container indexes
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com | site:storage.cloud.google.com | site:s3.us-east-1.amazonaws.com | site:s3.eu-west-1.amazonaws.com | site:s3.eu-central-1.amazonaws.com | site:.r2.dev | site:storage.yandexcloud.net) \"{}\"",
                clean_domain
            ),
            description: "Find target buckets across major and regional cloud providers"
                .to_string(),
            impact: "Public-listable buckets expose backups, PII, archived production data"
                .to_string(),
        });

        // ListBucketResult XML signature
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} intext:\"<ListBucketResult\" | intext:\"<Contents>\" intext:\"<Key>\"",
                clean_domain
            ),
            description: "Find S3 / S3-compatible bucket directory listings".to_string(),
            impact: "Confirms a public listable bucket and enumerates its contents".to_string(),
        });

        // Open directory listings
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (intext:\".env\" | intext:\".sql\" | intext:\".bak\" | intext:\"backup\" | intext:\".pem\" | intext:\".key\")",
                clean_domain
            ),
            description: "Find Apache/Nginx open directory listings with sensitive files"
                .to_string(),
            impact: "Direct download of secrets, backups, private keys".to_string(),
        });

        // SECURITY.txt drafts / disclosure pages
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/security.txt | inurl:/security.txt | inurl:/responsible-disclosure | inurl:/vulnerability-disclosure)",
                clean_domain
            ),
            description: "Find disclosure policies hosted by the target".to_string(),
            impact: "Confirms scope, contact, and bounty status for legal reporting".to_string(),
        });

        // Robots.txt + Sitemap discovery
        dorks.push(GoogleDork {
            category: "Reconnaissance".to_string(),
            query: format!(
                "site:{} (inurl:/robots.txt intext:\"Disallow:\" | inurl:/sitemap.xml | inurl:/sitemap_index.xml | inurl:/humans.txt)",
                clean_domain
            ),
            description: "Find robots.txt and sitemap entries".to_string(),
            impact: "Disallow entries advertise paths the operator considers sensitive"
                .to_string(),
        });

        // Public Jira / Bitbucket Cloud projects
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "(site:atlassian.net/jira | site:atlassian.net/browse | site:bitbucket.org) \"{}\"",
                clean_domain
            ),
            description: "Find publicly accessible Jira issues / Bitbucket repos".to_string(),
            impact: "Issue trackers leak vulnerability descriptions, PRs leak in-flight fixes"
                .to_string(),
        });

        // Public Slack / Discord / Telegram archives
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:t.me | site:slackarchive.io | site:discord.com/invite | site:linen.dev) \"{}\"",
                clean_domain
            ),
            description: "Find target mentions in public chat archives / invite links"
                .to_string(),
            impact: "Open chat communities often contain internal screenshots and tokens"
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
