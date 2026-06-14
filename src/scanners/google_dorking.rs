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

        // ==================================================================
        // High-impact sensitive-disclosure dorks.
        //
        // Each query below is anchored to either (a) a vendor-specific path
        // or filename (.env, tfstate, kubeconfig, /actuator/env, ...) or
        // (b) a unique string that only appears inside the real artifact
        // (e.g. "BEGIN RSA PRIVATE KEY", "INSERT INTO"), so the result set
        // is dominated by genuine leaks rather than coincidental matches.
        // None of these are XSS / SQLi / payload mutations — they are
        // recon queries that surface already-public-by-mistake content.
        // ==================================================================

        // --- Configuration & secret files exposed on the web root ---
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:env (intext:\"DB_PASSWORD=\" | intext:\"AWS_SECRET_ACCESS_KEY=\" | intext:\"STRIPE_SECRET\" | intext:\"DATABASE_URL=postgres\")",
                clean_domain
            ),
            description: "Find leaked .env files containing live credentials".to_string(),
            impact: "Critical: .env files leak DB passwords, cloud keys and payment secrets verbatim".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars) (intext:\"terraform_version\" | intext:\"sensitive\")",
                clean_domain
            ),
            description: "Find Terraform state / tfvars files".to_string(),
            impact: "Critical: tfstate contains plaintext credentials for every provisioned resource".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".kube/config\" | inurl:\"kubeconfig\") intext:\"client-certificate-data\"",
                clean_domain
            ),
            description: "Find leaked kubeconfig files".to_string(),
            impact: "Critical: kubeconfig grants full cluster control including secrets and exec".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".npmrc\" intext:\"_authToken\" | inurl:\".pypirc\" intext:\"password\")",
                clean_domain
            ),
            description: "Find npm / PyPI publishing credentials".to_string(),
            impact: "Critical: registry tokens allow malicious package publishing — supply-chain takeover".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk) (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find PEM-armored private keys".to_string(),
            impact: "Critical: SSH / TLS / signing private keys enable host takeover and MITM".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose\" | inurl:\"compose.yaml\") (intext:\"POSTGRES_PASSWORD\" | intext:\"MYSQL_ROOT_PASSWORD\" | intext:\"MONGO_INITDB_ROOT_PASSWORD\")",
                clean_domain
            ),
            description: "Find docker-compose files with embedded passwords".to_string(),
            impact: "Critical: container env vars commonly hold DB roots and service tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} inurl:\"values.yaml\" (intext:\"password:\" | intext:\"apiKey:\" | intext:\"secretKey:\")",
                clean_domain
            ),
            description: "Find Helm chart values with embedded secrets".to_string(),
            impact: "High: Helm values.yaml frequently checked-in with production credentials".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"web.config\" | inurl:\"appsettings.json\") (intext:\"ConnectionString\" | intext:\"Password=\")",
                clean_domain
            ),
            description: "Find ASP.NET config files with connection strings".to_string(),
            impact: "Critical: connection strings expose DB hosts and credentials in plaintext".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} inurl:\"id_rsa\" -inurl:\"pub\"",
                clean_domain
            ),
            description: "Find leaked SSH private keys named id_rsa".to_string(),
            impact: "Critical: id_rsa keys grant direct SSH access to authorized hosts".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"credentials\" | inurl:\".aws/credentials\") intext:\"aws_secret_access_key\"",
                clean_domain
            ),
            description: "Find AWS CLI credentials files".to_string(),
            impact: "Critical: AWS credentials grant API access to S3, EC2, IAM and billing".to_string(),
        });

        // --- Database dumps & backups ---
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql (intext:\"INSERT INTO \\`users\\`\" | intext:\"CREATE TABLE\" | intext:\"DUMP COMPLETED\" | intext:\"-- MySQL dump\")",
                clean_domain
            ),
            description: "Find SQL dump files with table data".to_string(),
            impact: "Critical: SQL dumps expose entire user tables, password hashes and PII".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:dump | ext:dmp | ext:mdf | ext:dbf | ext:sqlite | ext:db)",
                clean_domain
            ),
            description: "Find raw database files".to_string(),
            impact: "Critical: raw DB files contain complete schema and row data".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql.gz | ext:sql.bz2 | ext:sql.zip | ext:tar.gz inurl:backup)",
                clean_domain
            ),
            description: "Find compressed database backups".to_string(),
            impact: "Critical: compressed dumps are routinely uploaded next to web roots and indexed".to_string(),
        });

        // --- Spring Boot / Java actuator surface ---
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/mappings\")",
                clean_domain
            ),
            description: "Find Spring Boot Actuator endpoints exposing env vars and heap".to_string(),
            impact: "Critical: /env leaks every config property including DB and cloud secrets; /heapdump leaks memory".to_string(),
        });

        // --- Web server status interfaces ---
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\"server-status\" intitle:\"Apache Status\" | inurl:\"server-info\" intitle:\"Server Information\")",
                clean_domain
            ),
            description: "Find Apache mod_status / mod_info pages".to_string(),
            impact: "High: server-status exposes live requests, full URLs and remote client IPs".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\"/nginx_status\" intext:\"Active connections:\" | inurl:\"/stub_status\")",
                clean_domain
            ),
            description: "Find nginx stub_status endpoint".to_string(),
            impact: "Medium: leaks request volume and active-connection metrics".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\"/manager/html\" intitle:\"Tomcat Web Application Manager\" | inurl:\"/host-manager/html\")",
                clean_domain
            ),
            description: "Find Tomcat manager applications".to_string(),
            impact: "Critical: Tomcat manager allows WAR deployment — direct RCE on default creds".to_string(),
        });

        // --- Internal dashboards & databases on the web ---
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:\"/login\" | intitle:\"Kibana\" | intitle:\"Prometheus Time Series\")",
                clean_domain
            ),
            description: "Find Grafana / Kibana / Prometheus dashboards".to_string(),
            impact: "High: observability stacks routinely run with default creds and embed DB credentials".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" inurl:\"index.php\" | intitle:\"Adminer\" inurl:\"adminer.php\")",
                clean_domain
            ),
            description: "Find phpMyAdmin / Adminer database UIs".to_string(),
            impact: "Critical: DB admin UIs are routine targets for credential stuffing".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | intitle:\"Apache Airflow\" inurl:\"/home\" | intitle:\"Jenkins\" inurl:\"/manage\")",
                clean_domain
            ),
            description: "Find RabbitMQ / Airflow / Jenkins management UIs".to_string(),
            impact: "High: queue & orchestration UIs allow message inspection and pipeline execution".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} inurl:\"/jenkins/script\" intitle:\"Script Console\"",
                clean_domain
            ),
            description: "Find Jenkins Groovy Script Console".to_string(),
            impact: "Critical: Script Console executes Groovy as the Jenkins user — instant RCE".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\":9200/_cat/indices\" | inurl:\":9200/_search\" | inurl:\":5601/app/kibana\")",
                clean_domain
            ),
            description: "Find Elasticsearch / Kibana on default ports".to_string(),
            impact: "High: unauthenticated Elasticsearch leaks indexed application data".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Admin Surface".to_string(),
            query: format!(
                "site:{} (inurl:\"/solr/#/\" intitle:\"Solr Admin\" | inurl:\"/nifi/\" intitle:\"NiFi\")",
                clean_domain
            ),
            description: "Find Solr / NiFi admin consoles".to_string(),
            impact: "High: Solr Velocity / NiFi REST APIs have a long history of unauth RCEs".to_string(),
        });

        // --- API / mobile attack surface discovery ---
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (ext:json intext:\"\\\"openapi\\\":\" | ext:yaml intext:\"openapi:\" | ext:json intext:\"\\\"swagger\\\":\")",
                clean_domain
            ),
            description: "Find raw OpenAPI / Swagger specs".to_string(),
            impact: "High: specs enumerate every endpoint, parameter and auth scheme".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/playground\") intitle:\"GraphQL\"",
                clean_domain
            ),
            description: "Find GraphQL playgrounds and explorers".to_string(),
            impact: "High: GraphQL playgrounds typically allow introspection — full schema disclosure".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Mobile App Linking".to_string(),
            query: format!(
                "site:{} (inurl:\"apple-app-site-association\" | inurl:\".well-known/assetlinks.json\")",
                clean_domain
            ),
            description: "Find iOS / Android app-linking manifests".to_string(),
            impact: "Medium: reveals bundle IDs and deeplink paths used by the mobile app — recon for API endpoints".to_string(),
        });

        // --- WordPress-specific high-value paths ---
        dorks.push(GoogleDork {
            category: "WordPress Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.php.save\" | inurl:\"wp-config.txt\")",
                clean_domain
            ),
            description: "Find wp-config backup files".to_string(),
            impact: "Critical: wp-config contains DB credentials and auth salts in plaintext".to_string(),
        });
        dorks.push(GoogleDork {
            category: "WordPress Exposure".to_string(),
            query: format!(
                "site:{} inurl:\"/wp-content/debug.log\"",
                clean_domain
            ),
            description: "Find WordPress debug logs".to_string(),
            impact: "High: debug logs include stack traces, query parameters and occasionally session cookies".to_string(),
        });

        // --- Public SaaS surfaces that mention the target ---
        dorks.push(GoogleDork {
            category: "Public SaaS Mentions".to_string(),
            query: format!(
                "(site:notion.so | site:notion.site) \"{}\"",
                clean_domain
            ),
            description: "Find public Notion pages referencing the domain".to_string(),
            impact: "High: employees regularly publish internal runbooks/onboarding pages publicly".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Public SaaS Mentions".to_string(),
            query: format!(
                "(site:gitbook.io | site:gitbook.com) \"{}\"",
                clean_domain
            ),
            description: "Find public GitBook documentation".to_string(),
            impact: "Medium: GitBook hosts API/integration docs that may reveal internal endpoints".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Public SaaS Mentions".to_string(),
            query: format!(
                "(site:documenter.getpostman.com | site:postman.com/collection | site:www.postman.com/workspace) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman collections / workspaces".to_string(),
            impact: "High: public Postman collections frequently include valid bearer tokens and API keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Public SaaS Mentions".to_string(),
            query: format!(
                "site:stackoverflow.com \"{}\" (\"api key\" | \"bearer\" | \"private key\" | \"connection string\" | \"password\")",
                clean_domain
            ),
            description: "Find Stack Overflow questions pasting target credentials".to_string(),
            impact: "High: developers paste live tokens into questions and forget to redact".to_string(),
        });

        // --- Cloud storage providers beyond the originals ---
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:r2.dev | site:r2.cloudflarestorage.com) \"{}\"",
                clean_domain
            ),
            description: "Find Cloudflare R2 public buckets".to_string(),
            impact: "High: R2 buckets exposed publicly mirror the S3 misconfiguration class".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:backblazeb2.com | site:b2cdn.com | site:wasabisys.com) \"{}\"",
                clean_domain
            ),
            description: "Find Backblaze B2 / Wasabi public objects".to_string(),
            impact: "High: alternative object stores are often forgotten in S3-focused audits".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:linodeobjects.com | site:objects.dream.io | site:nyc3.digitaloceanspaces.com | site:sfo3.digitaloceanspaces.com) \"{}\"",
                clean_domain
            ),
            description: "Find regional Linode / DigitalOcean / DreamHost object stores".to_string(),
            impact: "High: regional providers often skipped by inventory tooling".to_string(),
        });

        // --- Preview / staging hosts (a common forgotten surface) ---
        dorks.push(GoogleDork {
            category: "Preview & Staging".to_string(),
            query: format!(
                "(site:vercel.app | site:netlify.app | site:pages.dev | site:github.io | site:surge.sh) \"{}\"",
                clean_domain
            ),
            description: "Find preview deployments referencing the domain".to_string(),
            impact: "High: preview URLs commonly run with debug mode, production data and weak auth".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Preview & Staging".to_string(),
            query: format!(
                "(site:ngrok.io | site:ngrok-free.app | site:loca.lt | site:trycloudflare.com) \"{}\"",
                clean_domain
            ),
            description: "Find tunnels exposing dev machines".to_string(),
            impact: "High: ad-hoc tunnels expose unauthenticated local dev servers to the internet".to_string(),
        });

        // --- Auth provider hosted UIs (great for OAuth recon) ---
        dorks.push(GoogleDork {
            category: "Identity Provider".to_string(),
            query: format!(
                "(site:auth0.com | site:okta.com | site:auth.amazoncognito.com | site:onelogin.com) \"{}\"",
                clean_domain
            ),
            description: "Find tenant pages on common identity providers".to_string(),
            impact: "Medium: identifies the IdP and tenant ID — entry point for OAuth/OIDC attacks".to_string(),
        });

        // --- Crash / observability providers ---
        dorks.push(GoogleDork {
            category: "Observability Leaks".to_string(),
            query: format!(
                "(site:sentry.io | site:rollbar.com | site:bugsnag.com | site:honeybadger.io) \"{}\"",
                clean_domain
            ),
            description: "Find public crash-reporter projects".to_string(),
            impact: "High: public Sentry organisations leak event metadata including auth headers".to_string(),
        });

        // --- Customer-support ticket SaaS ---
        dorks.push(GoogleDork {
            category: "Support Ticket Leaks".to_string(),
            query: format!(
                "(site:zendesk.com | site:freshdesk.com | site:helpscout.com | site:intercom.help) \"{}\"",
                clean_domain
            ),
            description: "Find publicly indexed support tickets / KB articles".to_string(),
            impact: "Medium: support agents frequently paste auth headers, account IDs and internal URLs into tickets".to_string(),
        });

        // --- Forms / surveys (PII collection points) ---
        dorks.push(GoogleDork {
            category: "PII Collection".to_string(),
            query: format!(
                "(site:docs.google.com/forms | site:typeform.com | site:surveymonkey.com | site:jotform.com | site:cognitoforms.com) \"{}\"",
                clean_domain
            ),
            description: "Find public forms / surveys collecting PII for the target".to_string(),
            impact: "Medium: open forms often log responses to public sheets — direct PII disclosure".to_string(),
        });

        // --- Code-hosting platforms beyond GitHub / GitLab ---
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:bitbucket.org | site:gitee.com | site:codeberg.org | site:sourcegraph.com) \"{}\"",
                clean_domain
            ),
            description: "Find code repositories on alternative hosts".to_string(),
            impact: "High: BitBucket / Gitee mirrors are routinely forgotten when revoking compromised secrets".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" (\"api_key\" | \"secret\" | \"password\" | \"token\")",
                clean_domain
            ),
            description: "Find GitHub gists pasting target secrets".to_string(),
            impact: "Critical: gists are public by default and a common accidental-leak vector".to_string(),
        });

        // --- WebDAV / file-share endpoints ---
        dorks.push(GoogleDork {
            category: "File Share Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/webdav/\" | inurl:\"/dav/\" | intitle:\"Index of /\" \"Parent Directory\")",
                clean_domain
            ),
            description: "Find WebDAV roots and open directory indexes".to_string(),
            impact: "High: open directory listings frequently expose backups, dumps and uploaded user files".to_string(),
        });

        // --- robots.txt revealing private paths ---
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} inurl:\"robots.txt\" (\"Disallow: /admin\" | \"Disallow: /api\" | \"Disallow: /private\")",
                clean_domain
            ),
            description: "Find robots.txt advertising private paths".to_string(),
            impact: "Low: robots.txt is a free roadmap to administratively-sensitive URLs".to_string(),
        });

        // --- Wayback Machine for vanished sensitive content ---
        dorks.push(GoogleDork {
            category: "Historical Exposure".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (\"api_key\" | \"BEGIN PRIVATE KEY\" | \"connectionString\")",
                clean_domain
            ),
            description: "Find archived snapshots that leaked credentials".to_string(),
            impact: "High: rotating a credential does not purge it from the Wayback Machine".to_string(),
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
