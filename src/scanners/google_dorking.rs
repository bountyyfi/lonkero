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

        // ── Exposed configuration / dotfiles ────────────────────────────────
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:.env OR inurl:.env.local OR inurl:.env.production OR inurl:.env.development) (intext:DB_PASSWORD OR intext:APP_KEY OR intext:SECRET_KEY OR intext:AWS_)",
                clean_domain
            ),
            description: "Find exposed .env files containing secrets".to_string(),
            impact: "Direct credential exposure - DB passwords, framework SECRET_KEYs, AWS keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php OR inurl:configuration.php OR inurl:settings.py OR inurl:config.yml OR inurl:application.properties) intext:password",
                clean_domain
            ),
            description: "Find exposed framework config files containing passwords".to_string(),
            impact: "WordPress/Joomla/Django/Spring credentials commit-leaks granting DB and admin access".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:.git/config OR inurl:.git/HEAD OR inurl:.svn/entries OR inurl:.hg/hgrc OR inurl:.bzr)",
                clean_domain
            ),
            description: "Find exposed VCS metadata directories".to_string(),
            impact: "Allows full source-code reconstruction via git-dumper / dvcs-ripper - typically a P1".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials OR inurl:.npmrc OR inurl:.pypirc OR inurl:.dockercfg OR inurl:docker-compose.yml OR inurl:kubeconfig)",
                clean_domain
            ),
            description: "Find exposed cloud / package-registry credential files".to_string(),
            impact: "Direct cloud / artifact-registry credential exposure".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (filetype:pem OR filetype:ppk OR filetype:key OR filetype:p12 OR filetype:pfx OR filetype:keystore OR filetype:jks)",
                clean_domain
            ),
            description: "Find exposed private-key / keystore files".to_string(),
            impact: "Private keys and Java/PKCS#12 keystores allow decryption and impersonation".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (filetype:sql OR filetype:dbf OR filetype:mdb OR filetype:bak OR filetype:dump) (intext:INSERT INTO OR intext:CREATE TABLE)",
                clean_domain
            ),
            description: "Find exposed database dumps and backups".to_string(),
            impact: "Full DB dumps frequently contain hashed/plaintext credentials and PII".to_string(),
        });

        // ── Backup / temp / editor artefacts ─────────────────────────────────
        dorks.push(GoogleDork {
            category: "Exposed Configuration".to_string(),
            query: format!(
                "site:{} (ext:bak OR ext:old OR ext:orig OR ext:save OR ext:backup OR ext:swp OR ext:swo OR ext:tmp OR ext:~)",
                clean_domain
            ),
            description: "Find leftover backup / editor swap files".to_string(),
            impact: "Backup copies of source frequently include the un-redacted credentials and pre-patch logic".to_string(),
        });

        // ── DevOps / CI exposure ─────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "DevOps Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.github/workflows OR inurl:.gitlab-ci.yml OR inurl:bitbucket-pipelines.yml OR inurl:Jenkinsfile OR inurl:.circleci/config.yml OR inurl:azure-pipelines.yml OR inurl:.drone.yml)",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline definitions".to_string(),
            impact: "Pipeline files reveal deploy targets, env vars, and frequently leak secret references".to_string(),
        });
        dorks.push(GoogleDork {
            category: "DevOps Exposure".to_string(),
            query: format!(
                "site:{} (inurl:Dockerfile OR inurl:Vagrantfile OR inurl:terraform.tfstate OR inurl:terraform.tfvars OR inurl:ansible OR inurl:playbook.yml)",
                clean_domain
            ),
            description: "Find exposed IaC / container build files".to_string(),
            impact: "Terraform state files contain plaintext secrets; Dockerfiles reveal base images and ARGs".to_string(),
        });

        // ── Exposed admin / management consoles ──────────────────────────────
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:phpmyadmin OR inurl:adminer.php OR inurl:pma OR intitle:\"phpMyAdmin\")",
                clean_domain
            ),
            description: "Find exposed phpMyAdmin / Adminer instances".to_string(),
            impact: "Direct DB management UI - regularly default-credentialed or version-vulnerable".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Jenkins\" inurl:/script OR intitle:\"Dashboard [Jenkins]\" OR inurl:/jenkins/login)",
                clean_domain
            ),
            description: "Find exposed Jenkins instances and Groovy script consoles".to_string(),
            impact: "Anonymous-readable Jenkins frequently exposes /script - direct RCE".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" OR inurl:/app/kibana OR intitle:\"Grafana\" inurl:/login OR intitle:\"Prometheus Time Series Collection\")",
                clean_domain
            ),
            description: "Find exposed monitoring dashboards (Kibana / Grafana / Prometheus)".to_string(),
            impact: "Frequently anonymous-readable, leaking metrics, logs, and infrastructure topology".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" OR intitle:\"Solr Admin\" OR intitle:\"Eureka\" OR intitle:\"Spring Boot Admin\" OR intitle:\"Consul by HashiCorp\")",
                clean_domain
            ),
            description: "Find exposed service-management consoles".to_string(),
            impact: "Reveal queue / search-index / service-registry contents and frequently allow writes".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env OR inurl:/actuator/heapdump OR inurl:/actuator/loggers OR inurl:/actuator/mappings OR inurl:/actuator/threaddump)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env leaks env vars; /heapdump leaks memory containing secrets; /loggers allows reconfig".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/manager/html OR inurl:/host-manager OR intitle:\"Tomcat\" inurl:/manager)",
                clean_domain
            ),
            description: "Find exposed Tomcat Manager".to_string(),
            impact: "Tomcat Manager with default creds (tomcat/tomcat, admin/admin) yields direct WAR-deploy RCE".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Consoles".to_string(),
            query: format!(
                "site:{} (inurl:/api/v1/namespaces OR inurl:/api/v1/pods OR intitle:\"Kubernetes Dashboard\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes API / Dashboard".to_string(),
            impact: "Anonymous /api/v1/* on Kubernetes API server is full cluster takeover".to_string(),
        });

        // ── API specs / docs / GraphQL ───────────────────────────────────────
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (filetype:json OR filetype:yaml OR filetype:yml) (intext:\"openapi\" OR intext:\"swagger:\\\"2.0\\\"\")",
                clean_domain
            ),
            description: "Find raw OpenAPI / Swagger specifications".to_string(),
            impact: "Full machine-readable spec of every endpoint - prime input for fuzzing".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:/graphql OR inurl:/graphiql OR inurl:/playground OR inurl:/altair OR inurl:/voyager) (intext:__schema OR intext:IntrospectionQuery)",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds with introspection".to_string(),
            impact: "Exposed introspection reveals every type, query, and mutation - and dev playgrounds run mutations live".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:postman.json OR inurl:postman_collection.json OR intext:\"info\\\":{{\\\"_postman_id\\\"\")",
                clean_domain
            ),
            description: "Find exposed Postman collections".to_string(),
            impact: "Postman collections frequently contain hardcoded auth headers and example PII".to_string(),
        });

        // ── Source-code / binary leakage ─────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Source Code Leakage".to_string(),
            query: format!(
                "site:{} (filetype:js intext:\"sourceMappingURL\" OR filetype:map ext:js.map OR filetype:map ext:css.map)",
                clean_domain
            ),
            description: "Find exposed JavaScript source maps".to_string(),
            impact: "Source maps reverse minified bundles back to original source, exposing logic and comments".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Source Code Leakage".to_string(),
            query: format!(
                "site:{} (inurl:WEB-INF OR inurl:WEB-INF/web.xml OR inurl:META-INF/MANIFEST.MF OR ext:war OR ext:jar OR ext:ear)",
                clean_domain
            ),
            description: "Find exposed Java WEB-INF / archives".to_string(),
            impact: "WEB-INF dumps spring config + DB credentials; WAR/JAR allows offline class extraction".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Source Code Leakage".to_string(),
            query: format!(
                "site:{} (filetype:rdp OR filetype:ovpn OR filetype:vpn OR filetype:remote OR filetype:dat intext:host)",
                clean_domain
            ),
            description: "Find exposed remote-access configuration files".to_string(),
            impact: "RDP / OpenVPN config files contain hostname + auth and grant pivot into internal networks".to_string(),
        });

        // ── Authentication / SSO discovery ───────────────────────────────────
        dorks.push(GoogleDork {
            category: "Authentication Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:.well-known/openid-configuration OR inurl:.well-known/oauth-authorization-server OR inurl:saml/metadata OR inurl:auth/realms)",
                clean_domain
            ),
            description: "Find OIDC / OAuth / SAML / Keycloak metadata".to_string(),
            impact: "Reveals authorization, token, JWKS endpoints + supported flows - input for SSO attacks".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Authentication Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:adfs/ls OR inurl:my.policy OR inurl:owa/auth OR inurl:rdweb OR inurl:vpn/index.html)",
                clean_domain
            ),
            description: "Find enterprise SSO / VPN portals (ADFS, F5 BIG-IP, Outlook Web, Citrix, RDWeb)".to_string(),
            impact: "Common pivots for credential-stuffing, MFA-bypass, and known-CVE chains (e.g. CVE-2022-1388, CVE-2023-3519)".to_string(),
        });

        // ── Storage / secret-laden services ──────────────────────────────────
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\" OR site:cdn.digitaloceanspaces.com \"{}\" OR site:wasabisys.com \"{}\" OR site:blackblaze.com \"{}\" OR site:r2.cloudflarestorage.com \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find files in alternate object-storage providers".to_string(),
            impact: "GCS / DO Spaces / Wasabi / Backblaze / R2 buckets are frequently misconfigured listable".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} (inurl:?list-type=2 OR intitle:\"Index of /\" intext:\"Last modified\" OR intext:\"<ListBucketResult\")",
                clean_domain
            ),
            description: "Find directory-listings and S3-style ListBucket responses".to_string(),
            impact: "Direct enumeration of every key on the server / bucket - bypass of obscurity-based access".to_string(),
        });

        // ── Source-control hosts ─────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:github.com OR site:gitlab.com OR site:bitbucket.org) \"{}\" (\"AKIA\" OR \"BEGIN PRIVATE KEY\" OR \"client_secret\" OR \"DB_PASSWORD\")",
                clean_domain
            ),
            description: "Find domain-mentioning code with credential indicators".to_string(),
            impact: "Public repos containing the domain plus credential-shaped strings - direct secret leakage".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:gist.github.com OR site:hastebin.com OR site:rentry.co OR site:paste.ee OR site:ghostbin.co OR site:dpaste.com) \"{}\"",
                clean_domain
            ),
            description: "Find domain mentions on additional paste sites".to_string(),
            impact: "Snippet sites hosting one-off configs / tokens / debug output".to_string(),
        });

        // ── Authentication tokens and secrets in Google index ────────────────
        dorks.push(GoogleDork {
            category: "Leaked Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" OR intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" OR intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\")",
                clean_domain
            ),
            description: "Find private keys indexed on the target domain".to_string(),
            impact: "Direct private-key recovery from search-engine cache".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Leaked Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN CERTIFICATE\" OR intext:\"-----BEGIN ENCRYPTED PRIVATE KEY-----\")",
                clean_domain
            ),
            description: "Find indexed certificates / encrypted keys".to_string(),
            impact: "Encrypted keys may be brute-forceable; certs reveal internal CN / SAN / hostnames".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Leaked Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"AKIA\" OR intext:\"ASIA\" OR intext:\"AIza\" OR intext:\"sk_live_\" OR intext:\"xoxb-\" OR intext:\"glpat-\")",
                clean_domain
            ),
            description: "Find vendor-prefixed token strings in indexed content".to_string(),
            impact: "Direct secret strings in the search-engine index - usually a P1".to_string(),
        });

        // ── Logs / debug / error pages ───────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:{} (ext:log OR filetype:log) (intext:password OR intext:exception OR intext:error OR intext:Authorization)",
                clean_domain
            ),
            description: "Find indexed log files containing passwords or auth headers".to_string(),
            impact: "Logs frequently contain plaintext credentials, session tokens, and stack-trace internals".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops, looks like something went wrong\" OR intext:\"Application Error\" OR intext:\"PHP Fatal error\" OR intext:\"NoMethodError\" OR intext:\"AttributeError\")",
                clean_domain
            ),
            description: "Find live framework error pages (Laravel/Heroku/PHP/Rails/Python)".to_string(),
            impact: "Stack traces leak file paths, framework versions, and frequently env vars".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php OR intext:\"PHP Version\" intext:\"System\" intext:\"Build Date\")",
                clean_domain
            ),
            description: "Find indexed phpinfo() pages".to_string(),
            impact: "Discloses full PHP/server config including loaded extensions and environment".to_string(),
        });

        // ── PII / breach signals ─────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "PII Parameters".to_string(),
            query: format!(
                "site:{} (filetype:csv OR filetype:xlsx OR filetype:xls) (intext:ssn OR intext:\"social security\" OR intext:\"date of birth\" OR intext:passport OR intext:credit card)",
                clean_domain
            ),
            description: "Find spreadsheets containing PII fields".to_string(),
            impact: "Indexed PII spreadsheets are directly reportable as data exposure (GDPR / CCPA)".to_string(),
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
