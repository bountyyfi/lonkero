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
        // Extended high-impact sensitive-data dorks
        // Each dork below targets exposures with concrete, exploitable
        // impact and low false-positive rates for triage.
        // ============================================================

        // Environment files exposed on the domain (very high signal)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:env | ext:envrc | filetype:env) (intext:DB_PASSWORD | intext:AWS_SECRET | intext:API_KEY | intext:SECRET_KEY | intext:JWT_SECRET)",
                clean_domain
            ),
            description: "Exposed .env files containing production secrets".to_string(),
            impact: "Direct disclosure of database, cloud, and API credentials - immediate rotation required".to_string(),
        });

        // Publicly indexed Kubernetes/Helm values (secrets in plaintext)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:values.yaml | inurl:values.yml | inurl:secrets.yaml | inurl:helm) (intext:password | intext:apiKey | intext:token)",
                clean_domain
            ),
            description: "Exposed Helm/Kubernetes values with embedded secrets".to_string(),
            impact: "Kubernetes secrets in plaintext reveal database/service credentials".to_string(),
        });

        // Ansible vault/inventory exposure
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:vault.yml | inurl:ansible | inurl:hosts.ini) (intext:ansible_ssh_pass | intext:vault_password | intext:become_pass)",
                clean_domain
            ),
            description: "Ansible inventory/vault files with credentials".to_string(),
            impact: "Reveals SSH passwords, become passwords, and vault decryption keys".to_string(),
        });

        // Terraform state exposed (plaintext secrets)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:terraform.tfstate) intext:\"terraform_version\"",
                clean_domain
            ),
            description: "Exposed Terraform state or tfvars".to_string(),
            impact: "Terraform state contains every resource secret in plaintext (DB passwords, IAM keys)".to_string(),
        });

        // Docker registry / K8s dashboard exposure
        dorks.push(GoogleDork {
            category: "Container Infrastructure".to_string(),
            query: format!(
                "site:{} (inurl:/v2/_catalog | inurl:/api/v1/namespaces | inurl:/kubernetes-dashboard | intitle:\"Kubernetes Dashboard\")",
                clean_domain
            ),
            description: "Exposed container registry catalog or Kubernetes dashboard".to_string(),
            impact: "Registry lists internal images; K8s dashboard may allow cluster control".to_string(),
        });

        // Prometheus / metrics / actuator endpoints
        dorks.push(GoogleDork {
            category: "Diagnostic Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/metrics | inurl:/actuator | inurl:/prometheus | intitle:\"Prometheus Time Series Collection\")",
                clean_domain
            ),
            description: "Exposed metrics, Prometheus, or Spring Boot Actuator endpoints".to_string(),
            impact: "Metrics/actuator endpoints leak internal architecture, env vars, and heap dumps".to_string(),
        });

        // GraphQL introspection / playgrounds
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/altair | inurl:/playground | intitle:\"GraphQL Playground\")",
                clean_domain
            ),
            description: "Exposed GraphQL endpoints with introspection or IDE".to_string(),
            impact: "GraphQL introspection exposes the entire schema, enabling targeted queries".to_string(),
        });

        // Jenkins / build server exposure
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/jenkins/ | inurl:/job/ | inurl:/asynchPeople | inurl:/script)",
                clean_domain
            ),
            description: "Publicly accessible Jenkins instance or scripts".to_string(),
            impact: "Jenkins /script gives Groovy RCE; job pages leak build secrets".to_string(),
        });

        // GitLab / self-hosted forge
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:{} (inurl:/gitlab/ | inurl:/-/snippets/ | inurl:/explore/projects | intitle:\"GitLab\")",
                clean_domain
            ),
            description: "Self-hosted GitLab instance with public snippets/projects".to_string(),
            impact: "Public snippets and projects may contain credentials or private source".to_string(),
        });

        // SonarQube / Nexus / Artifactory internal tooling
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"SonarQube\" | intitle:\"Nexus Repository Manager\" | intitle:\"Artifactory\" | inurl:/nexus/ | inurl:/artifactory/)",
                clean_domain
            ),
            description: "Exposed SonarQube, Nexus, or Artifactory instances".to_string(),
            impact: "Code-quality/package tools may expose credentials, tokens, or private builds".to_string(),
        });

        // Grafana / Kibana / observability
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" | intitle:\"Kibana\" | inurl:/grafana | inurl:/kibana | inurl:/_plugin/kibana)",
                clean_domain
            ),
            description: "Exposed Grafana or Kibana dashboards".to_string(),
            impact: "Dashboards leak sensitive metrics/logs; default creds often work".to_string(),
        });

        // Postman public collections referencing the domain
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com \"{}\"",
                clean_domain
            ),
            description: "Public Postman collections/workspaces referencing the target".to_string(),
            impact: "Postman collections often include API keys, bearer tokens, and auth details".to_string(),
        });

        // Insomnia public workspaces
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:insomnia.rest \"{}\"",
                clean_domain
            ),
            description: "Public Insomnia workspaces referencing the target".to_string(),
            impact: "Workspaces may contain saved API tokens or Basic auth headers".to_string(),
        });

        // Swagger/OpenAPI JSON files
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:swagger.yaml | inurl:openapi.json | inurl:openapi.yaml | inurl:v2/api-docs | inurl:v3/api-docs)",
                clean_domain
            ),
            description: "Raw Swagger/OpenAPI schema files exposed".to_string(),
            impact: "Schema reveals every endpoint, parameter, and auth mechanism for targeted attacks".to_string(),
        });

        // WSDL / SOAP schemas
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (ext:wsdl | inurl:?wsdl | inurl:/services/) intext:\"soap:Envelope\"",
                clean_domain
            ),
            description: "Exposed SOAP WSDL definitions".to_string(),
            impact: "WSDL exposes legacy SOAP endpoints, operations, and parameter types".to_string(),
        });

        // Backup / archive exposure (specific patterns, low-FP)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sql.gz | ext:dump | ext:dmp) (intext:\"CREATE TABLE\" | intext:\"INSERT INTO\" | intext:\"MySQL dump\" | intext:\"PostgreSQL database dump\")",
                clean_domain
            ),
            description: "Exposed SQL database dumps".to_string(),
            impact: "Full database exports typically contain PII, hashes, and business data".to_string(),
        });

        // WordPress-specific backup files
        dorks.push(GoogleDork {
            category: "CMS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.bak | inurl:wp-config.txt | inurl:wp-config.old | inurl:wp-config.php~ | inurl:wp-config.php.swp | inurl:wp-config.php.save)",
                clean_domain
            ),
            description: "WordPress config backup file exposure".to_string(),
            impact: "wp-config backups contain DB credentials and secret salts - full site takeover".to_string(),
        });

        // WordPress debug logs
        dorks.push(GoogleDork {
            category: "CMS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:wp-content/debug.log | inurl:wp-content/uploads/wp-config | inurl:wp-content/plugins/ intext:\"PHP Fatal error\")",
                clean_domain
            ),
            description: "WordPress debug log or uploaded config in wp-content".to_string(),
            impact: "Debug logs reveal plugin errors, file paths, and sometimes credentials".to_string(),
        });

        // Drupal / Joomla / Magento admin
        dorks.push(GoogleDork {
            category: "CMS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/user/login | inurl:/administrator/ | inurl:/admin/index.php | inurl:/admin/ intitle:login | inurl:/index.php/admin)",
                clean_domain
            ),
            description: "CMS admin panels (Drupal/Joomla/Magento/etc.)".to_string(),
            impact: "Admin panels are high-value credential-attack targets".to_string(),
        });

        // Adobe/AEM specific known-sensitive endpoints
        dorks.push(GoogleDork {
            category: "AEM Paths".to_string(),
            query: format!(
                "site:{} (inurl:/system/console | inurl:/etc/replication.html | inurl:/crx/explorer | inurl:/bin/querybuilder.json | inurl:/etc/packages)",
                clean_domain
            ),
            description: "Exposed AEM/CQ system console or QueryBuilder".to_string(),
            impact: "AEM QueryBuilder JSON leaks content trees; system console allows admin actions".to_string(),
        });

        // Django debug and admin
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (intitle:\"Django administration\" | inurl:/admin/login/ | intext:\"You're seeing this error because you have DEBUG = True\" | intext:\"Traceback (most recent call last)\")",
                clean_domain
            ),
            description: "Django admin login or DEBUG=True error pages".to_string(),
            impact: "DEBUG pages leak settings, env vars, and stack traces; admin is attack target".to_string(),
        });

        // Laravel debug (Ignition/Whoops)
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops! There was an error\" | intext:\"Ignition\" | intext:\"Illuminate\\\\\" | inurl:/telescope | inurl:/_ignition)",
                clean_domain
            ),
            description: "Laravel Whoops/Ignition/Telescope debug interfaces".to_string(),
            impact: "Debug interfaces expose env, stack traces; Ignition has known RCE (CVE-2021-3129)".to_string(),
        });

        // Symfony profiler
        dorks.push(GoogleDork {
            category: "Framework Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/_profiler | inurl:/app_dev.php | inurl:/_wdt | intitle:\"Symfony Profiler\")",
                clean_domain
            ),
            description: "Symfony web profiler / dev front controller exposed".to_string(),
            impact: "Profiler reveals every request, DB query, session, and configuration".to_string(),
        });

        // Server-status / Apache mod_status
        dorks.push(GoogleDork {
            category: "Diagnostic Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/server-status | inurl:/server-info | intitle:\"Apache Status\")",
                clean_domain
            ),
            description: "Apache mod_status / mod_info exposed".to_string(),
            impact: "Reveals every in-flight request URL - leaks tokens in querystrings".to_string(),
        });

        // Elasticsearch / Kibana / Solr indices
        dorks.push(GoogleDork {
            category: "Database Exposure".to_string(),
            query: format!(
                "site:{} (inurl:/_cat/indices | inurl:/_cluster/health | inurl:/solr/admin | intitle:\"Solr Admin\")",
                clean_domain
            ),
            description: "Exposed Elasticsearch or Solr admin interfaces".to_string(),
            impact: "Direct read/write access to search indices - often full document dumps".to_string(),
        });

        // MongoDB / Redis / RethinkDB admin UIs
        dorks.push(GoogleDork {
            category: "Database Exposure".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"MongoDB Express\" | intitle:\"Redis Commander\" | inurl:/phpmyadmin/ | inurl:/adminer.php)",
                clean_domain
            ),
            description: "Publicly exposed DB admin interfaces".to_string(),
            impact: "phpMyAdmin/Adminer/etc. are direct DB gateways - credential attacks and RCE".to_string(),
        });

        // Firebase / RTDB rules exposure
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" (inurl:.json | intext:\"rules\")",
                clean_domain
            ),
            description: "Firebase RTDB endpoints indexed with .json exposure".to_string(),
            impact: "Firebase RTDB with rules allowing read/write is a common critical finding".to_string(),
        });

        // Mobile app bundles (APK / IPA) linked from web
        dorks.push(GoogleDork {
            category: "Mobile Application".to_string(),
            query: format!(
                "site:{} (ext:apk | ext:ipa | ext:aab | ext:xapk)",
                clean_domain
            ),
            description: "Downloadable mobile app packages (APK/IPA)".to_string(),
            impact: "APK/IPA can be reversed to extract hardcoded secrets and API endpoints".to_string(),
        });

        // .well-known misuse (change-password, security.txt, apple-app-site-association)
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "site:{} (inurl:.well-known/security.txt | inurl:.well-known/apple-app-site-association | inurl:.well-known/openid-configuration)",
                clean_domain
            ),
            description: "Exposed .well-known metadata (security.txt, AASA, OIDC discovery)".to_string(),
            impact: "OIDC discovery reveals IdP config; AASA leaks deep-link routes".to_string(),
        });

        // Vault / Consul / Nomad UI
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "site:{} (inurl:/ui/vault | inurl:/v1/sys | intitle:\"Consul by HashiCorp\" | inurl:/v1/agent | intitle:\"Nomad\")",
                clean_domain
            ),
            description: "HashiCorp Vault / Consul / Nomad UI exposed".to_string(),
            impact: "Vault UI is the crown jewel of secrets management; Consul KV leaks configuration".to_string(),
        });

        // Rancher / Portainer container UIs
        dorks.push(GoogleDork {
            category: "Container Infrastructure".to_string(),
            query: format!(
                "site:{} (intitle:\"Rancher\" | intitle:\"Portainer\" | inurl:/rancher/ | inurl:/portainer/)",
                clean_domain
            ),
            description: "Container-orchestration UIs (Rancher/Portainer) exposed".to_string(),
            impact: "Container UIs may allow container spawn, shell exec, and secret exfiltration".to_string(),
        });

        // Mail server webmail interfaces
        dorks.push(GoogleDork {
            category: "Login Pages".to_string(),
            query: format!(
                "site:{} (inurl:/webmail | inurl:/roundcube | intitle:\"Roundcube Webmail\" | intitle:\"Zimbra\" | intitle:\"Outlook Web App\" | inurl:/owa/)",
                clean_domain
            ),
            description: "Exposed webmail portals (Roundcube/Zimbra/OWA)".to_string(),
            impact: "Webmail portals are prime credential-stuffing and phishing targets".to_string(),
        });

        // Remote desktop / VPN / firewall management
        dorks.push(GoogleDork {
            category: "Login Pages".to_string(),
            query: format!(
                "site:{} (intitle:\"FortiGate\" | intitle:\"pfSense\" | intitle:\"SonicWALL\" | intitle:\"Citrix Gateway\" | intitle:\"vSphere Web Client\" | intitle:\"iDRAC\" | intitle:\"iLO\")",
                clean_domain
            ),
            description: "Exposed VPN/firewall/hypervisor management portals".to_string(),
            impact: "Perimeter and hypervisor management panels are top-tier attack targets (often CVEs)".to_string(),
        });

        // Cisco / Juniper / Aruba management
        dorks.push(GoogleDork {
            category: "Login Pages".to_string(),
            query: format!(
                "site:{} (intitle:\"Cisco Configuration Professional\" | intitle:\"ScreenOS\" | intitle:\"Aruba Networks\" | intitle:\"WebVPN\")",
                clean_domain
            ),
            description: "Network device management interfaces".to_string(),
            impact: "Router/switch management access enables MITM and full network pivot".to_string(),
        });

        // Confluence spaces (often public accidentally)
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "site:{} (inurl:/wiki/spaces/ | inurl:/confluence/display | intitle:\"Confluence\") (intext:\"password\" | intext:\"credentials\" | intext:\"api key\" | intext:\"private\")",
                clean_domain
            ),
            description: "Confluence pages leaking secrets".to_string(),
            impact: "Wiki pages frequently contain runbooks with credentials in plaintext".to_string(),
        });

        // Notion / Coda public workspaces
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "(site:notion.so | site:coda.io) \"{}\" (intext:\"password\" | intext:\"credentials\" | intext:\"api\")",
                clean_domain
            ),
            description: "Public Notion/Coda pages tied to the domain".to_string(),
            impact: "Employee-shared docs often contain onboarding creds and API tokens".to_string(),
        });

        // StackOverflow / Superuser / ServerFault leaks (dev pasted logs)
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:serverfault.com | site:superuser.com) \"{}\"",
                clean_domain
            ),
            description: "Q&A posts referencing the domain".to_string(),
            impact: "Developers paste logs/configs/tokens when asking for help".to_string(),
        });

        // Bitbucket snippets / repos
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:bitbucket.org | site:bitbucket.com) \"{}\"",
                clean_domain
            ),
            description: "Bitbucket repositories/snippets referencing the domain".to_string(),
            impact: "Public snippets and forks may expose credentials or private code".to_string(),
        });

        // Sourcegraph and Grep.app public code search
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:sourcegraph.com | site:grep.app) \"{}\"",
                clean_domain
            ),
            description: "Sourcegraph / grep.app indexed code hits".to_string(),
            impact: "Cross-repo code search often surfaces overlooked credential leaks".to_string(),
        });

        // GitHub Gists (separate from repos)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\"",
                clean_domain
            ),
            description: "Public GitHub Gists mentioning the target domain".to_string(),
            impact: "Gists are a common accidental secret-leak vector".to_string(),
        });

        // GitHub Actions workflow leaks (secrets referenced)
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:github.com \"{}\" (inurl:/.github/workflows | intext:\"secrets.\" | intext:\"AWS_ACCESS_KEY_ID\" | intext:\"NPM_TOKEN\")",
                clean_domain
            ),
            description: "GitHub Actions workflows referencing this domain and secrets".to_string(),
            impact: "Workflow files reveal secret names and CI/CD deployment surfaces".to_string(),
        });

        // Docker Hub / GHCR image names
        dorks.push(GoogleDork {
            category: "Container Infrastructure".to_string(),
            query: format!(
                "(site:hub.docker.com | site:ghcr.io | site:quay.io) \"{}\"",
                clean_domain
            ),
            description: "Public container images referencing the target".to_string(),
            impact: "Images may contain layered secrets, source code, or private tooling".to_string(),
        });

        // NPM / PyPI packages leaking internal packages
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:npmjs.com | site:pypi.org | site:rubygems.org) \"{}\"",
                clean_domain
            ),
            description: "Public packages referencing the internal domain".to_string(),
            impact: "Internal package names enable dependency-confusion supply-chain attacks".to_string(),
        });

        // Chocolatey / Homebrew / snap
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:chocolatey.org | site:formulae.brew.sh | site:snapcraft.io) \"{}\"",
                clean_domain
            ),
            description: "OS-level package repositories referencing the domain".to_string(),
            impact: "Internal packages exposed publicly enable typosquatting and confusion attacks".to_string(),
        });

        // Kubernetes / Docker registry catalogs
        dorks.push(GoogleDork {
            category: "Container Infrastructure".to_string(),
            query: format!(
                "site:{} (inurl:/v2/ intext:\"repository\" | inurl:_catalog)",
                clean_domain
            ),
            description: "Docker Registry v2 catalog exposed".to_string(),
            impact: "Registry catalog enables enumeration of every private image and tag".to_string(),
        });

        // Ceph / MinIO / open object stores
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Browser\" | inurl:/minio/ | intitle:\"Ceph Dashboard\")",
                clean_domain
            ),
            description: "MinIO / Ceph object storage dashboards exposed".to_string(),
            impact: "S3-compatible dashboards enable direct read/write of buckets".to_string(),
        });

        // Backup services (Bacula, Veeam)
        dorks.push(GoogleDork {
            category: "Internal Tools".to_string(),
            query: format!(
                "site:{} (intitle:\"Bacula\" | intitle:\"Veeam Backup Enterprise Manager\" | inurl:/bareos-webui)",
                clean_domain
            ),
            description: "Backup management portals exposed".to_string(),
            impact: "Backup portals may allow triggering restores or accessing archived data".to_string(),
        });

        // Elastic APM / Sentry / observability leaks
        dorks.push(GoogleDork {
            category: "Diagnostic Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/apm | intitle:\"Sentry\" | inurl:/sentry/ | inurl:/jaeger | intitle:\"Jaeger UI\")",
                clean_domain
            ),
            description: "Exposed APM / Sentry / Jaeger tracing UIs".to_string(),
            impact: "Tracing UIs leak request URLs, tokens in querystrings, and internal service graph".to_string(),
        });

        // Git repo web viewers
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:{} (inurl:/gitweb | inurl:/cgit | inurl:/gitea | intitle:\"Gitea\" | intitle:\"gogs\")",
                clean_domain
            ),
            description: "Self-hosted Git web UIs (Gitea, Gogs, Gitweb, cgit)".to_string(),
            impact: "Self-hosted forges often lack SSO and can leak private repos".to_string(),
        });

        // PII in URLs (SSN, credit card, DOB)
        dorks.push(GoogleDork {
            category: "PII Parameters".to_string(),
            query: format!(
                "site:{} (inurl:ssn= | inurl:dob= | inurl:cc= | inurl:card= | inurl:passport= | inurl:national_id=)",
                clean_domain
            ),
            description: "URLs carrying PII/financial identifiers in querystring".to_string(),
            impact: "PII in URLs is logged in every proxy/CDN/analytics tool - GDPR/HIPAA violation".to_string(),
        });

        // Session/token leakage in URL
        dorks.push(GoogleDork {
            category: "Auth Token Leakage".to_string(),
            query: format!(
                "site:{} (inurl:token= | inurl:access_token= | inurl:session= | inurl:sessionid= | inurl:jwt= | inurl:apikey= | inurl:api_key=)",
                clean_domain
            ),
            description: "Tokens/session IDs in querystrings".to_string(),
            impact: "Session/API tokens in URLs leak via referrer, logs, and browser history".to_string(),
        });

        // Password reset links indexed
        dorks.push(GoogleDork {
            category: "Auth Token Leakage".to_string(),
            query: format!(
                "site:{} (inurl:reset_token= | inurl:password_reset | inurl:activation= | inurl:confirm_token= | inurl:invite_token=)",
                clean_domain
            ),
            description: "Password reset/invite tokens leaked in indexed URLs".to_string(),
            impact: "Indexed reset tokens can be replayed to hijack accounts".to_string(),
        });

        // OAuth callback exposure with code/state
        dorks.push(GoogleDork {
            category: "Auth Token Leakage".to_string(),
            query: format!(
                "site:{} (inurl:/oauth/callback | inurl:code= inurl:state=)",
                clean_domain
            ),
            description: "OAuth callback URLs indexed with code/state".to_string(),
            impact: "OAuth code leakage may enable token exchange within its validity window".to_string(),
        });

        // AWS Cognito hosted UI misconfig
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "(site:auth.amazoncognito.com | inurl:cognito-idp.amazonaws.com) \"{}\"",
                clean_domain
            ),
            description: "AWS Cognito hosted UI referencing the target".to_string(),
            impact: "Cognito misconfig can allow self-signup, IDP takeover, or user enum".to_string(),
        });

        // Azure Blob / Storage misconfig containers
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:blob.core.windows.net \"{}\" (inurl:?restype=container | inurl:?comp=list)",
                clean_domain
            ),
            description: "Enumerable Azure Blob containers".to_string(),
            impact: "Anonymous list-permitting containers expose every stored blob".to_string(),
        });

        // GCP Storage buckets with listBucketResult
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Google Cloud Storage buckets referenced".to_string(),
            impact: "Publicly readable GCS buckets often expose backups, exports, and PII".to_string(),
        });

        // Wasabi / Backblaze / Linode Object Storage
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:wasabisys.com | site:backblazeb2.com | site:linodeobjects.com) \"{}\"",
                clean_domain
            ),
            description: "Alternative S3-compatible object storage referencing target".to_string(),
            impact: "Non-AWS object storage is often forgotten during audits and left public".to_string(),
        });

        // Common secret files at root
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:/id_rsa | inurl:/authorized_keys | inurl:/.netrc | inurl:/.pgpass | inurl:/.my.cnf | inurl:/master.key)",
                clean_domain
            ),
            description: "Private keys / credential dotfiles indexed".to_string(),
            impact: "SSH keys, DB creds, and Rails master.key allow immediate compromise".to_string(),
        });

        // Kubeconfig / Docker config exposure
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:/.kube/config | inurl:/kubeconfig | inurl:/.docker/config.json | inurl:/.dockercfg)",
                clean_domain
            ),
            description: "Exposed kubeconfig / Docker registry auth".to_string(),
            impact: "kubeconfig = full cluster access; .docker/config.json = registry creds".to_string(),
        });

        // Java keystore/PKCS12 files
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:jks | ext:keystore | ext:p12 | ext:pfx | ext:pem)",
                clean_domain
            ),
            description: "Java keystores / TLS private key material".to_string(),
            impact: "Keystores contain private keys and are often password-protected with weak passwords".to_string(),
        });

        // Coredumps / crash reports
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:hprof | ext:core | ext:dmp | inurl:heapdump | inurl:threaddump)",
                clean_domain
            ),
            description: "Heap dumps / core dumps / thread dumps".to_string(),
            impact: "Memory dumps contain in-flight secrets, session tokens, and PII".to_string(),
        });

        // Sitemaps revealing hidden endpoints
        dorks.push(GoogleDork {
            category: "Attack Surface".to_string(),
            query: format!(
                "site:{} (inurl:sitemap.xml | inurl:sitemap_index.xml | inurl:sitemap-admin.xml)",
                clean_domain
            ),
            description: "XML sitemaps enumerating URLs".to_string(),
            impact: "Sitemaps reveal endpoints not linked from public pages".to_string(),
        });

        // robots.txt Disallow (often reveals sensitive paths)
        dorks.push(GoogleDork {
            category: "Attack Surface".to_string(),
            query: format!(
                "site:{} inurl:robots.txt",
                clean_domain
            ),
            description: "robots.txt Disallow directives".to_string(),
            impact: "Disallowed paths often point to admin/staging/API endpoints".to_string(),
        });

        // WebDAV / SVN / Mercurial dirs
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/.svn/entries | inurl:/.svn/wc.db | inurl:/.hg/hgrc | inurl:/.bzr/ | inurl:/CVS/Root)",
                clean_domain
            ),
            description: "VCS metadata directories (SVN/Hg/Bzr/CVS)".to_string(),
            impact: "VCS metadata enables full-source reconstruction".to_string(),
        });

        // .git directory pieces
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/.git/config | inurl:/.git/HEAD | inurl:/.git/logs/HEAD | inurl:/.git/refs/heads)",
                clean_domain
            ),
            description: "Exposed .git directory files".to_string(),
            impact: "Full .git enables source-code dumping via git-dumper".to_string(),
        });

        // DS_Store leaks folder structure
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} inurl:.DS_Store",
                clean_domain
            ),
            description: "macOS .DS_Store files exposing directory listings".to_string(),
            impact: ".DS_Store reveals hidden filenames in every deployed directory".to_string(),
        });

        // Public S3 buckets referencing corp identifiers
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:s3-website | inurl:s3.amazonaws.com) intext:\"{}\" (intext:\"ListBucketResult\" | intitle:\"Index of\")",
                clean_domain
            ),
            description: "Enumerable S3 buckets referencing the corp name".to_string(),
            impact: "Public-list S3 buckets expose all keys; download-anonymous variants leak files".to_string(),
        });

        // Firmware / IoT bin files
        dorks.push(GoogleDork {
            category: "Mobile Application".to_string(),
            query: format!(
                "site:{} (ext:bin | ext:img | ext:hex) (inurl:firmware | inurl:update | inurl:release)",
                clean_domain
            ),
            description: "Firmware binaries or update packages".to_string(),
            impact: "Firmware can be extracted for hardcoded secrets, keys, and RCE gadgets".to_string(),
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
