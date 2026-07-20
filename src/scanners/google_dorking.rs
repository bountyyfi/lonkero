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

        // ================================================================
        // HIGH-SIGNAL SENSITIVE-FILE EXPOSURE (impactful, low FP)
        // Each dork below is anchored on both site: and either a
        // characteristic filename OR a token that only appears inside the
        // sensitive content — so a hit is almost always a real exposure.
        // ================================================================

        // Exposed dotenv files (.env / .env.production / .env.local)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.prod | inurl:.env.dev | inurl:.env.staging | inurl:.env.backup | inurl:.env.old | inurl:.env~) (intext:DB_PASSWORD | intext:APP_KEY | intext:SECRET_KEY | intext:AWS_ACCESS_KEY_ID | intext:STRIPE_SECRET)",
                clean_domain
            ),
            description: "Find publicly exposed dotenv files containing credentials".to_string(),
            impact: "Directly exposes DB passwords, API keys, JWT secrets, cloud credentials — near-100% chance of full application compromise".to_string(),
        });

        // Exposed Git repository (loose .git/config)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.git/logs/HEAD) (intext:\"[core]\" | intext:\"repositoryformatversion\" | intext:\"ref: refs/heads\")",
                clean_domain
            ),
            description: "Find exposed .git directories on the web root".to_string(),
            impact: "Attackers can reconstruct full source tree, uncover hard-coded secrets, and inspect historical commits".to_string(),
        });

        // Kubernetes kubeconfig / kubectl config files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:kubeconfig | inurl:kube/config | inurl:.kube/config) intext:\"apiVersion:\" intext:\"clusters:\" intext:\"users:\"",
                clean_domain
            ),
            description: "Find exposed kubeconfig files".to_string(),
            impact: "Grants direct API access to the Kubernetes cluster with the embedded credentials/tokens".to_string(),
        });

        // Terraform state files (contain plaintext secrets)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:terraform.tfstate | inurl:terraform.tfstate.backup | inurl:.terraform/terraform.tfstate) intext:\"\\\"terraform_version\\\":\" intext:\"\\\"resources\\\":\"",
                clean_domain
            ),
            description: "Find exposed Terraform state files".to_string(),
            impact: "State files contain plaintext cloud credentials, DB passwords, and private keys for every managed resource".to_string(),
        });

        // Ansible vault or inventory with credentials
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:ansible | inurl:inventory | inurl:hosts.ini | inurl:vault.yml) (intext:\"$ANSIBLE_VAULT;\" | intext:\"ansible_user\" | intext:\"ansible_ssh_pass\")",
                clean_domain
            ),
            description: "Find exposed Ansible inventories and vault files".to_string(),
            impact: "Exposes bastion/SSH credentials or encrypted vaults whose keys often leak alongside them".to_string(),
        });

        // Private keys (RSA/EC/PGP/PPK/PEM)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:asc | ext:p12 | ext:pfx | ext:jks) (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN EC PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\" | intext:\"PuTTY-User-Key-File\")",
                clean_domain
            ),
            description: "Find exposed private keys (SSH, TLS, PGP, PuTTY)".to_string(),
            impact: "Any hit is an immediate credential leak enabling server login, TLS impersonation, or code signing".to_string(),
        });

        // AWS credentials files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:aws/credentials | inurl:credentials.aws) intext:\"aws_access_key_id\" intext:\"aws_secret_access_key\"",
                clean_domain
            ),
            description: "Find AWS credentials files".to_string(),
            impact: "Direct AWS account takeover via long-lived IAM keys".to_string(),
        });

        // Google Cloud service-account JSON
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} ext:json intext:\"\\\"type\\\": \\\"service_account\\\"\" intext:\"\\\"private_key\\\":\" intext:\"\\\"client_email\\\":\"",
                clean_domain
            ),
            description: "Find exposed GCP service-account key JSON files".to_string(),
            impact: "Provides authenticated access to the GCP project the service account belongs to".to_string(),
        });

        // Docker Compose files exposing environment/credentials
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:compose.yml) intext:\"services:\" (intext:\"POSTGRES_PASSWORD\" | intext:\"MYSQL_ROOT_PASSWORD\" | intext:\"MONGO_INITDB_ROOT_PASSWORD\" | intext:\"REDIS_PASSWORD\")",
                clean_domain
            ),
            description: "Find docker-compose files with baked-in credentials".to_string(),
            impact: "Reveals DB/Redis/queue passwords and internal service topology".to_string(),
        });

        // WordPress wp-config leak
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.php~ | inurl:wp-config.php.save | inurl:wp-config.txt) intext:\"DB_PASSWORD\" intext:\"AUTH_KEY\"",
                clean_domain
            ),
            description: "Find backup copies of wp-config.php served as plaintext".to_string(),
            impact: "Full WordPress DB credentials and salts, leading to account takeover and DB compromise".to_string(),
        });

        // Laravel .env / storage.log
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:storage/logs/laravel.log | inurl:storage/logs/laravel-) intext:\"[stacktrace]\" intext:\"App\\\\\"",
                clean_domain
            ),
            description: "Find exposed Laravel application logs".to_string(),
            impact: "Laravel logs frequently contain stack traces with request payloads, tokens, and DB queries".to_string(),
        });

        // Django settings/debug pages
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intitle:\"DisallowedHost\" | intitle:\"You're seeing this error because you have DEBUG = True\" | intext:\"Traceback (most recent call last)\" intext:\"django/core/handlers\")",
                clean_domain
            ),
            description: "Find Django debug pages leaking settings and stack traces".to_string(),
            impact: "Debug pages leak SECRET_KEY, DB DSNs, installed apps, and full source paths".to_string(),
        });

        // Rails secrets.yml / master.key
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:config/secrets.yml | inurl:config/master.key | inurl:config/credentials.yml.enc) (intext:\"secret_key_base\" | intext:\"aws_access_key_id\")",
                clean_domain
            ),
            description: "Find exposed Rails secrets/master.key files".to_string(),
            impact: "Allows forging session cookies, decrypting Rails encrypted credentials, and impersonating any user".to_string(),
        });

        // Spring Boot actuator env / heapdump / configprops
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/loggers | inurl:/actuator/mappings) intext:\"activeProfiles\" | intext:\"contexts\"",
                clean_domain
            ),
            description: "Find publicly exposed Spring Boot actuator endpoints".to_string(),
            impact: "/env leaks secrets; /heapdump downloads full JVM heap (session tokens, DB pool passwords); /loggers enables live config changes".to_string(),
        });

        // Elasticsearch/Kibana without auth
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/_cat/indices | inurl:/_cluster/health | inurl:/_search) intext:\"\\\"cluster_name\\\":\" intext:\"\\\"status\\\":\"",
                clean_domain
            ),
            description: "Find unauthenticated Elasticsearch APIs".to_string(),
            impact: "Enumerates and dumps indices; often contains PII, logs, or session data".to_string(),
        });

        // Prometheus / Grafana anonymous
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series Collection\" | intitle:\"Grafana\" inurl:/dashboard | inurl:/api/datasources) intext:\"prometheus\" | intext:\"grafana\"",
                clean_domain
            ),
            description: "Find open Prometheus / Grafana instances".to_string(),
            impact: "Metrics leak internal topology and credentials; Grafana datasources sometimes expose SQL/Splunk creds".to_string(),
        });

        // Jenkins script console / API
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/script | inurl:/scriptler | inurl:/asynchPeople | inurl:/computer) intitle:\"Jenkins\"",
                clean_domain
            ),
            description: "Find exposed Jenkins consoles/APIs".to_string(),
            impact: "Anonymous Jenkins with script console equals unauthenticated RCE on the CI host and downstream deploy keys".to_string(),
        });

        // GitLab / Gitea / Gogs internal-graphs
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/-/graphql-explorer | inurl:/-/metrics | inurl:/api/v4/projects | inurl:/api/v1/repos/search) (intext:\"GitLab\" | intext:\"Gitea\")",
                clean_domain
            ),
            description: "Find exposed GitLab/Gitea APIs and metrics".to_string(),
            impact: "Enumerates projects and users; frequently uncovers private repos and CI tokens".to_string(),
        });

        // Swagger + writable actions
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:swagger-ui | inurl:/api-docs | inurl:/v2/api-docs | inurl:/v3/api-docs) intext:\"openapi\" (intext:\"delete\" | intext:\"admin\" | intext:\"upload\")",
                clean_domain
            ),
            description: "Find Swagger/OpenAPI docs describing admin/delete/upload endpoints".to_string(),
            impact: "Documented but unauthenticated admin endpoints — a common source of high-impact BOLA/mass-assign findings".to_string(),
        });

        // Sentry / Rollbar / Bugsnag public projects (DSN leaks)
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (intext:\"https://\" intext:\"@sentry.io/\" | intext:\"@o0.ingest.sentry.io\" | intext:\"public.dsn\") intext:\"Sentry.init\"",
                clean_domain
            ),
            description: "Find Sentry DSNs embedded in the site".to_string(),
            impact: "Leaked DSN + writable projects allow attackers to inject events and, if server-side DSN, read release/source-map data".to_string(),
        });

        // Firebase Realtime DB open rules
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "intext:\"{}\" (intext:\"firebaseio.com/.json\" | intext:\"firebaseio.com/rules.json\")",
                clean_domain
            ),
            description: "Find Firebase databases with .json/rules.json enumerated".to_string(),
            impact: "Open Firebase read/write rules expose or overwrite entire application data".to_string(),
        });

        // Sensitive database dump extensions
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb | ext:bak | ext:dump | ext:backup) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"PRAGMA\" | intext:\"pg_dump\" | intext:\"MySQL dump\")",
                clean_domain
            ),
            description: "Find raw database dumps served over HTTP".to_string(),
            impact: "Complete PII/user/credential dumps recoverable without authentication".to_string(),
        });

        // Log files leaking secrets or requests
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:access.log | inurl:error.log | inurl:debug.log | inurl:trace.log) (intext:\"Authorization: Bearer\" | intext:\"password=\" | intext:\"api_key=\" | intext:\"set-cookie:\")",
                clean_domain
            ),
            description: "Find webserver/application logs leaking tokens, cookies, or requests".to_string(),
            impact: "Bearer tokens, session cookies, or credential-bearing URL parameters recoverable directly".to_string(),
        });

        // JSON web keys / OIDC discovery + admin OAuth clients
        dorks.push(GoogleDork {
            category: "Auth Discovery".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/openid-configuration | inurl:/.well-known/oauth-authorization-server | inurl:/oauth2/jwks | inurl:/.well-known/jwks.json)",
                clean_domain
            ),
            description: "Locate OIDC/OAuth2 discovery and JWKS endpoints".to_string(),
            impact: "Maps identity provider topology, JWT signing keys, and available grant/response types for auth attacks".to_string(),
        });

        // .well-known assetlinks / app site associations (mobile deep-link takeover)
        dorks.push(GoogleDork {
            category: "Mobile Attack Surface".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/apple-app-site-association | inurl:/.well-known/assetlinks.json)",
                clean_domain
            ),
            description: "Find deep-link/universal-link association files".to_string(),
            impact: "Enumerates deep-link intents for mobile-to-web attacks; loose patterns enable Universal Link hijacking".to_string(),
        });

        // Kibana / OpenSearch dashboards public
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | intitle:\"OpenSearch Dashboards\") (inurl:/app/dashboards | inurl:/app/kibana | inurl:/app/dev_tools)",
                clean_domain
            ),
            description: "Find unauthenticated Kibana/OpenSearch dashboards".to_string(),
            impact: "Anonymous read of dashboards and dev-tools console executing raw ES queries".to_string(),
        });

        // Vault / Consul / Nomad UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Vault\" inurl:/ui/ | intitle:\"Consul\" inurl:/ui/ | intitle:\"Nomad\" inurl:/ui/) intext:\"HashiCorp\"",
                clean_domain
            ),
            description: "Find publicly reachable HashiCorp Vault/Consul/Nomad UIs".to_string(),
            impact: "Any auth misconfig grants secrets read/write, KV browse, or job submission".to_string(),
        });

        // MinIO / S3-compatible dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Console\" | inurl:/minio/) intext:\"minio\"",
                clean_domain
            ),
            description: "Find exposed MinIO administrative consoles".to_string(),
            impact: "Default or leaked credentials grant full object-store read/write".to_string(),
        });

        // Directory listings of sensitive paths
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (intext:\"parent directory\" | intext:\"Name  Last modified  Size\") (intext:\".env\" | intext:\"backup\" | intext:\"config\" | intext:\".sql\" | intext:\".git\")",
                clean_domain
            ),
            description: "Find open directory listings containing sensitive filenames".to_string(),
            impact: "Autoindex-enabled directories reveal backups, dumps, and config files in one page".to_string(),
        });

        // GitHub credentials leaked in code
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" (\"AKIA\" | \"ASIA\" | \"ghp_\" | \"gho_\" | \"github_pat_\" | \"xoxb-\" | \"xoxp-\" | \"BEGIN PRIVATE KEY\" | \"stripe_secret\" | \"sk_live_\")",
                clean_domain
            ),
            description: "Find leaked API keys/tokens on GitHub referencing this domain".to_string(),
            impact: "Live credentials (AWS, GitHub PAT, Slack, Stripe, PEM keys) tied to the target organization".to_string(),
        });

        // GitLab credentials leaked in code
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gitlab.com \"{}\" (\"AKIA\" | \"glpat-\" | \"BEGIN PRIVATE KEY\" | \"sk_live_\" | \"xoxb-\")",
                clean_domain
            ),
            description: "Find leaked credentials on GitLab referencing this domain".to_string(),
            impact: "Live GitLab/AWS/Slack/Stripe credentials tied to the target".to_string(),
        });

        // Postman public workspaces mentioning the target
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:postman.co | site:documenter.getpostman.com | site:postman.com) \"{}\"",
                clean_domain
            ),
            description: "Find Postman collections/workspaces referencing the target".to_string(),
            impact: "Public Postman collections routinely embed API tokens, cookies, and internal endpoints".to_string(),
        });

        // Notion / Confluence / Google Docs public pages
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:notion.so | site:notion.site) \"{}\" (intext:\"password\" | intext:\"credentials\" | intext:\"api key\" | intext:\"internal\")",
                clean_domain
            ),
            description: "Find Notion pages accidentally exposing internal docs".to_string(),
            impact: "Public Notion pages often carry runbooks and credentials never intended for the internet".to_string(),
        });

        // Azure Storage / SAS URLs
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (inurl:blob.core.windows.net inurl:\"sig=\" inurl:\"se=\" | inurl:\".file.core.windows.net\")",
                clean_domain
            ),
            description: "Find Azure blob SAS URLs referencing the target".to_string(),
            impact: "Leaked SAS URLs grant time-limited (often long) read/write access to entire containers".to_string(),
        });

        // Backup archive extensions
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:rar | ext:7z | ext:tar | ext:tgz | ext:tar.gz | ext:gz) (inurl:backup | inurl:dump | inurl:archive | inurl:old | inurl:release)",
                clean_domain
            ),
            description: "Find archive files that likely contain source or DB backups".to_string(),
            impact: "Complete source/data snapshots downloadable without authentication".to_string(),
        });

        // JIRA / Confluence anonymous project browse
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/secure/Dashboard.jspa | inurl:/plugins/servlet | inurl:/rest/api/2 | inurl:/wiki/rest/api/content) (intext:\"Atlassian\" | intitle:\"JIRA\" | intitle:\"Confluence\")",
                clean_domain
            ),
            description: "Find Jira/Confluence instances with anonymous access to APIs".to_string(),
            impact: "Anonymous project/issue listing frequently leaks credentials pasted into tickets".to_string(),
        });

        // AEM CRXDE / servlets (unauthenticated content read)
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/crx/de/index.jsp | inurl:/system/console | inurl:/bin/querybuilder.json | inurl:/etc/replication)",
                clean_domain
            ),
            description: "Find AEM administrative consoles and unauthenticated servlets".to_string(),
            impact: "querybuilder.json alone enumerates every node; CRXDE/system-console can lead to RCE via bundle upload".to_string(),
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
