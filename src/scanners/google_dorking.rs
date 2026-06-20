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

        // ===========================================================
        // High-impact dorks targeting sensitive surface exposure.
        // Each query below is narrow enough (specific filename, header
        // string, or pathname) that real matches almost certainly
        // represent a real exposure — not a marketing page coincidence.
        // ===========================================================

        // -------- Version control system exposure --------
        // `.git/config` always contains the literal `[core]` section header,
        // so this string + the `.git/` path is a near-zero-FP signal.
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} inurl:/.git/ intext:\"[core]\" | inurl:/.git/HEAD | inurl:/.git/config | inurl:/.gitignore",
                clean_domain
            ),
            description: "Exposed .git repository directory or config".to_string(),
            impact: "Full source-code disclosure via git-dumper; commit history may include credentials, internal hostnames, and pre-patched vulnerabilities.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} inurl:/.svn/entries | inurl:/.svn/wc.db | inurl:/.hg/store | inurl:/.bzr/branch",
                clean_domain
            ),
            description: "Exposed SVN / Mercurial / Bazaar working copy".to_string(),
            impact: "Reconstructable source code and historical credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} inurl:/.DS_Store | inurl:/.gitkeep | inurl:/Thumbs.db | inurl:/desktop.ini",
                clean_domain
            ),
            description: "OS / IDE metadata files revealing directory structure".to_string(),
            impact: "Directory listings & filenames enable targeted file enumeration.".to_string(),
        });

        // -------- CI/CD pipeline definitions (often contain tokens) --------
        dorks.push(GoogleDork {
            category: "CI/CD Exposure".to_string(),
            query: format!(
                "site:{} inurl:.gitlab-ci.yml | inurl:.travis.yml | inurl:.circleci/config.yml | inurl:azure-pipelines.yml | inurl:bitbucket-pipelines.yml | inurl:Jenkinsfile",
                clean_domain
            ),
            description: "Exposed CI/CD pipeline definitions".to_string(),
            impact: "Pipeline files reveal build infrastructure, deployment targets, and frequently contain hard-coded secrets, registry URLs, and internal service names.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD Exposure".to_string(),
            query: format!(
                "site:{} inurl:.github/workflows | ext:yml inurl:.github",
                clean_domain
            ),
            description: "Exposed GitHub Actions workflow files".to_string(),
            impact: "Workflows disclose secret names, deploy targets, and self-hosted runner endpoints.".to_string(),
        });

        // -------- Container / orchestration manifests --------
        dorks.push(GoogleDork {
            category: "Container Config".to_string(),
            query: format!(
                "site:{} ext:yml (intext:\"apiVersion: v1\" | intext:\"kind: Secret\" | intext:\"kind: ConfigMap\" | intext:\"kind: Deployment\")",
                clean_domain
            ),
            description: "Kubernetes manifests served as static files".to_string(),
            impact: "Manifests expose internal service topology and frequently include base64-encoded secrets in Secret objects.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Container Config".to_string(),
            query: format!(
                "site:{} inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:Dockerfile | inurl:.dockerignore | inurl:values.yaml | inurl:Chart.yaml",
                clean_domain
            ),
            description: "Exposed Docker / Helm definitions".to_string(),
            impact: "Compose files commonly embed DB connection strings, admin passwords, and internal hostnames.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Container Config".to_string(),
            query: format!(
                "site:{} (intext:\"BEGIN CERTIFICATE\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"apiVersion: v1\" intext:\"kubeconfig\")",
                clean_domain
            ),
            description: "Exposed kubeconfig / TLS material in indexed content".to_string(),
            impact: "Full cluster API access or impersonation if real kubeconfig is recovered.".to_string(),
        });

        // -------- Cloud / IaC state files --------
        dorks.push(GoogleDork {
            category: "Infrastructure-as-Code".to_string(),
            query: format!(
                "site:{} (inurl:terraform.tfstate | inurl:.terraform | inurl:cdk.out | inurl:cloudformation.json | inurl:cloudformation.yml | inurl:serverless.yml)",
                clean_domain
            ),
            description: "Exposed Terraform / CDK / Serverless state".to_string(),
            impact: "State files contain plaintext outputs including IAM keys, RDS endpoints, and resource ARNs — a complete cloud inventory map.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Infrastructure-as-Code".to_string(),
            query: format!(
                "site:{} (inurl:.aws/credentials | inurl:.aws/config | inurl:.s3cfg | inurl:.boto | inurl:.gcloud)",
                clean_domain
            ),
            description: "Exposed cloud CLI credentials files".to_string(),
            impact: "Direct cloud account compromise via leaked access keys.".to_string(),
        });

        // -------- Environment / dotenv files --------
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.dev | inurl:.env.staging | ext:env)",
                clean_domain
            ),
            description: "Exposed dotenv files".to_string(),
            impact: ".env files routinely contain DB passwords, third-party API keys, JWT secrets, and OAuth client secrets.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD=\" | intext:\"SECRET_KEY=\" | intext:\"AWS_SECRET_ACCESS_KEY=\" | intext:\"STRIPE_SECRET_KEY=\" | intext:\"JWT_SECRET=\")",
                clean_domain
            ),
            description: "Indexed pages containing dotenv-style secret assignments".to_string(),
            impact: "Direct credential disclosure — these prefixes only appear in real env files or accidentally-published config.".to_string(),
        });

        // -------- Database dumps & backups --------
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:bak | ext:sqlite | ext:sqlitedb | ext:mdb | ext:accdb) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\")",
                clean_domain
            ),
            description: "Database dump files served by web server".to_string(),
            impact: "Full data dump of production tables — PII, password hashes, session tokens, internal IDs.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"DbNinja\" | intitle:\"SQL Buddy\") (intext:\"Welcome to phpMyAdmin\" | intext:\"Login\")",
                clean_domain
            ),
            description: "Exposed database admin web interfaces".to_string(),
            impact: "Direct database access if default credentials or weak auth — full data exfiltration possible.".to_string(),
        });

        // -------- Keystores and key material --------
        dorks.push(GoogleDork {
            category: "Keystores & Keys".to_string(),
            query: format!(
                "site:{} (ext:jks | ext:keystore | ext:p12 | ext:pfx | ext:pem | ext:key | ext:asc)",
                clean_domain
            ),
            description: "Exposed cryptographic key material".to_string(),
            impact: "Stolen JKS/PFX enable TLS impersonation, code-signing forgery, or service-account hijack.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Keystores & Keys".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\" | intext:\"-----BEGIN ENCRYPTED PRIVATE KEY-----\")",
                clean_domain
            ),
            description: "Indexed pages containing PEM-armored private keys".to_string(),
            impact: "PEM key blocks are unique enough that any indexed match is a real key leak.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Keystores & Keys".to_string(),
            query: format!(
                "site:{} (inurl:id_rsa | inurl:id_dsa | inurl:id_ecdsa | inurl:id_ed25519 | inurl:authorized_keys | inurl:known_hosts)",
                clean_domain
            ),
            description: "Exposed SSH key material".to_string(),
            impact: "SSH private keys yield direct host access; authorized_keys reveals trust topology.".to_string(),
        });

        // -------- CMS configuration files --------
        dorks.push(GoogleDork {
            category: "CMS Config".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.txt | inurl:wp-config.php.swp | ext:php inurl:wp-config)",
                clean_domain
            ),
            description: "Exposed WordPress wp-config backups".to_string(),
            impact: "wp-config contains DB credentials, salts, and auth keys — full WP compromise.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "CMS Config".to_string(),
            query: format!(
                "site:{} (inurl:configuration.php.bak | inurl:configuration.php~ | inurl:settings.php.bak | inurl:LocalSettings.php.bak | inurl:local.xml.bak)",
                clean_domain
            ),
            description: "Exposed Joomla / Drupal / Mediawiki / Magento config backups".to_string(),
            impact: "Each of these config files contains DB credentials and CMS secret keys.".to_string(),
        });

        // -------- Server status / debug surfaces --------
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:/server-status | inurl:/server-info | inurl:/balancer-manager | inurl:/nginx_status | inurl:/stub_status)",
                clean_domain
            ),
            description: "Exposed Apache / Nginx status pages".to_string(),
            impact: "Reveals every active request URL — leaks session IDs in query strings, internal hostnames, and request paths.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" intext:\"PHP Version\" | inurl:phpinfo.php | inurl:_phpinfo.php | inurl:info.php intext:\"PHP Version\")",
                clean_domain
            ),
            description: "Exposed phpinfo() pages".to_string(),
            impact: "phpinfo discloses env vars (often containing secrets), loaded extensions with CVE exposure, full SAPI/server paths.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/beans | inurl:/actuator/logfile)",
                clean_domain
            ),
            description: "Exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env leaks every property including secrets; /heapdump enables credential extraction from memory; /jolokia + /env enables RCE.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Server Status".to_string(),
            query: format!(
                "site:{} (inurl:/debug/vars | inurl:/debug/pprof | inurl:/_debug | inurl:/debug/requests | inurl:/debug/events)",
                clean_domain
            ),
            description: "Exposed Go expvar / pprof debug endpoints".to_string(),
            impact: "pprof allows heap inspection and CPU profiling — extract credentials and reconstruct request data.".to_string(),
        });

        // -------- Monitoring / observability exposure --------
        dorks.push(GoogleDork {
            category: "Observability".to_string(),
            query: format!(
                "site:{} (inurl:/metrics | inurl:/prometheus | inurl:/api/v1/query | inurl:/-/healthy | inurl:/-/ready) intext:\"# HELP\"",
                clean_domain
            ),
            description: "Exposed Prometheus metrics endpoints".to_string(),
            impact: "Internal cardinality (user IDs, tenant IDs, queue contents) leaks via labels; reveals service topology.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Observability".to_string(),
            query: format!(
                "site:{} (inurl:/grafana | inurl:/d/ | intitle:\"Grafana\" intext:\"Welcome to Grafana\")",
                clean_domain
            ),
            description: "Exposed Grafana dashboards".to_string(),
            impact: "Default Grafana credentials (admin/admin) common; dashboards reveal internal metrics, query annotations may include access tokens.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Observability".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | inurl:/_plugin/kibana | inurl:/app/kibana | inurl:/_cat/indices)",
                clean_domain
            ),
            description: "Exposed Kibana / Elasticsearch interface".to_string(),
            impact: "Direct access to indexed logs — PII, session tokens, internal events, debugging payloads.".to_string(),
        });

        // -------- Mobile app configuration leakage --------
        dorks.push(GoogleDork {
            category: "Mobile Config".to_string(),
            query: format!(
                "site:{} (ext:plist intext:\"<key>API_KEY</key>\" | ext:plist intext:\"<key>CLIENT_SECRET</key>\" | inurl:GoogleService-Info.plist)",
                clean_domain
            ),
            description: "Exposed iOS .plist with embedded API keys".to_string(),
            impact: "iOS app config plists routinely embed Firebase API keys, OAuth client secrets, and analytics tokens.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Mobile Config".to_string(),
            query: format!(
                "site:{} (inurl:google-services.json | inurl:AndroidManifest.xml | inurl:strings.xml intext:\"client_id\" | inurl:apikey.properties)",
                clean_domain
            ),
            description: "Exposed Android app configuration".to_string(),
            impact: "google-services.json contains the Firebase project ID + API key; strings.xml often contains hard-coded API tokens.".to_string(),
        });

        // -------- IDE / project metadata --------
        dorks.push(GoogleDork {
            category: "IDE Metadata".to_string(),
            query: format!(
                "site:{} (inurl:/.idea/workspace.xml | inurl:/.idea/dataSources.xml | inurl:/.vscode/launch.json | inurl:/.vscode/settings.json | ext:iml | inurl:.project | inurl:.classpath)",
                clean_domain
            ),
            description: "Exposed JetBrains / VS Code / Eclipse project files".to_string(),
            impact: "dataSources.xml contains plaintext database connection details; launch.json may embed runtime env vars.".to_string(),
        });

        // -------- NPM / package manager exposure --------
        dorks.push(GoogleDork {
            category: "Package Manager".to_string(),
            query: format!(
                "site:{} (inurl:.npmrc | inurl:.yarnrc | inurl:.yarnrc.yml | inurl:pip.conf | inurl:.netrc | inurl:auth.json | inurl:.composer/auth.json)",
                clean_domain
            ),
            description: "Exposed package manager credentials files".to_string(),
            impact: "These files contain auth tokens for npm/yarn/pip/Composer registries — enables supply-chain attacks on internal packages.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Package Manager".to_string(),
            query: format!(
                "site:{} (inurl:package-lock.json | inurl:yarn.lock | inurl:Pipfile.lock | inurl:Gemfile.lock | inurl:composer.lock | inurl:Cargo.lock | inurl:go.sum) intext:\"//npm\" | intext:\"git+ssh://\" | intext:\"git+https://\"",
                clean_domain
            ),
            description: "Lock files with credentials embedded in dependency URLs".to_string(),
            impact: "Lock files often retain `https://user:token@host/repo` URLs from internal package resolution.".to_string(),
        });

        // -------- Webhook URLs (per-token, irrevocable until rotated) --------
        dorks.push(GoogleDork {
            category: "Webhook Leakage".to_string(),
            query: format!(
                "site:{} (\"hooks.slack.com/services/\" | \"discord.com/api/webhooks/\" | \"discordapp.com/api/webhooks/\" | \"outlook.office.com/webhook/\" | \"office.com/webhookb2/\")",
                clean_domain
            ),
            description: "Exposed Slack / Discord / Teams webhook URLs".to_string(),
            impact: "Webhook URLs are bearer credentials — anyone who reads them can post into the target channel until rotated.".to_string(),
        });

        // -------- Log files (request bodies, stack traces, tokens) --------
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log intext:\"Authorization: Bearer\" | ext:log intext:\"set-cookie:\" | ext:log intext:\"password=\" | ext:log intext:\"X-Api-Key:\")",
                clean_domain
            ),
            description: "Exposed log files containing auth headers / secrets".to_string(),
            impact: "Authorization headers and Set-Cookie values logged in plaintext enable direct session/account takeover.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (inurl:/storage/logs | inurl:/var/log | inurl:laravel.log | inurl:error_log | inurl:debug.log | inurl:access_log) ext:log",
                clean_domain
            ),
            description: "Exposed application log files".to_string(),
            impact: "Logs typically contain stack traces revealing internal paths, query parameters with PII, and occasional credentials.".to_string(),
        });

        // -------- Webpack source maps actually being served --------
        dorks.push(GoogleDork {
            category: "Source Maps".to_string(),
            query: format!(
                "site:{} (ext:map intext:\"sourcesContent\" | ext:map intext:\"webpack://\" | inurl:.js.map | inurl:.css.map)",
                clean_domain
            ),
            description: "Exposed JavaScript / CSS source maps".to_string(),
            impact: "Source maps reconstruct full original source code including comments, hard-coded keys, internal endpoints, and pre-minified secrets.".to_string(),
        });

        // -------- Backup file extensions (broad sweep) --------
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp | ext:swo | ext:tmp | ext:temp | ext:inc | ext:cache)",
                clean_domain
            ),
            description: "Generic backup / temp file extensions".to_string(),
            impact: "Editor swap files and *.bak frequently contain unsanitized source code with credentials.".to_string(),
        });

        // -------- Atlassian / Confluence / Notion internal docs --------
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "(site:*.atlassian.net | site:notion.so | site:notion.site | site:gitbook.io | site:readme.io) \"{}\"",
                clean_domain
            ),
            description: "Publicly indexed internal wiki / docs pages mentioning the domain".to_string(),
            impact: "Internal docs leak architecture diagrams, runbooks, credentials, support handover details.".to_string(),
        });

        // -------- Public Postman / Apiary collections --------
        dorks.push(GoogleDork {
            category: "API Collections".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:apiary.io | site:stoplight.io) \"{}\"",
                clean_domain
            ),
            description: "Public Postman / Apiary / Stoplight collections".to_string(),
            impact: "Published API collections frequently contain real Bearer tokens, internal endpoint URLs, and example request bodies with sensitive data.".to_string(),
        });

        // -------- CI artifact / job storage exposure --------
        dorks.push(GoogleDork {
            category: "CI Artifacts".to_string(),
            query: format!(
                "(site:circleci.com/api | site:github.com/*/actions/runs | site:gitlab.com/*/-/jobs | site:travis-ci.com | site:codecov.io) \"{}\"",
                clean_domain
            ),
            description: "Public CI build outputs / coverage reports".to_string(),
            impact: "Build logs and coverage reports leak source file paths, env vars with secrets masked weakly, and dependency chains.".to_string(),
        });

        // -------- Cloud bucket index pages (Listing-bucket-result) --------
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net | site:r2.cloudflarestorage.com | site:digitaloceanspaces.com) intitle:\"Index of\" \"{}\"",
                clean_domain
            ),
            description: "Directory-listing-enabled cloud buckets".to_string(),
            impact: "Listable buckets allow systematic file enumeration; commonly include backups, customer exports, and analytics dumps.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} (intitle:\"Index of /\" | intext:\"Parent Directory\" | intext:\"<title>Directory listing for\")",
                clean_domain
            ),
            description: "Open directory listings on the target itself".to_string(),
            impact: "Directory listing enables file enumeration without guessing — leaks backups, logs, and stale assets.".to_string(),
        });

        // -------- GraphQL schema / introspection --------
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (intitle:\"GraphiQL\" | intitle:\"GraphQL Playground\" | inurl:/graphql intext:\"__schema\" | inurl:/graphiql | inurl:/playground)",
                clean_domain
            ),
            description: "Exposed GraphQL IDE / introspection".to_string(),
            impact: "GraphiQL discloses the full schema (types, mutations, internal fields). Introspection often left on in production.".to_string(),
        });

        // -------- Email / mailer credentials leak --------
        dorks.push(GoogleDork {
            category: "Email Config".to_string(),
            query: format!(
                "site:{} (intext:\"SMTP_PASSWORD=\" | intext:\"MAIL_PASSWORD=\" | intext:\"SENDGRID_API_KEY=\" | intext:\"MAILGUN_API_KEY=\" | intext:\"POSTMARK_SERVER_TOKEN=\")",
                clean_domain
            ),
            description: "Indexed config exposing SMTP / mailer credentials".to_string(),
            impact: "Mailer credentials enable phishing from the domain's reputation and password-reset interception.".to_string(),
        });

        // -------- IaaS / metadata pivot indicators --------
        dorks.push(GoogleDork {
            category: "Cloud Metadata".to_string(),
            query: format!(
                "site:{} (intext:\"AKIA\" | intext:\"ASIA\" | intext:\"aws_access_key_id\" | intext:\"aws_secret_access_key\")",
                clean_domain
            ),
            description: "AWS access key identifiers in indexed content".to_string(),
            impact: "AKIA / ASIA prefixes only appear in real AWS access keys — every match is a leaked credential.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Metadata".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN PRIVATE KEY-----\" intext:\"service_account\" | intext:\"\\\"type\\\": \\\"service_account\\\"\" | intext:\"private_key_id\")",
                clean_domain
            ),
            description: "Indexed Google Cloud service-account JSON keys".to_string(),
            impact: "Service-account JSON keys grant the project-level permissions of the bound SA — frequently editor or owner.".to_string(),
        });

        // -------- Bug-bounty disclosure cross-reference --------
        dorks.push(GoogleDork {
            category: "Disclosure Programs".to_string(),
            query: format!(
                "(site:hackerone.com/reports | site:bugcrowd.com/disclosures | site:huntr.dev | site:openbugbounty.org/reports) \"{}\"",
                clean_domain
            ),
            description: "Public disclosure reports referencing the target".to_string(),
            impact: "Previously-disclosed reports may not have been fully remediated; gives shape of historical attack surface.".to_string(),
        });

        // -------- Source-code search engines --------
        dorks.push(GoogleDork {
            category: "Code Search".to_string(),
            query: format!(
                "(site:grep.app | site:searchcode.com | site:sourcegraph.com | site:publicwww.com) \"{}\"",
                clean_domain
            ),
            description: "Public code-search engines indexing references to the domain".to_string(),
            impact: "Search engines like sourcegraph and grep.app surface every public repo mentioning the domain — useful for finding misconfigured CI, abandoned forks, and leaked test fixtures.".to_string(),
        });

        // -------- Generic high-signal credential strings --------
        dorks.push(GoogleDork {
            category: "Credential Strings".to_string(),
            query: format!(
                "site:{} (intext:\"client_secret\" intext:\"client_id\" | intext:\"refresh_token\" intext:\"access_token\" | intext:\"BEGIN DSA PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\")",
                clean_domain
            ),
            description: "Indexed pages with OAuth and key pair markers".to_string(),
            impact: "Each prefix is unique enough to indicate a real credential dump rather than documentation.".to_string(),
        });

        // -------- Wayback / cache references for historical leaks --------
        dorks.push(GoogleDork {
            category: "Historical Snapshots".to_string(),
            query: format!(
                "(site:web.archive.org | site:cachedview.com) \"{}\" (inurl:/admin | inurl:/.env | inurl:/.git | inurl:wp-config)",
                clean_domain
            ),
            description: "Archived snapshots of previously-exposed sensitive paths".to_string(),
            impact: "Historical snapshots can preserve credentials and pages that were briefly published — still useful if secrets weren't rotated.".to_string(),
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
