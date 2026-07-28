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
        // High-signal sensitive-information dorks
        // These are query generators for manual review — no automated
        // execution — so additions are additive with zero FP risk to the
        // scanner itself. Each targets a class of finding that is highly
        // impactful when it hits (credentials, keys, dumps, admin surfaces).
        // ==================================================================

        // Exposed .env / dotenv files (Rails, Laravel, Node, Python, ...)
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.staging\" | inurl:\".env.development\" | inurl:\".env.backup\" | inurl:\".env.example\") (intext:\"APP_KEY\" | intext:\"DB_PASSWORD\" | intext:\"AWS_ACCESS_KEY_ID\" | intext:\"SECRET_KEY\" | intext:\"API_KEY\")",
                clean_domain
            ),
            description: "Find exposed dotenv files with real credentials".to_string(),
            impact: "Dotenv files usually contain the DB password, app secret, and third-party API keys — direct app takeover on hit".to_string(),
        });

        // Git repository exposure
        dorks.push(GoogleDork {
            category: "Git Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\" | inurl:\".gitignore\" | inurl:\".git-credentials\" | inurl:\".gitconfig\")",
                clean_domain
            ),
            description: "Find exposed .git repository files".to_string(),
            impact: "Exposed .git allows full source tree reconstruction; .git-credentials/.gitconfig may leak push tokens".to_string(),
        });

        // Cloud provider credentials on disk
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".aws/config\" | inurl:\"credentials.json\" | inurl:\"client_secret.json\" | inurl:\"serviceAccountKey.json\" | inurl:\"firebase-adminsdk\" | inurl:\".boto\" | inurl:\".dockercfg\" | inurl:\"docker/config.json\")",
                clean_domain
            ),
            description: "Find exposed cloud/service-account credential files".to_string(),
            impact: "AWS/GCP/Azure/Firebase credential files grant direct cloud API access; Firebase admin SDK bypasses all Firestore/Storage rules".to_string(),
        });

        // Package-manager / registry auth tokens
        dorks.push(GoogleDork {
            category: "Package Auth Tokens".to_string(),
            query: format!(
                "site:{} (inurl:\".npmrc\" | inurl:\".yarnrc\" | inurl:\".pypirc\" | inurl:\"auth.json\" | inurl:\"pip.conf\" | inurl:\"nuget.config\") (intext:\"_authToken\" | intext:\"password\" | intext:\"api-key\" | intext:\"apikey\")",
                clean_domain
            ),
            description: "Find package manager files with publishing/auth tokens".to_string(),
            impact: "npm/PyPI/Yarn/NuGet publish tokens allow supply-chain package hijack under the org's namespace".to_string(),
        });

        // SSH private keys
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (inurl:\"id_rsa\" | inurl:\"id_dsa\" | inurl:\"id_ecdsa\" | inurl:\"id_ed25519\" | inurl:\".ssh/config\" | inurl:\"authorized_keys\" | inurl:\"known_hosts\" | inurl:\".pem\" | inurl:\".ppk\") (intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"BEGIN OPENSSH PRIVATE KEY\" | intext:\"BEGIN EC PRIVATE KEY\" | intext:\"BEGIN PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find exposed SSH / TLS / PGP private keys".to_string(),
            impact: "Private keys grant direct SSH/TLS/signing access — critical impact on any hit".to_string(),
        });

        // Database & app config files with secrets
        dorks.push(GoogleDork {
            category: "App Config Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php\" | inurl:\"configuration.php\" | inurl:\"config.php.bak\" | inurl:\"config.inc.php\" | inurl:\"LocalSettings.php\" | inurl:\"settings.py\" | inurl:\"local_settings.py\" | inurl:\"application.properties\" | inurl:\"application.yml\" | inurl:\"application-prod.yml\" | inurl:\"web.config\") (intext:\"DB_PASSWORD\" | intext:\"password=\" | intext:\"secret\" | intext:\"SECRET_KEY\" | intext:\"database_password\")",
                clean_domain
            ),
            description: "Find application config files with hardcoded secrets".to_string(),
            impact: "WP/Joomla/Django/Spring/.NET config files typically contain DB passwords and framework secrets used to forge sessions/cookies".to_string(),
        });

        // Database dumps / backups
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:bak | ext:sqlite | ext:sqlite3 | ext:db | ext:mdb) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\" | inurl:\"dump\" | inurl:\"backup\" | inurl:\"export\")",
                clean_domain
            ),
            description: "Find SQL dumps and database backups".to_string(),
            impact: "DB dumps expose entire tables — usually including password hashes, PII, and API tokens".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:gz | ext:tgz | ext:7z | ext:rar) (inurl:\"backup\" | inurl:\"bak\" | inurl:\"old\" | inurl:\"archive\" | inurl:\"www\" | inurl:\"site\" | inurl:\"dump\" | inurl:\"export\")",
                clean_domain
            ),
            description: "Find backup archives of source or data".to_string(),
            impact: "Full-site archives frequently include .env, DB dumps, and source with hardcoded secrets".to_string(),
        });

        // JS source-map exposure
        dorks.push(GoogleDork {
            category: "Source Map Exposure".to_string(),
            query: format!(
                "site:{} (ext:map | inurl:\".js.map\" | inurl:\".css.map\" | inurl:\"main.js.map\" | inurl:\"bundle.js.map\" | inurl:\"vendor.js.map\") intext:\"sourceMappingURL\"",
                clean_domain
            ),
            description: "Find exposed webpack/Rollup source maps".to_string(),
            impact: "Source maps rebuild original TypeScript/JSX including private API endpoints, business-logic guards, and inlined tokens".to_string(),
        });

        // Spring Boot Actuator / debug endpoints
        dorks.push(GoogleDork {
            category: "Actuator / Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/beans\" | inurl:\"/env\" | inurl:\"/heapdump\" | inurl:\"/mappings\" | inurl:\"/dump\" | inurl:\"/trace\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator management endpoints".to_string(),
            impact: "/env exposes secrets; /heapdump dumps memory with live tokens/JWTs; /mappings enumerates hidden routes".to_string(),
        });

        // Prometheus / Go debug endpoints
        dorks.push(GoogleDork {
            category: "Metrics & Debug".to_string(),
            query: format!(
                "site:{} (inurl:\"/metrics\" | inurl:\"/debug/vars\" | inurl:\"/debug/pprof\" | inurl:\"/debug/pprof/heap\" | inurl:\"/debug/pprof/goroutine\" | inurl:\"/-/config\" | inurl:\"/-/reload\" | inurl:\"/prometheus\" | inurl:\"/status/format/json\") -inurl:documentation",
                clean_domain
            ),
            description: "Find exposed Prometheus / Go net/http/pprof / expvar endpoints".to_string(),
            impact: "/debug/pprof allows heap dumps that leak in-memory secrets and JWTs; /metrics leaks internal topology & label PII".to_string(),
        });

        // Framework debug consoles (Django, Flask, Werkzeug, Rails, Symfony, Laravel Ignition)
        dorks.push(GoogleDork {
            category: "Debug Consoles".to_string(),
            query: format!(
                "site:{} (intext:\"Werkzeug Debugger\" | intext:\"You don't have to use Django\" | intext:\"DEBUG = True\" | intext:\"Whoops! There was an error\" | inurl:\"/_profiler\" | inurl:\"/_wdt\" | inurl:\"/_ignition/execute-solution\" | intext:\"Ignition\" intext:\"Laravel\" | intext:\"web-console\" intext:\"Rails\" | intext:\"Exception Details:\" intext:\"Stack Trace:\")",
                clean_domain
            ),
            description: "Find live framework debug consoles (RCE-prone: Werkzeug, Ignition, web-console, Symfony profiler)".to_string(),
            impact: "Werkzeug/Rails web-console/Laravel Ignition debug pages are direct RCE when authenticated PIN is off; Symfony profiler leaks tokens and DB queries".to_string(),
        });

        // Kubernetes / container platform exposure
        dorks.push(GoogleDork {
            category: "Kubernetes / Container".to_string(),
            query: format!(
                "site:{} (inurl:\"/api/v1/namespaces\" | inurl:\"/api/v1/pods\" | inurl:\"/apis/apps/v1\" | inurl:\"/healthz\" | inurl:\"/readyz\" | inurl:\"/livez\" | inurl:\"/version\" intext:\"gitVersion\" | intitle:\"Kubernetes Dashboard\" | inurl:\"/kubelet\" | inurl:\"/dashboard/\") intext:\"kind\" intext:\"apiVersion\"",
                clean_domain
            ),
            description: "Find exposed Kubernetes API / kubelet / dashboard surfaces".to_string(),
            impact: "Unauthenticated k8s API/kubelet is full cluster takeover; the dashboard often runs privileged".to_string(),
        });

        // Docker Registry / container registries left open
        dorks.push(GoogleDork {
            category: "Container Registry".to_string(),
            query: format!(
                "site:{} (inurl:\"/v2/_catalog\" | inurl:\"/v2/\" intext:\"repositories\" | inurl:\"/artifactory/api/repositories\" | inurl:\"/harbor/api\" | inurl:\"/api/v0/repositories\")",
                clean_domain
            ),
            description: "Find exposed Docker Registry / Harbor / Artifactory catalog endpoints".to_string(),
            impact: "Anonymous registry read exposes internal image names; often paired with anonymous pull that leaks proprietary code and baked-in secrets".to_string(),
        });

        // Elasticsearch / Kibana / OpenSearch open access
        dorks.push(GoogleDork {
            category: "Search Cluster".to_string(),
            query: format!(
                "site:{} (inurl:\"/_cluster/health\" | inurl:\"/_cat/indices\" | inurl:\"/_cat/nodes\" | inurl:\"/_search\" | inurl:\"/_all/_search\" | inurl:\"/_snapshot\" | inurl:\"/app/kibana\" | inurl:\"/app/discover\" | intitle:\"Kibana\") intext:\"cluster_name\" | intext:\"number_of_nodes\"",
                clean_domain
            ),
            description: "Find open Elasticsearch/OpenSearch clusters and Kibana instances".to_string(),
            impact: "Open ES clusters routinely leak entire log pipelines including PII, session tokens, and API traces".to_string(),
        });

        // HashiCorp Vault / Consul / etcd / Nomad exposure
        dorks.push(GoogleDork {
            category: "Secret Stores".to_string(),
            query: format!(
                "site:{} (inurl:\"/v1/sys/health\" intext:\"vault\" | inurl:\"/v1/sys/mounts\" | inurl:\"/v1/kv\" | inurl:\"/v1/agent/self\" | inurl:\"/v1/catalog/services\" | inurl:\"/v2/keys\" | inurl:\"/v1/status/leader\") -intext:documentation",
                clean_domain
            ),
            description: "Find exposed HashiCorp Vault / Consul / etcd / Nomad management APIs".to_string(),
            impact: "An unsealed Vault or open Consul KV is direct dumping of every secret managed by the org".to_string(),
        });

        // Jenkins / CI plane exposure
        dorks.push(GoogleDork {
            category: "CI / Build Servers".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:\"/jenkins\" | inurl:\"/script\" intext:\"Groovy\" | inurl:\"/manage\" intext:\"Jenkins\" | inurl:\"/asynchPeople\" | inurl:\"/computer/\" | intitle:\"TeamCity\" | intitle:\"Buildbot\" | intitle:\"GoCD\" | intitle:\"Drone\" | inurl:\"/actuator/gateway/routes\")",
                clean_domain
            ),
            description: "Find exposed CI build servers (Jenkins/TeamCity/GoCD/Drone)".to_string(),
            impact: "Anonymous Jenkins with /script access is direct RCE as the build agent; build logs typically contain secrets".to_string(),
        });

        // CI-config leaks in-tree (usually contain secret references, sometimes literal tokens)
        dorks.push(GoogleDork {
            category: "CI Config Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".travis.yml\" | inurl:\".circleci/config.yml\" | inurl:\".gitlab-ci.yml\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\"azure-pipelines.yml\" | inurl:\"Jenkinsfile\" | inurl:\".github/workflows/\") (intext:\"secret\" | intext:\"token\" | intext:\"password\" | intext:\"api_key\" | intext:\"AWS_\")",
                clean_domain
            ),
            description: "Find CI/CD pipeline configs referencing (or embedding) secrets".to_string(),
            impact: "Pipeline files reveal deployment topology, and inexperienced authors sometimes commit literal tokens instead of secret references".to_string(),
        });

        // GraphQL introspection + playground
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/api/graphql\" | inurl:\"/playground\" | inurl:\"/altair\" | inurl:\"/voyager\") (intitle:\"GraphiQL\" | intitle:\"GraphQL Playground\" | intext:\"__schema\" | intext:\"IntrospectionQuery\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints with introspection or playground UIs".to_string(),
            impact: "Introspection leaks the entire schema (private mutations included); playgrounds/altair on prod let anyone probe internal ops".to_string(),
        });

        // Salesforce / Zendesk / ServiceNow / Atlassian portal PII surfaces
        dorks.push(GoogleDork {
            category: "SaaS PII Surfaces".to_string(),
            query: format!(
                "(site:atlassian.net | site:jira.com | site:confluence.com | site:servicenow.com | site:zendesk.com | site:freshdesk.com | site:salesforce.com | site:my.salesforce.com | site:force.com) \"{}\"",
                clean_domain
            ),
            description: "Find company mentions in Atlassian/ServiceNow/Zendesk/Salesforce tenants".to_string(),
            impact: "Public JIRA/Confluence/ServiceNow tickets and Salesforce Sites frequently expose internal architecture and customer PII".to_string(),
        });

        // Notion / Slack / Miro / Figma public boards
        dorks.push(GoogleDork {
            category: "Collab Tools".to_string(),
            query: format!(
                "(site:notion.site | site:notion.so | site:miro.com/app/board | site:figma.com/file | site:figma.com/proto | site:slack.com/archives) \"{}\"",
                clean_domain
            ),
            description: "Find publicly shared Notion pages, Miro/Figma boards, and Slack archives".to_string(),
            impact: "Public collab pages routinely expose runbooks with credentials, wiring diagrams, and pre-release feature detail".to_string(),
        });

        // Wayback Machine (deleted-but-remembered)
        dorks.push(GoogleDork {
            category: "Historical Snapshots".to_string(),
            query: format!(
                "site:web.archive.org/web/*/{}/*",
                clean_domain
            ),
            description: "Find Wayback Machine snapshots of the target".to_string(),
            impact: "Wayback preserves pages that have since been access-controlled or deleted — including inadvertently exposed keys/config".to_string(),
        });

        // MediaWiki / DokuWiki config exposure
        dorks.push(GoogleDork {
            category: "Wiki Config".to_string(),
            query: format!(
                "site:{} (inurl:\"LocalSettings.php\" | inurl:\"AdminSettings.php\" | inurl:\"conf/local.php\" | inurl:\"conf/users.auth.php\" | inurl:\"data/pages/playground\")",
                clean_domain
            ),
            description: "Find MediaWiki/DokuWiki config or auth files".to_string(),
            impact: "Wiki settings expose DB creds, admin secrets, and (for DokuWiki) plaintext-hashed user credentials".to_string(),
        });

        // IDE / editor project drop-ins
        dorks.push(GoogleDork {
            category: "IDE Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\".idea/\" | inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources.xml\" | inurl:\".idea/webServers.xml\" | inurl:\".vscode/sftp.json\" | inurl:\".vscode/launch.json\" | inurl:\"sftp-config.json\" | inurl:\".ftpconfig\")",
                clean_domain
            ),
            description: "Find JetBrains/VSCode project files with SFTP/DB credentials".to_string(),
            impact: "IDE drop-ins routinely carry SFTP passwords and database connection strings in cleartext".to_string(),
        });

        // Third-party JS pastes/gists that mention the domain
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitee.com | site:hastebin.com | site:paste.ee | site:justpaste.it | site:controlc.com | site:rentry.co) \"{}\"",
                clean_domain
            ),
            description: "Find code/text pastes on additional paste services".to_string(),
            impact: "Devs regularly paste config files, logs, and stack traces containing live credentials to public paste services".to_string(),
        });

        // AWS console-style asset naming (uploaded to the org, indexed via S3)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:s3.*.amazonaws.com | site:*.s3.amazonaws.com | site:storage.googleapis.com | site:*.blob.core.windows.net | site:*.file.core.windows.net) intext:\"{}\"",
                clean_domain
            ),
            description: "Find AWS/GCP/Azure storage objects indexed under the org name".to_string(),
            impact: "Listable public buckets often contain internal exports, KYC scans, and backup dumps".to_string(),
        });

        // Common exposed status/info pages (phpinfo, server-status, info.php)
        dorks.push(GoogleDork {
            category: "Server Info Pages".to_string(),
            query: format!(
                "site:{} (inurl:\"phpinfo\" | inurl:\"info.php\" | inurl:\"test.php\" | inurl:\"i.php\" | inurl:\"server-status\" | inurl:\"server-info\") (intext:\"PHP Version\" | intext:\"Apache Status\" | intext:\"Server uptime\")",
                clean_domain
            ),
            description: "Find phpinfo() and Apache mod_status endpoints".to_string(),
            impact: "phpinfo leaks env vars (including cloud creds); server-status leaks live request URLs with tokens in query string".to_string(),
        });

        // Log files exposed via web root
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:\"laravel.log\" | inurl:\"error_log\" | inurl:\"access.log\" | inurl:\"debug.log\" | inurl:\"storage/logs/\" | inurl:\"/logs/\") (intext:\"stack trace\" | intext:\"exception\" | intext:\"Bearer \" | intext:\"password\" | intext:\"traceback\")",
                clean_domain
            ),
            description: "Find application/web log files exposed via the web root".to_string(),
            impact: "App logs leak request bodies with credentials, Bearer tokens, session IDs, and PII".to_string(),
        });

        // JWT tokens / hex secrets accidentally indexed
        dorks.push(GoogleDork {
            category: "Token Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"eyJhbGciOi\" | intext:\"Bearer eyJ\" | intext:\"xoxb-\" | intext:\"xoxp-\" | intext:\"AKIA\" intext:\"secret\" | intext:\"sk_live_\" | intext:\"rk_live_\" | intext:\"ghp_\" | intext:\"gho_\" | intext:\"github_pat_\")",
                clean_domain
            ),
            description: "Find pages that inadvertently embed JWT / OAuth / Stripe / GitHub tokens".to_string(),
            impact: "Any hit is a live token — direct credential compromise".to_string(),
        });

        // Postman collections / Insomnia workspaces
        dorks.push(GoogleDork {
            category: "API Workspaces".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:go.postman.co | site:insomnia.rest) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman collections and Insomnia workspaces referencing the org".to_string(),
            impact: "Public collections routinely include environment files with baked-in Bearer tokens, cookies, and internal endpoints".to_string(),
        });

        // Video/screen recordings with credentials in the URL bar
        dorks.push(GoogleDork {
            category: "Recorded Sessions".to_string(),
            query: format!(
                "(site:loom.com | site:youtube.com | site:vimeo.com) \"{}\" (intitle:\"demo\" | intitle:\"walkthrough\" | intitle:\"internal\" | intitle:\"training\")",
                clean_domain
            ),
            description: "Find recorded internal demos/walkthroughs referencing the org".to_string(),
            impact: "Screencasts routinely leak admin URLs, API keys visible in browser dev tools, and workflow secrets".to_string(),
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
