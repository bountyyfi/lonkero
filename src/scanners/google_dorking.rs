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

        // ---------------------------------------------------------------
        // Additional high-signal recon dorks (2026-08)
        //
        // Every new query below is scoped to `site:{clean_domain}` OR
        // pairs a globally-searchable operator with the target domain
        // as a literal. The goal is high signal-to-noise: each dork
        // aims at a concrete, exploitable finding (leaked credential,
        // exposed admin panel, unauthenticated data store, indexed
        // sensitive file) rather than "might be interesting".
        // ---------------------------------------------------------------

        // .env / .envrc leaks (Rails/Node/Django/Laravel)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:env | ext:envrc | inurl:/.env) -inurl:example",
                clean_domain
            ),
            description: ".env / .envrc files served publicly (excluding *.example)".to_string(),
            impact: "Environment files routinely contain DB URIs, AWS keys, Stripe/Twilio secrets, JWT signing keys".to_string(),
        });

        // Exposed .git directory listings
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} inurl:.git intitle:\"Index of /.git\"",
                clean_domain
            ),
            description: "Publicly listed .git/ directory - full repo dumpable".to_string(),
            impact: "Attacker can reconstruct full source tree + commit history (git-dumper); pre-baked credentials, keys, past secrets".to_string(),
        });

        // Exposed .svn / .hg / .bzr / CVS directories
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.svn/entries | inurl:.hg/store | inurl:CVS/Entries)",
                clean_domain
            ),
            description: "Legacy VCS metadata exposed".to_string(),
            impact: "Same source-reconstruction risk as .git leaks".to_string(),
        });

        // Exposed .DS_Store (macOS dev artifact)
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} inurl:.DS_Store intitle:\"Index of\"",
                clean_domain
            ),
            description: ".DS_Store files - reveal directory structure".to_string(),
            impact: "Enumerates hidden files/paths the site owner assumed were private (backups, admin dirs, staging)".to_string(),
        });

        // SQL dumps and DB backups
        dorks.push(GoogleDork {
            category: "Database Leaks".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:sql.gz | ext:sql.bak | ext:mdb) intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"password\"",
                clean_domain
            ),
            description: "SQL dumps with schema or INSERT statements".to_string(),
            impact: "Full user tables including hashed passwords, PII, session tokens, payment records".to_string(),
        });

        // NoSQL / MongoDB / Redis dumps
        dorks.push(GoogleDork {
            category: "Database Leaks".to_string(),
            query: format!(
                "site:{} (ext:bson | ext:rdb | ext:mongorc | inurl:mongodump | inurl:dump.rdb)",
                clean_domain
            ),
            description: "MongoDB / Redis backup artifacts".to_string(),
            impact: "Complete NoSQL state including credentials collections and session stores".to_string(),
        });

        // Rails secrets / master.key / credentials
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:config/master.key | inurl:config/secrets.yml | inurl:config/credentials.yml.enc | inurl:config/database.yml)",
                clean_domain
            ),
            description: "Rails master.key / secrets.yml / database.yml exposed".to_string(),
            impact: "Rails master.key decrypts all encrypted credentials (production DB, third-party API keys)".to_string(),
        });

        // Django settings / secret_key
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:settings.py | inurl:local_settings.py) intext:\"SECRET_KEY\"",
                clean_domain
            ),
            description: "Django settings.py with SECRET_KEY".to_string(),
            impact: "Django SECRET_KEY compromise = session forgery + arbitrary pickle deserialization on some setups".to_string(),
        });

        // Laravel .env / storage debug
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.env intext:\"APP_KEY=base64\" | inurl:/storage/logs/laravel.log)",
                clean_domain
            ),
            description: "Laravel APP_KEY or exposed laravel.log".to_string(),
            impact: "APP_KEY reveals cookie/session decryption; laravel.log leaks stack traces + query bindings".to_string(),
        });

        // Symfony parameters / .env
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:app/config/parameters.yml | inurl:config/packages/prod)",
                clean_domain
            ),
            description: "Symfony parameters.yml / prod configs".to_string(),
            impact: "Database DSN, secret tokens, third-party keys typically live here".to_string(),
        });

        // Spring Boot actuator endpoints exposed
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/beans)",
                clean_domain
            ),
            description: "Spring Boot Actuator env/heapdump/configprops".to_string(),
            impact: "/env leaks datasource passwords; /heapdump gives raw process memory including tokens; well-known RCE surface".to_string(),
        });

        // Django/Werkzeug/Flask debug pages
        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} (intext:\"Traceback (most recent call last)\" intext:\"Werkzeug Debugger\" | intitle:\"Django\" intext:\"DEBUG = True\")",
                clean_domain
            ),
            description: "Werkzeug / Flask / Django DEBUG=True pages".to_string(),
            impact: "Werkzeug debugger = interactive Python shell on the target (unauth RCE)".to_string(),
        });

        // Laravel Ignition / whoops debug pages
        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} (intext:\"Ignition\" intext:\"env variables\" | intext:\"Whoops! There was an error\" intext:\"vendor/laravel\")",
                clean_domain
            ),
            description: "Laravel Ignition / Whoops debug pages".to_string(),
            impact: "Historical CVE-2021-3129 gives unauth RCE via Ignition; leaks env vars regardless".to_string(),
        });

        // Rails debug / better_errors
        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"BetterErrors\" | intext:\"web-console\" intext:\"Rails.application\")",
                clean_domain
            ),
            description: "Rails web-console / better_errors accessible".to_string(),
            impact: "In-browser IRB context on the app process = code execution as the web user".to_string(),
        });

        // Adminer / phpMyAdmin / pgAdmin login pages
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" intext:\"Welcome to phpMyAdmin\" | intitle:\"Adminer\" | intitle:\"pgAdmin\" inurl:login)",
                clean_domain
            ),
            description: "Database admin UIs reachable from the internet".to_string(),
            impact: "Direct credential brute-force surface; historical auth-bypass CVEs; often deployed with default creds".to_string(),
        });

        // Elasticsearch / Kibana public endpoints
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" inurl:app/home | inurl:_cat/indices | inurl:_cluster/health | inurl:_search)",
                clean_domain
            ),
            description: "Kibana / raw Elasticsearch HTTP API".to_string(),
            impact: "Unauth ES cluster = read any index (logs frequently contain tokens, PII, request bodies)".to_string(),
        });

        // Grafana anonymous access
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:/login | inurl:/api/datasources | intext:\"grafana.session\")",
                clean_domain
            ),
            description: "Grafana login pages / API".to_string(),
            impact: "Anonymous dashboards leak infra metrics; CVE-2021-43798 gave arbitrary file read".to_string(),
        });

        // Prometheus / Alertmanager exposed
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (inurl:/metrics intext:\"# HELP\" intext:\"# TYPE\" | inurl:/graph intitle:\"Prometheus\" | inurl:/api/v1/alerts)",
                clean_domain
            ),
            description: "Prometheus /metrics or /graph, or Alertmanager".to_string(),
            impact: "Metrics leak internal service topology, hostnames, request paths; some exporters include secrets in labels".to_string(),
        });

        // Jenkins - script console, build history
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/script | inurl:/computer | inurl:/asynchPeople | inurl:/manage)",
                clean_domain
            ),
            description: "Jenkins dashboard / script console".to_string(),
            impact: "/script gives Groovy execution as the Jenkins user; build logs regularly contain secrets".to_string(),
        });

        // Kubernetes dashboard / Kubelet
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/api/v1/namespaces | inurl:/apis/apps/v1)",
                clean_domain
            ),
            description: "Kubernetes dashboard or unauth API".to_string(),
            impact: "Cluster-wide read frequently leaks secrets, configmaps, service accounts; sometimes exec into pods".to_string(),
        });

        // Rancher / Portainer / Traefik
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Rancher\" | intitle:\"Portainer\" inurl:/#/auth | intitle:\"Traefik\")",
                clean_domain
            ),
            description: "Container orchestration UIs".to_string(),
            impact: "Full container fleet control; Traefik dashboard leaks routing config = internal service map".to_string(),
        });

        // Splunk / SolarWinds / ManageEngine
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Splunk\" inurl:/en-US/account/login | intitle:\"ManageEngine\" | intitle:\"SolarWinds\")",
                clean_domain
            ),
            description: "Enterprise monitoring / ITSM logins".to_string(),
            impact: "High-value credentialed targets, historically CVE-heavy (Splunk RCEs, ManageEngine ADSelfService, SolarWinds Orion)".to_string(),
        });

        // OWA / Exchange / SharePoint / Skype
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (inurl:/owa/auth/logon | inurl:/ecp | inurl:/mapi/emsmdb | inurl:/_layouts/15/authenticate.aspx | inurl:/lyncdiscover)",
                clean_domain
            ),
            description: "Exchange OWA/ECP, SharePoint, Skype for Business".to_string(),
            impact: "OWA/ECP historically CVE-heavy (ProxyShell/ProxyNotShell); enterprise credential harvesting surface".to_string(),
        });

        // Confluence / Jira / Bitbucket
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Log in - Confluence\" | inurl:/wiki/spaces | inurl:/rest/api/latest | intitle:\"System Dashboard - Jira\" | inurl:/plugins/servlet/)",
                clean_domain
            ),
            description: "Atlassian self-hosted Confluence/Jira/Bitbucket".to_string(),
            impact: "Multiple critical CVEs (CVE-2022-26134 OGNL RCE, CVE-2023-22515); public spaces often leak internal docs".to_string(),
        });

        // GitLab CE self-hosted
        dorks.push(GoogleDork {
            category: "Admin Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"GitLab\" inurl:/users/sign_in | inurl:/explore/projects | inurl:/api/v4/projects)",
                clean_domain
            ),
            description: "Self-hosted GitLab CE".to_string(),
            impact: "Snippets/wikis often carry secrets; CVE-2023-7028 gave account takeover via password-reset to attacker email".to_string(),
        });

        // Router / firewall / VPN portals
        dorks.push(GoogleDork {
            category: "Network Devices".to_string(),
            query: format!(
                "site:{} (intitle:\"GlobalProtect Portal\" | intitle:\"FortiGate\" inurl:/remote/login | inurl:/sslvpn | intitle:\"Citrix\" inurl:/logon | intitle:\"Pulse Connect Secure\")",
                clean_domain
            ),
            description: "SSL-VPN / firewall admin portals".to_string(),
            impact: "Every major SSL-VPN vendor has had unauth RCE (PAN-OS, FortiOS, Citrix, Pulse) - even fingerprinting is prep for exploitation".to_string(),
        });

        // MinIO / S3-compatible storage admin
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Browser\" | inurl:/minio/health | inurl:/minio/webrpc)",
                clean_domain
            ),
            description: "MinIO web console / health".to_string(),
            impact: "Bucket enumeration; several unauth admin API CVEs; often used to store backups and CI artifacts".to_string(),
        });

        // Firebase real-time DB open reads
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (site:firebaseio.com | site:firebasedatabase.app) inurl:.json",
                clean_domain
            ),
            description: "Firebase real-time DB roots with .json read".to_string(),
            impact: "World-readable Firebase = full user table (auth tokens, PII) with a single curl".to_string(),
        });

        // Firebase Storage & Firestore
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (site:firebasestorage.googleapis.com | site:firestore.googleapis.com)",
                clean_domain
            ),
            description: "Firebase Storage / Firestore public buckets".to_string(),
            impact: "Uploaded documents, KYC images, user avatars, sometimes exports".to_string(),
        });

        // Google Cloud Functions / App Engine / Cloud Run
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" (site:cloudfunctions.net | site:appspot.com | site:run.app)",
                clean_domain
            ),
            description: "GCP Cloud Functions / App Engine / Cloud Run endpoints".to_string(),
            impact: "Often unauthenticated microservices with elevated GCP IAM; frequent SSRF & IAM-abuse targets".to_string(),
        });

        // AWS Lambda API Gateway / Amplify
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" (site:execute-api.us-east-1.amazonaws.com | site:execute-api.eu-west-1.amazonaws.com | site:amplifyapp.com)",
                clean_domain
            ),
            description: "AWS API Gateway / Amplify hosted apps".to_string(),
            impact: "Direct backend endpoints bypass CDN protections and reveal Lambda function names".to_string(),
        });

        // Azure hosted services
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" (site:azurewebsites.net | site:azurefd.net | site:azurestaticapps.net | site:trafficmanager.net)",
                clean_domain
            ),
            description: "Azure App Service / Front Door / Static Web Apps / Traffic Manager".to_string(),
            impact: "Enumerates cloud subdomains that may bypass on-prem WAF or expose staging slots".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z) (inurl:backup | inurl:bak | inurl:dump | inurl:archive | inurl:old)",
                clean_domain
            ),
            description: "Backup/archive files served by the web root".to_string(),
            impact: "Often contain full webroot, DB dumps, or config with cleartext credentials".to_string(),
        });

        // Editor/temp/swap files
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:swp | ext:swo | ext:tmp | ext:~ | inurl:.orig | inurl:.save | inurl:.bak)",
                clean_domain
            ),
            description: "Editor backup / swap / .orig / .save files".to_string(),
            impact: "Vim/nano swap files reveal original source of endpoints (often with secrets in the diff being edited)".to_string(),
        });

        // Log files (application + server)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:log intext:\"password\" | ext:log intext:\"stack trace\" | ext:log intext:\"Authorization: Bearer\")",
                clean_domain
            ),
            description: "Logs containing passwords, stack traces, bearer tokens".to_string(),
            impact: "Tokens in Authorization headers, DB error messages with query strings, credential resets in transit".to_string(),
        });

        // .htaccess / .htpasswd / server config
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:htpasswd | inurl:.htaccess | inurl:web.config | inurl:nginx.conf | inurl:php.ini)",
                clean_domain
            ),
            description: "Web server config files".to_string(),
            impact: ".htpasswd contains bcrypt hashes; web.config leaks connection strings; nginx.conf reveals upstreams and rewrites".to_string(),
        });

        // WordPress specific dumps
        dorks.push(GoogleDork {
            category: "CMS Leaks".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.txt | inurl:wp-content/backup | inurl:wp-content/uploads/backup)",
                clean_domain
            ),
            description: "WordPress config backups / plugin backup dumps".to_string(),
            impact: "wp-config leaks DB credentials + AUTH_KEY (site takeover); backup plugins often dump entire site DB".to_string(),
        });

        // WordPress user enumeration + REST API leaks
        dorks.push(GoogleDork {
            category: "CMS Leaks".to_string(),
            query: format!(
                "site:{} (inurl:/wp-json/wp/v2/users | inurl:?author=1 | inurl:xmlrpc.php)",
                clean_domain
            ),
            description: "WordPress user enumeration endpoints".to_string(),
            impact: "Enumerates valid usernames for brute force; xmlrpc.php amplifies attacks".to_string(),
        });

        // Drupal / Joomla config leaks
        dorks.push(GoogleDork {
            category: "CMS Leaks".to_string(),
            query: format!(
                "site:{} (inurl:sites/default/settings.php.bak | inurl:configuration.php.bak | inurl:configuration.php~ | inurl:CHANGELOG.txt intext:Drupal)",
                clean_domain
            ),
            description: "Drupal settings.php / Joomla configuration.php backups + version disclosure".to_string(),
            impact: "Reveals DB creds and framework version needed to pick the right CVE".to_string(),
        });

        // GraphQL endpoints + introspection
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/altair)",
                clean_domain
            ),
            description: "GraphQL / GraphiQL / Playground endpoints".to_string(),
            impact: "Introspection reveals full schema (all queries + mutations = full attack surface map)".to_string(),
        });

        // SOAP / WSDL / RPC endpoints
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:asmx | inurl:?wsdl | inurl:/services/ | inurl:/soap)",
                clean_domain
            ),
            description: "SOAP services and WSDLs".to_string(),
            impact: "WSDL enumerates all methods; SOAP endpoints commonly vulnerable to XXE and auth bypass".to_string(),
        });

        // Sentry DSNs indexed
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" intext:\"@sentry.io/\" | intext:\"@o[0-9]+.ingest.sentry.io/\"",
                clean_domain
            ),
            description: "Sentry DSN URLs referenced in indexed content".to_string(),
            impact: "Public DSN alone is low-impact; leaked private DSN with auth token allows event injection / release manipulation".to_string(),
        });

        // Slack webhooks / workspaces
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (intext:\"hooks.slack.com/services/\" | site:slack.com inurl:archives)",
                clean_domain
            ),
            description: "Slack incoming webhooks and workspace archives".to_string(),
            impact: "Webhook = anyone can post as the app into an internal channel (phishing / notification spoofing)".to_string(),
        });

        // Notion / Confluence Cloud / Airtable public pages
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (site:notion.site | site:notion.so | site:atlassian.net/wiki | site:airtable.com)",
                clean_domain
            ),
            description: "Public Notion/Confluence Cloud/Airtable pages".to_string(),
            impact: "Public-by-mistake internal handbooks, onboarding docs with default creds, customer lists".to_string(),
        });

        // Postman / SwaggerHub / Stoplight public workspaces
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (site:postman.com | site:documenter.getpostman.com | site:app.swaggerhub.com | site:stoplight.io)",
                clean_domain
            ),
            description: "Public Postman / SwaggerHub / Stoplight collections".to_string(),
            impact: "Live API tokens frequently pinned into public Postman collections as environment vars".to_string(),
        });

        // Docker Hub / GitHub Packages / ghcr images
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (site:hub.docker.com | site:ghcr.io | site:quay.io)",
                clean_domain
            ),
            description: "Container registry images referencing the domain".to_string(),
            impact: "Docker layers often embed baked credentials, SSH keys, /root/.aws/credentials from build time".to_string(),
        });

        // Public S3/CloudFront listing indices
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:s3.amazonaws.com intitle:\"{}\" intext:\"<ListBucketResult\"",
                clean_domain
            ),
            description: "S3 bucket XML listings mentioning target".to_string(),
            impact: "Public LIST permission = enumerate every object; often includes backups the owner forgot".to_string(),
        });

        // JWT tokens embedded in URLs
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "site:{} inurl:eyJhbGciOiJ",
                clean_domain
            ),
            description: "JWT (starts with base64 header \"eyJ\") embedded in indexed URLs".to_string(),
            impact: "Password-reset / magic-link / API-key JWTs cached by search engines are directly replayable".to_string(),
        });

        // API keys / tokens visible in URL params
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "site:{} (inurl:apikey= | inurl:api_key= | inurl:auth_token= | inurl:access_token= | inurl:client_secret= | inurl:password=)",
                clean_domain
            ),
            description: "Credentials in query strings indexed by search".to_string(),
            impact: "Values leak into referer, browser history, server access logs, and CDN caches - often long-lived".to_string(),
        });

        // Password-reset / signup magic links
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "site:{} (inurl:reset_token= | inurl:reset_password_token= | inurl:confirmation_token= | inurl:invitation_token=)",
                clean_domain
            ),
            description: "Password-reset / invitation tokens indexed".to_string(),
            impact: "Cached reset tokens = account takeover without owning the mailbox".to_string(),
        });

        // Directory listing (Apache / nginx / IIS)
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (\"Parent Directory\" | \"Last modified\")",
                clean_domain
            ),
            description: "Open directory listing".to_string(),
            impact: "Enumerates all files in the directory; typically leads to finding one of the sensitive-file dorks above".to_string(),
        });

        // Trace / axd / elmah error logs (ASP.NET)
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (inurl:elmah.axd | inurl:trace.axd | inurl:webservices/elmah.axd)",
                clean_domain
            ),
            description: "ELMAH / trace.axd exposed on ASP.NET".to_string(),
            impact: "Full request logs including cookies + Authorization headers of past users".to_string(),
        });

        // IIS webshell / handler artifacts
        dorks.push(GoogleDork {
            category: "Framework Secrets".to_string(),
            query: format!(
                "site:{} (ext:cshtml intext:@using | ext:vbs intitle:\"Error\" | inurl:aspnet_client)",
                clean_domain
            ),
            description: "ASP.NET server-side view files exposed as text / aspnet_client".to_string(),
            impact: "Server-side code disclosure through misconfigured IIS handlers".to_string(),
        });

        // Docker / Compose / K8s manifests exposed
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:Dockerfile | inurl:kubeconfig | inurl:.kubeconfig | inurl:kustomization.yaml)",
                clean_domain
            ),
            description: "Container / K8s manifests reachable".to_string(),
            impact: "docker-compose commonly contains DB passwords, registry creds; kubeconfig gives cluster admin".to_string(),
        });

        // Terraform state / tfvars leaked
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:terraform.tfstate)",
                clean_domain
            ),
            description: "Terraform state and tfvars".to_string(),
            impact: "tfstate is JSON with every secret, provider credential, and resource attribute in plaintext".to_string(),
        });

        // Ansible vault / inventory
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:group_vars | inurl:host_vars | ext:yml intext:\"$ANSIBLE_VAULT\")",
                clean_domain
            ),
            description: "Ansible inventory / vaulted files".to_string(),
            impact: "Even vault-encrypted files reveal structure; group_vars often unencrypted with DB creds".to_string(),
        });

        // CI/CD config
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.gitlab-ci.yml | inurl:.circleci/config.yml | inurl:Jenkinsfile | inurl:bitbucket-pipelines.yml | inurl:.github/workflows)",
                clean_domain
            ),
            description: "CI/CD pipeline definitions".to_string(),
            impact: "Reveals build-time secrets, deploy targets, internal image registries, artifact paths".to_string(),
        });

        // npm / yarn / composer manifests
        dorks.push(GoogleDork {
            category: "Dependency Manifests".to_string(),
            query: format!(
                "site:{} (inurl:package.json | inurl:package-lock.json | inurl:composer.json | inurl:requirements.txt | inurl:Gemfile | inurl:go.mod)",
                clean_domain
            ),
            description: "Language dependency manifests".to_string(),
            impact: "Exact library versions = pinpoint known CVEs; sometimes leaks private registry URLs with basic-auth".to_string(),
        });

        // Sitemap / robots hints
        dorks.push(GoogleDork {
            category: "Recon Aids".to_string(),
            query: format!(
                "site:{} (inurl:robots.txt | inurl:sitemap.xml | inurl:sitemap_index.xml) intext:\"Disallow\"",
                clean_domain
            ),
            description: "robots.txt / sitemap.xml surfaces".to_string(),
            impact: "Disallow entries advertise the exact admin/staging paths the owner considers private".to_string(),
        });

        // .well-known probing
        dorks.push(GoogleDork {
            category: "Recon Aids".to_string(),
            query: format!(
                "site:{} inurl:/.well-known/ (openid-configuration | oauth-authorization-server | security.txt | apple-app-site-association | assetlinks.json)",
                clean_domain
            ),
            description: ".well-known metadata endpoints".to_string(),
            impact: "OIDC config leaks token endpoints and JWKS; asset-links leak Android app IDs (deep-link hijack)".to_string(),
        });

        // OpenAPI / GraphQL specs served publicly
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:openapi.json | inurl:openapi.yaml | inurl:swagger.json | inurl:schema.graphql)",
                clean_domain
            ),
            description: "Machine-readable API specs".to_string(),
            impact: "Complete endpoint + auth-scheme map (skips crawling entirely)".to_string(),
        });

        // Video / conferencing shared links
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (site:loom.com/share | site:zoom.us/rec | site:vimeo.com | inurl:youtube.com/watch intitle:internal)",
                clean_domain
            ),
            description: "Public recordings of internal meetings".to_string(),
            impact: "Loom/Zoom recordings of engineering demos frequently show credentials on screen".to_string(),
        });

        // Bitbucket / Azure DevOps repos
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "\"{}\" (site:bitbucket.org | site:dev.azure.com | site:visualstudio.com)",
                clean_domain
            ),
            description: "Public Bitbucket / Azure DevOps projects".to_string(),
            impact: "Public-by-accident source often contains org-specific IaC and infra creds".to_string(),
        });

        // ChatGPT / LLM share links leaking prompts
        dorks.push(GoogleDork {
            category: "Third-Party Leaks".to_string(),
            query: format!(
                "\"{}\" (site:chat.openai.com/share | site:chatgpt.com/share | site:claude.ai/share)",
                clean_domain
            ),
            description: "Public ChatGPT / Claude conversation share links".to_string(),
            impact: "Engineers routinely paste config files, API responses, or credentials into shared conversations".to_string(),
        });

        // Sensitive PDF / DOCX with typical labels
        dorks.push(GoogleDork {
            category: "Sensitive Documents".to_string(),
            query: format!(
                "site:{} (ext:pdf | ext:docx | ext:xlsx) (intext:\"Confidential\" | intext:\"Internal Only\" | intext:\"Proprietary\" | intext:\"NDA\" | intext:\"Restricted Distribution\")",
                clean_domain
            ),
            description: "Documents self-labeled as internal / confidential".to_string(),
            impact: "Business docs the owner explicitly did not intend to publish (roadmaps, contracts, financials)".to_string(),
        });

        // PII in indexed documents
        dorks.push(GoogleDork {
            category: "PII Exposure".to_string(),
            query: format!(
                "site:{} (ext:xlsx | ext:csv | ext:txt | ext:pdf) (intext:\"@{}\" intext:\"password\" | intext:\"SSN\" | intext:\"IBAN\" | intext:\"credit card\" | intext:\"passport\")",
                clean_domain, clean_domain
            ),
            description: "Spreadsheets / docs with credentials or PII markers".to_string(),
            impact: "Employee CSVs with plaintext passwords, customer exports with SSN/IBAN/PAN - directly notifiable data breach".to_string(),
        });

        // Private-key headers indexed anywhere
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "\"{}\" (\"BEGIN RSA PRIVATE KEY\" | \"BEGIN OPENSSH PRIVATE KEY\" | \"BEGIN EC PRIVATE KEY\" | \"BEGIN PGP PRIVATE KEY BLOCK\")",
                clean_domain
            ),
            description: "PEM/PGP private-key blocks indexed anywhere".to_string(),
            impact: "TLS/SSH/GPG private keys are single-file compromises with no recovery path".to_string(),
        });

        // AWS access-key IDs indexed
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "\"{}\" \"AKIA\" (ext:log | ext:txt | ext:env | ext:json | ext:yml | ext:xml)",
                clean_domain
            ),
            description: "AWS access key IDs (AKIA…) in indexed files".to_string(),
            impact: "IAM access-key IDs are 20-char AWS-issued strings; pair with a nearby SECRET_KEY and you own the account".to_string(),
        });

        // Google / Stripe / Twilio-style prefixed keys
        dorks.push(GoogleDork {
            category: "Credential Exposure".to_string(),
            query: format!(
                "\"{}\" (\"AIza\" | \"sk_live_\" | \"sk-ant-\" | \"ghp_\" | \"glpat-\" | \"xoxb-\")",
                clean_domain
            ),
            description: "Prefixed vendor tokens (Google/Stripe/Anthropic/GitHub/GitLab/Slack) mentioning the domain".to_string(),
            impact: "Each prefix uniquely identifies a live credential type - low false-positive, high blast radius".to_string(),
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
