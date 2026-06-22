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

        // ====================================================================
        // EXPOSED VCS METADATA (.git, .svn, .hg) - frequently indexed
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/\" OR inurl:\"/.git/config\" OR inurl:\"/.git/HEAD\")",
                clean_domain
            ),
            description: "Find indexed .git/ directories".to_string(),
            impact: "A reachable .git/ exposes full source history and frequently hardcoded credentials via `git dump`.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:\"/.svn/entries\" OR inurl:\"/.svn/wc.db\" OR inurl:\"/.hg/store\" OR inurl:\"/CVS/Entries\")",
                clean_domain
            ),
            description: "Find indexed SVN/Mercurial/CVS metadata".to_string(),
            impact: "Source-control metadata leaks repository contents and developer identities.".to_string(),
        });

        // ====================================================================
        // ENVIRONMENT / DOTFILES with high-signal content
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Environment Leaks".to_string(),
            query: format!(
                "site:{} (ext:env OR inurl:\"/.env\" OR inurl:\".env.local\" OR inurl:\".env.production\")",
                clean_domain
            ),
            description: "Find indexed .env files".to_string(),
            impact: "`.env` files commonly contain DB credentials, JWT secrets, API keys, and OAuth client secrets.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"AWS_SECRET_ACCESS_KEY\" OR intext:\"DB_PASSWORD\" OR intext:\"DATABASE_URL\" OR intext:\"JWT_SECRET\" OR intext:\"APP_KEY=base64:\")",
                clean_domain
            ),
            description: "Find pages containing common secret variable names".to_string(),
            impact: "Direct content match for canonical secret names indicates leaked configuration.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Environment Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"/wp-config.php\" OR inurl:\"wp-config.bak\" OR inurl:\"wp-config.old\" OR inurl:\"wp-config.txt\" OR inurl:\"wp-config.save\")",
                clean_domain
            ),
            description: "Find WordPress config files left in webroot".to_string(),
            impact: "wp-config.php variants leak DB credentials and AUTH_KEYs allowing forged sessions.".to_string(),
        });

        // ====================================================================
        // DATABASE BACKUPS / DUMPS
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql OR ext:sqlite OR ext:sqlitedb OR ext:db OR ext:mdb OR ext:bak) (intext:\"INSERT INTO\" OR intext:\"CREATE TABLE\" OR intext:\"DROP TABLE\")",
                clean_domain
            ),
            description: "Find SQL dumps and database files".to_string(),
            impact: "Database backups expose entire schema and customer data, including hashed credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:gz OR ext:tar OR ext:zip OR ext:rar OR ext:7z) (inurl:backup OR inurl:dump OR inurl:export)",
                clean_domain
            ),
            description: "Find compressed archives in backup/export/dump paths".to_string(),
            impact: "Archive downloads in backup paths frequently contain database snapshots and credentials.".to_string(),
        });

        // ====================================================================
        // SPRING BOOT ACTUATOR (high impact: heap dumps, env, mappings)
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Spring Actuator".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" OR inurl:\"/actuator/heapdump\" OR inurl:\"/actuator/threaddump\" OR inurl:\"/actuator/mappings\" OR inurl:\"/actuator/loggers\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/actuator/env leaks environment variables (DB URLs, secrets). /heapdump can be analyzed offline to extract tokens and sessions.".to_string(),
        });

        // ====================================================================
        // METRICS / OBSERVABILITY EXPOSURE
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Metrics Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/metrics\" intext:\"# TYPE\" intext:\"# HELP\")",
                clean_domain
            ),
            description: "Find exposed Prometheus-format metrics endpoints".to_string(),
            impact: "Prometheus metrics expose internal hostnames, request labels, queue names, and sometimes user identifiers.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Metrics Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/debug/pprof/\" OR inurl:\"/debug/vars\" OR intitle:\"/debug/pprof/\")",
                clean_domain
            ),
            description: "Find exposed Go pprof / expvars endpoints".to_string(),
            impact: "Go pprof allows downloading goroutine, heap and CPU profiles that contain sensitive in-memory data.".to_string(),
        });

        // ====================================================================
        // KUBERNETES / CLOUD-NATIVE
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Kubernetes Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/api/v1/namespaces\" OR inurl:\"/api/v1/pods\" OR intitle:\"Kubernetes Dashboard\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes API surface".to_string(),
            impact: "Unauthenticated kube-apiserver exposes pods, secrets, and may allow exec into containers.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Kubernetes Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/v2/_catalog\" OR inurl:\"/v2/manifests\")",
                clean_domain
            ),
            description: "Find exposed Docker Registry v2 API".to_string(),
            impact: "An open /v2/_catalog lists private images; manifests reveal build provenance and may include embedded credentials.".to_string(),
        });

        // ====================================================================
        // API SCHEMAS & COLLECTIONS (recon gold)
        // ====================================================================
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"swagger.json\" OR inurl:\"swagger.yaml\" OR inurl:\"openapi.json\" OR inurl:\"openapi.yaml\" OR inurl:\"v2/api-docs\" OR inurl:\"v3/api-docs\")",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger schema files".to_string(),
            impact: "Raw schemas enumerate every operation, parameter, and auth scheme — accelerates targeted attacks vs. UI scraping.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com (\"{}\" OR \"{}\") inurl:collection",
                clean_domain, clean_domain.replace('.', "%20")
            ),
            description: "Find public Postman collections referencing the domain".to_string(),
            impact: "Public Postman workspaces routinely include API keys and bearer tokens in 'variables'.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:any.run \"{}\" OR site:joesandbox.com \"{}\" OR site:hybrid-analysis.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find sandbox submissions referencing the domain".to_string(),
            impact: "Public sandbox runs of legitimate apps leak internal URLs, API endpoints, and auth headers from captured traffic.".to_string(),
        });

        // ====================================================================
        // BUILD / DEPLOY ARTIFACTS LEFT IN WEBROOT
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Build Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"Dockerfile\" OR inurl:\"docker-compose.yml\" OR inurl:\"docker-compose.yaml\" OR inurl:\".dockerignore\")",
                clean_domain
            ),
            description: "Find exposed Docker build artifacts".to_string(),
            impact: "Dockerfiles reveal base images, copied secrets, and entrypoint binaries — useful for chained exploitation.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Build Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"Jenkinsfile\" OR inurl:\".gitlab-ci.yml\" OR inurl:\".github/workflows\" OR inurl:\".circleci/config.yml\" OR inurl:\"bitbucket-pipelines.yml\")",
                clean_domain
            ),
            description: "Find exposed CI/CD pipeline definitions".to_string(),
            impact: "Pipeline files name deploy targets, secret variable names, and runner labels — directly enabling secret-injection attacks.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Build Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"composer.lock\" OR inurl:\"package-lock.json\" OR inurl:\"yarn.lock\" OR inurl:\"Pipfile.lock\" OR inurl:\"Gemfile.lock\" OR inurl:\"go.sum\")",
                clean_domain
            ),
            description: "Find exposed lockfiles".to_string(),
            impact: "Lockfiles pin exact dependency versions, letting attackers correlate to known CVEs without scanning.".to_string(),
        });

        // ====================================================================
        // CRASH / DEBUG ARTIFACTS
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Debug Artifacts".to_string(),
            query: format!(
                "site:{} (ext:hprof OR ext:dump OR ext:dmp OR ext:core) (inurl:heap OR inurl:dump OR inurl:crash)",
                clean_domain
            ),
            description: "Find indexed heap/core dumps".to_string(),
            impact: "Heap dumps from JVM/.NET/Node frequently contain plaintext credentials, JWTs, and session tokens.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Debug Artifacts".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" OR inurl:phpinfo.php OR inurl:info.php OR inurl:test.php intext:\"PHP Version\")",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo() leaks loaded modules, paths, env vars (often including DB creds) and disabled functions.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Debug Artifacts".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops! There was an error\" OR intext:\"DEBUG = True\" OR intext:\"Symfony Profiler\" OR intext:\"You don't have a default home page yet\")",
                clean_domain
            ),
            description: "Find framework debug pages (Laravel Whoops, Django, Symfony, Werkzeug)".to_string(),
            impact: "Framework debug pages reveal stack traces, source code excerpts, env vars, and often allow interactive console access.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Debug Artifacts".to_string(),
            query: format!(
                "site:{} (intext:\"Werkzeug Debugger\" OR intext:\"console-pin\")",
                clean_domain
            ),
            description: "Find exposed Werkzeug interactive debugger".to_string(),
            impact: "Werkzeug debugger PIN-protected console gives direct Python RCE on the server.".to_string(),
        });

        // ====================================================================
        // BUCKET / STORAGE LISTINGS (server-style index pages)
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Storage Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (intext:\"backup\" OR intext:\".sql\" OR intext:\".env\" OR intext:\".bak\" OR intext:\"id_rsa\")",
                clean_domain
            ),
            description: "Find Apache/nginx open directory listings containing sensitive files".to_string(),
            impact: "Index-of pages with backup / SQL / .env / SSH-key entries indicate accidentally exposed sensitive content.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Storage Listings".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\" intext:\"<ListBucketResult\"",
                clean_domain
            ),
            description: "Find publicly listable GCS buckets referencing the domain".to_string(),
            impact: "Bucket listings reveal full object inventory — sift for backups, dumps, credentials.".to_string(),
        });

        // ====================================================================
        // EDITOR / OS METADATA LEAKS
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Metadata Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" OR inurl:\"Thumbs.db\" OR inurl:\".idea/workspace.xml\" OR inurl:\".vscode/settings.json\")",
                clean_domain
            ),
            description: "Find OS / editor metadata leaks".to_string(),
            impact: ".DS_Store enumerates sibling files; IDE configs may contain ssh-config snippets and deploy targets.".to_string(),
        });

        // ====================================================================
        // CLOUD CREDS LEFT IN WEBROOT
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\"id_rsa\" OR inurl:\"id_dsa\" OR inurl:\"id_ed25519\" OR inurl:\".ssh/known_hosts\" OR inurl:\".ssh/authorized_keys\")",
                clean_domain
            ),
            description: "Find exposed SSH key material".to_string(),
            impact: "Private SSH keys grant direct shell access; authorized_keys enumerate principals with access to the host.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" OR inurl:\".aws/config\" OR inurl:\"credentials.csv\" intext:\"AKIA\")",
                clean_domain
            ),
            description: "Find exposed AWS credentials".to_string(),
            impact: "AWS access keys in webroot or downloadable CSVs grant programmatic account access.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\"client_secret.json\" OR inurl:\"service-account.json\" OR intext:\"\\\"type\\\": \\\"service_account\\\"\")",
                clean_domain
            ),
            description: "Find exposed GCP service account JSON".to_string(),
            impact: "GCP service-account JSON files contain private signing keys that grant project-level access.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\".kube/config\" OR inurl:\"kubeconfig\" OR inurl:\"admin.conf\")",
                clean_domain
            ),
            description: "Find exposed kubeconfig files".to_string(),
            impact: "kubeconfig contains cluster API endpoint and embedded tokens / client certs — full cluster access.".to_string(),
        });

        // ====================================================================
        // SECRETS IN PUBLIC PASTE SITES
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:ghostbin.co OR site:paste.ee OR site:hastebin.com OR site:rentry.co OR site:dpaste.com OR site:bin.disroot.org) \"{}\"",
                clean_domain
            ),
            description: "Find leaks on alternative paste sites".to_string(),
            impact: "Pastebin alternatives are under-monitored and frequently host leaked credentials.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" (\"password\" OR \"secret\" OR \"token\" OR \"api_key\")",
                clean_domain
            ),
            description: "Find sensitive GitHub Gists referencing the domain".to_string(),
            impact: "Public gists referencing the domain alongside credential keywords are high-likelihood real leaks.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:replit.com \"{}\" (\"env\" OR \"secret\" OR \"api_key\")",
                clean_domain
            ),
            description: "Find Replit projects referencing the domain".to_string(),
            impact: "Public Replit forks may contain hardcoded API keys, tokens, and .env values.".to_string(),
        });

        // ====================================================================
        // CONFLUENCE / NOTION / INTERNAL DOCS LEFT PUBLIC
        // ====================================================================
        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "site:atlassian.net \"{}\" (\"runbook\" OR \"playbook\" OR \"credentials\" OR \"vault\")",
                clean_domain
            ),
            description: "Find public Confluence pages with operational content".to_string(),
            impact: "Anonymously-visible Confluence pages often contain runbooks with embedded credentials or VPN instructions.".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Docs".to_string(),
            query: format!(
                "(site:notion.site OR site:notion.so) \"{}\" (\"credentials\" OR \"api key\" OR \"runbook\")",
                clean_domain
            ),
            description: "Find public Notion pages mentioning the domain".to_string(),
            impact: "Notion public-share toggles silently expose pages; teams often publish internal SOPs by accident.".to_string(),
        });

        // ====================================================================
        // GRAPHQL / WS introspection surfaces
        // ====================================================================
        dorks.push(GoogleDork {
            category: "GraphQL Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" OR inurl:\"/graphiql\" OR inurl:\"/v1/graphql\" OR intitle:\"GraphiQL\" OR intitle:\"GraphQL Playground\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints / playgrounds".to_string(),
            impact: "Introspection-enabled GraphQL endpoints reveal entire schema including hidden mutations and admin fields.".to_string(),
        });

        // ====================================================================
        // EMAIL / SAML metadata
        // ====================================================================
        dorks.push(GoogleDork {
            category: "SAML / SSO".to_string(),
            query: format!(
                "site:{} (inurl:\"/saml/metadata\" OR inurl:\"FederationMetadata.xml\" OR inurl:\"/sso/saml/metadata\")",
                clean_domain
            ),
            description: "Find SAML federation metadata".to_string(),
            impact: "SAML metadata exposes IdP/SP entity IDs, ACS URLs, and signing certs — needed for SAML attack chains (SAMLRaider).".to_string(),
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
