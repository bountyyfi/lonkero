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

        // GitHub Gists — historically one of the highest hit-rates for leaked
        // .env / config snippets tied to a target org.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists mentioning the target".to_string(),
            impact: "Gists are often used to share config snippets and frequently contain live credentials".to_string(),
        });

        // Postman public workspaces / collections — leaking bearer tokens and
        // internal-only endpoints in "environments".
        dorks.push(GoogleDork {
            category: "API Leaks".to_string(),
            query: format!(
                "site:postman.com \"{}\" | site:documenter.getpostman.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find public Postman workspaces or collections".to_string(),
            impact: "Public Postman workspaces routinely embed API keys, bearer tokens and internal URLs in environment variables".to_string(),
        });

        // Insomnia / Bruno / Hoppscotch — same class as Postman for shared collections.
        dorks.push(GoogleDork {
            category: "API Leaks".to_string(),
            query: format!(
                "site:hoppscotch.io \"{}\" | site:insomnia.rest \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find shared REST client workspaces".to_string(),
            impact: "Shared REST tabs / environments may include live tokens for the target".to_string(),
        });

        // SwaggerHub / stoplight / apis.guru — hosted API specs, often prod.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:app.swaggerhub.com \"{}\" | site:stoplight.io \"{}\" | site:apis.guru \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find hosted OpenAPI/Swagger specs for the target".to_string(),
            impact: "Externally hosted specs may reveal internal endpoints, admin operations, and undocumented parameters".to_string(),
        });

        // Docker Hub / Quay / ghcr — internal image tags, sometimes with baked secrets.
        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "site:hub.docker.com \"{}\" | site:quay.io \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find public container images tied to the target".to_string(),
            impact: "Public images often ship with baked credentials, private URLs or unshipped internal tools".to_string(),
        });

        // NPM / PyPI / RubyGems — packages named after the target org tend to
        // ship internal-only code publicly by accident.
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "site:npmjs.com \"{}\" | site:pypi.org \"{}\" | site:rubygems.org \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find published packages tied to the target".to_string(),
            impact: "Package metadata / readmes can expose internal endpoints; malicious lookalikes are also a supply-chain risk".to_string(),
        });

        // Terraform / IaC registries — modules published from work laptops
        // regularly include private endpoints and provider tokens.
        dorks.push(GoogleDork {
            category: "Infrastructure as Code".to_string(),
            query: format!(
                "site:registry.terraform.io \"{}\" | site:app.terraform.io \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find public Terraform modules / workspaces tied to the target".to_string(),
            impact: "IaC modules may embed API tokens, private endpoint URLs, or reveal cloud account IDs".to_string(),
        });

        // Log aggregators & paste sites beyond Pastebin — high hit rate on incidents.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:hastebin.com \"{}\" | site:ghostbin.com \"{}\" | site:paste.ee \"{}\" | site:rentry.co \"{}\"",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find pasted content mentioning the target".to_string(),
            impact: "Paste sites frequently expose sensitive dumps, credentials or configuration".to_string(),
        });

        // Env / config file dorks — anchored on distinctive keys, not just names.
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (ext:env | ext:conf | ext:cnf | ext:properties) intext:\"DB_PASSWORD\" | intext:\"AWS_SECRET_ACCESS_KEY\" | intext:\"SECRET_KEY\" | intext:\"API_KEY\"",
                clean_domain
            ),
            description: "Find dotenv / config files exposing credential-shaped keys".to_string(),
            impact: "Indexed .env/.conf files with credential key names almost always contain live secrets".to_string(),
        });

        // .git / .svn / .hg / .bzr leftovers.
        dorks.push(GoogleDork {
            category: "Version Control Leaks".to_string(),
            query: format!(
                "site:{} inurl:.git/HEAD | inurl:.git/config | inurl:.svn/entries | inurl:.hg/store | inurl:.bzr",
                clean_domain
            ),
            description: "Find exposed VCS metadata".to_string(),
            impact: "Exposed .git enables full source-tree recovery; .git/config often includes remote URLs with embedded credentials".to_string(),
        });

        // Backup / dump files.
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sql.gz | ext:sql.bz2 | ext:dump | ext:sqlite | ext:sqlite3 | ext:bak | ext:backup | ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:7z)",
                clean_domain
            ),
            description: "Find exposed database dumps and archives".to_string(),
            impact: "Database dumps and archive backups routinely contain full PII/credentials".to_string(),
        });

        // Log files.
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:logs/ | inurl:/var/log/) intext:\"password\" | intext:\"token\" | intext:\"secret\" | intext:\"authorization\"",
                clean_domain
            ),
            description: "Find exposed application logs".to_string(),
            impact: "Application logs regularly contain session tokens, request bodies with credentials and PII".to_string(),
        });

        // Kubernetes / container manifests — highly sensitive when indexed.
        dorks.push(GoogleDork {
            category: "Kubernetes / Docker".to_string(),
            query: format!(
                "site:{} (ext:yaml | ext:yml) intext:\"kind: Secret\" | intext:\"apiVersion: v1\" intext:\"kubectl\" | intext:\"docker-compose\"",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Docker Compose manifests".to_string(),
            impact: "Manifests may leak internal service topology, secret names, image tags and pull-credentials".to_string(),
        });

        // GraphQL introspection / Playground exposed publicly.
        dorks.push(GoogleDork {
            category: "GraphQL".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/altair)",
                clean_domain
            ),
            description: "Find GraphQL endpoints and interactive IDEs".to_string(),
            impact: "Exposed GraphQL Playground / GraphiQL with introspection enabled reveals the full schema and internal mutations".to_string(),
        });

        // Prometheus / Grafana / Kibana exposure (post-auth data typically leaks
        // service names, hostnames and query metrics).
        dorks.push(GoogleDork {
            category: "Monitoring / Observability".to_string(),
            query: format!(
                "site:{} (inurl:/prometheus | inurl:/grafana | inurl:/kibana | inurl:/alertmanager | inurl:/metrics) intitle:\"Prometheus\" | intitle:\"Grafana\" | intitle:\"Kibana\"",
                clean_domain
            ),
            description: "Find exposed metrics / monitoring dashboards".to_string(),
            impact: "Metrics endpoints leak host names, internal service graph, and cardinality that maps the private network".to_string(),
        });

        // Spring Boot Actuator — /actuator/env / /heapdump are classic full-comp findings.
        dorks.push(GoogleDork {
            category: "Framework Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/httptrace | inurl:/actuator/gateway/routes)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator management endpoints".to_string(),
            impact: "/env leaks all configuration including plaintext secrets; /heapdump enables full memory extraction; /gateway/routes enables SSRF".to_string(),
        });

        // Django / Rails / Laravel debug pages.
        dorks.push(GoogleDork {
            category: "Debug Pages".to_string(),
            query: format!(
                "site:{} (intitle:\"DEBUG = True\" | intext:\"Django Version:\" | intext:\"Rails.application\" | intext:\"Whoops\\!\" | intitle:\"Laravel\" intext:\"stack trace\")",
                clean_domain
            ),
            description: "Find debug-mode framework error pages".to_string(),
            impact: "Framework debug pages expose stack traces, environment variables (Werkzeug/Ignition), and often allow arbitrary code execution".to_string(),
        });

        // Firebase realtime DB and Firestore misconfigurations.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:firebaseio.com \"{}\" | site:firebasestorage.googleapis.com \"{}\"",
                clean_domain, clean_domain
            ),
            description: "Find Firebase Realtime DB / Storage buckets tied to the target".to_string(),
            impact: "Misconfigured Firebase rules routinely expose user records and stored files without authentication".to_string(),
        });

        // Wasabi / Backblaze / Linode / R2 buckets.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.wasabisys.com | site:s3.us-west-002.backblazeb2.com | site:linodeobjects.com | site:r2.cloudflarestorage.com) \"{}\"",
                clean_domain
            ),
            description: "Find alternate-provider object storage tied to the target".to_string(),
            impact: "Bucket enumeration on non-AWS providers finds misconfigured storage that AWS-focused scans miss".to_string(),
        });

        // Elastic Cloud / Elasticsearch — cluster metadata + open Kibana.
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "site:*.es.io \"{}\" | site:*.elastic-cloud.com \"{}\" | site:*.kb.*.aws.found.io \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Elastic Cloud / Elasticsearch clusters tied to the target".to_string(),
            impact: "Publicly reachable Elasticsearch clusters have historically leaked huge PII dumps".to_string(),
        });

        // SaaS admin / CI / CD portals often accessed by employees over the internet.
        dorks.push(GoogleDork {
            category: "SaaS Admin Consoles".to_string(),
            query: format!(
                "(site:*.okta.com | site:*.auth0.com | site:*.pingone.com | site:*.duosecurity.com) \"{}\"",
                clean_domain
            ),
            description: "Find identity provider admin/tenant portals for the target".to_string(),
            impact: "IdP tenants leak organisation structure and can be phished; misconfigured self-registration is a common finding".to_string(),
        });

        // Notion / Confluence / Coda public pages — internal docs on public pages.
        dorks.push(GoogleDork {
            category: "Wiki / Docs".to_string(),
            query: format!(
                "(site:notion.site | site:*.notion.so | site:*.atlassian.net/wiki | site:coda.io | site:*.gitbook.io) \"{}\"",
                clean_domain
            ),
            description: "Find public internal docs mentioning the target".to_string(),
            impact: "Employees regularly publish onboarding docs / runbooks with credentials, internal URLs, and architecture diagrams".to_string(),
        });

        // AI chat / prompt sharing services — leak internal source snippets.
        dorks.push(GoogleDork {
            category: "AI Prompts".to_string(),
            query: format!(
                "(site:chat.openai.com/share | site:chatgpt.com/share | site:claude.ai/share | site:poe.com) \"{}\"",
                clean_domain
            ),
            description: "Find shared AI chat transcripts mentioning the target".to_string(),
            impact: "Shared AI transcripts frequently include pasted source code with secrets and stack traces".to_string(),
        });

        // WordPress-specific sensitive endpoints and known misconfigurations.
        dorks.push(GoogleDork {
            category: "WordPress".to_string(),
            query: format!(
                "site:{} (inurl:/wp-json/wp/v2/users | inurl:/xmlrpc.php | inurl:/wp-config.php | inurl:/wp-content/debug.log | inurl:/wp-content/uploads/backup)",
                clean_domain
            ),
            description: "Find sensitive WordPress endpoints".to_string(),
            impact: "REST users endpoint enumerates account IDs; xmlrpc enables brute-force; debug.log/backups leak credentials".to_string(),
        });

        // Employees on breach mirrors — canonical source of email + hash pairs.
        dorks.push(GoogleDork {
            category: "Breach Data".to_string(),
            query: format!(
                "(site:dehashed.com | site:leakcheck.io | site:snusbase.com) \"{}\"",
                clean_domain
            ),
            description: "Find target references on breach-data marketplaces".to_string(),
            impact: "Emails/hashes from historical breaches feed credential stuffing and password reuse attacks against the target".to_string(),
        });

        // Directory listing exposure — Apache/Nginx / IIS default listing signature.
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (intext:\"Parent Directory\" | intext:\"Name\" intext:\"Last modified\")",
                clean_domain
            ),
            description: "Find open directory listings".to_string(),
            impact: "Autoindex-enabled directories often expose backup archives, source trees, and internal file shares".to_string(),
        });

        // Third-party JS/CSS on subdomains — indexed source maps included.
        dorks.push(GoogleDork {
            category: "Source Maps".to_string(),
            query: format!(
                "site:{} (ext:map | inurl:\".js.map\" | inurl:\".css.map\")",
                clean_domain
            ),
            description: "Find exposed JavaScript / CSS source maps".to_string(),
            impact: "Source maps reveal original TypeScript / JSX with comments, API keys, and internal module structure".to_string(),
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
