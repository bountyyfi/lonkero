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

        // Notion public pages mentioning the domain
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:notion.so \"{}\"", clean_domain),
            description: "Find publicly shared Notion pages".to_string(),
            impact: "Public Notion pages frequently leak runbooks, credentials, customer data, and onboarding docs".to_string(),
        });

        // Confluence public spaces
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "site:atlassian.net inurl:wiki \"{}\"",
                clean_domain
            ),
            description: "Find public Confluence pages".to_string(),
            impact: "Public Confluence spaces routinely contain architecture diagrams, internal URLs, and credentials".to_string(),
        });

        // Spring Boot Actuator — exposes /env, /heapdump, /trace, /mappings
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/mappings | inurl:/actuator/trace | inurl:/actuator/configprops | inurl:/actuator/health)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator /env and /heapdump leak environment variables, JDBC credentials, and full process memory — frequently RCE pivot".to_string(),
        });

        // Kubernetes / container-orchestrator dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/api/v1/namespaces | inurl:/healthz | inurl:/swaggerapi | intitle:\"Rancher\" | intitle:\"Portainer\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Rancher / Portainer dashboards".to_string(),
            impact: "Unauthenticated cluster API endpoints permit pod creation, secret read, and full cluster takeover".to_string(),
        });

        // Prometheus / Alertmanager / Consul / Nomad
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series\" | inurl:/targets | intitle:\"Alertmanager\" | intitle:\"Consul by HashiCorp\" | inurl:/v1/agent/self | intitle:\"Nomad\")",
                clean_domain
            ),
            description: "Find exposed Prometheus/Consul/Nomad/Alertmanager UIs".to_string(),
            impact: "Internal infrastructure topology, service inventory, and frequently writable config — pivot into the network".to_string(),
        });

        // Elasticsearch / Kibana / OpenSearch
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | inurl:/_cat/indices | inurl:/_cluster/health | inurl:/app/kibana | intitle:\"OpenSearch Dashboards\")",
                clean_domain
            ),
            description: "Find exposed Elasticsearch/Kibana/OpenSearch instances".to_string(),
            impact: "Unauthenticated search clusters typically index logs containing credentials, tokens, PII, and full request bodies".to_string(),
        });

        // GraphQL playground / introspection UIs (non-prod misconfig)
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\" | inurl:/graphiql | inurl:/playground | inurl:/altair)",
                clean_domain
            ),
            description: "Find exposed GraphQL playground / introspection UIs".to_string(),
            impact: "Exposed playground in prod enables full schema introspection and arbitrary mutation discovery without auth".to_string(),
        });

        // Postman public workspaces and collections
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com (inurl:/workspace | inurl:/collection) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces and collections".to_string(),
            impact: "Public Postman collections frequently include long-lived API tokens, staging credentials, and undocumented internal endpoints".to_string(),
        });

        // SwaggerHub public APIs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!("site:app.swaggerhub.com \"{}\"", clean_domain),
            description: "Find SwaggerHub-hosted API specifications".to_string(),
            impact: "Internal API specs exposed on SwaggerHub reveal endpoint structure, parameters, and example payloads".to_string(),
        });

        // ReadMe.io / Stoplight / Apiary docs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:readme.io | site:stoplight.io | site:apiary.io | site:gitbook.io) \"{}\"",
                clean_domain
            ),
            description: "Find third-party-hosted API docs".to_string(),
            impact: "External doc portals often contain working tokens in cURL examples and reveal staging endpoints".to_string(),
        });

        // CI/CD pipeline files indexed in repos / archives
        dorks.push(GoogleDork {
            category: "CI/CD Exposure".to_string(),
            query: format!(
                "(site:github.com | site:gitlab.com | site:bitbucket.org) \"{}\" (filename:.env | filename:Jenkinsfile | filename:.gitlab-ci.yml | filename:Dockerfile | filename:docker-compose.yml | filename:.travis.yml | filename:.circleci/config.yml | path:.github/workflows)",
                clean_domain
            ),
            description: "Find CI/CD pipeline files referencing the domain".to_string(),
            impact: "Pipeline files frequently embed deployment tokens, registry credentials, and internal hostnames".to_string(),
        });

        // Exposed VCS metadata directories on the target itself
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:/.git/ | inurl:/.svn/ | inurl:/.hg/ | inurl:/.DS_Store)",
                clean_domain
            ),
            description: "Find exposed VCS metadata or filesystem artifacts".to_string(),
            impact: "Exposed .git/.svn directories enable full source-tree reconstruction; .DS_Store leaks directory listings".to_string(),
        });

        // Exposed dotfiles / env-style configs
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:/.env | inurl:/.env.local | inurl:/.env.production | inurl:/web.config | inurl:/wp-config.php.bak | inurl:/config.php.bak | inurl:/database.yml | inurl:/secrets.yml | inurl:/credentials.json)",
                clean_domain
            ),
            description: "Find exposed environment / configuration files".to_string(),
            impact: "Direct exposure of secrets — DB passwords, JWT signing keys, third-party API tokens".to_string(),
        });

        // Stack-trace and framework debug pages
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops! There was an error\" | intext:\"Werkzeug Debugger\" | intext:\"DEBUG = True\" | intext:\"Traceback (most recent call last)\" | intext:\"Symfony Exception\" | intext:\"Rails.application\" | intext:\"ASP.NET is configured to show verbose error messages\")",
                clean_domain
            ),
            description: "Find production debug pages from web frameworks".to_string(),
            impact: "Werkzeug/Symfony/Rails debug consoles allow direct code execution; stack traces leak internal paths and dependency versions".to_string(),
        });

        // Open directory listings
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} intitle:\"index of /\" (intext:\"backup\" | intext:\"private\" | intext:\"db\" | intext:\".sql\" | intext:\".tar\" | intext:\".zip\" | intext:\".log\")",
                clean_domain
            ),
            description: "Find Apache/nginx-style open directory listings".to_string(),
            impact: "Indexable directories often contain database dumps, source archives, and rotation logs".to_string(),
        });

        // Direct SQL / DB dumps and backups
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:db | ext:dump | ext:bak | ext:tar | ext:tar.gz | ext:7z) -ext:html",
                clean_domain
            ),
            description: "Find database dumps and archive backups".to_string(),
            impact: "Database dumps expose full user tables, password hashes, payment metadata, and PII".to_string(),
        });

        // Webhook URLs in indexed snippets
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:hooks.slack.com | site:discord.com/api/webhooks | site:outlook.office.com/webhook) \"{}\"",
                clean_domain
            ),
            description: "Find leaked webhook URLs".to_string(),
            impact: "Slack/Discord/Teams webhooks let attackers post arbitrary messages into corporate channels for phishing".to_string(),
        });

        // Public S3 bucket listings (XML response indexed)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:s3-eu-west-1.amazonaws.com | site:s3.eu-central-1.amazonaws.com) intitle:\"index of\" \"{}\"",
                clean_domain
            ),
            description: "Find world-listable S3 buckets owned by the org".to_string(),
            impact: "World-listable buckets typically also permit anonymous GET — direct data exposure".to_string(),
        });

        // GCS public listings
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:storage.googleapis.com \"{}\"",
                clean_domain
            ),
            description: "Find public Google Cloud Storage objects".to_string(),
            impact: "Anonymously readable GCS buckets often hold release builds, backups, and customer exports".to_string(),
        });

        // Azure Blob containers with $root listing
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:blob.core.windows.net intitle:\"EnumerationResults\" \"{}\"",
                clean_domain
            ),
            description: "Find publicly listable Azure Blob containers".to_string(),
            impact: "Anonymous list+read on Azure Blob containers — same impact as open S3".to_string(),
        });

        // Logged-in screen captures / session links
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:loom.com | site:vimeo.com | site:streamable.com | site:youtu.be) \"{}\" (\"admin\" | \"dashboard\" | \"internal\")",
                clean_domain
            ),
            description: "Find unlisted screen recordings showing internal UIs".to_string(),
            impact: "Loom/Vimeo recordings from engineers often display admin panels, tokens in URL bars, and session IDs".to_string(),
        });

        // Shorturl shorteners pointing into the org
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:bit.ly | site:tinyurl.com | site:t.co | site:rebrand.ly) \"{}\"",
                clean_domain
            ),
            description: "Find shortened links targeting the domain".to_string(),
            impact: "Public link shorteners reveal staging URLs, internal docs, and one-time-use share links".to_string(),
        });

        // Status pages exposing infrastructure
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:statuspage.io | site:status.io | site:instatus.com | site:cachethq.io) \"{}\"",
                clean_domain
            ),
            description: "Find public status pages".to_string(),
            impact: "Status pages enumerate every internal subsystem (db, cache, identity, billing) — invaluable for targeted attacks".to_string(),
        });

        // Public bug-bounty / disclosure trackers other than OBB
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "(site:hackerone.com/reports | site:bugcrowd.com/disclosures | site:huntr.dev | site:intigriti.com) \"{}\"",
                clean_domain
            ),
            description: "Find disclosed reports on major bounty platforms".to_string(),
            impact: "Disclosed reports often describe still-exploitable variants or unfixed root causes".to_string(),
        });

        // Hardcoded secrets in indexed code
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:github.com | site:gitlab.com | site:bitbucket.org) \"{}\" (\"AKIA\" | \"AIza\" | \"sk_live_\" | \"ghp_\" | \"glpat-\" | \"xox[bp]-\" | \"-----BEGIN PRIVATE KEY-----\")",
                clean_domain
            ),
            description: "Find indexed code containing high-confidence secret prefixes".to_string(),
            impact: "Vendor-prefixed tokens (AWS/Google/Stripe/GitHub/Slack) are immediately weaponizable".to_string(),
        });

        // SAML / OIDC metadata documents (often auto-discoverable)
        dorks.push(GoogleDork {
            category: "Authentication".to_string(),
            query: format!(
                "site:{} (inurl:/saml/metadata | inurl:/.well-known/openid-configuration | inurl:/auth/realms | inurl:/oauth2/.well-known | inurl:/FederationMetadata.xml)",
                clean_domain
            ),
            description: "Find SAML / OIDC metadata endpoints".to_string(),
            impact: "Metadata documents reveal IdP layout, supported algorithms (find weak signing), and Keycloak realm names for credential stuffing".to_string(),
        });

        // Phpinfo / server-status / probe pages
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:test.php intitle:\"phpinfo\" | inurl:/server-status | inurl:/server-info | intitle:\"Apache Status\")",
                clean_domain
            ),
            description: "Find phpinfo() and Apache server-status pages".to_string(),
            impact: "phpinfo() leaks the entire SAPI/environment including session secrets; server-status leaks live request URLs and IPs".to_string(),
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
