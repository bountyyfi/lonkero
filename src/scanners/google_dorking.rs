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

        // ---- High-impact "sensitive stuff" dorks ----------------------------
        // These are search queries — no false-positive surface on the scanner
        // side. They surface real, impactful exposures.

        // Environment / dotenv files indexed by Google
        dorks.push(GoogleDork {
            category: "Exposed Env / Config".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.\" | inurl:\"/env\" | inurl:\"/config.json\" | inurl:\"/config.yml\" | inurl:\"/config.yaml\")",
                clean_domain
            ),
            description: "Find indexed .env / config files exposed on the web root".to_string(),
            impact: "Dotenv / app config files routinely contain DB URLs, JWT secrets, API keys, and SMTP credentials.".to_string(),
        });

        // .git / .svn / .hg directories
        dorks.push(GoogleDork {
            category: "Exposed VCS".to_string(),
            query: format!(
                "site:{} (inurl:\".git/HEAD\" | inurl:\".git/config\" | inurl:\".gitignore\" | inurl:\".gitlab-ci.yml\" | inurl:\".svn/entries\" | inurl:\".hg/store\")",
                clean_domain
            ),
            description: "Find exposed source-control metadata".to_string(),
            impact: "Exposed .git/.svn lets attackers clone the full source tree, including hardcoded secrets and historical credentials.".to_string(),
        });

        // CI/CD pipeline definitions and build artifacts
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" | inurl:\".circleci/config\" | inurl:\"Jenkinsfile\" | inurl:\"azure-pipelines\" | inurl:\".buildspec.yml\" | inurl:\".drone.yml\" | inurl:\"bitbucket-pipelines.yml\")",
                clean_domain
            ),
            description: "Find CI/CD pipeline definitions".to_string(),
            impact: "Pipeline configs frequently leak deployment credentials, signing keys, and the target's internal service inventory.".to_string(),
        });

        // Kubernetes / Helm / Docker artifacts
        dorks.push(GoogleDork {
            category: "Container / Orchestration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"Dockerfile\" | inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\"values.yaml\" | inurl:\"kustomization.yaml\" | inurl:\".kubeconfig\")",
                clean_domain
            ),
            description: "Find Docker / Kubernetes / Helm files".to_string(),
            impact: "Container manifests contain mounted secrets, base images with embedded creds, and direct registry / cluster auth.".to_string(),
        });

        // Terraform and IaC state
        dorks.push(GoogleDork {
            category: "IaC State Files".to_string(),
            query: format!(
                "site:{} (inurl:\"terraform.tfstate\" | inurl:\"terraform.tfvars\" | inurl:\".terraform\" | inurl:\"main.tf\" | inurl:\"pulumi.yaml\" | inurl:\"cdk.out\")",
                clean_domain
            ),
            description: "Find exposed Terraform / Pulumi / CDK state".to_string(),
            impact: "tfstate files contain provider credentials, secret outputs, and the full cloud resource inventory in cleartext.".to_string(),
        });

        // Cloud credential files
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\"credentials\" | inurl:\".aws/credentials\" | inurl:\"gcloud/credentials\" | inurl:\".azure/credentials\" | inurl:\"service-account.json\" | inurl:\"credentials.json\" | inurl:\"client_secret\")",
                clean_domain
            ),
            description: "Find cloud-provider credential files".to_string(),
            impact: "Direct AWS / GCP / Azure principal credentials — first-class tenant compromise.".to_string(),
        });

        // SSH and private key material
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (inurl:id_rsa | inurl:id_dsa | inurl:id_ecdsa | inurl:id_ed25519 | inurl:\".pem\" | inurl:\".p12\" | inurl:\".pfx\" | inurl:\".key\" | inurl:\"known_hosts\")",
                clean_domain
            ),
            description: "Find exposed SSH / TLS / PKCS keys".to_string(),
            impact: "Private keys grant SSH access to production hosts or impersonation of TLS / code-signing identities.".to_string(),
        });

        // Backup and dump files
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:db | ext:sqlite | ext:bak | ext:tar | ext:tar.gz | ext:zip | ext:rar | ext:7z) (inurl:backup | inurl:dump | inurl:db | inurl:export | inurl:archive | inurl:tmp)",
                clean_domain
            ),
            description: "Find database dumps and backup archives".to_string(),
            impact: "DB dumps and backups frequently contain user PII, password hashes, and full application state.".to_string(),
        });

        // Log files exposed
        dorks.push(GoogleDork {
            category: "Exposed Logs".to_string(),
            query: format!(
                "site:{} (inurl:\"/logs/\" | inurl:\".log\" | inurl:\"error.log\" | inurl:\"debug.log\" | inurl:\"access.log\" | inurl:\"laravel.log\" | inurl:\"npm-debug.log\")",
                clean_domain
            ),
            description: "Find indexed application / server logs".to_string(),
            impact: "Log files often contain request bodies, session tokens, stack traces with file paths, and PII.".to_string(),
        });

        // Spring Boot Actuator and other framework debug surfaces
        dorks.push(GoogleDork {
            category: "Framework Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/loggers\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/configprops\" | inurl:\"/actuator/health\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/actuator/env leaks environment variables (secrets), /actuator/heapdump leaks live memory including session tokens, /actuator/loggers can be flipped to log credentials.".to_string(),
        });

        // Laravel debug / Telescope / Horizon
        dorks.push(GoogleDork {
            category: "Framework Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/_ignition\" | inurl:\"/telescope\" | inurl:\"/horizon\" | inurl:\"/_debugbar\")",
                clean_domain
            ),
            description: "Find Laravel debug interfaces".to_string(),
            impact: "Ignition (CVE-2021-3129) chains to RCE; Telescope and Debugbar leak every request payload including auth tokens.".to_string(),
        });

        // Django / Symfony / Rails debug pages
        dorks.push(GoogleDork {
            category: "Framework Debug Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"DEBUG = True\" | intitle:\"Werkzeug Debugger\" | intext:\"You're seeing this error because\" | intext:\"WhitelabelErrorPage\" | inurl:\"/_profiler\" | inurl:\"/_wdt\" | inurl:\"/__profile__\" | inurl:\"/__monitor__\")",
                clean_domain
            ),
            description: "Find live debug toolbars / interactive tracebacks".to_string(),
            impact: "Werkzeug debugger with PIN bypass = unauth RCE; Symfony profiler leaks full request/response history and DB queries.".to_string(),
        });

        // Server status / info endpoints
        dorks.push(GoogleDork {
            category: "Server Status Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"server-status\" | inurl:\"server-info\" | inurl:\"phpinfo.php\" | inurl:\"info.php\" | inurl:\"/web-console\" | inurl:\"/jmx-console\" | inurl:\"/manager/html\" | inurl:\"/host-manager\")",
                clean_domain
            ),
            description: "Find exposed server-status / phpinfo / Tomcat manager".to_string(),
            impact: "phpinfo leaks env vars and module versions; Tomcat manager with default creds = RCE; JMX-Console / web-console on JBoss = RCE.".to_string(),
        });

        // Metrics endpoints
        dorks.push(GoogleDork {
            category: "Metrics / Observability".to_string(),
            query: format!(
                "site:{} (inurl:\"/metrics\" | inurl:\"/prometheus\" | inurl:\"/stats\" | inurl:\"/varz\" | inurl:\"/debug/vars\" | inurl:\"/debug/pprof\")",
                clean_domain
            ),
            description: "Find Prometheus / Go pprof / NATS varz endpoints".to_string(),
            impact: "/debug/pprof allows arbitrary memory profiling and can leak in-memory secrets; metrics labels frequently embed hostnames and tokens.".to_string(),
        });

        // GraphQL endpoints with introspection
        dorks.push(GoogleDork {
            category: "GraphQL Surfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/playground\" | inurl:\"/altair\" | inurl:\"/api/graphql\" | inurl:\"/query\" intext:\"__schema\")",
                clean_domain
            ),
            description: "Find GraphQL endpoints and playgrounds".to_string(),
            impact: "Introspection-enabled GraphQL leaks the full schema; playgrounds in production let unauth users execute arbitrary queries / mutations.".to_string(),
        });

        // WebSocket / SSE endpoints
        dorks.push(GoogleDork {
            category: "Realtime Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/socket.io\" | inurl:\"/sockjs\" | inurl:\"/ws\" | inurl:\"/wss\" | inurl:\"/sse\" | inurl:\"/events\" | inurl:\"/stream\")",
                clean_domain
            ),
            description: "Find WebSocket / SSE endpoints".to_string(),
            impact: "WebSocket auth is often weaker than HTTP — check for token-leakage in handshakes and missing origin checks.".to_string(),
        });

        // OAuth / OIDC well-known and authorize endpoints
        dorks.push(GoogleDork {
            category: "OAuth / OIDC".to_string(),
            query: format!(
                "site:{} (inurl:\"/.well-known/openid-configuration\" | inurl:\"/.well-known/oauth-authorization-server\" | inurl:\"/oauth/authorize\" | inurl:\"/oauth2/token\" | inurl:\"/connect/token\" | inurl:\"/oauth/clients\")",
                clean_domain
            ),
            description: "Find OAuth / OIDC discovery and authorization endpoints".to_string(),
            impact: "Discovery docs map the auth surface; misconfigured redirect_uri / response_type combinations often allow token theft.".to_string(),
        });

        // Webhooks / payment / financial integrations
        dorks.push(GoogleDork {
            category: "Webhook / Payment Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/webhook\" | inurl:\"/webhooks\" | inurl:\"/callback\" | inurl:\"/notify\" | inurl:\"/ipn\" | inurl:\"/stripe\" | inurl:\"/paypal\" | inurl:\"/adyen\")",
                clean_domain
            ),
            description: "Find webhook / payment-callback endpoints".to_string(),
            impact: "Webhook endpoints often skip signature verification, accept forged events, and trigger high-impact state changes (refunds, account upgrades).".to_string(),
        });

        // Internal portals / SSO
        dorks.push(GoogleDork {
            category: "Internal Portals".to_string(),
            query: format!(
                "site:{} (inurl:\"/sso\" | inurl:\"/saml\" | inurl:\"/adfs\" | inurl:\"/portal\" | inurl:\"/intranet\" | inurl:\"/employee\" | inurl:\"/staff\" | inurl:\"/internal\")",
                clean_domain
            ),
            description: "Find internal / SSO portals exposed externally".to_string(),
            impact: "Employee-only portals reached from the internet are credential-stuffing targets and often skip MFA for legacy clients.".to_string(),
        });

        // VPN / remote-access portals
        dorks.push(GoogleDork {
            category: "VPN / Remote Access".to_string(),
            query: format!(
                "site:{} (inurl:\"/remote\" | inurl:\"/vpn\" | inurl:\"/sslvpn\" | inurl:\"/global-protect\" | inurl:\"/dana-na\" | inurl:\"/my.policy\" | inurl:\"/sslvpnclient\")",
                clean_domain
            ),
            description: "Find VPN / SSL-VPN web portals".to_string(),
            impact: "Ivanti, GlobalProtect, F5 BIG-IP APM, Citrix, SonicWall portals all have current unauth RCE / disclosure CVEs.".to_string(),
        });

        // Mail / SMTP web tools
        dorks.push(GoogleDork {
            category: "Mail Tooling".to_string(),
            query: format!(
                "site:{} (inurl:\"/mail\" | inurl:\"/roundcube\" | inurl:\"/squirrelmail\" | inurl:\"/owa\" | inurl:\"/ecp\" | inurl:\"/mailhog\" | inurl:\"/mailcatcher\")",
                clean_domain
            ),
            description: "Find webmail / dev SMTP UIs".to_string(),
            impact: "OWA/ECP have ProxyShell-class CVEs; MailHog/Mailcatcher leak every outbound dev email (password resets, OTPs).".to_string(),
        });

        // CMS admin entry points
        dorks.push(GoogleDork {
            category: "CMS Admin".to_string(),
            query: format!(
                "site:{} (inurl:\"/wp-admin\" | inurl:\"/wp-login.php\" | inurl:\"/administrator\" | inurl:\"/user/login\" | inurl:\"/admin.php\" | inurl:\"/typo3\" | inurl:\"/umbraco\" | inurl:\"/sitecore\")",
                clean_domain
            ),
            description: "Find CMS administrator login pages".to_string(),
            impact: "Common targets for credential stuffing / known-CVE chains (e.g. CVE-2024-46938 Sitecore unauth RCE).".to_string(),
        });

        // DB admin web tools
        dorks.push(GoogleDork {
            category: "DB Admin Tools".to_string(),
            query: format!(
                "site:{} (inurl:\"/phpmyadmin\" | inurl:\"/pma\" | inurl:\"/adminer\" | inurl:\"/adminer.php\" | inurl:\"/phppgadmin\" | inurl:\"/mongo-express\" | inurl:\"/redis-commander\")",
                clean_domain
            ),
            description: "Find web-based database admin tools".to_string(),
            impact: "Single-form gateway to internal DBs; default credentials and known auth-bypass CVEs are common.".to_string(),
        });

        // Container / orchestration UIs exposed
        dorks.push(GoogleDork {
            category: "Orchestration UIs".to_string(),
            query: format!(
                "site:{} (inurl:\"/portainer\" | inurl:\"/rancher\" | inurl:\"/kubernetes\" | inurl:\"/argo\" | inurl:\"/argocd\" | inurl:\"/k8s\" | inurl:\"/dashboard\" intitle:\"Kubernetes Dashboard\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes / container management UIs".to_string(),
            impact: "Argo CD / Rancher / Portainer with weak auth = cluster-wide RCE; K8s Dashboard with skip-auth flag = full namespace takeover.".to_string(),
        });

        // CI/CD web UIs
        dorks.push(GoogleDork {
            category: "CI/CD Web UIs".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | intitle:\"GoCD\" | intitle:\"TeamCity\" | intitle:\"Argo Workflows\" | inurl:\"/jenkins/login\" | inurl:\"/teamcity/login\" | inurl:\"/concourse\" | inurl:\"/drone\")",
                clean_domain
            ),
            description: "Find exposed CI/CD web UIs".to_string(),
            impact: "Jenkins script console / TeamCity (CVE-2024-27198) / Bamboo (OGNL) all chain trivially to RCE on the build host.".to_string(),
        });

        // Secret-management interfaces
        dorks.push(GoogleDork {
            category: "Secret Stores".to_string(),
            query: format!(
                "site:{} (intitle:\"Vault\" inurl:\"/ui/vault\" | intitle:\"Consul\" inurl:\"/ui/\" | inurl:\"/v1/sys/health\" | inurl:\"/v1/kv\" | inurl:\"/secrets/\" intitle:\"Doppler\")",
                clean_domain
            ),
            description: "Find HashiCorp Vault / Consul / Doppler interfaces".to_string(),
            impact: "Internet-exposed secret stores with weak ACLs are catastrophic; even unsealed-status / mount enumeration is high-signal recon.".to_string(),
        });

        // GitHub / GitLab / pastes mentioning the target with credential-style content
        dorks.push(GoogleDork {
            category: "Cross-site Credential Leaks".to_string(),
            query: format!(
                "(site:github.com | site:gitlab.com | site:bitbucket.org) \"{}\" (\"password\" | \"secret\" | \"api_key\" | \"token\" | \"BEGIN PRIVATE KEY\" | \"BEGIN RSA PRIVATE KEY\")",
                clean_domain
            ),
            description: "Find public commits / files mentioning the target alongside credential keywords".to_string(),
            impact: "Most-impactful single source of bug-bounty wins — committed .env, kube secret, or cloud key tied to the target's domain.".to_string(),
        });

        // Postman / Insomnia / Stoplight workspaces
        dorks.push(GoogleDork {
            category: "API Workspace Leaks".to_string(),
            query: format!(
                "(site:postman.com | site:postman.co | site:stoplight.io | site:swaggerhub.com | site:apidog.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman / SwaggerHub / Stoplight workspaces referencing the domain".to_string(),
            impact: "Public API workspaces frequently embed live bearer tokens, basic-auth creds, and internal-only endpoint inventories.".to_string(),
        });

        // Paste sites — broaden beyond Pastebin
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:rentry.co | site:hastebin.com | site:ide.geeksforgeeks.org | site:paste.ee | site:dpaste.com | site:paste2.org) \"{}\"",
                clean_domain
            ),
            description: "Find target references on additional paste services".to_string(),
            impact: "Engineers paste tracebacks and config snippets to these sites without scrubbing; often includes live tokens.".to_string(),
        });

        // S3 / GCS / Azure bucket discovery via third-party indexers
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:buckets.grayhatwarfare.com | site:opens3.org | site:web.archive.org) \"{}\"",
                clean_domain
            ),
            description: "Find target-mentioning cloud buckets in public indexers".to_string(),
            impact: "Grayhat Warfare regularly indexes open S3/GCS/Azure buckets; cross-reference with target's domain to find historic leaks.".to_string(),
        });

        // Cloud bucket naming variants
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com | site:storage.cloud.google.com | site:appspot.com | site:r2.dev | site:r2.cloudflarestorage.com | site:b-cdn.net | site:wasabisys.com | site:linodeobjects.com) \"{}\"",
                clean_domain
            ),
            description: "Find GCS / R2 / Wasabi / Linode / BunnyCDN object storage".to_string(),
            impact: "Non-AWS object storage is frequently misconfigured for public read; check directory listings and Range requests.".to_string(),
        });

        // Internal documentation / wiki tooling
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "(site:notion.site | site:notion.so | site:confluence.com | site:atlassian.net | site:gitbook.io | site:slab.com | site:tettra.app | site:slite.com | site:nuclino.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Notion / Confluence / GitBook / Slab pages".to_string(),
            impact: "Engineering docs accidentally set to public commonly disclose architecture diagrams, on-call runbooks, and admin URLs.".to_string(),
        });

        // Replit / CodeSandbox / Stackblitz / Glitch live prototypes
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:replit.com | site:repl.it | site:codesandbox.io | site:stackblitz.com | site:glitch.com | site:runkit.com) \"{}\"",
                clean_domain
            ),
            description: "Find target-mentioning prototype apps in live IDEs".to_string(),
            impact: "Live IDE projects often store env vars (Secrets/.env) that are reachable by URL once leaked in source.".to_string(),
        });

        // npm / PyPI / RubyGems / crates.io packages referencing internal infra
        dorks.push(GoogleDork {
            category: "Package Registry Leaks".to_string(),
            query: format!(
                "(site:npmjs.com/package | site:pypi.org/project | site:rubygems.org/gems | site:crates.io/crates | site:packagist.org) \"{}\"",
                clean_domain
            ),
            description: "Find internal-looking packages referencing the target".to_string(),
            impact: "Reveals internal package naming → enables dependency-confusion attacks against the target's build pipelines.".to_string(),
        });

        // Crash / error trackers indexed
        dorks.push(GoogleDork {
            category: "Error Tracker Leaks".to_string(),
            query: format!(
                "(site:sentry.io | site:bugsnag.com | site:rollbar.com | site:airbrake.io | site:raygun.com) \"{}\"",
                clean_domain
            ),
            description: "Find public error-tracker entries referencing the domain".to_string(),
            impact: "Public Sentry/Bugsnag issues often paste full stack traces with request payloads, including tokens and PII.".to_string(),
        });

        // Public Mobile binaries (APK / IPA mirrors)
        dorks.push(GoogleDork {
            category: "Mobile App Leaks".to_string(),
            query: format!(
                "(site:apkpure.com | site:apkmirror.com | site:apkmonk.com | site:f-droid.org) \"{}\"",
                clean_domain
            ),
            description: "Find third-party-hosted Android APKs for the target".to_string(),
            impact: "Decompiled APKs frequently reveal API keys, signing material, and undocumented internal endpoints.".to_string(),
        });

        // SOAP / WSDL legacy endpoints
        dorks.push(GoogleDork {
            category: "Legacy Web Services".to_string(),
            query: format!(
                "site:{} (inurl:\"?wsdl\" | inurl:\".wsdl\" | inurl:\".asmx\" | inurl:\".svc\" | inurl:\"/soap\" | inurl:\"/services/\" intext:\"<wsdl:\")",
                clean_domain
            ),
            description: "Find SOAP / WSDL service descriptions".to_string(),
            impact: "Legacy SOAP/ASMX endpoints often miss modern authn/authz and remain bound to internal back-ends; XXE / parameter-tamper friendly.".to_string(),
        });

        // ASP.NET trace / web.config / ELMAH leaks
        dorks.push(GoogleDork {
            category: "ASP.NET Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"trace.axd\" | inurl:\"elmah.axd\" | inurl:\"web.config\" | inurl:\"viewstate\" | inurl:\"/_appstart\" | inurl:\"appsettings.json\" | inurl:\"appsettings.Development.json\")",
                clean_domain
            ),
            description: "Find ASP.NET trace / ELMAH / config leaks".to_string(),
            impact: "trace.axd and elmah.axd expose full request history including auth headers; appsettings.* and web.config commonly hold connection strings.".to_string(),
        });

        // Java memory dumps and Spring config
        dorks.push(GoogleDork {
            category: "JVM Leaks".to_string(),
            query: format!(
                "site:{} (ext:hprof | ext:jfr | inurl:\"heapdump\" | inurl:\"threaddump\" | inurl:\"application.properties\" | inurl:\"application.yml\" | inurl:\"bootstrap.yml\")",
                clean_domain
            ),
            description: "Find Java heap/thread dumps and Spring config files".to_string(),
            impact: "Heap dumps contain decrypted credentials and live session tokens; application.properties typically holds DB URLs and API keys.".to_string(),
        });

        // Sourcemap (.map) files indexed publicly
        dorks.push(GoogleDork {
            category: "Source Maps".to_string(),
            query: format!(
                "site:{} (inurl:\".js.map\" | inurl:\".css.map\" | inurl:\"sourceMappingURL\" | inurl:\".min.js.map\")",
                clean_domain
            ),
            description: "Find exposed JavaScript / CSS source maps".to_string(),
            impact: "Source maps reconstruct the original TypeScript/ES source, often revealing internal API URLs and hardcoded secrets.".to_string(),
        });

        // Open directory listing
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (\"parent directory\" | \"server at\" | \"Last modified\")",
                clean_domain
            ),
            description: "Find Apache/Nginx auto-generated directory listings".to_string(),
            impact: "Open indexes routinely surface uploaded user content, backups, and forgotten build artifacts.".to_string(),
        });

        // Backup files with timestamp / tilde naming
        dorks.push(GoogleDork {
            category: "Backups & Dumps".to_string(),
            query: format!(
                "site:{} (ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp | ext:swo | inurl:\"~\" | inurl:\".orig\")",
                clean_domain
            ),
            description: "Find editor / deployment backup files".to_string(),
            impact: "Editor backups (.swp, .orig, file.php~) expose the un-rendered server-side source, including hardcoded credentials.".to_string(),
        });

        // Public Slack / Discord invite scrapes
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:slack.com/archives | site:discord.com/channels | site:discord.gg) \"{}\"",
                clean_domain
            ),
            description: "Find public Slack / Discord channel mentions of the target".to_string(),
            impact: "Public chat archives may reveal employee identities, on-call discussions, and accidentally pasted credentials.".to_string(),
        });

        // Pastebin / DocumentCloud / Scribd / Issuu doc dumps
        dorks.push(GoogleDork {
            category: "Document Leaks".to_string(),
            query: format!(
                "(site:documentcloud.org | site:scribd.com | site:issuu.com | site:slideshare.net | site:speakerdeck.com) \"{}\"",
                clean_domain
            ),
            description: "Find public document / slide-deck mentions".to_string(),
            impact: "Slide decks accidentally uploaded with internal screenshots leak admin UI URLs, network diagrams, and credentials.".to_string(),
        });

        // Subdomain takeover / DNS dangling indicators via passive DNS scrapers
        dorks.push(GoogleDork {
            category: "DNS / Subdomain".to_string(),
            query: format!(
                "(site:dnsdumpster.com | site:securitytrails.com | site:viewdns.info | site:crt.sh) \"{}\"",
                clean_domain
            ),
            description: "Pivot to passive-DNS / CT-log services".to_string(),
            impact: "Cross-reference subdomains observed historically vs currently resolving — gaps often correspond to subdomain takeover candidates.".to_string(),
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
