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

        // Environment Files (.env family)
        dorks.push(GoogleDork {
            category: "Secrets in Dotfiles".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.dev | inurl:.env.staging | inurl:.env.backup | inurl:.env.old | inurl:.env.save) (intext:DB_PASSWORD | intext:AWS_ | intext:SECRET | intext:STRIPE_ | intext:JWT_SECRET)",
                clean_domain
            ),
            description: "Find exposed .env files with credentials".to_string(),
            impact: "Critical - leaked .env files typically expose DB creds, API keys, and signing secrets".to_string(),
        });

        // Git / Version-control metadata
        dorks.push(GoogleDork {
            category: "Secrets in Version Control".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\" | inurl:\".gitignore\" intext:env | inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\".bzr/README\")",
                clean_domain
            ),
            description: "Find exposed VCS metadata (Git, SVN, Hg, Bzr)".to_string(),
            impact: "Allows full source-tree reconstruction, often including hardcoded secrets and CI tokens".to_string(),
        });

        // Spring Boot Actuator
        dorks.push(GoogleDork {
            category: "Spring Boot Actuator".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/configprops | inurl:/actuator/mappings | inurl:/actuator/trace | inurl:/actuator/gateway/routes | inurl:/env | inurl:/heapdump)",
                clean_domain
            ),
            description: "Find exposed Spring Boot actuator endpoints".to_string(),
            impact: "/actuator/env leaks full environment inc. secrets, /heapdump leaks memory inc. in-flight credentials and JWTs".to_string(),
        });

        // Laravel Telescope / Debugbar
        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/telescope | inurl:/_debugbar | inurl:/_ignition | inurl:/horizon | intitle:\"Telescope\" | intitle:\"Laravel Debug-bar\") -github.com",
                clean_domain
            ),
            description: "Find Laravel Telescope / Debugbar / Ignition / Horizon interfaces".to_string(),
            impact: "Exposes requests, queries, session tokens, and in Ignition (CVE-2021-3129) can lead to RCE".to_string(),
        });

        // Django / Flask debug
        dorks.push(GoogleDork {
            category: "Debug Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Django Debug\" | intext:\"Exception Value:\" intext:\"Request Method:\" | intext:\"Werkzeug Debugger\" | intitle:\"Werkzeug\")",
                clean_domain
            ),
            description: "Find Django DEBUG=True tracebacks and Werkzeug (Flask) debuggers".to_string(),
            impact: "DEBUG tracebacks leak settings, env and code paths; Werkzeug pin-less debugger allows RCE".to_string(),
        });

        // phpinfo / server-status
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | inurl:info.php | intitle:phpinfo() | intitle:\"Apache Status\" | inurl:/server-status | inurl:/server-info | inurl:/nginx_status)",
                clean_domain
            ),
            description: "Find phpinfo() and Apache/Nginx status pages".to_string(),
            impact: "Leaks installed modules, env vars, loaded paths, hostnames and active requests".to_string(),
        });

        // Swagger/OpenAPI including auth-revealing specs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:swagger.yaml | inurl:openapi.json | inurl:openapi.yaml | inurl:/v2/api-docs | inurl:/v3/api-docs | inurl:/api/swagger-resources | intitle:\"Swagger UI\" inurl:/admin)",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger specs and admin API docs".to_string(),
            impact: "Reveals every endpoint, required auth scopes, example secrets, and hidden admin routes".to_string(),
        });

        // GraphQL endpoints & introspection
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/altair | intitle:\"GraphiQL\" | intitle:\"Apollo Sandbox\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints and schema explorers".to_string(),
            impact: "Allows full schema introspection and interactive exploitation of GraphQL queries/mutations".to_string(),
        });

        // Cloud metadata & SSRF-looking proxies
        dorks.push(GoogleDork {
            category: "Cloud Metadata".to_string(),
            query: format!(
                "site:{} (intext:\"ami-id\" intext:\"instance-id\" | intext:\"iam/security-credentials/\" | intext:\"metadata/v1/\" | intext:\"169.254.169.254\" | intext:\"instance/service-accounts/default/token\")",
                clean_domain
            ),
            description: "Find leaked cloud instance metadata responses".to_string(),
            impact: "IAM credentials leaked from IMDS can grant direct cloud account access".to_string(),
        });

        // Kubernetes & container orchestration UIs
        dorks.push(GoogleDork {
            category: "Infrastructure Panels".to_string(),
            query: format!(
                "site:{} (inurl:/api/v1/namespaces | intitle:\"Kubernetes Dashboard\" | intitle:\"kube-apiserver\" | inurl:/healthz | intitle:\"Portainer\" | intitle:\"Rancher\" | intitle:\"Harbor\" | intitle:\"Argo CD\" | intitle:\"ArgoCD\")",
                clean_domain
            ),
            description: "Find Kubernetes/Rancher/Portainer/Harbor/ArgoCD dashboards".to_string(),
            impact: "Direct control-plane access; unauthenticated dashboards have historically been used for cluster takeover".to_string(),
        });

        // Prometheus / Grafana / Kibana
        dorks.push(GoogleDork {
            category: "Monitoring Panels".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series\" | inurl:/graph?g0 | inurl:/targets intitle:\"Prometheus\" | intitle:\"Grafana\" inurl:/login | inurl:/api/datasources | intitle:\"Kibana\" | inurl:/app/kibana | intitle:\"Alertmanager\")",
                clean_domain
            ),
            description: "Find exposed Prometheus/Grafana/Kibana/Alertmanager UIs".to_string(),
            impact: "Exposes time-series metrics (often incl. secrets in labels), dashboards, and alert routes".to_string(),
        });

        // Jenkins / CI artifacts
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:/jenkins/script | inurl:/script intitle:\"Jenkins\" | inurl:/computer/ | inurl:/job/ intitle:\"Jenkins\" | inurl:/asynchPeople | inurl:/credentials/store)",
                clean_domain
            ),
            description: "Find Jenkins script console and credential stores".to_string(),
            impact: "/script grants Groovy RCE on Jenkins controller when unauthenticated".to_string(),
        });

        // GitLab / GitHub enterprise exposure
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:/-/explore | inurl:/users/sign_in intitle:\"GitLab\" | inurl:/admin/runners | inurl:/api/v4/projects | inurl:/-/metrics)",
                clean_domain
            ),
            description: "Find exposed GitLab instances and admin runners".to_string(),
            impact: "Public project listings can expose internal code; exposed runners can be abused for CI token exfiltration".to_string(),
        });

        // S3 / GCS / Azure public listings scoped to target
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net) intitle:\"Index of\" \"{}\"",
                clean_domain
            ),
            description: "Find listable cloud storage buckets referencing the target".to_string(),
            impact: "Directory-listing buckets routinely leak PII, backups and internal tooling".to_string(),
        });

        // Backups
        dorks.push(GoogleDork {
            category: "Backups".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:db | ext:mdb | ext:bak | ext:rdb | ext:dump | ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:7z) (intitle:\"Index of\" | inurl:/backup | inurl:/backups | inurl:/db | inurl:/dump)",
                clean_domain
            ),
            description: "Find database and filesystem backup archives".to_string(),
            impact: "Backups typically include full PII datasets, hashed passwords and secrets".to_string(),
        });

        // WordPress-specific secrets
        dorks.push(GoogleDork {
            category: "CMS Secrets".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.php~ | inurl:wp-config.php.save | inurl:wp-config.old | inurl:wp-config.txt | inurl:/wp-content/debug.log)",
                clean_domain
            ),
            description: "Find WordPress config backups and debug logs".to_string(),
            impact: "wp-config leaks DB creds + AUTH keys; debug.log leaks user data and plugin errors".to_string(),
        });

        // Magento / Shopify admin
        dorks.push(GoogleDork {
            category: "CMS Secrets".to_string(),
            query: format!(
                "site:{} (inurl:/downloader/ intitle:\"Magento Connect Manager\" | inurl:/admin/dashboard | inurl:/magento_version | inurl:/app/etc/local.xml)",
                clean_domain
            ),
            description: "Find Magento admin and config paths".to_string(),
            impact: "local.xml leaks DB credentials; downloader reveals installed modules & versions".to_string(),
        });

        // Public Postman / Insomnia / Stoplight
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:postman.com/workspace | site:postman.co | site:documenter.getpostman.com | site:elements.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces and documenters".to_string(),
            impact: "Often include live Authorization headers, bearer tokens and environment variables".to_string(),
        });

        // Stack traces / framework errors
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"at org.springframework\" | intext:\"Traceback (most recent call last)\" | intext:\"Fatal error:\" intext:\"on line\" | intext:\"ORA-\" intext:\"at oracle\" | intext:\"System.Data.SqlClient.SqlException\")",
                clean_domain
            ),
            description: "Find stack traces leaking code paths and versions".to_string(),
            impact: "Framework versions, package paths, DB drivers and sometimes secrets get indexed".to_string(),
        });

        // CVS / DS_Store / editor swapfiles
        dorks.push(GoogleDork {
            category: "Secrets in Dotfiles".to_string(),
            query: format!(
                "site:{} (inurl:.DS_Store | inurl:Thumbs.db | inurl:.vscode/settings.json | inurl:.idea/workspace.xml | inurl:.idea/dataSources.xml | ext:swp | ext:swo)",
                clean_domain
            ),
            description: "Find editor / OS metadata files with project data".to_string(),
            impact: "Reveals filesystem structure, and JetBrains dataSources.xml typically contains DB connection strings".to_string(),
        });

        // Drone/Travis/CircleCI config exposure
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:.travis.yml | inurl:.circleci/config.yml | inurl:.drone.yml | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:.gitlab-ci.yml) intext:secret",
                clean_domain
            ),
            description: "Find CI pipeline configs that reference secrets".to_string(),
            impact: "Can reveal secret names and sometimes plaintext tokens committed by mistake".to_string(),
        });

        // Terraform / Ansible state
        dorks.push(GoogleDork {
            category: "IaC".to_string(),
            query: format!(
                "site:{} (inurl:terraform.tfstate | inurl:terraform.tfstate.backup | inurl:*.tfvars | inurl:ansible/vault | inurl:group_vars | inurl:host_vars)",
                clean_domain
            ),
            description: "Find Terraform state and Ansible variable files".to_string(),
            impact: "tfstate contains every resource ID + often plaintext secrets; tfvars commonly hold cloud credentials".to_string(),
        });

        // Docker / Kubernetes configs
        dorks.push(GoogleDork {
            category: "Secrets in Dotfiles".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml intext:environment | inurl:Dockerfile intext:ARG | inurl:kubeconfig | inurl:.kube/config | inurl:values.yaml intext:secret)",
                clean_domain
            ),
            description: "Find Docker / Kubernetes / Helm configs with secrets".to_string(),
            impact: "kubeconfig gives full cluster access; compose/helm values often hold hardcoded credentials".to_string(),
        });

        // Pastebin + gist scoped on internal identifiers
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:pastebin.com | site:ghostbin.com | site:rentry.co | site:paste.ee | site:hastebin.com) (\"{}\" AND (password OR secret OR api_key OR token OR BEGIN))",
                clean_domain
            ),
            description: "Find pastes containing target identifiers and secret keywords".to_string(),
            impact: "Frequent source of accidentally disclosed production credentials".to_string(),
        });

        // Mail archive disclosures
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:marc.info | site:mail-archive.com | site:groups.google.com | site:lists.apple.com) \"{}\" (password OR credentials OR \"API key\")",
                clean_domain
            ),
            description: "Find mailing-list archives mentioning the domain with sensitive keywords".to_string(),
            impact: "Historical support threads frequently leak configuration snippets and secrets".to_string(),
        });

        // OAuth redirect URIs exposed
        dorks.push(GoogleDork {
            category: "OAuth".to_string(),
            query: format!(
                "site:{} (inurl:redirect_uri=http | inurl:client_id= | inurl:/oauth/authorize | inurl:/.well-known/openid-configuration)",
                clean_domain
            ),
            description: "Find OAuth discovery and redirect URI exposure".to_string(),
            impact: "openid-configuration reveals IdP, signing keys and flows; redirect_uri exposure enables open-redirect + account takeover chains".to_string(),
        });

        // SAML
        dorks.push(GoogleDork {
            category: "OAuth".to_string(),
            query: format!(
                "site:{} (inurl:/saml/metadata | inurl:/simplesaml | inurl:/auth/saml | inurl:/Shibboleth.sso | intitle:\"SAML Assertion\")",
                clean_domain
            ),
            description: "Find SAML metadata and SSO endpoints".to_string(),
            impact: "SAML metadata reveals IdP config and signing certs; misconfig can lead to account takeover".to_string(),
        });

        // Internal Jira / Confluence with public indexing
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!(
                "(site:atlassian.net | site:jira.{}) (intitle:\"Issue Navigator\" | inurl:/browse/ | inurl:/wiki/spaces/)",
                clean_domain
            ),
            description: "Find Atlassian Jira/Confluence resources".to_string(),
            impact: "Historically leaks internal roadmap, credentials in comments, and attachments".to_string(),
        });

        // Exposed databases via admin UIs
        dorks.push(GoogleDork {
            category: "Database Admin".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" inurl:/phpmyadmin | intitle:\"Adminer\" | intitle:\"pgAdmin\" | intitle:\"Redis Commander\" | intitle:\"Mongo Express\" | inurl:/_utils intitle:\"CouchDB\")",
                clean_domain
            ),
            description: "Find exposed database admin web UIs".to_string(),
            impact: "Direct DB admin interface; if unauthenticated or weak auth, equals full DB compromise".to_string(),
        });

        // Exposed SCADA / ICS (low FP: strict titles)
        dorks.push(GoogleDork {
            category: "ICS/OT".to_string(),
            query: format!(
                "site:{} (intitle:\"HMI - Login\" | intitle:\"SIMATIC\" | intitle:\"Modbus\" | intitle:\"WAGO\" | intitle:\"Beckhoff\" | intitle:\"iFIX\" | intitle:\"Wonderware\")",
                clean_domain
            ),
            description: "Find industrial control system HMI login pages".to_string(),
            impact: "Safety-critical exposure; unauthenticated HMIs have been used to manipulate physical processes".to_string(),
        });

        // Exposed VPN / RDP / admin gateways
        dorks.push(GoogleDork {
            category: "Remote Access".to_string(),
            query: format!(
                "site:{} (intitle:\"Fortinet\" inurl:/remote/login | intitle:\"Pulse Secure\" | intitle:\"Cisco ASA\" | intitle:\"Citrix Gateway\" | intitle:\"GlobalProtect\" | inurl:/dana-na/auth/)",
                clean_domain
            ),
            description: "Find VPN/SSL-VPN portals".to_string(),
            impact: "Highest-value credential attack surface; frequent target of pre-auth RCE CVEs".to_string(),
        });

        // OpenBugBounty / HackerOne / Bugcrowd references (recon)
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "(site:hackerone.com/reports | site:bugcrowd.com/disclosure | site:openbugbounty.org/reports) intext:\"{}\"",
                clean_domain
            ),
            description: "Find disclosed reports mentioning the target".to_string(),
            impact: "Previously disclosed issues may still be exploitable or indicate weak areas to re-test".to_string(),
        });

        // Sensitive query strings (AWS pre-signed URLs, Azure SAS)
        dorks.push(GoogleDork {
            category: "Leaked Signed URLs".to_string(),
            query: format!(
                "site:{} (inurl:\"X-Amz-Signature=\" | inurl:\"X-Amz-Credential=\" | inurl:\"sig=\" inurl:\"se=\" inurl:\"sp=\" | inurl:\"sv=\" inurl:\"sr=\" inurl:\"sig=\")",
                clean_domain
            ),
            description: "Find indexed pre-signed S3 URLs and Azure SAS tokens".to_string(),
            impact: "Indexed signed URLs grant anyone time-limited (or permanent if long-expiry) access to private blobs".to_string(),
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
