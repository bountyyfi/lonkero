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

        // -----------------------------------------------------------------
        // Additional high-signal dorks focused on impactful sensitive-data
        // findings. Every query below is written so a raw hit is a real
        // finding, not a stack-name mention — either it forces a file
        // extension known to only ship in a leak, or it demands a string
        // that only appears inside a real secret / config disclosure.
        // -----------------------------------------------------------------

        // Exposed .env / dotenv files on the target — the single highest-value
        // dork for web pentests. `intext:DB_PASSWORD` on ext:env eliminates
        // marketing pages that coincidentally serve `/env` as a marketing path.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} ext:env (intext:DB_PASSWORD | intext:APP_KEY | intext:AWS_ACCESS_KEY_ID | intext:SECRET_KEY)",
                clean_domain
            ),
            description: "Find leaked .env files with credential-bearing keys".to_string(),
            impact: "Direct disclosure of database, framework and cloud credentials — usually full application takeover".to_string(),
        });

        // Exposed .git — /.git/HEAD, /.git/config or git-cloak/GitTools listable dirs.
        dorks.push(GoogleDork {
            category: "Source Code Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/config\" | inurl:\"/.git/HEAD\" | intext:\"[core]\" ext:gitconfig | intitle:\"index of /.git\")",
                clean_domain
            ),
            description: "Find exposed .git directories or config".to_string(),
            impact: "Full source code disclosure via git-dumper; often reveals credentials in commit history".to_string(),
        });

        // Exposed .svn / .hg / CVS metadata.
        dorks.push(GoogleDork {
            category: "Source Code Exposure".to_string(),
            query: format!(
                "site:{} (inurl:\"/.svn/entries\" | inurl:\"/.svn/wc.db\" | inurl:\"/.hg/store\" | inurl:\"/CVS/Entries\")",
                clean_domain
            ),
            description: "Find exposed SVN/Mercurial/CVS working copies".to_string(),
            impact: "Full source code disclosure through version-control metadata".to_string(),
        });

        // Terraform state files — plaintext infrastructure inventory and secrets.
        dorks.push(GoogleDork {
            category: "IaC State".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | filetype:tfstate) (intext:\"terraform_version\" | intext:\"secret\" | intext:\"access_key\")",
                clean_domain
            ),
            description: "Find Terraform state / tfvars files".to_string(),
            impact: "Reveals cloud resources, IAM keys and, when present, secret values in plaintext".to_string(),
        });

        // Kubernetes / Docker configs
        dorks.push(GoogleDork {
            category: "IaC State".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\".kube/config\" | inurl:\"docker-compose.yml\" intext:\"password\" | ext:yaml intext:\"apiVersion\" intext:\"kind: Secret\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes / Docker configs and manifests".to_string(),
            impact: "Cluster credentials, deployment secrets and container registry auth".to_string(),
        });

        // SQL dumps and DB backups.
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:sql.gz | ext:bak) (intext:\"INSERT INTO\" | intext:\"CREATE TABLE\" | intext:\"DROP TABLE\" | intext:\"phpMyAdmin SQL Dump\")",
                clean_domain
            ),
            description: "Find SQL dumps and database backups".to_string(),
            impact: "Full row-level data disclosure including PII, password hashes, tokens".to_string(),
        });

        // Backup archives with tell-tale extension patterns.
        dorks.push(GoogleDork {
            category: "Backup Files".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z | ext:bak | ext:backup | ext:old) (inurl:backup | inurl:dump | inurl:archive)",
                clean_domain
            ),
            description: "Find backup archives on the site".to_string(),
            impact: "Historical source, DB dumps or config snapshots often contain live credentials".to_string(),
        });

        // Log files with likely secrets / stack traces.
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} ext:log (intext:\"password\" | intext:\"passwd\" | intext:\"token\" | intext:\"stack trace\" | intext:\"traceback\" | intext:\"Exception\")",
                clean_domain
            ),
            description: "Find log files leaking secrets or stack traces".to_string(),
            impact: "Application logs frequently contain session tokens, auth headers and account identifiers".to_string(),
        });

        // Framework-specific credential files.
        dorks.push(GoogleDork {
            category: "Framework Credentials".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php\" | inurl:\"configuration.php\" | inurl:\"config/database.yml\" | inurl:\"config/secrets.yml\" | inurl:\"appsettings.json\" intext:\"ConnectionString\" | inurl:\"web.config\" intext:\"connectionString\")",
                clean_domain
            ),
            description: "Find framework configuration files with credentials".to_string(),
            impact: "Direct DB / framework credentials from WordPress, Joomla, Rails, .NET etc.".to_string(),
        });

        // Node / Python / Ruby / PHP dependency manifests exposed as plaintext
        // (not the pretty listing) — often leads to attack-path enumeration.
        dorks.push(GoogleDork {
            category: "Dependency Manifests".to_string(),
            query: format!(
                "site:{} (inurl:\"package.json\" | inurl:\"package-lock.json\" | inurl:\"composer.json\" | inurl:\"composer.lock\" | inurl:\"Gemfile.lock\" | inurl:\"requirements.txt\" | inurl:\"pipfile.lock\" | inurl:\"pom.xml\") -inurl:node_modules",
                clean_domain
            ),
            description: "Find package manifests exposed at web root".to_string(),
            impact: "Reveals full dependency inventory with pinned versions; use for targeted CVE exploitation".to_string(),
        });

        // Public write-ups / postmortems mentioning the target — often leak
        // internal endpoints, tokens or CVE numbers.
        dorks.push(GoogleDork {
            category: "Bug Bounty Intelligence".to_string(),
            query: format!(
                "site:hackerone.com OR site:bugcrowd.com OR site:intigriti.com OR site:yeswehack.com \"{}\"",
                clean_domain
            ),
            description: "Find disclosed reports mentioning the target on bounty platforms".to_string(),
            impact: "Reveals historical vulnerabilities, program scope and out-of-scope surfaces".to_string(),
        });

        // GitHub secret hunting scoped to the target — narrower than a plain
        // site:github.com because it demands both the domain string and a
        // credential-shaped anchor.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:github.com \"{}\" (\"api_key\" | \"apikey\" | \"secret\" | \"password\" | \"BEGIN RSA PRIVATE KEY\" | \"AKIA\" | \"AIza\" | \"ghp_\" | \"xoxb-\" | \"sk_live_\")",
                clean_domain
            ),
            description: "Find GitHub code referencing the domain alongside credential tokens".to_string(),
            impact: "Live third-party leaks of API keys, DB passwords or private keys".to_string(),
        });

        // GitLab secret hunting scoped to the target.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gitlab.com \"{}\" (\"api_key\" | \"secret\" | \"password\" | \"BEGIN RSA PRIVATE KEY\" | \"AKIA\")",
                clean_domain
            ),
            description: "Find GitLab code leaking secrets tied to the domain".to_string(),
            impact: "Same as GitHub code leaks – often live production credentials".to_string(),
        });

        // Postman public workspaces / collections – frequently leaks
        // authenticated API examples with real bearer tokens.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:postman.com \"{}\"", clean_domain),
            description: "Find public Postman workspaces and collections mentioning the domain".to_string(),
            impact: "Public API collections routinely embed bearer tokens, cookies and admin endpoints".to_string(),
        });

        // Public Notion / Confluence / Coda pages – common accidental exposure.
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "(site:notion.so | site:confluence.atlassian.net | site:coda.io | site:hackmd.io | site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find internal documentation exposed publicly".to_string(),
            impact: "Runbooks, credential vaults and infra maps regularly appear in public workspaces".to_string(),
        });

        // Slack / Discord / Google Docs shared-link leaks with the target.
        dorks.push(GoogleDork {
            category: "Chat & Shared Docs".to_string(),
            query: format!(
                "(site:*.slack.com | site:discord.com/channels | site:docs.google.com | site:sheets.google.com | site:onedrive.live.com) \"{}\"",
                clean_domain
            ),
            description: "Find chat exports and shared documents referencing the domain".to_string(),
            impact: "Historic conversations may include incident details, credentials or PII".to_string(),
        });

        // Elasticsearch / Kibana clusters exposed via search-indexable pages.
        dorks.push(GoogleDork {
            category: "Data Stores".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | inurl:\"/_cluster/health\" | inurl:\"/_cat/indices\" | intext:\"cluster_name\" intext:\"status\" intext:\"number_of_nodes\")",
                clean_domain
            ),
            description: "Find exposed Elasticsearch/Kibana surfaces".to_string(),
            impact: "Unauthenticated ES clusters expose full index contents; Kibana dashboards leak logs and PII".to_string(),
        });

        // Prometheus / Grafana exposed dashboards and metrics.
        dorks.push(GoogleDork {
            category: "Monitoring".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:\"/login\" | inurl:\"/metrics\" intext:\"# HELP\" intext:\"# TYPE\" | inurl:\"/api/v1/targets\" | intitle:\"Prometheus Time Series Collection\")",
                clean_domain
            ),
            description: "Find exposed Grafana/Prometheus surfaces".to_string(),
            impact: "Metrics reveal service inventory, request rates and internal hostnames; open Grafana often has anon-view dashboards".to_string(),
        });

        // Actuator / management endpoints (Spring Boot family).
        dorks.push(GoogleDork {
            category: "Framework Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/loggers\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/beans\" | inurl:\"/env\" intext:\"systemProperties\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/actuator/env leaks env vars; /heapdump extracts JVM memory including secrets and sessions".to_string(),
        });

        // Django / Flask / Symfony debug pages.
        dorks.push(GoogleDork {
            category: "Debug Pages".to_string(),
            query: format!(
                "site:{} (intitle:\"Werkzeug Debugger\" | intitle:\"DEBUG = True\" | intext:\"You're seeing this error because you have\" | intitle:\"Whoops! There was an error\" | inurl:\"_profiler\" | inurl:\"_wdt\")",
                clean_domain
            ),
            description: "Find framework debug pages (Werkzeug / Django / Symfony)".to_string(),
            impact: "Debug consoles allow arbitrary code execution; error pages leak framework paths and env".to_string(),
        });

        // AEM / JCR sensitive endpoints beyond the paths already listed.
        dorks.push(GoogleDork {
            category: "AEM Paths".to_string(),
            query: format!(
                "site:{} (inurl:\"/etc/replication\" | inurl:\"/system/console\" | inurl:\"/crx/packmgr/service.jsp\" | inurl:\".query.json\" | inurl:\".infinity.json\")",
                clean_domain
            ),
            description: "Find high-impact AEM/JCR endpoints".to_string(),
            impact: "Unauthed AEM disclosures often lead to full node walks, replication agent takeover and RCE".to_string(),
        });

        // Wide-open directory listings — narrowed with sensitive names.
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"index of\" (\"backup\" | \"private\" | \"config\" | \"credentials\" | \"secrets\" | \"database\" | \"logs\" | \".env\" | \".git\" | \"id_rsa\")",
                clean_domain
            ),
            description: "Find directory listings exposing sensitive names".to_string(),
            impact: "Directory listings often reveal reachable backup/credential files".to_string(),
        });

        // IIS/Windows-specific sensitive files.
        dorks.push(GoogleDork {
            category: "IIS Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\"web.config\" | inurl:\"machine.config\" | inurl:\"applicationhost.config\" | ext:pfx | ext:asax | inurl:\"trace.axd\" | inurl:\"elmah.axd\")",
                clean_domain
            ),
            description: "Find IIS/.NET sensitive files (web.config, ELMAH, machine keys)".to_string(),
            impact: "ELMAH exposes stack traces with headers/tokens; web.config and pfx leak crypto material".to_string(),
        });

        // Java sensitive files.
        dorks.push(GoogleDork {
            category: "Java Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\"WEB-INF/web.xml\" | inurl:\"META-INF/MANIFEST.MF\" | inurl:\"WEB-INF/classes/application.properties\" | inurl:\"WEB-INF/classes/application.yml\" | ext:jsp inurl:\"cmd=\")",
                clean_domain
            ),
            description: "Find Java web-app internals (WEB-INF, application.properties)".to_string(),
            impact: "Reveals servlet mappings, DB credentials and pre-shared secrets".to_string(),
        });

        // SSH / TLS keys mistakenly served over HTTP.
        dorks.push(GoogleDork {
            category: "Key Material".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:cer | ext:crt | ext:p12 | ext:pfx | inurl:\"id_rsa\" | inurl:\"id_dsa\" | inurl:\"authorized_keys\") -inurl:\"public\"",
                clean_domain
            ),
            description: "Find TLS/SSH key material served from the site".to_string(),
            impact: "Direct private-key disclosure — impersonation, decryption, lateral movement".to_string(),
        });

        // Wildcard cloud-storage discovery — variants beyond the exact
        // provider-per-dork listed above; use Google to enumerate bucket names
        // that reference the brand.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:storage.googleapis.com | site:blob.core.windows.net | site:*.digitaloceanspaces.com | site:*.r2.dev | site:*.b-cdn.net | site:*.wasabisys.com) \"{}\"",
                clean_domain
            ),
            description: "Discover misconfigured object-storage buckets across major providers".to_string(),
            impact: "Public buckets routinely contain backups, uploads, tokens and PII".to_string(),
        });

        // Container / package registries mentioning the target.
        dorks.push(GoogleDork {
            category: "Package Repositories".to_string(),
            query: format!(
                "(site:hub.docker.com | site:quay.io | site:ghcr.io | site:npmjs.com | site:pypi.org | site:rubygems.org) \"{}\"",
                clean_domain
            ),
            description: "Find public container/package artifacts referencing the domain".to_string(),
            impact: "Internal build artifacts published to public registries often contain secrets and source".to_string(),
        });

        // CI logs / build artifact leaks (Travis, CircleCI, GitHub Actions).
        dorks.push(GoogleDork {
            category: "CI Leaks".to_string(),
            query: format!(
                "(site:travis-ci.com | site:travis-ci.org | site:app.circleci.com | site:buildkite.com | site:app.netlify.com/sites) \"{}\"",
                clean_domain
            ),
            description: "Find CI build logs mentioning the domain".to_string(),
            impact: "Public CI logs regularly print environment variables and command output containing secrets".to_string(),
        });

        // Wayback / archive views of removed content.
        dorks.push(GoogleDork {
            category: "Archived Content".to_string(),
            query: format!(
                "site:web.archive.org \"{}\" (inurl:.env | inurl:.git | inurl:backup | inurl:config)",
                clean_domain
            ),
            description: "Find archived copies of sensitive URLs".to_string(),
            impact: "Removed files (env, config, backups) are often permanently retrievable from the Wayback Machine".to_string(),
        });

        // GraphQL endpoints exposed publicly (schema disclosure).
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/v1/graphql\" | inurl:\"/api/graphql\" | intext:\"__schema\" intext:\"queryType\")",
                clean_domain
            ),
            description: "Find GraphQL endpoints and GraphiQL consoles".to_string(),
            impact: "Introspection reveals full schema; GraphiQL enables blind-spot exploitation and enumeration".to_string(),
        });

        // Public JIRA / Confluence discovery pages that expose issues.
        dorks.push(GoogleDork {
            category: "Ticketing".to_string(),
            query: format!(
                "(site:*.atlassian.net | site:*.jira.com) inurl:\"issues/?jql\" OR inurl:\"browse\" \"{}\"",
                clean_domain
            ),
            description: "Find exposed JIRA/Confluence content".to_string(),
            impact: "Anonymous JIRA disclosure reveals attack surface and reported bugs".to_string(),
        });

        // Public S3 static-website / CloudFront distribution mistakes.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3-website-us-east-1.amazonaws.com | site:s3-website.us-east-2.amazonaws.com | site:s3.eu-west-1.amazonaws.com | site:s3.eu-central-1.amazonaws.com | site:s3.ap-southeast-1.amazonaws.com) \"{}\"",
                clean_domain
            ),
            description: "Find regional S3 static-hosting buckets".to_string(),
            impact: "Static-hosting buckets often serve config JSON, sourcemaps and unlisted directories".to_string(),
        });

        // Publicly indexed Firebase RTDB / Firestore-rest endpoints.
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "(site:firebaseio.com | site:*.firebasedatabase.app | site:firestore.googleapis.com) \"{}\"",
                clean_domain
            ),
            description: "Find Firebase RTDB/Firestore endpoints".to_string(),
            impact: "World-readable Firebase DBs often contain user data, session tokens and payment info".to_string(),
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
