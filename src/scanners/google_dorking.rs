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

        // ===== Sensitive-info dorks (additive; no XSS/SQLi/RCE payloads) =====
        // Each dork below targets indexed *content* that almost always represents a
        // real exposure when returned as a search hit. Categories were chosen for
        // signal-to-noise: backup archives, environment files, exposed VCS, leaked
        // credentials, monitoring/CI dashboards, and indexed paste/dev sites.

        // Backup archives indexed on the target domain.
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} ext:zip | ext:rar | ext:7z | ext:tar | ext:tgz | ext:tar.gz | ext:gz | ext:bz2 | ext:tar.bz2 | ext:bak | ext:backup | ext:old | ext:save | ext:dump",
                clean_domain
            ),
            description: "Find indexed backup archives on the target domain".to_string(),
            impact: "Backup archives often ship full source, .env, and DB credentials".to_string(),
        });

        // Database dumps / dump files
        dorks.push(GoogleDork {
            category: "Database Dumps".to_string(),
            query: format!(
                "site:{} ext:sql | ext:dbf | ext:mdb | ext:accdb | ext:sqlite | ext:sqlite3 | ext:db | ext:dmp",
                clean_domain
            ),
            description: "Find indexed database files / SQL dumps".to_string(),
            impact: "Database dumps disclose schemas, hashes, PII, and often production data wholesale".to_string(),
        });

        // .env / environment configuration files
        dorks.push(GoogleDork {
            category: "Environment Files".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:.env.local | inurl:.env.production | inurl:.env.dev | inurl:.env.staging | inurl:env.json) intext:\"DB_PASSWORD\" | intext:\"SECRET_KEY\" | intext:\"AWS_ACCESS_KEY_ID\" | intext:\"DATABASE_URL\"",
                clean_domain
            ),
            description: "Find exposed .env files containing secrets".to_string(),
            impact: "Direct disclosure of database, cloud, and API credentials".to_string(),
        });

        // .git directory / VCS metadata exposure
        dorks.push(GoogleDork {
            category: "VCS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.git/index | inurl:.gitignore | inurl:.svn/entries | inurl:.hg/store | inurl:CVS/Root)",
                clean_domain
            ),
            description: "Find exposed .git/.svn/.hg/CVS metadata".to_string(),
            impact: "Full repository can be reconstructed; leaks history, secrets, and intellectual property".to_string(),
        });

        // Private SSH/TLS keys
        dorks.push(GoogleDork {
            category: "Private Keys".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:p12 | ext:pfx | ext:keystore | ext:jks | ext:asc | ext:gpg | inurl:id_rsa | inurl:id_dsa | inurl:id_ecdsa | inurl:id_ed25519) intext:\"BEGIN \" intext:\"PRIVATE KEY\"",
                clean_domain
            ),
            description: "Find indexed PEM/PKCS#12/keystore private key material".to_string(),
            impact: "Server impersonation, code-signing abuse, full TLS or SSH compromise".to_string(),
        });

        // phpinfo() and similar debug endpoints
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" | inurl:phpinfo.php | inurl:test.php intext:\"PHP Version\" | inurl:info.php intext:\"PHP Version\" | intitle:\"Whoops! There was an error\" | intitle:\"Werkzeug Debugger\" | intext:\"Django Debug Toolbar\" | intext:\"Symfony Profiler\" | intitle:\"Rails Application\" intext:\"Routes\")",
                clean_domain
            ),
            description: "Find phpinfo and framework debug pages".to_string(),
            impact: "Discloses environment variables, paths, and often credentials; remote debug pages allow code execution".to_string(),
        });

        // Apache/Nginx server status / mod_status
        dorks.push(GoogleDork {
            category: "Server Status Pages".to_string(),
            query: format!(
                "site:{} (inurl:server-status | inurl:server-info | inurl:nginx_status | inurl:status?full | intitle:\"Apache Status\" | intitle:\"nginx status\")",
                clean_domain
            ),
            description: "Find exposed Apache mod_status / Nginx stub_status pages".to_string(),
            impact: "Exposes live URLs, internal IPs, vhost names, and request volumes".to_string(),
        });

        // Directory listings indexed by Google
        dorks.push(GoogleDork {
            category: "Directory Listings".to_string(),
            query: format!(
                "site:{} (intitle:\"Index of /\" | intitle:\"Index of /backup\" | intitle:\"Index of /admin\" | intitle:\"Index of /uploads\" | intitle:\"Index of /private\" | intitle:\"Index of /db\" | intitle:\"Index of /sql\" | intitle:\"Index of /logs\")",
                clean_domain
            ),
            description: "Find directory listings (Apache/Nginx autoindex)".to_string(),
            impact: "Browseable directories often contain backups, source, and credentials".to_string(),
        });

        // Spring Boot Actuator / management endpoints
        dorks.push(GoogleDork {
            category: "Management Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/actuator | inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/loggers | inurl:/actuator/configprops | inurl:/management | inurl:/jolokia | inurl:/metrics | inurl:/trace | inurl:/threaddump)",
                clean_domain
            ),
            description: "Find Spring Boot Actuator / Jolokia / management endpoints".to_string(),
            impact: "Heapdump leaks tokens and sessions; env exposes secrets; Jolokia can lead to RCE".to_string(),
        });

        // CI/CD systems
        dorks.push(GoogleDork {
            category: "CI/CD Systems".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/job/ | inurl:/jenkins/ | intitle:\"TeamCity\" | inurl:/teamcity | inurl:/buildbot | inurl:/concourse | intitle:\"GoCD\" | inurl:/.gitlab-ci.yml | inurl:/Jenkinsfile)",
                clean_domain
            ),
            description: "Find exposed Jenkins, TeamCity, GoCD, GitLab CI configs / dashboards".to_string(),
            impact: "Build histories leak tokens; unauthenticated build triggers enable supply-chain attacks".to_string(),
        });

        // Monitoring & observability dashboards
        dorks.push(GoogleDork {
            category: "Monitoring Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" | inurl:/grafana | intitle:\"Kibana\" | inurl:/kibana | intitle:\"Prometheus Time Series\" | inurl:/prometheus | inurl:/graph?g0.expr | intitle:\"Splunk\" inurl:/en-US/app | intitle:\"Datadog\" | intitle:\"New Relic\" | intitle:\"AppDynamics\")",
                clean_domain
            ),
            description: "Find exposed monitoring/observability UIs".to_string(),
            impact: "Grafana/Kibana frequently leak query data, dashboards, and embedded credentials".to_string(),
        });

        // Search-engine / data-store admin UIs
        dorks.push(GoogleDork {
            category: "Search & Data Stores".to_string(),
            query: format!(
                "site:{} (intitle:\"Elasticsearch\" inurl:/_cat | inurl:/_cluster/health | inurl:/_search?pretty | intitle:\"Mongo Express\" | inurl:/mongo-express | intitle:\"phpMyAdmin\" | inurl:/phpmyadmin | intitle:\"Adminer\" | inurl:/adminer.php | intitle:\"RethinkDB\" | inurl:/_admin)",
                clean_domain
            ),
            description: "Find exposed Elasticsearch, Mongo Express, phpMyAdmin, Adminer, etc.".to_string(),
            impact: "Direct database access; full data exfiltration and tampering".to_string(),
        });

        // Container / orchestration management
        dorks.push(GoogleDork {
            category: "Container Orchestration".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/api/v1/namespaces | inurl:/swagger.json inurl:kubernetes | intitle:\"Portainer\" | inurl:/portainer | intitle:\"Rancher\" | inurl:/rancher | inurl:/2375/info | inurl:/2376/info | intitle:\"Docker Registry\")",
                clean_domain
            ),
            description: "Find Kubernetes/Portainer/Rancher/Docker exposures".to_string(),
            impact: "Cluster takeover; container escape; image tampering".to_string(),
        });

        // Internal wikis / docs / issue trackers
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "site:{} (intitle:\"Confluence\" | inurl:/wiki/spaces | inurl:/display/ | intitle:\"DokuWiki\" | inurl:/doku.php | intitle:\"MediaWiki\" inurl:/index.php?title=Special: | intitle:\"Roadie\" | intitle:\"Backstage\" inurl:/catalog | intitle:\"Notion\" inurl:/wiki)",
                clean_domain
            ),
            description: "Find exposed wikis and internal knowledge bases".to_string(),
            impact: "Wikis routinely contain runbooks, secrets, IPs, and architectural details".to_string(),
        });

        // Issue trackers (separate from wiki because impact differs)
        dorks.push(GoogleDork {
            category: "Issue Trackers".to_string(),
            query: format!(
                "site:{} (inurl:/jira/browse | inurl:/projects/ inurl:/issues | intitle:\"YouTrack\" | inurl:/youtrack | intitle:\"Redmine\" | inurl:/redmine | intitle:\"Mantis\" | intitle:\"Bugzilla\" | inurl:/show_bug.cgi)",
                clean_domain
            ),
            description: "Find exposed issue trackers (Jira/YouTrack/Redmine/Mantis/Bugzilla)".to_string(),
            impact: "Tickets leak vulnerability reports, internal designs, employee names, and credentials".to_string(),
        });

        // Email archives, mailing list dumps, newsletter exposes
        dorks.push(GoogleDork {
            category: "Email & Mailing Lists".to_string(),
            query: format!(
                "site:{} (ext:eml | ext:msg | ext:mbox | inurl:/pipermail | inurl:/mailman | inurl:/listinfo | intitle:\"Mailman archives\")",
                clean_domain
            ),
            description: "Find email archives and mailing list dumps".to_string(),
            impact: "Internal communications, password resets, and PII frequently archived".to_string(),
        });

        // PII / financial data spreadsheets
        dorks.push(GoogleDork {
            category: "PII Spreadsheets".to_string(),
            query: format!(
                "site:{} (ext:xls | ext:xlsx | ext:csv | ext:ods) (intext:\"ssn\" | intext:\"social security\" | intext:\"credit card\" | intext:\"date of birth\" | intext:\"passport\" | intext:\"henkilotunnus\" | intext:\"personnummer\" | intext:\"national id\")",
                clean_domain
            ),
            description: "Find spreadsheets containing PII or financial identifiers".to_string(),
            impact: "Direct privacy / regulatory breach (GDPR, HIPAA, PCI)".to_string(),
        });

        // Log files indexed publicly
        dorks.push(GoogleDork {
            category: "Log Files".to_string(),
            query: format!(
                "site:{} (ext:log | ext:logs | ext:txt) (intext:\"error\" | intext:\"exception\" | intext:\"stacktrace\" | intext:\"traceback\" | intext:\"DEBUG\" | intext:\"Bearer \" | intext:\"Authorization:\")",
                clean_domain
            ),
            description: "Find exposed application/server log files".to_string(),
            impact: "Logs frequently leak tokens, session IDs, internal hosts, and PII".to_string(),
        });

        // Exposed Postman / Insomnia collections
        dorks.push(GoogleDork {
            category: "API Collections".to_string(),
            query: format!(
                "(site:postman.com inurl:workspace \"{}\") | (site:postman.com inurl:collection \"{}\") | (site:documenter.getpostman.com \"{}\")",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Postman workspaces / collections referencing the target".to_string(),
            impact: "Collections embed real auth tokens, environment vars, and full endpoint inventories".to_string(),
        });

        // Code-search engines
        dorks.push(GoogleDork {
            category: "Code Search Engines".to_string(),
            query: format!(
                "(site:sourcegraph.com \"{}\") | (site:grep.app \"{}\") | (site:publicwww.com \"{}\") | (site:searchcode.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find references to the target on public code-search engines".to_string(),
            impact: "Reveals leaked tokens, internal hostnames, and dependencies in third-party code".to_string(),
        });

        // GitHub gists (separate from generic github.com search; gists routinely leak)
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Find GitHub Gists mentioning the target domain".to_string(),
            impact: "Gists are commonly used to share quick snippets containing live credentials".to_string(),
        });

        // Bitbucket
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!("site:bitbucket.org \"{}\"", clean_domain),
            description: "Find Bitbucket repositories mentioning the target".to_string(),
            impact: "May expose source code, pipelines, and credentials".to_string(),
        });

        // Replit / Glitch / CodeSandbox / StackBlitz
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:replit.com \"{}\") | (site:glitch.com \"{}\") | (site:codesandbox.io \"{}\") | (site:stackblitz.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find Replit/Glitch/CodeSandbox/StackBlitz projects mentioning the target".to_string(),
            impact: "Sandbox projects often hardcode tokens and proxy real backend APIs".to_string(),
        });

        // Pastebin alternatives (additional sites beyond pastebin.com)
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:rentry.co \"{}\") | (site:hastebin.com \"{}\") | (site:dpaste.com \"{}\") | (site:paste.ee \"{}\") | (site:ghostbin.co \"{}\") | (site:0bin.net \"{}\") | (site:controlc.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find leaked snippets on alternative paste sites".to_string(),
            impact: "Paste sites frequently host stolen credentials and internal data dumps".to_string(),
        });

        // Public collaboration / docs
        dorks.push(GoogleDork {
            category: "Public Collaboration".to_string(),
            query: format!(
                "(site:notion.so \"{}\") | (site:notion.site \"{}\") | (site:coda.io \"{}\") | (site:airtable.com \"{}\") | (site:miro.com \"{}\") | (site:figma.com \"{}\") | (site:slab.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find publicly-shared Notion, Coda, Airtable, Miro, Figma, Slab pages".to_string(),
            impact: "Collaborative docs leak architecture, processes, employees, and sometimes secrets".to_string(),
        });

        // PaaS preview/staging deployments
        dorks.push(GoogleDork {
            category: "PaaS Preview Domains".to_string(),
            query: format!(
                "(site:vercel.app \"{}\") | (site:netlify.app \"{}\") | (site:onrender.com \"{}\") | (site:fly.dev \"{}\") | (site:railway.app \"{}\") | (site:herokuapp.com \"{}\") | (site:cloudfunctions.net \"{}\") | (site:run.app \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find PaaS preview/staging deployments referencing the target".to_string(),
            impact: "Preview environments often skip auth, expose debug data, and leak secrets".to_string(),
        });

        // Object storage (extended beyond AWS-only)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com \"{}\") | (site:storage.cloud.google.com \"{}\") | (site:firebasestorage.googleapis.com \"{}\") | (site:r2.cloudflarestorage.com \"{}\") | (site:wasabisys.com \"{}\") | (site:linodeobjects.com \"{}\") | (site:backblazeb2.com \"{}\") | (site:contabostorage.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find objects in additional cloud storage providers".to_string(),
            impact: "Misconfigured buckets across multi-cloud setups often leak data".to_string(),
        });

        // Indexed exception trackers
        dorks.push(GoogleDork {
            category: "Error Trackers".to_string(),
            query: format!(
                "(site:sentry.io \"{}\") | (site:bugsnag.com \"{}\") | (site:rollbar.com \"{}\") | (site:honeybadger.io \"{}\") | (site:airbrake.io \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find exception/error tracker pages referencing the target".to_string(),
            impact: "Crash reports leak stack traces, source paths, and user data".to_string(),
        });

        // Customer support / ticket portals (intel + sometimes attachments)
        dorks.push(GoogleDork {
            category: "Support Portals".to_string(),
            query: format!(
                "(site:zendesk.com \"{}\") | (site:freshdesk.com \"{}\") | (site:intercom.com \"{}\") | (site:helpscout.net \"{}\") | (site:groovehq.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find support portals referencing the target".to_string(),
            impact: "Public tickets sometimes contain PII, internal procedures, or credentials".to_string(),
        });

        // SOAP / WSDL endpoints
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (ext:wsdl | ext:asmx | inurl:?wsdl | inurl:?singleWsdl | inurl:?disco | inurl:Service.asmx)",
                clean_domain
            ),
            description: "Find SOAP/WSDL service descriptions".to_string(),
            impact: "WSDL enumerates every operation and parameter; legacy SOAP often skips auth".to_string(),
        });

        // GraphQL endpoint exposure (introspection / playground)
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/api/graphql | intitle:\"GraphQL Playground\" | intitle:\"Apollo Studio\")",
                clean_domain
            ),
            description: "Find exposed GraphQL endpoints / playgrounds".to_string(),
            impact: "Introspection reveals full schema; playgrounds frequently allow unauthenticated queries".to_string(),
        });

        // IIS / .NET configuration leftovers
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:config | ext:webconfig | inurl:web.config | inurl:appsettings.json | inurl:appsettings.Development.json | inurl:appsettings.Production.json)",
                clean_domain
            ),
            description: "Find exposed .NET / IIS configuration files".to_string(),
            impact: "appsettings/web.config commonly contain connection strings and machine keys".to_string(),
        });

        // WordPress sensitive paths
        dorks.push(GoogleDork {
            category: "CMS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php | inurl:wp-config.php.bak | inurl:wp-config.php.old | inurl:wp-config.php~ | inurl:.wp-config.php.swp | inurl:wp-content/debug.log | inurl:wp-content/uploads/backup)",
                clean_domain
            ),
            description: "Find WordPress wp-config backups and debug logs".to_string(),
            impact: "wp-config exposes DB credentials and auth keys; full site takeover".to_string(),
        });

        // IDE / editor leftovers
        dorks.push(GoogleDork {
            category: "IDE Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:.vscode/settings.json | inurl:.idea/workspace.xml | inurl:.idea/dataSources.xml | inurl:.DS_Store | inurl:Thumbs.db | inurl:.history)",
                clean_domain
            ),
            description: "Find IDE/editor artifact files left on the server".to_string(),
            impact: "DataSources.xml leaks DB connection info; .DS_Store enumerates filenames".to_string(),
        });

        // Cloud / IaC leftovers
        dorks.push(GoogleDork {
            category: "Infrastructure as Code".to_string(),
            query: format!(
                "site:{} (ext:tf | ext:tfvars | ext:tfstate | inurl:terraform.tfstate | inurl:terraform.tfstate.backup | ext:yaml inurl:helm | inurl:docker-compose.yml | inurl:docker-compose.override.yml | inurl:Dockerfile | inurl:.helmignore | inurl:kustomization.yaml)",
                clean_domain
            ),
            description: "Find indexed Terraform state, Helm, and docker-compose files".to_string(),
            impact: "tfstate often contains plaintext secrets and full infra topology".to_string(),
        });

        // Mobile app stores (intel for in-scope mobile apps)
        dorks.push(GoogleDork {
            category: "Mobile Applications".to_string(),
            query: format!(
                "(site:play.google.com \"{}\") | (site:apps.apple.com \"{}\") | (site:apkpure.com \"{}\") | (site:apkmirror.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find mobile applications associated with the target".to_string(),
            impact: "Mobile apps embed API keys and reveal additional attack surface".to_string(),
        });

        // Workforce intel via job postings (tech-stack recon, almost zero false positives)
        dorks.push(GoogleDork {
            category: "Tech Stack Recon".to_string(),
            query: format!(
                "(site:linkedin.com/jobs \"{}\") | (site:stackoverflow.com/jobs \"{}\") | (site:greenhouse.io \"{}\") | (site:lever.co \"{}\") | (site:workable.com \"{}\")",
                clean_domain, clean_domain, clean_domain, clean_domain, clean_domain
            ),
            description: "Find job postings disclosing the target's internal tech stack".to_string(),
            impact: "Job descriptions reveal exact frameworks, services, and security tooling in use".to_string(),
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
