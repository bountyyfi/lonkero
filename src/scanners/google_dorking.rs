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

        // Spring Boot Actuator (high impact - heap dump, env vars, logs)
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/configprops | inurl:/actuator/beans | inurl:/actuator/health | inurl:/actuator)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "Actuator endpoints can leak environment variables, heap dumps with credentials, internal routes, and DB connection strings".to_string(),
        });

        // Jenkins UI & Script Console
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:/script | inurl:/manage | inurl:/jenkins/login | intitle:\"Hudson\")",
                clean_domain
            ),
            description: "Find exposed Jenkins / Hudson CI dashboards".to_string(),
            impact: "Unauthenticated Jenkins may allow Groovy script execution leading to RCE on the build host".to_string(),
        });

        // Kibana / Elasticsearch dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | inurl:app/kibana | inurl:_cat/indices | inurl:_cluster/health)",
                clean_domain
            ),
            description: "Find exposed Kibana / Elasticsearch endpoints".to_string(),
            impact: "Open Kibana or Elasticsearch indexes may expose application logs, PII and credentials".to_string(),
        });

        // Grafana login/dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:/login | inurl:/d/ | inurl:/api/datasources)",
                clean_domain
            ),
            description: "Find exposed Grafana instances".to_string(),
            impact: "Exposed Grafana may leak internal metrics; weak credentials enable plugin RCE (CVE-2021-43798 path traversal lineage)".to_string(),
        });

        // Prometheus / Alertmanager
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Prometheus Time Series Collection\" | inurl:/targets | inurl:/graph | intitle:\"Alertmanager\")",
                clean_domain
            ),
            description: "Find exposed Prometheus and Alertmanager UIs".to_string(),
            impact: "Internal target lists expose attack surface; service discovery configs may leak credentials".to_string(),
        });

        // Adminer / phpMyAdmin / DB UIs
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"phpMyAdmin\" | inurl:/phpmyadmin | inurl:/adminer.php | intitle:\"Adminer\" | inurl:/myadmin)",
                clean_domain
            ),
            description: "Find exposed phpMyAdmin / Adminer database UIs".to_string(),
            impact: "Exposed DB admin tools are direct paths to credential-stuffing and DB takeover".to_string(),
        });

        // Jupyter Notebooks (often unauthenticated)
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Jupyter\" | inurl:/tree | inurl:/lab | inurl:/notebooks)",
                clean_domain
            ),
            description: "Find exposed Jupyter notebook servers".to_string(),
            impact: "Open Jupyter servers allow arbitrary code execution and access to data science workloads / cloud credentials".to_string(),
        });

        // RabbitMQ / Celery Flower / Redis Commander
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"RabbitMQ Management\" | intitle:\"Flower\" | intitle:\"Redis Commander\" | inurl:/api/queues)",
                clean_domain
            ),
            description: "Find exposed message-broker management UIs".to_string(),
            impact: "Default credentials on RabbitMQ/Redis admin allow queue inspection, message injection and host-level RCE via plugins".to_string(),
        });

        // Kubernetes / Docker dashboards
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/api/v1/namespaces | intitle:\"Portainer\" | intitle:\"Rancher\")",
                clean_domain
            ),
            description: "Find exposed container orchestration dashboards".to_string(),
            impact: "Kubernetes/Portainer/Rancher UIs without auth can lead to full cluster takeover".to_string(),
        });

        // SonarQube / Nexus / Artifactory
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"SonarQube\" | intitle:\"Sonatype Nexus\" | intitle:\"JFrog\" | inurl:/artifactory)",
                clean_domain
            ),
            description: "Find exposed code-quality and artifact repositories".to_string(),
            impact: "Default credentials are common; access leaks source code, secrets in pom.xml/gradle, and signing artifacts".to_string(),
        });

        // Splunk Web
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Splunk\" inurl:/en-US/account/login | inurl:/services/auth | inurl:/en-US/app/launcher)",
                clean_domain
            ),
            description: "Find exposed Splunk Web instances".to_string(),
            impact: "Splunk admin access exposes ingested logs, search-time secrets and supports app-based RCE".to_string(),
        });

        // Docker Registry v2
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/v2/_catalog | inurl:/v2/ intext:\"repositories\")",
                clean_domain
            ),
            description: "Find exposed Docker Registry catalogs".to_string(),
            impact: "Open registries leak proprietary images; layers frequently contain embedded credentials and source code".to_string(),
        });

        // Exposed .git directories
        dorks.push(GoogleDork {
            category: "Exposed Source Code".to_string(),
            query: format!(
                "site:{} (inurl:\"/.git/HEAD\" | inurl:\"/.git/config\" | inurl:\"/.git/logs/HEAD\" | inurl:\"/.gitignore\" inurl:src)",
                clean_domain
            ),
            description: "Find exposed Git metadata".to_string(),
            impact: "An exposed .git directory typically allows full source-code dump including committed secrets and historical credentials".to_string(),
        });

        // Exposed SVN / Mercurial
        dorks.push(GoogleDork {
            category: "Exposed Source Code".to_string(),
            query: format!(
                "site:{} (inurl:\"/.svn/entries\" | inurl:\"/.svn/wc.db\" | inurl:\"/.hg/store\")",
                clean_domain
            ),
            description: "Find exposed SVN / Mercurial metadata".to_string(),
            impact: "Exposes complete source tree and credentials from VCS metadata".to_string(),
        });

        // Exposed .env / dotfiles
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\"/.env\" | inurl:\"/.env.local\" | inurl:\"/.env.production\" | inurl:\"/.env.bak\" | intext:\"DB_PASSWORD=\" | intext:\"AWS_SECRET_ACCESS_KEY=\")",
                clean_domain
            ),
            description: "Find exposed .env files and embedded credentials".to_string(),
            impact: ".env files routinely contain DB passwords, AWS keys, JWT secrets and 3rd-party API tokens".to_string(),
        });

        // CI/CD config files
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:\".travis.yml\" | inurl:\".circleci/config.yml\" | inurl:\"docker-compose.yml\" | inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\"id_rsa\" | inurl:\"id_ed25519\")",
                clean_domain
            ),
            description: "Find exposed CI/CD configs and private keys".to_string(),
            impact: "Pipelines and dotfiles frequently embed deployment credentials, registry tokens and SSH private keys".to_string(),
        });

        // PHP info / debug pages
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" | inurl:phpinfo.php | inurl:info.php intext:\"PHP Version\" | intitle:\"Django Debug\" | intext:\"Werkzeug Debugger\")",
                clean_domain
            ),
            description: "Find exposed phpinfo / framework debug pages".to_string(),
            impact: "Reveals full server configuration, loaded extensions and absolute paths; Werkzeug debugger PIN can yield RCE".to_string(),
        });

        // Atlassian Jira / Confluence anonymous access
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:/jira/secure/Dashboard.jspa | inurl:/secure/IssueNavigator.jspa | inurl:/confluence/display | inurl:/wiki/spaces | intitle:\"Confluence\" \"Log In\")",
                clean_domain
            ),
            description: "Find Jira/Confluence instances with anonymous access".to_string(),
            impact: "Anonymous Jira/Confluence frequently exposes internal tickets, credentials in comments, and signed-in-only pages via known auth bypass CVEs".to_string(),
        });

        // GitLab snippets / issues exposed
        dorks.push(GoogleDork {
            category: "Exposed Source Code".to_string(),
            query: format!(
                "site:{} (inurl:/snippets | inurl:/-/snippets | inurl:/dashboard/snippets | inurl:/.git-rewrite)",
                clean_domain
            ),
            description: "Find exposed GitLab snippets and rewrite artifacts".to_string(),
            impact: "Snippets are commonly used as scratchpads for secrets, internal scripts and PoC tokens".to_string(),
        });

        // Open S3 / GCS listings via XML
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:{} intext:\"<ListBucketResult\" | intext:\"<Contents>\" intext:\"<Key>\"",
                clean_domain
            ),
            description: "Find directory listings of S3/GCS buckets".to_string(),
            impact: "A successful ListBucket response indicates public bucket contents (often backups, exports, CI artifacts)".to_string(),
        });

        // WSDL / SOAP endpoints
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:?wsdl | ext:wsdl | inurl:/services/ | intitle:\"WSDL\")",
                clean_domain
            ),
            description: "Find SOAP/WSDL service descriptions".to_string(),
            impact: "WSDL files enumerate every operation; legacy SOAP services often lack auth and are vulnerable to XXE/SQLi".to_string(),
        });

        // Exposed backups
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:dmp | ext:rdb | ext:tar | ext:tgz | ext:tar.gz | ext:7z | ext:zip) (intext:\"backup\" | intext:\"dump\" | inurl:backup | inurl:dump)",
                clean_domain
            ),
            description: "Find exposed database and full-disk backups".to_string(),
            impact: "Backups are the highest-value target: they include full DB contents, user PII and historic secrets at once".to_string(),
        });

        // OpenAPI / Swagger UI exposing internal APIs
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:swagger-ui.html | inurl:openapi.json | inurl:openapi.yaml | inurl:/v3/api-docs | inurl:/swagger/v1)",
                clean_domain
            ),
            description: "Find Swagger/OpenAPI spec files".to_string(),
            impact: "Specs reveal internal admin endpoints and parameter shapes - the fastest path to mass assignment and IDOR".to_string(),
        });

        // SAML / SSO metadata
        dorks.push(GoogleDork {
            category: "Authentication".to_string(),
            query: format!(
                "site:{} (inurl:saml/metadata | inurl:/saml2/idp/metadata.php | inurl:/.well-known/openid-configuration | inurl:/oauth/authorize)",
                clean_domain
            ),
            description: "Find SAML/OIDC metadata and OAuth endpoints".to_string(),
            impact: "SSO metadata leaks signing certs, ACS URLs, IdP entity IDs - prerequisites for SAML response forging and discovery of allowed redirect_uris".to_string(),
        });

        // Mailman / mailing lists
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:/pipermail/ | inurl:/mailman/listinfo | inurl:/mailman/admin)",
                clean_domain
            ),
            description: "Find exposed mailing list archives and admin".to_string(),
            impact: "Archives often contain employee emails, internal-only announcements and credentials; admin allows password change".to_string(),
        });

        // ServiceNow / Salesforce communities
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:.service-now.com | inurl:/sys_attachment.do | inurl:/lightning/n/ | intitle:\"ServiceNow\")",
                clean_domain
            ),
            description: "Find ServiceNow / Salesforce community endpoints".to_string(),
            impact: "Public access to sys_attachment.do and unrestricted lightning Aura controllers has produced repeated mass-leak incidents".to_string(),
        });

        // Slack public archives mentioning the org
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:slack-redir.net \"{}\" | site:slack-files.com \"{}\" | site:slack.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find Slack archive links referencing the domain".to_string(),
            impact: "Slack export links and external channel mentions often expose internal communications and tokens".to_string(),
        });

        // CVE/disclosure hubs
        dorks.push(GoogleDork {
            category: "Known Vulnerabilities".to_string(),
            query: format!(
                "site:hackerone.com \"{}\" | site:bugcrowd.com \"{}\" | site:huntr.dev \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public bug-bounty disclosures referencing the domain".to_string(),
            impact: "Disclosed reports can highlight unpatched classes of vulnerabilities and prior intrusion paths".to_string(),
        });

        // Exposed Apache server-status / server-info
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:server-status | inurl:server-info | intitle:\"Apache Status\")",
                clean_domain
            ),
            description: "Find exposed Apache server-status / server-info".to_string(),
            impact: "Server-status leaks active request URLs (often with session tokens in query strings) and vhost layout".to_string(),
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
        assert!(results.by_category.contains_key("Exposed Admin Interfaces"));
        assert!(results.by_category.contains_key("Exposed Source Code"));
        assert!(results.by_category.contains_key("Exposed Secrets"));
        assert!(results.by_category.contains_key("Authentication"));
    }

    #[test]
    fn test_high_value_dorks_present() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        // Spot-check that signature-strong, high-impact queries are emitted.
        let queries: Vec<&str> = results.dorks.iter().map(|d| d.query.as_str()).collect();
        let joined = queries.join("\n");
        assert!(joined.contains("/actuator/heapdump"));
        assert!(joined.contains("/.git/HEAD"));
        assert!(joined.contains("swagger.json"));
        assert!(joined.contains("phpinfo"));
        assert!(joined.contains("Jupyter"));
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
