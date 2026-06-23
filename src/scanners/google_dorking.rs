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

        // Spring Boot Actuator endpoints - extremely high impact
        dorks.push(GoogleDork {
            category: "Exposed Actuator".to_string(),
            query: format!(
                "site:{} (inurl:/actuator/env | inurl:/actuator/heapdump | inurl:/actuator/threaddump | inurl:/actuator/mappings | inurl:/actuator/beans | inurl:/actuator/configprops | inurl:/env | inurl:/jolokia | inurl:/trace | inurl:/heapdump)",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env, /heapdump, /trace can leak credentials, JWTs, full config; /jolokia and /beans can lead to RCE".to_string(),
        });

        // Exposed VCS metadata - .git, .svn, .hg
        dorks.push(GoogleDork {
            category: "Exposed Source".to_string(),
            query: format!(
                "site:{} (inurl:/.git/HEAD | inurl:/.git/config | inurl:/.svn/entries | inurl:/.hg/store | inurl:/.bzr | inurl:/CVS/Entries)",
                clean_domain
            ),
            description: "Find exposed VCS metadata directories".to_string(),
            impact: "Allows reconstruction of full source history including secrets that were later removed".to_string(),
        });

        // Exposed env / config files - extremely impactful
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:env.production | inurl:env.local | inurl:.env.bak | inurl:.env.backup | inurl:wp-config.php.bak | inurl:settings.py.bak | inurl:application.properties | inurl:application.yml | inurl:secrets.yml | inurl:credentials.json | inurl:firebase.json | inurl:.aws/credentials | inurl:config/database.yml)",
                clean_domain
            ),
            description: "Find exposed environment / config files".to_string(),
            impact: ".env / application.* / database.yml typically contain DB credentials, API keys, JWT secrets, OAuth client secrets".to_string(),
        });

        // Source maps - allow full source reconstruction
        dorks.push(GoogleDork {
            category: "Exposed Source".to_string(),
            query: format!(
                "site:{} (ext:map | inurl:.js.map | inurl:.css.map | inurl:.mjs.map)",
                clean_domain
            ),
            description: "Find exposed JavaScript/CSS source maps".to_string(),
            impact: "Source maps reveal original (often minified-away) source code, internal endpoints, comments and developer notes".to_string(),
        });

        // Postman collections / Insomnia / Bruno - often contain keys
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "(site:postman.com | site:getpostman.com | site:documenter.getpostman.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman workspaces / collections".to_string(),
            impact: "Public Postman collections often embed Authorization headers, API keys, and full request examples with real data".to_string(),
        });

        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:postman_collection.json | inurl:insomnia.json | inurl:bruno.json | inurl:thunder-collection)",
                clean_domain
            ),
            description: "Find exposed API client collections on the target".to_string(),
            impact: "API client export files frequently contain authorization headers, tokens, and internal endpoints".to_string(),
        });

        // GraphQL endpoints
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/playground | inurl:/altair | inurl:/voyager | intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\")",
                clean_domain
            ),
            description: "Find GraphQL endpoints and exposed playgrounds".to_string(),
            impact: "Exposed GraphiQL / Playground often allow introspection on production schemas, exposing internal types and queries".to_string(),
        });

        // Database admin panels - very high impact when found
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/phpmyadmin | inurl:/adminer.php | inurl:/dbadmin | inurl:/mysql/admin | inurl:/pgadmin | inurl:/myadmin | intitle:\"phpMyAdmin\" | intitle:\"Adminer\")",
                clean_domain
            ),
            description: "Find database administration interfaces".to_string(),
            impact: "Direct DB admin panels are high-impact entry points; common targets for credential bruteforce or known CVEs".to_string(),
        });

        // Internal dashboards & monitoring (Kibana / Grafana / Prometheus / Consul)
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/kibana | inurl:/_plugin/kibana | inurl:/grafana/login | inurl:/prometheus | inurl:/alertmanager | inurl:/consul/ui | inurl:/nomad/ui | inurl:/vault/ui | intitle:\"Kibana\" | intitle:\"Grafana\")",
                clean_domain
            ),
            description: "Find internal monitoring / orchestration dashboards".to_string(),
            impact: "These dashboards often run with default creds and expose internal services, secrets and metrics".to_string(),
        });

        // PHP debug pages, info disclosure
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (inurl:phpinfo.php | intitle:\"phpinfo()\" | intext:\"PHP Version\" intext:\"System\" intext:\"Configuration File\")",
                clean_domain
            ),
            description: "Find exposed phpinfo() pages".to_string(),
            impact: "phpinfo() reveals server config, env vars, loaded modules and absolute paths - useful for chaining exploits".to_string(),
        });

        // Laravel debug page (Whoops/Ignition) - has RCE CVE-2021-3129
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"Whoops! There was an error\" | intext:\"Ignition\" | intext:\"laravel\" intext:\"trace\" | intext:\"file_get_contents\" intext:\"vendor/laravel\")",
                clean_domain
            ),
            description: "Find Laravel debug/Whoops error pages".to_string(),
            impact: "Whoops/Ignition pages leak source paths and env vars; CVE-2021-3129 allows RCE through the Ignition debug bar".to_string(),
        });

        // Django debug page (DEBUG=True in prod)
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intitle:\"DisallowedHost\" | intext:\"You're seeing this error because you have DEBUG = True\" | intext:\"Django Version\" intext:\"Traceback\")",
                clean_domain
            ),
            description: "Find Django DEBUG=True error pages".to_string(),
            impact: "Django debug mode leaks settings, installed apps, middleware, full traceback with local variables and secrets".to_string(),
        });

        // Symfony / Rails debug pages
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intitle:\"Symfony Exception\" | intext:\"Symfony Profiler\" | inurl:/_profiler | inurl:/_wdt | intext:\"Action Controller: Exception caught\" | intitle:\"Web Console\")",
                clean_domain
            ),
            description: "Find Symfony Profiler / Rails web-console exposure".to_string(),
            impact: "Symfony /_profiler exposes routes, env and request data; Rails web-console allows IRB on the server (RCE)".to_string(),
        });

        // Hasura console exposed
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:/console/data | inurl:/console/api/graphql | intitle:\"Hasura Console\")",
                clean_domain
            ),
            description: "Find exposed Hasura GraphQL admin console".to_string(),
            impact: "Hasura console exposes full schema and (if admin-secret leaks) gives unrestricted DB access".to_string(),
        });

        // Strapi admin
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/admin/auth/login intitle:\"Strapi\" | intitle:\"Welcome to your Strapi app\")",
                clean_domain
            ),
            description: "Find Strapi CMS admin login pages".to_string(),
            impact: "Strapi has had multiple auth bypass CVEs; default install is often left with weak admin password".to_string(),
        });

        // Drupal install / install.php
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/install.php | inurl:/install/ | inurl:/setup.php | inurl:/setup-config.php | intext:\"Drupal installation\")",
                clean_domain
            ),
            description: "Find leftover installation scripts".to_string(),
            impact: "Unfinished installers (Drupal/WordPress/Joomla install.php, etc.) allow attacker to reinstall the app with their own DB and creds".to_string(),
        });

        // Apache Solr admin
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/solr/admin | inurl:/solr/#/ | intitle:\"Solr Admin\")",
                clean_domain
            ),
            description: "Find Apache Solr admin interfaces".to_string(),
            impact: "Exposed Solr admin allows index manipulation, has historical RCE CVEs (e.g. CVE-2017-12629, CVE-2019-17558)".to_string(),
        });

        // ElasticSearch / Cluster status pages
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/_cat/indices | inurl:/_cluster/health | inurl:/_search?q= | inurl:/_nodes | intext:\"cluster_name\" intext:\"version\" intext:\"lucene_version\")",
                clean_domain
            ),
            description: "Find unauthenticated Elasticsearch endpoints".to_string(),
            impact: "Open Elasticsearch enables full data extraction and index deletion; common ransom target".to_string(),
        });

        // Jenkins exposed UI / script console
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/script | inurl:/manage/script | inurl:/asynchPeople | intitle:\"Dashboard [Jenkins]\" | intitle:\"Jenkins\")",
                clean_domain
            ),
            description: "Find Jenkins instances and script console".to_string(),
            impact: "Jenkins Script Console = Groovy on the master = RCE; even read-only access often exposes job configs with secrets".to_string(),
        });

        // GitLab login / instance discovery
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:{} (inurl:/users/sign_in intitle:\"GitLab\" | inurl:/explore intitle:\"GitLab\" | inurl:/api/v4/projects)",
                clean_domain
            ),
            description: "Find self-hosted GitLab instances".to_string(),
            impact: "Self-hosted GitLab often lags patches; multiple unauth RCEs in recent years (e.g. CVE-2023-7028)".to_string(),
        });

        // Confluence / Jira self-hosted (with CVE history)
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (intitle:\"Log in - Confluence\" | inurl:/login.action?os_destination | inurl:/secure/Dashboard.jspa | inurl:/rest/api/2/user | inurl:/rest/api/latest/projects)",
                clean_domain
            ),
            description: "Find self-hosted Confluence/Jira instances".to_string(),
            impact: "Self-hosted Confluence/Jira have a long history of unauth RCEs (CVE-2023-22515, CVE-2022-26134, CVE-2019-11581)".to_string(),
        });

        // Sitecore / AEM / Liferay specific paths
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/sitecore/login | inurl:/sitecore/api | inurl:/c/portal/login intitle:\"Liferay\" | inurl:/group/control_panel)",
                clean_domain
            ),
            description: "Find enterprise CMS admin endpoints (Sitecore, Liferay)".to_string(),
            impact: "Sitecore and Liferay have repeated critical RCEs; admin endpoints exposed are high-value targets".to_string(),
        });

        // CI/CD config files
        dorks.push(GoogleDork {
            category: "Exposed Source".to_string(),
            query: format!(
                "site:{} (inurl:.github/workflows/ | inurl:.gitlab-ci.yml | inurl:.circleci/config.yml | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:Jenkinsfile)",
                clean_domain
            ),
            description: "Find exposed CI/CD configuration files".to_string(),
            impact: "CI configs reveal secret names, deploy targets, build matrices; sometimes secrets are committed in clear".to_string(),
        });

        // Crash / heapdump / coredump artifacts
        dorks.push(GoogleDork {
            category: "Exposed Secrets".to_string(),
            query: format!(
                "site:{} (ext:hprof | ext:dump | ext:core | inurl:heapdump | inurl:threaddump | inurl:crashreport)",
                clean_domain
            ),
            description: "Find heap/thread/core dumps".to_string(),
            impact: "Heap dumps contain in-memory secrets (JWTs, DB passwords, session tokens) extractable with MAT/jhat".to_string(),
        });

        // Specific 'open' S3-bucket-style indexes
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.amazonaws.com | site:s3-website-* | site:storage.googleapis.com | site:storage.cloud.google.com | site:blob.core.windows.net) (intext:\"{}\" | intitle:\"Index of\")",
                clean_domain
            ),
            description: "Find listable cloud-storage buckets referencing the target".to_string(),
            impact: "Directory-listing buckets typically expose backups, dumps, and PII".to_string(),
        });

        // Backup files with broader extensions
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dmp | ext:db | ext:sqlite | ext:mdb | ext:rdb | ext:dump | ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z | ext:bak | ext:bk | ext:old)",
                clean_domain
            ),
            description: "Find archive and database backup files".to_string(),
            impact: "DB exports and full-site backups are jackpots: they typically contain credentials, PII and full source".to_string(),
        });

        // Open Directory Listing
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} intitle:\"Index of\" (intext:\"Parent Directory\" | intext:\"Last modified\")",
                clean_domain
            ),
            description: "Find pages with directory listing enabled".to_string(),
            impact: "Directory listings expose hidden files (backups, configs, dumps) that weren't meant to be browsed".to_string(),
        });

        // WordPress sensitive paths
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/wp-content/uploads/ | inurl:/wp-content/backup-db/ | inurl:/wp-content/debug.log | inurl:/wp-config.php.swp | inurl:/.wp-cli/config.yml | inurl:/wp-json/wp/v2/users)",
                clean_domain
            ),
            description: "Find WordPress sensitive files and user enumeration endpoints".to_string(),
            impact: "/wp-json/wp/v2/users enumerates user login names; debug.log leaks paths/PHP errors; backup-db dumps DB".to_string(),
        });

        // Open Mail / SMTP test endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/mail/?_task=mail intitle:\"Roundcube\" | inurl:/squirrelmail | inurl:/horde | inurl:/webmail | inurl:/exchange | inurl:/owa/auth)",
                clean_domain
            ),
            description: "Find webmail / OWA / Roundcube interfaces".to_string(),
            impact: "Webmail is a high-value bruteforce / phishing target; OWA has had several pre-auth CVEs".to_string(),
        });

        // VPN portals (Pulse, FortiGate, Citrix - large CVE history)
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/dana-na/auth | inurl:/remote/login | inurl:/vpn/index.html | inurl:/+CSCOE+/logon.html | intitle:\"FortiGate\" | intitle:\"Citrix Gateway\" | intitle:\"GlobalProtect\")",
                clean_domain
            ),
            description: "Find VPN / SSL-VPN web portals".to_string(),
            impact: "VPN appliances have a notorious record of pre-auth RCEs and credential-extraction CVEs".to_string(),
        });

        // Misconfigured IIS / Windows server identifiers
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"Server Error in '/' Application\" | intext:\"Microsoft .NET Framework Version\" | inurl:trace.axd | inurl:elmah.axd)",
                clean_domain
            ),
            description: "Find ASP.NET error pages, trace.axd, ELMAH".to_string(),
            impact: "trace.axd / elmah.axd often expose request logs containing cookies, auth headers and internal paths".to_string(),
        });

        // Spring Boot / Java stack traces
        dorks.push(GoogleDork {
            category: "Error Messages".to_string(),
            query: format!(
                "site:{} (intext:\"Whitelabel Error Page\" intext:\"Spring Boot\" | intext:\"Caused by:\" intext:\"at java.\" | intext:\"NullPointerException\" intext:\"Servlet\")",
                clean_domain
            ),
            description: "Find Java/Spring uncaught exception pages".to_string(),
            impact: "Stack traces leak class paths, framework versions, internal hostnames - useful for chaining gadget attacks".to_string(),
        });

        // Public package & artifact registries referencing the org
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "(site:npmjs.com | site:pypi.org | site:rubygems.org | site:hub.docker.com | site:nuget.org) \"{}\"",
                clean_domain
            ),
            description: "Find packages published under the target's name on public registries".to_string(),
            impact: "Public packages may leak internal code, contain secrets in published archives, or enable dependency-confusion attacks".to_string(),
        });

        // GitHub / GitLab gists referencing the target
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitlab.com/-/snippets) \"{}\"",
                clean_domain
            ),
            description: "Find code gists/snippets referencing the target".to_string(),
            impact: "Developer-shared snippets are a common source of leaked API keys, internal hostnames and config".to_string(),
        });

        // StackOverflow / Q&A leakage
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:stackoverflow.com | site:stackexchange.com | site:serverfault.com) \"{}\"",
                clean_domain
            ),
            description: "Find StackOverflow questions mentioning the target".to_string(),
            impact: "Devs often paste real config (API keys, JWTs, internal URLs) when asking debugging questions".to_string(),
        });

        // Wayback Machine (uses Google index of archives)
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!("site:web.archive.org/web/*/{}*", clean_domain),
            description: "Find archived versions of pages (Wayback Machine)".to_string(),
            impact: "Archived snapshots may show endpoints, parameters and content that have since been removed or hidden".to_string(),
        });

        // .well-known sensitive endpoints
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/openid-configuration | inurl:/.well-known/jwks.json | inurl:/.well-known/oauth-authorization-server | inurl:/.well-known/apple-app-site-association | inurl:/.well-known/assetlinks.json)",
                clean_domain
            ),
            description: "Find OIDC / OAuth / mobile-app .well-known metadata".to_string(),
            impact: "OIDC metadata reveals issuer/token endpoints; AASA/assetlinks expose mobile app deep-link targets used for account-linking attacks".to_string(),
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
