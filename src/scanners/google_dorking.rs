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

        // ────────────────────────────────────────────────────────────────
        // Exposed VCS metadata — instant source-code disclosure
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/index\" | inurl:\".gitignore\" | inurl:\".svn/entries\" | inurl:\".hg/store\" | inurl:\".bzr\")",
                clean_domain
            ),
            description: "Exposed VCS metadata (.git, .svn, .hg, .bzr)".to_string(),
            impact: "Allows full source code reconstruction via git-dumper/svn-extractor — \
                often leaks credentials, internal endpoints and pre-release vulnerabilities."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Environment / dotfiles — credentials in production
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\".env\" | inurl:\".env.local\" | inurl:\".env.production\" | inurl:\".env.dev\" | inurl:\".env.staging\" | inurl:\".env.backup\" | inurl:\"env.js\" | inurl:\"environment.ts\")",
                clean_domain
            ),
            description: "Exposed .env / environment files".to_string(),
            impact: "Production .env files routinely contain DB passwords, JWT/encryption \
                secrets, third-party API keys and SMTP credentials — full app takeover."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"DB_PASSWORD=\" | intext:\"DATABASE_URL=\" | intext:\"AWS_SECRET_ACCESS_KEY=\" | intext:\"STRIPE_SECRET_KEY=\" | intext:\"JWT_SECRET=\")",
                clean_domain
            ),
            description: "Plaintext secret assignments indexed by Google".to_string(),
            impact: "Hardcoded secrets visible in indexed source — immediately usable credentials."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Backups, dumps and editor swap files — full data leaks
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:dump | ext:dmp | ext:bak | ext:backup | ext:tar | ext:tar.gz | ext:tgz | ext:zip | ext:rar | ext:7z | ext:gz | ext:bz2)",
                clean_domain
            ),
            description: "Database dumps and archive backups".to_string(),
            impact: "SQL dumps and backup archives often contain entire user tables, \
                hashed passwords and PII — direct breach material."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.bak | inurl:.bk | inurl:.old | inurl:.orig | inurl:.original | inurl:.copy | inurl:.tmp | inurl:.swp | inurl:.swo | inurl:.un~ | inurl:~)",
                clean_domain
            ),
            description: "Editor swap / backup file artifacts".to_string(),
            impact: "Vim/emacs swap files and *.bak copies bypass server-side execution \
                and reveal raw source (PHP, JSP, ASP) including DB credentials."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:\".DS_Store\" | inurl:\"Thumbs.db\" | inurl:\"desktop.ini\")",
                clean_domain
            ),
            description: "Filesystem metadata files".to_string(),
            impact: ".DS_Store enumerates every file in a directory; a starting point for \
                deeper recon and follow-on file discovery."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Cryptographic material in the wild
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:pfx | ext:p12 | ext:asc | ext:gpg | ext:ppk | ext:jks | ext:keystore)",
                clean_domain
            ),
            description: "Private keys, PKCS#12, JKS and GPG keys".to_string(),
            impact: "Private keys allow impersonation of TLS endpoints, signing of \
                releases, decryption of traffic, and SSH access to infrastructure."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN EC PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\")",
                clean_domain
            ),
            description: "PEM-armored private key blocks indexed in pages".to_string(),
            impact: "Private key material exposed verbatim — drop-in compromise of the \
                associated identity."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (filetype:ovpn | inurl:\"client.ovpn\" | inurl:\"vpn-config\" | filetype:rdp | filetype:pcap | filetype:pcapng | filetype:cap)",
                clean_domain
            ),
            description: "VPN configs and packet captures".to_string(),
            impact: "OpenVPN/RDP profiles grant network foothold; packet captures may \
                expose plaintext credentials and session cookies."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Cloud metadata / IaC — keys to the kingdom
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Cloud Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\".aws/config\" | inurl:\".npmrc\" | inurl:\".pypirc\" | inurl:\".dockercfg\" | inurl:\".docker/config.json\" | inurl:\"id_rsa\" | inurl:\"authorized_keys\" | inurl:\"known_hosts\")",
                clean_domain
            ),
            description: "User-level credential dotfiles".to_string(),
            impact: "AWS/NPM/PyPI/Docker credential files give push access to \
                production accounts and supply-chain pipelines."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Configuration".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | inurl:\"terraform.tfstate\" | inurl:\"terraform.tfvars\" | inurl:\".terraform/\")",
                clean_domain
            ),
            description: "Terraform state and tfvars".to_string(),
            impact: "tfstate stores resource secrets in plaintext (DB passwords, \
                provider credentials) — full IaC compromise."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Configuration".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\"Dockerfile\" | inurl:\".kube/config\" | inurl:\"kubeconfig\" | inurl:\"helm/values.yaml\")",
                clean_domain
            ),
            description: "Container & orchestration config".to_string(),
            impact: "kubeconfig grants cluster-admin context; compose files expose \
                service credentials and internal architecture."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Application server admin / debug endpoints
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/trace\" | inurl:\"/actuator/threaddump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/health\")",
                clean_domain
            ),
            description: "Spring Boot Actuator endpoints".to_string(),
            impact: "Unauthenticated /actuator/env and /heapdump leak environment \
                variables, secrets, and full memory snapshots — credential extraction \
                and pre-auth RCE in legacy versions."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/manager/html\" | inurl:\"/host-manager\" | inurl:\"/manager/status\" | intitle:\"Tomcat Manager\")",
                clean_domain
            ),
            description: "Apache Tomcat manager UI".to_string(),
            impact: "Default tomcat:tomcat or weak credentials grant WAR upload — \
                instant unauthenticated RCE."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/jmx-console\" | inurl:\"/web-console\" | inurl:\"/jolokia\" | inurl:\"/jolokia/list\")",
                clean_domain
            ),
            description: "JBoss / JMX / Jolokia consoles".to_string(),
            impact: "JMX MBeans expose deployment/RCE; Jolokia is a known SSRF and \
                deserialization vector."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/wp-admin\" | inurl:\"/wp-login.php\" | inurl:\"/xmlrpc.php\" | inurl:\"/wp-config.php\" | inurl:\"/wp-config.php.bak\")",
                clean_domain
            ),
            description: "WordPress admin / config exposure".to_string(),
            impact: "wp-config.php contains DB credentials and AUTH_KEY salts; \
                xmlrpc.php enables credential stuffing and SSRF."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/.well-known/security.txt\" | inurl:\"/.well-known/openid-configuration\" | inurl:\"/.well-known/oauth-authorization-server\" | inurl:\"/.well-known/assetlinks.json\" | inurl:\"/.well-known/apple-app-site-association\")",
                clean_domain
            ),
            description: "well-known endpoints (OIDC/AASA)".to_string(),
            impact: "OIDC discovery enumerates auth flows and JWKS; AASA exposes \
                deeplink intents that often bypass app-side authentication."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/console\" | inurl:\"/h2-console\" | intitle:\"H2 Console\" | inurl:\"/druid/\" | intitle:\"druid stat\")",
                clean_domain
            ),
            description: "H2 / Druid consoles".to_string(),
            impact: "H2 console without auth → arbitrary SQL → RCE via JDBC URL \
                (CVE-2021-42392). Druid stat exposes DB credentials."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/phpmyadmin\" | inurl:\"/pma/\" | inurl:\"/myadmin/\" | inurl:\"/adminer.php\" | inurl:\"/adminer/\")",
                clean_domain
            ),
            description: "Database web admin tools".to_string(),
            impact: "phpMyAdmin / Adminer with default or guessable creds gives \
                direct DB RCE through MySQL UDF or file write."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // CI/CD platforms — supply chain entry points
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:\"/jenkins\" | inurl:\"/script\" intitle:\"Jenkins\" | inurl:\"/asynchPeople\" | inurl:\"/computer/\")",
                clean_domain
            ),
            description: "Jenkins instances and script console".to_string(),
            impact: "Anonymous /script gives Groovy RCE; /asynchPeople enumerates \
                users for credential stuffing."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "CI/CD".to_string(),
            query: format!(
                "site:{} (inurl:\"/.gitlab-ci.yml\" | inurl:\"/.github/workflows\" | inurl:\"bitbucket-pipelines.yml\" | inurl:\".circleci/config.yml\" | inurl:\".drone.yml\" | inurl:\"Jenkinsfile\")",
                clean_domain
            ),
            description: "CI pipeline definitions".to_string(),
            impact: "Pipeline files reveal build secrets, deploy targets, internal \
                container registries and signing infrastructure."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // GraphQL / API documentation
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/api/graphql\" | inurl:\"/altair\" | inurl:\"/voyager\" | inurl:\"/playground\")",
                clean_domain
            ),
            description: "GraphQL and explorer UIs".to_string(),
            impact: "Introspection-enabled GraphQL leaks the entire schema, often \
                exposing internal/admin mutations and fields not used by the front-end."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"swagger.json\" | inurl:\"swagger.yaml\" | inurl:\"openapi.json\" | inurl:\"openapi.yaml\" | inurl:\"v2/api-docs\" | inurl:\"v3/api-docs\")",
                clean_domain
            ),
            description: "OpenAPI / Swagger spec files".to_string(),
            impact: "Reveals every authenticated endpoint, parameter shape and \
                expected role — drastically reduces post-auth fuzzing surface."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Code-paste / archive sites — bigger leak ecosystem
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:gist.github.com \"{}\"", clean_domain),
            description: "Gists mentioning the domain".to_string(),
            impact: "Engineers commonly paste config/snippets including tokens to \
                gists; often public by accident."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:stackoverflow.com \"{}\"", clean_domain),
            description: "Stack Overflow questions referencing the domain".to_string(),
            impact: "Sanitized-but-not-quite snippets often reveal internal hosts, \
                stack traces with paths, and disabled-auth examples."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("(site:hastebin.com | site:dpaste.org | site:ghostbin.com | site:0bin.net | site:paste.ee | site:rentry.co | site:controlc.com | site:justpaste.it) \"{}\"", clean_domain),
            description: "Alternative pastebin platforms".to_string(),
            impact: "Engineers and attackers route around pastebin.com; coverage \
                here surfaces leaks Pastebin alone misses."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:postman.com | site:explore.postman.com) \"{}\"",
                clean_domain
            ),
            description: "Public Postman workspaces and collections".to_string(),
            impact: "Leaked Postman collections frequently include working API keys \
                and internal endpoints in environment variables."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:swaggerhub.com | site:apicur.io) \"{}\"",
                clean_domain
            ),
            description: "SwaggerHub public API definitions".to_string(),
            impact: "Hosted API specs may expose admin / partner endpoints not \
                advertised on the public site."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:replit.com \"{}\"", clean_domain),
            description: "Replit projects referencing the domain".to_string(),
            impact: "Public Replits often contain working tokens in committed \
                .env / Secrets files."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:huggingface.co \"{}\"", clean_domain),
            description: "Hugging Face spaces / repositories".to_string(),
            impact: "ML projects frequently embed inference API tokens, S3 paths \
                and internal model endpoints."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:web.archive.org \"{}\" (intext:\"password\" | intext:\"api_key\" | intext:\"BEGIN PRIVATE KEY\")", clean_domain),
            description: "Wayback Machine snapshots of secret-leaking pages".to_string(),
            impact: "Leaks removed from the live site often persist in archive.org \
                snapshots and remain valid for weeks."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Server-status / mod_status / log files
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"/server-status\" | inurl:\"/server-info\" | inurl:\"/nginx_status\" | inurl:\"/status?full=true\" | inurl:\"/php-fpm-status\")",
                clean_domain
            ),
            description: "Apache/Nginx/PHP-FPM status pages".to_string(),
            impact: "Live request URLs (with session IDs / tokens), internal IPs, \
                and worker stats — passive credential harvesting."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (ext:log inurl:access | ext:log inurl:error | ext:log inurl:debug | inurl:logs/ | inurl:logfile)",
                clean_domain
            ),
            description: "Indexed access/error/debug logs".to_string(),
            impact: "Logs contain query strings with credentials, session IDs, and \
                stack traces revealing file paths and DB schema."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (ext:php intext:\"Fatal error\" | ext:php intext:\"Warning:\" | intext:\"Whoops, looks like something went wrong\" | intext:\"DEBUG = True\" | intext:\"You don't have permission\" intext:\"DEBUG\")",
                clean_domain
            ),
            description: "PHP/Laravel/Django debug stack traces".to_string(),
            impact: "Whoops/Werkzeug debuggers expose source code, environment \
                variables, and in some configs an interactive RCE shell."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Cloud storage — bucket pivot patterns
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:storage.googleapis.com | site:storage.cloud.google.com) \"{}\"",
                clean_domain
            ),
            description: "GCS buckets referencing the domain".to_string(),
            impact: "Public GCS buckets frequently host backups, PII exports and \
                user uploads with no per-object ACL."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:s3.us-east-1.amazonaws.com | site:s3.us-west-2.amazonaws.com | site:s3.eu-west-1.amazonaws.com | site:s3.eu-central-1.amazonaws.com | site:s3-website.amazonaws.com) \"{}\"",
                clean_domain
            ),
            description: "Region-specific S3 endpoints".to_string(),
            impact: "Captures region-pinned buckets that the generic s3.amazonaws.com \
                dork misses (e.g., -website hosted assets)."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "(site:r2.cloudflarestorage.com | site:r2.dev | site:wasabisys.com | site:linodeobjects.com | site:backblazeb2.com | site:storage.yandexcloud.net | site:storage.selcloud.ru | site:fra1.digitaloceanspaces.com) \"{}\"",
                clean_domain
            ),
            description: "Non-AWS object storage providers".to_string(),
            impact: "R2/Wasabi/B2/Linode/Yandex/Selectel buckets are systematically \
                under-audited and routinely public."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "intext:\"<ListBucketResult\" \"{}\"",
                clean_domain
            ),
            description: "S3-compatible bucket listings (XML index)".to_string(),
            impact: "ListBucketResult XML is the smoking gun for an unauthenticated, \
                listable bucket — every object is enumerable."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Authentication / OAuth artifacts
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Auth Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"client_id=\" inurl:\"redirect_uri=\" | inurl:\"access_token=\" | inurl:\"id_token=\" | inurl:\"refresh_token=\" | inurl:\"saml=\" | inurl:\"SAMLResponse=\")",
                clean_domain
            ),
            description: "OAuth/SAML tokens leaked in URLs".to_string(),
            impact: "Tokens in URLs end up in referrer logs, browser history and \
                CDN access logs — replay yields full account access."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Auth Artifacts".to_string(),
            query: format!(
                "site:{} (inurl:\"reset?token=\" | inurl:\"invite?token=\" | inurl:\"confirm?token=\" | inurl:\"verify?token=\" | inurl:\"unsubscribe?token=\")",
                clean_domain
            ),
            description: "Reset/invite/verify tokens in indexed URLs".to_string(),
            impact: "Long-lived password reset / invite tokens cached in search \
                indexes can hijack accounts that never claimed them."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // Internal infrastructure dashboards
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Index of\" | intitle:\"Directory listing for\")",
                clean_domain
            ),
            description: "Open directory indexing".to_string(),
            impact: "Directory listings turn the entire web root into a file \
                browser — a baseline for all subsequent disclosure findings."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Grafana\" inurl:login | intitle:\"Kibana\" | intitle:\"Prometheus Time Series\" | intitle:\"AlertManager\" | intitle:\"Argo CD\" | intitle:\"Rancher\" | intitle:\"Portainer\" | intitle:\"Traefik\")",
                clean_domain
            ),
            description: "Observability and orchestration UIs".to_string(),
            impact: "These dashboards routinely have anonymous viewer access — \
                logs leak credentials, metrics expose internal hostnames, and \
                Argo/Rancher can grant cluster control."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Jenkins\" | intitle:\"GitLab\" | intitle:\"Gitea\" | intitle:\"Bitbucket\" | intitle:\"Harbor\" | intitle:\"Nexus Repository\" | intitle:\"Artifactory\")",
                clean_domain
            ),
            description: "DevOps platforms exposed publicly".to_string(),
            impact: "Self-hosted GitLab/Gitea/Harbor expose private repos and \
                container images when auth is misconfigured (signup-on-by-default)."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"phpinfo()\" | inurl:\"phpinfo.php\" | inurl:\"info.php\" | inurl:\"test.php\")",
                clean_domain
            ),
            description: "phpinfo() pages".to_string(),
            impact: "phpinfo reveals OS, PHP version, loaded modules, full env \
                including database credentials, and document root paths — a perfect \
                pre-exploit cheat sheet."
                .to_string(),
        });

        // ────────────────────────────────────────────────────────────────
        // PII / regulated data leaks
        // ────────────────────────────────────────────────────────────────
        dorks.push(GoogleDork {
            category: "PII / Regulated Data".to_string(),
            query: format!(
                "site:{} (intext:\"social security number\" | intext:\"SSN:\" | intext:\"date of birth\" | intext:\"DOB:\" | intext:\"passport number\" | intext:\"driver's license\")",
                clean_domain
            ),
            description: "PII fields indexed in pages".to_string(),
            impact: "Direct evidence of PII exposure — high-impact GDPR/HIPAA/PCI \
                finding; usually warrants immediate disclosure."
                .to_string(),
        });
        dorks.push(GoogleDork {
            category: "PII / Regulated Data".to_string(),
            query: format!(
                "site:{} (ext:csv | ext:xls | ext:xlsx) (intext:\"@gmail.com\" | intext:\"@yahoo.com\" | intext:\"@outlook.com\")",
                clean_domain
            ),
            description: "Spreadsheets containing personal email addresses".to_string(),
            impact: "User export spreadsheets — frequently the source of \
                breach-notification incidents."
                .to_string(),
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
