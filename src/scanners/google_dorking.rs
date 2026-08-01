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

        // Notion Public Pages
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:notion.so \"{}\"", clean_domain),
            description: "Find public Notion pages referencing the domain".to_string(),
            impact: "Public Notion pages regularly leak internal runbooks, credentials, and roadmaps".to_string(),
        });

        // Confluence / Atlassian
        dorks.push(GoogleDork {
            category: "Project Management".to_string(),
            query: format!("site:atlassian.net \"{}\"", clean_domain),
            description: "Find public Atlassian (Jira/Confluence) pages referencing the domain".to_string(),
            impact: "Public Jira/Confluence spaces may expose internal tickets, tokens, or infrastructure details".to_string(),
        });

        // Environment / dotenv files
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (ext:env | inurl:\".env\") intext:(DB_PASSWORD | DATABASE_URL | AWS_SECRET_ACCESS_KEY | STRIPE_SECRET | SLACK_TOKEN | JWT_SECRET | SECRET_KEY_BASE)",
                clean_domain
            ),
            description: "Find leaked .env files containing production secrets".to_string(),
            impact: "Exposed .env files typically leak database credentials, AWS keys, and third-party API tokens".to_string(),
        });

        // Terraform State
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (ext:tfstate | inurl:\".tfstate\" | inurl:\"terraform.tfstate\") intext:\"terraform_version\"",
                clean_domain
            ),
            description: "Find exposed Terraform state files".to_string(),
            impact: "Terraform state files contain plaintext secrets, cloud resource IDs, and full infrastructure topology".to_string(),
        });

        // Ansible Vault / inventory
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"group_vars\" | inurl:\"host_vars\" | inurl:\"ansible.cfg\" | inurl:\"vault.yml\" | intext:\"ANSIBLE_VAULT;1.1\")",
                clean_domain
            ),
            description: "Find Ansible inventory, group_vars, or Vault files".to_string(),
            impact: "Ansible artifacts expose infrastructure inventory, SSH configuration, and encrypted-but-crackable vault blobs".to_string(),
        });

        // Docker / Kubernetes config leaks
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"docker-compose.yml\" | inurl:\"docker-compose.yaml\" | inurl:\"Dockerfile\" | inurl:\".dockerignore\") intext:(password | secret | token | KEY)",
                clean_domain
            ),
            description: "Find Docker Compose / Dockerfiles containing embedded credentials".to_string(),
            impact: "Docker manifests routinely ship with hard-coded database passwords, registry tokens, and API keys".to_string(),
        });

        // Kubernetes Manifest Leaks
        dorks.push(GoogleDork {
            category: "Configuration Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"kubeconfig\" | inurl:\".kube/config\" | intext:\"apiVersion: v1\" intext:\"kind: Secret\" | intext:\"kind: ConfigMap\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes kubeconfig, Secrets, or ConfigMaps".to_string(),
            impact: "kubeconfig files grant cluster-admin access; Secret manifests leak base64-encoded credentials".to_string(),
        });

        // Exposed .git directory
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".git/config\" | inurl:\".git/HEAD\" | inurl:\".git/logs/HEAD\" | intitle:\"Index of\" intext:\".git\")",
                clean_domain
            ),
            description: "Find directory-listable .git repositories".to_string(),
            impact: "Exposed .git allows full source-code reconstruction and often contains historical credentials".to_string(),
        });

        // Exposed .svn / .hg
        dorks.push(GoogleDork {
            category: "Source Code Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".svn/entries\" | inurl:\".svn/wc.db\" | inurl:\".hg/store\" | intitle:\"Index of\" intext:\".svn\")",
                clean_domain
            ),
            description: "Find exposed SVN/Mercurial working directories".to_string(),
            impact: "Legacy VCS metadata still enables full source-tree extraction".to_string(),
        });

        // Private SSH / PGP keys
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"-----BEGIN RSA PRIVATE KEY-----\" | intext:\"-----BEGIN OPENSSH PRIVATE KEY-----\" | intext:\"-----BEGIN DSA PRIVATE KEY-----\" | intext:\"-----BEGIN EC PRIVATE KEY-----\" | intext:\"-----BEGIN PGP PRIVATE KEY BLOCK-----\")",
                clean_domain
            ),
            description: "Find exposed private keys inside indexed pages".to_string(),
            impact: "Any leaked private key grants immediate impersonation, decryption, or code-signing capability".to_string(),
        });

        // AWS credential file leaks
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".aws/credentials\" | inurl:\"credentials.csv\" | intext:\"aws_access_key_id\" intext:\"aws_secret_access_key\")",
                clean_domain
            ),
            description: "Find AWS credentials files".to_string(),
            impact: "Leaked long-lived AWS keys typically grant broad access to production accounts".to_string(),
        });

        // NPM / Ruby / Python package tokens
        dorks.push(GoogleDork {
            category: "Credential Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".npmrc\" intext:\"_authToken\" | inurl:\".pypirc\" intext:\"password\" | inurl:\".gem/credentials\" | intext:\"//registry.npmjs.org/:_authToken\")",
                clean_domain
            ),
            description: "Find leaked package-registry publish tokens".to_string(),
            impact: "npm/PyPI/RubyGems tokens allow supply-chain attacks against every downstream consumer".to_string(),
        });

        // Spring Boot Actuator
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/actuator\" | inurl:\"/actuator/env\" | inurl:\"/actuator/heapdump\" | inurl:\"/actuator/mappings\" | inurl:\"/actuator/threaddump\")",
                clean_domain
            ),
            description: "Find exposed Spring Boot Actuator endpoints".to_string(),
            impact: "/env leaks secrets, /heapdump gives full memory dumps, /mappings enumerates internal routes".to_string(),
        });

        // Prometheus / Grafana / Node Exporter
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/metrics\" intext:\"# HELP\" | intitle:\"Prometheus Time Series Collection and Processing Server\" | intitle:\"Grafana\" inurl:\"/login\" | intitle:\"Node Exporter\")",
                clean_domain
            ),
            description: "Find open Prometheus/Grafana/Node Exporter instances".to_string(),
            impact: "Exposed telemetry surfaces sensitive metric labels (users, tokens, hostnames) and admin dashboards".to_string(),
        });

        // Kubernetes Dashboard / kubelet
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:\":10250/pods\" | inurl:\"/api/v1/namespaces\" intext:\"kind\":\"NamespaceList\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes Dashboards or unauthenticated kubelet APIs".to_string(),
            impact: "Any accessible dashboard or kubelet API path is typically a full-cluster compromise".to_string(),
        });

        // Docker Registry v2
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/v2/_catalog\" | intext:\"\\\"repositories\\\":[\" inurl:\"/v2/\")",
                clean_domain
            ),
            description: "Find unauthenticated Docker registries".to_string(),
            impact: "Registries without auth allow arbitrary image pull/push and expose proprietary containers".to_string(),
        });

        // Jenkins
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | inurl:\"/script\" intitle:\"Jenkins\" | inurl:\"/asynchPeople\" | inurl:\"/manage\" intitle:\"Jenkins\")",
                clean_domain
            ),
            description: "Find exposed Jenkins consoles".to_string(),
            impact: "/script grants Groovy RCE, /asynchPeople enumerates users, /manage is admin surface".to_string(),
        });

        // Airflow / MLflow / Argo
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Airflow\" inurl:\"/home\" | intitle:\"MLflow\" inurl:\"/#/experiments\" | intitle:\"Argo Workflows\" | intitle:\"Kubeflow\")",
                clean_domain
            ),
            description: "Find exposed data/ML orchestration UIs".to_string(),
            impact: "These UIs regularly hold DB connection strings, S3 keys, and DAG source with embedded secrets".to_string(),
        });

        // MinIO Console
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Console\" | inurl:\"/minio/login\" | inurl:\":9001/login\")",
                clean_domain
            ),
            description: "Find exposed MinIO S3-compatible object storage consoles".to_string(),
            impact: "MinIO installs commonly ship with default minioadmin/minioadmin credentials".to_string(),
        });

        // Elasticsearch / Kibana / Solr / RabbitMQ
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (inurl:\"/_cat/indices\" | intext:\"\\\"cluster_name\\\"\" inurl:\":9200\" | intitle:\"Kibana\" inurl:\"/app/\" | intitle:\"Solr Admin\" | intitle:\"RabbitMQ Management\")",
                clean_domain
            ),
            description: "Find open Elasticsearch/Kibana/Solr/RabbitMQ management surfaces".to_string(),
            impact: "Each of these commonly ships without authentication and exposes user data or queue contents".to_string(),
        });

        // PHPinfo pages
        dorks.push(GoogleDork {
            category: "Information Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:\"phpinfo.php\" | inurl:\"info.php\" | inurl:\"test.php\" | intitle:\"phpinfo()\" intext:\"PHP Version\")",
                clean_domain
            ),
            description: "Find phpinfo() pages".to_string(),
            impact: "phpinfo leaks environment variables, cookies, loaded modules, and filesystem paths".to_string(),
        });

        // Swagger/OpenAPI with real endpoints
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"swagger.json\" | inurl:\"openapi.json\" | inurl:\"openapi.yaml\" | inurl:\"v3/api-docs\") intext:(\"paths\":|\"components\":|\"securitySchemes\":)",
                clean_domain
            ),
            description: "Find raw OpenAPI/Swagger specifications".to_string(),
            impact: "Raw specs disclose every backend route, parameter, and authentication scheme".to_string(),
        });

        // GraphQL playgrounds / introspection
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:\"/graphql\" | inurl:\"/graphiql\" | inurl:\"/altair\" | inurl:\"/playground\") (intitle:\"GraphQL Playground\" | intitle:\"GraphiQL\" | intext:\"__schema\")",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds and introspection endpoints".to_string(),
            impact: "Playgrounds enable interactive schema discovery and querying without auth on many deployments".to_string(),
        });

        // WordPress user enum / config backups
        dorks.push(GoogleDork {
            category: "CMS Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"wp-config.php.bak\" | inurl:\"wp-config.php~\" | inurl:\"wp-config.old\" | inurl:\"wp-config.txt\" | inurl:\"/?author=\" | inurl:\"/wp-json/wp/v2/users\")",
                clean_domain
            ),
            description: "Find WordPress config backups and user enumeration endpoints".to_string(),
            impact: "wp-config backups leak DB credentials and salts; /wp-json/wp/v2/users enumerates admin usernames".to_string(),
        });

        // Drupal / Joomla settings backups
        dorks.push(GoogleDork {
            category: "CMS Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"sites/default/settings.php\" | inurl:\"configuration.php.bak\" | inurl:\"configuration.php~\" | inurl:\"/administrator/manifests\") intext:(\"password\" | \"$databases\")",
                clean_domain
            ),
            description: "Find Drupal/Joomla configuration backups".to_string(),
            impact: "settings.php / configuration.php typically contain database credentials and secret salts".to_string(),
        });

        // CI/CD secret files
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".github/workflows\" intext:(\"secrets.\" | \"AWS_ACCESS_KEY\") | inurl:\".gitlab-ci.yml\" intext:(\"password\" | \"token\") | inurl:\"circle.yml\" | inurl:\".travis.yml\" intext:(\"password\" | \"token\"))",
                clean_domain
            ),
            description: "Find CI pipeline files that inline secrets".to_string(),
            impact: "Inlined pipeline secrets often persist in cache/artifacts and grant deploy access".to_string(),
        });

        // JetBrains / IDE workspace leaks
        dorks.push(GoogleDork {
            category: "IDE / Workspace Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\".idea/workspace.xml\" | inurl:\".idea/dataSources.xml\" | inurl:\".vscode/settings.json\" | inurl:\".vscode/sftp.json\")",
                clean_domain
            ),
            description: "Find leaked IDE workspace/config files".to_string(),
            impact: "IDE workspace files frequently contain DB credentials, SFTP passwords, and internal path structure".to_string(),
        });

        // Log files with sensitive data
        dorks.push(GoogleDork {
            category: "Log Leaks".to_string(),
            query: format!(
                "site:{} (ext:log | inurl:\"access.log\" | inurl:\"error.log\" | inurl:\"debug.log\") intext:(\"password\" | \"authorization: bearer\" | \"api_key\" | \"traceback\")",
                clean_domain
            ),
            description: "Find application/access logs containing secrets or tracebacks".to_string(),
            impact: "Log files often echo Authorization headers, credentials, and full request bodies".to_string(),
        });

        // Database dumps
        dorks.push(GoogleDork {
            category: "Database Leaks".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:db | ext:dump) intext:(\"INSERT INTO\" | \"CREATE TABLE\" | \"password_hash\" | \"bcrypt\")",
                clean_domain
            ),
            description: "Find exposed database dumps or SQLite files".to_string(),
            impact: "Full DB dumps expose the entire user table, hashed passwords, and business data".to_string(),
        });

        // Open directory listings (index of)
        dorks.push(GoogleDork {
            category: "Directory Listing".to_string(),
            query: format!(
                "site:{} intitle:\"Index of /\" (intext:\"parent directory\" | intext:\"Last modified\") -intext:\"disallowed\"",
                clean_domain
            ),
            description: "Find open directory listings".to_string(),
            impact: "Autoindex pages routinely expose backups, keys, dumps, and internal tooling".to_string(),
        });

        // Backup archives
        dorks.push(GoogleDork {
            category: "Backup Archives".to_string(),
            query: format!(
                "site:{} (ext:zip | ext:tar | ext:tar.gz | ext:tgz | ext:rar | ext:7z | ext:bak | ext:old | ext:backup)",
                clean_domain
            ),
            description: "Find exposed backup archives".to_string(),
            impact: "Archive files at web-accessible paths regularly contain full source, DB dumps, and credentials".to_string(),
        });

        // SharePoint / Office 365 leakage
        dorks.push(GoogleDork {
            category: "Corporate Document Leaks".to_string(),
            query: format!(
                "site:{} (inurl:\"/_layouts/\" | inurl:\"/Forms/AllItems.aspx\" | inurl:\"/personal/\") intitle:\"Shared Documents\"",
                clean_domain
            ),
            description: "Find publicly indexed SharePoint document libraries".to_string(),
            impact: "SharePoint misconfiguration exposes internal document libraries and OneDrive personal shares".to_string(),
        });

        // Password reset / signup abuse targets
        dorks.push(GoogleDork {
            category: "Auth Flow Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"reset_password\" | inurl:\"forgot\" | inurl:\"resetpassword\" | inurl:\"verify_email\" | inurl:\"invite?token=\" | inurl:\"activate?token=\")",
                clean_domain
            ),
            description: "Find password reset, invite, and email verification endpoints".to_string(),
            impact: "Reset/invite endpoints are prime targets for host-header poisoning and token-leak issues".to_string(),
        });

        // OAuth / SAML metadata
        dorks.push(GoogleDork {
            category: "Auth Flow Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\".well-known/openid-configuration\" | inurl:\".well-known/oauth-authorization-server\" | inurl:\"/saml/metadata\" | inurl:\"/adfs/ls/\")",
                clean_domain
            ),
            description: "Find OIDC/OAuth/SAML metadata endpoints".to_string(),
            impact: "Metadata reveals issuer, endpoints, supported flows, and IdP identifiers used for auth-flow attacks".to_string(),
        });

        // Debug / trace endpoints
        dorks.push(GoogleDork {
            category: "Debug Endpoints".to_string(),
            query: format!(
                "site:{} (inurl:\"/debug/pprof\" | inurl:\"/debug/vars\" | inurl:\"/_profiler\" | inurl:\"/rails/info\" | inurl:\"/_debugbar\" | inurl:\"/__debug__/\" )",
                clean_domain
            ),
            description: "Find framework debug/profiler endpoints".to_string(),
            impact: "Debug endpoints expose environment, routes, memory profiles and often full request/response bodies".to_string(),
        });

        // Postman / API collection leaks
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com \"{}\" | site:documenter.getpostman.com \"{}\" | site:app.getpostman.com \"{}\"",
                clean_domain, clean_domain, clean_domain
            ),
            description: "Find public Postman workspaces mentioning the domain".to_string(),
            impact: "Public Postman collections frequently include real bearer tokens and internal API URLs".to_string(),
        });

        // Slack workspace / shared links
        dorks.push(GoogleDork {
            category: "Chat Leaks".to_string(),
            query: format!(
                "(site:slack.com | site:files.slack.com) \"{}\"",
                clean_domain
            ),
            description: "Find Slack workspace links or shared files referencing the domain".to_string(),
            impact: "Public Slack shares can leak internal conversations, screenshots and file uploads".to_string(),
        });

        // Discord / Telegram exposures
        dorks.push(GoogleDork {
            category: "Chat Leaks".to_string(),
            query: format!(
                "(site:discord.com/invite | site:t.me | site:telegram.me) \"{}\"",
                clean_domain
            ),
            description: "Find Discord/Telegram community invites referencing the domain".to_string(),
            impact: "Community groups often contain internal chatter, leaked credentials, and beta credentials".to_string(),
        });

        // Public bug bounty scope references
        dorks.push(GoogleDork {
            category: "Security Information".to_string(),
            query: format!(
                "(site:hackerone.com | site:bugcrowd.com | site:intigriti.com | site:yeswehack.com) \"{}\"",
                clean_domain
            ),
            description: "Find bug bounty program references for the target".to_string(),
            impact: "Confirms scope, historical disclosure, and hunting hints from prior researchers".to_string(),
        });

        // Envoy / Istio admin
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Envoy Admin\" | inurl:\"/config_dump\" | inurl:\"/clusters\" intext:\"upstream_rq_active\" | inurl:\"/stats\" intext:\"cluster.\")",
                clean_domain
            ),
            description: "Find exposed Envoy/Istio admin interfaces".to_string(),
            impact: "/config_dump reveals full service mesh config including upstream secrets and mTLS certificates".to_string(),
        });

        // HashiCorp / secret managers UI
        dorks.push(GoogleDork {
            category: "Exposed Admin Interfaces".to_string(),
            query: format!(
                "site:{} (intitle:\"Vault\" inurl:\"/ui/vault\" | intitle:\"Consul by HashiCorp\" | intitle:\"Nomad\" inurl:\"/ui/\" | inurl:\"/v1/sys/health\" intext:\"initialized\")",
                clean_domain
            ),
            description: "Find HashiCorp Vault/Consul/Nomad UIs and unauth API surfaces".to_string(),
            impact: "Any unauthenticated response from these tools indicates catastrophic secret exposure".to_string(),
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
