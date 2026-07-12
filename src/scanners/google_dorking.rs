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

        // ============================================================
        // Extended high-impact dorks for sensitive information
        // Each targets an artefact that, when found, has near-zero
        // ambiguity about whether it should have been public.
        // ============================================================

        // .env / dotenv exposure - very high impact
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.env | inurl:env.local | inurl:env.production | inurl:env.staging | ext:env) -inurl:.env.example -inurl:.env.sample",
                clean_domain
            ),
            description: "Find exposed .env dotenv files (excluding example templates)".to_string(),
            impact: "dotenv files contain database credentials, API keys, and JWT secrets in plaintext.".to_string(),
        });

        // Kubernetes secrets / kubeconfig
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:.kube | inurl:kubeconfig | ext:yaml intext:\"kind: Secret\" | ext:yml intext:\"kind: Secret\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes kubeconfig or Secret manifests".to_string(),
            impact: "kubeconfig grants direct cluster access; Secret manifests contain base64-encoded credentials.".to_string(),
        });

        // Terraform / Terragrunt state files
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:terraform.tfstate | inurl:.terraform | ext:tfstate | ext:tfvars | ext:tfstate.backup)",
                clean_domain
            ),
            description: "Find exposed Terraform state / tfvars files".to_string(),
            impact: "Terraform state stores plaintext IAM keys, DB passwords, connection strings, and the full inferred infrastructure map.".to_string(),
        });

        // Ansible vault / playbook secrets
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:ansible-vault | inurl:group_vars | inurl:host_vars | intext:\"$ANSIBLE_VAULT\")",
                clean_domain
            ),
            description: "Find Ansible vault-encrypted or plaintext playbook secrets".to_string(),
            impact: "Ansible vault files, once obtained, can be cracked offline; group_vars/host_vars often contain plaintext credentials.".to_string(),
        });

        // Docker Compose / .dockercfg / config.json (has base64 registry credentials)
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:docker-compose.yml | inurl:docker-compose.yaml | inurl:.dockercfg | inurl:config.json intext:\"auths\":)",
                clean_domain
            ),
            description: "Find exposed Docker Compose and registry auth config".to_string(),
            impact: "docker-compose files leak environment variables; .dockercfg / config.json store base64 registry credentials.".to_string(),
        });

        // SSH private keys of any form
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:pem | ext:key | ext:ppk | ext:pfx | ext:p12 | ext:rsa | ext:jks) -inurl:public",
                clean_domain
            ),
            description: "Find exposed private-key files (PEM, PPK, PFX, JKS)".to_string(),
            impact: "Private keys allow immediate impersonation, MITM, or code signing under the target's identity.".to_string(),
        });

        // GitHub Actions / CI workflow secrets accidentally committed to public sites
        dorks.push(GoogleDork {
            category: "CI/CD Leaks".to_string(),
            query: format!(
                "site:{} (inurl:.github/workflows | inurl:.circleci/config | inurl:.gitlab-ci.yml | inurl:bitbucket-pipelines.yml | inurl:azure-pipelines.yml | inurl:.travis.yml | inurl:Jenkinsfile)",
                clean_domain
            ),
            description: "Find CI/CD workflow files hosted on the target".to_string(),
            impact: "CI/CD manifests often reveal deployment endpoints, secret variable names, and cloud project IDs.".to_string(),
        });

        // Sentry / Rollbar / Bugsnag runtime DSN & auth tokens
        dorks.push(GoogleDork {
            category: "Observability Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"sentry_dsn\" | intext:\"sentry-cli\" | intext:\"rollbar_access_token\" | intext:\"bugsnag_api_key\" | inurl:sentry-cli)",
                clean_domain
            ),
            description: "Find leaked Sentry/Rollbar/Bugsnag project tokens".to_string(),
            impact: "DSN + auth tokens allow attackers to submit fake events, exfiltrate stack traces, and pivot to source-map access.".to_string(),
        });

        // Elasticsearch / Kibana / Prometheus / Grafana dashboards
        dorks.push(GoogleDork {
            category: "Admin Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Kibana\" | intitle:\"Grafana\" | intitle:\"Prometheus Time Series\" | inurl:_search | inurl:_cat/indices | inurl:_cluster/health)",
                clean_domain
            ),
            description: "Find exposed Elasticsearch / Kibana / Prometheus / Grafana surfaces".to_string(),
            impact: "Unauthenticated dashboards / Elasticsearch APIs allow full data enumeration and often destructive writes.".to_string(),
        });

        // Jenkins / Bamboo / TeamCity / Argo CD
        dorks.push(GoogleDork {
            category: "Admin Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Dashboard [Jenkins]\" | intitle:\"Bamboo\" | intitle:\"TeamCity\" | inurl:argocd | inurl:/argo/ | intitle:\"Argo CD\")",
                clean_domain
            ),
            description: "Find exposed build / CD control planes".to_string(),
            impact: "Anonymous CI/CD panels frequently allow job creation → RCE on build agents, or reading build secrets.".to_string(),
        });

        // Metabase / Superset / Redash / Looker / Tableau (BI dashboards with query access)
        dorks.push(GoogleDork {
            category: "Business Intelligence".to_string(),
            query: format!(
                "site:{} (intitle:\"Metabase\" | intitle:\"Apache Superset\" | intitle:\"Redash\" | inurl:/tableau/ | inurl:/looker/)",
                clean_domain
            ),
            description: "Find internal BI dashboards".to_string(),
            impact: "BI tools often permit ad-hoc SQL and expose the target's data warehouse.".to_string(),
        });

        // MinIO / RabbitMQ / Consul / Vault UI (self-hosted infra with default panels)
        dorks.push(GoogleDork {
            category: "Admin Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"MinIO Console\" | intitle:\"RabbitMQ Management\" | intitle:\"Consul by HashiCorp\" | intitle:\"Vault UI\" | inurl:/ui/vault)",
                clean_domain
            ),
            description: "Find exposed infrastructure control planes".to_string(),
            impact: "Any of these panels, if open, is a foothold to secrets, queues, service discovery, or object storage.".to_string(),
        });

        // Backup / dump files
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:sql | ext:sqlite | ext:mdb | ext:bak | ext:tar.gz | ext:zip | ext:rar | ext:dump | ext:dmp) (intext:\"CREATE TABLE\" | intext:\"INSERT INTO\" | intext:\"pg_dump\" | intext:\"mysqldump\")",
                clean_domain
            ),
            description: "Find database dumps and backup archives".to_string(),
            impact: "DB dumps disclose full production data; archive backups often contain source, credentials, and PII.".to_string(),
        });

        // .git / .svn / .hg / .bzr directory exposure (dev VCS metadata)
        dorks.push(GoogleDork {
            category: "Source Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:.git/config | inurl:.git/HEAD | inurl:.svn/entries | inurl:.hg/store | inurl:.DS_Store | inurl:Thumbs.db)",
                clean_domain
            ),
            description: "Find exposed VCS metadata directories".to_string(),
            impact: ".git/.svn exposure allows full source reconstruction; .DS_Store reveals directory listings.".to_string(),
        });

        // Package manager lockfiles / manifests hint at supply-chain surface
        dorks.push(GoogleDork {
            category: "Source Disclosure".to_string(),
            query: format!(
                "site:{} (inurl:package.json | inurl:composer.json | inurl:Gemfile.lock | inurl:requirements.txt | inurl:go.sum | inurl:Cargo.lock | inurl:yarn.lock | inurl:pnpm-lock.yaml)",
                clean_domain
            ),
            description: "Find shipped package manager manifests".to_string(),
            impact: "Manifests enumerate the exact dependency tree, enabling CVE mapping and dependency-confusion attacks.".to_string(),
        });

        // GraphQL introspection / playground exposure
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:/graphql | inurl:/graphiql | inurl:/altair | intitle:\"GraphQL Playground\" | intitle:\"Apollo Studio\")",
                clean_domain
            ),
            description: "Find exposed GraphQL playgrounds / introspection endpoints".to_string(),
            impact: "Introspection-enabled GraphQL endpoints give attackers a complete map of every mutation and object field.".to_string(),
        });

        // Public presigned / signed URLs (leaked via docs / blog / commits)
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (inurl:X-Amz-Signature | inurl:X-Amz-Credential | inurl:Signature= inurl:Expires= inurl:AWSAccessKeyId)",
                clean_domain
            ),
            description: "Find leaked S3 presigned URLs on the wider web".to_string(),
            impact: "Presigned URLs grant direct object access - if the expiry is far in the future, they remain valid.".to_string(),
        });

        // Postman / Insomnia public workspaces & collections
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:postman.com | site:documenter.getpostman.com | site:app.getpostman.com | site:insomnia.rest) \"{}\"",
                clean_domain
            ),
            description: "Find public Postman / Insomnia collections referencing the domain".to_string(),
            impact: "Shared API collections often embed live tokens as environment variables.".to_string(),
        });

        // Docker Hub / GHCR / Quay public image tags
        dorks.push(GoogleDork {
            category: "Container Registries".to_string(),
            query: format!(
                "(site:hub.docker.com | site:ghcr.io | site:quay.io) \"{}\"",
                clean_domain
            ),
            description: "Find public container images tagged for the target".to_string(),
            impact: "Public images often ship burned-in secrets, private CA certificates, or unstripped debug binaries.".to_string(),
        });

        // Notion / Confluence / Slack / Miro / Airtable public shares
        dorks.push(GoogleDork {
            category: "Information Leakage".to_string(),
            query: format!(
                "(site:notion.so | site:notion.site | site:confluence.atlassian.com | site:atlassian.net/wiki | site:airtable.com | site:miro.com) \"{}\"",
                clean_domain
            ),
            description: "Find internal wikis / boards inadvertently shared publicly".to_string(),
            impact: "Public knowledge-base shares regularly contain org charts, runbooks, credentials, and incident writeups.".to_string(),
        });

        // Public code snippets on GitHub Gist / GitLab snippets
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "(site:gist.github.com | site:gitlab.com/-/snippets | site:gitlab.com/*/snippets) \"{}\"",
                clean_domain
            ),
            description: "Find developer gists / snippets mentioning the domain".to_string(),
            impact: "Snippets are the single largest source of accidentally-published production secrets.".to_string(),
        });

        // Sentry public issue explorer / Rollbar dashboards
        dorks.push(GoogleDork {
            category: "Observability Leaks".to_string(),
            query: format!(
                "(site:sentry.io | site:rollbar.com) \"{}\"",
                clean_domain
            ),
            description: "Find public Sentry / Rollbar issue lists".to_string(),
            impact: "Public error-tracking projects can disclose stack traces, request payloads, and JWTs used in errors.".to_string(),
        });

        // SWF/YAML/JSON config files with `password`, `secret`, `token` mentions
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:yaml | ext:yml | ext:json | ext:properties | ext:xml | ext:ini | ext:cfg) (intext:password | intext:passwd | intext:\"secret_key\" | intext:\"private_key\" | intext:\"access_token\" | intext:\"api_key\")",
                clean_domain
            ),
            description: "Find config files that mention password / secret / token".to_string(),
            impact: "Application config files with credential-shaped keys typically contain the actual live values.".to_string(),
        });

        // WordPress / Drupal / Joomla exposed installer / debug pages
        dorks.push(GoogleDork {
            category: "CMS Exposure".to_string(),
            query: format!(
                "site:{} (inurl:wp-config.php.bak | inurl:wp-config.txt | inurl:configuration.php.bak | inurl:sites/default/settings.php.bak | inurl:install.php)",
                clean_domain
            ),
            description: "Find CMS config backups and installer scripts".to_string(),
            impact: "Backup CMS configs contain plaintext DB credentials; open installers allow full takeover.".to_string(),
        });

        // Coralogix, Datadog RUM, Segment write keys frequently leak in JS
        dorks.push(GoogleDork {
            category: "Observability Leaks".to_string(),
            query: format!(
                "site:{} (intext:\"ddApplicationId\" | intext:\"ddClientToken\" | intext:\"segment.io\" intext:\"writeKey\" | intext:\"coralogix\" intext:\"apiKey\")",
                clean_domain
            ),
            description: "Find leaked Datadog RUM / Segment / Coralogix client keys".to_string(),
            impact: "Client-write keys allow attackers to poison analytics and, on Segment, replay writes across integrations.".to_string(),
        });

        // Cloud credential file names leaked in web-hosted mirrors
        dorks.push(GoogleDork {
            category: "Cloud Credentials".to_string(),
            query: format!(
                "site:{} (inurl:aws/credentials | inurl:.aws/config | inurl:gcloud/credentials.db | inurl:application_default_credentials.json | inurl:azure/accessTokens.json)",
                clean_domain
            ),
            description: "Find shipped cloud SDK credential caches".to_string(),
            impact: "Any of these files, when web-served, is a direct handover of the developer's cloud identity.".to_string(),
        });

        // Kubernetes / Docker Swarm exposed dashboards
        dorks.push(GoogleDork {
            category: "Admin Dashboards".to_string(),
            query: format!(
                "site:{} (intitle:\"Kubernetes Dashboard\" | inurl:/#!/login | intitle:\"Portainer\" | intitle:\"Rancher\" | intitle:\"Traefik\")",
                clean_domain
            ),
            description: "Find exposed container-orchestration dashboards".to_string(),
            impact: "Rancher/Portainer/K8s dashboards frequently allow exec-into-container, granting cluster-wide code execution.".to_string(),
        });

        // Grafana anonymous / snapshot links
        dorks.push(GoogleDork {
            category: "Business Intelligence".to_string(),
            query: format!(
                "(site:snapshots.raintank.io | site:*.grafana.net | inurl:/dashboard/snapshot/) \"{}\"",
                clean_domain
            ),
            description: "Find Grafana public snapshots containing target data".to_string(),
            impact: "Snapshots regularly leak internal metric names, service topology, and time-series data.".to_string(),
        });

        // SSO error / debug pages with token echoes
        dorks.push(GoogleDork {
            category: "Auth Exposure".to_string(),
            query: format!(
                "site:{} (inurl:SAMLResponse= | inurl:id_token= | inurl:access_token= | inurl:code= inurl:state=)",
                clean_domain
            ),
            description: "Find SSO callback URLs indexed with tokens".to_string(),
            impact: "Indexed OAuth/SAML callbacks may leak tokens that remain valid until their natural expiry.".to_string(),
        });

        // OpenAPI / Swagger raw specs
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:{} (inurl:swagger.json | inurl:openapi.json | inurl:openapi.yaml | inurl:api-docs.json | inurl:v2/api-docs | inurl:v3/api-docs)",
                clean_domain
            ),
            description: "Find raw OpenAPI / Swagger spec files".to_string(),
            impact: "The raw spec enumerates every endpoint, parameter, and (often) auth scheme - a complete attack map.".to_string(),
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
