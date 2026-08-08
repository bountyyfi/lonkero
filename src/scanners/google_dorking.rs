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

        // ---------------------------------------------------------------------
        // Additional high-signal dorks (no false positives when reviewed
        // manually - each targets a distinct exposure surface that regularly
        // leaks credentials, PII, or internal architecture details in
        // real-world bug bounty reports and incident disclosures).
        // ---------------------------------------------------------------------

        // Postman public workspaces - one of the most common API-key leak
        // surfaces on the internet. Public collections routinely embed
        // Authorization headers, Bearer tokens, and environment variables.
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:postman.com \"{}\" (\"authorization\" | \"bearer\" | \"api_key\" | \"apikey\" | \"token\")",
                clean_domain
            ),
            description: "Find Postman public workspaces referencing the domain".to_string(),
            impact: "Public Postman collections frequently expose live API keys, bearer tokens, session cookies and full request/response captures containing PII".to_string(),
        });
        dorks.push(GoogleDork {
            category: "API Documentation".to_string(),
            query: format!(
                "site:documenter.getpostman.com \"{}\"",
                clean_domain
            ),
            description: "Find published Postman documentation pages".to_string(),
            impact: "Published Postman docs enumerate the full internal API surface, sometimes with example responses containing real customer data".to_string(),
        });

        // Notion / Coda / Confluence public pages - internal wikis
        // accidentally set to public.
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "site:notion.site \"{}\" (\"password\" | \"credential\" | \"api key\" | \"onboarding\" | \"runbook\")",
                clean_domain
            ),
            description: "Find publicly-shared Notion pages referencing the domain".to_string(),
            impact: "Public Notion pages regularly expose onboarding docs, runbooks, and shared credentials for internal systems".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!("site:coda.io \"{}\"", clean_domain),
            description: "Find publicly-shared Coda docs".to_string(),
            impact: "Public Coda docs often mirror internal Notion content: runbooks, on-call rotations, credential lists".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "site:atlassian.net inurl:/wiki/ \"{}\"",
                clean_domain
            ),
            description: "Find public Confluence Cloud pages for the domain".to_string(),
            impact: "Anonymously-viewable Confluence Cloud spaces expose architecture diagrams, secrets in code blocks, and internal contact info".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!("site:gitbook.io \"{}\"", clean_domain),
            description: "Find GitBook documentation referencing the domain".to_string(),
            impact: "GitBook is frequently used for internal engineering docs made public by mistake".to_string(),
        });

        // Airtable public bases and shared views - relational databases
        // published for convenience, exposing customer/contact lists.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "site:airtable.com (inurl:/shr | inurl:/embed) \"{}\"",
                clean_domain
            ),
            description: "Find Airtable public shares / embeds referencing the domain".to_string(),
            impact: "Airtable public bases and shared views regularly expose full customer lists, CRM data, and internal trackers with contact details".to_string(),
        });

        // Miro / Figma / Whimsical - design and diagram tools
        // often containing full architecture and threat models.
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!("site:miro.com \"{}\"", clean_domain),
            description: "Find public Miro boards".to_string(),
            impact: "Miro boards frequently expose architecture diagrams, network topologies, and threat models set to public-share by mistake".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "site:figma.com inurl:/file \"{}\"",
                clean_domain
            ),
            description: "Find publicly-viewable Figma files for the domain".to_string(),
            impact: "Public Figma files reveal unreleased UI, admin panel layouts and feature flags before launch".to_string(),
        });

        // Google Colab and Kaggle notebooks - data science workflows
        // that routinely embed API keys and DB connection strings.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:colab.research.google.com \"{}\"",
                clean_domain
            ),
            description: "Find Google Colab notebooks referencing the domain".to_string(),
            impact: "Colab notebooks routinely contain hardcoded API keys, database connection strings, and OAuth tokens in cells".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!("site:kaggle.com \"{}\"", clean_domain),
            description: "Find Kaggle notebooks/datasets referencing the domain".to_string(),
            impact: "Kaggle notebooks and public datasets have leaked full production customer data on multiple occasions".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:huggingface.co \"{}\" (\"api_key\" | \"HF_TOKEN\" | \"OPENAI_API_KEY\")",
                clean_domain
            ),
            description: "Find HuggingFace Spaces/repos leaking keys tied to the domain".to_string(),
            impact: "HuggingFace Spaces frequently embed OpenAI/Anthropic keys and DB URLs in app.py or environment files".to_string(),
        });

        // Sourcegraph - hosted code search that indexes public repos and,
        // when self-hosted, sometimes exposes private repo search unauth'd.
        dorks.push(GoogleDork {
            category: "Code Repositories".to_string(),
            query: format!(
                "site:sourcegraph.com \"{}\"",
                clean_domain
            ),
            description: "Find code indexed by public Sourcegraph mentioning the domain".to_string(),
            impact: "Sourcegraph indexes millions of repos with full-text search - a domain reference often leads directly to code referencing internal services".to_string(),
        });

        // Bitbucket snippets - the equivalent of GitHub Gists,
        // frequently used to share config/deployment scripts with secrets.
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:bitbucket.org inurl:/snippets/ \"{}\"",
                clean_domain
            ),
            description: "Find Bitbucket snippets referencing the domain".to_string(),
            impact: "Snippets are shared without repo-level access controls and routinely contain deployment credentials or ephemeral scripts with hardcoded tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Code Leaks".to_string(),
            query: format!(
                "site:gist.github.com \"{}\" (\"password\" | \"api_key\" | \"token\" | \"BEGIN RSA\")",
                clean_domain
            ),
            description: "Find GitHub Gists leaking credentials for the domain".to_string(),
            impact: "Anonymous/public gists are a persistent credential-leak vector - even after deletion they remain in Google's index for months".to_string(),
        });

        // Zendesk / Freshdesk / Intercom - public help centers often
        // reveal internal support workflow, staff names, and sample tokens.
        dorks.push(GoogleDork {
            category: "PII Exposure".to_string(),
            query: format!(
                "site:zendesk.com \"{}\" (\"internal\" | \"password\" | \"support ticket\")",
                clean_domain
            ),
            description: "Find Zendesk help center articles mentioning the domain".to_string(),
            impact: "Help center articles leak internal support workflows, staff email formats, and sometimes attach screenshots with tokens".to_string(),
        });
        dorks.push(GoogleDork {
            category: "PII Exposure".to_string(),
            query: format!(
                "site:freshdesk.com \"{}\"",
                clean_domain
            ),
            description: "Find Freshdesk portals mentioning the domain".to_string(),
            impact: "Public Freshdesk tickets can leak customer PII and internal-only knowledge base articles".to_string(),
        });

        // Terraform / Ansible / Kubernetes public state files - IaC
        // artifacts that contain every secret in plaintext.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (ext:tfstate | ext:tfvars | ext:tfstate.backup)",
                clean_domain
            ),
            description: "Find Terraform state or variable files on the target domain".to_string(),
            impact: "tfstate files contain every credential Terraform manages in plaintext: DB passwords, cloud provider keys, TLS private keys".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "\"{}\" (\"terraform.tfstate\" | \"terraform.tfvars\") (ext:txt | ext:json | ext:log)",
                clean_domain
            ),
            description: "Find Terraform state referenced in logs/dumps mentioning the domain".to_string(),
            impact: "Terraform state pasted into logs or Gists leaks the full infrastructure inventory alongside credentials".to_string(),
        });

        // Firebase / Supabase / Appwrite / PocketBase - BaaS platforms
        // where security rules are commonly left in permissive test mode.
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!("site:supabase.co \"{}\"", clean_domain),
            description: "Find Supabase project references for the domain".to_string(),
            impact: "Supabase projects use RLS; anon-key with disabled RLS gives read/write access to every row in the database".to_string(),
        });
        dorks.push(GoogleDork {
            category: "Cloud Services".to_string(),
            query: format!(
                "\"{}\" (\"firebasestorage.googleapis.com\" | \"firestore.googleapis.com\") (\"rules_version\" | \"allow read: if true\")",
                clean_domain
            ),
            description: "Find Firebase security rules set to allow public read".to_string(),
            impact: "'allow read: if true' rules make the entire Firestore/Storage bucket world-readable - one of the most common critical misconfigs".to_string(),
        });

        // Backstage / internal developer portals - the modern
        // \"internal wiki\" pattern for engineering orgs.
        dorks.push(GoogleDork {
            category: "Internal Documentation".to_string(),
            query: format!(
                "\"{}\" (inurl:/catalog/default/system | inurl:/catalog-graph | inurl:/api-docs) intitle:\"Backstage\"",
                clean_domain
            ),
            description: "Find exposed Backstage developer-portal instances for the domain".to_string(),
            impact: "Backstage catalogs enumerate every service, owner, oncall rotation and API - devastating recon aid when exposed unauth'd".to_string(),
        });

        // ArgoCD / Rancher / Portainer / K8s dashboard - exposed
        // cluster management UIs.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"Argo CD\" | intitle:\"Rancher\" | intitle:\"Portainer\" | intitle:\"Kubernetes Dashboard\")",
                clean_domain
            ),
            description: "Find exposed Kubernetes management dashboards".to_string(),
            impact: "Unauthenticated cluster dashboards grant full RCE on every workload in the cluster".to_string(),
        });

        // HashiCorp Vault / Consul / Nomad - exposed cluster UIs.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"Vault\" \"HashiCorp\" | intitle:\"Consul by HashiCorp\" | intitle:\"Nomad\")",
                clean_domain
            ),
            description: "Find exposed HashiCorp Vault/Consul/Nomad UIs".to_string(),
            impact: "Even the login page confirms Vault presence and version; misconfigured unseal/init endpoints allow full secret compromise".to_string(),
        });

        // Prometheus / Alertmanager / Netdata / cAdvisor - unauth
        // metrics endpoints leaking internal topology.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"Prometheus Time Series\" | intitle:\"Alertmanager\" | intitle:\"Netdata\" | intext:\"cAdvisor\")",
                clean_domain
            ),
            description: "Find unauth'd metrics/monitoring dashboards".to_string(),
            impact: "Prometheus /targets and /config leak the full internal service inventory, DB hostnames, and job configurations - prime attacker intel".to_string(),
        });

        // Jaeger / Zipkin / Tempo - distributed tracing UIs that leak
        // full internal request paths including headers.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"Jaeger UI\" | intitle:\"Zipkin\" | inurl:/jaeger/search)",
                clean_domain
            ),
            description: "Find exposed distributed tracing UIs".to_string(),
            impact: "Traces contain full request URLs, headers (including Authorization), and internal service RPC chains - complete architecture disclosure".to_string(),
        });

        // Sentry - self-hosted deployments occasionally expose issue
        // browsing without auth or leak DSNs in front-end code.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (inurl:sentry.io/organizations | inurl:/issues/ intitle:\"Sentry\")",
                clean_domain
            ),
            description: "Find Sentry organization/issue pages referencing the domain".to_string(),
            impact: "Sentry issues expose full stack traces with request/user context - each unfixed exception is a mini-recon report".to_string(),
        });

        // MinIO / Ceph / Swift - self-hosted S3-compatible endpoints.
        dorks.push(GoogleDork {
            category: "Cloud Storage".to_string(),
            query: format!(
                "\"{}\" (intitle:\"MinIO Console\" | intitle:\"MinIO Browser\" | intext:\"MinIO Object Storage\")",
                clean_domain
            ),
            description: "Find exposed MinIO consoles/browsers".to_string(),
            impact: "MinIO console with default minioadmin credentials grants read/write to all buckets; even the login page confirms the endpoint".to_string(),
        });

        // RabbitMQ / NATS / Kafka management UIs.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"RabbitMQ Management\" | intitle:\"Kafka Manager\" | intitle:\"NATS Streaming\")",
                clean_domain
            ),
            description: "Find exposed message-broker management interfaces".to_string(),
            impact: "Broker UIs allow queue inspection (which frequently contains customer data in messages) and often permit publishing arbitrary messages".to_string(),
        });

        // Envoy / Traefik / HAProxy admin - reverse proxy consoles that
        // leak the full backend routing table.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "\"{}\" (intitle:\"Traefik\" inurl:/dashboard | inurl:/envoy/ (\"clusters\" | \"config_dump\") | intitle:\"HAProxy Statistics Report\")",
                clean_domain
            ),
            description: "Find exposed reverse-proxy admin interfaces".to_string(),
            impact: "Proxy admin endpoints enumerate all backends, their health, and often admin routes intended for VPN-only access".to_string(),
        });

        // Env files exposed as public docs.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (filetype:env | filetype:cfg | filetype:ini) (\"DB_PASSWORD\" | \"SECRET_KEY\" | \"API_KEY\" | \"AWS_SECRET\")",
                clean_domain
            ),
            description: "Find dotenv or config files with credential keys on the target".to_string(),
            impact: "A single .env file exposure typically contains every credential the application uses in one file".to_string(),
        });

        // Login-page / SSO bypass hunt - directs the hunter to
        // authentication surfaces on the target.
        dorks.push(GoogleDork {
            category: "Login Pages".to_string(),
            query: format!(
                "site:{} (inurl:sso | inurl:saml | inurl:oauth | inurl:oidc | inurl:/auth/callback | inurl:/.well-known/openid-configuration)",
                clean_domain
            ),
            description: "Find SSO/OAuth/OIDC/SAML endpoints".to_string(),
            impact: "Federation endpoints reveal identity provider metadata, redirect_uri patterns, and are the highest-yield target for auth-bypass bugs".to_string(),
        });

        // Common backup filename patterns that Google indexes.
        dorks.push(GoogleDork {
            category: "Sensitive Files".to_string(),
            query: format!(
                "site:{} (inurl:backup | inurl:.bak | inurl:.old | inurl:.orig | inurl:.save | inurl:.swp | inurl:.swo) -site:github.com",
                clean_domain
            ),
            description: "Find backup/temporary-file remnants on the target".to_string(),
            impact: "Backup files served as static content reveal previous versions of code, including secrets that were rotated but not scrubbed".to_string(),
        });

        // WordPress-specific sensitive paths (blog-heavy targets).
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/wp-content/uploads/ (ext:sql | ext:zip | ext:log | ext:xlsx | ext:xls | ext:csv) | inurl:/wp-content/plugins/duplicator/ | inurl:/wp-content/backups-dup-lite/)",
                clean_domain
            ),
            description: "Find WordPress uploads directory leaking backups or spreadsheets".to_string(),
            impact: "wp-content/uploads is world-readable by default; duplicator/UpdraftPlus backups end up there and contain full DB dumps".to_string(),
        });

        // .well-known misconfigurations - modern security metadata paths
        // that occasionally leak internal domains and PKI info.
        dorks.push(GoogleDork {
            category: "Sensitive Paths".to_string(),
            query: format!(
                "site:{} (inurl:/.well-known/apple-app-site-association | inurl:/.well-known/assetlinks.json | inurl:/.well-known/appspecific/)",
                clean_domain
            ),
            description: "Find mobile-app deep-link config files".to_string(),
            impact: "app-site-association and assetlinks.json enumerate every mobile-app deep-link path, exposing internal-only routes the mobile app uses".to_string(),
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
