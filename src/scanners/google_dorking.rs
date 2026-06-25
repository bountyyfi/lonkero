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

        // --- High-impact, low-false-positive additions ---
        // The dorks below are vendor- or signature-anchored and restricted to
        // the target via `site:` or `intext:"{domain}"`. Each one is either an
        // exact product banner (no benign overlap) or a filesystem artifact
        // that should never be indexed in production.

        Self::push_exposed_admin_panels(&mut dorks, clean_domain);
        Self::push_internal_dashboards(&mut dorks, clean_domain);
        Self::push_directory_listings(&mut dorks, clean_domain);
        Self::push_backup_and_secret_files(&mut dorks, clean_domain);
        Self::push_vcs_artifacts(&mut dorks, clean_domain);
        Self::push_credentialed_configs(&mut dorks, clean_domain);
        Self::push_wordpress_artifacts(&mut dorks, clean_domain);
        Self::push_graphql_and_api_schemas(&mut dorks, clean_domain);
        Self::push_soap_wsdl(&mut dorks, clean_domain);
        Self::push_cloud_storage_extra(&mut dorks, clean_domain);
        Self::push_paste_and_code_leaks(&mut dorks, clean_domain);
        Self::push_bug_bounty_disclosures(&mut dorks, clean_domain);
        Self::push_document_leaks(&mut dorks, clean_domain);
        Self::push_log_and_debug_files(&mut dorks, clean_domain);
        Self::push_devops_artifacts(&mut dorks, clean_domain);

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

impl GoogleDorkingScanner {
    /// Exposed admin / management UIs. Each title string is a verbatim banner
    /// emitted by the product itself, so a `intitle:` hit on the target domain
    /// is essentially proof the panel is publicly reachable.
    fn push_exposed_admin_panels(dorks: &mut Vec<GoogleDork>, d: &str) {
        let panels: &[(&str, &str, &str)] = &[
            ("intitle:\"Dashboard [Jenkins]\"", "Jenkins CI dashboard",
             "Anonymous read of Jenkins exposes jobs, build logs and often credentials"),
            ("intitle:\"GitLab\" inurl:/users/sign_in", "Self-hosted GitLab login",
             "Public GitLab portal — enables user enumeration and possible repo exposure"),
            ("intitle:\"Gitea: Git with a cup of tea\"", "Gitea instance",
             "Self-hosted Gitea may expose internal repos and tokens"),
            ("intitle:\"Sign in - Gerrit Code Review\"", "Gerrit Code Review",
             "Public Gerrit may expose code review queues and patch sets"),
            ("intitle:\"phpMyAdmin\" inurl:index.php", "phpMyAdmin login page",
             "phpMyAdmin reachable from the internet — direct DB credential surface"),
            ("intitle:\"Adminer\" \"Login\"", "Adminer DB front-end",
             "Adminer is a single-file DB UI — exposure is high-impact"),
            ("intitle:\"phpPgAdmin\"", "phpPgAdmin (Postgres)",
             "Postgres web admin exposed — credential surface for Postgres"),
            ("intitle:\"Kibana\"", "Kibana dashboard",
             "Kibana usually has read access to ALL indexed logs/PII"),
            ("intitle:\"Grafana\" inurl:/login", "Grafana login",
             "Public Grafana often allows anonymous read of metrics and dashboards"),
            ("intitle:\"Prometheus Time Series Collection and Processing Server\"", "Prometheus UI",
             "Prometheus has no auth by default — exposes internal target list and metrics"),
            ("intitle:\"Alertmanager\"", "Prometheus Alertmanager",
             "Alertmanager exposes routing rules, silences and incident metadata"),
            ("intitle:\"splunk\" inurl:en-US/account/login", "Splunk login",
             "Splunk exposed — typically indexes credentials and PII"),
            ("intitle:\"Sign In - Airflow\"", "Apache Airflow login",
             "Airflow public — DAG code and connection secrets risk"),
            ("intitle:\"Spark Master at\"", "Apache Spark master UI",
             "Spark master allows job submission == RCE on the cluster"),
            ("intitle:\"Hadoop\" intext:\"Cluster\"", "Hadoop ResourceManager / NameNode",
             "Hadoop UI exposed — HDFS browsing and job submission"),
            ("intitle:\"SonarQube\" inurl:sessions/new", "SonarQube login",
             "SonarQube exposes source code, secrets and vulnerability reports"),
            ("intitle:\"RabbitMQ Management\"", "RabbitMQ management UI",
             "RabbitMQ UI exposed — message contents and credentials risk"),
            ("intitle:\"Sign in to Argo CD\"", "Argo CD login",
             "Argo CD exposes cluster manifests and deployment secrets"),
            ("intitle:\"Rancher\" inurl:dashboard", "Rancher cluster manager",
             "Rancher exposed — full Kubernetes cluster takeover risk"),
            ("intitle:\"Portainer\" inurl:#!/auth", "Portainer container UI",
             "Portainer exposed — full Docker/k8s control plane"),
            ("intitle:\"Traefik\"", "Traefik dashboard",
             "Traefik dashboard exposes routing rules and backend endpoints"),
            ("intitle:\"HAProxy Statistics Report\"", "HAProxy stats",
             "HAProxy stats page leaks backend server names and health"),
            ("intitle:\"Apache Tomcat\" intext:\"Manager App\"", "Tomcat Manager",
             "Tomcat Manager exposed — WAR upload == RCE"),
            ("intitle:\"WebLogic Server Administration Console\"", "Oracle WebLogic console",
             "WebLogic admin console is a long-standing critical RCE target"),
            ("intitle:\"JBoss\" inurl:/console", "JBoss admin console",
             "JBoss/Wildfly admin exposed — deployment-based RCE"),
            ("intitle:\"Solr Admin\"", "Apache Solr admin",
             "Solr admin exposed — query injection and historical RCE CVEs"),
            ("intitle:\"Couchbase\" intext:\"Sign in\"", "Couchbase admin",
             "Couchbase web console exposed — direct data and bucket access"),
            ("intitle:\"MinIO Console\"", "MinIO object storage console",
             "MinIO console exposed — S3-compatible bucket access surface"),
        ];
        for (q, desc, impact) in panels {
            dorks.push(GoogleDork {
                category: "Exposed Admin Panels".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Internal observability / dev dashboards that should never be public.
    fn push_internal_dashboards(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("intitle:\"Index of\" \"cgi-bin\"", "Apache cgi-bin listing",
             "Directory listing of cgi-bin — exposes executable scripts"),
            ("intitle:\"Mongo Express\"", "mongo-express UI",
             "mongo-express exposed — direct read/write to MongoDB"),
            ("intitle:\"Redis Commander\"", "redis-commander UI",
             "Redis web UI exposed — full key-value access"),
            ("intitle:\"Elasticsearch\" intext:\"cluster_name\"", "Elasticsearch JSON banner",
             "Elasticsearch HTTP API exposed — cluster takeover surface"),
            ("intitle:\"Consul by HashiCorp\"", "HashiCorp Consul UI",
             "Consul UI exposed — KV store and service catalog leak"),
            ("intitle:\"Nomad\"", "HashiCorp Nomad UI",
             "Nomad UI exposed — job submission == RCE"),
            ("intitle:\"Vault\" intext:\"sign in to Vault\"", "HashiCorp Vault login",
             "Vault UI exposed — token brute-force surface"),
            ("intitle:\"cAdvisor - /\"", "cAdvisor container metrics",
             "cAdvisor exposes container metadata and host paths"),
            ("intitle:\"node_exporter\"", "Prometheus node_exporter",
             "node_exporter exposes host-level OS metrics"),
            ("intitle:\"Sentry\" inurl:/auth/login", "Self-hosted Sentry",
             "Sentry exposes stack traces, request payloads and tokens"),
            ("intitle:\"Mattermost\" inurl:/login", "Self-hosted Mattermost",
             "Mattermost login exposed — user enum and OAuth abuse"),
            ("intitle:\"Bitbucket\" inurl:/login", "Self-hosted Bitbucket",
             "Bitbucket exposed — repo enumeration and potential SSRF"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "Internal Dashboards".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Directory listings — the `Index of` banner is emitted only by web
    /// servers in autoindex mode, so a hit is high-confidence.
    fn push_directory_listings(dorks: &mut Vec<GoogleDork>, d: &str) {
        let queries: &[(&str, &str, &str)] = &[
            ("intitle:\"Index of /\" \"Parent Directory\"",
             "Open directory listing", "Any indexed directory may expose source, backups or secrets"),
            ("intitle:\"Index of /\" \".git\"",
             "Indexed .git directory", "Full source-code disclosure via .git directory exposure"),
            ("intitle:\"Index of /\" \".env\"",
             "Indexed .env file", "Environment variables / secrets exposed"),
            ("intitle:\"Index of /backup\" OR intitle:\"Index of /backups\" OR intitle:\"Index of /bak\"",
             "Indexed backup directory", "Backup directory exposed — full database/source download risk"),
            ("intitle:\"Index of /uploads\"",
             "Indexed uploads directory", "User-uploaded files exposed — PII / document leak"),
            ("intitle:\"Index of /\" \"sql\"",
             "Indexed SQL dump", "Directory listing containing .sql dumps"),
            ("intitle:\"Index of /\" \"private\"",
             "Indexed private directory", "Private directory exposed by autoindex"),
            ("intitle:\"Index of /\" \"id_rsa\"",
             "Indexed SSH private key", "SSH private key inside an exposed directory"),
            ("intitle:\"Index of /\" \"wp-config\"",
             "Indexed WordPress config", "WordPress DB credentials exposure"),
            ("intitle:\"Index of /\" \"docker-compose\"",
             "Indexed docker-compose.yml", "Compose files often hardcode service credentials"),
        ];
        for (q, desc, impact) in queries {
            dorks.push(GoogleDork {
                category: "Directory Listings".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Backup, swap and secret files. Combined with `site:` these have an
    /// extremely high signal-to-noise ratio.
    fn push_backup_and_secret_files(dorks: &mut Vec<GoogleDork>, d: &str) {
        let files: &[(&str, &str, &str)] = &[
            ("ext:env", ".env file",
             "Environment file with API keys / DB creds"),
            ("inurl:\".env.production\" OR inurl:\".env.local\" OR inurl:\".env.staging\"",
             "Environment file variants",
             "Per-environment env files routinely contain production secrets"),
            ("ext:bak OR ext:backup OR ext:old OR ext:save OR ext:swp OR ext:swo",
             "Editor/server backup files",
             "Backup of source or config — direct credential/source leak"),
            ("ext:sql OR ext:dump OR ext:db",
             "Database dumps",
             "SQL dump on the web root — full DB exfiltration risk"),
            ("ext:sqlite OR ext:sqlite3 OR ext:db3",
             "SQLite database file",
             "Embedded DB on the web root — direct read of user records"),
            ("inurl:\"phpinfo.php\" OR inurl:\"info.php\" OR inurl:\"test.php\" intext:\"PHP Version\"",
             "phpinfo() output",
             "phpinfo leaks env vars, paths, modules and request headers"),
            ("ext:pem OR ext:key OR ext:crt OR ext:cer OR ext:p12 OR ext:pfx",
             "Key/certificate material",
             "Private keys or certs on the web root — TLS / signing compromise"),
            ("inurl:.npmrc intext:_authToken",
             ".npmrc with auth token",
             "Indexed .npmrc grants publish access to private npm packages"),
            ("inurl:.pypirc intext:password",
             ".pypirc with password",
             "PyPI publishing credentials"),
            ("inurl:.netrc intext:machine",
             ".netrc file",
             ".netrc stores plaintext passwords for HTTP/FTP automation"),
            ("inurl:\".bash_history\" OR inurl:\".zsh_history\"",
             "Shell history",
             "Shell history regularly contains pasted secrets and tokens"),
            ("inurl:\"id_rsa\" OR inurl:\"id_dsa\" OR inurl:\"id_ecdsa\" OR inurl:\"id_ed25519\"",
             "SSH private key file name",
             "SSH private key exposed by name — direct host compromise"),
            ("inurl:\".aws/credentials\" OR inurl:\"credentials\" filetype:csv intext:\"AKIA\"",
             "AWS credentials file",
             "AWS access keys exposed in a credentials file"),
            ("filetype:pem intext:\"BEGIN RSA PRIVATE KEY\" OR intext:\"BEGIN OPENSSH PRIVATE KEY\"",
             "PEM-armored private key",
             "Indexed PEM private key — used for TLS/SSH/JWT signing"),
            ("ext:cfg OR ext:conf OR ext:config intext:password",
             "Config file containing 'password'",
             "Configuration files referencing passwords"),
            ("ext:yml OR ext:yaml intext:password OR intext:secret_key",
             "YAML config with secrets",
             "Application YAML config exposing credentials"),
            ("ext:properties intext:password OR intext:jdbc",
             "Java .properties file",
             "Spring/Java properties files commonly contain DB credentials"),
            ("inurl:\".DS_Store\"",
             "Mac .DS_Store file",
             ".DS_Store enumerates files/folders that exist in a directory"),
            ("inurl:\"Thumbs.db\"",
             "Windows Thumbs.db",
             "Thumbs.db reveals file names and metadata from Windows dirs"),
        ];
        for (q, desc, impact) in files {
            dorks.push(GoogleDork {
                category: "Backup & Secret Files".to_string(),
                query: format!("site:{} {}", d, q),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Version-control artifacts exposed on the web root.
    fn push_vcs_artifacts(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\".git/config\" OR inurl:\".git/HEAD\" OR inurl:\".git/index\"",
             "Exposed .git internals", "Full repo reconstruction == source-code disclosure"),
            ("inurl:\".svn/entries\" OR inurl:\".svn/wc.db\"",
             "Exposed .svn metadata", "Subversion repo metadata — source reconstruction"),
            ("inurl:\".hg/store\" OR inurl:\".hg/dirstate\"",
             "Exposed Mercurial repo", "Mercurial metadata — source reconstruction"),
            ("inurl:\".bzr/branch-format\"",
             "Exposed Bazaar repo", "Bazaar metadata exposed"),
            ("inurl:\"CVS/Entries\" OR inurl:\"CVS/Root\"",
             "Exposed CVS metadata", "Legacy CVS metadata exposed"),
            ("inurl:\".gitlab-ci.yml\" OR inurl:\".github/workflows\"",
             "CI/CD pipeline definitions",
             "Pipeline YAML often references secret names and registry hosts"),
            ("inurl:\".gitignore\" intext:\".env\" OR intext:\"secrets\"",
             ".gitignore mentioning secrets",
             ".gitignore confirms which sensitive files exist next to it"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "VCS Artifacts".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Application-config files that hardcode credentials.
    fn push_credentialed_configs(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\"web.config\" intext:\"connectionString\"",
             "ASP.NET web.config with DB conn", "DB connection string with credentials"),
            ("inurl:\"appsettings.json\" intext:\"ConnectionStrings\"",
             ".NET appsettings.json", ".NET Core config with DB / API secrets"),
            ("inurl:\"application.properties\" intext:\"spring.datasource\"",
             "Spring datasource config", "Spring Boot DB credentials"),
            ("inurl:\"application.yml\" intext:\"datasource\"",
             "Spring YAML datasource", "Spring Boot DB credentials"),
            ("inurl:\"database.yml\" intext:\"password\"",
             "Rails database.yml", "Rails DB credentials"),
            ("inurl:\"secrets.yml\" intext:\"secret_key_base\"",
             "Rails secrets.yml", "Rails master signing key"),
            ("inurl:\"config/master.key\"",
             "Rails master.key", "Decrypts encrypted Rails credentials.yml.enc"),
            ("inurl:\"docker-compose.yml\" intext:\"password\" OR intext:\"API_KEY\"",
             "docker-compose with secrets", "Compose file with hardcoded credentials"),
            ("inurl:\"Dockerfile\" intext:\"ENV \" intext:\"KEY\" OR intext:\"TOKEN\" OR intext:\"PASSWORD\"",
             "Dockerfile ENV with secret", "Build-time secrets baked into image"),
            ("inurl:\"kubeconfig\" OR inurl:\".kube/config\"",
             "kubeconfig file", "Kubernetes cluster credentials"),
            ("inurl:\"terraform.tfstate\"",
             "Terraform state file", "Terraform state contains plaintext secrets and infra map"),
            ("inurl:\"terraform.tfvars\" intext:\"password\" OR intext:\"secret\"",
             "Terraform variable file", "Terraform variables with provider credentials"),
            ("inurl:\"ansible/group_vars\" OR inurl:\"vault.yml\" intext:\"$ANSIBLE_VAULT\"",
             "Ansible vault file", "Encrypted secrets — offline brute-force surface"),
            ("inurl:\"pubspec.yaml\" intext:\"secret\"",
             "Flutter pubspec with secret", "Flutter app secrets leaked"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "Credentialed Configs".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// WordPress-specific exposures. Each one targets a documented artifact.
    fn push_wordpress_artifacts(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\"wp-config.php.bak\" OR inurl:\"wp-config.php.old\" OR inurl:\"wp-config.php~\" OR inurl:\"wp-config.bak\"",
             "WordPress wp-config backup",
             "wp-config backups contain DB credentials and auth salts"),
            ("inurl:\"wp-content/debug.log\"",
             "WordPress debug.log", "Debug log leaks paths, plugin errors and sometimes tokens"),
            ("inurl:\"wp-content/uploads/wpallimport\"",
             "WP All Import uploads", "Importer uploads frequently contain CSVs with PII"),
            ("inurl:\"wp-content/uploads/backup\" OR inurl:\"wp-content/backup-db\"",
             "WordPress DB backups", "WP DB backups indexed — full site dump"),
            ("inurl:\"wp-json/wp/v2/users\"",
             "WP REST users endpoint", "User enumeration via REST"),
            ("inurl:\"xmlrpc.php\"",
             "WordPress xmlrpc endpoint",
             "xmlrpc supports password brute force amplification and pingback SSRF"),
            ("inurl:\"wp-content/uploads/.htpasswd\" OR inurl:\".htpasswd\"",
             ".htpasswd file", "Apache basic-auth hash file"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "WordPress Artifacts".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// GraphQL endpoints and exposed schemas.
    fn push_graphql_and_api_schemas(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\"/graphql\" OR inurl:\"/api/graphql\" OR inurl:\"/query\"",
             "GraphQL endpoint", "Reachable GraphQL endpoint — introspection / IDOR surface"),
            ("intitle:\"GraphQL Playground\" OR intitle:\"GraphiQL\" OR intitle:\"Apollo Studio\"",
             "GraphQL interactive UI", "Interactive GraphQL UI exposed — full schema browsing"),
            ("inurl:\"openapi.json\" OR inurl:\"swagger.json\" OR inurl:\"swagger.yaml\" OR inurl:\"openapi.yaml\"",
             "OpenAPI spec file", "Full API schema — enables targeted auth bypass / IDOR tests"),
            ("inurl:\"/swagger-ui\" OR inurl:\"/swagger-ui.html\" OR inurl:\"/v3/api-docs\"",
             "Swagger UI", "Interactive API docs — enumerates every endpoint"),
            ("inurl:\"/_postman/\" OR inurl:\"postman_collection.json\"",
             "Postman collection",
             "Exported Postman collections often embed API keys and example bodies"),
            ("inurl:\"AsyncAPI\" OR inurl:\"asyncapi.yaml\" OR inurl:\"asyncapi.json\"",
             "AsyncAPI spec", "Streaming/event-driven API schema exposed"),
            ("inurl:\"actuator\" OR inurl:\"actuator/env\" OR inurl:\"actuator/heapdump\"",
             "Spring Boot Actuator endpoint",
             "Actuator exposes env vars, beans, heap dumps and trace data"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "API Schemas & GraphQL".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// SOAP / WSDL endpoints, often forgotten legacy attack surface.
    fn push_soap_wsdl(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\"?wsdl\" OR ext:wsdl",
             "Exposed WSDL", "SOAP service description — full operation/parameter map"),
            ("inurl:\"asmx?wsdl\" OR ext:asmx",
             "ASP.NET .asmx service", "Legacy .NET web services often unauthenticated"),
            ("inurl:\".svc?wsdl\"",
             "WCF service", "WCF service description — legacy .NET attack surface"),
            ("inurl:\"jaxws\" OR inurl:\"cxf/services\"",
             "JAX-WS / CXF SOAP endpoint", "Java SOAP service listing"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "SOAP / WSDL".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Additional cloud-storage providers not in the original list.
    fn push_cloud_storage_extra(dorks: &mut Vec<GoogleDork>, d: &str) {
        let providers: &[(&str, &str, &str)] = &[
            ("site:r2.dev", "Cloudflare R2 public hostname",
             "Cloudflare R2 public bucket referencing the domain"),
            ("site:r2.cloudflarestorage.com", "Cloudflare R2 storage",
             "R2 buckets serving content for the domain"),
            ("site:storage.googleapis.com", "Google Cloud Storage bucket",
             "GCS bucket content referencing the domain"),
            ("site:storage.cloud.google.com", "Google Cloud Storage browser",
             "GCS bucket browser referencing the domain"),
            ("site:s3.us-east-1.amazonaws.com OR site:s3.us-west-2.amazonaws.com OR site:s3.eu-west-1.amazonaws.com",
             "Region-prefixed S3 hosts", "S3 buckets in common regions"),
            ("site:s3-website.us-east-1.amazonaws.com OR site:s3-website-us-east-1.amazonaws.com",
             "S3 static website endpoints", "Static sites served from S3"),
            ("site:wasabisys.com", "Wasabi object storage",
             "Wasabi bucket referencing the domain"),
            ("site:backblazeb2.com OR site:b2cdn.com",
             "Backblaze B2 storage", "B2 bucket referencing the domain"),
            ("site:linodeobjects.com", "Linode object storage",
             "Linode bucket referencing the domain"),
            ("site:scw.cloud", "Scaleway object storage",
             "Scaleway bucket referencing the domain"),
            ("site:fly.storage.tigris.dev", "Fly.io Tigris storage",
             "Tigris bucket referencing the domain"),
            ("site:supabase.co inurl:storage", "Supabase storage",
             "Supabase storage URL referencing the domain"),
            ("site:appspot.com", "GAE / Cloud Run default domain",
             "Default appspot host referencing the target"),
            ("site:azurewebsites.net", "Azure App Service default host",
             "Default Azure App Service host referencing the target"),
            ("site:azurefd.net OR site:azureedge.net",
             "Azure Front Door / CDN host", "Azure CDN hosts referencing the target"),
            ("site:cloudfront.net",
             "AWS CloudFront", "CloudFront distributions referencing the target"),
            ("site:herokuapp.com",
             "Heroku default host", "Heroku app referencing the target"),
            ("site:vercel.app OR site:netlify.app OR site:pages.dev",
             "Static / serverless host", "Preview deployments referencing the target"),
        ];
        for (q, desc, impact) in providers {
            dorks.push(GoogleDork {
                category: "Cloud Storage".to_string(),
                query: format!("{} \"{}\"", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Paste / snippet / code-sharing sites — anchored by exact domain string.
    fn push_paste_and_code_leaks(dorks: &mut Vec<GoogleDork>, d: &str) {
        let sites: &[(&str, &str, &str)] = &[
            ("site:gist.github.com",
             "GitHub Gists", "Gists often hold one-off scripts with embedded credentials"),
            ("site:gitlab.com/snippets OR site:gitlab.com/-/snippets",
             "GitLab snippets", "GitLab snippets — credential paste risk"),
            ("site:bitbucket.org/snippets",
             "Bitbucket snippets", "Bitbucket snippets — credential paste risk"),
            ("site:scribd.com",
             "Scribd documents", "Uploaded docs may contain HR/financial/PII data"),
            ("site:slideshare.net",
             "SlideShare presentations", "Internal-style decks routinely uploaded publicly"),
            ("site:hastebin.com OR site:dpaste.com OR site:rentry.co OR site:paste.ee OR site:ghostbin.com",
             "Generic paste services", "Credential / log paste risk"),
            ("site:ideone.com OR site:repl.it OR site:replit.com",
             "Online IDE / runner snippets",
             "Hosted code snippets often retain embedded credentials"),
        ];
        for (q, desc, impact) in sites {
            dorks.push(GoogleDork {
                category: "Code Leaks".to_string(),
                query: format!("{} \"{}\"", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Bug-bounty / vulnerability-disclosure platforms.
    fn push_bug_bounty_disclosures(dorks: &mut Vec<GoogleDork>, d: &str) {
        let sites: &[(&str, &str, &str)] = &[
            ("site:hackerone.com inurl:reports",
             "HackerOne disclosed reports", "Previously disclosed bugs targeting the domain"),
            ("site:bugcrowd.com/disclosures",
             "Bugcrowd disclosures", "Disclosed Bugcrowd reports for the domain"),
            ("site:intigriti.com",
             "Intigriti disclosures", "Intigriti research about the domain"),
            ("site:yeswehack.com",
             "YesWeHack reports", "YesWeHack disclosures for the domain"),
            ("site:huntr.com OR site:huntr.dev",
             "huntr reports", "huntr open-source disclosures referencing the domain"),
            ("site:securitytrails.com",
             "SecurityTrails data", "Historical DNS / subdomain intelligence"),
            ("site:crt.sh",
             "Certificate transparency", "Issued certs reveal subdomains and SAN entries"),
        ];
        for (q, desc, impact) in sites {
            dorks.push(GoogleDork {
                category: "Public Disclosures".to_string(),
                query: format!("{} intext:\"{}\"", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Confidential documents indexed under the target.
    fn push_document_leaks(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("filetype:pdf intext:\"confidential\" OR intext:\"internal use only\" OR intext:\"do not distribute\"",
             "Confidential PDF",
             "PDF marked confidential — potential PII / IP disclosure"),
            ("filetype:xlsx OR filetype:xls intext:\"password\" OR intext:\"username\"",
             "Spreadsheet with credentials",
             "Spreadsheet containing credential-style columns"),
            ("filetype:docx intext:\"NDA\" OR intext:\"non-disclosure\"",
             "NDA document", "NDA documents indexed publicly"),
            ("filetype:csv intext:\"@\" intext:\"phone\" OR intext:\"address\"",
             "PII CSV", "CSV containing PII columns"),
            ("filetype:pptx intext:\"internal\" OR intext:\"roadmap\"",
             "Internal slide deck", "Internal roadmap deck leaked publicly"),
            ("filetype:vsdx OR filetype:vsd",
             "Visio diagrams", "Network/architecture diagrams indexed"),
            ("filetype:eml OR filetype:msg",
             "Raw email files", "Indexed emails — header + body disclosure"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "Document Leaks".to_string(),
                query: format!("site:{} {}", d, q),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// Logs and debug output — often indexed accidentally.
    fn push_log_and_debug_files(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("ext:log intext:\"DEBUG\" OR intext:\"ERROR\" OR intext:\"Exception\"",
             "Application log file", "Indexed application log — stack traces and IDs"),
            ("ext:log intext:\"Authorization: Bearer\"",
             "Log containing bearer tokens", "Bearer tokens echoed into a log file"),
            ("ext:log intext:\"set-cookie\" intext:\"session\"",
             "Log containing session cookies", "Session cookies leaked via access log"),
            ("inurl:\"access.log\" OR inurl:\"access_log\" OR inurl:\"error.log\"",
             "Web-server log files", "Apache/Nginx logs indexed"),
            ("inurl:\"laravel.log\"",
             "Laravel log file", "Laravel debug log — secrets often present"),
            ("inurl:\"sentry/issues\" OR inurl:\"sentry-dsn\"",
             "Sentry DSN / issue link", "Sentry DSN may be abused for noise injection"),
            ("intitle:\"Whoops! There was an error\"",
             "Symfony / Laravel debug page",
             "Whoops debug page exposes source, env vars and config"),
            ("intitle:\"Werkzeug Debugger\"",
             "Flask Werkzeug debugger",
             "Werkzeug PIN debugger may allow RCE if exposed"),
            ("intitle:\"Django Debug Page\"",
             "Django debug page", "Django DEBUG=True page leaks settings and traceback"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "Logs & Debug Output".to_string(),
                query: format!("site:{} {}", d, q),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
    }

    /// DevOps and CI/CD-adjacent artifacts.
    fn push_devops_artifacts(dorks: &mut Vec<GoogleDork>, d: &str) {
        let items: &[(&str, &str, &str)] = &[
            ("inurl:\".travis.yml\" OR inurl:\".circleci/config.yml\" OR inurl:\"bitbucket-pipelines.yml\" OR inurl:\"Jenkinsfile\"",
             "CI pipeline file",
             "Pipeline definitions reference secret names and registry hosts"),
            ("inurl:\"argocd-cm\" OR inurl:\"argocd-secret\"",
             "Argo CD config map / secret",
             "Argo CD config exposes cluster credentials"),
            ("inurl:\"flux-system\" intext:\"Kind: Kustomization\"",
             "Flux CD manifests", "GitOps manifests may include sealed/unsealed secrets"),
            ("inurl:\"helm/charts\" intext:\"values.yaml\" intext:\"password\"",
             "Helm values.yaml with password", "Helm chart values containing credentials"),
            ("inurl:\".env.vault\"",
             "dotenv-vault file", "Encrypted dotenv vault file — offline brute-force surface"),
            ("inurl:\"id_rsa.pub\" OR inurl:\"authorized_keys\"",
             "SSH key files", "authorized_keys / pub-key files exposed"),
            ("ext:rdp",
             "RDP connection file", "RDP shortcut with host + sometimes credentials"),
            ("ext:ovpn",
             "OpenVPN profile", "OpenVPN client config — connect into internal network"),
            ("inurl:\"wireguard\" ext:conf intext:\"PrivateKey\"",
             "WireGuard config",
             "WireGuard config with private key — VPN takeover"),
        ];
        for (q, desc, impact) in items {
            dorks.push(GoogleDork {
                category: "DevOps Artifacts".to_string(),
                query: format!("{} site:{}", q, d),
                description: (*desc).to_string(),
                impact: (*impact).to_string(),
            });
        }
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
    fn test_high_impact_categories_exist() {
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        for expected in [
            "Exposed Admin Panels",
            "Internal Dashboards",
            "Directory Listings",
            "Backup & Secret Files",
            "VCS Artifacts",
            "Credentialed Configs",
            "WordPress Artifacts",
            "API Schemas & GraphQL",
            "SOAP / WSDL",
            "Public Disclosures",
            "Document Leaks",
            "Logs & Debug Output",
            "DevOps Artifacts",
        ] {
            assert!(
                results.by_category.contains_key(expected),
                "missing category: {}",
                expected
            );
        }
    }

    #[test]
    fn test_every_dork_references_target_or_known_site() {
        // Every generated dork must constrain its search to either the target
        // domain (via `site:` / `intext:`) or a known third-party site, so a
        // hit cannot be a generic, unrelated result.
        let scanner = GoogleDorkingScanner::new();
        let results = scanner.generate_dorks("example.com");

        for dork in &results.dorks {
            let q = &dork.query;
            let mentions_target =
                q.contains("example.com") || q.contains("\"example.com\"");
            // Allow generic security.txt enumeration which intentionally is global.
            let is_known_global = q.contains("site:*/security.txt");
            assert!(
                mentions_target || is_known_global,
                "dork is not anchored to the target: {}",
                q
            );
        }
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
