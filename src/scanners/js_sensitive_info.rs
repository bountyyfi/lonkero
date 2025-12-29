// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info};

pub struct JsSensitiveInfoScanner {
    http_client: Arc<HttpClient>,
    patterns: SensitivePatterns,
}

/// Categories of sensitive information
#[derive(Debug, Clone)]
struct SensitivePatterns {
    /// Jira/issue tracker patterns
    jira_patterns: Vec<CompiledPattern>,
    /// Internal tool URLs
    internal_tools: Vec<CompiledPattern>,
    /// Document/file paths
    document_patterns: Vec<CompiledPattern>,
    /// Admin/debug logic
    admin_debug_patterns: Vec<CompiledPattern>,
    /// Sensitive comments
    comment_patterns: Vec<CompiledPattern>,
    /// Credential patterns
    credential_patterns: Vec<CompiledPattern>,
    /// Employee/internal info
    employee_patterns: Vec<CompiledPattern>,
    /// Environment/config leaks
    environment_patterns: Vec<CompiledPattern>,
    /// Analytics/BI tools
    analytics_patterns: Vec<CompiledPattern>,
}

#[derive(Clone)]
struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
    cwe: String,
}

impl std::fmt::Debug for CompiledPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPattern")
            .field("name", &self.name)
            .field("severity", &self.severity)
            .finish()
    }
}

/// Found sensitive information
#[derive(Debug, Clone)]
struct SensitiveMatch {
    pattern_name: String,
    matched_value: String,
    context: String,
    line_number: usize,
    severity: Severity,
    category: String,
    cwe: String,
    description: String,
}

impl JsSensitiveInfoScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            patterns: Self::build_patterns(),
        }
    }

    fn build_patterns() -> SensitivePatterns {
        SensitivePatterns {
            jira_patterns: vec![
                CompiledPattern {
                    name: "Jira Ticket Reference".to_string(),
                    // Must be uppercase letters followed by dash and number, and NOT match common CSS/JS patterns
                    // Require at least 3 letters to avoid matching CSS like "fi-2", and number >= 10 to avoid "north-1"
                    regex: Regex::new(r#"\b([A-Z]{3,10}-\d{2,6})\b"#).unwrap(),
                    severity: Severity::Low,
                    description: "Jira ticket reference found - may reveal project names and internal tracking".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Jira URL".to_string(),
                    regex: Regex::new(r#"https?://[a-zA-Z0-9\-]+\.atlassian\.net/[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Direct Jira URL found - exposes internal issue tracker".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Jira On-Premise URL".to_string(),
                    regex: Regex::new(r#"https?://jira\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Self-hosted Jira URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
            ],
            internal_tools: vec![
                CompiledPattern {
                    name: "Confluence URL".to_string(),
                    regex: Regex::new(r#"https?://[a-zA-Z0-9\-]+\.atlassian\.net/wiki/[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Confluence documentation URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Slack Webhook".to_string(),
                    regex: Regex::new(r#"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+"#).unwrap(),
                    severity: Severity::High,
                    description: "Slack webhook URL exposed - can be used to send messages to internal channels".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Discord Webhook".to_string(),
                    regex: Regex::new(r#"https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+"#).unwrap(),
                    severity: Severity::High,
                    description: "Discord webhook URL exposed".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Internal GitLab URL".to_string(),
                    regex: Regex::new(r#"https?://gitlab\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Internal GitLab URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Jenkins URL".to_string(),
                    regex: Regex::new(r#"https?://jenkins\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Jenkins CI/CD URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "SonarQube URL".to_string(),
                    regex: Regex::new(r#"https?://sonar[a-zA-Z0-9\-]*\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "SonarQube code quality URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Grafana URL".to_string(),
                    regex: Regex::new(r#"https?://grafana\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Grafana monitoring URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Kibana URL".to_string(),
                    regex: Regex::new(r#"https?://kibana\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Kibana logging URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
            ],
            document_patterns: vec![
                CompiledPattern {
                    name: "PDF Document Path".to_string(),
                    regex: Regex::new(r#"[\"'/][a-zA-Z0-9_\-/]+\.pdf"#).unwrap(),
                    severity: Severity::Low,
                    description: "PDF document path found - may contain sensitive documents".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Excel/CSV Path".to_string(),
                    regex: Regex::new(r#"[\"'/][a-zA-Z0-9_\-/]+\.(xlsx?|csv)"#).unwrap(),
                    severity: Severity::Low,
                    description: "Spreadsheet file path found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Internal Document Server".to_string(),
                    regex: Regex::new(r#"https?://docs?\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Internal document server URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "SharePoint URL".to_string(),
                    regex: Regex::new(r#"https?://[a-zA-Z0-9\-]+\.sharepoint\.com[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "SharePoint URL found - may expose internal documents".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Google Drive Document".to_string(),
                    regex: Regex::new(r#"https://docs\.google\.com/(document|spreadsheets|presentation)/d/[a-zA-Z0-9_-]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Google Drive document URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
            ],
            admin_debug_patterns: vec![
                CompiledPattern {
                    name: "isDev/isDebug Flag".to_string(),
                    regex: Regex::new(r#"(?i)(isDev|isDebug|isTest|debugMode|devMode|testMode)\s*[=:]\s*(true|1|!0)"#).unwrap(),
                    severity: Severity::High,
                    description: "Debug/development mode flag enabled in production".to_string(),
                    cwe: "CWE-489".to_string(),
                },
                CompiledPattern {
                    name: "Admin Check Logic".to_string(),
                    regex: Regex::new(r#"(?i)(isAdmin|isSuperUser|isRoot|hasAdminRole)\s*[=:&|]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Admin privilege check logic exposed - may reveal access control bypass".to_string(),
                    cwe: "CWE-284".to_string(),
                },
                CompiledPattern {
                    name: "Debug Endpoint".to_string(),
                    regex: Regex::new(r#"[\"'](/debug|/admin/debug|/api/debug|/__debug__|/phpinfo|/server-status)[\"']"#).unwrap(),
                    severity: Severity::High,
                    description: "Debug endpoint reference found".to_string(),
                    cwe: "CWE-489".to_string(),
                },
                CompiledPattern {
                    name: "Console.log with Sensitive Data".to_string(),
                    regex: Regex::new(r#"console\.(log|debug|info)\s*\([^)]*(?i)(password|secret|token|key|auth|credit|ssn)[^)]*\)"#).unwrap(),
                    severity: Severity::High,
                    description: "Console logging of sensitive data detected".to_string(),
                    cwe: "CWE-532".to_string(),
                },
                CompiledPattern {
                    name: "Bypass Authentication Flag".to_string(),
                    regex: Regex::new(r#"(?i)(bypassAuth|skipAuth|noAuth|disableAuth|mockAuth)\s*[=:]\s*(true|1)"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Authentication bypass flag found".to_string(),
                    cwe: "CWE-287".to_string(),
                },
                CompiledPattern {
                    name: "Feature Flag - Admin".to_string(),
                    regex: Regex::new(r#"(?i)(?:feature|flag)[_.]?(?:admin|superuser|elevated)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Admin feature flag reference found".to_string(),
                    cwe: "CWE-284".to_string(),
                },
            ],
            comment_patterns: vec![
                CompiledPattern {
                    name: "TODO with Security Implication".to_string(),
                    regex: Regex::new(r#"(?i)(//|/\*|\*)\s*(TODO|FIXME|HACK|XXX|BUG)[:\s].*(?:security|auth|password|token|key|vuln|exploit|bypass|inject)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Security-related TODO/FIXME comment found".to_string(),
                    cwe: "CWE-615".to_string(),
                },
                CompiledPattern {
                    name: "Hardcoded Credential Comment".to_string(),
                    regex: Regex::new(r#"(?i)(//|/\*|\*)\s*(?:password|secret|key|token)\s*[=:]\s*[^\s]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Hardcoded credential in comment".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Temporary/Test Comment".to_string(),
                    regex: Regex::new(r#"(?i)(//|/\*|\*)\s*(TEMP|TEST|REMOVE|DELETE|DEBUG)\s*[:-]"#).unwrap(),
                    severity: Severity::Low,
                    description: "Temporary/test code marker found".to_string(),
                    cwe: "CWE-489".to_string(),
                },
                CompiledPattern {
                    name: "Internal Note".to_string(),
                    regex: Regex::new(r#"(?i)(//|/\*|\*)\s*(internal|private|confidential|do not share)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Internal/confidential note in code".to_string(),
                    cwe: "CWE-615".to_string(),
                },
            ],
            credential_patterns: vec![
                CompiledPattern {
                    name: "AWS Access Key".to_string(),
                    regex: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "AWS Access Key ID found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "AWS Secret Key Pattern".to_string(),
                    regex: Regex::new(r#"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "AWS Secret Access Key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Generic API Key".to_string(),
                    regex: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "API key found in JavaScript".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Generic Secret".to_string(),
                    regex: Regex::new(r#"(?i)(secret|private[_-]?key)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Secret/private key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Password Assignment".to_string(),
                    regex: Regex::new(r#"(?i)password\s*[=:]\s*['\"][^'\"]{4,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Hardcoded password found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Bearer Token".to_string(),
                    regex: Regex::new(r#"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Bearer token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "JWT Token".to_string(),
                    regex: Regex::new(r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"#).unwrap(),
                    severity: Severity::High,
                    description: "JWT token found in JavaScript".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Private Key Block".to_string(),
                    regex: Regex::new(r#"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Private key found in JavaScript".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                CompiledPattern {
                    name: "Google API Key".to_string(),
                    regex: Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Google API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Stripe Key".to_string(),
                    regex: Regex::new(r#"(?:sk|pk)_(test|live)_[a-zA-Z0-9]{24,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Stripe API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "GitHub Token".to_string(),
                    regex: Regex::new(r#"gh[pousr]_[A-Za-z0-9_]{36,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "GitHub token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "NPM Token".to_string(),
                    regex: Regex::new(r#"npm_[a-zA-Z0-9]{36}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "NPM token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Mapbox Access Token".to_string(),
                    // Mapbox tokens start with pk.eyJ (public) or sk.eyJ (secret)
                    regex: Regex::new(r#"(?:pk|sk)\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Mapbox access token found - can be exploited for massive billing abuse. \
                        Attackers can automate millions of API calls to Mapbox Static API causing \
                        significant financial damage (~$2 per 1000 requests = $200K for 100M requests).".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Mapbox Secret Token".to_string(),
                    regex: Regex::new(r#"sk\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Mapbox SECRET token found - provides elevated API access. \
                        More dangerous than public tokens, should never be exposed client-side.".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "HERE API Key".to_string(),
                    regex: Regex::new(r#"(?i)here[_-]?api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "HERE Maps API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "OpenAI API Key".to_string(),
                    regex: Regex::new(r#"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "OpenAI API key found - can be exploited for significant billing abuse".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Twilio API Key".to_string(),
                    regex: Regex::new(r#"SK[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Twilio API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "SendGrid API Key".to_string(),
                    regex: Regex::new(r#"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "SendGrid API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Mailgun API Key".to_string(),
                    regex: Regex::new(r#"key-[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::High,
                    description: "Mailgun API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Firebase
                CompiledPattern {
                    name: "Firebase URL".to_string(),
                    regex: Regex::new(r#"https://[a-zA-Z0-9_-]+\.firebaseio\.com"#).unwrap(),
                    severity: Severity::High,
                    description: "Firebase database URL found - check for unauthenticated read/write access".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Firebase API Key".to_string(),
                    regex: Regex::new(r#"(?i)firebase[_-]?api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_-]{20,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Firebase API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Heroku
                CompiledPattern {
                    name: "Heroku API Key".to_string(),
                    regex: Regex::new(r#"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Heroku API key found - allows full account access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Azure
                CompiledPattern {
                    name: "Azure Storage Key".to_string(),
                    regex: Regex::new(r#"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Azure Storage connection string with account key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Azure SAS Token".to_string(),
                    regex: Regex::new(r#"[?&]sig=[a-zA-Z0-9%]{43,}(&|$)"#).unwrap(),
                    severity: Severity::High,
                    description: "Azure SAS token found - check expiration and permissions".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // DigitalOcean
                CompiledPattern {
                    name: "DigitalOcean Token".to_string(),
                    regex: Regex::new(r#"dop_v1_[a-f0-9]{64}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "DigitalOcean personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "DigitalOcean OAuth Token".to_string(),
                    regex: Regex::new(r#"doo_v1_[a-f0-9]{64}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "DigitalOcean OAuth token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "DigitalOcean Refresh Token".to_string(),
                    regex: Regex::new(r#"dor_v1_[a-f0-9]{64}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "DigitalOcean refresh token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // GitLab
                CompiledPattern {
                    name: "GitLab Personal Access Token".to_string(),
                    regex: Regex::new(r#"glpat-[a-zA-Z0-9_-]{20}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "GitLab personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "GitLab Pipeline Token".to_string(),
                    regex: Regex::new(r#"glptt-[a-f0-9]{40}"#).unwrap(),
                    severity: Severity::High,
                    description: "GitLab pipeline trigger token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "GitLab Runner Token".to_string(),
                    regex: Regex::new(r#"glrt-[a-zA-Z0-9_-]{20}"#).unwrap(),
                    severity: Severity::High,
                    description: "GitLab runner registration token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Bitbucket
                CompiledPattern {
                    name: "Bitbucket App Password".to_string(),
                    regex: Regex::new(r#"(?i)bitbucket[_-]?(?:app[_-]?)?password\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Bitbucket app password found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Telegram
                CompiledPattern {
                    name: "Telegram Bot Token".to_string(),
                    regex: Regex::new(r#"\d{8,10}:[a-zA-Z0-9_-]{35}"#).unwrap(),
                    severity: Severity::High,
                    description: "Telegram bot token found - allows bot control and message access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Facebook
                CompiledPattern {
                    name: "Facebook Access Token".to_string(),
                    regex: Regex::new(r#"EAA[a-zA-Z0-9]{100,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Facebook access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Facebook App Secret".to_string(),
                    regex: Regex::new(r#"(?i)fb[_-]?(?:app[_-]?)?secret\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Facebook app secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Twitter
                CompiledPattern {
                    name: "Twitter Bearer Token".to_string(),
                    regex: Regex::new(r#"AAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{30,}"#).unwrap(),
                    severity: Severity::High,
                    description: "Twitter bearer token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Twitter API Key".to_string(),
                    regex: Regex::new(r#"(?i)twitter[_-]?(?:api[_-]?)?(?:key|consumer)\s*[=:]\s*['\"][a-zA-Z0-9]{25}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Twitter API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Shopify
                CompiledPattern {
                    name: "Shopify Access Token".to_string(),
                    regex: Regex::new(r#"shpat_[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Shopify access token found - allows store API access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Shopify Private App Token".to_string(),
                    regex: Regex::new(r#"shppa_[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Shopify private app access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Shopify Shared Secret".to_string(),
                    regex: Regex::new(r#"shpss_[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Shopify shared secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // PayPal/Braintree
                CompiledPattern {
                    name: "PayPal/Braintree Access Token".to_string(),
                    regex: Regex::new(r#"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "PayPal/Braintree production access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Square
                CompiledPattern {
                    name: "Square Access Token".to_string(),
                    regex: Regex::new(r#"sq0atp-[a-zA-Z0-9_-]{22}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Square access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Square OAuth Secret".to_string(),
                    regex: Regex::new(r#"sq0csp-[a-zA-Z0-9_-]{43}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Square OAuth secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Algolia
                CompiledPattern {
                    name: "Algolia Admin API Key".to_string(),
                    regex: Regex::new(r#"(?i)algolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Algolia admin API key found - allows index modification".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Cloudinary
                CompiledPattern {
                    name: "Cloudinary URL".to_string(),
                    regex: Regex::new(r#"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Cloudinary URL with API secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Sentry
                CompiledPattern {
                    name: "Sentry DSN".to_string(),
                    regex: Regex::new(r#"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Sentry DSN found - may allow error injection".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Sentry Auth Token".to_string(),
                    regex: Regex::new(r#"sntrys_[a-zA-Z0-9]{64}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Sentry auth token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Datadog
                CompiledPattern {
                    name: "Datadog API Key".to_string(),
                    regex: Regex::new(r#"(?i)datadog[_-]?api[_-]?key\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Datadog API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Datadog App Key".to_string(),
                    regex: Regex::new(r#"(?i)datadog[_-]?app[_-]?key\s*[=:]\s*['\"][a-f0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Datadog app key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // New Relic
                CompiledPattern {
                    name: "New Relic License Key".to_string(),
                    regex: Regex::new(r#"(?i)new[_-]?relic[_-]?license\s*[=:]\s*['\"][a-f0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "New Relic license key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "New Relic API Key".to_string(),
                    regex: Regex::new(r#"NRAK-[A-Z0-9]{27}"#).unwrap(),
                    severity: Severity::High,
                    description: "New Relic API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Anthropic
                CompiledPattern {
                    name: "Anthropic API Key".to_string(),
                    regex: Regex::new(r#"sk-ant-api[a-zA-Z0-9_-]{32,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Anthropic API key found - can be exploited for billing abuse".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Cohere
                CompiledPattern {
                    name: "Cohere API Key".to_string(),
                    regex: Regex::new(r#"(?i)cohere[_-]?api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Cohere API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Notion
                CompiledPattern {
                    name: "Notion Integration Token".to_string(),
                    regex: Regex::new(r#"secret_[a-zA-Z0-9]{43}"#).unwrap(),
                    severity: Severity::High,
                    description: "Notion integration token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Asana
                CompiledPattern {
                    name: "Asana Personal Access Token".to_string(),
                    regex: Regex::new(r#"[01]/[0-9]{16}:[a-f0-9]{32}"#).unwrap(),
                    severity: Severity::High,
                    description: "Asana personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Linear
                CompiledPattern {
                    name: "Linear API Key".to_string(),
                    regex: Regex::new(r#"lin_api_[a-zA-Z0-9]{40}"#).unwrap(),
                    severity: Severity::High,
                    description: "Linear API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Doppler
                CompiledPattern {
                    name: "Doppler API Key".to_string(),
                    regex: Regex::new(r#"dp\.pt\.[a-zA-Z0-9]{43}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Doppler API key found - secrets manager access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Postman
                CompiledPattern {
                    name: "Postman API Key".to_string(),
                    regex: Regex::new(r#"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"#).unwrap(),
                    severity: Severity::High,
                    description: "Postman API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Supabase
                CompiledPattern {
                    name: "Supabase Service Key".to_string(),
                    regex: Regex::new(r#"sbp_[a-f0-9]{40}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Supabase service key found - bypasses RLS".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // PlanetScale
                CompiledPattern {
                    name: "PlanetScale Token".to_string(),
                    regex: Regex::new(r#"pscale_tkn_[a-zA-Z0-9_-]{43}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "PlanetScale database token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "PlanetScale Password".to_string(),
                    regex: Regex::new(r#"pscale_pw_[a-zA-Z0-9_-]{43}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "PlanetScale database password found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Vercel
                CompiledPattern {
                    name: "Vercel Token".to_string(),
                    regex: Regex::new(r#"(?i)vercel[_-]?token\s*[=:]\s*['\"][a-zA-Z0-9]{24}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Vercel authentication token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Netlify
                CompiledPattern {
                    name: "Netlify Personal Access Token".to_string(),
                    regex: Regex::new(r#"nfp_[a-zA-Z0-9]{40}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Netlify personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Contentful
                CompiledPattern {
                    name: "Contentful Delivery Token".to_string(),
                    regex: Regex::new(r#"(?i)contentful[_-]?(?:delivery[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9_-]{43}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Contentful delivery/preview token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Airtable - API keys must be in assignment context to avoid false positives
                // like "keyboard", "keydown", "keypress", etc.
                CompiledPattern {
                    name: "Airtable API Key".to_string(),
                    // Real Airtable keys look like: keyXXXXXXXXXXXXXX (key + 14 alphanumeric chars)
                    // Require assignment context (=, :, or quote) to filter out variable names
                    regex: Regex::new(r#"[=:'"]\s*key[a-zA-Z0-9]{14}\s*['"}\],;]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Potential Airtable API key".to_string(),
                    cwe: "CWE-312".to_string(),
                },
                CompiledPattern {
                    name: "Airtable Personal Access Token".to_string(),
                    regex: Regex::new(r#"pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Airtable personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Okta
                CompiledPattern {
                    name: "Okta API Token".to_string(),
                    regex: Regex::new(r#"00[a-zA-Z0-9_-]{40}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Okta API token found - identity provider access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Auth0
                CompiledPattern {
                    name: "Auth0 Client Secret".to_string(),
                    regex: Regex::new(r#"(?i)auth0[_-]?client[_-]?secret\s*[=:]\s*['\"][a-zA-Z0-9_-]{32,}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Auth0 client secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Pusher
                CompiledPattern {
                    name: "Pusher App Key".to_string(),
                    regex: Regex::new(r#"(?i)pusher[_-]?(?:app[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{20}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Pusher app key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // PGP Private Key
                CompiledPattern {
                    name: "PGP Private Key".to_string(),
                    regex: Regex::new(r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "PGP private key found".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                // SSH Private Key
                CompiledPattern {
                    name: "SSH Private Key (OpenSSH)".to_string(),
                    regex: Regex::new(r#"-----BEGIN OPENSSH PRIVATE KEY-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "OpenSSH private key found".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                CompiledPattern {
                    name: "SSH Private Key (DSA)".to_string(),
                    regex: Regex::new(r#"-----BEGIN DSA PRIVATE KEY-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "DSA private key found".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                CompiledPattern {
                    name: "SSH Private Key (EC)".to_string(),
                    regex: Regex::new(r#"-----BEGIN EC PRIVATE KEY-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "EC private key found".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                // Generic high-entropy secrets
                CompiledPattern {
                    name: "Hardcoded Basic Auth".to_string(),
                    regex: Regex::new(r#"(?i)authorization\s*[=:]\s*['\"]basic\s+[a-zA-Z0-9+/=]{20,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Hardcoded Basic authentication header found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // MongoDB Atlas
                CompiledPattern {
                    name: "MongoDB Atlas Connection String".to_string(),
                    regex: Regex::new(r#"mongodb\+srv://[^:]+:[^@]+@[a-zA-Z0-9.-]+\.mongodb\.net"#).unwrap(),
                    severity: Severity::Critical,
                    description: "MongoDB Atlas connection string with credentials found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Redis
                CompiledPattern {
                    name: "Redis URL with Password".to_string(),
                    regex: Regex::new(r#"redis://[^:]+:[^@]+@[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Redis connection URL with password found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // MySQL/PostgreSQL
                CompiledPattern {
                    name: "MySQL Connection String".to_string(),
                    regex: Regex::new(r#"mysql://[^:]+:[^@]+@[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "MySQL connection string with credentials found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "PostgreSQL Connection String".to_string(),
                    regex: Regex::new(r#"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "PostgreSQL connection string with credentials found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // RabbitMQ/AMQP
                CompiledPattern {
                    name: "AMQP Connection String".to_string(),
                    regex: Regex::new(r#"amqps?://[^:]+:[^@]+@[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "AMQP/RabbitMQ connection string with credentials found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Instagram
                CompiledPattern {
                    name: "Instagram Access Token".to_string(),
                    regex: Regex::new(r#"(?i)instagram[_-]?(?:access[_-]?)?token\s*[=:]\s*['\"][0-9]{5,}[.][a-zA-Z0-9_-]+['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Instagram access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Dropbox
                CompiledPattern {
                    name: "Dropbox Access Token".to_string(),
                    regex: Regex::new(r#"sl\.[a-zA-Z0-9_-]{130,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Dropbox access token found - allows file access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Dropbox App Secret".to_string(),
                    regex: Regex::new(r#"(?i)dropbox[_-]?(?:app[_-]?)?secret\s*[=:]\s*['\"][a-z0-9]{15}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Dropbox app secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Zoom
                CompiledPattern {
                    name: "Zoom JWT Token".to_string(),
                    regex: Regex::new(r#"(?i)zoom[_-]?(?:jwt[_-]?)?token\s*[=:]\s*['\"]eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Zoom JWT token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // CircleCI
                CompiledPattern {
                    name: "CircleCI API Token".to_string(),
                    regex: Regex::new(r#"(?i)circle[_-]?(?:ci[_-]?)?token\s*[=:]\s*['\"][a-f0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "CircleCI API token found - allows build access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Travis CI
                CompiledPattern {
                    name: "Travis CI Token".to_string(),
                    regex: Regex::new(r#"(?i)travis[_-]?(?:ci[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9_-]{22}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Travis CI token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Docker Hub
                CompiledPattern {
                    name: "Docker Hub Access Token".to_string(),
                    regex: Regex::new(r#"dckr_pat_[a-zA-Z0-9_-]{27}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Docker Hub personal access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Mailchimp
                CompiledPattern {
                    name: "Mailchimp API Key".to_string(),
                    regex: Regex::new(r#"[a-f0-9]{32}-us[0-9]{1,2}"#).unwrap(),
                    severity: Severity::High,
                    description: "Mailchimp API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // HubSpot
                CompiledPattern {
                    name: "HubSpot API Key".to_string(),
                    regex: Regex::new(r#"(?i)hubspot[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "HubSpot API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "HubSpot Private App Token".to_string(),
                    regex: Regex::new(r#"pat-[a-z]{2,3}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "HubSpot private app token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Zendesk
                CompiledPattern {
                    name: "Zendesk API Token".to_string(),
                    regex: Regex::new(r#"(?i)zendesk[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Zendesk API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Intercom
                CompiledPattern {
                    name: "Intercom Access Token".to_string(),
                    regex: Regex::new(r#"(?i)intercom[_-]?(?:access[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9=_-]{60,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Intercom access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Jira/Atlassian
                CompiledPattern {
                    name: "Atlassian API Token".to_string(),
                    regex: Regex::new(r#"(?i)atlassian[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9]{24}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Atlassian API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Trello
                CompiledPattern {
                    name: "Trello API Key".to_string(),
                    regex: Regex::new(r#"(?i)trello[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Trello API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Snyk
                CompiledPattern {
                    name: "Snyk API Token".to_string(),
                    regex: Regex::new(r#"(?i)snyk[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Snyk API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // LaunchDarkly
                CompiledPattern {
                    name: "LaunchDarkly SDK Key".to_string(),
                    regex: Regex::new(r#"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#).unwrap(),
                    severity: Severity::High,
                    description: "LaunchDarkly SDK key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "LaunchDarkly API Key".to_string(),
                    regex: Regex::new(r#"api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "LaunchDarkly API key found - full access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Bugsnag
                CompiledPattern {
                    name: "Bugsnag API Key".to_string(),
                    regex: Regex::new(r#"(?i)bugsnag[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Bugsnag API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Rollbar
                CompiledPattern {
                    name: "Rollbar Access Token".to_string(),
                    regex: Regex::new(r#"(?i)rollbar[_-]?(?:access[_-]?)?token\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Rollbar access token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Vonage/Nexmo
                CompiledPattern {
                    name: "Vonage/Nexmo API Secret".to_string(),
                    regex: Regex::new(r#"(?i)(?:nexmo|vonage)[_-]?(?:api[_-]?)?secret\s*[=:]\s*['\"][a-zA-Z0-9]{16}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Vonage/Nexmo API secret found - allows SMS/voice access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // MessageBird
                CompiledPattern {
                    name: "MessageBird API Key".to_string(),
                    regex: Regex::new(r#"(?i)messagebird[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-zA-Z0-9]{25}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "MessageBird API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Plivo
                CompiledPattern {
                    name: "Plivo Auth Token".to_string(),
                    regex: Regex::new(r#"(?i)plivo[_-]?(?:auth[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9]{40}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Plivo auth token found - allows SMS/voice access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // URL with embedded credentials (e.g., Elasticsearch, MongoDB, Redis)
                // Must match: https://user:pass@host or http://user:pass@host:port
                // Key: The @ symbol MUST be present and password comes BEFORE @
                // Example: https://admin:secret123@elastic.example.com:9200
                CompiledPattern {
                    name: "URL with Embedded Credentials".to_string(),
                    // Pattern breakdown:
                    // - https?:// - protocol
                    // - [a-zA-Z0-9_][a-zA-Z0-9_-]* - username (starts with alphanumeric)
                    // - : - separator between user and pass
                    // - [^@\s'"<>]+ - password (anything except @ and whitespace, at least 1 char)
                    // - @ - REQUIRED separator (this is key - regular URLs don't have this)
                    // - [a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,} - hostname with TLD
                    regex: Regex::new(r#"https?://[a-zA-Z0-9_][a-zA-Z0-9_-]*:[^@\s'"<>]+@[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s'"<>]*)?"#).unwrap(),
                    severity: Severity::Critical,
                    description: "URL with embedded credentials found (e.g., https://user:pass@host)".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Dynatrace
                CompiledPattern {
                    name: "Dynatrace API Token".to_string(),
                    regex: Regex::new(r#"dt0c01\.[a-zA-Z0-9]{24}\.[a-f0-9]{64}"#).unwrap(),
                    severity: Severity::High,
                    description: "Dynatrace API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Grafana
                CompiledPattern {
                    name: "Grafana API Key".to_string(),
                    regex: Regex::new(r#"eyJrIjoi[a-zA-Z0-9_-]+['\"]?"#).unwrap(),
                    severity: Severity::High,
                    description: "Grafana API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Grafana Cloud API Token".to_string(),
                    regex: Regex::new(r#"glc_[a-zA-Z0-9_-]{32,}"#).unwrap(),
                    severity: Severity::High,
                    description: "Grafana Cloud API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Pulumi
                CompiledPattern {
                    name: "Pulumi Access Token".to_string(),
                    regex: Regex::new(r#"pul-[a-f0-9]{40}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Pulumi access token found - infrastructure access".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // HashiCorp
                CompiledPattern {
                    name: "HashiCorp Vault Token".to_string(),
                    regex: Regex::new(r#"hvs\.[a-zA-Z0-9_-]{24,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "HashiCorp Vault service token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "HashiCorp Terraform Cloud Token".to_string(),
                    regex: Regex::new(r#"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Terraform Cloud API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Buildkite
                CompiledPattern {
                    name: "Buildkite Agent Token".to_string(),
                    regex: Regex::new(r#"bkua_[a-f0-9]{40}"#).unwrap(),
                    severity: Severity::High,
                    description: "Buildkite agent token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Codecov
                CompiledPattern {
                    name: "Codecov Token".to_string(),
                    regex: Regex::new(r#"(?i)codecov[_-]?token\s*[=:]\s*['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Codecov upload token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Twitch
                CompiledPattern {
                    name: "Twitch OAuth Token".to_string(),
                    regex: Regex::new(r#"(?i)twitch[_-]?(?:oauth[_-]?)?token\s*[=:]\s*['\"][a-z0-9]{30}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Twitch OAuth token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // LinkedIn
                CompiledPattern {
                    name: "LinkedIn Client Secret".to_string(),
                    regex: Regex::new(r#"(?i)linkedin[_-]?(?:client[_-]?)?secret\s*[=:]\s*['\"][a-zA-Z0-9]{16}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "LinkedIn client secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Spotify
                CompiledPattern {
                    name: "Spotify Client Secret".to_string(),
                    regex: Regex::new(r#"(?i)spotify[_-]?(?:client[_-]?)?secret\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Spotify client secret found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Rapid API
                CompiledPattern {
                    name: "RapidAPI Key".to_string(),
                    regex: Regex::new(r#"(?i)(?:rapid|x-rapidapi)[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{50}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "RapidAPI key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Clarifai
                CompiledPattern {
                    name: "Clarifai API Key".to_string(),
                    regex: Regex::new(r#"(?i)clarifai[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Clarifai API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // IBM Watson
                CompiledPattern {
                    name: "IBM Cloud API Key".to_string(),
                    regex: Regex::new(r#"(?i)ibm[_-]?(?:cloud[_-]?)?(?:api[_-]?)?key\s*[=:]\s*['\"][a-zA-Z0-9_-]{44}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "IBM Cloud API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Yandex
                CompiledPattern {
                    name: "Yandex API Key".to_string(),
                    regex: Regex::new(r#"(?i)yandex[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]AQVN[a-zA-Z0-9_-]{35,}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Yandex API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // GCP Service Account
                CompiledPattern {
                    name: "GCP Service Account Key".to_string(),
                    regex: Regex::new(r#"\"private_key\":\s*\"-----BEGIN PRIVATE KEY-----"#).unwrap(),
                    severity: Severity::Critical,
                    description: "GCP service account private key found".to_string(),
                    cwe: "CWE-321".to_string(),
                },
                // Fastly
                CompiledPattern {
                    name: "Fastly API Key".to_string(),
                    regex: Regex::new(r#"(?i)fastly[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-zA-Z0-9_-]{32}['\"]"#).unwrap(),
                    severity: Severity::High,
                    description: "Fastly API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                // Cloudflare
                CompiledPattern {
                    name: "Cloudflare API Key".to_string(),
                    regex: Regex::new(r#"(?i)cloudflare[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"][a-f0-9]{37}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Cloudflare API key found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
                CompiledPattern {
                    name: "Cloudflare API Token".to_string(),
                    regex: Regex::new(r#"(?i)cloudflare[_-]?(?:api[_-]?)?token\s*[=:]\s*['\"][a-zA-Z0-9_-]{40}['\"]"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Cloudflare API token found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
            ],
            employee_patterns: vec![
                CompiledPattern {
                    name: "Corporate Email Pattern".to_string(),
                    regex: Regex::new(r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|fi|de|uk|io|co)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Corporate email address found - enables discovery of employee email list/patterns".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Email List/Array".to_string(),
                    // Matches arrays of emails like ["john@company.com", "jane@company.com"]
                    regex: Regex::new(r#"\[\s*["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["']\s*(?:,\s*["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["']\s*)+"#).unwrap(),
                    severity: Severity::High,
                    description: "Employee email list found in JavaScript - exposes organizational structure and enables targeted attacks".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Admin/Support Email".to_string(),
                    regex: Regex::new(r#"(?i)(admin|support|help|info|contact|sales|hr|finance|it|dev|ops|security)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Administrative/departmental email found - reveals internal organization".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Email Domain Pattern".to_string(),
                    // Matches email domain configuration like emailDomain: "company.com"
                    regex: Regex::new(r#"(?i)(email[_-]?domain|allowed[_-]?domain|corporate[_-]?domain)\s*[=:]\s*["']@?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["']"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Email domain configuration found - reveals corporate email pattern".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Employee Object".to_string(),
                    // Matches employee objects like {email: "...", name: "..."}
                    regex: Regex::new(r#"\{\s*(?:["']?(?:email|mail)["']?\s*:\s*["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["'])"#).unwrap(),
                    severity: Severity::High,
                    description: "Employee data object found in JavaScript".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Team/Department List".to_string(),
                    regex: Regex::new(r#"(?i)(team|department|staff|employees?|members?)\s*[=:]\s*\[[\s\S]*?@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#).unwrap(),
                    severity: Severity::High,
                    description: "Team/department member list found - enables organizational reconnaissance".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Slack User/Channel".to_string(),
                    regex: Regex::new(r#"<@[A-Z0-9]+>|<#[A-Z0-9]+\|[a-zA-Z0-9_-]+>"#).unwrap(),
                    severity: Severity::Low,
                    description: "Slack user/channel reference found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Internal Phone Extension".to_string(),
                    regex: Regex::new(r#"(?i)ext(?:ension)?\.?\s*\d{3,5}"#).unwrap(),
                    severity: Severity::Low,
                    description: "Internal phone extension found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Employee ID Pattern".to_string(),
                    regex: Regex::new(r#"(?i)(employee[_-]?id|emp[_-]?id|staff[_-]?id|worker[_-]?id)\s*[=:]\s*["']?[A-Z0-9]{4,12}["']?"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Employee ID pattern found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Organization Chart Data".to_string(),
                    regex: Regex::new(r#"(?i)(org[_-]?chart|hierarchy|reports[_-]?to|manager|supervisor)\s*[=:]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Organizational hierarchy data found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Active Directory/LDAP Reference".to_string(),
                    // Must be in LDAP context - look for actual LDAP URLs or complete DN patterns
                    // IMPORTANT: Do NOT match standalone OU=, CN=, DC= as these appear in minified JS (e.g., oU=!0)
                    // Only match:
                    // 1. Complete LDAP URLs: ldap://...
                    // 2. Complete DN with multiple components: CN=value,DC=value or OU=value,DC=value
                    // 3. Explicit "active_directory" or "active-directory" strings
                    regex: Regex::new(r#"(?i)(?:ldap://[a-zA-Z0-9\.\-]+(?::\d+)?(?:/[^\s\"'<>]*)?|active[_-]directory\b|(?:CN|OU)=[a-zA-Z][a-zA-Z0-9_\- ]{2,},\s*(?:DC|OU|CN)=[a-zA-Z][a-zA-Z0-9_\- ]+)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Active Directory/LDAP reference found - reveals internal identity infrastructure".to_string(),
                    cwe: "CWE-200".to_string(),
                },
            ],
            environment_patterns: vec![
                CompiledPattern {
                    name: "Staging/Dev URL".to_string(),
                    regex: Regex::new(r#"https?://(?:staging|dev|test|qa|uat|preprod|sandbox)\.[a-zA-Z0-9\-]+\.[a-zA-Z]+[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Staging/development environment URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Internal IP Address".to_string(),
                    regex: Regex::new(r#"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Internal IP address found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Localhost Reference".to_string(),
                    regex: Regex::new(r#"https?://(?:localhost|127\.0\.0\.1):\d+"#).unwrap(),
                    severity: Severity::Low,
                    description: "Localhost URL found - may indicate debug code".to_string(),
                    cwe: "CWE-489".to_string(),
                },
                CompiledPattern {
                    name: "Environment Variable Reference".to_string(),
                    regex: Regex::new(r#"process\.env\.(?:SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE)"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Reference to sensitive environment variable".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Database Connection String".to_string(),
                    regex: Regex::new(r#"(?:mongodb|mysql|postgres|postgresql|redis|amqp)://[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Critical,
                    description: "Database connection string found".to_string(),
                    cwe: "CWE-798".to_string(),
                },
            ],
            analytics_patterns: vec![
                CompiledPattern {
                    name: "PowerBI Embed URL".to_string(),
                    regex: Regex::new(r#"https://app\.powerbi\.com/[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "PowerBI dashboard URL found - may expose business analytics".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "PowerBI Report ID".to_string(),
                    regex: Regex::new(r#"(?i)reportId\s*[=:]\s*['\"][a-f0-9\-]{36}['\"]"#).unwrap(),
                    severity: Severity::Medium,
                    description: "PowerBI report ID found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Tableau URL".to_string(),
                    regex: Regex::new(r#"https://[a-zA-Z0-9\-]+\.tableau(?:software)?\.com[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Tableau analytics URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Looker URL".to_string(),
                    regex: Regex::new(r#"https://[a-zA-Z0-9\-]+\.looker\.com[^\s\"'<>]*"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Looker analytics URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Datadog Dashboard".to_string(),
                    regex: Regex::new(r#"https://app\.datadoghq\.com/[^\s\"'<>]+"#).unwrap(),
                    severity: Severity::Medium,
                    description: "Datadog dashboard URL found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Mixpanel Project".to_string(),
                    regex: Regex::new(r#"(?i)mixpanel\.init\s*\(\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Low,
                    description: "Mixpanel project token found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Amplitude API Key".to_string(),
                    regex: Regex::new(r#"(?i)amplitude\.init\s*\(\s*['\"][a-f0-9]{32}['\"]"#).unwrap(),
                    severity: Severity::Low,
                    description: "Amplitude API key found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
                CompiledPattern {
                    name: "Segment Write Key".to_string(),
                    regex: Regex::new(r#"(?i)analytics\.load\s*\(\s*['\"][a-zA-Z0-9]{22,}['\"]"#).unwrap(),
                    severity: Severity::Low,
                    description: "Segment write key found".to_string(),
                    cwe: "CWE-200".to_string(),
                },
            ],
        }
    }

    /// Scan for sensitive information leakage in JavaScript
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Scanning for JavaScript sensitive information leakage");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let mut all_matches: Vec<SensitiveMatch> = Vec::new();

        // Get the main page
        tests_run += 1;
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((vulnerabilities, tests_run)),
        };

        // Scan the main page content
        let page_matches = self.scan_content(&response.body, "Main page");
        all_matches.extend(page_matches);

        // Extract and scan JavaScript files
        let js_urls = self.extract_js_urls(&response.body, url);
        info!("Found {} JavaScript files to scan", js_urls.len());

        // Limit JS files in fast mode
        let js_limit = if config.scan_mode.as_str() == "fast" { 5 } else { 20 };

        for js_url in js_urls.iter().take(js_limit) {
            tests_run += 1;
            if let Ok(js_response) = self.http_client.get(js_url).await {
                let js_matches = self.scan_content(&js_response.body, js_url);
                all_matches.extend(js_matches);
            }
        }

        // Group matches by category and severity
        let grouped = self.group_matches(&all_matches);

        // Create vulnerabilities from grouped matches
        for (category, matches) in grouped {
            if matches.is_empty() {
                continue;
            }

            // Determine overall severity (highest among matches)
            let max_severity = matches.iter()
                .map(|m| &m.severity)
                .max_by_key(|s| match s {
                    Severity::Critical => 4,
                    Severity::High => 3,
                    Severity::Medium => 2,
                    Severity::Low => 1,
                    Severity::Info => 0,
                })
                .cloned()
                .unwrap_or(Severity::Low);

            // Build evidence
            let evidence = matches.iter()
                .take(10)  // Limit evidence items
                .map(|m| format!(
                    "- {} (line {}): {}\n  Context: {}",
                    m.pattern_name,
                    m.line_number,
                    Self::truncate(&m.matched_value, 100),
                    Self::truncate(&m.context, 150)
                ))
                .collect::<Vec<_>>()
                .join("\n\n");

            let additional = if matches.len() > 10 {
                format!("\n\n... and {} more instances", matches.len() - 10)
            } else {
                String::new()
            };

            // Get CWE from first match
            let cwe = matches.first().map(|m| m.cwe.clone()).unwrap_or_else(|| "CWE-200".to_string());

            let cvss = match max_severity {
                Severity::Critical => 9.0,
                Severity::High => 7.5,
                Severity::Medium => 5.3,
                Severity::Low => 3.1,
                Severity::Info => 0.0,
            };

            vulnerabilities.push(Vulnerability {
                id: format!("js_sensitive_{}_{}", category.to_lowercase().replace(" ", "_"), Self::generate_id()),
                vuln_type: format!("JavaScript Sensitive Information - {}", category),
                severity: max_severity,
                confidence: Confidence::High,
                category: "Information Disclosure".to_string(),
                url: url.to_string(),
                parameter: None,
                payload: format!("{} instances found", matches.len()),
                description: format!(
                    "Found {} instances of potentially sensitive {} information in JavaScript code. \
                    This information may be useful to attackers for reconnaissance or direct exploitation.",
                    matches.len(),
                    category
                ),
                evidence: Some(format!("{}{}", evidence, additional)),
                cwe,
                cvss,
                verified: true,
                false_positive: false,
                remediation: self.get_remediation_for_category(&category),
                discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
            });
        }

        // Fast mode: stop after finding vulnerabilities
        if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
            return Ok((vulnerabilities, tests_run));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan content for sensitive patterns
    fn scan_content(&self, content: &str, source: &str) -> Vec<SensitiveMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Skip very large files (likely minified/bundled)
        if content.len() > 5_000_000 {
            debug!("Skipping very large file: {}", source);
            return matches;
        }

        // Scan each category of patterns
        self.scan_patterns(&self.patterns.credential_patterns, content, &lines, source, "Credentials", &mut matches);
        self.scan_patterns(&self.patterns.admin_debug_patterns, content, &lines, source, "Admin/Debug", &mut matches);
        self.scan_patterns(&self.patterns.jira_patterns, content, &lines, source, "Issue Tracking", &mut matches);
        self.scan_patterns(&self.patterns.internal_tools, content, &lines, source, "Internal Tools", &mut matches);
        self.scan_patterns(&self.patterns.document_patterns, content, &lines, source, "Documents", &mut matches);
        self.scan_patterns(&self.patterns.comment_patterns, content, &lines, source, "Comments", &mut matches);
        self.scan_patterns(&self.patterns.environment_patterns, content, &lines, source, "Environment", &mut matches);
        self.scan_patterns(&self.patterns.analytics_patterns, content, &lines, source, "Analytics", &mut matches);
        self.scan_patterns(&self.patterns.employee_patterns, content, &lines, source, "Employee Info", &mut matches);

        matches
    }

    /// Scan content with a set of patterns
    fn scan_patterns(
        &self,
        patterns: &[CompiledPattern],
        content: &str,
        lines: &[&str],
        source: &str,
        category: &str,
        matches: &mut Vec<SensitiveMatch>,
    ) {
        for pattern in patterns {
            for cap in pattern.regex.captures_iter(content) {
                let matched = cap.get(0).unwrap().as_str();

                // Skip false positives
                if self.is_false_positive(matched, &pattern.name, content) {
                    continue;
                }

                // Find line number
                let match_start = cap.get(0).unwrap().start();
                let line_number = content[..match_start].matches('\n').count() + 1;

                // Get context
                let context = if line_number <= lines.len() {
                    lines[line_number - 1].to_string()
                } else {
                    String::new()
                };

                matches.push(SensitiveMatch {
                    pattern_name: pattern.name.clone(),
                    matched_value: matched.to_string(),
                    context: format!("{}: {}", source, context),
                    line_number,
                    severity: pattern.severity.clone(),
                    category: category.to_string(),
                    cwe: pattern.cwe.clone(),
                    description: pattern.description.clone(),
                });
            }
        }
    }

    /// Check if a match is likely a false positive
    fn is_false_positive(&self, matched: &str, pattern_name: &str, content: &str) -> bool {
        let matched_lower = matched.to_lowercase();

        // Generic API key - skip if it's a placeholder/example
        if pattern_name.contains("API Key") || pattern_name.contains("Secret") || pattern_name.contains("Password") {
            let placeholder_patterns = [
                "your_", "example", "xxx", "placeholder", "change_me", "insert_",
                "todo", "fixme", "replace", "dummy", "test_", "sample",
                "<your", "{your", "[your", "api_key_here", "secret_here",
            ];
            for p in placeholder_patterns {
                if matched_lower.contains(p) {
                    return true;
                }
            }
        }

        // Skip Jira patterns that are common CSS/JS/web false positives
        if pattern_name == "Jira Ticket Reference" {
            let matched_lower = matched.to_lowercase();
            let parts: Vec<&str> = matched.split('-').collect();

            if parts.len() == 2 {
                let prefix = parts[0].to_uppercase();
                let suffix = parts[1];

                // Skip if suffix is too short (< 2 digits) - likely CSS/JS patterns
                if suffix.len() < 2 {
                    return true;
                }

                // Skip common false positives like ISO codes, CSS classes, etc.
                let common_fp_prefixes = [
                    "UTF", "ISO", "ASCII", "EUC", // Character encodings
                    "CSS", "HTML", "SVG", "XML",   // Web standards
                    "RGB", "HSL", "HEX",           // Color formats
                    "GET", "POST", "PUT", "DELETE", // HTTP methods
                    "PNG", "JPG", "GIF", "WEBP",   // Image formats
                    "MP3", "MP4", "WAV", "AVI",    // Media formats
                    "NORTH", "SOUTH", "EAST", "WEST", // Directions
                    "TOP", "BOTTOM", "LEFT", "RIGHT", // Positions
                    "SCRIPT", "STYLE", "LINK",     // HTML tags
                    "INSET", "OUTSET",             // CSS values
                    "INDEX", "LENGTH", "LAST", "LASTINDEX", // JS properties
                    "PANOSE",                       // Font metadata
                    "SEC", "MIN", "MAX",           // Time/math abbreviations
                    "FI", "FL", "FF",              // Font ligatures
                    "ID", "REF", "KEY",            // Generic identifiers
                ];
                if common_fp_prefixes.iter().any(|fp| prefix == *fp) {
                    return true;
                }

                // Also check for common CSS/Tailwind patterns (case insensitive)
                let css_patterns = [
                    "col-", "row-", "flex-", "grid-", "gap-", "space-",
                    "text-", "font-", "bg-", "border-", "rounded-",
                    "px-", "py-", "pt-", "pb-", "pl-", "pr-", "mx-", "my-",
                    "w-", "h-", "min-", "max-", "z-", "top-", "left-", "right-", "bottom-",
                    "inset-", "opacity-", "scale-", "rotate-", "translate-",
                    "duration-", "delay-", "ease-", "transition-",
                    "sr-", "not-", "group-", "peer-", "focus-", "hover-",
                    "active-", "disabled-", "checked-", "first-", "last-",
                    "odd-", "even-", "xs-", "sm-", "md-", "lg-", "xl-",
                ];
                if css_patterns.iter().any(|p| matched_lower.starts_with(p)) {
                    return true;
                }

                // Skip common JS property patterns
                let js_patterns = [
                    "length-", "index-", "count-", "size-", "width-", "height-",
                    "offset-", "margin-", "padding-", "border-", "radius-",
                    "timeout-", "interval-", "delay-", "version-", "revision-",
                    "lastindex-", "script-", "style-", "class-", "data-",
                ];
                if js_patterns.iter().any(|p| matched_lower.starts_with(p)) {
                    return true;
                }
            }
        }

        // Skip email patterns that are examples or public contact emails
        if pattern_name.contains("Email") || pattern_name.contains("Corporate Email") {
            let example_domains = ["example.com", "example.org", "test.com", "localhost", "domain.com"];
            for domain in example_domains {
                if matched_lower.contains(domain) {
                    return true;
                }
            }
            // Skip public contact emails - these are intentionally public
            let public_prefixes = ["info@", "contact@", "support@", "help@", "sales@", "hello@",
                                   "press@", "media@", "feedback@", "enquiries@", "team@",
                                   "mail@", "office@", "admin@", "noreply@", "no-reply@"];
            for prefix in public_prefixes {
                if matched_lower.starts_with(prefix) {
                    return true;
                }
            }
        }

        // Skip localhost references in development-only contexts
        if pattern_name.contains("Localhost") {
            // Check if there's a conditional around it
            let pos = content.find(matched).unwrap_or(0);
            let context_start = pos.saturating_sub(100);
            let context = &content[context_start..pos.min(content.len())];
            if context.contains("isDev") || context.contains("isDebug") || context.contains("NODE_ENV") {
                return true;
            }
        }

        // Skip PDF patterns that are clearly public/intended
        if pattern_name.contains("PDF") {
            let public_paths = ["/public/", "/assets/", "/static/", "/docs/", "documentation"];
            for path in public_paths {
                if matched_lower.contains(path) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract JavaScript URLs from HTML
    fn extract_js_urls(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut urls = HashSet::new();

        // Pattern for script src
        let script_pattern = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();

        for cap in script_pattern.captures_iter(html) {
            if let Some(src) = cap.get(1) {
                let src_str = src.as_str();

                // Skip external CDNs we don't need to scan
                if src_str.contains("cdn") ||
                   src_str.contains("googleapis.com") ||
                   src_str.contains("cloudflare") ||
                   src_str.contains("unpkg.com") ||
                   src_str.contains("jsdelivr") {
                    continue;
                }

                let full_url = self.resolve_url(src_str, base_url);
                urls.insert(full_url);
            }
        }

        // Also look for dynamically loaded scripts
        let import_pattern = Regex::new(r#"import\s*\(\s*["']([^"']+\.js[^"']*)["']\s*\)"#).unwrap();
        for cap in import_pattern.captures_iter(html) {
            if let Some(path) = cap.get(1) {
                let full_url = self.resolve_url(path.as_str(), base_url);
                urls.insert(full_url);
            }
        }

        urls.into_iter().collect()
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, src: &str, base_url: &str) -> String {
        if src.starts_with("http://") || src.starts_with("https://") {
            return src.to_string();
        }

        if let Ok(base) = url::Url::parse(base_url) {
            if src.starts_with("//") {
                return format!("{}:{}", base.scheme(), src);
            }

            if let Ok(resolved) = base.join(src) {
                return resolved.to_string();
            }
        }

        // Fallback
        if src.starts_with('/') {
            if let Ok(parsed) = url::Url::parse(base_url) {
                let host = parsed.host_str().unwrap_or("localhost");
                let scheme = parsed.scheme();
                return format!("{}://{}{}", scheme, host, src);
            }
        }

        src.to_string()
    }

    /// Group matches by category
    fn group_matches<'a>(&self, matches: &'a [SensitiveMatch]) -> HashMap<String, Vec<&'a SensitiveMatch>> {
        let mut grouped: HashMap<String, Vec<&SensitiveMatch>> = HashMap::new();

        for m in matches {
            grouped.entry(m.category.clone()).or_default().push(m);
        }

        // Deduplicate by matched value within each category
        for (_, matches) in grouped.iter_mut() {
            let mut seen = HashSet::new();
            matches.retain(|m| seen.insert(m.matched_value.clone()));
        }

        grouped
    }

    /// Get remediation advice for a category
    fn get_remediation_for_category(&self, category: &str) -> String {
        match category {
            "Credentials" => "1. CRITICAL: Rotate all exposed credentials immediately\n\
                              2. Remove hardcoded secrets from source code\n\
                              3. Use environment variables or secret managers\n\
                              4. Implement proper secret scanning in CI/CD\n\
                              5. Review git history for exposed secrets".to_string(),
            "Admin/Debug" => "1. Remove debug flags and code before production deployment\n\
                              2. Use build-time environment checks to strip debug code\n\
                              3. Implement proper feature flags with server-side control\n\
                              4. Remove console.log statements with sensitive data\n\
                              5. Use production builds that strip development code".to_string(),
            "Issue Tracking" => "1. Remove internal issue tracker references from client code\n\
                                 2. Use generic error messages instead of ticket numbers\n\
                                 3. Implement server-side error logging with correlation IDs\n\
                                 4. Review what internal information is exposed".to_string(),
            "Internal Tools" => "1. Remove internal tool URLs from client-side code\n\
                                 2. Ensure internal tools require authentication\n\
                                 3. Use network segmentation to protect internal resources\n\
                                 4. Audit for webhook/integration URL exposure".to_string(),
            "Documents" => "1. Move sensitive documents behind authentication\n\
                            2. Remove internal document paths from client code\n\
                            3. Implement access controls on document servers\n\
                            4. Use pre-signed URLs with expiration for document access".to_string(),
            "Comments" => "1. Strip comments from production JavaScript builds\n\
                           2. Use minification/uglification in build process\n\
                           3. Review TODO/FIXME comments for sensitive information\n\
                           4. Implement code review process for comment content".to_string(),
            "Environment" => "1. Remove staging/dev URLs from production code\n\
                              2. Use environment-specific configuration\n\
                              3. Implement proper network isolation between environments\n\
                              4. Remove database connection strings from client code".to_string(),
            "Analytics" => "1. Review which analytics dashboards are referenced\n\
                            2. Ensure PowerBI/Tableau dashboards require authentication\n\
                            3. Use row-level security in BI tools\n\
                            4. Audit analytics data for sensitive information".to_string(),
            "Employee Info" => "1. Remove internal email addresses from client code\n\
                                2. Use role-based contact forms instead of direct emails\n\
                                3. Audit code for PII exposure\n\
                                4. Implement proper contact management".to_string(),
            _ => "1. Review and remove sensitive information from client-side code\n\
                  2. Implement proper access controls\n\
                  3. Use server-side processing for sensitive operations\n\
                  4. Conduct regular security audits".to_string(),
        }
    }

    /// Truncate string with ellipsis
    fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len])
        }
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jira_ticket_pattern() {
        // Pattern requires 3+ letter prefix and 2+ digit number to avoid CSS/JS false positives
        let pattern = Regex::new(r#"\b([A-Z]{3,10}-\d{2,6})\b"#).unwrap();

        assert!(pattern.is_match("PROJ-123"));
        assert!(pattern.is_match("SEC-12"));
        assert!(pattern.is_match("MYPROJECT-99999"));
        assert!(!pattern.is_match("A-1")); // Too short prefix
        assert!(!pattern.is_match("FI-2")); // Too short prefix (CSS false positive)
        assert!(!pattern.is_match("NORTH-1")); // Single digit (CSS false positive)
        assert!(!pattern.is_match("inset-0")); // CSS value
    }

    #[test]
    fn test_aws_key_pattern() {
        let pattern = Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap();

        assert!(pattern.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!pattern.is_match("AKIA123")); // Too short
    }

    #[test]
    fn test_jwt_pattern() {
        let pattern = Regex::new(r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"#).unwrap();

        // Example JWT (not real)
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(pattern.is_match(jwt));
    }

    #[test]
    fn test_powerbi_pattern() {
        let pattern = Regex::new(r#"https://app\.powerbi\.com/[^\s\"'<>]+"#).unwrap();

        assert!(pattern.is_match("https://app.powerbi.com/groups/abc123/reports/xyz789"));
    }

    #[test]
    fn test_is_dev_pattern() {
        let pattern = Regex::new(r#"(?i)(isDev|isDebug|isTest|debugMode|devMode|testMode)\s*[=:]\s*(true|1|!0)"#).unwrap();

        assert!(pattern.is_match("isDev = true"));
        assert!(pattern.is_match("isDebug: true"));
        assert!(pattern.is_match("testMode = 1"));
        assert!(pattern.is_match("debugMode: !0"));
    }
}
