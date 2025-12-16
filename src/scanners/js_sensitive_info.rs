// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - JavaScript Sensitive Information Leakage Scanner
 * Analyzes JavaScript files for leaked sensitive information
 *
 * Detects:
 * - Jira links and ticket references
 * - Internal URLs and endpoints
 * - PDF and document file paths
 * - Admin logic and debug functions
 * - Sensitive comments (TODO, FIXME, HACK, passwords, etc.)
 * - isDev/isDebug/isTest flags
 * - PowerBI and analytics links
 * - Hardcoded credentials and API keys
 * - Employee names and emails
 * - Internal tool references (Confluence, Slack, etc.)
 * - Development/staging environment URLs
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

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
                    regex: Regex::new(r#"(?i)\b([A-Z]{2,10}-\d{1,6})\b"#).unwrap(),
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
                    regex: Regex::new(r#"(?i)(ldap|active[_-]?directory|ad[_-]?user|cn=|dc=|ou=)[^\s\"'<>]+"#).unwrap(),
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

        // Skip Jira patterns that are too generic (2-3 letter projects with low numbers)
        if pattern_name == "Jira Ticket Reference" {
            let parts: Vec<&str> = matched.split('-').collect();
            if parts.len() == 2 {
                // Skip common false positives like ISO codes, etc.
                let common_fp = ["UTF-8", "ISO-8859", "US-ASCII", "GB-2312", "EUC-KR"];
                if common_fp.iter().any(|fp| matched.eq_ignore_ascii_case(fp)) {
                    return true;
                }
            }
        }

        // Skip email patterns that are examples
        if pattern_name.contains("Email") {
            let example_domains = ["example.com", "example.org", "test.com", "localhost", "domain.com"];
            for domain in example_domains {
                if matched_lower.contains(domain) {
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
    fn group_matches(&self, matches: &[SensitiveMatch]) -> HashMap<String, Vec<&SensitiveMatch>> {
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
        let pattern = Regex::new(r#"(?i)\b([A-Z]{2,10}-\d{1,6})\b"#).unwrap();

        assert!(pattern.is_match("PROJ-123"));
        assert!(pattern.is_match("SEC-1"));
        assert!(pattern.is_match("MYPROJECT-99999"));
        assert!(!pattern.is_match("A-1")); // Too short prefix
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
