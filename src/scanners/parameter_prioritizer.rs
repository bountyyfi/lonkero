// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Parameter Prioritizer Module
//!
//! Risk-based parameter scoring system that analyzes parameters to determine
//! vulnerability likelihood. High-risk parameters get tested first and more thoroughly.
//!
//! Features:
//! - Smart name matching (case-insensitive, handles variations like user_id, userId, user-id)
//! - Contextual bonuses (login forms, payment forms, admin areas)
//! - Scanner suggestions based on risk factors
//! - Comprehensive list of dangerous parameter names
//!
//! @copyright 2026 Bountyy Oy
//! @license Proprietary

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============================================================================
// CONSTANTS - Comprehensive lists of dangerous parameter names
// ============================================================================

/// Authentication-related parameter patterns (weight: 25 points)
const AUTH_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "token",
    "auth",
    "session",
    "sessionid",
    "session_id",
    "sessid",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "accesstoken",
    "access-token",
    "refresh_token",
    "refreshtoken",
    "refresh-token",
    "bearer",
    "jwt",
    "oauth",
    "oauth_token",
    "oauthtoken",
    "credentials",
    "credential",
    "login",
    "signin",
    "sign_in",
    "private_key",
    "privatekey",
    "private-key",
    "secret_key",
    "secretkey",
    "secret-key",
    "auth_token",
    "authtoken",
    "auth-token",
    "cookie",
    "remember",
    "remember_me",
    "rememberme",
    "keep_logged",
    "keeplogged",
    "persistent",
];

/// ID parameter patterns for IDOR vulnerabilities (weight: 22 points)
const ID_PATTERNS: &[&str] = &[
    "id",
    "user_id",
    "userid",
    "user-id",
    "account_id",
    "accountid",
    "account-id",
    "order_id",
    "orderid",
    "order-id",
    "customer_id",
    "customerid",
    "customer-id",
    "profile_id",
    "profileid",
    "profile-id",
    "doc_id",
    "docid",
    "doc-id",
    "document_id",
    "documentid",
    "document-id",
    "invoice_id",
    "invoiceid",
    "invoice-id",
    "transaction_id",
    "transactionid",
    "transaction-id",
    "payment_id",
    "paymentid",
    "payment-id",
    "record_id",
    "recordid",
    "record-id",
    "item_id",
    "itemid",
    "item-id",
    "product_id",
    "productid",
    "product-id",
    "object_id",
    "objectid",
    "object-id",
    "entity_id",
    "entityid",
    "entity-id",
    "ref",
    "reference",
    "ref_id",
    "refid",
    "ref-id",
    "uid",
    "uuid",
    "guid",
    "oid",
    "pid",
    "cid",
    "tid",
    "sid",
    "fid",
    "rid",
    "aid",
    "bid",
    "did",
];

/// File/path parameter patterns for LFI/Path Traversal (weight: 23 points)
const FILE_PATTERNS: &[&str] = &[
    "file",
    "filename",
    "file_name",
    "file-name",
    "filepath",
    "file_path",
    "file-path",
    "path",
    "pathname",
    "path_name",
    "path-name",
    "document",
    "doc",
    "upload",
    "download",
    "attachment",
    "attach",
    "template",
    "include",
    "require",
    "load",
    "read",
    "open",
    "view",
    "show",
    "display",
    "image",
    "img",
    "photo",
    "picture",
    "avatar",
    "icon",
    "logo",
    "banner",
    "pdf",
    "csv",
    "xml",
    "json",
    "config",
    "conf",
    "cfg",
    "log",
    "logs",
    "backup",
    "bak",
    "tmp",
    "temp",
    "cache",
    "resource",
    "asset",
    "media",
    "folder",
    "dir",
    "directory",
    "location",
    "source",
    "src",
    "dest",
    "destination",
    "target",
    "output",
    "input",
    "data",
    "content",
];

/// URL/redirect parameter patterns for SSRF/Open Redirect (weight: 24 points)
const URL_PATTERNS: &[&str] = &[
    "url",
    "uri",
    "link",
    "href",
    "src",
    "source",
    "redirect",
    "redirect_url",
    "redirecturl",
    "redirect-url",
    "redirect_uri",
    "redirecturi",
    "redirect-uri",
    "next",
    "next_url",
    "nexturl",
    "next-url",
    "return",
    "return_url",
    "returnurl",
    "return-url",
    "return_to",
    "returnto",
    "return-to",
    "callback",
    "callback_url",
    "callbackurl",
    "callback-uri",
    "goto",
    "go",
    "target",
    "dest",
    "destination",
    "continue",
    "continue_url",
    "continueurl",
    "continue-url",
    "forward",
    "forward_url",
    "forwardurl",
    "forward-url",
    "redir",
    "out",
    "outbound",
    "external",
    "external_url",
    "externalurl",
    "external-url",
    "site",
    "website",
    "domain",
    "host",
    "proxy",
    "proxy_url",
    "proxyurl",
    "proxy-url",
    "fetch",
    "load",
    "image_url",
    "imageurl",
    "image-url",
    "img_url",
    "imgurl",
    "img-url",
    "preview",
    "preview_url",
    "previewurl",
    "preview-url",
    "webhook",
    "webhook_url",
    "webhookurl",
    "webhook-url",
    "endpoint",
    "api",
    "api_url",
    "apiurl",
    "api-url",
    "service",
    "service_url",
    "serviceurl",
    "service-url",
];

/// Command/execution parameter patterns (weight: 30 points - highest risk)
const COMMAND_PATTERNS: &[&str] = &[
    "cmd",
    "command",
    "exec",
    "execute",
    "run",
    "shell",
    "bash",
    "sh",
    "powershell",
    "ps",
    "terminal",
    "console",
    "cli",
    "script",
    "code",
    "eval",
    "expression",
    "expr",
    "query",
    "sql",
    "system",
    "syscall",
    "process",
    "spawn",
    "fork",
    "popen",
    "subprocess",
    "pipe",
    "program",
    "binary",
    "executable",
    "action",
    "operation",
    "task",
    "job",
    "func",
    "function",
    "method",
    "call",
    "invoke",
    "trigger",
    "handler",
    "processor",
    "worker",
    "daemon",
    "service",
];

/// Email parameter patterns (weight: 12 points)
const EMAIL_PATTERNS: &[&str] = &[
    "email",
    "e-mail",
    "mail",
    "emailaddress",
    "email_address",
    "email-address",
    "user_email",
    "useremail",
    "user-email",
    "contact_email",
    "contactemail",
    "contact-email",
    "from",
    "to",
    "cc",
    "bcc",
    "recipient",
    "sender",
    "reply_to",
    "replyto",
    "reply-to",
    "notify",
    "notification",
];

/// Search/query parameter patterns (weight: 13 points)
const SEARCH_PATTERNS: &[&str] = &[
    "q",
    "query",
    "search",
    "keyword",
    "keywords",
    "term",
    "terms",
    "find",
    "filter",
    "filters",
    "where",
    "condition",
    "criteria",
    "lookup",
    "seek",
    "match",
    "pattern",
    "regex",
    "regexp",
    "expression",
    "text",
    "fulltext",
    "fts",
    "searchterm",
    "search_term",
    "search-term",
    "searchquery",
    "search_query",
    "search-query",
    "s",
    "k",
    "kw",
];

/// Admin/privilege parameter patterns (weight: 15 points)
const ADMIN_PATTERNS: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "superuser",
    "super_user",
    "super-user",
    "role",
    "roles",
    "privilege",
    "privileges",
    "permission",
    "permissions",
    "access",
    "access_level",
    "accesslevel",
    "access-level",
    "level",
    "tier",
    "group",
    "groups",
    "rights",
    "grant",
    "grants",
    "scope",
    "scopes",
    "authority",
    "authorities",
    "power",
    "powers",
    "capability",
    "capabilities",
    "is_admin",
    "isadmin",
    "is-admin",
    "is_superuser",
    "issuperuser",
    "is-superuser",
    "is_root",
    "isroot",
    "is-root",
    "elevated",
    "sudo",
    "system",
];

/// Debug/test parameter patterns (weight: 12 points)
const DEBUG_PATTERNS: &[&str] = &[
    "debug",
    "test",
    "testing",
    "dev",
    "development",
    "verbose",
    "trace",
    "log",
    "logging",
    "loglevel",
    "log_level",
    "log-level",
    "mode",
    "env",
    "environment",
    "stage",
    "staging",
    "sandbox",
    "demo",
    "preview",
    "beta",
    "alpha",
    "internal",
    "hidden",
    "secret",
    "backdoor",
    "bypass",
    "skip",
    "override",
    "force",
    "unsafe",
    "insecure",
    "disable",
    "disabled",
    "enable",
    "enabled",
    "flag",
    "flags",
    "feature",
    "features",
    "experiment",
];

/// Pagination parameter patterns (weight: 5 points)
const PAGINATION_PATTERNS: &[&str] = &[
    "page",
    "pages",
    "paging",
    "p",
    "pg",
    "limit",
    "max",
    "maximum",
    "count",
    "size",
    "pagesize",
    "page_size",
    "page-size",
    "perpage",
    "per_page",
    "per-page",
    "offset",
    "start",
    "from",
    "skip",
    "cursor",
    "after",
    "before",
    "next",
    "prev",
    "previous",
    "first",
    "last",
    "top",
    "take",
    "batch",
    "chunk",
];

/// Sort parameter patterns (weight: 5 points)
const SORT_PATTERNS: &[&str] = &[
    "sort",
    "sortby",
    "sort_by",
    "sort-by",
    "order",
    "orderby",
    "order_by",
    "order-by",
    "ordering",
    "direction",
    "dir",
    "asc",
    "desc",
    "ascending",
    "descending",
    "arrange",
    "rank",
    "ranking",
    "priority",
];

/// Filter parameter patterns (weight: 5 points)
const FILTER_PATTERNS: &[&str] = &[
    "filter",
    "filters",
    "status",
    "state",
    "type",
    "types",
    "category",
    "categories",
    "cat",
    "tag",
    "tags",
    "label",
    "labels",
    "class",
    "classes",
    "kind",
    "kinds",
    "variant",
    "variants",
    "version",
    "versions",
    "format",
    "formats",
    "style",
    "styles",
    "theme",
    "themes",
    "view",
    "views",
];

// ============================================================================
// TYPES AND STRUCTS
// ============================================================================

/// Scanner types that can be suggested based on parameter risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScannerType {
    SQLi,
    XSS,
    IDOR,
    SSRF,
    OpenRedirect,
    PathTraversal,
    LFI,
    RFI,
    CommandInjection,
    XXE,
    NoSQL,
    LDAP,
    TemplateInjection,
    CodeInjection,
    HeaderInjection,
    EmailInjection,
    AuthBypass,
    SessionFixation,
    CSRF,
    MassAssignment,
    RaceCondition,
    BusinessLogic,
}

/// Risk factors that contribute to a parameter's risk score
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskFactor {
    // High risk (20+ points each)
    /// Password, token, auth, session, api_key related
    AuthRelated,
    /// id, user_id, account_id, order_id (IDOR risk)
    IdParameter,
    /// file, path, filename, document, upload
    FileParameter,
    /// url, redirect, next, return, callback (SSRF/redirect)
    UrlParameter,
    /// cmd, command, exec, run, shell
    CommandParameter,

    // Medium risk (10-15 points each)
    /// email (enumeration, injection)
    EmailParameter,
    /// q, query, search, keyword (XSS, SQLi)
    SearchParameter,
    /// admin, role, privilege, permission
    AdminIndicator,
    /// debug, test, dev, verbose
    DebugParameter,

    // Lower risk (5 points each)
    /// page, limit, offset, size
    PaginationParameter,
    /// sort, order, orderby
    SortParameter,
    /// filter, status, type, category
    FilterParameter,

    // Context bonuses
    /// +15 if parameter is in a login form
    InLoginForm,
    /// +20 if parameter is in payment/checkout
    InPaymentForm,
    /// +15 if URL contains /admin/, /dashboard/
    InAdminArea,
    /// +5 for potential SQLi/IDOR
    HasNumericValue,
    /// +10 for text/textarea vs hidden/select
    AcceptsUserInput,
    /// +8 for parameters ending with common ID suffixes
    HasIdSuffix,
    /// +7 for parameters containing sensitive keywords
    ContainsSensitiveKeyword,
}

impl RiskFactor {
    /// Returns the base weight for this risk factor
    pub fn weight(&self) -> u8 {
        match self {
            // High risk factors
            RiskFactor::CommandParameter => 30,
            RiskFactor::AuthRelated => 25,
            RiskFactor::UrlParameter => 24,
            RiskFactor::FileParameter => 23,
            RiskFactor::IdParameter => 22,

            // Medium risk factors
            RiskFactor::AdminIndicator => 15,
            RiskFactor::SearchParameter => 13,
            RiskFactor::EmailParameter => 12,
            RiskFactor::DebugParameter => 12,

            // Lower risk factors
            RiskFactor::PaginationParameter => 5,
            RiskFactor::SortParameter => 5,
            RiskFactor::FilterParameter => 5,

            // Context bonuses
            RiskFactor::InPaymentForm => 20,
            RiskFactor::InLoginForm => 15,
            RiskFactor::InAdminArea => 15,
            RiskFactor::AcceptsUserInput => 10,
            RiskFactor::ContainsSensitiveKeyword => 7,
            RiskFactor::HasIdSuffix => 8,
            RiskFactor::HasNumericValue => 5,
        }
    }

    /// Returns a description of this risk factor
    pub fn description(&self) -> &'static str {
        match self {
            RiskFactor::AuthRelated => {
                "Authentication-related parameter (passwords, tokens, sessions)"
            }
            RiskFactor::IdParameter => "ID parameter susceptible to IDOR attacks",
            RiskFactor::FileParameter => "File/path parameter vulnerable to LFI/Path Traversal",
            RiskFactor::UrlParameter => "URL parameter vulnerable to SSRF/Open Redirect",
            RiskFactor::CommandParameter => "Command execution parameter (highest risk)",
            RiskFactor::EmailParameter => "Email parameter for enumeration/injection",
            RiskFactor::SearchParameter => "Search/query parameter for XSS/SQLi",
            RiskFactor::AdminIndicator => "Admin/privilege parameter for authorization bypass",
            RiskFactor::DebugParameter => "Debug/test parameter may expose internals",
            RiskFactor::PaginationParameter => "Pagination parameter for SQLi/DoS",
            RiskFactor::SortParameter => "Sort parameter for SQLi",
            RiskFactor::FilterParameter => "Filter parameter for injection attacks",
            RiskFactor::InLoginForm => "Parameter in login form context",
            RiskFactor::InPaymentForm => "Parameter in payment/checkout context",
            RiskFactor::InAdminArea => "Parameter in admin area",
            RiskFactor::HasNumericValue => "Parameter has numeric value (IDOR/SQLi potential)",
            RiskFactor::AcceptsUserInput => "Parameter accepts user text input",
            RiskFactor::HasIdSuffix => "Parameter name ends with ID suffix pattern",
            RiskFactor::ContainsSensitiveKeyword => "Parameter contains sensitive keyword",
        }
    }
}

/// Source of the parameter discovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterSource {
    /// Parameter from URL query string
    URL,
    /// Parameter from HTML form
    Form,
    /// Parameter from JSON body
    JSON,
    /// Parameter from HTTP header
    Header,
    /// Parameter from cookie
    Cookie,
    /// Parameter from path segment
    Path,
    /// Unknown source
    Unknown,
}

/// Context information about the form containing the parameter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FormContext {
    /// Whether the form has a password field
    pub has_password_field: bool,
    /// Whether the form has an email field
    pub has_email_field: bool,
    /// Whether the form has payment-related fields (credit_card, cvv, expiry)
    pub has_payment_fields: bool,
    /// Keywords found in the form's action URL or surrounding context
    pub action_contains: Vec<String>,
}

impl FormContext {
    /// Create a new empty form context
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this appears to be a login form
    pub fn is_login_form(&self) -> bool {
        self.has_password_field
            || self.action_contains.iter().any(|s| {
                let lower = s.to_lowercase();
                lower.contains("login")
                    || lower.contains("signin")
                    || lower.contains("auth")
                    || lower.contains("session")
            })
    }

    /// Check if this appears to be a payment form
    pub fn is_payment_form(&self) -> bool {
        self.has_payment_fields
            || self.action_contains.iter().any(|s| {
                let lower = s.to_lowercase();
                lower.contains("payment")
                    || lower.contains("checkout")
                    || lower.contains("purchase")
                    || lower.contains("order")
                    || lower.contains("billing")
                    || lower.contains("stripe")
                    || lower.contains("paypal")
            })
    }

    /// Check if this appears to be in an admin area
    pub fn is_admin_area(&self) -> bool {
        self.action_contains.iter().any(|s| {
            let lower = s.to_lowercase();
            lower.contains("/admin")
                || lower.contains("/dashboard")
                || lower.contains("/manage")
                || lower.contains("/control")
                || lower.contains("/backend")
                || lower.contains("/console")
                || lower.contains("/panel")
        })
    }
}

/// Input information about a parameter to be scored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    /// Name of the parameter
    pub name: String,
    /// Current value of the parameter (if known)
    pub value: Option<String>,
    /// Input type (text, hidden, password, email, etc.)
    pub input_type: String,
    /// Source of the parameter
    pub source: ParameterSource,
    /// URL of the endpoint containing this parameter
    pub endpoint_url: String,
    /// Form context if parameter is from a form
    pub form_context: Option<FormContext>,
}

impl ParameterInfo {
    /// Create a new parameter info with minimal information
    pub fn new(name: &str, endpoint_url: &str) -> Self {
        Self {
            name: name.to_string(),
            value: None,
            input_type: "text".to_string(),
            source: ParameterSource::Unknown,
            endpoint_url: endpoint_url.to_string(),
            form_context: None,
        }
    }

    /// Builder method to set value
    pub fn with_value(mut self, value: &str) -> Self {
        self.value = Some(value.to_string());
        self
    }

    /// Builder method to set input type
    pub fn with_input_type(mut self, input_type: &str) -> Self {
        self.input_type = input_type.to_string();
        self
    }

    /// Builder method to set source
    pub fn with_source(mut self, source: ParameterSource) -> Self {
        self.source = source;
        self
    }

    /// Builder method to set form context
    pub fn with_form_context(mut self, context: FormContext) -> Self {
        self.form_context = Some(context);
        self
    }
}

/// Result of parameter risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRisk {
    /// Name of the parameter
    pub name: String,
    /// Risk score from 0-100 (higher = more risky)
    pub score: u8,
    /// Risk factors that contributed to the score
    pub risk_factors: Vec<RiskFactor>,
    /// Suggested scanners based on risk factors
    pub suggested_scanners: Vec<ScannerType>,
}

impl ParameterRisk {
    /// Returns true if this is considered high risk (score >= 50)
    pub fn is_high_risk(&self) -> bool {
        self.score >= 50
    }

    /// Returns true if this is considered critical risk (score >= 75)
    pub fn is_critical_risk(&self) -> bool {
        self.score >= 75
    }

    /// Returns a human-readable risk level
    pub fn risk_level(&self) -> &'static str {
        match self.score {
            0..=19 => "Low",
            20..=39 => "Medium",
            40..=59 => "High",
            60..=79 => "Very High",
            80..=100 => "Critical",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// PARAMETER PRIORITIZER
// ============================================================================

/// Parameter prioritizer for risk-based scoring
pub struct ParameterPrioritizer {
    /// Compiled regex patterns for efficient matching
    id_suffix_regex: Regex,
    /// Cached normalized patterns
    auth_patterns_set: HashSet<String>,
    id_patterns_set: HashSet<String>,
    file_patterns_set: HashSet<String>,
    url_patterns_set: HashSet<String>,
    command_patterns_set: HashSet<String>,
    email_patterns_set: HashSet<String>,
    search_patterns_set: HashSet<String>,
    admin_patterns_set: HashSet<String>,
    debug_patterns_set: HashSet<String>,
    pagination_patterns_set: HashSet<String>,
    sort_patterns_set: HashSet<String>,
    filter_patterns_set: HashSet<String>,
}

impl Default for ParameterPrioritizer {
    fn default() -> Self {
        Self::new()
    }
}

impl ParameterPrioritizer {
    /// Create a new parameter prioritizer
    pub fn new() -> Self {
        Self {
            id_suffix_regex: Regex::new(
                r"(?i)_id$|id$|-id$|_ref$|ref$|-ref$|_key$|key$|-key$|_token$|token$|-token$",
            )
            .unwrap(),
            auth_patterns_set: AUTH_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            id_patterns_set: ID_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            file_patterns_set: FILE_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            url_patterns_set: URL_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            command_patterns_set: COMMAND_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            email_patterns_set: EMAIL_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            search_patterns_set: SEARCH_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            admin_patterns_set: ADMIN_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            debug_patterns_set: DEBUG_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            pagination_patterns_set: PAGINATION_PATTERNS
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
            sort_patterns_set: SORT_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
            filter_patterns_set: FILTER_PATTERNS.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Normalize a parameter name for matching
    /// Handles variations like user_id, userId, user-id, userid
    fn normalize_name(&self, name: &str) -> String {
        name.to_lowercase().replace('-', "_").replace(' ', "_")
    }

    /// Get all normalized variations of a parameter name
    fn get_name_variations(&self, name: &str) -> Vec<String> {
        let lower = name.to_lowercase();
        let mut variations = vec![lower.clone()];

        // Add underscore variation
        let underscore = lower.replace('-', "_");
        if underscore != lower {
            variations.push(underscore.clone());
        }

        // Add hyphen variation
        let hyphen = lower.replace('_', "-");
        if hyphen != lower {
            variations.push(hyphen);
        }

        // Add no-separator variation
        let no_sep = lower.replace(['_', '-'], "");
        if no_sep != lower {
            variations.push(no_sep);
        }

        // Add camelCase to snake_case conversion
        let mut snake_case = String::new();
        for (i, c) in lower.chars().enumerate() {
            if c.is_uppercase() && i > 0 {
                snake_case.push('_');
            }
            snake_case.push(c.to_ascii_lowercase());
        }
        if snake_case != lower {
            variations.push(snake_case);
        }

        variations
    }

    /// Check if a name matches any pattern in a set, considering variations
    fn matches_pattern_set(&self, name: &str, patterns: &HashSet<String>) -> bool {
        let variations = self.get_name_variations(name);

        for variation in &variations {
            // Exact match
            if patterns.contains(variation) {
                return true;
            }

            // Prefix/suffix match (e.g., new_password, password_confirm)
            for pattern in patterns {
                if variation.starts_with(pattern) || variation.ends_with(pattern) {
                    return true;
                }
                // Contains match for common patterns
                if variation.contains(pattern) && pattern.len() >= 3 {
                    return true;
                }
            }
        }

        false
    }

    /// Score a single parameter
    pub fn score_parameter(&self, param: &ParameterInfo) -> ParameterRisk {
        let mut risk_factors = Vec::new();
        let mut score: u32 = 0;
        let name = &param.name;

        // Check parameter name patterns (primary scoring)
        if self.matches_pattern_set(name, &self.command_patterns_set) {
            risk_factors.push(RiskFactor::CommandParameter);
        }
        if self.matches_pattern_set(name, &self.auth_patterns_set) {
            risk_factors.push(RiskFactor::AuthRelated);
        }
        if self.matches_pattern_set(name, &self.url_patterns_set) {
            risk_factors.push(RiskFactor::UrlParameter);
        }
        if self.matches_pattern_set(name, &self.file_patterns_set) {
            risk_factors.push(RiskFactor::FileParameter);
        }
        if self.matches_pattern_set(name, &self.id_patterns_set) {
            risk_factors.push(RiskFactor::IdParameter);
        }
        if self.matches_pattern_set(name, &self.admin_patterns_set) {
            risk_factors.push(RiskFactor::AdminIndicator);
        }
        if self.matches_pattern_set(name, &self.search_patterns_set) {
            risk_factors.push(RiskFactor::SearchParameter);
        }
        if self.matches_pattern_set(name, &self.email_patterns_set) {
            risk_factors.push(RiskFactor::EmailParameter);
        }
        if self.matches_pattern_set(name, &self.debug_patterns_set) {
            risk_factors.push(RiskFactor::DebugParameter);
        }
        if self.matches_pattern_set(name, &self.pagination_patterns_set) {
            risk_factors.push(RiskFactor::PaginationParameter);
        }
        if self.matches_pattern_set(name, &self.sort_patterns_set) {
            risk_factors.push(RiskFactor::SortParameter);
        }
        if self.matches_pattern_set(name, &self.filter_patterns_set) {
            risk_factors.push(RiskFactor::FilterParameter);
        }

        // Check for ID suffix pattern
        if self.id_suffix_regex.is_match(name) {
            risk_factors.push(RiskFactor::HasIdSuffix);
        }

        // Check value for numeric content (IDOR/SQLi potential)
        if let Some(value) = &param.value {
            if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) {
                risk_factors.push(RiskFactor::HasNumericValue);
            }
        }

        // Check input type for user input acceptance
        let input_type_lower = param.input_type.to_lowercase();
        if matches!(
            input_type_lower.as_str(),
            "text" | "textarea" | "search" | "url" | "tel"
        ) {
            risk_factors.push(RiskFactor::AcceptsUserInput);
        }

        // Context bonuses
        if let Some(context) = &param.form_context {
            if context.is_login_form() {
                risk_factors.push(RiskFactor::InLoginForm);
            }
            if context.is_payment_form() {
                risk_factors.push(RiskFactor::InPaymentForm);
            }
            if context.is_admin_area() {
                risk_factors.push(RiskFactor::InAdminArea);
            }
        }

        // Check endpoint URL for admin area
        let url_lower = param.endpoint_url.to_lowercase();
        if url_lower.contains("/admin")
            || url_lower.contains("/dashboard")
            || url_lower.contains("/manage")
            || url_lower.contains("/control")
        {
            if !risk_factors.contains(&RiskFactor::InAdminArea) {
                risk_factors.push(RiskFactor::InAdminArea);
            }
        }

        // Calculate total score
        for factor in &risk_factors {
            score += factor.weight() as u32;
        }

        // Cap score at 100
        let final_score = std::cmp::min(score, 100) as u8;

        // Determine suggested scanners based on risk factors
        let suggested_scanners = self.get_suggested_scanners(&risk_factors);

        ParameterRisk {
            name: param.name.clone(),
            score: final_score,
            risk_factors,
            suggested_scanners,
        }
    }

    /// Score all parameters and return sorted by risk (highest first)
    pub fn score_all(&self, params: &[ParameterInfo]) -> Vec<ParameterRisk> {
        let mut risks: Vec<ParameterRisk> =
            params.iter().map(|p| self.score_parameter(p)).collect();

        // Sort by score descending (highest risk first)
        risks.sort_by(|a, b| b.score.cmp(&a.score));

        risks
    }

    /// Get only high-priority parameters above a threshold
    pub fn get_high_priority(&self, params: &[ParameterInfo], threshold: u8) -> Vec<ParameterRisk> {
        self.score_all(params)
            .into_iter()
            .filter(|r| r.score >= threshold)
            .collect()
    }

    /// Get scanners suggested for a set of risk factors
    fn get_suggested_scanners(&self, risk_factors: &[RiskFactor]) -> Vec<ScannerType> {
        let mut scanners = HashSet::new();

        for factor in risk_factors {
            match factor {
                RiskFactor::IdParameter | RiskFactor::HasIdSuffix | RiskFactor::HasNumericValue => {
                    scanners.insert(ScannerType::IDOR);
                    scanners.insert(ScannerType::SQLi);
                }
                RiskFactor::UrlParameter => {
                    scanners.insert(ScannerType::SSRF);
                    scanners.insert(ScannerType::OpenRedirect);
                }
                RiskFactor::FileParameter => {
                    scanners.insert(ScannerType::PathTraversal);
                    scanners.insert(ScannerType::LFI);
                    scanners.insert(ScannerType::RFI);
                }
                RiskFactor::SearchParameter => {
                    scanners.insert(ScannerType::XSS);
                    scanners.insert(ScannerType::SQLi);
                    scanners.insert(ScannerType::NoSQL);
                }
                RiskFactor::CommandParameter => {
                    scanners.insert(ScannerType::CommandInjection);
                    scanners.insert(ScannerType::CodeInjection);
                }
                RiskFactor::AuthRelated => {
                    scanners.insert(ScannerType::AuthBypass);
                    scanners.insert(ScannerType::SessionFixation);
                    scanners.insert(ScannerType::SQLi);
                }
                RiskFactor::AdminIndicator => {
                    scanners.insert(ScannerType::AuthBypass);
                    scanners.insert(ScannerType::IDOR);
                    scanners.insert(ScannerType::MassAssignment);
                }
                RiskFactor::EmailParameter => {
                    scanners.insert(ScannerType::EmailInjection);
                    scanners.insert(ScannerType::HeaderInjection);
                    scanners.insert(ScannerType::SQLi);
                }
                RiskFactor::DebugParameter => {
                    scanners.insert(ScannerType::CodeInjection);
                    scanners.insert(ScannerType::TemplateInjection);
                }
                RiskFactor::SortParameter | RiskFactor::PaginationParameter => {
                    scanners.insert(ScannerType::SQLi);
                }
                RiskFactor::FilterParameter => {
                    scanners.insert(ScannerType::SQLi);
                    scanners.insert(ScannerType::NoSQL);
                }
                RiskFactor::InLoginForm => {
                    scanners.insert(ScannerType::SQLi);
                    scanners.insert(ScannerType::AuthBypass);
                    scanners.insert(ScannerType::CSRF);
                }
                RiskFactor::InPaymentForm => {
                    scanners.insert(ScannerType::SQLi);
                    scanners.insert(ScannerType::XSS);
                    scanners.insert(ScannerType::CSRF);
                    scanners.insert(ScannerType::RaceCondition);
                    scanners.insert(ScannerType::BusinessLogic);
                }
                RiskFactor::InAdminArea => {
                    scanners.insert(ScannerType::AuthBypass);
                    scanners.insert(ScannerType::IDOR);
                    scanners.insert(ScannerType::CSRF);
                }
                RiskFactor::AcceptsUserInput => {
                    scanners.insert(ScannerType::XSS);
                    scanners.insert(ScannerType::SQLi);
                }
                RiskFactor::ContainsSensitiveKeyword => {
                    scanners.insert(ScannerType::SQLi);
                    scanners.insert(ScannerType::IDOR);
                }
            }
        }

        let mut result: Vec<ScannerType> = scanners.into_iter().collect();
        // Sort for consistent ordering
        result.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        result
    }

    /// Check if a parameter name contains sensitive keywords
    pub fn contains_sensitive_keyword(&self, name: &str) -> bool {
        let sensitive = [
            "secret",
            "private",
            "internal",
            "hidden",
            "key",
            "token",
            "password",
            "credential",
        ];
        let lower = name.to_lowercase();
        sensitive.iter().any(|s| lower.contains(s))
    }

    /// Get a quick priority score without full analysis (for filtering)
    pub fn quick_priority(&self, name: &str) -> u8 {
        let normalized = self.normalize_name(name);

        // Critical priority
        if self.matches_pattern_set(&normalized, &self.command_patterns_set)
            || self.matches_pattern_set(&normalized, &self.auth_patterns_set)
        {
            return 10;
        }

        // High priority
        if self.matches_pattern_set(&normalized, &self.url_patterns_set)
            || self.matches_pattern_set(&normalized, &self.file_patterns_set)
        {
            return 8;
        }

        // Medium-high priority
        if self.matches_pattern_set(&normalized, &self.id_patterns_set)
            || self.matches_pattern_set(&normalized, &self.admin_patterns_set)
            || self.matches_pattern_set(&normalized, &self.search_patterns_set)
        {
            return 6;
        }

        // Medium priority
        if self.matches_pattern_set(&normalized, &self.email_patterns_set)
            || self.matches_pattern_set(&normalized, &self.debug_patterns_set)
        {
            return 4;
        }

        // Low priority
        if self.matches_pattern_set(&normalized, &self.pagination_patterns_set)
            || self.matches_pattern_set(&normalized, &self.sort_patterns_set)
            || self.matches_pattern_set(&normalized, &self.filter_patterns_set)
        {
            return 2;
        }

        // ID suffix check
        if self.id_suffix_regex.is_match(name) {
            return 3;
        }

        // Default
        1
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_prioritizer() -> ParameterPrioritizer {
        ParameterPrioritizer::new()
    }

    #[test]
    fn test_auth_parameter_detection() {
        let prioritizer = create_prioritizer();

        let params = vec![
            ParameterInfo::new("password", "https://example.com/login"),
            ParameterInfo::new("user_password", "https://example.com/login"),
            ParameterInfo::new("api_key", "https://example.com/api"),
            ParameterInfo::new("session_token", "https://example.com/auth"),
            ParameterInfo::new("access_token", "https://example.com/oauth"),
        ];

        for param in params {
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::AuthRelated),
                "Parameter '{}' should be detected as auth-related",
                param.name
            );
            assert!(
                risk.score >= 20,
                "Auth parameter '{}' should have score >= 20, got {}",
                param.name,
                risk.score
            );
        }
    }

    #[test]
    fn test_id_parameter_detection() {
        let prioritizer = create_prioritizer();

        let test_cases = vec![
            ("user_id", true),
            ("userId", true),
            ("user-id", true),
            ("userid", true),
            ("account_id", true),
            ("order_id", true),
            ("id", true),
            ("customer_id", true),
            ("username", false), // Should not match
        ];

        for (name, should_match) in test_cases {
            let param = ParameterInfo::new(name, "https://example.com/api");
            let risk = prioritizer.score_parameter(&param);
            let contains_id_factor = risk.risk_factors.contains(&RiskFactor::IdParameter)
                || risk.risk_factors.contains(&RiskFactor::HasIdSuffix);

            if should_match {
                assert!(
                    contains_id_factor,
                    "Parameter '{}' should be detected as ID parameter",
                    name
                );
            }
        }
    }

    #[test]
    fn test_file_parameter_detection() {
        let prioritizer = create_prioritizer();

        let params = vec![
            "file",
            "filename",
            "file_path",
            "filepath",
            "document",
            "upload",
            "attachment",
        ];

        for name in params {
            let param = ParameterInfo::new(name, "https://example.com/upload");
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::FileParameter),
                "Parameter '{}' should be detected as file parameter",
                name
            );
            assert!(
                risk.suggested_scanners
                    .contains(&ScannerType::PathTraversal)
                    || risk.suggested_scanners.contains(&ScannerType::LFI),
                "File parameter '{}' should suggest PathTraversal or LFI scanner",
                name
            );
        }
    }

    #[test]
    fn test_url_parameter_detection() {
        let prioritizer = create_prioritizer();

        let params = vec![
            "url",
            "redirect",
            "redirect_url",
            "callback",
            "next",
            "return_url",
            "goto",
        ];

        for name in params {
            let param = ParameterInfo::new(name, "https://example.com/redirect");
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::UrlParameter),
                "Parameter '{}' should be detected as URL parameter",
                name
            );
            assert!(
                risk.suggested_scanners.contains(&ScannerType::SSRF)
                    || risk.suggested_scanners.contains(&ScannerType::OpenRedirect),
                "URL parameter '{}' should suggest SSRF or OpenRedirect scanner",
                name
            );
        }
    }

    #[test]
    fn test_command_parameter_detection() {
        let prioritizer = create_prioritizer();

        let params = vec!["cmd", "command", "exec", "shell", "run"];

        for name in params {
            let param = ParameterInfo::new(name, "https://example.com/admin");
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::CommandParameter),
                "Parameter '{}' should be detected as command parameter",
                name
            );
            assert!(
                risk.score >= 25,
                "Command parameter '{}' should have high score, got {}",
                name,
                risk.score
            );
        }
    }

    #[test]
    fn test_search_parameter_detection() {
        let prioritizer = create_prioritizer();

        let params = vec!["q", "query", "search", "keyword", "filter"];

        for name in params {
            let param = ParameterInfo::new(name, "https://example.com/search");
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::SearchParameter)
                    || risk.risk_factors.contains(&RiskFactor::FilterParameter),
                "Parameter '{}' should be detected as search/filter parameter",
                name
            );
            assert!(
                risk.suggested_scanners.contains(&ScannerType::XSS)
                    || risk.suggested_scanners.contains(&ScannerType::SQLi),
                "Search parameter '{}' should suggest XSS or SQLi scanner",
                name
            );
        }
    }

    #[test]
    fn test_form_context_login() {
        let prioritizer = create_prioritizer();

        let context = FormContext {
            has_password_field: true,
            has_email_field: true,
            has_payment_fields: false,
            action_contains: vec!["login".to_string()],
        };

        let param =
            ParameterInfo::new("username", "https://example.com/login").with_form_context(context);

        let risk = prioritizer.score_parameter(&param);
        assert!(
            risk.risk_factors.contains(&RiskFactor::InLoginForm),
            "Parameter should have InLoginForm context"
        );
    }

    #[test]
    fn test_form_context_payment() {
        let prioritizer = create_prioritizer();

        let context = FormContext {
            has_password_field: false,
            has_email_field: true,
            has_payment_fields: true,
            action_contains: vec!["checkout".to_string()],
        };

        let param = ParameterInfo::new("card_number", "https://example.com/checkout")
            .with_form_context(context);

        let risk = prioritizer.score_parameter(&param);
        assert!(
            risk.risk_factors.contains(&RiskFactor::InPaymentForm),
            "Parameter should have InPaymentForm context"
        );
    }

    #[test]
    fn test_admin_area_context() {
        let prioritizer = create_prioritizer();

        let param = ParameterInfo::new("user_id", "https://example.com/admin/users");
        let risk = prioritizer.score_parameter(&param);

        assert!(
            risk.risk_factors.contains(&RiskFactor::InAdminArea),
            "Parameter should have InAdminArea context for /admin/ URL"
        );
    }

    #[test]
    fn test_numeric_value_detection() {
        let prioritizer = create_prioritizer();

        let param = ParameterInfo::new("id", "https://example.com/api/users").with_value("12345");

        let risk = prioritizer.score_parameter(&param);
        assert!(
            risk.risk_factors.contains(&RiskFactor::HasNumericValue),
            "Parameter with numeric value should have HasNumericValue factor"
        );
    }

    #[test]
    fn test_score_all_sorting() {
        let prioritizer = create_prioritizer();

        let params = vec![
            ParameterInfo::new("page", "https://example.com/list"), // Low risk
            ParameterInfo::new("cmd", "https://example.com/admin"), // High risk
            ParameterInfo::new("user_id", "https://example.com/users"), // Medium risk
            ParameterInfo::new("password", "https://example.com/login"), // High risk
        ];

        let risks = prioritizer.score_all(&params);

        // Should be sorted by score descending
        for i in 0..risks.len() - 1 {
            assert!(
                risks[i].score >= risks[i + 1].score,
                "Results should be sorted by score descending"
            );
        }

        // High risk params should be first
        assert!(
            risks[0].name == "cmd" || risks[0].name == "password",
            "Highest risk parameter should be first"
        );
    }

    #[test]
    fn test_get_high_priority() {
        let prioritizer = create_prioritizer();

        let params = vec![
            ParameterInfo::new("page", "https://example.com/list"), // Low risk (~5)
            ParameterInfo::new("cmd", "https://example.com/admin"), // High risk (~30+)
            ParameterInfo::new("password", "https://example.com/login"), // High risk (~25+)
        ];

        let high_priority = prioritizer.get_high_priority(&params, 20);

        assert!(
            high_priority.len() >= 2,
            "Should have at least 2 high priority params"
        );

        // All returned should be above threshold
        for risk in &high_priority {
            assert!(
                risk.score >= 20,
                "All returned params should have score >= threshold"
            );
        }
    }

    #[test]
    fn test_input_type_bonus() {
        let prioritizer = create_prioritizer();

        let text_param =
            ParameterInfo::new("search", "https://example.com").with_input_type("text");
        let hidden_param =
            ParameterInfo::new("search", "https://example.com").with_input_type("hidden");

        let text_risk = prioritizer.score_parameter(&text_param);
        let hidden_risk = prioritizer.score_parameter(&hidden_param);

        assert!(
            text_risk
                .risk_factors
                .contains(&RiskFactor::AcceptsUserInput),
            "Text input should have AcceptsUserInput factor"
        );
        assert!(
            !hidden_risk
                .risk_factors
                .contains(&RiskFactor::AcceptsUserInput),
            "Hidden input should not have AcceptsUserInput factor"
        );
    }

    #[test]
    fn test_scanner_suggestions() {
        let prioritizer = create_prioritizer();

        // ID parameter should suggest IDOR and SQLi
        let id_param = ParameterInfo::new("user_id", "https://example.com/users");
        let id_risk = prioritizer.score_parameter(&id_param);
        assert!(id_risk.suggested_scanners.contains(&ScannerType::IDOR));
        assert!(id_risk.suggested_scanners.contains(&ScannerType::SQLi));

        // URL parameter should suggest SSRF and OpenRedirect
        let url_param = ParameterInfo::new("redirect_url", "https://example.com/auth");
        let url_risk = prioritizer.score_parameter(&url_param);
        assert!(url_risk.suggested_scanners.contains(&ScannerType::SSRF));
        assert!(url_risk
            .suggested_scanners
            .contains(&ScannerType::OpenRedirect));

        // File parameter should suggest PathTraversal and LFI
        let file_param = ParameterInfo::new("file_path", "https://example.com/download");
        let file_risk = prioritizer.score_parameter(&file_param);
        assert!(file_risk
            .suggested_scanners
            .contains(&ScannerType::PathTraversal));
        assert!(file_risk.suggested_scanners.contains(&ScannerType::LFI));
    }

    #[test]
    fn test_quick_priority() {
        let prioritizer = create_prioritizer();

        // Critical priority (10)
        assert_eq!(prioritizer.quick_priority("password"), 10);
        assert_eq!(prioritizer.quick_priority("cmd"), 10);

        // High priority (8)
        assert_eq!(prioritizer.quick_priority("redirect_url"), 8);
        assert_eq!(prioritizer.quick_priority("file_path"), 8);

        // Medium-high priority (6)
        assert_eq!(prioritizer.quick_priority("user_id"), 6);
        assert_eq!(prioritizer.quick_priority("search"), 6);

        // Low priority (2)
        assert_eq!(prioritizer.quick_priority("page"), 2);
        assert_eq!(prioritizer.quick_priority("sort"), 2);
    }

    #[test]
    fn test_name_variations() {
        let prioritizer = create_prioritizer();

        // All these variations should be detected as the same type
        let variations = vec!["user_id", "userId", "user-id", "userid", "USER_ID"];

        for name in variations {
            let param = ParameterInfo::new(name, "https://example.com/api");
            let risk = prioritizer.score_parameter(&param);
            assert!(
                risk.risk_factors.contains(&RiskFactor::IdParameter)
                    || risk.risk_factors.contains(&RiskFactor::HasIdSuffix),
                "Variation '{}' should be detected as ID parameter",
                name
            );
        }
    }

    #[test]
    fn test_risk_level_classification() {
        let low_risk = ParameterRisk {
            name: "test".to_string(),
            score: 15,
            risk_factors: vec![],
            suggested_scanners: vec![],
        };
        assert_eq!(low_risk.risk_level(), "Low");

        let medium_risk = ParameterRisk {
            name: "test".to_string(),
            score: 35,
            risk_factors: vec![],
            suggested_scanners: vec![],
        };
        assert_eq!(medium_risk.risk_level(), "Medium");

        let high_risk = ParameterRisk {
            name: "test".to_string(),
            score: 55,
            risk_factors: vec![],
            suggested_scanners: vec![],
        };
        assert_eq!(high_risk.risk_level(), "High");

        let critical_risk = ParameterRisk {
            name: "test".to_string(),
            score: 85,
            risk_factors: vec![],
            suggested_scanners: vec![],
        };
        assert_eq!(critical_risk.risk_level(), "Critical");
    }

    #[test]
    fn test_score_capped_at_100() {
        let prioritizer = create_prioritizer();

        // Parameter with many risk factors should still cap at 100
        let context = FormContext {
            has_password_field: true,
            has_email_field: true,
            has_payment_fields: true,
            action_contains: vec!["admin".to_string(), "login".to_string()],
        };

        let param = ParameterInfo::new("cmd", "https://example.com/admin/execute")
            .with_value("12345")
            .with_input_type("text")
            .with_form_context(context);

        let risk = prioritizer.score_parameter(&param);
        assert!(
            risk.score <= 100,
            "Score should be capped at 100, got {}",
            risk.score
        );
    }

    #[test]
    fn test_combined_factors() {
        let prioritizer = create_prioritizer();

        // A parameter in admin area with ID suffix should have multiple factors
        let param = ParameterInfo::new("secret_token_id", "https://example.com/admin/api");

        let risk = prioritizer.score_parameter(&param);

        // Should have auth-related (token) and admin area factors
        assert!(
            risk.risk_factors.len() >= 2,
            "Should have multiple risk factors, got {:?}",
            risk.risk_factors
        );
    }

    #[test]
    fn test_prefix_suffix_matching() {
        let prioritizer = create_prioritizer();

        // Test prefix matching (new_password should match password pattern)
        let new_password = ParameterInfo::new("new_password", "https://example.com/profile");
        let risk = prioritizer.score_parameter(&new_password);
        assert!(
            risk.risk_factors.contains(&RiskFactor::AuthRelated),
            "new_password should be detected as auth-related"
        );

        // Test suffix matching (password_confirm should match password pattern)
        let password_confirm =
            ParameterInfo::new("password_confirm", "https://example.com/register");
        let risk = prioritizer.score_parameter(&password_confirm);
        assert!(
            risk.risk_factors.contains(&RiskFactor::AuthRelated),
            "password_confirm should be detected as auth-related"
        );
    }
}
