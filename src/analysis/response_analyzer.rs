// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Response Analyzer - Semantic understanding of HTTP responses
//!
//! Uses pattern matching to understand what responses "mean" semantically,
//! enabling smarter vulnerability detection and false positive filtering.
//! This module provides NLP-lite analysis without external dependencies.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

// =============================================================================
// SQL Error Patterns by Database Type
// =============================================================================

static SQL_MYSQL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:mysql|mariadb|mysqli).*(?:error|syntax|query|warning)|You have an error in your SQL syntax|MySQL server version|mysql_fetch|mysql_num_rows|SQLSTATE\[HY000\]").unwrap()
});

static SQL_POSTGRES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:postgresql|pg_|psql|postgres).*(?:error|syntax|query)|ERROR:\s+syntax error|unterminated quoted string|invalid input syntax|PG::").unwrap()
});

static SQL_MSSQL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:microsoft sql|mssql|sqlserver|sql server).*(?:error|syntax)|Unclosed quotation mark|Microsoft OLE DB Provider|ODBC SQL Server Driver|SqlException|System\.Data\.SqlClient").unwrap()
});

static SQL_ORACLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:oracle|ora-).*(?:error|syntax)|ORA-\d{5}|Oracle error|oracle\.jdbc|PLS-\d{5}",
    )
    .unwrap()
});

static SQL_SQLITE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:sqlite|sqlite3).*(?:error|syntax)|SQLite/JDBCDriver|SQLiteException|System\.Data\.SQLite|SQLITE_ERROR").unwrap()
});

// =============================================================================
// Stack Trace Patterns by Framework/Language
// =============================================================================

static STACK_PYTHON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)Traceback \(most recent call last\)|File ".*", line \d+|^\s*at .*\.py:\d+|raise \w+Error|django\.|flask\.|pyramid\."#).unwrap()
});

static STACK_JAVA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)(?:java\.\w+\.\w+Exception|at\s+[\w.]+\([\w.]+:\d+\)|javax?\.\w+|org\.springframework|com\.sun\.|java\.lang\.NullPointerException|java\.io\.\w+Exception)").unwrap()
});

static STACK_PHP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Fatal error|Parse error|Warning|Notice):\s+.*in\s+.+\.php(?:\s+on\s+line\s+\d+)?|Stack trace:|#\d+\s+.+\.php\(\d+\)|PHP (?:Fatal|Parse|Warning|Notice) error").unwrap()
});

static STACK_NODEJS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)at\s+(?:Object\.|Module\.|Function\.)?[\w.]+\s+\((?:/|[A-Z]:).+\.js:\d+:\d+\)|Error:\s+.*\n\s+at\s+|node_modules|TypeError:|ReferenceError:|SyntaxError:").unwrap()
});

static STACK_DOTNET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)(?:System\.\w+Exception|at\s+[\w.]+\s+in\s+.*:\s*line\s+\d+|Server Error in|ASP\.NET|Microsoft\.AspNetCore|System\.Web\.)").unwrap()
});

static STACK_RUBY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)(?:\.rb:\d+:in\s+`|Rails\.root|ActionController|ActiveRecord|NoMethodError|NameError|ArgumentError.*from)").unwrap()
});

static STACK_GO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)(?:goroutine\s+\d+|runtime error:|panic:|\.go:\d+)").unwrap());

static STACK_RUST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)(?:panicked at|thread '.*' panicked|\.rs:\d+:\d+|backtrace:|RUST_BACKTRACE)")
        .unwrap()
});

// =============================================================================
// Authentication State Patterns
// =============================================================================

static AUTH_LOGIN_REQUIRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:please\s+(?:log\s*in|sign\s*in|authenticate)|login\s+required|authentication\s+required|must\s+be\s+logged\s*in|unauthorized\s+access|access\s+denied.*login|session\s+(?:expired|invalid|required)|not\s+authenticated)").unwrap()
});

static AUTH_INVALID_CREDENTIALS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:invalid\s+(?:credentials|username|password|login)|incorrect\s+(?:password|username|credentials)|wrong\s+password|bad\s+credentials|authentication\s+failed|login\s+failed|user\s+not\s+found)").unwrap()
});

static AUTH_SESSION_EXPIRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:session\s+(?:expired|timed?\s*out|invalid)|token\s+(?:expired|invalid)|please\s+(?:log\s*in|sign\s*in)\s+again|your\s+session\s+has\s+(?:expired|ended))").unwrap()
});

static AUTH_MFA_REQUIRED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:(?:two|2|multi)\s*-?\s*factor|mfa|2fa|otp|one\s*-?\s*time\s+(?:password|code)|verification\s+code\s+(?:required|sent)|enter\s+(?:the\s+)?code|authenticator\s+app)").unwrap()
});

static AUTH_ACCOUNT_LOCKED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:account\s+(?:locked|disabled|suspended|blocked)|too\s+many\s+(?:attempts|failed|login)|temporarily\s+(?:locked|blocked|disabled)|try\s+again\s+(?:later|in\s+\d+))").unwrap()
});

static AUTH_LOGGED_IN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:welcome\s+back|logged\s+in\s+as|hello,?\s+[\w@.]+|my\s+account|dashboard|profile|logout|sign\s*out|settings)").unwrap()
});

// =============================================================================
// Path Disclosure Patterns
// =============================================================================

static PATH_LINUX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:/(?:home|var|etc|usr|opt|tmp|root)/[\w./-]+|/var/www/[\w./-]+|/app/[\w./-]+)")
        .unwrap()
});

static PATH_WINDOWS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:[A-Z]:\\(?:Users|Program Files(?: \(x86\))?|Windows|inetpub|wwwroot)\\[\w\\./-]+)",
    )
    .unwrap()
});

static PATH_FRAMEWORK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:vendor/|node_modules/|site-packages/|gems/|\.bundle/|target/|__pycache__/)[\w./-]+").unwrap()
});

// =============================================================================
// Internal IP Patterns
// =============================================================================

static IP_INTERNAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:(?:10|127)\.(?:\d{1,3}\.){2}\d{1,3}|(?:172\.(?:1[6-9]|2\d|3[01])|192\.168)\.(?:\d{1,3}\.)\d{1,3}|localhost|::1|fe80::[:\da-f]+)").unwrap()
});

// =============================================================================
// WAF Detection Patterns
// =============================================================================

static WAF_CLOUDFLARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:cloudflare|cf-ray|__cfduid|attention\s+required.*cloudflare)").unwrap()
});

static WAF_AKAMAI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:akamai|ak_bmsc|akam/|ghost|access\s+denied.*akamai)").unwrap()
});

static WAF_AWS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:awswaf|aws-waf|x-amzn-waf|request\s+blocked.*aws)").unwrap());

static WAF_MODSECURITY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:mod_security|modsecurity|owasp.*crs|not\s+acceptable.*406|request\s+blocked\s+by)",
    )
    .unwrap()
});

static WAF_IMPERVA: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:incapsula|imperva|visid_incap|incap_ses)").unwrap());

static WAF_F5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:big-?ip|f5\s+networks|asm|request\s+rejected.*security)").unwrap()
});

static WAF_SUCURI: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:sucuri|cloudproxy|access\s+denied.*sucuri)").unwrap());

static WAF_FORTIWEB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:fortiweb|fortigate|.fgtauth|fortitoken)").unwrap());

// =============================================================================
// Sensitive Data Patterns
// =============================================================================

static DATA_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static DATA_API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})"#).unwrap()
});

static DATA_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:bearer\s+|token['"]?\s*[:=]\s*['"]?)([a-zA-Z0-9_.-]{20,})"#).unwrap()
});

static DATA_PASSWORD_HASH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\$2[aby]?\$\d{2}\$[\w./]{53}|\$6\$[\w./]+\$[\w./]{86}|\$5\$[\w./]+\$[\w./]{43}|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})").unwrap()
});

static DATA_AWS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap()
});

static DATA_PRIVATE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap());

// =============================================================================
// Error Type Patterns
// =============================================================================

static ERROR_DATABASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:database|db|sql|query|connection).*(?:error|failed|exception|refused)|could\s+not\s+connect\s+to\s+(?:database|server)|no\s+such\s+(?:table|column|database)").unwrap()
});

static ERROR_FILESYSTEM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:file|directory|path).*(?:not\s+found|does\s+not\s+exist|permission\s+denied|no\s+such)|failed\s+to\s+open\s+stream|cannot\s+(?:read|write|access)").unwrap()
});

static ERROR_VALIDATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:validation|input|parameter|field).*(?:error|invalid|required|missing)|must\s+be\s+(?:a\s+)?(?:valid|number|string|email)|required\s+field|invalid\s+(?:format|value|input)").unwrap()
});

static ERROR_CONFIG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:configuration|config|settings?).*(?:error|invalid|missing)|misconfigur|environment\s+variable.*(?:not\s+set|missing)|undefined\s+(?:constant|variable)").unwrap()
});

static ERROR_TIMEOUT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:timed?\s*out|timeout|gateway\s+timeout|request\s+timeout|operation\s+timed?\s*out|connection\s+timed?\s*out|504)").unwrap()
});

// =============================================================================
// Business Context Patterns
// =============================================================================

static CONTEXT_USER_MANAGEMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:user|account|profile|registration|signup|sign\s*up|password|email\s+verification|activate|deactivate)").unwrap()
});

static CONTEXT_PAYMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:payment|checkout|cart|order|invoice|billing|subscription|credit\s*card|stripe|paypal|transaction)").unwrap()
});

static CONTEXT_FILE_MANAGEMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:upload|download|file|attachment|document|media|image|storage|bucket)")
        .unwrap()
});

static CONTEXT_ADMIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:admin|administrator|manage|dashboard|control\s*panel|settings|configuration|system)").unwrap()
});

static CONTEXT_API: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:\{["\s]*(?:data|error|message|status|result)|application/json|api[/.]v?\d|endpoint|rest|graphql)"#).unwrap()
});

static CONTEXT_SEARCH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:search|query|filter|find|results?\s+for|no\s+(?:results?|matches?)\s+found)",
    )
    .unwrap()
});

static CONTEXT_REPORTING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:report|analytics|statistics|metrics|dashboard|chart|graph|export)").unwrap()
});

// =============================================================================
// Security Indicator Patterns
// =============================================================================

static SECURITY_CSRF: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken)").unwrap()
});

static SECURITY_RATE_LIMIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:rate\s*limit|too\s+many\s+requests|throttl|slow\s+down|retry\s+after|429)")
        .unwrap()
});

static SECURITY_DEBUG_MODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:debug\s*=\s*true|DEBUG_MODE|development\s+mode|stack\s+trace|exception\s+details)",
    )
    .unwrap()
});

// =============================================================================
// Utility Regex Patterns (moved from runtime compilation)
// =============================================================================

static UTIL_ADMIN_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:admin|administrator|superuser|root)").unwrap());

static UTIL_MODERATOR_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:moderator|mod|editor)").unwrap());

static UTIL_JSON_ERROR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["\'](?:error|message|msg)["\']:\s*["\']([^"\']+)["\']"#).unwrap());

static UTIL_HTML_ERROR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<(?:div|p|span)[^>]*class=[^>]*error[^>]*>([^<]+)").unwrap()
});

static UTIL_GENERIC_ERROR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:error|exception|warning):\s*(.{10,100})").unwrap());

static UTIL_LINE_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:line|ln|l)\s*(?:number|no|#)?:?\s*(\d+)").unwrap());

static UTIL_COLON_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.\w{2,4}:(\d+)").unwrap());

static UTIL_TRACEBACK_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)(Traceback.*?(?:\n\n|\z))").unwrap());

static UTIL_AT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)((?:at\s+[\w.$]+.*?\n)+)").unwrap());

static UTIL_PHP_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)(#\d+\s+.*?(?:\n\n|\z))").unwrap());

static UTIL_ENTITY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:user|account|order|product|item|file|document|customer|admin|role|group|team|organization|project)s?").unwrap()
});

static UTIL_ACTION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:create|read|update|delete|edit|view|list|search|upload|download|submit|cancel|approve|reject|enable|disable)(?:d|ing|s)?").unwrap()
});

static UTIL_PERM_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:permission|access|authorize|role|admin|user|guest|public|private|restricted|allowed|denied|forbidden|grant|revoke)s?").unwrap()
});

static UTIL_ENCODING_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"&(?:lt|gt|amp|quot|#\d+);").unwrap());

// =============================================================================
// Types and Structures
// =============================================================================

/// Semantic meaning extracted from a response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSemantics {
    /// The primary type of response
    pub response_type: ResponseType,
    /// Authentication state detected
    pub auth_state: AuthState,
    /// Error information if present
    pub error_info: Option<ErrorInfo>,
    /// Business context detected
    pub business_context: Option<BusinessContext>,
    /// Sensitive data exposures found
    pub data_exposure: Vec<DataExposure>,
    /// Security mechanisms detected
    pub security_indicators: Vec<SecurityIndicator>,
    /// Overall confidence in the analysis (0.0 - 1.0)
    pub confidence: f32,
}

/// Primary response type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseType {
    /// Successful response (2xx)
    Success,
    /// Authentication required (401)
    AuthRequired,
    /// Authentication failed
    AuthFailed,
    /// Access forbidden (403)
    Forbidden,
    /// Resource not found (404)
    NotFound,
    /// Server error (5xx)
    ServerError,
    /// Input validation error (400/422)
    ValidationError,
    /// Rate limited (429)
    RateLimited,
    /// Redirect response (3xx)
    Redirect,
    /// API/JSON response
    ApiResponse,
    /// HTML page response
    HtmlPage,
    /// Unknown response type
    Unknown,
}

impl ResponseType {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            ResponseType::Success => "success",
            ResponseType::AuthRequired => "auth_required",
            ResponseType::AuthFailed => "auth_failed",
            ResponseType::Forbidden => "forbidden",
            ResponseType::NotFound => "not_found",
            ResponseType::ServerError => "server_error",
            ResponseType::ValidationError => "validation_error",
            ResponseType::RateLimited => "rate_limited",
            ResponseType::Redirect => "redirect",
            ResponseType::ApiResponse => "api_response",
            ResponseType::HtmlPage => "html_page",
            ResponseType::Unknown => "unknown",
        }
    }
}

/// Authentication state detected in response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthState {
    /// User is authenticated
    Authenticated {
        /// Type of user (admin, user, etc.)
        user_type: String,
    },
    /// Not authenticated / anonymous
    Unauthenticated,
    /// Session has expired
    SessionExpired,
    /// Invalid credentials provided
    InvalidCredentials,
    /// Multi-factor authentication required
    MfaRequired,
    /// Account is locked
    AccountLocked,
    /// Cannot determine auth state
    Unknown,
}

impl AuthState {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            AuthState::Authenticated { .. } => "authenticated",
            AuthState::Unauthenticated => "unauthenticated",
            AuthState::SessionExpired => "session_expired",
            AuthState::InvalidCredentials => "invalid_credentials",
            AuthState::MfaRequired => "mfa_required",
            AuthState::AccountLocked => "account_locked",
            AuthState::Unknown => "unknown",
        }
    }
}

/// Detailed error information extracted from response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Type of error
    pub error_type: ErrorType,
    /// Error message if found
    pub error_message: Option<String>,
    /// Stack trace if present
    pub stack_trace: Option<String>,
    /// File path disclosed
    pub file_path: Option<String>,
    /// Line number disclosed
    pub line_number: Option<u32>,
    /// Framework/technology hint
    pub framework_hint: Option<String>,
}

/// Classification of error types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorType {
    /// Database error with optional DB type
    Database {
        /// Database type (MySQL, PostgreSQL, etc.)
        db_type: Option<String>,
    },
    /// File system error
    FileSystem,
    /// Authentication error
    Authentication,
    /// Authorization error
    Authorization,
    /// Input validation error
    Validation,
    /// Configuration error
    Configuration,
    /// Internal server error
    Internal,
    /// Timeout error
    Timeout,
    /// Unknown error type
    Unknown,
}

impl ErrorType {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            ErrorType::Database { .. } => "database",
            ErrorType::FileSystem => "filesystem",
            ErrorType::Authentication => "authentication",
            ErrorType::Authorization => "authorization",
            ErrorType::Validation => "validation",
            ErrorType::Configuration => "configuration",
            ErrorType::Internal => "internal",
            ErrorType::Timeout => "timeout",
            ErrorType::Unknown => "unknown",
        }
    }
}

/// Business context detected in response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessContext {
    /// Type of business context
    pub context_type: BusinessContextType,
    /// Entities mentioned (user, order, etc.)
    pub entities_mentioned: Vec<String>,
    /// Actions mentioned (create, delete, etc.)
    pub actions_mentioned: Vec<String>,
    /// Permissions mentioned
    pub permissions_mentioned: Vec<String>,
}

/// Classification of business contexts
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BusinessContextType {
    /// User management operations
    UserManagement,
    /// Payment/financial operations
    Payment,
    /// File management operations
    FileManagement,
    /// Admin panel operations
    AdminPanel,
    /// API endpoint
    ApiEndpoint,
    /// Search functionality
    Search,
    /// Reporting/analytics
    Reporting,
    /// Settings/configuration
    Settings,
    /// Unknown context
    Unknown,
}

impl BusinessContextType {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            BusinessContextType::UserManagement => "user_management",
            BusinessContextType::Payment => "payment",
            BusinessContextType::FileManagement => "file_management",
            BusinessContextType::AdminPanel => "admin_panel",
            BusinessContextType::ApiEndpoint => "api_endpoint",
            BusinessContextType::Search => "search",
            BusinessContextType::Reporting => "reporting",
            BusinessContextType::Settings => "settings",
            BusinessContextType::Unknown => "unknown",
        }
    }
}

/// Sensitive data exposure detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExposure {
    /// Type of data exposed
    pub exposure_type: ExposureType,
    /// Truncated sample (GDPR compliant - max 20 chars with masking)
    pub sample: String,
    /// Location where found (header, body, etc.)
    pub location: String,
}

/// Types of sensitive data exposure
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExposureType {
    /// Internal IP address
    InternalIp,
    /// File system path
    FilePath,
    /// Database schema/table info
    DatabaseSchema,
    /// Stack trace
    StackTrace,
    /// Version information
    Version,
    /// Email address
    Email,
    /// User ID
    UserId,
    /// API key
    ApiKey,
    /// Authentication token
    Token,
    /// AWS credentials
    AwsCredentials,
    /// Private key
    PrivateKey,
    /// Password hash
    PasswordHash,
}

impl ExposureType {
    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            ExposureType::InternalIp => "internal_ip",
            ExposureType::FilePath => "file_path",
            ExposureType::DatabaseSchema => "database_schema",
            ExposureType::StackTrace => "stack_trace",
            ExposureType::Version => "version",
            ExposureType::Email => "email",
            ExposureType::UserId => "user_id",
            ExposureType::ApiKey => "api_key",
            ExposureType::Token => "token",
            ExposureType::AwsCredentials => "aws_credentials",
            ExposureType::PrivateKey => "private_key",
            ExposureType::PasswordHash => "password_hash",
        }
    }

    /// Get severity level (1-5)
    pub fn severity(&self) -> u8 {
        match self {
            ExposureType::PrivateKey => 5,
            ExposureType::AwsCredentials => 5,
            ExposureType::ApiKey => 4,
            ExposureType::Token => 4,
            ExposureType::PasswordHash => 4,
            ExposureType::DatabaseSchema => 3,
            ExposureType::StackTrace => 3,
            ExposureType::FilePath => 2,
            ExposureType::InternalIp => 2,
            ExposureType::Email => 2,
            ExposureType::UserId => 1,
            ExposureType::Version => 1,
        }
    }
}

/// Security indicators detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityIndicator {
    /// WAF detected
    WafPresent {
        /// Type of WAF
        waf_type: String,
    },
    /// CSRF protection present
    CsrfProtection,
    /// Rate limiting active
    RateLimiting,
    /// Input sanitization detected
    InputSanitization,
    /// Output encoding detected
    OutputEncoding,
    /// Strict security headers
    StrictHeaders,
    /// Debug mode enabled (bad)
    DebugMode,
    /// Verbose errors enabled (bad)
    VerboseErrors,
}

impl SecurityIndicator {
    /// Check if this is a positive security indicator
    pub fn is_positive(&self) -> bool {
        match self {
            SecurityIndicator::WafPresent { .. } => true,
            SecurityIndicator::CsrfProtection => true,
            SecurityIndicator::RateLimiting => true,
            SecurityIndicator::InputSanitization => true,
            SecurityIndicator::OutputEncoding => true,
            SecurityIndicator::StrictHeaders => true,
            SecurityIndicator::DebugMode => false,
            SecurityIndicator::VerboseErrors => false,
        }
    }

    /// Get string representation
    pub fn as_str(&self) -> &str {
        match self {
            SecurityIndicator::WafPresent { .. } => "waf_present",
            SecurityIndicator::CsrfProtection => "csrf_protection",
            SecurityIndicator::RateLimiting => "rate_limiting",
            SecurityIndicator::InputSanitization => "input_sanitization",
            SecurityIndicator::OutputEncoding => "output_encoding",
            SecurityIndicator::StrictHeaders => "strict_headers",
            SecurityIndicator::DebugMode => "debug_mode",
            SecurityIndicator::VerboseErrors => "verbose_errors",
        }
    }
}

/// Semantic difference between two responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SemanticDifference {
    /// Authentication state changed
    AuthStateChanged {
        /// Previous state
        from: AuthState,
        /// New state
        to: AuthState,
    },
    /// Error type changed
    ErrorTypeChanged {
        /// Previous error type
        from: ErrorType,
        /// New error type
        to: ErrorType,
    },
    /// New data was exposed
    NewDataExposed {
        /// The exposure details
        exposure: DataExposure,
    },
    /// Security bypass indicator
    SecurityBypassIndicator {
        /// Description of the indicator
        indicator: String,
    },
    /// Response type changed
    ResponseTypeChanged {
        /// Previous response type
        from: ResponseType,
        /// New response type
        to: ResponseType,
    },
    /// New security indicator appeared
    SecurityIndicatorChanged {
        /// Description
        description: String,
    },
}

/// Hint about a potential vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityHint {
    /// Type of vulnerability
    pub vuln_type: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence found
    pub evidence: String,
    /// Severity (1-5)
    pub severity: u8,
}

// =============================================================================
// Response Analyzer Implementation
// =============================================================================

/// Main response analyzer for semantic understanding
pub struct ResponseAnalyzer {
    /// Maximum sample length for GDPR compliance
    max_sample_length: usize,
}

impl ResponseAnalyzer {
    /// Create a new response analyzer
    pub fn new() -> Self {
        Self {
            max_sample_length: 20,
        }
    }

    /// Create analyzer with custom sample length
    pub fn with_max_sample_length(max_length: usize) -> Self {
        Self {
            max_sample_length: max_length,
        }
    }

    /// Analyze a response and extract semantic meaning
    pub fn analyze(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> ResponseSemantics {
        debug!(
            "Analyzing response with status {} and body length {}",
            status,
            body.len()
        );

        let response_type = self.determine_response_type(status, headers, body);
        let auth_state = self.detect_auth_state(status, headers, body);
        let error_info = self.extract_error_info(body);
        let business_context = self.detect_business_context(body);
        let data_exposure = self.detect_data_exposure(body);
        let security_indicators = self.detect_security_indicators(headers, body);

        // Calculate confidence based on how much we could extract
        let confidence = self.calculate_confidence(
            &response_type,
            &auth_state,
            &error_info,
            &business_context,
            &data_exposure,
        );

        ResponseSemantics {
            response_type,
            auth_state,
            error_info,
            business_context,
            data_exposure,
            security_indicators,
            confidence,
        }
    }

    /// Determine the primary response type
    fn determine_response_type(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> ResponseType {
        // Check status code first
        match status {
            200..=299 => {
                // Check content type for API vs HTML
                let content_type = headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == "content-type")
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");

                if content_type.contains("application/json")
                    || body.trim_start().starts_with('{')
                    || body.trim_start().starts_with('[')
                {
                    ResponseType::ApiResponse
                } else if content_type.contains("text/html")
                    || body.contains("<!DOCTYPE")
                    || body.contains("<html")
                {
                    ResponseType::HtmlPage
                } else {
                    ResponseType::Success
                }
            }
            301 | 302 | 303 | 307 | 308 => ResponseType::Redirect,
            400 | 422 => {
                if ERROR_VALIDATION.is_match(body) {
                    ResponseType::ValidationError
                } else {
                    ResponseType::ValidationError
                }
            }
            401 => ResponseType::AuthRequired,
            403 => ResponseType::Forbidden,
            404 => ResponseType::NotFound,
            429 => ResponseType::RateLimited,
            500..=599 => ResponseType::ServerError,
            _ => {
                // Check body content for clues
                if AUTH_LOGIN_REQUIRED.is_match(body) || AUTH_INVALID_CREDENTIALS.is_match(body) {
                    ResponseType::AuthFailed
                } else if SECURITY_RATE_LIMIT.is_match(body) {
                    ResponseType::RateLimited
                } else {
                    ResponseType::Unknown
                }
            }
        }
    }

    /// Quick check if response contains SQL errors
    pub fn has_sql_error(&self, body: &str) -> Option<String> {
        if SQL_MYSQL.is_match(body) {
            return Some("MySQL".to_string());
        }
        if SQL_POSTGRES.is_match(body) {
            return Some("PostgreSQL".to_string());
        }
        if SQL_MSSQL.is_match(body) {
            return Some("MSSQL".to_string());
        }
        if SQL_ORACLE.is_match(body) {
            return Some("Oracle".to_string());
        }
        if SQL_SQLITE.is_match(body) {
            return Some("SQLite".to_string());
        }
        None
    }

    /// Quick check if response contains stack trace
    pub fn has_stack_trace(&self, body: &str) -> Option<String> {
        if STACK_PYTHON.is_match(body) {
            return Some("Python".to_string());
        }
        if STACK_JAVA.is_match(body) {
            return Some("Java".to_string());
        }
        if STACK_PHP.is_match(body) {
            return Some("PHP".to_string());
        }
        if STACK_NODEJS.is_match(body) {
            return Some("Node.js".to_string());
        }
        if STACK_DOTNET.is_match(body) {
            return Some(".NET".to_string());
        }
        if STACK_RUBY.is_match(body) {
            return Some("Ruby".to_string());
        }
        if STACK_GO.is_match(body) {
            return Some("Go".to_string());
        }
        if STACK_RUST.is_match(body) {
            return Some("Rust".to_string());
        }
        None
    }

    /// Detect authentication state from response
    pub fn detect_auth_state(
        &self,
        status: u16,
        _headers: &HashMap<String, String>,
        body: &str,
    ) -> AuthState {
        // Check for specific states in body first (more reliable than status alone)
        if AUTH_MFA_REQUIRED.is_match(body) {
            return AuthState::MfaRequired;
        }

        if AUTH_ACCOUNT_LOCKED.is_match(body) {
            return AuthState::AccountLocked;
        }

        if AUTH_SESSION_EXPIRED.is_match(body) {
            return AuthState::SessionExpired;
        }

        if AUTH_INVALID_CREDENTIALS.is_match(body) {
            return AuthState::InvalidCredentials;
        }

        if AUTH_LOGIN_REQUIRED.is_match(body) {
            return AuthState::Unauthenticated;
        }

        // Check for logged in indicators
        if AUTH_LOGGED_IN.is_match(body) {
            // Try to extract user type
            let user_type = self.extract_user_type(body);
            return AuthState::Authenticated { user_type };
        }

        // Check status codes
        match status {
            401 => AuthState::Unauthenticated,
            403 => {
                // Could be authenticated but not authorized
                if AUTH_LOGGED_IN.is_match(body) {
                    AuthState::Authenticated {
                        user_type: "user".to_string(),
                    }
                } else {
                    AuthState::Unknown
                }
            }
            _ => AuthState::Unknown,
        }
    }

    /// Extract user type from response body
    fn extract_user_type(&self, body: &str) -> String {
        if UTIL_ADMIN_PATTERN.is_match(body) {
            "admin".to_string()
        } else if UTIL_MODERATOR_PATTERN.is_match(body) {
            "moderator".to_string()
        } else {
            "user".to_string()
        }
    }

    /// Extract error information from response body
    pub fn extract_error_info(&self, body: &str) -> Option<ErrorInfo> {
        // Check for SQL errors first (most specific)
        if let Some(db_type) = self.has_sql_error(body) {
            let error_message = self.extract_error_message(body);
            let file_path = self.extract_file_path(body);
            let line_number = self.extract_line_number(body);

            return Some(ErrorInfo {
                error_type: ErrorType::Database {
                    db_type: Some(db_type),
                },
                error_message,
                stack_trace: None,
                file_path,
                line_number,
                framework_hint: None,
            });
        }

        // Check for stack traces
        if let Some(framework) = self.has_stack_trace(body) {
            let error_message = self.extract_error_message(body);
            let stack_trace = self.extract_stack_trace(body);
            let file_path = self.extract_file_path(body);
            let line_number = self.extract_line_number(body);

            return Some(ErrorInfo {
                error_type: ErrorType::Internal,
                error_message,
                stack_trace,
                file_path,
                line_number,
                framework_hint: Some(framework),
            });
        }

        // Check for other error types
        if ERROR_TIMEOUT.is_match(body) {
            return Some(ErrorInfo {
                error_type: ErrorType::Timeout,
                error_message: self.extract_error_message(body),
                stack_trace: None,
                file_path: None,
                line_number: None,
                framework_hint: None,
            });
        }

        if ERROR_FILESYSTEM.is_match(body) {
            return Some(ErrorInfo {
                error_type: ErrorType::FileSystem,
                error_message: self.extract_error_message(body),
                stack_trace: None,
                file_path: self.extract_file_path(body),
                line_number: None,
                framework_hint: None,
            });
        }

        if ERROR_VALIDATION.is_match(body) {
            return Some(ErrorInfo {
                error_type: ErrorType::Validation,
                error_message: self.extract_error_message(body),
                stack_trace: None,
                file_path: None,
                line_number: None,
                framework_hint: None,
            });
        }

        if ERROR_CONFIG.is_match(body) {
            return Some(ErrorInfo {
                error_type: ErrorType::Configuration,
                error_message: self.extract_error_message(body),
                stack_trace: None,
                file_path: self.extract_file_path(body),
                line_number: None,
                framework_hint: None,
            });
        }

        if ERROR_DATABASE.is_match(body) {
            return Some(ErrorInfo {
                error_type: ErrorType::Database { db_type: None },
                error_message: self.extract_error_message(body),
                stack_trace: None,
                file_path: None,
                line_number: None,
                framework_hint: None,
            });
        }

        None
    }

    /// Extract error message from body
    fn extract_error_message(&self, body: &str) -> Option<String> {
        // Try JSON error format first
        if let Some(cap) = UTIL_JSON_ERROR.captures(body) {
            return cap.get(1).map(|m| self.truncate_sample(m.as_str(), 100));
        }

        // Try HTML error format
        if let Some(cap) = UTIL_HTML_ERROR.captures(body) {
            return cap
                .get(1)
                .map(|m| self.truncate_sample(m.as_str().trim(), 100));
        }

        // Try generic error patterns
        if let Some(cap) = UTIL_GENERIC_ERROR.captures(body) {
            return cap
                .get(1)
                .map(|m| self.truncate_sample(m.as_str().trim(), 100));
        }

        None
    }

    /// Extract file path from body
    fn extract_file_path(&self, body: &str) -> Option<String> {
        if let Some(cap) = PATH_LINUX.captures(body) {
            return cap.get(0).map(|m| self.truncate_sample(m.as_str(), 80));
        }
        if let Some(cap) = PATH_WINDOWS.captures(body) {
            return cap.get(0).map(|m| self.truncate_sample(m.as_str(), 80));
        }
        if let Some(cap) = PATH_FRAMEWORK.captures(body) {
            return cap.get(0).map(|m| self.truncate_sample(m.as_str(), 80));
        }
        None
    }

    /// Extract line number from body
    fn extract_line_number(&self, body: &str) -> Option<u32> {
        if let Some(cap) = UTIL_LINE_PATTERN.captures(body) {
            return cap.get(1).and_then(|m| m.as_str().parse().ok());
        }

        // Try format: filename.ext:123
        if let Some(cap) = UTIL_COLON_PATTERN.captures(body) {
            return cap.get(1).and_then(|m| m.as_str().parse().ok());
        }

        None
    }

    /// Extract stack trace from body
    fn extract_stack_trace(&self, body: &str) -> Option<String> {
        // Look for common stack trace patterns and extract a portion
        if let Some(cap) = UTIL_TRACEBACK_PATTERN.captures(body) {
            return cap.get(1).map(|m| self.truncate_sample(m.as_str(), 500));
        }

        // Java/Node.js style
        if let Some(cap) = UTIL_AT_PATTERN.captures(body) {
            return cap.get(1).map(|m| self.truncate_sample(m.as_str(), 500));
        }

        // PHP style
        if let Some(cap) = UTIL_PHP_PATTERN.captures(body) {
            return cap.get(1).map(|m| self.truncate_sample(m.as_str(), 500));
        }

        None
    }

    /// Detect business context from response body
    fn detect_business_context(&self, body: &str) -> Option<BusinessContext> {
        let mut contexts: Vec<(BusinessContextType, usize)> = Vec::new();

        // Count matches for each context type
        if let Some(count) = self.count_pattern_matches(&CONTEXT_USER_MANAGEMENT, body) {
            contexts.push((BusinessContextType::UserManagement, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_PAYMENT, body) {
            contexts.push((BusinessContextType::Payment, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_FILE_MANAGEMENT, body) {
            contexts.push((BusinessContextType::FileManagement, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_ADMIN, body) {
            contexts.push((BusinessContextType::AdminPanel, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_API, body) {
            contexts.push((BusinessContextType::ApiEndpoint, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_SEARCH, body) {
            contexts.push((BusinessContextType::Search, count));
        }
        if let Some(count) = self.count_pattern_matches(&CONTEXT_REPORTING, body) {
            contexts.push((BusinessContextType::Reporting, count));
        }

        // Find the most prevalent context
        contexts.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((context_type, _)) = contexts.first() {
            let entities = self.extract_entities(body);
            let actions = self.extract_actions(body);
            let permissions = self.extract_permissions(body);

            return Some(BusinessContext {
                context_type: context_type.clone(),
                entities_mentioned: entities,
                actions_mentioned: actions,
                permissions_mentioned: permissions,
            });
        }

        None
    }

    /// Count pattern matches in body
    fn count_pattern_matches(&self, pattern: &Regex, body: &str) -> Option<usize> {
        let count = pattern.find_iter(body).count();
        if count > 0 {
            Some(count)
        } else {
            None
        }
    }

    /// Extract entity mentions from body
    fn extract_entities(&self, body: &str) -> Vec<String> {
        let mut entities = Vec::new();

        for cap in UTIL_ENTITY_PATTERN.find_iter(body).take(10) {
            let entity = cap.as_str().to_lowercase();
            if !entities.contains(&entity) {
                entities.push(entity);
            }
        }

        entities
    }

    /// Extract action mentions from body
    fn extract_actions(&self, body: &str) -> Vec<String> {
        let mut actions = Vec::new();

        for cap in UTIL_ACTION_PATTERN.find_iter(body).take(10) {
            let action = cap.as_str().to_lowercase();
            if !actions.contains(&action) {
                actions.push(action);
            }
        }

        actions
    }

    /// Extract permission mentions from body
    fn extract_permissions(&self, body: &str) -> Vec<String> {
        let mut permissions = Vec::new();

        for cap in UTIL_PERM_PATTERN.find_iter(body).take(10) {
            let perm = cap.as_str().to_lowercase();
            if !permissions.contains(&perm) {
                permissions.push(perm);
            }
        }

        permissions
    }

    /// Detect exposed sensitive data in response
    pub fn detect_data_exposure(&self, body: &str) -> Vec<DataExposure> {
        let mut exposures = Vec::new();

        // Check for internal IPs
        for cap in IP_INTERNAL.find_iter(body).take(5) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::InternalIp,
                sample: self.mask_sample(cap.as_str()),
                location: "body".to_string(),
            });
        }

        // Check for file paths
        for cap in PATH_LINUX.find_iter(body).take(5) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::FilePath,
                sample: self.mask_sample(cap.as_str()),
                location: "body".to_string(),
            });
        }
        for cap in PATH_WINDOWS.find_iter(body).take(5) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::FilePath,
                sample: self.mask_sample(cap.as_str()),
                location: "body".to_string(),
            });
        }

        // Check for emails
        for cap in DATA_EMAIL.find_iter(body).take(5) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::Email,
                sample: self.mask_email(cap.as_str()),
                location: "body".to_string(),
            });
        }

        // Check for API keys
        if let Some(cap) = DATA_API_KEY.captures(body) {
            if let Some(key) = cap.get(1) {
                exposures.push(DataExposure {
                    exposure_type: ExposureType::ApiKey,
                    sample: self.mask_sample(key.as_str()),
                    location: "body".to_string(),
                });
            }
        }

        // Check for tokens
        if let Some(cap) = DATA_TOKEN.captures(body) {
            if let Some(token) = cap.get(1) {
                exposures.push(DataExposure {
                    exposure_type: ExposureType::Token,
                    sample: self.mask_sample(token.as_str()),
                    location: "body".to_string(),
                });
            }
        }

        // Check for AWS keys
        if let Some(cap) = DATA_AWS_KEY.captures(body) {
            if let Some(m) = cap.get(0) {
                exposures.push(DataExposure {
                    exposure_type: ExposureType::AwsCredentials,
                    sample: self.mask_sample(m.as_str()),
                    location: "body".to_string(),
                });
            }
        }

        // Check for private keys
        if DATA_PRIVATE_KEY.is_match(body) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::PrivateKey,
                sample: "-----BEGIN PRIVATE KEY-----...".to_string(),
                location: "body".to_string(),
            });
        }

        // Check for password hashes
        for cap in DATA_PASSWORD_HASH.find_iter(body).take(3) {
            exposures.push(DataExposure {
                exposure_type: ExposureType::PasswordHash,
                sample: self.mask_sample(cap.as_str()),
                location: "body".to_string(),
            });
        }

        // Check for stack traces
        if self.has_stack_trace(body).is_some() {
            exposures.push(DataExposure {
                exposure_type: ExposureType::StackTrace,
                sample: "[stack trace detected]".to_string(),
                location: "body".to_string(),
            });
        }

        exposures
    }

    /// Detect security mechanisms present in response
    pub fn detect_security_indicators(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Vec<SecurityIndicator> {
        let mut indicators = Vec::new();

        // Normalize headers
        let normalized_headers: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Check for WAF
        if let Some(waf) = self.detect_waf(&normalized_headers, body) {
            indicators.push(SecurityIndicator::WafPresent { waf_type: waf });
        }

        // Check for CSRF protection
        if SECURITY_CSRF.is_match(body) {
            indicators.push(SecurityIndicator::CsrfProtection);
        }

        // Check for rate limiting
        if normalized_headers.contains_key("x-ratelimit-limit")
            || normalized_headers.contains_key("retry-after")
            || SECURITY_RATE_LIMIT.is_match(body)
        {
            indicators.push(SecurityIndicator::RateLimiting);
        }

        // Check for strict security headers
        let strict_headers = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "x-xss-protection",
        ];
        let strict_count = strict_headers
            .iter()
            .filter(|h| normalized_headers.contains_key(&h.to_string()))
            .count();
        if strict_count >= 3 {
            indicators.push(SecurityIndicator::StrictHeaders);
        }

        // Check for debug mode (negative indicator)
        if SECURITY_DEBUG_MODE.is_match(body) {
            indicators.push(SecurityIndicator::DebugMode);
        }

        // Check for verbose errors (negative indicator)
        if self.has_stack_trace(body).is_some() || self.has_sql_error(body).is_some() {
            indicators.push(SecurityIndicator::VerboseErrors);
        }

        // Check for output encoding (looking for HTML entities in output)
        if UTIL_ENCODING_PATTERN.is_match(body) {
            indicators.push(SecurityIndicator::OutputEncoding);
        }

        indicators
    }

    /// Detect WAF from headers and body
    fn detect_waf(&self, headers: &HashMap<String, String>, body: &str) -> Option<String> {
        // Check headers first
        if headers.contains_key("cf-ray")
            || headers
                .get("server")
                .map_or(false, |v| v.to_lowercase().contains("cloudflare"))
        {
            return Some("Cloudflare".to_string());
        }
        if headers.contains_key("x-akamai-transformed")
            || headers.contains_key("x-akamai-request-id")
        {
            return Some("Akamai".to_string());
        }
        if headers.contains_key("x-amzn-waf-action") || headers.contains_key("x-amzn-requestid") {
            return Some("AWS WAF".to_string());
        }
        if headers
            .get("server")
            .map_or(false, |v| v.contains("BigIP") || v.contains("F5"))
        {
            return Some("F5 BIG-IP".to_string());
        }

        // Check body patterns
        if WAF_CLOUDFLARE.is_match(body) {
            return Some("Cloudflare".to_string());
        }
        if WAF_AKAMAI.is_match(body) {
            return Some("Akamai".to_string());
        }
        if WAF_AWS.is_match(body) {
            return Some("AWS WAF".to_string());
        }
        if WAF_MODSECURITY.is_match(body) {
            return Some("ModSecurity".to_string());
        }
        if WAF_IMPERVA.is_match(body) {
            return Some("Imperva/Incapsula".to_string());
        }
        if WAF_F5.is_match(body) {
            return Some("F5 BIG-IP".to_string());
        }
        if WAF_SUCURI.is_match(body) {
            return Some("Sucuri".to_string());
        }
        if WAF_FORTIWEB.is_match(body) {
            return Some("FortiWeb".to_string());
        }

        None
    }

    /// Compare two responses for semantic differences
    pub fn compare_responses(
        &self,
        baseline: &ResponseSemantics,
        current: &ResponseSemantics,
    ) -> Vec<SemanticDifference> {
        let mut differences = Vec::new();

        // Check for auth state changes
        if baseline.auth_state != current.auth_state {
            differences.push(SemanticDifference::AuthStateChanged {
                from: baseline.auth_state.clone(),
                to: current.auth_state.clone(),
            });
        }

        // Check for response type changes
        if baseline.response_type != current.response_type {
            differences.push(SemanticDifference::ResponseTypeChanged {
                from: baseline.response_type.clone(),
                to: current.response_type.clone(),
            });
        }

        // Check for error type changes
        if let (Some(baseline_error), Some(current_error)) =
            (&baseline.error_info, &current.error_info)
        {
            if baseline_error.error_type != current_error.error_type {
                differences.push(SemanticDifference::ErrorTypeChanged {
                    from: baseline_error.error_type.clone(),
                    to: current_error.error_type.clone(),
                });
            }
        }

        // Check for new data exposures
        for exposure in &current.data_exposure {
            let is_new = !baseline
                .data_exposure
                .iter()
                .any(|e| e.exposure_type == exposure.exposure_type && e.sample == exposure.sample);
            if is_new {
                differences.push(SemanticDifference::NewDataExposed {
                    exposure: exposure.clone(),
                });
            }
        }

        // Check for security bypass indicators
        let baseline_has_waf = baseline
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::WafPresent { .. }));
        let current_has_waf = current
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::WafPresent { .. }));

        if baseline_has_waf && !current_has_waf {
            differences.push(SemanticDifference::SecurityBypassIndicator {
                indicator: "WAF may have been bypassed".to_string(),
            });
        }

        // Check for CSRF bypass
        let baseline_has_csrf = baseline
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::CsrfProtection));
        let current_has_csrf = current
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::CsrfProtection));

        if baseline_has_csrf && !current_has_csrf {
            differences.push(SemanticDifference::SecurityBypassIndicator {
                indicator: "CSRF protection may have been bypassed".to_string(),
            });
        }

        differences
    }

    /// Check if response indicates a vulnerability
    pub fn indicates_vulnerability(
        &self,
        semantics: &ResponseSemantics,
    ) -> Option<VulnerabilityHint> {
        // SQL injection indicators
        if let Some(ref error_info) = semantics.error_info {
            if let ErrorType::Database { ref db_type } = error_info.error_type {
                return Some(VulnerabilityHint {
                    vuln_type: "SQL Injection".to_string(),
                    confidence: 0.9,
                    evidence: format!(
                        "Database error detected: {}",
                        db_type.as_ref().unwrap_or(&"Unknown".to_string())
                    ),
                    severity: 4,
                });
            }
        }

        // Path traversal / LFI indicators
        let sensitive_paths = ["/etc/passwd", "/etc/shadow", "win.ini", "boot.ini"];
        for exposure in &semantics.data_exposure {
            if exposure.exposure_type == ExposureType::FilePath {
                for path in &sensitive_paths {
                    if exposure.sample.contains(path) {
                        return Some(VulnerabilityHint {
                            vuln_type: "Path Traversal / LFI".to_string(),
                            confidence: 0.85,
                            evidence: format!("Sensitive file path exposed: {}", exposure.sample),
                            severity: 4,
                        });
                    }
                }
            }
        }

        // Information disclosure via stack trace
        if semantics
            .data_exposure
            .iter()
            .any(|e| e.exposure_type == ExposureType::StackTrace)
        {
            return Some(VulnerabilityHint {
                vuln_type: "Information Disclosure".to_string(),
                confidence: 0.8,
                evidence: "Stack trace exposed in response".to_string(),
                severity: 2,
            });
        }

        // Credential exposure
        let high_severity_exposures = [
            ExposureType::ApiKey,
            ExposureType::AwsCredentials,
            ExposureType::PrivateKey,
            ExposureType::Token,
            ExposureType::PasswordHash,
        ];
        for exposure in &semantics.data_exposure {
            if high_severity_exposures.contains(&exposure.exposure_type) {
                return Some(VulnerabilityHint {
                    vuln_type: "Sensitive Data Exposure".to_string(),
                    confidence: 0.95,
                    evidence: format!("{:?} exposed in response", exposure.exposure_type),
                    severity: exposure.exposure_type.severity(),
                });
            }
        }

        // Debug mode enabled
        if semantics
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::DebugMode))
        {
            return Some(VulnerabilityHint {
                vuln_type: "Security Misconfiguration".to_string(),
                confidence: 0.7,
                evidence: "Debug mode appears to be enabled".to_string(),
                severity: 2,
            });
        }

        // Auth bypass potential
        if semantics.auth_state == AuthState::Unauthenticated
            && semantics.response_type == ResponseType::Success
        {
            // This might indicate successful auth bypass
            return Some(VulnerabilityHint {
                vuln_type: "Potential Authentication Bypass".to_string(),
                confidence: 0.5,
                evidence: "Successful response without authentication".to_string(),
                severity: 3,
            });
        }

        None
    }

    /// Calculate confidence score for the analysis
    fn calculate_confidence(
        &self,
        response_type: &ResponseType,
        auth_state: &AuthState,
        error_info: &Option<ErrorInfo>,
        business_context: &Option<BusinessContext>,
        data_exposure: &[DataExposure],
    ) -> f32 {
        let mut confidence = 0.0;
        let mut factors = 0;

        // Response type confidence
        if *response_type != ResponseType::Unknown {
            confidence += 0.2;
            factors += 1;
        }

        // Auth state confidence
        if *auth_state != AuthState::Unknown {
            confidence += 0.2;
            factors += 1;
        }

        // Error info adds confidence
        if error_info.is_some() {
            confidence += 0.2;
            factors += 1;
        }

        // Business context adds confidence
        if business_context.is_some() {
            confidence += 0.2;
            factors += 1;
        }

        // Data exposures add confidence
        if !data_exposure.is_empty() {
            confidence += 0.2;
            factors += 1;
        }

        // Normalize
        if factors > 0 {
            (confidence / 0.2 / factors as f32).min(1.0).max(0.0)
        } else {
            0.1 // Minimum confidence for any analysis
        }
    }

    /// Truncate sample for privacy/GDPR compliance
    fn truncate_sample(&self, sample: &str, max_length: usize) -> String {
        let length = max_length.min(self.max_sample_length);
        if sample.len() <= length {
            sample.to_string()
        } else {
            format!("{}...", &sample[..length])
        }
    }

    /// Mask sensitive data sample
    fn mask_sample(&self, sample: &str) -> String {
        let length = self.max_sample_length.min(sample.len());
        if length <= 4 {
            "*".repeat(length)
        } else {
            let prefix: String = sample.chars().take(4).collect();
            let prefix_len = prefix.len();
            format!("{}{}", prefix, "*".repeat((length - prefix_len).min(16)))
        }
    }

    /// Mask email for GDPR compliance
    fn mask_email(&self, email: &str) -> String {
        if let Some(at_pos) = email.find('@') {
            let local = &email[..at_pos];
            let domain = &email[at_pos..];
            let masked_local = if local.len() <= 2 {
                "*".repeat(local.len())
            } else {
                let first_char: String = local.chars().take(1).collect();
                format!("{}***", first_char)
            };
            format!("{}{}", masked_local, domain)
        } else {
            self.mask_sample(email)
        }
    }
}

impl Default for ResponseAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Shared Action Success Detection
// =============================================================================
// Replaces per-scanner ad-hoc success detection with a tiered system.
// Avoids both "too loose" (bare contains("success")) and "too tight"
// (only matches "success":true) extremes.

/// Confidence level for action success detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SuccessConfidence {
    /// No success indicators found
    None,
    /// Weak indicators only (generic words in body, but could be normal page content)
    Low,
    /// Moderate indicators (JSON-ish patterns, status code + keyword combo)
    Medium,
    /// Strong indicators (structured JSON success, redirect to authenticated area, new tokens)
    High,
}

/// Result of action success analysis.
#[derive(Debug, Clone)]
pub struct ActionSuccessResult {
    pub confidence: SuccessConfidence,
    pub indicators: Vec<String>,
}

/// Detect whether an HTTP response indicates a successful action (login, registration,
/// password change, bypass, etc). Uses tiered matching:
///
/// - **High**: Structured JSON success (`"success":true`, `"authenticated":true`, etc),
///   redirect to dashboard/admin, new auth token in response
/// - **Medium**: JSON-like patterns (`"result":"ok"`, `"status":200`), status 302 + success-ish
///   Location, HTML success with structural context (`class="success"`, `class="alert-success"`)
/// - **Low**: Bare keywords ("welcome", "dashboard", "logged in") — useful as supporting
///   evidence but not sufficient alone
///
/// Scanners should require `Medium` or higher for automated detection.
/// `Low` should only count when combined with other signals (status code change, etc).
pub fn detect_action_success(status_code: u16, body: &str, location_header: Option<&str>) -> ActionSuccessResult {
    let body_lower = body.to_lowercase();
    let mut indicators = Vec::new();
    let mut high = false;
    let mut medium = false;
    let mut low = false;

    // ===== HIGH confidence: structured success responses =====

    // JSON boolean success fields
    let json_high_patterns = [
        "\"success\":true", "\"success\": true",
        "\"authenticated\":true", "\"authenticated\": true",
        "\"logged_in\":true", "\"logged_in\": true",
        "\"loggedin\":true", "\"loggedin\": true",
        "\"is_authenticated\":true", "\"is_authenticated\": true",
        "\"valid\":true", "\"valid\": true",
        "\"authorized\":true", "\"authorized\": true",
        "\"is_admin\":true", "\"is_admin\": true",
        "\"verified\":true", "\"verified\": true",
    ];
    for pattern in &json_high_patterns {
        if body_lower.contains(pattern) {
            indicators.push(format!("json_bool: {}", pattern));
            high = true;
        }
    }

    // JSON string success status
    let json_status_patterns = [
        "\"status\":\"success\"", "\"status\": \"success\"",
        "\"status\":\"ok\"", "\"status\": \"ok\"",
        "\"result\":\"success\"", "\"result\": \"success\"",
        "\"result\":\"ok\"", "\"result\": \"ok\"",
        "\"message\":\"success\"", "\"message\": \"success\"",
        "\"state\":\"authenticated\"", "\"state\": \"authenticated\"",
    ];
    for pattern in &json_status_patterns {
        if body_lower.contains(pattern) {
            indicators.push(format!("json_status: {}", pattern));
            high = true;
        }
    }

    // New auth token in response (strong signal)
    if body_lower.contains("\"token\":\"") || body_lower.contains("\"access_token\":\"")
        || body_lower.contains("\"jwt\":\"") || body_lower.contains("\"session_token\":\"")
        || body_lower.contains("\"auth_token\":\"") || body_lower.contains("\"id_token\":\"")
    {
        indicators.push("auth_token_in_response".into());
        high = true;
    }

    // Redirect to authenticated area (302/303 + admin/dashboard/account in location)
    if (status_code == 302 || status_code == 303) {
        if let Some(loc) = location_header {
            let loc_lower = loc.to_lowercase();
            let auth_destinations = ["dashboard", "admin", "account", "profile", "home", "panel", "my-"];
            for dest in &auth_destinations {
                if loc_lower.contains(dest) {
                    indicators.push(format!("redirect_to_auth_area: {}", loc));
                    high = true;
                }
            }
        }
    }

    // ===== MEDIUM confidence: structured but less specific =====

    // JSON numeric success codes
    let json_medium_patterns = [
        "\"code\":200", "\"code\": 200",
        "\"code\":0", "\"code\": 0",  // many APIs use 0 = success
        "\"error\":false", "\"error\": false",
        "\"errors\":[]", "\"errors\": []",
        "\"status\":200", "\"status\": 200",
    ];
    for pattern in &json_medium_patterns {
        if body_lower.contains(pattern) {
            indicators.push(format!("json_code: {}", pattern));
            medium = true;
        }
    }

    // HTML structural success (class-based, not bare text)
    let html_medium_patterns = [
        "class=\"success\"", "class=\"alert-success\"", "class=\"alert success\"",
        "class=\"msg-success\"", "class=\"message-success\"", "class=\"text-success\"",
        "class=\"notification-success\"", "class=\"toast-success\"",
        "class=\"bg-success\"", "class=\"badge-success\"",
        "data-status=\"success\"", "data-result=\"success\"",
    ];
    for pattern in &html_medium_patterns {
        if body_lower.contains(pattern) {
            indicators.push(format!("html_class: {}", pattern));
            medium = true;
        }
    }

    // 302 redirect (any location) when status indicates success
    if (status_code == 302 || status_code == 303) && location_header.is_some() {
        if !medium && !high {
            indicators.push("redirect_302".into());
            medium = true;
        }
    }

    // "successfully" as a word (stronger than bare "success" because it's used in action confirmations)
    if body_lower.contains("successfully") {
        indicators.push("word_successfully".into());
        medium = true;
    }

    // ===== LOW confidence: bare keywords (supporting evidence only) =====

    let weak_keywords = [
        "welcome", "dashboard", "logged in", "signed in", "login successful",
        "authentication successful", "access granted", "sign out", "logout",
        "my account", "my profile",
    ];
    for kw in &weak_keywords {
        if body_lower.contains(kw) {
            indicators.push(format!("weak_keyword: {}", kw));
            low = true;
        }
    }

    // Negative signals — if these appear, demote confidence
    let failure_signals = [
        "invalid", "incorrect", "failed", "denied", "unauthorized",
        "forbidden", "error", "wrong password", "bad credentials",
        "login failed", "authentication failed", "access denied",
    ];
    let has_failure = failure_signals.iter().any(|f| body_lower.contains(f));
    if has_failure {
        // Demote: high → medium, medium → low, low → none
        if high {
            high = false;
            medium = true;
            indicators.push("demoted_by_failure_signal".into());
        } else if medium {
            medium = false;
            low = true;
            indicators.push("demoted_by_failure_signal".into());
        } else if low {
            low = false;
            indicators.push("negated_by_failure_signal".into());
        }
    }

    let confidence = if high {
        SuccessConfidence::High
    } else if medium {
        SuccessConfidence::Medium
    } else if low {
        SuccessConfidence::Low
    } else {
        SuccessConfidence::None
    };

    ActionSuccessResult { confidence, indicators }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_headers() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn test_sql_error_detection_mysql() {
        let analyzer = ResponseAnalyzer::new();
        let body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
        assert_eq!(analyzer.has_sql_error(body), Some("MySQL".to_string()));
    }

    #[test]
    fn test_sql_error_detection_postgres() {
        let analyzer = ResponseAnalyzer::new();
        let body = "ERROR: syntax error at or near \"SELECT\" at character 1";
        assert_eq!(analyzer.has_sql_error(body), Some("PostgreSQL".to_string()));
    }

    #[test]
    fn test_sql_error_detection_mssql() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Unclosed quotation mark after the character string 'test'";
        assert_eq!(analyzer.has_sql_error(body), Some("MSSQL".to_string()));
    }

    #[test]
    fn test_sql_error_detection_oracle() {
        let analyzer = ResponseAnalyzer::new();
        let body = "ORA-00942: table or view does not exist";
        assert_eq!(analyzer.has_sql_error(body), Some("Oracle".to_string()));
    }

    #[test]
    fn test_sql_error_detection_sqlite() {
        let analyzer = ResponseAnalyzer::new();
        let body = "SQLITE_ERROR: near \"SELECT\": syntax error";
        assert_eq!(analyzer.has_sql_error(body), Some("SQLite".to_string()));
    }

    #[test]
    fn test_stack_trace_detection_python() {
        let analyzer = ResponseAnalyzer::new();
        let body = r#"Traceback (most recent call last):
  File "/app/main.py", line 42
    raise ValueError("test")
ValueError: test"#;
        assert_eq!(analyzer.has_stack_trace(body), Some("Python".to_string()));
    }

    #[test]
    fn test_stack_trace_detection_java() {
        let analyzer = ResponseAnalyzer::new();
        let body =
            "java.lang.NullPointerException\n\tat com.example.Service.process(Service.java:123)";
        assert_eq!(analyzer.has_stack_trace(body), Some("Java".to_string()));
    }

    #[test]
    fn test_stack_trace_detection_php() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Fatal error: Uncaught Exception in /var/www/html/index.php on line 42";
        assert_eq!(analyzer.has_stack_trace(body), Some("PHP".to_string()));
    }

    #[test]
    fn test_stack_trace_detection_nodejs() {
        let analyzer = ResponseAnalyzer::new();
        let body = "TypeError: Cannot read property 'x' of undefined\n    at Object.<anonymous> (/app/server.js:25:10)";
        assert_eq!(analyzer.has_stack_trace(body), Some("Node.js".to_string()));
    }

    #[test]
    fn test_stack_trace_detection_dotnet() {
        let analyzer = ResponseAnalyzer::new();
        let body = "System.NullReferenceException: Object reference not set to an instance of an object\n   at MyApp.Controllers.HomeController.Index() in C:\\app\\Controllers\\HomeController.cs: line 15";
        assert_eq!(analyzer.has_stack_trace(body), Some(".NET".to_string()));
    }

    #[test]
    fn test_auth_state_login_required() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "Please log in to continue";

        let state = analyzer.detect_auth_state(200, &headers, body);
        assert_eq!(state, AuthState::Unauthenticated);
    }

    #[test]
    fn test_auth_state_invalid_credentials() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "Invalid username or password";

        let state = analyzer.detect_auth_state(401, &headers, body);
        assert_eq!(state, AuthState::InvalidCredentials);
    }

    #[test]
    fn test_auth_state_session_expired() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "Your session has expired. Please log in again.";

        let state = analyzer.detect_auth_state(401, &headers, body);
        assert_eq!(state, AuthState::SessionExpired);
    }

    #[test]
    fn test_auth_state_mfa_required() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body =
            "Two-factor authentication required. Enter the code from your authenticator app.";

        let state = analyzer.detect_auth_state(200, &headers, body);
        assert_eq!(state, AuthState::MfaRequired);
    }

    #[test]
    fn test_auth_state_account_locked() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "Account locked due to too many failed attempts. Try again in 30 minutes.";

        let state = analyzer.detect_auth_state(403, &headers, body);
        assert_eq!(state, AuthState::AccountLocked);
    }

    #[test]
    fn test_data_exposure_internal_ip() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Connected to database at 10.0.0.15:5432";

        let exposures = analyzer.detect_data_exposure(body);
        assert!(exposures
            .iter()
            .any(|e| e.exposure_type == ExposureType::InternalIp));
    }

    #[test]
    fn test_data_exposure_file_path_linux() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Error reading file: /var/www/html/config/database.yml";

        let exposures = analyzer.detect_data_exposure(body);
        assert!(exposures
            .iter()
            .any(|e| e.exposure_type == ExposureType::FilePath));
    }

    #[test]
    fn test_data_exposure_file_path_windows() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Cannot access C:\\inetpub\\wwwroot\\web.config";

        let exposures = analyzer.detect_data_exposure(body);
        assert!(exposures
            .iter()
            .any(|e| e.exposure_type == ExposureType::FilePath));
    }

    #[test]
    fn test_data_exposure_email() {
        let analyzer = ResponseAnalyzer::new();
        let body = "Contact admin at admin@example.com for support";

        let exposures = analyzer.detect_data_exposure(body);
        let email_exposure = exposures
            .iter()
            .find(|e| e.exposure_type == ExposureType::Email);
        assert!(email_exposure.is_some());
        // Check email is masked
        assert!(email_exposure.unwrap().sample.contains("***"));
    }

    #[test]
    fn test_data_exposure_aws_key() {
        let analyzer = ResponseAnalyzer::new();
        let body = "AWS Access Key: AKIAIOSFODNN7EXAMPLE";

        let exposures = analyzer.detect_data_exposure(body);
        assert!(exposures
            .iter()
            .any(|e| e.exposure_type == ExposureType::AwsCredentials));
    }

    #[test]
    fn test_data_exposure_private_key() {
        let analyzer = ResponseAnalyzer::new();
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";

        let exposures = analyzer.detect_data_exposure(body);
        assert!(exposures
            .iter()
            .any(|e| e.exposure_type == ExposureType::PrivateKey));
    }

    #[test]
    fn test_waf_detection_cloudflare() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "12345-SJC".to_string());
        headers.insert("server".to_string(), "cloudflare".to_string());

        let indicators = analyzer.detect_security_indicators(&headers, "");
        assert!(indicators.iter().any(
            |i| matches!(i, SecurityIndicator::WafPresent { waf_type } if waf_type == "Cloudflare")
        ));
    }

    #[test]
    fn test_waf_detection_akamai() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert(
            "x-akamai-transformed".to_string(),
            "9 - 0 pmb=mRUM,3".to_string(),
        );

        let indicators = analyzer.detect_security_indicators(&headers, "");
        assert!(indicators.iter().any(
            |i| matches!(i, SecurityIndicator::WafPresent { waf_type } if waf_type == "Akamai")
        ));
    }

    #[test]
    fn test_csrf_protection_detection() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = r#"<input type="hidden" name="csrf_token" value="abc123">"#;

        let indicators = analyzer.detect_security_indicators(&headers, body);
        assert!(indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::CsrfProtection)));
    }

    #[test]
    fn test_rate_limiting_detection() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("x-ratelimit-limit".to_string(), "100".to_string());

        let indicators = analyzer.detect_security_indicators(&headers, "");
        assert!(indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::RateLimiting)));
    }

    #[test]
    fn test_debug_mode_detection() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "DEBUG = True, showing exception details";

        let indicators = analyzer.detect_security_indicators(&headers, body);
        assert!(indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::DebugMode)));
    }

    #[test]
    fn test_response_type_api_json() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let body = r#"{"status": "ok", "data": []}"#;

        let semantics = analyzer.analyze(200, &headers, body);
        assert_eq!(semantics.response_type, ResponseType::ApiResponse);
    }

    #[test]
    fn test_response_type_html() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let body = "<!DOCTYPE html><html><head></head><body>Hello</body></html>";

        let semantics = analyzer.analyze(200, &headers, body);
        assert_eq!(semantics.response_type, ResponseType::HtmlPage);
    }

    #[test]
    fn test_response_type_rate_limited() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();

        let semantics = analyzer.analyze(429, &headers, "Too many requests");
        assert_eq!(semantics.response_type, ResponseType::RateLimited);
    }

    #[test]
    fn test_business_context_user_management() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let body = "User registration successful. Please verify your email address.";

        let semantics = analyzer.analyze(200, &headers, body);
        assert!(semantics.business_context.is_some());
        assert_eq!(
            semantics.business_context.unwrap().context_type,
            BusinessContextType::UserManagement
        );
    }

    #[test]
    fn test_business_context_payment() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let body =
            "Your payment has been processed. Order #12345 confirmed. Stripe transaction ID: xyz";

        let semantics = analyzer.analyze(200, &headers, body);
        assert!(semantics.business_context.is_some());
        assert_eq!(
            semantics.business_context.unwrap().context_type,
            BusinessContextType::Payment
        );
    }

    #[test]
    fn test_vulnerability_hint_sql_injection() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "You have an error in your SQL syntax; check the manual for MySQL server";

        let semantics = analyzer.analyze(500, &headers, body);
        let hint = analyzer.indicates_vulnerability(&semantics);

        assert!(hint.is_some());
        assert_eq!(hint.unwrap().vuln_type, "SQL Injection");
    }

    #[test]
    fn test_vulnerability_hint_sensitive_data() {
        let analyzer = ResponseAnalyzer::new();
        let headers = create_headers();
        let body = "API_KEY = 'sk_live_1234567890abcdefghij'";

        let semantics = analyzer.analyze(200, &headers, body);
        let hint = analyzer.indicates_vulnerability(&semantics);

        assert!(hint.is_some());
        assert_eq!(hint.unwrap().vuln_type, "Sensitive Data Exposure");
    }

    #[test]
    fn test_compare_responses_auth_change() {
        let analyzer = ResponseAnalyzer::new();

        let baseline = ResponseSemantics {
            response_type: ResponseType::AuthRequired,
            auth_state: AuthState::Unauthenticated,
            error_info: None,
            business_context: None,
            data_exposure: vec![],
            security_indicators: vec![],
            confidence: 0.8,
        };

        let current = ResponseSemantics {
            response_type: ResponseType::Success,
            auth_state: AuthState::Authenticated {
                user_type: "admin".to_string(),
            },
            error_info: None,
            business_context: None,
            data_exposure: vec![],
            security_indicators: vec![],
            confidence: 0.8,
        };

        let differences = analyzer.compare_responses(&baseline, &current);

        assert!(differences
            .iter()
            .any(|d| matches!(d, SemanticDifference::AuthStateChanged { .. })));
        assert!(differences
            .iter()
            .any(|d| matches!(d, SemanticDifference::ResponseTypeChanged { .. })));
    }

    #[test]
    fn test_compare_responses_waf_bypass() {
        let analyzer = ResponseAnalyzer::new();

        let baseline = ResponseSemantics {
            response_type: ResponseType::Forbidden,
            auth_state: AuthState::Unknown,
            error_info: None,
            business_context: None,
            data_exposure: vec![],
            security_indicators: vec![SecurityIndicator::WafPresent {
                waf_type: "Cloudflare".to_string(),
            }],
            confidence: 0.8,
        };

        let current = ResponseSemantics {
            response_type: ResponseType::Success,
            auth_state: AuthState::Unknown,
            error_info: None,
            business_context: None,
            data_exposure: vec![],
            security_indicators: vec![],
            confidence: 0.8,
        };

        let differences = analyzer.compare_responses(&baseline, &current);

        assert!(differences
            .iter()
            .any(|d| matches!(d, SemanticDifference::SecurityBypassIndicator { .. })));
    }

    #[test]
    fn test_mask_sample() {
        let analyzer = ResponseAnalyzer::new();

        let masked = analyzer.mask_sample("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains("*"));
        assert!(!masked.contains("EXAMPLE"));
    }

    #[test]
    fn test_mask_email() {
        let analyzer = ResponseAnalyzer::new();

        let masked = analyzer.mask_email("admin@example.com");
        assert!(masked.starts_with("a***"));
        assert!(masked.ends_with("@example.com"));
        assert!(!masked.contains("admin"));
    }

    #[test]
    fn test_extract_error_info_with_file_path() {
        let analyzer = ResponseAnalyzer::new();
        let body =
            "Fatal error: Call to undefined function foo() in /var/www/html/app.php on line 42";

        let error_info = analyzer.extract_error_info(body);
        assert!(error_info.is_some());

        let info = error_info.unwrap();
        assert!(info.file_path.is_some());
        assert!(info.line_number.is_some());
        assert_eq!(info.line_number.unwrap(), 42);
    }

    #[test]
    fn test_full_analysis() {
        let analyzer = ResponseAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let body = r#"<!DOCTYPE html>
<html>
<head><title>Admin Dashboard</title></head>
<body>
<div>Welcome back, admin</div>
<form>
<input type="hidden" name="csrf_token" value="abc123">
</form>
</body>
</html>"#;

        let semantics = analyzer.analyze(200, &headers, body);

        assert_eq!(semantics.response_type, ResponseType::HtmlPage);
        assert!(matches!(
            semantics.auth_state,
            AuthState::Authenticated { .. }
        ));
        assert!(semantics
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::CsrfProtection)));
        assert!(semantics
            .security_indicators
            .iter()
            .any(|i| matches!(i, SecurityIndicator::StrictHeaders)));
        assert!(semantics.confidence > 0.5);
    }

    #[test]
    fn test_exposure_severity() {
        assert_eq!(ExposureType::PrivateKey.severity(), 5);
        assert_eq!(ExposureType::AwsCredentials.severity(), 5);
        assert_eq!(ExposureType::ApiKey.severity(), 4);
        assert_eq!(ExposureType::StackTrace.severity(), 3);
        assert_eq!(ExposureType::FilePath.severity(), 2);
        assert_eq!(ExposureType::Version.severity(), 1);
    }

    #[test]
    fn test_security_indicator_positive() {
        assert!(SecurityIndicator::WafPresent {
            waf_type: "test".to_string()
        }
        .is_positive());
        assert!(SecurityIndicator::CsrfProtection.is_positive());
        assert!(!SecurityIndicator::DebugMode.is_positive());
        assert!(!SecurityIndicator::VerboseErrors.is_positive());
    }

    // =========================================================================
    // detect_action_success tests
    // =========================================================================

    #[test]
    fn test_success_json_bool_high() {
        // PR#216 pattern — strict JSON bool
        let body = r#"{"success":true,"user":{"id":42}}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::High);
    }

    #[test]
    fn test_success_json_string_status_high() {
        // {"status":"success"} — common in REST APIs
        let body = r#"{"status":"success","data":[]}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::High);
    }

    #[test]
    fn test_success_json_result_ok_high() {
        // {"result":"ok"} — another common pattern PR#216 would miss
        let body = r#"{"result":"ok","message":"Account created"}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::High);
    }

    #[test]
    fn test_success_token_in_response_high() {
        let body = r#"{"access_token":"eyJhbGciOiJIUzI1NiJ9.abc.def"}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::High);
    }

    #[test]
    fn test_success_redirect_to_dashboard_high() {
        let r = detect_action_success(302, "", Some("/dashboard"));
        assert_eq!(r.confidence, SuccessConfidence::High);
    }

    #[test]
    fn test_success_html_class_medium() {
        // HTML success with structural context — not bare keyword
        let body = r#"<div class="alert-success">Registration complete</div>"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::Medium);
    }

    #[test]
    fn test_success_json_code_200_medium() {
        // {"code":200} — medium because less specific
        let body = r#"{"code":200,"data":{"id":1}}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::Medium);
    }

    #[test]
    fn test_success_successfully_word_medium() {
        let body = "Your password was changed successfully.";
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::Medium);
    }

    #[test]
    fn test_success_bare_keyword_low() {
        // Bare "welcome" — too common on normal pages
        let body = "<h1>Welcome to our site</h1><p>Browse our products</p>";
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::Low);
    }

    #[test]
    fn test_success_none_on_error_page() {
        let body = "<h1>404 Not Found</h1><p>The page you requested does not exist.</p>";
        let r = detect_action_success(404, body, None);
        assert_eq!(r.confidence, SuccessConfidence::None);
    }

    #[test]
    fn test_success_demoted_by_failure() {
        // Has "success":true but ALSO "invalid" — demote to medium
        let body = r#"{"success":true,"message":"invalid token"}"#;
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::Medium);
    }

    #[test]
    fn test_success_plain_html_no_indicators() {
        // Normal marketing page — no success indicators
        let body = "<html><body><h1>Our Product</h1><p>Best in class</p></body></html>";
        let r = detect_action_success(200, body, None);
        assert_eq!(r.confidence, SuccessConfidence::None);
    }
}
