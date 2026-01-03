// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Attack Surface Module
 * Intelligent endpoint and parameter deduplication for efficient security testing
 *
 * Purpose: Deduplicate endpoints and parameters so we test unique attack vectors once,
 * not 50+ times. Same form on 50 pages = 1 test target.
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::crawler::FormInput;
use regex::Regex;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use tracing::debug;

// ============================================================================
// Content Type Enum
// ============================================================================

/// Content type categories for HTTP requests
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// application/x-www-form-urlencoded
    FormUrlEncoded,
    /// application/json
    Json,
    /// application/xml or text/xml
    Xml,
    /// multipart/form-data
    Multipart,
    /// text/plain
    PlainText,
    /// GraphQL queries
    GraphQL,
    /// Unknown or other content types
    Other(String),
}

impl ContentType {
    /// Parse content type from HTTP header value
    pub fn from_header(header: &str) -> Self {
        let lower = header.to_lowercase();
        if lower.contains("application/x-www-form-urlencoded") {
            ContentType::FormUrlEncoded
        } else if lower.contains("application/json") {
            ContentType::Json
        } else if lower.contains("application/xml") || lower.contains("text/xml") {
            ContentType::Xml
        } else if lower.contains("multipart/form-data") {
            ContentType::Multipart
        } else if lower.contains("text/plain") {
            ContentType::PlainText
        } else if lower.contains("application/graphql") {
            ContentType::GraphQL
        } else {
            ContentType::Other(header.to_string())
        }
    }

    /// Infer content type from URL path or method
    pub fn infer_from_context(path: &str, method: &str) -> Self {
        let path_lower = path.to_lowercase();

        // GraphQL endpoints
        if path_lower.contains("graphql") {
            return ContentType::GraphQL;
        }

        // API endpoints typically use JSON
        if path_lower.contains("/api/")
            || path_lower.starts_with("/v1/")
            || path_lower.starts_with("/v2/")
            || path_lower.starts_with("/v3/")
        {
            return ContentType::Json;
        }

        // POST forms typically use FormUrlEncoded unless multipart
        if method.to_uppercase() == "POST" {
            return ContentType::FormUrlEncoded;
        }

        ContentType::FormUrlEncoded
    }
}

impl Default for ContentType {
    fn default() -> Self {
        ContentType::FormUrlEncoded
    }
}

// ============================================================================
// Value Type Enum
// ============================================================================

/// Detected value types for parameters
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// Pure numeric value (integer or float)
    Numeric,
    /// String/text value
    String,
    /// Email address format
    Email,
    /// UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    UUID,
    /// Boolean (true/false, 0/1, yes/no)
    Boolean,
    /// Date format (YYYY-MM-DD, DD/MM/YYYY, etc.)
    Date,
    /// DateTime format
    DateTime,
    /// URL format
    Url,
    /// JSON object or array
    Json,
    /// Base64 encoded data
    Base64,
    /// JWT token format
    Jwt,
    /// Unknown type
    Unknown,
}

impl ValueType {
    /// Detect value type from a sample value
    pub fn detect(value: &str) -> Self {
        if value.is_empty() {
            return ValueType::Unknown;
        }

        // Boolean check
        let lower = value.to_lowercase();
        if matches!(lower.as_str(), "true" | "false" | "yes" | "no" | "0" | "1") {
            return ValueType::Boolean;
        }

        // Numeric check
        if value.parse::<f64>().is_ok() {
            return ValueType::Numeric;
        }

        // UUID check
        let uuid_re = Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .unwrap();
        if uuid_re.is_match(value) {
            return ValueType::UUID;
        }

        // Email check
        let email_re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        if email_re.is_match(value) {
            return ValueType::Email;
        }

        // JWT check (header.payload.signature)
        if value.matches('.').count() == 2 && value.len() > 50 {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.iter().all(|p| base64_like(p)) {
                return ValueType::Jwt;
            }
        }

        // URL check
        if value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")
        {
            return ValueType::Url;
        }

        // Date check (various formats)
        let date_patterns = [
            r"^\d{4}-\d{2}-\d{2}$", // YYYY-MM-DD
            r"^\d{2}/\d{2}/\d{4}$", // DD/MM/YYYY or MM/DD/YYYY
            r"^\d{2}-\d{2}-\d{4}$", // DD-MM-YYYY
        ];
        for pattern in &date_patterns {
            if Regex::new(pattern)
                .map(|re| re.is_match(value))
                .unwrap_or(false)
            {
                return ValueType::Date;
            }
        }

        // DateTime check
        let datetime_patterns = [
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",  // ISO 8601
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", // YYYY-MM-DD HH:MM:SS
        ];
        for pattern in &datetime_patterns {
            if Regex::new(pattern)
                .map(|re| re.is_match(value))
                .unwrap_or(false)
            {
                return ValueType::DateTime;
            }
        }

        // JSON check
        if (value.starts_with('{') && value.ends_with('}'))
            || (value.starts_with('[') && value.ends_with(']'))
        {
            if serde_json::from_str::<serde_json::Value>(value).is_ok() {
                return ValueType::Json;
            }
        }

        // Base64 check (minimum length and valid characters)
        if value.len() > 20 && base64_like(value) {
            return ValueType::Base64;
        }

        ValueType::String
    }

    /// Get risk score for this value type (1-10)
    pub fn risk_score(&self) -> u8 {
        match self {
            ValueType::Jwt => 10,    // JWTs are always security-critical
            ValueType::Base64 => 8,  // Could be serialized data
            ValueType::Json => 7,    // Could be deserialized
            ValueType::Url => 7,     // SSRF potential
            ValueType::Email => 6,   // Often used in auth flows
            ValueType::String => 5,  // General injection target
            ValueType::UUID => 3,    // Usually internal IDs
            ValueType::Numeric => 2, // Often just IDs
            ValueType::Boolean => 1, // Usually flags
            ValueType::Date => 2,
            ValueType::DateTime => 2,
            ValueType::Unknown => 3,
        }
    }
}

/// Check if a string looks like base64
fn base64_like(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
    })
}

// ============================================================================
// Parameter Source Enum
// ============================================================================

/// Source of a parameter (where it was discovered)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParameterSource {
    /// URL query string parameter
    Url,
    /// Form field (input, textarea, select)
    Form,
    /// JSON request body
    JsonBody,
    /// XML request body
    XmlBody,
    /// HTTP header
    Header,
    /// Cookie
    Cookie,
    /// Path segment (e.g., /users/{id})
    PathSegment,
    /// GraphQL variable
    GraphQLVariable,
    /// Multipart form field
    MultipartField,
}

impl ParameterSource {
    /// Get risk multiplier for this source (1.0-2.0)
    pub fn risk_multiplier(&self) -> f32 {
        match self {
            ParameterSource::Header => 1.5,      // Headers often less validated
            ParameterSource::Cookie => 1.4,      // Cookies trusted too much
            ParameterSource::PathSegment => 1.3, // Path segments often trusted
            ParameterSource::GraphQLVariable => 1.2, // GraphQL sometimes bypasses validation
            ParameterSource::JsonBody => 1.1,
            ParameterSource::XmlBody => 1.2, // XML parsers can be vulnerable
            ParameterSource::Form => 1.0,
            ParameterSource::Url => 1.0,
            ParameterSource::MultipartField => 1.1,
        }
    }
}

// ============================================================================
// Endpoint Signature
// ============================================================================

/// Normalized endpoint signature for deduplication
#[derive(Debug, Clone)]
pub struct EndpointSignature {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,
    /// Normalized path pattern (e.g., /api/users/{id})
    pub path_pattern: String,
    /// Sorted parameter names
    pub param_names: Vec<String>,
    /// Content type used for requests
    pub content_type: ContentType,
}

impl EndpointSignature {
    /// Create a new endpoint signature
    pub fn new(method: &str, url: &str, params: &[String], content_type: ContentType) -> Self {
        let path_pattern = PathNormalizer::normalize(url);
        let mut sorted_params = params.to_vec();
        sorted_params.sort();
        sorted_params.dedup();

        Self {
            method: method.to_uppercase(),
            path_pattern,
            param_names: sorted_params,
            content_type,
        }
    }

    /// Generate a hash for this signature
    pub fn hash_signature(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.method.hash(&mut hasher);
        self.path_pattern.hash(&mut hasher);
        for param in &self.param_names {
            param.hash(&mut hasher);
        }
        self.content_type.hash(&mut hasher);
        hasher.finish()
    }
}

impl PartialEq for EndpointSignature {
    fn eq(&self, other: &Self) -> bool {
        self.method == other.method
            && self.path_pattern == other.path_pattern
            && self.param_names == other.param_names
            && self.content_type == other.content_type
    }
}

impl Eq for EndpointSignature {}

impl Hash for EndpointSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.method.hash(state);
        self.path_pattern.hash(state);
        self.param_names.hash(state);
        self.content_type.hash(state);
    }
}

// ============================================================================
// Path Normalizer
// ============================================================================

/// Normalizes URL paths by replacing dynamic segments with placeholders
pub struct PathNormalizer;

impl PathNormalizer {
    // Lazy static patterns for path normalization
    fn uuid_pattern() -> Regex {
        Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
            .unwrap()
    }

    fn numeric_id_pattern() -> Regex {
        Regex::new(r"^[0-9]+$").unwrap()
    }

    fn hex_id_pattern() -> Regex {
        Regex::new(r"^[0-9a-fA-F]{24,}$").unwrap() // MongoDB ObjectId and similar
    }

    fn date_pattern() -> Regex {
        Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap()
    }

    fn base64_id_pattern() -> Regex {
        Regex::new(r"^[A-Za-z0-9+/=_-]{20,}$").unwrap()
    }

    fn version_pattern() -> Regex {
        Regex::new(r"^v\d+(\.\d+)*$").unwrap() // v1, v1.0, v2.1.3
    }

    fn hash_pattern() -> Regex {
        Regex::new(r"^[a-fA-F0-9]{32,64}$").unwrap() // MD5, SHA-1, SHA-256
    }

    /// Normalize a URL path by replacing dynamic segments with placeholders
    pub fn normalize(url: &str) -> String {
        // Parse URL and extract path
        let path = match url::Url::parse(url) {
            Ok(parsed) => parsed.path().to_string(),
            Err(_) => {
                // If full URL parse fails, try to extract path
                if url.starts_with('/') {
                    url.split('?').next().unwrap_or(url).to_string()
                } else if let Some(idx) = url.find("://") {
                    let after_scheme = &url[idx + 3..];
                    if let Some(path_start) = after_scheme.find('/') {
                        after_scheme[path_start..]
                            .split('?')
                            .next()
                            .unwrap_or("")
                            .to_string()
                    } else {
                        "/".to_string()
                    }
                } else {
                    url.split('?').next().unwrap_or(url).to_string()
                }
            }
        };

        // Split path into segments
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut normalized_segments = Vec::new();

        for segment in segments {
            let normalized = Self::normalize_segment(segment);
            normalized_segments.push(normalized);
        }

        if normalized_segments.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", normalized_segments.join("/"))
        }
    }

    /// Normalize a single path segment
    fn normalize_segment(segment: &str) -> String {
        // Check for UUID
        if Self::uuid_pattern().is_match(segment) {
            return "{uuid}".to_string();
        }

        // Check for numeric ID
        if Self::numeric_id_pattern().is_match(segment) {
            return "{id}".to_string();
        }

        // Check for MongoDB ObjectId or hex IDs
        if Self::hex_id_pattern().is_match(segment) {
            return "{hex_id}".to_string();
        }

        // Check for date
        if Self::date_pattern().is_match(segment) {
            return "{date}".to_string();
        }

        // Check for hash
        if Self::hash_pattern().is_match(segment) {
            return "{hash}".to_string();
        }

        // Check for base64-encoded IDs
        if Self::base64_id_pattern().is_match(segment) && segment.len() > 20 {
            return "{encoded_id}".to_string();
        }

        // Check for API version
        if Self::version_pattern().is_match(segment) {
            return segment.to_string(); // Keep version as-is
        }

        // Check for file extensions
        if segment.contains('.') {
            let parts: Vec<&str> = segment.rsplitn(2, '.').collect();
            if parts.len() == 2 {
                let extension = parts[0].to_lowercase();
                let filename = parts[1];

                // Common dynamic file patterns
                if Self::numeric_id_pattern().is_match(filename)
                    || Self::uuid_pattern().is_match(filename)
                {
                    return format!("{{file}}.{}", extension);
                }
            }
        }

        // Check if segment looks like a slug (lowercase with hyphens/underscores)
        if Self::is_likely_slug(segment) {
            return "{slug}".to_string();
        }

        // Keep static segments as-is
        segment.to_string()
    }

    /// Check if a segment is likely a URL slug
    fn is_likely_slug(segment: &str) -> bool {
        // Slugs are typically lowercase with hyphens or underscores
        // and contain a mix of letters and possibly numbers
        if segment.len() < 3 || segment.len() > 100 {
            return false;
        }

        let has_separator = segment.contains('-') || segment.contains('_');
        let all_slug_chars = segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        let has_letters = segment.chars().any(|c| c.is_ascii_lowercase());

        // It's a slug if it has separators and looks like text
        has_separator && all_slug_chars && has_letters
    }
}

// ============================================================================
// Parameter Context
// ============================================================================

/// Context information about a discovered parameter
#[derive(Debug, Clone)]
pub struct ParameterContext {
    /// Parameter name
    pub name: String,
    /// Sources where this parameter was found
    pub sources: HashSet<ParameterSource>,
    /// Detected value type
    pub value_type: ValueType,
    /// Endpoints where this parameter was seen
    pub endpoints_seen: Vec<String>,
    /// Calculated priority/risk score (1-10)
    pub priority_score: u8,
    /// Sample values seen for this parameter
    pub sample_values: Vec<String>,
}

impl ParameterContext {
    /// Create a new parameter context
    pub fn new(name: &str, source: ParameterSource, endpoint: &str) -> Self {
        let mut sources = HashSet::new();
        sources.insert(source);

        Self {
            name: name.to_string(),
            sources,
            value_type: ValueType::Unknown,
            endpoints_seen: vec![endpoint.to_string()],
            priority_score: Self::calculate_base_priority(name),
            sample_values: Vec::new(),
        }
    }

    /// Add a source for this parameter
    pub fn add_source(&mut self, source: ParameterSource) {
        self.sources.insert(source);
        self.recalculate_priority();
    }

    /// Add an endpoint where this parameter was seen
    pub fn add_endpoint(&mut self, endpoint: &str) {
        if !self.endpoints_seen.contains(&endpoint.to_string()) {
            self.endpoints_seen.push(endpoint.to_string());
        }
    }

    /// Add a sample value and detect type
    pub fn add_sample_value(&mut self, value: &str) {
        if !value.is_empty() && !self.sample_values.contains(&value.to_string()) {
            if self.sample_values.len() < 5 {
                // Keep up to 5 samples
                self.sample_values.push(value.to_string());
            }

            // Detect type from value
            let detected_type = ValueType::detect(value);
            if self.value_type == ValueType::Unknown
                || detected_type.risk_score() > self.value_type.risk_score()
            {
                self.value_type = detected_type;
            }
        }
        self.recalculate_priority();
    }

    /// Calculate base priority score based on parameter name
    fn calculate_base_priority(name: &str) -> u8 {
        let name_lower = name.to_lowercase();

        // CRITICAL (10): Auth/security-related
        let critical = [
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "key",
            "auth",
            "credential",
            "apikey",
            "api_key",
            "access_token",
            "refresh_token",
            "session",
            "jwt",
            "bearer",
        ];
        for term in &critical {
            if name_lower.contains(term) {
                return 10;
            }
        }

        // HIGH (8-9): User input fields
        let high = [
            "email",
            "username",
            "user",
            "message",
            "comment",
            "feedback",
            "description",
            "search",
            "query",
            "input",
            "text",
            "content",
            "body",
            "title",
            "subject",
            "name",
        ];
        for term in &high {
            if name_lower.contains(term) {
                return 9;
            }
        }

        // MEDIUM-HIGH (7): File/URL operations
        let medium_high = [
            "file",
            "path",
            "url",
            "uri",
            "link",
            "redirect",
            "callback",
            "upload",
            "download",
            "attachment",
            "image",
            "document",
            "template",
        ];
        for term in &medium_high {
            if name_lower.contains(term) {
                return 7;
            }
        }

        // MEDIUM (5): Business data
        let medium = [
            "address", "phone", "company", "business", "product", "price", "city", "country",
            "zip", "postal",
        ];
        for term in &medium {
            if name_lower.contains(term) {
                return 5;
            }
        }

        // LOW (3): ID fields
        if name_lower.ends_with("id") || name_lower.ends_with("_id") || name_lower == "id" {
            return 3;
        }

        // LOWEST (2): Pagination, sorting, boolean flags
        let lowest = [
            "page", "limit", "offset", "sort", "order", "filter", "enabled", "active", "visible",
            "show", "hide",
        ];
        for term in &lowest {
            if name_lower.contains(term) {
                return 2;
            }
        }

        // Default
        4
    }

    /// Recalculate priority based on all context
    fn recalculate_priority(&mut self) {
        let mut score = Self::calculate_base_priority(&self.name) as f32;

        // Boost for appearing in multiple sources
        if self.sources.len() > 1 {
            score *= 1.1;
        }

        // Boost for high-risk value types
        score *= 1.0 + (self.value_type.risk_score() as f32 / 20.0);

        // Boost for appearing in multiple endpoints
        if self.endpoints_seen.len() > 3 {
            score *= 1.1;
        }

        // Apply source risk multipliers
        let max_multiplier = self
            .sources
            .iter()
            .map(|s| s.risk_multiplier())
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(1.0);
        score *= max_multiplier;

        self.priority_score = (score.min(10.0).max(1.0)) as u8;
    }
}

// ============================================================================
// Form Signature
// ============================================================================

/// Signature for form deduplication
#[derive(Debug, Clone)]
pub struct FormSignature {
    /// Normalized action path pattern
    pub action_pattern: String,
    /// HTTP method
    pub method: String,
    /// Sorted field names
    pub field_names: Vec<String>,
    /// Field types (input types)
    pub field_types: Vec<String>,
}

impl FormSignature {
    /// Create a new form signature
    pub fn new(action: &str, method: &str, fields: &[FormInput]) -> Self {
        let action_pattern = PathNormalizer::normalize(action);

        let mut field_names: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
        field_names.sort();
        field_names.dedup();

        let mut field_types: Vec<String> = fields.iter().map(|f| f.input_type.clone()).collect();
        field_types.sort();

        Self {
            action_pattern,
            method: method.to_uppercase(),
            field_names,
            field_types,
        }
    }

    /// Generate a hash for this signature
    pub fn hash_signature(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.action_pattern.hash(&mut hasher);
        self.method.hash(&mut hasher);
        for name in &self.field_names {
            name.hash(&mut hasher);
        }
        for ftype in &self.field_types {
            ftype.hash(&mut hasher);
        }
        hasher.finish()
    }
}

impl PartialEq for FormSignature {
    fn eq(&self, other: &Self) -> bool {
        self.action_pattern == other.action_pattern
            && self.method == other.method
            && self.field_names == other.field_names
    }
}

impl Eq for FormSignature {}

impl Hash for FormSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.action_pattern.hash(state);
        self.method.hash(state);
        self.field_names.hash(state);
    }
}

// ============================================================================
// Form Data
// ============================================================================

/// Stored form data for a unique form signature
#[derive(Debug, Clone)]
pub struct FormData {
    /// Representative action URL
    pub action: String,
    /// HTTP method
    pub method: String,
    /// Form input fields
    pub fields: Vec<FormInput>,
    /// All pages where this form was discovered
    pub discovered_at: Vec<String>,
}

// ============================================================================
// Test Endpoint
// ============================================================================

/// A deduplicated endpoint for testing
#[derive(Debug, Clone)]
pub struct TestEndpoint {
    /// Endpoint signature for identification
    pub signature: EndpointSignature,
    /// Representative URL to test
    pub representative_url: String,
    /// All similar URLs that match this signature
    pub similar_urls: Vec<String>,
    /// Parameters to test on this endpoint
    pub parameters: Vec<String>,
}

// ============================================================================
// Test Form
// ============================================================================

/// A deduplicated form for testing
#[derive(Debug, Clone)]
pub struct TestForm {
    /// Form signature for identification
    pub signature: FormSignature,
    /// Representative action URL
    pub action: String,
    /// HTTP method
    pub method: String,
    /// Form fields to test
    pub fields: Vec<FormInput>,
    /// All pages where identical form was found
    pub found_on_pages: Vec<String>,
}

// ============================================================================
// Test Parameter
// ============================================================================

/// A parameter with full context for testing
#[derive(Debug, Clone)]
pub struct TestParameter {
    /// Parameter name
    pub name: String,
    /// Context information
    pub context: ParameterContext,
    /// Recommended test strategies based on context
    pub recommended_tests: Vec<String>,
}

impl TestParameter {
    /// Generate recommended tests based on parameter context
    pub fn generate_recommendations(context: &ParameterContext) -> Vec<String> {
        let mut recommendations = Vec::new();
        let name_lower = context.name.to_lowercase();

        // Value type based recommendations
        match &context.value_type {
            ValueType::Email => {
                recommendations.push("email_header_injection".to_string());
                recommendations.push("xss".to_string());
            }
            ValueType::Url => {
                recommendations.push("ssrf".to_string());
                recommendations.push("open_redirect".to_string());
            }
            ValueType::Jwt => {
                recommendations.push("jwt_vulnerabilities".to_string());
            }
            ValueType::Json => {
                recommendations.push("nosql_injection".to_string());
                recommendations.push("mass_assignment".to_string());
            }
            ValueType::Base64 => {
                recommendations.push("deserialization".to_string());
            }
            _ => {}
        }

        // Name-based recommendations
        if name_lower.contains("file") || name_lower.contains("path") || name_lower.contains("dir")
        {
            recommendations.push("path_traversal".to_string());
        }
        if name_lower.contains("url")
            || name_lower.contains("uri")
            || name_lower.contains("callback")
        {
            recommendations.push("ssrf".to_string());
        }
        if name_lower.contains("redirect")
            || name_lower.contains("next")
            || name_lower.contains("return")
        {
            recommendations.push("open_redirect".to_string());
        }
        if name_lower.contains("query")
            || name_lower.contains("search")
            || name_lower.contains("filter")
        {
            recommendations.push("sqli".to_string());
            recommendations.push("nosql_injection".to_string());
        }
        if name_lower.contains("template") || name_lower.contains("render") {
            recommendations.push("ssti".to_string());
        }
        if name_lower.contains("cmd")
            || name_lower.contains("exec")
            || name_lower.contains("command")
        {
            recommendations.push("command_injection".to_string());
        }
        if name_lower.contains("xml") || name_lower.contains("soap") {
            recommendations.push("xxe".to_string());
        }
        if name_lower.contains("ldap") {
            recommendations.push("ldap_injection".to_string());
        }

        // Source-based recommendations
        if context.sources.contains(&ParameterSource::Header) {
            recommendations.push("host_header_injection".to_string());
            recommendations.push("crlf_injection".to_string());
        }
        if context.sources.contains(&ParameterSource::Cookie) {
            recommendations.push("session_fixation".to_string());
        }

        // General recommendations for string types
        if recommendations.is_empty() || context.value_type == ValueType::String {
            recommendations.push("xss".to_string());
            recommendations.push("sqli".to_string());
        }

        recommendations.sort();
        recommendations.dedup();
        recommendations
    }
}

// ============================================================================
// Deduplicated Targets (Output)
// ============================================================================

/// The output of the attack surface analysis
#[derive(Debug, Clone)]
pub struct DeduplicatedTargets {
    /// Unique endpoints to test
    pub unique_endpoints: Vec<TestEndpoint>,
    /// Unique forms to test
    pub unique_forms: Vec<TestForm>,
    /// Unique parameters with context
    pub unique_parameters: Vec<TestParameter>,
    /// Original count before deduplication
    pub total_original: usize,
    /// Count after deduplication
    pub total_deduplicated: usize,
    /// Reduction percentage
    pub reduction_percent: f32,
}

impl DeduplicatedTargets {
    /// Get statistics as a formatted string
    pub fn stats(&self) -> String {
        format!(
            "Attack Surface Analysis:\n\
             - Original targets: {}\n\
             - Deduplicated targets: {}\n\
             - Reduction: {:.1}%\n\
             - Unique endpoints: {}\n\
             - Unique forms: {}\n\
             - Unique parameters: {}",
            self.total_original,
            self.total_deduplicated,
            self.reduction_percent,
            self.unique_endpoints.len(),
            self.unique_forms.len(),
            self.unique_parameters.len()
        )
    }

    /// Get high priority parameters (score >= 7)
    pub fn high_priority_parameters(&self) -> Vec<&TestParameter> {
        self.unique_parameters
            .iter()
            .filter(|p| p.context.priority_score >= 7)
            .collect()
    }

    /// Sort parameters by priority score (descending)
    pub fn parameters_by_priority(&self) -> Vec<&TestParameter> {
        let mut params: Vec<_> = self.unique_parameters.iter().collect();
        params.sort_by(|a, b| b.context.priority_score.cmp(&a.context.priority_score));
        params
    }
}

// ============================================================================
// Attack Surface Builder
// ============================================================================

/// Builder for attack surface analysis with deduplication
pub struct AttackSurface {
    /// Endpoints by signature
    endpoints: HashMap<EndpointSignature, Vec<String>>,
    /// Parameters by name
    parameters: HashMap<String, ParameterContext>,
    /// Forms by signature
    forms: HashMap<FormSignature, FormData>,
    /// Track original counts
    original_endpoint_count: usize,
    original_form_count: usize,
    original_param_count: usize,
}

impl AttackSurface {
    /// Create a new attack surface builder
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            parameters: HashMap::new(),
            forms: HashMap::new(),
            original_endpoint_count: 0,
            original_form_count: 0,
            original_param_count: 0,
        }
    }

    /// Add an endpoint to the attack surface
    pub fn add_endpoint(&mut self, url: &str, method: &str, params: &[String]) {
        self.add_endpoint_with_content_type(url, method, params, ContentType::default());
    }

    /// Add an endpoint with explicit content type
    pub fn add_endpoint_with_content_type(
        &mut self,
        url: &str,
        method: &str,
        params: &[String],
        content_type: ContentType,
    ) {
        self.original_endpoint_count += 1;

        let signature = EndpointSignature::new(method, url, params, content_type);

        self.endpoints
            .entry(signature)
            .or_insert_with(Vec::new)
            .push(url.to_string());

        debug!(
            "[AttackSurface] Added endpoint: {} {} (normalized: {})",
            method,
            url,
            PathNormalizer::normalize(url)
        );
    }

    /// Add a form to the attack surface
    pub fn add_form(&mut self, action: &str, method: &str, fields: &[FormInput]) {
        self.add_form_with_source(action, method, fields, action);
    }

    /// Add a form with source page tracking
    pub fn add_form_with_source(
        &mut self,
        action: &str,
        method: &str,
        fields: &[FormInput],
        source_page: &str,
    ) {
        self.original_form_count += 1;

        let signature = FormSignature::new(action, method, fields);

        match self.forms.get_mut(&signature) {
            Some(form_data) => {
                if !form_data.discovered_at.contains(&source_page.to_string()) {
                    form_data.discovered_at.push(source_page.to_string());
                }
            }
            None => {
                self.forms.insert(
                    signature,
                    FormData {
                        action: action.to_string(),
                        method: method.to_uppercase(),
                        fields: fields.to_vec(),
                        discovered_at: vec![source_page.to_string()],
                    },
                );
            }
        }

        debug!(
            "[AttackSurface] Added form: {} {} with {} fields",
            method,
            action,
            fields.len()
        );
    }

    /// Add a parameter to the attack surface
    pub fn add_parameter(&mut self, name: &str, source: ParameterSource, endpoint: &str) {
        self.add_parameter_with_value(name, source, endpoint, None);
    }

    /// Add a parameter with a sample value
    pub fn add_parameter_with_value(
        &mut self,
        name: &str,
        source: ParameterSource,
        endpoint: &str,
        value: Option<&str>,
    ) {
        self.original_param_count += 1;

        match self.parameters.get_mut(name) {
            Some(ctx) => {
                ctx.add_source(source);
                ctx.add_endpoint(endpoint);
                if let Some(v) = value {
                    ctx.add_sample_value(v);
                }
            }
            None => {
                let mut ctx = ParameterContext::new(name, source, endpoint);
                if let Some(v) = value {
                    ctx.add_sample_value(v);
                }
                self.parameters.insert(name.to_string(), ctx);
            }
        }
    }

    /// Add parameters extracted from a URL's query string
    pub fn add_url_parameters(&mut self, url: &str) {
        if let Ok(parsed) = url::Url::parse(url) {
            for (key, value) in parsed.query_pairs() {
                self.add_parameter_with_value(&key, ParameterSource::Url, url, Some(&value));
            }
        }
    }

    /// Add all parameters from form fields
    pub fn add_form_parameters(&mut self, fields: &[FormInput], endpoint: &str) {
        for field in fields {
            let source = if field.input_type == "file" {
                ParameterSource::MultipartField
            } else {
                ParameterSource::Form
            };

            self.add_parameter_with_value(&field.name, source, endpoint, field.value.as_deref());
        }
    }

    /// Build the deduplicated targets
    pub fn build(self) -> DeduplicatedTargets {
        let total_original =
            self.original_endpoint_count + self.original_form_count + self.original_param_count;

        // Build unique endpoints
        let unique_endpoints: Vec<TestEndpoint> = self
            .endpoints
            .into_iter()
            .map(|(signature, urls)| {
                let representative = urls.first().cloned().unwrap_or_default();
                TestEndpoint {
                    signature: signature.clone(),
                    representative_url: representative,
                    similar_urls: urls,
                    parameters: signature.param_names,
                }
            })
            .collect();

        // Build unique forms
        let unique_forms: Vec<TestForm> = self
            .forms
            .into_iter()
            .map(|(signature, data)| TestForm {
                signature,
                action: data.action,
                method: data.method,
                fields: data.fields,
                found_on_pages: data.discovered_at,
            })
            .collect();

        // Build unique parameters with recommendations
        let unique_parameters: Vec<TestParameter> = self
            .parameters
            .into_iter()
            .map(|(name, context)| {
                let recommendations = TestParameter::generate_recommendations(&context);
                TestParameter {
                    name,
                    context,
                    recommended_tests: recommendations,
                }
            })
            .collect();

        let total_deduplicated =
            unique_endpoints.len() + unique_forms.len() + unique_parameters.len();

        let reduction_percent = if total_original > 0 {
            ((total_original - total_deduplicated) as f32 / total_original as f32) * 100.0
        } else {
            0.0
        };

        DeduplicatedTargets {
            unique_endpoints,
            unique_forms,
            unique_parameters,
            total_original,
            total_deduplicated,
            reduction_percent,
        }
    }

    /// Get current statistics without consuming the builder
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.endpoints.len(),
            self.forms.len(),
            self.parameters.len(),
        )
    }
}

impl Default for AttackSurface {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_normalization_numeric_id() {
        let url = "https://example.com/api/users/123";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/api/users/{id}");
    }

    #[test]
    fn test_path_normalization_uuid() {
        let url = "https://example.com/api/orders/550e8400-e29b-41d4-a716-446655440000";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/api/orders/{uuid}");
    }

    #[test]
    fn test_path_normalization_slug() {
        let url = "https://example.com/products/comfortable-running-shoes";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/products/{slug}");
    }

    #[test]
    fn test_path_normalization_date() {
        let url = "https://example.com/events/2024-01-15";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/events/{date}");
    }

    #[test]
    fn test_path_normalization_mixed() {
        let url =
            "https://example.com/api/v2/users/123/orders/550e8400-e29b-41d4-a716-446655440000";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/api/v2/users/{id}/orders/{uuid}");
    }

    #[test]
    fn test_path_normalization_mongo_id() {
        let url = "https://example.com/api/items/507f1f77bcf86cd799439011";
        let normalized = PathNormalizer::normalize(url);
        assert_eq!(normalized, "/api/items/{hex_id}");
    }

    #[test]
    fn test_endpoint_signature_equality() {
        let sig1 = EndpointSignature::new(
            "GET",
            "https://example.com/api/users/123",
            &["name".to_string(), "email".to_string()],
            ContentType::Json,
        );
        let sig2 = EndpointSignature::new(
            "GET",
            "https://example.com/api/users/456",
            &["email".to_string(), "name".to_string()],
            ContentType::Json,
        );
        // Same normalized path, same params (sorted), same method = equal
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_form_signature_equality() {
        let fields1 = vec![
            FormInput {
                name: "email".to_string(),
                input_type: "text".to_string(),
                value: None,
                options: None,
                required: true,
            },
            FormInput {
                name: "password".to_string(),
                input_type: "password".to_string(),
                value: None,
                options: None,
                required: true,
            },
        ];
        let fields2 = vec![
            FormInput {
                name: "password".to_string(),
                input_type: "password".to_string(),
                value: None,
                options: None,
                required: false,
            },
            FormInput {
                name: "email".to_string(),
                input_type: "text".to_string(),
                value: Some("test@test.com".to_string()),
                options: None,
                required: false,
            },
        ];

        let sig1 = FormSignature::new("/login", "POST", &fields1);
        let sig2 = FormSignature::new("/login", "POST", &fields2);

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_value_type_detection() {
        assert_eq!(ValueType::detect("123"), ValueType::Numeric);
        assert_eq!(ValueType::detect("true"), ValueType::Boolean);
        assert_eq!(ValueType::detect("test@example.com"), ValueType::Email);
        assert_eq!(
            ValueType::detect("550e8400-e29b-41d4-a716-446655440000"),
            ValueType::UUID
        );
        assert_eq!(ValueType::detect("2024-01-15"), ValueType::Date);
        assert_eq!(ValueType::detect("https://example.com"), ValueType::Url);
        assert_eq!(ValueType::detect("hello world"), ValueType::String);
    }

    #[test]
    fn test_parameter_priority() {
        // High priority
        assert!(ParameterContext::calculate_base_priority("password") >= 9);
        assert!(ParameterContext::calculate_base_priority("api_key") >= 9);
        assert!(ParameterContext::calculate_base_priority("email") >= 8);

        // Medium priority
        assert!(ParameterContext::calculate_base_priority("filepath") >= 6);

        // Low priority
        assert!(ParameterContext::calculate_base_priority("user_id") <= 4);
        assert!(ParameterContext::calculate_base_priority("page") <= 3);
    }

    #[test]
    fn test_attack_surface_deduplication() {
        let mut surface = AttackSurface::new();

        // Add same endpoint pattern with different IDs
        surface.add_endpoint("https://example.com/api/users/123", "GET", &[]);
        surface.add_endpoint("https://example.com/api/users/456", "GET", &[]);
        surface.add_endpoint("https://example.com/api/users/789", "GET", &[]);

        // Add same form from different pages
        let fields = vec![FormInput {
            name: "email".to_string(),
            input_type: "text".to_string(),
            value: None,
            options: None,
            required: true,
        }];
        surface.add_form_with_source("/submit", "POST", &fields, "/page1");
        surface.add_form_with_source("/submit", "POST", &fields, "/page2");
        surface.add_form_with_source("/submit", "POST", &fields, "/page3");

        let targets = surface.build();

        // Should deduplicate to 1 endpoint (all /api/users/{id})
        assert_eq!(targets.unique_endpoints.len(), 1);
        assert_eq!(targets.unique_endpoints[0].similar_urls.len(), 3);

        // Should deduplicate to 1 form
        assert_eq!(targets.unique_forms.len(), 1);
        assert_eq!(targets.unique_forms[0].found_on_pages.len(), 3);

        // Check reduction
        assert!(targets.reduction_percent > 0.0);
    }

    #[test]
    fn test_attack_surface_builder_pattern() {
        let mut surface = AttackSurface::new();

        surface.add_endpoint(
            "https://example.com/api/test",
            "POST",
            &["name".to_string()],
        );
        surface.add_form(
            "/login",
            "POST",
            &[FormInput {
                name: "username".to_string(),
                input_type: "text".to_string(),
                value: None,
                options: None,
                required: true,
            }],
        );
        surface.add_parameter("search", ParameterSource::Url, "/search");

        let (endpoints, forms, params) = surface.stats();
        assert_eq!(endpoints, 1);
        assert_eq!(forms, 1);
        assert_eq!(params, 1);

        let targets = surface.build();
        assert_eq!(targets.unique_endpoints.len(), 1);
        assert_eq!(targets.unique_forms.len(), 1);
        assert_eq!(targets.unique_parameters.len(), 1);
    }

    #[test]
    fn test_content_type_parsing() {
        assert_eq!(
            ContentType::from_header("application/json"),
            ContentType::Json
        );
        assert_eq!(
            ContentType::from_header("application/x-www-form-urlencoded"),
            ContentType::FormUrlEncoded
        );
        assert_eq!(
            ContentType::from_header("multipart/form-data; boundary=----"),
            ContentType::Multipart
        );
        assert_eq!(
            ContentType::from_header("application/xml"),
            ContentType::Xml
        );
    }

    #[test]
    fn test_parameter_source_risk_multiplier() {
        assert!(
            ParameterSource::Header.risk_multiplier() > ParameterSource::Form.risk_multiplier()
        );
        assert!(ParameterSource::Cookie.risk_multiplier() > ParameterSource::Url.risk_multiplier());
    }

    #[test]
    fn test_test_parameter_recommendations() {
        let mut context = ParameterContext::new("filepath", ParameterSource::Url, "/download");
        context.add_sample_value("/etc/passwd");

        let recommendations = TestParameter::generate_recommendations(&context);
        assert!(recommendations.contains(&"path_traversal".to_string()));
    }

    #[test]
    fn test_jwt_detection() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(ValueType::detect(jwt), ValueType::Jwt);
    }

    #[test]
    fn test_high_priority_parameters() {
        let mut surface = AttackSurface::new();

        surface.add_parameter("password", ParameterSource::Form, "/login");
        surface.add_parameter("page", ParameterSource::Url, "/list");
        surface.add_parameter("email", ParameterSource::Form, "/register");

        let targets = surface.build();
        let high_priority = targets.high_priority_parameters();

        // password and email should be high priority
        assert!(high_priority.len() >= 1);
        assert!(high_priority.iter().any(|p| p.name == "password"));
    }

    #[test]
    fn test_path_hash_normalization() {
        let url1 = "https://example.com/files/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        let url2 = "https://example.com/files/f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4";

        let norm1 = PathNormalizer::normalize(url1);
        let norm2 = PathNormalizer::normalize(url2);

        assert_eq!(norm1, norm2);
        assert_eq!(norm1, "/files/{hash}");
    }
}
