// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - OpenAPI/Swagger Specification Analyzer
 *
 * Context-aware security analyzer for OpenAPI 2.0 (Swagger) and 3.x specifications.
 *
 * Detects:
 * - Missing security definitions
 * - Weak authentication schemes
 * - OAuth2 scope analysis issues
 * - API key exposure risks
 * - Missing HTTPS requirement
 * - Endpoints without authentication
 * - Dangerous operations (DELETE, PATCH) without auth
 * - Admin/debug endpoints exposed
 * - Missing parameter validation
 * - Weak regex patterns
 * - No length limits on strings
 * - Sensitive data in examples
 * - Hardcoded credentials in spec
 * - Internal server names/IPs
 * - Deprecated endpoints still accessible
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

mod uuid {
    pub use uuid::Uuid;
}

/// Common paths where OpenAPI specs are served
const OPENAPI_PATHS: &[&str] = &[
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/swagger.json",
    "/docs/openapi.json",
    "/openapi/v3/api-docs",
    "/.well-known/openapi.json",
    "/openapi.yaml",
    "/swagger.yaml",
    "/api-docs.yaml",
];

/// Common Swagger UI paths
const SWAGGER_UI_PATHS: &[&str] = &[
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger-ui/",
    "/swagger/",
    "/api/swagger-ui.html",
    "/docs/",
    "/api-docs/",
    "/api/docs",
    "/redoc",
    "/rapidoc",
];

/// Sensitive data patterns to check in examples and defaults
const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    (r#"(?i)password\s*[:=]\s*["'][^"']+["']"#, "hardcoded password"),
    (r#"(?i)api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']"#, "API key"),
    (r#"(?i)secret\s*[:=]\s*["'][^"']+["']"#, "secret value"),
    (r#"(?i)token\s*[:=]\s*["'][a-zA-Z0-9._-]{20,}["']"#, "token value"),
    (r"(?i)bearer\s+[a-zA-Z0-9._-]{20,}", "bearer token"),
    (r#"(?i)authorization\s*[:=]\s*["']basic\s+[a-zA-Z0-9+/=]+["']"#, "basic auth"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email address"),
    (r#"(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["']AKIA[A-Z0-9]{16}["']"#, "AWS access key"),
    (r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']"#, "AWS secret key"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "internal IP address"),
    (r"(?i)(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "private IP address"),
    (r"(?i)localhost|127\.0\.0\.1|0\.0\.0\.0", "localhost reference"),
    (r"(?i)internal[._-]?(?:api|server|host)", "internal hostname"),
    (r"(?i)(?:dev|staging|test)[._-]", "non-production environment"),
];

/// Admin/debug endpoint patterns
const ADMIN_PATTERNS: &[&str] = &[
    r"(?i)/admin",
    r"(?i)/debug",
    r"(?i)/internal",
    r"(?i)/management",
    r"(?i)/actuator",
    r"(?i)/metrics",
    r"(?i)/health",
    r"(?i)/status",
    r"(?i)/config",
    r"(?i)/settings",
    r"(?i)/system",
    r"(?i)/console",
    r"(?i)/shell",
    r"(?i)/exec",
    r"(?i)/eval",
    r"(?i)/test",
    r"(?i)/_",
];

/// Dangerous HTTP methods that should require authentication
const DANGEROUS_METHODS: &[&str] = &["DELETE", "PUT", "PATCH", "POST"];

/// Detected OpenAPI specification version
#[derive(Debug, Clone, PartialEq)]
pub enum OpenApiVersion {
    Swagger2,
    OpenApi30,
    OpenApi31,
    Unknown,
}

impl std::fmt::Display for OpenApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenApiVersion::Swagger2 => write!(f, "Swagger 2.0"),
            OpenApiVersion::OpenApi30 => write!(f, "OpenAPI 3.0"),
            OpenApiVersion::OpenApi31 => write!(f, "OpenAPI 3.1"),
            OpenApiVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Parsed OpenAPI specification
#[derive(Debug, Clone)]
pub struct OpenApiSpec {
    pub version: OpenApiVersion,
    pub title: String,
    pub description: Option<String>,
    pub servers: Vec<String>,
    pub base_path: Option<String>,
    pub security_definitions: HashMap<String, SecurityScheme>,
    pub global_security: Vec<SecurityRequirement>,
    pub endpoints: Vec<Endpoint>,
    pub raw_spec: Value,
    pub spec_url: String,
}

/// Security scheme definition
#[derive(Debug, Clone)]
pub struct SecurityScheme {
    pub scheme_type: String,
    pub name: Option<String>,
    pub in_location: Option<String>,
    pub scheme: Option<String>,
    pub flows: Option<Value>,
    pub bearer_format: Option<String>,
    pub openid_connect_url: Option<String>,
}

/// Security requirement (name -> scopes)
#[derive(Debug, Clone)]
pub struct SecurityRequirement {
    pub scheme_name: String,
    pub scopes: Vec<String>,
}

/// API endpoint definition
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub path: String,
    pub method: String,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub security: Option<Vec<SecurityRequirement>>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub deprecated: bool,
    pub tags: Vec<String>,
}

/// Parameter definition
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub in_location: String,
    pub required: bool,
    pub param_type: Option<String>,
    pub format: Option<String>,
    pub pattern: Option<String>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enum_values: Option<Vec<String>>,
    pub example: Option<Value>,
    pub default: Option<Value>,
}

/// Request body definition
#[derive(Debug, Clone)]
pub struct RequestBody {
    pub required: bool,
    pub content_types: Vec<String>,
    pub schema: Option<Value>,
}

/// Security issue found in the spec
#[derive(Debug, Clone)]
pub struct SecurityIssue {
    pub issue_type: String,
    pub severity: Severity,
    pub location: String,
    pub description: String,
    pub recommendation: String,
    pub cwe: String,
}

/// OpenAPI/Swagger Specification Analyzer
pub struct OpenApiAnalyzer {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl OpenApiAnalyzer {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("openapi-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run OpenAPI security analysis
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
        }

        info!("[OpenAPI] Starting OpenAPI/Swagger specification analysis on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // First, check if this looks like an API application
        let baseline_response = self.http_client.get(url).await?;
        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        // Skip if this is a pure static site with no API indicators
        if characteristics.is_static && !characteristics.is_api {
            debug!("[OpenAPI] Static site detected with no API indicators - skipping OpenAPI scan");
            return Ok((all_vulnerabilities, total_tests));
        }

        // Step 1: Discover OpenAPI specifications
        total_tests += 1;
        let discovered_specs = self.discover_openapi_specs(url).await?;

        if discovered_specs.is_empty() {
            debug!("[OpenAPI] No OpenAPI specifications found at {}", url);
            return Ok((all_vulnerabilities, total_tests));
        }

        info!("[OpenAPI] Found {} OpenAPI specification(s)", discovered_specs.len());

        // Step 2: Analyze each discovered specification
        for spec in discovered_specs {
            info!("[OpenAPI] Analyzing {} specification at {}", spec.version, spec.spec_url);

            // Analyze security definitions
            let (vulns, tests) = self.analyze_security_definitions(&spec, url).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Analyze endpoints
            let (vulns, tests) = self.analyze_endpoints(&spec, url).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Analyze input validation
            let (vulns, tests) = self.analyze_input_validation(&spec, url).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Check for information disclosure
            let (vulns, tests) = self.analyze_information_disclosure(&spec, url).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Check deprecated features
            let (vulns, tests) = self.analyze_deprecated_features(&spec, url).await;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Check for Swagger UI exposure
            let (vulns, tests) = self.check_swagger_ui_exposure(url).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;
        }

        info!(
            "[OpenAPI] Analysis completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Discover OpenAPI specifications at common paths
    async fn discover_openapi_specs(&self, base_url: &str) -> Result<Vec<OpenApiSpec>> {
        let mut specs = Vec::new();
        let base = base_url.trim_end_matches('/');

        for path in OPENAPI_PATHS {
            let spec_url = format!("{}{}", base, path);
            debug!("[OpenAPI] Checking for spec at {}", spec_url);

            match self.http_client.get(&spec_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if let Some(spec) = self.parse_openapi_spec(&response.body, &spec_url) {
                            info!("[OpenAPI] Found {} spec at {}", spec.version, spec_url);
                            specs.push(spec);
                            // Continue checking other paths as there might be multiple versions
                        }
                    }
                }
                Err(e) => {
                    debug!("[OpenAPI] Failed to fetch {}: {}", spec_url, e);
                }
            }
        }

        Ok(specs)
    }

    /// Parse OpenAPI/Swagger specification from JSON or YAML
    fn parse_openapi_spec(&self, content: &str, spec_url: &str) -> Option<OpenApiSpec> {
        // Try JSON first
        let json_value: Value = if content.trim().starts_with('{') {
            serde_json::from_str(content).ok()?
        } else {
            // Try YAML
            serde_yaml::from_str(content).ok()?
        };

        // Detect version
        let version = self.detect_version(&json_value);
        if version == OpenApiVersion::Unknown {
            debug!("[OpenAPI] Could not determine OpenAPI version");
            return None;
        }

        // Parse based on version
        match version {
            OpenApiVersion::Swagger2 => self.parse_swagger2(&json_value, spec_url),
            OpenApiVersion::OpenApi30 | OpenApiVersion::OpenApi31 => {
                self.parse_openapi3(&json_value, spec_url, version.clone())
            }
            _ => None,
        }
    }

    /// Detect OpenAPI/Swagger version
    fn detect_version(&self, spec: &Value) -> OpenApiVersion {
        // Check for OpenAPI 3.x
        if let Some(openapi) = spec.get("openapi").and_then(|v| v.as_str()) {
            if openapi.starts_with("3.1") {
                return OpenApiVersion::OpenApi31;
            } else if openapi.starts_with("3.0") || openapi.starts_with("3.") {
                return OpenApiVersion::OpenApi30;
            }
        }

        // Check for Swagger 2.0
        if let Some(swagger) = spec.get("swagger").and_then(|v| v.as_str()) {
            if swagger == "2.0" {
                return OpenApiVersion::Swagger2;
            }
        }

        OpenApiVersion::Unknown
    }

    /// Parse Swagger 2.0 specification
    fn parse_swagger2(&self, spec: &Value, spec_url: &str) -> Option<OpenApiSpec> {
        let info = spec.get("info")?;
        let title = info.get("title").and_then(|v| v.as_str()).unwrap_or("Unknown API").to_string();
        let description = info.get("description").and_then(|v| v.as_str()).map(String::from);

        // Parse host and basePath
        let host = spec.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let base_path = spec.get("basePath").and_then(|v| v.as_str()).map(String::from);
        let schemes = spec.get("schemes")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["https"]);

        let servers: Vec<String> = schemes.iter()
            .map(|scheme| format!("{}://{}{}", scheme, host, base_path.as_deref().unwrap_or("")))
            .collect();

        // Parse security definitions
        let security_definitions = self.parse_swagger2_security_definitions(spec);

        // Parse global security
        let global_security = self.parse_security_requirements(spec.get("security"));

        // Parse paths/endpoints
        let endpoints = self.parse_swagger2_paths(spec);

        Some(OpenApiSpec {
            version: OpenApiVersion::Swagger2,
            title,
            description,
            servers,
            base_path,
            security_definitions,
            global_security,
            endpoints,
            raw_spec: spec.clone(),
            spec_url: spec_url.to_string(),
        })
    }

    /// Parse OpenAPI 3.x specification
    fn parse_openapi3(&self, spec: &Value, spec_url: &str, version: OpenApiVersion) -> Option<OpenApiSpec> {
        let info = spec.get("info")?;
        let title = info.get("title").and_then(|v| v.as_str()).unwrap_or("Unknown API").to_string();
        let description = info.get("description").and_then(|v| v.as_str()).map(String::from);

        // Parse servers
        let servers = spec.get("servers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.get("url").and_then(|u| u.as_str()))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        // Parse security schemes from components
        let security_definitions = self.parse_openapi3_security_schemes(spec);

        // Parse global security
        let global_security = self.parse_security_requirements(spec.get("security"));

        // Parse paths/endpoints
        let endpoints = self.parse_openapi3_paths(spec);

        Some(OpenApiSpec {
            version,
            title,
            description,
            servers,
            base_path: None,
            security_definitions,
            global_security,
            endpoints,
            raw_spec: spec.clone(),
            spec_url: spec_url.to_string(),
        })
    }

    /// Parse Swagger 2.0 security definitions
    fn parse_swagger2_security_definitions(&self, spec: &Value) -> HashMap<String, SecurityScheme> {
        let mut schemes = HashMap::new();

        if let Some(defs) = spec.get("securityDefinitions").and_then(|v| v.as_object()) {
            for (name, def) in defs {
                let scheme = SecurityScheme {
                    scheme_type: def.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    name: def.get("name").and_then(|v| v.as_str()).map(String::from),
                    in_location: def.get("in").and_then(|v| v.as_str()).map(String::from),
                    scheme: None,
                    flows: def.get("flow").cloned().or_else(|| def.get("scopes").cloned()),
                    bearer_format: None,
                    openid_connect_url: def.get("authorizationUrl").and_then(|v| v.as_str()).map(String::from),
                };
                schemes.insert(name.clone(), scheme);
            }
        }

        schemes
    }

    /// Parse OpenAPI 3.x security schemes
    fn parse_openapi3_security_schemes(&self, spec: &Value) -> HashMap<String, SecurityScheme> {
        let mut schemes = HashMap::new();

        if let Some(components) = spec.get("components") {
            if let Some(security_schemes) = components.get("securitySchemes").and_then(|v| v.as_object()) {
                for (name, def) in security_schemes {
                    let scheme = SecurityScheme {
                        scheme_type: def.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        name: def.get("name").and_then(|v| v.as_str()).map(String::from),
                        in_location: def.get("in").and_then(|v| v.as_str()).map(String::from),
                        scheme: def.get("scheme").and_then(|v| v.as_str()).map(String::from),
                        flows: def.get("flows").cloned(),
                        bearer_format: def.get("bearerFormat").and_then(|v| v.as_str()).map(String::from),
                        openid_connect_url: def.get("openIdConnectUrl").and_then(|v| v.as_str()).map(String::from),
                    };
                    schemes.insert(name.clone(), scheme);
                }
            }
        }

        schemes
    }

    /// Parse security requirements
    fn parse_security_requirements(&self, security: Option<&Value>) -> Vec<SecurityRequirement> {
        let mut requirements = Vec::new();

        if let Some(security_array) = security.and_then(|v| v.as_array()) {
            for item in security_array {
                if let Some(obj) = item.as_object() {
                    for (name, scopes) in obj {
                        let scope_vec = scopes.as_array()
                            .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        requirements.push(SecurityRequirement {
                            scheme_name: name.clone(),
                            scopes: scope_vec,
                        });
                    }
                }
            }
        }

        requirements
    }

    /// Parse Swagger 2.0 paths
    fn parse_swagger2_paths(&self, spec: &Value) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        if let Some(paths) = spec.get("paths").and_then(|v| v.as_object()) {
            for (path, methods) in paths {
                if let Some(methods_obj) = methods.as_object() {
                    for (method, operation) in methods_obj {
                        // Skip non-HTTP method keys like "parameters"
                        if !["get", "post", "put", "delete", "patch", "options", "head"].contains(&method.to_lowercase().as_str()) {
                            continue;
                        }

                        let endpoint = self.parse_operation(path, method, operation, false);
                        endpoints.push(endpoint);
                    }
                }
            }
        }

        endpoints
    }

    /// Parse OpenAPI 3.x paths
    fn parse_openapi3_paths(&self, spec: &Value) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        if let Some(paths) = spec.get("paths").and_then(|v| v.as_object()) {
            for (path, methods) in paths {
                if let Some(methods_obj) = methods.as_object() {
                    for (method, operation) in methods_obj {
                        // Skip non-HTTP method keys like "parameters", "summary", "description"
                        if !["get", "post", "put", "delete", "patch", "options", "head", "trace"].contains(&method.to_lowercase().as_str()) {
                            continue;
                        }

                        let endpoint = self.parse_operation(path, method, operation, true);
                        endpoints.push(endpoint);
                    }
                }
            }
        }

        endpoints
    }

    /// Parse an operation (endpoint) definition
    fn parse_operation(&self, path: &str, method: &str, operation: &Value, is_openapi3: bool) -> Endpoint {
        let operation_id = operation.get("operationId").and_then(|v| v.as_str()).map(String::from);
        let summary = operation.get("summary").and_then(|v| v.as_str()).map(String::from);
        let description = operation.get("description").and_then(|v| v.as_str()).map(String::from);
        let deprecated = operation.get("deprecated").and_then(|v| v.as_bool()).unwrap_or(false);

        let tags = operation.get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let security = if operation.get("security").is_some() {
            Some(self.parse_security_requirements(operation.get("security")))
        } else {
            None
        };

        let parameters = self.parse_parameters(operation.get("parameters"), is_openapi3);

        let request_body = if is_openapi3 {
            self.parse_request_body(operation.get("requestBody"))
        } else {
            // In Swagger 2.0, body parameters are in the parameters array
            None
        };

        Endpoint {
            path: path.to_string(),
            method: method.to_uppercase(),
            operation_id,
            summary,
            description,
            security,
            parameters,
            request_body,
            deprecated,
            tags,
        }
    }

    /// Parse parameters
    fn parse_parameters(&self, params: Option<&Value>, _is_openapi3: bool) -> Vec<Parameter> {
        let mut parameters = Vec::new();

        if let Some(params_array) = params.and_then(|v| v.as_array()) {
            for param in params_array {
                let name = param.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let in_location = param.get("in").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let required = param.get("required").and_then(|v| v.as_bool()).unwrap_or(false);

                // Schema might be nested or direct
                let schema = param.get("schema").unwrap_or(param);

                let param_type = schema.get("type").and_then(|v| v.as_str()).map(String::from);
                let format = schema.get("format").and_then(|v| v.as_str()).map(String::from);
                let pattern = schema.get("pattern").and_then(|v| v.as_str()).map(String::from);
                let min_length = schema.get("minLength").and_then(|v| v.as_u64());
                let max_length = schema.get("maxLength").and_then(|v| v.as_u64());
                let minimum = schema.get("minimum").and_then(|v| v.as_f64());
                let maximum = schema.get("maximum").and_then(|v| v.as_f64());

                let enum_values = schema.get("enum")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|e| e.as_str().map(String::from)).collect());

                let example = param.get("example").or_else(|| schema.get("example")).cloned();
                let default = param.get("default").or_else(|| schema.get("default")).cloned();

                parameters.push(Parameter {
                    name,
                    in_location,
                    required,
                    param_type,
                    format,
                    pattern,
                    min_length,
                    max_length,
                    minimum,
                    maximum,
                    enum_values,
                    example,
                    default,
                });
            }
        }

        parameters
    }

    /// Parse request body (OpenAPI 3.x)
    fn parse_request_body(&self, body: Option<&Value>) -> Option<RequestBody> {
        let body = body?;

        let required = body.get("required").and_then(|v| v.as_bool()).unwrap_or(false);

        let content = body.get("content").and_then(|v| v.as_object())?;

        let content_types: Vec<String> = content.keys().cloned().collect();

        // Get schema from the first content type
        let schema = content.values()
            .next()
            .and_then(|v| v.get("schema"))
            .cloned();

        Some(RequestBody {
            required,
            content_types,
            schema,
        })
    }

    /// Analyze security definitions
    async fn analyze_security_definitions(&self, spec: &OpenApiSpec, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        tests_run += 1;

        // Check for missing security definitions
        if spec.security_definitions.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OpenAPI Missing Security Definitions",
                base_url,
                &format!("The {} specification at {} has no security schemes defined. All endpoints may be publicly accessible.", spec.version, spec.spec_url),
                Severity::High,
                "CWE-306",
                &spec.spec_url,
            ));
        }

        // Check for missing global security
        tests_run += 1;
        if spec.global_security.is_empty() && !spec.security_definitions.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OpenAPI Missing Global Security",
                base_url,
                "No global security requirements defined. Each endpoint must explicitly declare security requirements.",
                Severity::Medium,
                "CWE-1059",
                &spec.spec_url,
            ));
        }

        // Analyze each security scheme
        for (name, scheme) in &spec.security_definitions {
            tests_run += 1;

            // Check for API key in query parameter (insecure)
            if scheme.scheme_type == "apiKey" {
                if let Some(ref location) = scheme.in_location {
                    if location == "query" {
                        vulnerabilities.push(self.create_vulnerability(
                            "OpenAPI API Key in Query Parameter",
                            base_url,
                            &format!("Security scheme '{}' places API key in query parameter. This exposes the key in URLs, browser history, and server logs.", name),
                            Severity::Medium,
                            "CWE-598",
                            &spec.spec_url,
                        ));
                    }
                }
            }

            // Check for basic auth without HTTPS requirement
            if scheme.scheme_type == "basic" || (scheme.scheme_type == "http" && scheme.scheme.as_deref() == Some("basic")) {
                let has_https = spec.servers.iter().all(|s| s.starts_with("https://"));
                if !has_https && !spec.servers.is_empty() {
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Basic Auth Without HTTPS",
                        base_url,
                        &format!("Security scheme '{}' uses Basic authentication but HTTPS is not enforced. Credentials may be transmitted in plaintext.", name),
                        Severity::High,
                        "CWE-319",
                        &spec.spec_url,
                    ));
                }
            }

            // Check for OAuth2 with implicit flow (deprecated)
            if scheme.scheme_type == "oauth2" {
                if let Some(ref flows) = scheme.flows {
                    if flows.get("implicit").is_some() {
                        vulnerabilities.push(self.create_vulnerability(
                            "OpenAPI OAuth2 Implicit Flow",
                            base_url,
                            &format!("Security scheme '{}' uses OAuth2 implicit flow, which is deprecated and insecure. Use authorization code flow with PKCE instead.", name),
                            Severity::Medium,
                            "CWE-1059",
                            &spec.spec_url,
                        ));
                    }
                }
            }
        }

        // Check for HTTPS requirement
        tests_run += 1;
        if !spec.servers.is_empty() {
            let non_https_servers: Vec<_> = spec.servers.iter()
                .filter(|s| !s.starts_with("https://") && !s.starts_with("{"))
                .collect();

            if !non_https_servers.is_empty() {
                vulnerabilities.push(self.create_vulnerability(
                    "OpenAPI Missing HTTPS Requirement",
                    base_url,
                    &format!("API servers do not enforce HTTPS: {:?}. Sensitive data may be transmitted in plaintext.", non_https_servers),
                    Severity::Medium,
                    "CWE-311",
                    &spec.spec_url,
                ));
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Analyze endpoints for security issues
    async fn analyze_endpoints(&self, spec: &OpenApiSpec, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Compile admin patterns
        let admin_regexes: Vec<Regex> = ADMIN_PATTERNS.iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        for endpoint in &spec.endpoints {
            tests_run += 1;

            // Check for endpoints without authentication
            let has_security = endpoint.security.as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(!spec.global_security.is_empty());

            if !has_security {
                // Check if this is a dangerous method without auth
                if DANGEROUS_METHODS.contains(&endpoint.method.as_str()) {
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Dangerous Operation Without Auth",
                        base_url,
                        &format!("{} {} has no authentication requirement. Dangerous operations should always require authentication.", endpoint.method, endpoint.path),
                        Severity::High,
                        "CWE-306",
                        &spec.spec_url,
                    ));
                }
            }

            // Check for admin/debug endpoints
            for regex in &admin_regexes {
                if regex.is_match(&endpoint.path) {
                    let severity = if has_security { Severity::Low } else { Severity::High };
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Admin/Debug Endpoint Exposed",
                        base_url,
                        &format!("Potentially sensitive endpoint exposed: {} {}. {}",
                            endpoint.method,
                            endpoint.path,
                            if has_security { "Authentication is required." } else { "No authentication required!" }
                        ),
                        severity,
                        "CWE-200",
                        &spec.spec_url,
                    ));
                    break;
                }
            }

            // Check for explicit empty security (security: [])
            if let Some(ref security) = endpoint.security {
                if security.is_empty() {
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Endpoint Explicitly Unauthenticated",
                        base_url,
                        &format!("{} {} explicitly disables authentication (security: []). Verify this is intentional.", endpoint.method, endpoint.path),
                        Severity::Medium,
                        "CWE-306",
                        &spec.spec_url,
                    ));
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Analyze input validation
    async fn analyze_input_validation(&self, spec: &OpenApiSpec, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for endpoint in &spec.endpoints {
            for param in &endpoint.parameters {
                tests_run += 1;

                // Check for string parameters without length limits
                if param.param_type.as_deref() == Some("string") {
                    if param.max_length.is_none() && param.pattern.is_none() && param.enum_values.is_none() {
                        vulnerabilities.push(self.create_vulnerability(
                            "OpenAPI Missing String Validation",
                            base_url,
                            &format!("Parameter '{}' in {} {} is a string with no maxLength, pattern, or enum constraint. This may allow excessively long inputs.", param.name, endpoint.method, endpoint.path),
                            Severity::Low,
                            "CWE-20",
                            &spec.spec_url,
                        ));
                    }
                }

                // Check for weak regex patterns
                if let Some(ref pattern) = param.pattern {
                    if self.is_weak_pattern(pattern) {
                        vulnerabilities.push(self.create_vulnerability(
                            "OpenAPI Weak Validation Pattern",
                            base_url,
                            &format!("Parameter '{}' in {} {} uses a weak regex pattern '{}' that may be bypassable.", param.name, endpoint.method, endpoint.path, pattern),
                            Severity::Low,
                            "CWE-185",
                            &spec.spec_url,
                        ));
                    }
                }

                // Check for missing required validation
                if param.in_location == "path" && !param.required {
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Path Parameter Not Required",
                        base_url,
                        &format!("Path parameter '{}' in {} {} is not marked as required. Path parameters should always be required.", param.name, endpoint.method, endpoint.path),
                        Severity::Low,
                        "CWE-20",
                        &spec.spec_url,
                    ));
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Check if a regex pattern is weak
    fn is_weak_pattern(&self, pattern: &str) -> bool {
        // Very permissive patterns
        let weak_patterns = [
            r"^.*$",
            r"^.+$",
            r".*",
            r".+",
            r"[\s\S]*",
            r"[\s\S]+",
            r"^[^/]+$",  // Often too permissive for path validation
        ];

        weak_patterns.iter().any(|weak| pattern == *weak)
    }

    /// Analyze for information disclosure
    async fn analyze_information_disclosure(&self, spec: &OpenApiSpec, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Convert spec to string for pattern matching
        let spec_string = serde_json::to_string(&spec.raw_spec).unwrap_or_default();

        for (pattern, description) in SENSITIVE_PATTERNS {
            tests_run += 1;

            if let Ok(regex) = Regex::new(pattern) {
                if let Some(capture) = regex.find(&spec_string) {
                    let evidence = &spec_string[capture.start()..capture.end().min(capture.start() + 100)];
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Sensitive Data Exposure",
                        base_url,
                        &format!("OpenAPI specification contains {}: '{}...'", description, evidence),
                        if description.contains("password") || description.contains("secret") || description.contains("AWS") {
                            Severity::High
                        } else if description.contains("internal") || description.contains("localhost") {
                            Severity::Medium
                        } else {
                            Severity::Low
                        },
                        "CWE-200",
                        &spec.spec_url,
                    ));
                }
            }
        }

        // Check for version information disclosure
        tests_run += 1;
        if let Some(info) = spec.raw_spec.get("info") {
            if info.get("version").is_some() {
                // Only flag if it looks like an internal version
                let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if version.contains("dev") || version.contains("internal") || version.contains("snapshot") {
                    vulnerabilities.push(self.create_vulnerability(
                        "OpenAPI Internal Version Exposed",
                        base_url,
                        &format!("API version '{}' suggests internal/development version. This may expose environment information.", version),
                        Severity::Low,
                        "CWE-200",
                        &spec.spec_url,
                    ));
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Analyze deprecated features
    async fn analyze_deprecated_features(&self, spec: &OpenApiSpec, base_url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let mut deprecated_endpoints = Vec::new();

        for endpoint in &spec.endpoints {
            tests_run += 1;

            if endpoint.deprecated {
                deprecated_endpoints.push(format!("{} {}", endpoint.method, endpoint.path));
            }
        }

        if !deprecated_endpoints.is_empty() {
            vulnerabilities.push(self.create_vulnerability(
                "OpenAPI Deprecated Endpoints",
                base_url,
                &format!("{} deprecated endpoint(s) are still documented and potentially accessible: {}",
                    deprecated_endpoints.len(),
                    if deprecated_endpoints.len() <= 5 {
                        deprecated_endpoints.join(", ")
                    } else {
                        format!("{}, and {} more", deprecated_endpoints[..5].join(", "), deprecated_endpoints.len() - 5)
                    }
                ),
                Severity::Low,
                "CWE-1059",
                &spec.spec_url,
            ));
        }

        (vulnerabilities, tests_run)
    }

    /// Check for Swagger UI exposure
    async fn check_swagger_ui_exposure(&self, base_url: &str) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let base = base_url.trim_end_matches('/');

        for path in SWAGGER_UI_PATHS {
            tests_run += 1;
            let ui_url = format!("{}{}", base, path);

            match self.http_client.get(&ui_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        let body_lower = response.body.to_lowercase();
                        if body_lower.contains("swagger-ui") ||
                           body_lower.contains("swagger ui") ||
                           body_lower.contains("redoc") ||
                           body_lower.contains("rapidoc") ||
                           body_lower.contains("api documentation") {
                            vulnerabilities.push(self.create_vulnerability(
                                "OpenAPI Documentation UI Exposed",
                                base_url,
                                &format!("Interactive API documentation is publicly accessible at {}. This may allow attackers to discover and test API endpoints.", ui_url),
                                Severity::Medium,
                                "CWE-200",
                                &ui_url,
                            ));
                            break; // Only report one UI exposure
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        spec_url: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("openapi_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(format!("OpenAPI Spec: {}", spec_url)),
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "OpenAPI Missing Security Definitions" => {
                "Define security schemes in your OpenAPI specification using 'securityDefinitions' (Swagger 2.0) or 'components/securitySchemes' (OpenAPI 3.x). Common schemes include OAuth2, API keys, and HTTP bearer authentication.".to_string()
            }
            "OpenAPI Missing Global Security" => {
                "Add a 'security' property at the root level of your specification to apply security requirements to all endpoints. Use 'security: []' only on endpoints that should be publicly accessible.".to_string()
            }
            "OpenAPI API Key in Query Parameter" => {
                "Move API key authentication from query parameters to HTTP headers. Use 'in: header' instead of 'in: query' in your security scheme definition to prevent exposure in URLs and logs.".to_string()
            }
            "OpenAPI Basic Auth Without HTTPS" => {
                "Enforce HTTPS for all API endpoints, especially those using Basic authentication. Update the 'servers' or 'schemes' in your specification to only include HTTPS URLs.".to_string()
            }
            "OpenAPI OAuth2 Implicit Flow" => {
                "Replace OAuth2 implicit flow with authorization code flow with PKCE (Proof Key for Code Exchange). Update the 'flows' in your OAuth2 security scheme.".to_string()
            }
            "OpenAPI Missing HTTPS Requirement" => {
                "Update your API servers to use HTTPS only. In OpenAPI 3.x, update the 'servers' array. In Swagger 2.0, update the 'schemes' array to only include 'https'.".to_string()
            }
            "OpenAPI Dangerous Operation Without Auth" => {
                "Add security requirements to all endpoints that perform dangerous operations (DELETE, PUT, PATCH, POST). Use the 'security' property on each operation or define global security requirements.".to_string()
            }
            "OpenAPI Admin/Debug Endpoint Exposed" => {
                "Remove or restrict access to administrative and debug endpoints in production. If these endpoints are necessary, ensure they require strong authentication and are not publicly documented.".to_string()
            }
            "OpenAPI Endpoint Explicitly Unauthenticated" => {
                "Review endpoints with 'security: []' to ensure they should be publicly accessible. Document the business reason for unauthenticated access.".to_string()
            }
            "OpenAPI Missing String Validation" => {
                "Add validation constraints to string parameters: 'maxLength' to prevent excessive input, 'pattern' for format validation, or 'enum' for fixed value sets.".to_string()
            }
            "OpenAPI Weak Validation Pattern" => {
                "Use more specific regex patterns for parameter validation. Avoid overly permissive patterns like '.*' or '.+'. Define patterns that match only expected input formats.".to_string()
            }
            "OpenAPI Path Parameter Not Required" => {
                "Mark path parameters as 'required: true'. Path parameters are always required for the URL to be valid.".to_string()
            }
            "OpenAPI Sensitive Data Exposure" => {
                "Remove sensitive data from API specifications including examples, defaults, and descriptions. Use placeholder values and document proper credential management separately.".to_string()
            }
            "OpenAPI Internal Version Exposed" => {
                "Use production-appropriate version numbers in your API specification. Avoid version identifiers that reveal environment information (dev, internal, snapshot).".to_string()
            }
            "OpenAPI Deprecated Endpoints" => {
                "Remove deprecated endpoints from your specification once they are no longer in use. If they must remain documented, ensure they are properly secured and plan for their removal.".to_string()
            }
            "OpenAPI Documentation UI Exposed" => {
                "Restrict access to API documentation in production environments. Consider requiring authentication for documentation access or hosting it on internal networks only.".to_string()
            }
            _ => {
                "Review your OpenAPI specification for security best practices. Consult OWASP API Security Top 10 and the OpenAPI Specification security guidelines.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> OpenApiAnalyzer {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        OpenApiAnalyzer::new(client)
    }

    #[test]
    fn test_detect_version_swagger2() {
        let scanner = create_test_scanner();
        let spec: Value = serde_json::from_str(r#"{"swagger": "2.0", "info": {"title": "Test"}}"#).unwrap();
        assert_eq!(scanner.detect_version(&spec), OpenApiVersion::Swagger2);
    }

    #[test]
    fn test_detect_version_openapi30() {
        let scanner = create_test_scanner();
        let spec: Value = serde_json::from_str(r#"{"openapi": "3.0.1", "info": {"title": "Test"}}"#).unwrap();
        assert_eq!(scanner.detect_version(&spec), OpenApiVersion::OpenApi30);
    }

    #[test]
    fn test_detect_version_openapi31() {
        let scanner = create_test_scanner();
        let spec: Value = serde_json::from_str(r#"{"openapi": "3.1.0", "info": {"title": "Test"}}"#).unwrap();
        assert_eq!(scanner.detect_version(&spec), OpenApiVersion::OpenApi31);
    }

    #[test]
    fn test_detect_version_unknown() {
        let scanner = create_test_scanner();
        let spec: Value = serde_json::from_str(r#"{"info": {"title": "Test"}}"#).unwrap();
        assert_eq!(scanner.detect_version(&spec), OpenApiVersion::Unknown);
    }

    #[test]
    fn test_is_weak_pattern() {
        let scanner = create_test_scanner();
        assert!(scanner.is_weak_pattern(".*"));
        assert!(scanner.is_weak_pattern(".+"));
        assert!(scanner.is_weak_pattern("^.*$"));
        assert!(!scanner.is_weak_pattern(r"^[a-zA-Z0-9]+$"));
        assert!(!scanner.is_weak_pattern(r"^\d{4}-\d{2}-\d{2}$"));
    }

    #[test]
    fn test_parse_swagger2_spec() {
        let scanner = create_test_scanner();
        let spec_json = r#"{
            "swagger": "2.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "securityDefinitions": {
                "api_key": {
                    "type": "apiKey",
                    "name": "X-API-Key",
                    "in": "header"
                }
            },
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "summary": "Get all users",
                        "security": [{"api_key": []}],
                        "parameters": []
                    }
                }
            }
        }"#;

        let spec = scanner.parse_openapi_spec(spec_json, "https://example.com/swagger.json");
        assert!(spec.is_some());

        let spec = spec.unwrap();
        assert_eq!(spec.version, OpenApiVersion::Swagger2);
        assert_eq!(spec.title, "Test API");
        assert_eq!(spec.security_definitions.len(), 1);
        assert!(spec.security_definitions.contains_key("api_key"));
        assert_eq!(spec.endpoints.len(), 1);
        assert_eq!(spec.endpoints[0].path, "/users");
        assert_eq!(spec.endpoints[0].method, "GET");
    }

    #[test]
    fn test_parse_openapi3_spec() {
        let scanner = create_test_scanner();
        let spec_json = r#"{
            "openapi": "3.0.1",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "servers": [{"url": "https://api.example.com/v1"}],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [{"bearerAuth": []}],
            "paths": {
                "/users/{id}": {
                    "delete": {
                        "operationId": "deleteUser",
                        "summary": "Delete a user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                        ]
                    }
                }
            }
        }"#;

        let spec = scanner.parse_openapi_spec(spec_json, "https://example.com/openapi.json");
        assert!(spec.is_some());

        let spec = spec.unwrap();
        assert_eq!(spec.version, OpenApiVersion::OpenApi30);
        assert_eq!(spec.title, "Test API");
        assert_eq!(spec.security_definitions.len(), 1);
        assert!(spec.security_definitions.contains_key("bearerAuth"));
        assert_eq!(spec.global_security.len(), 1);
        assert_eq!(spec.endpoints.len(), 1);
        assert_eq!(spec.endpoints[0].path, "/users/{id}");
        assert_eq!(spec.endpoints[0].method, "DELETE");
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();
        let vuln = scanner.create_vulnerability(
            "OpenAPI Missing Security Definitions",
            "https://example.com",
            "No security schemes defined",
            Severity::High,
            "CWE-306",
            "https://example.com/swagger.json",
        );

        assert_eq!(vuln.vuln_type, "OpenAPI Missing Security Definitions");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-306");
        assert!(vuln.id.starts_with("openapi_"));
    }

    #[test]
    fn test_get_remediation() {
        let scanner = create_test_scanner();

        let remediation = scanner.get_remediation("OpenAPI Missing Security Definitions");
        assert!(remediation.contains("security schemes"));
        assert!(remediation.contains("securityDefinitions"));

        let remediation = scanner.get_remediation("OpenAPI API Key in Query Parameter");
        assert!(remediation.contains("header"));
        assert!(remediation.contains("in: header"));

        let remediation = scanner.get_remediation("Unknown Vulnerability");
        assert!(remediation.contains("OWASP"));
    }

    #[test]
    fn test_parse_security_requirements() {
        let scanner = create_test_scanner();
        let security: Value = serde_json::from_str(r#"[{"oauth2": ["read", "write"]}, {"api_key": []}]"#).unwrap();
        let requirements = scanner.parse_security_requirements(Some(&security));

        assert_eq!(requirements.len(), 2);
        assert_eq!(requirements[0].scheme_name, "oauth2");
        assert_eq!(requirements[0].scopes, vec!["read", "write"]);
        assert_eq!(requirements[1].scheme_name, "api_key");
        assert!(requirements[1].scopes.is_empty());
    }

    #[test]
    fn test_parse_parameters() {
        let scanner = create_test_scanner();
        let params: Value = serde_json::from_str(r#"[
            {
                "name": "id",
                "in": "path",
                "required": true,
                "schema": {"type": "integer", "minimum": 1}
            },
            {
                "name": "name",
                "in": "query",
                "schema": {"type": "string", "maxLength": 100, "pattern": "^[a-zA-Z]+$"}
            }
        ]"#).unwrap();

        let parameters = scanner.parse_parameters(Some(&params), true);

        assert_eq!(parameters.len(), 2);
        assert_eq!(parameters[0].name, "id");
        assert_eq!(parameters[0].in_location, "path");
        assert!(parameters[0].required);
        assert_eq!(parameters[0].param_type, Some("integer".to_string()));
        assert_eq!(parameters[0].minimum, Some(1.0));

        assert_eq!(parameters[1].name, "name");
        assert_eq!(parameters[1].in_location, "query");
        assert!(!parameters[1].required);
        assert_eq!(parameters[1].max_length, Some(100));
        assert_eq!(parameters[1].pattern, Some("^[a-zA-Z]+$".to_string()));
    }
}
