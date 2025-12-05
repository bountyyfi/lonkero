// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Nuclei Template Validator
 * Production-grade validation for custom Nuclei templates
 *
 * Features:
 * - YAML syntax validation
 * - Nuclei template schema validation
 * - Dangerous pattern detection
 * - Performance impact analysis
 * - Security validation
 *
 * © 2025 Bountyy Oy
 */

use serde::{Deserialize, Serialize};
use serde_yaml;
use regex::Regex;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub security_score: u8, // 0-100
    pub performance_score: u8, // 0-100
    pub metadata: ValidationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub error_type: String,
    pub message: String,
    pub line: Option<usize>,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    pub warning_type: String,
    pub message: String,
    pub line: Option<usize>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetadata {
    pub template_type: String,
    pub request_count: usize,
    pub matcher_count: usize,
    pub extractor_count: usize,
    pub has_stop_at_first_match: bool,
    pub estimated_execution_time_ms: u64,
    pub max_redirects: usize,
    pub potential_rate_limit_issues: bool,
}

#[derive(Debug, Deserialize)]
struct NucleiTemplate {
    id: String,
    info: TemplateInfo,
    #[serde(default)]
    http: Option<Vec<HttpRequest>>,
    #[serde(default)]
    network: Option<Vec<NetworkRequest>>,
    #[serde(default)]
    dns: Option<Vec<DnsRequest>>,
    #[serde(default)]
    file: Option<Vec<FileRequest>>,
    #[serde(default)]
    variables: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct TemplateInfo {
    name: String,
    author: Option<String>,
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    reference: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct HttpRequest {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<Vec<String>>,
    #[serde(default)]
    raw: Option<Vec<String>>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    matchers: Option<Vec<Matcher>>,
    #[serde(default)]
    extractors: Option<Vec<Extractor>>,
    #[serde(default)]
    redirects: Option<bool>,
    #[serde(default)]
    max_redirects: Option<usize>,
    #[serde(default)]
    stop_at_first_match: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct NetworkRequest {
    #[serde(default)]
    inputs: Option<Vec<NetworkInput>>,
    #[serde(default)]
    matchers: Option<Vec<Matcher>>,
}

#[derive(Debug, Deserialize)]
struct NetworkInput {
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DnsRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    matchers: Option<Vec<Matcher>>,
}

#[derive(Debug, Deserialize)]
struct FileRequest {
    #[serde(default)]
    extensions: Option<Vec<String>>,
    #[serde(default)]
    matchers: Option<Vec<Matcher>>,
}

#[derive(Debug, Deserialize)]
struct Matcher {
    #[serde(rename = "type")]
    matcher_type: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    words: Option<Vec<String>>,
    #[serde(default)]
    regex: Option<Vec<String>>,
    #[serde(default)]
    status: Option<Vec<u16>>,
    #[serde(default)]
    dsl: Option<Vec<String>>,
    #[serde(default)]
    part: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Extractor {
    #[serde(rename = "type")]
    extractor_type: Option<String>,
    #[serde(default)]
    regex: Option<Vec<String>>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    part: Option<String>,
}

pub struct TemplateValidator {
    dangerous_patterns: HashSet<String>,
    dangerous_commands: HashSet<String>,
    max_request_count: usize,
    max_execution_time_ms: u64,
}

impl Default for TemplateValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateValidator {
    pub fn new() -> Self {
        let mut dangerous_patterns = HashSet::new();
        dangerous_patterns.insert("eval(".to_string());
        dangerous_patterns.insert("exec(".to_string());
        dangerous_patterns.insert("system(".to_string());
        dangerous_patterns.insert("shell_exec".to_string());
        dangerous_patterns.insert("passthru".to_string());
        dangerous_patterns.insert("rm -rf".to_string());
        dangerous_patterns.insert("DROP TABLE".to_string());
        dangerous_patterns.insert("DELETE FROM".to_string());
        dangerous_patterns.insert("TRUNCATE".to_string());

        let mut dangerous_commands = HashSet::new();
        dangerous_commands.insert("curl".to_string());
        dangerous_commands.insert("wget".to_string());
        dangerous_commands.insert("nc".to_string());
        dangerous_commands.insert("netcat".to_string());
        dangerous_commands.insert("bash".to_string());
        dangerous_commands.insert("sh".to_string());
        dangerous_commands.insert("/bin/".to_string());

        Self {
            dangerous_patterns,
            dangerous_commands,
            max_request_count: 50,
            max_execution_time_ms: 60000, // 60 seconds
        }
    }

    /// Validate a Nuclei template YAML
    pub fn validate(&self, template_yaml: &str) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut security_score = 100u8;
        let mut performance_score = 100u8;

        // 1. YAML Syntax Validation
        let template = match serde_yaml::from_str::<NucleiTemplate>(template_yaml) {
            Ok(t) => t,
            Err(e) => {
                errors.push(ValidationError {
                    error_type: "syntax_error".to_string(),
                    message: format!("Invalid YAML syntax: {}", e),
                    line: None,
                    severity: ErrorSeverity::Critical,
                });

                return ValidationResult {
                    valid: false,
                    errors,
                    warnings,
                    security_score: 0,
                    performance_score: 0,
                    metadata: ValidationMetadata {
                        template_type: "unknown".to_string(),
                        request_count: 0,
                        matcher_count: 0,
                        extractor_count: 0,
                        has_stop_at_first_match: false,
                        estimated_execution_time_ms: 0,
                        max_redirects: 0,
                        potential_rate_limit_issues: false,
                    },
                };
            }
        };

        // 2. Schema Validation
        self.validate_schema(&template, &mut errors, &mut warnings);

        // 3. Security Validation
        let security_issues = self.validate_security(&template, template_yaml);
        if !security_issues.is_empty() {
            security_score = security_score.saturating_sub((security_issues.len() * 20) as u8);
            errors.extend(security_issues);
        }

        // 4. Performance Validation
        let (perf_warnings, perf_metadata) = self.validate_performance(&template);
        if !perf_warnings.is_empty() {
            performance_score = performance_score.saturating_sub((perf_warnings.len() * 10) as u8);
            warnings.extend(perf_warnings);
        }

        // 5. Best Practices Validation
        let best_practice_warnings = self.validate_best_practices(&template);
        warnings.extend(best_practice_warnings);

        // Determine template type
        let template_type = if template.http.is_some() {
            "http"
        } else if template.network.is_some() {
            "network"
        } else if template.dns.is_some() {
            "dns"
        } else if template.file.is_some() {
            "file"
        } else {
            "unknown"
        }.to_string();

        let valid = errors.is_empty();

        ValidationResult {
            valid,
            errors,
            warnings,
            security_score,
            performance_score,
            metadata: ValidationMetadata {
                template_type,
                ..perf_metadata
            },
        }
    }

    fn validate_schema(&self, template: &NucleiTemplate, errors: &mut Vec<ValidationError>, warnings: &mut Vec<ValidationWarning>) {
        // Validate ID
        if template.id.is_empty() {
            errors.push(ValidationError {
                error_type: "missing_id".to_string(),
                message: "Template ID is required".to_string(),
                line: None,
                severity: ErrorSeverity::High,
            });
        }

        // Validate ID format (should be lowercase with hyphens)
        if !template.id.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()) {
            warnings.push(ValidationWarning {
                warning_type: "id_format".to_string(),
                message: "Template ID should use lowercase letters, numbers, and hyphens only".to_string(),
                line: None,
                suggestion: Some(template.id.to_lowercase().replace('_', "-")),
            });
        }

        // Validate severity
        let valid_severities = ["info", "low", "medium", "high", "critical"];
        if !valid_severities.contains(&template.info.severity.as_str()) {
            errors.push(ValidationError {
                error_type: "invalid_severity".to_string(),
                message: format!("Invalid severity '{}'. Must be one of: info, low, medium, high, critical", template.info.severity),
                line: None,
                severity: ErrorSeverity::Medium,
            });
        }

        // Validate name
        if template.info.name.is_empty() {
            errors.push(ValidationError {
                error_type: "missing_name".to_string(),
                message: "Template name is required".to_string(),
                line: None,
                severity: ErrorSeverity::High,
            });
        }

        // Check for at least one request type
        if template.http.is_none() && template.network.is_none() && template.dns.is_none() && template.file.is_none() {
            errors.push(ValidationError {
                error_type: "no_requests".to_string(),
                message: "Template must have at least one request (http, network, dns, or file)".to_string(),
                line: None,
                severity: ErrorSeverity::Critical,
            });
        }

        // Validate HTTP requests
        if let Some(http_requests) = &template.http {
            for (idx, req) in http_requests.iter().enumerate() {
                if req.path.is_none() && req.raw.is_none() {
                    errors.push(ValidationError {
                        error_type: "missing_path_or_raw".to_string(),
                        message: format!("HTTP request {} must have either 'path' or 'raw' defined", idx + 1),
                        line: None,
                        severity: ErrorSeverity::High,
                    });
                }

                if req.matchers.is_none() {
                    warnings.push(ValidationWarning {
                        warning_type: "no_matchers".to_string(),
                        message: format!("HTTP request {} has no matchers defined", idx + 1),
                        line: None,
                        suggestion: Some("Add matchers to detect vulnerabilities".to_string()),
                    });
                }
            }
        }
    }

    fn validate_security(&self, template: &NucleiTemplate, template_yaml: &str) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check for dangerous patterns in the entire template
        for pattern in &self.dangerous_patterns {
            if template_yaml.contains(pattern) {
                errors.push(ValidationError {
                    error_type: "dangerous_pattern".to_string(),
                    message: format!("Dangerous pattern detected: '{}'. This could lead to code execution.", pattern),
                    line: None,
                    severity: ErrorSeverity::Critical,
                });
            }
        }

        // Check for dangerous commands
        for command in &self.dangerous_commands {
            if template_yaml.contains(command) {
                errors.push(ValidationError {
                    error_type: "dangerous_command".to_string(),
                    message: format!("Potentially dangerous command detected: '{}'. Ensure proper safeguards are in place.", command),
                    line: None,
                    severity: ErrorSeverity::High,
                });
            }
        }

        // Check for credential leakage patterns
        let credential_patterns = vec![
            (r#"password\s*=\s*['"][^'"]+['"]"#, "hardcoded password"),
            (r#"api[_-]?key\s*=\s*['"][^'"]+['"]"#, "hardcoded API key"),
            (r#"secret\s*=\s*['"][^'"]+['"]"#, "hardcoded secret"),
            (r#"token\s*=\s*['"][^'"]+['"]"#, "hardcoded token"),
            (r"aws_access_key_id", "AWS credentials"),
            (r"private[_-]?key", "private key"),
        ];

        for (pattern, name) in credential_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(template_yaml) {
                    errors.push(ValidationError {
                        error_type: "credential_leakage".to_string(),
                        message: format!("Potential {} detected in template. Never hardcode credentials.", name),
                        line: None,
                        severity: ErrorSeverity::Critical,
                    });
                }
            }
        }

        // Check for SSRF without proper validation
        if let Some(http_requests) = &template.http {
            for req in http_requests {
                if let Some(paths) = &req.path {
                    for path in paths {
                        if path.contains("{{") && (path.contains("http://") || path.contains("https://")) {
                            errors.push(ValidationError {
                                error_type: "potential_ssrf".to_string(),
                                message: "Template uses user-controlled URLs which could lead to SSRF. Ensure proper validation.".to_string(),
                                line: None,
                                severity: ErrorSeverity::High,
                            });
                        }
                    }
                }
            }
        }

        // Check for SQL injection without proper context
        if template_yaml.contains("SQL") || template_yaml.contains("sql") {
            if !template_yaml.contains("safe") && !template_yaml.contains("test") {
                errors.push(ValidationError {
                    error_type: "potential_sqli".to_string(),
                    message: "Template appears to test for SQL injection. Ensure it's properly scoped to test environments.".to_string(),
                    line: None,
                    severity: ErrorSeverity::Medium,
                });
            }
        }

        errors
    }

    fn validate_performance(&self, template: &NucleiTemplate) -> (Vec<ValidationWarning>, ValidationMetadata) {
        let mut warnings = Vec::new();
        let mut request_count = 0;
        let mut matcher_count = 0;
        let mut extractor_count = 0;
        let mut has_stop_at_first_match = false;
        let mut max_redirects = 5;
        let mut estimated_time_ms = 0u64;

        // Count HTTP requests and analyze
        if let Some(http_requests) = &template.http {
            request_count = http_requests.len();

            if request_count > self.max_request_count {
                warnings.push(ValidationWarning {
                    warning_type: "too_many_requests".to_string(),
                    message: format!("Template has {} requests. Consider reducing for better performance.", request_count),
                    line: None,
                    suggestion: Some(format!("Recommended maximum: {} requests", self.max_request_count)),
                });
            }

            for req in http_requests {
                // Estimate execution time per request (average 1000ms per HTTP request)
                estimated_time_ms += 1000;

                // Check for path explosion
                if let Some(paths) = &req.path {
                    if paths.len() > 10 {
                        warnings.push(ValidationWarning {
                            warning_type: "path_explosion".to_string(),
                            message: format!("Request has {} paths. This will multiply execution time.", paths.len()),
                            line: None,
                            suggestion: Some("Consider splitting into multiple templates".to_string()),
                        });
                        estimated_time_ms += (paths.len() as u64 - 1) * 1000;
                    }
                }

                // Count matchers
                if let Some(matchers) = &req.matchers {
                    matcher_count += matchers.len();

                    // Check for complex regex matchers
                    for matcher in matchers {
                        if let Some(regexes) = &matcher.regex {
                            for regex_pattern in regexes {
                                if regex_pattern.contains(".*.*") || regex_pattern.contains(".+.+") {
                                    warnings.push(ValidationWarning {
                                        warning_type: "complex_regex".to_string(),
                                        message: "Complex regex pattern detected. May cause performance issues.".to_string(),
                                        line: None,
                                        suggestion: Some("Simplify regex or use word matchers where possible".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }

                // Count extractors
                if let Some(extractors) = &req.extractors {
                    extractor_count += extractors.len();
                }

                // Check stop_at_first_match
                if req.stop_at_first_match.unwrap_or(false) {
                    has_stop_at_first_match = true;
                }

                // Check redirects
                if let Some(max_redir) = req.max_redirects {
                    max_redirects = max_redir;
                    if max_redir > 10 {
                        warnings.push(ValidationWarning {
                            warning_type: "excessive_redirects".to_string(),
                            message: format!("max_redirects set to {}. This may cause slow execution.", max_redir),
                            line: None,
                            suggestion: Some("Consider limiting redirects to 5 or less".to_string()),
                        });
                    }
                }
            }
        }

        // Check for rate limit issues
        let potential_rate_limit = request_count > 20;
        if potential_rate_limit {
            warnings.push(ValidationWarning {
                warning_type: "rate_limit_risk".to_string(),
                message: "High request count may trigger rate limiting on target servers.".to_string(),
                line: None,
                suggestion: Some("Add delays between requests or use threads carefully".to_string()),
            });
        }

        // Check total estimated execution time
        if estimated_time_ms > self.max_execution_time_ms {
            warnings.push(ValidationWarning {
                warning_type: "long_execution".to_string(),
                message: format!("Estimated execution time: {}s. Consider optimizing.", estimated_time_ms / 1000),
                line: None,
                suggestion: Some("Reduce request count or use stop-at-first-match".to_string()),
            });
        }

        let metadata = ValidationMetadata {
            template_type: "http".to_string(),
            request_count,
            matcher_count,
            extractor_count,
            has_stop_at_first_match,
            estimated_execution_time_ms: estimated_time_ms,
            max_redirects,
            potential_rate_limit_issues: potential_rate_limit,
        };

        (warnings, metadata)
    }

    fn validate_best_practices(&self, template: &NucleiTemplate) -> Vec<ValidationWarning> {
        let mut warnings = Vec::new();

        // Check for author
        if template.info.author.is_none() {
            warnings.push(ValidationWarning {
                warning_type: "missing_author".to_string(),
                message: "Template should include author information".to_string(),
                line: None,
                suggestion: Some("Add 'author' field in template info".to_string()),
            });
        }

        // Check for description
        if template.info.description.is_none() {
            warnings.push(ValidationWarning {
                warning_type: "missing_description".to_string(),
                message: "Template should include a description".to_string(),
                line: None,
                suggestion: Some("Add 'description' field explaining what this template detects".to_string()),
            });
        }

        // Check for tags
        if template.info.tags.is_none() || template.info.tags.as_ref().unwrap().is_empty() {
            warnings.push(ValidationWarning {
                warning_type: "missing_tags".to_string(),
                message: "Template should include tags for better organization".to_string(),
                line: None,
                suggestion: Some("Add relevant tags (e.g., 'sqli', 'xss', 'cve-2023-xxxx')".to_string()),
            });
        }

        // Check for reference
        if template.info.reference.is_none() {
            warnings.push(ValidationWarning {
                warning_type: "missing_reference".to_string(),
                message: "Consider adding references to vulnerability advisories or documentation".to_string(),
                line: None,
                suggestion: Some("Add 'reference' field with relevant URLs".to_string()),
            });
        }

        warnings
    }

    /// Quick validation (basic checks only)
    pub fn validate_quick(&self, template_yaml: &str) -> bool {
        serde_yaml::from_str::<NucleiTemplate>(template_yaml).is_ok()
    }

    /// Validate template schema only
    pub fn validate_schema_only(&self, template_yaml: &str) -> Result<(), String> {
        match serde_yaml::from_str::<NucleiTemplate>(template_yaml) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Schema validation failed: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_template() {
        let validator = TemplateValidator::new();
        let template = r#"
id: test-template
info:
  name: Test Template
  author: test
  severity: medium
  description: Test description
  tags:
    - test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "vulnerable"
"#;

        let result = validator.validate(template);
        assert!(result.valid);
    }

    #[test]
    fn test_invalid_yaml() {
        let validator = TemplateValidator::new();
        let template = "invalid: yaml: syntax: error:";

        let result = validator.validate(template);
        assert!(!result.valid);
    }

    #[test]
    fn test_dangerous_pattern_detection() {
        let validator = TemplateValidator::new();
        let template = r#"
id: dangerous-template
info:
  name: Dangerous
  severity: high
http:
  - raw:
      - |
        GET /test?cmd=eval($_GET['x']) HTTP/1.1
"#;

        let result = validator.validate(template);
        assert!(!result.errors.is_empty());
    }
}
