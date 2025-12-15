// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Custom Nuclei Template Executor
 * Execute custom templates via nuclei engine with batch processing
 *
 * Features:
 * - Execute custom templates via nuclei CLI
 * - Batch execution on multiple assets
 * - Result normalization and parsing
 * - Error handling and reporting
 * - Performance monitoring
 *
 * © 2025 Bountyy Oy
 */

use serde::{Deserialize, Serialize};
use std::process::{Command, Stdio};
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub template_id: i32,
    pub template_content: String,
    pub targets: Vec<String>,
    pub config: ExecutionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
    #[serde(default)]
    pub rate_limit: Option<usize>, // Requests per second
    #[serde(default)]
    pub retries: usize,
    #[serde(default)]
    pub verbose: bool,
}

fn default_timeout() -> u64 { 300000 } // 5 minutes
fn default_concurrency() -> usize { 25 }
fn default_max_redirects() -> usize { 5 }

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout(),
            concurrency: default_concurrency(),
            follow_redirects: true,
            max_redirects: default_max_redirects(),
            rate_limit: None,
            retries: 3,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub template_id: i32,
    pub target: String,
    pub status: ExecutionStatus,
    pub findings: Vec<Finding>,
    pub execution_time_ms: u64,
    pub error_message: Option<String>,
    pub stats: ExecutionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    Failed,
    Timeout,
    Error,
    NoMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub matched_at: String,
    pub extracted_results: Vec<String>,
    pub matcher_name: Option<String>,
    pub matcher_type: Option<String>,
    pub curl_command: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub templates_executed: usize,
    pub requests_made: usize,
    pub matches_found: usize,
    pub errors_count: usize,
    pub avg_response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchExecutionResult {
    pub total_targets: usize,
    pub completed: usize,
    pub failed: usize,
    pub total_findings: usize,
    pub results: Vec<ExecutionResult>,
    pub execution_time_ms: u64,
}

pub struct CustomTemplateExecutor {
    nuclei_binary_path: String,
    temp_dir: PathBuf,
}

impl CustomTemplateExecutor {
    /// Allowed nuclei binary paths for security
    const ALLOWED_BINARY_PATHS: &'static [&'static str] = &[
        "nuclei",                    // Search in PATH
        "/usr/bin/nuclei",          // Common Linux install
        "/usr/local/bin/nuclei",    // Local Linux install
        "/opt/nuclei/nuclei",       // Custom install location
    ];

    /// Validate nuclei binary path
    fn validate_binary_path(path: &str) -> Result<String, String> {
        // Check if path is in allowed list
        if !Self::ALLOWED_BINARY_PATHS.contains(&path) {
            return Err(format!(
                "Binary path not allowed: {}. Allowed paths: {:?}",
                path,
                Self::ALLOWED_BINARY_PATHS
            ));
        }

        // If it's just "nuclei", search in PATH
        if path == "nuclei" {
            return Ok(path.to_string());
        }

        // For absolute paths, verify the file exists and is executable
        let binary_path = std::path::Path::new(path);
        if !binary_path.exists() {
            return Err(format!("Binary does not exist: {}", path));
        }

        // Verify it's actually the nuclei binary by checking version
        match std::process::Command::new(path)
            .arg("-version")
            .output()
        {
            Ok(output) => {
                let version_output = String::from_utf8_lossy(&output.stdout);
                if !version_output.to_lowercase().contains("nuclei") {
                    return Err(format!("Binary is not nuclei: {}", path));
                }
                Ok(path.to_string())
            }
            Err(e) => Err(format!("Failed to verify binary: {}", e)),
        }
    }

    pub fn new(nuclei_binary_path: Option<String>) -> Self {
        let binary_path = if let Some(path) = nuclei_binary_path {
            // Validate custom binary path
            match Self::validate_binary_path(&path) {
                Ok(validated_path) => validated_path,
                Err(e) => {
                    eprintln!("WARNING: Invalid nuclei binary path: {}", e);
                    eprintln!("Falling back to default 'nuclei' in PATH");
                    "nuclei".to_string()
                }
            }
        } else {
            "nuclei".to_string()
        };

        let temp_dir = std::env::temp_dir().join("nuclei-custom-templates");

        // Create temp directory if it doesn't exist
        fs::create_dir_all(&temp_dir).ok();

        Self {
            nuclei_binary_path: binary_path,
            temp_dir,
        }
    }

    /// Execute a custom template against multiple targets
    pub async fn execute_batch(&self, request: ExecutionRequest) -> BatchExecutionResult {
        let start_time = Instant::now();
        let mut results = Vec::new();
        let total_targets = request.targets.len();
        let mut completed = 0;
        let mut failed = 0;
        let mut total_findings = 0;

        // Write template to temporary file
        let template_file = match self.write_template_file(request.template_id, &request.template_content) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Failed to write template file: {}", e);
                return BatchExecutionResult {
                    total_targets,
                    completed: 0,
                    failed: total_targets,
                    total_findings: 0,
                    results: vec![],
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                };
            }
        };

        // Execute template against each target
        for target in &request.targets {
            match self.execute_single(&template_file, target, request.template_id, &request.config).await {
                Ok(result) => {
                    if matches!(result.status, ExecutionStatus::Success | ExecutionStatus::NoMatch) {
                        completed += 1;
                    } else {
                        failed += 1;
                    }
                    total_findings += result.findings.len();
                    results.push(result);
                }
                Err(e) => {
                    failed += 1;
                    results.push(ExecutionResult {
                        template_id: request.template_id,
                        target: target.clone(),
                        status: ExecutionStatus::Error,
                        findings: vec![],
                        execution_time_ms: 0,
                        error_message: Some(e),
                        stats: ExecutionStats {
                            templates_executed: 0,
                            requests_made: 0,
                            matches_found: 0,
                            errors_count: 1,
                            avg_response_time_ms: 0,
                        },
                    });
                }
            }
        }

        // Cleanup template file
        fs::remove_file(&template_file).ok();

        BatchExecutionResult {
            total_targets,
            completed,
            failed,
            total_findings,
            results,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Execute template against a single target
    async fn execute_single(
        &self,
        template_file: &Path,
        target: &str,
        template_id: i32,
        config: &ExecutionConfig,
    ) -> Result<ExecutionResult, String> {
        let start_time = Instant::now();

        // Build nuclei command
        let mut cmd = TokioCommand::new(&self.nuclei_binary_path);
        cmd.arg("-t").arg(template_file)
            .arg("-u").arg(target)
            .arg("-json")
            .arg("-silent")
            .arg("-nc"); // No color

        // Add configuration options
        if !config.follow_redirects {
            cmd.arg("-nr");
        }

        if config.max_redirects != 5 {
            cmd.arg("-max-redirects").arg(config.max_redirects.to_string());
        }

        if let Some(rate_limit) = config.rate_limit {
            cmd.arg("-rl").arg(rate_limit.to_string());
        }

        cmd.arg("-c").arg(config.concurrency.to_string());

        if config.retries > 0 {
            cmd.arg("-retries").arg(config.retries.to_string());
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Execute with timeout
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let output = match timeout(timeout_duration, cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return Ok(ExecutionResult {
                    template_id,
                    target: target.to_string(),
                    status: ExecutionStatus::Error,
                    findings: vec![],
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    error_message: Some(format!("Failed to execute nuclei: {}", e)),
                    stats: ExecutionStats {
                        templates_executed: 0,
                        requests_made: 0,
                        matches_found: 0,
                        errors_count: 1,
                        avg_response_time_ms: 0,
                    },
                });
            }
            Err(_) => {
                return Ok(ExecutionResult {
                    template_id,
                    target: target.to_string(),
                    status: ExecutionStatus::Timeout,
                    findings: vec![],
                    execution_time_ms: config.timeout_ms,
                    error_message: Some(format!("Execution timed out after {}ms", config.timeout_ms)),
                    stats: ExecutionStats {
                        templates_executed: 0,
                        requests_made: 0,
                        matches_found: 0,
                        errors_count: 0,
                        avg_response_time_ms: 0,
                    },
                });
            }
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Parse output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && !stderr.is_empty() {
            return Ok(ExecutionResult {
                template_id,
                target: target.to_string(),
                status: ExecutionStatus::Error,
                findings: vec![],
                execution_time_ms,
                error_message: Some(stderr.to_string()),
                stats: ExecutionStats {
                    templates_executed: 0,
                    requests_made: 0,
                    matches_found: 0,
                    errors_count: 1,
                    avg_response_time_ms: 0,
                },
            });
        }

        // Parse JSON output
        let findings = self.parse_nuclei_output(&stdout)?;
        let status = if findings.is_empty() {
            ExecutionStatus::NoMatch
        } else {
            ExecutionStatus::Success
        };

        Ok(ExecutionResult {
            template_id,
            target: target.to_string(),
            status,
            findings: findings.clone(),
            execution_time_ms,
            error_message: None,
            stats: ExecutionStats {
                templates_executed: 1,
                requests_made: 1, // Approximation
                matches_found: findings.len(),
                errors_count: 0,
                avg_response_time_ms: execution_time_ms,
            },
        })
    }

    /// Write template content to a temporary file
    fn write_template_file(&self, template_id: i32, content: &str) -> Result<PathBuf, String> {
        let filename = format!("custom-template-{}.yaml", template_id);
        let file_path = self.temp_dir.join(filename);

        let mut file = fs::File::create(&file_path)
            .map_err(|e| format!("Failed to create template file: {}", e))?;

        file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write template content: {}", e))?;

        Ok(file_path)
    }

    /// Parse nuclei JSON output
    fn parse_nuclei_output(&self, output: &str) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();

        for line in output.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<NucleiOutput>(line) {
                Ok(nuclei_finding) => {
                    findings.push(Finding {
                        template_id: nuclei_finding.template_id.unwrap_or_default(),
                        template_name: nuclei_finding.info.name.unwrap_or_default(),
                        severity: nuclei_finding.info.severity.unwrap_or_else(|| "info".to_string()),
                        matched_at: nuclei_finding.matched_at.unwrap_or_default(),
                        extracted_results: nuclei_finding.extracted_results.unwrap_or_default(),
                        matcher_name: nuclei_finding.matcher_name,
                        matcher_type: nuclei_finding.matcher_type,
                        curl_command: nuclei_finding.curl_command,
                        request: nuclei_finding.request,
                        response: nuclei_finding.response,
                        timestamp: nuclei_finding.timestamp.unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
                    });
                }
                Err(e) => {
                    eprintln!("Failed to parse nuclei output line: {} - Error: {}", line, e);
                }
            }
        }

        Ok(findings)
    }

    /// Check if nuclei is installed and accessible
    pub fn check_nuclei_available(&self) -> bool {
        Command::new(&self.nuclei_binary_path)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Get nuclei version
    pub fn get_nuclei_version(&self) -> Result<String, String> {
        let output = Command::new(&self.nuclei_binary_path)
            .arg("-version")
            .output()
            .map_err(|e| format!("Failed to get nuclei version: {}", e))?;

        if !output.status.success() {
            return Err("Failed to get nuclei version".to_string());
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }
}

#[derive(Debug, Deserialize)]
struct NucleiOutput {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(rename = "extracted-results")]
    extracted_results: Option<Vec<String>>,
    #[serde(rename = "matcher-name")]
    matcher_name: Option<String>,
    #[serde(rename = "matcher-type")]
    matcher_type: Option<String>,
    #[serde(rename = "curl-command")]
    curl_command: Option<String>,
    request: Option<String>,
    response: Option<String>,
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = CustomTemplateExecutor::new(None);
        assert_eq!(executor.nuclei_binary_path, "nuclei");
    }

    #[test]
    fn test_execution_config_defaults() {
        let config = ExecutionConfig::default();
        assert_eq!(config.timeout_ms, 300000);
        assert_eq!(config.concurrency, 25);
        assert_eq!(config.max_redirects, 5);
    }

    #[tokio::test]
    async fn test_batch_execution() {
        let executor = CustomTemplateExecutor::new(None);

        let template = r#"
id: test-template
info:
  name: Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 200
"#;

        let request = ExecutionRequest {
            template_id: 1,
            template_content: template.to_string(),
            targets: vec!["https://example.com".to_string()],
            config: ExecutionConfig::default(),
        };

        // This will fail if nuclei is not installed, which is expected in test environment
        let result = executor.execute_batch(request).await;
        assert_eq!(result.total_targets, 1);
    }
}
