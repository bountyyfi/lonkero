// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * GitLab CI/CD Security Scanner
 *
 * Scans GitLab CI/CD pipelines for security misconfigurations
 *
 * © 2025 Bountyy Oy
 */

use crate::http_client::HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;

#[derive(Debug, Serialize, Deserialize)]
pub struct GitLabCICDFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub project_id: String,
    pub project_name: String,
    pub pipeline_id: Option<i64>,
    pub job_name: Option<String>,
    pub variable_name: Option<String>,
    pub remediation: String,
    pub cwe: String,
    pub cvss: f32,
    pub category: String,
}

#[derive(Debug, Deserialize)]
struct GitLabProject {
    id: i64,
    name: String,
    path_with_namespace: String,
    visibility: String,
    #[serde(default)]
    public_builds: bool,
    #[serde(default)]
    only_allow_merge_if_pipeline_succeeds: bool,
    #[serde(default)]
    shared_runners_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabPipeline {
    id: i64,
    #[serde(rename = "ref")]
    git_ref: String,
    status: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GitLabJob {
    id: i64,
    name: String,
    status: String,
    stage: String,
    #[serde(default)]
    tag_list: Vec<String>,
    runner: Option<GitLabRunner>,
}

#[derive(Debug, Deserialize)]
struct GitLabRunner {
    id: i64,
    description: String,
    #[serde(default)]
    is_shared: bool,
    #[serde(default)]
    online: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabVariable {
    key: String,
    value: String,
    #[serde(default)]
    protected: bool,
    #[serde(default)]
    masked: bool,
    #[serde(default)]
    environment_scope: String,
}

#[derive(Debug, Deserialize)]
struct GitLabCIConfig {
    content: String,
}

pub struct GitLabCICDScanner {
    http_client: Arc<HttpClient>,
    gitlab_url: String,
    gitlab_token: String,
}

impl GitLabCICDScanner {
    pub fn new(http_client: Arc<HttpClient>, gitlab_url: String, gitlab_token: String) -> Self {
        Self {
            http_client,
            gitlab_url: gitlab_url.trim_end_matches('/').to_string(),
            gitlab_token,
        }
    }

    /// Scan a GitLab project for CI/CD security issues
    pub async fn scan_project(&self, project_id: &str) -> Result<Vec<GitLabCICDFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Get project details
        let project = self.get_project(project_id).await?;

        // Check if project has pipelines
        let pipelines = self.list_pipelines(&project.id.to_string()).await?;

        if pipelines.is_empty() {
            findings.push(GitLabCICDFinding {
                severity: "LOW".to_string(),
                title: "No CI/CD Pipelines Configured".to_string(),
                description: format!("Project '{}' has no CI/CD pipelines configured. This may indicate lack of automated testing and deployment.", project.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Configure CI/CD pipelines with automated security scanning, testing, and deployment.".to_string(),
                cwe: "CWE-1008".to_string(),
                cvss: 3.0,
                category: "CI/CD Configuration".to_string(),
            });
        }

        // Scan CI/CD configuration
        if let Ok(ci_config) = self.get_ci_config(&project.id.to_string()).await {
            findings.extend(self.scan_ci_config(&ci_config, &project).await?);
        }

        // Scan CI/CD variables
        if let Ok(variables) = self.list_variables(&project.id.to_string()).await {
            findings.extend(self.scan_variables(&variables, &project).await?);
        }

        // Scan recent pipelines
        for pipeline in pipelines.iter().take(5) {
            if let Ok(jobs) = self.get_pipeline_jobs(&project.id.to_string(), pipeline.id).await {
                findings.extend(self.scan_pipeline_jobs(&jobs, &project, pipeline.id).await?);
            }
        }

        // Check project settings
        findings.extend(self.scan_project_settings(&project).await?);

        Ok(findings)
    }

    /// Scan CI/CD configuration file for security issues
    async fn scan_ci_config(&self, config: &GitLabCIConfig, project: &GitLabProject) -> Result<Vec<GitLabCICDFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();
        let content = &config.content;

        // Check for hardcoded secrets
        let secret_patterns = vec![
            (r#"password\s*[:=]\s*['"]([^'"]+)['"]"#, "Hardcoded Password"),
            (r#"api[_-]?key\s*[:=]\s*['"]([^'"]+)['"]"#, "Hardcoded API Key"),
            (r#"secret[_-]?key\s*[:=]\s*['"]([^'"]+)['"]"#, "Hardcoded Secret Key"),
            (r#"token\s*[:=]\s*['"]([^'"]+)['"]"#, "Hardcoded Token"),
            (r#"aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['"]([^'"]+)['"]"#, "Hardcoded AWS Access Key"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", "Private Key"),
        ];

        for (pattern, name) in secret_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(content) {
                    findings.push(GitLabCICDFinding {
                        severity: "CRITICAL".to_string(),
                        title: format!("{} in CI/CD Configuration", name),
                        description: format!("Found {} hardcoded in .gitlab-ci.yml file. This exposes sensitive credentials.", name),
                        project_id: project.id.to_string(),
                        project_name: project.name.clone(),
                        pipeline_id: None,
                        job_name: None,
                        variable_name: None,
                        remediation: "Use GitLab CI/CD variables with masking enabled to store sensitive data. Never commit secrets to version control.".to_string(),
                        cwe: "CWE-798".to_string(),
                        cvss: 9.8,
                        category: "Hardcoded Credentials".to_string(),
                    });
                }
            }
        }

        // Check for missing secret scanning
        if !content.contains("secret") && !content.contains("trufflehog") && !content.contains("gitleaks") {
            findings.push(GitLabCICDFinding {
                severity: "MEDIUM".to_string(),
                title: "No Secret Scanning in Pipeline".to_string(),
                description: "CI/CD pipeline does not include secret scanning. Secrets may be accidentally committed.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Add secret scanning tools like TruffleHog, GitLeaks, or Detect-Secrets to your CI/CD pipeline.".to_string(),
                cwe: "CWE-798".to_string(),
                cvss: 6.5,
                category: "Missing Security Control".to_string(),
            });
        }

        // Check for Docker-in-Docker without TLS
        if content.contains("docker:dind") || content.contains("docker:stable-dind") {
            if !content.contains("DOCKER_TLS_CERTDIR") {
                findings.push(GitLabCICDFinding {
                    severity: "HIGH".to_string(),
                    title: "Docker-in-Docker without TLS".to_string(),
                    description: "Docker-in-Docker service is used without TLS encryption, exposing Docker API.".to_string(),
                    project_id: project.id.to_string(),
                    project_name: project.name.clone(),
                    pipeline_id: None,
                    job_name: None,
                    variable_name: None,
                    remediation: "Enable Docker TLS by setting DOCKER_TLS_CERTDIR variable. Use docker:dind with TLS enabled.".to_string(),
                    cwe: "CWE-319".to_string(),
                    cvss: 7.5,
                    category: "Docker Security".to_string(),
                });
            }
        }

        // Check for privileged mode
        if content.contains("privileged: true") || content.contains("--privileged") {
            findings.push(GitLabCICDFinding {
                severity: "HIGH".to_string(),
                title: "Privileged Mode Enabled in Pipeline".to_string(),
                description: "CI/CD jobs running in privileged mode have elevated permissions and can compromise the host.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Avoid using privileged mode. Use specific capabilities (cap_add) instead. Consider using kaniko for container builds.".to_string(),
                cwe: "CWE-250".to_string(),
                cvss: 7.8,
                category: "Privilege Escalation".to_string(),
            });
        }

        // Check for missing artifact expiration
        if content.contains("artifacts:") && !content.contains("expire_in:") {
            findings.push(GitLabCICDFinding {
                severity: "LOW".to_string(),
                title: "Artifacts Without Expiration".to_string(),
                description: "Pipeline artifacts do not have expiration configured, potentially consuming storage indefinitely.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Set expire_in for artifacts to automatically clean up old builds. Example: expire_in: 30 days".to_string(),
                cwe: "CWE-1188".to_string(),
                cvss: 3.1,
                category: "Resource Management".to_string(),
            });
        }

        // Check for missing code signing
        if (content.contains("docker build") || content.contains("docker push")) && !content.contains("sign") {
            findings.push(GitLabCICDFinding {
                severity: "MEDIUM".to_string(),
                title: "Missing Code/Image Signing".to_string(),
                description: "Container images are built and pushed without signing, making them susceptible to tampering.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Implement image signing using Docker Content Trust, Cosign, or Notary.".to_string(),
                cwe: "CWE-345".to_string(),
                cvss: 5.9,
                category: "Integrity Verification".to_string(),
            });
        }

        Ok(findings)
    }

    /// Scan CI/CD variables for security issues
    async fn scan_variables(&self, variables: &[GitLabVariable], project: &GitLabProject) -> Result<Vec<GitLabCICDFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        for var in variables {
            // Check for unprotected sensitive variables
            if !var.protected && self.is_sensitive_variable(&var.key) {
                findings.push(GitLabCICDFinding {
                    severity: "HIGH".to_string(),
                    title: "Unprotected Sensitive CI/CD Variable".to_string(),
                    description: format!("CI/CD variable '{}' appears to contain sensitive data but is not protected. It can be accessed from any branch.", var.key),
                    project_id: project.id.to_string(),
                    project_name: project.name.clone(),
                    pipeline_id: None,
                    job_name: None,
                    variable_name: Some(var.key.clone()),
                    remediation: "Enable 'Protected' flag for sensitive variables to restrict access to protected branches only.".to_string(),
                    cwe: "CWE-522".to_string(),
                    cvss: 7.5,
                    category: "Variable Protection".to_string(),
                });
            }

            // Check for unmasked sensitive variables
            if !var.masked && self.is_sensitive_variable(&var.key) {
                findings.push(GitLabCICDFinding {
                    severity: "MEDIUM".to_string(),
                    title: "Unmasked Sensitive CI/CD Variable".to_string(),
                    description: format!("CI/CD variable '{}' appears to contain sensitive data but is not masked. It may be exposed in job logs.", var.key),
                    project_id: project.id.to_string(),
                    project_name: project.name.clone(),
                    pipeline_id: None,
                    job_name: None,
                    variable_name: Some(var.key.clone()),
                    remediation: "Enable 'Masked' flag for sensitive variables to prevent them from appearing in job logs.".to_string(),
                    cwe: "CWE-532".to_string(),
                    cvss: 6.5,
                    category: "Variable Masking".to_string(),
                });
            }
        }

        Ok(findings)
    }

    /// Scan pipeline jobs for security issues
    async fn scan_pipeline_jobs(&self, jobs: &[GitLabJob], project: &GitLabProject, pipeline_id: i64) -> Result<Vec<GitLabCICDFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        for job in jobs {
            // Check for jobs without runner tags (may run on shared runners)
            if job.tag_list.is_empty() {
                if let Some(runner) = &job.runner {
                    if runner.is_shared {
                        findings.push(GitLabCICDFinding {
                            severity: "MEDIUM".to_string(),
                            title: "Job Running on Shared Runner".to_string(),
                            description: format!("Job '{}' is running on shared GitLab runner without specific tags. Shared runners may not meet security requirements.", job.name),
                            project_id: project.id.to_string(),
                            project_name: project.name.clone(),
                            pipeline_id: Some(pipeline_id),
                            job_name: Some(job.name.clone()),
                            variable_name: None,
                            remediation: "Use specific runner tags to ensure jobs run on trusted, dedicated runners.".to_string(),
                            cwe: "CWE-923".to_string(),
                            cvss: 5.3,
                            category: "Runner Configuration".to_string(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Scan project settings for security issues
    async fn scan_project_settings(&self, project: &GitLabProject) -> Result<Vec<GitLabCICDFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Check for public builds
        if project.public_builds {
            findings.push(GitLabCICDFinding {
                severity: "MEDIUM".to_string(),
                title: "Public CI/CD Jobs Enabled".to_string(),
                description: "Pipeline jobs are publicly accessible. Job logs and artifacts may contain sensitive information.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Disable 'Public pipelines' in project settings to restrict access to pipeline jobs and logs.".to_string(),
                cwe: "CWE-200".to_string(),
                cvss: 5.3,
                category: "Information Disclosure".to_string(),
            });
        }

        // Check if merge requires pipeline success
        if !project.only_allow_merge_if_pipeline_succeeds {
            findings.push(GitLabCICDFinding {
                severity: "MEDIUM".to_string(),
                title: "Merge Allowed Without Pipeline Success".to_string(),
                description: "Merge requests can be merged even if pipeline fails. This bypasses automated quality and security checks.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                pipeline_id: None,
                job_name: None,
                variable_name: None,
                remediation: "Enable 'Pipelines must succeed' setting in project merge request settings.".to_string(),
                cwe: "CWE-1269".to_string(),
                cvss: 5.3,
                category: "Pipeline Enforcement".to_string(),
            });
        }

        Ok(findings)
    }

    /// Check if variable name indicates sensitive data
    fn is_sensitive_variable(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();

        let sensitive_keywords = [
            "password", "passwd", "pwd",
            "secret", "private",
            "token", "key", "api",
            "credential", "auth",
            "access", "session",
            "certificate", "cert",
        ];

        sensitive_keywords.iter().any(|keyword| name_lower.contains(keyword))
    }

    /// Get project details from GitLab API
    async fn get_project(&self, project_id: &str) -> Result<GitLabProject, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}", self.gitlab_url, project_id);
        let headers = vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())];
        let response = self.http_client
            .get_with_headers(&url, headers)
            .await?;

        let project: GitLabProject = serde_json::from_str(&response.body)?;
        Ok(project)
    }

    /// List pipelines for a project
    async fn list_pipelines(&self, project_id: &str) -> Result<Vec<GitLabPipeline>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/pipelines?per_page=10", self.gitlab_url, project_id);
        let headers = vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())];
        let response = self.http_client
            .get_with_headers(&url, headers)
            .await?;

        let pipelines: Vec<GitLabPipeline> = serde_json::from_str(&response.body)?;
        Ok(pipelines)
    }

    /// Get CI/CD configuration
    async fn get_ci_config(&self, project_id: &str) -> Result<GitLabCIConfig, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/repository/files/.gitlab-ci.yml?ref=main", self.gitlab_url, project_id);
        let headers = vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())];
        let response = self.http_client
            .get_with_headers(&url, headers)
            .await?;

        let config_raw: serde_json::Value = serde_json::from_str(&response.body)?;

        // Decode base64 content
        if let Some(content_b64) = config_raw.get("content").and_then(|v| v.as_str()) {
            let content = String::from_utf8(STANDARD.decode(content_b64)?)?;
            Ok(GitLabCIConfig { content })
        } else {
            Err("Failed to get CI config content".into())
        }
    }

    /// List CI/CD variables
    async fn list_variables(&self, project_id: &str) -> Result<Vec<GitLabVariable>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/variables", self.gitlab_url, project_id);
        let headers = vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())];
        let response = self.http_client
            .get_with_headers(&url, headers)
            .await?;

        let variables: Vec<GitLabVariable> = serde_json::from_str(&response.body)?;
        Ok(variables)
    }

    /// Get pipeline jobs
    async fn get_pipeline_jobs(&self, project_id: &str, pipeline_id: i64) -> Result<Vec<GitLabJob>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/pipelines/{}/jobs", self.gitlab_url, project_id, pipeline_id);
        let headers = vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())];
        let response = self.http_client
            .get_with_headers(&url, headers)
            .await?;

        let jobs: Vec<GitLabJob> = serde_json::from_str(&response.body)?;
        Ok(jobs)
    }
}
