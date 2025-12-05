// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * GitLab Code Security Scanner
 *
 * Scans GitLab repositories for security misconfigurations and exposed secrets
 *
 * © 2025 Bountyy Oy
 */

use crate::http_client::HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Debug, Serialize, Deserialize)]
pub struct GitLabCodeFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub project_id: String,
    pub project_name: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub branch_name: Option<String>,
    pub secret_type: Option<String>,
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
    only_allow_merge_if_pipeline_succeeds: bool,
    #[serde(default)]
    only_allow_merge_if_all_discussions_are_resolved: bool,
    #[serde(default)]
    merge_requests_enabled: bool,
    #[serde(default)]
    approvals_before_merge: i32,
    default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitLabBranch {
    name: String,
    #[serde(default)]
    protected: bool,
    #[serde(default)]
    developers_can_push: bool,
    #[serde(default)]
    developers_can_merge: bool,
}

#[derive(Debug, Deserialize)]
struct GitLabProtectedBranch {
    name: String,
    push_access_levels: Vec<AccessLevel>,
    merge_access_levels: Vec<AccessLevel>,
    #[serde(default)]
    allow_force_push: bool,
}

#[derive(Debug, Deserialize)]
struct AccessLevel {
    access_level: i32,
    access_level_description: String,
}

#[derive(Debug, Deserialize)]
struct GitLabMergeRequest {
    iid: i64,
    title: String,
    state: String,
    #[serde(default)]
    merge_status: String,
    #[serde(default)]
    upvotes: i32,
    #[serde(default)]
    downvotes: i32,
}

#[derive(Debug, Deserialize)]
struct GitLabSearchResult {
    basename: String,
    data: String,
    path: String,
    filename: String,
    #[serde(default)]
    startline: i32,
    #[serde(rename = "ref")]
    git_ref: String,
}

pub struct GitLabCodeScanner {
    http_client: Arc<HttpClient>,
    gitlab_url: String,
    gitlab_token: String,
}

impl GitLabCodeScanner {
    pub fn new(http_client: Arc<HttpClient>, gitlab_url: String, gitlab_token: String) -> Self {
        Self {
            http_client,
            gitlab_url: gitlab_url.trim_end_matches('/').to_string(),
            gitlab_token,
        }
    }

    /// Scan a GitLab project for code security issues
    pub async fn scan_project(&self, project_id: &str) -> Result<Vec<GitLabCodeFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Get project details
        let project = self.get_project(project_id).await?;

        // Check project visibility
        if project.visibility == "public" {
            findings.push(GitLabCodeFinding {
                severity: "HIGH".to_string(),
                title: "Public Project Repository".to_string(),
                description: format!("Project '{}' is publicly accessible. Source code and potentially sensitive data are exposed.", project.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                file_path: None,
                line_number: None,
                branch_name: None,
                secret_type: None,
                remediation: "Make the project private or internal unless it's intended to be open source.".to_string(),
                cwe: "CWE-200".to_string(),
                cvss: 7.5,
                category: "Access Control".to_string(),
            });
        }

        // Check branch protection
        findings.extend(self.scan_branch_protection(&project).await?);

        // Check merge request settings
        findings.extend(self.scan_merge_request_settings(&project).await?);

        // Scan for exposed secrets
        findings.extend(self.scan_for_secrets(&project).await?);

        // Check security features
        findings.extend(self.scan_security_features(&project).await?);

        Ok(findings)
    }

    /// Scan branch protection settings
    async fn scan_branch_protection(&self, project: &GitLabProject) -> Result<Vec<GitLabCodeFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Get default branch
        let default_branch = project.default_branch.as_ref().unwrap_or(&"main".to_string()).clone();

        // Check if default branch is protected
        match self.get_protected_branch(&project.id.to_string(), &default_branch).await {
            Ok(protected_branch) => {
                // Check if force push is allowed
                if protected_branch.allow_force_push {
                    findings.push(GitLabCodeFinding {
                        severity: "HIGH".to_string(),
                        title: "Force Push Allowed on Default Branch".to_string(),
                        description: format!("Default branch '{}' allows force push, which can rewrite history and remove commits.", default_branch),
                        project_id: project.id.to_string(),
                        project_name: project.name.clone(),
                        file_path: None,
                        line_number: None,
                        branch_name: Some(default_branch.clone()),
                        secret_type: None,
                        remediation: "Disable force push on protected branches to prevent history rewriting.".to_string(),
                        cwe: "CWE-284".to_string(),
                        cvss: 7.5,
                        category: "Branch Protection".to_string(),
                    });
                }

                // Check push access levels
                let has_developer_push = protected_branch.push_access_levels.iter()
                    .any(|level| level.access_level == 30); // 30 = Developer

                if has_developer_push {
                    findings.push(GitLabCodeFinding {
                        severity: "MEDIUM".to_string(),
                        title: "Developers Can Push to Default Branch".to_string(),
                        description: format!("Developers have direct push access to default branch '{}', bypassing code review.", default_branch),
                        project_id: project.id.to_string(),
                        project_name: project.name.clone(),
                        file_path: None,
                        line_number: None,
                        branch_name: Some(default_branch.clone()),
                        secret_type: None,
                        remediation: "Restrict push access to Maintainers only. Require all changes to go through merge requests.".to_string(),
                        cwe: "CWE-732".to_string(),
                        cvss: 5.3,
                        category: "Branch Protection".to_string(),
                    });
                }
            }
            Err(_) => {
                // Default branch is not protected
                findings.push(GitLabCodeFinding {
                    severity: "CRITICAL".to_string(),
                    title: "Default Branch Not Protected".to_string(),
                    description: format!("Default branch '{}' is not protected. Anyone with push access can modify it directly.", default_branch),
                    project_id: project.id.to_string(),
                    project_name: project.name.clone(),
                    file_path: None,
                    line_number: None,
                    branch_name: Some(default_branch.clone()),
                    secret_type: None,
                    remediation: "Enable branch protection for the default branch. Require merge requests and code reviews.".to_string(),
                    cwe: "CWE-732".to_string(),
                    cvss: 9.1,
                    category: "Branch Protection".to_string(),
                });
            }
        }

        Ok(findings)
    }

    /// Scan merge request settings
    async fn scan_merge_request_settings(&self, project: &GitLabProject) -> Result<Vec<GitLabCodeFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Check if merge requests are enabled
        if !project.merge_requests_enabled {
            findings.push(GitLabCodeFinding {
                severity: "MEDIUM".to_string(),
                title: "Merge Requests Disabled".to_string(),
                description: "Merge requests are disabled. All changes are pushed directly without code review.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                file_path: None,
                line_number: None,
                branch_name: None,
                secret_type: None,
                remediation: "Enable merge requests and require code review for all changes.".to_string(),
                cwe: "CWE-1259".to_string(),
                cvss: 5.3,
                category: "Code Review".to_string(),
            });
        }

        // Check if approvals are required
        if project.approvals_before_merge == 0 {
            findings.push(GitLabCodeFinding {
                severity: "MEDIUM".to_string(),
                title: "No Required Approvals for Merge Requests".to_string(),
                description: "Merge requests can be merged without any approvals, bypassing code review.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                file_path: None,
                line_number: None,
                branch_name: None,
                secret_type: None,
                remediation: "Configure minimum number of required approvals (recommend at least 1 for small teams, 2+ for larger teams).".to_string(),
                cwe: "CWE-1259".to_string(),
                cvss: 5.3,
                category: "Code Review".to_string(),
            });
        }

        // Check if pipeline success is required
        if !project.only_allow_merge_if_pipeline_succeeds {
            findings.push(GitLabCodeFinding {
                severity: "MEDIUM".to_string(),
                title: "Merge Allowed Without Pipeline Success".to_string(),
                description: "Merge requests can be merged even if CI/CD pipeline fails, bypassing automated tests.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                file_path: None,
                line_number: None,
                branch_name: None,
                secret_type: None,
                remediation: "Enable 'Pipelines must succeed' in project merge request settings.".to_string(),
                cwe: "CWE-1269".to_string(),
                cvss: 5.3,
                category: "Pipeline Enforcement".to_string(),
            });
        }

        // Check if all discussions must be resolved
        if !project.only_allow_merge_if_all_discussions_are_resolved {
            findings.push(GitLabCodeFinding {
                severity: "LOW".to_string(),
                title: "Merge Allowed With Unresolved Discussions".to_string(),
                description: "Merge requests can be merged with unresolved review comments.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                file_path: None,
                line_number: None,
                branch_name: None,
                secret_type: None,
                remediation: "Enable 'All discussions must be resolved' to ensure all review comments are addressed.".to_string(),
                cwe: "CWE-1259".to_string(),
                cvss: 3.7,
                category: "Code Review".to_string(),
            });
        }

        Ok(findings)
    }

    /// Scan for exposed secrets using TruffleHog-like patterns
    async fn scan_for_secrets(&self, project: &GitLabProject) -> Result<Vec<GitLabCodeFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Secret patterns (TruffleHog-inspired)
        let secret_patterns = vec![
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CWE-798", 9.8),
            ("AWS Secret Key", r#"(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z/+]{40}['"]"#, "CWE-798", 9.8),
            ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}", "CWE-798", 9.8),
            ("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20}", "CWE-798", 9.8),
            ("Private Key", r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "CWE-798", 9.8),
            ("Generic API Key", r#"(?i)(api[_-]?key|apikey)(.{0,20})?['"][0-9a-zA-Z]{32,45}['"]"#, "CWE-798", 8.5),
            ("Generic Secret", r#"(?i)(secret|password|passwd|pwd)(.{0,20})?['"][0-9a-zA-Z]{8,}['"]"#, "CWE-798", 7.5),
            ("Database URL", r"(?i)(postgres|mysql|mongodb)://[^\\s]+:[^\\s]+@", "CWE-798", 8.0),
            ("JWT Token", r"eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*", "CWE-522", 7.5),
            ("Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}", "CWE-798", 8.5),
        ];

        // Search for each secret pattern
        for (secret_type, pattern, cwe, cvss) in secret_patterns {
            match self.search_code(&project.id.to_string(), pattern).await {
                Ok(results) => {
                    for result in results {
                        findings.push(GitLabCodeFinding {
                            severity: "CRITICAL".to_string(),
                            title: format!("Exposed {} in Code", secret_type),
                            description: format!("Found potential {} in file '{}'. This credential should never be committed to version control.",
                                secret_type, result.path),
                            project_id: project.id.to_string(),
                            project_name: project.name.clone(),
                            file_path: Some(result.path.clone()),
                            line_number: Some(result.startline),
                            branch_name: Some(result.git_ref.clone()),
                            secret_type: Some(secret_type.to_string()),
                            remediation: format!("1. Immediately revoke the exposed {}. 2. Remove it from version control history (git filter-branch or BFG). 3. Use environment variables or secret management tools.", secret_type),
                            cwe: cwe.to_string(),
                            cvss,
                            category: "Exposed Secrets".to_string(),
                        });
                    }
                }
                Err(_) => {
                    // Search failed or no results - continue
                }
            }
        }

        Ok(findings)
    }

    /// Scan security features
    async fn scan_security_features(&self, project: &GitLabProject) -> Result<Vec<GitLabCodeFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Check for security scanning configuration files
        let security_files = vec![
            (".gitlab-ci.yml", "CI/CD Pipeline"),
            ("SECURITY.md", "Security Policy"),
            (".dependabot.yml", "Dependency Updates"),
            ("renovate.json", "Dependency Updates"),
        ];

        for (filename, feature) in security_files {
            match self.get_file(&project.id.to_string(), filename).await {
                Ok(_) => {
                    // File exists - good
                }
                Err(_) => {
                    if filename == ".gitlab-ci.yml" {
                        findings.push(GitLabCodeFinding {
                            severity: "MEDIUM".to_string(),
                            title: "Missing CI/CD Configuration".to_string(),
                            description: format!("Project is missing {} configuration file.", feature),
                            project_id: project.id.to_string(),
                            project_name: project.name.clone(),
                            file_path: Some(filename.to_string()),
                            line_number: None,
                            branch_name: None,
                            secret_type: None,
                            remediation: format!("Add {} configuration to enable automated security scanning and testing.", filename),
                            cwe: "CWE-1008".to_string(),
                            cvss: 5.3,
                            category: "Security Configuration".to_string(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Get project details from GitLab API
    async fn get_project(&self, project_id: &str) -> Result<GitLabProject, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}", self.gitlab_url, project_id);
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let project: GitLabProject = serde_json::from_str(&response.body)?;
        Ok(project)
    }

    /// Get protected branch details
    async fn get_protected_branch(&self, project_id: &str, branch_name: &str) -> Result<GitLabProtectedBranch, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/protected_branches/{}",
            self.gitlab_url, project_id, urlencoding::encode(branch_name));
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let branch: GitLabProtectedBranch = serde_json::from_str(&response.body)?;
        Ok(branch)
    }

    /// Search code in project
    async fn search_code(&self, project_id: &str, query: &str) -> Result<Vec<GitLabSearchResult>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/search?scope=blobs&search={}",
            self.gitlab_url, project_id, urlencoding::encode(query));
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let results: Vec<GitLabSearchResult> = serde_json::from_str(&response.body)?;
        Ok(results)
    }

    /// Get file from repository
    async fn get_file(&self, project_id: &str, file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/repository/files/{}?ref=main",
            self.gitlab_url, project_id, urlencoding::encode(file_path));
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let file_data: serde_json::Value = serde_json::from_str(&response.body)?;

        if let Some(content_b64) = file_data.get("content").and_then(|v| v.as_str()) {
            let content = String::from_utf8(STANDARD.decode(content_b64)?)?;
            Ok(content)
        } else {
            Err("Failed to get file content".into())
        }
    }
}
