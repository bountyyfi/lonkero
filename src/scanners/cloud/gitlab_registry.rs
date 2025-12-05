// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * GitLab Container Registry Security Scanner
 *
 * Scans GitLab Container Registry for security misconfigurations and vulnerabilities
 *
 * © 2025 Bountyy Oy
 */

use crate::http_client::HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct GitLabRegistryFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub project_id: String,
    pub project_name: String,
    pub repository_id: Option<i64>,
    pub repository_name: Option<String>,
    pub tag_name: Option<String>,
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
    container_registry_enabled: bool,
    #[serde(default)]
    container_registry_access_level: String,
}

#[derive(Debug, Deserialize)]
struct GitLabRepository {
    id: i64,
    name: String,
    path: String,
    location: String,
    created_at: String,
    #[serde(default)]
    cleanup_policy_started_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitLabTag {
    name: String,
    path: String,
    location: String,
    revision: String,
    short_revision: String,
    digest: String,
    created_at: String,
    total_size: i64,
}

#[derive(Debug, Deserialize)]
struct GitLabTagDetail {
    name: String,
    digest: String,
    revision: String,
    total_size: i64,
    created_at: String,
}

pub struct GitLabRegistryScanner {
    http_client: Arc<HttpClient>,
    gitlab_url: String,
    gitlab_token: String,
}

impl GitLabRegistryScanner {
    pub fn new(http_client: Arc<HttpClient>, gitlab_url: String, gitlab_token: String) -> Self {
        Self {
            http_client,
            gitlab_url: gitlab_url.trim_end_matches('/').to_string(),
            gitlab_token,
        }
    }

    /// Scan a GitLab project's container registry for security issues
    pub async fn scan_project(&self, project_id: &str) -> Result<Vec<GitLabRegistryFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Get project details
        let project = self.get_project(project_id).await?;

        // Check if container registry is enabled
        if !project.container_registry_enabled {
            findings.push(GitLabRegistryFinding {
                severity: "INFO".to_string(),
                title: "Container Registry Disabled".to_string(),
                description: format!("Project '{}' does not have Container Registry enabled.", project.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                repository_id: None,
                repository_name: None,
                tag_name: None,
                remediation: "Enable Container Registry if the project uses containers.".to_string(),
                cwe: "CWE-1188".to_string(),
                cvss: 0.0,
                category: "Registry Configuration".to_string(),
            });
            return Ok(findings);
        }

        // Check registry access level
        if project.container_registry_access_level == "enabled" && project.visibility == "public" {
            findings.push(GitLabRegistryFinding {
                severity: "HIGH".to_string(),
                title: "Public Container Registry".to_string(),
                description: format!("Project '{}' has a public container registry. Images are publicly accessible.", project.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                repository_id: None,
                repository_name: None,
                tag_name: None,
                remediation: "Restrict container registry access to project members only or make the project private.".to_string(),
                cwe: "CWE-200".to_string(),
                cvss: 7.5,
                category: "Access Control".to_string(),
            });
        }

        // Get registry repositories
        let repositories = match self.list_repositories(project_id).await {
            Ok(repos) => repos,
            Err(_) => {
                // No repositories found or access denied
                return Ok(findings);
            }
        };

        if repositories.is_empty() {
            return Ok(findings);
        }

        // Check for cleanup policy
        let has_cleanup_policy = repositories.iter().any(|r| r.cleanup_policy_started_at.is_some());

        if !has_cleanup_policy {
            findings.push(GitLabRegistryFinding {
                severity: "LOW".to_string(),
                title: "Missing Registry Cleanup Policy".to_string(),
                description: "Container registry does not have a cleanup policy configured. Old images will accumulate.".to_string(),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                repository_id: None,
                repository_name: None,
                tag_name: None,
                remediation: "Configure cleanup policies to automatically remove old or unused container images.".to_string(),
                cwe: "CWE-1188".to_string(),
                cvss: 3.1,
                category: "Resource Management".to_string(),
            });
        }

        // Scan each repository
        for repo in repositories {
            findings.extend(self.scan_repository(&project, &repo).await?);
        }

        Ok(findings)
    }

    /// Scan a specific registry repository
    async fn scan_repository(&self, project: &GitLabProject, repo: &GitLabRepository) -> Result<Vec<GitLabRegistryFinding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Get tags for this repository
        let tags = match self.list_tags(&project.id.to_string(), repo.id).await {
            Ok(tags) => tags,
            Err(_) => {
                return Ok(findings);
            }
        };

        if tags.is_empty() {
            findings.push(GitLabRegistryFinding {
                severity: "LOW".to_string(),
                title: "Empty Container Repository".to_string(),
                description: format!("Container repository '{}' exists but contains no images.", repo.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                repository_id: Some(repo.id),
                repository_name: Some(repo.name.clone()),
                tag_name: None,
                remediation: "Remove unused repositories or push container images to them.".to_string(),
                cwe: "CWE-1188".to_string(),
                cvss: 2.0,
                category: "Resource Management".to_string(),
            });
            return Ok(findings);
        }

        // Check for untagged images (using 'latest' or 'untagged')
        let has_latest = tags.iter().any(|t| t.name == "latest");
        if has_latest {
            findings.push(GitLabRegistryFinding {
                severity: "MEDIUM".to_string(),
                title: "Container Image Using 'latest' Tag".to_string(),
                description: format!("Repository '{}' contains images tagged as 'latest'. This is not recommended for production.", repo.name),
                project_id: project.id.to_string(),
                project_name: project.name.clone(),
                repository_id: Some(repo.id),
                repository_name: Some(repo.name.clone()),
                tag_name: Some("latest".to_string()),
                remediation: "Use semantic versioning or commit SHA for container image tags. Avoid 'latest' in production.".to_string(),
                cwe: "CWE-1088".to_string(),
                cvss: 5.3,
                category: "Versioning".to_string(),
            });
        }

        // Check for old images (older than 90 days)
        let ninety_days_ago = Utc::now() - Duration::days(90);

        for tag in &tags {
            if let Ok(created_at) = tag.created_at.parse::<DateTime<Utc>>() {
                if created_at < ninety_days_ago {
                    findings.push(GitLabRegistryFinding {
                        severity: "LOW".to_string(),
                        title: "Outdated Container Image".to_string(),
                        description: format!("Image '{}:{}' is older than 90 days and may contain unpatched vulnerabilities.", repo.name, tag.name),
                        project_id: project.id.to_string(),
                        project_name: project.name.clone(),
                        repository_id: Some(repo.id),
                        repository_name: Some(repo.name.clone()),
                        tag_name: Some(tag.name.clone()),
                        remediation: "Rebuild and push updated container images regularly to include security patches.".to_string(),
                        cwe: "CWE-1104".to_string(),
                        cvss: 4.3,
                        category: "Image Age".to_string(),
                    });
                }
            }
        }

        // Check for excessive image layers (more than 50 layers)
        for tag in &tags {
            // Get detailed tag information
            if let Ok(tag_detail) = self.get_tag_detail(&project.id.to_string(), repo.id, &tag.name).await {
                // Check image size (larger than 1GB)
                if tag_detail.total_size > 1_073_741_824 {
                    findings.push(GitLabRegistryFinding {
                        severity: "MEDIUM".to_string(),
                        title: "Large Container Image Size".to_string(),
                        description: format!("Image '{}:{}' is larger than 1GB ({} bytes). Large images slow down deployments.",
                            repo.name, tag.name, tag_detail.total_size),
                        project_id: project.id.to_string(),
                        project_name: project.name.clone(),
                        repository_id: Some(repo.id),
                        repository_name: Some(repo.name.clone()),
                        tag_name: Some(tag.name.clone()),
                        remediation: "Optimize Dockerfile: use multi-stage builds, minimize layers, use alpine base images, clean up package caches.".to_string(),
                        cwe: "CWE-1094".to_string(),
                        cvss: 4.3,
                        category: "Image Size".to_string(),
                    });
                }
            }
        }

        // Check for missing vulnerability scanning
        // Note: This would require integration with GitLab vulnerability scanning features
        findings.push(GitLabRegistryFinding {
            severity: "MEDIUM".to_string(),
            title: "Container Vulnerability Scanning Recommendation".to_string(),
            description: format!("Repository '{}' should have automated vulnerability scanning enabled.", repo.name),
            project_id: project.id.to_string(),
            project_name: project.name.clone(),
            repository_id: Some(repo.id),
            repository_name: Some(repo.name.clone()),
            tag_name: None,
            remediation: "Enable GitLab Container Scanning or integrate with Trivy, Clair, or Anchore for automated vulnerability detection.".to_string(),
            cwe: "CWE-1395".to_string(),
            cvss: 5.3,
            category: "Vulnerability Scanning".to_string(),
        });

        // Check for tag protection
        findings.push(GitLabRegistryFinding {
            severity: "LOW".to_string(),
            title: "Tag Protection Recommendation".to_string(),
            description: format!("Consider enabling tag protection for repository '{}' to prevent accidental deletion of production images.", repo.name),
            project_id: project.id.to_string(),
            project_name: project.name.clone(),
            repository_id: Some(repo.id),
            repository_name: Some(repo.name.clone()),
            tag_name: None,
            remediation: "Configure protected tags in GitLab to prevent deletion of important image versions.".to_string(),
            cwe: "CWE-1164".to_string(),
            cvss: 3.7,
            category: "Tag Protection".to_string(),
        });

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

    /// List container registry repositories
    async fn list_repositories(&self, project_id: &str) -> Result<Vec<GitLabRepository>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/registry/repositories", self.gitlab_url, project_id);
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let repositories: Vec<GitLabRepository> = serde_json::from_str(&response.body)?;
        Ok(repositories)
    }

    /// List tags in a repository
    async fn list_tags(&self, project_id: &str, repository_id: i64) -> Result<Vec<GitLabTag>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/registry/repositories/{}/tags",
            self.gitlab_url, project_id, repository_id);
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let tags: Vec<GitLabTag> = serde_json::from_str(&response.body)?;
        Ok(tags)
    }

    /// Get detailed tag information
    async fn get_tag_detail(&self, project_id: &str, repository_id: i64, tag_name: &str) -> Result<GitLabTagDetail, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v4/projects/{}/registry/repositories/{}/tags/{}",
            self.gitlab_url, project_id, repository_id, urlencoding::encode(tag_name));
        let response = self.http_client
            .get_with_headers(&url, vec![("PRIVATE-TOKEN".to_string(), self.gitlab_token.clone())])
            .await?;

        let tag: GitLabTagDetail = serde_json::from_str(&response.body)?;
        Ok(tag)
    }
}
