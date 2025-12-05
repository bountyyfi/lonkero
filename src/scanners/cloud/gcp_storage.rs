// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GCP Cloud Storage Scanner
 * Production-grade GCS vulnerability scanner
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;
use reqwest::Client;
use tracing::{debug, info};

/// GCS bucket vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsVulnerability {
    pub id: String,
    pub severity: VulnerabilitySeverity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub resource_type: String,
    pub resource_name: String,
    pub project_id: String,
    pub location: Option<String>,
    pub remediation: String,
    pub compliance: Vec<String>,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// GCS bucket details
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcsBucket {
    pub name: String,
    pub location: String,
    pub storage_class: String,
    pub created: String,
    pub updated: Option<String>,
    pub encryption: Option<BucketEncryption>,
    pub versioning: bool,
    pub logging: bool,
    pub lifecycle: Vec<LifecycleRule>,
    pub cors: Vec<CorsConfig>,
    pub uniform_bucket_level_access: bool,
    pub is_public: bool,
    pub retention_policy: Option<RetentionPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryption {
    pub default_kms_key_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LifecycleRule {
    pub action: LifecycleAction,
    pub condition: LifecycleCondition,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub storage_class: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleCondition {
    pub age: Option<u32>,
    pub created_before: Option<String>,
    pub is_live: Option<bool>,
    pub num_newer_versions: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorsConfig {
    pub origin: Vec<String>,
    pub method: Vec<String>,
    pub response_header: Option<Vec<String>>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    pub retention_period: Option<String>,
    pub effective_time: Option<String>,
    pub is_locked: Option<bool>,
}

/// IAM policy for bucket
#[derive(Debug, Clone, Deserialize)]
pub struct IamPolicy {
    pub bindings: Vec<IamBinding>,
    pub etag: Option<String>,
    pub version: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IamBinding {
    pub role: String,
    pub members: Vec<String>,
    pub condition: Option<IamCondition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IamCondition {
    pub expression: String,
    pub title: Option<String>,
    pub description: Option<String>,
}

/// GCP Cloud Storage Scanner
pub struct GcpStorageScanner {
    client: Client,
    access_token: Option<String>,
}

impl GcpStorageScanner {
    /// Create a new GCS scanner
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            access_token: None,
        }
    }

    /// Set access token for authentication
    pub fn with_access_token(mut self, token: String) -> Self {
        self.access_token = Some(token);
        self
    }

    /// Scan GCS buckets for vulnerabilities
    pub async fn scan_buckets(
        &self,
        project_id: &str,
        buckets: &[GcsBucket],
        iam_policies: &HashMap<String, IamPolicy>,
    ) -> Result<Vec<GcsVulnerability>> {
        info!("Starting GCS bucket scan for project {}", project_id);

        let mut vulnerabilities = Vec::new();

        for bucket in buckets {
            // Check for public buckets
            if let Some(vuln) = self.check_public_bucket(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check IAM policy for public access
            if let Some(policy) = iam_policies.get(&bucket.name) {
                if let Some(vulns) = self.check_bucket_iam_policy(project_id, bucket, policy) {
                    vulnerabilities.extend(vulns);
                }
            }

            // Check for uniform bucket-level access
            if let Some(vuln) = self.check_uniform_bucket_level_access(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check encryption
            if let Some(vuln) = self.check_bucket_encryption(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check versioning
            if let Some(vuln) = self.check_versioning(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check logging
            if let Some(vuln) = self.check_logging(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check retention policy
            if let Some(vuln) = self.check_retention_policy(project_id, bucket) {
                vulnerabilities.push(vuln);
            }

            // Check CORS configuration
            if let Some(vulns) = self.check_cors_configuration(project_id, bucket) {
                vulnerabilities.extend(vulns);
            }

            // Check lifecycle rules
            if let Some(vuln) = self.check_lifecycle_rules(project_id, bucket) {
                vulnerabilities.push(vuln);
            }
        }

        info!("GCS bucket scan completed: {} vulnerabilities found", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Check for publicly accessible buckets
    fn check_public_bucket(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if bucket.is_public {
            debug!("Bucket {} is publicly accessible", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-public-bucket-{}", bucket.name),
                severity: VulnerabilitySeverity::Critical,
                category: "Data Exposure".to_string(),
                title: "Publicly Accessible GCS Bucket".to_string(),
                description: format!(
                    "Bucket '{}' is publicly accessible. This allows anyone on the internet \
                    to access the bucket's contents, potentially exposing sensitive data.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Remove public access from the bucket. Use signed URLs or Cloud CDN \
                    for controlled public access. Enable uniform bucket-level access and review IAM policies.".to_string(),
                compliance: vec![
                    "CIS GCP 5.1".to_string(),
                    "NIST 800-53 AC-3".to_string(),
                    "PCI DSS 1.2.1".to_string()
                ],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check bucket IAM policy for public access
    fn check_bucket_iam_policy(
        &self,
        project_id: &str,
        bucket: &GcsBucket,
        policy: &IamPolicy,
    ) -> Option<Vec<GcsVulnerability>> {
        let mut vulnerabilities = Vec::new();

        for binding in &policy.bindings {
            // Check for allUsers or allAuthenticatedUsers
            let has_all_users = binding.members.iter().any(|m| m == "allUsers");
            let has_all_authenticated = binding.members.iter().any(|m| m == "allAuthenticatedUsers");

            if has_all_users {
                debug!("Bucket {} has allUsers in IAM policy for role {}", bucket.name, binding.role);

                vulnerabilities.push(GcsVulnerability {
                    id: format!("gcs-iam-all-users-{}-{}", bucket.name, binding.role),
                    severity: VulnerabilitySeverity::Critical,
                    category: "IAM & Permissions".to_string(),
                    title: "GCS Bucket Grants Public Access via IAM".to_string(),
                    description: format!(
                        "Bucket '{}' grants access to 'allUsers' with role '{}'. \
                        This makes the bucket publicly accessible to anyone on the internet.",
                        bucket.name, binding.role
                    ),
                    resource_type: "storage.googleapis.com/Bucket".to_string(),
                    resource_name: bucket.name.clone(),
                    project_id: project_id.to_string(),
                    location: Some(bucket.location.clone()),
                    remediation: "Remove 'allUsers' from IAM bindings. Use specific service accounts \
                        or user groups for access control. Consider using signed URLs for temporary access.".to_string(),
                    compliance: vec!["CIS GCP 5.1".to_string(), "NIST 800-53 AC-3".to_string()],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            if has_all_authenticated {
                debug!("Bucket {} has allAuthenticatedUsers in IAM policy for role {}", bucket.name, binding.role);

                vulnerabilities.push(GcsVulnerability {
                    id: format!("gcs-iam-all-auth-{}-{}", bucket.name, binding.role),
                    severity: VulnerabilitySeverity::High,
                    category: "IAM & Permissions".to_string(),
                    title: "GCS Bucket Accessible to All Authenticated Users".to_string(),
                    description: format!(
                        "Bucket '{}' grants access to 'allAuthenticatedUsers' with role '{}'. \
                        This allows any authenticated Google account to access the bucket.",
                        bucket.name, binding.role
                    ),
                    resource_type: "storage.googleapis.com/Bucket".to_string(),
                    resource_name: bucket.name.clone(),
                    project_id: project_id.to_string(),
                    location: Some(bucket.location.clone()),
                    remediation: "Remove 'allAuthenticatedUsers' from IAM bindings. Grant access only \
                        to specific service accounts or groups that require it.".to_string(),
                    compliance: vec!["CIS GCP 5.1".to_string(), "NIST 800-53 AC-3".to_string()],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for overly broad roles
            let is_owner = binding.role.contains("roles/storage.objectAdmin") ||
                binding.role.contains("roles/storage.admin");

            if is_owner && binding.members.len() > 5 {
                debug!("Bucket {} has broad admin access for {} members", bucket.name, binding.members.len());

                vulnerabilities.push(GcsVulnerability {
                    id: format!("gcs-broad-admin-{}", bucket.name),
                    severity: VulnerabilitySeverity::Medium,
                    category: "IAM & Permissions".to_string(),
                    title: "GCS Bucket with Overly Broad Admin Access".to_string(),
                    description: format!(
                        "Bucket '{}' grants admin access ({}) to {} members. \
                        Consider reducing the number of admins and using more granular roles.",
                        bucket.name, binding.role, binding.members.len()
                    ),
                    resource_type: "storage.googleapis.com/Bucket".to_string(),
                    resource_name: bucket.name.clone(),
                    project_id: project_id.to_string(),
                    location: Some(bucket.location.clone()),
                    remediation: "Apply the principle of least privilege. Use granular roles like \
                        storage.objectCreator or storage.objectViewer instead of admin roles.".to_string(),
                    compliance: vec!["NIST 800-53 AC-6".to_string()],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        if vulnerabilities.is_empty() {
            None
        } else {
            Some(vulnerabilities)
        }
    }

    /// Check for uniform bucket-level access
    fn check_uniform_bucket_level_access(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if !bucket.uniform_bucket_level_access {
            debug!("Bucket {} does not have uniform bucket-level access enabled", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-ubla-{}", bucket.name),
                severity: VulnerabilitySeverity::Medium,
                category: "Access Control".to_string(),
                title: "GCS Bucket Without Uniform Bucket-Level Access".to_string(),
                description: format!(
                    "Bucket '{}' does not have uniform bucket-level access enabled. \
                    This allows object-level ACLs, which can lead to inconsistent access controls.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Enable uniform bucket-level access to enforce IAM policies consistently. \
                    This disables ACLs and uses only IAM for access control.".to_string(),
                compliance: vec!["CIS GCP 5.2".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check bucket encryption
    fn check_bucket_encryption(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        let has_cmek = bucket.encryption.as_ref()
            .and_then(|enc| enc.default_kms_key_name.as_ref())
            .is_some();

        if !has_cmek {
            debug!("Bucket {} not encrypted with CMEK", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-cmek-{}", bucket.name),
                severity: VulnerabilitySeverity::Medium,
                category: "Encryption".to_string(),
                title: "GCS Bucket Without Customer-Managed Encryption Key (CMEK)".to_string(),
                description: format!(
                    "Bucket '{}' is not encrypted with a customer-managed encryption key (CMEK). \
                    While Google encrypts all data at rest, using CMEK provides additional control.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Enable CMEK encryption using Cloud KMS keys. Implement key rotation \
                    policies and access controls for encryption keys.".to_string(),
                compliance: vec!["CIS GCP 5.3".to_string(), "NIST 800-53 SC-28".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check versioning configuration
    fn check_versioning(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if !bucket.versioning {
            debug!("Bucket {} does not have versioning enabled", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-versioning-{}", bucket.name),
                severity: VulnerabilitySeverity::Low,
                category: "Data Protection".to_string(),
                title: "GCS Bucket Without Versioning".to_string(),
                description: format!(
                    "Bucket '{}' does not have versioning enabled. \
                    Versioning helps protect against accidental deletion or modification of objects.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Enable object versioning to maintain multiple versions of objects. \
                    Configure lifecycle rules to manage old versions and control storage costs.".to_string(),
                compliance: vec!["CIS GCP 5.4".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check logging configuration
    fn check_logging(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if !bucket.logging {
            debug!("Bucket {} does not have access logging enabled", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-logging-{}", bucket.name),
                severity: VulnerabilitySeverity::Medium,
                category: "Logging & Monitoring".to_string(),
                title: "GCS Bucket Without Access Logging".to_string(),
                description: format!(
                    "Bucket '{}' does not have access logging enabled. \
                    Access logs are crucial for security monitoring and compliance.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Enable access logging to track all requests to the bucket. \
                    Store logs in a separate bucket with appropriate retention policies.".to_string(),
                compliance: vec![
                    "CIS GCP 5.5".to_string(),
                    "NIST 800-53 AU-2".to_string(),
                    "PCI DSS 10.2.1".to_string()
                ],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check retention policy
    fn check_retention_policy(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if bucket.retention_policy.is_none() {
            debug!("Bucket {} does not have a retention policy", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-retention-{}", bucket.name),
                severity: VulnerabilitySeverity::Info,
                category: "Data Protection".to_string(),
                title: "GCS Bucket Without Retention Policy".to_string(),
                description: format!(
                    "Bucket '{}' does not have a retention policy configured. \
                    Retention policies help prevent accidental or malicious deletion of data.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Configure a retention policy appropriate for your data compliance requirements. \
                    Lock the policy if immutability is required.".to_string(),
                compliance: vec!["GDPR Article 17".to_string(), "HIPAA 164.316(b)(2)".to_string()],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }

    /// Check CORS configuration
    fn check_cors_configuration(&self, project_id: &str, bucket: &GcsBucket) -> Option<Vec<GcsVulnerability>> {
        let mut vulnerabilities = Vec::new();

        for (idx, cors) in bucket.cors.iter().enumerate() {
            // Check for wildcard origins
            if cors.origin.iter().any(|o| o == "*") {
                debug!("Bucket {} has wildcard CORS origin", bucket.name);

                vulnerabilities.push(GcsVulnerability {
                    id: format!("gcs-cors-wildcard-{}-{}", bucket.name, idx),
                    severity: VulnerabilitySeverity::Medium,
                    category: "Configuration".to_string(),
                    title: "GCS Bucket with Overly Permissive CORS".to_string(),
                    description: format!(
                        "Bucket '{}' has a CORS configuration with wildcard origin (*). \
                        This allows any website to make requests to the bucket.",
                        bucket.name
                    ),
                    resource_type: "storage.googleapis.com/Bucket".to_string(),
                    resource_name: bucket.name.clone(),
                    project_id: project_id.to_string(),
                    location: Some(bucket.location.clone()),
                    remediation: "Specify explicit origins in CORS configuration instead of using wildcards. \
                        Limit allowed methods to only those required.".to_string(),
                    compliance: vec!["OWASP API Security Top 10".to_string()],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }

            // Check for dangerous methods
            let dangerous_methods = ["PUT", "DELETE", "POST"];
            let has_dangerous = cors.method.iter()
                .any(|m| dangerous_methods.contains(&m.as_str()));

            if has_dangerous && cors.origin.len() > 10 {
                debug!("Bucket {} has CORS with dangerous methods for many origins", bucket.name);

                vulnerabilities.push(GcsVulnerability {
                    id: format!("gcs-cors-dangerous-{}-{}", bucket.name, idx),
                    severity: VulnerabilitySeverity::Low,
                    category: "Configuration".to_string(),
                    title: "GCS Bucket CORS Allows Dangerous Methods".to_string(),
                    description: format!(
                        "Bucket '{}' has a CORS configuration allowing write operations (PUT/DELETE/POST) \
                        for {} origins. Review if this is necessary.",
                        bucket.name, cors.origin.len()
                    ),
                    resource_type: "storage.googleapis.com/Bucket".to_string(),
                    resource_name: bucket.name.clone(),
                    project_id: project_id.to_string(),
                    location: Some(bucket.location.clone()),
                    remediation: "Restrict CORS methods to read-only (GET, HEAD) unless write operations \
                        are specifically required. Limit origins to trusted domains only.".to_string(),
                    compliance: vec![],
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        if vulnerabilities.is_empty() {
            None
        } else {
            Some(vulnerabilities)
        }
    }

    /// Check lifecycle rules
    fn check_lifecycle_rules(&self, project_id: &str, bucket: &GcsBucket) -> Option<GcsVulnerability> {
        if bucket.lifecycle.is_empty() {
            debug!("Bucket {} does not have lifecycle rules", bucket.name);

            return Some(GcsVulnerability {
                id: format!("gcs-no-lifecycle-{}", bucket.name),
                severity: VulnerabilitySeverity::Info,
                category: "Cost Optimization".to_string(),
                title: "GCS Bucket Without Lifecycle Rules".to_string(),
                description: format!(
                    "Bucket '{}' does not have lifecycle management rules configured. \
                    Lifecycle rules help optimize storage costs by automatically managing object lifecycle.",
                    bucket.name
                ),
                resource_type: "storage.googleapis.com/Bucket".to_string(),
                resource_name: bucket.name.clone(),
                project_id: project_id.to_string(),
                location: Some(bucket.location.clone()),
                remediation: "Configure lifecycle rules to automatically transition objects to cheaper \
                    storage classes or delete old objects. This helps optimize storage costs.".to_string(),
                compliance: vec![],
                discovered_at: chrono::Utc::now().to_rfc3339(),
            });
        }
        None
    }
}

impl Default for GcpStorageScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_public_bucket() {
        let scanner = GcpStorageScanner::new();
        let bucket = GcsBucket {
            name: "test-bucket".to_string(),
            location: "us-central1".to_string(),
            storage_class: "STANDARD".to_string(),
            created: "2024-01-01T00:00:00Z".to_string(),
            updated: None,
            encryption: None,
            versioning: false,
            logging: false,
            lifecycle: vec![],
            cors: vec![],
            uniform_bucket_level_access: false,
            is_public: true,
            retention_policy: None,
        };

        let vuln = scanner.check_public_bucket("test-project", &bucket);
        assert!(vuln.is_some());

        let vuln = vuln.unwrap();
        assert_eq!(vuln.severity as i32, VulnerabilitySeverity::Critical as i32);
        assert!(vuln.title.contains("Publicly Accessible"));
    }

    #[test]
    fn test_check_uniform_bucket_level_access() {
        let scanner = GcpStorageScanner::new();
        let bucket = GcsBucket {
            name: "test-bucket".to_string(),
            location: "us-central1".to_string(),
            storage_class: "STANDARD".to_string(),
            created: "2024-01-01T00:00:00Z".to_string(),
            updated: None,
            encryption: None,
            versioning: false,
            logging: false,
            lifecycle: vec![],
            cors: vec![],
            uniform_bucket_level_access: false,
            is_public: false,
            retention_policy: None,
        };

        let vuln = scanner.check_uniform_bucket_level_access("test-project", &bucket);
        assert!(vuln.is_some());
    }

    #[test]
    fn test_check_versioning() {
        let scanner = GcpStorageScanner::new();
        let bucket = GcsBucket {
            name: "test-bucket".to_string(),
            location: "us-central1".to_string(),
            storage_class: "STANDARD".to_string(),
            created: "2024-01-01T00:00:00Z".to_string(),
            updated: None,
            encryption: None,
            versioning: false,
            logging: false,
            lifecycle: vec![],
            cors: vec![],
            uniform_bucket_level_access: true,
            is_public: false,
            retention_policy: None,
        };

        let vuln = scanner.check_versioning("test-project", &bucket);
        assert!(vuln.is_some());

        let vuln = vuln.unwrap();
        assert_eq!(vuln.severity as i32, VulnerabilitySeverity::Low as i32);
    }
}
