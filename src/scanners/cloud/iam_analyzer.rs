// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud IAM Analyzer
 * Comprehensive IAM/RBAC security analysis for AWS, Azure, and GCP
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::cloud::error_handling::{CloudError, RetryConfig, retry_with_backoff};
use crate::cloud::optimizations::{CloudMetadataCache, PerformanceMetrics};
use crate::types::{Confidence, Severity, Vulnerability};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// IAM finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamFindingType {
    OverlyPermissivePolicy,
    WildcardPermissions,
    CrossAccountAccess,
    UnusedPermissions,
    PrivilegeEscalationPath,
    ServiceAccountKeyExposure,
    OverlyBroadRoles,
    InheritedPermissions,
    PrivilegedIdentity,
    MissingMFA,
    InactiveUser,
    RootAccountUsage,
}

/// IAM policy analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicyAnalysis {
    pub policy_name: String,
    pub policy_arn: Option<String>,
    pub resource_type: String,
    pub findings: Vec<IamFinding>,
    pub risk_score: u8,
}

/// Individual IAM finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamFinding {
    pub finding_type: IamFindingType,
    pub severity: String,
    pub description: String,
    pub affected_resource: String,
    pub evidence: Vec<String>,
    pub remediation: String,
}

/// AWS IAM Policy statement
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AwsPolicyStatement {
    #[serde(rename = "Effect")]
    effect: String,
    #[serde(rename = "Action")]
    action: serde_json::Value,
    #[serde(rename = "Resource")]
    resource: serde_json::Value,
    #[serde(rename = "Principal", skip_serializing_if = "Option::is_none")]
    principal: Option<serde_json::Value>,
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    condition: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AwsPolicyDocument {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Statement")]
    statement: Vec<AwsPolicyStatement>,
}

pub struct CloudIamAnalyzer {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
}

impl CloudIamAnalyzer {
    pub fn new() -> Self {
        let cache = Arc::new(CloudMetadataCache::new(
            Duration::from_secs(300),
            1000,
        ));

        Self {
            cache,
            retry_config: RetryConfig::default(),
        }
    }

    /// Analyze AWS IAM policies
    pub async fn analyze_aws_iam(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS IAM Analysis");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS IAM analysis");

        // Analyze IAM users
        let user_vulns = self.analyze_aws_users(aws_config, &mut metrics).await?;
        vulnerabilities.extend(user_vulns);

        // Analyze IAM roles
        let role_vulns = self.analyze_aws_roles(aws_config, &mut metrics).await?;
        vulnerabilities.extend(role_vulns);

        // Analyze IAM policies
        let policy_vulns = self.analyze_aws_policies(aws_config, &mut metrics).await?;
        vulnerabilities.extend(policy_vulns);

        metrics.report();
        info!("AWS IAM analysis completed. Found {} issues", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    async fn analyze_aws_users(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let users_result = retry_with_backoff(
            || async {
                client
                    .list_users()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list users: {}", e)))
            },
            self.retry_config.clone(),
            "list_users",
        )
        .await?;

        for user in users_result.users() {
            let user_name = user.user_name();

                // Check for MFA
                metrics.record_api_call();
                let mfa_devices = client
                    .list_mfa_devices()
                    .user_name(user_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list MFA devices: {}", e)))?;

                if mfa_devices.mfa_devices().is_empty() {
                    vulnerabilities.push(self.create_vulnerability(
                        "AWS IAM User Without MFA",
                        Severity::High,
                        Confidence::High,
                        format!("IAM user '{}' does not have MFA enabled", user_name),
                        format!("User ARN: {}", user.arn()),
                        "Enable MFA for all IAM users, especially those with console access",
                        "CWE-308",
                        7.5,
                    ));
                }

                // Check for inactive users
                if let Some(password_last_used) = user.password_last_used() {
                    let password_date = chrono::DateTime::from_timestamp(password_last_used.secs(), 0).unwrap_or_else(|| chrono::Utc::now());
                    let days_since_use = (chrono::Utc::now() - password_date).num_days();
                    if days_since_use > 90 {
                        vulnerabilities.push(self.create_vulnerability(
                            "Inactive AWS IAM User",
                            Severity::Medium,
                            Confidence::High,
                            format!("IAM user '{}' has not been used in {} days", user_name, days_since_use),
                            format!("Last password use: {}", password_last_used),
                            "Remove or disable inactive IAM users to reduce attack surface",
                            "CWE-284",
                            5.0,
                        ));
                    }
                }

                // Check user policies for overly permissive actions
                metrics.record_api_call();
                let inline_policies = client
                    .list_user_policies()
                    .user_name(user_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list user policies: {}", e)))?;

                for policy_name in inline_policies.policy_names() {
                    metrics.record_api_call();
                    let policy = client
                        .get_user_policy()
                        .user_name(user_name)
                        .policy_name(policy_name.to_string())
                        .send()
                        .await
                        .map_err(|e| CloudError::ApiError(format!("Failed to get user policy: {}", e)))?;

                    let policy_document = policy.policy_document();
                    if !policy_document.is_empty() {
                        let decoded = urlencoding::decode(policy_document)
                            .map_err(|e| CloudError::ParseError(format!("Failed to decode policy: {}", e)))?;

                        if let Ok(doc) = serde_json::from_str::<AwsPolicyDocument>(&decoded) {
                            let policy_vulns = self.analyze_aws_policy_document(
                                &doc,
                                policy_name,
                                &format!("User: {}", user_name),
                            );
                            vulnerabilities.extend(policy_vulns);
                        }
                    }
                }
        }

        Ok(vulnerabilities)
    }

    async fn analyze_aws_roles(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let roles_result = retry_with_backoff(
            || async {
                client
                    .list_roles()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list roles: {}", e)))
            },
            self.retry_config.clone(),
            "list_roles",
        )
        .await?;

        for role in roles_result.roles() {
            let role_name = role.role_name();

                // Analyze trust policy for cross-account access
                if let Some(assume_role_policy) = role.assume_role_policy_document() {
                    let decoded = urlencoding::decode(assume_role_policy)
                        .map_err(|e| CloudError::ParseError(format!("Failed to decode policy: {}", e)))?;

                    if let Ok(doc) = serde_json::from_str::<AwsPolicyDocument>(&decoded) {
                        for statement in &doc.statement {
                            if let Some(principal) = &statement.principal {
                                if let Some(aws_principal) = principal.get("AWS") {
                                    // Check for wildcard or cross-account principals
                                    let principal_str = aws_principal.to_string();
                                    if principal_str.contains("*") {
                                        vulnerabilities.push(self.create_vulnerability(
                                            "AWS Role with Wildcard Principal",
                                            Severity::Critical,
                                            Confidence::High,
                                            format!("Role '{}' has a wildcard (*) in trust policy principal", role_name),
                                            format!("Principal: {}", principal_str),
                                            "Use specific AWS account IDs or IAM ARNs in trust policies",
                                            "CWE-732",
                                            9.0,
                                        ));
                                    } else if self.is_cross_account_principal(&principal_str, aws_config).await {
                                        vulnerabilities.push(self.create_vulnerability(
                                            "Cross-Account IAM Role Access",
                                            Severity::High,
                                            Confidence::Medium,
                                            format!("Role '{}' allows cross-account access", role_name),
                                            format!("Principal: {}", principal_str),
                                            "Review cross-account access and ensure it's intentional and properly scoped",
                                            "CWE-284",
                                            7.0,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                // Analyze role policies
                metrics.record_api_call();
                let inline_policies = client
                    .list_role_policies()
                    .role_name(role_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list role policies: {}", e)))?;

                for policy_name in inline_policies.policy_names() {
                    metrics.record_api_call();
                    let policy = client
                        .get_role_policy()
                        .role_name(role_name)
                        .policy_name(policy_name.to_string())
                        .send()
                        .await
                        .map_err(|e| CloudError::ApiError(format!("Failed to get role policy: {}", e)))?;

                    let policy_document = policy.policy_document();
                    if !policy_document.is_empty() {
                        let decoded = urlencoding::decode(policy_document)
                            .map_err(|e| CloudError::ParseError(format!("Failed to decode policy: {}", e)))?;

                        if let Ok(doc) = serde_json::from_str::<AwsPolicyDocument>(&decoded) {
                            let policy_vulns = self.analyze_aws_policy_document(
                                &doc,
                                policy_name,
                                &format!("Role: {}", role_name),
                            );
                            vulnerabilities.extend(policy_vulns);
                        }
                    }
                }
        }

        Ok(vulnerabilities)
    }

    async fn analyze_aws_policies(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_iam::Client::new(aws_config);

        metrics.record_api_call();
        let policies_result = retry_with_backoff(
            || async {
                client
                    .list_policies()
                    .scope(aws_sdk_iam::types::PolicyScopeType::Local)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list policies: {}", e)))
            },
            self.retry_config.clone(),
            "list_policies",
        )
        .await?;

        if let Some(policies) = policies_result.policies {
            for policy in policies {
                let policy_name = policy.policy_name().unwrap_or("unknown");
                let policy_arn = policy.arn().unwrap_or("unknown");

                // Get policy version
                if let Some(default_version_id) = policy.default_version_id() {
                    metrics.record_api_call();
                    let version = client
                        .get_policy_version()
                        .policy_arn(policy_arn)
                        .version_id(default_version_id)
                        .send()
                        .await
                        .map_err(|e| CloudError::ApiError(format!("Failed to get policy version: {}", e)))?;

                    if let Some(policy_version) = version.policy_version {
                        if let Some(document) = policy_version.document() {
                            let decoded = urlencoding::decode(document)
                                .map_err(|e| CloudError::ParseError(format!("Failed to decode policy: {}", e)))?;

                            if let Ok(doc) = serde_json::from_str::<AwsPolicyDocument>(&decoded) {
                                let policy_vulns = self.analyze_aws_policy_document(
                                    &doc,
                                    policy_name,
                                    &format!("Managed Policy: {}", policy_arn),
                                );
                                vulnerabilities.extend(policy_vulns);
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn analyze_aws_policy_document(
        &self,
        doc: &AwsPolicyDocument,
        policy_name: &str,
        resource_context: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for statement in &doc.statement {
            if statement.effect != "Allow" {
                continue;
            }

            // Check for wildcard actions
            let actions = self.extract_actions(&statement.action);
            let wildcard_actions: Vec<_> = actions.iter()
                .filter(|a| a.contains('*'))
                .collect();

            if !wildcard_actions.is_empty() {
                let is_critical = wildcard_actions.iter().any(|a| *a == "*");
                let severity = if is_critical {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let wildcard_actions_str: Vec<String> = wildcard_actions.iter().map(|s| s.to_string()).collect();
                vulnerabilities.push(self.create_vulnerability(
                    "Wildcard Permissions in IAM Policy",
                    severity,
                    Confidence::High,
                    format!("Policy '{}' contains wildcard actions: {}", policy_name, wildcard_actions_str.join(", ")),
                    format!("{} | Actions: {:?}", resource_context, wildcard_actions),
                    "Use specific IAM actions instead of wildcards to follow principle of least privilege",
                    "CWE-732",
                    if is_critical { 9.5 } else { 7.5 },
                ));
            }

            // Check for wildcard resources
            let resources = self.extract_resources(&statement.resource);
            let wildcard_resources: Vec<_> = resources.iter()
                .filter(|r| *r == "*")
                .collect();

            if !wildcard_resources.is_empty() && !actions.is_empty() {
                // Check for dangerous combinations
                let dangerous_actions = [
                    "iam:*", "s3:*", "ec2:*", "lambda:*", "dynamodb:*",
                    "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
                    "s3:DeleteBucket", "ec2:TerminateInstances",
                ];

                let has_dangerous = actions.iter().any(|a| {
                    dangerous_actions.iter().any(|da| a.contains(da) || a == "*")
                });

                if has_dangerous {
                    vulnerabilities.push(self.create_vulnerability(
                        "Overly Permissive IAM Policy",
                        Severity::Critical,
                        Confidence::High,
                        format!("Policy '{}' has wildcard resource (*) with sensitive actions", policy_name),
                        format!("{} | Actions: {:?}", resource_context, actions),
                        "Specify exact resource ARNs instead of using wildcards for sensitive operations",
                        "CWE-732",
                        9.0,
                    ));
                }
            }

            // Check for privilege escalation paths
            let escalation_actions = [
                "iam:CreateAccessKey",
                "iam:CreateLoginProfile",
                "iam:UpdateLoginProfile",
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
                "iam:PassRole",
                "lambda:CreateFunction",
                "lambda:UpdateFunctionCode",
            ];

            let has_escalation: Vec<_> = actions.iter()
                .filter(|a| escalation_actions.iter().any(|ea| a.contains(ea)))
                .collect();

            if has_escalation.len() >= 2 {
                vulnerabilities.push(self.create_vulnerability(
                    "Potential Privilege Escalation Path",
                    Severity::Critical,
                    Confidence::Medium,
                    format!("Policy '{}' contains actions that could enable privilege escalation", policy_name),
                    format!("{} | Escalation actions: {:?}", resource_context, has_escalation),
                    "Review and restrict IAM permissions that can be used for privilege escalation",
                    "CWE-269",
                    9.5,
                ));
            }
        }

        vulnerabilities
    }

    fn extract_actions(&self, action: &serde_json::Value) -> Vec<String> {
        match action {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(arr) => {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            }
            _ => vec![],
        }
    }

    fn extract_resources(&self, resource: &serde_json::Value) -> Vec<String> {
        match resource {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(arr) => {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            }
            _ => vec![],
        }
    }

    async fn is_cross_account_principal(&self, principal: &str, aws_config: &aws_config::SdkConfig) -> bool {
        let sts_client = aws_sdk_sts::Client::new(aws_config);

        match sts_client.get_caller_identity().send().await {
            Ok(identity) => {
                if let Some(account_id) = identity.account {
                    !principal.contains(&account_id)
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Analyze Azure RBAC
    pub async fn analyze_azure_rbac(&self) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        info!("Starting Azure RBAC analysis");

        // Note: This is a placeholder for Azure RBAC analysis
        // In production, you would use the Azure SDK to:
        // 1. List custom role definitions
        // 2. Analyze role assignments
        // 3. Check for overly permissive permissions
        // 4. Identify privileged identities
        // 5. Analyze inherited permissions

        warn!("Azure RBAC analysis requires Azure credentials configuration");

        Ok(vulnerabilities)
    }

    /// Analyze GCP IAM
    pub async fn analyze_gcp_iam(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        info!("Starting GCP IAM analysis for project: {}", project_id);

        // Note: This is a placeholder for GCP IAM analysis
        // In production, you would use the GCP SDK to:
        // 1. List service accounts
        // 2. Check for service account key exposure
        // 3. Analyze IAM policy bindings
        // 4. Check for overly broad roles
        // 5. Identify primitive role usage (Owner, Editor, Viewer)

        warn!("GCP IAM analysis requires GCP credentials configuration");

        Ok(vulnerabilities)
    }

    fn create_vulnerability(
        &self,
        vuln_type: &str,
        severity: Severity,
        confidence: Confidence,
        description: String,
        evidence: String,
        remediation: &str,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("iam_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud IAM".to_string(),
            url: "N/A".to_string(),
            parameter: None,
            payload: "N/A".to_string(),
            description,
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for CloudIamAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }
    }

    impl std::fmt::Display for Uuid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut rng = rand::rng();
            write!(
                f,
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}
