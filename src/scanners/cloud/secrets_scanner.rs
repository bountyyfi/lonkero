// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Secrets Scanner
 * Scans cloud resources for hardcoded secrets and credentials
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::cloud::error_handling::{CloudError, RetryConfig, retry_with_backoff};
use crate::cloud::optimizations::{CloudMetadataCache, PerformanceMetrics};
use crate::types::{Confidence, Severity, Vulnerability};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use base64::{Engine, engine::general_purpose::STANDARD};
use tracing::{info, warn};

/// Secret pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    AzureClientSecret,
    GcpApiKey,
    GenericApiKey,
    Password,
    PrivateKey,
    DatabaseConnection,
    JwtSecret,
    SlackToken,
    GithubToken,
    DockerRegistryAuth,
}

/// Secret finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: SecretType,
    pub location: String,
    pub resource_id: String,
    pub matched_pattern: String,
    pub entropy_score: f64,
    pub confidence_score: f64,
}

pub struct CloudSecretsScanner {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
    patterns: Vec<SecretPattern>,
}

#[derive(Clone)]
struct SecretPattern {
    name: String,
    pattern: Regex,
    secret_type: SecretType,
    entropy_threshold: f64,
}

impl CloudSecretsScanner {
    pub fn new() -> Self {
        let cache = Arc::new(CloudMetadataCache::new(
            Duration::from_secs(300),
            1000,
        ));

        let patterns = Self::initialize_patterns();

        Self {
            cache,
            retry_config: RetryConfig::default(),
            patterns,
        }
    }

    fn initialize_patterns() -> Vec<SecretPattern> {
        vec![
            SecretPattern {
                name: "AWS Access Key ID".to_string(),
                pattern: Regex::new(r#"(?i)(?:aws)?_?(?:access)?_?key_?id['"]?\s*[:=]\s*['"]?(AKIA[0-9A-Z]{16})"#).unwrap(),
                secret_type: SecretType::AwsAccessKey,
                entropy_threshold: 3.5,
            },
            SecretPattern {
                name: "AWS Secret Access Key".to_string(),
                pattern: Regex::new(r#"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#).unwrap(),
                secret_type: SecretType::AwsSecretKey,
                entropy_threshold: 4.5,
            },
            SecretPattern {
                name: "Azure Client Secret".to_string(),
                pattern: Regex::new(r#"(?i)client[_-]?secret['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.~]{34,})"#).unwrap(),
                secret_type: SecretType::AzureClientSecret,
                entropy_threshold: 4.0,
            },
            SecretPattern {
                name: "GCP API Key".to_string(),
                pattern: Regex::new(r"(?i)AIza[0-9A-Za-z\\-_]{35}").unwrap(),
                secret_type: SecretType::GcpApiKey,
                entropy_threshold: 4.0,
            },
            SecretPattern {
                name: "Generic API Key".to_string(),
                pattern: Regex::new(r#"(?i)api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})"#).unwrap(),
                secret_type: SecretType::GenericApiKey,
                entropy_threshold: 3.5,
            },
            SecretPattern {
                name: "Password".to_string(),
                pattern: Regex::new(r#"(?i)password['"]?\s*[:=]\s*['"]?([^\s'"]{8,})"#).unwrap(),
                secret_type: SecretType::Password,
                entropy_threshold: 3.0,
            },
            SecretPattern {
                name: "Private Key".to_string(),
                pattern: Regex::new(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
                secret_type: SecretType::PrivateKey,
                entropy_threshold: 4.5,
            },
            SecretPattern {
                name: "Database Connection String".to_string(),
                pattern: Regex::new(r#"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'"]+

"#).unwrap(),
                secret_type: SecretType::DatabaseConnection,
                entropy_threshold: 3.5,
            },
            SecretPattern {
                name: "JWT Secret".to_string(),
                pattern: Regex::new(r#"(?i)jwt[_-]?secret['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-.]{20,})"#).unwrap(),
                secret_type: SecretType::JwtSecret,
                entropy_threshold: 3.5,
            },
            SecretPattern {
                name: "Slack Token".to_string(),
                pattern: Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}").unwrap(),
                secret_type: SecretType::SlackToken,
                entropy_threshold: 4.0,
            },
            SecretPattern {
                name: "GitHub Token".to_string(),
                pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
                secret_type: SecretType::GithubToken,
                entropy_threshold: 4.0,
            },
            SecretPattern {
                name: "Docker Registry Auth".to_string(),
                pattern: Regex::new(r#"(?i)(?:docker|registry)[_-]?(?:auth|password)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9+/=]{20,})"#).unwrap(),
                secret_type: SecretType::DockerRegistryAuth,
                entropy_threshold: 3.5,
            },
        ]
    }

    /// Scan AWS resources for secrets
    pub async fn scan_aws_resources(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS Secrets Scanning");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS secrets scanning");

        // Scan Lambda function environment variables
        let lambda_findings = self.scan_lambda_functions(aws_config, &mut metrics).await?;
        vulnerabilities.extend(lambda_findings);

        // Scan EC2 user data
        let ec2_findings = self.scan_ec2_user_data(aws_config, &mut metrics).await?;
        vulnerabilities.extend(ec2_findings);

        // Scan CloudFormation templates
        let cfn_findings = self.scan_cloudformation_templates(aws_config, &mut metrics).await?;
        vulnerabilities.extend(cfn_findings);

        metrics.report();
        info!("AWS secrets scanning completed. Found {} secrets", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    async fn scan_lambda_functions(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_lambda::Client::new(aws_config);

        metrics.record_api_call();
        let functions = retry_with_backoff(
            || async {
                client
                    .list_functions()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to list Lambda functions: {}", e)))
            },
            self.retry_config.clone(),
            "list_functions",
        )
        .await?;

        if let Some(functions_list) = functions.functions {
            for function in functions_list {
                let function_name = function.function_name().unwrap_or("unknown");

                // Get function configuration
                metrics.record_api_call();
                let config = client
                    .get_function_configuration()
                    .function_name(function_name)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to get function config: {}", e)))?;

                // Check environment variables
                if let Some(environment) = config.environment() {
                    if let Some(variables) = environment.variables() {
                        for (key, value) in variables {
                            let findings = self.scan_text_for_secrets(value);
                            for finding in findings {
                                vulnerabilities.push(self.create_vulnerability(
                                    &format!("Secret in Lambda Environment Variable: {:?}", finding.secret_type),
                                    Severity::Critical,
                                    Confidence::High,
                                    format!(
                                        "Lambda function '{}' has a potential secret in environment variable '{}'",
                                        function_name, key
                                    ),
                                    format!(
                                        "Function: {}, Variable: {}, Pattern: {}, Entropy: {:.2}",
                                        function_name, key, finding.matched_pattern, finding.entropy_score
                                    ),
                                    "Use AWS Secrets Manager or Parameter Store to store sensitive data instead of environment variables",
                                    "CWE-798",
                                    9.0,
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn scan_ec2_user_data(
        &self,
        aws_config: &aws_config::SdkConfig,
        metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut vulnerabilities = Vec::new();
        let client = aws_sdk_ec2::Client::new(aws_config);

        metrics.record_api_call();
        let instances = retry_with_backoff(
            || async {
                client
                    .describe_instances()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to describe instances: {}", e)))
            },
            self.retry_config.clone(),
            "describe_instances",
        )
        .await?;

        if let Some(reservations) = instances.reservations {
            for reservation in reservations {
                if let Some(instances_list) = reservation.instances {
                    for instance in instances_list {
                        let instance_id = instance.instance_id().unwrap_or("unknown");

                        // Get instance user data
                        metrics.record_api_call();
                        let user_data_result = client
                            .describe_instance_attribute()
                            .instance_id(instance_id)
                            .attribute(aws_sdk_ec2::types::InstanceAttributeName::UserData)
                            .send()
                            .await;

                        if let Ok(user_data) = user_data_result {
                            if let Some(attribute) = user_data.user_data() {
                                if let Some(value) = attribute.value() {
                                    // Decode base64 user data
                                    if let Ok(decoded) = STANDARD.decode(value) {
                                        if let Ok(user_data_str) = String::from_utf8(decoded) {
                                            let findings = self.scan_text_for_secrets(&user_data_str);
                                            for finding in findings {
                                                vulnerabilities.push(self.create_vulnerability(
                                                    &format!("Secret in EC2 User Data: {:?}", finding.secret_type),
                                                    Severity::Critical,
                                                    Confidence::High,
                                                    format!(
                                                        "EC2 instance '{}' has a potential secret in user data",
                                                        instance_id
                                                    ),
                                                    format!(
                                                        "Instance: {}, Pattern: {}, Entropy: {:.2}",
                                                        instance_id, finding.matched_pattern, finding.entropy_score
                                                    ),
                                                    "Remove secrets from user data and use AWS Secrets Manager or Parameter Store",
                                                    "CWE-798",
                                                    9.5,
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn scan_cloudformation_templates(
        &self,
        _aws_config: &aws_config::SdkConfig,
        _metrics: &mut PerformanceMetrics,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let vulnerabilities = Vec::new();

        // Note: Scanning CloudFormation templates would require:
        // 1. Listing all stacks
        // 2. Getting template for each stack
        // 3. Scanning template JSON/YAML for secrets
        //
        // This is a placeholder for the full implementation

        Ok(vulnerabilities)
    }

    fn scan_text_for_secrets(&self, text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            if let Some(captures) = pattern.pattern.captures(text) {
                if let Some(matched) = captures.get(0) {
                    let matched_text = matched.as_str();
                    let entropy = self.calculate_entropy(matched_text);

                    if entropy >= pattern.entropy_threshold {
                        let confidence = self.calculate_confidence(entropy, pattern.entropy_threshold);

                        findings.push(SecretFinding {
                            secret_type: pattern.secret_type.clone(),
                            location: "text".to_string(),
                            resource_id: "N/A".to_string(),
                            matched_pattern: pattern.name.clone(),
                            entropy_score: entropy,
                            confidence_score: confidence,
                        });
                    }
                }
            }
        }

        findings
    }

    fn calculate_entropy(&self, text: &str) -> f64 {
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        let len = text.len() as f64;

        for ch in text.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let mut entropy = 0.0;
        for count in char_counts.values() {
            let probability = *count as f64 / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn calculate_confidence(&self, entropy: f64, threshold: f64) -> f64 {
        let ratio = entropy / threshold;
        (ratio.min(2.0) / 2.0) * 100.0
    }

    /// Scan Azure resources for secrets
    pub async fn scan_azure_resources(&self) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting Azure secrets scanning");

        // Note: Placeholder for Azure secrets scanning
        warn!("Azure secrets scanning requires Azure credentials configuration");

        Ok(vec![])
    }

    /// Scan GCP resources for secrets
    pub async fn scan_gcp_resources(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting GCP secrets scanning for project: {}", project_id);

        // Note: Placeholder for GCP secrets scanning
        warn!("GCP secrets scanning requires GCP credentials configuration");

        Ok(vec![])
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
            id: format!("secret_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud Secrets Exposure".to_string(),
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

impl Default for CloudSecretsScanner {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let scanner = CloudSecretsScanner::new();

        let high_entropy = scanner.calculate_entropy("aK3!pQz9@mN7");
        let low_entropy = scanner.calculate_entropy("aaaaaaaaaa");

        assert!(high_entropy > low_entropy);
        assert!(high_entropy > 3.0);
        assert!(low_entropy < 1.0);
    }

    #[test]
    fn test_secret_patterns() {
        let scanner = CloudSecretsScanner::new();

        let text_with_secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = scanner.scan_text_for_secrets(text_with_secret);

        assert!(!findings.is_empty());
    }
}
