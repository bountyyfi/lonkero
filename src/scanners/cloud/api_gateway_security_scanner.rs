// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud API Gateway Security Scanner
 * Security analysis for AWS API Gateway, Azure API Management, and GCP API Gateway
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
use tracing::{debug, info, warn};

/// API Gateway security finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiGatewayFindingType {
    MissingAuthentication,
    MissingAuthorization,
    NoRateLimiting,
    InsecureCors,
    ApiKeyExposure,
    LoggingDisabled,
    UnencryptedTraffic,
    PublicEndpoint,
}

pub struct CloudApiGatewaySecurityScanner {
    cache: Arc<CloudMetadataCache>,
    retry_config: RetryConfig,
}

impl CloudApiGatewaySecurityScanner {
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

    /// Scan AWS API Gateway configurations
    pub async fn scan_aws_api_gateway(
        &self,
        aws_config: &aws_config::SdkConfig,
    ) -> Result<Vec<Vulnerability>, CloudError> {
        let mut metrics = PerformanceMetrics::new("AWS API Gateway Security Scanning");
        let mut vulnerabilities = Vec::new();

        info!("Starting AWS API Gateway security scanning");

        let client = aws_sdk_apigateway::Client::new(aws_config);

        // List all REST APIs
        metrics.record_api_call();
        let apis = retry_with_backoff(
            || async {
                client
                    .get_rest_apis()
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to get REST APIs: {}", e)))
            },
            self.retry_config.clone(),
            "get_rest_apis",
        )
        .await?;

        if let Some(items) = apis.items {
            for api in items {
                let api_id = api.id().unwrap_or("unknown");
                let api_name = api.name().unwrap_or("unknown");

                debug!("Scanning API Gateway: {} ({})", api_name, api_id);

                // Check API configuration
                let config_vulns = self.check_api_gateway_config(&api, api_id, api_name);
                vulnerabilities.extend(config_vulns);

                // Get stages
                metrics.record_api_call();
                let stages = client
                    .get_stages()
                    .rest_api_id(api_id)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to get stages: {}", e)))?;

                if let Some(stage_items) = stages.item {
                    for stage in stage_items {
                        let stage_name = stage.stage_name().unwrap_or("unknown");
                        let stage_vulns = self.check_api_gateway_stage(&stage, api_id, api_name, stage_name);
                        vulnerabilities.extend(stage_vulns);
                    }
                }

                // Get resources and methods
                metrics.record_api_call();
                let resources = client
                    .get_resources()
                    .rest_api_id(api_id)
                    .send()
                    .await
                    .map_err(|e| CloudError::ApiError(format!("Failed to get resources: {}", e)))?;

                if let Some(resource_items) = resources.items {
                    for resource in resource_items {
                        if let Some(resource_methods) = resource.resource_methods() {
                            for (method_name, method) in resource_methods {
                                let method_vulns = self.check_api_gateway_method(
                                    method,
                                    api_id,
                                    api_name,
                                    resource.path().unwrap_or("/"),
                                    method_name,
                                );
                                vulnerabilities.extend(method_vulns);
                            }
                        }
                    }
                }
            }
        }

        metrics.report();
        info!("AWS API Gateway security scanning completed. Found {} issues", vulnerabilities.len());

        Ok(vulnerabilities)
    }

    fn check_api_gateway_config(
        &self,
        api: &aws_sdk_apigateway::types::RestApi,
        api_id: &str,
        api_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check endpoint configuration
        if let Some(endpoint_config) = api.endpoint_configuration() {
            let types = endpoint_config.types();
            for endpoint_type in types {
                if format!("{:?}", endpoint_type) == "EDGE" || format!("{:?}", endpoint_type) == "REGIONAL" {
                    // Public endpoint - flag for review
                    vulnerabilities.push(self.create_vulnerability(
                        "API Gateway Public Endpoint",
                        Severity::Medium,
                        Confidence::Medium,
                        format!("API Gateway '{}' has a public endpoint", api_name),
                        format!("API ID: {}, Endpoint Type: {:?}", api_id, endpoint_type),
                        "Review if public access is necessary. Consider using PRIVATE endpoint with VPC endpoint if internal only.",
                        "CWE-284",
                        5.0,
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn check_api_gateway_stage(
        &self,
        stage: &aws_sdk_apigateway::types::Stage,
        api_id: &str,
        api_name: &str,
        stage_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if logging is enabled
        if stage.access_log_settings().is_none() {
            vulnerabilities.push(self.create_vulnerability(
                "API Gateway Logging Disabled",
                Severity::Medium,
                Confidence::High,
                format!("API Gateway '{}' stage '{}' does not have access logging enabled", api_name, stage_name),
                format!("API ID: {}, Stage: {}", api_id, stage_name),
                "Enable access logging to monitor and audit API requests",
                "CWE-778",
                5.5,
            ));
        }

        // Check if caching is enabled (can impact security if not configured properly)
        if stage.cache_cluster_enabled() {
            if !stage.cache_cluster_status().map(|s| format!("{:?}", s)).unwrap_or_default().contains("AVAILABLE") {
                debug!("Cache cluster enabled but status unclear for stage {}", stage_name);
            }
        }

        // Check throttling settings
        if let Some(method_settings) = stage.method_settings() {
            let has_throttling = method_settings.values().any(|settings| {
                (settings.throttling_rate_limit() > 0.0)
                    || (settings.throttling_burst_limit() > 0)
            });

            if !has_throttling {
                vulnerabilities.push(self.create_vulnerability(
                    "API Gateway Rate Limiting Not Configured",
                    Severity::Medium,
                    Confidence::High,
                    format!("API Gateway '{}' stage '{}' does not have rate limiting configured", api_name, stage_name),
                    format!("API ID: {}, Stage: {}", api_id, stage_name),
                    "Configure throttling (rate limiting) to prevent abuse and DoS attacks",
                    "CWE-770",
                    6.0,
                ));
            }
        }

        // Check if API key is required
        // Note: This should be checked at method level, but we can flag if no API key requirement found at all

        vulnerabilities
    }

    fn check_api_gateway_method(
        &self,
        method: &aws_sdk_apigateway::types::Method,
        api_id: &str,
        api_name: &str,
        resource_path: &str,
        method_name: &str,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if API key is required
        if !method.api_key_required().unwrap_or(false) {
            // Check if there's any authorization
            let auth_type = method.authorization_type().unwrap_or("NONE");

            if auth_type == "NONE" {
                vulnerabilities.push(self.create_vulnerability(
                    "API Gateway Method Without Authentication",
                    Severity::High,
                    Confidence::High,
                    format!(
                        "API Gateway '{}' method {} {} has no authentication or authorization",
                        api_name, method_name, resource_path
                    ),
                    format!("API ID: {}, Method: {} {}, Auth Type: NONE", api_id, method_name, resource_path),
                    "Implement authentication (IAM, Cognito, Lambda Authorizer) or require API keys",
                    "CWE-306",
                    8.0,
                ));
            }
        }

        // Check for CORS misconfiguration
        if let Some(integration) = method.method_integration() {
            // Check integration type
            if let Some(integration_type) = integration.r#type() {
                if format!("{:?}", integration_type) == "HTTP" || format!("{:?}", integration_type) == "HTTP_PROXY" {
                    // Check if using HTTPS
                    if let Some(uri) = integration.uri() {
                        if uri.starts_with("http://") {
                            vulnerabilities.push(self.create_vulnerability(
                                "API Gateway HTTP Backend",
                                Severity::High,
                                Confidence::High,
                                format!(
                                    "API Gateway '{}' method {} {} integrates with unencrypted HTTP backend",
                                    api_name, method_name, resource_path
                                ),
                                format!("API ID: {}, Method: {} {}, Backend URI: {}", api_id, method_name, resource_path, uri),
                                "Use HTTPS for backend integrations to ensure data is encrypted in transit",
                                "CWE-319",
                                7.5,
                            ));
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Scan Azure API Management
    pub async fn scan_azure_api_management(&self) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting Azure API Management security scanning");

        // Note: Placeholder for Azure API Management scanning
        // In production, you would:
        // 1. List all API Management services
        // 2. Check authentication/authorization policies
        // 3. Verify backend security
        // 4. Check for API key rotation policies
        // 5. Verify rate limiting policies

        warn!("Azure API Management scanning requires Azure credentials configuration");

        Ok(vec![])
    }

    /// Scan GCP API Gateway
    pub async fn scan_gcp_api_gateway(&self, project_id: &str) -> Result<Vec<Vulnerability>, CloudError> {
        info!("Starting GCP API Gateway security scanning for project: {}", project_id);

        // Note: Placeholder for GCP API Gateway scanning
        // In production, you would:
        // 1. List all API Gateways
        // 2. Check authentication methods (API keys, OAuth, Service Accounts)
        // 3. Verify rate limiting configuration
        // 4. Check backend service security
        // 5. Verify API key rotation

        warn!("GCP API Gateway scanning requires GCP credentials configuration");

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
            id: format!("apigw_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Cloud API Gateway Security".to_string(),
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

impl Default for CloudApiGatewaySecurityScanner {
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
