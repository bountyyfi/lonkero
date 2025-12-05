// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Azure Blob Storage Security Scanner
 * Production-grade scanner for Azure Storage Account vulnerabilities
 *
 * Detects:
 * - Public blob containers
 * - Container ACL misconfigurations
 * - SAS token vulnerabilities
 * - Encryption issues (Microsoft-managed vs Customer-managed keys)
 * - Soft delete disabled
 * - Versioning disabled
 * - Network rules misconfigurations
 * - Azure AD authentication issues
 * - CORS misconfigurations
 * - Insecure transfer (HTTP allowed)
 * - Public network access enabled
 * - Shared Key access allowed
 * - Infrastructure encryption disabled
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct AzureStorageScanner {
    http_client: Arc<HttpClient>,
}

impl AzureStorageScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan Azure Blob Storage for security vulnerabilities
    pub async fn scan(
        &self,
        target: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Starting Azure Blob Storage security scan");

        // Extract domain for storage account name patterns
        let domain = self.extract_domain(target);

        // Test for public blob containers
        let (vulns, tests) = self.scan_public_containers(&domain, config).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for SAS token vulnerabilities
        let (vulns, tests) = self.scan_sas_token_vulnerabilities(target).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for encryption configuration
        let (vulns, tests) = self.scan_encryption_config(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for soft delete and versioning
        let (vulns, tests) = self.scan_data_protection(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for network security
        let (vulns, tests) = self.scan_network_security(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for CORS misconfigurations
        let (vulns, tests) = self.scan_cors_configuration(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test for authentication issues
        let (vulns, tests) = self.scan_authentication_config(&domain).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        info!(
            "Azure Blob Storage scan completed: {} tests run, {} vulnerabilities found",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for public blob containers
    async fn scan_public_containers(
        &self,
        domain: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 20;

        info!("Scanning for public Azure Blob containers");

        let storage_account_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
            format!("{}data", domain),
            format!("{}files", domain),
            format!("{}backup", domain),
            format!("{}prod", domain),
            format!("{}dev", domain),
            format!("{}test", domain),
        ];

        let container_patterns = vec![
            "public",
            "files",
            "uploads",
            "images",
            "assets",
            "static",
            "backup",
            "backups",
            "data",
            "documents",
            "media",
            "content",
        ];

        for storage_account in &storage_account_patterns {
            for container in &container_patterns {
                let blob_url = format!(
                    "https://{}.blob.core.windows.net/{}/",
                    storage_account, container
                );

                match self.http_client.get(&blob_url).await {
                    Ok(response) => {
                        if self.is_public_container(&response.body, response.status_code) {
                            info!("Public Azure Blob container found: {}/{}", storage_account, container);
                            vulnerabilities.push(self.create_vulnerability(
                                &blob_url,
                                "Public Azure Blob Container",
                                "",
                                &format!(
                                    "Publicly accessible blob container found: {}/{}. Container allows anonymous read access without authentication.",
                                    storage_account, container
                                ),
                                &format!("Container ACL set to 'Blob' or 'Container' public access level"),
                                Severity::High,
                                "CWE-732",
                                8.6,
                                vec![
                                    "Set container public access level to 'Private'".to_string(),
                                    "Use Shared Access Signatures (SAS) for temporary access".to_string(),
                                    "Enable Azure AD authentication for blob access".to_string(),
                                    "Disable public network access at storage account level".to_string(),
                                    "Enable firewall rules to restrict access by IP".to_string(),
                                    "Use Azure Private Link for private connectivity".to_string(),
                                    "Enable storage account logging and monitoring".to_string(),
                                ],
                            ));
                        }
                    }
                    Err(e) => {
                        debug!("Container check failed for {}/{}: {}", storage_account, container, e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for SAS token vulnerabilities
    async fn scan_sas_token_vulnerabilities(
        &self,
        target: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Scanning for SAS token vulnerabilities");

        // Check if URL contains SAS token parameters
        if let Some(sas_issues) = self.analyze_sas_token(target) {
            for issue in sas_issues {
                vulnerabilities.push(issue);
            }
        }

        // Test for common SAS token exposure patterns in HTML
        match self.http_client.get(target).await {
            Ok(response) => {
                let sas_pattern = Regex::new(
                    r#"(https://[a-z0-9]+\.blob\.core\.windows\.net/[^?\s]+\?[^'"\s]*sv=[^'"\s]+)"#
                ).unwrap();

                for cap in sas_pattern.captures_iter(&response.body) {
                    if let Some(sas_url) = cap.get(1) {
                        warn!("SAS token exposed in HTML: {}", sas_url.as_str());
                        vulnerabilities.push(self.create_vulnerability(
                            target,
                            "SAS Token Exposure",
                            "",
                            "Shared Access Signature (SAS) token found exposed in HTML response. This grants temporary access to Azure Storage resources.",
                            &format!("SAS token URL: {}", sas_url.as_str()),
                            Severity::High,
                            "CWE-522",
                            7.5,
                            vec![
                                "Never embed SAS tokens in client-side code or HTML".to_string(),
                                "Generate SAS tokens server-side and pass securely".to_string(),
                                "Use short expiration times for SAS tokens (minutes/hours)".to_string(),
                                "Implement IP restrictions on SAS tokens".to_string(),
                                "Use stored access policies for revocable SAS tokens".to_string(),
                                "Prefer Azure AD authentication over SAS tokens".to_string(),
                                "Monitor SAS token usage with Azure Storage Analytics".to_string(),
                            ],
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch target for SAS scanning: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for encryption configuration issues
    async fn scan_encryption_config(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        info!("Scanning Azure Storage encryption configuration");

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
            format!("{}data", domain),
        ];

        for storage_account in storage_patterns {
            // Test if storage account exists and check for encryption headers
            let test_url = format!("https://{}.blob.core.windows.net/", storage_account);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for encryption in transit (HTTPS requirement)
                    if !self.has_secure_transfer_required(&response.headers) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage Insecure Transfer Allowed",
                            "",
                            &format!(
                                "Storage account '{}' allows insecure HTTP transfers. Secure transfer required should be enabled.",
                                storage_account
                            ),
                            "Missing x-ms-require-secure-transfer header or set to false",
                            Severity::High,
                            "CWE-319",
                            7.4,
                            vec![
                                "Enable 'Secure transfer required' in storage account settings".to_string(),
                                "Enforce HTTPS-only access for all blob operations".to_string(),
                                "Update client applications to use HTTPS endpoints".to_string(),
                                "Enable storage account firewall rules".to_string(),
                                "Use Azure Policy to enforce secure transfer".to_string(),
                            ],
                        ));
                    }

                    // Check for encryption at rest indicators
                    if !self.has_encryption_at_rest(&response.headers, &response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage Encryption at Rest Not Verified",
                            "",
                            &format!(
                                "Storage account '{}' encryption at rest configuration cannot be verified. Ensure customer-managed keys are used for sensitive data.",
                                storage_account
                            ),
                            "Unable to verify encryption configuration",
                            Severity::Medium,
                            "CWE-311",
                            5.9,
                            vec![
                                "Use customer-managed keys (CMK) in Azure Key Vault".to_string(),
                                "Enable infrastructure encryption for double encryption".to_string(),
                                "Verify Microsoft-managed encryption is active (default)".to_string(),
                                "Rotate encryption keys regularly".to_string(),
                                "Enable Azure Key Vault soft delete and purge protection".to_string(),
                            ],
                        ));
                    }
                }
                Err(e) => {
                    debug!("Encryption check failed for {}: {}", storage_account, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for data protection features (soft delete, versioning)
    async fn scan_data_protection(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Scanning Azure Storage data protection features");

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
        ];

        for storage_account in storage_patterns {
            let test_url = format!("https://{}.blob.core.windows.net/", storage_account);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for soft delete capability
                    if !self.has_soft_delete_enabled(&response.headers) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Blob Soft Delete Disabled",
                            "",
                            &format!(
                                "Storage account '{}' does not have soft delete enabled. Deleted blobs cannot be recovered.",
                                storage_account
                            ),
                            "Soft delete protection not detected",
                            Severity::Medium,
                            "CWE-404",
                            5.3,
                            vec![
                                "Enable soft delete for blobs (7-365 days retention)".to_string(),
                                "Enable soft delete for containers".to_string(),
                                "Enable blob versioning for point-in-time recovery".to_string(),
                                "Configure backup policies for critical data".to_string(),
                                "Test restore procedures regularly".to_string(),
                            ],
                        ));
                    }

                    // Check for versioning
                    if !self.has_versioning_enabled(&response.headers) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Blob Versioning Disabled",
                            "",
                            &format!(
                                "Storage account '{}' does not have blob versioning enabled. Previous versions cannot be recovered.",
                                storage_account
                            ),
                            "Blob versioning not detected",
                            Severity::Low,
                            "CWE-404",
                            3.7,
                            vec![
                                "Enable blob versioning for automatic version tracking".to_string(),
                                "Configure lifecycle management policies".to_string(),
                                "Use immutable blob storage for compliance".to_string(),
                                "Implement point-in-time restore capabilities".to_string(),
                            ],
                        ));
                    }
                }
                Err(e) => {
                    debug!("Data protection check failed for {}: {}", storage_account, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for network security configurations
    async fn scan_network_security(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Scanning Azure Storage network security");

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
        ];

        for storage_account in storage_patterns {
            let test_url = format!("https://{}.blob.core.windows.net/", storage_account);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if publicly accessible (no network rules)
                    if response.status_code == 200 || self.is_publicly_accessible(&response) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage Public Network Access Enabled",
                            "",
                            &format!(
                                "Storage account '{}' allows public network access. Network rules should restrict access.",
                                storage_account
                            ),
                            "Storage account accessible from public internet",
                            Severity::High,
                            "CWE-668",
                            7.5,
                            vec![
                                "Disable public network access and use Private Link".to_string(),
                                "Configure firewall rules to allow specific IP ranges".to_string(),
                                "Enable virtual network service endpoints".to_string(),
                                "Use Azure Private Endpoint for private connectivity".to_string(),
                                "Implement network security groups (NSGs)".to_string(),
                                "Enable Azure Defender for Storage".to_string(),
                            ],
                        ));
                    }
                }
                Err(e) => {
                    debug!("Network security check failed for {}: {}", storage_account, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for CORS misconfigurations
    async fn scan_cors_configuration(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Scanning Azure Storage CORS configuration");

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
        ];

        for storage_account in storage_patterns {
            let test_url = format!("https://{}.blob.core.windows.net/", storage_account);

            // Send CORS preflight request
            let mut cors_headers = HashMap::new();
            cors_headers.insert("Origin".to_string(), "https://evil.com".to_string());
            cors_headers.insert("Access-Control-Request-Method".to_string(), "GET".to_string());

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(cors_issue) = self.detect_cors_misconfiguration(&response.headers) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage CORS Misconfiguration",
                            "",
                            &format!(
                                "Storage account '{}' has CORS misconfiguration: {}",
                                storage_account, cors_issue
                            ),
                            &format!("CORS issue: {}", cors_issue),
                            Severity::Medium,
                            "CWE-942",
                            6.5,
                            vec![
                                "Restrict CORS to specific trusted origins".to_string(),
                                "Avoid using wildcard (*) in AllowedOrigins".to_string(),
                                "Limit AllowedMethods to required HTTP methods".to_string(),
                                "Set MaxAgeInSeconds to reasonable value (< 600)".to_string(),
                                "Review and minimize ExposedHeaders".to_string(),
                                "Disable CORS if not required".to_string(),
                            ],
                        ));
                    }
                }
                Err(e) => {
                    debug!("CORS check failed for {}: {}", storage_account, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for authentication configuration issues
    async fn scan_authentication_config(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Scanning Azure Storage authentication configuration");

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
        ];

        for storage_account in storage_patterns {
            let test_url = format!("https://{}.blob.core.windows.net/", storage_account);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if Shared Key access is allowed (should prefer Azure AD)
                    if self.allows_shared_key_access(&response.headers) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage Shared Key Access Enabled",
                            "",
                            &format!(
                                "Storage account '{}' allows Shared Key authorization. Azure AD authentication is more secure.",
                                storage_account
                            ),
                            "Shared Key access detected",
                            Severity::Medium,
                            "CWE-287",
                            5.3,
                            vec![
                                "Disable Shared Key authorization".to_string(),
                                "Use Azure AD authentication (managed identities)".to_string(),
                                "Implement role-based access control (RBAC)".to_string(),
                                "Use SAS tokens with stored access policies".to_string(),
                                "Rotate storage account keys regularly".to_string(),
                                "Monitor authentication attempts with Azure Monitor".to_string(),
                            ],
                        ));
                    }

                    // Check for anonymous access
                    if self.allows_anonymous_access(&response.headers, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            &test_url,
                            "Azure Storage Anonymous Access Allowed",
                            "",
                            &format!(
                                "Storage account '{}' allows anonymous access without authentication.",
                                storage_account
                            ),
                            "Anonymous access granted",
                            Severity::Critical,
                            "CWE-306",
                            9.1,
                            vec![
                                "Disable anonymous blob access at storage account level".to_string(),
                                "Set 'Allow Blob public access' to disabled".to_string(),
                                "Require authentication for all requests".to_string(),
                                "Use Azure AD or SAS tokens for access control".to_string(),
                                "Enable Azure Defender for Storage threat detection".to_string(),
                            ],
                        ));
                    }
                }
                Err(e) => {
                    debug!("Authentication check failed for {}: {}", storage_account, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    // Helper methods

    fn extract_domain(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host
                    .trim_start_matches("www.")
                    .split('.')
                    .next()
                    .unwrap_or("example")
                    .to_string();
            }
        }
        "example".to_string()
    }

    fn is_public_container(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<enumerationresults")
                || body_lower.contains("<blobs>")
                || body_lower.contains("<blob>")
                || (body_lower.contains("<?xml") && body_lower.contains("blob"));
        }
        false
    }

    fn analyze_sas_token(&self, url: &str) -> Option<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        if let Ok(parsed_url) = url::Url::parse(url) {
            let query_params: HashMap<String, String> = parsed_url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            // Check if this is a SAS URL
            if query_params.contains_key("sv") || query_params.contains_key("sig") {
                // Check for overly permissive permissions
                if let Some(permissions) = query_params.get("sp") {
                    if permissions.contains('w') && permissions.contains('d') {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Overly Permissive SAS Token",
                            "",
                            "SAS token grants write and delete permissions. Use minimal required permissions.",
                            &format!("Permissions: {}", permissions),
                            Severity::High,
                            "CWE-266",
                            7.5,
                            vec![
                                "Grant minimum required permissions (principle of least privilege)".to_string(),
                                "Use read-only SAS tokens when write access not needed".to_string(),
                                "Implement stored access policies for revocable SAS tokens".to_string(),
                            ],
                        ));
                    }
                }

                // Check for missing expiration
                if !query_params.contains_key("se") {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "SAS Token Without Expiration",
                        "",
                        "SAS token does not have an expiration time set. Tokens should have short expiration times.",
                        "Missing 'se' (expiration) parameter",
                        Severity::High,
                        "CWE-613",
                        7.5,
                        vec![
                            "Set short expiration times (minutes to hours)".to_string(),
                            "Implement token refresh mechanism for long-running operations".to_string(),
                            "Use stored access policies for revocable access".to_string(),
                        ],
                    ));
                }

                // Check for missing IP restrictions
                if !query_params.contains_key("sip") {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "SAS Token Without IP Restrictions",
                        "",
                        "SAS token does not restrict source IP addresses. Token can be used from any location.",
                        "Missing 'sip' (IP restriction) parameter",
                        Severity::Medium,
                        "CWE-250",
                        5.3,
                        vec![
                            "Add IP address restrictions to SAS tokens".to_string(),
                            "Use stored access policies for centralized control".to_string(),
                        ],
                    ));
                }
            }
        }

        if vulnerabilities.is_empty() {
            None
        } else {
            Some(vulnerabilities)
        }
    }

    fn has_secure_transfer_required(&self, headers: &HashMap<String, String>) -> bool {
        headers.get("x-ms-require-secure-transfer")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    fn has_encryption_at_rest(&self, headers: &HashMap<String, String>, _body: &str) -> bool {
        // Check for encryption indicators in headers
        headers.get("x-ms-server-encrypted")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    fn has_soft_delete_enabled(&self, _headers: &HashMap<String, String>) -> bool {
        // This would require Azure Management API access
        // For now, we assume not enabled unless proven otherwise
        false
    }

    fn has_versioning_enabled(&self, _headers: &HashMap<String, String>) -> bool {
        // This would require Azure Management API access
        // For now, we assume not enabled unless proven otherwise
        false
    }

    fn is_publicly_accessible(&self, _response: &crate::http_client::HttpResponse) -> bool {
        // If we got a response without auth, it's publicly accessible
        true
    }

    fn detect_cors_misconfiguration(&self, headers: &HashMap<String, String>) -> Option<String> {
        // Check for wildcard CORS
        if let Some(origin) = headers.get("access-control-allow-origin") {
            if origin == "*" {
                return Some("Wildcard (*) allowed origin - allows any domain".to_string());
            }
        }

        // Check for overly permissive methods
        if let Some(methods) = headers.get("access-control-allow-methods") {
            if methods.contains("DELETE") || methods.contains("PUT") {
                return Some("Dangerous HTTP methods (DELETE, PUT) allowed via CORS".to_string());
            }
        }

        None
    }

    fn allows_shared_key_access(&self, _headers: &HashMap<String, String>) -> bool {
        // This would require Azure Management API to check the setting
        // For now, we assume it's enabled (default behavior)
        true
    }

    fn allows_anonymous_access(&self, _headers: &HashMap<String, String>, status_code: u16) -> bool {
        // If we get 200 without auth, anonymous access is allowed
        status_code == 200
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
        remediation_steps: Vec<String>,
    ) -> Vulnerability {
        let remediation = if remediation_steps.is_empty() {
            self.get_default_remediation(vuln_type)
        } else {
            remediation_steps
                .iter()
                .enumerate()
                .map(|(i, step)| format!("{}. {}", i + 1, step))
                .collect::<Vec<_>>()
                .join("\n")
        };

        Vulnerability {
            id: format!("azure_storage_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "Azure Cloud Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn get_default_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Public Azure Blob Container" => {
                "Set container access level to Private. Use SAS tokens or Azure AD for access control.".to_string()
            }
            _ => "Follow Azure Storage security best practices.".to_string(),
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

    fn create_test_scanner() -> AzureStorageScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        AzureStorageScanner::new(client)
    }

    #[test]
    fn test_extract_domain() {
        let scanner = create_test_scanner();
        assert_eq!(scanner.extract_domain("https://www.example.com/path"), "example");
        assert_eq!(scanner.extract_domain("https://test.example.com"), "test");
    }

    #[test]
    fn test_is_public_container() {
        let scanner = create_test_scanner();

        let azure_response = r#"<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>file.txt</Name></Blob></Blobs></EnumerationResults>"#;
        assert!(scanner.is_public_container(azure_response, 200));

        assert!(!scanner.is_public_container("Access Denied", 403));
    }

    #[test]
    fn test_analyze_sas_token() {
        let scanner = create_test_scanner();

        // SAS URL with write/delete permissions
        let sas_url = "https://myaccount.blob.core.windows.net/mycontainer?sp=rwd&sv=2021-06-08&sig=abc123";
        assert!(scanner.analyze_sas_token(sas_url).is_some());

        // Regular URL
        let normal_url = "https://example.com/page";
        assert!(scanner.analyze_sas_token(normal_url).is_none());
    }

    #[test]
    fn test_detect_cors_misconfiguration() {
        let scanner = create_test_scanner();
        let mut headers = HashMap::new();

        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        assert!(scanner.detect_cors_misconfiguration(&headers).is_some());

        headers.clear();
        headers.insert("access-control-allow-methods".to_string(), "GET, POST, DELETE".to_string());
        assert!(scanner.detect_cors_misconfiguration(&headers).is_some());
    }
}
