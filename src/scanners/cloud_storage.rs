// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for cloud storage misconfigurations (S3, Azure Blob, GCS)
pub struct CloudStorageScanner {
    http_client: Arc<HttpClient>,
}

impl CloudStorageScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Run cloud storage misconfiguration scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // Premium feature check - cloud_scanning requires paid license
        if !crate::license::is_feature_available("cloud_scanning") {
            info!("[SKIP] Cloud storage scanning requires Professional or higher license");
            return Ok((Vec::new(), 0));
        }

        info!("Starting cloud storage misconfiguration scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        let domain = self.extract_domain(url);

        // Test S3 buckets
        let (vulns, tests) = self.scan_s3_buckets(&domain).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Azure Blob
        let (vulns, tests) = self.scan_azure_blob(&domain).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test Google Cloud Storage
        let (vulns, tests) = self.scan_gcs(&domain).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "Cloud storage scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Extract domain from URL
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

    /// Scan for exposed S3 buckets
    async fn scan_s3_buckets(&self, domain: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        info!("Testing S3 buckets for domain: {}", domain);

        let bucket_patterns = vec![
            format!("{}-backups", domain),
            format!("{}-backup", domain),
            format!("{}-data", domain),
            format!("{}-files", domain),
            format!("{}-uploads", domain),
            format!("{}-images", domain),
            format!("{}-assets", domain),
            format!("{}-static", domain),
            format!("{}-dev", domain),
            format!("{}-prod", domain),
        ];

        for bucket_name in bucket_patterns {
            let s3_url = format!("https://{}.s3.amazonaws.com/", bucket_name);

            match self.http_client.get(&s3_url).await {
                Ok(response) => {
                    if self.detect_exposed_bucket(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Exposed S3 Bucket",
                            &s3_url,
                            &format!("Publicly accessible S3 bucket found: {}", bucket_name),
                            Severity::High,
                            "CWE-732",
                        ));
                    }
                }
                Err(_) => {
                    // Bucket doesn't exist or not accessible
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for exposed Azure Blob storage
    async fn scan_azure_blob(&self, domain: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing Azure Blob storage for domain: {}", domain);

        let storage_patterns = vec![
            format!("{}", domain),
            format!("{}storage", domain),
            format!("{}data", domain),
            format!("{}files", domain),
            format!("{}backup", domain),
        ];

        for storage_name in storage_patterns {
            let azure_url = format!("https://{}.blob.core.windows.net/", storage_name);

            match self.http_client.get(&azure_url).await {
                Ok(response) => {
                    if self.detect_exposed_blob(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Exposed Azure Blob Storage",
                            &azure_url,
                            &format!("Publicly accessible Azure Blob storage found: {}", storage_name),
                            Severity::High,
                            "CWE-732",
                        ));
                    }
                }
                Err(_) => {
                    // Storage doesn't exist or not accessible
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for exposed Google Cloud Storage
    async fn scan_gcs(&self, domain: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing Google Cloud Storage for domain: {}", domain);

        let bucket_patterns = vec![
            format!("{}", domain),
            format!("{}-storage", domain),
            format!("{}-data", domain),
            format!("{}-files", domain),
            format!("{}-backup", domain),
        ];

        for bucket_name in bucket_patterns {
            let gcs_url = format!("https://storage.googleapis.com/{}/", bucket_name);

            match self.http_client.get(&gcs_url).await {
                Ok(response) => {
                    if self.detect_exposed_gcs(&response.body, response.status_code) {
                        vulnerabilities.push(self.create_vulnerability(
                            "Exposed Google Cloud Storage",
                            &gcs_url,
                            &format!("Publicly accessible GCS bucket found: {}", bucket_name),
                            Severity::High,
                            "CWE-732",
                        ));
                    }
                }
                Err(_) => {
                    // Bucket doesn't exist or not accessible
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect exposed S3 bucket
    fn detect_exposed_bucket(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<listbucketresult") ||
                   body_lower.contains("<contents>") ||
                   body_lower.contains("<key>") && body_lower.contains("</key>");
        }
        false
    }

    /// Detect exposed Azure Blob storage
    fn detect_exposed_blob(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<enumerationresults") ||
                   body_lower.contains("<blobs>") ||
                   body_lower.contains("<containers>");
        }
        false
    }

    /// Detect exposed Google Cloud Storage
    fn detect_exposed_gcs(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<listbucketresult") ||
                   body_lower.contains("storage.googleapis.com") ||
                   (body_lower.contains("<contents>") && body_lower.contains("</contents>"));
        }
        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("cloud_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Cloud Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Exposed S3 Bucket" => {
                "Restrict S3 bucket access using IAM policies and bucket policies. Remove public read/write permissions. Enable S3 Block Public Access. Use CloudFront with Origin Access Identity for public content. Enable S3 access logging and monitor for unauthorized access.".to_string()
            }
            "Exposed Azure Blob Storage" => {
                "Set blob storage access level to Private. Use Shared Access Signatures (SAS) with expiration for temporary access. Enable Azure Storage encryption. Use Azure CDN with private endpoints. Monitor storage account activity logs.".to_string()
            }
            "Exposed Google Cloud Storage" => {
                "Set bucket ACLs to private. Use signed URLs for temporary access. Enable uniform bucket-level access. Implement Cloud IAM policies. Enable Cloud Storage object versioning. Monitor audit logs for unauthorized access.".to_string()
            }
            _ => {
                "Implement proper cloud storage access controls. Use private buckets by default. Implement least privilege access. Enable logging and monitoring. Use encryption at rest and in transit.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> CloudStorageScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        CloudStorageScanner::new(client)
    }

    #[test]
    fn test_extract_domain() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.extract_domain("https://www.example.com/path"), "example");
        assert_eq!(scanner.extract_domain("https://test.example.com"), "test");
        assert_eq!(scanner.extract_domain("http://api.domain.com"), "api");
    }

    #[test]
    fn test_detect_exposed_bucket() {
        let scanner = create_test_scanner();

        let s3_response = r#"<?xml version="1.0"?><ListBucketResult><Contents><Key>file.txt</Key></Contents></ListBucketResult>"#;
        assert!(scanner.detect_exposed_bucket(s3_response, 200));

        assert!(!scanner.detect_exposed_bucket("Access Denied", 403));
    }

    #[test]
    fn test_detect_exposed_blob() {
        let scanner = create_test_scanner();

        let azure_response = r#"<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>file.txt</Name></Blob></Blobs></EnumerationResults>"#;
        assert!(scanner.detect_exposed_blob(azure_response, 200));

        assert!(!scanner.detect_exposed_blob("Not found", 404));
    }

    #[test]
    fn test_detect_exposed_gcs() {
        let scanner = create_test_scanner();

        let gcs_response = r#"<?xml version="1.0"?><ListBucketResult><Contents><Key>data.json</Key></Contents></ListBucketResult>"#;
        assert!(scanner.detect_exposed_gcs(gcs_response, 200));

        assert!(!scanner.detect_exposed_gcs("Forbidden", 403));
    }
}
