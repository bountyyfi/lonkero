// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use chrono::Datelike;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

// Lazy-compiled regex patterns for S3 URL detection (compiled once at startup)
static S3_VIRTUAL_HOSTED_REGEX: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"^([^.]+)\.s3[.-]([^.]+)\.amazonaws\.com$").ok());

static S3_VIRTUAL_HOSTED_US_EAST_REGEX: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"^([^.]+)\.s3\.amazonaws\.com$").ok());

static S3_PATH_STYLE_REGEX: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"s3[.-]([^.]+)\.amazonaws\.com").ok());

// CVSS scores as constants for consistency
const CVSS_CRITICAL: f32 = 9.5;
const CVSS_HIGH: f32 = 8.5;
const CVSS_MEDIUM: f32 = 5.5;
const CVSS_LOW: f32 = 3.5;
const CVSS_INFO: f32 = 2.0;

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

        // First try to detect if URL is a direct S3 bucket URL
        if let Some((bucket_name, region)) = self.detect_s3_url(url) {
            info!(
                "Direct S3 bucket URL detected: {} in region {}",
                bucket_name, region
            );
            let (vulns, tests) = self.scan_single_s3_bucket(&bucket_name, &region).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // Return immediately for direct S3 URLs - don't test other patterns
            return Ok((all_vulnerabilities, total_tests));
        }

        // Otherwise extract domain and test patterns
        let domain = self.extract_domain(url);

        // Test S3 buckets
        let (vulns, tests) = self.scan_s3_buckets(url).await?;
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

    /// Detect if URL is a direct S3 bucket URL
    /// Uses pre-compiled lazy regexes for performance
    fn detect_s3_url(&self, url: &str) -> Option<(String, String)> {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                // Pattern 1: bucket-name.s3.region.amazonaws.com (virtual-hosted with region)
                if let Some(ref re) = *S3_VIRTUAL_HOSTED_REGEX {
                    if let Some(caps) = re.captures(host) {
                        let bucket = caps.get(1)?.as_str().to_string();
                        let region = caps.get(2)?.as_str().to_string();
                        return Some((bucket, region));
                    }
                }

                // Pattern 2: bucket-name.s3.amazonaws.com (virtual-hosted us-east-1)
                if let Some(ref re) = *S3_VIRTUAL_HOSTED_US_EAST_REGEX {
                    if let Some(caps) = re.captures(host) {
                        let bucket = caps.get(1)?.as_str().to_string();
                        return Some((bucket, "us-east-1".to_string()));
                    }
                }

                // Pattern 3: s3.region.amazonaws.com/bucket-name (path-style)
                if host.starts_with("s3.") || host.starts_with("s3-") {
                    let path = parsed.path();
                    if !path.is_empty() && path != "/" {
                        let bucket = path.trim_start_matches('/').split('/').next()?.to_string();

                        // Extract region from host using pre-compiled regex
                        if let Some(ref re) = *S3_PATH_STYLE_REGEX {
                            if let Some(caps) = re.captures(host) {
                                let region = caps.get(1)?.as_str().to_string();
                                return Some((bucket, region));
                            }
                        }
                        return Some((bucket, "us-east-1".to_string()));
                    }
                }
            }
        }
        None
    }

    /// Scan for exposed S3 buckets
    /// Note: Direct S3 URL detection is handled in scan() before this is called
    async fn scan_s3_buckets(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract just the hostname from URL if a full URL was passed
        // oh2fih thanks
        let hostname = if url.starts_with("http://") || url.starts_with("https://") {
            url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| url.to_string())
        } else {
            url.to_string()
        };

        // Extract base domain name (without TLD for bucket naming)
        // e.g., "example.com" -> "example", "sub.example.co.uk" -> "sub-example"
        let base_name = hostname
            .split('.')
            .filter(|part| {
                ![
                    "com", "org", "net", "io", "co", "uk", "fi", "se", "de", "fr", "es", "it",
                    "nl", "be", "at", "ch", "www",
                ]
                .contains(part)
            })
            .collect::<Vec<_>>()
            .join("-");

        // Use base_name if we extracted something useful, otherwise use the hostname without dots
        let bucket_base = if base_name.is_empty() {
            hostname.replace('.', "-")
        } else {
            base_name
        };

        // Test common bucket naming patterns
        debug!(
            "Testing S3 buckets for URL: {} (bucket base: {})",
            url, bucket_base
        );

        let bucket_patterns = vec![
            format!("{}-backups", bucket_base),
            format!("{}-backup", bucket_base),
            format!("{}-data", bucket_base),
            format!("{}-files", bucket_base),
            format!("{}-uploads", bucket_base),
            format!("{}-images", bucket_base),
            format!("{}-assets", bucket_base),
            format!("{}-static", bucket_base),
            format!("{}-dev", bucket_base),
            format!("{}-prod", bucket_base),
        ];

        let regions = vec!["us-east-1", "us-west-2", "eu-west-1", "eu-north-1"];

        for bucket_name in bucket_patterns {
            // Try multiple regions
            for region in &regions {
                tests_run += 1;
                let s3_url = format!("https://{}.s3.{}.amazonaws.com/", bucket_name, region);

                match self.http_client.get(&s3_url).await {
                    Ok(response) => {
                        if self.detect_exposed_bucket(&response.body, response.status_code) {
                            info!("Found exposed S3 bucket: {} in {}", bucket_name, region);
                            // Run thorough scan on found bucket
                            let (vulns, tests) =
                                self.scan_single_s3_bucket(&bucket_name, region).await?;
                            vulnerabilities.extend(vulns);
                            tests_run += tests;
                            break; // Found it, no need to test other regions
                        }
                    }
                    Err(e) => {
                        // Bucket doesn't exist or not accessible - expected for most tests
                        debug!(
                            "S3 bucket {} not accessible in {}: {}",
                            bucket_name, region, e
                        );
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Perform thorough scan on a single S3 bucket
    async fn scan_single_s3_bucket(
        &self,
        bucket_name: &str,
        region: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!(
            "Running thorough S3 scan on bucket: {} (region: {})",
            bucket_name, region
        );

        let bucket_url = format!("https://{}.s3.{}.amazonaws.com", bucket_name, region);

        // Test 1: Directory listing
        tests_run += 1;
        match self.http_client.get(&bucket_url).await {
            Ok(response) => {
                if response.status_code == 200
                    && self.detect_exposed_bucket(&response.body, response.status_code)
                {
                    let object_count = response.body.matches("<Key>").count();

                    vulnerabilities.push(self.create_vulnerability_with_evidence(
                        "Public S3 Directory Listing",
                        &bucket_url,
                        &format!(
                            "S3 bucket '{}' allows public directory listing. Found approximately {} objects exposed.",
                            bucket_name, object_count
                        ),
                        Severity::Critical,
                        "CWE-548",
                        format!("Bucket: {}\nRegion: {}\nObjects found: {}\nStatus: {}",
                                bucket_name, region, object_count, response.status_code),
                    ));

                    // Check for sensitive file patterns in listing
                    let sensitive_patterns = vec![
                        ".env",
                        ".git",
                        "config",
                        "credentials",
                        "secret",
                        "password",
                        "private",
                        ".pem",
                        ".key",
                        "backup",
                        ".sql",
                        ".db",
                        "dump",
                        ".htpasswd",
                        "wp-config",
                        "id_rsa",
                    ];

                    for pattern in sensitive_patterns {
                        if response.body.to_lowercase().contains(pattern) {
                            vulnerabilities.push(self.create_vulnerability_with_evidence(
                                "Sensitive File in Public S3 Bucket",
                                &bucket_url,
                                &format!(
                                    "Potentially sensitive file pattern '{}' found in bucket '{}'",
                                    pattern, bucket_name
                                ),
                                Severity::Critical,
                                "CWE-538",
                                format!(
                                    "Bucket: {}\nRegion: {}\nPattern: {}",
                                    bucket_name, region, pattern
                                ),
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Directory listing test failed for {}: {}", bucket_name, e);
            }
        }

        // Test 2: Advanced sensitive file paths - really comprehensive list
        let sensitive_paths = vec![
            // Git files
            ".git/config",
            ".git/HEAD",
            ".git/index",
            ".git/logs/HEAD",
            ".gitignore",
            ".github/workflows/deploy.yml",
            ".github/workflows/ci.yml",
            // Environment & Config
            ".env",
            ".env.local",
            ".env.production",
            ".env.backup",
            "config.json",
            "config.php",
            "wp-config.php",
            "settings.py",
            "config.yml",
            "application.properties",
            // AWS & Cloud Credentials
            ".aws/credentials",
            ".aws/config",
            "aws.json",
            "credentials.json",
            "secrets.json",
            "api-keys.json",
            "firebase.json",
            ".firebase",
            // SSH & Crypto Keys
            "id_rsa",
            "id_rsa.pub",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "private.key",
            "server.key",
            "privatekey.pem",
            ".ssh/id_rsa",
            ".ssh/authorized_keys",
            // Database Files
            "backup.sql",
            "database.sql",
            "dump.sql",
            "db.sql",
            "database.db",
            "database.sqlite",
            "database.sqlite3",
            "db.sqlite",
            "data.db",
            // Backup & Archive Files
            "backup.zip",
            "backup.tar.gz",
            "backup.tar",
            "site-backup.zip",
            "backup.7z",
            "dump.tar.gz",
            "www.zip",
            "site.tar.gz",
            "prod-backup.zip",
            // Web Configs
            ".htaccess",
            ".htpasswd",
            "web.config",
            "httpd.conf",
            "nginx.conf",
            // Docker & Container
            "docker-compose.yml",
            "Dockerfile",
            ".dockerignore",
            // Package Managers
            "package.json",
            "package-lock.json",
            "composer.json",
            "composer.lock",
            "Gemfile",
            "Gemfile.lock",
            "requirements.txt",
            "yarn.lock",
            // API Documentation
            "swagger.json",
            "openapi.json",
            "postman_collection.json",
            // Laravel specific
            ".env.example",
            "storage/logs/laravel.log",
            // WordPress
            "wp-config-sample.php",
            "wp-content/debug.log",
            // Terraform & IaC
            "terraform.tfstate",
            "terraform.tfvars",
            ".terraform/",
            // CI/CD
            ".travis.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            "circle.yml",
            ".circleci/config.yml",
        ];

        // Test first 25 most critical patterns
        for path in sensitive_paths.iter().take(25) {
            tests_run += 1;
            let test_url = format!("{}/{}", bucket_url, path);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code >= 200 && response.status_code < 300 {
                        let file_size = response.body.len();

                        // Check for actual content (not empty or error pages)
                        if file_size > 0 && !response.body.contains("<Error>") {
                            let severity = if path.contains("credentials")
                                || path.contains("secret")
                                || path.contains("key")
                                || path.contains(".env")
                            {
                                Severity::Critical
                            } else if path.contains("backup")
                                || path.contains("dump")
                                || path.contains("database")
                            {
                                Severity::Critical
                            } else {
                                Severity::High
                            };

                            vulnerabilities.push(self.create_vulnerability_with_evidence(
                                "Exposed Sensitive File in S3",
                                &test_url,
                                &format!("Sensitive file '{}' is publicly accessible. File size: {} bytes",
                                        path, file_size),
                                severity,
                                "CWE-538",
                                format!("Bucket: {}\nRegion: {}\nFile: {}\nStatus: {}\nSize: {} bytes",
                                        bucket_name, region, path, response.status_code, file_size),
                            ));
                        }
                    }
                }
                Err(_) => {
                    // Expected - most files won't exist
                }
            }
        }

        // Test dated backup files (pattern: backup-YYYY-MM-DD.sql)
        let current_year = chrono::Utc::now().year_ce().1 as i32;
        for year in (current_year - 2)..=current_year {
            for month in [1, 6, 12] {
                tests_run += 1;
                let dated_backup = format!("backup-{}-{:02}-01.sql", year, month);
                let test_url = format!("{}/{}", bucket_url, dated_backup);

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if response.status_code >= 200
                            && response.status_code < 300
                            && response.body.len() > 1000
                        {
                            vulnerabilities.push(self.create_vulnerability_with_evidence(
                                "Exposed Database Backup in S3",
                                &test_url,
                                &format!(
                                    "Dated database backup '{}' is publicly accessible",
                                    dated_backup
                                ),
                                Severity::Critical,
                                "CWE-538",
                                format!(
                                    "Bucket: {}\nRegion: {}\nFile: {}\nSize: {} bytes",
                                    bucket_name,
                                    region,
                                    dated_backup,
                                    response.body.len()
                                ),
                            ));
                            break; // Found one
                        }
                    }
                    Err(_) => {
                        // Expected - most dated backup patterns won't exist
                    }
                }
            }
        }

        // Test 3: ACL endpoint
        tests_run += 1;
        let acl_url = format!("{}/?acl", bucket_url);
        match self.http_client.get(&acl_url).await {
            Ok(response) => {
                if response.status_code == 200 && response.body.contains("<AccessControlList") {
                    if response.body.contains("AllUsers")
                        || response.body.contains("AuthenticatedUsers")
                    {
                        vulnerabilities.push(self.create_vulnerability_with_evidence(
                            "S3 Bucket ACL Too Permissive",
                            &acl_url,
                            &format!("S3 bucket '{}' has publicly accessible ACL granting AllUsers or AuthenticatedUsers", bucket_name),
                            Severity::Critical,
                            "CWE-732",
                            format!("Bucket: {}\nRegion: {}\nACL accessible", bucket_name, region),
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("ACL endpoint test failed for {}: {}", bucket_name, e);
            }
        }

        // Test 4: Bucket policy endpoint
        tests_run += 1;
        let policy_url = format!("{}/?policy", bucket_url);
        match self.http_client.get(&policy_url).await {
            Ok(response) => {
                if response.status_code == 200 && response.body.contains("\"Statement\"") {
                    if response.body.contains("\"Principal\":\"*\"")
                        || response.body.contains("\"Principal\":{\"AWS\":\"*\"}")
                    {
                        vulnerabilities.push(self.create_vulnerability_with_evidence(
                            "S3 Bucket Policy Allows Public Access",
                            &policy_url,
                            &format!("S3 bucket '{}' has bucket policy granting access to all principals (*)", bucket_name),
                            Severity::Critical,
                            "CWE-732",
                            format!("Bucket: {}\nRegion: {}\nPolicy contains wildcard principal", bucket_name, region),
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to fetch bucket policy for {}: {}", bucket_name, e);
            }
        }

        // Test 5: Write access test - attempt to PUT a harmless test file
        // This is a critical security check - public write = immediate compromise
        tests_run += 1;
        let write_test_key = format!(".lonkero-write-test-{}", Uuid::new_v4());
        let write_test_url = format!("{}/{}", bucket_url, write_test_key);
        let write_test_body = "lonkero-security-scan-write-test";

        match self.http_client.put(&write_test_url, write_test_body).await {
            Ok(response) => {
                if response.status_code == 200 || response.status_code == 204 {
                    // Write succeeded! This is critical - immediately try to delete the test file
                    warn!(
                        "CRITICAL: S3 bucket {} allows public write access! Test file created at {}",
                        bucket_name, write_test_key
                    );

                    vulnerabilities.push(self.create_vulnerability_with_evidence(
                        "Public S3 Write Access",
                        &bucket_url,
                        &format!(
                            "S3 bucket '{}' allows UNAUTHENTICATED WRITE access. \
                            Attackers can upload malicious files, overwrite existing content, \
                            or use the bucket for malware distribution.",
                            bucket_name
                        ),
                        Severity::Critical,
                        "CWE-732",
                        format!(
                            "Bucket: {}\nRegion: {}\nTest: PUT request succeeded (status {})\n\
                            Test key: {}\nIMPACT: Complete bucket compromise possible",
                            bucket_name, region, response.status_code, write_test_key
                        ),
                    ));

                    // Attempt cleanup - delete the test file we created
                    if let Err(e) = self.http_client.delete(&write_test_url).await {
                        debug!("Could not delete write test file {}: {}", write_test_key, e);
                    }
                }
            }
            Err(e) => {
                // Expected - most buckets don't allow public write
                debug!("Write test failed for {} (expected): {}", bucket_name, e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for exposed Azure Blob storage
    async fn scan_azure_blob(&self, domain: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing Azure Blob storage for domain: {}", domain);

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
                            &format!(
                                "Publicly accessible Azure Blob storage found: {}",
                                storage_name
                            ),
                            Severity::High,
                            "CWE-732",
                        ));
                    }
                }
                Err(e) => {
                    // Storage doesn't exist or not accessible - expected for most tests
                    debug!("Azure Blob {} not accessible: {}", storage_name, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for exposed Google Cloud Storage
    async fn scan_gcs(&self, domain: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing Google Cloud Storage for domain: {}", domain);

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
                Err(e) => {
                    // Bucket doesn't exist or not accessible - expected for most tests
                    debug!("GCS bucket {} not accessible: {}", bucket_name, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect exposed S3 bucket
    fn detect_exposed_bucket(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<listbucketresult")
                || body_lower.contains("<contents>")
                || body_lower.contains("<key>") && body_lower.contains("</key>");
        }
        false
    }

    /// Detect exposed Azure Blob storage
    fn detect_exposed_blob(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<enumerationresults")
                || body_lower.contains("<blobs>")
                || body_lower.contains("<containers>");
        }
        false
    }

    /// Detect exposed Google Cloud Storage
    fn detect_exposed_gcs(&self, body: &str, status_code: u16) -> bool {
        if status_code == 200 {
            let body_lower = body.to_lowercase();
            return body_lower.contains("<listbucketresult")
                || body_lower.contains("storage.googleapis.com")
                || (body_lower.contains("<contents>") && body_lower.contains("</contents>"));
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
            Severity::Critical => CVSS_CRITICAL,
            Severity::High => CVSS_HIGH,
            Severity::Medium => CVSS_MEDIUM,
            Severity::Low => CVSS_LOW,
            Severity::Info => CVSS_INFO,
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
            ml_data: None,
        }
    }

    /// Create a vulnerability record with detailed evidence
    fn create_vulnerability_with_evidence(
        &self,
        vuln_type: &str,
        url: &str,
        description: &str,
        severity: Severity,
        cwe: &str,
        evidence: String,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => CVSS_CRITICAL,
            Severity::High => CVSS_HIGH,
            Severity::Medium => CVSS_MEDIUM,
            Severity::Low => CVSS_LOW,
            Severity::Info => CVSS_INFO,
        };

        Vulnerability {
            id: format!("s3_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::High,
            category: "Cloud Security - AWS S3".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Get remediation advice
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Public S3 Directory Listing" | "Exposed S3 Bucket" => {
                "1. CRITICAL: Remove public access from S3 bucket immediately\n\
                 2. Enable S3 Block Public Access at account and bucket level\n\
                 3. Review and restrict bucket ACL - remove AllUsers and AuthenticatedUsers grants\n\
                 4. Update bucket policy to restrict access to specific principals\n\
                 5. Use CloudFront with Origin Access Identity (OAI) for public content delivery\n\
                 6. Enable S3 access logging to monitor for unauthorized access\n\
                 7. Implement versioning and MFA delete for data protection\n\
                 8. Audit existing data for exposed sensitive information\n\
                 9. Use AWS Access Analyzer to identify public resources".to_string()
            }
            "Sensitive File in Public S3 Bucket" | "Exposed Sensitive File in S3" => {
                "1. IMMEDIATE: Remove or restrict access to sensitive file\n\
                 2. Rotate any exposed credentials, API keys, or secrets\n\
                 3. Enable S3 Block Public Access settings\n\
                 4. Review and update bucket ACL and policy\n\
                 5. Implement S3 Object Lock for critical files\n\
                 6. Use AWS Secrets Manager or Parameter Store for credentials\n\
                 7. Enable S3 versioning to recover from accidental exposures\n\
                 8. Set up CloudWatch alarms for suspicious access patterns\n\
                 9. Conduct security audit to identify other exposed secrets".to_string()
            }
            "Public S3 Write Access" => {
                "1. CRITICAL EMERGENCY: Remove public write access immediately\n\
                 2. Check bucket for malicious uploads - scan all recent objects\n\
                 3. Enable S3 Block Public Access settings (all 4 options)\n\
                 4. Review and restrict bucket policy - remove wildcard principals\n\
                 5. Update bucket ACL - remove WRITE and FULL_CONTROL from AllUsers\n\
                 6. Enable S3 Object Lock to prevent object deletion\n\
                 7. Implement bucket versioning and MFA delete\n\
                 8. Set up CloudWatch Events to alert on PutObject operations\n\
                 9. Review CloudTrail logs for unauthorized uploads\n\
                 10. Consider using AWS SCPs to prevent public access at org level".to_string()
            }
            "S3 Bucket ACL Too Permissive" => {
                "1. Remove AllUsers and AuthenticatedUsers from bucket ACL\n\
                 2. Enable S3 Block Public Access (BlockPublicAcls, IgnorePublicAcls)\n\
                 3. Use bucket policies instead of ACLs for access control\n\
                 4. Implement least privilege IAM policies for bucket access\n\
                 5. Use CloudFront with OAI for public content delivery\n\
                 6. Regularly audit bucket permissions using AWS Access Analyzer\n\
                 7. Enable S3 access logging and monitor for unauthorized access".to_string()
            }
            "S3 Bucket Policy Allows Public Access" => {
                "1. Update bucket policy to remove wildcard (*) principals\n\
                 2. Specify exact IAM users, roles, or AWS accounts in Principal field\n\
                 3. Enable S3 Block Public Access (BlockPublicPolicy, RestrictPublicBuckets)\n\
                 4. Use IAM policies for internal access control\n\
                 5. Test policy changes using AWS Policy Simulator\n\
                 6. Implement condition keys in policies for additional security\n\
                 7. Use AWS SCPs to enforce policy restrictions at org level\n\
                 8. Monitor policy changes using CloudTrail and Config".to_string()
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

        assert_eq!(
            scanner.extract_domain("https://www.example.com/path"),
            "example"
        );
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

    #[test]
    fn test_detect_s3_url_virtual_hosted_with_region() {
        let scanner = create_test_scanner();

        // Pattern: bucket-name.s3.region.amazonaws.com
        let result =
            scanner.detect_s3_url("https://my-bucket.s3.us-west-2.amazonaws.com/path/file.txt");
        assert!(result.is_some());
        let (bucket, region) = result.unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(region, "us-west-2");

        // With eu-north-1 region
        let result = scanner.detect_s3_url("https://test-data.s3.eu-north-1.amazonaws.com/");
        assert!(result.is_some());
        let (bucket, region) = result.unwrap();
        assert_eq!(bucket, "test-data");
        assert_eq!(region, "eu-north-1");
    }

    #[test]
    fn test_detect_s3_url_virtual_hosted_us_east_1() {
        let scanner = create_test_scanner();

        // Pattern: bucket-name.s3.amazonaws.com (us-east-1 default)
        let result = scanner.detect_s3_url("https://legacy-bucket.s3.amazonaws.com/data");
        assert!(result.is_some());
        let (bucket, region) = result.unwrap();
        assert_eq!(bucket, "legacy-bucket");
        assert_eq!(region, "us-east-1");
    }

    #[test]
    fn test_detect_s3_url_path_style() {
        let scanner = create_test_scanner();

        // Pattern: s3.region.amazonaws.com/bucket-name
        let result = scanner.detect_s3_url("https://s3.eu-west-1.amazonaws.com/my-bucket/file.txt");
        assert!(result.is_some());
        let (bucket, region) = result.unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(region, "eu-west-1");

        // Path-style with s3- prefix
        let result =
            scanner.detect_s3_url("https://s3-ap-southeast-1.amazonaws.com/another-bucket/");
        assert!(result.is_some());
        let (bucket, region) = result.unwrap();
        assert_eq!(bucket, "another-bucket");
        assert_eq!(region, "ap-southeast-1");
    }

    #[test]
    fn test_detect_s3_url_non_s3() {
        let scanner = create_test_scanner();

        // Non-S3 URLs should return None
        assert!(scanner.detect_s3_url("https://example.com/path").is_none());
        assert!(scanner
            .detect_s3_url("https://storage.googleapis.com/bucket/")
            .is_none());
        assert!(scanner
            .detect_s3_url("https://myaccount.blob.core.windows.net/container/")
            .is_none());
        assert!(scanner.detect_s3_url("not-a-url").is_none());
    }

    #[test]
    fn test_detect_s3_url_empty_path() {
        let scanner = create_test_scanner();

        // Path-style URL with empty path should return None
        let result = scanner.detect_s3_url("https://s3.us-east-1.amazonaws.com/");
        assert!(result.is_none());
    }
}
