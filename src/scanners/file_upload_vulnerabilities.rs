// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for file upload vulnerabilities
pub struct FileUploadVulnerabilitiesScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl FileUploadVulnerabilitiesScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("upload-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run file upload vulnerabilities scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting file upload vulnerabilities scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test unrestricted file extensions
        let (vulns, tests) = self.test_unrestricted_extensions(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test MIME type bypass
        let (vulns, tests) = self.test_mime_type_bypass(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test path traversal in filename
        let (vulns, tests) = self.test_path_traversal(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test double extension bypass
        let (vulns, tests) = self.test_double_extension(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "File upload vulnerabilities scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test unrestricted file extensions
    async fn test_unrestricted_extensions(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing unrestricted file extensions");

        // Try common upload endpoints
        let upload_endpoints = vec![
            format!("{}/upload", url.trim_end_matches('/')),
            format!("{}/api/upload", url.trim_end_matches('/')),
            format!("{}/file/upload", url.trim_end_matches('/')),
        ];

        // Dangerous file extensions
        let dangerous_extensions = vec![
            ("php", "<?php echo 'test'; ?>"),
            ("jsp", "<% out.println(\"test\"); %>"),
            ("asp", "<% Response.Write(\"test\") %>"),
            ("aspx", "<%@ Page Language=\"C#\" %><% Response.Write(\"test\"); %>"),
            ("sh", "#!/bin/bash\necho test"),
        ];

        for endpoint in &upload_endpoints {
            for (ext, content) in &dangerous_extensions {
                let filename = format!("{}.{}", self.test_marker, ext);
                let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

                let body = self.create_multipart_body(&boundary, &filename, content, "application/octet-stream");
                let headers = vec![
                    ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
                ];

                match self.http_client.post_with_headers(endpoint, &body, headers).await {
                    Ok(response) => {
                        if self.detect_upload_success(&response.body, response.status_code, &filename) {
                            vulnerabilities.push(self.create_vulnerability(
                                "Unrestricted File Upload",
                                endpoint,
                                &format!("Server accepted dangerous file extension .{}: {}", ext, filename),
                                Severity::Critical,
                                "CWE-434",
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        info!("Unrestricted extension test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test MIME type validation bypass
    async fn test_mime_type_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing MIME type validation bypass");

        let upload_endpoints = vec![
            format!("{}/upload", url.trim_end_matches('/')),
        ];

        // Upload PHP file with image MIME type
        let payloads = vec![
            ("php", "<?php echo 'test'; ?>", "image/jpeg", "MIME type spoofing with image/jpeg"),
            ("php", "<?php echo 'test'; ?>", "image/png", "MIME type spoofing with image/png"),
            ("jsp", "<% out.println(\"test\"); %>", "image/gif", "MIME type spoofing with image/gif"),
        ];

        for endpoint in &upload_endpoints {
            for (ext, content, mime_type, description) in &payloads {
                let filename = format!("{}.{}", self.test_marker, ext);
                let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

                let body = self.create_multipart_body(&boundary, &filename, content, mime_type);
                let headers = vec![
                    ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
                ];

                match self.http_client.post_with_headers(endpoint, &body, headers).await {
                    Ok(response) => {
                        if self.detect_upload_success(&response.body, response.status_code, &filename) {
                            vulnerabilities.push(self.create_vulnerability(
                                "File Upload MIME Type Bypass",
                                endpoint,
                                &format!("{}: Uploaded {} as {}", description, filename, mime_type),
                                Severity::Critical,
                                "CWE-434",
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        info!("MIME type bypass test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test path traversal in filename
    async fn test_path_traversal(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing path traversal in file upload");

        let upload_endpoints = vec![
            format!("{}/upload", url.trim_end_matches('/')),
        ];

        // Path traversal filenames
        let traversal_filenames = vec![
            format!("../../../{}.txt", self.test_marker),
            format!("..\\..\\..\\{}.txt", self.test_marker),
            format!("....//....//....//....//....//....//....//tmp/{}.txt", self.test_marker),
        ];

        for endpoint in &upload_endpoints {
            for filename in &traversal_filenames {
                let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
                let content = "test content";

                let body = self.create_multipart_body(&boundary, filename, content, "text/plain");
                let headers = vec![
                    ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
                ];

                match self.http_client.post_with_headers(endpoint, &body, headers).await {
                    Ok(response) => {
                        if self.detect_path_traversal_success(&response.body, response.status_code) {
                            vulnerabilities.push(self.create_vulnerability(
                                "File Upload Path Traversal",
                                endpoint,
                                &format!("Server accepted path traversal in filename: {}", filename),
                                Severity::High,
                                "CWE-22",
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        info!("Path traversal test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test double extension bypass
    async fn test_double_extension(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing double extension bypass");

        let upload_endpoints = vec![
            format!("{}/upload", url.trim_end_matches('/')),
        ];

        // Double extension filenames
        let double_extensions = vec![
            format!("{}.php.jpg", self.test_marker),
            format!("{}.jsp.png", self.test_marker),
            format!("{}.php.gif", self.test_marker),
        ];

        for endpoint in &upload_endpoints {
            for filename in &double_extensions {
                let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
                let content = "<?php echo 'test'; ?>";

                let body = self.create_multipart_body(&boundary, filename, content, "image/jpeg");
                let headers = vec![
                    ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
                ];

                match self.http_client.post_with_headers(endpoint, &body, headers).await {
                    Ok(response) => {
                        if self.detect_upload_success(&response.body, response.status_code, filename) {
                            vulnerabilities.push(self.create_vulnerability(
                                "File Upload Double Extension Bypass",
                                endpoint,
                                &format!("Server accepted double extension file: {}", filename),
                                Severity::Critical,
                                "CWE-434",
                            ));
                            return Ok((vulnerabilities, tests_run));
                        }
                    }
                    Err(e) => {
                        info!("Double extension test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Create multipart/form-data body
    fn create_multipart_body(&self, boundary: &str, filename: &str, content: &str, mime_type: &str) -> String {
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n{}\r\n--{}--\r\n",
            boundary, filename, mime_type, content, boundary
        )
    }

    /// Detect successful file upload
    fn detect_upload_success(&self, body: &str, status_code: u16, filename: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Success status codes
        if status_code == 200 || status_code == 201 {
            // Check for success indicators
            let filename_lower = filename.to_lowercase();
            let success_indicators = vec![
                "upload",
                "success",
                "uploaded",
                "file saved",
                "completed",
                filename_lower.as_str(),
            ];

            for indicator in success_indicators {
                if body_lower.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect path traversal success
    fn detect_path_traversal_success(&self, body: &str, status_code: u16) -> bool {
        let body_lower = body.to_lowercase();

        // If upload succeeded without error about invalid path
        (status_code == 200 || status_code == 201) &&
        !body_lower.contains("invalid path") &&
        !body_lower.contains("invalid filename") &&
        !body_lower.contains("path not allowed")
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
            Severity::Critical => 9.8,
            Severity::High => 8.1,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("upload_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::Medium,
            category: "File Upload".to_string(),
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

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Unrestricted File Upload" => {
                "Implement strict file extension validation using an allow-list (not deny-list). Validate file content and magic bytes, not just the extension. Store uploaded files outside the web root. Use randomized filenames. Implement file size limits. Scan uploads with antivirus.".to_string()
            }
            "File Upload MIME Type Bypass" => {
                "Don't rely solely on MIME type validation. Verify file content and magic bytes. Use an allow-list of permitted file types. Implement server-side validation of file headers. Store files outside web root with no execute permissions.".to_string()
            }
            "File Upload Path Traversal" => {
                "Sanitize filenames to remove path traversal characters (../, .\\, etc.). Use a allow-list of permitted characters. Generate random filenames server-side. Store files in a dedicated directory with no path traversal possible.".to_string()
            }
            "File Upload Double Extension Bypass" => {
                "Validate the complete filename, not just the last extension. Use allow-list validation for extensions. Consider generating filenames server-side. Configure web server to not execute files based on any extension in the filename.".to_string()
            }
            _ => {
                "Implement comprehensive file upload security: use extension allow-lists, validate file content and magic bytes, sanitize filenames, store outside web root, use random filenames, implement size limits, and scan with antivirus.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> FileUploadVulnerabilitiesScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        FileUploadVulnerabilitiesScanner::new(client)
    }

    #[test]
    fn test_detect_upload_success() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_upload_success(r#"{"message":"File uploaded successfully"}"#, 200, "test.php"));
        assert!(scanner.detect_upload_success(r#"Upload completed: test.jpg"#, 201, "test.jpg"));

        assert!(!scanner.detect_upload_success(r#"{"error":"Upload failed"}"#, 400, "test.php"));
    }

    #[test]
    fn test_detect_path_traversal_success() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_path_traversal_success(r#"{"message":"File saved"}"#, 200));

        assert!(!scanner.detect_path_traversal_success(r#"Invalid path detected"#, 400));
        assert!(!scanner.detect_path_traversal_success(r#"Path not allowed"#, 403));
    }

    #[test]
    fn test_create_multipart_body() {
        let scanner = create_test_scanner();

        let body = scanner.create_multipart_body("boundary123", "test.txt", "content", "text/plain");

        assert!(body.contains("boundary123"));
        assert!(body.contains("test.txt"));
        assert!(body.contains("text/plain"));
        assert!(body.contains("content"));
    }

    #[test]
    fn test_test_marker_uniqueness() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("upload-"));
    }
}
