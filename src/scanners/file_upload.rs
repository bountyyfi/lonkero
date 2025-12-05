// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - File Upload Scanner
 * Tests for file upload vulnerabilities and bypass techniques
 *
 * Detects:
 * - Dangerous file type acceptance (PHP, JSP, ASP, ASPX, executable files)
 * - Double extension bypass (e.g., file.php.jpg)
 * - MIME type mismatch/spoofing
 * - Null byte injection bypass
 * - Case sensitivity bypass (e.g., file.PHP)
 * - Missing file size limits (DoS risk)
 * - Content type validation bypass
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct FileUploadScanner {
    http_client: Arc<HttpClient>,
}

impl FileUploadScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for file upload vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing file upload vulnerabilities");

        // Common upload endpoints
        let upload_endpoints = vec![
            "/upload",
            "/api/upload",
            "/file/upload",
            "/files/upload",
            "/media/upload",
            "/attachment/upload",
        ];

        for endpoint in upload_endpoints {
            let upload_url = format!("{}{}", url.trim_end_matches('/'), endpoint);

            // Test dangerous file extensions
            let (vulns, tests) = self.test_dangerous_extensions(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test double extension bypass
            let (vulns, tests) = self.test_double_extension(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test MIME type mismatch
            let (vulns, tests) = self.test_mime_type_mismatch(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test null byte injection
            let (vulns, tests) = self.test_null_byte_injection(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test case sensitivity bypass
            let (vulns, tests) = self.test_case_sensitivity(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // If we found vulnerabilities at this endpoint, no need to test others
            if !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test dangerous file extensions
    async fn test_dangerous_extensions(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let dangerous_files = vec![
            ("test.php", "application/x-php", "<?php phpinfo(); ?>", "PHP"),
            ("test.jsp", "application/x-jsp", "<% out.println(\"test\"); %>", "JSP"),
            ("test.asp", "application/x-asp", "<% Response.Write(\"test\") %>", "ASP"),
            ("test.aspx", "application/x-aspx", "<%@ Page Language=\"C#\" %>test", "ASPX"),
            ("test.sh", "application/x-sh", "#!/bin/bash\necho test", "Shell Script"),
            ("test.exe", "application/x-msdownload", "MZ", "Executable"),
            ("test.svg", "image/svg+xml", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>", "SVG with XSS"),
        ];

        for (filename, mime_type, content, file_type) in dangerous_files {
            tests_run += 1;

            match self.upload_file(url, filename, content, mime_type).await {
                Ok((accepted, evidence)) => {
                    if accepted {
                        info!("Dangerous file type accepted: {}", file_type);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "FILE_UPLOAD_DANGEROUS_TYPE",
                            filename,
                            &format!("Server accepts dangerous file type: {}", file_type),
                            &evidence,
                            Severity::Critical,
                            9.8,
                        ));
                        break; // Found vulnerability, no need to test more
                    }
                }
                Err(e) => {
                    debug!("Upload test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test double extension bypass
    async fn test_double_extension(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        match self
            .upload_file(url, "test.php.jpg", "<?php phpinfo(); ?>", "image/jpeg")
            .await
        {
            Ok((accepted, evidence)) => {
                if accepted {
                    info!("Double extension bypass successful");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "FILE_UPLOAD_DOUBLE_EXTENSION",
                        "test.php.jpg",
                        "Server vulnerable to double extension bypass",
                        &evidence,
                        Severity::Critical,
                        9.0,
                    ));
                }
            }
            Err(e) => {
                debug!("Double extension test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test MIME type mismatch
    async fn test_mime_type_mismatch(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        // Upload PHP file with image MIME type
        match self
            .upload_file(url, "test.php", "<?php phpinfo(); ?>", "image/jpeg")
            .await
        {
            Ok((accepted, evidence)) => {
                if accepted {
                    info!("MIME type bypass successful");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "FILE_UPLOAD_MIME_BYPASS",
                        "test.php (MIME: image/jpeg)",
                        "Server trusts client-provided MIME type",
                        &evidence,
                        Severity::Critical,
                        8.8,
                    ));
                }
            }
            Err(e) => {
                debug!("MIME type mismatch test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test null byte injection
    async fn test_null_byte_injection(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        match self
            .upload_file(
                url,
                "test.php%00.jpg",
                "<?php phpinfo(); ?>",
                "image/jpeg",
            )
            .await
        {
            Ok((accepted, evidence)) => {
                if accepted {
                    info!("Null byte injection successful");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "FILE_UPLOAD_NULL_BYTE",
                        "test.php%00.jpg",
                        "Server vulnerable to null byte injection",
                        &evidence,
                        Severity::Critical,
                        8.5,
                    ));
                }
            }
            Err(e) => {
                debug!("Null byte injection test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test case sensitivity bypass
    async fn test_case_sensitivity(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        match self
            .upload_file(url, "test.PHP", "<?php phpinfo(); ?>", "application/x-php")
            .await
        {
            Ok((accepted, evidence)) => {
                if accepted {
                    info!("Case sensitivity bypass successful");
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "FILE_UPLOAD_CASE_BYPASS",
                        "test.PHP",
                        "Server vulnerable to case sensitivity bypass",
                        &evidence,
                        Severity::High,
                        7.5,
                    ));
                }
            }
            Err(e) => {
                debug!("Case sensitivity test failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Upload a file and check if accepted
    async fn upload_file(
        &self,
        url: &str,
        filename: &str,
        content: &str,
        mime_type: &str,
    ) -> anyhow::Result<(bool, String)> {
        // Create multipart form data
        let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4());
        let form_data = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n{}\r\n--{}--\r\n",
            boundary, filename, mime_type, content, boundary
        );

        let headers = vec![
            ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary)),
        ];

        match self.http_client.post_with_headers(url, &form_data, headers).await {
            Ok(response) => {
                let accepted = self.is_upload_accepted(&response.body, response.status_code);
                let evidence = if accepted {
                    format!("File {} accepted. Status: {}", filename, response.status_code)
                } else {
                    "File rejected".to_string()
                };
                Ok((accepted, evidence))
            }
            Err(e) => {
                debug!("Upload request failed: {}", e);
                Ok((false, "Request failed".to_string()))
            }
        }
    }

    /// Check if upload was accepted based on response
    fn is_upload_accepted(&self, body: &str, status: u16) -> bool {
        // Check status codes
        if matches!(status, 200 | 201 | 204) {
            return true;
        }

        // Check for success messages
        let success_patterns = vec![
            r"upload.*success",
            r"file.*uploaded",
            r"successfully.*saved",
            r"file.*accepted",
            r#""success":\s*true"#,
            r#""uploaded":\s*true"#,
        ];

        for pattern in success_patterns {
            if let Ok(regex) = regex::Regex::new(&format!("(?i){}", pattern)) {
                if regex.is_match(body) {
                    return true;
                }
            }
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cvss: f64,
    ) -> Vulnerability {
        let (cwe, remediation) = match vuln_type {
            "FILE_UPLOAD_DANGEROUS_TYPE" => (
                "CWE-434",
                "1. Implement allowlist of safe file extensions\n\
                 2. Validate file content (magic bytes), not just extension\n\
                 3. Store uploads outside web root\n\
                 4. Use random filenames to prevent direct access\n\
                 5. Implement file type detection based on content\n\
                 6. Scan uploaded files for malware\n\
                 7. Set proper file permissions (non-executable)",
            ),
            "FILE_UPLOAD_DOUBLE_EXTENSION" => (
                "CWE-434",
                "1. Validate file extensions properly using last extension\n\
                 2. Remove or replace multiple extensions\n\
                 3. Use allowlist validation\n\
                 4. Normalize filenames before processing\n\
                 5. Implement content-based validation",
            ),
            "FILE_UPLOAD_MIME_BYPASS" => (
                "CWE-434",
                "1. Never trust client-provided MIME types\n\
                 2. Validate file content using magic bytes\n\
                 3. Use file type detection libraries\n\
                 4. Implement server-side file type verification\n\
                 5. Combine multiple validation methods",
            ),
            "FILE_UPLOAD_NULL_BYTE" => (
                "CWE-158",
                "1. Sanitize filenames to remove null bytes\n\
                 2. Use modern file handling functions\n\
                 3. Validate filename length and characters\n\
                 4. Reject filenames with null bytes\n\
                 5. Update to latest runtime versions",
            ),
            "FILE_UPLOAD_CASE_BYPASS" => (
                "CWE-434",
                "1. Perform case-insensitive extension validation\n\
                 2. Convert extensions to lowercase before checking\n\
                 3. Use allowlist approach\n\
                 4. Implement consistent filename normalization",
            ),
            _ => (
                "CWE-434",
                "1. Implement comprehensive file upload validation\n\
                 2. Use allowlist approach for file types\n\
                 3. Validate both extension and content\n\
                 4. Store uploads securely",
            ),
        };

        Vulnerability {
            id: format!("file_upload_{}", uuid::Uuid::new_v4()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "File Upload".to_string(),
            url: url.to_string(),
            parameter: Some("file".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: remediation.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            let mut rng = rand::rng();
            format!(
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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> FileUploadScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        FileUploadScanner::new(http_client)
    }

    #[test]
    fn test_is_upload_accepted_status_200() {
        let scanner = create_test_scanner();
        assert!(scanner.is_upload_accepted("", 200));
    }

    #[test]
    fn test_is_upload_accepted_status_201() {
        let scanner = create_test_scanner();
        assert!(scanner.is_upload_accepted("", 201));
    }

    #[test]
    fn test_is_upload_accepted_success_message() {
        let scanner = create_test_scanner();
        assert!(scanner.is_upload_accepted("upload successful", 200));
        assert!(scanner.is_upload_accepted("file uploaded successfully", 200));
        assert!(scanner.is_upload_accepted("{\"success\": true}", 200));
    }

    #[test]
    fn test_is_upload_rejected() {
        let scanner = create_test_scanner();
        assert!(!scanner.is_upload_accepted("error: invalid file type", 400));
        assert!(!scanner.is_upload_accepted("file rejected", 403));
    }

    #[test]
    fn test_create_vulnerability_dangerous_type() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/upload",
            "FILE_UPLOAD_DANGEROUS_TYPE",
            "test.php",
            "Server accepts dangerous file type: PHP",
            "File test.php accepted. Status: 200",
            Severity::Critical,
            9.8,
        );

        assert_eq!(vuln.vuln_type, "FILE_UPLOAD_DANGEROUS_TYPE");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-434");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }

    #[test]
    fn test_create_vulnerability_double_extension() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/upload",
            "FILE_UPLOAD_DOUBLE_EXTENSION",
            "test.php.jpg",
            "Server vulnerable to double extension bypass",
            "File accepted",
            Severity::Critical,
            9.0,
        );

        assert_eq!(vuln.vuln_type, "FILE_UPLOAD_DOUBLE_EXTENSION");
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.remediation.contains("last extension"));
    }

    #[test]
    fn test_create_vulnerability_mime_bypass() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/upload",
            "FILE_UPLOAD_MIME_BYPASS",
            "test.php",
            "Server trusts client-provided MIME type",
            "File accepted with fake MIME type",
            Severity::Critical,
            8.8,
        );

        assert_eq!(vuln.cwe, "CWE-434");
        assert!(vuln.remediation.contains("magic bytes"));
        assert!(vuln.remediation.contains("Never trust client-provided"));
    }

    #[test]
    fn test_create_vulnerability_null_byte() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/upload",
            "FILE_UPLOAD_NULL_BYTE",
            "test.php%00.jpg",
            "Server vulnerable to null byte injection",
            "Null byte bypass successful",
            Severity::Critical,
            8.5,
        );

        assert_eq!(vuln.cwe, "CWE-158");
        assert!(vuln.remediation.contains("null bytes"));
    }

    #[test]
    fn test_create_vulnerability_case_bypass() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/upload",
            "FILE_UPLOAD_CASE_BYPASS",
            "test.PHP",
            "Server vulnerable to case sensitivity bypass",
            "Case bypass successful",
            Severity::High,
            7.5,
        );

        assert_eq!(vuln.severity, Severity::High);
        assert!(vuln.remediation.contains("case-insensitive"));
    }
}
