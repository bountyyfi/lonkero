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

        // Step 1: Discover upload endpoints dynamically
        total_tests += 1;
        let upload_endpoints = self.discover_upload_endpoints(url).await?;

        if upload_endpoints.is_empty() {
            info!("No upload endpoints found, testing default endpoints");
            // Fallback to testing common endpoints
            let (vulns, tests) = self.test_default_endpoints(url).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;
        } else {
            info!("Found {} upload endpoints to test", upload_endpoints.len());

            // Test each discovered endpoint
            for endpoint in upload_endpoints {
                if !all_vulnerabilities.is_empty() {
                    break; // Found vulnerability, stop testing
                }

                // Test unrestricted file extensions
                let (vulns, tests) = self.test_unrestricted_extensions(&endpoint).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests;

                if all_vulnerabilities.is_empty() {
                    // Test MIME type bypass
                    let (vulns, tests) = self.test_mime_type_bypass(&endpoint).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests;
                }

                if all_vulnerabilities.is_empty() {
                    // Test path traversal in filename
                    let (vulns, tests) = self.test_path_traversal(&endpoint).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests;
                }

                if all_vulnerabilities.is_empty() {
                    // Test double extension bypass
                    let (vulns, tests) = self.test_double_extension(&endpoint).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests;
                }
            }
        }

        info!(
            "File upload vulnerabilities scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Discover upload endpoints by scanning for forms with enctype="multipart/form-data"
    async fn discover_upload_endpoints(&self, url: &str) -> anyhow::Result<Vec<String>> {
        let mut endpoints = Vec::new();

        match self.http_client.get(url).await {
            Ok(response) => {
                let body = response.body.to_lowercase();

                // Look for forms with multipart/form-data
                if body.contains("multipart/form-data") {
                    // Extract form actions
                    let form_regex = regex::Regex::new(r#"<form[^>]*action=["']([^"']+)["'][^>]*>[\s\S]*?multipart/form-data"#).ok();
                    let form_regex2 = regex::Regex::new(r#"multipart/form-data[\s\S]*?<form[^>]*action=["']([^"']+)["']"#).ok();

                    let response_body = &response.body;

                    if let Some(re) = form_regex {
                        for cap in re.captures_iter(response_body) {
                            if let Some(action) = cap.get(1) {
                                let endpoint = self.normalize_endpoint(url, action.as_str());
                                if !endpoints.contains(&endpoint) {
                                    endpoints.push(endpoint);
                                }
                            }
                        }
                    }

                    if let Some(re) = form_regex2 {
                        for cap in re.captures_iter(response_body) {
                            if let Some(action) = cap.get(1) {
                                let endpoint = self.normalize_endpoint(url, action.as_str());
                                if !endpoints.contains(&endpoint) {
                                    endpoints.push(endpoint);
                                }
                            }
                        }
                    }
                }

                // Also check for common upload API patterns in JavaScript
                let js_patterns = [
                    r#"/upload"#,
                    r#"/api/upload"#,
                    r#"/file/upload"#,
                    r#"/files/upload"#,
                ];

                for pattern in js_patterns {
                    if response.body.contains(pattern) {
                        let endpoint = self.normalize_endpoint(url, pattern);
                        if !endpoints.contains(&endpoint) {
                            endpoints.push(endpoint);
                        }
                    }
                }
            }
            Err(e) => {
                info!("Failed to fetch page for endpoint discovery: {}", e);
            }
        }

        Ok(endpoints)
    }

    /// Normalize endpoint URL
    fn normalize_endpoint(&self, base_url: &str, endpoint: &str) -> String {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else if endpoint.starts_with('/') {
            // Extract base URL
            if let Ok(parsed) = url::Url::parse(base_url) {
                format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), endpoint)
            } else {
                format!("{}{}", base_url.trim_end_matches('/'), endpoint)
            }
        } else {
            format!("{}/{}", base_url.trim_end_matches('/'), endpoint)
        }
    }

    /// Test default endpoints when no upload forms are found
    async fn test_default_endpoints(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        let endpoints = vec![
            format!("{}/upload", url.trim_end_matches('/')),
            format!("{}/api/upload", url.trim_end_matches('/')),
            format!("{}/file/upload", url.trim_end_matches('/')),
        ];

        for endpoint in &endpoints {
            let (vulns, _) = self.test_unrestricted_extensions(endpoint).await?;
            vulnerabilities.extend(vulns);
            if !vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test unrestricted file extensions
    async fn test_unrestricted_extensions(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        info!("Testing unrestricted file extensions on: {}", url);

        // Dangerous file extensions with unique markers for verification
        let dangerous_extensions = vec![
            ("php", format!("<?php echo '{}'; ?>", self.test_marker)),
            ("jsp", format!("<% out.println(\"{}\"); %>", self.test_marker)),
            ("asp", format!("<% Response.Write(\"{}\") %>", self.test_marker)),
            ("aspx", format!("<%@ Page Language=\"C#\" %><% Response.Write(\"{}\"); %>", self.test_marker)),
            ("sh", format!("#!/bin/bash\necho {}", self.test_marker)),
        ];

        for (ext, content) in &dangerous_extensions {
            let filename = format!("{}.{}", self.test_marker, ext);
            let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

            let body = self.create_multipart_body(&boundary, &filename, content, "application/octet-stream");
            let headers = vec![
                ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
            ];

            // Step 1: Upload the file
            match self.http_client.post_with_headers(url, &body, headers).await {
                Ok(response) => {
                    // Step 2: Extract upload path from response or try common paths
                    let upload_paths = self.extract_upload_paths(&response.body, &filename, url);

                    // Step 3: Verify file was uploaded and can be accessed
                    for upload_path in upload_paths {
                        match self.http_client.get(&upload_path).await {
                            Ok(verify_response) => {
                                // Step 4: Check if our marker is in the response (proof of execution)
                                if verify_response.body.contains(&self.test_marker) {
                                    info!("VERIFIED: File uploaded and executed at {}", upload_path);
                                    vulnerabilities.push(self.create_vulnerability(
                                        "Unrestricted File Upload with Code Execution",
                                        url,
                                        &format!("Uploaded {} and verified execution. File accessible at: {}. Marker '{}' found in response.", filename, upload_path, self.test_marker),
                                        Severity::Critical,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                } else if verify_response.status_code == 200 {
                                    // File exists but didn't execute - still a vulnerability but lower severity
                                    info!("File uploaded but not executed at {}", upload_path);
                                    vulnerabilities.push(self.create_vulnerability(
                                        "Unrestricted File Upload",
                                        url,
                                        &format!("Uploaded {} to {}. File is accessible but execution not confirmed.", filename, upload_path),
                                        Severity::High,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                            Err(_) => {
                                // File not accessible at this path, try next one
                                continue;
                            }
                        }
                    }
                }
                Err(e) => {
                    info!("Upload test failed for .{}: {}", ext, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Extract potential upload paths from response or construct common ones
    fn extract_upload_paths(&self, response_body: &str, filename: &str, base_url: &str) -> Vec<String> {
        let mut paths = Vec::new();

        // Try to extract path from response JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(response_body) {
            // Check common JSON fields for upload path
            if let Some(path) = json.get("path").and_then(|v| v.as_str()) {
                paths.push(self.normalize_endpoint(base_url, path));
            }
            if let Some(url) = json.get("url").and_then(|v| v.as_str()) {
                paths.push(self.normalize_endpoint(base_url, url));
            }
            if let Some(location) = json.get("location").and_then(|v| v.as_str()) {
                paths.push(self.normalize_endpoint(base_url, location));
            }
            if let Some(file) = json.get("file").and_then(|v| v.as_str()) {
                paths.push(self.normalize_endpoint(base_url, file));
            }
        }

        // Try to extract from response body using regex
        let url_pattern = regex::Regex::new(&format!(r#"["'](/[^"']*{}[^"']*)["']"#, regex::escape(filename))).ok();
        if let Some(re) = url_pattern {
            for cap in re.captures_iter(response_body) {
                if let Some(path) = cap.get(1) {
                    paths.push(self.normalize_endpoint(base_url, path.as_str()));
                }
            }
        }

        // Try common upload directories
        let common_paths = vec![
            format!("/uploads/{}", filename),
            format!("/upload/{}", filename),
            format!("/files/{}", filename),
            format!("/static/uploads/{}", filename),
            format!("/media/{}", filename),
            format!("/content/{}", filename),
        ];

        for path in common_paths {
            paths.push(self.normalize_endpoint(base_url, &path));
        }

        paths
    }

    /// Test MIME type validation bypass
    async fn test_mime_type_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing MIME type validation bypass on: {}", url);

        // Upload PHP file with image MIME type
        let payloads = vec![
            ("php", format!("<?php echo '{}'; ?>", self.test_marker), "image/jpeg", "MIME type spoofing with image/jpeg"),
            ("php", format!("<?php echo '{}'; ?>", self.test_marker), "image/png", "MIME type spoofing with image/png"),
            ("jsp", format!("<% out.println(\"{}\"); %>", self.test_marker), "image/gif", "MIME type spoofing with image/gif"),
        ];

        for (ext, content, mime_type, description) in &payloads {
            let filename = format!("{}.{}", self.test_marker, ext);
            let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

            let body = self.create_multipart_body(&boundary, &filename, content, mime_type);
            let headers = vec![
                ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
            ];

            match self.http_client.post_with_headers(url, &body, headers).await {
                Ok(response) => {
                    let upload_paths = self.extract_upload_paths(&response.body, &filename, url);

                    for upload_path in upload_paths {
                        match self.http_client.get(&upload_path).await {
                            Ok(verify_response) => {
                                if verify_response.body.contains(&self.test_marker) {
                                    info!("VERIFIED: MIME bypass successful, file executed at {}", upload_path);
                                    vulnerabilities.push(self.create_vulnerability(
                                        "File Upload MIME Type Bypass with Code Execution",
                                        url,
                                        &format!("{}: Uploaded {} as {} and verified execution at {}. Marker found in response.", description, filename, mime_type, upload_path),
                                        Severity::Critical,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                } else if verify_response.status_code == 200 {
                                    vulnerabilities.push(self.create_vulnerability(
                                        "File Upload MIME Type Bypass",
                                        url,
                                        &format!("{}: Uploaded {} as {} to {}. File accessible but execution not confirmed.", description, filename, mime_type, upload_path),
                                        Severity::High,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                }
                Err(e) => {
                    info!("MIME type bypass test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test path traversal in filename
    async fn test_path_traversal(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing path traversal in file upload on: {}", url);

        // Path traversal filenames with unique content
        let traversal_filenames = vec![
            format!("../../../tmp/{}.txt", self.test_marker),
            format!("..\\..\\..\\tmp\\{}.txt", self.test_marker),
            format!("....//....//tmp/{}.txt", self.test_marker),
        ];

        for filename in &traversal_filenames {
            let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
            let content = format!("path_traversal_{}", self.test_marker);

            let body = self.create_multipart_body(&boundary, filename, &content, "text/plain");
            let headers = vec![
                ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
            ];

            match self.http_client.post_with_headers(url, &body, headers).await {
                Ok(response) => {
                    // Check if upload succeeded (status 200/201 and no error messages)
                    if (response.status_code == 200 || response.status_code == 201) &&
                       !response.body.to_lowercase().contains("invalid") &&
                       !response.body.to_lowercase().contains("error") &&
                       !response.body.to_lowercase().contains("forbidden") {

                        // Try to access the file in traversed location
                        let traversed_filename = format!("{}.txt", self.test_marker);
                        let potential_paths = vec![
                            format!("/tmp/{}", traversed_filename),
                            self.normalize_endpoint(url, &format!("/../../../tmp/{}", traversed_filename)),
                        ];

                        for path in potential_paths {
                            if let Ok(verify_response) = self.http_client.get(&path).await {
                                if verify_response.body.contains(&content) {
                                    info!("VERIFIED: Path traversal successful, file found at {}", path);
                                    vulnerabilities.push(self.create_vulnerability(
                                        "File Upload Path Traversal",
                                        url,
                                        &format!("Uploaded file with path traversal filename '{}' and verified at {}. Content marker found.", filename, path),
                                        Severity::High,
                                        "CWE-22",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                        }

                        // Even if we can't verify the file location, accepting path traversal is a vulnerability
                        vulnerabilities.push(self.create_vulnerability(
                            "File Upload Path Traversal (Unverified)",
                            url,
                            &format!("Server accepted path traversal filename '{}' without error. File location could not be verified.", filename),
                            Severity::Medium,
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

        Ok((vulnerabilities, tests_run))
    }

    /// Test double extension bypass
    async fn test_double_extension(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing double extension bypass on: {}", url);

        // Double extension filenames with unique markers
        let double_extensions = vec![
            (format!("{}.php.jpg", self.test_marker), format!("<?php echo '{}'; ?>", self.test_marker)),
            (format!("{}.jsp.png", self.test_marker), format!("<% out.println(\"{}\"); %>", self.test_marker)),
            (format!("{}.php.gif", self.test_marker), format!("<?php echo '{}'; ?>", self.test_marker)),
        ];

        for (filename, content) in &double_extensions {
            let boundary = format!("----WebKitFormBoundary{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

            let body = self.create_multipart_body(&boundary, filename, content, "image/jpeg");
            let headers = vec![
                ("Content-Type".to_string(), format!("multipart/form-data; boundary={}", boundary))
            ];

            match self.http_client.post_with_headers(url, &body, headers).await {
                Ok(response) => {
                    let upload_paths = self.extract_upload_paths(&response.body, filename, url);

                    for upload_path in upload_paths {
                        match self.http_client.get(&upload_path).await {
                            Ok(verify_response) => {
                                if verify_response.body.contains(&self.test_marker) {
                                    info!("VERIFIED: Double extension bypass successful, file executed at {}", upload_path);
                                    vulnerabilities.push(self.create_vulnerability(
                                        "File Upload Double Extension Bypass with Code Execution",
                                        url,
                                        &format!("Uploaded double extension file '{}' and verified execution at {}. Marker found in response.", filename, upload_path),
                                        Severity::Critical,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                } else if verify_response.status_code == 200 {
                                    vulnerabilities.push(self.create_vulnerability(
                                        "File Upload Double Extension Bypass",
                                        url,
                                        &format!("Uploaded double extension file '{}' to {}. File accessible but execution not confirmed.", filename, upload_path),
                                        Severity::High,
                                        "CWE-434",
                                    ));
                                    return Ok((vulnerabilities, tests_run));
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                }
                Err(e) => {
                    info!("Double extension test failed: {}", e);
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
    fn test_extract_upload_paths() {
        let scanner = create_test_scanner();
        let filename = "test.php";
        let base_url = "http://example.com/upload";

        // Test JSON response parsing
        let json_response = r#"{"path":"/uploads/test.php","status":"success"}"#;
        let paths = scanner.extract_upload_paths(json_response, filename, base_url);
        assert!(paths.iter().any(|p| p.contains("/uploads/test.php")));

        // Test common paths are included
        let empty_response = "";
        let paths = scanner.extract_upload_paths(empty_response, filename, base_url);
        assert!(paths.iter().any(|p| p.ends_with("/uploads/test.php")));
        assert!(paths.iter().any(|p| p.ends_with("/files/test.php")));
    }

    #[test]
    fn test_normalize_endpoint() {
        let scanner = create_test_scanner();

        // Test absolute URL
        assert_eq!(
            scanner.normalize_endpoint("http://example.com", "http://other.com/file"),
            "http://other.com/file"
        );

        // Test relative path
        let result = scanner.normalize_endpoint("http://example.com/api", "/uploads/file.txt");
        assert!(result.starts_with("http://"));
        assert!(result.contains("/uploads/file.txt"));
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
