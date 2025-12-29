// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info};

/// Compliance framework types supported by this scanner
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceFramework {
    Soc2,
    PciDss,
    Hipaa,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::Soc2 => write!(f, "SOC2"),
            ComplianceFramework::PciDss => write!(f, "PCI-DSS"),
            ComplianceFramework::Hipaa => write!(f, "HIPAA"),
        }
    }
}

/// Compliance issue with framework mapping
#[derive(Debug, Clone)]
struct ComplianceIssue {
    frameworks: Vec<ComplianceFramework>,
    requirement_id: String,
    title: String,
    description: String,
    severity: Severity,
    remediation: String,
    cwe: String,
    cvss: f32,
}

pub struct ComplianceScanner {
    http_client: Arc<HttpClient>,
}

impl ComplianceScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan target for compliance violations across SOC2, PCI-DSS, and HIPAA
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[Compliance] Starting SOC2/PCI-DSS/HIPAA compliance scan for: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Encryption in transit (TLS, HSTS)
        tests_run += 1;
        let tls_vulns = self.check_encryption_in_transit(url).await;
        vulnerabilities.extend(tls_vulns);

        // Test 2: Security headers for data protection
        tests_run += 1;
        let header_vulns = self.check_data_protection_headers(url).await;
        vulnerabilities.extend(header_vulns);

        // Test 3: Cookie security flags
        tests_run += 1;
        let cookie_vulns = self.check_cookie_security(url).await;
        vulnerabilities.extend(cookie_vulns);

        // Test 4: Error handling and information disclosure
        tests_run += 1;
        let error_vulns = self.check_error_handling(url).await;
        vulnerabilities.extend(error_vulns);

        // Test 5: API authentication indicators
        tests_run += 1;
        let api_auth_vulns = self.check_api_authentication(url).await;
        vulnerabilities.extend(api_auth_vulns);

        // Test 6: Audit logging indicators
        tests_run += 1;
        let audit_vulns = self.check_audit_logging(url).await;
        vulnerabilities.extend(audit_vulns);

        // Test 7: Session management security
        tests_run += 1;
        let session_vulns = self.check_session_management(url).await;
        vulnerabilities.extend(session_vulns);

        // Test 8: Access control headers
        tests_run += 1;
        let access_vulns = self.check_access_control_headers(url).await;
        vulnerabilities.extend(access_vulns);

        // Test 9: Sensitive endpoint exposure
        tests_run += 1;
        let endpoint_vulns = self.check_sensitive_endpoints(url).await;
        vulnerabilities.extend(endpoint_vulns);

        // Test 10: PCI-DSS specific checks
        tests_run += 1;
        let pci_vulns = self.check_pci_specific(url).await;
        vulnerabilities.extend(pci_vulns);

        info!(
            "[Compliance] Scan complete: {} compliance issues found in {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Check encryption in transit requirements (TLS 1.2+, HSTS)
    async fn check_encryption_in_transit(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Check if HTTPS is being used
        if !url.starts_with("https://") {
            vulnerabilities.push(self.create_compliance_vulnerability(
                ComplianceIssue {
                    frameworks: vec![
                        ComplianceFramework::Soc2,
                        ComplianceFramework::PciDss,
                        ComplianceFramework::Hipaa,
                    ],
                    requirement_id: "CC6.1/PCI-4.1/HIPAA-164.312(e)(1)".to_string(),
                    title: "Missing HTTPS - Encryption in Transit Not Enforced".to_string(),
                    description: "The application is accessible over unencrypted HTTP. \
                        All data transmitted between the client and server can be intercepted. \
                        This violates encryption requirements for SOC2 (CC6.1), PCI-DSS (Requirement 4.1), \
                        and HIPAA (164.312(e)(1)).".to_string(),
                    severity: Severity::Critical,
                    remediation: "1. Obtain and install a valid TLS certificate\n\
                        2. Configure the server to use TLS 1.2 or higher\n\
                        3. Redirect all HTTP traffic to HTTPS\n\
                        4. Implement HSTS to prevent protocol downgrade attacks".to_string(),
                    cwe: "CWE-319".to_string(),
                    cvss: 9.1,
                },
                url,
            ));
        }

        // Check HSTS header
        if let Ok(response) = self.http_client.get(url).await {
            let hsts = response.header("strict-transport-security");

            if url.starts_with("https://") && hsts.is_none() {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![
                            ComplianceFramework::Soc2,
                            ComplianceFramework::PciDss,
                        ],
                        requirement_id: "CC6.1/PCI-4.1".to_string(),
                        title: "Missing HSTS Header - TLS Not Strictly Enforced".to_string(),
                        description: "HTTP Strict Transport Security (HSTS) header is missing. \
                            Without HSTS, browsers may allow protocol downgrade attacks where \
                            attackers can intercept initial HTTP requests before HTTPS redirect. \
                            This weakens encryption controls required by SOC2 and PCI-DSS.".to_string(),
                        severity: Severity::Medium,
                        remediation: "Add the HSTS header with appropriate max-age:\n\
                            Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n\
                            Consider HSTS preload submission for maximum protection.".to_string(),
                        cwe: "CWE-319".to_string(),
                        cvss: 5.9,
                    },
                    url,
                ));
            } else if let Some(hsts_value) = hsts {
                // Check for weak HSTS configuration
                let max_age_re = Regex::new(r"max-age=(\d+)").ok();
                if let Some(re) = max_age_re {
                    if let Some(cap) = re.captures(&hsts_value) {
                        if let Some(age_str) = cap.get(1) {
                            if let Ok(age) = age_str.as_str().parse::<u64>() {
                                // Less than 6 months is considered weak
                                if age < 15768000 {
                                    vulnerabilities.push(self.create_compliance_vulnerability(
                                        ComplianceIssue {
                                            frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                                            requirement_id: "CC6.1/PCI-4.1".to_string(),
                                            title: "Weak HSTS Configuration - Short max-age".to_string(),
                                            description: format!(
                                                "HSTS max-age is set to {} seconds ({}), which is less than \
                                                the recommended minimum of 6 months (15768000 seconds). \
                                                Short HSTS periods leave users vulnerable during gaps between visits.",
                                                age,
                                                Self::format_duration(age)
                                            ),
                                            severity: Severity::Low,
                                            remediation: "Increase HSTS max-age to at least 1 year (31536000 seconds):\n\
                                                Strict-Transport-Security: max-age=31536000; includeSubDomains".to_string(),
                                            cwe: "CWE-319".to_string(),
                                            cvss: 3.7,
                                        },
                                        url,
                                    ));
                                }
                            }
                        }
                    }
                }

                // Check for missing includeSubDomains
                if !hsts_value.to_lowercase().contains("includesubdomains") {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2],
                            requirement_id: "CC6.1".to_string(),
                            title: "HSTS Missing includeSubDomains Directive".to_string(),
                            description: "HSTS is configured but does not include the includeSubDomains \
                                directive. Subdomains can be accessed over HTTP, potentially exposing \
                                session cookies or other sensitive data.".to_string(),
                            severity: Severity::Low,
                            remediation: "Add includeSubDomains to HSTS header:\n\
                                Strict-Transport-Security: max-age=31536000; includeSubDomains".to_string(),
                            cwe: "CWE-319".to_string(),
                            cvss: 3.1,
                        },
                        url,
                    ));
                }
            }

            // Check for TLS version indicators in response
            if let Some(via) = response.header("via") {
                if via.contains("1.0") || via.contains("1.1") {
                    let via_lower = via.to_lowercase();
                    if via_lower.contains("tls/1.0") || via_lower.contains("ssl") {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::PciDss, ComplianceFramework::Hipaa],
                                requirement_id: "PCI-4.1/HIPAA-164.312(e)(1)".to_string(),
                                title: "Deprecated TLS/SSL Version Detected".to_string(),
                                description: "Response headers indicate use of deprecated TLS 1.0/1.1 or SSL. \
                                    PCI-DSS requires TLS 1.2 or higher. HIPAA requires current encryption standards.".to_string(),
                                severity: Severity::High,
                                remediation: "1. Disable TLS 1.0, TLS 1.1, and all SSL versions\n\
                                    2. Configure server to only accept TLS 1.2 and TLS 1.3\n\
                                    3. Update cipher suites to use strong algorithms".to_string(),
                                cwe: "CWE-326".to_string(),
                                cvss: 7.4,
                            },
                            url,
                        ));
                    }
                }
            }
        }

        // Test HTTP to HTTPS redirect
        let http_url = base_url.replace("https://", "http://");
        if url.starts_with("https://") {
            if let Ok(http_response) = self.http_client.get(&http_url).await {
                if http_response.status_code == 200 {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                            requirement_id: "CC6.1/PCI-4.1".to_string(),
                            title: "HTTP Not Redirecting to HTTPS".to_string(),
                            description: "The application responds to HTTP requests without redirecting \
                                to HTTPS. Users accessing the site via HTTP will transmit data unencrypted.".to_string(),
                            severity: Severity::Medium,
                            remediation: "Configure HTTP to HTTPS redirect on the web server:\n\
                                - Apache: Use RewriteRule or Redirect directive\n\
                                - Nginx: Use return 301 https://$host$request_uri;\n\
                                - CDN: Configure HTTPS redirect at edge".to_string(),
                            cwe: "CWE-319".to_string(),
                            cvss: 5.3,
                        },
                        &http_url,
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check data protection headers (CSP, X-Content-Type-Options, etc.)
    async fn check_data_protection_headers(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            // Check Content-Security-Policy
            let csp = response.header("content-security-policy");
            if csp.is_none() {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                        requirement_id: "CC6.1/PCI-6.5.7".to_string(),
                        title: "Missing Content Security Policy".to_string(),
                        description: "Content Security Policy (CSP) header is not implemented. \
                            CSP provides defense-in-depth against XSS and data injection attacks. \
                            PCI-DSS 6.5.7 requires protection against XSS vulnerabilities.".to_string(),
                        severity: Severity::Medium,
                        remediation: "Implement a strict Content Security Policy:\n\
                            Content-Security-Policy: default-src 'self'; script-src 'self'; \
                            style-src 'self'; img-src 'self' data:; font-src 'self'; \
                            frame-ancestors 'none'; form-action 'self';\n\n\
                            Start with a report-only policy to identify issues before enforcing.".to_string(),
                        cwe: "CWE-1021".to_string(),
                        cvss: 5.3,
                    },
                    url,
                ));
            } else if let Some(ref csp_value) = csp {
                // Check for unsafe CSP directives
                if csp_value.contains("unsafe-inline") && csp_value.contains("unsafe-eval") {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                            requirement_id: "CC6.1/PCI-6.5.7".to_string(),
                            title: "Weak Content Security Policy - Unsafe Directives".to_string(),
                            description: "CSP allows both 'unsafe-inline' and 'unsafe-eval' which \
                                significantly weakens XSS protection. This undermines the security \
                                control intended by CSP.".to_string(),
                            severity: Severity::Medium,
                            remediation: "1. Remove 'unsafe-inline' by using nonces or hashes for inline scripts\n\
                                2. Remove 'unsafe-eval' by refactoring code that uses eval()\n\
                                3. Use strict-dynamic if dynamic script loading is required".to_string(),
                            cwe: "CWE-1021".to_string(),
                            cvss: 4.7,
                        },
                        url,
                    ));
                }
            }

            // Check X-Content-Type-Options
            if response.header("x-content-type-options").is_none() {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::Soc2],
                        requirement_id: "CC6.1".to_string(),
                        title: "Missing X-Content-Type-Options Header".to_string(),
                        description: "X-Content-Type-Options header is not set. Without this header, \
                            browsers may MIME-sniff responses, potentially executing content as scripts.".to_string(),
                        severity: Severity::Low,
                        remediation: "Add the header to all responses:\n\
                            X-Content-Type-Options: nosniff".to_string(),
                        cwe: "CWE-693".to_string(),
                        cvss: 3.7,
                    },
                    url,
                ));
            }

            // Check X-Frame-Options or frame-ancestors
            let xfo = response.header("x-frame-options");
            let has_frame_ancestors = csp
                .map(|c| c.to_lowercase().contains("frame-ancestors"))
                .unwrap_or(false);

            if xfo.is_none() && !has_frame_ancestors {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                        requirement_id: "CC6.1/PCI-6.5.9".to_string(),
                        title: "Missing Clickjacking Protection".to_string(),
                        description: "Neither X-Frame-Options nor CSP frame-ancestors is set. \
                            The application can be embedded in frames on malicious sites, enabling \
                            clickjacking attacks that trick users into unintended actions.".to_string(),
                        severity: Severity::Medium,
                        remediation: "Add frame protection header:\n\
                            X-Frame-Options: DENY\n\
                            Or use CSP:\n\
                            Content-Security-Policy: frame-ancestors 'none';".to_string(),
                        cwe: "CWE-1021".to_string(),
                        cvss: 4.7,
                    },
                    url,
                ));
            }

            // Check Referrer-Policy for data leakage
            if response.header("referrer-policy").is_none() {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::Hipaa],
                        requirement_id: "CC6.1/HIPAA-164.312(e)(1)".to_string(),
                        title: "Missing Referrer-Policy Header".to_string(),
                        description: "Referrer-Policy header is not set. URLs containing sensitive \
                            data (tokens, IDs) may be leaked to third-party sites through the Referer header.".to_string(),
                        severity: Severity::Low,
                        remediation: "Add Referrer-Policy header:\n\
                            Referrer-Policy: strict-origin-when-cross-origin\n\
                            Or for maximum privacy:\n\
                            Referrer-Policy: no-referrer".to_string(),
                        cwe: "CWE-200".to_string(),
                        cvss: 3.1,
                    },
                    url,
                ));
            }

            // Check Cache-Control for sensitive pages
            let cache_control = response.header("cache-control");
            let _pragma = response.header("pragma");
            let has_forms = response.body.contains("<form") || response.body.contains("<input");
            let is_sensitive = response.body.to_lowercase().contains("password")
                || response.body.to_lowercase().contains("credit")
                || response.body.to_lowercase().contains("ssn")
                || response.body.to_lowercase().contains("social security");

            if (has_forms || is_sensitive) && cache_control.is_none() {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::PciDss, ComplianceFramework::Hipaa],
                        requirement_id: "PCI-3.2/HIPAA-164.312(e)(1)".to_string(),
                        title: "Sensitive Page Missing Cache Control".to_string(),
                        description: "Page containing forms or sensitive content does not set \
                            Cache-Control headers. Sensitive data may be cached by browsers or \
                            intermediate proxies, violating data protection requirements.".to_string(),
                        severity: Severity::Medium,
                        remediation: "Add cache prevention headers for sensitive pages:\n\
                            Cache-Control: no-store, no-cache, must-revalidate, private\n\
                            Pragma: no-cache\n\
                            Expires: 0".to_string(),
                        cwe: "CWE-525".to_string(),
                        cvss: 4.3,
                    },
                    url,
                ));
            }
        }

        vulnerabilities
    }

    /// Check cookie security flags
    async fn check_cookie_security(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            // Get all Set-Cookie headers
            let cookies: Vec<&str> = response.headers
                .iter()
                .filter(|(k, _)| k.to_lowercase() == "set-cookie")
                .map(|(_, v)| v.as_str())
                .collect();

            // Also check the cookies field if available
            for cookie in &cookies {
                let cookie_lower = cookie.to_lowercase();
                let cookie_name = cookie.split('=').next().unwrap_or("unknown");

                // Check for session-like cookies
                let is_session_cookie = cookie_lower.contains("session")
                    || cookie_lower.contains("sid")
                    || cookie_lower.contains("token")
                    || cookie_lower.contains("auth")
                    || cookie_lower.contains("jwt")
                    || cookie_lower.contains("csrf");

                // Check Secure flag
                if !cookie_lower.contains("secure") && url.starts_with("https://") {
                    let severity = if is_session_cookie {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![
                                ComplianceFramework::Soc2,
                                ComplianceFramework::PciDss,
                                ComplianceFramework::Hipaa,
                            ],
                            requirement_id: "CC6.1/PCI-4.1/HIPAA-164.312(e)(1)".to_string(),
                            title: format!("Cookie Missing Secure Flag: {}", cookie_name),
                            description: format!(
                                "Cookie '{}' does not have the Secure flag set. \
                                This cookie can be transmitted over unencrypted HTTP connections, \
                                exposing it to interception. {}",
                                cookie_name,
                                if is_session_cookie {
                                    "This appears to be a session/authentication cookie, making this a high-severity issue."
                                } else {
                                    ""
                                }
                            ),
                            severity,
                            remediation: "Set the Secure flag on all cookies:\n\
                                Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict".to_string(),
                            cwe: "CWE-614".to_string(),
                            cvss: if is_session_cookie { 7.4 } else { 4.3 },
                        },
                        url,
                    ));
                }

                // Check HttpOnly flag
                if is_session_cookie && !cookie_lower.contains("httponly") {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                            requirement_id: "CC6.1/PCI-6.5.7".to_string(),
                            title: format!("Session Cookie Missing HttpOnly Flag: {}", cookie_name),
                            description: format!(
                                "Session cookie '{}' does not have the HttpOnly flag set. \
                                JavaScript can access this cookie, making it vulnerable to theft via XSS attacks.",
                                cookie_name
                            ),
                            severity: Severity::Medium,
                            remediation: "Set the HttpOnly flag on session cookies:\n\
                                Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict".to_string(),
                            cwe: "CWE-1004".to_string(),
                            cvss: 5.3,
                        },
                        url,
                    ));
                }

                // Check SameSite attribute
                if is_session_cookie && !cookie_lower.contains("samesite") {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2],
                            requirement_id: "CC6.1".to_string(),
                            title: format!("Session Cookie Missing SameSite Attribute: {}", cookie_name),
                            description: format!(
                                "Session cookie '{}' does not have the SameSite attribute set. \
                                This cookie may be sent with cross-site requests, potentially enabling CSRF attacks.",
                                cookie_name
                            ),
                            severity: Severity::Low,
                            remediation: "Set SameSite attribute on cookies:\n\
                                Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict\n\
                                Use 'Lax' if cross-site GET requests are needed.".to_string(),
                            cwe: "CWE-1275".to_string(),
                            cvss: 3.7,
                        },
                        url,
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check error handling for information disclosure
    async fn check_error_handling(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Test various error-inducing requests
        let error_paths = vec![
            (format!("{}/'\"<>test", base_url), "special characters"),
            (format!("{}/nonexistent-{}", base_url, Self::generate_id()), "404 error"),
            (format!("{}/.git/config", base_url), "sensitive path"),
            (format!("{}/?id=1'", base_url), "SQL syntax"),
            (format!("{}/{{{{7*7}}}}", base_url), "template syntax"),
        ];

        for (test_url, test_type) in error_paths {
            if let Ok(response) = self.http_client.get(&test_url).await {
                let body_lower = response.body.to_lowercase();

                // Check for stack traces
                let has_stack_trace = body_lower.contains("stack trace")
                    || body_lower.contains("traceback")
                    || body_lower.contains("exception in")
                    || body_lower.contains("at line")
                    || response.body.contains(".java:")
                    || response.body.contains(".py:")
                    || response.body.contains(".rb:")
                    || response.body.contains(".php:")
                    || response.body.contains(".cs:")
                    || response.body.contains("at Object.")
                    || response.body.contains("at Module.")
                    || response.body.contains("at Function.");

                if has_stack_trace {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![
                                ComplianceFramework::Soc2,
                                ComplianceFramework::PciDss,
                                ComplianceFramework::Hipaa,
                            ],
                            requirement_id: "CC6.1/PCI-6.5.5/HIPAA-164.312(e)(1)".to_string(),
                            title: "Stack Trace Exposed in Error Response".to_string(),
                            description: format!(
                                "Application exposes stack traces in error responses (triggered by {}). \
                                Stack traces reveal internal implementation details including file paths, \
                                library versions, and code structure that attackers can use to plan attacks.",
                                test_type
                            ),
                            severity: Severity::Medium,
                            remediation: "1. Configure custom error pages for all error codes\n\
                                2. Disable debug mode in production\n\
                                3. Log detailed errors server-side only\n\
                                4. Return generic error messages to clients".to_string(),
                            cwe: "CWE-209".to_string(),
                            cvss: 5.3,
                        },
                        &test_url,
                    ));
                    break; // One finding is enough
                }

                // Check for detailed error messages
                let has_detailed_error = body_lower.contains("sql syntax")
                    || body_lower.contains("mysql error")
                    || body_lower.contains("postgresql error")
                    || body_lower.contains("oracle error")
                    || body_lower.contains("database error")
                    || body_lower.contains("syntax error")
                    || body_lower.contains("undefined variable")
                    || body_lower.contains("undefined index")
                    || body_lower.contains("null pointer")
                    || body_lower.contains("nullreferenceexception");

                if has_detailed_error {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                            requirement_id: "CC6.1/PCI-6.5.5".to_string(),
                            title: "Detailed Error Messages Exposed".to_string(),
                            description: "Application returns detailed technical error messages. \
                                These messages reveal internal system information that could help attackers.".to_string(),
                            severity: Severity::Low,
                            remediation: "1. Implement custom error handling\n\
                                2. Return user-friendly error messages\n\
                                3. Log detailed errors securely server-side".to_string(),
                            cwe: "CWE-209".to_string(),
                            cvss: 3.7,
                        },
                        &test_url,
                    ));
                    break;
                }

                // Check for server version disclosure
                if let Some(server) = response.header("server") {
                    let version_re = Regex::new(r"[\d]+\.[\d]+").ok();
                    if version_re.map(|re| re.is_match(&server)).unwrap_or(false) {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::Soc2],
                                requirement_id: "CC6.1".to_string(),
                                title: "Server Version Disclosed".to_string(),
                                description: format!(
                                    "Server header reveals version information: '{}'. \
                                    Version disclosure helps attackers identify vulnerable software versions.",
                                    server
                                ),
                                severity: Severity::Info,
                                remediation: "Configure the web server to hide version information:\n\
                                    - Apache: ServerTokens Prod\n\
                                    - Nginx: server_tokens off;\n\
                                    - IIS: Remove X-Powered-By and version from Server header".to_string(),
                                cwe: "CWE-200".to_string(),
                                cvss: 0.0,
                            },
                            &test_url,
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check API authentication requirements
    async fn check_api_authentication(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Common API endpoints to test
        let api_endpoints = vec![
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/users",
            "/api/user",
            "/api/account",
            "/api/data",
            "/graphql",
            "/rest",
            "/v1",
            "/v2",
        ];

        for endpoint in api_endpoints {
            let test_url = format!("{}{}", base_url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check if API endpoint returns data without authentication
                if response.status_code == 200 {
                    let content_type = response.header("content-type").unwrap_or_default();
                    let is_json = content_type.contains("json") || response.body.trim().starts_with('{')
                        || response.body.trim().starts_with('[');

                    if is_json && response.body.len() > 50 {
                        // Check for sensitive data patterns in response
                        let body_lower = response.body.to_lowercase();
                        let has_user_data = body_lower.contains("\"email\"")
                            || body_lower.contains("\"username\"")
                            || body_lower.contains("\"user\"")
                            || body_lower.contains("\"name\"")
                            || body_lower.contains("\"id\"");

                        if has_user_data {
                            vulnerabilities.push(self.create_compliance_vulnerability(
                                ComplianceIssue {
                                    frameworks: vec![
                                        ComplianceFramework::Soc2,
                                        ComplianceFramework::PciDss,
                                        ComplianceFramework::Hipaa,
                                    ],
                                    requirement_id: "CC6.1/PCI-7.1/HIPAA-164.312(d)".to_string(),
                                    title: "API Endpoint Accessible Without Authentication".to_string(),
                                    description: format!(
                                        "API endpoint {} returns data without requiring authentication. \
                                        The response appears to contain user-related data. \
                                        All API endpoints handling sensitive data must require authentication.",
                                        endpoint
                                    ),
                                    severity: Severity::High,
                                    remediation: "1. Implement authentication for all API endpoints\n\
                                        2. Use API keys, OAuth 2.0, or JWT tokens\n\
                                        3. Apply principle of least privilege\n\
                                        4. Implement proper authorization checks".to_string(),
                                    cwe: "CWE-306".to_string(),
                                    cvss: 7.5,
                                },
                                &test_url,
                            ));
                            break; // One finding is enough
                        }
                    }
                }

                // Check for missing authentication headers indicators
                let has_auth_header = response.header("www-authenticate").is_some();
                if response.status_code == 200 && !has_auth_header {
                    // Check if this looks like an API that should require auth
                    if response.body.contains("\"data\"") || response.body.contains("\"results\"") {
                        debug!("API endpoint {} may lack proper authentication", endpoint);
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for audit logging indicators
    async fn check_audit_logging(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Check for exposed logging endpoints (which indicates logging exists but may be misconfigured)
        let log_endpoints = vec![
            "/logs",
            "/log",
            "/audit",
            "/audit-log",
            "/api/logs",
            "/admin/logs",
            "/debug/logs",
            "/actuator/logfile",
            "/actuator/auditevents",
            "/.log",
            "/error.log",
            "/access.log",
        ];

        for endpoint in log_endpoints {
            let test_url = format!("{}{}", base_url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    // Check if actual log content is exposed
                    let is_log_content = body_lower.contains("[error]")
                        || body_lower.contains("[info]")
                        || body_lower.contains("[warn]")
                        || body_lower.contains("[debug]")
                        || body_lower.contains("timestamp")
                        || response.body.contains(" - - [")
                        || body_lower.contains("exception")
                        || body_lower.contains("stacktrace");

                    if is_log_content {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![
                                    ComplianceFramework::Soc2,
                                    ComplianceFramework::PciDss,
                                    ComplianceFramework::Hipaa,
                                ],
                                requirement_id: "CC7.2/PCI-10.5/HIPAA-164.312(b)".to_string(),
                                title: "Audit Logs Publicly Accessible".to_string(),
                                description: format!(
                                    "Audit log endpoint {} is publicly accessible. \
                                    Logs may contain sensitive information including user actions, \
                                    IP addresses, and system events. \
                                    SOC2, PCI-DSS, and HIPAA require audit logs to be protected from unauthorized access.",
                                    endpoint
                                ),
                                severity: Severity::High,
                                remediation: "1. Restrict access to log endpoints to authorized personnel only\n\
                                    2. Implement authentication for log access\n\
                                    3. Store logs in a secure, centralized logging system\n\
                                    4. Never expose logs through web-accessible endpoints".to_string(),
                                cwe: "CWE-532".to_string(),
                                cvss: 7.5,
                            },
                            &test_url,
                        ));
                        break;
                    }
                }
            }
        }

        // Check for missing audit-related headers (X-Request-ID for traceability)
        if let Ok(response) = self.http_client.get(url).await {
            let has_request_id = response.header("x-request-id").is_some()
                || response.header("x-correlation-id").is_some()
                || response.header("x-trace-id").is_some();

            if !has_request_id {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::Soc2],
                        requirement_id: "CC7.2".to_string(),
                        title: "Missing Request Tracing Headers".to_string(),
                        description: "Application does not return request tracing headers \
                            (X-Request-ID, X-Correlation-ID, or X-Trace-ID). \
                            These headers are important for audit trail correlation and incident investigation.".to_string(),
                        severity: Severity::Info,
                        remediation: "Implement request tracing:\n\
                            1. Generate unique request IDs for each request\n\
                            2. Return the ID in response headers: X-Request-ID\n\
                            3. Include the ID in all related log entries\n\
                            4. Propagate IDs across service calls".to_string(),
                        cwe: "CWE-778".to_string(),
                        cvss: 0.0,
                    },
                    url,
                ));
            }
        }

        vulnerabilities
    }

    /// Check session management security
    async fn check_session_management(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            // Check for session ID in URL
            let url_lower = url.to_lowercase();
            if url_lower.contains("sessionid=")
                || url_lower.contains("jsessionid=")
                || url_lower.contains("phpsessid=")
                || url_lower.contains("sid=")
                || url_lower.contains("session_id=")
            {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![
                            ComplianceFramework::Soc2,
                            ComplianceFramework::PciDss,
                            ComplianceFramework::Hipaa,
                        ],
                        requirement_id: "CC6.1/PCI-6.5.10/HIPAA-164.312(d)".to_string(),
                        title: "Session ID Exposed in URL".to_string(),
                        description: "Session identifier is passed in the URL query string. \
                            This exposes the session ID in browser history, server logs, referrer headers, \
                            and potentially to other users sharing links.".to_string(),
                        severity: Severity::High,
                        remediation: "1. Never pass session IDs in URLs\n\
                            2. Use cookies with Secure, HttpOnly, and SameSite flags\n\
                            3. Implement proper session management using server-side sessions\n\
                            4. Use POST requests for session-related operations".to_string(),
                        cwe: "CWE-598".to_string(),
                        cvss: 7.5,
                    },
                    url,
                ));
            }

            // Check response body for session IDs
            let body = &response.body;
            if body.contains("sessionid") || body.contains("jsessionid") {
                let session_in_js_re = Regex::new(r#"session[_-]?id\s*[=:]\s*["'][^"']+["']"#).ok();
                if let Some(re) = session_in_js_re {
                    if re.is_match(&body.to_lowercase()) {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                                requirement_id: "CC6.1/PCI-6.5.10".to_string(),
                                title: "Session ID Exposed in Page Content".to_string(),
                                description: "Session identifier appears to be embedded in page content or JavaScript. \
                                    This may expose the session ID to XSS attacks or unauthorized access.".to_string(),
                                severity: Severity::Medium,
                                remediation: "1. Do not embed session IDs in page content\n\
                                    2. Use HttpOnly cookies for session management\n\
                                    3. Implement proper CSRF protection".to_string(),
                                cwe: "CWE-200".to_string(),
                                cvss: 5.3,
                            },
                            url,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check access control headers
    async fn check_access_control_headers(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            // Check CORS configuration
            let acao = response.header("access-control-allow-origin");
            let acac = response.header("access-control-allow-credentials");

            if let Some(origin) = acao {
                if origin == "*" {
                    if acac.map(|v| v == "true").unwrap_or(false) {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::PciDss],
                                requirement_id: "CC6.1/PCI-6.5.8".to_string(),
                                title: "Dangerous CORS Configuration".to_string(),
                                description: "CORS is configured with Access-Control-Allow-Origin: * \
                                    AND Access-Control-Allow-Credentials: true. This is an invalid \
                                    and dangerous configuration that may expose authenticated data.".to_string(),
                                severity: Severity::High,
                                remediation: "1. Never use wildcard (*) with credentials\n\
                                    2. Specify allowed origins explicitly\n\
                                    3. Validate Origin header against allowlist".to_string(),
                                cwe: "CWE-346".to_string(),
                                cvss: 7.5,
                            },
                            url,
                        ));
                    } else {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::Soc2],
                                requirement_id: "CC6.1".to_string(),
                                title: "Permissive CORS Configuration".to_string(),
                                description: "CORS allows requests from any origin (Access-Control-Allow-Origin: *). \
                                    While not directly exploitable without credentials, this may indicate \
                                    overly permissive access controls.".to_string(),
                                severity: Severity::Low,
                                remediation: "Restrict CORS to specific trusted origins:\n\
                                    Access-Control-Allow-Origin: https://trusted-domain.com".to_string(),
                                cwe: "CWE-346".to_string(),
                                cvss: 3.7,
                            },
                            url,
                        ));
                    }
                }
            }

            // Check for missing authorization indicators on sensitive-looking pages
            let body_lower = response.body.to_lowercase();
            let is_admin_page = url.contains("/admin")
                || url.contains("/dashboard")
                || url.contains("/manage")
                || body_lower.contains("administration")
                || body_lower.contains("admin panel");

            if is_admin_page && response.status_code == 200 {
                // Check if there are auth-related elements
                let has_login_form = body_lower.contains("login") || body_lower.contains("sign in");
                if !has_login_form {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![
                                ComplianceFramework::Soc2,
                                ComplianceFramework::PciDss,
                                ComplianceFramework::Hipaa,
                            ],
                            requirement_id: "CC6.1/PCI-7.1/HIPAA-164.312(d)".to_string(),
                            title: "Administrative Page Potentially Accessible Without Authentication".to_string(),
                            description: "An administrative or management page is accessible and does not \
                                appear to require authentication. Administrative functions must be protected \
                                with strong access controls.".to_string(),
                            severity: Severity::High,
                            remediation: "1. Implement strong authentication for all admin pages\n\
                                2. Use multi-factor authentication for administrative access\n\
                                3. Restrict admin access to specific IP ranges if possible\n\
                                4. Implement proper authorization checks".to_string(),
                            cwe: "CWE-306".to_string(),
                            cvss: 8.1,
                        },
                        url,
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for sensitive endpoint exposure
    async fn check_sensitive_endpoints(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let base_url = self.get_base_url(url);

        // Health check endpoints that may expose sensitive info
        let sensitive_endpoints = vec![
            ("/health", "Health check endpoint"),
            ("/healthz", "Kubernetes health endpoint"),
            ("/ready", "Readiness probe"),
            ("/status", "Status endpoint"),
            ("/metrics", "Metrics endpoint"),
            ("/env", "Environment variables"),
            ("/config", "Configuration"),
            ("/info", "Application info"),
            ("/debug", "Debug endpoint"),
            ("/.env", "Environment file"),
            ("/phpinfo.php", "PHP info"),
            ("/server-status", "Apache status"),
            ("/nginx_status", "Nginx status"),
        ];

        for (endpoint, description) in sensitive_endpoints {
            let test_url = format!("{}{}", base_url, endpoint);
            if let Ok(response) = self.http_client.get(&test_url).await {
                if response.status_code == 200 {
                    let body_lower = response.body.to_lowercase();

                    // Check for sensitive data patterns
                    let has_sensitive_data = body_lower.contains("password")
                        || body_lower.contains("secret")
                        || body_lower.contains("api_key")
                        || body_lower.contains("apikey")
                        || body_lower.contains("database")
                        || body_lower.contains("connection_string")
                        || body_lower.contains("aws_")
                        || body_lower.contains("azure_")
                        || body_lower.contains("gcp_")
                        || body_lower.contains("private_key");

                    if has_sensitive_data {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![
                                    ComplianceFramework::Soc2,
                                    ComplianceFramework::PciDss,
                                    ComplianceFramework::Hipaa,
                                ],
                                requirement_id: "CC6.1/PCI-6.5.8/HIPAA-164.312(e)(1)".to_string(),
                                title: format!("Sensitive Data Exposed via {}", description),
                                description: format!(
                                    "Endpoint {} ({}) exposes sensitive configuration data including \
                                    potential credentials or secrets. This violates data protection requirements.",
                                    endpoint, description
                                ),
                                severity: Severity::Critical,
                                remediation: "1. Disable or remove debug/info endpoints in production\n\
                                    2. Implement authentication for necessary operational endpoints\n\
                                    3. Never expose credentials or secrets through any endpoint\n\
                                    4. Use environment-specific configuration".to_string(),
                                cwe: "CWE-200".to_string(),
                                cvss: 9.1,
                            },
                            &test_url,
                        ));
                        continue;
                    }

                    // Check for version/environment disclosure
                    let has_env_info = body_lower.contains("version")
                        || body_lower.contains("environment")
                        || body_lower.contains("node_env")
                        || body_lower.contains("spring.profiles");

                    if has_env_info && (endpoint == "/health" || endpoint == "/info" || endpoint == "/status") {
                        vulnerabilities.push(self.create_compliance_vulnerability(
                            ComplianceIssue {
                                frameworks: vec![ComplianceFramework::Soc2],
                                requirement_id: "CC6.1".to_string(),
                                title: format!("{} Exposes Environment Information", description),
                                description: format!(
                                    "Endpoint {} reveals environment and version information. \
                                    While not directly exploitable, this information aids attackers in \
                                    targeting specific vulnerabilities.",
                                    endpoint
                                ),
                                severity: Severity::Low,
                                remediation: "1. Limit information exposed by health endpoints\n\
                                    2. Return only essential health status (UP/DOWN)\n\
                                    3. Implement authentication for detailed health info".to_string(),
                                cwe: "CWE-200".to_string(),
                                cvss: 3.1,
                            },
                            &test_url,
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// PCI-DSS specific checks
    async fn check_pci_specific(&self, url: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Ok(response) = self.http_client.get(url).await {
            let body_lower = response.body.to_lowercase();

            // Check for payment-related pages
            let is_payment_page = body_lower.contains("credit card")
                || body_lower.contains("card number")
                || body_lower.contains("cvv")
                || body_lower.contains("expiry")
                || body_lower.contains("payment")
                || body_lower.contains("checkout");

            if is_payment_page {
                // Check for autocomplete on payment fields
                if response.body.contains("autocomplete=\"on\"")
                    || (!response.body.contains("autocomplete=\"off\"")
                        && response.body.contains("<input")
                        && (response.body.contains("card") || response.body.contains("cvv")))
                {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::PciDss],
                            requirement_id: "PCI-3.2".to_string(),
                            title: "Payment Fields Missing Autocomplete Disable".to_string(),
                            description: "Payment form fields do not have autocomplete disabled. \
                                Browsers may cache sensitive card data, which violates PCI-DSS requirements \
                                for protecting stored cardholder data.".to_string(),
                            severity: Severity::Medium,
                            remediation: "Add autocomplete=\"off\" to payment form fields:\n\
                                <input type=\"text\" name=\"cardnumber\" autocomplete=\"off\">\n\
                                Or use autocomplete=\"cc-number\" for modern browsers.".to_string(),
                            cwe: "CWE-524".to_string(),
                            cvss: 4.3,
                        },
                        url,
                    ));
                }

                // Check for inline payment forms (should use iframes)
                if response.body.contains("<input")
                    && (response.body.contains("name=\"card") || response.body.contains("name=\"cvv"))
                    && !response.body.contains("<iframe")
                {
                    vulnerabilities.push(self.create_compliance_vulnerability(
                        ComplianceIssue {
                            frameworks: vec![ComplianceFramework::PciDss],
                            requirement_id: "PCI-3.4/PCI-6.5.3".to_string(),
                            title: "Direct Card Number Input Without PCI-Compliant Form".to_string(),
                            description: "The page appears to collect card numbers directly without using \
                                a PCI-compliant payment provider's iframe. Direct handling of card data \
                                increases PCI-DSS scope and compliance requirements significantly.".to_string(),
                            severity: Severity::High,
                            remediation: "1. Use a PCI-DSS compliant payment provider\n\
                                2. Implement payment forms using provider's hosted fields or iframes\n\
                                3. Never handle raw card numbers on your servers\n\
                                4. Consider tokenization for recurring payments".to_string(),
                            cwe: "CWE-311".to_string(),
                            cvss: 7.5,
                        },
                        url,
                    ));
                }
            }

            // Check for test/debug payment indicators
            if body_lower.contains("test card")
                || body_lower.contains("4242424242424242")
                || body_lower.contains("test mode")
                || body_lower.contains("sandbox")
            {
                vulnerabilities.push(self.create_compliance_vulnerability(
                    ComplianceIssue {
                        frameworks: vec![ComplianceFramework::PciDss],
                        requirement_id: "PCI-6.4.2".to_string(),
                        title: "Test/Sandbox Payment Configuration Exposed".to_string(),
                        description: "Page contains references to test card numbers, test mode, or sandbox \
                            configuration. Production systems should not expose test payment configurations.".to_string(),
                        severity: Severity::Low,
                        remediation: "1. Ensure production uses live payment credentials\n\
                            2. Remove test card numbers from production code\n\
                            3. Use environment variables for payment configuration\n\
                            4. Separate test and production environments".to_string(),
                        cwe: "CWE-489".to_string(),
                        cvss: 3.1,
                    },
                    url,
                ));
            }
        }

        vulnerabilities
    }

    /// Create a compliance vulnerability with proper formatting
    fn create_compliance_vulnerability(
        &self,
        issue: ComplianceIssue,
        url: &str,
    ) -> Vulnerability {
        let frameworks_str: Vec<String> = issue.frameworks.iter().map(|f| f.to_string()).collect();

        Vulnerability {
            id: format!("COMPLIANCE-{}", Self::generate_id()),
            vuln_type: format!("Compliance: {}", issue.title),
            severity: issue.severity,
            confidence: Confidence::High,
            category: "Compliance".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: issue.requirement_id.clone(),
            description: format!(
                "[Frameworks: {}]\n[Requirements: {}]\n\n{}",
                frameworks_str.join(", "),
                issue.requirement_id,
                issue.description
            ),
            evidence: Some(format!("Affects: {}", frameworks_str.join(", "))),
            cwe: issue.cwe,
            cvss: issue.cvss,
            verified: true,
            false_positive: false,
            remediation: issue.remediation,
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get base URL from full URL
    fn get_base_url(&self, url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let host = parsed.host_str().unwrap_or("localhost");
            let scheme = parsed.scheme();
            if let Some(port) = parsed.port() {
                format!("{}://{}:{}", scheme, host, port)
            } else {
                format!("{}://{}", scheme, host)
            }
        } else {
            url.to_string()
        }
    }

    /// Generate unique ID for vulnerability
    fn generate_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{:x}", timestamp)
    }

    /// Format duration for human readability
    fn format_duration(seconds: u64) -> String {
        if seconds < 60 {
            format!("{} seconds", seconds)
        } else if seconds < 3600 {
            format!("{} minutes", seconds / 60)
        } else if seconds < 86400 {
            format!("{} hours", seconds / 3600)
        } else if seconds < 2592000 {
            format!("{} days", seconds / 86400)
        } else if seconds < 31536000 {
            format!("{} months", seconds / 2592000)
        } else {
            format!("{} years", seconds / 31536000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_framework_display() {
        assert_eq!(format!("{}", ComplianceFramework::Soc2), "SOC2");
        assert_eq!(format!("{}", ComplianceFramework::PciDss), "PCI-DSS");
        assert_eq!(format!("{}", ComplianceFramework::Hipaa), "HIPAA");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(ComplianceScanner::format_duration(30), "30 seconds");
        assert_eq!(ComplianceScanner::format_duration(120), "2 minutes");
        assert_eq!(ComplianceScanner::format_duration(7200), "2 hours");
        assert_eq!(ComplianceScanner::format_duration(172800), "2 days");
        assert_eq!(ComplianceScanner::format_duration(5184000), "2 months");
        assert_eq!(ComplianceScanner::format_duration(63072000), "2 years");
    }

    #[test]
    fn test_generate_id() {
        let id1 = ComplianceScanner::generate_id();
        let id2 = ComplianceScanner::generate_id();
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
    }
}
