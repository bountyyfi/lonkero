// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Host Header Injection Scanner
 * Tests for Host header injection vulnerabilities
 *
 * Detects:
 * - Password reset poisoning
 * - Cache poisoning via Host header
 * - Web cache deception
 * - SSRF via Host header
 * - Virtual host confusion
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct HostHeaderInjectionScanner {
    http_client: Arc<HttpClient>,
    test_domain: String,
}

impl HostHeaderInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Use a unique test domain for detection
        let test_domain = format!("hhi-{}.attacker.test", Self::generate_id());
        Self {
            http_client,
            test_domain,
        }
    }

    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}", rng.random::<u32>())
    }

    /// Scan for host header injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check
        if !crate::license::verify_scan_authorized() {
            return Err(anyhow::anyhow!(
                "Scan not authorized. Please check your license."
            ));
        }

        info!("[HostHeader] Scanning for host header injection vulnerabilities");

        // Intelligent detection - skip for static sites
        if let Ok(response) = self.http_client.get(url).await {
            let characteristics = AppCharacteristics::from_response(&response, url);
            if characteristics.should_skip_injection_tests() {
                info!("[HostHeader] Skipping - static/SPA site detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test 1: Basic Host header injection
        let (vulns, tests) = self.test_host_header_reflection(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 2: Password reset poisoning
        let (vulns, tests) = self.test_password_reset_poisoning(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 3: X-Forwarded-Host injection
        let (vulns, tests) = self.test_forwarded_headers(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 4: Absolute URL override
        let (vulns, tests) = self.test_absolute_url(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 5: Port-based injection
        let (vulns, tests) = self.test_port_injection(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test 6: Duplicate Host header
        let (vulns, tests) = self.test_duplicate_host(url).await;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "[HostHeader] Completed {} tests, found {} vulnerabilities",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test basic Host header reflection
    async fn test_host_header_reflection(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing Host header reflection");

        // Get baseline response first
        let baseline = match self.http_client.get(url).await {
            Ok(r) => Some(r),
            Err(_) => None,
        };

        // Test Host header injection
        let host_payloads = vec![
            (self.test_domain.clone(), "direct_injection"),
            (
                format!("{}@{}", self.test_domain, self.extract_host(url)),
                "at_sign_bypass",
            ),
            (
                format!("{}.{}", self.test_domain, self.extract_host(url)),
                "subdomain_prefix",
            ),
        ];

        for (host_value, technique) in &host_payloads {
            tests_run += 1;

            let headers = vec![("Host".to_string(), host_value.clone())];

            debug!("Testing Host header with: {} ({})", host_value, technique);

            // We need to use a method that allows custom Host header
            // Most HTTP clients don't allow overriding Host, so we test via X-Forwarded-Host too
            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    // Check if our injected host appears in the response
                    if response.body.contains(&self.test_domain) {
                        info!("Host header injection detected via {}", technique);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("Host: {}", host_value),
                            technique,
                            "Host Header Reflection",
                            Confidence::High,
                            &format!(
                                "Injected host '{}' reflected in response body",
                                self.test_domain
                            ),
                            Severity::Medium,
                        ));
                    }

                    // Check response headers for reflection
                    for (header_name, header_value) in &response.headers {
                        if header_value.contains(&self.test_domain) {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                &format!("Host: {}", host_value),
                                technique,
                                "Host Header Reflection in Response Headers",
                                Confidence::High,
                                &format!("Injected host reflected in {} header", header_name),
                                Severity::Medium,
                            ));
                            break;
                        }
                    }

                    // Check for different response compared to baseline (potential routing change)
                    // Note: 400, 403, 421 responses indicate proper security - NOT a vulnerability
                    // 403 = WAF/Cloudflare blocking invalid Host (correct behavior)
                    // 400 = Bad Request (server rejecting invalid Host)
                    // 421 = Misdirected Request (proper HTTP/2 host validation)
                    if let Some(ref base) = baseline {
                        if response.status_code != base.status_code
                            && response.status_code != 400
                            && response.status_code != 403
                            && response.status_code != 421
                        {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                &format!("Host: {}", host_value),
                                technique,
                                "Host Header Causes Routing Change",
                                Confidence::Medium,
                                &format!(
                                    "Status changed from {} to {} with modified Host header",
                                    base.status_code, response.status_code
                                ),
                                Severity::Medium,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test password reset poisoning
    async fn test_password_reset_poisoning(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing password reset poisoning");

        // Common password reset endpoints
        let reset_endpoints = vec![
            "/password/reset",
            "/forgot-password",
            "/reset-password",
            "/api/auth/forgot-password",
            "/api/password/reset",
            "/users/password/new",
            "/account/recover",
        ];

        let base_url = url.trim_end_matches('/');

        for endpoint in &reset_endpoints {
            tests_run += 1;
            let reset_url = format!("{}{}", base_url, endpoint);

            // Test with X-Forwarded-Host (more commonly accepted)
            let headers = vec![
                ("X-Forwarded-Host".to_string(), self.test_domain.clone()),
                (
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
            ];

            // Send a fake password reset request
            let body = "email=test@example.com";

            debug!(
                "Testing password reset at {} with X-Forwarded-Host",
                reset_url
            );

            match self
                .http_client
                .post_with_headers(&reset_url, body, headers)
                .await
            {
                Ok(response) => {
                    // Check if the reset link contains our attacker domain
                    if response.body.contains(&self.test_domain) {
                        info!("Password reset poisoning detected at {}", endpoint);
                        vulnerabilities.push(self.create_vulnerability(
                            &reset_url,
                            &format!("X-Forwarded-Host: {}", self.test_domain),
                            "password_reset_poisoning",
                            "Password Reset Poisoning",
                            Confidence::High,
                            &format!(
                                "Password reset response contains attacker-controlled domain '{}'. \
                                 Reset links will point to attacker's server.",
                                self.test_domain
                            ),
                            Severity::High,
                        ));
                        break; // One finding is enough
                    }

                    // Note: We do NOT report "potential" password reset poisoning
                    // just because the endpoint returns a success message like "email sent".
                    // Most password reset endpoints always return the same message regardless
                    // of whether X-Forwarded-Host was used, as a security best practice.
                    // Only report when the attacker domain is actually reflected in the
                    // response (checked above), which proves the vulnerability.
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test X-Forwarded-Host and similar headers
    async fn test_forwarded_headers(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing X-Forwarded-* headers");

        let forwarded_headers = vec![
            ("X-Forwarded-Host", "x_forwarded_host"),
            ("X-Host", "x_host"),
            ("X-Forwarded-Server", "x_forwarded_server"),
            ("X-HTTP-Host-Override", "x_http_host_override"),
            ("Forwarded", "forwarded_rfc7239"),
        ];

        for (header_name, technique) in &forwarded_headers {
            tests_run += 1;

            let header_value = if *header_name == "Forwarded" {
                format!("host={}", self.test_domain)
            } else {
                self.test_domain.clone()
            };

            let headers = vec![(header_name.to_string(), header_value.clone())];

            debug!("Testing {} header", header_name);

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if response.body.contains(&self.test_domain) {
                        info!("{} injection detected", header_name);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("{}: {}", header_name, header_value),
                            technique,
                            &format!("{} Injection", header_name),
                            Confidence::High,
                            &format!("Injected domain via {} reflected in response", header_name),
                            Severity::Medium,
                        ));
                    }

                    // Check Location header for redirects
                    if let Some(location) = response.headers.get("location") {
                        if location.contains(&self.test_domain) {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                &format!("{}: {}", header_name, header_value),
                                technique,
                                "Open Redirect via Host Header",
                                Confidence::High,
                                &format!("Location header contains attacker domain: {}", location),
                                Severity::High,
                            ));
                        }
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test absolute URL in request line
    async fn test_absolute_url(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing absolute URL override");

        // This test requires crafting a request with absolute URL
        // Most HTTP clients don't support this directly
        // We simulate by using X-Original-URL or X-Rewrite-URL

        let headers = vec![(
            "X-Original-URL".to_string(),
            format!("http://{}/", self.test_domain),
        )];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if response.body.contains(&self.test_domain) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        &format!("X-Original-URL: http://{}/", self.test_domain),
                        "x_original_url",
                        "X-Original-URL Override",
                        Confidence::Medium,
                        "Application processes X-Original-URL header, allowing URL override",
                        Severity::Medium,
                    ));
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test port-based injection
    async fn test_port_injection(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        debug!("Testing port-based Host header injection");

        let original_host = self.extract_host(url);

        let port_payloads = vec![
            (format!("{}:1337", original_host), "arbitrary_port"),
            (
                format!("{}:@{}", self.test_domain, original_host),
                "port_at_bypass",
            ),
            (
                format!("{}:80@{}", original_host, self.test_domain),
                "port_redirect",
            ),
        ];

        for (host_value, technique) in &port_payloads {
            tests_run += 1;

            let headers = vec![("X-Forwarded-Host".to_string(), host_value.clone())];

            debug!("Testing port injection: {}", technique);

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    // Check for port in response
                    if response.body.contains(":1337") || response.body.contains(&self.test_domain)
                    {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            &format!("X-Forwarded-Host: {}", host_value),
                            technique,
                            "Port-based Host Header Injection",
                            Confidence::Medium,
                            &format!(
                                "Injected port/host via {} technique reflected in response",
                                technique
                            ),
                            Severity::Medium,
                        ));
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Test duplicate Host header
    async fn test_duplicate_host(&self, url: &str) -> (Vec<Vulnerability>, usize) {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing duplicate Host header");

        // Some servers use the second Host header
        let original_host = self.extract_host(url);
        let headers = vec![
            ("Host".to_string(), original_host.clone()),
            ("Host".to_string(), self.test_domain.clone()),
        ];

        match self.http_client.get_with_headers(url, headers).await {
            Ok(response) => {
                if response.body.contains(&self.test_domain) {
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        &format!("Host: {}\nHost: {}", original_host, self.test_domain),
                        "duplicate_host",
                        "Duplicate Host Header Injection",
                        Confidence::High,
                        "Server uses second Host header value, allowing injection",
                        Severity::Medium,
                    ));
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        (vulnerabilities, tests_run)
    }

    /// Extract host from URL
    fn extract_host(&self, url: &str) -> String {
        url.trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("localhost")
            .to_string()
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        payload: &str,
        technique: &str,
        vuln_type: &str,
        confidence: Confidence,
        evidence: &str,
        severity: Severity,
    ) -> Vulnerability {
        let verified = matches!(confidence, Confidence::High);
        let cvss = match severity {
            Severity::High => 8.1,
            Severity::Medium => 6.1,
            _ => 4.3,
        };
        Vulnerability {
            id: format!("host_header_injection_{}", Self::generate_id()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("Host Header".to_string()),
            payload: payload.to_string(),
            description: format!(
                "Host header injection vulnerability detected.\n\n\
                Technique: {}\n\n\
                This vulnerability can be exploited for:\n\
                - **Password Reset Poisoning**: Attacker receives password reset links\n\
                - **Web Cache Poisoning**: Serving malicious content to other users\n\
                - **SSRF**: Forcing server to make requests to internal hosts\n\
                - **Virtual Host Confusion**: Accessing other virtual hosts\n\
                - **OAuth Token Theft**: Redirecting OAuth callbacks",
                technique
            ),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-644".to_string(), // Improper Neutralization of HTTP Headers
            cvss,
            verified,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Validate Host Header**
   ```python
   # Python/Django example
   ALLOWED_HOSTS = ['example.com', 'www.example.com']
   ```

   ```javascript
   // Node.js/Express example
   const allowedHosts = ['example.com', 'www.example.com'];
   app.use((req, res, next) => {
     if (!allowedHosts.includes(req.hostname)) {
       return res.status(400).send('Invalid host');
     }
     next();
   });
   ```

2. **Ignore X-Forwarded-Host Unless from Trusted Proxy**
   ```nginx
   # Nginx - only trust X-Forwarded-Host from specific IPs
   set_real_ip_from 10.0.0.0/8;
   real_ip_header X-Forwarded-For;
   ```

3. **Use Absolute URLs in Configuration**
   ```python
   # Django settings.py
   SITE_URL = 'https://example.com'  # Don't use request.get_host()
   ```

4. **Password Reset - Use Configured Domain**
   ```python
   # BAD: Uses Host header
   reset_url = f"{request.scheme}://{request.get_host()}/reset/{token}"

   # GOOD: Uses configured domain
   reset_url = f"{settings.SITE_URL}/reset/{token}"
   ```

5. **Configure Reverse Proxy Correctly**
   ```nginx
   # Set Host header explicitly
   proxy_set_header Host $host;
   proxy_set_header X-Forwarded-Host $host;
   ```

6. **Web Cache Configuration**
   - Include Host header in cache key
   - Validate Host before caching

References:
- https://portswigger.net/web-security/host-header
- https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html"#
                .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> HostHeaderInjectionScanner {
        let http_client = Arc::new(HttpClient::new(5, 2).unwrap());
        HostHeaderInjectionScanner::new(http_client)
    }

    #[test]
    fn test_extract_host() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.extract_host("https://example.com/path"),
            "example.com"
        );
        assert_eq!(
            scanner.extract_host("http://test.com:8080/"),
            "test.com:8080"
        );
        assert_eq!(
            scanner.extract_host("https://sub.domain.com"),
            "sub.domain.com"
        );
    }

    #[test]
    fn test_generate_id() {
        let id1 = HostHeaderInjectionScanner::generate_id();
        let id2 = HostHeaderInjectionScanner::generate_id();

        assert_eq!(id1.len(), 8);
        assert_ne!(id1, id2);
    }
}
