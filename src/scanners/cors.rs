// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - CORS Misconfiguration Scanner
 * Tests for insecure Cross-Origin Resource Sharing configurations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};

pub struct CorsScanner {
    http_client: Arc<HttpClient>,
}

impl CorsScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for CORS misconfigurations
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[CORS] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Check baseline CORS headers (no Origin header)
        tests_run += 1;
        match self.http_client.get(url).await {
            Ok(response) => {
                // Store characteristics for intelligent detection
                let _characteristics = AppCharacteristics::from_response(&response, url);
                self.check_baseline_cors(&response, url, &mut vulnerabilities);
            }
            Err(e) => {
                debug!("Failed to fetch URL for CORS check: {}", e);
            }
        }

        // Test 2: Test with attacker origin
        tests_run += 1;
        if let Ok(response) = self.send_with_origin(url, "https://evil.com").await {
            self.check_reflected_origin(&response, url, "https://evil.com", &mut vulnerabilities);
        }

        // Test 3: Test with null origin
        tests_run += 1;
        if let Ok(response) = self.send_with_origin(url, "null").await {
            self.check_null_origin(&response, url, &mut vulnerabilities);
        }

        // Test 4: Test with subdomain origin
        tests_run += 1;
        if let Some(domain) = self.extract_domain(url) {
            let subdomain_origin = format!("https://evil.{}", domain);
            if let Ok(response) = self.send_with_origin(url, &subdomain_origin).await {
                self.check_subdomain_exploit(
                    &response,
                    url,
                    &subdomain_origin,
                    &mut vulnerabilities,
                );
            }
        }

        // Test 5: Test with pre-domain origin (prefix attack)
        tests_run += 1;
        if let Some(domain) = self.extract_domain(url) {
            let prefix_origin = format!("https://{}.evil.com", domain);
            if let Ok(response) = self.send_with_origin(url, &prefix_origin).await {
                self.check_prefix_exploit(&response, url, &prefix_origin, &mut vulnerabilities);
            }
        }

        // Test 6: Test with localhost origin
        tests_run += 1;
        if let Ok(response) = self.send_with_origin(url, "http://localhost").await {
            self.check_localhost_origin(&response, url, &mut vulnerabilities);
        }

        // Test 7: Test for credentials exposure
        tests_run += 1;
        if let Ok(response) = self
            .send_with_credentials(url, "https://attacker.com")
            .await
        {
            self.check_credentials_exposure(&response, url, &mut vulnerabilities);
        }

        info!(
            "[SUCCESS] [CORS] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Send request with custom Origin header
    async fn send_with_origin(&self, url: &str, origin: &str) -> Result<HttpResponse> {
        let headers = vec![("Origin".to_string(), origin.to_string())];
        self.http_client.get_with_headers(url, headers).await
    }

    /// Send request with credentials
    async fn send_with_credentials(&self, url: &str, origin: &str) -> Result<HttpResponse> {
        let headers = vec![
            ("Origin".to_string(), origin.to_string()),
            (
                "Cookie".to_string(),
                "session=test_session_value".to_string(),
            ),
        ];
        self.http_client.get_with_headers(url, headers).await
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> Option<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            parsed.host_str().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Check baseline CORS configuration
    fn check_baseline_cors(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == "*" {
                if let Some(credentials) = response.header("access-control-allow-credentials") {
                    if credentials == "true" {
                        // Wildcard + credentials is a real vulnerability
                        vulnerabilities.push(self.create_vulnerability(
                            "Critical CORS Misconfiguration",
                            url,
                            Severity::Critical,
                            Confidence::High,
                            "CORS allows all origins (*) with credentials enabled",
                            format!("Access-Control-Allow-Origin: {}, Access-Control-Allow-Credentials: true", acao),
                            8.8,
                        ));
                    }
                }
                // Note: Wildcard (*) WITHOUT credentials is NOT reported.
                // This is standard practice for public APIs, CDNs, open data
                // endpoints, and any resource meant to be publicly accessible.
                // Browsers already prevent credentialed requests with wildcard
                // CORS, so there is no security impact.
            }
        }
    }

    /// Check for reflected origin (trusts any origin)
    fn check_reflected_origin(
        &self,
        response: &HttpResponse,
        url: &str,
        test_origin: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == test_origin {
                let has_credentials = response
                    .header("access-control-allow-credentials")
                    .map(|c| c == "true")
                    .unwrap_or(false);

                if has_credentials {
                    vulnerabilities.push(self.create_vulnerability(
                        "CORS Reflected Origin with Credentials",
                        url,
                        Severity::Critical,
                        Confidence::High,
                        "Server reflects arbitrary Origin header and allows credentials",
                        format!(
                            "Sent Origin: {}, Reflected: {}, Credentials: true",
                            test_origin, acao
                        ),
                        9.1,
                    ));
                } else {
                    vulnerabilities.push(self.create_vulnerability(
                        "CORS Reflected Origin",
                        url,
                        Severity::High,
                        Confidence::High,
                        "Server reflects arbitrary Origin header",
                        format!("Sent Origin: {}, Reflected: {}", test_origin, acao),
                        7.4,
                    ));
                }
            }
        }
    }

    /// Check for null origin acceptance
    fn check_null_origin(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == "null" {
                vulnerabilities.push(self.create_vulnerability(
                    "CORS Allows Null Origin",
                    url,
                    Severity::High,
                    Confidence::High,
                    "CORS accepts 'null' origin - exploitable via sandboxed iframes",
                    "Access-Control-Allow-Origin: null - Can be exploited via data: URIs or sandboxed iframes".to_string(),
                    7.5,
                ));
            }
        }
    }

    /// Check for subdomain exploitation
    fn check_subdomain_exploit(
        &self,
        response: &HttpResponse,
        url: &str,
        subdomain_origin: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == subdomain_origin || acao.contains("*.") {
                vulnerabilities.push(self.create_vulnerability(
                    "CORS Subdomain Wildcard Exploit",
                    url,
                    Severity::High,
                    Confidence::Medium,
                    "CORS trusts subdomains - attacker can register malicious subdomain",
                    format!("Server accepts subdomain origin: {}", subdomain_origin),
                    6.8,
                ));
            }
        }
    }

    /// Check for prefix exploitation
    fn check_prefix_exploit(
        &self,
        response: &HttpResponse,
        url: &str,
        prefix_origin: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == prefix_origin {
                vulnerabilities.push(self.create_vulnerability(
                    "CORS Domain Prefix Exploit",
                    url,
                    Severity::High,
                    Confidence::High,
                    "CORS validates origin with weak regex - accepts malicious domains with trusted domain as prefix",
                    format!("Server accepts prefix origin: {}", prefix_origin),
                    7.2,
                ));
            }
        }
    }

    /// Check for localhost origin acceptance
    fn check_localhost_origin(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao == "http://localhost" || acao == "http://127.0.0.1" {
                vulnerabilities.push(self.create_vulnerability(
                    "CORS Allows Localhost",
                    url,
                    Severity::Medium,
                    Confidence::High,
                    "CORS accepts localhost origin - could be exploited by local attackers",
                    format!("Access-Control-Allow-Origin: {}", acao),
                    5.5,
                ));
            }
        }
    }

    /// Check for credentials exposure
    fn check_credentials_exposure(
        &self,
        response: &HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if let Some(acao) = response.header("access-control-allow-origin") {
            if acao != "null" && acao != "" {
                if let Some(credentials) = response.header("access-control-allow-credentials") {
                    if credentials == "true" {
                        // Check if methods include sensitive operations
                        if let Some(methods) = response.header("access-control-allow-methods") {
                            if methods.contains("DELETE")
                                || methods.contains("PUT")
                                || methods.contains("PATCH")
                            {
                                vulnerabilities.push(self.create_vulnerability(
                                    "CORS Exposes Credentials with Write Methods",
                                    url,
                                    Severity::High,
                                    Confidence::Medium,
                                    "CORS allows credentials with write methods (PUT/DELETE/PATCH)",
                                    format!(
                                        "Origin: {}, Methods: {}, Credentials: true",
                                        acao, methods
                                    ),
                                    7.1,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("cors_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("CORS Misconfiguration - {}", title),
            severity,
            confidence,
            category: "Configuration".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: String::new(),
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-942".to_string(), // Permissive Cross-domain Policy with Untrusted Domains
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Implement Strict Origin Whitelist**
   - Never use Access-Control-Allow-Origin: *
   - Maintain explicit list of trusted origins
   - Validate Origin header against whitelist

2. **Secure Credentials Handling**
   - Only enable credentials (Access-Control-Allow-Credentials: true) for trusted origins
   - Never combine wildcard (*) with credentials

3. **Avoid Common Mistakes**
   - Don't reflect Origin header without validation
   - Don't trust null origin
   - Don't use weak regex validation (e.g., contains() checks)
   - Don't trust all subdomains

4. **Recommended Configuration (Example)**
   ```
   // Node.js/Express example
   const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

   app.use((req, res, next) => {
     const origin = req.headers.origin;
     if (allowedOrigins.includes(origin)) {
       res.setHeader('Access-Control-Allow-Origin', origin);
       res.setHeader('Access-Control-Allow-Credentials', 'true');
     }
     next();
   });
   ```

5. **Security Headers**
   - Use Vary: Origin header
   - Implement proper pre-flight request handling
   - Limit Access-Control-Allow-Methods to necessary methods

6. **Additional Protection**
   - Implement CSRF tokens for state-changing operations
   - Use SameSite cookie attribute
   - Consider implementing Content Security Policy

References:
- OWASP CORS Guide: https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
- PortSwigger CORS: https://portswigger.net/web-security/cors
"#
            .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
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
            Self
        }

        pub fn to_string(&self) -> String {
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
    use std::collections::HashMap;

    #[test]
    fn test_wildcard_with_credentials() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        headers.insert(
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_baseline_cors(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect wildcard with credentials");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_reflected_origin() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "access-control-allow-origin".to_string(),
            "https://evil.com".to_string(),
        );
        headers.insert(
            "access-control-allow-credentials".to_string(),
            "true".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_reflected_origin(
            &response,
            "https://example.com",
            "https://evil.com",
            &mut vulns,
        );

        assert!(
            vulns.len() > 0,
            "Should detect reflected origin with credentials"
        );
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_null_origin() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert(
            "access-control-allow-origin".to_string(),
            "null".to_string(),
        );

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_null_origin(&response, "https://example.com", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect null origin");
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_extract_domain() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let domain = scanner.extract_domain("https://api.example.com/path");
        assert_eq!(domain, Some("api.example.com".to_string()));

        let domain2 = scanner.extract_domain("http://localhost:3000");
        assert_eq!(domain2, Some("localhost".to_string()));
    }

    #[test]
    fn test_no_cors_headers() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_baseline_cors(&response, "https://example.com", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "Should not report vulnerability when no CORS headers present"
        );
    }

    #[test]
    fn test_wildcard_without_credentials_no_false_positive() {
        let scanner = CorsScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let mut headers = HashMap::new();
        headers.insert("access-control-allow-origin".to_string(), "*".to_string());
        // No credentials header - this is normal for public APIs

        let response = HttpResponse {
            status_code: 200,
            body: String::new(),
            headers,
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_baseline_cors(&response, "https://api.example.com/v1/data", &mut vulns);

        assert_eq!(
            vulns.len(),
            0,
            "Wildcard CORS without credentials is normal for public APIs - should NOT be reported"
        );
    }
}
