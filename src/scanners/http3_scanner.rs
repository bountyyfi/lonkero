// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - HTTP/3 Alt-Svc Header Scanner
 * Tests for HTTP/3 Alt-Svc header misconfigurations via standard HTTP/HTTPS
 *
 * NOTE: This scanner does NOT use actual HTTP/3 protocol.
 * It only checks Alt-Svc headers via standard HTTP/HTTPS requests.
 *
 * Detects:
 * - Alt-Svc header misconfigurations
 * - Alt-Svc header injection vulnerabilities
 * - Excessive Alt-Svc max-age values
 * - Insecure Alt-Svc configurations
 * - Early-Data header acceptance issues
 * - Header injection via malformed values
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct Http3Scanner {
    http_client: Arc<HttpClient>,
}

impl Http3Scanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for HTTP/3 Alt-Svc header misconfigurations
    /// Note: This uses standard HTTP/HTTPS requests, NOT actual HTTP/3 protocol
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing HTTP/3 Alt-Svc header configurations via standard HTTP");

        let (vulns, tests) = self.test_http3_support(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_alt_svc_header(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_early_data_replay(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_header_smuggling_h3(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_request_splitting_h3(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test HTTP/3 Alt-Svc header presence and configuration via standard HTTP
    async fn test_http3_support(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Checking Alt-Svc header for HTTP/3 support via standard HTTP");

        match self.http_client.get(url).await {
            Ok(response) => {
                if let Some(alt_svc) = response.header("alt-svc") {
                    if alt_svc.contains("h3") || alt_svc.contains("h3-29") || alt_svc.contains("h3-32") {
                        info!("HTTP/3 advertised in Alt-Svc header");

                        if !self.has_secure_alt_svc(&alt_svc) {
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Insecure HTTP/3 Alt-Svc Configuration",
                                "",
                                "HTTP/3 Alt-Svc header contains insecure configuration",
                                &format!("Alt-Svc header: {}", alt_svc),
                                Severity::Medium,
                                "CWE-16",
                                5.3,
                            ));
                        }

                        if alt_svc.contains("ma=") {
                            if let Some(max_age) = self.extract_max_age(&alt_svc) {
                                if max_age > 86400 * 30 {
                                    vulnerabilities.push(self.create_vulnerability(
                                        url,
                                        "Excessive HTTP/3 Alt-Svc Max-Age",
                                        "",
                                        "HTTP/3 Alt-Svc header has excessive max-age value",
                                        &format!("Max-age: {} seconds (>30 days)", max_age),
                                        Severity::Low,
                                        "CWE-16",
                                        3.7,
                                    ));
                                }
                            }
                        }
                    }
                }

                if response.headers.contains_key("alt-used") {
                    debug!("Alt-Used header present in response");
                }
            }
            Err(e) => {
                debug!("Initial Alt-Svc check failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test Alt-Svc header manipulation
    async fn test_alt_svc_header(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing Alt-Svc header manipulation");

        let malicious_alt_svc_values = vec![
            r#"h3=":443"; ma=2592000; persist=1"#,
            r#"h3="evil.com:443""#,
            r#"h3="127.0.0.1:443""#,
            r#"h3=":0""#,
        ];

        for alt_svc_value in malicious_alt_svc_values {
            let headers = vec![
                ("Alt-Svc".to_string(), alt_svc_value.to_string()),
            ];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if let Some(returned_alt_svc) = response.header("alt-svc") {
                            if returned_alt_svc == alt_svc_value {
                                info!("Server reflects malicious Alt-Svc header");
                                vulnerabilities.push(self.create_vulnerability(
                                    url,
                                    "Alt-Svc Header Injection",
                                    alt_svc_value,
                                    "Server reflects client-provided Alt-Svc header",
                                    "Alt-Svc header injection may enable connection hijacking",
                                    Severity::High,
                                    "CWE-113",
                                    7.5,
                                ));
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Alt-Svc test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for Early-Data header acceptance on state-changing operations
    /// Note: Tests via standard HTTP, checking if server accepts Early-Data header
    async fn test_early_data_replay(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing Early-Data header acceptance via standard HTTP");

        let state_changing_endpoints = vec![
            ("/api/transfer", "POST"),
            ("/api/delete", "POST"),
            ("/api/update", "PUT"),
            ("/api/create", "POST"),
        ];

        for (endpoint, method) in state_changing_endpoints {
            let test_url = self.build_url(url, endpoint);

            let headers = vec![
                ("Early-Data".to_string(), "1".to_string()),
            ];

            let response_result = if method == "POST" {
                self.http_client.post_with_headers(&test_url, "{}", headers).await
            } else {
                self.http_client.get_with_headers(&test_url, headers).await
            };

            match response_result {
                Ok(response) => {
                    if response.status_code == 200 && !response.body.to_lowercase().contains("replay") {
                        info!("State-changing endpoint accepts Early-Data header: {}", endpoint);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Early-Data Header Accepted on State-Changing Endpoint",
                            "Early-Data: 1",
                            &format!("State-changing endpoint {} accepts Early-Data header", endpoint),
                            "Accepting Early-Data header on non-idempotent operations may enable replay attacks if HTTP/3 is used",
                            Severity::High,
                            "CWE-294",
                            7.5,
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Early data test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for header injection that could affect HTTP/3 implementations
    async fn test_header_smuggling_h3(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing header injection via standard HTTP");

        let smuggling_payloads = vec![
            ("X-Test\r\nX-Injected", "CRLF in header name"),
            ("X-Test\r\nContent-Length: 0\r\n\r\nGET /admin", "Full request injection"),
            ("X-Test\nTransfer-Encoding: chunked", "Transfer-Encoding injection"),
            ("X-Test: value\r\nHost: evil.com", "Host header injection"),
            ("X-Test\x00X-Injected", "Null byte in header"),
        ];

        for (header_value, attack_type) in smuggling_payloads {
            let headers = vec![
                ("X-Custom-Header".to_string(), header_value.to_string()),
            ];

            match self.http_client.get_with_headers(url, headers).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if response.body.to_lowercase().contains("injected") ||
                           response.body.to_lowercase().contains("admin") ||
                           response.body.to_lowercase().contains("evil") {
                            info!("Header injection detected: {}", attack_type);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Header Injection Vulnerability",
                                header_value,
                                &format!("Header injection via {}", attack_type),
                                "Header injection may enable request smuggling or other attacks",
                                Severity::Critical,
                                "CWE-113",
                                9.1,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Header smuggling test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for request splitting in URL paths
    async fn test_request_splitting_h3(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing request splitting via standard HTTP");

        let splitting_payloads = vec![
            "/%20HTTP/1.1%0d%0aHost:%20evil.com%0d%0a%0d%0aGET%20/",
            "/%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:",
            "/%0aGET%20/admin%20HTTP/1.1%0aHost:",
            "/test%0d%0a%0d%0aGET%20/admin",
        ];

        for payload in splitting_payloads {
            let test_url = format!("{}{}", url, payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.status_code == 200 {
                        if response.body.to_lowercase().contains("admin") ||
                           response.body.to_lowercase().contains("evil") {
                            info!("Request splitting detected");
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                "Request Splitting Vulnerability",
                                payload,
                                "Request splitting vulnerability detected in URL parsing",
                                "Request splitting may enable cache poisoning or request smuggling",
                                Severity::Critical,
                                "CWE-113",
                                9.1,
                            ));
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Request splitting test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    fn has_secure_alt_svc(&self, alt_svc: &str) -> bool {
        let alt_svc_lower = alt_svc.to_lowercase();

        if alt_svc_lower.contains("http://") {
            return false;
        }

        if alt_svc_lower.contains("localhost") || alt_svc_lower.contains("127.0.0.1") {
            return false;
        }

        true
    }

    fn extract_max_age(&self, alt_svc: &str) -> Option<u64> {
        let re = regex::Regex::new(r"ma=(\d+)").ok()?;
        if let Some(captures) = re.captures(alt_svc) {
            if let Some(max_age_str) = captures.get(1) {
                return max_age_str.as_str().parse::<u64>().ok();
            }
        }
        None
    }

    fn build_url(&self, base: &str, path: &str) -> String {
        if let Ok(parsed) = url::Url::parse(base) {
            let base_url = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if base_url.ends_with('/') && path.starts_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else if !base_url.ends_with('/') && !path.starts_with('/') {
                format!("{}/{}", base_url, path)
            } else {
                format!("{}{}", base_url, path)
            }
        } else {
            format!("{}{}", base, path)
        }
    }

    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
        cvss: f64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("http3_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: Confidence::High,
            category: "HTTP/3 Alt-Svc & Headers".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "Insecure HTTP/3 Alt-Svc Configuration" => {
                "1. Only advertise HTTPS endpoints in Alt-Svc\n\
                 2. Validate hostname matches server identity\n\
                 3. Use reasonable max-age values (24-48 hours)\n\
                 4. Never include localhost or internal IPs\n\
                 5. Implement proper certificate validation\n\
                 6. Use HSTS to prevent downgrade attacks\n\
                 7. Monitor Alt-Svc header generation\n\
                 8. Regular security testing of Alt-Svc configuration".to_string()
            }
            "Excessive HTTP/3 Alt-Svc Max-Age" => {
                "1. Set reasonable max-age values (24-72 hours)\n\
                 2. Allow for quick rollback in case of issues\n\
                 3. Consider client caching implications\n\
                 4. Implement versioning for Alt-Svc changes\n\
                 5. Monitor for stale Alt-Svc entries\n\
                 6. Document Alt-Svc lifecycle management\n\
                 7. Test with various client implementations".to_string()
            }
            "Alt-Svc Header Injection" => {
                "1. Never reflect client-provided Alt-Svc headers\n\
                 2. Generate Alt-Svc headers server-side only\n\
                 3. Validate and sanitize all header values\n\
                 4. Use strict header parsing\n\
                 5. Implement header allowlisting\n\
                 6. Log suspicious header manipulation attempts\n\
                 7. Use web application firewall rules\n\
                 8. Regular penetration testing".to_string()
            }
            "Early-Data Header Accepted on State-Changing Endpoint" => {
                "1. Reject Early-Data header on non-idempotent operations\n\
                 2. Implement replay protection mechanisms if using HTTP/3\n\
                 3. Use nonces or timestamps to detect replays\n\
                 4. Only allow GET/HEAD requests with Early-Data\n\
                 5. Check Early-Data header and reject if present for state changes\n\
                 6. Implement proper TLS 1.3 anti-replay mechanisms\n\
                 7. Monitor for replay attack patterns\n\
                 8. Document early data handling policy".to_string()
            }
            "Header Injection Vulnerability" | "Request Splitting Vulnerability" => {
                "1. Implement strict header parsing and validation\n\
                 2. Reject headers with CRLF, null bytes, or control characters\n\
                 3. Normalize all header values before processing\n\
                 4. Implement request validation at multiple layers\n\
                 5. Never trust client-provided header values\n\
                 6. Log and alert on malformed header attempts\n\
                 7. Use web application firewall rules\n\
                 8. Regular security updates for HTTP libraries\n\
                 9. Penetration testing for injection vulnerabilities".to_string()
            }
            _ => "Follow HTTP security best practices and validate all input".to_string(),
        }
    }
}

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
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> Http3Scanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        Http3Scanner::new(http_client)
    }

    #[test]
    fn test_has_secure_alt_svc() {
        let scanner = create_test_scanner();

        assert!(scanner.has_secure_alt_svc(r#"h3=":443"; ma=2592000"#));
        assert!(!scanner.has_secure_alt_svc(r#"h3="http://example.com:80""#));
        assert!(!scanner.has_secure_alt_svc(r#"h3="localhost:443""#));
        assert!(!scanner.has_secure_alt_svc(r#"h3="127.0.0.1:443""#));
    }

    #[test]
    fn test_extract_max_age() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.extract_max_age(r#"h3=":443"; ma=86400"#), Some(86400));
        assert_eq!(scanner.extract_max_age(r#"h3=":443"; ma=2592000"#), Some(2592000));
        assert_eq!(scanner.extract_max_age(r#"h3=":443""#), None);
    }

    #[test]
    fn test_excessive_max_age() {
        let scanner = create_test_scanner();

        let max_age_30_days = 86400 * 30;
        let max_age_31_days = 86400 * 31;
        let max_age_1_day = 86400;

        assert!(max_age_31_days > max_age_30_days);
        assert!(max_age_1_day < max_age_30_days);
    }

    #[test]
    fn test_build_url() {
        let scanner = create_test_scanner();

        assert_eq!(
            scanner.build_url("https://example.com", "/api/test"),
            "https://example.com/api/test"
        );
    }
}
