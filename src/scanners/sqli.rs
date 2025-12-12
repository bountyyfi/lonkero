// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - SQL Injection Scanner Module
 * Concurrent SQLi vulnerability testing with baseline comparison
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::payloads;
use crate::types::{ScanConfig, Vulnerability};
use crate::vulnerability::VulnerabilityDetector;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct SqliScanner {
    http_client: Arc<HttpClient>,
    detector: VulnerabilityDetector,
}

impl SqliScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            detector: VulnerabilityDetector::new(),
        }
    }

    /// Scan a parameter for SQL injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Integrity verification
        if !crate::license::verify_rt_state() {
            return Ok((Vec::new(), 0));
        }

        info!("Testing parameter '{}' for SQL injection", parameter);

        // First, get baseline response
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to get baseline response: {}", e);
                // Create empty baseline to continue testing
                HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: std::collections::HashMap::new(),
                    duration_ms: 0,
                }
            }
        };

        let payloads = payloads::get_sqli_payloads(config.scan_mode.as_str());
        let total_payloads = payloads.len();

        debug!("Testing {} SQLi payloads", total_payloads);

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 100;

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();

                async move {
                    // Build URL with payload
                    let test_url = if url.contains('?') {
                        format!("{}&{}={}", url, param, urlencoding::encode(&payload))
                    } else {
                        format!("{}?{}={}", url, param, urlencoding::encode(&payload))
                    };

                    // Send request
                    match client.get(&test_url).await {
                        Ok(response) => {
                            Some((payload, response, test_url, baseline_clone))
                        }
                        Err(e) => {
                            debug!("Request failed for SQLi payload: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        // Analyze responses for SQL injection
        for result in results {
            if let Some((payload, response, test_url, baseline)) = result {
                if let Some(vuln) = self.detector.detect_sqli(
                    &test_url,
                    parameter,
                    &payload,
                    &response,
                    &baseline,
                ) {
                    info!(
                        "SQL injection vulnerability detected: {} in parameter '{}'",
                        vuln.severity, parameter
                    );
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Test POST request body for SQLi
    pub async fn scan_post_body(
        &self,
        url: &str,
        body_param: &str,
        existing_body: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing POST parameter '{}' for SQL injection", body_param);

        // Get baseline response
        let baseline = match self.http_client.post(url, existing_body.to_string()).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to get baseline POST response: {}", e);
                HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: std::collections::HashMap::new(),
                    duration_ms: 0,
                }
            }
        };

        let payloads = payloads::get_sqli_payloads(config.scan_mode.as_str());
        let total_payloads = payloads.len();

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 100;

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = url.to_string();
                let param = body_param.to_string();
                let body = existing_body.to_string();
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();

                async move {
                    // Inject payload into body
                    let test_body = body.replace(
                        &format!("\"{}\":", param),
                        &format!("\"{}\":\"{}\"", param, payload)
                    );

                    match client.post(&url, test_body.clone()).await {
                        Ok(response) => Some((payload, response, url, baseline_clone)),
                        Err(e) => {
                            debug!("POST request failed: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        for result in results {
            if let Some((payload, response, test_url, baseline)) = result {
                if let Some(vuln) = self.detector.detect_sqli(
                    &test_url,
                    body_param,
                    &payload,
                    &response,
                    &baseline,
                ) {
                    info!(
                        "SQL injection in POST body: {} in parameter '{}'",
                        vuln.severity, body_param
                    );
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Test time-based blind SQL injection
    pub async fn scan_time_based(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing parameter '{}' for time-based blind SQLi", parameter);

        // Time-based SQLi payloads that cause delays
        let time_based_payloads = vec![
            "' OR SLEEP(5)--",
            "' OR pg_sleep(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5) AND '1'='1",
            "' || pg_sleep(5)--",
        ];

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for payload in time_based_payloads {
            tests_run += 1;

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // If response took longer than 4.5 seconds, likely time-based SQLi
                    if response.duration_ms > 4500 {
                        info!(
                            "Time-based blind SQLi detected: response took {}ms",
                            response.duration_ms
                        );

                        // Create vulnerability
                        let vuln = Vulnerability {
                            id: format!("sqli_time_{}", uuid::Uuid::new_v4().to_string()),
                            vuln_type: "Time-based Blind SQL Injection".to_string(),
                            severity: crate::types::Severity::Critical,
                            confidence: crate::types::Confidence::High,
                            category: "Injection".to_string(),
                            url: test_url.clone(),
                            parameter: Some(parameter.to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "Time-based blind SQL injection detected in parameter '{}'. Response delayed by {}ms.",
                                parameter, response.duration_ms
                            ),
                            evidence: Some(format!(
                                "Response time: {}ms (expected < 1000ms)",
                                response.duration_ms
                            )),
                            cwe: "CWE-89".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Use parameterized queries/prepared statements\n2. Implement input validation\n3. Apply principle of least privilege for database accounts".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        };

                        vulnerabilities.push(vuln);
                    }
                }
                Err(e) => {
                    debug!("Time-based SQLi test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }
}

// UUID generation (same as in vulnerability.rs)
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
