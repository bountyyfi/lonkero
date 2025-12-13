// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Command Injection Scanner Module
 * Tests for OS command injection vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::payloads;
use crate::types::{ScanConfig, Vulnerability};
use crate::vulnerability::VulnerabilityDetector;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tracing::{debug, info};

pub struct CommandInjectionScanner {
    http_client: Arc<HttpClient>,
    detector: VulnerabilityDetector,
}

impl CommandInjectionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            detector: VulnerabilityDetector::new(),
        }
    }

    /// Scan a parameter for command injection vulnerabilities
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
            tracing::warn!("Command injection scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("Testing parameter '{}' for command injection", parameter);

        let payloads = payloads::get_command_injection_payloads();
        let total_payloads = payloads.len();

        debug!("Testing {} command injection payloads", total_payloads);

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 50; // Lower concurrency for command injection

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);

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
                            Some((payload, response, test_url))
                        }
                        Err(e) => {
                            debug!("Request failed for command injection payload: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        // Analyze responses for command injection
        for result in results {
            if let Some((payload, response, test_url)) = result {
                if let Some(vuln) = self.detector.detect_command_injection(
                    &test_url,
                    parameter,
                    &payload,
                    &response,
                ) {
                    info!(
                        "Command injection vulnerability detected: {} in parameter '{}'",
                        vuln.severity, parameter
                    );
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Test POST request body for command injection
    pub async fn scan_post_body(
        &self,
        url: &str,
        body_param: &str,
        existing_body: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing POST parameter '{}' for command injection", body_param);

        let payloads = payloads::get_command_injection_payloads();
        let total_payloads = payloads.len();

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 50;

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = url.to_string();
                let param = body_param.to_string();
                let body = existing_body.to_string();
                let client = Arc::clone(&self.http_client);

                async move {
                    // Inject payload into body
                    let test_body = body.replace(
                        &format!("\"{}\":", param),
                        &format!("\"{}\":\"{}\"", param, payload)
                    );

                    match client.post(&url, test_body.clone()).await {
                        Ok(response) => Some((payload, response, url)),
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
            if let Some((payload, response, test_url)) = result {
                if let Some(vuln) = self.detector.detect_command_injection(
                    &test_url,
                    body_param,
                    &payload,
                    &response,
                ) {
                    info!(
                        "Command injection in POST body: {} in parameter '{}'",
                        vuln.severity, body_param
                    );
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }
}
