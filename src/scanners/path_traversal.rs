// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Path Traversal Scanner Module
 * Tests for directory traversal vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::payloads;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tracing::{debug, info};

pub struct PathTraversalScanner {
    http_client: Arc<HttpClient>,
}

impl PathTraversalScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for path traversal vulnerabilities
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing parameter '{}' for path traversal", parameter);

        let payloads = payloads::get_path_traversal_payloads();
        let total_payloads = payloads.len();

        debug!("Testing {} path traversal payloads", total_payloads);

        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 50;

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);

                async move {
                    let test_url = if url.contains('?') {
                        format!("{}&{}={}", url, param, urlencoding::encode(&payload))
                    } else {
                        format!("{}?{}={}", url, param, urlencoding::encode(&payload))
                    };

                    match client.get(&test_url).await {
                        Ok(response) => Some((payload, response, test_url)),
                        Err(e) => {
                            debug!("Request failed for path traversal payload: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        // Check for path traversal indicators in responses
        for result in results {
            if let Some((payload, response, test_url)) = result {
                if self.detect_path_traversal(&response.body) {
                    info!(
                        "Path traversal vulnerability detected in parameter '{}'",
                        parameter
                    );

                    let vuln = Vulnerability {
                        id: format!("path_{}", uuid::Uuid::new_v4().to_string()),
                        vuln_type: "Path Traversal".to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: "Path Traversal".to_string(),
                        url: test_url,
                        parameter: Some(parameter.to_string()),
                        payload: payload.clone(),
                        description: format!(
                            "Path traversal vulnerability detected in parameter '{}'. The application allows reading arbitrary files.",
                            parameter
                        ),
                        evidence: Some("Sensitive file content detected in response".to_string()),
                        cwe: "CWE-22".to_string(),
                        cvss: 7.5,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Validate and sanitize all file paths\n2. Use allowlists for permitted files\n3. Implement proper access controls\n4. Avoid using user input in file operations".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    };

                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Detect path traversal by checking for sensitive file content
    fn detect_path_traversal(&self, body: &str) -> bool {
        let indicators = vec![
            "root:x:",           // /etc/passwd
            "[boot loader]",     // boot.ini
            "extension=",        // php.ini
            "<?xml",             // web.config
            "Administrative Tools", // Windows system
            "/bin/bash",         // shell references
            "daemon:x:",         // Unix user
        ];

        indicators.iter().any(|indicator| body.contains(indicator))
    }
}

// UUID generation
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
