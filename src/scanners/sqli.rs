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

    /// Test UNION-based SQL injection
    /// First determines column count using ORDER BY, then attempts UNION SELECT with marker strings
    pub async fn scan_union_based(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing parameter '{}' for UNION-based SQLi", parameter);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Step 1: Determine column count using ORDER BY technique
        let order_by_tests = vec![1, 5, 10, 20];
        let mut column_count: Option<usize> = None;

        info!("Determining column count using ORDER BY technique...");

        for &columns in &order_by_tests {
            tests_run += 1;
            let payload = format!("' ORDER BY {}--", columns);

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(&payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // If status is 200 and no obvious error, ORDER BY succeeded
                    let has_error = response.body.to_lowercase().contains("error")
                        || response.body.to_lowercase().contains("syntax")
                        || response.body.to_lowercase().contains("mysql")
                        || response.body.to_lowercase().contains("unknown column")
                        || response.status_code >= 400;

                    if !has_error {
                        debug!("ORDER BY {} succeeded", columns);
                        // This column count works, but we need to find where it fails
                        // to determine exact count

                        // Test the next value to see if it fails
                        if columns < 20 {
                            let next_columns = columns + 1;
                            tests_run += 1;
                            let next_payload = format!("' ORDER BY {}--", next_columns);
                            let next_test_url = if base_url.contains('?') {
                                format!("{}&{}={}", base_url, parameter, urlencoding::encode(&next_payload))
                            } else {
                                format!("{}?{}={}", base_url, parameter, urlencoding::encode(&next_payload))
                            };

                            if let Ok(next_response) = self.http_client.get(&next_test_url).await {
                                let next_has_error = next_response.body.to_lowercase().contains("error")
                                    || next_response.body.to_lowercase().contains("syntax")
                                    || next_response.body.to_lowercase().contains("mysql")
                                    || next_response.body.to_lowercase().contains("unknown column")
                                    || next_response.status_code >= 400;

                                if next_has_error {
                                    // Found the boundary - column count is current value
                                    column_count = Some(columns);
                                    info!("Column count determined: {}", columns);
                                    break;
                                }
                            }
                        }
                    } else {
                        debug!("ORDER BY {} failed", columns);
                        // If this is the first test and it fails, column count is less than this
                        if columns == 1 {
                            debug!("Even ORDER BY 1 failed, may not be vulnerable");
                        }
                    }
                }
                Err(e) => {
                    debug!("ORDER BY test request failed: {}", e);
                }
            }
        }

        // Step 2: Test UNION SELECT with NULL values for column counts 1-10
        info!("Testing UNION SELECT with NULL values...");

        for cols in 1..=10 {
            tests_run += 1;

            // Build UNION SELECT with appropriate number of NULLs
            let nulls = vec!["NULL"; cols].join(",");
            let payload = format!("' UNION SELECT {}--", nulls);

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(&payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(&payload))
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if UNION succeeded (no error in response)
                    let has_error = response.body.to_lowercase().contains("error")
                        || response.body.to_lowercase().contains("syntax")
                        || response.status_code >= 400;

                    if !has_error && response.status_code == 200 {
                        debug!("UNION SELECT with {} columns succeeded", cols);

                        // If we haven't determined column count yet, do it now
                        if column_count.is_none() {
                            column_count = Some(cols);
                        }
                    }
                }
                Err(e) => {
                    debug!("UNION SELECT test failed: {}", e);
                }
            }
        }

        // Step 3: Test UNION SELECT with marker strings
        if let Some(cols) = column_count {
            info!("Testing UNION SELECT with marker strings for {} columns...", cols);

            // Test marker in different positions
            for marker_pos in 1..=cols {
                tests_run += 1;

                // Build UNION SELECT with marker at specific position
                let mut values = Vec::new();
                for i in 1..=cols {
                    if i == marker_pos {
                        values.push("'LONKERO_SQLI_MARKER'");
                    } else {
                        values.push(&format!("{}", i));
                    }
                }

                let payload = format!("' UNION SELECT {}--", values.join(","));

                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, parameter, urlencoding::encode(&payload))
                } else {
                    format!("{}?{}={}", base_url, parameter, urlencoding::encode(&payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        // Check if our marker appears in the response
                        if response.body.contains("LONKERO_SQLI_MARKER") {
                            info!(
                                "UNION-based SQLi confirmed: marker found in response for {} columns, position {}",
                                cols, marker_pos
                            );

                            let vuln = Vulnerability {
                                id: format!("sqli_union_{}", uuid::Uuid::new_v4().to_string()),
                                vuln_type: "UNION-based SQL Injection".to_string(),
                                severity: crate::types::Severity::Critical,
                                confidence: crate::types::Confidence::High,
                                category: "Injection".to_string(),
                                url: test_url.clone(),
                                parameter: Some(parameter.to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "UNION-based SQL injection detected in parameter '{}'. Successfully injected data using UNION SELECT with {} columns. Marker string appeared in response.",
                                    parameter, cols
                                ),
                                evidence: Some(format!(
                                    "Column count: {}, Marker position: {}, Marker 'LONKERO_SQLI_MARKER' found in response body",
                                    cols, marker_pos
                                )),
                                cwe: "CWE-89".to_string(),
                                cvss: 9.8,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Use parameterized queries/prepared statements\n2. Implement strict input validation\n3. Apply principle of least privilege for database accounts\n4. Use ORM frameworks that prevent SQL injection".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            };

                            vulnerabilities.push(vuln);
                            // Found vulnerability, no need to test other positions
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UNION SELECT marker test failed: {}", e);
                    }
                }
            }
        } else {
            // Even if we couldn't determine exact column count, try common values with markers
            info!("Column count not determined, testing common column counts with markers...");

            for cols in 1..=10 {
                tests_run += 1;

                let payload = if cols == 1 {
                    "' UNION SELECT 'LONKERO_SQLI_MARKER'--".to_string()
                } else if cols == 2 {
                    "' UNION SELECT 1,'LONKERO_SQLI_MARKER'--".to_string()
                } else if cols == 3 {
                    "' UNION SELECT 1,2,'LONKERO_SQLI_MARKER'--".to_string()
                } else {
                    // For more columns, put marker in the middle
                    let mut values = Vec::new();
                    for i in 1..=cols {
                        if i == 2 {
                            values.push("'LONKERO_SQLI_MARKER'");
                        } else {
                            values.push(&format!("{}", i));
                        }
                    }
                    format!("' UNION SELECT {}--", values.join(","))
                };

                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, parameter, urlencoding::encode(&payload))
                } else {
                    format!("{}?{}={}", base_url, parameter, urlencoding::encode(&payload))
                };

                match self.http_client.get(&test_url).await {
                    Ok(response) => {
                        if response.body.contains("LONKERO_SQLI_MARKER") {
                            info!(
                                "UNION-based SQLi confirmed: marker found in response for {} columns",
                                cols
                            );

                            let vuln = Vulnerability {
                                id: format!("sqli_union_{}", uuid::Uuid::new_v4().to_string()),
                                vuln_type: "UNION-based SQL Injection".to_string(),
                                severity: crate::types::Severity::Critical,
                                confidence: crate::types::Confidence::High,
                                category: "Injection".to_string(),
                                url: test_url.clone(),
                                parameter: Some(parameter.to_string()),
                                payload: payload.to_string(),
                                description: format!(
                                    "UNION-based SQL injection detected in parameter '{}'. Successfully injected data using UNION SELECT. Marker string appeared in response.",
                                    parameter
                                ),
                                evidence: Some(format!(
                                    "Marker 'LONKERO_SQLI_MARKER' found in response body using {} column(s)",
                                    cols
                                )),
                                cwe: "CWE-89".to_string(),
                                cvss: 9.8,
                                verified: true,
                                false_positive: false,
                                remediation: "1. Use parameterized queries/prepared statements\n2. Implement strict input validation\n3. Apply principle of least privilege for database accounts\n4. Use ORM frameworks that prevent SQL injection".to_string(),
                                discovered_at: chrono::Utc::now().to_rfc3339(),
                            };

                            vulnerabilities.push(vuln);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UNION SELECT marker test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test boolean-based blind SQL injection
    /// Tests true/false condition pairs and detects SQLi when responses differ
    pub async fn scan_boolean_based(
        &self,
        base_url: &str,
        parameter: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing parameter '{}' for boolean-based blind SQLi", parameter);

        // Define true/false payload pairs for different database syntaxes
        let payload_pairs = vec![
            // Generic SQL - most common patterns
            ("' OR '1'='1", "' OR '1'='2"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
            ("') OR ('1'='1", "') OR ('1'='2"),
            ("' OR 'x'='x", "' OR 'x'='y"),
            ("1 OR 1=1", "1 OR 1=2"),
            // MySQL specific (using # for comments)
            ("' OR '1'='1'#", "' OR '1'='2'#"),
            ("' AND 1=1#", "' AND 1=2#"),
            // PostgreSQL specific
            ("' OR '1'='1'--", "' OR '1'='2'--"),
            ("' AND 1=1--", "' AND 1=2--"),
            // MSSQL specific (semicolon before comment)
            ("' OR '1'='1';--", "' OR '1'='2';--"),
            ("' AND 1=1;--", "' AND 1=2;--"),
            // Oracle specific (using || for concatenation)
            ("' OR '1'='1'||'", "' OR '1'='2'||'"),
            // Numeric context
            (" OR 1=1--", " OR 1=2--"),
            (" AND 1=1--", " AND 1=2--"),
        ];

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response for comparison
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to get baseline response: {}", e);
                HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: std::collections::HashMap::new(),
                    duration_ms: 0,
                }
            }
        };

        let baseline_size = baseline.body.len();

        for (true_payload, false_payload) in payload_pairs {
            tests_run += 2; // We test both true and false conditions

            // Build URLs for true and false conditions
            let true_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(true_payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(true_payload))
            };

            let false_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(false_payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(false_payload))
            };

            // Send true condition request
            let true_response = match self.http_client.get(&true_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("True condition request failed: {}", e);
                    continue;
                }
            };

            // Send false condition request
            let false_response = match self.http_client.get(&false_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("False condition request failed: {}", e);
                    continue;
                }
            };

            // Analyze response differences
            let true_size = true_response.body.len();
            let false_size = false_response.body.len();

            let size_diff_true_false = (true_size as i64 - false_size as i64).abs();
            let size_diff_true_baseline = (true_size as i64 - baseline_size as i64).abs();
            let size_diff_false_baseline = (false_size as i64 - baseline_size as i64).abs();

            // Detection logic:
            // Boolean-based SQLi is detected when:
            // 1. True and false conditions produce significantly different responses
            // 2. The difference is substantial enough to indicate different query results
            //
            // We use 200 bytes as threshold to avoid false positives from minor variations
            // Also check status codes for additional confirmation
            let significant_size_diff = size_diff_true_false > 200;
            let status_differs = true_response.status_code != false_response.status_code;

            if significant_size_diff || status_differs {
                info!(
                    "Boolean-based blind SQLi detected: true size={}, false size={}, baseline={}, diff={}",
                    true_size, false_size, baseline_size, size_diff_true_false
                );

                let vuln = Vulnerability {
                    id: format!("sqli_boolean_{}", uuid::Uuid::new_v4().to_string()),
                    vuln_type: "Boolean-based Blind SQL Injection".to_string(),
                    severity: crate::types::Severity::Critical,
                    confidence: crate::types::Confidence::High,
                    category: "Injection".to_string(),
                    url: base_url.to_string(),
                    parameter: Some(parameter.to_string()),
                    payload: format!("TRUE: {} | FALSE: {}", true_payload, false_payload),
                    description: format!(
                        "Boolean-based blind SQL injection detected in parameter '{}'. True and false SQL conditions produce measurably different responses, indicating the application is vulnerable.",
                        parameter
                    ),
                    evidence: Some(format!(
                        "True condition ({}): {} bytes, status {}\nFalse condition ({}): {} bytes, status {}\nBaseline: {} bytes\nDifference: {} bytes",
                        true_payload, true_size, true_response.status_code,
                        false_payload, false_size, false_response.status_code,
                        baseline_size, size_diff_true_false
                    )),
                    cwe: "CWE-89".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Use parameterized queries/prepared statements\n2. Implement input validation and sanitization\n3. Apply principle of least privilege for database accounts\n4. Use an ORM framework\n5. Implement proper error handling that doesn't expose database details".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                };

                vulnerabilities.push(vuln);

                // Break after first detection to avoid redundant findings with similar payloads
                break;
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
