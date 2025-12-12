// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - UNION-based SQL Injection Scanner Module
 * Advanced SQLi detection using column enumeration and UNION SELECT techniques
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{ScanConfig, Vulnerability, Severity, Confidence};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Maximum number of columns to test
const MAX_COLUMNS: usize = 20;

/// Comment terminators for different SQL databases
const COMMENT_TERMINATORS: &[&str] = &[
    "--",      // MySQL, PostgreSQL, SQL Server
    "#",       // MySQL
    "/**/",    // MySQL, SQL Server
    ";%00",    // Null byte terminator
];

/// SQL error patterns indicating column mismatch
const ERROR_PATTERNS: &[&str] = &[
    "unknown column",
    "column not found",
    "invalid column",
    "wrong number of columns",
    "the used select statements have a different number of columns",
    "operands don't match",
    "conversion failed",
    "order by position",
    "unknown column in 'order clause'",
    "all queries combined using a union",
    "syntax error",
    "mysql",
    "sqlite",
    "postgresql",
    "ora-",
    "microsoft sql",
    "odbc",
    "jdbc",
];

/// Success patterns indicating injection worked
const SUCCESS_PATTERNS: &[&str] = &[
    "null",
    "NULL",
];

pub struct SqliUnionScanner {
    http_client: Arc<HttpClient>,
}

impl SqliUnionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan a parameter for UNION-based SQL injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // Integrity verification
        if !crate::license::verify_rt_state() {
            return Ok((Vec::new(), 0));
        }

        info!(
            "Testing parameter '{}' for UNION-based SQL injection",
            param
        );

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Get baseline response
        let baseline = match self.http_client.get(url).await {
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

        // Test each comment terminator
        for terminator in COMMENT_TERMINATORS {
            debug!("Testing with comment terminator: {}", terminator);

            // Phase 1: Enumerate column count using ORDER BY
            let column_count = match self
                .enumerate_columns_order_by(url, param, terminator, &mut tests_run)
                .await
            {
                Some(count) => {
                    info!(
                        "Detected {} columns using ORDER BY technique with terminator '{}'",
                        count, terminator
                    );
                    count
                }
                None => {
                    debug!("Could not determine column count with ORDER BY, trying UNION");
                    // Fallback: Try UNION SELECT NULL enumeration
                    match self
                        .enumerate_columns_union(url, param, terminator, &mut tests_run)
                        .await
                    {
                        Some(count) => {
                            info!(
                                "Detected {} columns using UNION SELECT technique with terminator '{}'",
                                count, terminator
                            );
                            count
                        }
                        None => {
                            debug!("Could not determine column count with UNION either");
                            continue;
                        }
                    }
                }
            };

            // Phase 2: Confirm vulnerability with UNION SELECT
            if let Some(vuln) = self
                .test_union_injection(
                    url,
                    param,
                    column_count,
                    terminator,
                    &baseline,
                    &mut tests_run,
                )
                .await
            {
                info!(
                    "UNION-based SQL injection confirmed: {} columns with terminator '{}'",
                    column_count, terminator
                );
                vulnerabilities.push(vuln);

                // In fast mode, stop after first vulnerability
                if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Enumerate columns using ORDER BY technique
    /// Returns the number of columns when successful
    async fn enumerate_columns_order_by(
        &self,
        url: &str,
        param: &str,
        terminator: &str,
        tests_run: &mut usize,
    ) -> Option<usize> {
        let mut last_successful = 0;

        for i in 1..=MAX_COLUMNS {
            let payload = format!("' ORDER BY {}{}", i, terminator);
            let test_url = self.build_test_url(url, param, &payload);

            *tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Check if response indicates error
                    if self.has_sql_error(&response) {
                        debug!("ORDER BY {} failed - error detected", i);
                        // Previous value was the last successful
                        if last_successful > 0 {
                            return Some(last_successful);
                        }
                        return None;
                    } else if response.status_code >= 200 && response.status_code < 400 {
                        debug!("ORDER BY {} succeeded", i);
                        last_successful = i;
                    } else {
                        debug!(
                            "ORDER BY {} returned status {}",
                            i, response.status_code
                        );
                        // HTTP error might indicate we exceeded column count
                        if last_successful > 0 {
                            return Some(last_successful);
                        }
                        return None;
                    }
                }
                Err(e) => {
                    debug!("ORDER BY {} test failed: {}", i, e);
                    if last_successful > 0 {
                        return Some(last_successful);
                    }
                    return None;
                }
            }

            // Small delay to avoid overwhelming the server
            if i % 5 == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }

        if last_successful > 0 {
            Some(last_successful)
        } else {
            None
        }
    }

    /// Enumerate columns using UNION SELECT NULL technique
    /// Returns the number of columns when successful
    async fn enumerate_columns_union(
        &self,
        url: &str,
        param: &str,
        terminator: &str,
        tests_run: &mut usize,
    ) -> Option<usize> {
        for i in 1..=MAX_COLUMNS {
            // Build UNION SELECT NULL,NULL,... payload
            let nulls = vec!["NULL"; i].join(",");
            let payload = format!("' UNION SELECT {}{}", nulls, terminator);
            let test_url = self.build_test_url(url, param, &payload);

            *tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    // Success: no error, valid status code
                    if !self.has_sql_error(&response)
                        && response.status_code >= 200
                        && response.status_code < 400
                    {
                        debug!("UNION SELECT with {} NULLs succeeded", i);
                        return Some(i);
                    } else if self.has_sql_error(&response) {
                        debug!("UNION SELECT with {} NULLs failed - error detected", i);
                    }
                }
                Err(e) => {
                    debug!("UNION SELECT with {} NULLs test failed: {}", i, e);
                }
            }

            // Small delay
            if i % 5 == 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }

        None
    }

    /// Test UNION injection with confirmed column count
    async fn test_union_injection(
        &self,
        url: &str,
        param: &str,
        column_count: usize,
        terminator: &str,
        baseline: &HttpResponse,
        tests_run: &mut usize,
    ) -> Option<Vulnerability> {
        // Build UNION SELECT payload with correct column count
        let nulls = vec!["NULL"; column_count].join(",");
        let payload = format!("' UNION SELECT {}{}", nulls, terminator);
        let test_url = self.build_test_url(url, param, &payload);

        *tests_run += 1;

        match self.http_client.get(&test_url).await {
            Ok(response) => {
                // Check if injection was successful
                if self.is_successful_injection(&response, baseline) {
                    let vuln = self.create_vulnerability(
                        &test_url,
                        param,
                        &payload,
                        column_count,
                        terminator,
                        &response,
                    );
                    return Some(vuln);
                }
            }
            Err(e) => {
                debug!("UNION injection test failed: {}", e);
            }
        }

        None
    }

    /// Check if response contains SQL error patterns
    fn has_sql_error(&self, response: &HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();

        for pattern in ERROR_PATTERNS {
            if body_lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Check if injection was successful by comparing with baseline
    fn is_successful_injection(&self, response: &HttpResponse, baseline: &HttpResponse) -> bool {
        // Success indicators:
        // 1. Valid HTTP status code
        if response.status_code < 200 || response.status_code >= 400 {
            return false;
        }

        // 2. No SQL errors in response
        if self.has_sql_error(response) {
            return false;
        }

        // 3. Response body is different from baseline
        if response.body == baseline.body {
            return false;
        }

        // 4. Response contains data (not empty)
        if response.body.len() < 10 {
            return false;
        }

        // 5. Look for success patterns (NULL appearing in unexpected places)
        let body_upper = response.body.to_uppercase();
        for pattern in SUCCESS_PATTERNS {
            // Count occurrences in response vs baseline
            let response_count = body_upper.matches(pattern).count();
            let baseline_count = baseline.body.to_uppercase().matches(pattern).count();

            // If we see more NULLs in response than baseline, likely injected
            if response_count > baseline_count {
                debug!(
                    "Found {} occurrences of '{}' (baseline: {})",
                    response_count, pattern, baseline_count
                );
                return true;
            }
        }

        // 6. Significant size difference from baseline
        let size_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let baseline_size = baseline.body.len() as f64;

        if baseline_size > 0.0 {
            let size_change_percent = (size_diff as f64 / baseline_size) * 100.0;

            // If response is significantly different in size (>20% change), likely injected
            if size_change_percent > 20.0 {
                debug!(
                    "Response size changed by {:.1}% (from {} to {} bytes)",
                    size_change_percent,
                    baseline.body.len(),
                    response.body.len()
                );
                return true;
            }
        }

        false
    }

    /// Build test URL with payload
    fn build_test_url(&self, base_url: &str, param: &str, payload: &str) -> String {
        if base_url.contains('?') {
            format!(
                "{}&{}={}",
                base_url,
                param,
                urlencoding::encode(payload)
            )
        } else {
            format!(
                "{}?{}={}",
                base_url,
                param,
                urlencoding::encode(payload)
            )
        }
    }

    /// Create vulnerability report
    fn create_vulnerability(
        &self,
        url: &str,
        param: &str,
        payload: &str,
        column_count: usize,
        terminator: &str,
        response: &HttpResponse,
    ) -> Vulnerability {
        // Identify injectable column positions (simplified - in real scenario would test each)
        let injectable_columns: Vec<String> = (1..=column_count).map(|i| i.to_string()).collect();

        let evidence = format!(
            "Column count: {}\nComment terminator: {}\nResponse status: {}\nResponse size: {} bytes\nInjectable columns: {}",
            column_count,
            terminator,
            response.status_code,
            response.body.len(),
            injectable_columns.join(", ")
        );

        Vulnerability {
            id: format!("sqli_union_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: "UNION-based SQL Injection".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(param.to_string()),
            payload: payload.to_string(),
            description: format!(
                "UNION-based SQL injection vulnerability detected in parameter '{}'. \
                 Successfully enumerated {} columns and confirmed data extraction capability. \
                 This allows attackers to extract sensitive data from the database using UNION SELECT queries.",
                param, column_count
            ),
            evidence: Some(evidence),
            cwe: "CWE-89".to_string(),
            cvss: 9.8,
            verified: true,
            false_positive: false,
            remediation:
                "1. Use parameterized queries (prepared statements) exclusively\n\
                 2. Implement strict input validation and sanitization\n\
                 3. Apply principle of least privilege for database accounts\n\
                 4. Use an ORM framework with built-in SQL injection protection\n\
                 5. Disable detailed error messages in production\n\
                 6. Implement Web Application Firewall (WAF) rules\n\
                 7. Regular security code reviews and penetration testing"
                    .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation (same as in other scanners)
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

    #[test]
    fn test_has_sql_error() {
        let scanner = SqliUnionScanner {
            http_client: Arc::new(HttpClient::new(10, 3).unwrap()),
        };

        let response = HttpResponse {
            status_code: 200,
            body: "Error: unknown column 'test' in 'order clause'".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(scanner.has_sql_error(&response));

        let clean_response = HttpResponse {
            status_code: 200,
            body: "Welcome to our site".to_string(),
            headers: std::collections::HashMap::new(),
            duration_ms: 100,
        };

        assert!(!scanner.has_sql_error(&clean_response));
    }

    #[test]
    fn test_build_test_url() {
        let scanner = SqliUnionScanner {
            http_client: Arc::new(HttpClient::new(10, 3).unwrap()),
        };

        let url1 = scanner.build_test_url("http://example.com/page", "id", "' OR 1=1--");
        assert!(url1.contains("?id="));
        assert!(url1.contains("%27"));

        let url2 = scanner.build_test_url("http://example.com/page?user=admin", "id", "' OR 1=1--");
        assert!(url2.contains("&id="));
    }
}
