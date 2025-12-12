// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Boolean-based Blind SQL Injection Scanner
 * Advanced blind SQLi detection using boolean logic differential analysis
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Boolean-based blind SQL injection scanner
pub struct SqliBooleanScanner {
    http_client: Arc<HttpClient>,
}

/// Payload pair for boolean-based blind SQLi testing
#[derive(Clone)]
struct BooleanPayloadPair {
    true_payload: &'static str,
    false_payload: &'static str,
    db_type: &'static str,
    description: &'static str,
}

impl SqliBooleanScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Get boolean-based blind SQLi payload pairs for multiple databases
    fn get_payload_pairs() -> Vec<BooleanPayloadPair> {
        vec![
            // MySQL / MariaDB payloads
            BooleanPayloadPair {
                true_payload: "' AND '1'='1",
                false_payload: "' AND '1'='2",
                db_type: "MySQL/MariaDB",
                description: "Basic string comparison",
            },
            BooleanPayloadPair {
                true_payload: "' AND 1=1--",
                false_payload: "' AND 1=2--",
                db_type: "MySQL/Generic",
                description: "Numeric comparison with comment",
            },
            BooleanPayloadPair {
                true_payload: "' OR '1'='1",
                false_payload: "' OR '1'='2",
                db_type: "MySQL/Generic",
                description: "OR-based string comparison",
            },
            BooleanPayloadPair {
                true_payload: "' AND 'a'='a",
                false_payload: "' AND 'a'='b",
                db_type: "Generic",
                description: "Character comparison",
            },
            // Double quote variants
            BooleanPayloadPair {
                true_payload: "\" AND \"1\"=\"1",
                false_payload: "\" AND \"1\"=\"2",
                db_type: "Generic",
                description: "Double quote string comparison",
            },
            // Parenthesis bypass
            BooleanPayloadPair {
                true_payload: "') AND ('1'='1",
                false_payload: "') AND ('1'='2",
                db_type: "Generic",
                description: "Parenthesis bypass",
            },
            // PostgreSQL specific
            BooleanPayloadPair {
                true_payload: "' AND '1'='1'--",
                false_payload: "' AND '1'='2'--",
                db_type: "PostgreSQL",
                description: "PostgreSQL comment syntax",
            },
            // MSSQL specific
            BooleanPayloadPair {
                true_payload: "' AND 1=1;--",
                false_payload: "' AND 1=2;--",
                db_type: "MSSQL",
                description: "MSSQL semicolon terminator",
            },
            // Oracle specific
            BooleanPayloadPair {
                true_payload: "' AND '1'='1'||'",
                false_payload: "' AND '1'='2'||'",
                db_type: "Oracle",
                description: "Oracle concatenation",
            },
            // Advanced bypass techniques
            BooleanPayloadPair {
                true_payload: "' AND 'x'='x",
                false_payload: "' AND 'x'='y",
                db_type: "Generic",
                description: "Alternative character comparison",
            },
            BooleanPayloadPair {
                true_payload: "' AND '1'LIKE'1",
                false_payload: "' AND '1'LIKE'2",
                db_type: "Generic",
                description: "LIKE operator comparison",
            },
            // Numeric parameter variants
            BooleanPayloadPair {
                true_payload: " AND 1=1",
                false_payload: " AND 1=2",
                db_type: "Generic",
                description: "Numeric context (no quotes)",
            },
        ]
    }

    /// Scan a parameter for boolean-based blind SQL injection vulnerabilities
    pub async fn scan_parameter(
        &self,
        url: &str,
        param: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License verification
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }

        info!(
            "Testing parameter '{}' for boolean-based blind SQLi",
            param
        );

        let mut vulnerabilities = Vec::new();
        let payload_pairs = Self::get_payload_pairs();
        let total_tests = payload_pairs.len() * 2; // Each pair = 2 requests (true + false)

        // Step 1: Get baseline response (no payload)
        let baseline_response = match self.http_client.get(url).await {
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

        debug!(
            "Baseline response: status={}, length={}",
            baseline_response.status_code,
            baseline_response.body.len()
        );

        // Step 2: Test each payload pair
        for pair in payload_pairs {
            // Early termination for fast mode
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                debug!("Fast mode: vulnerability found, skipping remaining tests");
                break;
            }

            // Build test URLs
            let true_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(pair.true_payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(pair.true_payload))
            };

            let false_url = if url.contains('?') {
                format!(
                    "{}&{}={}",
                    url,
                    param,
                    urlencoding::encode(pair.false_payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    url,
                    param,
                    urlencoding::encode(pair.false_payload)
                )
            };

            // Send TRUE condition request
            let true_response = match self.http_client.get(&true_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("True payload request failed: {}", e);
                    continue;
                }
            };

            // Send FALSE condition request
            let false_response = match self.http_client.get(&false_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("False payload request failed: {}", e);
                    continue;
                }
            };

            // Step 3: Differential analysis
            let db_type = pair.db_type.clone();
            let description = pair.description.clone();
            let vulnerability = self.analyze_boolean_responses(
                url,
                param,
                &baseline_response,
                &true_response,
                &false_response,
                pair,
            );

            if let Some(vuln) = vulnerability {
                info!(
                    "Boolean-based blind SQLi detected: {} ({})",
                    db_type, description
                );
                vulnerabilities.push(vuln);

                // In normal/fast mode, stop after first finding
                if config.scan_mode.as_str() != "thorough"
                    && config.scan_mode.as_str() != "insane"
                {
                    break;
                }
            }
        }

        Ok((vulnerabilities, total_tests))
    }

    /// Analyze boolean-based blind SQLi responses using differential comparison
    ///
    /// Detection Logic:
    /// 1. Compare TRUE response to baseline (should be similar)
    /// 2. Compare FALSE response to baseline (should differ)
    /// 3. Compare TRUE response to FALSE response (should differ)
    /// 4. If TRUE ≈ baseline AND FALSE ≠ baseline AND TRUE ≠ FALSE -> VULNERABLE
    fn analyze_boolean_responses(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        true_response: &HttpResponse,
        false_response: &HttpResponse,
        pair: BooleanPayloadPair,
    ) -> Option<Vulnerability> {
        // Calculate response similarities
        let true_to_baseline_similarity =
            self.calculate_similarity(baseline, true_response);
        let false_to_baseline_similarity =
            self.calculate_similarity(baseline, false_response);
        let true_to_false_similarity =
            self.calculate_similarity(true_response, false_response);

        debug!(
            "Similarity analysis for {}: true/baseline={:.2}%, false/baseline={:.2}%, true/false={:.2}%",
            pair.db_type,
            true_to_baseline_similarity * 100.0,
            false_to_baseline_similarity * 100.0,
            true_to_false_similarity * 100.0
        );

        // Boolean-based blind SQLi detection criteria:
        // 1. TRUE response should be very similar to baseline (>85% similarity)
        // 2. FALSE response should differ from baseline (<70% similarity)
        // 3. TRUE and FALSE responses should differ from each other (<70% similarity)
        let true_matches_baseline = true_to_baseline_similarity > 0.85;
        let false_differs_from_baseline = false_to_baseline_similarity < 0.70;
        let true_differs_from_false = true_to_false_similarity < 0.70;

        // Additional check: status codes should be consistent
        let status_codes_consistent = true_response.status_code == baseline.status_code
            || true_response.status_code == 200;

        // Check for classic SQLi error messages that increase confidence
        let has_sql_error = self.has_sql_error_indicators(true_response)
            || self.has_sql_error_indicators(false_response);

        // Determine if vulnerable
        let is_vulnerable = true_matches_baseline
            && false_differs_from_baseline
            && true_differs_from_false
            && status_codes_consistent;

        if is_vulnerable {
            // Calculate confidence based on various factors
            let confidence = if has_sql_error {
                Confidence::High
            } else if true_to_baseline_similarity > 0.95
                && false_to_baseline_similarity < 0.50
            {
                Confidence::High
            } else if true_to_baseline_similarity > 0.90
                && false_to_baseline_similarity < 0.60
            {
                Confidence::Medium
            } else {
                Confidence::Low
            };

            // Build evidence string
            let evidence = format!(
                "Boolean-based blind SQLi detected:\n\
                - TRUE condition similarity to baseline: {:.1}%\n\
                - FALSE condition similarity to baseline: {:.1}%\n\
                - TRUE/FALSE response difference: {:.1}%\n\
                - Database type: {}\n\
                - Technique: {}\n\
                {}",
                true_to_baseline_similarity * 100.0,
                false_to_baseline_similarity * 100.0,
                (1.0 - true_to_false_similarity) * 100.0,
                pair.db_type,
                pair.description,
                if has_sql_error {
                    "- SQL error messages detected in response"
                } else {
                    ""
                }
            );

            Some(Vulnerability {
                id: format!("sqli_boolean_{}", Self::generate_id()),
                vuln_type: "Boolean-based Blind SQL Injection".to_string(),
                severity: Severity::Critical,
                confidence,
                category: "Injection".to_string(),
                url: url.to_string(),
                parameter: Some(param.to_string()),
                payload: format!(
                    "TRUE: {} | FALSE: {}",
                    pair.true_payload, pair.false_payload
                ),
                description: format!(
                    "Boolean-based blind SQL injection vulnerability detected in parameter '{}'. \
                    The application's response varies based on TRUE/FALSE SQL conditions, \
                    allowing an attacker to extract data byte-by-byte through boolean logic. \
                    Detected database type: {}.",
                    param, pair.db_type
                ),
                evidence: Some(evidence),
                cwe: "CWE-89".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation: "1. Use parameterized queries/prepared statements exclusively\n\
                              2. Implement strict input validation and sanitization\n\
                              3. Apply principle of least privilege for database accounts\n\
                              4. Use an ORM framework with built-in SQLi protection\n\
                              5. Enable SQL query logging and monitoring\n\
                              6. Implement Web Application Firewall (WAF) rules\n\
                              7. Regularly audit database queries for injection vulnerabilities"
                    .to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    /// Calculate similarity between two HTTP responses
    ///
    /// Uses multiple factors:
    /// - Body length similarity
    /// - Status code match
    /// - Content similarity (using simple ratio)
    fn calculate_similarity(
        &self,
        response_a: &HttpResponse,
        response_b: &HttpResponse,
    ) -> f64 {
        // Factor 1: Status code match (25% weight)
        let status_similarity = if response_a.status_code == response_b.status_code {
            1.0
        } else {
            0.0
        };

        // Factor 2: Body length similarity (25% weight)
        let len_a = response_a.body.len() as f64;
        let len_b = response_b.body.len() as f64;
        let max_len = len_a.max(len_b);
        let min_len = len_a.min(len_b);

        let length_similarity = if max_len == 0.0 {
            1.0
        } else {
            min_len / max_len
        };

        // Factor 3: Content similarity using character-level comparison (50% weight)
        let content_similarity = self.calculate_content_similarity(
            &response_a.body,
            &response_b.body,
        );

        // Weighted average
        (status_similarity * 0.25) + (length_similarity * 0.25) + (content_similarity * 0.50)
    }

    /// Calculate content similarity using simple character matching
    fn calculate_content_similarity(&self, text_a: &str, text_b: &str) -> f64 {
        if text_a.is_empty() && text_b.is_empty() {
            return 1.0;
        }

        if text_a.is_empty() || text_b.is_empty() {
            return 0.0;
        }

        // For performance, compare first 5000 characters
        let sample_a = if text_a.len() > 5000 {
            &text_a[..5000]
        } else {
            text_a
        };
        let sample_b = if text_b.len() > 5000 {
            &text_b[..5000]
        } else {
            text_b
        };

        // Count matching characters in the same positions
        let matches = sample_a
            .chars()
            .zip(sample_b.chars())
            .filter(|(a, b)| a == b)
            .count();

        let max_len = sample_a.len().max(sample_b.len());

        if max_len == 0 {
            1.0
        } else {
            matches as f64 / max_len as f64
        }
    }

    /// Check if response contains SQL error indicators
    fn has_sql_error_indicators(&self, response: &HttpResponse) -> bool {
        let sql_error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "Microsoft SQL Server",
            "SQLite",
            "syntax error",
            "Warning: mysql",
            "pg_query",
            "mysqli",
            "SQLSTATE",
            "SQL Server",
            "OleDbException",
            "SqlException",
            "PDOException",
            "org.postgresql",
            "oracle.jdbc",
            "SQLServer JDBC",
            "SQL error",
            "database error",
        ];

        sql_error_patterns
            .iter()
            .any(|pattern| response.body.contains(pattern))
    }

    /// Generate unique ID for vulnerability
    fn generate_id() -> String {
        use rand::Rng;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_pairs_valid() {
        let pairs = SqliBooleanScanner::get_payload_pairs();
        assert!(!pairs.is_empty());

        for pair in pairs {
            assert!(!pair.true_payload.is_empty());
            assert!(!pair.false_payload.is_empty());
            assert!(!pair.db_type.is_empty());
            assert!(!pair.description.is_empty());
            assert_ne!(pair.true_payload, pair.false_payload);
        }
    }

    #[test]
    fn test_content_similarity() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = SqliBooleanScanner::new(client);

        // Identical strings
        assert_eq!(scanner.calculate_content_similarity("hello", "hello"), 1.0);

        // Completely different
        let sim = scanner.calculate_content_similarity("abc", "xyz");
        assert!(sim < 0.5);

        // Partially similar
        let sim = scanner.calculate_content_similarity("hello world", "hello there");
        assert!(sim > 0.4 && sim < 0.8);

        // Empty strings
        assert_eq!(scanner.calculate_content_similarity("", ""), 1.0);
    }
}
