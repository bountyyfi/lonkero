// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GraphQL Batching Attack Scanner
 *
 * Production-ready, context-aware scanner for detecting GraphQL batching vulnerabilities:
 * - Batching DoS attacks (array batching, unbounded batch sizes)
 * - Alias-based query amplification attacks
 * - Query complexity abuse via batching
 * - Rate limit bypass through batched operations
 * - Authentication bypass via mixed batch queries
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// GraphQL Batching Attack Scanner
///
/// Detects vulnerabilities related to GraphQL query batching:
/// - Resource exhaustion via unbounded batching
/// - Rate limit bypass through batch operations
/// - Authentication bypass in batch queries
/// - Query complexity amplification
pub struct GraphQlBatchingScanner {
    http_client: Arc<HttpClient>,
}

/// Common GraphQL endpoint paths to probe
const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/graphql/v1",
    "/graphql/v2",
];

/// Result of a batching test
#[derive(Debug)]
struct BatchTestResult {
    endpoint: String,
    batch_size: usize,
    accepted: bool,
    response_time_ms: u64,
    response_count: usize,
    error_message: Option<String>,
}

/// Result of an alias abuse test
#[derive(Debug)]
struct AliasTestResult {
    endpoint: String,
    alias_count: usize,
    accepted: bool,
    response_time_ms: u64,
    multiplier_detected: bool,
}

/// Result of rate limit bypass test
#[derive(Debug)]
struct RateLimitBypassResult {
    endpoint: String,
    queries_in_batch: usize,
    counted_as: CountMethod,
    bypass_successful: bool,
}

#[derive(Debug)]
enum CountMethod {
    SingleRequest,
    MultipleOperations,
    Unknown,
}

/// Result of auth bypass test
#[derive(Debug)]
struct AuthBypassResult {
    endpoint: String,
    partial_execution: bool,
    mixed_auth_allowed: bool,
    failed_atomically: bool,
}

impl GraphQlBatchingScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Main scan entry point
    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[GraphQL Batching] Starting scan on {}", url);

        // License check
        if !crate::license::verify_scan_authorized() {
            warn!("[GraphQL Batching] Scan not authorized - license validation failed");
            return Ok((Vec::new(), 0));
        }

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Step 1: Detect GraphQL endpoint
        tests_run += 1;
        let graphql_endpoint = match self.detect_graphql_endpoint(url).await {
            Some(endpoint) => {
                info!("[GraphQL Batching] GraphQL endpoint detected: {}", endpoint);
                endpoint
            }
            None => {
                // Try context-aware detection
                if let Ok(response) = self.http_client.get(url).await {
                    let characteristics = AppCharacteristics::from_response(&response, url);
                    if !characteristics.is_api {
                        info!("[GraphQL Batching] No GraphQL endpoint detected, skipping scan");
                        return Ok((vulnerabilities, tests_run));
                    }
                }
                info!("[GraphQL Batching] No GraphQL endpoint detected, skipping scan");
                return Ok((vulnerabilities, tests_run));
            }
        };

        // Step 2: Test array-based batching
        tests_run += 5;
        let batch_results = self.test_array_batching(&graphql_endpoint, config).await;
        for result in batch_results {
            if result.accepted && result.batch_size >= 10 {
                vulnerabilities.push(self.create_batch_dos_vulnerability(&result, url));
            }
        }

        // Step 3: Test alias-based attacks
        tests_run += 4;
        let alias_results = self.test_alias_abuse(&graphql_endpoint, config).await;
        for result in alias_results {
            if result.accepted && result.alias_count >= 50 {
                vulnerabilities.push(self.create_alias_abuse_vulnerability(&result, url));
            }
        }

        // Step 4: Test query complexity via batching
        tests_run += 3;
        if let Some(vuln) = self
            .test_complexity_abuse(&graphql_endpoint, url, config)
            .await
        {
            vulnerabilities.push(vuln);
        }

        // Step 5: Test rate limit bypass
        tests_run += 2;
        let rate_limit_result = self.test_rate_limit_bypass(&graphql_endpoint, config).await;
        if let Some(result) = rate_limit_result {
            if result.bypass_successful {
                vulnerabilities.push(self.create_rate_limit_bypass_vulnerability(&result, url));
            }
        }

        // Step 6: Test authentication bypass via batching
        tests_run += 2;
        let auth_bypass_result = self.test_auth_bypass(&graphql_endpoint, config).await;
        if let Some(result) = auth_bypass_result {
            if result.partial_execution || result.mixed_auth_allowed {
                vulnerabilities.push(self.create_auth_bypass_vulnerability(&result, url));
            }
        }

        // Step 7: Test fragment spreading via batching
        tests_run += 2;
        if let Some(vuln) = self
            .test_fragment_spreading(&graphql_endpoint, url, config)
            .await
        {
            vulnerabilities.push(vuln);
        }

        // Step 8: Test mutation batching
        tests_run += 2;
        if let Some(vuln) = self
            .test_mutation_batching(&graphql_endpoint, url, config)
            .await
        {
            vulnerabilities.push(vuln);
        }

        info!(
            "[GraphQL Batching] Completed {} tests, found {} vulnerabilities",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect GraphQL endpoint by probing common paths
    async fn detect_graphql_endpoint(&self, base_url: &str) -> Option<String> {
        let base = base_url.trim_end_matches('/');

        // First check if base URL itself is a GraphQL endpoint
        if self.is_graphql_endpoint(base_url).await {
            return Some(base_url.to_string());
        }

        // Probe common GraphQL paths
        for path in GRAPHQL_PATHS {
            let test_url = format!("{}{}", base, path);
            if self.is_graphql_endpoint(&test_url).await {
                return Some(test_url);
            }
        }

        None
    }

    /// Check if endpoint responds to GraphQL
    async fn is_graphql_endpoint(&self, url: &str) -> bool {
        let introspection_query = json!({
            "query": "query { __typename }"
        });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(url, &introspection_query.to_string(), headers)
            .await
        {
            Ok(response) => {
                // Check for GraphQL-like response
                let body = &response.body;
                let is_graphql = body.contains("\"data\"")
                    || body.contains("\"errors\"")
                    || body.contains("__typename");

                // Exclude HTML responses (SPA fallbacks)
                let is_html = body.contains("<!DOCTYPE")
                    || body.contains("<html")
                    || body.contains("__NEXT_DATA__")
                    || body.contains("__NUXT__");

                is_graphql && !is_html
            }
            Err(_) => false,
        }
    }

    /// Test array-based batch queries with increasing sizes
    async fn test_array_batching(
        &self,
        endpoint: &str,
        _config: &ScanConfig,
    ) -> Vec<BatchTestResult> {
        let mut results = Vec::new();
        let batch_sizes = vec![5, 10, 50, 100, 500];

        for size in batch_sizes {
            let result = self.send_batch_query(endpoint, size).await;
            results.push(result);

            // Stop if server rejects batching
            if results.last().is_some_and(|r| !r.accepted) {
                break;
            }
        }

        results
    }

    /// Send a batch query with specified number of operations
    async fn send_batch_query(&self, endpoint: &str, count: usize) -> BatchTestResult {
        // Build array of queries
        let queries: Vec<Value> = (0..count)
            .map(|i| {
                json!({
                    "query": format!("query Q{} {{ __typename }}", i),
                    "operationName": format!("Q{}", i)
                })
            })
            .collect();

        let batch_payload = Value::Array(queries);

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let start = Instant::now();
        match self
            .http_client
            .post_with_headers(endpoint, &batch_payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let body = &response.body;

                // Count successful responses in batch
                let response_count = body.matches("__typename").count();
                let accepted = response.status_code == 200
                    && (body.starts_with('[') || body.contains("\"data\""));

                let error_message = if body.contains("\"errors\"") {
                    // Extract error message if present
                    if let Ok(json) = serde_json::from_str::<Value>(body) {
                        json.get("errors")
                            .and_then(|e| e.get(0))
                            .and_then(|e| e.get("message"))
                            .and_then(|m| m.as_str())
                            .map(String::from)
                    } else {
                        None
                    }
                } else {
                    None
                };

                BatchTestResult {
                    endpoint: endpoint.to_string(),
                    batch_size: count,
                    accepted,
                    response_time_ms: elapsed,
                    response_count,
                    error_message,
                }
            }
            Err(e) => BatchTestResult {
                endpoint: endpoint.to_string(),
                batch_size: count,
                accepted: false,
                response_time_ms: start.elapsed().as_millis() as u64,
                response_count: 0,
                error_message: Some(e.to_string()),
            },
        }
    }

    /// Test alias-based query amplification
    async fn test_alias_abuse(&self, endpoint: &str, _config: &ScanConfig) -> Vec<AliasTestResult> {
        let mut results = Vec::new();
        let alias_counts = vec![10, 50, 100, 500];

        for count in alias_counts {
            let result = self.send_aliased_query(endpoint, count).await;
            results.push(result);

            if results.last().is_some_and(|r| !r.accepted) {
                break;
            }
        }

        results
    }

    /// Send a query with multiple aliases for the same field
    async fn send_aliased_query(&self, endpoint: &str, count: usize) -> AliasTestResult {
        // Build query with many aliases
        let aliases: Vec<String> = (0..count).map(|i| format!("a{}: __typename", i)).collect();

        let query = format!("query AliasTest {{ {} }}", aliases.join(" "));
        let payload = json!({ "query": query });

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        // Also measure baseline for comparison
        let baseline_start = Instant::now();
        let baseline_query = json!({ "query": "query { __typename }" });
        let _ = self
            .http_client
            .post_with_headers(endpoint, &baseline_query.to_string(), headers.clone())
            .await;
        let baseline_time = baseline_start.elapsed().as_millis() as u64;

        let start = Instant::now();
        match self
            .http_client
            .post_with_headers(endpoint, &payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let body = &response.body;

                let accepted = response.status_code == 200 && body.contains("\"data\"");

                // Check if response time scales with alias count
                let multiplier_detected = elapsed > baseline_time * 5 && count >= 50;

                AliasTestResult {
                    endpoint: endpoint.to_string(),
                    alias_count: count,
                    accepted,
                    response_time_ms: elapsed,
                    multiplier_detected,
                }
            }
            Err(_) => AliasTestResult {
                endpoint: endpoint.to_string(),
                alias_count: count,
                accepted: false,
                response_time_ms: start.elapsed().as_millis() as u64,
                multiplier_detected: false,
            },
        }
    }

    /// Test query complexity abuse via batching
    async fn test_complexity_abuse(
        &self,
        endpoint: &str,
        url: &str,
        _config: &ScanConfig,
    ) -> Option<Vulnerability> {
        // Test deep nesting via batched operations
        let deep_queries: Vec<Value> = (0..10)
            .map(|i| {
                let nested =
                    "user { posts { author { posts { author { posts { author { id } } } } } } }";
                json!({
                    "query": format!("query Deep{} {{ {} }}", i, nested),
                    "operationName": format!("Deep{}", i)
                })
            })
            .collect();

        let payload = Value::Array(deep_queries);

        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let start = Instant::now();
        match self
            .http_client
            .post_with_headers(endpoint, &payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed();
                let body = &response.body;

                // Check for complexity issues
                let has_depth_error = body.to_lowercase().contains("depth")
                    || body.to_lowercase().contains("complexity")
                    || body.to_lowercase().contains("too deep");

                let has_data = body.contains("\"data\"");
                let slow_response = elapsed.as_secs() > 3;

                if (has_data || slow_response) && !has_depth_error {
                    Some(self.create_complexity_vulnerability(
                        endpoint,
                        url,
                        elapsed.as_millis() as u64,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Test if batching bypasses rate limiting
    async fn test_rate_limit_bypass(
        &self,
        endpoint: &str,
        _config: &ScanConfig,
    ) -> Option<RateLimitBypassResult> {
        // First, send 5 individual requests to establish baseline
        let mut individual_count = 0;
        for _ in 0..5 {
            let query = json!({ "query": "query { __typename }" });
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            if let Ok(response) = self
                .http_client
                .post_with_headers(endpoint, &query.to_string(), headers)
                .await
            {
                if response.status_code == 429 {
                    break;
                }
                individual_count += 1;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Now send a batch with 100 queries
        let batch_queries: Vec<Value> = (0..100)
            .map(|i| json!({ "query": format!("query Q{} {{ __typename }}", i) }))
            .collect();

        let batch_payload = Value::Array(batch_queries);
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(endpoint, &batch_payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let body = &response.body;
                let responses_in_batch = body.matches("__typename").count();

                // Determine if batch was counted as 1 or N requests
                let counted_as = if responses_in_batch >= 50 && response.status_code == 200 {
                    CountMethod::SingleRequest
                } else if responses_in_batch < 50 && responses_in_batch > 0 {
                    CountMethod::MultipleOperations
                } else {
                    CountMethod::Unknown
                };

                let bypass_successful =
                    matches!(counted_as, CountMethod::SingleRequest) && responses_in_batch >= 50;

                Some(RateLimitBypassResult {
                    endpoint: endpoint.to_string(),
                    queries_in_batch: 100,
                    counted_as,
                    bypass_successful,
                })
            }
            Err(_) => None,
        }
    }

    /// Test authentication bypass via mixed batch queries
    async fn test_auth_bypass(
        &self,
        endpoint: &str,
        _config: &ScanConfig,
    ) -> Option<AuthBypassResult> {
        // Create batch with mix of public and protected queries
        let mixed_batch = vec![
            json!({ "query": "query Public { __typename }" }),
            json!({ "query": "query Protected { user { id email password } }" }),
            json!({ "query": "query Admin { admin { users { id password } } }" }),
            json!({ "query": "query Public2 { __typename }" }),
        ];

        let payload = Value::Array(mixed_batch);
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        match self
            .http_client
            .post_with_headers(endpoint, &payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let body = &response.body;

                // Check if any protected data was returned
                let has_sensitive =
                    body.contains("password") || body.contains("email") || body.contains("admin");

                // Check if some queries succeeded and others failed
                let has_data = body.contains("\"data\"");
                let has_errors = body.contains("\"errors\"");
                let has_auth_error = body.to_lowercase().contains("unauthorized")
                    || body.to_lowercase().contains("forbidden")
                    || body.to_lowercase().contains("authentication");

                // Partial execution = some succeeded, some failed
                let partial_execution = has_data && has_errors;

                // Mixed auth = batch ran with mix of auth states
                let mixed_auth_allowed = has_sensitive && !has_auth_error;

                // Atomic = all fail if any fail
                let failed_atomically = has_auth_error && !has_data;

                Some(AuthBypassResult {
                    endpoint: endpoint.to_string(),
                    partial_execution,
                    mixed_auth_allowed,
                    failed_atomically,
                })
            }
            Err(_) => None,
        }
    }

    /// Test fragment spreading via batching
    async fn test_fragment_spreading(
        &self,
        endpoint: &str,
        url: &str,
        _config: &ScanConfig,
    ) -> Option<Vulnerability> {
        // Create queries with circular fragment references
        let fragment_query = r#"
            query FragmentSpread {
                ...UserData
                ...UserData
                ...UserData
                ...UserData
                ...UserData
            }
            fragment UserData on Query {
                user {
                    id
                    name
                    friends { ...FriendData }
                }
            }
            fragment FriendData on User {
                id
                friends { ...FriendData2 }
            }
            fragment FriendData2 on User {
                id
                friends { id name }
            }
        "#;

        let queries: Vec<Value> = (0..10)
            .map(|_| json!({ "query": fragment_query }))
            .collect();

        let payload = Value::Array(queries);
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let start = Instant::now();
        match self
            .http_client
            .post_with_headers(endpoint, &payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed();
                let body = &response.body;

                let no_fragment_limit = !body.to_lowercase().contains("fragment")
                    && !body.to_lowercase().contains("depth")
                    && !body.to_lowercase().contains("circular");

                let slow_response = elapsed.as_secs() > 2;

                if (no_fragment_limit && response.status_code == 200) || slow_response {
                    Some(self.create_fragment_vulnerability(
                        endpoint,
                        url,
                        elapsed.as_millis() as u64,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Test mutation batching for race conditions
    async fn test_mutation_batching(
        &self,
        endpoint: &str,
        url: &str,
        _config: &ScanConfig,
    ) -> Option<Vulnerability> {
        // Create batch of identical mutations (race condition test)
        let test_id = format!("batch_test_{}", rand::random::<u32>());
        let mutations: Vec<Value> = (0..20)
            .map(|i| {
                json!({
                    "query": format!(
                        r#"mutation Batch{} {{ updateCounter(id: "{}", increment: 1) {{ id value }} }}"#,
                        i, test_id
                    ),
                    "operationName": format!("Batch{}", i)
                })
            })
            .collect();

        let payload = Value::Array(mutations);
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let start = Instant::now();
        match self
            .http_client
            .post_with_headers(endpoint, &payload.to_string(), headers)
            .await
        {
            Ok(response) => {
                let elapsed = start.elapsed();
                let body = &response.body;

                // Check if mutations were executed in parallel (race condition risk)
                let batch_accepted = response.status_code == 200 && body.starts_with('[');
                let no_rate_limit = !body.to_lowercase().contains("rate limit")
                    && !body.to_lowercase().contains("too many");

                if batch_accepted && no_rate_limit {
                    Some(self.create_mutation_batch_vulnerability(
                        endpoint,
                        url,
                        20,
                        elapsed.as_millis() as u64,
                    ))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    // ========== Vulnerability Creators ==========

    fn create_batch_dos_vulnerability(&self, result: &BatchTestResult, url: &str) -> Vulnerability {
        let poc_queries: Vec<String> = (0..5)
            .map(|i| format!(r#"{{"query":"query Q{} {{ __typename }}"}}"#, i))
            .collect();
        let poc_payload = format!("[{}]", poc_queries.join(","));

        Vulnerability {
            id: format!("graphql_batch_dos_{}", Self::generate_id()),
            vuln_type: "GraphQL Unbounded Batching DoS".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(result.endpoint.clone()),
            payload: poc_payload.clone(),
            description: format!(
                "GraphQL endpoint accepts unbounded batch queries. Successfully executed batch of {} queries in {}ms. \
                This can be exploited for Denial of Service attacks by sending large batches of resource-intensive queries. \
                A single HTTP request can trigger hundreds or thousands of server-side operations, bypassing per-request rate limits.",
                result.batch_size,
                result.response_time_ms
            ),
            evidence: Some(format!(
                "Batch Size: {}\nResponse Time: {}ms\nResponses Received: {}\nEndpoint: {}",
                result.batch_size,
                result.response_time_ms,
                result.response_count,
                result.endpoint
            )),
            cwe: "CWE-400".to_string(),
            cvss: 5.5,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTIONS REQUIRED:

1. **Limit Batch Size**
   ```javascript
   // Apollo Server
   const server = new ApolloServer({
     allowBatchedHttpRequests: true,
     plugins: [
       {
         requestDidStart: () => ({
           didResolveOperation: (context) => {
             // Limit to 10 operations per batch
             if (context.document.definitions.length > 10) {
               throw new Error('Batch size exceeds limit');
             }
           }
         })
       }
     ]
   });
   ```

2. **Disable Batching in Production**
   ```javascript
   const server = new ApolloServer({
     allowBatchedHttpRequests: false
   });
   ```

3. **Implement Query Cost Analysis**
   - Calculate cost per query in batch
   - Reject batches exceeding total cost limit
   - Use graphql-cost-analysis or similar library

4. **Rate Limit by Operation Count**
   - Count each operation in batch separately
   - Apply rate limits per operation, not per request

5. **Monitor and Alert**
   - Log batch sizes
   - Alert on unusually large batches
   - Track resource consumption per batch

References:
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Apollo Server Security: https://www.apollographql.com/docs/apollo-server/security/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_alias_abuse_vulnerability(
        &self,
        result: &AliasTestResult,
        url: &str,
    ) -> Vulnerability {
        let aliases: Vec<String> = (0..10).map(|i| format!("a{}: __typename", i)).collect();
        let poc_query = format!("query {{ {} }}", aliases.join(" "));

        Vulnerability {
            id: format!("graphql_alias_abuse_{}", Self::generate_id()),
            vuln_type: "GraphQL Alias Abuse Attack".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(result.endpoint.clone()),
            payload: format!(r#"{{"query":"{}"}}"#, poc_query),
            description: format!(
                "GraphQL endpoint allows excessive aliases in a single query. Successfully executed {} aliases in {}ms. \
                Aliases can be used to multiply the execution of expensive resolvers within a single request, \
                bypassing query count limits and causing resource exhaustion. {}",
                result.alias_count,
                result.response_time_ms,
                if result.multiplier_detected {
                    "Response time scaling detected - server processes each alias separately."
                } else {
                    "No response time scaling detected, but alias count indicates potential abuse vector."
                }
            ),
            evidence: Some(format!(
                "Alias Count: {}\nResponse Time: {}ms\nMultiplier Detected: {}\nEndpoint: {}",
                result.alias_count,
                result.response_time_ms,
                result.multiplier_detected,
                result.endpoint
            )),
            cwe: "CWE-770".to_string(),
            cvss: 5.5,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTIONS REQUIRED:

1. **Limit Alias Count**
   ```javascript
   // Custom validation rule
   const aliasLimitRule = (context) => ({
     Field(node) {
       const aliases = context.getDocument().definitions
         .flatMap(d => d.selectionSet?.selections || [])
         .filter(s => s.alias);

       if (aliases.length > 20) {
         context.reportError(new GraphQLError('Too many aliases'));
       }
     }
   });
   ```

2. **Implement Query Complexity Analysis**
   - Count aliases as multipliers in complexity calculation
   - Each alias should add to the query cost

3. **Field-Level Rate Limiting**
   ```graphql
   type Query {
     expensiveOperation: Result @rateLimit(limit: 10, duration: 60)
   }
   ```

4. **Use Persisted Queries**
   - Only allow pre-approved queries
   - Prevents arbitrary alias injection

5. **Response Size Limits**
   - Limit maximum response size
   - Prevents large alias-amplified responses

References:
- GraphQL Alias Attacks: https://escape.tech/blog/graphql-alias-attacks/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_complexity_vulnerability(
        &self,
        endpoint: &str,
        url: &str,
        response_time_ms: u64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("graphql_complexity_batch_{}", Self::generate_id()),
            vuln_type: "GraphQL Complexity Abuse via Batching".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(endpoint.to_string()),
            payload: r#"[{"query":"query{user{posts{author{posts{author{id}}}}}}"},...]"#.to_string(),
            description: format!(
                "GraphQL endpoint allows batched complex/deeply nested queries without complexity limits. \
                Response time: {}ms. Multiple deeply nested queries can be batched together to multiply \
                the resource consumption, potentially causing exponential server load.",
                response_time_ms
            ),
            evidence: Some(format!(
                "Batched 10 deeply nested queries (6 levels deep)\nResponse Time: {}ms\nNo complexity limits detected\nEndpoint: {}",
                response_time_ms,
                endpoint
            )),
            cwe: "CWE-400".to_string(),
            cvss: 6.5,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTIONS REQUIRED:

1. **Implement Query Depth Limiting**
   ```javascript
   const depthLimit = require('graphql-depth-limit');

   const server = new ApolloServer({
     validationRules: [depthLimit(10)]
   });
   ```

2. **Implement Query Complexity Analysis**
   ```javascript
   const { createComplexityLimitRule } = require('graphql-validation-complexity');

   const server = new ApolloServer({
     validationRules: [
       createComplexityLimitRule(1000, {
         scalarCost: 1,
         objectCost: 10,
         listFactor: 20
       })
     ]
   });
   ```

3. **Apply Aggregate Limits to Batches**
   - Sum complexity across all queries in batch
   - Reject if total exceeds threshold

4. **Timeout Expensive Operations**
   - Set resolver-level timeouts
   - Cancel long-running queries

References:
- GraphQL Query Complexity: https://www.apollographql.com/docs/apollo-server/security/performance/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_rate_limit_bypass_vulnerability(
        &self,
        result: &RateLimitBypassResult,
        url: &str,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("graphql_rate_limit_bypass_{}", Self::generate_id()),
            vuln_type: "GraphQL Rate Limit Bypass via Batching".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(result.endpoint.clone()),
            payload: format!(
                r#"[{{"query":"query{{__typename}}"}},...] (x{})"#,
                result.queries_in_batch
            ),
            description: format!(
                "GraphQL endpoint rate limiting can be bypassed using batch queries. \
                A batch of {} queries was counted as a single request, allowing an attacker \
                to multiply their effective request rate. This defeats per-request rate limiting \
                and enables brute force attacks, credential stuffing, or enumeration at scale.",
                result.queries_in_batch
            ),
            evidence: Some(format!(
                "Queries in Batch: {}\nCounted As: {:?}\nBypass Successful: {}\nEndpoint: {}",
                result.queries_in_batch,
                result.counted_as,
                result.bypass_successful,
                result.endpoint
            )),
            cwe: "CWE-770".to_string(),
            cvss: 7.0,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTIONS REQUIRED:

1. **Count Operations, Not Requests**
   ```javascript
   // Rate limit middleware
   const rateLimitPlugin = {
     requestDidStart: () => ({
       didResolveOperation: async (context) => {
         const operationCount = context.document.definitions.length;

         // Apply rate limit per operation
         for (let i = 0; i < operationCount; i++) {
           await rateLimiter.consume(context.request.ip);
         }
       }
     })
   };
   ```

2. **Limit Batch Size Strictly**
   - Maximum 5-10 operations per batch
   - Reject larger batches entirely

3. **Implement Cost-Based Rate Limiting**
   - Calculate query cost before execution
   - Rate limit based on cumulative cost

4. **Per-Resolver Rate Limiting**
   ```graphql
   type Query {
     login(email: String!, password: String!): AuthPayload @rateLimit(
       window: "1m",
       max: 5,
       message: "Too many login attempts"
     )
   }
   ```

5. **Monitor Batch Patterns**
   - Alert on unusual batch sizes
   - Track batch rate per client

References:
- GraphQL Rate Limiting: https://escape.tech/blog/graphql-rate-limiting/
"#
            .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_auth_bypass_vulnerability(
        &self,
        result: &AuthBypassResult,
        url: &str,
    ) -> Vulnerability {
        let severity = if result.mixed_auth_allowed {
            Severity::High
        } else {
            Severity::Medium
        };

        Vulnerability {
            id: format!("graphql_auth_bypass_batch_{}", Self::generate_id()),
            vuln_type: "GraphQL Authentication Bypass via Batching".to_string(),
            severity,
            confidence: Confidence::Medium,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(result.endpoint.clone()),
            payload: r#"[{"query":"query{__typename}"},{"query":"query{user{password}}"}]"#.to_string(),
            description: format!(
                "GraphQL batch queries may bypass authentication controls. \
                Partial Execution: {}, Mixed Auth Allowed: {}, Failed Atomically: {}. \
                {}",
                result.partial_execution,
                result.mixed_auth_allowed,
                result.failed_atomically,
                if result.partial_execution {
                    "Batch queries are executed partially - some succeed while others fail. \
                    This can leak information about authentication state and allow mixing of contexts."
                } else if result.mixed_auth_allowed {
                    "Protected queries returned sensitive data without proper authentication in batch context."
                } else {
                    "Batch queries do not fail atomically, potentially leaking authorization state."
                }
            ),
            evidence: Some(format!(
                "Partial Execution: {}\nMixed Auth Allowed: {}\nFailed Atomically: {}\nEndpoint: {}",
                result.partial_execution,
                result.mixed_auth_allowed,
                result.failed_atomically,
                result.endpoint
            )),
            cwe: "CWE-862".to_string(),
            cvss: if result.mixed_auth_allowed { 7.5 } else { 5.5 },
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTIONS REQUIRED:

1. **Atomic Batch Execution**
   - All queries in batch should fail if any lacks authorization
   - Use transaction-like semantics for batches

2. **Consistent Authentication Context**
   ```javascript
   // Apply auth to entire batch
   const authPlugin = {
     requestDidStart: () => ({
       willSendResponse: (context) => {
         // Verify auth for all operations
         const allAuthorized = context.operationResults.every(
           result => result.authorized
         );

         if (!allAuthorized) {
           throw new AuthenticationError('Unauthorized');
         }
       }
     })
   };
   ```

3. **Field-Level Authorization**
   - Apply @auth directives to sensitive fields
   - Check auth before resolver execution

4. **Disable Mixed Auth Batches**
   - Reject batches mixing public and protected queries
   - Require consistent auth level across batch

5. **Audit Batch Authorization**
   - Log all batch query authorization decisions
   - Alert on partial authorization failures

References:
- GraphQL Authorization: https://www.apollographql.com/docs/apollo-server/security/authentication/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_fragment_vulnerability(
        &self,
        endpoint: &str,
        url: &str,
        response_time_ms: u64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("graphql_fragment_batch_{}", Self::generate_id()),
            vuln_type: "GraphQL Fragment Spreading Abuse via Batching".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(endpoint.to_string()),
            payload: r#"[{"query":"query{...F} fragment F on Query{user{friends{...G}}} fragment G on User{id}"}]"#.to_string(),
            description: format!(
                "GraphQL endpoint allows batched queries with fragment spreading that may bypass depth limits. \
                Response time: {}ms. Fragment spreading can be used to create complex queries that evade \
                simple depth checks, especially when combined with batching.",
                response_time_ms
            ),
            evidence: Some(format!(
                "Batched 10 fragment-heavy queries\nResponse Time: {}ms\nNo fragment limits detected\nEndpoint: {}",
                response_time_ms,
                endpoint
            )),
            cwe: "CWE-674".to_string(),
            cvss: 5.0,
            verified: true,
            false_positive: false,
            remediation: r#"ACTIONS REQUIRED:

1. **Limit Fragment Depth**
   - Track depth through fragment spreads
   - Count fragment references towards depth limit

2. **Detect Circular Fragments**
   - Reject queries with circular fragment references
   - Validate fragment graph before execution

3. **Fragment Count Limits**
   - Limit number of fragments per query
   - Limit fragment spread count per selection

4. **Use Schema-Based Complexity**
   - Calculate complexity including fragments
   - Weight fragments by their resolved complexity

References:
- GraphQL Fragment Attacks: https://escape.tech/blog/graphql-fragment-attacks/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    fn create_mutation_batch_vulnerability(
        &self,
        endpoint: &str,
        url: &str,
        mutation_count: usize,
        response_time_ms: u64,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("graphql_mutation_batch_{}", Self::generate_id()),
            vuln_type: "GraphQL Mutation Batching Attack".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: Some(endpoint.to_string()),
            payload: format!(r#"[{{"query":"mutation{{update(id:1){{id}}}}"}},...] (x{})"#, mutation_count),
            description: format!(
                "GraphQL endpoint allows batched mutations without rate limiting. \
                {} mutations executed in {}ms. Batched mutations can be exploited for \
                race conditions (TOCTOU), bulk operations abuse, or bypassing per-mutation limits.",
                mutation_count,
                response_time_ms
            ),
            evidence: Some(format!(
                "Mutations in Batch: {}\nResponse Time: {}ms\nNo rate limiting detected\nEndpoint: {}",
                mutation_count,
                response_time_ms,
                endpoint
            )),
            cwe: "CWE-770".to_string(),
            cvss: 5.5,
            verified: true,
            false_positive: false,
            remediation: r#"ACTIONS REQUIRED:

1. **Disable Mutation Batching**
   ```javascript
   // Reject batches containing mutations
   const noMutationBatchPlugin = {
     requestDidStart: () => ({
       didResolveOperation: (context) => {
         const hasMutation = context.operation.operation === 'mutation';
         const isBatch = Array.isArray(context.request.query);

         if (hasMutation && isBatch) {
           throw new Error('Mutation batching is not allowed');
         }
       }
     })
   };
   ```

2. **Sequential Mutation Execution**
   - Process mutations in order, not parallel
   - Prevent race conditions

3. **Per-Mutation Rate Limiting**
   - Apply rate limits to each mutation separately
   - Track mutation frequency per user

4. **Idempotency Keys**
   - Require idempotency keys for mutations
   - Prevent duplicate operations

References:
- GraphQL Mutation Security: https://www.apollographql.com/docs/apollo-server/security/
"#.to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_confidence: None,
                ml_data: None,
        }
    }

    /// Generate unique ID
    fn generate_id() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        format!("{:08x}{:08x}", rng.random::<u32>(), rng.random::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_scanner() -> GraphQlBatchingScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        GraphQlBatchingScanner::new(client)
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = create_test_scanner();
        assert!(Arc::strong_count(&scanner.http_client) > 0);
    }

    #[test]
    fn test_batch_test_result() {
        let result = BatchTestResult {
            endpoint: "https://example.com/graphql".to_string(),
            batch_size: 100,
            accepted: true,
            response_time_ms: 500,
            response_count: 100,
            error_message: None,
        };

        assert!(result.accepted);
        assert_eq!(result.batch_size, 100);
        assert_eq!(result.response_count, 100);
    }

    #[test]
    fn test_alias_test_result() {
        let result = AliasTestResult {
            endpoint: "https://example.com/graphql".to_string(),
            alias_count: 50,
            accepted: true,
            response_time_ms: 1000,
            multiplier_detected: true,
        };

        assert!(result.accepted);
        assert!(result.multiplier_detected);
    }

    #[test]
    fn test_rate_limit_bypass_result() {
        let result = RateLimitBypassResult {
            endpoint: "https://example.com/graphql".to_string(),
            queries_in_batch: 100,
            counted_as: CountMethod::SingleRequest,
            bypass_successful: true,
        };

        assert!(result.bypass_successful);
        assert!(matches!(result.counted_as, CountMethod::SingleRequest));
    }

    #[test]
    fn test_auth_bypass_result() {
        let result = AuthBypassResult {
            endpoint: "https://example.com/graphql".to_string(),
            partial_execution: true,
            mixed_auth_allowed: false,
            failed_atomically: false,
        };

        assert!(result.partial_execution);
        assert!(!result.mixed_auth_allowed);
    }

    #[test]
    fn test_generate_id() {
        let id1 = GraphQlBatchingScanner::generate_id();
        let id2 = GraphQlBatchingScanner::generate_id();

        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_vulnerability_creation() {
        let scanner = create_test_scanner();

        let result = BatchTestResult {
            endpoint: "https://example.com/graphql".to_string(),
            batch_size: 100,
            accepted: true,
            response_time_ms: 500,
            response_count: 100,
            error_message: None,
        };

        let vuln = scanner.create_batch_dos_vulnerability(&result, "https://example.com");

        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.cwe, "CWE-400");
        assert!(vuln.description.contains("100 queries"));
    }

    #[test]
    fn test_alias_vulnerability_creation() {
        let scanner = create_test_scanner();

        let result = AliasTestResult {
            endpoint: "https://example.com/graphql".to_string(),
            alias_count: 100,
            accepted: true,
            response_time_ms: 2000,
            multiplier_detected: true,
        };

        let vuln = scanner.create_alias_abuse_vulnerability(&result, "https://example.com");

        assert_eq!(vuln.severity, Severity::Medium);
        assert_eq!(vuln.cwe, "CWE-770");
        assert!(vuln.description.contains("100 aliases"));
    }
}
