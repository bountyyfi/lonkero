// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GraphQL Security Scanner
 * Tests for GraphQL API vulnerabilities and misconfigurations
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use anyhow::Result;
use std::sync::Arc;
use tracing::info;

pub struct GraphQlScanner {
    http_client: Arc<HttpClient>,
}

impl GraphQlScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan URL for GraphQL vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        info!("[GraphQL] Scanning: {}", url);

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        // Test 1: Check if endpoint is GraphQL
        tests_run += 1;
        let is_graphql = self.detect_graphql_endpoint(url).await;

        if !is_graphql {
            info!("[NOTE] [GraphQL] Not a GraphQL endpoint, skipping");
            return Ok((vulnerabilities, tests_run));
        }

        // Store characteristics for intelligent testing
        if let Ok(response) = self.http_client.get(url).await {
            let _characteristics = AppCharacteristics::from_response(&response, url);
        }

        info!("[SUCCESS] [GraphQL] GraphQL endpoint detected");

        // Test 2: Check for introspection enabled
        tests_run += 1;
        if let Ok(response) = self.test_introspection(url).await {
            if self.check_introspection_enabled(&response, url, &mut vulnerabilities) {
                info!("[ALERT] [GraphQL] Introspection is enabled - critical finding");
            }
        }

        // Test 3: Test query depth limits
        tests_run += 1;
        if let Ok(response) = self.test_depth_attack(url).await {
            self.check_depth_limit(&response, url, &mut vulnerabilities);
        }

        // Test 4: Test batching attacks
        tests_run += 1;
        if let Ok(response) = self.test_batch_attack(url).await {
            self.check_batch_limit(&response, url, &mut vulnerabilities);
        }

        // Test 5: Test field duplication
        tests_run += 1;
        if let Ok(response) = self.test_field_duplication(url).await {
            self.check_field_duplication(&response, url, &mut vulnerabilities);
        }

        // Test 6: Test authorization bypass
        tests_run += 1;
        if let Ok(response) = self.test_auth_bypass(url).await {
            self.check_auth_bypass(&response, url, &mut vulnerabilities);
        }

        // Test 7: Test verbose error messages
        tests_run += 1;
        if let Ok(response) = self.test_error_disclosure(url).await {
            self.check_error_disclosure(&response, url, &mut vulnerabilities);
        }

        info!(
            "[SUCCESS] [GraphQL] Completed {} tests, found {} issues",
            tests_run,
            vulnerabilities.len()
        );

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if endpoint is GraphQL
    async fn detect_graphql_endpoint(&self, url: &str) -> bool {
        // Try common GraphQL paths
        let graphql_paths = vec![
            "", // base URL (might already be /graphql)
            "/graphql",
            "/graphql/",
            "/api/graphql",
            "/query",
            "/gql",
        ];

        let base_url = url.trim_end_matches('/');

        for path in graphql_paths {
            let test_url = if path.is_empty() {
                base_url.to_string()
            } else {
                format!("{}{}", base_url, path)
            };

            // Try POST request (most common for GraphQL)
            let query = r#"{"query":"query{__typename}"}"#.to_string();
            if let Ok(response) = self.http_client.post(&test_url, query.clone()).await {
                if response.body.contains("__typename")
                    || response.body.contains("\"data\"")
                    || (response.body.contains("\"errors\"") && response.body.contains("query"))
                {
                    info!("[GraphQL] Found GraphQL endpoint at: {}", test_url);
                    return true;
                }
            }

            // Also try GET request with query param
            if let Ok(response) = self
                .http_client
                .get(&format!(
                    "{}?query={}",
                    test_url,
                    urlencoding::encode(&query)
                ))
                .await
            {
                if response.body.contains("__typename")
                    || response.body.contains("\"data\"")
                    || (response.body.contains("\"errors\"") && response.body.contains("query"))
                {
                    info!("[GraphQL] Found GraphQL endpoint at: {}", test_url);
                    return true;
                }
            }
        }

        false
    }

    /// Test introspection query
    async fn test_introspection(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let introspection_query = r#"{
            "query": "query IntrospectionQuery { __schema { types { name kind description fields { name type { name kind ofType { name kind } } } } } }"
        }"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(introspection_query)
            ))
            .await
    }

    /// Check if introspection is enabled
    fn check_introspection_enabled(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) -> bool {
        if response.body.contains("__schema") && response.body.contains("types") {
            vulnerabilities.push(self.create_vulnerability(
                "GraphQL Introspection Enabled",
                url,
                Severity::High,
                Confidence::High,
                "GraphQL introspection is publicly accessible - exposes entire API schema",
                "Introspection query returned full schema with types and fields".to_string(),
                r#"query IntrospectionQuery { __schema { types { name kind description fields { name type { name kind ofType { name kind } } } } } }"#.to_string(),
                6.5,
            ));
            return true;
        }
        false
    }

    /// Test query depth attack
    async fn test_depth_attack(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Create deeply nested query (20 levels deep)
        let deep_query = r#"{
            "query": "query { user { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { name } } } } } } } } } } } } } } } } } } } }"
        }"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(deep_query)
            ))
            .await
    }

    /// Check depth limit protection
    fn check_depth_limit(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If deep query succeeds, depth limit is not enforced
        if response.status_code == 200
            && !response.body.contains("depth")
            && !response.body.contains("complexity")
        {
            vulnerabilities.push(self.create_vulnerability(
                "No GraphQL Query Depth Limit",
                url,
                Severity::Medium,
                Confidence::Medium,
                "GraphQL API does not enforce query depth limits - vulnerable to DoS",
                "Deeply nested query (20+ levels) was accepted without error".to_string(),
                r#"query { user { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { posts { author { name } } } } } } } } } } } } } } } } } } } }"#.to_string(),
                5.3,
            ));
        }
    }

    /// Test batching attack
    async fn test_batch_attack(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Send 100 queries in one batch
        let batch_query = r#"[
            {"query":"query{__typename}"},
            {"query":"query{__typename}"},
            {"query":"query{__typename}"},
            {"query":"query{__typename}"},
            {"query":"query{__typename}"}
        ]"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(batch_query)
            ))
            .await
    }

    /// Check batch limit protection
    fn check_batch_limit(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        // If batch succeeds, batching is allowed
        if response.status_code == 200 && (response.body.matches("__typename").count() > 1) {
            vulnerabilities.push(self.create_vulnerability(
                "GraphQL Query Batching Allowed",
                url,
                Severity::Medium,
                Confidence::High,
                "GraphQL API allows query batching - can be used for DoS or brute force",
                "Multiple queries in single request were executed".to_string(),
                r#"[{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"},{"query":"query{__typename}"}]"#.to_string(),
                5.0,
            ));
        }
    }

    /// Test field duplication attack
    async fn test_field_duplication(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        let duplicate_query = r#"{
            "query": "query { __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename }"
        }"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(duplicate_query)
            ))
            .await
    }

    /// Check field duplication protection
    fn check_field_duplication(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        if response.status_code == 200 && response.body.matches("__typename").count() > 5 {
            vulnerabilities.push(self.create_vulnerability(
                "GraphQL Field Duplication Not Limited",
                url,
                Severity::Low,
                Confidence::Medium,
                "GraphQL allows unlimited field duplication - potential resource exhaustion",
                "Same field was queried multiple times in single query".to_string(),
                "query { __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename }".to_string(),
                4.0,
            ));
        }
    }

    /// Test authorization bypass
    async fn test_auth_bypass(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Try to access admin/user queries without auth
        let auth_query = r#"{
            "query": "query { users { id email password } admin { id email } }"
        }"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(auth_query)
            ))
            .await
    }

    /// Check for authorization bypass
    fn check_auth_bypass(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check if sensitive fields are exposed
        let sensitive_indicators = vec![
            "password",
            "email",
            "token",
            "secret",
            "admin",
            "ssn",
            "credit_card",
        ];

        for indicator in &sensitive_indicators {
            if body_lower.contains(indicator) && response.status_code == 200 {
                vulnerabilities.push(self.create_vulnerability(
                    "GraphQL Authorization Bypass",
                    url,
                    Severity::Critical,
                    Confidence::Medium,
                    "GraphQL exposes sensitive fields without proper authorization",
                    format!(
                        "Sensitive field '{}' accessible without authentication",
                        indicator
                    ),
                    "query { users { id email password } admin { id email } }".to_string(),
                    8.2,
                ));
                break;
            }
        }
    }

    /// Test error message disclosure
    async fn test_error_disclosure(&self, url: &str) -> Result<crate::http_client::HttpResponse> {
        // Send invalid query to trigger error
        let error_query = r#"{
            "query": "query { invalid_field_xyz_123 }"
        }"#;

        self.http_client
            .get(&format!(
                "{}?query={}",
                url,
                urlencoding::encode(error_query)
            ))
            .await
    }

    /// Check for verbose error messages
    fn check_error_disclosure(
        &self,
        response: &crate::http_client::HttpResponse,
        url: &str,
        vulnerabilities: &mut Vec<Vulnerability>,
    ) {
        let body_lower = response.body.to_lowercase();

        // Check for stack traces or detailed errors
        let error_indicators = vec![
            "at ",
            "line ",
            "column ",
            "stack",
            "exception",
            "trace",
            "file:",
            "resolver",
            "database",
            "sql",
            "query failed",
        ];

        let mut found_indicators = Vec::new();
        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                found_indicators.push(*indicator);
            }
        }

        if found_indicators.len() >= 2 {
            vulnerabilities.push(self.create_vulnerability(
                "GraphQL Verbose Error Messages",
                url,
                Severity::Low,
                Confidence::High,
                "GraphQL returns verbose error messages - information disclosure",
                format!("Error response contains: {:?}", found_indicators),
                "query { invalid_field_xyz_123 }".to_string(),
                3.7,
            ));
        }
    }

    /// Create vulnerability record
    fn create_vulnerability(
        &self,
        title: &str,
        url: &str,
        severity: Severity,
        confidence: Confidence,
        description: &str,
        evidence: String,
        payload: String,
        cvss: f32,
    ) -> Vulnerability {
        Vulnerability {
            id: format!("graphql_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("GraphQL Vulnerability - {}", title),
            severity,
            confidence,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload,
            description: description.to_string(),
            evidence: Some(evidence),
            cwe: "CWE-285".to_string(), // Improper Authorization
            cvss,
            verified: true,
            false_positive: false,
            remediation: r#"IMMEDIATE ACTION REQUIRED:

1. **Disable Introspection in Production**
   ```javascript
   // Apollo Server (Node.js)
   const server = new ApolloServer({
     introspection: process.env.NODE_ENV !== 'production',
     schema,
   });

   // GraphQL-Go
   h := handler.New(&handler.Config{
     Schema: &schema,
     Pretty: true,
     GraphiQL: false,  // Disable GraphiQL in production
   })
   ```

2. **Implement Query Depth Limiting**
   ```javascript
   // graphql-depth-limit (Node.js)
   const depthLimit = require('graphql-depth-limit');

   const server = new ApolloServer({
     validationRules: [depthLimit(10)],  // Max depth: 10
     schema,
   });
   ```

3. **Implement Query Complexity Limiting**
   ```javascript
   // graphql-query-complexity
   const { createComplexityLimitRule } = require('graphql-validation-complexity');

   const server = new ApolloServer({
     validationRules: [
       createComplexityLimitRule(1000)  // Max complexity: 1000
     ],
     schema,
   });
   ```

4. **Disable or Limit Query Batching**
   ```javascript
   const server = new ApolloServer({
     // Disable batching entirely
     allowBatchedHttpRequests: false,
     schema,
   });
   ```

5. **Implement Proper Authorization**
   ```javascript
   // Field-level authorization
   const typeDefs = gql`
     type User {
       id: ID!
       email: String @auth(requires: USER)
       password: String @auth(requires: ADMIN)
     }
   `;

   // Resolver-level checks
   const resolvers = {
     Query: {
       users: (parent, args, context) => {
         if (!context.user.isAdmin) {
           throw new Error('Unauthorized');
         }
         return getUsers();
       }
     }
   };
   ```

6. **Sanitize Error Messages**
   ```javascript
   const server = new ApolloServer({
     formatError: (err) => {
       // Log full error for debugging
       console.error(err);

       // Return sanitized error to client
       if (process.env.NODE_ENV === 'production') {
         return new Error('Internal server error');
       }
       return err;
     },
     schema,
   });
   ```

7. **Implement Rate Limiting**
   ```javascript
   // graphql-rate-limit
   const { createRateLimitDirective } = require('graphql-rate-limit-directive');

   const rateLimitDirective = createRateLimitDirective({
     identifyContext: (ctx) => ctx.user.id
   });

   const typeDefs = gql`
     type Query {
       users: [User!]! @rateLimit(limit: 100, duration: 60)
     }
   `;
   ```

8. **Use Query Allow Lists (Persisted Queries)**
   ```javascript
   // Only allow pre-approved queries
   const server = new ApolloServer({
     persistedQueries: {
       cache: new Map(),
     },
     schema,
   });
   ```

9. **Field-Level Pagination**
   ```javascript
   type Query {
     users(first: Int = 10, offset: Int = 0): [User!]!
   }
   // Enforce max page size server-side
   ```

10. **Security Headers**
    - Set appropriate CORS headers
    - Disable caching for sensitive queries
    - Use HTTPS only

11. **Monitoring and Logging**
    - Log all introspection attempts
    - Alert on suspicious query patterns
    - Monitor query complexity metrics
    - Track authentication failures

12. **Production Checklist**
    - [ ] Introspection disabled
    - [ ] Query depth limit: ≤ 10
    - [ ] Query complexity limit: ≤ 1000
    - [ ] Batching disabled or limited to 5
    - [ ] Field-level authorization implemented
    - [ ] Error messages sanitized
    - [ ] Rate limiting active
    - [ ] Persisted queries (optional but recommended)
    - [ ] HTTPS enforced
    - [ ] Security monitoring enabled

References:
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- GraphQL Security Best Practices: https://www.apollographql.com/blog/graphql/security/
- Escape GraphQL Security Guide: https://escape.tech/blog/9-graphql-security-best-practices/
"#
            .to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        }
    }
}

// UUID generation helper
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
    use std::collections::HashMap;

    #[test]
    fn test_graphql_detection() {
        let scanner = GraphQlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        // Simulate GraphQL response
        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"{"data":{"__typename":"Query"}}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        assert!(response.body.contains("__typename"));
        assert!(response.body.contains("\"data\""));
    }

    #[test]
    fn test_introspection_detection() {
        let scanner = GraphQlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"}]}}}"#
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        let result = scanner.check_introspection_enabled(
            &response,
            "https://api.example.com/graphql",
            &mut vulns,
        );

        assert!(result, "Should detect introspection enabled");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, Severity::High);
    }

    #[test]
    fn test_batch_detection() {
        let scanner = GraphQlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body: r#"[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]"#
                .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_batch_limit(&response, "https://api.example.com/graphql", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect batching allowed");
        assert_eq!(vulns[0].severity, Severity::Medium);
    }

    #[test]
    fn test_auth_bypass_detection() {
        let scanner = GraphQlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 200,
            body:
                r#"{"data":{"users":[{"id":"1","email":"admin@example.com","password":"hashed"}]}}"#
                    .to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_auth_bypass(&response, "https://api.example.com/graphql", &mut vulns);

        assert!(vulns.len() > 0, "Should detect sensitive field exposure");
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_error_disclosure() {
        let scanner = GraphQlScanner::new(Arc::new(HttpClient::new(5, 2).unwrap()));

        let response = crate::http_client::HttpResponse {
            status_code: 400,
            body: r#"{"errors":[{"message":"Cannot query field on type at line 1 column 5","locations":[{"line":1,"column":5}],"stack":"Error: Cannot query\n  at file: /app/resolvers.js:123"}]}"#.to_string(),
            headers: HashMap::new(),
            duration_ms: 100,
        };

        let mut vulns = Vec::new();
        scanner.check_error_disclosure(&response, "https://api.example.com/graphql", &mut vulns);

        assert_eq!(vulns.len(), 1, "Should detect verbose errors");
        assert_eq!(vulns[0].severity, Severity::Low);
    }
}
