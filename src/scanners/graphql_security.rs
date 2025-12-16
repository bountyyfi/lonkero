// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::info;

mod uuid {
    pub use uuid::Uuid;
}

/// Scanner for GraphQL security vulnerabilities
pub struct GraphqlSecurityScanner {
    http_client: Arc<HttpClient>,
    test_marker: String,
}

impl GraphqlSecurityScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        let test_marker = format!("gql-{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        Self {
            http_client,
            test_marker,
        }
    }

    /// Run GraphQL security scan
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        info!("Starting GraphQL security scan on {}", url);

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        // Test introspection enabled
        let (vulns, tests) = self.test_introspection(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test GraphQL injection
        let (vulns, tests) = self.test_graphql_injection(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test field suggestions
        let (vulns, tests) = self.test_field_suggestions(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Test batch query attacks
        let (vulns, tests) = self.test_batch_queries(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Query complexity / DoS via deep nesting
        let (vulns, tests) = self.test_query_complexity_dos(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Alias abuse attacks
        let (vulns, tests) = self.test_alias_abuse(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Persisted query attacks
        let (vulns, tests) = self.test_persisted_query_attacks(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Subscription vulnerabilities
        let (vulns, tests) = self.test_subscription_vulnerabilities(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Fragment spreading attacks
        let (vulns, tests) = self.test_fragment_attacks(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Directive abuse
        let (vulns, tests) = self.test_directive_abuse(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        // Advanced: Authorization bypass via query manipulation
        let (vulns, tests) = self.test_auth_bypass(url).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests;

        info!(
            "GraphQL security scan completed: {} tests run, {} vulnerabilities found",
            total_tests,
            all_vulnerabilities.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    /// Test if GraphQL introspection is enabled
    async fn test_introspection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing GraphQL introspection");

        // Try common GraphQL endpoints
        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
            format!("{}/api/graphql", url.trim_end_matches('/')),
        ];

        // Introspection query
        let introspection_query = r#"{"query":"{\n  __schema {\n    types {\n      name\n    }\n  }\n}"}"#;

        for endpoint in graphql_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self.http_client.post_with_headers(&endpoint, introspection_query, headers).await {
                Ok(response) => {
                    if self.detect_introspection_enabled(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "GraphQL Introspection Enabled",
                            &endpoint,
                            &format!("GraphQL introspection is enabled. Response contains schema information: {}",
                                self.extract_evidence(&response.body, 200)),
                            Severity::Medium,
                            "CWE-200",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Introspection test failed for {}: {}", endpoint, e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for GraphQL injection vulnerabilities
    async fn test_graphql_injection(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing GraphQL injection");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
            format!("{}/api/graphql", url.trim_end_matches('/')),
        ];

        // Injection payloads
        let injection_payloads = vec![
            (r#"{"query":"{ user(id: \"1' OR '1'='1\") { name } }"}"#, "SQL injection in GraphQL"),
            (r#"{"query":"{ user(id: \"1; DROP TABLE users--\") { name } }"}"#, "SQL injection with DROP"),
            (r#"{"query":"{ user(id: \"$ne\") { name } }"}"#, "NoSQL injection"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &injection_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        if self.detect_injection_success(&response.body) {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Injection",
                                endpoint,
                                &format!("{}: {}", description, payload),
                                Severity::Critical,
                                "CWE-89",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        info!("GraphQL injection test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for field suggestions (information disclosure)
    async fn test_field_suggestions(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Testing GraphQL field suggestions");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Query with typo to trigger field suggestions
        let suggestion_query = r#"{"query":"{ usr { name } }"}"#;

        for endpoint in graphql_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self.http_client.post_with_headers(&endpoint, suggestion_query, headers).await {
                Ok(response) => {
                    if self.detect_field_suggestions(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "GraphQL Field Suggestions Enabled",
                            &endpoint,
                            &format!("GraphQL exposes field suggestions which can leak schema information: {}",
                                self.extract_evidence(&response.body, 150)),
                            Severity::Low,
                            "CWE-200",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Field suggestions test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for batch query attacks
    async fn test_batch_queries(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 1;

        info!("Testing GraphQL batch query attacks");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Batch query with multiple operations
        let batch_query = r#"[
            {"query":"{ __typename }"},
            {"query":"{ __typename }"},
            {"query":"{ __typename }"},
            {"query":"{ __typename }"},
            {"query":"{ __typename }"}
        ]"#;

        for endpoint in graphql_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self.http_client.post_with_headers(&endpoint, batch_query, headers).await {
                Ok(response) => {
                    if self.detect_batch_query_accepted(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            "GraphQL Batch Queries Enabled",
                            &endpoint,
                            "GraphQL endpoint accepts batch queries without rate limiting, potentially enabling DoS attacks",
                            Severity::Medium,
                            "CWE-770",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    info!("Batch query test failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for query complexity DoS attacks via deep nesting
    async fn test_query_complexity_dos(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing GraphQL query complexity / deep nesting DoS");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Deep nesting query (exponential complexity)
        let deep_nesting_query = r#"{"query":"query DeepNest { user { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { id name } } } } } } } } } } } }"}"#;

        // Field duplication query
        let field_duplication_query = r#"{"query":"query Dup { user { id id id id id id id id id id id id id id id id id id id id } }"}"#;

        // Circular fragment query
        let circular_query = r#"{"query":"query Circular { ...A } fragment A on Query { ...B } fragment B on Query { ...A }"}"#;

        let complexity_payloads = vec![
            (deep_nesting_query, "Deep nesting DoS (exponential complexity)"),
            (field_duplication_query, "Field duplication attack"),
            (circular_query, "Circular fragment reference"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &complexity_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                let start = std::time::Instant::now();
                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        let elapsed = start.elapsed();

                        // Check if query was accepted (no complexity error)
                        let accepted = !response.body.to_lowercase().contains("complexity")
                            && !response.body.to_lowercase().contains("depth")
                            && !response.body.to_lowercase().contains("max")
                            && !response.body.to_lowercase().contains("limit exceeded");

                        // Check if server took long time (>2s indicates DoS potential)
                        let slow_response = elapsed.as_secs() > 2;

                        if accepted || slow_response {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Query Complexity DoS",
                                endpoint,
                                &format!("{} - Response time: {}ms. No complexity limits detected.",
                                    description, elapsed.as_millis()),
                                Severity::High,
                                "CWE-400",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        info!("Complexity test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for alias abuse attacks (amplification)
    async fn test_alias_abuse(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing GraphQL alias abuse attacks");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Alias amplification attack - same expensive query with many aliases
        let alias_amplification = r#"{"query":"query AliasAmplification {
            a1: user(id: \"1\") { id name email }
            a2: user(id: \"1\") { id name email }
            a3: user(id: \"1\") { id name email }
            a4: user(id: \"1\") { id name email }
            a5: user(id: \"1\") { id name email }
            a6: user(id: \"1\") { id name email }
            a7: user(id: \"1\") { id name email }
            a8: user(id: \"1\") { id name email }
            a9: user(id: \"1\") { id name email }
            a10: user(id: \"1\") { id name email }
            a11: user(id: \"1\") { id name email }
            a12: user(id: \"1\") { id name email }
            a13: user(id: \"1\") { id name email }
            a14: user(id: \"1\") { id name email }
            a15: user(id: \"1\") { id name email }
            a16: user(id: \"1\") { id name email }
            a17: user(id: \"1\") { id name email }
            a18: user(id: \"1\") { id name email }
            a19: user(id: \"1\") { id name email }
            a20: user(id: \"1\") { id name email }
        }"}"#;

        // Array-based alias attack
        let array_alias = r#"{"query":"query ArrayAlias {
            a1: users(first: 100) { id }
            a2: users(first: 100) { id }
            a3: users(first: 100) { id }
            a4: users(first: 100) { id }
            a5: users(first: 100) { id }
        }"}"#;

        let alias_payloads = vec![
            (alias_amplification, "Alias amplification attack (20 aliases)"),
            (array_alias, "Array-based alias amplification"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &alias_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                let start = std::time::Instant::now();
                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        let elapsed = start.elapsed();

                        // Check if aliases were executed
                        let alias_executed = response.body.contains("a1")
                            || response.body.contains("\"data\"");

                        let no_limits = !response.body.to_lowercase().contains("alias")
                            && !response.body.to_lowercase().contains("limit")
                            && !response.body.to_lowercase().contains("max");

                        if alias_executed && no_limits {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Alias Abuse",
                                endpoint,
                                &format!("{} - No alias limits detected. Response time: {}ms",
                                    description, elapsed.as_millis()),
                                Severity::High,
                                "CWE-770",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        info!("Alias abuse test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for persisted query attacks
    async fn test_persisted_query_attacks(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing GraphQL persisted query attacks");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // APQ (Automatic Persisted Queries) probe
        let apq_probe = r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}"#;

        // APQ registration attempt
        let apq_register = r#"{"query":"{ __typename }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}"#;

        // Persisted query bypass with full query
        let pq_bypass = r#"{"query":"{ user { id } }","extensions":{"persistedQuery":{"version":1,"sha256Hash":"invalidhash"}}}"#;

        let pq_payloads = vec![
            (apq_probe, "APQ probe without query"),
            (apq_register, "APQ registration attempt"),
            (pq_bypass, "Persisted query bypass"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &pq_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        // Check if APQ is enabled without proper validation
                        let apq_enabled = response.body.contains("PersistedQueryNotFound")
                            || response.body.contains("persistedQuery");

                        let apq_registered = response.body.contains("__typename")
                            && !response.body.contains("error");

                        let bypass_worked = description.contains("bypass")
                            && response.body.contains("user")
                            && !response.body.contains("error");

                        if apq_enabled {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Automatic Persisted Queries Enabled",
                                endpoint,
                                &format!("{} - APQ is enabled. This can be abused for cache poisoning or bypass attacks.",
                                    description),
                                Severity::Medium,
                                "CWE-668",
                            ));
                        }

                        if apq_registered || bypass_worked {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Persisted Query Bypass",
                                endpoint,
                                &format!("{} - Queries can be registered or bypass validation.",
                                    description),
                                Severity::High,
                                "CWE-284",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        info!("Persisted query test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for subscription vulnerabilities
    async fn test_subscription_vulnerabilities(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing GraphQL subscription vulnerabilities");

        // Check for WebSocket endpoint
        let ws_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/').replace("http", "ws")),
            format!("{}/subscriptions", url.trim_end_matches('/').replace("http", "ws")),
        ];

        // Subscription probe query via HTTP (some implementations allow this)
        let subscription_http_query = r#"{"query":"subscription { newMessage { id content } }"}"#;

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        for endpoint in &graphql_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            match self.http_client.post_with_headers(endpoint, subscription_http_query, headers).await {
                Ok(response) => {
                    // Check if subscriptions are exposed via HTTP
                    let subscription_enabled = response.body.contains("subscription")
                        || response.body.contains("newMessage");

                    let no_auth_error = !response.body.to_lowercase().contains("unauthorized")
                        && !response.body.to_lowercase().contains("forbidden")
                        && !response.body.to_lowercase().contains("auth");

                    if subscription_enabled && no_auth_error {
                        vulnerabilities.push(self.create_vulnerability(
                            "GraphQL Subscriptions Without Authentication",
                            endpoint,
                            "GraphQL subscriptions are accessible without proper authentication. This can leak real-time data.",
                            Severity::High,
                            "CWE-287",
                        ));
                    }
                }
                Err(e) => {
                    info!("Subscription test failed: {}", e);
                }
            }

            // Test for subscription DoS (many concurrent subscriptions)
            let subscription_dos_query = r#"{"query":"subscription SubDoS { onAnyEvent { type data } }"}"#;

            match self.http_client.post_with_headers(endpoint, subscription_dos_query, vec![
                ("Content-Type".to_string(), "application/json".to_string())
            ]).await {
                Ok(response) => {
                    let no_limit = !response.body.to_lowercase().contains("limit")
                        && !response.body.to_lowercase().contains("max")
                        && !response.body.to_lowercase().contains("too many");

                    if no_limit && !response.body.contains("error") {
                        vulnerabilities.push(self.create_vulnerability(
                            "GraphQL Subscription DoS Risk",
                            endpoint,
                            "GraphQL subscriptions have no apparent connection limits. This can be abused for DoS attacks.",
                            Severity::Medium,
                            "CWE-770",
                        ));
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for fragment spreading attacks
    async fn test_fragment_attacks(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 2;

        info!("Testing GraphQL fragment attacks");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Fragment spread amplification
        let fragment_amplification = r#"{"query":"query FragmentAmplification { ...UserData ...UserData ...UserData ...UserData ...UserData ...UserData ...UserData ...UserData ...UserData ...UserData } fragment UserData on Query { user { id name email friends { id name } } }"}"#;

        // Deeply nested fragments
        let nested_fragments = r#"{"query":"query NestedFragments { ...A } fragment A on Query { user { ...B } } fragment B on User { friends { ...C } } fragment C on User { friends { ...D } } fragment D on User { friends { ...E } } fragment E on User { id name email }"}"#;

        let fragment_payloads = vec![
            (fragment_amplification, "Fragment spread amplification (10x)"),
            (nested_fragments, "Deeply nested fragments (5 levels)"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &fragment_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                let start = std::time::Instant::now();
                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        let elapsed = start.elapsed();

                        let no_limits = !response.body.to_lowercase().contains("fragment")
                            && !response.body.to_lowercase().contains("depth")
                            && !response.body.to_lowercase().contains("limit");

                        let slow_response = elapsed.as_secs() > 2;

                        if no_limits || slow_response {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Fragment Attack",
                                endpoint,
                                &format!("{} - No fragment limits detected. Response time: {}ms",
                                    description, elapsed.as_millis()),
                                Severity::Medium,
                                "CWE-400",
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        info!("Fragment test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for directive abuse
    async fn test_directive_abuse(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        info!("Testing GraphQL directive abuse");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // @skip/@include directive abuse
        let directive_abuse = r#"{"query":"query DirectiveAbuse { user @skip(if: false) @include(if: true) @skip(if: false) @include(if: true) { id @deprecated name @skip(if: false) } }"}"#;

        // Custom directive injection
        let custom_directive = r#"{"query":"query CustomDir { user @debug @trace @admin { id name } }"}"#;

        // Directive with dangerous arguments
        let directive_injection = r#"{"query":"query DirInject { user @export(as: \"${{ process.env }}\") { id } }"}"#;

        let directive_payloads = vec![
            (directive_abuse, "Multiple directive stacking"),
            (custom_directive, "Custom directive probing (@debug, @admin)"),
            (directive_injection, "Directive argument injection"),
        ];

        for endpoint in &graphql_endpoints {
            for (payload, description) in &directive_payloads {
                let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

                match self.http_client.post_with_headers(endpoint, payload, headers).await {
                    Ok(response) => {
                        // Check for debug/admin directive acceptance
                        let debug_accepted = response.body.contains("debug")
                            || response.body.contains("trace")
                            || response.body.contains("admin");

                        // Check for directive info disclosure
                        let info_leak = response.body.contains("process")
                            || response.body.contains("env")
                            || response.body.contains("stack");

                        // Check for unrestricted directives
                        let no_directive_limit = !response.body.to_lowercase().contains("directive")
                            && !response.body.to_lowercase().contains("unknown")
                            && response.body.contains("data");

                        if debug_accepted || info_leak {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Custom Directive Abuse",
                                endpoint,
                                &format!("{} - Server accepts or leaks info from custom directives",
                                    description),
                                Severity::High,
                                "CWE-200",
                            ));
                            break;
                        }

                        if no_directive_limit && description.contains("stacking") {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Directive Stacking",
                                endpoint,
                                "Server allows multiple directives on single field without limits",
                                Severity::Low,
                                "CWE-400",
                            ));
                        }
                    }
                    Err(e) => {
                        info!("Directive test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for authorization bypass via query manipulation
    async fn test_auth_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Testing GraphQL authorization bypass");

        let graphql_endpoints = vec![
            format!("{}/graphql", url.trim_end_matches('/')),
        ];

        // Access admin fields without auth
        let admin_access = r#"{"query":"{ admin { users { id email password } } }"}"#;

        // IDOR via GraphQL
        let idor_query = r#"{"query":"{ user(id: \"1\") { id email sensitiveData } }"}"#;

        // Type confusion attack
        let type_confusion = r#"{"query":"mutation { updateUser(id: \"1\", role: \"admin\") { id role } }"}"#;

        // Nested authorization bypass
        let nested_bypass = r#"{"query":"{ publicData { privateRelation { secretField } } }"}"#;

        let auth_payloads = vec![
            (admin_access, "Admin field access without authentication"),
            (idor_query, "IDOR via GraphQL user ID manipulation"),
            (type_confusion, "Role escalation via mutation"),
            (nested_bypass, "Nested authorization bypass"),
        ];

        for endpoint in &graphql_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

            for (payload, description) in &auth_payloads {
                match self.http_client.post_with_headers(endpoint, payload, headers.clone()).await {
                    Ok(response) => {
                        // Check for successful unauthorized access
                        let has_data = response.body.contains("\"data\"")
                            && !response.body.contains("null");

                        let no_auth_error = !response.body.to_lowercase().contains("unauthorized")
                            && !response.body.to_lowercase().contains("forbidden")
                            && !response.body.to_lowercase().contains("permission")
                            && !response.body.to_lowercase().contains("access denied");

                        let sensitive_data = response.body.contains("password")
                            || response.body.contains("sensitiveData")
                            || response.body.contains("secretField")
                            || response.body.contains("admin");

                        if has_data && no_auth_error && sensitive_data {
                            vulnerabilities.push(self.create_vulnerability(
                                "GraphQL Authorization Bypass",
                                endpoint,
                                &format!("{} - Sensitive data accessible without proper authorization: {}",
                                    description, self.extract_evidence(&response.body, 150)),
                                Severity::Critical,
                                "CWE-862",
                            ));
                        }
                    }
                    Err(e) => {
                        info!("Auth bypass test failed: {}", e);
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect if introspection is enabled
    fn detect_introspection_enabled(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for schema information in response
        (body_lower.contains("__schema") || body_lower.contains("__type")) &&
        (body_lower.contains("types") || body_lower.contains("fields")) &&
        !body_lower.contains("error") &&
        !body_lower.contains("introspection is disabled")
    }

    /// Detect successful injection
    fn detect_injection_success(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for SQL/database errors or unexpected data
        let sql_errors = vec![
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "syntax error",
            "unclosed quotation",
            "ora-",
        ];

        for error in sql_errors {
            if body_lower.contains(error) {
                return true;
            }
        }

        // Check for successful data extraction
        body_lower.contains("\"data\"") &&
        !body_lower.contains("\"errors\"") &&
        (body_lower.contains("user") || body_lower.contains("admin"))
    }

    /// Detect field suggestions
    fn detect_field_suggestions(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        body_lower.contains("did you mean") ||
        body_lower.contains("suggestion") ||
        (body_lower.contains("field") && body_lower.contains("not found") && body_lower.contains("available"))
    }

    /// Detect batch query acceptance
    fn detect_batch_query_accepted(&self, body: &str) -> bool {
        // Check if response contains array of results
        body.starts_with('[') && body.ends_with(']') && body.contains("__typename")
    }

    /// Extract evidence from response
    fn extract_evidence(&self, body: &str, max_len: usize) -> String {
        if body.len() <= max_len {
            body.to_string()
        } else {
            format!("{}...", &body[..max_len])
        }
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        vuln_type: &str,
        url: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            Severity::Low => 3.7,
            Severity::Info => 2.0,
        };

        Vulnerability {
            id: format!("gql_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
            severity,
            confidence: crate::types::Confidence::Medium,
            category: "API Security".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: "".to_string(),
            description: format!("{}: {}", vuln_type, evidence),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: self.get_remediation(vuln_type),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Get remediation advice based on vulnerability type
    fn get_remediation(&self, vuln_type: &str) -> String {
        match vuln_type {
            "GraphQL Introspection Enabled" => {
                "Disable GraphQL introspection in production environments. Configure your GraphQL server to reject introspection queries. Use schema validation and access control to protect sensitive schema information.".to_string()
            }
            "GraphQL Injection" => {
                "Implement proper input validation and parameterized queries. Use GraphQL query complexity analysis. Validate and sanitize all user inputs. Implement proper error handling that doesn't leak sensitive information.".to_string()
            }
            "GraphQL Field Suggestions Enabled" => {
                "Disable field suggestions in production. Return generic error messages that don't reveal schema information. Implement proper access control and authentication.".to_string()
            }
            "GraphQL Batch Queries Enabled" => {
                "Implement query batching limits. Use query complexity analysis and depth limiting. Implement rate limiting at the API level. Set maximum batch size and reject oversized batches.".to_string()
            }
            _ => {
                "Implement proper GraphQL security: disable introspection in production, use query complexity limits, implement proper authentication and authorization, validate all inputs, and monitor for abuse.".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanConfig;

    fn create_test_scanner() -> GraphqlSecurityScanner {
        let client = Arc::new(HttpClient::new(10000, 3).unwrap());
        GraphqlSecurityScanner::new(client)
    }

    #[test]
    fn test_detect_introspection_enabled() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_introspection_enabled(r#"{"data":{"__schema":{"types":[{"name":"User"}]}}}"#));
        assert!(scanner.detect_introspection_enabled(r#"{"__type":{"fields":[{"name":"id"}]}}"#));

        assert!(!scanner.detect_introspection_enabled(r#"{"error":"Introspection is disabled"}"#));
        assert!(!scanner.detect_introspection_enabled(r#"{"data":{"user":{"name":"John"}}}"#));
    }

    #[test]
    fn test_detect_injection_success() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_injection_success(r#"SQL syntax error near 'OR'"#));
        assert!(scanner.detect_injection_success(r#"MySQL error: unclosed quotation"#));

        assert!(!scanner.detect_injection_success(r#"{"errors":[{"message":"Invalid query"}]}"#));
    }

    #[test]
    fn test_detect_field_suggestions() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_field_suggestions(r#"Field 'usr' not found. Did you mean 'user'?"#));
        assert!(scanner.detect_field_suggestions(r#"No field found with suggestion 'user'"#));

        assert!(!scanner.detect_field_suggestions(r#"Field not found"#));
    }

    #[test]
    fn test_detect_batch_query_accepted() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_batch_query_accepted(r#"[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]"#));

        assert!(!scanner.detect_batch_query_accepted(r#"{"data":{"__typename":"Query"}}"#));
    }

    #[test]
    fn test_test_marker_uniqueness() {
        let scanner1 = create_test_scanner();
        let scanner2 = create_test_scanner();

        assert_ne!(scanner1.test_marker, scanner2.test_marker);
        assert!(scanner1.test_marker.starts_with("gql-"));
    }
}
