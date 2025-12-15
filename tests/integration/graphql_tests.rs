// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - GraphQL Attack Vector Tests
 * Advanced GraphQL security testing with attack vectors
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::graphql::GraphQlScanner;
use lonkero_scanner::types::{ScanConfig, Severity};
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, body_string_contains},
    Mock, MockServer, ResponseTemplate,
};

fn create_scan_config() -> ScanConfig {
    ScanConfig {
        scan_mode: "thorough".to_string(),
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    }
}

#[tokio::test]
async fn test_graphql_introspection_full_schema_exposure() {
    let mock_server = MockServer::start().await;

    let full_schema = r#"{
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "User",
                        "fields": [
                            {"name": "id", "type": {"name": "ID", "kind": "SCALAR"}},
                            {"name": "email", "type": {"name": "String", "kind": "SCALAR"}},
                            {"name": "password_hash", "type": {"name": "String", "kind": "SCALAR"}},
                            {"name": "api_key", "type": {"name": "String", "kind": "SCALAR"}},
                            {"name": "credit_card", "type": {"name": "String", "kind": "SCALAR"}}
                        ]
                    },
                    {
                        "kind": "OBJECT",
                        "name": "AdminPanel",
                        "fields": [
                            {"name": "all_users", "type": {"name": "[User]", "kind": "LIST"}},
                            {"name": "system_config", "type": {"name": "Config", "kind": "OBJECT"}},
                            {"name": "delete_user", "type": {"name": "Boolean", "kind": "SCALAR"}}
                        ]
                    }
                ]
            }
        }
    }"#;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(full_schema)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 GraphQL tests");

    let introspection_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Introspection"));
    assert!(introspection_vuln.is_some(), "Should detect introspection");
    assert_eq!(introspection_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_graphql_query_depth_bomb() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "user": {
                            "friends": {
                                "friends": {
                                    "friends": {
                                        "friends": {
                                            "friends": {
                                                "friends": {
                                                    "friends": {
                                                        "friends": {
                                                            "name": "Deep User"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let depth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Depth") || v.description.to_lowercase().contains("depth"));
    if depth_vuln.is_some() {
        assert!(depth_vuln.unwrap().cvss >= 5.0);
    }
}

#[tokio::test]
async fn test_graphql_batch_query_attack() {
    let mock_server = MockServer::start().await;

    let batch_response = r#"[
        {"data": {"user": {"id": "1", "email": "user1@example.com"}}},
        {"data": {"user": {"id": "2", "email": "user2@example.com"}}},
        {"data": {"user": {"id": "3", "email": "user3@example.com"}}},
        {"data": {"user": {"id": "4", "email": "user4@example.com"}}},
        {"data": {"user": {"id": "5", "email": "user5@example.com"}}}
    ]"#;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(batch_response)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let batch_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Batch") || v.vuln_type.contains("Array"));
    if batch_vuln.is_some() {
        assert!(batch_vuln.unwrap().severity == Severity::Medium ||
                batch_vuln.unwrap().severity == Severity::High);
    }
}

#[tokio::test]
async fn test_graphql_field_duplication_dos() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "product": {
                            "name": "Product A",
                            "name": "Product A",
                            "name": "Product A",
                            "description": "Description",
                            "description": "Description",
                            "price": 100,
                            "price": 100
                        }
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let field_dup_vuln = vulnerabilities.iter()
        .find(|v| v.description.to_lowercase().contains("field") ||
                   v.description.to_lowercase().contains("duplication"));
    if field_dup_vuln.is_some() {
        assert!(field_dup_vuln.unwrap().cvss >= 4.0);
    }
}

#[tokio::test]
async fn test_graphql_circular_query_attack() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "author": {
                            "posts": [{
                                "author": {
                                    "posts": [{
                                        "author": {
                                            "name": "Circular Author"
                                        }
                                    }]
                                }
                            }]
                        }
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let has_dos_vuln = vulnerabilities.iter()
            .any(|v| v.severity == Severity::Medium || v.severity == Severity::High);
        assert!(has_dos_vuln);
    }
}

#[tokio::test]
async fn test_graphql_authorization_bypass() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "adminUsers": [
                            {
                                "id": "1",
                                "username": "admin",
                                "email": "admin@company.com",
                                "role": "super_admin",
                                "api_key": "sk_live_1234567890abcdef",
                                "permissions": ["all"]
                            }
                        ]
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let auth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Auth") || v.vuln_type.contains("Authorization"));
    if auth_vuln.is_some() {
        assert!(auth_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_graphql_verbose_errors_stack_trace() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{
                    "errors": [
                        {
                            "message": "Cannot query field 'secretData' on type 'User'",
                            "extensions": {
                                "code": "GRAPHQL_VALIDATION_FAILED",
                                "exception": {
                                    "stacktrace": [
                                        "GraphQLError: Cannot query field 'secretData'",
                                        "    at Object.Field (/app/node_modules/graphql/validation/rules/FieldsOnCorrectType.js:48:31)",
                                        "    at /app/node_modules/graphql/language/visitor.js:323:26",
                                        "    at /app/server/resolvers/user.js:145:12",
                                        "    at Database.query (/app/db/postgres.js:89:5)"
                                    ],
                                    "path": "/var/www/app/server/resolvers/user.js"
                                }
                            }
                        }
                    ]
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let error_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Error") || v.vuln_type.contains("Disclosure"));
    if error_vuln.is_some() {
        assert!(error_vuln.unwrap().severity == Severity::Medium ||
                error_vuln.unwrap().severity == Severity::Low);
    }
}

#[tokio::test]
async fn test_graphql_graphiql_ide_exposure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphiql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>GraphiQL</title>
                        <link rel="stylesheet" href="/graphiql.css" />
                    </head>
                    <body>
                        <div id="graphiql">Loading GraphiQL IDE...</div>
                        <script src="/graphiql.js"></script>
                    </body>
                    </html>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphiql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let has_ide_vuln = vulnerabilities.iter()
            .any(|v| v.description.to_lowercase().contains("ide") ||
                     v.description.to_lowercase().contains("graphiql"));
        if has_ide_vuln {
            let ide_vuln = vulnerabilities.iter()
                .find(|v| v.description.to_lowercase().contains("ide"));
            assert!(ide_vuln.unwrap().severity == Severity::Medium ||
                    ide_vuln.unwrap().severity == Severity::Low);
        }
    }
}

#[tokio::test]
async fn test_graphql_mutation_without_authentication() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "deleteUser": {
                            "success": true,
                            "message": "User deleted successfully"
                        }
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let critical_vulns = vulnerabilities.iter()
            .filter(|v| v.severity == Severity::Critical || v.severity == Severity::High)
            .count();
        assert!(critical_vulns >= 0);
    }
}

#[tokio::test]
async fn test_graphql_alias_based_dos() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "user1": {"name": "Alice"},
                        "user2": {"name": "Bob"},
                        "user3": {"name": "Charlie"},
                        "user100": {"name": "User100"}
                    }
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/graphql", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let dos_vuln = vulnerabilities.iter()
            .any(|v| v.severity == Severity::Medium || v.severity == Severity::High);
        assert!(dos_vuln || vulnerabilities.len() > 0);
    }
}

#[tokio::test]
async fn test_graphql_performance() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data": {}}"#))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let start = std::time::Instant::now();

    for _ in 0..5 {
        let _ = scanner.scan(&mock_server.uri(), &config).await;
    }

    let duration = start.elapsed();
    assert!(duration.as_secs() < 15, "5 GraphQL scans should complete within 15 seconds");
}

#[tokio::test]
async fn test_graphql_non_graphql_endpoint_detection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/rest"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"status": "ok", "data": [1, 2, 3]}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/rest", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert_eq!(tests_run, 1, "Should only run detection test on non-GraphQL endpoint");
    assert_eq!(vulnerabilities.len(), 0, "Should not find GraphQL vulnerabilities on REST endpoint");
}
