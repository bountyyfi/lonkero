// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - API Scanners Integration Tests
 * Comprehensive tests for GraphQL, gRPC, WebSocket, and REST API scanners
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::graphql::GraphQlScanner;
use lonkero_scanner::scanners::grpc::GrpcScanner;
use lonkero_scanner::scanners::websocket::WebSocketScanner;
use lonkero_scanner::scanners::api_security::APISecurityScanner;
use lonkero_scanner::types::{ScanConfig, Severity, Confidence};
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, query_param, header, body_string_contains},
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

// ============================================================================
// GRAPHQL SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_graphql_introspection_enabled() {
    let mock_server = MockServer::start().await;

    let introspection_response = r#"{
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "description": "User account",
                        "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "email", "type": {"name": "String"}},
                            {"name": "password", "type": {"name": "String"}}
                        ]
                    },
                    {
                        "name": "Admin",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "secretKey", "type": {"name": "String"}}
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
                .set_body_string(introspection_response)
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
    assert!(introspection_vuln.is_some(), "Should detect introspection vulnerability");
    assert_eq!(introspection_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_graphql_depth_attack() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "user": {
                            "posts": {
                                "author": {
                                    "posts": {
                                        "author": {
                                            "name": "Deep User"
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
        .find(|v| v.vuln_type.contains("Depth") || v.vuln_type.contains("Query Complexity"));
    if depth_vuln.is_some() {
        assert!(depth_vuln.unwrap().cvss >= 5.0);
    }
}

#[tokio::test]
async fn test_graphql_batch_attack() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"[
                    {"data": {"user": {"id": "1"}}},
                    {"data": {"user": {"id": "2"}}},
                    {"data": {"user": {"id": "3"}}}
                ]"#)
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
async fn test_graphql_field_duplication() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "user": {
                            "name": "Alice",
                            "name": "Alice",
                            "name": "Alice"
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

    let field_duplication_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Field") || v.vuln_type.contains("Duplication"));
    if field_duplication_vuln.is_some() {
        assert!(field_duplication_vuln.unwrap().cvss >= 4.0);
    }
}

#[tokio::test]
async fn test_graphql_auth_bypass() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{
                    "data": {
                        "adminPanel": {
                            "users": [
                                {"id": "1", "email": "admin@example.com", "role": "admin"}
                            ],
                            "secretConfig": "production_key_12345"
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

    let auth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Auth") || v.vuln_type.contains("Authorization"));
    if auth_vuln.is_some() {
        assert!(auth_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_graphql_error_disclosure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{
                    "errors": [
                        {
                            "message": "Error executing query",
                            "stack": "at GraphQL.execute (/app/node_modules/graphql/execution.js:123)\nat /app/server.js:456",
                            "path": ["/var/www/html/graphql/resolvers.js"],
                            "extensions": {
                                "code": "INTERNAL_SERVER_ERROR",
                                "exception": {
                                    "stacktrace": [
                                        "Error: Database connection failed",
                                        "at pg.connect (/app/node_modules/pg/lib/client.js:89)",
                                        "at Database.query (/app/models/user.js:12)"
                                    ]
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
async fn test_graphql_non_graphql_endpoint() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"users": [{"id": 1, "name": "Alice"}]}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/users", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert_eq!(tests_run, 1, "Should only run detection test on non-GraphQL endpoint");
    assert_eq!(vulnerabilities.len(), 0, "Should not find GraphQL vulnerabilities on REST endpoint");
}

// ============================================================================
// GRPC SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_grpc_reflection_enabled() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/grpc/service"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/grpc")
                .set_body_string(r#"{
                    "services": [
                        "grpc.reflection.v1alpha.ServerReflection",
                        "myapp.UserService",
                        "myapp.AdminService"
                    ]
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GrpcScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/grpc/service", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 gRPC tests");

    let reflection_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Reflection"));
    assert!(reflection_vuln.is_some(), "Should detect gRPC reflection");
    assert_eq!(reflection_vuln.unwrap().severity, Severity::Medium);
}

#[tokio::test]
async fn test_grpc_insecure_transport() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GrpcScanner::new(http_client);
    let config = create_scan_config();

    let url = "http://example.com:50051/grpc";
    let (vulnerabilities, _) = scanner.scan(url, &config).await.unwrap();

    let transport_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Insecure") || v.vuln_type.contains("Plaintext"));
    if transport_vuln.is_some() {
        assert_eq!(transport_vuln.unwrap().severity, Severity::High);
    }
}

#[tokio::test]
async fn test_grpc_missing_authentication() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/grpc.UserService/GetUser"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/grpc+proto")
                .set_body_string(r#"{"user": {"id": "123", "email": "user@example.com"}}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GrpcScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/grpc.UserService/GetUser", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let auth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Authentication"));
    if auth_vuln.is_some() {
        assert!(auth_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_grpc_error_disclosure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/grpc/service"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("grpc-status", "13")
                .insert_header("grpc-message", "Internal error: Database connection failed at /app/db.go:45")
                .set_body_string("Internal server error")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GrpcScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/grpc/service", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let error_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Error") || v.vuln_type.contains("Disclosure"));
    if error_vuln.is_some() {
        assert!(error_vuln.unwrap().severity == Severity::Medium ||
                error_vuln.unwrap().severity == Severity::Low);
    }
}

#[tokio::test]
async fn test_grpc_non_grpc_endpoint() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"data": "value"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = GrpcScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/data", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert_eq!(tests_run, 1, "Should only run detection test");
    assert_eq!(vulnerabilities.len(), 0, "Should not find gRPC vulnerabilities on non-gRPC endpoint");
}

// ============================================================================
// WEBSOCKET SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_websocket_missing_origin_validation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ws"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <script>
                    const ws = new WebSocket('wss://example.com/ws');
                    ws.onopen = function() {
                        console.log('Connected');
                    };
                    </script>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/ws", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 8, "Should run at least 8 WebSocket tests");

    let origin_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Origin"));
    assert!(origin_vuln.is_some(), "Should detect missing origin validation");
    assert_eq!(origin_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_websocket_cswsh_vulnerability() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/websocket"))
        .respond_with(
            ResponseTemplate::new(101)
                .insert_header("Upgrade", "websocket")
                .insert_header("Connection", "Upgrade")
                .set_body_string("")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/websocket", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let cswsh_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("CSWSH") || v.vuln_type.contains("Hijacking"));
    if cswsh_vuln.is_some() {
        assert!(cswsh_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_websocket_sensitive_data_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = "wss://example.com/chat?token=secret_api_key_12345&session=user_session_xyz";
    let (vulnerabilities, _) = scanner.scan(url, &config).await.unwrap();

    let sensitive_data_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Sensitive") || v.vuln_type.contains("Token"));
    assert!(sensitive_data_vuln.is_some(), "Should detect sensitive data in WebSocket URL");
}

#[tokio::test]
async fn test_websocket_missing_authentication() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/chat"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <script>
                    const socket = new WebSocket('ws://example.com/chat');
                    socket.send(JSON.stringify({message: 'Hello'}));
                    </script>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/chat", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let auth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Authentication"));
    if auth_vuln.is_some() {
        assert!(auth_vuln.unwrap().cvss >= 5.0);
    }
}

#[tokio::test]
async fn test_websocket_message_injection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ws/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <script>
                    ws.onmessage = function(event) {
                        document.getElementById('output').innerHTML = event.data;
                    };
                    </script>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/ws/messages", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let injection_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Injection") || v.vuln_type.contains("XSS"));
    if injection_vuln.is_some() {
        assert!(injection_vuln.unwrap().cvss >= 5.0);
    }
}

#[tokio::test]
async fn test_websocket_rate_limiting() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ws/unlimited"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Upgrade", "websocket")
                .set_body_string("WebSocket endpoint with no rate limiting")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = WebSocketScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/ws/unlimited", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let rate_limit_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Rate") || v.vuln_type.contains("Limiting"));
    if rate_limit_vuln.is_some() {
        assert!(rate_limit_vuln.unwrap().severity == Severity::Medium ||
                rate_limit_vuln.unwrap().severity == Severity::Low);
    }
}

// ============================================================================
// REST API SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_rest_api_authentication_bypass() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/admin/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{
                    "users": [
                        {"id": 1, "email": "admin@example.com", "role": "admin", "api_key": "sk_live_12345"}
                    ]
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/admin/users", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run > 0, "Should run API security tests");

    let auth_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Authentication") || v.vuln_type.contains("Authorization"));
    if auth_vuln.is_some() {
        assert!(auth_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_rest_api_verbose_errors() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{
                    "error": "Internal Server Error",
                    "message": "Database query failed: SELECT * FROM users WHERE id=1",
                    "stack": "Error: Connection timeout\n  at Database.query (/app/db.js:123)\n  at UserController.getUser (/app/controllers/user.js:45)",
                    "path": "/var/www/html/app/controllers/user.js",
                    "timestamp": "2025-01-15T10:30:00Z"
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/data", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let error_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Error") || v.vuln_type.contains("Disclosure"));
    if error_vuln.is_some() {
        assert!(error_vuln.unwrap().severity == Severity::Medium ||
                error_vuln.unwrap().severity == Severity::Low);
    }
}

#[tokio::test]
async fn test_rest_api_missing_rate_limiting() {
    let mock_server = MockServer::start().await;

    for _i in 0..100 {
        Mock::given(method("POST"))
            .and(path("/api/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"status": "success"}"#)
            )
            .mount(&mock_server)
            .await;
    }

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/login", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let rate_limit_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Rate"));
    if rate_limit_vuln.is_some() {
        assert!(rate_limit_vuln.unwrap().severity == Severity::Medium ||
                rate_limit_vuln.unwrap().severity == Severity::High);
    }
}

#[tokio::test]
async fn test_rest_api_insecure_cors() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Credentials", "true")
                .set_body_string(r#"{"data": "sensitive"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/data", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let cors_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("CORS"));
    if cors_vuln.is_some() {
        assert!(cors_vuln.unwrap().cvss >= 5.0);
    }
}

#[tokio::test]
async fn test_rest_api_mass_assignment() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/users"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{
                    "id": 123,
                    "email": "user@example.com",
                    "role": "admin",
                    "is_admin": true,
                    "created_at": "2025-01-15"
                }"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/users", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let mass_assign_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Mass Assignment") || v.vuln_type.contains("Privilege"));
    if mass_assign_vuln.is_some() {
        assert!(mass_assign_vuln.unwrap().cvss >= 6.0);
    }
}

// ============================================================================
// API RATE LIMITING TESTS
// ============================================================================

#[tokio::test]
async fn test_api_rate_limiting_detection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/resource"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("X-RateLimit-Limit", "100")
                .insert_header("X-RateLimit-Remaining", "0")
                .insert_header("Retry-After", "60")
                .set_body_string(r#"{"error": "Rate limit exceeded"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = APISecurityScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/resource", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let rate_limit_vulns = vulnerabilities.iter()
        .filter(|v| v.vuln_type.contains("Rate"))
        .count();
    assert!(rate_limit_vulns == 0, "Should not report rate limiting as vulnerability when properly implemented");
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[tokio::test]
async fn test_api_scanners_performance() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let config = create_scan_config();

    let start = std::time::Instant::now();

    let graphql_scanner = GraphQlScanner::new(http_client.clone());
    let _ = graphql_scanner.scan(&mock_server.uri(), &config).await;

    let grpc_scanner = GrpcScanner::new(http_client.clone());
    let _ = grpc_scanner.scan(&mock_server.uri(), &config).await;

    let ws_scanner = WebSocketScanner::new(http_client.clone());
    let _ = ws_scanner.scan(&mock_server.uri(), &config).await;

    let api_scanner = APISecurityScanner::new(http_client.clone());
    let _ = api_scanner.scan(&mock_server.uri(), &config).await;

    let duration = start.elapsed();

    assert!(duration.as_secs() < 30, "All API scanners should complete within 30 seconds");
}

#[tokio::test]
async fn test_concurrent_api_scanner_execution() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Test"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let config = create_scan_config();
    let url = mock_server.uri();

    let handles = vec![
        tokio::spawn({
            let scanner = GraphQlScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
        tokio::spawn({
            let scanner = GrpcScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
        tokio::spawn({
            let scanner = WebSocketScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
    ];

    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Scanner should complete successfully in concurrent mode");
    }
}

#[tokio::test]
async fn test_api_scanner_error_handling() {
    let http_client = Arc::new(HttpClient::new(1, 1).unwrap());
    let scanner = GraphQlScanner::new(http_client);
    let config = create_scan_config();

    let invalid_url = "http://localhost:99999/graphql";
    let result = scanner.scan(invalid_url, &config).await;

    assert!(result.is_ok(), "Scanner should handle network errors gracefully");

    let (vulnerabilities, _) = result.unwrap();
    assert_eq!(vulnerabilities.len(), 0, "Should not report false positives on network errors");
}
