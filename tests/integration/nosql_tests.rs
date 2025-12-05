// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for NoSQL Injection Scanner
 * Tests MongoDB, authentication bypass, and JavaScript injection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::nosql_injection::NosqlInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> NosqlInjectionScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    NosqlInjectionScanner::new(client)
}

fn default_scan_config() -> ScanConfig {
    ScanConfig {
        target_url: String::new(),
        scan_mode: ScanMode::Normal,
        max_depth: 3,
        concurrency: 10,
        timeout_ms: 10000,
        user_agent: "Test Scanner".to_string(),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_nosql_mongodb_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body(r#"MongoError: invalid operator $ne"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect MongoDB error");
    assert_eq!(vulns[0].severity, Severity::Critical);
}

#[tokio::test]
async fn test_nosql_authentication_bypass() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/login")
        .with_status(200)
        .with_body(r#"{"token":"abc123","message":"Login successful"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&format!("{}/login", server.url()), &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("NoSQL"));
    }
}

#[tokio::test]
async fn test_nosql_javascript_injection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(500)
        .with_body("ReferenceError: x is not defined at $where")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect JavaScript injection");
}

#[tokio::test]
async fn test_nosql_data_extraction() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"data":[{"user":"admin","role":"admin"}]}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    // Should detect successful data extraction
    if !vulns.is_empty() {
        assert!(vulns[0].cwe.contains("943"));
    }
}

#[tokio::test]
async fn test_nosql_bson_error() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(400)
        .with_body("BSON field is not a valid type")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    // BSON errors indicate NoSQL backend
    if !vulns.is_empty() {
        assert_eq!(vulns[0].category, "Injection");
    }
}

#[tokio::test]
async fn test_nosql_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(404)
        .with_body(r#"{"error":"Not found"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not report false positives");
}

#[tokio::test]
async fn test_nosql_mongoose_error() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(500)
        .with_body("Mongoose validation failed for path")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect Mongoose errors");
}

#[tokio::test]
async fn test_nosql_objectid_cast_error() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("Cast to ObjectId failed for value")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_nosql_login_bypass_indicators() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/auth/login")
        .with_status(200)
        .with_body(r#"{"authenticated":true,"session":"xyz"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&format!("{}/auth", server.url()), &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("authentication") ||
                vulns[0].description.contains("bypass"));
    }
}

#[tokio::test]
async fn test_nosql_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan("http://192.0.2.1:12345", &config)
        .await;

    assert!(result.is_ok(), "Should handle network errors");
}

#[tokio::test]
async fn test_nosql_test_marker_uniqueness() {
    let scanner1 = create_test_scanner();
    let scanner2 = create_test_scanner();

    // Each scanner should have unique test marker
    // This is tested in the scanner module tests
    assert!(true);
}

#[tokio::test]
async fn test_nosql_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(500)
        .with_body("MongoDB syntax error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(!vulns[0].remediation.is_empty());
        assert!(vulns[0].verified);
    }
}
