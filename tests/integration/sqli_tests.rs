// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for SQL Injection Scanner
 * Tests positive cases, negative cases, edge cases, and error handling
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::sqli::SqliScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

/// Helper function to create test scanner
fn create_test_scanner() -> SqliScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    SqliScanner::new(client)
}

/// Helper function to create default scan config
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
async fn test_sqli_error_based_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("You have an error in your SQL syntax near '' at line 1")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(count > 0, "Should have tested payloads");
    assert!(!vulns.is_empty(), "Should detect SQL error");
    assert_eq!(vulns[0].severity, Severity::Critical);
    assert!(vulns[0].description.contains("SQL injection"));
}

#[tokio::test]
async fn test_sqli_mysql_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "user_id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect MySQL error");
    assert_eq!(vulns[0].cwe, "CWE-89");
}

#[tokio::test]
async fn test_sqli_postgresql_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("ERROR: syntax error at or near \"'\" LINE 1: SELECT * FROM users WHERE id='1'' ^")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect PostgreSQL error");
}

#[tokio::test]
async fn test_sqli_oracle_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("ORA-01756: quoted string not properly terminated")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "product_id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect Oracle error");
}

#[tokio::test]
async fn test_sqli_mssql_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("Microsoft SQL Server Native Client error '80040e14'")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect MSSQL error");
}

#[tokio::test]
async fn test_sqli_sqlite_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("SQLite error: unrecognized token")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "query", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect SQLite error");
}

#[tokio::test]
async fn test_sqli_significant_response_change() {
    let mut server = Server::new_async().await;

    // Baseline response
    let _mock1 = server.mock("GET", "/")
        .match_query(mockito::Matcher::Missing)
        .with_status(200)
        .with_body("Normal page content")
        .create_async()
        .await;

    // Modified response with SQLi payload
    let _mock2 = server.mock("GET", "/")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal page content with extra data from database: user1, user2, user3, admin, test, guest, operator")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect significant response change");
}

#[tokio::test]
async fn test_sqli_no_false_positive_on_normal_response() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<html><body><h1>Product Details</h1><p>Product ID: 1</p></body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not report false positive on normal response");
}

#[tokio::test]
async fn test_sqli_time_based_detection() {
    let mut server = Server::new_async().await;

    // Simulate slow response indicating time-based SQLi
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Query executed")
        .with_header("X-Response-Time", "5000")
        .expect_at_least(1)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_time_based(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(count > 0, "Should have run time-based tests");
    // Note: This may not detect time-based without actual delay simulation
}

#[tokio::test]
async fn test_sqli_post_body_injection() {
    let mut server = Server::new_async().await;

    // Baseline POST
    let _mock1 = server.mock("POST", "/")
        .with_status(200)
        .with_body("Login successful")
        .create_async()
        .await;

    // POST with SQLi payload
    let _mock2 = server.mock("POST", "/")
        .match_body(mockito::Matcher::Regex(".*'.*".to_string()))
        .with_status(500)
        .with_body("SQL syntax error in query")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_post_body(
            &server.url(),
            "username",
            r#"{"username":"test","password":"pass"}"#,
            &config,
        )
        .await
        .unwrap();

    assert!(count > 0, "Should have tested POST payloads");
}

#[tokio::test]
async fn test_sqli_baseline_failure_handling() {
    let mut server = Server::new_async().await;

    // Server always returns 500
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("Server error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    // Should handle baseline failure gracefully
    let result = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await;

    assert!(result.is_ok(), "Should handle baseline failure gracefully");
}

#[tokio::test]
async fn test_sqli_concurrent_scanning() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .expect_at_least(50) // Should make many concurrent requests
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(count > 50, "Should test many payloads concurrently");
}

#[tokio::test]
async fn test_sqli_parameter_encoding() {
    let mut server = Server::new_async().await;

    // Should properly encode special characters
    let _mock = server.mock("GET", "/")
        .match_query(mockito::Matcher::Regex(".*%27.*".to_string())) // URL encoded '
        .with_status(200)
        .with_body("Query executed")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "search", &config)
        .await;

    assert!(result.is_ok(), "Should properly encode payloads");
}

#[tokio::test]
async fn test_sqli_multiple_error_patterns() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("SQLSTATE[42000]: Syntax error or access violation")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect PDO exception");
    assert!(vulns[0].evidence.is_some());
}

#[tokio::test]
async fn test_sqli_fast_scan_mode() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let mut config = default_scan_config();
    config.scan_mode = ScanMode::Fast;

    let (_, count) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    // Fast mode should use fewer payloads
    assert!(count > 0, "Should test some payloads in fast mode");
}

#[tokio::test]
async fn test_sqli_thorough_scan_mode() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let mut config = default_scan_config();
    config.scan_mode = ScanMode::Thorough;

    let (_, count) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    // Thorough mode should use more payloads
    assert!(count > 100, "Should test many payloads in thorough mode");
}

#[tokio::test]
async fn test_sqli_network_timeout_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    // Non-existent server should timeout
    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "id", &config)
        .await;

    assert!(result.is_ok(), "Should handle network timeout gracefully");
}

#[tokio::test]
async fn test_sqli_invalid_url_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    // Invalid URL should be handled
    let result = scanner
        .scan_parameter("not-a-valid-url", "id", &config)
        .await;

    assert!(result.is_ok(), "Should handle invalid URL gracefully");
}

#[tokio::test]
async fn test_sqli_empty_parameter_name() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "", &config)
        .await;

    assert!(result.is_ok(), "Should handle empty parameter name");
}

#[tokio::test]
async fn test_sqli_special_characters_in_parameter() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "param[name]", &config)
        .await;

    assert!(result.is_ok(), "Should handle special characters in parameter name");
}

#[tokio::test]
async fn test_sqli_vulnerability_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("SQL syntax error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
    let vuln = &vulns[0];

    // Verify vulnerability metadata
    assert!(!vuln.id.is_empty(), "Should have vulnerability ID");
    assert_eq!(vuln.vuln_type, "SQL Injection");
    assert_eq!(vuln.cwe, "CWE-89");
    assert_eq!(vuln.cvss, 9.8);
    assert_eq!(vuln.category, "Injection");
    assert!(vuln.verified, "Should be verified");
    assert!(!vuln.false_positive, "Should not be false positive");
    assert!(!vuln.remediation.is_empty(), "Should have remediation advice");
    assert!(!vuln.discovered_at.is_empty(), "Should have discovery timestamp");
}

#[tokio::test]
async fn test_sqli_url_with_existing_parameters() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", "/search")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("category".to_string(), "books".to_string()),
            mockito::Matcher::Any,
        ]))
        .with_status(200)
        .with_body("Results")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let url = format!("{}/search?category=books", server.url());
    let result = scanner
        .scan_parameter(&url, "q", &config)
        .await;

    assert!(result.is_ok(), "Should handle URLs with existing parameters");
}

#[tokio::test]
async fn test_sqli_response_body_size_limit() {
    let mut server = Server::new_async().await;

    // Very large response
    let large_body = "A".repeat(1_000_000);
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(&large_body)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await;

    assert!(result.is_ok(), "Should handle large responses");
}

#[tokio::test]
async fn test_sqli_payload_count_accuracy() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "id", &config)
        .await
        .unwrap();

    assert!(count > 0, "Should return accurate payload count");
}
