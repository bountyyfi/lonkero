// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for Path Traversal Scanner
 * Tests directory traversal vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::path_traversal::PathTraversalScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> PathTraversalScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    PathTraversalScanner::new(client)
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
async fn test_path_traversal_etc_passwd() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "file", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect /etc/passwd");
    assert_eq!(vulns[0].severity, Severity::High);
    assert_eq!(vulns[0].cwe, "CWE-22");
}

#[tokio::test]
async fn test_path_traversal_boot_ini() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("[boot loader]\ntimeout=30")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "path", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect boot.ini");
}

#[tokio::test]
async fn test_path_traversal_php_ini() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("extension=mysqli\nextension=pdo")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "config", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_path_traversal_web_config() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<?xml version="1.0"?><configuration></configuration>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "file", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_path_traversal_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<html><body>File content</body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "doc", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_path_traversal_shell_reference() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("#!/bin/bash\necho 'test'")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "script", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_path_traversal_concurrent_scanning() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(404)
        .with_body("Not found")
        .expect_at_least(30)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "file", &config)
        .await
        .unwrap();

    assert!(count >= 30);
}

#[tokio::test]
async fn test_path_traversal_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "file", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_path_traversal_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "path", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(vulns[0].remediation.contains("allowlist") ||
                vulns[0].remediation.contains("validate"));
        assert_eq!(vulns[0].vuln_type, "Path Traversal");
    }
}
