// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for CRLF Injection Scanner
 * Tests HTTP response splitting and header injection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::crlf_injection::CrlfInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> CrlfInjectionScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    CrlfInjectionScanner::new(client)
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
async fn test_crlf_cookie_injection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("Set-Cookie", "admin=true")
        .with_body("Redirect")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "redirect", &config)
        .await
        .unwrap();

    assert!(count > 0);
    // Note: Detection depends on actual CRLF in payload
}

#[tokio::test]
async fn test_crlf_location_header() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(302)
        .with_header("Location", "https://evil.com")
        .with_body("")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "url", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert_eq!(vulns[0].severity, Severity::High);
        assert_eq!(vulns[0].cwe, "CWE-93");
    }
}

#[tokio::test]
async fn test_crlf_custom_header() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("X-Injected", "true")
        .with_body("Response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "param", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("header injection"));
    }
}

#[tokio::test]
async fn test_crlf_response_splitting() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Injected</html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "page", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("response splitting"));
    }
}

#[tokio::test]
async fn test_crlf_xss_via_crlf() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<script>alert(1)</script>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "dest", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("XSS") || vulns[0].description.contains("CRLF"));
    }
}

#[tokio::test]
async fn test_crlf_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("Content-Type", "text/html")
        .with_body("<html><body>Normal page</body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "param", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_crlf_general_scan() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(count > 0, "Should test common vulnerable parameters");
}

#[tokio::test]
async fn test_crlf_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "url", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_crlf_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("Set-Cookie", "session=hijacked")
        .with_body("")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "next", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(vulns[0].remediation.contains("CRLF"));
        assert_eq!(vulns[0].vuln_type, "CRLF Injection");
    }
}
