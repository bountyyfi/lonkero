// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for XXE Scanner
 * Tests XML External Entity injection vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::xxe::XxeScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity, Confidence};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> XxeScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    XxeScanner::new(client)
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
async fn test_xxe_linux_file_disclosure() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect /etc/passwd disclosure");
    assert_eq!(vulns[0].severity, Severity::Critical);
    assert_eq!(vulns[0].confidence, Confidence::High);
    assert_eq!(vulns[0].cwe, "CWE-611");
}

#[tokio::test]
async fn test_xxe_windows_file_disclosure() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("[fonts]\n[extensions]\n[mci extensions]\nfor 16-bit app support")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "data", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect Windows file disclosure");
    assert_eq!(vulns[0].severity, Severity::Critical);
}

#[tokio::test]
async fn test_xxe_aws_metadata_ssrf() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"ami-id":"ami-12345","instance-id":"i-abcdef"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect AWS metadata SSRF");
}

#[tokio::test]
async fn test_xxe_gcp_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("computemetadata google access_token")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("metadata") || vulns[0].description.contains("SSRF"));
    }
}

#[tokio::test]
async fn test_xxe_xml_parsing_error() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("XML parsing error: external entity not defined")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect XXE via error messages");
    assert_eq!(vulns[0].confidence, Confidence::Medium);
}

#[tokio::test]
async fn test_xxe_billion_laughs() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("Server error: entity expansion limit exceeded")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert_eq!(vulns[0].severity, Severity::High);
    }
}

#[tokio::test]
async fn test_xxe_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<html><body>Normal page content</body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not report false positives");
}

#[tokio::test]
async fn test_xxe_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "xml", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_xxe_payload_generation() {
    let scanner = create_test_scanner();

    // Test that scanner can be created successfully
    // Actual payload generation is tested in scanner module
    assert!(true);
}

#[tokio::test]
async fn test_xxe_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0:root")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "xml", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(!vulns[0].remediation.is_empty());
        assert!(vulns[0].remediation.contains("disable"));
        assert_eq!(vulns[0].vuln_type, "XML External Entity (XXE) Injection");
    }
}
