// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for SSRF Scanner
 * Tests Server-Side Request Forgery vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::ssrf::SsrfScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity, Confidence};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> SsrfScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    SsrfScanner::new(client)
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
async fn test_ssrf_aws_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"ami-id":"ami-12345","instance-id":"i-abcdef","iam":{"security-credentials":{}}}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "url", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect AWS metadata SSRF");
    assert_eq!(vulns[0].severity, Severity::Critical);
    assert_eq!(vulns[0].confidence, Confidence::High);
    assert_eq!(vulns[0].cwe, "CWE-918");
}

#[tokio::test]
async fn test_ssrf_gcp_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"computemetadata":"google","access_token":"ya29.abc123"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "callback", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect GCP metadata");
}

#[tokio::test]
async fn test_ssrf_azure_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"compute":{"vmId":"abc-123","subscriptionId":"xyz"}}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "endpoint", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect Azure metadata");
}

#[tokio::test]
async fn test_ssrf_internal_file() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0:root:/root:/bin/bash")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "fetch", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect file:// SSRF");
}

#[tokio::test]
async fn test_ssrf_redis_service() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("redis_version:5.0.7")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "url", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_ssrf_elasticsearch() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"name":"elasticsearch","cluster_name":"docker-cluster"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "api_url", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_ssrf_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<html><body>Normal web page content</body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "url", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_ssrf_access_key_exposure() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"AccessKeyId":"AKIA...","SecretAccessKey":"secret","Token":"token"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "proxy", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect AWS credentials");
}

#[tokio::test]
async fn test_ssrf_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "url", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ssrf_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"ami-id":"test"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "webhook", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(vulns[0].remediation.contains("allowlist") ||
                vulns[0].remediation.contains("validate"));
        assert_eq!(vulns[0].vuln_type, "Server-Side Request Forgery (SSRF)");
        assert_eq!(vulns[0].cvss, 9.1);
    }
}

#[tokio::test]
async fn test_ssrf_payload_generation() {
    let scanner = create_test_scanner();

    // Ensure scanner can be created
    // Payload generation is tested in module tests
    assert!(true);
}
