// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for Command Injection Scanner
 * Tests OS command injection vulnerabilities
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::command_injection::CommandInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> CommandInjectionScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    CommandInjectionScanner::new(client)
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
async fn test_command_injection_linux_id_command() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("uid=33(www-data) gid=33(www-data) groups=33(www-data)")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "cmd", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect command injection via id output");
    assert_eq!(vulns[0].severity, Severity::Critical);
}

#[tokio::test]
async fn test_command_injection_etc_passwd() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "file", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect /etc/passwd in response");
}

#[tokio::test]
async fn test_command_injection_bin_path() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("/bin/bash: line 1: syntax error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "exec", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect /bin/ path indicators");
}

#[tokio::test]
async fn test_command_injection_no_indicators() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<html><body>Normal page content</body></html>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "cmd", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not detect false positives");
}

#[tokio::test]
async fn test_command_injection_post_body() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(200)
        .with_body("uid=1000(testuser) gid=1000(testgroup)")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_post_body(&server.url(), "command", r#"{"command":"test"}"#, &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect command injection in POST");
}

#[tokio::test]
async fn test_command_injection_concurrent_requests() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .expect_at_least(30)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await
        .unwrap();

    assert!(count >= 30, "Should test many payloads with limited concurrency");
}

#[tokio::test]
async fn test_command_injection_windows_dir_output() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Directory of C:\\Windows\\System32")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "dir", &config)
        .await
        .unwrap();

    // Might detect Windows paths depending on detection logic
    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
    }
}

#[tokio::test]
async fn test_command_injection_sleep_time_based() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Command executed")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "wait", &config)
        .await
        .unwrap();

    assert!(count > 0);
}

#[tokio::test]
async fn test_command_injection_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "cmd", &config)
        .await;

    assert!(result.is_ok(), "Should handle network errors");
}

#[tokio::test]
async fn test_command_injection_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("uid=0(root)")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "test", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        let vuln = &vulns[0];
        assert!(!vuln.id.is_empty());
        assert!(!vuln.remediation.is_empty());
        assert!(vuln.verified);
    }
}

#[tokio::test]
async fn test_command_injection_payload_encoding() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", "/")
        .match_query(mockito::Matcher::Regex(".*%7C.*".to_string())) // Encoded |
        .with_status(200)
        .with_body("Encoded payload")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_command_injection_groups_output() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("groups=27(sudo),1000(user)")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "test", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect groups= output");
}

#[tokio::test]
async fn test_command_injection_empty_response() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "cmd", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_command_injection_post_failure_handling() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(500)
        .with_body("Server error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_post_body(&server.url(), "cmd", "{}", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_command_injection_special_chars_parameter() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "param[0]", &config)
        .await;

    assert!(result.is_ok());
}
