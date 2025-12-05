// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for Template Injection Scanner
 * Tests SSTI across multiple template engines
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::template_injection::TemplateInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> TemplateInjectionScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    TemplateInjectionScanner::new(client)
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
async fn test_ssti_jinja2_math_evaluation() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Result: 49")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "template", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect Jinja2 math evaluation");
    assert_eq!(vulns[0].severity, Severity::Critical);
    assert_eq!(vulns[0].cwe, "CWE-94");
}

#[tokio::test]
async fn test_ssti_string_multiplication() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Output: 7777777")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "name", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect string multiplication");
}

#[tokio::test]
async fn test_ssti_jinja2_class_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("<class 'flask.config.Config'>")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "data", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_ssti_command_execution() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("uid=1000(user) gid=1000(user)")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect RCE via template injection");
    assert_eq!(vulns[0].severity, Severity::Critical);
}

#[tokio::test]
async fn test_ssti_freemarker() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("FreeMarker Template Error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "view", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].vuln_type.contains("FREEMARKER"));
    }
}

#[tokio::test]
async fn test_ssti_twig() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Twig_Environment object")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "template", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].vuln_type.contains("TWIG"));
    }
}

#[tokio::test]
async fn test_ssti_smarty() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Smarty version 3.1.39")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "page", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].vuln_type.contains("SMARTY"));
    }
}

#[tokio::test]
async fn test_ssti_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal page content")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_ssti_general_scan() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(count > 0);
}

#[tokio::test]
async fn test_ssti_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "template", &config)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_ssti_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("49")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "tpl", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(vulns[0].remediation.contains("sandboxed") ||
                vulns[0].remediation.contains("template"));
        assert!(vulns[0].vuln_type.contains("Template Injection"));
    }
}
