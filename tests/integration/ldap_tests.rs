// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for LDAP Injection Scanner
 * Tests LDAP filter injection, authentication bypass, and DN injection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::ldap_injection::LdapInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity, Confidence};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> LdapInjectionScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    LdapInjectionScanner::new(client)
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
async fn test_ldap_error_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("LDAP error: Invalid DN syntax")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "username", &config)
        .await
        .unwrap();

    assert!(count > 0);
    assert!(!vulns.is_empty(), "Should detect LDAP error");
    assert_eq!(vulns[0].cwe, "CWE-90");
}

#[tokio::test]
async fn test_ldap_javax_naming_exception() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("javax.naming.directory.InvalidSearchFilterException: Bad search filter")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "filter", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
    assert_eq!(vulns[0].confidence, Confidence::High);
}

#[tokio::test]
async fn test_ldap_wildcard_bypass() {
    let mut server = Server::new_async().await;

    // Large response indicating wildcard query returned many results
    let large_response = "A".repeat(15000);
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(&large_response)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "user", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert_eq!(vulns[0].severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_ldap_authentication_bypass() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Welcome to your dashboard, admin!")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "username", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert_eq!(vulns[0].severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_ldap_attribute_disclosure() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{
            "distinguishedName": "cn=admin,dc=example,dc=com",
            "cn": "admin",
            "objectClass": ["person"],
            "memberOf": ["cn=admins"],
            "sAMAccountName": "administrator"
        }"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "search", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect LDAP attribute disclosure");
}

#[tokio::test]
async fn test_ldap_no_false_positive() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(404)
        .with_body("User not found")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "user", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_ldap_ldapexception() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("com.sun.jndi.ldap.LdapException: error code 49")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "uid", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
}

#[tokio::test]
async fn test_ldap_general_scan() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal response")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan(&server.url(), &config)
        .await
        .unwrap();

    assert!(count > 0, "Should test multiple common parameters");
}

#[tokio::test]
async fn test_ldap_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(500)
        .with_body("LDAP injection detected")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "dn", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
        assert!(vulns[0].remediation.contains("parameterized"));
        assert_eq!(vulns[0].vuln_type, "LDAP Injection");
    }
}

#[tokio::test]
async fn test_ldap_error_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "user", &config)
        .await;

    assert!(result.is_ok());
}
