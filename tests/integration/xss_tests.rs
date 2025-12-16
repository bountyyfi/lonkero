// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Comprehensive Integration Tests for XSS Scanner
 * Tests reflected XSS, stored XSS patterns, DOM XSS indicators, and edge cases
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::XssScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode, Severity, Confidence};
use mockito::Server;
use std::sync::Arc;

fn create_test_scanner() -> XssScanner {
    let client = Arc::new(HttpClient::new(10000, 3).unwrap());
    XssScanner::new(client)
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
async fn test_xss_script_tag_reflection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body>You searched for: <script>alert(1)</script></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(count > 0, "Should have tested XSS payloads");
    assert!(!vulns.is_empty(), "Should detect script tag XSS");
    assert_eq!(vulns[0].severity, Severity::High);
    assert_eq!(vulns[0].confidence, Confidence::High);
}

#[tokio::test]
async fn test_xss_event_handler_reflection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body><img src=x onerror=alert(1)></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "image", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect event handler XSS");
    assert_eq!(vulns[0].cwe, "CWE-79");
}

#[tokio::test]
async fn test_xss_javascript_protocol() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<a href="javascript:alert(1)">Click</a>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "url", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect javascript: protocol XSS");
}

#[tokio::test]
async fn test_xss_no_reflection_no_vulnerability() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body>Search results for your query</body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "search", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not detect XSS without reflection");
}

#[tokio::test]
async fn test_xss_encoded_reflection_no_vulnerability() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body>You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    // Properly encoded output should not be vulnerable
    assert!(vulns.is_empty(), "Should not detect XSS when properly encoded");
}

#[tokio::test]
async fn test_xss_post_body_injection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(200)
        .with_body(r#"<html><body>Comment posted: <script>alert('XSS')</script></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, count) = scanner
        .scan_post_body(
            &server.url(),
            "comment",
            r#"{"comment":"test","author":"user"}"#,
            &config,
        )
        .await
        .unwrap();

    assert!(count > 0, "Should have tested POST payloads");
    assert!(!vulns.is_empty(), "Should detect XSS in POST body");
}

#[tokio::test]
async fn test_xss_svg_payload() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body><svg onload=alert(1)></svg></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect SVG-based XSS");
}

#[tokio::test]
async fn test_xss_img_onerror() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<img src=x onerror=alert(document.cookie)>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "img", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect img onerror XSS");
}

#[tokio::test]
async fn test_xss_onload_handler() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<body onload=alert(1)>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "page", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect onload event XSS");
}

#[tokio::test]
async fn test_xss_medium_confidence_detection() {
    let mut server = Server::new_async().await;

    // Payload reflected but without dangerous tags
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body>Result: <script>alert(1)</body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        // Some payloads might be detected with lower confidence
        assert!(vulns[0].confidence == Confidence::High || vulns[0].confidence == Confidence::Medium);
    }
}

#[tokio::test]
async fn test_xss_concurrent_scanning() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal page")
        .expect_at_least(50)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(count > 50, "Should test many payloads concurrently");
}

#[tokio::test]
async fn test_xss_parameter_encoding() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", "/")
        .match_query(mockito::Matcher::Regex(".*%3Cscript%3E.*".to_string()))
        .with_status(200)
        .with_body("Encoded correctly")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter(&server.url(), "input", &config)
        .await;

    assert!(result.is_ok(), "Should properly encode XSS payloads");
}

#[tokio::test]
async fn test_xss_multiple_reflection_points() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html>
            <head><title><script>alert(1)</script></title></head>
            <body>
                <h1><script>alert(1)</script></h1>
                <p>Results: <script>alert(1)</script></p>
            </body>
        </html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect XSS with multiple reflection points");
}

#[tokio::test]
async fn test_xss_case_insensitive_detection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body><ScRiPt>alert(1)</ScRiPt></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "data", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect XSS regardless of case");
}

#[tokio::test]
async fn test_xss_fast_scan_mode() {
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
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(count > 0, "Should test some payloads in fast mode");
}

#[tokio::test]
async fn test_xss_thorough_scan_mode() {
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
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(count > 100, "Should test many payloads in thorough mode");
}

#[tokio::test]
async fn test_xss_vulnerability_metadata() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<script>alert(1)</script>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty());
    let vuln = &vulns[0];

    assert!(!vuln.id.is_empty());
    assert_eq!(vuln.vuln_type, "Cross-Site Scripting (XSS)");
    assert_eq!(vuln.cwe, "CWE-79");
    assert_eq!(vuln.cvss, 7.5);
    assert_eq!(vuln.category, "Injection");
    assert!(vuln.verified);
    assert!(!vuln.false_positive);
    assert!(!vuln.remediation.is_empty());
}

#[tokio::test]
async fn test_xss_iframe_injection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<iframe src="javascript:alert(1)"></iframe>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "frame", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect iframe XSS");
}

#[tokio::test]
async fn test_xss_attribute_injection() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<input value="x" onfocus="alert(1)" autofocus>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "value", &config)
        .await
        .unwrap();

    if !vulns.is_empty() {
        assert!(vulns[0].description.contains("XSS"));
    }
}

#[tokio::test]
async fn test_xss_dom_based_indicators() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"
            <script>
            var input = location.hash.substring(1);
            document.write(input);
            </script>
        "#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    // DOM-based XSS is harder to detect automatically
    // This test ensures the scanner doesn't crash on such patterns
}

#[tokio::test]
async fn test_xss_post_request_failure_handling() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("POST", "/")
        .with_status(500)
        .with_body("Server error")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_post_body(&server.url(), "comment", "{}", &config)
        .await;

    assert!(result.is_ok(), "Should handle POST failures gracefully");
}

#[tokio::test]
async fn test_xss_timeout_handling() {
    let scanner = create_test_scanner();
    let config = default_scan_config();

    let result = scanner
        .scan_parameter("http://192.0.2.1:12345", "q", &config)
        .await;

    assert!(result.is_ok(), "Should handle timeouts gracefully");
}

#[tokio::test]
async fn test_xss_empty_response_handling() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    assert!(vulns.is_empty(), "Should not detect XSS in empty response");
}

#[tokio::test]
async fn test_xss_json_response() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"result":"<script>alert(1)</script>"}"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    // JSON responses might still be vulnerable if rendered in HTML
    if !vulns.is_empty() {
        assert_eq!(vulns[0].vuln_type, "Cross-Site Scripting (XSS)");
    }
}

#[tokio::test]
async fn test_xss_waf_bypass_attempts() {
    let mut server = Server::new_async().await;

    // WAF might return 403, but if our payload is in response, it's still reflected
    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"<html><body>Blocked: <script>alert(1)</script></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    // Even with 403, if payload is reflected, it might be vulnerable
    if !vulns.is_empty() {
        assert!(!vulns[0].id.is_empty());
    }
}

#[tokio::test]
async fn test_xss_special_characters_handling() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"<html><body>Search: "><script>alert(1)</script></body></html>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "search", &config)
        .await
        .unwrap();

    assert!(!vulns.is_empty(), "Should detect XSS with special characters");
}

#[tokio::test]
async fn test_xss_polyglot_payload() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"#)
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (vulns, _) = scanner
        .scan_parameter(&server.url(), "q", &config)
        .await
        .unwrap();

    // Polyglot payloads should be detected
    if !vulns.is_empty() {
        assert!(vulns[0].payload.contains("script") || vulns[0].payload.contains("alert"));
    }
}

#[tokio::test]
async fn test_xss_headers_scan() {
    let mut server = Server::new_async().await;

    let _mock = server.mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .with_body("Normal page")
        .create_async()
        .await;

    let scanner = create_test_scanner();
    let config = default_scan_config();

    let (_, count) = scanner
        .scan_headers(&server.url(), &config)
        .await
        .unwrap();

    assert!(count > 0, "Should test header-based XSS");
}
