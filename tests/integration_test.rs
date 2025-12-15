// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Integration Tests
 * End-to-end tests for scanner workflows and vulnerability detection
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::crawler::WebCrawler;
use lonkero_scanner::framework_detector::FrameworkDetector;
use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::xss::XssScanner;
use lonkero_scanner::types::{ScanConfig, Severity};
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_xss_detection_workflow() {
    let mock_server = MockServer::start().await;

    let xss_payload = "<script>alert('XSS')</script>";
    let reflected_response = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {}</p>
        </body>
        </html>
    "#,
        xss_payload
    );

    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", xss_payload))
        .respond_with(ResponseTemplate::new(200).set_body_string(&reflected_response))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = XssScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let url = format!("{}/search", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan_parameter(&url, "q", &config).await.unwrap();

    assert!(tests_run > 0, "Should run some tests");
    assert!(!vulnerabilities.is_empty(), "Should detect XSS vulnerability");

    let xss_vuln = &vulnerabilities[0];
    assert_eq!(xss_vuln.vuln_type, "Cross-Site Scripting (XSS)");
    assert!(xss_vuln.severity == Severity::High || xss_vuln.severity == Severity::Medium);
    assert_eq!(xss_vuln.parameter, Some("q".to_string()));
}

#[tokio::test]
async fn test_crawler_plus_scanner_integration() {
    let mock_server = MockServer::start().await;

    let main_page = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Main Page</h1>
            <a href="{}/search?q=test">Search</a>
            <form action="/submit" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    "#,
        mock_server.uri()
    );

    let search_page = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Search Results</h1>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(main_page))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string(search_page))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client.clone(), 2, 10);

    let crawl_results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(!crawl_results.forms.is_empty(), "Should discover forms");
    assert!(!crawl_results.links.is_empty(), "Should discover links");

    let params = crawl_results.get_all_parameters();
    assert!(params.contains("username") || params.contains("password") || params.contains("q"),
        "Should discover parameters from forms or URLs");
}

#[tokio::test]
async fn test_framework_detection_integration() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/_next/static/chunks/main.js"></script>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/css/bootstrap.min.css">
        </head>
        <body>
            <div id="__next">
                <h1>Next.js App</h1>
            </div>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.18.0")
                .insert_header("CF-RAY", "1234567890abc-SJC")
                .set_body_string(html),
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    assert!(detected.iter().any(|t| t.name == "Next.js"), "Should detect Next.js");
    assert!(detected.iter().any(|t| t.name == "Bootstrap"), "Should detect Bootstrap");
    assert!(detected.iter().any(|t| t.name == "jQuery"), "Should detect jQuery");
    assert!(detected.iter().any(|t| t.name == "Nginx"), "Should detect Nginx");
    assert!(detected.iter().any(|t| t.name == "Cloudflare"), "Should detect Cloudflare");
}

#[tokio::test]
async fn test_multiple_vulnerability_detection() {
    let mock_server = MockServer::start().await;

    let xss_response = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script>alert('XSS')</script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/xss"))
        .respond_with(ResponseTemplate::new(200).set_body_string(xss_response))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = XssScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let url = format!("{}/xss", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_parameter(&url, "param", &config).await.unwrap();

    for vuln in &vulnerabilities {
        assert!(!vuln.id.is_empty(), "Vulnerability should have ID");
        assert!(!vuln.vuln_type.is_empty(), "Vulnerability should have type");
        assert!(!vuln.description.is_empty(), "Vulnerability should have description");
        assert!(!vuln.cwe.is_empty(), "Vulnerability should have CWE");
        assert!(vuln.cvss > 0.0, "Vulnerability should have CVSS score");
        assert!(!vuln.remediation.is_empty(), "Vulnerability should have remediation");
    }
}

#[tokio::test]
async fn test_scan_with_error_handling() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/error"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = XssScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let url = format!("{}/error", mock_server.uri());
    let result = scanner.scan_parameter(&url, "param", &config).await;

    assert!(result.is_ok(), "Scanner should handle errors gracefully");
}

#[tokio::test]
async fn test_post_body_scanning() {
    let mock_server = MockServer::start().await;

    let reflected_response = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <p>Submitted: <script>alert('XSS')</script></p>
        </body>
        </html>
    "#;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_string(reflected_response))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = XssScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let url = format!("{}/submit", mock_server.uri());
    let (vulnerabilities, _) = scanner
        .scan_post_body(&url, "data", r#"{"data":""}"#, &config)
        .await
        .unwrap();

    assert!(!vulnerabilities.is_empty(), "Should detect XSS in POST body");
}

#[tokio::test]
async fn test_scan_modes_payload_count() {
    let config_fast = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let config_normal = ScanConfig {
        scan_mode: "normal".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let config_thorough = ScanConfig {
        scan_mode: "thorough".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    assert_eq!(config_fast.payload_count(), 50);
    assert_eq!(config_normal.payload_count(), 500);
    assert_eq!(config_thorough.payload_count(), 5000);
}

#[tokio::test]
async fn test_crawl_and_detect_technologies() {
    let mock_server = MockServer::start().await;

    let page_with_tech = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        <body>
            <div id="__next">
                <a href="/about">About</a>
                <form action="/contact" method="POST">
                    <input type="email" name="email" />
                    <textarea name="message"></textarea>
                </form>
            </div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.18.0")
                .set_body_string(page_with_tech),
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());

    let crawler = WebCrawler::new(http_client.clone(), 1, 10);
    let crawl_results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(!crawl_results.forms.is_empty(), "Should discover contact form");
    assert!(crawl_results.get_all_parameters().contains("email"), "Should discover email parameter");
    assert!(crawl_results.get_all_parameters().contains("message"), "Should discover message parameter");

    let detector = FrameworkDetector::new(http_client);
    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    assert!(detected.iter().any(|t| t.name == "Next.js"), "Should detect Next.js");
    assert!(detected.iter().any(|t| t.name == "Nginx"), "Should detect Nginx");
}

#[tokio::test]
async fn test_vulnerability_false_positive_filtering() {
    let mock_server = MockServer::start().await;

    let safe_response = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Safe Page</h1>
            <p>No vulnerabilities here</p>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/safe"))
        .respond_with(ResponseTemplate::new(200).set_body_string(safe_response))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = XssScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let url = format!("{}/safe", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_parameter(&url, "param", &config).await.unwrap();

    assert!(vulnerabilities.is_empty() || vulnerabilities.iter().all(|v| !v.false_positive),
        "Should not report false positives");
}

#[tokio::test]
async fn test_concurrent_scanning() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Test</body></html>"))
        .expect(10..)
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = Arc::new(XssScanner::new(http_client));

    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 1,
        max_pages: 10,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    let mut handles = vec![];
    for i in 0..5 {
        let scanner = Arc::clone(&scanner);
        let url = format!("{}/test", mock_server.uri());
        let config = config.clone();
        let param = format!("param{}", i);

        let handle = tokio::spawn(async move {
            scanner.scan_parameter(&url, &param, &config).await
        });

        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent scans should succeed");
    }
}

#[tokio::test]
async fn test_deep_crawl_with_limits() {
    let mock_server = MockServer::start().await;

    for i in 0..20 {
        let page = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <body>
                <h1>Page {}</h1>
                <a href="{}/page{}">Next</a>
            </body>
            </html>
        "#,
            i,
            mock_server.uri(),
            i + 1
        );

        Mock::given(method("GET"))
            .and(path(format!("/page{}", i)))
            .respond_with(ResponseTemplate::new(200).set_body_string(page))
            .mount(&mock_server)
            .await;
    }

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 5, 10);

    let url = format!("{}/page0", mock_server.uri());
    let results = crawler.crawl(&url).await.unwrap();

    assert!(results.crawled_urls.len() <= 10, "Should respect max_pages limit");
}

#[tokio::test]
async fn test_api_endpoint_vs_html_detection() {
    let mock_server = MockServer::start().await;

    let json_response = r#"{"status":"success","data":{"users":[]}}"#;
    let html_response = r#"<!DOCTYPE html><html><body>HTML Page</body></html>"#;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(json_response),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string(html_response),
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let api_url = format!("{}/api/data", mock_server.uri());
    let results = crawler.crawl(&api_url).await.unwrap();
    assert!(results.api_endpoints.contains(&api_url), "Should detect API endpoint");

    let crawler2 = WebCrawler::new(Arc::new(HttpClient::new(30, 3).unwrap()), 1, 10);
    let page_url = format!("{}/page", mock_server.uri());
    let results2 = crawler2.crawl(&page_url).await.unwrap();
    assert!(!results2.api_endpoints.contains(&page_url), "Should not mark HTML as API");
}
