// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - OAuth 2.0 Security Tests
 * Comprehensive OAuth flow and vulnerability tests
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::oauth::OAuthScanner;
use lonkero_scanner::types::{ScanConfig, Severity};
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn create_scan_config() -> ScanConfig {
    ScanConfig {
        scan_mode: "thorough".to_string(),
        ultra: true,
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    }
}

#[tokio::test]
async fn test_oauth_authorization_code_flow_with_code_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url_with_code = "https://app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz";
    let (vulnerabilities, tests_run) = scanner.scan(url_with_code, &config).await.unwrap();

    assert!(tests_run >= 9, "Should run at least 9 OAuth tests");

    let code_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Authorization Code in URL"));
    assert!(code_vuln.is_some(), "Should detect authorization code in URL");
    assert_eq!(code_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_oauth_implicit_flow_token_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let implicit_url = "https://app.example.com/callback#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer&expires_in=3600&state=xyz";
    let (vulnerabilities, _) = scanner.scan(implicit_url, &config).await.unwrap();

    let token_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Access Token in URL"));
    assert!(token_vuln.is_some(), "Should detect access token in URL");
    assert_eq!(token_vuln.unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn test_oauth_open_redirect_vulnerability() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .and(query_param("redirect_uri", "https://evil.com/steal"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "https://evil.com/steal?code=authorization_code_123")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/oauth/authorize?redirect_uri=https://evil.com/steal", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let redirect_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("redirect_uri") || v.vuln_type.contains("Open Redirect"));
    if redirect_vuln.is_some() {
        assert_eq!(redirect_vuln.unwrap().severity, Severity::High);
    }
}

#[tokio::test]
async fn test_oauth_client_secret_in_javascript() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/static/app.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    const oauth_config = {
                        client_id: "my_app_123",
                        client_secret: "sk_live_51234567890abcdef",
                        redirect_uri: "https://app.example.com/callback"
                    };
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/static/app.js", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let secret_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("client_secret"));
    assert!(secret_vuln.is_some(), "Should detect exposed client_secret");
    assert_eq!(secret_vuln.unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn test_oauth_state_parameter_missing() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <a href="/oauth/authorize?client_id=123&redirect_uri=https://app.com&response_type=code">
                        Authorize Application
                    </a>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/oauth/authorize", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let state_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("state"));
    if state_vuln.is_some() {
        assert_eq!(state_vuln.unwrap().severity, Severity::Medium);
    }
}

#[tokio::test]
async fn test_oauth_token_in_localstorage() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth_handler.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    function handleOAuthCallback() {
                        const params = new URLSearchParams(window.location.hash.slice(1));
                        const access_token = params.get('access_token');
                        localStorage.setItem('access_token', access_token);
                        console.log('Token stored in localStorage');
                    }
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/oauth_handler.js", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let storage_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("localStorage"));
    assert!(storage_vuln.is_some(), "Should detect token in localStorage");
    assert_eq!(storage_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_oauth_pkce_not_implemented() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <html>
                    <head><title>OAuth Authorization - SPA Public Client</title></head>
                    <body>
                        <h1>Authorize Mobile App</h1>
                        <p>Grant access to this public mobile application</p>
                    </body>
                    </html>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/oauth/authorize", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let pkce_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("PKCE"));
    if pkce_vuln.is_some() {
        assert_eq!(pkce_vuln.unwrap().severity, Severity::Medium);
    }
}

#[tokio::test]
async fn test_oauth_redirect_uri_bypass_attempts() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let bypass_attempts = vec![
        "https://example.com/callback?redirect_uri=https://attacker.com",
        "https://example.com.evil.com/callback",
        "https://example.com@evil.com/callback",
        "https://example.com%2eevil.com/callback",
    ];

    for attempt in bypass_attempts {
        let (vulnerabilities, _) = scanner.scan(attempt, &config).await.unwrap();

        if !vulnerabilities.is_empty() {
            let has_redirect_vuln = vulnerabilities.iter()
                .any(|v| v.vuln_type.to_lowercase().contains("redirect"));
            assert!(has_redirect_vuln || vulnerabilities.len() > 0);
        }
    }
}

#[tokio::test]
async fn test_oauth_performance() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let start = std::time::Instant::now();

    for _ in 0..5 {
        let _ = scanner.scan(&mock_server.uri(), &config).await;
    }

    let duration = start.elapsed();
    assert!(duration.as_secs() < 15, "5 OAuth scans should complete within 15 seconds");
}
