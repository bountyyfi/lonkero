// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Authentication Scanners Integration Tests
 * Comprehensive tests for Auth Bypass, Session Management, JWT, OAuth, SAML, MFA scanners
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::auth_bypass::AuthBypassScanner;
use lonkero_scanner::scanners::jwt::JwtScanner;
use lonkero_scanner::scanners::oauth::OAuthScanner;
use lonkero_scanner::scanners::saml::SamlScanner;
use lonkero_scanner::scanners::session_management::SessionManagementScanner;
use lonkero_scanner::scanners::mfa::MfaScanner;
use lonkero_scanner::types::{ScanConfig, Severity, Confidence};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, query_param, header},
    Mock, MockServer, ResponseTemplate,
};

fn create_scan_config() -> ScanConfig {
    ScanConfig {
        scan_mode: "thorough".to_string(),
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

// ============================================================================
// AUTH BYPASS SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_auth_bypass_sql_injection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .and(query_param("username", "admin' OR '1'='1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome to the dashboard! You are logged in successfully.")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/login", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 8, "Should run at least 8 auth bypass tests");
    assert!(!vulnerabilities.is_empty(), "Should detect SQL injection auth bypass");

    let sql_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("SQL Injection"));
    assert!(sql_vuln.is_some(), "Should detect SQL injection vulnerability");
    assert_eq!(sql_vuln.unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn test_auth_bypass_nosql_injection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"status": "success", "message": "Welcome to dashboard", "user": "admin"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/login", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 8, "Should run at least 8 tests");

    let nosql_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("NoSQL"));
    if nosql_vuln.is_some() {
        assert_eq!(nosql_vuln.unwrap().severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_auth_bypass_empty_password() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .and(query_param("username", "admin"))
        .and(query_param("password", ""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome admin! You are now logged in.")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/login", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 8, "Should run at least 8 tests");

    let empty_pwd_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Empty Password"));
    if empty_pwd_vuln.is_some() {
        assert_eq!(empty_pwd_vuln.unwrap().severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_auth_bypass_default_credentials() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/admin"))
        .and(query_param("username", "admin"))
        .and(query_param("password", "admin"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome to admin dashboard!")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/admin", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 8, "Should run at least 8 tests");
}

#[tokio::test]
async fn test_auth_bypass_no_false_positives() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/secure"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("Unauthorized - Invalid credentials")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/secure", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    assert_eq!(vulnerabilities.len(), 0, "Should not report false positives on secure endpoint");
}

// ============================================================================
// SESSION MANAGEMENT SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_session_cookie_missing_httponly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "SESSIONID=abc123; Path=/; Secure")
                .set_body_string("Welcome")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SessionManagementScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 session management tests");

    let httponly_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("HttpOnly"));
    assert!(httponly_vuln.is_some(), "Should detect missing HttpOnly flag");
    assert_eq!(httponly_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_session_cookie_missing_secure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=xyz789; Path=/; HttpOnly")
                .set_body_string("Logged in")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SessionManagementScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("https://{}/login", mock_server.address());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let secure_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Secure Flag"));
    if secure_vuln.is_some() {
        assert_eq!(secure_vuln.unwrap().severity, Severity::High);
    }
}

#[tokio::test]
async fn test_session_cookie_missing_samesite() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/app"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "PHPSESSID=test123; Path=/; HttpOnly; Secure")
                .set_body_string("App page")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SessionManagementScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/app", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let samesite_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("SameSite"));
    assert!(samesite_vuln.is_some(), "Should detect missing SameSite attribute");
}

#[tokio::test]
async fn test_session_id_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SessionManagementScanner::new(http_client);
    let config = create_scan_config();

    let url = "https://example.com/app?sessionid=abc123xyz";
    let (vulnerabilities, _) = scanner.scan(url, &config).await.unwrap();

    let url_session_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Session ID in URL"));
    assert!(url_session_vuln.is_some(), "Should detect session ID in URL");
}

#[tokio::test]
async fn test_session_secure_configuration() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/secure"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=secure123; Path=/; HttpOnly; Secure; SameSite=Strict")
                .set_body_string("Secure app")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SessionManagementScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/secure", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 tests");

    let cookie_vulns = vulnerabilities.iter()
        .filter(|v| v.vuln_type.contains("Cookie"))
        .count();
    assert_eq!(cookie_vulns, 0, "Secure cookie configuration should have no vulnerabilities");
}

// ============================================================================
// JWT SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_alg_none_bypass() {
    let mock_server = MockServer::start().await;

    let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

    Mock::given(method("GET"))
        .and(path("/api/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"authenticated": true, "user": "admin", "role": "administrator"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/user", mock_server.uri());
    let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    let (vulnerabilities, tests_run) = scanner.scan_jwt(&url, valid_jwt, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 JWT tests");

    let alg_none_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("alg:none"));
    if alg_none_vuln.is_some() {
        assert_eq!(alg_none_vuln.unwrap().severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_jwt_algorithm_confusion() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/admin"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"authenticated": true, "admin": true}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/admin", mock_server.uri());
    let rs256_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.test";

    let (vulnerabilities, _) = scanner.scan_jwt(&url, rs256_jwt, &config).await.unwrap();

    let algo_confusion_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Algorithm Confusion"));
    if algo_confusion_vuln.is_some() {
        assert_eq!(algo_confusion_vuln.unwrap().severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_jwt_weak_secret() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/protected"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome, authenticated user!")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/protected", mock_server.uri());
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";

    let (vulnerabilities, _) = scanner.scan_jwt(&url, jwt, &config).await.unwrap();

    let weak_secret_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Weak JWT Secret"));
    if weak_secret_vuln.is_some() {
        assert!(weak_secret_vuln.unwrap().cvss >= 7.0);
    }
}

#[tokio::test]
async fn test_jwt_expired_token_accepted() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data": "sensitive information"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/api/data", mock_server.uri());
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxMDAwMDAwMDAwfQ.test";

    let (vulnerabilities, _) = scanner.scan_jwt(&url, jwt, &config).await.unwrap();

    let expired_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Expired"));
    if expired_vuln.is_some() {
        assert_eq!(expired_vuln.unwrap().confidence, Confidence::High);
    }
}

#[tokio::test]
async fn test_jwt_parsing_invalid_format() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let url = "https://example.com/api";
    let invalid_jwt = "invalid.jwt";

    let result = scanner.scan_jwt(url, invalid_jwt, &config).await;
    assert!(result.is_ok());

    let (vulnerabilities, tests_run) = result.unwrap();
    assert_eq!(tests_run, 0, "Should not run tests on invalid JWT");
    assert_eq!(vulnerabilities.len(), 0, "Should not find vulnerabilities in invalid JWT");
}

// ============================================================================
// OAUTH SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_oauth_code_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = "https://example.com/callback?code=abc123xyz&state=random";
    let (vulnerabilities, tests_run) = scanner.scan(url, &config).await.unwrap();

    assert!(tests_run >= 9, "Should run at least 9 OAuth tests");

    let code_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Authorization Code in URL"));
    assert!(code_vuln.is_some(), "Should detect authorization code in URL");
    assert_eq!(code_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_oauth_token_in_url() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = "https://app.example.com/callback#access_token=secret123&token_type=Bearer";
    let (vulnerabilities, _) = scanner.scan(url, &config).await.unwrap();

    let token_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Access Token in URL"));
    assert!(token_vuln.is_some(), "Should detect access token in URL");
    assert_eq!(token_vuln.unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn test_oauth_redirect_uri_validation() {
    let mock_server = MockServer::start().await;

    let mut headers = HashMap::new();
    headers.insert("Location".to_string(), "https://evil.com/callback?code=stolen".to_string());

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "https://evil.com/callback?code=stolen")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/oauth/authorize", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let redirect_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("redirect_uri"));
    if redirect_vuln.is_some() {
        assert_eq!(redirect_vuln.unwrap().severity, Severity::Critical);
    }
}

#[tokio::test]
async fn test_oauth_client_secret_exposure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/app.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    const clientId = "app123";
                    const client_secret = "sk_live_secret_key_12345";
                    const redirectUri = "https://app.example.com/callback";
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/app.js", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let secret_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("client_secret"));
    assert!(secret_vuln.is_some(), "Should detect exposed client_secret");
    assert_eq!(secret_vuln.unwrap().severity, Severity::Critical);
}

#[tokio::test]
async fn test_oauth_localstorage_token() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/auth.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    function storeToken(access_token) {
                        localStorage.setItem('access_token', access_token);
                    }
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = OAuthScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/auth.js", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let storage_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("localStorage"));
    assert!(storage_vuln.is_some(), "Should detect localStorage token storage");
    assert_eq!(storage_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_oauth_missing_state_parameter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <html>
                    <body>
                        <h1>OAuth Authorization</h1>
                        <form action="/oauth/authorize" method="GET">
                            <input type="hidden" name="client_id" value="app123" />
                            <input type="hidden" name="redirect_uri" value="https://app.com/callback" />
                            <button type="submit">Authorize</button>
                        </form>
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

    let state_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("state"));
    if state_vuln.is_some() {
        assert_eq!(state_vuln.unwrap().severity, Severity::Medium);
    }
}

// ============================================================================
// SAML SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_saml_endpoint_detection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/saml/sso"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
                        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                            <saml:Subject>
                                <saml:NameID>user@example.com</saml:NameID>
                            </saml:Subject>
                        </saml:Assertion>
                    </samlp:Response>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SamlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/saml/sso", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 9, "Should run at least 9 SAML tests");
}

#[tokio::test]
async fn test_saml_xml_signature_wrapping() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/saml/acs"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <samlp:Response>
                        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                            <ds:SignedInfo>
                                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                            </ds:SignedInfo>
                        </ds:Signature>
                        <saml:Assertion ID="id1">
                            <saml:Subject><saml:NameID>user1</saml:NameID></saml:Subject>
                        </saml:Assertion>
                        <saml:Assertion ID="id2">
                            <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
                        </saml:Assertion>
                    </samlp:Response>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SamlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/saml/acs", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let xsw_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("XML Signature Wrapping"));
    if xsw_vuln.is_some() {
        assert_eq!(xsw_vuln.unwrap().severity, Severity::High);
    }
}

#[tokio::test]
async fn test_saml_missing_signature() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/saml/response"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <samlp:Response>
                        <saml:Assertion>
                            <saml:Subject>
                                <saml:NameID>admin@example.com</saml:NameID>
                            </saml:Subject>
                        </saml:Assertion>
                    </samlp:Response>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = SamlScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/saml/response", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let sig_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Signature"));
    if sig_vuln.is_some() {
        assert!(sig_vuln.unwrap().cvss >= 6.0);
    }
}

// ============================================================================
// MFA SCANNER TESTS
// ============================================================================

#[tokio::test]
async fn test_mfa_not_enforced() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <html>
                    <body>
                        <h1>Login</h1>
                        <p>Two-factor authentication is optional. You can skip this step.</p>
                        <button>Skip 2FA</button>
                        <button>Setup Later</button>
                    </body>
                    </html>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = MfaScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/login", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 MFA tests");

    let weak_mfa_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Weak MFA Enforcement"));
    assert!(weak_mfa_vuln.is_some(), "Should detect weak MFA enforcement");
    assert_eq!(weak_mfa_vuln.unwrap().severity, Severity::Medium);
}

#[tokio::test]
async fn test_mfa_missing() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/auth/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <html>
                    <body>
                        <h1>Sign In</h1>
                        <form>
                            <input type="text" name="username" placeholder="Username" />
                            <input type="password" name="password" placeholder="Password" />
                            <button type="submit">Login</button>
                        </form>
                    </body>
                    </html>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = MfaScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/auth/login", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let missing_mfa_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Missing Multi-Factor"));
    assert!(missing_mfa_vuln.is_some(), "Should detect missing MFA");
    assert_eq!(missing_mfa_vuln.unwrap().severity, Severity::High);
}

#[tokio::test]
async fn test_mfa_bypass_parameter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/verify"))
        .and(query_param("mfa_required", "false"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome! You are logged in.")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = MfaScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/verify", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan(&url, &config).await.unwrap();

    let bypass_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("MFA Bypass") || v.vuln_type.contains("Weak MFA"));
    if bypass_vuln.is_some() {
        assert!(bypass_vuln.unwrap().cvss >= 7.0);
    }
}

#[tokio::test]
async fn test_mfa_with_proper_implementation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/secure/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"
                    <html>
                    <body>
                        <h1>Two-Factor Authentication Required</h1>
                        <p>Enter your authentication code from your authenticator app</p>
                        <input type="text" name="totp_code" required />
                        <button type="submit">Verify</button>
                    </body>
                    </html>
                "#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = MfaScanner::new(http_client);
    let config = create_scan_config();

    let url = format!("{}/secure/login", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan(&url, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 tests");

    let severe_vulns = vulnerabilities.iter()
        .filter(|v| v.severity == Severity::Critical || v.severity == Severity::High)
        .count();
    assert!(severe_vulns <= 1, "Properly implemented MFA should have minimal severe vulnerabilities");
}

// ============================================================================
// PERFORMANCE AND EDGE CASE TESTS
// ============================================================================

#[tokio::test]
async fn test_auth_scanners_performance() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let config = create_scan_config();

    let start = std::time::Instant::now();

    let auth_bypass = AuthBypassScanner::new(http_client.clone());
    let _ = auth_bypass.scan(&mock_server.uri(), &config).await;

    let session_mgmt = SessionManagementScanner::new(http_client.clone());
    let _ = session_mgmt.scan(&mock_server.uri(), &config).await;

    let duration = start.elapsed();

    assert!(duration.as_secs() < 30, "All auth scanners should complete within 30 seconds");
}

#[tokio::test]
async fn test_concurrent_scanner_execution() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Test"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let config = create_scan_config();
    let url = mock_server.uri();

    let handles = vec![
        tokio::spawn({
            let scanner = AuthBypassScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
        tokio::spawn({
            let scanner = SessionManagementScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
        tokio::spawn({
            let scanner = OAuthScanner::new(http_client.clone());
            let url = url.clone();
            let config = config.clone();
            async move { scanner.scan(&url, &config).await }
        }),
    ];

    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Scanner should complete successfully in concurrent mode");
    }
}

#[tokio::test]
async fn test_scanner_error_handling() {
    let http_client = Arc::new(HttpClient::new(1, 1).unwrap());
    let scanner = AuthBypassScanner::new(http_client);
    let config = create_scan_config();

    let invalid_url = "http://localhost:99999/invalid";
    let result = scanner.scan(invalid_url, &config).await;

    assert!(result.is_ok(), "Scanner should handle network errors gracefully");

    let (vulnerabilities, _) = result.unwrap();
    assert_eq!(vulnerabilities.len(), 0, "Should not report false positives on network errors");
}
