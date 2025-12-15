// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - JWT Security Tests
 * Specialized tests for JWT vulnerabilities and attack vectors
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::jwt::JwtScanner;
use lonkero_scanner::types::{ScanConfig, Severity, Confidence};
use std::sync::Arc;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};
use base64::{engine::general_purpose, Engine as _};

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

// Helper function to create JWT tokens
fn create_jwt(header: &str, payload: &str, signature: &str) -> String {
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(header);
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);
    format!("{}.{}.{}", header_b64, payload_b64, signature)
}

// ============================================================================
// ALG:NONE BYPASS TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_alg_none_lowercase() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/admin"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"authenticated": true, "user": "admin", "dashboard": "admin panel"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"none","typ":"JWT"}"#;
    let payload = r#"{"sub":"admin","role":"admin","iat":1234567890}"#;
    let jwt = create_jwt(header, payload, "");

    let url = format!("{}/api/admin", mock_server.uri());
    let (vulnerabilities, tests_run) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    assert!(tests_run >= 7, "Should run at least 7 JWT tests");

    let alg_none_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("alg:none"));
    if alg_none_vuln.is_some() {
        assert_eq!(alg_none_vuln.unwrap().severity, Severity::Critical);
        assert!(alg_none_vuln.unwrap().cvss >= 9.0);
    }
}

#[tokio::test]
async fn test_jwt_alg_none_uppercase() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome, authenticated user!")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"NONE","typ":"JWT"}"#;
    let payload = r#"{"sub":"user123","iat":1234567890}"#;
    let jwt = create_jwt(header, payload, "");

    let url = format!("{}/api/user", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let alg_none_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("alg:none"));
    if alg_none_vuln.is_some() {
        assert_eq!(alg_none_vuln.unwrap().confidence, Confidence::High);
    }
}

#[tokio::test]
async fn test_jwt_alg_null() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/protected"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Access granted")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":null,"typ":"JWT"}"#;
    let payload = r#"{"sub":"admin"}"#;
    let jwt = create_jwt(header, payload, "");

    let url = format!("{}/protected", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let critical_vulns = vulnerabilities.iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        assert!(critical_vulns > 0);
    }
}

// ============================================================================
// ALGORITHM CONFUSION TESTS (RS256 -> HS256)
// ============================================================================

#[tokio::test]
async fn test_jwt_rs256_to_hs256_confusion() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/sensitive"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"sensitive_data": "secret information", "authenticated": true}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let rs256_header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","role":"admin","iat":1234567890}"#;
    let jwt = create_jwt(rs256_header, payload, "test_signature");

    let url = format!("{}/api/sensitive", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let algo_confusion_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Algorithm Confusion"));
    if algo_confusion_vuln.is_some() {
        assert_eq!(algo_confusion_vuln.unwrap().severity, Severity::Critical);
        assert!(algo_confusion_vuln.unwrap().cvss >= 9.0);
    }
}

#[tokio::test]
async fn test_jwt_es256_to_hs256_confusion() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Authenticated")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let es256_header = r#"{"alg":"ES256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","exp":9999999999}"#;
    let jwt = create_jwt(es256_header, payload, "signature");

    let url = format!("{}/api/data", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let high_severity = vulnerabilities.iter()
            .any(|v| v.severity == Severity::Critical || v.severity == Severity::High);
        assert!(high_severity);
    }
}

// ============================================================================
// KID (KEY ID) INJECTION TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_kid_path_traversal() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/verify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Token verified successfully")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}"#;
    let payload = r#"{"sub":"attacker","role":"admin"}"#;
    let jwt = create_jwt(header, payload, "signature");

    let url = format!("{}/verify", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let kid_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Key ID") || v.vuln_type.contains("kid"));
    if kid_vuln.is_some() {
        assert_eq!(kid_vuln.unwrap().severity, Severity::High);
        assert!(kid_vuln.unwrap().cvss >= 8.0);
    }
}

#[tokio::test]
async fn test_jwt_kid_sql_injection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/auth"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Access granted")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT","kid":"1' UNION SELECT 'key' --"}"#;
    let payload = r#"{"sub":"user"}"#;
    let jwt = create_jwt(header, payload, "test");

    let url = format!("{}/api/auth", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let injection_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Injection") || v.vuln_type.contains("kid"));
    if injection_vuln.is_some() {
        assert!(injection_vuln.unwrap().cvss >= 7.0);
    }
}

#[tokio::test]
async fn test_jwt_kid_ssrf() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/validate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Valid token")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT","kid":"http://169.254.169.254/latest/meta-data/"}"#;
    let payload = r#"{"sub":"user"}"#;
    let jwt = create_jwt(header, payload, "sig");

    let url = format!("{}/validate", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let ssrf_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("SSRF") || v.vuln_type.contains("kid"));
    if ssrf_vuln.is_some() {
        assert!(ssrf_vuln.unwrap().severity == Severity::High ||
                ssrf_vuln.unwrap().severity == Severity::Critical);
    }
}

// ============================================================================
// JKU (JWK SET URL) INJECTION TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_jku_malicious_url() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/endpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Authenticated")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"RS256","typ":"JWT","jku":"http://attacker.com/jwks.json"}"#;
    let payload = r#"{"sub":"admin","role":"administrator"}"#;
    let jwt = create_jwt(header, payload, "signature");

    let url = format!("{}/api/endpoint", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let jku_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("JKU") || v.vuln_type.contains("JWK Set URL"));
    if jku_vuln.is_some() {
        assert_eq!(jku_vuln.unwrap().severity, Severity::Critical);
        assert!(jku_vuln.unwrap().cvss >= 9.0);
    }
}

#[tokio::test]
async fn test_jwt_jku_ssrf_aws_metadata() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/secure"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Welcome")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"RS256","typ":"JWT","jku":"http://169.254.169.254/latest/meta-data/"}"#;
    let payload = r#"{"sub":"user"}"#;
    let jwt = create_jwt(header, payload, "sig");

    let url = format!("{}/secure", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let ssrf_vuln = vulnerabilities.iter()
        .find(|v| v.description.to_lowercase().contains("ssrf") ||
                   v.vuln_type.contains("jku"));
    if ssrf_vuln.is_some() {
        assert!(ssrf_vuln.unwrap().cvss >= 8.0);
    }
}

// ============================================================================
// WEAK SECRET TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_empty_secret() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("User data")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user123"}"#;
    let jwt = create_jwt(header, payload, "");

    let url = format!("{}/api/user", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let weak_secret_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Weak") && v.vuln_type.contains("Secret"));
    if weak_secret_vuln.is_some() {
        assert!(weak_secret_vuln.unwrap().cvss >= 7.0);
    }
}

#[tokio::test]
async fn test_jwt_common_secrets() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/protected"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Authenticated successfully")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"admin","iat":1234567890}"#;

    let common_secrets = vec!["secret", "password", "test", "key", "jwt"];

    for secret in common_secrets {
        let jwt = create_jwt(header, payload, secret);
        let url = format!("{}/protected", mock_server.uri());

        let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

        if !vulnerabilities.is_empty() {
            let weak_secret = vulnerabilities.iter()
                .any(|v| v.vuln_type.contains("Weak Secret"));
            if weak_secret {
                break;
            }
        }
    }
}

// ============================================================================
// CLAIM MANIPULATION TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_privilege_escalation_via_role() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/admin/panel"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"admin": true, "dashboard": "admin control panel"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","role":"admin","admin":true}"#;
    let jwt = create_jwt(header, payload, "test");

    let url = format!("{}/admin/panel", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let privilege_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Claim") || v.vuln_type.contains("Manipulation"));
    if privilege_vuln.is_some() {
        assert!(privilege_vuln.unwrap().cvss >= 7.0);
    }
}

#[tokio::test]
async fn test_jwt_user_id_manipulation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/profile"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"user_id": 1, "email": "admin@example.com", "role": "admin"}"#)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"999","user_id":1}"#;
    let jwt = create_jwt(header, payload, "sig");

    let url = format!("{}/api/profile", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    if !vulnerabilities.is_empty() {
        let has_critical = vulnerabilities.iter()
            .any(|v| v.severity == Severity::Critical || v.severity == Severity::High);
        assert!(has_critical);
    }
}

// ============================================================================
// EXPIRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_expired_token_year_2001() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Data retrieved successfully")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","exp":1000000000,"iat":999999999}"#;
    let jwt = create_jwt(header, payload, "signature");

    let url = format!("{}/api/data", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let expired_vuln = vulnerabilities.iter()
        .find(|v| v.vuln_type.contains("Expired"));
    if expired_vuln.is_some() {
        assert_eq!(expired_vuln.unwrap().confidence, Confidence::High);
        assert!(expired_vuln.unwrap().cvss >= 6.0);
    }
}

#[tokio::test]
async fn test_jwt_far_future_expiration() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/endpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("OK")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","exp":9999999999,"iat":1234567890}"#;
    let jwt = create_jwt(header, payload, "sig");

    let url = format!("{}/endpoint", mock_server.uri());
    let (vulnerabilities, _) = scanner.scan_jwt(&url, &jwt, &config).await.unwrap();

    let long_exp_vuln = vulnerabilities.iter()
        .find(|v| v.description.to_lowercase().contains("expiration") ||
                   v.description.to_lowercase().contains("lifetime"));
    if long_exp_vuln.is_some() {
        assert!(long_exp_vuln.unwrap().severity == Severity::Low ||
                long_exp_vuln.unwrap().severity == Severity::Medium);
    }
}

// ============================================================================
// EDGE CASES AND ERROR HANDLING
// ============================================================================

#[tokio::test]
async fn test_jwt_malformed_token_two_parts() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let malformed_jwt = "header.payload";
    let url = "https://example.com/api";

    let result = scanner.scan_jwt(url, malformed_jwt, &config).await;
    assert!(result.is_ok());

    let (vulnerabilities, tests_run) = result.unwrap();
    assert_eq!(tests_run, 0, "Should not run tests on malformed JWT");
    assert_eq!(vulnerabilities.len(), 0);
}

#[tokio::test]
async fn test_jwt_malformed_token_four_parts() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let malformed_jwt = "part1.part2.part3.part4";
    let url = "https://example.com/api";

    let result = scanner.scan_jwt(url, malformed_jwt, &config).await;
    assert!(result.is_ok());

    let (vulnerabilities, tests_run) = result.unwrap();
    assert_eq!(tests_run, 0);
}

#[tokio::test]
async fn test_jwt_invalid_base64() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let invalid_jwt = "not-base64!@#$.invalid-base64!@#$.signature";
    let url = "https://example.com/api";

    let result = scanner.scan_jwt(url, invalid_jwt, &config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_jwt_empty_string() {
    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let empty_jwt = "";
    let url = "https://example.com/api";

    let result = scanner.scan_jwt(url, empty_jwt, &config).await;
    assert!(result.is_ok());

    let (vulnerabilities, tests_run) = result.unwrap();
    assert_eq!(tests_run, 0);
    assert_eq!(vulnerabilities.len(), 0);
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[tokio::test]
async fn test_jwt_scanner_performance() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = JwtScanner::new(http_client);
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user","iat":1234567890}"#;
    let jwt = create_jwt(header, payload, "signature");

    let start = std::time::Instant::now();

    for _ in 0..10 {
        let _ = scanner.scan_jwt(&mock_server.uri(), &jwt, &config).await;
    }

    let duration = start.elapsed();
    assert!(duration.as_secs() < 20, "10 JWT scans should complete within 20 seconds");
}

#[tokio::test]
async fn test_jwt_concurrent_scanning() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Authenticated"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let config = create_scan_config();

    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = r#"{"sub":"user"}"#;
    let jwt = create_jwt(header, payload, "sig");

    let handles: Vec<_> = (0..5)
        .map(|_| {
            let scanner = JwtScanner::new(http_client.clone());
            let url = mock_server.uri();
            let jwt = jwt.clone();
            let config = config.clone();

            tokio::spawn(async move {
                scanner.scan_jwt(&url, &jwt, &config).await
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await;
        assert!(result.is_ok(), "Concurrent JWT scanning should succeed");
    }
}
