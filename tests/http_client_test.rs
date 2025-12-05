// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - HTTP Client Tests
 * Tests for User-Agent rotation, retry logic, caching, and rate limiting
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::rate_limiter::{AdaptiveRateLimiter, RateLimiterConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_http_client_get_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/test", &mock_server.uri());
    let response = client.get(&url).await.unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "Success");
}

#[tokio::test]
async fn test_http_client_post_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(201).set_body_string("Created"))
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/submit", &mock_server.uri());
    let response = client.post(&url, "test=data".to_string()).await.unwrap();

    assert_eq!(response.status_code, 201);
    assert_eq!(response.body, "Created");
}

#[tokio::test]
async fn test_http_client_retry_on_failure() {
    let mock_server = MockServer::start().await;

    let mut attempt = 0;
    Mock::given(method("GET"))
        .and(path("/flaky"))
        .respond_with(move |_req: &wiremock::Request| {
            attempt += 1;
            if attempt < 3 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_string("Success after retry")
            }
        })
        .expect(3)
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/flaky", &mock_server.uri());
    let result = client.get(&url).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_http_client_max_retries_exceeded() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/always-fail"))
        .respond_with(ResponseTemplate::new(500))
        .expect(4)
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/always-fail", &mock_server.uri());
    let result = client.get(&url).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_http_client_custom_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/headers"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/headers", &mock_server.uri());

    let headers = vec![
        ("X-Custom-Header".to_string(), "CustomValue".to_string()),
        ("Authorization".to_string(), "Bearer token123".to_string()),
    ];

    let response = client.get_with_headers(&url, headers).await.unwrap();
    assert_eq!(response.status_code, 200);
}

#[tokio::test]
async fn test_http_client_post_with_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/api", &mock_server.uri());

    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-API-Key".to_string(), "secret123".to_string()),
    ];

    let response = client.post_with_headers(&url, r#"{"test":"data"}"#, headers).await.unwrap();
    assert_eq!(response.status_code, 200);
}

#[tokio::test]
async fn test_http_client_caching() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/cacheable"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Cached response"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3)
        .unwrap()
        .with_cache(100, 60);

    let url = format!("{}/cacheable", &mock_server.uri());

    let response1 = client.get(&url).await.unwrap();
    assert_eq!(response1.status_code, 200);

    let response2 = client.get(&url).await.unwrap();
    assert_eq!(response2.status_code, 200);
    assert_eq!(response2.body, response1.body);
}

#[tokio::test]
async fn test_http_client_rate_limiting() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/limited"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("Too many requests")
        )
        .expect(1..)
        .mount(&mock_server)
        .await;

    let config = RateLimiterConfig {
        default_rps: 10,
        min_rps: 1,
        max_rps: 100,
        backoff_multiplier: 0.5,
        recovery_multiplier: 1.1,
        adaptive: true,
    };

    let rate_limiter = Arc::new(AdaptiveRateLimiter::new(config));
    let client = HttpClient::new(30, 3)
        .unwrap()
        .with_rate_limiter(rate_limiter.clone());

    let url = format!("{}/limited", &mock_server.uri());

    let initial_rps = rate_limiter.get_current_rps(&url).await;

    let _response = client.get(&url).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let new_rps = rate_limiter.get_current_rps(&url).await;
    assert!(new_rps < initial_rps, "Rate limit should decrease after 429");
}

#[tokio::test]
async fn test_http_client_rate_limiting_recovery() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/recovery"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&mock_server)
        .await;

    let config = RateLimiterConfig {
        default_rps: 50,
        min_rps: 10,
        max_rps: 200,
        backoff_multiplier: 0.5,
        recovery_multiplier: 1.2,
        adaptive: true,
    };

    let rate_limiter = Arc::new(AdaptiveRateLimiter::new(config));
    let client = HttpClient::new(30, 0)
        .unwrap()
        .with_rate_limiter(rate_limiter.clone());

    let url = format!("{}/recovery", &mock_server.uri());

    let initial_rps = rate_limiter.get_current_rps(&url).await;

    for _ in 0..101 {
        let _ = client.get(&url).await;
    }

    let new_rps = rate_limiter.get_current_rps(&url).await;
    assert!(new_rps >= initial_rps, "Rate limit should not decrease on success");
}

#[tokio::test]
async fn test_http_client_timeout() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(5))
                .set_body_string("Too slow")
        )
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(2, 0).unwrap();
    let url = format!("{}/slow", &mock_server.uri());
    let result = client.get(&url).await;

    assert!(result.is_err(), "Request should timeout");
}

#[tokio::test]
async fn test_http_client_redirect_following() {
    let mock_server = MockServer::start().await;

    let redirect_url = format!("{}/final", &mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", redirect_url.as_str())
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Final destination"))
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/redirect", &mock_server.uri());
    let response = client.get(&url).await.unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "Final destination");
}

#[tokio::test]
async fn test_http_client_response_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/headers"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Custom", "TestValue")
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"test":"data"}"#)
        )
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/headers", &mock_server.uri());
    let response = client.get(&url).await.unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.header("x-custom").map(|s| s.as_str()), Some("TestValue"));
    assert_eq!(response.header("content-type").map(|s| s.as_str()), Some("application/json"));
}

#[tokio::test]
async fn test_http_client_contains_method() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("This response contains a vulnerability marker")
        )
        .mount(&mock_server)
        .await;

    let client = HttpClient::new(30, 3).unwrap();
    let url = format!("{}/test", &mock_server.uri());
    let response = client.get(&url).await.unwrap();

    assert!(response.contains("vulnerability"));
    assert!(response.contains("marker"));
    assert!(!response.contains("not-present"));
}

#[tokio::test]
async fn test_http_client_error_handling() {
    let client = HttpClient::new(30, 0).unwrap();
    let result = client.get("http://invalid-host-that-does-not-exist-12345.com").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_http_client_http2_config() {
    let client = HttpClient::with_config(
        30,
        3,
        true,
        true,
        100,
        10
    );

    assert!(client.is_ok(), "HTTP/2 client configuration should succeed");
}

#[tokio::test]
async fn test_http_client_concurrent_requests() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/concurrent"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(10)
        .mount(&mock_server)
        .await;

    let client = Arc::new(HttpClient::new(30, 3).unwrap());
    let url = format!("{}/concurrent", &mock_server.uri());

    let mut handles = vec![];
    for _ in 0..10 {
        let client = Arc::clone(&client);
        let url = url.clone();

        let handle = tokio::spawn(async move {
            client.get(&url).await
        });

        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}
