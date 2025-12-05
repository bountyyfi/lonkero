// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Framework Detector Tests
 * Tests for technology detection from headers, HTML, cookies, and URLs
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::framework_detector::{FrameworkDetector, TechCategory, Confidence};
use lonkero_scanner::http_client::HttpClient;
use std::sync::Arc;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_detect_nginx_from_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.18.0")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let nginx = detected.iter().find(|t| t.name == "Nginx");
    assert!(nginx.is_some(), "Should detect Nginx");

    let nginx = nginx.unwrap();
    assert_eq!(nginx.category, TechCategory::Server);
    assert_eq!(nginx.confidence, Confidence::High);
    assert_eq!(nginx.version, Some("1.18.0".to_string()));
}

#[tokio::test]
async fn test_detect_apache_from_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "Apache/2.4.41 (Ubuntu)")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let apache = detected.iter().find(|t| t.name == "Apache");
    assert!(apache.is_some(), "Should detect Apache");

    let apache = apache.unwrap();
    assert_eq!(apache.category, TechCategory::Server);
    assert_eq!(apache.version, Some("2.4.41".to_string()));
}

#[tokio::test]
async fn test_detect_cloudflare_from_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("CF-RAY", "1234567890abc-SJC")
                .insert_header("CF-Cache-Status", "HIT")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let cloudflare = detected.iter().find(|t| t.name == "Cloudflare");
    assert!(cloudflare.is_some(), "Should detect Cloudflare from headers");
    assert_eq!(cloudflare.unwrap().category, TechCategory::CDN);
}

#[tokio::test]
async fn test_detect_cloudfront() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Amz-Cf-Id", "abcdef123456")
                .insert_header("X-Amz-Cf-Pop", "SFO5-C1")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let cloudfront = detected.iter().find(|t| t.name == "Amazon CloudFront");
    assert!(cloudfront.is_some(), "Should detect CloudFront");
    assert_eq!(cloudfront.unwrap().category, TechCategory::CDN);
}

#[tokio::test]
async fn test_detect_vercel_from_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Vercel-Id", "sfo1::abcde-1234567890")
                .insert_header("X-Vercel-Cache", "HIT")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let vercel = detected.iter().find(|t| t.name == "Vercel");
    assert!(vercel.is_some(), "Should detect Vercel");
    assert_eq!(vercel.unwrap().category, TechCategory::CloudProvider);
}

#[tokio::test]
async fn test_detect_netlify() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-NF-Request-Id", "01234567-89ab-cdef-0123-456789abcdef")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let netlify = detected.iter().find(|t| t.name == "Netlify");
    assert!(netlify.is_some(), "Should detect Netlify");
}

#[tokio::test]
async fn test_detect_php_from_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Powered-By", "PHP/7.4.3")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let php = detected.iter().find(|t| t.name == "PHP");
    assert!(php.is_some(), "Should detect PHP");
    assert_eq!(php.unwrap().category, TechCategory::Language);
}

#[tokio::test]
async fn test_detect_express_framework() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Powered-By", "Express")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let express = detected.iter().find(|t| t.name == "Express");
    assert!(express.is_some(), "Should detect Express");
    assert_eq!(express.unwrap().category, TechCategory::Framework);
}

#[tokio::test]
async fn test_detect_nextjs_from_html() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        <body>
            <div id="__next">
                <div>Content</div>
            </div>
            <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let nextjs = detected.iter().find(|t| t.name == "Next.js");
    assert!(nextjs.is_some(), "Should detect Next.js");
    assert_eq!(nextjs.unwrap().category, TechCategory::Framework);
}

#[tokio::test]
async fn test_detect_react_from_html() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <div id="root" data-reactroot="">
                <div>React App</div>
            </div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let react = detected.iter().find(|t| t.name == "React");
    assert!(react.is_some(), "Should detect React");
    assert_eq!(react.unwrap().category, TechCategory::JavaScript);
}

#[tokio::test]
async fn test_detect_vuejs() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <div id="app" data-v-12345678="">
                <div>Vue App</div>
            </div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let vue = detected.iter().find(|t| t.name == "Vue.js");
    assert!(vue.is_some(), "Should detect Vue.js");
}

#[tokio::test]
async fn test_detect_angular() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body ng-version="12.0.0">
            <app-root _nghost-abc-c123="">
                <div>Angular App</div>
            </app-root>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let angular = detected.iter().find(|t| t.name == "Angular");
    assert!(angular.is_some(), "Should detect Angular");
}

#[tokio::test]
async fn test_detect_wordpress() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">
        </head>
        <body>
            <script src="/wp-includes/js/jquery.js"></script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let wordpress = detected.iter().find(|t| t.name == "WordPress");
    assert!(wordpress.is_some(), "Should detect WordPress");
    assert_eq!(wordpress.unwrap().category, TechCategory::CMS);
}

#[tokio::test]
async fn test_detect_drupal() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="Generator" content="Drupal 9" />
            <link rel="stylesheet" href="/sites/default/files/css/style.css">
        </head>
        <body>
            <div>Drupal Site</div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let drupal = detected.iter().find(|t| t.name == "Drupal");
    assert!(drupal.is_some(), "Should detect Drupal");
}

#[tokio::test]
async fn test_detect_bootstrap() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/css/bootstrap.min.css">
        </head>
        <body class="container">
            <div class="row">Content</div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let bootstrap = detected.iter().find(|t| t.name == "Bootstrap");
    assert!(bootstrap.is_some(), "Should detect Bootstrap");
    assert_eq!(bootstrap.unwrap().category, TechCategory::CSS);
}

#[tokio::test]
async fn test_detect_tailwind() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body class="bg-gray-100 tw-container">
            <div class="flex items-center justify-center">Content</div>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let tailwind = detected.iter().find(|t| t.name == "Tailwind CSS");
    assert!(tailwind.is_some(), "Should detect Tailwind CSS");
}

#[tokio::test]
async fn test_detect_jquery() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let jquery = detected.iter().find(|t| t.name == "jQuery");
    assert!(jquery.is_some(), "Should detect jQuery");
}

#[tokio::test]
async fn test_detect_google_analytics() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script async src="https://www.google-analytics.com/analytics.js"></script>
            <script>
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
            </script>
        </head>
        <body>Content</body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let ga = detected.iter().find(|t| t.name == "Google Analytics");
    assert!(ga.is_some(), "Should detect Google Analytics");
    assert_eq!(ga.unwrap().category, TechCategory::Analytics);
}

#[tokio::test]
async fn test_detect_webpack() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <script src="/static/js/main.chunk.js"></script>
            <script>!function(e){function r(r){for(var n,l,f=r[0],i=r[1],a=r[2],c=0,s=[];c<f.length;c++)l=f[c],Object.prototype.hasOwnProperty.call(o,l)&&o[l]&&s.push(o[l][0]),o[l]=0;for(n in i)Object.prototype.hasOwnProperty.call(i,n)&&(e[n]=i[n]);for(p&&p(r);s.length;)s.shift()();return u.push.apply(u,a||[]),t()}function t(){for(var e,r=0;r<u.length;r++){for(var t=u[r],n=!0,f=1;f<t.length;f++){var i=t[f];0!==o[i]&&(n=!1)}n&&(u.splice(r--,1),e=l(l.s=t[0]))}return e}var n={},o={1:0},u=[];function l(r){if(n[r])return n[r].exports;var t=n[r]={i:r,l:!1,exports:{}};return e[r].call(t.exports,t,t.exports,l),t.l=!0,t.exports}l.m=e,l.c=n,l.d=function(e,r,t){l.o(e,r)||Object.defineProperty(e,r,{enumerable:!0,get:t})},l.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},l.t=function(e,r){if(1&r&&(e=l(e)),8&r)return e;if(4&r&&"object"==typeof e&&e&&e.__esModule)return e;var t=Object.create(null);if(l.r(t),Object.defineProperty(t,"default",{enumerable:!0,value:e}),2&r&&"string"!=typeof e)for(var n in e)l.d(t,n,function(r){return e[r]}.bind(null,n));return t},l.n=function(e){var r=e&&e.__esModule?function(){return e.default}:function(){return e};return l.d(r,"a",r),r},l.o=function(e,r){return Object.prototype.hasOwnProperty.call(e,r)},l.p="/";var f=this["webpackJsonp"]=this["webpackJsonp"]||[],i=f.push.bind(f);f.push=r,f=f.slice();for(var a=0;a<f.length;a++)r(f[a]);var p=i;t()}([]);</script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let webpack = detected.iter().find(|t| t.name == "Webpack");
    assert!(webpack.is_some(), "Should detect Webpack");
}

#[tokio::test]
async fn test_detect_laravel_from_cookie() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "laravel_session=eyJ...")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let laravel = detected.iter().find(|t| t.name == "Laravel");
    assert!(laravel.is_some(), "Should detect Laravel from cookie");
    assert_eq!(laravel.unwrap().category, TechCategory::Framework);
}

#[tokio::test]
async fn test_detect_aspnet_from_cookie() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "ASP.NET_SessionId=abc123; __RequestVerificationToken=xyz789")
                .insert_header("X-Powered-By", "ASP.NET")
                .set_body_string("<html><body>Test</body></html>")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let aspnet = detected.iter().find(|t| t.name == "ASP.NET");
    assert!(aspnet.is_some(), "Should detect ASP.NET");
}

#[tokio::test]
async fn test_detect_cloudflare_from_blocked_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("CF-RAY", "123456789abcdef-SJC")
                .set_body_string("Access Denied - Cloudflare")
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    let cloudflare = detected.iter().find(|t| t.name == "Cloudflare");
    assert!(cloudflare.is_some(), "Should detect Cloudflare even from 403 response");
}

#[tokio::test]
async fn test_detect_multiple_technologies() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/css/bootstrap.min.css">
        </head>
        <body>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script src="https://www.google-analytics.com/analytics.js"></script>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.18.0")
                .insert_header("X-Powered-By", "PHP/7.4.3")
                .set_body_string(html)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    assert!(detected.iter().any(|t| t.name == "Nginx"));
    assert!(detected.iter().any(|t| t.name == "PHP"));
    assert!(detected.iter().any(|t| t.name == "WordPress"));
    assert!(detected.iter().any(|t| t.name == "Bootstrap"));
    assert!(detected.iter().any(|t| t.name == "jQuery"));
    assert!(detected.iter().any(|t| t.name == "Google Analytics"));
}

#[tokio::test]
async fn test_no_detection_for_minimal_site() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Simple HTML Page</h1>
            <p>No frameworks here</p>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let detector = FrameworkDetector::new(http_client);

    let detected = detector.detect(&mock_server.uri()).await.unwrap();

    assert!(detected.is_empty() || detected.len() < 2, "Should detect minimal or no technologies");
}
