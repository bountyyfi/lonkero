// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Web Crawler Tests
 * Tests for form extraction, link following, parameter discovery, and edge cases
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use lonkero_scanner::crawler::{WebCrawler, CrawlResults};
use lonkero_scanner::http_client::HttpClient;
use std::sync::Arc;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_crawler_form_extraction() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/submit" method="POST">
                <input type="text" name="username" value="" />
                <input type="password" name="password" />
                <input type="email" name="email" value="test@example.com" />
                <textarea name="comment"></textarea>
                <select name="country">
                    <option value="us">USA</option>
                </select>
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert_eq!(results.forms.len(), 1);
    let form = &results.forms[0];
    assert_eq!(form.method, "POST");
    assert!(form.action.contains("/submit"));
    assert_eq!(form.inputs.len(), 5);

    let input_names: Vec<String> = form.inputs.iter().map(|i| i.name.clone()).collect();
    assert!(input_names.contains(&"username".to_string()));
    assert!(input_names.contains(&"password".to_string()));
    assert!(input_names.contains(&"email".to_string()));
    assert!(input_names.contains(&"comment".to_string()));
    assert!(input_names.contains(&"country".to_string()));
}

#[tokio::test]
async fn test_crawler_link_following() {
    let mock_server = MockServer::start().await;

    let page1 = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="{}/page2">Page 2</a>
            <a href="{}/page3">Page 3</a>
        </body>
        </html>
    "#, mock_server.uri(), mock_server.uri());

    let page2 = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Page 2</h1>
        </body>
        </html>
    "#;

    let page3 = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Page 3</h1>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page1))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/page2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page2))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/page3"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page3))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 2, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(results.crawled_urls.len() >= 3, "Should crawl at least 3 pages");
    assert!(results.links.len() >= 2, "Should discover at least 2 links");
}

#[tokio::test]
async fn test_crawler_max_depth_limit() {
    let mock_server = MockServer::start().await;

    let page1 = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="{}/level2">Level 2</a>
        </body>
        </html>
    "#, mock_server.uri());

    let page2 = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="{}/level3">Level 3</a>
        </body>
        </html>
    "#, mock_server.uri());

    let page3 = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Level 3</h1>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page1))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/level2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page2))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/level3"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page3))
        .expect(0)
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(results.crawled_urls.len() <= 2, "Should respect max depth of 1");
}

#[tokio::test]
async fn test_crawler_max_pages_limit() {
    let mock_server = MockServer::start().await;

    let mut links = String::new();
    for i in 1..=10 {
        links.push_str(&format!(r#"<a href="{}/page{}">Page {}</a>"#, mock_server.uri(), i, i));
    }

    let main_page = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            {}
        </body>
        </html>
    "#, links);

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(main_page))
        .mount(&mock_server)
        .await;

    for i in 1..=10 {
        Mock::given(method("GET"))
            .and(path(format!("/page{}", i)))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Page</body></html>"))
            .mount(&mock_server)
            .await;
    }

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 10, 5);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(results.crawled_urls.len() <= 5, "Should respect max pages limit");
}

#[tokio::test]
async fn test_crawler_parameter_discovery() {
    let mock_server = MockServer::start().await;

    let html = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="{}/search?q=test&page=1">Search</a>
            <a href="{}/product?id=123&category=books">Product</a>
            <a href="{}/user?name=john&age=30">User</a>
        </body>
        </html>
    "#, mock_server.uri(), mock_server.uri(), mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    let all_params = results.get_all_parameters();
    assert!(all_params.contains("q"));
    assert!(all_params.contains("page"));
    assert!(all_params.contains("id"));
    assert!(all_params.contains("category"));
    assert!(all_params.contains("name"));
    assert!(all_params.contains("age"));
}

#[tokio::test]
async fn test_crawler_script_extraction() {
    let mock_server = MockServer::start().await;

    let html = format!(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <script src="{}/js/app.js"></script>
            <script src="{}/js/vendor.js"></script>
        </head>
        <body>
            <h1>Test Page</h1>
        </body>
        </html>
    "#, mock_server.uri(), mock_server.uri());

    let js_content = "console.log('test');";

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/js/app.js"))
        .respond_with(ResponseTemplate::new(200).set_body_string(js_content))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/js/vendor.js"))
        .respond_with(ResponseTemplate::new(200).set_body_string(js_content))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert_eq!(results.scripts.len(), 2);
    assert!(results.scripts.iter().any(|s| s.url.contains("app.js")));
    assert!(results.scripts.iter().any(|s| s.url.contains("vendor.js")));
}

#[tokio::test]
async fn test_crawler_api_endpoint_detection() {
    let mock_server = MockServer::start().await;

    let json_response = r#"{"status":"ok","data":{"items":[1,2,3]}}"#;

    Mock::given(method("GET"))
        .and(path("/api/data"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(json_response)
        )
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let url = format!("{}/api/data", mock_server.uri());
    let results = crawler.crawl(&url).await.unwrap();

    assert!(results.api_endpoints.contains(&url), "Should detect API endpoint");
}

#[tokio::test]
async fn test_crawler_same_domain_only() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="/internal">Internal Link</a>
            <a href="https://external.com/page">External Link</a>
            <a href="http://example.com/page">Another External</a>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Internal</body></html>"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 2, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    for link in &results.links {
        assert!(link.contains(&mock_server.address().to_string()),
            "All links should be same-domain: {}", link);
    }
}

#[tokio::test]
async fn test_crawler_ignore_fragments() {
    let mock_server = MockServer::start().await;

    let html = r##"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="#section1">Section 1</a>
            <a href="#section2">Section 2</a>
            <a href="javascript:void(0)">JavaScript Link</a>
        </body>
        </html>
    "##;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert_eq!(results.crawled_urls.len(), 1, "Should only crawl the main page");
    assert_eq!(results.links.len(), 0, "Should not follow fragment links");
}

#[tokio::test]
async fn test_crawler_error_handling() {
    let mock_server = MockServer::start().await;

    let html = format!(r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="{}/error">Error Page</a>
            <a href="{}/valid">Valid Page</a>
        </body>
        </html>
    "#, mock_server.uri(), mock_server.uri());

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/error"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/valid"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Valid</body></html>"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 2, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(results.crawled_urls.len() >= 2, "Should continue after errors");
}

#[tokio::test]
async fn test_crawler_results_merge() {
    let mut results1 = CrawlResults::new();
    results1.links.insert("https://example.com/page1".to_string());
    results1.forms.push(lonkero_scanner::crawler::DiscoveredForm {
        action: "/submit1".to_string(),
        method: "POST".to_string(),
        inputs: vec![],
        discovered_at: "https://example.com".to_string(),
    });

    let mut results2 = CrawlResults::new();
    results2.links.insert("https://example.com/page2".to_string());
    results2.forms.push(lonkero_scanner::crawler::DiscoveredForm {
        action: "/submit2".to_string(),
        method: "GET".to_string(),
        inputs: vec![],
        discovered_at: "https://example.com".to_string(),
    });

    results1.merge(results2);

    assert_eq!(results1.links.len(), 2);
    assert_eq!(results1.forms.len(), 2);
}

#[tokio::test]
async fn test_crawler_empty_form_inputs_ignored() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/submit" method="POST">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert_eq!(results.forms.len(), 0, "Forms without inputs should be ignored");
}

#[tokio::test]
async fn test_crawler_relative_url_resolution() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <a href="/absolute">Absolute</a>
            <a href="relative">Relative</a>
            <a href="../parent">Parent</a>
            <a href="./current">Current</a>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>OK</body></html>"))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 2, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert!(results.links.len() > 0, "Should resolve relative URLs");
}

#[tokio::test]
async fn test_crawler_multiple_forms() {
    let mock_server = MockServer::start().await;

    let html = r#"
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
            <form action="/search" method="GET">
                <input type="text" name="query" />
                <input type="submit" value="Search" />
            </form>
            <form action="/contact" method="POST">
                <input type="email" name="email" />
                <textarea name="message"></textarea>
            </form>
        </body>
        </html>
    "#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let crawler = WebCrawler::new(http_client, 1, 10);

    let results = crawler.crawl(&mock_server.uri()).await.unwrap();

    assert_eq!(results.forms.len(), 3);

    let methods: Vec<String> = results.forms.iter().map(|f| f.method.clone()).collect();
    assert!(methods.contains(&"POST".to_string()));
    assert!(methods.contains(&"GET".to_string()));
}
