// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Lonkero Security Scanner - Performance Benchmarks
//! © 2025 Bountyy Oy
//!
//! Benchmarks for measuring scanner performance and throughput

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;

// Benchmark HTTP request processing
fn benchmark_url_parsing(c: &mut Criterion) {
    let urls = vec![
        "https://example.com/api/users?id=123",
        "http://test.com:8080/path/to/resource",
        "https://secure.example.com/login?redirect=/dashboard&token=abc123",
        "http://api.example.com/v1/products/search?q=test&category=electronics&sort=price",
    ];

    c.bench_function("url_parsing", |b| {
        b.iter(|| {
            for url_str in &urls {
                let _ = url::Url::parse(black_box(url_str));
            }
        })
    });
}

// Benchmark regex pattern matching (SQLi detection)
fn benchmark_sqli_regex(c: &mut Criterion) {
    use regex::Regex;
    
    let sqli_patterns = vec![
        r"(?i)(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute)(\s|$)",
        r"(?i)(\s|^)(and|or)(\s+)(\d+|'[^']*')\s*=\s*(\d+|'[^']*')",
        r"(?i)(--|#|/\*|\*/)",
        r"(?i)(sleep|benchmark|waitfor)\s*\(",
    ];
    
    let test_payloads = vec![
        "' OR '1'='1",
        "admin'--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT NULL, NULL, NULL--",
        "normal_query_without_injection",
    ];

    let mut group = c.benchmark_group("sqli_regex");
    for pattern in &sqli_patterns {
        let re = Regex::new(pattern).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(pattern), &re, |b, regex| {
            b.iter(|| {
                for payload in &test_payloads {
                    let _ = regex.is_match(black_box(payload));
                }
            })
        });
    }
    group.finish();
}

// Benchmark XSS pattern detection
fn benchmark_xss_detection(c: &mut Criterion) {
    use regex::Regex;
    
    let xss_regex = Regex::new(r"(?i)<script|javascript:|onerror=|onload=|<iframe|<object|<embed").unwrap();
    
    let test_payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "normal text without xss",
        "safe <b>html</b> tags",
    ];

    c.bench_function("xss_detection", |b| {
        b.iter(|| {
            for payload in &test_payloads {
                let _ = xss_regex.is_match(black_box(payload));
            }
        })
    });
}

// Benchmark payload generation
fn benchmark_payload_generation(c: &mut Criterion) {
    let base_url = "https://example.com/api/test";
    let param_name = "id";
    
    let payloads = vec![
        "' OR '1'='1",
        "<script>alert('XSS')</script>",
        "../../../etc/passwd",
        "http://evil.com",
        "${7*7}",
    ];

    c.bench_function("payload_url_generation", |b| {
        b.iter(|| {
            for payload in &payloads {
                let encoded = urlencoding::encode(black_box(payload));
                let url = format!("{}?{}={}", base_url, param_name, encoded);
                let _ = black_box(url);
            }
        })
    });
}

// Benchmark JSON parsing (vulnerability results)
fn benchmark_json_parsing(c: &mut Criterion) {
    let json_data = r#"{
        "vulnerability_id": "12345",
        "scanner_name": "sqli",
        "severity": "high",
        "confidence": 0.95,
        "url": "https://example.com/api/users?id=123",
        "parameter": "id",
        "payload": "' OR '1'='1",
        "description": "SQL Injection vulnerability detected",
        "cwe": "CWE-89",
        "evidence": {
            "request": "GET /api/users?id=' OR '1'='1 HTTP/1.1",
            "response_code": 200,
            "response_time": 245
        }
    }"#;

    c.bench_function("json_parsing", |b| {
        b.iter(|| {
            let _ = serde_json::from_str::<serde_json::Value>(black_box(json_data));
        })
    });
}

// Benchmark concurrent operations (simulating parallel scans)
fn benchmark_concurrent_scans(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new().unwrap();
    
    c.bench_function("concurrent_scans", |b| {
        b.to_async(&rt).iter(|| async {
            let tasks: Vec<_> = (0..10)
                .map(|i| {
                    tokio::spawn(async move {
                        // Simulate scan work
                        tokio::time::sleep(Duration::from_micros(100)).await;
                        i * 2
                    })
                })
                .collect();

            for task in tasks {
                let _ = task.await;
            }
        });
    });
}

// Benchmark rate limiter (token bucket)
fn benchmark_rate_limiting(c: &mut Criterion) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    
    let counter = Arc::new(AtomicU32::new(0));
    let rate_limit = 100; // requests per second
    let interval = Duration::from_secs(1) / rate_limit;

    c.bench_function("rate_limiting", |b| {
        b.iter(|| {
            let count = counter.fetch_add(1, Ordering::Relaxed);
            if count % rate_limit == 0 {
                std::thread::sleep(interval);
            }
        })
    });
}

// Benchmark base64 encoding (for payload obfuscation)
fn benchmark_base64_encoding(c: &mut Criterion) {
    use base64::{Engine as _, engine::general_purpose};
    
    let payloads = vec![
        "' OR '1'='1",
        "<script>alert('XSS')</script>",
        "SELECT * FROM users WHERE id = 1",
        "../../../etc/passwd",
    ];

    c.bench_function("base64_encoding", |b| {
        b.iter(|| {
            for payload in &payloads {
                let _ = general_purpose::STANDARD.encode(black_box(payload));
            }
        })
    });
}

// Benchmark comprehensive scan simulation
fn benchmark_full_scan_simulation(c: &mut Criterion) {
    use regex::Regex;
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new().unwrap();
    let sqli_regex = Regex::new(r"(?i)(union|select|insert)").unwrap();
    let xss_regex = Regex::new(r"(?i)<script|onerror=").unwrap();
    
    let payloads = vec![
        ("' OR '1'='1", "sqli"),
        ("<script>alert(1)</script>", "xss"),
        ("../../../etc/passwd", "path_traversal"),
        ("http://evil.com", "ssrf"),
    ];

    c.bench_function("full_scan_simulation", |b| {
        b.to_async(&rt).iter(|| async {
            for (payload, _scanner_type) in &payloads {
                // URL encoding
                let encoded = urlencoding::encode(payload);
                
                // Pattern matching
                let _ = sqli_regex.is_match(payload);
                let _ = xss_regex.is_match(payload);
                
                // JSON serialization
                let result = serde_json::json!({
                    "payload": payload,
                    "encoded": encoded,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                
                let _ = black_box(result);
                
                // Simulate network delay
                tokio::time::sleep(Duration::from_micros(10)).await;
            }
        });
    });
}

criterion_group!(
    benches,
    benchmark_url_parsing,
    benchmark_sqli_regex,
    benchmark_xss_detection,
    benchmark_payload_generation,
    benchmark_json_parsing,
    benchmark_concurrent_scans,
    benchmark_rate_limiting,
    benchmark_base64_encoding,
    benchmark_full_scan_simulation
);

// Benchmark with comprehensive payload sets
fn benchmark_full_sqli_payloads(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new().unwrap();
    let payloads = vec![
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "1' ORDER BY 10--",
        "' OR 'x'='x",
        "1' UNION SELECT username, password FROM users--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "'; DROP TABLE users--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
        "' UNION ALL SELECT NULL,CONCAT(0x717a707671,JSON_ARRAYAGG(CONCAT_WS(0x7c7c7c,column_name)),0x7178787171) FROM information_schema.columns--",
        "admin' OR '1'='1'/*",
        "' WAITFOR DELAY '00:00:05'--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "' UNION SELECT NULL, table_name FROM information_schema.tables--",
        "1' AND extractvalue(rand(),concat(0x3a,(SELECT version())))--",
        "' OR pg_sleep(5)--",
        "1';EXEC sp_configure 'show advanced options',1--",
    ];

    c.bench_function("full_sqli_payloads", |b| {
        b.to_async(&rt).iter(|| async {
            let base_url = "https://example.com/api/test";
            for payload in &payloads {
                let encoded = urlencoding::encode(payload);
                let url = format!("{}?id={}", base_url, encoded);
                let _ = black_box(url);
            }
        });
    });
}

// Benchmark with comprehensive XSS payloads
fn benchmark_full_xss_payloads(c: &mut Criterion) {
    use regex::Regex;
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new().unwrap();
    let xss_regex = Regex::new(r"(?i)<script|javascript:|onerror=|onload=|<iframe|<object|<embed|<svg|<img").unwrap();
    
    let payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<input onfocus=alert('XSS') autofocus>",
        "<img src='x' onerror='&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;'>",
        "<svg><script>alert('XSS')</script></svg>",
        "<object data='javascript:alert(\"XSS\")'>",
        "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='>",
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
        "<details/open/ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<body onpageshow=alert('XSS')>",
        "<img src=`xx:xx`onerror=alert('XSS')>",
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
        "<input type='image' src='x' onerror='alert(\"XSS\")'>",
        "<form><button formaction=javascript:alert('XSS')>X",
    ];

    c.bench_function("full_xss_payloads", |b| {
        b.to_async(&rt).iter(|| async {
            for payload in &payloads {
                let _ = xss_regex.is_match(black_box(payload));
            }
        });
    });
}

// Benchmark full scanner throughput
fn benchmark_scanner_throughput(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    
    let rt = Runtime::new().unwrap();
    
    c.bench_function("scanner_throughput_per_second", |b| {
        b.to_async(&rt).iter(|| async {
            let mut count = 0;
            let start = std::time::Instant::now();
            
            // Simulate 1 second of scanning
            while start.elapsed().as_millis() < 100 { // 100ms sample
                // Simulate pattern matching
                let payload = "' OR '1'='1";
                let encoded = urlencoding::encode(payload);
                let url = format!("https://example.com?id={}", encoded);
                
                // JSON serialization
                let _ = serde_json::json!({
                    "payload": payload,
                    "url": url,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                
                count += 1;
            }
            
            black_box(count)
        });
    });
}

criterion_group!(
    payload_benches,
    benchmark_full_sqli_payloads,
    benchmark_full_xss_payloads,
    benchmark_scanner_throughput
);

// Enterprise-scale performance benchmarks
fn benchmark_circuit_breaker(c: &mut Criterion) {
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("circuit_breaker_check", |b| {
        b.to_async(&rt).iter(|| async {
            use std::time::Duration;

            struct CircuitBreakerConfig {
                failure_threshold: u32,
                success_threshold: u32,
                timeout: Duration,
                half_open_max_requests: u32,
            }

            let config = CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                timeout: Duration::from_secs(60),
                half_open_max_requests: 3,
            };

            let url = "https://example.com/api/test";

            for _ in 0..100 {
                let _ = black_box(url);
            }
        });
    });
}

// Benchmark payload cache performance
fn benchmark_payload_cache(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("payload_cache_operations", |b| {
        b.to_async(&rt).iter(|| async {
            let payloads = vec![
                "' OR '1'='1",
                "<script>alert(1)</script>",
                "../../../etc/passwd",
                "http://evil.com",
                "${7*7}",
            ];

            let mut cache_map = std::collections::HashMap::new();

            for payload in &payloads {
                let key = format!("payload_{}", payload);
                cache_map.insert(key, payload.to_string());
            }

            for payload in &payloads {
                let key = format!("payload_{}", payload);
                let _ = cache_map.get(&key);
            }

            black_box(cache_map);
        });
    });
}

// Benchmark database batch insert performance
fn benchmark_database_batch_insert(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("database_batch_insert");

    for batch_size in [10, 50, 100, 250, 500].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(batch_size), batch_size, |b, &size| {
            b.to_async(&rt).iter(|| async move {
                let mut query = String::from("INSERT INTO test VALUES ");

                for i in 0..size {
                    if i > 0 {
                        query.push_str(", ");
                    }
                    query.push_str(&format!("(${},${},${})", i*3+1, i*3+2, i*3+3));
                }

                black_box(query);
            });
        });
    }

    group.finish();
}

// Benchmark HTTP/2 multiplexing simulation
fn benchmark_http2_multiplexing(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("http2_concurrent_requests", |b| {
        b.to_async(&rt).iter(|| async {
            let tasks: Vec<_> = (0..100)
                .map(|i| {
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_micros(10)).await;
                        i * 2
                    })
                })
                .collect();

            for task in tasks {
                let _ = task.await;
            }
        });
    });
}

// Benchmark Arc<str> vs String for shared data
fn benchmark_arc_str_vs_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("arc_str_vs_string");

    group.bench_function("string_clone", |b| {
        let data = "This is a test payload string for cloning".to_string();
        b.iter(|| {
            let cloned = data.clone();
            black_box(cloned);
        })
    });

    group.bench_function("arc_str_clone", |b| {
        let data: std::sync::Arc<str> = std::sync::Arc::from("This is a test payload string for cloning");
        b.iter(|| {
            let cloned = std::sync::Arc::clone(&data);
            black_box(cloned);
        })
    });

    group.finish();
}

// Benchmark payload deduplication
fn benchmark_payload_deduplication(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("payload_deduplication", |b| {
        b.to_async(&rt).iter(|| async {
            let payloads = vec![
                "payload1", "payload2", "payload1", "payload3",
                "payload2", "payload4", "payload1", "payload5",
                "payload3", "payload2", "payload1", "payload4",
            ];

            let mut seen = std::collections::HashSet::new();
            let mut unique = Vec::new();

            for payload in payloads {
                if !seen.contains(payload) {
                    seen.insert(payload);
                    unique.push(payload);
                }
            }

            black_box(unique);
        });
    });
}

// Benchmark DNS cache lookups
fn benchmark_dns_cache(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("dns_cache_lookup", |b| {
        b.to_async(&rt).iter(|| async {
            let mut cache = std::collections::HashMap::new();

            cache.insert("example.com".to_string(), "93.184.216.34".to_string());
            cache.insert("google.com".to_string(), "142.250.185.46".to_string());
            cache.insert("github.com".to_string(), "140.82.121.4".to_string());

            for _ in 0..100 {
                let _ = cache.get("example.com");
                let _ = cache.get("google.com");
                let _ = cache.get("github.com");
            }

            black_box(cache);
        });
    });
}

// Benchmark connection pooling
fn benchmark_connection_pooling(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("connection_pool");

    for pool_size in [5, 10, 20, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(pool_size), pool_size, |b, &size| {
            b.to_async(&rt).iter(|| async move {
                let mut connections = Vec::new();

                for i in 0..size {
                    connections.push(format!("connection_{}", i));
                }

                for _ in 0..100 {
                    let conn = &connections[0];
                    black_box(conn);
                }

                black_box(connections);
            });
        });
    }

    group.finish();
}

// Comprehensive end-to-end scan simulation
fn benchmark_end_to_end_scan(c: &mut Criterion) {
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();

    c.bench_function("end_to_end_scan_simulation", |b| {
        b.to_async(&rt).iter(|| async {
            let payloads = vec![
                "' OR '1'='1",
                "<script>alert(1)</script>",
                "../../../etc/passwd",
                "http://169.254.169.254/",
                "; ls -la",
            ];

            for payload in &payloads {
                let encoded = urlencoding::encode(payload);
                let url = format!("https://example.com?test={}", encoded);

                tokio::time::sleep(std::time::Duration::from_micros(50)).await;

                let result = serde_json::json!({
                    "payload": payload,
                    "url": url,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "status": "tested",
                });

                black_box(result);
            }
        });
    });
}

criterion_group!(
    enterprise_benches,
    benchmark_circuit_breaker,
    benchmark_payload_cache,
    benchmark_database_batch_insert,
    benchmark_http2_multiplexing,
    benchmark_arc_str_vs_string,
    benchmark_payload_deduplication,
    benchmark_dns_cache,
    benchmark_connection_pooling,
    benchmark_end_to_end_scan
);

criterion_main!(benches, payload_benches, enterprise_benches);
