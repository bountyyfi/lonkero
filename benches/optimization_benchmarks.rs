// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Performance Optimization Benchmarks
//! © 2025 Bountyy Oy
//!
//! Benchmarks for measuring optimization improvements

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;

/// Benchmark HTTP/2 connection pooling performance
fn benchmark_connection_pool_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_pool_optimization");

    for pool_size in [8, 16, 32, 64, 128].iter() {
        group.throughput(Throughput::Elements(*pool_size as u64));
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            pool_size,
            |b, &size| {
                b.iter(|| {
                    let mut connections = Vec::with_capacity(size);
                    for i in 0..size {
                        connections.push(format!("conn_{}", i));
                    }
                    for conn in &connections {
                        black_box(conn);
                    }
                    connections
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Arc<str> vs String for payload sharing
fn benchmark_payload_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload_sharing");

    let payload_string = "' OR '1'='1' -- This is a SQL injection test payload".to_string();
    let payload_arc: std::sync::Arc<str> = std::sync::Arc::from(payload_string.as_str());

    group.bench_function("string_clone_1000", |b| {
        b.iter(|| {
            let mut clones = Vec::with_capacity(1000);
            for _ in 0..1000 {
                clones.push(payload_string.clone());
            }
            black_box(clones);
        })
    });

    group.bench_function("arc_str_clone_1000", |b| {
        b.iter(|| {
            let mut clones = Vec::with_capacity(1000);
            for _ in 0..1000 {
                clones.push(std::sync::Arc::clone(&payload_arc));
            }
            black_box(clones);
        })
    });

    group.finish();
}

/// Benchmark bulk database inserts
fn benchmark_bulk_insert_strategies(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("bulk_insert_strategies");

    for batch_size in [10, 50, 100, 250, 500, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("multi_row_insert", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async move {
                    // Simulate building multi-row INSERT
                    let mut query = String::with_capacity(1024 + size * 256);
                    query.push_str("INSERT INTO test VALUES ");

                    for i in 0..size {
                        if i > 0 {
                            query.push_str(", ");
                        }
                        query.push_str(&format!("(${}, ${}, ${})", i*3+1, i*3+2, i*3+3));
                    }

                    black_box(query);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("individual_inserts", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async move {
                    // Simulate individual INSERT statements
                    let mut queries = Vec::with_capacity(size);
                    for i in 0..size {
                        queries.push(format!("INSERT INTO test VALUES ($1, $2, $3) -- {}", i));
                    }
                    black_box(queries);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark TCP_NODELAY impact
fn benchmark_tcp_settings(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    c.bench_function("tcp_with_nodelay", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate rapid small writes (benefits from TCP_NODELAY)
            for _ in 0..100 {
                let data = "GET /test HTTP/1.1\r\n\r\n";
                tokio::time::sleep(Duration::from_micros(1)).await;
                black_box(data);
            }
        });
    });
}

/// Benchmark DNS cache with different strategies
fn benchmark_dns_cache_strategies(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("dns_cache_strategies");

    // HashMap approach
    group.bench_function("hashmap_cache", |b| {
        b.to_async(&rt).iter(|| async {
            use std::collections::HashMap;
            let mut cache = HashMap::new();

            // Populate cache
            for i in 0..100 {
                cache.insert(format!("domain{}.com", i), format!("192.168.1.{}", i));
            }

            // Lookups
            for i in 0..1000 {
                let key = format!("domain{}.com", i % 100);
                let _ = cache.get(&key);
            }

            black_box(cache);
        });
    });

    // Moka cache approach
    group.bench_function("moka_cache", |b| {
        b.to_async(&rt).iter(|| async {
            use moka::future::Cache;
            let cache = Cache::builder()
                .max_capacity(100)
                .time_to_live(Duration::from_secs(300))
                .build();

            // Populate cache
            for i in 0..100 {
                cache.insert(
                    format!("domain{}.com", i),
                    format!("192.168.1.{}", i)
                ).await;
            }

            // Lookups
            for i in 0..1000 {
                let key = format!("domain{}.com", i % 100);
                let _ = cache.get(&key).await;
            }

            black_box(&cache);
        });
    });

    group.finish();
}

/// Benchmark response body size limiting
fn benchmark_body_size_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("body_size_limiting");

    // Large response body (5MB)
    let large_body = vec![b'x'; 5 * 1024 * 1024];
    let max_size = 1024 * 1024; // 1MB limit

    group.bench_function("no_limit", |b| {
        b.iter(|| {
            let body = String::from_utf8_lossy(&large_body);
            black_box(body);
        });
    });

    group.bench_function("with_limit", |b| {
        b.iter(|| {
            let truncated = if large_body.len() > max_size {
                &large_body[..max_size]
            } else {
                &large_body[..]
            };
            let body = String::from_utf8_lossy(truncated);
            black_box(body);
        });
    });

    group.finish();
}

/// Benchmark payload deduplication
fn benchmark_payload_deduplication(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("payload_deduplication");

    // Create payloads with 30% duplicates
    let mut payloads = Vec::with_capacity(1000);
    for i in 0..700 {
        payloads.push(format!("payload_{}", i));
    }
    // Add duplicates
    for i in 0..300 {
        payloads.push(format!("payload_{}", i % 100));
    }

    group.bench_function("with_deduplication", |b| {
        b.to_async(&rt).iter(|| async {
            use ahash::AHashSet;
            let mut seen = AHashSet::with_capacity(payloads.len());
            let mut unique = Vec::with_capacity(payloads.len());

            for payload in &payloads {
                if seen.insert(payload.clone()) {
                    unique.push(payload.clone());
                }
            }

            black_box(unique);
        });
    });

    group.bench_function("without_deduplication", |b| {
        b.to_async(&rt).iter(|| async {
            let all: Vec<_> = payloads.iter().cloned().collect();
            black_box(all);
        });
    });

    group.finish();
}

/// Benchmark concurrent request batching
fn benchmark_request_batching(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("request_batching");

    for batch_size in [10, 50, 100, 200].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_batch", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async move {
                    let tasks: Vec<_> = (0..size)
                        .map(|i| {
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_micros(100)).await;
                                i * 2
                            })
                        })
                        .collect();

                    for task in tasks {
                        let _ = task.await;
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark string capacity pre-allocation
fn benchmark_string_preallocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_preallocation");

    group.bench_function("no_preallocation", |b| {
        b.iter(|| {
            let mut s = String::new();
            for i in 0..100 {
                s.push_str(&format!("item_{},", i));
            }
            black_box(s);
        });
    });

    group.bench_function("with_preallocation", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(1000);
            for i in 0..100 {
                s.push_str(&format!("item_{},", i));
            }
            black_box(s);
        });
    });

    group.finish();
}

/// Benchmark HashMap with capacity
fn benchmark_hashmap_capacity(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashmap_capacity");

    group.bench_function("no_capacity", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::new();
            for i in 0..1000 {
                map.insert(format!("key_{}", i), i);
            }
            black_box(map);
        });
    });

    group.bench_function("with_capacity", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::with_capacity(1000);
            for i in 0..1000 {
                map.insert(format!("key_{}", i), i);
            }
            black_box(map);
        });
    });

    group.bench_function("ahash_with_capacity", |b| {
        b.iter(|| {
            let mut map = ahash::AHashMap::with_capacity(1000);
            for i in 0..1000 {
                map.insert(format!("key_{}", i), i);
            }
            black_box(map);
        });
    });

    group.finish();
}

/// Benchmark throughput target (1000+ req/s)
fn benchmark_throughput_target(c: &mut Criterion) {
    use tokio::runtime::Runtime;
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("throughput_target");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("1000_requests_per_second", |b| {
        b.to_async(&rt).iter(|| async {
            let start = std::time::Instant::now();
            let mut count = 0;

            // Run for 1 second
            while start.elapsed().as_secs() < 1 {
                // Simulate request processing
                let url = format!("https://example.com?test={}", count);
                let encoded = urlencoding::encode("' OR '1'='1");
                let result = serde_json::json!({
                    "url": url,
                    "payload": encoded,
                });

                tokio::time::sleep(Duration::from_micros(10)).await;
                black_box(result);
                count += 1;
            }

            count
        });
    });

    group.finish();
}

criterion_group!(
    optimization_benches,
    benchmark_connection_pool_sizes,
    benchmark_payload_sharing,
    benchmark_bulk_insert_strategies,
    benchmark_tcp_settings,
    benchmark_dns_cache_strategies,
    benchmark_body_size_limiting,
    benchmark_payload_deduplication,
    benchmark_request_batching,
    benchmark_string_preallocation,
    benchmark_hashmap_capacity,
    benchmark_throughput_target
);

criterion_main!(optimization_benches);
