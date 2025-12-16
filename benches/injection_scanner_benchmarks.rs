// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Performance Benchmarks for Injection Scanners
 * Measures scanner performance and throughput
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::sqli::SqliScanner;
use lonkero_scanner::scanners::XssScanner;
use lonkero_scanner::scanners::command_injection::CommandInjectionScanner;
use lonkero_scanner::types::{ScanConfig, ScanMode};
use std::sync::Arc;

fn default_scan_config() -> ScanConfig {
    ScanConfig {
        target_url: "http://example.com".to_string(),
        scan_mode: ScanMode::Fast,
        max_depth: 3,
        concurrency: 10,
        timeout_ms: 5000,
        user_agent: "Benchmark Scanner".to_string(),
        ..Default::default()
    }
}

fn bench_sqli_scanner_initialization(c: &mut Criterion) {
    c.bench_function("sqli_scanner_init", |b| {
        b.iter(|| {
            let client = Arc::new(HttpClient::new(10000, 3).unwrap());
            black_box(SqliScanner::new(client))
        });
    });
}

fn bench_xss_scanner_initialization(c: &mut Criterion) {
    c.bench_function("xss_scanner_init", |b| {
        b.iter(|| {
            let client = Arc::new(HttpClient::new(10000, 3).unwrap());
            black_box(XssScanner::new(client))
        });
    });
}

fn bench_command_injection_scanner_initialization(c: &mut Criterion) {
    c.bench_function("command_injection_scanner_init", |b| {
        b.iter(|| {
            let client = Arc::new(HttpClient::new(10000, 3).unwrap());
            black_box(CommandInjectionScanner::new(client))
        });
    });
}

fn bench_scan_modes(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_modes");

    for mode in &[ScanMode::Fast, ScanMode::Normal, ScanMode::Thorough] {
        group.bench_with_input(
            BenchmarkId::new("config_creation", format!("{:?}", mode)),
            mode,
            |b, mode| {
                b.iter(|| {
                    let mut config = default_scan_config();
                    config.scan_mode = mode.clone();
                    black_box(config)
                });
            },
        );
    }

    group.finish();
}

fn bench_http_client_creation(c: &mut Criterion) {
    c.bench_function("http_client_creation", |b| {
        b.iter(|| {
            black_box(HttpClient::new(10000, 3).unwrap())
        });
    });
}

fn bench_concurrent_scanner_creation(c: &mut Criterion) {
    c.bench_function("concurrent_scanner_creation", |b| {
        b.iter(|| {
            let client = Arc::new(HttpClient::new(10000, 3).unwrap());
            let _sqli = SqliScanner::new(Arc::clone(&client));
            let _xss = XssScanner::new(Arc::clone(&client));
            let _cmd = CommandInjectionScanner::new(Arc::clone(&client));
            black_box((_sqli, _xss, _cmd))
        });
    });
}

criterion_group!(
    benches,
    bench_sqli_scanner_initialization,
    bench_xss_scanner_initialization,
    bench_command_injection_scanner_initialization,
    bench_scan_modes,
    bench_http_client_creation,
    bench_concurrent_scanner_creation
);

criterion_main!(benches);
