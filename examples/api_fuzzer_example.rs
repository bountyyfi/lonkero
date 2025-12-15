// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * API Fuzzer Example - Demonstrates advanced API security testing
 *
 * This example shows how to use the API fuzzer to test various API types:
 * - REST APIs
 * - GraphQL APIs
 * - gRPC APIs
 *
 * Run with: cargo run --example api_fuzzer_example
 */

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::api_fuzzer::ApiFuzzerScanner;
use lonkero_scanner::types::{ScanConfig, Severity};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,api_fuzzer=debug")
        .init();

    println!("=== API Fuzzer Example ===\n");

    // Example 1: REST API Fuzzing
    println!("1. Testing REST API Security...");
    test_rest_api().await?;

    println!("\n");

    // Example 2: GraphQL API Fuzzing
    println!("2. Testing GraphQL API Security...");
    test_graphql_api().await?;

    println!("\n");

    // Example 3: Authentication Testing
    println!("3. Testing Authentication Bypass...");
    test_authentication().await?;

    println!("\n=== All Tests Complete ===");

    Ok(())
}

/// Example 1: REST API Security Testing
async fn test_rest_api() -> anyhow::Result<()> {
    // Create HTTP client
    let http_client = Arc::new(HttpClient::new(30, 3)?);

    // Create fuzzer
    let fuzzer = ApiFuzzerScanner::new(http_client);

    // Basic configuration
    let config = ScanConfig {
        scan_mode: "fast".to_string(),
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Example target (replace with your API)
    let target = "https://jsonplaceholder.typicode.com/posts";

    println!("  Target: {}", target);
    println!("  Mode: {}", config.scan_mode);

    // Run fuzzing
    let (vulnerabilities, tests_run) = fuzzer.scan(target, &config).await?;

    // Display results
    println!("  Tests run: {}", tests_run);
    println!("  Vulnerabilities found: {}", vulnerabilities.len());

    for vuln in &vulnerabilities {
        println!("\n  [{}] {}", vuln.severity, vuln.vuln_type);
        println!("  CWE: {} | CVSS: {}", vuln.cwe, vuln.cvss);
        println!("  Description: {}", vuln.description);
    }

    Ok(())
}

/// Example 2: GraphQL API Security Testing
async fn test_graphql_api() -> anyhow::Result<()> {
    let http_client = Arc::new(HttpClient::new(30, 3)?);
    let fuzzer = ApiFuzzerScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "normal".to_string(),
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: None,
        auth_basic: None,
        custom_headers: None,
    };

    // Example GraphQL endpoint (replace with your GraphQL API)
    let target = "https://countries.trevorblades.com/graphql";

    println!("  Target: {}", target);
    println!("  Mode: {} (Cloud: {})", config.scan_mode, config.enable_cloud_scanning());

    let (vulnerabilities, tests_run) = fuzzer.scan(target, &config).await?;

    println!("  Tests run: {}", tests_run);
    println!("  Vulnerabilities found: {}", vulnerabilities.len());

    // Show GraphQL-specific vulnerabilities
    let graphql_vulns: Vec<_> = vulnerabilities
        .iter()
        .filter(|v| v.vuln_type.contains("GraphQL"))
        .collect();

    if !graphql_vulns.is_empty() {
        println!("\n  GraphQL-specific issues:");
        for vuln in graphql_vulns {
            println!("    - {}", vuln.vuln_type);
        }
    }

    Ok(())
}

/// Example 3: Authentication Bypass Testing
async fn test_authentication() -> anyhow::Result<()> {
    let http_client = Arc::new(HttpClient::new(30, 3)?);
    let fuzzer = ApiFuzzerScanner::new(http_client);

    // Configuration with authentication
    let mut custom_headers = HashMap::new();
    custom_headers.insert(
        "X-API-Key".to_string(),
        "test-api-key-12345".to_string(),
    );

    let config = ScanConfig {
        scan_mode: "thorough".to_string(),
        enable_crawler: false,
        max_depth: 3,
        max_pages: 100,
        enum_subdomains: false,
        auth_cookie: None,
        auth_token: Some("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".to_string()),
        auth_basic: None,
        custom_headers: Some(custom_headers),
    };

    // Example API endpoint
    let target = "https://jsonplaceholder.typicode.com/users";

    println!("  Target: {}", target);
    println!("  Mode: {} (Cloud: {})", config.scan_mode, config.enable_cloud_scanning());
    println!("  Authentication: Yes");

    let (vulnerabilities, tests_run) = fuzzer.scan(target, &config).await?;

    println!("  Tests run: {}", tests_run);
    println!("  Vulnerabilities found: {}", vulnerabilities.len());

    // Show critical vulnerabilities
    let critical_vulns: Vec<_> = vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .collect();

    if !critical_vulns.is_empty() {
        println!("\n  [WARNING]  CRITICAL VULNERABILITIES:");
        for vuln in critical_vulns {
            println!("    - {}", vuln.vuln_type);
            println!("      {}", vuln.description);
            println!("      Remediation: {}", vuln.remediation.lines().next().unwrap_or(""));
        }
    }

    // Show JWT-specific vulnerabilities
    let jwt_vulns: Vec<_> = vulnerabilities
        .iter()
        .filter(|v| v.vuln_type.contains("JWT"))
        .collect();

    if !jwt_vulns.is_empty() {
        println!("\n  JWT Vulnerabilities:");
        for vuln in jwt_vulns {
            println!("    - {} (CVSS: {})", vuln.vuln_type, vuln.cvss);
        }
    }

    Ok(())
}

/// Example 4: Comprehensive API Audit (not called in main, for reference)
#[allow(dead_code)]
async fn comprehensive_audit(target: &str) -> anyhow::Result<()> {
    let http_client = Arc::new(HttpClient::new(60, 5)?);
    let fuzzer = ApiFuzzerScanner::new(http_client);

    let config = ScanConfig {
        scan_mode: "insane".to_string(), // Most thorough
        enable_crawler: true, // Discover additional endpoints
        max_depth: 5,
        max_pages: 500,
        enum_subdomains: true, // Test subdomains
        auth_cookie: Some("session=abc123".to_string()),
        auth_token: Some("Bearer token...".to_string()),
        auth_basic: Some("admin:password".to_string()),
        custom_headers: Some(HashMap::from([
            ("X-API-Key".to_string(), "key123".to_string()),
            ("X-Custom-Auth".to_string(), "custom".to_string()),
        ])),
    };

    println!("Running comprehensive audit on: {}", target);
    println!("[WARNING]  This may take several minutes...");

    let start = std::time::Instant::now();
    let (vulnerabilities, tests_run) = fuzzer.scan(target, &config).await?;
    let duration = start.elapsed();

    println!("\n=== Audit Complete ===");
    println!("Duration: {:.2}s", duration.as_secs_f64());
    println!("Tests run: {}", tests_run);
    println!("Vulnerabilities: {}", vulnerabilities.len());

    // Categorize by severity
    let mut by_severity = HashMap::new();
    for vuln in &vulnerabilities {
        *by_severity.entry(&vuln.severity).or_insert(0) += 1;
    }

    println!("\nBy Severity:");
    if let Some(count) = by_severity.get(&Severity::Critical) {
        println!("  Critical: {}", count);
    }
    if let Some(count) = by_severity.get(&Severity::High) {
        println!("  High: {}", count);
    }
    if let Some(count) = by_severity.get(&Severity::Medium) {
        println!("  Medium: {}", count);
    }
    if let Some(count) = by_severity.get(&Severity::Low) {
        println!("  Low: {}", count);
    }

    // Categorize by type
    let mut by_type = HashMap::new();
    for vuln in &vulnerabilities {
        *by_type.entry(&vuln.category).or_insert(0) += 1;
    }

    println!("\nBy Category:");
    for (category, count) in by_type.iter() {
        println!("  {}: {}", category, count);
    }

    // Save report to file
    let report = serde_json::to_string_pretty(&vulnerabilities)?;
    std::fs::write("api_audit_report.json", report)?;
    println!("\nFull report saved to: api_audit_report.json");

    Ok(())
}
