// Test the Chromium XSS scanner directly
// Run with: cargo run --example test_chromium_xss

use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::scanners::chromium_xss_scanner::{ChromiumXssScanner, SharedBrowser};
use lonkero_scanner::types::{ScanConfig, ScanMode};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("Testing Chromium XSS Scanner against training endpoint...\n");

    let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
    let scanner = ChromiumXssScanner::new(http_client);

    // Create shared browser for efficient testing
    let shared_browser = SharedBrowser::new().expect("Failed to launch browser");

    let config = ScanConfig {
        scan_mode: ScanMode::Intelligent,
        ..Default::default()
    };

    // Test stored XSS endpoint
    let url =
        "https://training-data-lonkero.bountyy-fi-clients.workers.dev/xss/admin?action=comments";

    println!("Target: {}\n", url);

    match scanner.scan(url, &config, Some(&shared_browser)).await {
        Ok((vulns, tests)) => {
            println!("\n=== Results ===");
            println!("Tests run: {}", tests);
            println!("Vulnerabilities found: {}", vulns.len());

            for vuln in &vulns {
                println!("\n[{}] {}", vuln.severity, vuln.vuln_type);
                println!("  URL: {}", vuln.url);
                println!("  Payload: {}", vuln.payload);
                if let Some(ref evidence) = vuln.evidence {
                    println!("  Evidence: {}", evidence);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
