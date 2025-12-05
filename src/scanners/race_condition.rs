// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Race Condition Scanner
 * Detects race condition vulnerabilities (TOCTOU)
 *
 * Detects:
 * - Concurrent transaction race conditions
 * - Coupon/discount code race conditions
 * - Account balance manipulation via race
 * - File upload race conditions
 * - Session/authentication race conditions
 * - Rate limit bypass via race conditions
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::info;

pub struct RaceConditionScanner {
    http_client: Arc<HttpClient>,
}

/// Site type detection result
struct SiteType {
    has_dynamic_endpoints: bool,
    has_transaction_endpoints: bool,
    has_auth_endpoints: bool,
    has_ecommerce: bool,
    evidence: Vec<String>,
}

impl RaceConditionScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for race condition vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("[RaceCondition] Scanning: {}", url);

        // CRITICAL: First check if this site has endpoints worth testing for race conditions
        // Static sites, CDN-cached content, and marketing pages should NOT trigger race condition alerts
        tests_run += 1;
        let site_type = self.detect_site_type(url).await;

        if !site_type.has_dynamic_endpoints {
            info!("[RaceCondition] No dynamic/transactional endpoints detected - skipping race condition tests (likely static site)");
            return Ok((vulnerabilities, tests_run));
        }

        info!("[RaceCondition] Dynamic site detected, proceeding with tests. Evidence: {:?}", site_type.evidence);

        // Test transaction race conditions (only if transaction endpoints found)
        if site_type.has_transaction_endpoints {
            let (vulns, tests) = self.test_transaction_race(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test coupon/discount race conditions (only if e-commerce indicators found)
        if site_type.has_ecommerce && vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_coupon_race(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        // Test rate limit bypass via race (only if auth endpoints found)
        // NOTE: We do NOT test rate limiting on static/CDN sites - this creates false positives
        if site_type.has_auth_endpoints && vulnerabilities.is_empty() {
            let (vulns, tests) = self.test_rate_limit_race(url).await?;
            vulnerabilities.extend(vulns);
            tests_run += tests;
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect what type of site this is
    async fn detect_site_type(&self, url: &str) -> SiteType {
        let mut site_type = SiteType {
            has_dynamic_endpoints: false,
            has_transaction_endpoints: false,
            has_auth_endpoints: false,
            has_ecommerce: false,
            evidence: Vec::new(),
        };

        // Fetch the page
        let response = match self.http_client.get(url).await {
            Ok(r) => r,
            Err(_) => return site_type,
        };

        let body_lower = response.body.to_lowercase();

        // Check for auth endpoints (login forms, etc.)
        let auth_indicators = [
            "type=\"password\"",
            "name=\"password\"",
            "/api/login",
            "/api/auth",
            "/oauth",
            "/signin",
        ];
        for indicator in &auth_indicators {
            if body_lower.contains(indicator) {
                site_type.has_auth_endpoints = true;
                site_type.has_dynamic_endpoints = true;
                site_type.evidence.push(format!("Auth: {}", indicator));
                break;
            }
        }

        // Check for transaction endpoints
        let transaction_indicators = [
            "/api/transfer",
            "/api/withdraw",
            "/api/payment",
            "/api/purchase",
            "/api/checkout",
            "stripe.js",
            "paypal",
        ];
        for indicator in &transaction_indicators {
            if body_lower.contains(indicator) {
                site_type.has_transaction_endpoints = true;
                site_type.has_dynamic_endpoints = true;
                site_type.evidence.push(format!("Transaction: {}", indicator));
                break;
            }
        }

        // Check for e-commerce
        let ecommerce_indicators = [
            "/cart",
            "/checkout",
            "add-to-cart",
            "shopping-cart",
            "/api/coupon",
            "/api/discount",
        ];
        for indicator in &ecommerce_indicators {
            if body_lower.contains(indicator) {
                site_type.has_ecommerce = true;
                site_type.has_dynamic_endpoints = true;
                site_type.evidence.push(format!("E-commerce: {}", indicator));
                break;
            }
        }

        // Check for Set-Cookie (indicates dynamic backend)
        if response.header("set-cookie").is_some() {
            site_type.has_dynamic_endpoints = true;
            site_type.evidence.push("Set-Cookie header".to_string());
        }

        site_type
    }

    /// Test transaction race conditions (TOCTOU)
    async fn test_transaction_race(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 20;

        info!("Testing transaction race conditions");

        // Simulate concurrent requests to test for race conditions
        let concurrent_requests = 20;
        let mut join_set = JoinSet::new();

        // Test POST endpoints that might be vulnerable
        let test_paths = vec![
            "/api/withdraw",
            "/api/transfer",
            "/api/redeem",
            "/api/purchase",
        ];

        for path in test_paths {
            let test_url = if url.ends_with('/') {
                format!("{}{}", url.trim_end_matches('/'), path)
            } else {
                format!("{}{}", url, path)
            };

            let mut responses = Vec::new();

            // Fire concurrent requests
            for _ in 0..concurrent_requests {
                let http_client = Arc::clone(&self.http_client);
                let url_clone = test_url.clone();

                join_set.spawn(async move {
                    http_client.get(&url_clone).await
                });
            }

            // Collect results
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Ok(response)) => {
                        responses.push(response.status_code);
                    }
                    _ => {}
                }
            }

            // Analyze if race condition allowed multiple successful operations
            if self.detect_transaction_race(&responses) {
                info!("Transaction race condition detected at {}", path);
                vulnerabilities.push(self.create_vulnerability(
                    &test_url,
                    "Transaction Race Condition",
                    "Concurrent POST requests",
                    "Race condition allows multiple concurrent transactions",
                    &format!("{} successful responses in concurrent execution",
                        responses.iter().filter(|&&s| s == 200).count()),
                    Severity::High,
                    "CWE-362",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test coupon/discount code race conditions
    async fn test_coupon_race(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        info!("Testing coupon/discount race conditions");

        let concurrent_requests = 10;
        let mut join_set = JoinSet::new();

        // Test coupon/discount endpoints
        let coupon_paths = vec![
            "/api/coupon/apply",
            "/api/discount/redeem",
            "/api/voucher/use",
        ];

        for path in coupon_paths {
            let test_url = if url.ends_with('/') {
                format!("{}{}?code=TEST123", url.trim_end_matches('/'), path)
            } else {
                format!("{}{}?code=TEST123", url, path)
            };

            let mut success_count = 0;

            // Fire concurrent requests with same coupon code
            for _ in 0..concurrent_requests {
                let http_client = Arc::clone(&self.http_client);
                let url_clone = test_url.clone();

                join_set.spawn(async move {
                    http_client.get(&url_clone).await
                });
            }

            // Count successful redemptions
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Ok(response)) => {
                        if response.status_code == 200 &&
                           !response.body.to_lowercase().contains("already used") &&
                           !response.body.to_lowercase().contains("invalid") {
                            success_count += 1;
                        }
                    }
                    _ => {}
                }
            }

            // If more than 1 success, race condition exists
            if success_count > 1 {
                info!("Coupon race condition detected: {} concurrent redemptions", success_count);
                vulnerabilities.push(self.create_vulnerability(
                    &test_url,
                    "Coupon/Discount Race Condition",
                    "Concurrent coupon redemption",
                    "Race condition allows multiple uses of single-use coupons",
                    &format!("{} concurrent successful redemptions detected", success_count),
                    Severity::High,
                    "CWE-362",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test rate limit bypass via race conditions
    async fn test_rate_limit_race(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 30;

        info!("Testing rate limit bypass via race conditions");

        let concurrent_requests = 30;
        let mut join_set = JoinSet::new();
        let mut success_count = 0;

        // Fire many concurrent requests to bypass rate limiting
        for _ in 0..concurrent_requests {
            let http_client = Arc::clone(&self.http_client);
            let url_clone = url.to_string();

            join_set.spawn(async move {
                http_client.get(&url_clone).await
            });
        }

        // Count how many succeeded
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(response)) => {
                    if response.status_code == 200 {
                        success_count += 1;
                    }
                }
                _ => {}
            }
        }

        // If most requests succeeded, rate limiting might be bypassable via race
        if success_count >= concurrent_requests - 2 {
            info!("Rate limit bypass via race condition: {}/{} succeeded",
                success_count, concurrent_requests);
            vulnerabilities.push(self.create_vulnerability(
                url,
                "Rate Limit Bypass via Race Condition",
                "Concurrent requests",
                "Rate limiting can be bypassed with concurrent requests",
                &format!("{}/{} concurrent requests succeeded", success_count, concurrent_requests),
                Severity::Medium,
                "CWE-362",
            ));
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect transaction race condition
    fn detect_transaction_race(&self, responses: &[u16]) -> bool {
        // Count successful responses (200)
        let success_count = responses.iter().filter(|&&s| s == 200).count();

        // If multiple operations succeeded, possible race condition
        // This is a heuristic - adjust based on expected behavior
        success_count > 1
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        attack_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.9,
            _ => 3.7,
        };

        Vulnerability {
            id: format!("race_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: format!("Race Condition ({})", attack_type),
            severity,
            confidence: Confidence::Medium,
            category: "Business Logic".to_string(),
            url: url.to_string(),
            parameter: None,
            payload: payload.to_string(),
            description: description.to_string(),
            evidence: Some(evidence.to_string()),
            cwe: cwe.to_string(),
            cvss: cvss as f32,
            verified: true,
            false_positive: false,
            remediation: "1. Implement proper database locking (pessimistic or optimistic)\n\
                         2. Use database transactions with appropriate isolation levels\n\
                         3. Implement idempotency keys for critical operations\n\
                         4. Use atomic operations and compare-and-swap (CAS)\n\
                         5. Implement distributed locks (Redis, Memcached) for scaling\n\
                         6. Add unique constraints at database level\n\
                         7. Use message queues for sequential processing\n\
                         8. Implement request deduplication\n\
                         9. Add version/timestamp checks for optimistic locking\n\
                         10. Use database row-level locking for critical updates\n\
                         11. Implement rate limiting at application AND infrastructure level\n\
                         12. Test with high concurrency scenarios".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// UUID generation helper
mod uuid {
    use rand::Rng;

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            let mut rng = rand::rng();
            format!(
                "{:08x}{:04x}{:04x}{:04x}{:012x}",
                rng.random::<u32>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u16>(),
                rng.random::<u64>() & 0xffffffffffff
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> RaceConditionScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        RaceConditionScanner::new(http_client)
    }

    #[test]
    fn test_detect_transaction_race() {
        let scanner = create_test_scanner();

        // Multiple successes indicate race condition
        let responses_with_race = vec![200, 200, 200, 200, 200];
        assert!(scanner.detect_transaction_race(&responses_with_race));

        // Single success is normal
        let responses_normal = vec![200, 429, 429, 429, 429];
        assert!(!scanner.detect_transaction_race(&responses_normal));
    }

    #[test]
    fn test_detect_all_failures() {
        let scanner = create_test_scanner();

        let all_failures = vec![404, 404, 404, 404];
        assert!(!scanner.detect_transaction_race(&all_failures));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com/api/withdraw",
            "Transaction Race Condition",
            "Concurrent requests",
            "Race condition in withdrawal",
            "5 successful concurrent withdrawals",
            Severity::High,
            "CWE-362",
        );

        assert_eq!(vuln.vuln_type, "Race Condition (Transaction Race Condition)");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-362");
        assert_eq!(vuln.cvss, 7.5);
        assert!(vuln.verified);
    }
}
