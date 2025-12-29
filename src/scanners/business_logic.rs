// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct BusinessLogicScanner {
    http_client: Arc<HttpClient>,
}

/// Token analysis result
struct TokenAnalysis {
    is_weak: bool,
    critically_weak: bool,
    reason: String,
    evidence: String,
}

impl BusinessLogicScanner {
    pub fn new(http_client: Arc<HttpClient>) -> Self {
        Self { http_client }
    }

    /// Scan endpoint for business logic vulnerabilities
    pub async fn scan(
        &self,
        url: &str,
        _config: &ScanConfig,
    ) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        info!("Testing business logic vulnerabilities");

        // Test negative values
        let (vulns, tests) = self.test_negative_values(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test workflow bypass
        let (vulns, tests) = self.test_workflow_bypass(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Test parameter tampering
        let (vulns, tests) = self.test_parameter_tampering(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Race condition testing (TOCTOU)
        let (vulns, tests) = self.test_race_conditions(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Price manipulation
        let (vulns, tests) = self.test_price_manipulation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Quantity tampering
        let (vulns, tests) = self.test_quantity_tampering(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Coupon/voucher abuse
        let (vulns, tests) = self.test_coupon_abuse(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Double-spend / replay attacks
        let (vulns, tests) = self.test_double_spend(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Integer overflow/underflow
        let (vulns, tests) = self.test_integer_overflow(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Time-based attacks
        let (vulns, tests) = self.test_time_based_attacks(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Enhanced price manipulation
        let (vulns, tests) = self.test_enhanced_price_manipulation(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Multi-step workflow bypass
        let (vulns, tests) = self.test_multi_step_workflow_bypass(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Multi-step form bypass
        let (vulns, tests) = self.test_multi_step_form_bypass(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Account enumeration timing
        let (vulns, tests) = self.test_account_enumeration_timing(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Password reset token prediction
        let (vulns, tests) = self.test_password_reset_token_prediction(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        // Advanced: Enhanced coupon/discount abuse
        let (vulns, tests) = self.test_enhanced_coupon_abuse(url).await?;
        vulnerabilities.extend(vulns);
        tests_run += tests;

        Ok((vulnerabilities, tests_run))
    }

    /// Test negative quantity/price values
    async fn test_negative_values(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing negative value handling");

        let negative_tests = vec![
            ("quantity", "-1"),
            ("quantity", "-10"),
            ("price", "-1.00"),
            ("amount", "-100"),
            ("discount", "200"),  // Over 100%
            ("balance", "-1000"),
        ];

        for (param, value) in negative_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_negative_value_accepted(&response.body, param, value) {
                        info!("Negative/invalid value accepted: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Negative Value Manipulation",
                            &format!("{}={}", param, value),
                            &format!("Application accepts negative/invalid {} value", param),
                            &format!("Successfully set {}={}", param, value),
                            Severity::High,
                            "CWE-840",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test workflow bypass
    async fn test_workflow_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        debug!("Testing workflow bypass");

        let workflow_tests = vec![
            ("step", "10"),  // Skip to final step
            ("status", "completed"),
            ("state", "paid"),
            ("verified", "true"),
        ];

        for (param, value) in workflow_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_workflow_bypass(&response.body, value) {
                        info!("Workflow bypass detected: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Workflow Bypass",
                            &format!("{}={}", param, value),
                            "Application workflow can be bypassed by manipulating parameters",
                            &format!("Successfully bypassed workflow with {}={}", param, value),
                            Severity::High,
                            "CWE-841",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test parameter tampering
    async fn test_parameter_tampering(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing parameter tampering");

        let tampering_tests = vec![
            ("discount", "100"),
            ("discount_percent", "99"),
            ("shipping", "0"),
            ("tax", "0"),
            ("total", "0.01"),
        ];

        for (param, value) in tampering_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_parameter_tampering(&response.body, param, value) {
                        info!("Parameter tampering successful: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Parameter Tampering",
                            &format!("{}={}", param, value),
                            &format!("Business logic parameter '{}' can be manipulated", param),
                            &format!("Successfully tampered with {}={}", param, value),
                            Severity::High,
                            "CWE-472",
                        ));
                        break;
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for race conditions (TOCTOU attacks)
    async fn test_race_conditions(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing race condition vulnerabilities (TOCTOU)");

        // Common endpoints vulnerable to race conditions
        let race_endpoints = vec![
            ("checkout", "order_id=1"),
            ("transfer", "amount=100"),
            ("redeem", "code=DISCOUNT10"),
            ("withdraw", "amount=50"),
            ("apply-coupon", "coupon=SAVE20"),
        ];

        for (endpoint, params) in &race_endpoints {
            let test_url = format!("{}/{}", url.trim_end_matches('/'), endpoint);

            // Send concurrent requests to detect race conditions
            let mut handles = Vec::new();

            for _ in 0..5 {
                let client = Arc::clone(&self.http_client);
                let url_clone = test_url.clone();
                let params_clone = params.to_string();

                let handle = tokio::spawn(async move {
                    let headers = vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];
                    client.post_with_headers(&url_clone, &params_clone, headers).await
                });
                handles.push(handle);
            }

            // Wait for all requests
            let mut success_count = 0;
            let mut responses = Vec::new();

            for handle in handles {
                if let Ok(result) = handle.await {
                    if let Ok(response) = result {
                        responses.push(response.clone());
                        if self.detect_successful_transaction(&response.body) {
                            success_count += 1;
                        }
                    }
                }
            }

            // If multiple requests succeeded, race condition exists
            if success_count > 1 {
                info!("Race condition detected at {}!", test_url);
                vulnerabilities.push(self.create_vulnerability(
                    &test_url,
                    "Race Condition (TOCTOU)",
                    &format!("5 concurrent requests with {}", params),
                    &format!(
                        "Race condition vulnerability detected. {} out of 5 concurrent requests succeeded. \
                         This can lead to double-spending, inventory manipulation, or unauthorized access.",
                        success_count
                    ),
                    &format!("{} successful transactions from 5 concurrent requests", success_count),
                    Severity::Critical,
                    "CWE-362",
                ));
                break;
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for price manipulation
    async fn test_price_manipulation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing price manipulation vulnerabilities");

        let price_tests = vec![
            ("price", "0.01"),
            ("price", "0"),
            ("unit_price", "-1"),
            ("total", "0.01"),
            ("total_amount", "0"),
            ("item_price", "0.001"),
            ("subtotal", "0"),
            ("final_price", "1"),
        ];

        for (param, value) in &price_tests {
            // Test via GET
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_price_manipulation(&response.body, param, value) {
                        info!("Price manipulation successful: {}={}", param, value);
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Price Manipulation",
                            &format!("{}={}", param, value),
                            &format!(
                                "Server-side price validation is missing. The '{}' parameter can be \
                                 manipulated to set arbitrary prices, potentially allowing free purchases.",
                                param
                            ),
                            &format!("Successfully set {} to {}", param, value),
                            Severity::Critical,
                            "CWE-472",
                        ));
                        break;
                    }
                }
                Err(e) => debug!("Request failed: {}", e),
            }

            // Test via POST
            let checkout_url = format!("{}/checkout", url.trim_end_matches('/'));
            let post_data = format!("{}={}&product_id=1", param, value);

            match self.http_client.post_with_headers(
                &checkout_url,
                &post_data,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_price_manipulation(&response.body, param, value) {
                        vulnerabilities.push(self.create_vulnerability(
                            &checkout_url,
                            "Price Manipulation (POST)",
                            &post_data,
                            "Checkout endpoint accepts manipulated prices via POST request",
                            &format!("Successfully set {} to {} via POST", param, value),
                            Severity::Critical,
                            "CWE-472",
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for quantity tampering
    async fn test_quantity_tampering(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        debug!("Testing quantity tampering vulnerabilities");

        let quantity_tests = vec![
            ("quantity", "0"),
            ("qty", "-1"),
            ("count", "999999"),
            ("amount", "0.0001"),
            ("items", "-10"),
            ("num", "2147483647"),  // Max int
        ];

        for (param, value) in &quantity_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_quantity_tampering(&response.body, param, value) {
                        let severity = if value.starts_with('-') || *value == "0" {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Quantity Tampering",
                            &format!("{}={}", param, value),
                            &format!(
                                "Quantity validation is insufficient. Setting {}={} was accepted, \
                                 which could lead to inventory manipulation or financial loss.",
                                param, value
                            ),
                            &format!("Successfully set {} to {}", param, value),
                            severity,
                            "CWE-1284",
                        ));
                        break;
                    }
                }
                Err(e) => debug!("Request failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for coupon/voucher abuse
    async fn test_coupon_abuse(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing coupon/voucher abuse vulnerabilities");

        let coupon_endpoints = vec![
            format!("{}/apply-coupon", url.trim_end_matches('/')),
            format!("{}/discount", url.trim_end_matches('/')),
            format!("{}/voucher", url.trim_end_matches('/')),
            format!("{}/promo", url.trim_end_matches('/')),
        ];

        let coupon_tests = vec![
            ("code", "TEST100"),
            ("coupon", "' OR '1'='1"),  // SQL injection in coupon
            ("discount_code", "%00"),    // Null byte injection
            ("promo_code", "../../etc/passwd"),  // Path traversal
            ("voucher", "-1"),           // Negative value
        ];

        for endpoint in &coupon_endpoints {
            for (param, value) in &coupon_tests {
                let post_data = format!("{}={}", param, value);

                match self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await {
                    Ok(response) => {
                        // Check for coupon bypass
                        if self.detect_coupon_bypass(&response.body, value) {
                            vulnerabilities.push(self.create_vulnerability(
                                endpoint,
                                "Coupon/Voucher Abuse",
                                &format!("{}={}", param, value),
                                "Coupon validation can be bypassed using malformed input or injection techniques",
                                &format!("Coupon bypass detected with: {}", value),
                                Severity::High,
                                "CWE-20",
                            ));
                            break;
                        }

                        // Check if same coupon can be applied multiple times
                        let second_response = self.http_client.post_with_headers(
                            endpoint,
                            &post_data,
                            vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                        ).await;

                        if let Ok(second_resp) = second_response {
                            if self.detect_coupon_reuse(&response.body, &second_resp.body) {
                                vulnerabilities.push(self.create_vulnerability(
                                    endpoint,
                                    "Coupon Reuse Vulnerability",
                                    &format!("{}={}", param, value),
                                    "Same coupon code can be applied multiple times to stack discounts",
                                    "Coupon applied successfully multiple times",
                                    Severity::High,
                                    "CWE-837",
                                ));
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for double-spend / replay attacks
    async fn test_double_spend(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 3;

        debug!("Testing double-spend / replay attack vulnerabilities");

        let transaction_endpoints = vec![
            format!("{}/transfer", url.trim_end_matches('/')),
            format!("{}/payment", url.trim_end_matches('/')),
            format!("{}/withdraw", url.trim_end_matches('/')),
            format!("{}/send", url.trim_end_matches('/')),
        ];

        let transaction_data = "amount=100&to=attacker&transaction_id=TX123456";

        for endpoint in &transaction_endpoints {
            let headers = vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];

            // First request
            let first_response = self.http_client.post_with_headers(
                &endpoint,
                transaction_data,
                headers.clone()
            ).await;

            if let Ok(first_resp) = first_response {
                // Replay the same request
                let second_response = self.http_client.post_with_headers(
                    &endpoint,
                    transaction_data,
                    headers.clone()
                ).await;

                if let Ok(second_resp) = second_response {
                    // Check if both transactions succeeded
                    let first_success = self.detect_successful_transaction(&first_resp.body);
                    let second_success = self.detect_successful_transaction(&second_resp.body);

                    if first_success && second_success {
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint,
                            "Double-Spend / Replay Attack",
                            transaction_data,
                            &format!(
                                "Transaction replay protection is missing. The same transaction \
                                 can be submitted multiple times, potentially leading to double-spending \
                                 or duplicated operations."
                            ),
                            "Same transaction accepted twice",
                            Severity::Critical,
                            "CWE-294",
                        ));
                        break;
                    }
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for integer overflow/underflow
    async fn test_integer_overflow(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing integer overflow/underflow vulnerabilities");

        let overflow_tests = vec![
            ("amount", "2147483647"),   // Max int32
            ("amount", "2147483648"),   // Max int32 + 1
            ("quantity", "9223372036854775807"),  // Max int64
            ("price", "999999999999999.99"),
            ("balance", "-9223372036854775808"),  // Min int64
        ];

        for (param, value) in &overflow_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_integer_overflow(&response.body, param) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Integer Overflow/Underflow",
                            &format!("{}={}", param, value),
                            &format!(
                                "Integer overflow/underflow vulnerability detected. Large or boundary \
                                 values for '{}' are not properly validated, which could lead to \
                                 incorrect calculations or security bypasses.",
                                param
                            ),
                            &format!("Overflow value {} accepted for {}", value, param),
                            Severity::High,
                            "CWE-190",
                        ));
                        break;
                    }
                }
                Err(e) => debug!("Request failed: {}", e),
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test for time-based attacks
    /// NOTE: This test requires actual API endpoints with timestamp parameters.
    /// Running against arbitrary URLs (especially SPAs) produces false positives.
    async fn test_time_based_attacks(&self, _url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let vulnerabilities = Vec::new();
        let tests_run = 0;

        debug!("Skipping time-based attacks test - requires actual API endpoints with timestamp parameters");

        // TODO: This test should only run on discovered API endpoints that actually use
        // timestamp parameters. The current approach of adding ?timestamp=0 to any URL
        // causes false positives on SPAs that return their index.html for all routes.
        //
        // To properly test time-based attacks:
        // 1. First discover API endpoints that accept timestamp parameters
        // 2. Establish a baseline of valid responses
        // 3. Then test with manipulated timestamps and compare responses
        // 4. Look for actual behavior differences, not just word matching

        Ok((vulnerabilities, tests_run))
    }

    /// Test enhanced price manipulation with advanced techniques
    async fn test_enhanced_price_manipulation(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 12;

        debug!("Testing enhanced price manipulation vulnerabilities");

        // Generate unique order ID for tracking
        let order_id = format!("TEST_{}", chrono::Utc::now().timestamp());

        let advanced_price_tests = vec![
            // Negative quantities (refund instead of charge)
            ("quantity", "-1", "price", "100", "Negative quantity refund abuse"),
            ("qty", "-10", "unit_price", "50", "Negative quantity bulk refund"),

            // Decimal abuse
            ("price", "0.01", "quantity", "1", "Decimal price manipulation"),
            ("price", "-99.99", "quantity", "1", "Negative price manipulation"),

            // Integer overflow
            ("quantity", "2147483647", "price", "1", "Integer overflow quantity"),
            ("amount", "2147483647", "", "", "Integer overflow amount"),

            // Float precision abuse
            ("price", "0.0000001", "quantity", "1", "Float precision rounds to zero"),
            ("unit_price", "0.000000001", "qty", "100", "Precision loss exploitation"),

            // Currency manipulation (VND = Vietnamese Dong, 1/1000 of USD)
            ("amount", "100", "currency", "VND", "Currency arbitrage VND"),
            ("price", "1000", "currency", "IDR", "Currency arbitrage IDR"),

            // Combined attacks
            ("price", "-0.01", "quantity", "-1", "Double negative becomes positive"),
            ("amount", "0", "shipping", "0", "Zero-dollar order"),
        ];

        for (param1, value1, param2, value2, attack_type) in &advanced_price_tests {
            let checkout_url = format!("{}/checkout", url.trim_end_matches('/'));

            let post_data = if param2.is_empty() {
                format!("{}={}&product_id=1&order_id={}", param1, value1, order_id)
            } else {
                format!("{}={}&{}={}&product_id=1&order_id={}",
                    param1, value1, param2, value2, order_id)
            };

            match self.http_client.post_with_headers(
                &checkout_url,
                &post_data,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_enhanced_price_manipulation(&response.body, value1, value2) {
                        info!("Enhanced price manipulation successful: {}", attack_type);

                        let severity = if attack_type.contains("negative") ||
                                         attack_type.contains("zero") ||
                                         attack_type.contains("currency") {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        vulnerabilities.push(self.create_vulnerability(
                            &checkout_url,
                            "Enhanced Price Manipulation",
                            &post_data,
                            &format!(
                                "{}: Order total may be negative or suspiciously low. \
                                 Attack vector: {}. This can lead to financial loss through \
                                 refunds, zero-cost orders, or currency arbitrage.",
                                attack_type, post_data
                            ),
                            &format!("Order created with suspicious pricing: {} (Order ID: {})",
                                attack_type, order_id),
                            severity,
                            "CWE-682",
                        ));
                        break;
                    }
                }
                Err(e) => debug!("Enhanced price test failed: {}", e),
            }
        }

        // Test currency manipulation specifically
        let currency_endpoints = vec![
            format!("{}/cart/update", url.trim_end_matches('/')),
            format!("{}/order/create", url.trim_end_matches('/')),
        ];

        for endpoint in &currency_endpoints {
            let currency_test = format!(
                "amount=1000000&currency=VND&convert=false&order_id={}",
                order_id
            );

            match self.http_client.post_with_headers(
                endpoint,
                &currency_test,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_currency_manipulation(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            endpoint,
                            "Currency Manipulation",
                            &currency_test,
                            "Application accepts arbitrary currency codes without proper conversion. \
                             1,000,000 VND = ~$40 USD, allowing massive price reduction through \
                             currency selection abuse.",
                            &format!("Currency manipulation detected (Order ID: {})", order_id),
                            Severity::Critical,
                            "CWE-840",
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test multi-step workflow bypass
    async fn test_multi_step_workflow_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing multi-step workflow bypass vulnerabilities");

        let order_id = format!("TEST_{}", chrono::Utc::now().timestamp());

        // Multi-step checkout bypass scenarios
        let workflow_bypasses = vec![
            // Skip to final step
            (vec![("step", "5"), ("order_id", &order_id)], "Skip to checkout completion"),
            (vec![("step", "final"), ("order_id", &order_id)], "Skip to final step"),

            // Skip payment step
            (vec![("skip_payment", "true"), ("order_id", &order_id)], "Skip payment validation"),
            (vec![("payment_verified", "true"), ("order_id", &order_id)], "Fake payment verification"),

            // State manipulation
            (vec![("status", "shipped"), ("order_id", &order_id)], "Change to shipped status"),
            (vec![("order_status", "completed"), ("order_id", &order_id)], "Mark order completed"),
            (vec![("payment_status", "paid"), ("order_id", &order_id)], "Mark payment as paid"),

            // Cookie/session tampering simulation
            (vec![("checkout_step", "complete"), ("order_id", &order_id)], "Cookie step tampering"),
            (vec![("workflow_state", "confirmed"), ("order_id", &order_id)], "Workflow state bypass"),
            (vec![("validated", "1"), ("payment_done", "1"), ("order_id", &order_id)], "Multi-flag bypass"),
        ];

        for (params, attack_type) in &workflow_bypasses {
            // Test POST to order complete endpoint
            let complete_url = format!("{}/order/complete", url.trim_end_matches('/'));
            let post_data: String = params.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");

            match self.http_client.post_with_headers(
                &complete_url,
                &post_data,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_workflow_bypass_success(&response.body) {
                        info!("Workflow bypass successful: {}", attack_type);
                        vulnerabilities.push(self.create_vulnerability(
                            &complete_url,
                            "Multi-Step Workflow Bypass",
                            &post_data,
                            &format!(
                                "{}: Order created without completing required steps. \
                                 The application does not enforce sequential workflow validation, \
                                 allowing attackers to skip payment or verification steps.",
                                attack_type
                            ),
                            &format!("Order completed without payment: {} (Order ID: {})",
                                attack_type, order_id),
                            Severity::Critical,
                            "CWE-841",
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }

            // Also test direct POST to payment endpoint
            let payment_url = format!("{}/payment/process", url.trim_end_matches('/'));

            match self.http_client.post_with_headers(
                &payment_url,
                &post_data,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_payment_bypass(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            &payment_url,
                            "Payment Step Bypass",
                            &post_data,
                            "Payment processing endpoint accepts requests without proper state validation, \
                             allowing orders to be marked as paid without actual payment.",
                            &format!("Payment bypass detected (Order ID: {})", order_id),
                            Severity::Critical,
                            "CWE-840",
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test multi-step form bypass
    async fn test_multi_step_form_bypass(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 8;

        debug!("Testing multi-step form bypass vulnerabilities");

        let test_email = format!("test_{}@example.com", chrono::Utc::now().timestamp());

        // Pre-allocate all string values to avoid temporary value issues
        let zero = String::from("0");
        let complete = String::from("complete");
        let skip = String::from("skip");
        let empty_captcha = String::new();
        let false_str = String::from("false");
        let false_str2 = String::from("false");
        let purchase_action = String::from("purchase");
        let unverified_email = String::from("unverified@test.com");
        let true_str = String::from("true");
        let false_terms = String::from("false");
        let submit_one = String::from("1");

        let form_bypass_tests = vec![
            // CAPTCHA bypass
            (vec![("email", &test_email), ("captcha", &empty_captcha)],
             "Submit without CAPTCHA", "CAPTCHA Bypass"),
            (vec![("email", &test_email), ("captcha_verified", &false_str)],
             "Submit with false CAPTCHA flag", "CAPTCHA Validation Bypass"),

            // Email verification bypass
            (vec![("email", &test_email), ("email_verified", &false_str2), ("action", &purchase_action)],
             "Action with unverified email", "Email Verification Bypass"),
            (vec![("email", &unverified_email), ("skip_verification", &true_str)],
             "Skip email verification flag", "Verification Skip"),

            // Terms acceptance bypass
            (vec![("email", &test_email), ("agreed_to_terms", &false_terms), ("submit", &submit_one)],
             "Submit without agreeing to terms", "Terms Acceptance Bypass"),
            (vec![("email", &test_email), ("terms", &zero), ("privacy", &zero)],
             "Submit with declined terms", "Terms Validation Bypass"),

            // Required field bypass
            (vec![("email", &test_email)],
             "Submit with missing required fields", "Required Field Bypass"),
            (vec![("action", &complete), ("validation", &skip)],
             "Skip field validation", "Validation Skip"),
        ];

        for (params, attack_type, vuln_name) in &form_bypass_tests {
            let form_endpoints = vec![
                format!("{}/register", url.trim_end_matches('/')),
                format!("{}/checkout", url.trim_end_matches('/')),
                format!("{}/submit", url.trim_end_matches('/')),
            ];

            for endpoint in &form_endpoints {
                let post_data: String = params.iter()
                    .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");

                match self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await {
                    Ok(response) => {
                        if self.detect_form_bypass_success(&response.body, attack_type) {
                            info!("Form bypass successful: {}", attack_type);
                            vulnerabilities.push(self.create_vulnerability(
                                endpoint,
                                vuln_name,
                                &post_data,
                                &format!(
                                    "{}: The application accepted form submission despite missing \
                                     or invalid required fields. This indicates insufficient \
                                     server-side validation of form requirements.",
                                    attack_type
                                ),
                                &format!("Form submitted successfully: {}", attack_type),
                                Severity::High,
                                "CWE-20",
                            ));
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test account enumeration via timing attacks
    async fn test_account_enumeration_timing(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 30; // 10 requests × 3 scenarios

        debug!("Testing account enumeration timing vulnerabilities");

        let timing_scenarios = vec![
            (format!("{}/login", url.trim_end_matches('/')),
             "username", "password", "Login timing"),
            (format!("{}/reset-password", url.trim_end_matches('/')),
             "email", "", "Password reset timing"),
            (format!("{}/register", url.trim_end_matches('/')),
             "username", "password", "Registration timing"),
        ];

        for (endpoint, user_param, pass_param, scenario) in &timing_scenarios {
            // Test with likely existing user
            let existing_user = "admin";
            let mut existing_times = Vec::new();

            for i in 0..10 {
                let post_data = if pass_param.is_empty() {
                    format!("{}={}", user_param, existing_user)
                } else {
                    format!("{}={}&{}=wrong_password_{}", user_param, existing_user, pass_param, i)
                };

                let start = std::time::Instant::now();
                let _ = self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await;
                let duration = start.elapsed().as_millis() as f64;
                existing_times.push(duration);

                // Small delay between requests
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }

            // Test with non-existing user
            let nonexistent_user = format!("nonexistent_user_{}", chrono::Utc::now().timestamp());
            let mut nonexistent_times = Vec::new();

            for i in 0..10 {
                let post_data = if pass_param.is_empty() {
                    format!("{}={}", user_param, nonexistent_user)
                } else {
                    format!("{}={}&{}=wrong_password_{}", user_param, nonexistent_user, pass_param, i)
                };

                let start = std::time::Instant::now();
                let _ = self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await;
                let duration = start.elapsed().as_millis() as f64;
                nonexistent_times.push(duration);

                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }

            // Statistical analysis
            let existing_avg = existing_times.iter().sum::<f64>() / existing_times.len() as f64;
            let nonexistent_avg = nonexistent_times.iter().sum::<f64>() / nonexistent_times.len() as f64;

            let existing_variance = existing_times.iter()
                .map(|x| (x - existing_avg).powi(2))
                .sum::<f64>() / existing_times.len() as f64;
            let existing_stddev = existing_variance.sqrt();

            let nonexistent_variance = nonexistent_times.iter()
                .map(|x| (x - nonexistent_avg).powi(2))
                .sum::<f64>() / nonexistent_times.len() as f64;
            let nonexistent_stddev = nonexistent_variance.sqrt();

            let time_diff = (existing_avg - nonexistent_avg).abs();

            // Report if difference > 100ms consistently (stddev < 50ms for both)
            if time_diff > 100.0 && existing_stddev < 50.0 && nonexistent_stddev < 50.0 {
                info!("Timing-based enumeration detected: {} (diff: {}ms)", scenario, time_diff);

                let evidence = format!(
                    "Existing user avg: {:.2}ms (σ={:.2}ms), \
                     Non-existing user avg: {:.2}ms (σ={:.2}ms), \
                     Difference: {:.2}ms",
                    existing_avg, existing_stddev, nonexistent_avg, nonexistent_stddev, time_diff
                );

                vulnerabilities.push(self.create_vulnerability(
                    endpoint,
                    "Account Enumeration via Timing Attack",
                    &format!("Statistical analysis: 10 requests each"),
                    &format!(
                        "{}: The application exhibits consistent timing differences between \
                         existing and non-existing accounts ({}ms difference, p<0.01). \
                         This allows attackers to enumerate valid usernames/emails through \
                         response time analysis.",
                        scenario, time_diff as u32
                    ),
                    &evidence,
                    Severity::Medium,
                    "CWE-208",
                ));
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test password reset token prediction
    async fn test_password_reset_token_prediction(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 5;

        debug!("Testing password reset token prediction vulnerabilities");

        let reset_endpoints = vec![
            format!("{}/reset-password", url.trim_end_matches('/')),
            format!("{}/forgot-password", url.trim_end_matches('/')),
            format!("{}/password/reset", url.trim_end_matches('/')),
        ];

        for endpoint in &reset_endpoints {
            let mut tokens = Vec::new();
            let test_email = format!("test_{}@example.com", chrono::Utc::now().timestamp());

            // Request 5 password reset tokens
            for i in 0..5 {
                let post_data = format!("email={}_{}", test_email, i);

                match self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await {
                    Ok(response) => {
                        if let Some(token) = self.extract_token_from_response(&response.body) {
                            tokens.push(token);
                        }
                    }
                    Err(_) => {}
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }

            if tokens.len() >= 3 {
                // Analyze token entropy and predictability
                let analysis = self.analyze_token_security(&tokens);

                if analysis.is_weak {
                    info!("Weak password reset tokens detected: {}", analysis.reason);

                    let severity = if analysis.critically_weak {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    vulnerabilities.push(self.create_vulnerability(
                        endpoint,
                        "Weak Password Reset Token",
                        &format!("Analyzed {} tokens", tokens.len()),
                        &format!(
                            "Password reset tokens are predictable or weak. {}\n\
                             Sample tokens analyzed: {}\n\
                             This allows attackers to predict valid reset tokens and \
                             hijack password reset flows for arbitrary accounts.",
                            analysis.reason, analysis.evidence
                        ),
                        &format!("Token analysis: {} | Samples: {}",
                            analysis.reason,
                            tokens.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                        ),
                        severity,
                        "CWE-640",
                    ));
                    break;
                }
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Test enhanced coupon/discount abuse
    async fn test_enhanced_coupon_abuse(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 10;

        debug!("Testing enhanced coupon/discount abuse vulnerabilities");

        let order_id = format!("TEST_{}", chrono::Utc::now().timestamp());

        let coupon_endpoints = vec![
            format!("{}/apply-coupon", url.trim_end_matches('/')),
            format!("{}/cart/coupon", url.trim_end_matches('/')),
            format!("{}/discount/apply", url.trim_end_matches('/')),
        ];

        for endpoint in &coupon_endpoints {
            // Test 1: Reuse single-use coupon
            let coupon_code = "SAVE10";
            let post_data = format!("code={}&order_id={}", coupon_code, order_id);

            let first_result = self.http_client.post_with_headers(
                endpoint,
                &post_data,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await;

            if let Ok(first_resp) = first_result {
                // Try to reuse the same coupon
                let second_result = self.http_client.post_with_headers(
                    endpoint,
                    &post_data,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await;

                if let Ok(second_resp) = second_result {
                    if self.detect_coupon_reuse(&first_resp.body, &second_resp.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            endpoint,
                            "Coupon Reuse Vulnerability",
                            &post_data,
                            "Single-use coupon can be applied multiple times to the same order, \
                             allowing discount stacking and financial loss.",
                            &format!("Coupon '{}' applied multiple times (Order: {})",
                                coupon_code, order_id),
                            Severity::High,
                            "CWE-837",
                        ));
                    }
                }
            }

            // Test 2: Stack incompatible coupons
            let stacked_coupons = format!(
                "code=SAVE10&code=SAVE20&code=SAVE30&order_id={}",
                order_id
            );

            match self.http_client.post_with_headers(
                endpoint,
                &stacked_coupons,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_coupon_stacking(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            endpoint,
                            "Coupon Stacking Vulnerability",
                            &stacked_coupons,
                            "Multiple incompatible coupons can be stacked to achieve excessive discounts. \
                             This violates business rules and can lead to negative-profit transactions.",
                            &format!("Multiple coupons stacked (Order: {})", order_id),
                            Severity::High,
                            "CWE-840",
                        ));
                    }
                }
                Err(_) => {}
            }

            // Test 3: Expired coupon acceptance
            let expired_tests = vec![
                format!("code=EXPIRED2020&order_id={}", order_id),
                format!("code=OLD_PROMO&valid_until=2000-01-01&order_id={}", order_id),
            ];

            for expired_test in &expired_tests {
                match self.http_client.post_with_headers(
                    endpoint,
                    expired_test,
                    vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
                ).await {
                    Ok(response) => {
                        if self.detect_coupon_applied(&response.body) {
                            vulnerabilities.push(self.create_vulnerability(
                                endpoint,
                                "Expired Coupon Acceptance",
                                expired_test,
                                "Application accepts expired coupons without proper validation, \
                                 allowing use of outdated promotional offers.",
                                &format!("Expired coupon accepted (Order: {})", order_id),
                                Severity::Medium,
                                "CWE-613",
                            ));
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }

            // Test 4: Negative discount
            let negative_discount = format!("discount=-50&order_id={}", order_id);

            match self.http_client.post_with_headers(
                endpoint,
                &negative_discount,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_negative_discount(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            endpoint,
                            "Negative Discount Manipulation",
                            &negative_discount,
                            "Application accepts negative discount values, which increases the price \
                             instead of decreasing it. This can be exploited in refund scenarios.",
                            &format!("Negative discount applied (Order: {})", order_id),
                            Severity::High,
                            "CWE-840",
                        ));
                    }
                }
                Err(_) => {}
            }

            // Test 5: Percentage over 100
            let over_discount = format!("discount_percent=200&order_id={}", order_id);

            match self.http_client.post_with_headers(
                endpoint,
                &over_discount,
                vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())]
            ).await {
                Ok(response) => {
                    if self.detect_excessive_discount(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            endpoint,
                            "Excessive Discount Percentage",
                            &over_discount,
                            "Application accepts discount percentages over 100%, potentially \
                             resulting in negative order totals and paying customers to purchase.",
                            &format!("200% discount applied (Order: {})", order_id),
                            Severity::Critical,
                            "CWE-682",
                        ));
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
    }

    /// Detect enhanced price manipulation
    fn detect_enhanced_price_manipulation(&self, body: &str, value1: &str, value2: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for order creation success
        let success_indicators = vec![
            "order created", "order placed", "order confirmed",
            "checkout complete", "purchase successful",
            "total: 0", "total\":0", "total\": 0",
            "amount: -", "amount\":-", "negative total",
        ];

        for indicator in success_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check if suspicious values appear in response
        if (value1.starts_with('-') || value1.contains("0.00") || value1 == "0") &&
           (body_lower.contains("success") || body_lower.contains("confirmed")) {
            return true;
        }

        // Check for currency manipulation indicators
        if !value2.is_empty() && (value2 == "VND" || value2 == "IDR") {
            if body_lower.contains("currency") && body_lower.contains("success") {
                return true;
            }
        }

        false
    }

    /// Detect currency manipulation
    fn detect_currency_manipulation(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if VND/IDR currency was accepted
        let currency_accepted = (body_lower.contains("vnd") || body_lower.contains("idr")) &&
                                (body_lower.contains("success") || body_lower.contains("confirmed"));

        // Check for suspiciously low converted amounts
        let low_amount = body_lower.contains("total") &&
                        (body_lower.contains("$0") || body_lower.contains("$1") ||
                         body_lower.contains("usd 0") || body_lower.contains("usd 1"));

        currency_accepted || low_amount
    }

    /// Detect workflow bypass success
    fn detect_workflow_bypass_success(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Order completed without payment
        let bypass_indicators = vec![
            "order completed", "order confirmed", "order shipped",
            "payment status: paid", "status\": \"completed\"",
            "checkout complete", "order successful",
        ];

        for indicator in bypass_indicators {
            if body_lower.contains(indicator) {
                // Check that it's not an error message
                if !body_lower.contains("error") && !body_lower.contains("payment required") {
                    return true;
                }
            }
        }

        false
    }

    /// Detect payment bypass
    fn detect_payment_bypass(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let bypass_indicators = vec![
            "payment successful", "payment confirmed", "payment processed",
            "transaction complete", "paid\": true", "payment_status\": \"paid\"",
        ];

        for indicator in bypass_indicators {
            if body_lower.contains(indicator) {
                if !body_lower.contains("pending") && !body_lower.contains("failed") {
                    return true;
                }
            }
        }

        false
    }

    /// Detect form bypass success
    fn detect_form_bypass_success(&self, body: &str, attack_type: &str) -> bool {
        // First check if this is a SPA/single-page-app fallback response
        // SPAs return the same HTML for all routes - this is NOT a real form success
        let is_spa_response = body.contains("<app-root>") ||
            body.contains("<div id=\"root\">") ||
            body.contains("<div id=\"app\">") ||
            body.contains("__NEXT_DATA__") ||
            body.contains("__NUXT__") ||
            body.contains("ng-version=") ||
            body.contains("polyfills.js") ||
            body.contains("data-reactroot") ||
            body.contains("/_next/static/") ||
            (body.contains("<!DOCTYPE html>") && body.contains("<script") && body.len() > 5000);

        if is_spa_response {
            return false;
        }

        // Don't treat HTML responses as successful form submissions
        if body.contains("<!DOCTYPE") || body.contains("<html") {
            return false;
        }

        let body_lower = body.to_lowercase();

        // General success indicators - must be in API-like response, not HTML
        let success = body_lower.contains("success") ||
                     body_lower.contains("submitted") ||
                     body_lower.contains("registered") ||
                     body_lower.contains("complete") ||
                     body_lower.contains("thank you");

        // Specific checks based on attack type
        let bypass_detected = if attack_type.contains("CAPTCHA") {
            success && !body_lower.contains("captcha required") &&
                      !body_lower.contains("invalid captcha")
        } else if attack_type.contains("email") {
            success && !body_lower.contains("verify your email") &&
                      !body_lower.contains("email not verified")
        } else if attack_type.contains("terms") {
            success && !body_lower.contains("must agree") &&
                      !body_lower.contains("accept terms")
        } else {
            success && !body_lower.contains("required field") &&
                      !body_lower.contains("validation error")
        };

        bypass_detected
    }

    /// Extract token from response body
    fn extract_token_from_response(&self, body: &str) -> Option<String> {
        // Try to extract token from JSON response
        if let Some(start) = body.find("\"token\":\"") {
            let token_start = start + 9;
            if let Some(end) = body[token_start..].find('"') {
                return Some(body[token_start..token_start + end].to_string());
            }
        }

        // Try to extract from reset_token field
        if let Some(start) = body.find("\"reset_token\":\"") {
            let token_start = start + 15;
            if let Some(end) = body[token_start..].find('"') {
                return Some(body[token_start..token_start + end].to_string());
            }
        }

        // Try to extract from URL parameter
        if let Some(start) = body.find("token=") {
            let token_start = start + 6;
            let token_end = body[token_start..]
                .find(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
                .unwrap_or(body[token_start..].len());
            if token_end > 0 {
                return Some(body[token_start..token_start + token_end].to_string());
            }
        }

        None
    }

    /// Analyze token security
    fn analyze_token_security(&self, tokens: &[String]) -> TokenAnalysis {
        if tokens.is_empty() {
            return TokenAnalysis {
                is_weak: false,
                critically_weak: false,
                reason: "No tokens to analyze".to_string(),
                evidence: String::new(),
            };
        }

        let first_token = &tokens[0];

        // Check token length (< 20 chars = weak)
        if first_token.len() < 20 {
            return TokenAnalysis {
                is_weak: true,
                critically_weak: true,
                reason: format!("Token length too short: {} characters (minimum: 20)", first_token.len()),
                evidence: format!("Sample: {}", first_token),
            };
        }

        // Check if tokens are sequential
        if tokens.len() >= 2 {
            let sequential = self.check_sequential_tokens(tokens);
            if sequential {
                return TokenAnalysis {
                    is_weak: true,
                    critically_weak: true,
                    reason: "Tokens are sequential or incremental".to_string(),
                    evidence: format!("Tokens: {} -> {}", tokens[0], tokens[1]),
                };
            }
        }

        // Check charset (only numbers = weak)
        if first_token.chars().all(|c| c.is_numeric()) {
            return TokenAnalysis {
                is_weak: true,
                critically_weak: true,
                reason: "Token uses only numeric characters (low entropy)".to_string(),
                evidence: format!("Sample: {}", first_token),
            };
        }

        // Check for timestamp-based tokens
        if self.is_timestamp_based(first_token) {
            return TokenAnalysis {
                is_weak: true,
                critically_weak: false,
                reason: "Token appears to be timestamp-based (predictable)".to_string(),
                evidence: format!("Sample: {}", first_token),
            };
        }

        // Check for low entropy (repetitive patterns)
        let entropy = self.calculate_entropy(first_token);
        if entropy < 3.0 {
            return TokenAnalysis {
                is_weak: true,
                critically_weak: false,
                reason: format!("Token has low entropy: {:.2} bits/char (minimum: 3.0)", entropy),
                evidence: format!("Sample: {}", first_token),
            };
        }

        TokenAnalysis {
            is_weak: false,
            critically_weak: false,
            reason: "Token appears secure".to_string(),
            evidence: String::new(),
        }
    }

    /// Check if tokens are sequential
    fn check_sequential_tokens(&self, tokens: &[String]) -> bool {
        if tokens.len() < 2 {
            return false;
        }

        // Try to parse as numbers
        if let (Ok(num1), Ok(num2)) = (tokens[0].parse::<i64>(), tokens[1].parse::<i64>()) {
            return (num1 - num2).abs() == 1;
        }

        // Check if hex values are sequential
        if tokens[0].chars().all(|c| c.is_ascii_hexdigit()) &&
           tokens[1].chars().all(|c| c.is_ascii_hexdigit()) {
            if let (Ok(num1), Ok(num2)) = (
                i64::from_str_radix(&tokens[0], 16),
                i64::from_str_radix(&tokens[1], 16)
            ) {
                return (num1 - num2).abs() < 10;
            }
        }

        false
    }

    /// Check if token is timestamp-based
    fn is_timestamp_based(&self, token: &str) -> bool {
        // Check if token contains current timestamp
        let now = chrono::Utc::now().timestamp();
        let _now_str = now.to_string();

        // Check if token contains recent timestamp (within 1 day)
        for i in 0..86400 {
            let ts = (now - i).to_string();
            if token.contains(&ts) {
                return true;
            }
        }

        // Check for MD5/SHA1 of timestamp (32/40 hex chars)
        if token.len() == 32 || token.len() == 40 {
            if token.chars().all(|c| c.is_ascii_hexdigit()) {
                // Likely a hash, could be timestamp-based
                return true;
            }
        }

        false
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = std::collections::HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Detect coupon stacking
    fn detect_coupon_stacking(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Look for multiple discounts applied
        let stacking_indicators = vec![
            "discount applied", "discounts applied",
            "total savings", "multiple coupons",
            "save10", "save20", "save30",
        ];

        let mut discount_count = 0;
        for indicator in &stacking_indicators {
            if body_lower.contains(indicator) {
                discount_count += 1;
            }
        }

        // If we see references to multiple discount codes
        if discount_count >= 2 {
            return !body_lower.contains("only one") && !body_lower.contains("cannot combine");
        }

        // Check for multiple discount amounts in response
        let discount_pattern = body_lower.matches("discount").count();
        discount_pattern >= 3
    }

    /// Detect coupon applied
    fn detect_coupon_applied(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let applied_indicators = vec![
            "coupon applied", "discount applied", "promo applied",
            "code accepted", "savings", "discounted",
        ];

        for indicator in applied_indicators {
            if body_lower.contains(indicator) {
                if !body_lower.contains("invalid") && !body_lower.contains("expired") {
                    return true;
                }
            }
        }

        false
    }

    /// Detect negative discount
    fn detect_negative_discount(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Look for negative discount amounts
        let negative_indicators = vec![
            "discount: -", "discount\":-", "discount\": -",
            "savings: -", "total increased",
        ];

        for indicator in negative_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check if price increased instead of decreased
        if body_lower.contains("discount") && body_lower.contains("added") {
            return true;
        }

        false
    }

    /// Detect excessive discount
    fn detect_excessive_discount(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Look for over 100% discount
        let excessive_indicators = vec![
            "discount: 100%", "discount: 200%", "discount\": 100",
            "discount\": 200", "total: -", "total\": -",
            "negative total", "amount: $-", "amount\": -",
        ];

        for indicator in excessive_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check for discount percentage over 100 in JSON
        if body_lower.contains("discount_percent") {
            // Try to extract the value
            if let Some(start) = body_lower.find("discount_percent") {
                let substr = &body_lower[start..];
                if substr.contains("100") || substr.contains("200") || substr.contains("150") {
                    return true;
                }
            }
        }

        false
    }

    /// Detect successful transaction
    fn detect_successful_transaction(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let success_indicators = vec![
            "success",
            "completed",
            "confirmed",
            "approved",
            "processed",
            "accepted",
            "transaction_id",
            "order_id",
            "reference",
            "\"status\":\"ok\"",
            "\"status\":\"success\"",
        ];

        for indicator in success_indicators {
            if body_lower.contains(indicator) && !body_lower.contains("error") && !body_lower.contains("failed") {
                return true;
            }
        }

        false
    }

    /// Detect price manipulation success
    fn detect_price_manipulation(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if manipulated price appears in response
        if body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("{}={}", param, value)) {
            return true;
        }

        // Check for success without price validation error
        let no_error = !body_lower.contains("invalid price") &&
            !body_lower.contains("price error") &&
            !body_lower.contains("validation failed");

        let success = body_lower.contains("success") ||
            body_lower.contains("confirmed") ||
            body_lower.contains("order placed");

        no_error && success
    }

    /// Detect quantity tampering success
    fn detect_quantity_tampering(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if tampered quantity appears in response
        if body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) {
            return true;
        }

        // Check for acceptance without validation error
        let no_error = !body_lower.contains("invalid quantity") &&
            !body_lower.contains("quantity error") &&
            !body_lower.contains("out of range");

        let success = body_lower.contains("added") ||
            body_lower.contains("updated") ||
            body_lower.contains("success");

        no_error && success
    }

    /// Detect coupon bypass
    fn detect_coupon_bypass(&self, body: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for SQL injection success
        if value.contains("'") && (body_lower.contains("sql") || body_lower.contains("syntax")) {
            return true;
        }

        // Check for path traversal success
        if value.contains("../") && (body_lower.contains("root:") || body_lower.contains("etc/passwd")) {
            return true;
        }

        // Check for coupon applied successfully
        (body_lower.contains("discount applied") ||
         body_lower.contains("coupon valid") ||
         body_lower.contains("savings")) &&
        !body_lower.contains("invalid") &&
        !body_lower.contains("expired")
    }

    /// Detect coupon reuse vulnerability
    fn detect_coupon_reuse(&self, first_body: &str, second_body: &str) -> bool {
        let first_lower = first_body.to_lowercase();
        let second_lower = second_body.to_lowercase();

        // Both requests show discount applied
        let first_success = first_lower.contains("applied") || first_lower.contains("discount");
        let second_success = second_lower.contains("applied") || second_lower.contains("discount");

        // Second doesn't show "already used" error
        let no_reuse_error = !second_lower.contains("already used") &&
            !second_lower.contains("already applied") &&
            !second_lower.contains("one time only");

        first_success && second_success && no_reuse_error
    }

    /// Detect integer overflow
    fn detect_integer_overflow(&self, body: &str, param: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check for overflow indicators
        let overflow_indicators = vec![
            "negative",
            "-2147483648",
            "-9223372036854775808",
            "infinity",
            "nan",
            "overflow",
        ];

        for indicator in overflow_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check if large value was accepted
        let accepted = body_lower.contains("success") ||
            body_lower.contains("accepted") ||
            body_lower.contains(&format!("\"{}\":", param));

        let no_error = !body_lower.contains("error") &&
            !body_lower.contains("invalid") &&
            !body_lower.contains("too large");

        accepted && no_error
    }

    /// Detect timestamp manipulation success
    fn detect_timestamp_manipulation(&self, body: &str, param: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if timestamp was accepted
        let no_error = !body_lower.contains("invalid date") &&
            !body_lower.contains("timestamp error") &&
            !body_lower.contains("date format");

        let accepted = body_lower.contains("success") ||
            body_lower.contains(&format!("\"{}\":", param)) ||
            body_lower.contains("valid");

        no_error && accepted
    }

    /// Detect if expired token was accepted
    fn detect_token_accepted(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();

        let accepted = body_lower.contains("valid") ||
            body_lower.contains("success") ||
            body_lower.contains("authenticated");

        let no_error = !body_lower.contains("expired") &&
            !body_lower.contains("invalid token") &&
            !body_lower.contains("token error");

        accepted && no_error
    }

    /// Detect if negative value was accepted
    fn detect_negative_value_accepted(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if value appears in response as accepted
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("'{}':'{}'", param, value)) {
            return true;
        }

        // Check for success indicators
        let success_indicators = vec![
            "success",
            "updated",
            "saved",
            "accepted",
            "confirmed",
        ];

        for indicator in success_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Detect workflow bypass
    fn detect_workflow_bypass(&self, body: &str, target_state: &str) -> bool {
        let body_lower = body.to_lowercase();
        let target_lower = target_state.to_lowercase();

        // Check if target state is reflected
        if body_lower.contains(&target_lower) {
            // Check for success indicators
            let success_indicators = vec![
                "completed",
                "success",
                "confirmed",
                "approved",
                "verified",
            ];

            for indicator in success_indicators {
                if body_lower.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect parameter tampering
    fn detect_parameter_tampering(&self, body: &str, param: &str, value: &str) -> bool {
        let body_lower = body.to_lowercase();

        // Check if tampered value was accepted
        if body_lower.contains(&format!("\"{}\":\"{}\"", param, value)) ||
           body_lower.contains(&format!("\"{}\":{}", param, value)) ||
           body_lower.contains(&format!("{}={}", param, value)) {
            return true;
        }

        // Check for indicators that tampering worked
        if param.contains("discount") && body_lower.contains("discount") {
            return true;
        }

        if (param == "shipping" || param == "tax") && value == "0" {
            if body_lower.contains(&format!("{}:0", param)) ||
               body_lower.contains(&format!("{}\":0", param)) {
                return true;
            }
        }

        false
    }

    /// Create a vulnerability record
    fn create_vulnerability(
        &self,
        url: &str,
        vuln_type: &str,
        payload: &str,
        description: &str,
        evidence: &str,
        severity: Severity,
        cwe: &str,
    ) -> Vulnerability {
        let cvss = match severity {
            Severity::Critical => 9.1,
            Severity::High => 7.5,
            Severity::Medium => 5.3,
            _ => 3.1,
        };

        Vulnerability {
            id: format!("bl_{}", uuid::Uuid::new_v4().to_string()),
            vuln_type: vuln_type.to_string(),
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
            remediation: "1. Implement server-side validation for all business logic\n\
                         2. Validate data types, ranges, and business rules\n\
                         3. Reject negative values for quantities and prices\n\
                         4. Implement proper state machine for workflows\n\
                         5. Validate workflow transitions server-side\n\
                         6. Never trust client-supplied business logic parameters\n\
                         7. Recalculate prices, totals, and discounts server-side\n\
                         8. Implement business rule engines for complex logic\n\
                         9. Log and monitor unusual parameter values\n\
                         10. Use database constraints for data integrity\n\
                         11. Implement authorization checks for each workflow step\n\
                         12. Test edge cases and boundary values".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
                ml_data: None,
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
    use crate::detection_helpers::AppCharacteristics;
use crate::http_client::HttpClient;
    use std::sync::Arc;

    fn create_test_scanner() -> BusinessLogicScanner {
        let http_client = Arc::new(HttpClient::new(30, 3).unwrap());
        BusinessLogicScanner::new(http_client)
    }

    #[test]
    fn test_detect_negative_value_accepted() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_negative_value_accepted(r#"{"quantity":"-1"}"#, "quantity", "-1"));
        assert!(scanner.detect_negative_value_accepted("Update successful", "price", "-10"));
    }

    #[test]
    fn test_detect_workflow_bypass() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_workflow_bypass("Order completed successfully", "completed"));
        assert!(scanner.detect_workflow_bypass("Payment verified", "verified"));
    }

    #[test]
    fn test_detect_parameter_tampering() {
        let scanner = create_test_scanner();

        assert!(scanner.detect_parameter_tampering(r#"{"discount":"100"}"#, "discount", "100"));
        assert!(scanner.detect_parameter_tampering(r#"{"shipping":0}"#, "shipping", "0"));
    }

    #[test]
    fn test_no_false_positives() {
        let scanner = create_test_scanner();

        assert!(!scanner.detect_negative_value_accepted("Invalid input", "quantity", "-1"));
        assert!(!scanner.detect_workflow_bypass("Error", "completed"));
        assert!(!scanner.detect_parameter_tampering("Failed", "discount", "100"));
    }

    #[test]
    fn test_create_vulnerability() {
        let scanner = create_test_scanner();

        let vuln = scanner.create_vulnerability(
            "http://example.com",
            "Negative Value Manipulation",
            "quantity=-1",
            "Negative values accepted",
            "quantity set to -1",
            Severity::High,
            "CWE-840",
        );

        assert_eq!(vuln.vuln_type, "Negative Value Manipulation");
        assert_eq!(vuln.severity, Severity::High);
        assert_eq!(vuln.cwe, "CWE-840");
        assert_eq!(vuln.cvss, 7.5);
    }
}
