// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Business Logic Scanner
 * Detects business logic vulnerabilities
 *
 * Detects:
 * - Negative quantity/price manipulation
 * - Workflow bypass
 * - Parameter tampering for discounts
 * - Insufficient process validation
 * - State manipulation
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, Severity, Vulnerability};
use std::sync::Arc;
use tracing::{debug, info};

pub struct BusinessLogicScanner {
    http_client: Arc<HttpClient>,
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

        Ok((vulnerabilities, tests_run))
    }

    /// Test negative quantity/price values
    async fn test_negative_values(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 6;

        info!("Testing negative value handling");

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

        info!("Testing workflow bypass");

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

        info!("Testing parameter tampering");

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

        info!("Testing race condition vulnerabilities (TOCTOU)");

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

        info!("Testing price manipulation vulnerabilities");

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

        info!("Testing quantity tampering vulnerabilities");

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

        info!("Testing coupon/voucher abuse vulnerabilities");

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

        info!("Testing double-spend / replay attack vulnerabilities");

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

        info!("Testing integer overflow/underflow vulnerabilities");

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
    async fn test_time_based_attacks(&self, url: &str) -> anyhow::Result<(Vec<Vulnerability>, usize)> {
        let mut vulnerabilities = Vec::new();
        let tests_run = 4;

        info!("Testing time-based attack vulnerabilities");

        // Test timestamp manipulation
        let timestamp_tests = vec![
            ("timestamp", "0"),
            ("date", "2099-12-31"),
            ("expires", "9999999999"),
            ("valid_until", "2000-01-01"),
            ("created_at", "1970-01-01"),
        ];

        for (param, value) in &timestamp_tests {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, value)
            } else {
                format!("{}?{}={}", url, param, value)
            };

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_timestamp_manipulation(&response.body, param) {
                        vulnerabilities.push(self.create_vulnerability(
                            url,
                            "Time-Based Attack",
                            &format!("{}={}", param, value),
                            &format!(
                                "Timestamp validation is insufficient. The '{}' parameter can be \
                                 manipulated to bypass time-based restrictions, extend validity periods, \
                                 or access expired resources.",
                                param
                            ),
                            &format!("Timestamp {} accepted for {}", value, param),
                            Severity::Medium,
                            "CWE-367",
                        ));
                        break;
                    }
                }
                Err(e) => debug!("Request failed: {}", e),
            }
        }

        // Test for expired token reuse
        let token_endpoints = vec![
            format!("{}/verify", url.trim_end_matches('/')),
            format!("{}/validate", url.trim_end_matches('/')),
        ];

        let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjB9.invalid";

        for endpoint in &token_endpoints {
            let test_url = format!("{}?token={}", endpoint, expired_token);

            match self.http_client.get(&test_url).await {
                Ok(response) => {
                    if self.detect_token_accepted(&response.body) {
                        vulnerabilities.push(self.create_vulnerability(
                            &endpoint,
                            "Expired Token Acceptance",
                            &format!("token={}", expired_token),
                            "Server accepts expired or invalid tokens without proper validation",
                            "Expired token was accepted",
                            Severity::High,
                            "CWE-613",
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }
        }

        Ok((vulnerabilities, tests_run))
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
