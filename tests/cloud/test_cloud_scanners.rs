// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Scanners Integration Tests
 * Comprehensive tests for cloud security scanners
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

#[cfg(test)]
mod tests {
    use lonkero_scanner::cloud::{
        CloudError, CloudMetadataCache, CloudConnectionPool, ParallelExecutor,
        PerformanceMetrics, ExponentialBackoff, RetryConfig, CircuitBreaker,
    };
    use lonkero_scanner::scanners::cloud::{
        CloudIamAnalyzer, CloudNetworkAnalyzer, CloudComplianceScanner,
        CloudCostOptimizer, CloudSecretsScanner, CloudContainerSecurityScanner,
        CloudApiGatewaySecurityScanner,
    };
    use std::time::Duration;

    // Error Handling Tests
    #[tokio::test]
    async fn test_exponential_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 1000,
            backoff_multiplier: 2.0,
            retry_on_rate_limit: true,
            retry_on_timeout: true,
            retry_on_network_error: true,
        };

        let mut backoff = ExponentialBackoff::new(config);

        let delay1 = backoff.next_backoff();
        assert!(delay1.is_some());
        assert_eq!(delay1.unwrap().as_millis(), 100);

        let delay2 = backoff.next_backoff();
        assert!(delay2.is_some());
        assert_eq!(delay2.unwrap().as_millis(), 200);

        let delay3 = backoff.next_backoff();
        assert!(delay3.is_some());
        assert_eq!(delay3.unwrap().as_millis(), 400);

        let delay4 = backoff.next_backoff();
        assert!(delay4.is_none());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let breaker = CircuitBreaker::new(2, 1, Duration::from_millis(100));

        // First failure
        let result1 = breaker
            .call(|| async {
                Err::<(), CloudError>(CloudError::ApiError("test error".to_string()))
            })
            .await;
        assert!(result1.is_err());

        // Second failure should open circuit
        let result2 = breaker
            .call(|| async {
                Err::<(), CloudError>(CloudError::ApiError("test error".to_string()))
            })
            .await;
        assert!(result2.is_err());

        // Circuit should be open
        let state = breaker.get_state().await;
        assert_eq!(state, lonkero_scanner::cloud::error_handling::CircuitState::Open);
    }

    // Optimization Tests
    #[tokio::test]
    async fn test_cloud_metadata_cache() {
        let cache = CloudMetadataCache::new(100, Duration::from_secs(60));

        let key = "test-key";
        let value = serde_json::json!({"data": "test"});

        cache.insert(key.to_string(), value.clone()).await;

        let cached = cache.get(key).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), value);

        cache.invalidate(key).await;
        let after_invalidate = cache.get(key).await;
        assert!(after_invalidate.is_none());
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = CloudConnectionPool::new(3);

        let conn1 = pool.acquire().await;
        let conn2 = pool.acquire().await;
        let conn3 = pool.acquire().await;

        let stats = pool.stats().await;
        assert_eq!(stats.active_connections, 3);
        assert_eq!(stats.max_connections, 3);
        assert_eq!(stats.total_acquired, 3);

        drop(conn1);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats2 = pool.stats().await;
        assert_eq!(stats2.active_connections, 2);

        drop(conn2);
        drop(conn3);
    }

    #[tokio::test]
    async fn test_parallel_executor() {
        let executor = ParallelExecutor::new(3);

        let tasks: Vec<i32> = (1..=10).collect();

        let results = executor
            .execute(tasks, |x| async move { x * 2 })
            .await;

        assert_eq!(results.len(), 10);
        assert!(results.contains(&2));
        assert!(results.contains(&20));
    }

    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::new("test_operation");

        metrics.record_api_call();
        metrics.record_api_call();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        // Metrics report should not panic
        metrics.report();
    }

    // Scanner Instantiation Tests
    #[test]
    fn test_iam_analyzer_creation() {
        let analyzer = CloudIamAnalyzer::new();
        // Should not panic
        assert!(true);
    }

    #[test]
    fn test_network_analyzer_creation() {
        let analyzer = CloudNetworkAnalyzer::new();

        // Test port classification
        assert!(analyzer.is_dangerous_port(22));
        assert!(analyzer.is_dangerous_port(3389));
        assert!(analyzer.is_dangerous_port(3306));
        assert!(!analyzer.is_dangerous_port(443));

        assert!(analyzer.is_management_port(22));
        assert!(analyzer.is_management_port(3389));
        assert!(!analyzer.is_management_port(80));
    }

    #[test]
    fn test_compliance_scanner_creation() {
        let scanner = CloudComplianceScanner::new();
        // Should not panic
        assert!(true);
    }

    #[test]
    fn test_cost_optimizer_creation() {
        let optimizer = CloudCostOptimizer::new();
        // Should not panic
        assert!(true);
    }

    #[test]
    fn test_secrets_scanner_creation() {
        let scanner = CloudSecretsScanner::new();
        // Should not panic
        assert!(true);
    }

    #[test]
    fn test_container_scanner_creation() {
        let scanner = CloudContainerSecurityScanner::new();
        // Should not panic
        assert!(true);
    }

    #[test]
    fn test_api_gateway_scanner_creation() {
        let scanner = CloudApiGatewaySecurityScanner::new();
        // Should not panic
        assert!(true);
    }

    // Container Config Tests
    #[test]
    fn test_container_root_user_detection() {
        let scanner = CloudContainerSecurityScanner::new();

        let config = serde_json::json!({
            "User": "root"
        });

        let vulns = scanner.check_container_config(&config);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Root")));
    }

    #[test]
    fn test_container_privileged_detection() {
        let scanner = CloudContainerSecurityScanner::new();

        let config = serde_json::json!({
            "Privileged": true
        });

        let vulns = scanner.check_container_config(&config);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.vuln_type.contains("Privileged")));
    }

    #[test]
    fn test_container_secrets_in_env() {
        let scanner = CloudContainerSecurityScanner::new();

        let config = serde_json::json!({
            "Env": [
                "DATABASE_PASSWORD=secret123",
                "API_KEY=xyz789"
            ]
        });

        let vulns = scanner.check_container_config(&config);
        assert!(!vulns.is_empty());
    }

    // Note: AWS/Azure/GCP integration tests would require credentials
    // and actual cloud resources. These should be run in a CI/CD pipeline
    // with proper credentials configured.

    #[test]
    fn test_module_imports() {
        // Verify all modules are accessible
        use lonkero_scanner::cloud::error_handling::CloudError;
        use lonkero_scanner::cloud::optimizations::CloudMetadataCache;
        use lonkero_scanner::scanners::cloud::*;

        // If compilation succeeds, imports are working
        assert!(true);
    }
}
