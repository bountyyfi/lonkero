// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Cloud Performance Optimizations
 * Connection pooling, caching, and parallel processing for cloud operations
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{Instant, Duration};
use tracing::info;

/// Cache for cloud metadata to reduce API calls
pub struct CloudMetadataCache {
    cache: Arc<RwLock<HashMap<String, String>>>,
    ttl_secs: u64,
    max_size: usize,
}

impl CloudMetadataCache {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_secs: ttl.as_secs(),
            max_size,
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.cache.read().get(key).cloned()
    }

    pub fn set(&self, key: String, value: String) {
        let mut cache = self.cache.write();
        if cache.len() >= self.max_size {
            // Simple eviction: clear cache when full
            cache.clear();
        }
        cache.insert(key, value);
    }

    pub fn clear(&self) {
        self.cache.write().clear();
    }

    pub fn size(&self) -> usize {
        self.cache.read().len()
    }
}

impl Default for CloudMetadataCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300), 1000)
    }
}

/// Connection pool for managing cloud API connections
pub struct CloudConnectionPool {
    max_connections: usize,
    active_connections: Arc<RwLock<usize>>,
    total_acquired: Arc<RwLock<u64>>,
    total_released: Arc<RwLock<u64>>,
}

impl CloudConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active_connections: Arc::new(RwLock::new(0)),
            total_acquired: Arc::new(RwLock::new(0)),
            total_released: Arc::new(RwLock::new(0)),
        }
    }

    pub fn acquire(&self) -> Option<ConnectionGuard> {
        let mut count = self.active_connections.write();
        if *count < self.max_connections {
            *count += 1;
            *self.total_acquired.write() += 1;
            Some(ConnectionGuard {
                pool: self.active_connections.clone(),
                released: Arc::clone(&self.total_released),
            })
        } else {
            None
        }
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            max_connections: self.max_connections,
            active_connections: *self.active_connections.read(),
            total_acquired: *self.total_acquired.read(),
            total_released: *self.total_released.read(),
        }
    }

    pub fn available(&self) -> usize {
        self.max_connections.saturating_sub(*self.active_connections.read())
    }
}

impl Default for CloudConnectionPool {
    fn default() -> Self {
        Self::new(10)
    }
}

/// RAII guard for connection pool
pub struct ConnectionGuard {
    pool: Arc<RwLock<usize>>,
    released: Arc<RwLock<u64>>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut count = self.pool.write();
        *count = count.saturating_sub(1);
        *self.released.write() += 1;
    }
}

/// Statistics about connection pool usage
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub max_connections: usize,
    pub active_connections: usize,
    pub total_acquired: u64,
    pub total_released: u64,
}

/// Batches multiple requests for efficient processing
pub struct BatchRequestProcessor<T> {
    batch_size: usize,
    pending: Arc<RwLock<Vec<T>>>,
}

impl<T> BatchRequestProcessor<T> {
    pub fn new(batch_size: usize) -> Self {
        Self {
            batch_size,
            pending: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn add(&self, item: T) {
        self.pending.write().push(item);
    }

    pub fn flush(&self) -> Vec<T> {
        let mut pending = self.pending.write();
        std::mem::take(&mut *pending)
    }

    pub fn should_flush(&self) -> bool {
        self.pending.read().len() >= self.batch_size
    }

    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    pub fn clear(&self) {
        self.pending.write().clear();
    }
}

impl<T> Default for BatchRequestProcessor<T> {
    fn default() -> Self {
        Self::new(50)
    }
}

/// Executes tasks in parallel with concurrency control
pub struct ParallelExecutor {
    max_parallel: usize,
}

impl ParallelExecutor {
    pub fn new(max_parallel: usize) -> Self {
        Self { max_parallel }
    }

    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    pub fn set_max_parallel(&mut self, max_parallel: usize) {
        self.max_parallel = max_parallel;
    }
}

impl Default for ParallelExecutor {
    fn default() -> Self {
        Self::new(5)
    }
}

/// Deduplicates identical requests
pub struct RequestDeduplicator {
    seen: Arc<RwLock<HashMap<String, Instant>>>,
    ttl_secs: u64,
}

impl RequestDeduplicator {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            seen: Arc::new(RwLock::new(HashMap::new())),
            ttl_secs,
        }
    }

    pub fn is_duplicate(&self, key: &str) -> bool {
        let seen = self.seen.read();
        if let Some(timestamp) = seen.get(key) {
            timestamp.elapsed().as_secs() < self.ttl_secs
        } else {
            false
        }
    }

    pub fn mark_seen(&self, key: String) {
        self.seen.write().insert(key, Instant::now());
    }

    pub fn clear(&self) {
        self.seen.write().clear();
    }

    pub fn cleanup_expired(&self) {
        let mut seen = self.seen.write();
        seen.retain(|_, timestamp| timestamp.elapsed().as_secs() < self.ttl_secs);
    }

    pub fn size(&self) -> usize {
        self.seen.read().len()
    }
}

impl Default for RequestDeduplicator {
    fn default() -> Self {
        Self::new(60)
    }
}

/// Tracks performance metrics for cloud operations
pub struct PerformanceMetrics {
    start: Instant,
    name: String,
    api_calls: usize,
    cache_hits: usize,
    cache_misses: usize,
    errors: usize,
}

impl PerformanceMetrics {
    pub fn new(name: &str) -> Self {
        Self {
            start: Instant::now(),
            name: name.to_string(),
            api_calls: 0,
            cache_hits: 0,
            cache_misses: 0,
            errors: 0,
        }
    }

    pub fn record_api_call(&mut self) {
        self.api_calls += 1;
    }

    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    pub fn api_calls(&self) -> usize {
        self.api_calls
    }

    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub fn cache_misses(&self) -> usize {
        self.cache_misses
    }

    pub fn errors(&self) -> usize {
        self.errors
    }

    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{}: {}ms, {} API calls, {} errors, cache hit rate: {:.2}%",
            self.name,
            self.elapsed_ms(),
            self.api_calls,
            self.errors,
            self.cache_hit_rate() * 100.0
        )
    }

    pub fn reset(&mut self) {
        self.start = Instant::now();
        self.api_calls = 0;
        self.cache_hits = 0;
        self.cache_misses = 0;
        self.errors = 0;
    }

    pub fn report(&self) {
        info!("{}", self.summary());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache() {
        let cache = CloudMetadataCache::new(Duration::from_secs(300), 10);
        cache.set("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        assert_eq!(cache.size(), 1);
        cache.clear();
        assert_eq!(cache.get("key1"), None);
        assert_eq!(cache.size(), 0);
    }

    #[test]
    fn test_cache_eviction() {
        let cache = CloudMetadataCache::new(Duration::from_secs(300), 2);
        cache.set("key1".to_string(), "value1".to_string());
        cache.set("key2".to_string(), "value2".to_string());
        assert_eq!(cache.size(), 2);

        // Adding third item should trigger eviction
        cache.set("key3".to_string(), "value3".to_string());
        assert_eq!(cache.size(), 1);
    }

    #[test]
    fn test_connection_pool() {
        let pool = CloudConnectionPool::new(2);
        let _guard1 = pool.acquire().unwrap();
        let _guard2 = pool.acquire().unwrap();
        assert!(pool.acquire().is_none());

        let stats = pool.stats();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.max_connections, 2);

        drop(_guard1);
        assert!(pool.acquire().is_some());
    }

    #[test]
    fn test_connection_pool_stats() {
        let pool = CloudConnectionPool::new(5);

        let guard1 = pool.acquire().unwrap();
        let guard2 = pool.acquire().unwrap();

        let stats = pool.stats();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_acquired, 2);
        assert_eq!(stats.total_released, 0);
        assert_eq!(pool.available(), 3);

        drop(guard1);

        let stats = pool.stats();
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_released, 1);

        drop(guard2);
    }

    #[test]
    fn test_batch_processor() {
        let processor = BatchRequestProcessor::<i32>::new(5);

        processor.add(1);
        processor.add(2);
        processor.add(3);

        assert_eq!(processor.pending_count(), 3);
        assert!(!processor.should_flush());

        processor.add(4);
        processor.add(5);

        assert!(processor.should_flush());

        let items = processor.flush();
        assert_eq!(items.len(), 5);
        assert_eq!(processor.pending_count(), 0);
    }

    #[test]
    fn test_deduplicator() {
        let dedup = RequestDeduplicator::new(60);

        assert!(!dedup.is_duplicate("key1"));
        dedup.mark_seen("key1".to_string());
        assert!(dedup.is_duplicate("key1"));
        assert_eq!(dedup.size(), 1);

        dedup.clear();
        assert!(!dedup.is_duplicate("key1"));
        assert_eq!(dedup.size(), 0);
    }

    #[test]
    fn test_deduplicator_expiry() {
        let dedup = RequestDeduplicator::new(0); // 0 second TTL

        dedup.mark_seen("key1".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Should be expired
        assert!(!dedup.is_duplicate("key1"));
    }

    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::new("test");

        metrics.record_api_call();
        metrics.record_api_call();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        metrics.record_error();

        assert_eq!(metrics.api_calls(), 2);
        assert_eq!(metrics.cache_hits(), 1);
        assert_eq!(metrics.cache_misses(), 1);
        assert_eq!(metrics.errors(), 1);
        assert_eq!(metrics.cache_hit_rate(), 0.5);

        let summary = metrics.summary();
        assert!(summary.contains("test"));
        assert!(summary.contains("2 API calls"));
        assert!(summary.contains("50.00%"));
    }

    #[test]
    fn test_performance_metrics_reset() {
        let mut metrics = PerformanceMetrics::new("test");

        metrics.record_api_call();
        metrics.record_cache_hit();

        assert_eq!(metrics.api_calls(), 1);

        metrics.reset();

        assert_eq!(metrics.api_calls(), 0);
        assert_eq!(metrics.cache_hits(), 0);
    }

    #[test]
    fn test_parallel_executor() {
        let executor = ParallelExecutor::new(3);
        assert_eq!(executor.max_parallel(), 3);

        let mut executor = ParallelExecutor::default();
        assert_eq!(executor.max_parallel(), 5);

        executor.set_max_parallel(10);
        assert_eq!(executor.max_parallel(), 10);
    }
}
