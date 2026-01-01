// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Payload Cache System
 * High-performance payload deduplication and caching with metrics
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use moka::future::Cache;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

pub struct PayloadCacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    deduplication_saves: AtomicU64,
}

impl PayloadCacheMetrics {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            deduplication_saves: AtomicU64::new(0),
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_deduplication(&self) {
        self.deduplication_saves.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> PayloadCacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        PayloadCacheStats {
            hits,
            misses,
            evictions: self.evictions.load(Ordering::Relaxed),
            deduplication_saves: self.deduplication_saves.load(Ordering::Relaxed),
            hit_rate: if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.deduplication_saves.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct PayloadCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub deduplication_saves: u64,
    pub hit_rate: f64,
}

pub struct PayloadCache {
    cache: Cache<Arc<str>, Arc<str>>,
    seen_payloads: Arc<RwLock<HashSet<Arc<str>>>>,
    metrics: Arc<PayloadCacheMetrics>,
}

impl PayloadCache {
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();

        info!(
            "Initialized payload cache: capacity={}, ttl={}s",
            max_capacity, ttl_secs
        );

        Self {
            cache,
            seen_payloads: Arc::new(RwLock::new(HashSet::new())),
            metrics: Arc::new(PayloadCacheMetrics::new()),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Arc<str>> {
        let result = self.cache.get(&Arc::from(key)).await;

        if result.is_some() {
            self.metrics.record_hit();
            debug!("Cache hit for key: {}", key);
        } else {
            self.metrics.record_miss();
        }

        result
    }

    pub async fn insert(&self, key: String, value: String) {
        let key_arc = Arc::from(key.as_str());
        let value_arc = Arc::from(value.as_str());

        self.cache.insert(key_arc, value_arc).await;
    }

    pub async fn is_payload_seen(&self, payload: &str) -> bool {
        let seen = self.seen_payloads.read().await;
        let payload_arc = Arc::from(payload);

        if seen.contains(&payload_arc) {
            self.metrics.record_deduplication();
            true
        } else {
            false
        }
    }

    pub async fn mark_payload_seen(&self, payload: String) {
        let mut seen = self.seen_payloads.write().await;
        let payload_arc = Arc::from(payload.as_str());
        seen.insert(payload_arc);
    }

    pub async fn deduplicate_payloads(&self, payloads: Vec<String>) -> Vec<Arc<str>> {
        let mut unique_payloads = Vec::new();
        let mut seen = self.seen_payloads.write().await;

        for payload in payloads {
            let payload_arc = Arc::from(payload.as_str());

            if !seen.contains(&payload_arc) {
                seen.insert(payload_arc.clone());
                unique_payloads.push(payload_arc);
            } else {
                self.metrics.record_deduplication();
            }
        }

        debug!(
            "Deduplicated payloads: {} unique out of {}",
            unique_payloads.len(),
            unique_payloads.len() + self.metrics.deduplication_saves.load(Ordering::Relaxed) as usize
        );

        unique_payloads
    }

    pub fn get_metrics(&self) -> PayloadCacheStats {
        self.metrics.get_stats()
    }

    pub async fn warm_cache(&self, common_keys: Vec<(String, String)>) {
        info!("Warming cache with {} common payloads", common_keys.len());

        for (key, value) in common_keys {
            self.insert(key, value).await;
        }

        info!("Cache warming completed");
    }

    pub async fn invalidate(&self, key: &str) {
        let key_arc = Arc::from(key);
        self.cache.invalidate(&key_arc).await;
        self.metrics.record_eviction();
    }

    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all();
        let mut seen = self.seen_payloads.write().await;
        seen.clear();
        info!("Cache invalidated");
    }

    pub async fn get_size(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn reset_metrics(&self) {
        self.metrics.reset();
    }
}

pub fn get_common_payloads_for_warming() -> Vec<(String, String)> {
    vec![
        ("xss_basic".to_string(), "<script>alert(1)</script>".to_string()),
        ("xss_img".to_string(), "<img src=x onerror=alert(1)>".to_string()),
        ("sqli_basic".to_string(), "' OR '1'='1".to_string()),
        ("sqli_union".to_string(), "' UNION SELECT NULL--".to_string()),
        ("path_basic".to_string(), "../../../etc/passwd".to_string()),
        ("path_windows".to_string(), "..\\..\\..\\windows\\system32\\config\\sam".to_string()),
        ("ssrf_aws".to_string(), "http://169.254.169.254/latest/meta-data/".to_string()),
        ("ssrf_gcp".to_string(), "http://metadata.google.internal/".to_string()),
        ("cmd_basic".to_string(), "; ls -la".to_string()),
        ("cmd_windows".to_string(), "& dir".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_hit_miss() {
        let cache = PayloadCache::new(100, 300);

        cache.insert("key1".to_string(), "value1".to_string()).await;

        let result = cache.get("key1").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), "value1");

        let result = cache.get("key2").await;
        assert!(result.is_none());

        let stats = cache.get_metrics();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[tokio::test]
    async fn test_payload_deduplication() {
        let cache = PayloadCache::new(100, 300);

        let payloads = vec![
            "payload1".to_string(),
            "payload2".to_string(),
            "payload1".to_string(),
            "payload3".to_string(),
            "payload2".to_string(),
        ];

        let unique = cache.deduplicate_payloads(payloads).await;

        assert_eq!(unique.len(), 3);

        let stats = cache.get_metrics();
        assert_eq!(stats.deduplication_saves, 2);
    }

    #[tokio::test]
    async fn test_cache_warming() {
        let cache = PayloadCache::new(100, 300);

        let common_payloads = get_common_payloads_for_warming();
        cache.warm_cache(common_payloads.clone()).await;

        for (key, value) in common_payloads {
            let result = cache.get(&key).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().as_ref(), value);
        }

        let stats = cache.get_metrics();
        assert!(stats.hit_rate > 0.0);
    }

    #[tokio::test]
    async fn test_payload_seen_tracking() {
        let cache = PayloadCache::new(100, 300);

        assert!(!cache.is_payload_seen("test_payload").await);

        cache.mark_payload_seen("test_payload".to_string()).await;

        assert!(cache.is_payload_seen("test_payload").await);
    }
}
