// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - DNS Caching Module
 * Optimized caching with moka, TTL, and metrics
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use std::net::IpAddr;
use std::time::Duration;
use moka::future::Cache;
use tracing::{debug, info};

/// Default TTL for DNS cache entries (5 minutes)
const DEFAULT_DNS_TTL: u64 = 300;

/// Default maximum cache size
const DEFAULT_MAX_CAPACITY: u64 = 10000;

/// Optimized DNS cache using moka with TTL and eviction
pub struct DnsCache {
    cache: Cache<String, IpAddr>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl DnsCache {
    /// Create a new DNS cache with default settings
    pub fn new() -> Self {
        Self::with_config(DEFAULT_MAX_CAPACITY, DEFAULT_DNS_TTL)
    }

    /// Create DNS cache with custom capacity and TTL
    pub fn with_config(max_capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();

        info!(
            "DNS cache initialized: max_capacity={}, ttl={}s",
            max_capacity, ttl_secs
        );

        Self {
            cache,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Resolve a hostname, using cache if available
    pub async fn resolve(&self, hostname: &str) -> Option<IpAddr> {
        // Check cache first
        if let Some(ip) = self.cache.get(hostname).await {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("DNS cache hit for: {} -> {}", hostname, ip);
            return Some(ip);
        }

        // Cache miss
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("DNS cache miss for: {}, using system resolver", hostname);

        // Use tokio's built-in DNS resolution (async)
        match tokio::net::lookup_host(format!("{}:80", hostname)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let ip = addr.ip();
                    // Store in cache
                    self.cache.insert(hostname.to_string(), ip).await;
                    debug!("DNS resolved and cached: {} -> {}", hostname, ip);
                    Some(ip)
                } else {
                    None
                }
            }
            Err(e) => {
                debug!("DNS resolution failed for {}: {}", hostname, e);
                None
            }
        }
    }

    /// Clear all cached entries
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
        debug!("DNS cache cleared");
    }

    /// Get cache size
    pub async fn size(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Get cache statistics
    pub fn stats(&self) -> DnsCacheStats {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        DnsCacheStats {
            hits,
            misses,
            hit_rate,
        }
    }
}

/// DNS cache statistics
#[derive(Debug, Clone)]
pub struct DnsCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_cache_resolve() {
        let cache = DnsCache::new();

        // First resolution should cache it
        let ip1 = cache.resolve("localhost").await;
        assert!(ip1.is_some());

        // Second resolution should hit cache
        let ip2 = cache.resolve("localhost").await;
        assert!(ip2.is_some());
        assert_eq!(ip1, ip2);

        // Cache size should be 1
        assert_eq!(cache.size().await, 1);

        // Verify cache hit
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_dns_cache_clear() {
        let cache = DnsCache::new();

        cache.resolve("localhost").await;
        assert_eq!(cache.size().await, 1);

        cache.clear().await;
        assert_eq!(cache.size().await, 0);
    }

    #[tokio::test]
    async fn test_dns_cache_stats() {
        let cache = DnsCache::new();

        // Initial stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);

        // First lookup
        cache.resolve("localhost").await;
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);

        // Second lookup (cache hit)
        cache.resolve("localhost").await;
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert!(stats.hit_rate > 0.0);
    }
}
