// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::{Context, Result};
use deadpool_redis::{Config, Pool, Runtime};
use tracing::{debug, info};

use crate::types::{ScanJob, ScanProgress, ScanResults};

#[derive(Clone)]
pub struct RedisQueue {
    pool: Pool,
}

impl RedisQueue {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let cfg = Config::from_url(redis_url);
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .context("Failed to create Redis pool")?;

        // Test connection
        let mut conn = pool.get().await.context("Failed to get Redis connection")?;
        let _: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("Failed to ping Redis")?;

        Ok(Self { pool })
    }

    /// Pop a scan job from the queue (blocking with timeout)
    pub async fn pop_scan_job(&self, timeout_secs: u64) -> Result<Option<ScanJob>> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;

        // BRPOP scan:queue timeout
        let result: Option<(String, String)> = deadpool_redis::redis::cmd("BRPOP")
            .arg("scan:queue")
            .arg(timeout_secs)
            .query_async(&mut conn)
            .await
            .context("Failed to pop from queue")?;

        match result {
            Some((_, job_json)) => {
                let job: ScanJob = serde_json::from_str(&job_json)
                    .context("Failed to deserialize scan job")?;
                debug!("Popped scan job: {}", job.scan_id);
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Update scan status
    pub async fn update_scan_status(&self, scan_id: String, status: String) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("scan:{}:status", scan_id);

        deadpool_redis::redis::cmd("SET")
            .arg(&key)
            .arg(&status)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to update scan status")?;

        // Set expiry (24 hours)
        deadpool_redis::redis::cmd("EXPIRE")
            .arg(&key)
            .arg(86400)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to set expiry")?;

        debug!("Updated scan {} status to {}", scan_id, status);
        Ok(())
    }

    /// Publish scan progress
    pub async fn publish_progress(&self, progress: &ScanProgress) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let channel = format!("scan:{}:progress", progress.scan_id);
        let message = serde_json::to_string(progress)
            .context("Failed to serialize progress")?;

        deadpool_redis::redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(message)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to publish progress")?;

        Ok(())
    }

    /// Store scan results
    pub async fn store_scan_results(&self, scan_id: String, results: &ScanResults) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("scan:{}:results", scan_id);
        let results_json = serde_json::to_string(results)
            .context("Failed to serialize scan results")?;

        deadpool_redis::redis::cmd("SET")
            .arg(&key)
            .arg(results_json)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to store scan results")?;

        // Set expiry (7 days)
        deadpool_redis::redis::cmd("EXPIRE")
            .arg(&key)
            .arg(604800)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to set expiry")?;

        info!(
            "Stored results for scan {} ({} vulnerabilities)",
            scan_id,
            results.vulnerabilities.len()
        );
        Ok(())
    }

    /// Store scan error
    pub async fn store_scan_error(&self, scan_id: String, error: String) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("scan:{}:error", scan_id);

        deadpool_redis::redis::cmd("SET")
            .arg(&key)
            .arg(&error)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to store scan error")?;

        // Set expiry (24 hours)
        deadpool_redis::redis::cmd("EXPIRE")
            .arg(&key)
            .arg(86400)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to set expiry")?;

        Ok(())
    }

    /// Increment test counter
    pub async fn increment_tests(&self, scan_id: String, count: u64) -> Result<()> {
        let mut conn = self.pool.get().await.context("Failed to get Redis connection")?;
        let key = format!("scan:{}:tests", scan_id);

        deadpool_redis::redis::cmd("INCRBY")
            .arg(&key)
            .arg(count)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to increment test counter")?;

        // Set expiry (24 hours)
        deadpool_redis::redis::cmd("EXPIRE")
            .arg(&key)
            .arg(86400)
            .query_async::<()>(&mut conn)
            .await
            .context("Failed to set expiry")?;

        Ok(())
    }
}
