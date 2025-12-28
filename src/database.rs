// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - PostgreSQL Database Layer
 * High-performance batch operations with connection pooling
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */

use anyhow::{Context, Result};
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;
use tracing::{debug, info};
use std::time::Instant;

use crate::types::ScanResults;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL
    pub database_url: String,

    /// Maximum pool size (number of connections)
    pub pool_size: usize,

    /// Batch size for bulk inserts
    pub batch_size: usize,

    /// Enable database writes
    pub enabled: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://lonkero:lonkero@localhost:5432/lonkero".to_string(),
            pool_size: 20,
            batch_size: 250,
            enabled: false,
        }
    }
}

/// PostgreSQL database client with connection pooling
pub struct DatabaseClient {
    pool: Pool,
    config: DatabaseConfig,
}

// Safety: Pool from deadpool_postgres is Send + Sync, and DatabaseConfig is Clone
unsafe impl Send for DatabaseClient {}
unsafe impl Sync for DatabaseClient {}

impl DatabaseClient {
    /// Create a new database client with connection pool
    pub async fn new(config: DatabaseConfig) -> Result<Self> {
        if !config.enabled {
            info!("[WARNING]  PostgreSQL disabled - using Redis only");
            // Return a dummy pool that won't be used
            let mut pg_config = Config::new();
            pg_config.url = Some(config.database_url.clone());
            pg_config.manager = Some(ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            });
            pg_config.pool = Some(deadpool_postgres::PoolConfig::new(1));

            let pool = pg_config
                .create_pool(Some(Runtime::Tokio1), NoTls)
                .context("Failed to create PostgreSQL pool")?;

            return Ok(Self {
                pool,
                config,
            });
        }

        // Parse connection URL
        let mut pg_config = Config::new();
        pg_config.url = Some(config.database_url.clone());

        // Configure connection pool
        pg_config.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });

        pg_config.pool = Some(deadpool_postgres::PoolConfig::new(config.pool_size));

        // Create pool
        let pool = pg_config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .context("Failed to create PostgreSQL pool")?;

        // Test connection
        let client = pool
            .get()
            .await
            .context("Failed to get connection from pool")?;

        client
            .query("SELECT 1", &[])
            .await
            .context("Failed to test database connection")?;

        info!(
            "[SUCCESS] PostgreSQL connected: pool_size={}, batch_size={}",
            config.pool_size, config.batch_size
        );

        Ok(Self {
            pool,
            config,
        })
    }

    /// Initialize database schema
    pub async fn init_schema(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let client = self.pool.get().await?;

        // Create scans table
        client
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS scans (
                    id SERIAL PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    tests_run BIGINT DEFAULT 0,
                    vulnerabilities_count INT DEFAULT 0,
                    status VARCHAR(50) DEFAULT 'PENDING',
                    started_at TIMESTAMP WITH TIME ZONE,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    duration_seconds DOUBLE PRECISION,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
                "#,
                &[],
            )
            .await
            .context("Failed to create scans table")?;

        // Create vulnerabilities table
        client
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    vuln_id VARCHAR(255) UNIQUE NOT NULL,
                    scan_id VARCHAR(255) NOT NULL,
                    vuln_type VARCHAR(255) NOT NULL,
                    severity VARCHAR(50) NOT NULL,
                    confidence VARCHAR(50) NOT NULL,
                    category VARCHAR(100) NOT NULL,
                    url TEXT NOT NULL,
                    parameter VARCHAR(255),
                    payload TEXT,
                    description TEXT,
                    evidence TEXT,
                    cwe VARCHAR(50),
                    cvss DOUBLE PRECISION,
                    verified BOOLEAN DEFAULT false,
                    false_positive BOOLEAN DEFAULT false,
                    remediation TEXT,
                    discovered_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
                "#,
                &[],
            )
            .await
            .context("Failed to create vulnerabilities table")?;

        // Create indexes for better query performance
        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_vulns_url ON vulnerabilities(url)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)",
                &[],
            )
            .await?;

        client
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_vulns_discovered_at ON vulnerabilities(discovered_at)",
                &[],
            )
            .await?;

        info!("[SUCCESS] Database schema initialized with optimized indexes");

        Ok(())
    }

    /// Store scan results in batch with optimized bulk insert
    pub async fn store_scan_results(&self, results: &ScanResults) -> Result<()> {
        if !self.config.enabled {
            debug!("PostgreSQL disabled, skipping store_scan_results");
            return Ok(());
        }

        let start = Instant::now();
        let mut client = self.pool.get().await?;
        let transaction = client.transaction().await?;

        // Insert scan record using prepared statement
        transaction
            .execute(
                r#"
                INSERT INTO scans (scan_id, target, tests_run, vulnerabilities_count, status, started_at, completed_at, duration_seconds)
                VALUES ($1, $2, $3, $4, 'COMPLETED', $5, $6, $7)
                ON CONFLICT (scan_id) DO UPDATE SET
                    tests_run = EXCLUDED.tests_run,
                    vulnerabilities_count = EXCLUDED.vulnerabilities_count,
                    status = EXCLUDED.status,
                    completed_at = EXCLUDED.completed_at,
                    duration_seconds = EXCLUDED.duration_seconds
                "#,
                &[
                    &results.scan_id,
                    &results.target,
                    &(results.tests_run as i64),
                    &(results.vulnerabilities.len() as i32),
                    &results.started_at,
                    &results.completed_at,
                    &results.duration_seconds,
                ],
            )
            .await
            .context("Failed to insert scan")?;

        // Optimized bulk insert using multi-row VALUES
        if !results.vulnerabilities.is_empty() {
            let batch_size = self.config.batch_size;
            let chunks: Vec<_> = results.vulnerabilities.chunks(batch_size).collect();

            for (chunk_idx, chunk) in chunks.iter().enumerate() {
                let chunk_start = Instant::now();

                debug!(
                    "Inserting vulnerability batch {}/{} ({} records)",
                    chunk_idx + 1,
                    chunks.len(),
                    chunk.len()
                );

                // Build multi-row INSERT statement
                let mut query = String::with_capacity(1024 + chunk.len() * 512);
                query.push_str(
                    r#"INSERT INTO vulnerabilities (
                        vuln_id, scan_id, vuln_type, severity, confidence, category,
                        url, parameter, payload, description, evidence, cwe, cvss,
                        verified, false_positive, remediation, discovered_at
                    ) VALUES "#
                );

                let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::with_capacity(chunk.len() * 17);
                let mut severity_strs = Vec::with_capacity(chunk.len());
                let mut confidence_strs = Vec::with_capacity(chunk.len());

                for (i, vuln) in chunk.iter().enumerate() {
                    if i > 0 {
                        query.push_str(", ");
                    }

                    let base = i * 17;
                    query.push_str(&format!(
                        "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                        base + 1, base + 2, base + 3, base + 4, base + 5, base + 6,
                        base + 7, base + 8, base + 9, base + 10, base + 11, base + 12,
                        base + 13, base + 14, base + 15, base + 16, base + 17
                    ));

                    severity_strs.push(format!("{:?}", vuln.severity));
                    confidence_strs.push(format!("{:?}", vuln.confidence));
                }

                query.push_str(" ON CONFLICT (vuln_id) DO NOTHING");

                // Collect parameters
                for (i, vuln) in chunk.iter().enumerate() {
                    params.push(&vuln.id);
                    params.push(&results.scan_id);
                    params.push(&vuln.vuln_type);
                    params.push(&severity_strs[i]);
                    params.push(&confidence_strs[i]);
                    params.push(&vuln.category);
                    params.push(&vuln.url);
                    params.push(&vuln.parameter);
                    params.push(&vuln.payload);
                    params.push(&vuln.description);
                    params.push(&vuln.evidence);
                    params.push(&vuln.cwe);
                    params.push(&vuln.cvss);
                    params.push(&vuln.verified);
                    params.push(&vuln.false_positive);
                    params.push(&vuln.remediation);
                    params.push(&vuln.discovered_at);
                }

                let rows_affected = transaction
                    .execute(&query, &params)
                    .await
                    .context("Failed to bulk insert vulnerabilities")?;

                debug!(
                    "Bulk inserted {} vulnerabilities in batch {} ({:.2}ms)",
                    rows_affected,
                    chunk_idx + 1,
                    chunk_start.elapsed().as_secs_f64() * 1000.0
                );
            }
        }

        transaction.commit().await?;

        let elapsed = start.elapsed();
        info!(
            "[SUCCESS] Stored scan {} with {} vulnerabilities to PostgreSQL in {:.2}ms",
            results.scan_id,
            results.vulnerabilities.len(),
            elapsed.as_secs_f64() * 1000.0
        );

        Ok(())
    }

    /// Get connection pool stats
    pub fn get_pool_stats(&self) -> (usize, usize) {
        let status = self.pool.status();
        (status.size, status.available)
    }
}

/// Type alias for backward compatibility
pub type Database = DatabaseClient;
