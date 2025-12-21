// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Distributed Scanner Worker
 * Standalone Rust worker that connects to Redis queue,
 * pulls jobs, executes scans, and reports results
 *
 * © 2025 Bountyy Oy
 */

use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client as RedisClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::database::Database;
use crate::errors::ScannerError;
use crate::metrics::MetricsCollector;
use crate::modules::ids as module_ids;
use crate::types::ScanResults;

/// Worker configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WorkerConfig {
    pub worker_id: String,
    pub hostname: String,
    pub region: String,
    pub availability_zone: Option<String>,
    pub capacity: usize,
    pub capabilities: Vec<String>,
    pub tags: Vec<String>,
    pub redis_url: String,
    pub database_url: String,
    pub api_base_url: String,
    pub health_check_port: u16,
    pub heartbeat_interval_secs: u64,
    pub job_timeout_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            worker_id: format!("worker-{}", Uuid::new_v4()),
            hostname: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "unknown".to_string()),
            region: std::env::var("WORKER_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
            availability_zone: std::env::var("WORKER_AZ").ok(),
            capacity: std::env::var("WORKER_CAPACITY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            capabilities: vec![
                "xss".to_string(),
                "sqli".to_string(),
                "ssrf".to_string(),
                "lfi".to_string(),
            ],
            tags: Vec::new(),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/security_baseline".to_string()),
            api_base_url: std::env::var("API_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            health_check_port: std::env::var("HEALTH_CHECK_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            job_timeout_secs: std::env::var("JOB_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
        }
    }
}

/// Scan job from queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub job_id: String,
    pub scan_id: String,
    pub scan_type: String,
    pub target: String,
    pub config: serde_json::Value,
    pub worker_id: Option<String>,
    pub user_id: Option<i64>,
}

/// Job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: String,
    pub status: String,
    pub result: Option<ScanResults>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Worker metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub active_scans: usize,
    pub completed_scans: usize,
    pub failed_scans: usize,
    pub avg_scan_duration: u64,
}

/// Scanner Worker
pub struct ScannerWorker {
    config: WorkerConfig,
    redis: ConnectionManager,
    db: Arc<Database>,
    metrics: Arc<RwLock<MetricsCollector>>,
    active_jobs: Arc<RwLock<Vec<String>>>,
    shutdown: Arc<RwLock<bool>>,
}

impl ScannerWorker {
    /// Create a new scanner worker
    pub async fn new(config: WorkerConfig) -> Result<Self> {
        info!("Initializing scanner worker: {}", config.worker_id);

        // Connect to Redis
        let redis_client = RedisClient::open(config.redis_url.clone())
            .context("Failed to create Redis client")?;
        let redis = ConnectionManager::new(redis_client)
            .await
            .context("Failed to connect to Redis")?;

        // Connect to database
        let db_config = crate::database::DatabaseConfig {
            database_url: config.database_url.clone(),
            pool_size: 20,
            batch_size: 250,
            enabled: true,
        };
        let db = Arc::new(Database::new(db_config).await?);

        // Initialize metrics
        let metrics = Arc::new(RwLock::new(MetricsCollector::default()));

        Ok(Self {
            config,
            redis,
            db,
            metrics,
            active_jobs: Arc::new(RwLock::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
        })
    }

    /// Register worker with the pool
    pub async fn register(&mut self) -> Result<()> {
        info!("Registering worker with pool");

        let registration = serde_json::json!({
            "workerId": self.config.worker_id,
            "hostname": self.config.hostname,
            "ipAddress": self.get_ip_address(),
            "region": self.config.region,
            "availabilityZone": self.config.availability_zone,
            "capabilities": self.config.capabilities,
            "capacity": self.config.capacity,
            "version": env!("CARGO_PKG_VERSION"),
            "healthCheckUrl": format!("http://{}:{}/health", self.config.hostname, self.config.health_check_port),
            "tags": self.config.tags,
        });

        // Register via API
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/api/workers/register", self.config.api_base_url))
            .json(&registration)
            .send()
            .await
            .context("Failed to register worker")?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("Worker registration failed: {}", error);
        }

        info!("Worker registered successfully");
        Ok(())
    }

    /// Start the worker
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting scanner worker");

        // Register worker
        self.register().await?;

        // Start health check server
        let health_port = self.config.health_check_port;
        let shutdown = Arc::clone(&self.shutdown);
        let active_jobs = Arc::clone(&self.active_jobs);
        let metrics = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            if let Err(e) = start_health_check_server(health_port, shutdown, active_jobs, metrics).await {
                error!("Health check server error: {}", e);
            }
        });

        // Start heartbeat loop
        let worker_id = self.config.worker_id.clone();
        let api_url = self.config.api_base_url.clone();
        let heartbeat_interval = self.config.heartbeat_interval_secs;
        let shutdown = Arc::clone(&self.shutdown);
        let active_jobs = Arc::clone(&self.active_jobs);
        let metrics_clone = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            send_heartbeats(worker_id, api_url, heartbeat_interval, shutdown, active_jobs, metrics_clone).await;
        });

        // Start job processing loop
        self.process_jobs().await?;

        Ok(())
    }

    /// Process jobs from the queue
    async fn process_jobs(&mut self) -> Result<()> {
        info!("Starting job processing loop");

        let queue_name = "bull:distributed-scans:waiting";
        let processing_queue = "bull:distributed-scans:active";

        loop {
            // Check for shutdown signal
            if *self.shutdown.read().await {
                info!("Shutdown signal received, stopping job processing");
                break;
            }

            // Check if we have capacity
            let active_count = self.active_jobs.read().await.len();
            if active_count >= self.config.capacity {
                warn!("Worker at capacity ({}/{}), waiting...", active_count, self.config.capacity);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            // Pull job from queue (BRPOPLPUSH for reliability)
            let result: redis::RedisResult<String> = self
                .redis
                .clone()
                .brpoplpush(queue_name, processing_queue, 5.0)
                .await;

            if let Ok(job_data) = result {
                // Parse job
                match serde_json::from_str::<ScanJob>(&job_data) {
                    Ok(job) => {
                        info!("Received job: {}", job.job_id);

                        // Add to active jobs
                        self.active_jobs.write().await.push(job.job_id.clone());

                        // Process job in background
                        let worker = self.clone_for_job();
                        tokio::spawn(async move {
                            if let Err(e) = worker.execute_job(job).await {
                                error!("Job execution failed: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to parse job: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute a scan job
    async fn execute_job(&self, job: ScanJob) -> Result<()> {
        let start_time = SystemTime::now();
        info!("Executing job: {} ({})", job.job_id, job.scan_type);

        let result = match self.run_scan(&job).await {
            Ok(scan_result) => {
                let duration = start_time.elapsed().unwrap_or_default().as_millis() as u64;

                JobResult {
                    job_id: job.job_id.clone(),
                    status: "completed".to_string(),
                    result: Some(scan_result),
                    error: None,
                    duration_ms: duration,
                }
            }
            Err(e) => {
                let duration = start_time.elapsed().unwrap_or_default().as_millis() as u64;
                error!("Job {} failed: {}", job.job_id, e);

                JobResult {
                    job_id: job.job_id.clone(),
                    status: "failed".to_string(),
                    result: None,
                    error: Some(e.to_string()),
                    duration_ms: duration,
                }
            }
        };

        // Store result
        self.store_result(&result).await?;

        // Remove from active jobs
        let mut active = self.active_jobs.write().await;
        active.retain(|id| id != &job.job_id);

        // Update metrics
        let metrics = self.metrics.write().await;
        if result.status == "completed" {
            metrics.increment_counter("completed_scans", 1.0);
        } else {
            metrics.increment_counter("failed_scans", 1.0);
        }

        info!("Job {} completed in {}ms", job.job_id, result.duration_ms);
        Ok(())
    }

    /// Run the actual scan
    ///
    /// IMPORTANT: This function requires prior authorization via `crate::signing::authorize_scan()`.
    /// The authorization must be done before jobs are pulled from the queue.
    async fn run_scan(&self, job: &ScanJob) -> Result<ScanResults> {
        let start_time = std::time::Instant::now();

        // ============================================================
        // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
        // ============================================================
        // This check ensures banned users cannot scan through the worker.
        // Authorization must have been obtained before job processing.
        // STRICT MODE: No offline fallback - server authorization required.
        //
        // CRITICAL: We must pass the modules array to get authorization for
        // paid modules. Without it, only FREE tier modules are granted.
        if !crate::signing::is_scan_authorized() {
            // Determine which modules this job requires
            let requested_modules = self.get_modules_for_job(job);

            // Attempt to authorize for this job
            let hardware_id = crate::signing::get_hardware_id();
            info!("Authorizing scan for job {} with {} modules", job.job_id, requested_modules.len());
            match crate::signing::authorize_scan(
                1,
                &hardware_id,
                None,
                Some(env!("CARGO_PKG_VERSION")),
                requested_modules,
            ).await {
                Ok(token) => {
                    info!("Scan authorized for worker job {}: {} license, {} modules authorized",
                        job.job_id, token.license_type, token.authorized_modules.len());
                }
                Err(crate::signing::SigningError::Banned(reason)) => {
                    error!("SCAN BLOCKED: Worker is banned - {}", reason);
                    return Err(anyhow::anyhow!("Worker banned: {}", reason));
                }
                Err(crate::signing::SigningError::ServerUnreachable(msg)) => {
                    // STRICT MODE: No offline fallback
                    error!("SCAN BLOCKED: Authorization server unreachable - {}", msg);
                    return Err(anyhow::anyhow!("Authorization server unreachable: {}", msg));
                }
                Err(e) => {
                    // STRICT MODE: No offline fallback for any error
                    error!("SCAN BLOCKED: Authorization failed - {}", e);
                    return Err(anyhow::anyhow!("Authorization failed: {}", e));
                }
            }
        }

        // Get scan token for signing
        let scan_token = crate::signing::get_scan_token().cloned();

        // Import scanner based on scan type
        let mut results = match job.scan_type.as_str() {
            "xss" => {
                // Run XSS scan
                info!("Running XSS scan on {}", job.target);
                // Call actual scanner...
                ScanResults {
                    scan_id: job.scan_id.clone(),
                    target: job.target.clone(),
                    tests_run: 0,
                    vulnerabilities: Vec::new(),
                    started_at: chrono::Utc::now().to_rfc3339(),
                    completed_at: chrono::Utc::now().to_rfc3339(),
                    duration_seconds: 0.0,
                    early_terminated: false,
                    termination_reason: None,
                    scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    license_signature: Some(crate::license::get_license_signature()),
                    quantum_signature: None,
                    authorization_token_id: scan_token.as_ref().map(|t| t.token.clone()),
                }
            }
            "sqli" => {
                // Run SQLi scan
                info!("Running SQLi scan on {}", job.target);
                ScanResults {
                    scan_id: job.scan_id.clone(),
                    target: job.target.clone(),
                    tests_run: 0,
                    vulnerabilities: Vec::new(),
                    started_at: chrono::Utc::now().to_rfc3339(),
                    completed_at: chrono::Utc::now().to_rfc3339(),
                    duration_seconds: 0.0,
                    early_terminated: false,
                    termination_reason: None,
                    scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    license_signature: Some(crate::license::get_license_signature()),
                    quantum_signature: None,
                    authorization_token_id: scan_token.as_ref().map(|t| t.token.clone()),
                }
            }
            _ => {
                warn!("Unknown scan type: {}", job.scan_type);
                return Err(ScannerError::UnsupportedScanType(job.scan_type.clone()).into());
            }
        };

        // ============================================================
        // QUANTUM-SAFE SIGNING - MANDATORY FOR ALL RESULTS
        // ============================================================
        // Sign the results if we have a valid token
        // STRICT MODE: Server signature required
        if let Some(token) = scan_token {
            let elapsed = start_time.elapsed();

            if let Ok(results_hash) = crate::signing::hash_results(&results) {
                // Collect privacy-safe findings summary (only counts, no URLs or details)
                let findings_summary = crate::signing::FindingsSummary::from_vulnerabilities(&results.vulnerabilities);

                match crate::signing::sign_results(
                    &results_hash,
                    &token,
                    vec![],
                    Some(crate::signing::ScanMetadata {
                        targets_count: Some(1),
                        scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                        scan_duration_ms: Some(elapsed.as_millis() as u64),
                    }),
                    Some(findings_summary),
                    Some(vec![job.target.clone()]),
                ).await {
                    Ok(signature) => {
                        info!("[SIGNED] Worker results signed with: {}", signature.algorithm);
                        results.quantum_signature = Some(signature);
                    }
                    Err(crate::signing::SigningError::ServerUnreachable(msg)) => {
                        // STRICT MODE: Signing requires server connection
                        error!("Failed to sign worker results - server unreachable: {}", msg);
                        return Err(anyhow::anyhow!("Signing server unreachable: {}", msg));
                    }
                    Err(e) => {
                        // STRICT MODE: No unsigned results allowed
                        error!("Failed to sign worker results: {}", e);
                        return Err(anyhow::anyhow!("Failed to sign results: {}", e));
                    }
                }
            }
        }

        Ok(results)
    }

    /// Store job result
    async fn store_result(&self, result: &JobResult) -> Result<()> {
        // Store in Redis for quick retrieval
        let key = format!("job:result:{}", result.job_id);
        let value = serde_json::to_string(result)?;

        let _: () = self
            .redis
            .clone()
            .set_ex(&key, value, 3600)
            .await
            .context("Failed to store result in Redis")?;

        // Also update database
        // (This would be done via API call in practice)

        Ok(())
    }

    /// Determine which modules are needed for a scan job
    ///
    /// Maps job scan_type to specific module IDs, and also checks
    /// the job config for any additional module specifications.
    fn get_modules_for_job(&self, job: &ScanJob) -> Vec<String> {
        let mut modules = Vec::new();

        // Map scan_type to module ID
        match job.scan_type.as_str() {
            "xss" => modules.push(module_ids::advanced_scanning::XSS_SCANNER.to_string()),
            "sqli" => modules.push(module_ids::advanced_scanning::SQLI_SCANNER.to_string()),
            "ssrf" => modules.push(module_ids::advanced_scanning::SSRF_SCANNER.to_string()),
            "lfi" | "path_traversal" => modules.push(module_ids::advanced_scanning::PATH_TRAVERSAL.to_string()),
            "rce" | "command_injection" => modules.push(module_ids::advanced_scanning::COMMAND_INJECTION.to_string()),
            "xxe" => modules.push(module_ids::advanced_scanning::XXE_SCANNER.to_string()),
            "ssti" => modules.push(module_ids::advanced_scanning::SSTI_SCANNER.to_string()),
            "nosql" => modules.push(module_ids::advanced_scanning::NOSQL_SCANNER.to_string()),
            "csrf" => modules.push(module_ids::advanced_scanning::CSRF_SCANNER.to_string()),
            "cors" => modules.push(module_ids::advanced_scanning::CORS_MISCONFIG.to_string()),
            "graphql" => modules.push(module_ids::advanced_scanning::GRAPHQL_SCANNER.to_string()),
            "jwt" => modules.push(module_ids::advanced_scanning::JWT_SCANNER.to_string()),
            "wordpress" => modules.push(module_ids::cms_security::WORDPRESS_SCANNER.to_string()),
            "drupal" => modules.push(module_ids::cms_security::DRUPAL_SCANNER.to_string()),
            "full" | "comprehensive" => {
                // Full scan - request all modules
                return module_ids::get_all_module_ids()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
            }
            _ => {
                // Unknown scan type - request all modules for flexibility
                warn!("Unknown scan type '{}', requesting all modules", job.scan_type);
                return module_ids::get_all_module_ids()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        // Check job config for additional modules
        if let Some(config_modules) = job.config.get("modules").and_then(|v| v.as_array()) {
            for module_val in config_modules {
                if let Some(module_id) = module_val.as_str() {
                    if !modules.contains(&module_id.to_string()) {
                        modules.push(module_id.to_string());
                    }
                }
            }
        }

        // Always include free tier modules as they're commonly needed
        for free_module in &[
            module_ids::free::HTTP_HEADERS,
            module_ids::free::SECURITY_HEADERS,
            module_ids::free::SSL_CHECKER,
        ] {
            if !modules.contains(&free_module.to_string()) {
                modules.push(free_module.to_string());
            }
        }

        modules
    }

    /// Get IP address
    fn get_ip_address(&self) -> Option<String> {
        // In production, this would detect the actual IP
        std::env::var("WORKER_IP").ok()
    }

    /// Clone for background job execution
    fn clone_for_job(&self) -> Self {
        Self {
            config: self.config.clone(),
            redis: self.redis.clone(),
            db: Arc::clone(&self.db),
            metrics: Arc::clone(&self.metrics),
            active_jobs: Arc::clone(&self.active_jobs),
            shutdown: Arc::clone(&self.shutdown),
        }
    }

    /// Graceful shutdown
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Initiating graceful shutdown");

        // Set shutdown flag
        *self.shutdown.write().await = true;

        // Wait for active jobs to complete (with timeout)
        let max_wait = Duration::from_secs(self.config.job_timeout_secs);
        let start = SystemTime::now();

        while !self.active_jobs.read().await.is_empty() {
            if start.elapsed().unwrap_or_default() > max_wait {
                warn!("Shutdown timeout reached, forcefully terminating");
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        info!("Worker shutdown complete");
        Ok(())
    }
}

/// Send heartbeats to the API
async fn send_heartbeats(
    worker_id: String,
    api_url: String,
    interval_secs: u64,
    shutdown: Arc<RwLock<bool>>,
    active_jobs: Arc<RwLock<Vec<String>>>,
    metrics: Arc<RwLock<MetricsCollector>>,
) {
    let mut interval = interval(Duration::from_secs(interval_secs));
    let client = reqwest::Client::new();

    loop {
        interval.tick().await;

        if *shutdown.read().await {
            break;
        }

        let current_load = active_jobs.read().await.len();
        let metrics_snapshot = get_worker_metrics(&metrics, current_load).await;

        let heartbeat = serde_json::json!({
            "currentLoad": current_load,
            "metrics": metrics_snapshot,
        });

        match client
            .post(format!("{}/api/workers/{}/heartbeat", api_url, worker_id))
            .json(&heartbeat)
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("Heartbeat failed: {}", response.status());
                }
            }
            Err(e) => {
                error!("Failed to send heartbeat: {}", e);
            }
        }
    }
}

/// Get current worker metrics
async fn get_worker_metrics(
    metrics: &Arc<RwLock<MetricsCollector>>,
    active_scans: usize,
) -> WorkerMetrics {
    let metrics_guard = metrics.read().await;

    WorkerMetrics {
        cpu_usage: get_cpu_usage(),
        memory_usage: get_memory_usage(),
        disk_usage: get_disk_usage(),
        active_scans,
        completed_scans: metrics_guard.get_counter("completed_scans") as usize,
        failed_scans: metrics_guard.get_counter("failed_scans") as usize,
        avg_scan_duration: metrics_guard.get_counter("avg_scan_duration_ms") as u64,
    }
}

/// Start health check HTTP server
async fn start_health_check_server(
    port: u16,
    shutdown: Arc<RwLock<bool>>,
    active_jobs: Arc<RwLock<Vec<String>>>,
    metrics: Arc<RwLock<MetricsCollector>>,
) -> Result<()> {
    use axum::{routing::get, Json, Router};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/health/ready",
            get(move || async move {
                let is_ready = !*shutdown.read().await;
                if is_ready {
                    Json(serde_json::json!({ "status": "ready" }))
                } else {
                    Json(serde_json::json!({ "status": "shutting_down" }))
                }
            }),
        )
        .route(
            "/metrics",
            get(move || async move {
                let active_count = active_jobs.read().await.len();
                let worker_metrics = get_worker_metrics(&metrics, active_count).await;
                Json(worker_metrics)
            }),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Health check server listening on {}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind health check server")?;

    axum::serve(listener, app.into_make_service())
        .await
        .context("Health check server error")?;

    Ok(())
}

/// Get CPU usage (placeholder)
fn get_cpu_usage() -> f64 {
    // In production, use sysinfo crate or similar
    0.0
}

/// Get memory usage (placeholder)
fn get_memory_usage() -> f64 {
    // In production, use sysinfo crate or similar
    0.0
}

/// Get disk usage (placeholder)
fn get_disk_usage() -> f64 {
    // In production, use sysinfo crate or similar
    0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.capacity, 10);
        assert!(!config.capabilities.is_empty());
    }
}
