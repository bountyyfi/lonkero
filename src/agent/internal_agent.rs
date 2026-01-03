// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Internal Scanning Agent
 * Lightweight agent for deployment in internal networks
 *
 * Features:
 * - Self-contained Rust binary
 * - Mutual TLS authentication
 * - Secure communication with central server
 * - Local scan execution
 * - Result streaming
 * - Health monitoring
 * - Auto-update capability
 * - Resource usage limits
 *
 * © 2026 Bountyy Oy
 */
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};

// Config imports removed - using AgentConfig defined locally

/// Agent configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub agent_name: String,
    pub server_url: String,
    pub network_segment: String,

    // TLS mutual authentication
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_ca_path: String,

    // Resource limits
    pub max_cpu_percent: u8,
    pub max_memory_mb: u64,
    pub max_concurrent_scans: usize,

    // Heartbeat configuration
    pub heartbeat_interval_secs: u64,

    // Auto-update
    pub auto_update_enabled: bool,
    pub update_check_interval_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: uuid::Uuid::new_v4().to_string(),
            agent_name: String::from("internal-agent"),
            server_url: String::from("https://localhost:8443"),
            network_segment: String::from("default"),
            tls_cert_path: String::from("/etc/lonkero/agent-cert.pem"),
            tls_key_path: String::from("/etc/lonkero/agent-key.pem"),
            tls_ca_path: String::from("/etc/lonkero/ca-cert.pem"),
            max_cpu_percent: 50,
            max_memory_mb: 512,
            max_concurrent_scans: 5,
            heartbeat_interval_secs: 30,
            auto_update_enabled: true,
            update_check_interval_secs: 3600,
        }
    }
}

/// Scan task from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub scan_id: i32,
    pub scan_type: String,
    pub targets: Vec<String>,
    pub credential_ids: Vec<i32>,
    pub options: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Scan result to send back to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: i32,
    pub target: String,
    pub success: bool,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Agent health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_id: String,
    pub status: HealthStatus,
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub disk_usage_percent: f32,
    pub active_scans: usize,
    pub queued_scans: usize,
    pub network_latency_ms: Option<u64>,
    pub error_count: u64,
    pub last_error: Option<String>,
    pub uptime_secs: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Error,
}

/// Internal scanning agent
pub struct InternalAgent {
    config: AgentConfig,
    client: reqwest::Client,
    active_scans: Arc<RwLock<Vec<ScanTask>>>,
    scan_queue: Arc<RwLock<Vec<ScanTask>>>,
    error_count: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
    start_time: std::time::Instant,
}

impl InternalAgent {
    /// Create new agent instance
    pub fn new(config: AgentConfig) -> Result<Self> {
        info!("Initializing internal agent: {}", config.agent_name);

        // Load TLS certificates for mutual auth
        let client = Self::create_mtls_client(&config)?;

        Ok(Self {
            config,
            client,
            active_scans: Arc::new(RwLock::new(Vec::new())),
            scan_queue: Arc::new(RwLock::new(Vec::new())),
            error_count: Arc::new(RwLock::new(0)),
            last_error: Arc::new(RwLock::new(None)),
            start_time: std::time::Instant::now(),
        })
    }

    /// Create HTTP client with mutual TLS
    fn create_mtls_client(config: &AgentConfig) -> Result<reqwest::Client> {
        info!("Creating mutual TLS client");

        // Load client certificate
        let cert_pem =
            std::fs::read(&config.tls_cert_path).context("Failed to read client certificate")?;
        let key_pem =
            std::fs::read(&config.tls_key_path).context("Failed to read client private key")?;

        // Combine cert and key into single PEM buffer for reqwest::Identity::from_pem
        let mut combined_pem = cert_pem.clone();
        combined_pem.push(b'\n');
        combined_pem.extend_from_slice(&key_pem);

        let identity = reqwest::Identity::from_pem(&combined_pem)
            .context("Failed to create identity from certificate and key")?;

        // Load CA certificate
        let ca_pem = std::fs::read(&config.tls_ca_path).context("Failed to read CA certificate")?;
        let ca_cert =
            reqwest::Certificate::from_pem(&ca_pem).context("Failed to parse CA certificate")?;

        // Build client with mutual TLS
        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")?;

        info!("Mutual TLS client created successfully");
        Ok(client)
    }

    /// Register agent with server
    pub async fn register(&self) -> Result<()> {
        info!("Registering agent with server: {}", self.config.server_url);

        let registration_data = serde_json::json!({
            "agent_id": self.config.agent_id,
            "name": self.config.agent_name,
            "network_segment": self.config.network_segment,
            "version": env!("CARGO_PKG_VERSION"),
            "capabilities": {
                "network_discovery": true,
                "authenticated_scan": true,
                "vulnerability_scan": true,
                "patch_audit": true,
            },
            "resource_limits": {
                "max_cpu_percent": self.config.max_cpu_percent,
                "max_memory_mb": self.config.max_memory_mb,
                "max_concurrent_scans": self.config.max_concurrent_scans,
            }
        });

        let url = format!("{}/api/internal/agent/register", self.config.server_url);

        let response = self
            .client
            .post(&url)
            .json(&registration_data)
            .send()
            .await
            .context("Failed to send registration request")?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Registration failed: {}", error_text));
        }

        info!("Agent registered successfully");
        Ok(())
    }

    /// Run agent main loop
    pub async fn run(&self) -> Result<()> {
        info!("Starting agent main loop");

        // Start background tasks
        let heartbeat_handle = self.start_heartbeat_loop();
        let task_polling_handle = self.start_task_polling_loop();
        let update_check_handle = self.start_update_check_loop();

        // Wait for all tasks to complete (they run indefinitely)
        tokio::select! {
            result = heartbeat_handle => {
                error!("Heartbeat loop exited: {:?}", result);
            }
            result = task_polling_handle => {
                error!("Task polling loop exited: {:?}", result);
            }
            result = update_check_handle => {
                error!("Update check loop exited: {:?}", result);
            }
        }

        Ok(())
    }

    /// Start heartbeat loop
    fn start_heartbeat_loop(&self) -> tokio::task::JoinHandle<()> {
        let agent_id = self.config.agent_id.clone();
        let client = self.client.clone();
        let server_url = self.config.server_url.clone();
        let heartbeat_interval = self.config.heartbeat_interval_secs;
        let active_scans = Arc::clone(&self.active_scans);
        let scan_queue = Arc::clone(&self.scan_queue);
        let error_count = Arc::clone(&self.error_count);
        let last_error = Arc::clone(&self.last_error);
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(heartbeat_interval));

            loop {
                interval.tick().await;

                // Collect health metrics
                let health = Self::collect_health_metrics(
                    &agent_id,
                    &active_scans,
                    &scan_queue,
                    &error_count,
                    &last_error,
                    start_time,
                )
                .await;

                // Send heartbeat
                if let Err(e) = Self::send_heartbeat(&client, &server_url, &health).await {
                    error!("Failed to send heartbeat: {}", e);
                }
            }
        })
    }

    /// Start task polling loop
    fn start_task_polling_loop(&self) -> tokio::task::JoinHandle<()> {
        let agent_id = self.config.agent_id.clone();
        let client = self.client.clone();
        let server_url = self.config.server_url.clone();
        let scan_queue = Arc::clone(&self.scan_queue);
        let active_scans = Arc::clone(&self.active_scans);
        let error_count = Arc::clone(&self.error_count);
        let last_error = Arc::clone(&self.last_error);
        let max_concurrent = self.config.max_concurrent_scans;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Check if we can accept more scans
                let active_count = active_scans.read().await.len();
                if active_count >= max_concurrent {
                    continue;
                }

                // Poll for new tasks
                match Self::poll_for_tasks(&client, &server_url, &agent_id).await {
                    Ok(tasks) => {
                        if !tasks.is_empty() {
                            info!("Received {} new scan tasks", tasks.len());
                            let mut queue = scan_queue.write().await;
                            queue.extend(tasks);
                        }
                    }
                    Err(e) => {
                        error!("Failed to poll for tasks: {}", e);
                        *error_count.write().await += 1;
                        *last_error.write().await = Some(e.to_string());
                    }
                }

                // Process queued tasks
                Self::process_queued_tasks(
                    &scan_queue,
                    &active_scans,
                    &client,
                    &server_url,
                    &error_count,
                    &last_error,
                    max_concurrent,
                )
                .await;
            }
        })
    }

    /// Start update check loop
    fn start_update_check_loop(&self) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        let server_url = self.config.server_url.clone();
        let check_interval = self.config.update_check_interval_secs;
        let auto_update = self.config.auto_update_enabled;

        tokio::spawn(async move {
            if !auto_update {
                info!("Auto-update disabled, skipping update checks");
                // Sleep forever
                sleep(Duration::from_secs(u64::MAX)).await;
                return;
            }

            let mut interval = interval(Duration::from_secs(check_interval));

            loop {
                interval.tick().await;

                if let Err(e) = Self::check_for_updates(&client, &server_url).await {
                    warn!("Failed to check for updates: {}", e);
                }
            }
        })
    }

    /// Collect health metrics
    async fn collect_health_metrics(
        agent_id: &str,
        active_scans: &Arc<RwLock<Vec<ScanTask>>>,
        scan_queue: &Arc<RwLock<Vec<ScanTask>>>,
        error_count: &Arc<RwLock<u64>>,
        last_error: &Arc<RwLock<Option<String>>>,
        start_time: std::time::Instant,
    ) -> AgentHealth {
        // Get system metrics
        let (cpu_usage, memory_usage, disk_usage) = Self::get_system_metrics();

        let active_count = active_scans.read().await.len();
        let queued_count = scan_queue.read().await.len();
        let errors = *error_count.read().await;
        let last_err = last_error.read().await.clone();

        let status = if errors > 10 {
            HealthStatus::Error
        } else if cpu_usage > 80.0 || memory_usage > 450 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        AgentHealth {
            agent_id: agent_id.to_string(),
            status,
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            disk_usage_percent: disk_usage,
            active_scans: active_count,
            queued_scans: queued_count,
            network_latency_ms: None,
            error_count: errors,
            last_error: last_err,
            uptime_secs: start_time.elapsed().as_secs(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get system metrics
    fn get_system_metrics() -> (f32, u64, f32) {
        // Simplified metrics - in production, use a proper system metrics library
        (25.0, 128, 45.0)
    }

    /// Send heartbeat to server
    async fn send_heartbeat(
        client: &reqwest::Client,
        server_url: &str,
        health: &AgentHealth,
    ) -> Result<()> {
        let url = format!("{}/api/internal/agent/heartbeat", server_url);

        client
            .post(&url)
            .json(health)
            .send()
            .await
            .context("Failed to send heartbeat")?;

        Ok(())
    }

    /// Poll for new scan tasks
    async fn poll_for_tasks(
        client: &reqwest::Client,
        server_url: &str,
        agent_id: &str,
    ) -> Result<Vec<ScanTask>> {
        let url = format!("{}/api/internal/agent/{}/tasks", server_url, agent_id);

        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to poll for tasks")?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let tasks: Vec<ScanTask> = response
            .json()
            .await
            .context("Failed to parse tasks response")?;

        Ok(tasks)
    }

    /// Process queued tasks
    async fn process_queued_tasks(
        scan_queue: &Arc<RwLock<Vec<ScanTask>>>,
        active_scans: &Arc<RwLock<Vec<ScanTask>>>,
        client: &reqwest::Client,
        server_url: &str,
        error_count: &Arc<RwLock<u64>>,
        last_error: &Arc<RwLock<Option<String>>>,
        max_concurrent: usize,
    ) {
        let active_count = active_scans.read().await.len();
        if active_count >= max_concurrent {
            return;
        }

        let available_slots = max_concurrent - active_count;

        // Dequeue tasks
        let tasks_to_process = {
            let mut queue = scan_queue.write().await;
            let take_count = std::cmp::min(available_slots, queue.len());
            queue.drain(..take_count).collect::<Vec<_>>()
        };

        // Execute tasks
        for task in tasks_to_process {
            let task_clone = task.clone();
            let active_scans_clone = Arc::clone(active_scans);
            let client_clone = client.clone();
            let server_url_clone = server_url.to_string();
            let error_count_clone = Arc::clone(error_count);
            let last_error_clone = Arc::clone(last_error);

            // Add to active scans
            active_scans.write().await.push(task.clone());

            // Spawn task execution
            tokio::spawn(async move {
                if let Err(e) =
                    Self::execute_scan_task(&client_clone, &server_url_clone, &task_clone).await
                {
                    error!("Scan task failed: {}", e);
                    *error_count_clone.write().await += 1;
                    *last_error_clone.write().await = Some(e.to_string());
                }

                // Remove from active scans
                let mut active = active_scans_clone.write().await;
                active.retain(|t| t.scan_id != task_clone.scan_id);
            });
        }
    }

    /// Execute scan task
    async fn execute_scan_task(
        client: &reqwest::Client,
        server_url: &str,
        task: &ScanTask,
    ) -> Result<()> {
        info!(
            "Executing scan task: scan_id={}, type={}",
            task.scan_id, task.scan_type
        );

        let start_time = std::time::Instant::now();

        // Execute scan for each target
        for target in &task.targets {
            let result = match task.scan_type.as_str() {
                "network_discovery" => Self::execute_network_discovery(target, &task.options).await,
                "authenticated" => {
                    Self::execute_authenticated_scan(target, &task.credential_ids, &task.options)
                        .await
                }
                _ => Err(anyhow::anyhow!("Unknown scan type: {}", task.scan_type)),
            };

            let duration = start_time.elapsed().as_millis() as u64;

            let scan_result = match result {
                Ok(data) => ScanResults {
                    scan_id: task.scan_id,
                    target: target.clone(),
                    success: true,
                    data,
                    error: None,
                    duration_ms: duration,
                    timestamp: chrono::Utc::now(),
                },
                Err(e) => ScanResults {
                    scan_id: task.scan_id,
                    target: target.clone(),
                    success: false,
                    data: serde_json::json!({}),
                    error: Some(e.to_string()),
                    duration_ms: duration,
                    timestamp: chrono::Utc::now(),
                },
            };

            // Send result to server
            Self::send_scan_result(client, server_url, &scan_result).await?;
        }

        Ok(())
    }

    /// Execute network discovery scan
    async fn execute_network_discovery(
        target: &str,
        _options: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Call network discovery module
        info!("Running network discovery for {}", target);

        // Placeholder - actual implementation would call the network discovery scanner
        Ok(serde_json::json!({
            "ip_address": target,
            "hostname": "example-host",
            "open_ports": [80, 443],
            "services": ["http", "https"],
        }))
    }

    /// Execute authenticated scan
    async fn execute_authenticated_scan(
        target: &str,
        _credential_ids: &[i32],
        _options: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Call authenticated scanner module
        info!("Running authenticated scan for {}", target);

        // Placeholder - actual implementation would call the authenticated scanner
        Ok(serde_json::json!({
            "authenticated": true,
            "hostname": "example-host",
            "os_type": "linux",
            "patches_installed": [],
            "patches_missing": [],
        }))
    }

    /// Send scan result to server
    async fn send_scan_result(
        client: &reqwest::Client,
        server_url: &str,
        result: &ScanResults,
    ) -> Result<()> {
        let url = format!("{}/api/internal/agent/results", server_url);

        client
            .post(&url)
            .json(result)
            .send()
            .await
            .context("Failed to send scan result")?;

        info!(
            "Sent scan result for scan_id={}, target={}",
            result.scan_id, result.target
        );
        Ok(())
    }

    /// Check for updates
    async fn check_for_updates(client: &reqwest::Client, server_url: &str) -> Result<()> {
        let url = format!("{}/api/internal/agent/version", server_url);

        let response = client
            .get(&url)
            .send()
            .await
            .context("Failed to check for updates")?;

        let latest_version: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse version response")?;

        let current_version = env!("CARGO_PKG_VERSION");

        if let Some(latest) = latest_version.get("version").and_then(|v| v.as_str()) {
            if latest != current_version {
                info!(
                    "New version available: {} (current: {})",
                    latest, current_version
                );
                // In production, would download and apply update
            }
        }

        Ok(())
    }
}
