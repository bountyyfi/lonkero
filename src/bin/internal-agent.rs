// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero Internal Network Agent
 * Lightweight agent for scanning internal networks
 *
 * Features:
 * - Deploys behind firewalls
 * - Mutual TLS authentication
 * - Heartbeat monitoring
 * - Auto-update capability
 * - Resource-constrained operation
 *
 * (c) 2026 Bountyy Oy
 */
use anyhow::Result;
use clap::Parser;
use lonkero_scanner::agent::{AgentConfig, InternalAgent};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Lonkero Internal Network Agent
#[derive(Parser)]
#[command(name = "lonkero-agent")]
#[command(author = "Bountyy Oy <info@bountyy.fi>")]
#[command(version = "1.0.0")]
#[command(about = "Internal network scanning agent for Lonkero")]
struct Cli {
    /// Agent configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Server URL to connect to
    #[arg(short, long, default_value = "https://localhost:8443")]
    server: String,

    /// Agent name/identifier
    #[arg(short, long, default_value = "internal-agent")]
    name: String,

    /// Network segment identifier
    #[arg(short = 'S', long, default_value = "default")]
    segment: String,

    /// TLS client certificate path
    #[arg(long, default_value = "/etc/lonkero/agent-cert.pem")]
    tls_cert: PathBuf,

    /// TLS client key path
    #[arg(long, default_value = "/etc/lonkero/agent-key.pem")]
    tls_key: PathBuf,

    /// TLS CA certificate path
    #[arg(long, default_value = "/etc/lonkero/ca-cert.pem")]
    tls_ca: PathBuf,

    /// Maximum CPU usage percent
    #[arg(long, default_value = "50")]
    max_cpu: u8,

    /// Maximum memory usage in MB
    #[arg(long, default_value = "512")]
    max_memory: u64,

    /// Maximum concurrent scans
    #[arg(long, default_value = "5")]
    max_scans: usize,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "30")]
    heartbeat: u64,

    /// Enable auto-update
    #[arg(long)]
    auto_update: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Lonkero Internal Agent v1.0.0");
    info!("Agent name: {}", cli.name);
    info!("Network segment: {}", cli.segment);
    info!("Server: {}", cli.server);

    // Build agent configuration
    let config = AgentConfig {
        agent_id: uuid::Uuid::new_v4().to_string(),
        agent_name: cli.name,
        server_url: cli.server,
        network_segment: cli.segment,
        tls_cert_path: cli.tls_cert.to_string_lossy().to_string(),
        tls_key_path: cli.tls_key.to_string_lossy().to_string(),
        tls_ca_path: cli.tls_ca.to_string_lossy().to_string(),
        max_cpu_percent: cli.max_cpu,
        max_memory_mb: cli.max_memory,
        max_concurrent_scans: cli.max_scans,
        heartbeat_interval_secs: cli.heartbeat,
        auto_update_enabled: cli.auto_update,
        update_check_interval_secs: 3600,
    };

    info!("Configuration:");
    info!("  Max CPU: {}%", config.max_cpu_percent);
    info!("  Max Memory: {} MB", config.max_memory_mb);
    info!("  Max Concurrent Scans: {}", config.max_concurrent_scans);
    info!("  Heartbeat Interval: {}s", config.heartbeat_interval_secs);
    info!("  Auto-update: {}", config.auto_update_enabled);

    // Create agent instance
    let agent = match InternalAgent::new(config) {
        Ok(agent) => agent,
        Err(e) => {
            error!("Failed to create agent: {}", e);
            error!("Make sure TLS certificates are properly configured");
            std::process::exit(1);
        }
    };

    // Register with server
    info!("Registering with server...");
    if let Err(e) = agent.register().await {
        error!("Failed to register with server: {}", e);
        error!("Check server URL and TLS configuration");
        std::process::exit(1);
    }
    info!("Agent registered successfully");

    // Setup signal handler for graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    // Run agent with graceful shutdown
    tokio::select! {
        result = agent.run() => {
            if let Err(e) = result {
                error!("Agent error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
            info!("Agent shutting down...");
        }
    }

    info!("Lonkero Agent stopped");
    Ok(())
}
