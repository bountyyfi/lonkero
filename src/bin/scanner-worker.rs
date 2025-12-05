// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Scanner Worker Binary
 * Standalone worker executable for distributed scanning
 *
 * © 2025 Bountyy Oy
 */

use anyhow::Result;
use lonkero_scanner::worker::{ScannerWorker, WorkerConfig};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Scanner Worker");

    // Load configuration
    let config = WorkerConfig::default();

    info!(
        "Worker configuration: region={}, capacity={}, capabilities={:?}",
        config.region, config.capacity, config.capabilities
    );

    // Create and start worker
    let mut worker = ScannerWorker::new(config).await?;

    // Setup signal handler for graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    // Run worker with graceful shutdown
    tokio::select! {
        result = worker.start() => {
            if let Err(e) = result {
                error!("Worker error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
            if let Err(e) = worker.shutdown().await {
                error!("Error during shutdown: {}", e);
            }
        }
    }

    info!("Scanner Worker stopped");
    Ok(())
}
