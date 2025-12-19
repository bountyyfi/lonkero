// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

use lonkero_scanner::config::AppConfig;
use lonkero_scanner::database::{DatabaseClient, DatabaseConfig};
use lonkero_scanner::queue::RedisQueue;
use lonkero_scanner::scanners::ScanEngine;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Christmas colors: Red (\x1b[91m), Green (\x1b[92m), White (\x1b[97m), Bold (\x1b[1m), Reset (\x1b[0m)
    print!("\x1b[92m");
    println!("   __                __");
    println!("  / /   ____  ____  / /_____  _________");
    println!(" / /   / __ \\/ __ \\/ //_/ _ \\/ ___/ __ \\");
    print!("\x1b[91m");
    println!(" / /___/ /_/ / / / / ,< /  __/ /  / /_/ /");
    println!("/_____/\\____/_/ /_/_/|_|\\___/_/   \\____/");
    print!("\x1b[0m");
    println!();
    print!("\x1b[1m\x1b[97m");
    println!("        Enterprise Web Security Scanner");
    print!("\x1b[0m\x1b[92m");
    println!("         v2.0 - Happy Holidays - (c) 2025");
    print!("\x1b[0m");
    println!();

    // Christmas easter egg - 10% chance
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if seed % 10 == 0 {
        let messages = [
            "🎅 Ho ho ho! Checking your security list twice...",
            "🎄 May your scans be merry and your vulns be zero!",
            "❄️  All I want for Christmas is zero-day patches...",
            "🎁 Santa's checking for IDOR, XSS, and SQLi!",
            "⛄ Frosty found a CSRF! Time to patch it up!",
            "🔔 Jingle bells, SQL smells, XSS went away!",
            "🎅 Naughty or nice? Your security posture says...",
        ];
        let msg_idx = (seed / 10) % (messages.len() as u64);
        println!("\x1b[93m        {}\x1b[0m\n", messages[msg_idx as usize]);
    }

    info!("Lonkero Rust Scanner v1.0.0 - Starting");

    // Create optimized tokio runtime for enterprise-scale performance
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .thread_name("lonkero-worker")
        .thread_stack_size(3 * 1024 * 1024)
        .max_blocking_threads(512)
        .enable_all()
        .build()?;

    info!("[SUCCESS] Optimized tokio runtime initialized with {} worker threads", num_cpus::get());

    runtime.block_on(async_main())?;

    Ok(())
}

fn worker_loop(
    queue: Arc<RedisQueue>,
    engine: Arc<ScanEngine>,
    database: Arc<DatabaseClient>,
    worker_id: usize,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    async move {
        info!("Worker {} started", worker_id);
        loop {
            let q = queue.clone();
            let e = engine.clone();
            let d = database.clone();

            match process_next_job(q, e, d, worker_id).await {
                Ok(_) => {}
                Err(err) => {
                    let err_msg = err.to_string();
                    error!("Worker {} error: {}", worker_id, err_msg);
                }
            }

            // Small delay to prevent tight loop
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}

async fn async_main() -> Result<()> {
    // Compile-time Send assertions
    fn assert_send<T: Send>() {}
    assert_send::<Arc<RedisQueue>>();
    assert_send::<Arc<ScanEngine>>();
    assert_send::<Arc<DatabaseClient>>();

    // Load configuration
    let config = AppConfig::from_env()?;
    let num_workers = config.scanner.max_concurrency;
    info!("Configuration loaded: workers={}, redis={}", num_workers, config.redis.url);

    // Connect to Redis
    let queue = Arc::new(RedisQueue::new(&config.redis.url).await?);
    info!("[SUCCESS] Connected to Redis");

    // Connect to PostgreSQL (if enabled)
    let db_config = DatabaseConfig {
        database_url: config.database.url.clone(),
        pool_size: config.database.pool_size,
        batch_size: config.database.batch_size,
        enabled: config.database.enabled,
    };
    let database = Arc::new(DatabaseClient::new(db_config).await?);

    // Initialize database schema if enabled
    if config.database.enabled {
        database.init_schema().await?;
    }

    // Create scan engine
    let engine = Arc::new(ScanEngine::new(config.scanner.clone())?);
    info!("[SUCCESS] Scan engine initialized");

    // Spawn multiple worker threads
    info!("Spawning {} parallel workers", num_workers);
    let mut handles = vec![];

    for worker_id in 0..num_workers {
        let queue = Arc::clone(&queue);
        let engine = Arc::clone(&engine);
        let database = Arc::clone(&database);

        let handle = tokio::spawn(worker_loop(queue, engine, database, worker_id));

        handles.push(handle);
    }

    // Wait for all workers (runs forever)
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn process_next_job(
    queue: Arc<RedisQueue>,
    engine: Arc<ScanEngine>,
    database: Arc<DatabaseClient>,
    worker_id: usize,
) -> Result<()> {
    // Pop job from queue (blocking with timeout)
    let job = match queue.pop_scan_job(30).await? {
        Some(job) => Arc::new(job),  // Wrap in Arc for thread safety
        None => return Ok(()), // No job available, continue loop
    };

    // Clone scan_id to own it (fixes Send lifetime issue)
    let scan_id = job.scan_id.clone();
    let target = job.target.clone();

    info!("[Worker {}] Processing scan job: {} (target: {})", worker_id, scan_id, target);

    // Update status to RUNNING
    queue
        .update_scan_status(scan_id.clone(), "RUNNING".to_string())
        .await?;

    // Execute scan
    match engine.execute_scan(job.clone(), queue.clone()).await {
        Ok(results) => {
            info!(
                "[SUCCESS] [Worker {}] Scan {} completed: {} vulnerabilities found",
                worker_id,
                scan_id,
                results.vulnerabilities.len()
            );

            // Store results in Redis
            queue.store_scan_results(scan_id.clone(), &results).await?;

            // Store results in PostgreSQL (if enabled)
            if let Err(e) = database.store_scan_results(&results).await {
                error!("Failed to store results in PostgreSQL: {}", e);
                // Continue anyway - Redis has the results
            }

            // Update status to COMPLETED
            queue
                .update_scan_status(scan_id.clone(), "COMPLETED".to_string())
                .await?;
        }
        Err(e) => {
            let error_msg = e.to_string();
            error!("[ERROR] [Worker {}] Scan {} failed: {}", worker_id, scan_id, error_msg);

            // Update status to FAILED
            queue
                .update_scan_status(scan_id.clone(), "FAILED".to_string())
                .await?;

            // Store error message
            queue.store_scan_error(scan_id.clone(), error_msg).await?;
        }
    }

    Ok(())
}
