// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Lonkero - Enterprise Web Security Scanner
 * Standalone CLI for vulnerability assessment
 *
 * Features:
 * - 60+ vulnerability scanner modules
 * - Multiple output formats (JSON, HTML, PDF, SARIF, Markdown)
 * - Configurable scan profiles
 * - Multi-target support
 * - Subdomain enumeration
 * - Technology detection
 * - Cloud security scanning
 *
 * (c) 2025 Bountyy Oy
 */

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn, Level};

use std::collections::HashSet;

use lonkero_scanner::config::ScannerConfig;
use lonkero_scanner::detection_helpers::detect_technology;
use lonkero_scanner::http_client::HttpClient;
use lonkero_scanner::license::{self, LicenseStatus, LicenseType};
use lonkero_scanner::modules::ids as module_ids;
use lonkero_scanner::scanners::ScanEngine;
use lonkero_scanner::signing::{self, SigningError, ScanToken};
use lonkero_scanner::types::{ScanConfig, ScanJob, ScanMode, ScanResults};

/// Lonkero - Enterprise Web Security Scanner
#[derive(Parser)]
#[command(name = "lonkero")]
#[command(author = "Bountyy Oy <info@bountyy.fi>")]
#[command(version = "2.0.0")]
#[command(about = "Web scanner built for actual pentests. Fast, modular, Rust.", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable debug output
    #[arg(short, long, global = true)]
    debug: bool,

    /// Quiet mode - only show vulnerabilities
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// License key (or set LONKERO_LICENSE_KEY environment variable)
    #[arg(short = 'L', long, global = true, env = "LONKERO_LICENSE_KEY")]
    license_key: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target for vulnerabilities
    Scan {
        /// Target URL(s) to scan
        #[arg(required = true)]
        targets: Vec<String>,

        /// Scan mode: fast, normal, thorough, insane
        #[arg(short, long, default_value = "normal")]
        mode: ScanModeArg,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: json, html, pdf, sarif, markdown, csv, xlsx
        #[arg(short, long, default_value = "json")]
        format: OutputFormat,

        /// Enable subdomain enumeration
        #[arg(long)]
        subdomains: bool,

        /// Generate Google dork queries for reconnaissance (not enabled by default)
        #[arg(long)]
        dorks: bool,

        /// Enable web crawler (enabled by default to discover real parameters)
        #[arg(long, default_value = "true")]
        crawl: bool,

        /// Maximum crawl depth
        #[arg(long, default_value = "3")]
        max_depth: u32,

        /// Maximum concurrent requests
        #[arg(long, default_value = "50")]
        concurrency: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Custom User-Agent string
        #[arg(long)]
        user_agent: Option<String>,

        /// Authentication cookie
        #[arg(long)]
        cookie: Option<String>,

        /// Authentication bearer token
        #[arg(long)]
        token: Option<String>,

        /// HTTP Basic auth (user:pass)
        #[arg(long)]
        basic_auth: Option<String>,

        /// Auto-login username (requires --auth-password)
        #[arg(long)]
        auth_username: Option<String>,

        /// Auto-login password (requires --auth-username)
        #[arg(long)]
        auth_password: Option<String>,

        /// Custom login URL (for auto-login)
        #[arg(long)]
        auth_login_url: Option<String>,

        /// Custom headers (format: "Header: Value")
        #[arg(short = 'H', long)]
        header: Vec<String>,

        /// Skip specific scanner modules
        #[arg(long)]
        skip: Vec<String>,

        /// Only run specific scanner modules
        #[arg(long)]
        only: Vec<String>,

        /// Proxy URL (http://host:port)
        #[arg(long)]
        proxy: Option<String>,

        /// Disable TLS certificate verification
        #[arg(long)]
        insecure: bool,

        /// Rate limit (requests per second)
        #[arg(long, default_value = "100")]
        rate_limit: u32,

        /// Disable rate limiting entirely (use with caution!)
        #[arg(long)]
        no_rate_limit: bool,
    },

    /// List available scanner modules
    List {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,

        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Validate target URL(s)
    Validate {
        /// Target URL(s) to validate
        targets: Vec<String>,
    },

    /// Generate sample configuration file
    Init {
        /// Output path for config file
        #[arg(short, long, default_value = "lonkero.toml")]
        output: PathBuf,
    },

    /// Show scanner version and build info
    Version,

    /// Manage license
    License {
        #[command(subcommand)]
        action: LicenseAction,
    },
}

#[derive(Subcommand)]
enum LicenseAction {
    /// Activate a license key
    Activate {
        /// License key to activate
        key: String,
    },
    /// Show current license status
    Status,
    /// Deactivate the current license
    Deactivate,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ScanModeArg {
    Fast,
    Normal,
    Thorough,
    Insane,
}

impl From<ScanModeArg> for ScanMode {
    fn from(mode: ScanModeArg) -> Self {
        match mode {
            ScanModeArg::Fast => ScanMode::Fast,
            ScanModeArg::Normal => ScanMode::Normal,
            ScanModeArg::Thorough => ScanMode::Thorough,
            ScanModeArg::Insane => ScanMode::Insane,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputFormat {
    Json,
    Html,
    Pdf,
    Sarif,
    Markdown,
    Csv,
    Xlsx,
    Junit,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.debug {
        Level::DEBUG
    } else if cli.verbose {
        Level::INFO
    } else if cli.quiet {
        Level::ERROR
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    // Create async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .thread_name("lonkero-scanner")
        .enable_all()
        .build()?;

    runtime.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scan {
            targets,
            mode,
            output,
            format,
            subdomains,
            dorks,
            crawl,
            max_depth,
            concurrency,
            timeout,
            user_agent,
            cookie,
            token,
            basic_auth,
            auth_username,
            auth_password,
            auth_login_url,
            header,
            skip,
            only,
            proxy,
            insecure,
            rate_limit,
            no_rate_limit,
        } => {
            // Determine which modules to request authorization for
            // CRITICAL: The modules array is now REQUIRED for paid modules.
            // Without it, the server only grants FREE tier modules (8 modules).
            let requested_modules = determine_requested_modules(&skip, &only);

            // Verify license AND authorize scan before proceeding
            // Ban check happens during authorization - banned users are blocked here
            let (license_status, scan_token) = verify_license_before_scan(
                cli.license_key.as_deref(),
                targets.len(),
                requested_modules,
            ).await?;

            // Log authorized modules and check for denied modules
            info!("[Auth] {} modules authorized by server", scan_token.authorized_modules.len());

            // Defensive check: warn if any requested modules were denied
            let denied = scan_token.get_denied_modules(&determine_requested_modules(&skip, &only));
            if !denied.is_empty() {
                warn!("[Auth] {} modules were not authorized: {:?}",
                    denied.len(),
                    if denied.len() <= 5 { &denied[..] } else { &denied[..5] }
                );
            }

            run_scan(
                targets,
                mode.into(),
                output,
                format,
                subdomains,
                dorks,
                crawl,
                max_depth,
                concurrency,
                timeout,
                user_agent,
                cookie,
                token,
                basic_auth,
                auth_username,
                auth_password,
                auth_login_url,
                header,
                skip,
                only,
                proxy,
                insecure,
                rate_limit,
                no_rate_limit,
                license_status,
                scan_token,
            )
            .await
        }
        Commands::List { verbose, category } => list_scanners(verbose, category),
        Commands::Validate { targets } => validate_targets(targets).await,
        Commands::Init { output } => generate_config(output),
        Commands::Version => show_version(),
        Commands::License { action } => handle_license_command(action, cli.license_key.as_deref()).await,
    }
}

/// Determine which modules to request authorization for
///
/// If `only` is specified, only those modules are requested.
/// Otherwise, all modules are requested except those in `skip`.
///
/// WARNING: If the resulting list is empty, only FREE tier modules will be authorized.
fn determine_requested_modules(skip: &[String], only: &[String]) -> Vec<String> {
    let all_modules = module_ids::get_all_module_ids();

    let result: Vec<String> = if !only.is_empty() {
        // Only request specific modules
        let only_set: HashSet<&str> = only.iter().map(|s| s.as_str()).collect();
        all_modules
            .into_iter()
            .filter(|m| only_set.contains(*m))
            .map(|s| s.to_string())
            .collect()
    } else if !skip.is_empty() {
        // Request all modules except skipped ones
        let skip_set: HashSet<&str> = skip.iter().map(|s| s.as_str()).collect();
        all_modules
            .into_iter()
            .filter(|m| !skip_set.contains(*m))
            .map(|s| s.to_string())
            .collect()
    } else {
        // Request all modules
        all_modules.into_iter().map(|s| s.to_string()).collect()
    };

    // Warn if the filter resulted in an empty list
    if result.is_empty() && !only.is_empty() {
        warn!("[Auth] No modules matched --only filter {:?}. Only FREE tier modules will be authorized.", only);
    }

    result
}

/// Verify license and authorize scan before starting
///
/// This function performs two critical checks:
/// 1. License verification (killswitch, limits, commercial use)
/// 2. Scan authorization (ban check, token generation)
///
/// Both must pass for scanning to proceed. Banned users are
/// rejected at the authorization stage - they cannot scan.
///
/// # Arguments
/// * `license_key` - Optional license key for premium features
/// * `target_count` - Number of targets to scan
/// * `requested_modules` - List of module IDs to request authorization for
async fn verify_license_before_scan(
    license_key: Option<&str>,
    target_count: usize,
    requested_modules: Vec<String>,
) -> Result<(LicenseStatus, ScanToken)> {
    // Check if this appears to be commercial use (heuristic)
    let is_commercial = std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("JENKINS_URL").is_ok();

    // Step 1: Verify license
    let status = match license::verify_license_for_scan(license_key, target_count, is_commercial).await {
        Ok(status) => {
            license::print_license_info(&status);
            status
        }
        Err(e) => {
            error!("========================================================");
            error!("LICENSE VERIFICATION FAILED");
            error!("========================================================");
            error!("");
            error!("{}", e);
            error!("");
            error!("To obtain a license, visit: https://bountyy.fi");
            error!("For support, contact: info@bountyy.fi");
            error!("");
            error!("========================================================");
            return Err(e);
        }
    };

    // Step 2: Authorize scan (ban check happens here!)
    // This is where banned users are blocked from scanning.
    // CRITICAL: We now pass the modules array so the server knows which
    // modules we intend to use. Without this, only FREE tier modules are granted.
    let hardware_id = signing::get_hardware_id();

    info!("Authorizing scan with {} requested modules...", requested_modules.len());
    let scan_token = match signing::authorize_scan(
        target_count as u32,
        &hardware_id,
        license_key,
        Some(env!("CARGO_PKG_VERSION")),
        requested_modules,
    ).await {
        Ok(token) => {
            info!("[OK] Scan authorized: {} license, max {} targets, {} modules authorized",
                token.license_type, token.max_targets, token.authorized_modules.len());
            token
        }
        Err(SigningError::Banned(reason)) => {
            error!("========================================================");
            error!("ACCESS DENIED - USER BANNED");
            error!("========================================================");
            error!("");
            error!("Reason: {}", reason);
            error!("");
            error!("If you believe this is an error, contact:");
            error!("  info@bountyy.fi");
            error!("");
            error!("========================================================");
            std::process::exit(1);
        }
        Err(SigningError::LicenseError(msg)) => {
            error!("========================================================");
            error!("LICENSE ERROR");
            error!("========================================================");
            error!("");
            error!("{}", msg);
            error!("");
            error!("========================================================");
            std::process::exit(1);
        }
        Err(SigningError::ServerUnreachable(msg)) => {
            // STRICT MODE: No offline fallback - server connection required
            error!("========================================================");
            error!("SERVER UNREACHABLE - SCAN BLOCKED");
            error!("========================================================");
            error!("");
            error!("Cannot connect to authorization server: {}", msg);
            error!("");
            error!("Server connectivity is REQUIRED for scanning.");
            error!("Please check your network connection and try again.");
            error!("");
            error!("========================================================");
            std::process::exit(1);
        }
        Err(e) => {
            // Other errors (server error, invalid response) - no fallback
            error!("========================================================");
            error!("AUTHORIZATION FAILED");
            error!("========================================================");
            error!("");
            error!("{}", e);
            error!("");
            error!("========================================================");
            std::process::exit(1);
        }
    };

    Ok((status, scan_token))
}

/// Handle license management commands
async fn handle_license_command(action: LicenseAction, _current_key: Option<&str>) -> Result<()> {
    let mut manager = license::LicenseManager::new()?;

    match action {
        LicenseAction::Activate { key } => {
            println!("Activating license key...");

            // Set and validate the key
            manager.set_license_key(key.clone());
            let status = manager.validate().await?;

            if status.valid {
                // Save the license
                manager.save_license(&key)?;

                println!();
                println!("License activated successfully!");
                println!();
                license::print_license_info(&status);
                println!();
                println!("License saved. You can now run scans without specifying the key.");
            } else {
                error!("License validation failed");
                if let Some(msg) = status.message {
                    error!("{}", msg);
                }
                std::process::exit(1);
            }
        }
        LicenseAction::Status => {
            // Load and display current license
            manager.load_license()?;
            let status = manager.validate().await?;

            println!();
            println!("========================================================");
            println!("LONKERO LICENSE STATUS");
            println!("========================================================");
            println!();

            if status.valid {
                if let Some(lt) = status.license_type {
                    match lt {
                        LicenseType::Personal => println!("License Type:    Free Non-Commercial"),
                        _ => println!("License Type:    {}", lt),
                    }
                }
                if let Some(ref licensee) = status.licensee {
                    println!("Licensed to:     {}", licensee);
                }
                if let Some(ref org) = status.organization {
                    println!("Organization:    {}", org);
                }
                if let Some(ref expires) = status.expires_at {
                    println!("Expires:         {}", expires);
                }
                if let Some(max) = status.max_targets {
                    println!("Max targets:     {}", max);
                }
                if !status.features.is_empty() {
                    println!("Features:        {}", status.features.join(", "));
                }
            } else {
                println!("Status:          No valid license");
                println!();
                println!("Running in Personal/Non-Commercial mode.");
                println!("For commercial use, obtain a license at:");
                println!("  https://bountyy.fi/license");
            }

            println!();
            println!("========================================================");
        }
        LicenseAction::Deactivate => {
            let config_dir = dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("lonkero");
            let license_file = config_dir.join("license.key");
            let cache_file = config_dir.join(".license_cache");

            if license_file.exists() {
                std::fs::remove_file(&license_file)?;
                println!("License key removed.");
            }
            if cache_file.exists() {
                std::fs::remove_file(&cache_file)?;
            }

            println!("License deactivated successfully.");
            println!("You can activate a new license with: lonkero license activate <KEY>");
        }
    }

    Ok(())
}

async fn run_scan(
    targets: Vec<String>,
    mode: ScanMode,
    output: Option<PathBuf>,
    format: OutputFormat,
    subdomains: bool,
    dorks: bool,
    crawl: bool,
    max_depth: u32,
    concurrency: usize,
    timeout: u64,
    user_agent: Option<String>,
    cookie: Option<String>,
    token: Option<String>,
    basic_auth: Option<String>,
    auth_username: Option<String>,
    auth_password: Option<String>,
    auth_login_url: Option<String>,
    headers: Vec<String>,
    _skip: Vec<String>,
    _only: Vec<String>,
    _proxy: Option<String>,
    _insecure: bool,
    rate_limit: u32,
    no_rate_limit: bool,
    license_status: LicenseStatus,
    scan_token: ScanToken,
) -> Result<()> {
    // Check if killswitch is active
    if license_status.killswitch_active {
        error!("========================================================");
        error!("SCANNER DISABLED");
        error!("========================================================");
        error!("");
        error!("This scanner has been remotely disabled.");
        if let Some(reason) = &license_status.killswitch_reason {
            error!("Reason: {}", reason);
        }
        error!("");
        error!("If you believe this is an error, please contact:");
        error!("  info@bountyy.fi");
        error!("");
        error!("========================================================");
        std::process::exit(1);
    }

    // Check target count against license
    if let Some(max_targets) = license_status.max_targets {
        if targets.len() as u32 > max_targets {
            error!("========================================================");
            error!("LICENSE LIMIT EXCEEDED");
            error!("========================================================");
            error!("");
            error!("Your license allows {} target(s), but you specified {}.", max_targets, targets.len());
            error!("");
            error!("To scan more targets, upgrade your license at:");
            error!("  https://bountyy.fi");
            error!("");
            error!("========================================================");
            std::process::exit(1);
        }
    }

    print_banner();

    info!("Initializing Lonkero Scanner v2.0.0");
    info!("Scan mode: {:?}", mode);
    info!("Targets: {}", targets.len());

    // Build scanner configuration
    let scanner_config = ScannerConfig {
        max_concurrency: concurrency,
        request_timeout_secs: timeout,
        max_retries: 2,
        rate_limit_rps: if no_rate_limit { 0 } else { rate_limit },
        rate_limit_enabled: !no_rate_limit,
        rate_limit_adaptive: !no_rate_limit,
        http2_enabled: true,
        http2_adaptive_window: true,
        http2_max_concurrent_streams: 100,
        pool_max_idle_per_host: 10,
        cache_enabled: true,
        cache_max_capacity: 10000,
        cache_ttl_secs: 300,
        dns_cache_enabled: true,
        subdomain_enum_enabled: subdomains,
        subdomain_enum_thorough: matches!(mode, ScanMode::Thorough | ScanMode::Insane),
        cdn_detection_enabled: true,
        early_termination_enabled: false,
        adaptive_concurrency_enabled: true,
        initial_concurrency: 10,
        max_concurrency_per_target: concurrency,
        request_batching_enabled: false,
        batch_size: 50,
        ..Default::default()
    };

    // Parse custom headers
    let mut custom_headers = std::collections::HashMap::new();
    for h in headers {
        if let Some((key, value)) = h.split_once(':') {
            custom_headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    if let Some(ua) = &user_agent {
        custom_headers.insert("User-Agent".to_string(), ua.clone());
    }

    // Initialize authentication session
    use lonkero_scanner::auth_context::{AuthSession, Authenticator, LoginCredentials};

    let auth_session: Option<AuthSession> = if let (Some(username), Some(password)) = (&auth_username, &auth_password) {
        // Auto-login mode
        info!("[Auth] Auto-login enabled for user: {}", username);
        let authenticator = Authenticator::new(timeout);
        let mut creds = LoginCredentials::new(username, password);
        if let Some(login_url) = &auth_login_url {
            creds = creds.with_login_url(login_url);
        }

        // Use first target as base URL for login
        let base_url = targets.first().map(|t| t.as_str()).unwrap_or("");
        match authenticator.login(base_url, &creds).await {
            Ok(session) => {
                if session.is_authenticated {
                    info!("[Auth] Login successful - {} cookies, JWT: {}",
                        session.cookies.len(),
                        session.find_jwt().is_some()
                    );
                    Some(session)
                } else {
                    warn!("[Auth] Login may have failed - proceeding without auth");
                    None
                }
            }
            Err(e) => {
                warn!("[Auth] Auto-login failed: {} - proceeding without auth", e);
                None
            }
        }
    } else if let Some(tok) = &token {
        // Bearer token provided
        info!("[Auth] Using provided bearer token");
        Some(Authenticator::from_token(tok, "bearer"))
    } else if let Some(cook) = &cookie {
        // Cookie provided
        info!("[Auth] Using provided cookies");
        Some(Authenticator::from_token(cook, "cookie"))
    } else {
        None
    };

    // Add auth headers to custom headers if we have a session
    if let Some(ref session) = auth_session {
        for (key, value) in session.auth_headers() {
            custom_headers.insert(key, value);
        }
        info!("[Auth] Authentication context ready - scanning authenticated endpoints");
    }

    // Create scan engine
    let engine = Arc::new(ScanEngine::new(scanner_config.clone())?);
    info!("[OK] Scan engine initialized with {} scanner modules", 60);

    // Google Dorking - generate reconnaissance queries if enabled
    if dorks {
        info!("");
        info!("=== Google Dorking Reconnaissance ===");
        info!("Generating Google dork queries for {} target(s)...", targets.len());
        info!("");

        use lonkero_scanner::scanners::GoogleDorkingScanner;

        for target in &targets {
            let dork_results = engine.google_dorking_scanner.generate_dorks(target);
            let output_text = GoogleDorkingScanner::format_dorks_for_display(&dork_results);
            println!("{}", output_text);

            // If output file is specified, save dorks to a separate file
            if let Some(ref out_path) = output {
                let dorks_filename = out_path
                    .with_file_name(format!(
                        "{}_dorks.json",
                        out_path.file_stem().and_then(|s| s.to_str()).unwrap_or("scan")
                    ));
                let dorks_json = GoogleDorkingScanner::format_dorks_as_json(&dork_results);
                if let Ok(json_str) = serde_json::to_string_pretty(&dorks_json) {
                    if let Err(e) = std::fs::write(&dorks_filename, json_str) {
                        warn!("Failed to write dorks file: {}", e);
                    } else {
                        info!("Google dorks saved to: {}", dorks_filename.display());
                    }
                }
            }
        }

        info!("");
        info!("=== Google Dorking Complete ===");
        info!("Copy the queries above and use them in Google Search manually.");
        info!("Note: Automated Google searches violate Google's Terms of Service.");
        info!("");
    }

    let start_time = Instant::now();
    let mut all_results: Vec<ScanResults> = Vec::new();
    let mut total_vulns = 0;
    let mut total_tests = 0;

    // Scan each target
    for (idx, target) in targets.iter().enumerate() {
        info!("");
        info!("=== Scanning target {}/{}: {} ===", idx + 1, targets.len(), target);

        // Validate target URL
        if let Err(e) = url::Url::parse(target) {
            error!("Invalid target URL '{}': {}", target, e);
            continue;
        }

        // Build scan job
        let scan_config = ScanConfig {
            scan_mode: mode,
            enable_crawler: crawl,
            max_depth,
            max_pages: 100,
            enum_subdomains: subdomains,
            auth_cookie: cookie.clone(),
            auth_token: token.clone(),
            auth_basic: basic_auth.clone(),
            custom_headers: if custom_headers.is_empty() {
                None
            } else {
                Some(custom_headers.clone())
            },
        };

        let job = Arc::new(ScanJob {
            scan_id: format!("scan_{}", uuid::Uuid::new_v4()),
            target: target.clone(),
            config: scan_config,
        });

        // Execute scan (standalone mode - no Redis queue)
        match execute_standalone_scan(Arc::clone(&engine), job, &scanner_config).await {
            Ok(results) => {
                let vuln_count = results.vulnerabilities.len();
                total_vulns += vuln_count;
                total_tests += results.tests_run;

                // Print vulnerability summary
                print_vulnerability_summary(&results);

                all_results.push(results);
            }
            Err(e) => {
                error!("Scan failed for {}: {}", target, e);
            }
        }
    }

    let elapsed = start_time.elapsed();

    // Print final summary
    println!();
    println!("{}", "=".repeat(60));
    println!("SCAN COMPLETE");
    println!("{}", "=".repeat(60));
    println!("Targets scanned:    {}", targets.len());
    println!("Total tests run:    {}", total_tests);
    println!("Vulnerabilities:    {}", total_vulns);
    println!("Duration:           {:.2}s", elapsed.as_secs_f64());
    println!("{}", "=".repeat(60));

    // Output results
    if let Some(output_path) = output {
        write_results(&all_results, &output_path, format)?;
        info!("Results written to: {}", output_path.display());
    } else {
        // Print to stdout if no output file specified
        let json = serde_json::to_string_pretty(&all_results)?;
        println!("{}", json);
    }

    // Exit with error code if vulnerabilities found
    if total_vulns > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Generate smart dummy values for form fields based on field name
fn get_dummy_value(field_name: &str) -> String {
    let name_lower = field_name.to_lowercase();

    // Email fields
    if name_lower.contains("email") || name_lower.contains("mail") {
        return "test@example.com".to_string();
    }

    // Phone fields
    if name_lower.contains("phone") || name_lower.contains("tel") || name_lower.contains("mobile") {
        return "+1234567890".to_string();
    }

    // Name fields
    if name_lower.contains("name") || name_lower.contains("nimi") {
        return "Test User".to_string();
    }

    // Message/comment fields
    if name_lower.contains("message") || name_lower.contains("comment") || name_lower.contains("viesti") ||
       name_lower.contains("description") || name_lower.contains("text") || name_lower.contains("body") {
        return "Test message content".to_string();
    }

    // Password fields
    if name_lower.contains("password") || name_lower.contains("pass") {
        return "TestPass123!".to_string();
    }

    // URL fields
    if name_lower.contains("url") || name_lower.contains("website") || name_lower.contains("link") {
        return "https://example.com".to_string();
    }

    // Number/amount fields
    if name_lower.contains("amount") || name_lower.contains("price") || name_lower.contains("number") ||
       name_lower.contains("quantity") || name_lower.contains("age") {
        return "100".to_string();
    }

    // Subject fields
    if name_lower.contains("subject") || name_lower.contains("title") || name_lower.contains("aihe") {
        return "Test Subject".to_string();
    }

    // Company fields
    if name_lower.contains("company") || name_lower.contains("organization") || name_lower.contains("yritys") {
        return "Test Company Ltd".to_string();
    }

    // Address fields
    if name_lower.contains("address") || name_lower.contains("street") || name_lower.contains("osoite") {
        return "123 Test Street".to_string();
    }

    // City fields
    if name_lower.contains("city") || name_lower.contains("kaupunki") {
        return "Helsinki".to_string();
    }

    // Country fields
    if name_lower.contains("country") || name_lower.contains("maa") {
        return "Finland".to_string();
    }

    // Zip/postal code
    if name_lower.contains("zip") || name_lower.contains("postal") || name_lower.contains("postinumero") {
        return "00100".to_string();
    }

    // Default: generic test value
    "test_value".to_string()
}

/// Get value for a form input, using SELECT options if available
fn get_form_input_value(input: &lonkero_scanner::crawler::FormInput) -> String {
    // For SELECT elements with options, use first option
    if input.input_type.eq_ignore_ascii_case("select") {
        if let Some(options) = &input.options {
            if !options.is_empty() {
                return options[0].clone();
            }
        }
    }

    // If input has a preset value, use it
    if let Some(value) = &input.value {
        if !value.is_empty() {
            return value.clone();
        }
    }

    // Fall back to smart dummy value based on field name
    get_dummy_value(&input.name)
}

/// Check if a form input should be skipped (auto-generated select, language selector, buttons, etc.)
/// Returns true if the input should NOT be tested
fn should_skip_form_input(input: &lonkero_scanner::crawler::FormInput) -> bool {
    let name_lower = input.name.to_lowercase();
    let input_type_lower = input.input_type.to_lowercase();

    // Skip buttons - they're not attack surfaces
    if input_type_lower == "button" || input_type_lower == "submit" || input_type_lower == "reset" {
        return true;
    }

    // Skip GTM (Google Tag Manager) prefixed fields - tracking only, not attack surfaces
    if name_lower.starts_with("gtm-") || name_lower.starts_with("gtm_") {
        return true;
    }

    // Skip auto-generated select elements - these are framework-generated and not useful attack surfaces
    // Examples: input_1, input_2, select_0, field_1
    if input_type_lower == "select" {
        let is_auto_generated = name_lower.starts_with("input_")
            || name_lower.starts_with("select_")
            || name_lower.starts_with("field_")
            || name_lower.starts_with("form_")
            || name_lower == "input"
            || name_lower == "select"
            || name_lower.chars().all(|c| c.is_ascii_digit() || c == '_');

        if is_auto_generated {
            return true;
        }

        // Check if options look like language codes
        if let Some(options) = &input.options {
            let lang_codes = ["en", "fi", "sv", "de", "fr", "es", "it", "nl", "pt", "ja", "zh", "ko", "ru",
                             "en-us", "en-gb", "fi-fi", "sv-se", "de-de", "fr-fr", "es-es",
                             "english", "finnish", "swedish", "german", "french", "spanish"];
            let has_language_options = options.iter().any(|opt| {
                let opt_lower = opt.to_lowercase();
                lang_codes.iter().any(|lc| opt_lower == *lc || opt_lower.starts_with(&format!("{}-", lc)))
            });
            if has_language_options {
                return true;
            }
        }
    }

    // Skip common language/locale selector field names (any input type)
    let is_lang_field_name = name_lower.contains("lang")
        || name_lower.contains("locale")
        || name_lower.contains("language")
        || name_lower.contains("country")
        || name_lower.contains("region");

    if is_lang_field_name {
        return true;
    }

    false
}

/// Check if a form looks like a language/locale selector (legacy, checks whole form)
fn is_language_selector_form(form_inputs: &[lonkero_scanner::crawler::FormInput], action: &str) -> bool {
    // If all inputs should be skipped, skip the whole form
    if form_inputs.iter().all(should_skip_form_input) {
        return true;
    }

    // Check if action URL looks like a language page
    let action_lower = action.to_lowercase();
    let action_no_fragment = action_lower.split('#').next().unwrap_or(&action_lower);
    let action_clean = action_no_fragment.split('?').next().unwrap_or(action_no_fragment);

    let path = if let Some(pos) = action_clean.find("://") {
        let after_scheme = &action_clean[pos + 3..];
        after_scheme.find('/').map(|p| &after_scheme[p..]).unwrap_or("")
    } else {
        action_clean
    };

    let is_language_url = path.contains("/en/")
        || path.contains("/fi/")
        || path.contains("/sv/")
        || path.contains("/de/")
        || path.contains("/fr/")
        || path.contains("/es/")
        || path.contains("/it/")
        || path.contains("/nl/")
        || path.contains("/pt/")
        || path.contains("/ja/")
        || path.contains("/zh/")
        || path.contains("/ko/")
        || path.contains("/ru/")
        || path == "/en" || path == "/fi" || path == "/sv" || path == "/de"
        || path == "/fr" || path == "/es" || path == "/it" || path == "/nl" || path == "/pt";

    // Single select on language URL = language selector
    if form_inputs.len() == 1 && form_inputs[0].input_type.eq_ignore_ascii_case("select") && is_language_url {
        return true;
    }

    false
}

async fn execute_standalone_scan(
    engine: Arc<ScanEngine>,
    job: Arc<ScanJob>,
    config: &ScannerConfig,
) -> Result<ScanResults> {
    use lonkero_scanner::crawler::WebCrawler;
    use lonkero_scanner::headless_crawler::HeadlessCrawler;
    use lonkero_scanner::framework_detector::FrameworkDetector;
    
    use lonkero_scanner::types::Vulnerability;

    // ============================================================
    // MANDATORY AUTHORIZATION CHECK - CANNOT BE BYPASSED
    // ============================================================
    // This ensures banned users cannot scan even through the standalone path.
    if !signing::is_scan_authorized() {
        return Err(anyhow::anyhow!(
            "SCAN BLOCKED: Authorization required before scanning. \
            This check prevents banned users from accessing the scanner."
        ));
    }

    // Get scan token for signing results later
    let scan_token = signing::get_scan_token()
        .ok_or_else(|| anyhow::anyhow!("No valid scan token available. Re-authorize to continue."))?
        .clone();

    let start_time = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();

    let target = &job.target;
    let scan_config = &job.config;

    info!("Starting scan for: {}", target);

    // Create HTTP client for reconnaissance
    let http_client = Arc::new(HttpClient::with_config(
        config.request_timeout_secs,
        config.max_retries,
        config.http2_enabled,
        config.http2_adaptive_window,
        config.http2_max_concurrent_streams,
        config.pool_max_idle_per_host,
    )?);

    let mut all_vulnerabilities: Vec<Vulnerability> = Vec::new();
    let mut total_tests: u64 = 0;

    // Phase 0: Reconnaissance
    info!("Phase 0: Reconnaissance");

    // Web crawling (if enabled) - STORE results for parameter discovery
    let mut discovered_params: Vec<String> = Vec::new();
    let mut discovered_forms: Vec<(String, Vec<lonkero_scanner::crawler::FormInput>)> = Vec::new(); // (action_url, form_inputs)
    let mut is_spa_detected = false;  // SPA detection from crawler

    if scan_config.enable_crawler {
        info!("  - Running web crawler (depth: {})", scan_config.max_depth);
        let crawler = WebCrawler::new(Arc::clone(&http_client), scan_config.max_depth as usize, scan_config.max_pages as usize);
        match crawler.crawl(target).await {
            Ok(results) => {
                info!("  - Discovered {} URLs, {} forms", results.crawled_urls.len(), results.forms.len());
                is_spa_detected = results.is_spa;  // Capture SPA detection

                // Extract parameters from discovered forms for XSS testing
                for form in &results.forms {
                    let form_inputs: Vec<lonkero_scanner::crawler::FormInput> = form.inputs.iter()
                        .filter(|input| !input.input_type.eq_ignore_ascii_case("hidden") &&
                                       !input.input_type.eq_ignore_ascii_case("submit") &&
                                       !input.name.is_empty())
                        .cloned()
                        .collect();

                    // Skip language selector forms - these have a single select with auto-generated name
                    // and typically have language code options (en, fi, sv, de, etc.)
                    if is_language_selector_form(&form_inputs, &form.action) {
                        debug!("[Crawler] Skipping language selector form at {}", form.action);
                        continue;
                    }

                    if !form_inputs.is_empty() {
                        let action_url = if form.action.is_empty() {
                            target.to_string()
                        } else {
                            form.action.clone()
                        };
                        let param_names: Vec<String> = form_inputs.iter().map(|i| i.name.clone()).collect();
                        discovered_forms.push((action_url, form_inputs));
                        discovered_params.extend(param_names);
                    }
                }

                if !discovered_params.is_empty() {
                    info!("  - Found {} input fields to test for XSS", discovered_params.len());
                }
            }
            Err(e) => {
                warn!("  - Crawler failed: {}", e);
            }
        }
    }

    // Technology detection - STORE RESULTS for smart filtering
    info!("  - Detecting technologies");
    let detector = FrameworkDetector::new(Arc::clone(&http_client));
    let detected_technologies: std::collections::HashSet<String> = match detector.detect(target).await {
        Ok(techs) => {
            if !techs.is_empty() {
                info!("[SUCCESS] Detected {} technologies", techs.len());
                for tech in &techs {
                    info!("    - {} ({:?})", tech.name, tech.category);
                }
            }
            techs.iter().map(|t| t.name.to_lowercase()).collect()
        }
        Err(e) => {
            warn!("  - Technology detection failed: {}", e);
            std::collections::HashSet::new()
        }
    };

    // Determine tech stack for smart scanner filtering
    let is_nodejs_stack = detected_technologies.iter().any(|t|
        t.contains("next") || t.contains("node") || t.contains("express") ||
        t.contains("react") || t.contains("vue") || t.contains("angular") ||
        t.contains("nuxt") || t.contains("gatsby")
    );
    let is_php_stack = detected_technologies.iter().any(|t|
        t.contains("php") || t.contains("wordpress") || t.contains("laravel") ||
        t.contains("drupal") || t.contains("magento")
    );
    let is_python_stack = detected_technologies.iter().any(|t|
        t.contains("python") || t.contains("django") || t.contains("flask") ||
        t.contains("jinja") || t.contains("fastapi")
    );
    let is_java_stack = detected_technologies.iter().any(|t|
        t.contains("java") || t.contains("spring") || t.contains("tomcat") ||
        t.contains("struts") || t.contains("jsp")
    );
    let is_static_site = detected_technologies.iter().any(|t|
        t.contains("cloudflare pages") || t.contains("vercel") || t.contains("netlify") ||
        t.contains("github pages")
    );

    // HEADLESS BROWSER CRAWLING for SPA/JS frameworks
    // Use headless if: (1) tech detection found JS framework, OR (2) crawler detected SPA pattern
    // AND static crawler found few/no forms
    let needs_headless = (is_nodejs_stack || is_spa_detected) && discovered_forms.is_empty();
    let mut intercepted_endpoints: Vec<String> = Vec::new();
    if needs_headless {
        info!("  - SPA detected with no forms found, using headless browser to discover real endpoints...");
        // Pass auth token to headless crawler for authenticated form discovery
        let headless = HeadlessCrawler::with_auth(30, scan_config.auth_token.clone());

        // For authenticated scans, do full site crawl to discover all pages and forms
        if scan_config.auth_token.is_some() {
            info!("  - Using authenticated headless session - performing full site crawl");
            let max_pages = 50; // Limit pages for reasonable scan time

            match headless.crawl_authenticated_site(target, max_pages).await {
                Ok(crawl_results) => {
                    info!("[SUCCESS] Authenticated site crawl complete:");
                    info!("    - Pages visited: {}", crawl_results.pages_visited.len());
                    info!("    - Forms discovered: {}", crawl_results.forms.len());
                    info!("    - API endpoints found: {}", crawl_results.api_endpoints.len());

                    // Add all discovered forms
                    for form in &crawl_results.forms {
                        let form_inputs: Vec<lonkero_scanner::crawler::FormInput> = form.inputs.iter()
                            .filter(|input| !input.input_type.eq_ignore_ascii_case("hidden") &&
                                           !input.input_type.eq_ignore_ascii_case("submit") &&
                                           !input.name.is_empty())
                            .cloned()
                            .collect();

                        // Skip language selector forms
                        if is_language_selector_form(&form_inputs, &form.action) {
                            debug!("[Headless] Skipping language selector form at {}", form.action);
                            continue;
                        }

                        if !form_inputs.is_empty() {
                            let action_url = if form.action.is_empty() {
                                form.discovered_at.clone()
                            } else {
                                form.action.clone()
                            };
                            let param_names: Vec<String> = form_inputs.iter().map(|i| i.name.clone()).collect();
                            discovered_forms.push((action_url, form_inputs));
                            discovered_params.extend(param_names);
                        }
                    }

                    // Add all discovered API endpoints
                    for ep in &crawl_results.api_endpoints {
                        info!("    - API: {} {}", ep.method, ep.url);
                        intercepted_endpoints.push(ep.url.clone());
                    }

                    // Log discovered JS files for debugging
                    if !crawl_results.js_files.is_empty() {
                        info!("    - JS files discovered: {}", crawl_results.js_files.len());
                    }

                    // Add discovered GraphQL endpoints to testing queue
                    if !crawl_results.graphql_endpoints.is_empty() {
                        info!("    - GraphQL endpoints: {}", crawl_results.graphql_endpoints.len());
                        for gql_ep in &crawl_results.graphql_endpoints {
                            info!("      - {}", gql_ep);
                            // Add to intercepted endpoints for advanced testing
                            if !intercepted_endpoints.contains(gql_ep) {
                                intercepted_endpoints.push(gql_ep.clone());
                            }
                        }
                    }

                    // Log discovered GraphQL operations
                    if !crawl_results.graphql_operations.is_empty() {
                        info!("    - GraphQL operations discovered: {}", crawl_results.graphql_operations.len());
                        for op in &crawl_results.graphql_operations {
                            info!("      - {} {} (from {})", op.operation_type, op.name, op.source);
                        }
                    }

                    info!("  - Total: {} forms with {} fields, {} API endpoints, {} GraphQL endpoints",
                          discovered_forms.len(), discovered_params.len(),
                          intercepted_endpoints.len(), crawl_results.graphql_endpoints.len());
                }
                Err(e) => {
                    warn!("  - Full site crawl failed: {}", e);
                    warn!("  - Falling back to single-page scan");
                }
            }
        } else {
            // Non-authenticated: use single-page discovery (existing behavior)
            // First: Discover actual form submission endpoints via network interception
            // This is crucial for React/Next.js apps where forms POST to /api/ routes
            info!("  - Intercepting network requests to discover form endpoints...");
            match headless.discover_form_endpoints(target).await {
                Ok(endpoints) => {
                    if !endpoints.is_empty() {
                        info!("[SUCCESS] Intercepted {} form submission endpoints:", endpoints.len());
                        for ep in &endpoints {
                            info!("    - {} {} ({})", ep.method, ep.url, ep.content_type.as_deref().unwrap_or("unknown"));
                            intercepted_endpoints.push(ep.url.clone());
                        }
                    } else {
                        info!("  - No POST requests intercepted during form submission");
                    }
                }
                Err(e) => {
                    warn!("  - Network interception failed: {}", e);
                }
            }

            // Second: Extract form field info
            match headless.extract_forms(target).await {
                Ok(forms) => {
                    if !forms.is_empty() {
                        info!("[SUCCESS] Headless browser found {} forms", forms.len());
                        for form in &forms {
                            let form_inputs: Vec<lonkero_scanner::crawler::FormInput> = form.inputs.iter()
                                .filter(|input| !input.input_type.eq_ignore_ascii_case("hidden") &&
                                               !input.input_type.eq_ignore_ascii_case("submit") &&
                                               !input.name.is_empty())
                                .cloned()
                                .collect();

                            // Skip language selector forms
                            if is_language_selector_form(&form_inputs, &form.action) {
                                debug!("[Headless] Skipping language selector form at {}", form.action);
                                continue;
                            }

                            if !form_inputs.is_empty() {
                                // Use intercepted endpoint if available, otherwise fall back to form.action
                                let action_url = if !intercepted_endpoints.is_empty() {
                                    // Use first intercepted endpoint as the real form target
                                    intercepted_endpoints[0].clone()
                                } else if form.action.is_empty() {
                                    target.to_string()
                                } else {
                                    form.action.clone()
                                };
                                let param_names: Vec<String> = form_inputs.iter().map(|i| i.name.clone()).collect();
                                discovered_forms.push((action_url.clone(), form_inputs.clone()));
                                discovered_params.extend(param_names.clone());

                                // Also add entries for other intercepted endpoints (if any)
                                for ep in intercepted_endpoints.iter().skip(1) {
                                    discovered_forms.push((ep.clone(), form_inputs.clone()));
                                }
                            }
                        }
                        info!("  - Found {} real form fields from rendered page", discovered_params.len());
                        if !intercepted_endpoints.is_empty() {
                            info!("  - Using intercepted API endpoint(s) instead of page URL");
                        }
                    }
                }
                Err(e) => {
                    warn!("  - Headless browser failed: {} (Chrome/Chromium may not be installed)", e);
                }
            }
        }
    }

    // CVE-2025-55182 Check - CRITICAL for Next.js/React sites
    // This is a CVSS 10.0 RCE vulnerability in React Server Components
    if is_nodejs_stack || detected_technologies.iter().any(|t| t.contains("next") || t.contains("react")) {
        info!("  - Checking CVE-2025-55182 (React Server Components RCE)");
        let (vulns, tests) = engine.cve_2025_55182_scanner.scan(target, scan_config).await?;
        // Only warn if actually vulnerable (not just WAF-protected informational note)
        if vulns.iter().any(|v| v.severity == lonkero_scanner::types::Severity::Critical) {
            warn!("[CRITICAL] CVE-2025-55182 vulnerability detected!");
        } else if !vulns.is_empty() {
            info!("[OK] CVE-2025-55182: Protected by WAF");
        }
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // CVE-2025-55183 Check - Source Code Exposure (Medium, CVSS 5.3)
        // Only affects Next.js 15.x+ - can leak Server Action source code
        info!("  - Checking CVE-2025-55183 (RSC Source Code Exposure)");
        let (vulns, tests) = engine.cve_2025_55183_scanner.scan(target, scan_config).await?;
        if vulns.iter().any(|v| v.severity == lonkero_scanner::types::Severity::Medium || v.severity == lonkero_scanner::types::Severity::High) {
            warn!("[ALERT] CVE-2025-55183 vulnerability detected!");
        } else if !vulns.is_empty() {
            info!("[OK] CVE-2025-55183: Protected by WAF");
        }
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // CVE-2025-55184 Check - Denial of Service (High, CVSS 7.5)
        // Cyclic Promise references cause server hang
        info!("  - Checking CVE-2025-55184 (RSC Denial of Service)");
        let (vulns, tests) = engine.cve_2025_55184_scanner.scan(target, scan_config).await?;
        if vulns.iter().any(|v| v.severity == lonkero_scanner::types::Severity::High || v.severity == lonkero_scanner::types::Severity::Critical) {
            warn!("[ALERT] CVE-2025-55184 vulnerability detected!");
        } else if !vulns.is_empty() {
            info!("[OK] CVE-2025-55184: Protected by WAF");
        }
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Azure APIM Cross-Tenant Signup Bypass Check (GHSA-vcwf-73jp-r7mv)
    // Check for any target - the scanner will detect if it's an APIM portal
    {
        info!("  - Checking Azure APIM Cross-Tenant Signup Bypass");
        let (vulns, tests) = engine.azure_apim_scanner.scan(target, scan_config).await?;
        if !vulns.is_empty() {
            warn!("[ALERT] Azure APIM Cross-Tenant Signup Bypass detected!");
        }
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Phase 0.5: JavaScript Mining for API endpoints and parameters
    // Run this BEFORE injection tests to discover testable endpoints in SPAs
    info!("  - Pre-scanning JavaScript for API endpoints and parameters");
    let js_miner_results = engine.js_miner_scanner.scan_with_extraction(target, scan_config).await?;
    all_vulnerabilities.extend(js_miner_results.vulnerabilities);
    total_tests += js_miner_results.tests_run as u64;

    // Log discovered endpoints
    let js_param_count: usize = js_miner_results.parameters.values().map(|s| s.len()).sum();
    if !js_miner_results.api_endpoints.is_empty() || !js_miner_results.graphql_endpoints.is_empty() {
        info!("[SUCCESS] JS Mining found {} API endpoints, {} GraphQL endpoints, {} parameters",
              js_miner_results.api_endpoints.len(),
              js_miner_results.graphql_endpoints.len(),
              js_param_count);
    }

    // ==========================================================================
    // EARLY AUTH TESTING: Run auth-critical tests first while JWT token is fresh
    // JWT tokens expire - we need to test auth endpoints before doing slow injection tests
    // ==========================================================================
    let mut auth_tests_done = false;
    if scan_config.auth_token.is_some() {
        info!("Phase 0.5: Early authentication testing (JWT token may expire)");

        // JWT vulnerabilities - MUST run first while token is valid
        info!("  - Testing JWT Security (priority: token freshness)");
        if let Some(ref token) = scan_config.auth_token {
            let (vulns, tests) = engine.jwt_scanner.scan_jwt(target, token, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // JWT Vulnerabilities Scanner (general JWT analysis)
        info!("  - Testing JWT Vulnerabilities");
        let (vulns, tests) = engine.jwt_vulnerabilities_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // GraphQL - often uses JWT for auth, test while token works
        info!("  - Testing GraphQL Security (uses auth token)");
        let (vulns, tests) = engine.graphql_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // Advanced GraphQL
        info!("  - Testing Advanced GraphQL Security");
        let (vulns, tests) = engine.graphql_security_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // Test discovered GraphQL endpoints from crawl/JS mining
        for ep in &intercepted_endpoints {
            if ep.to_lowercase().contains("graphql") {
                info!("  - Testing discovered GraphQL endpoint: {}", ep);
                let (vulns, tests) = engine.graphql_scanner.scan(ep, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        }

        // API Security - often auth-dependent
        info!("  - Testing API Security");
        let (vulns, tests) = engine.api_security_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // Auth Bypass - requires valid token to compare responses
        info!("  - Testing Authentication Bypass");
        let (vulns, tests) = engine.auth_bypass_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // IDOR - needs auth to test resource access
        info!("  - Testing IDOR");
        let (vulns, tests) = engine.idor_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // BOLA
        info!("  - Testing BOLA");
        let (vulns, tests) = engine.bola_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        auth_tests_done = true;
        info!("[SUCCESS] Early auth testing complete - token-dependent tests done");
    }

    // Phase 1: Parameter-based scanning
    info!("Phase 1: Parameter injection testing");

    // Extract REAL parameters from URL
    let parsed_url = url::Url::parse(target)?;
    let mut test_params: Vec<(String, String)> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Also add discovered form fields from crawling
    for param in &discovered_params {
        if !test_params.iter().any(|(name, _)| name == param) {
            test_params.push((param.clone(), "test".to_string()));
        }
    }

    // Add parameters discovered from JavaScript analysis
    // ONLY add JS miner params if they're tied to actual API endpoints, not generic "global" ones
    // Generic params like "email", "username" from security_params cause false positives
    for (endpoint, param_set) in js_miner_results.parameters.iter() {
        // Skip "global" and "*" params - these are generic guesses, not discovered from forms
        if endpoint == "global" || endpoint == "*" {
            continue;
        }
        for param in param_set {
            if !test_params.iter().any(|(name, _)| name == param) {
                test_params.push((param.clone(), "test".to_string()));
            }
        }
    }

    // Limit parameters to prevent excessive testing (max 100 params for performance)
    const MAX_PARAMS_TO_TEST: usize = 100;
    let original_count = test_params.len();
    if test_params.len() > MAX_PARAMS_TO_TEST {
        info!("  [NOTE] Limiting parameter tests from {} to {} (max limit)", original_count, MAX_PARAMS_TO_TEST);
        test_params.truncate(MAX_PARAMS_TO_TEST);
    }

    // Only test parameters that actually exist
    let has_real_params = !test_params.is_empty();

    if !has_real_params {
        info!("  [NOTE] No parameters found - skipping parameter injection tests");
    } else {
        info!("  [OK] Found {} parameters to test (URL + discovered forms)", test_params.len());
    }

    // Detect if this is a GraphQL-only backend (Vue/Nuxt + GraphQL)
    // GraphQL apps don't use traditional form POST - they use GraphQL mutations
    // Check both: intercepted endpoints (from headless browser) AND js_miner_results.graphql_endpoints
    let has_graphql_from_miner = !js_miner_results.graphql_endpoints.is_empty();
    let all_intercepted_are_graphql = intercepted_endpoints.iter().all(|ep| ep.to_lowercase().contains("graphql"));

    // Exclude common utility endpoints from non-GraphQL API check (health checks, etc.)
    let utility_endpoints = ["ping", "health", "healthz", "status", "ready", "live", "metrics", "version"];
    let has_non_graphql_api = js_miner_results.api_endpoints.iter()
        .any(|ep| {
            let ep_lower = ep.to_lowercase();
            let is_graphql = ep_lower.contains("graphql");
            let is_utility = utility_endpoints.iter().any(|u| {
                ep_lower.ends_with(&format!("/{}", u)) || ep_lower.ends_with(&format!("/{}/", u))
            });
            !is_graphql && !is_utility
        });

    // GraphQL-only if:
    // 1. JS Miner found GraphQL endpoints, AND
    // 2. No non-GraphQL API endpoints were found (excluding utility endpoints), AND
    // 3. Either no intercepted endpoints OR all intercepted endpoints are GraphQL
    let is_graphql_only = has_graphql_from_miner
        && !has_non_graphql_api
        && (intercepted_endpoints.is_empty() || all_intercepted_are_graphql);

    if is_graphql_only {
        info!("  [GraphQL] Detected GraphQL-only backend (found {} GraphQL endpoints)",
              js_miner_results.graphql_endpoints.len());
    }

    // Get baseline response early for context building
    let baseline_response = match engine.http_client.get(target).await {
        Ok(r) => Some(r),
        Err(_) => None,
    };

    // Extract server and content-type from baseline response for ScanContext
    let detected_server = baseline_response.as_ref()
        .and_then(|r| r.headers.get("server"))
        .cloned();

    let content_type = baseline_response.as_ref()
        .and_then(|r| r.headers.get("content-type"))
        .cloned();

    // Determine primary framework from detected technologies
    let primary_framework = if is_nodejs_stack {
        detected_technologies.iter()
            .find(|t| t.contains("next") || t.contains("nuxt") || t.contains("gatsby"))
            .or_else(|| detected_technologies.iter().find(|t| t.contains("react") || t.contains("vue") || t.contains("angular")))
            .or_else(|| detected_technologies.iter().find(|t| t.contains("express") || t.contains("node")))
            .cloned()
    } else if is_php_stack {
        detected_technologies.iter()
            .find(|t| t.contains("laravel") || t.contains("wordpress") || t.contains("drupal") || t.contains("magento"))
            .or_else(|| detected_technologies.iter().find(|t| t.contains("php")))
            .cloned()
    } else if is_python_stack {
        detected_technologies.iter()
            .find(|t| t.contains("django") || t.contains("flask") || t.contains("fastapi"))
            .or_else(|| detected_technologies.iter().find(|t| t.contains("python")))
            .cloned()
    } else if is_java_stack {
        detected_technologies.iter()
            .find(|t| t.contains("spring") || t.contains("struts") || t.contains("jsp"))
            .or_else(|| detected_technologies.iter().find(|t| t.contains("tomcat") || t.contains("java")))
            .cloned()
    } else {
        None
    };

    // Only run parameter injection tests if we have REAL parameters to test
    if has_real_params {
        // FIRST: Test discovered forms with POST (full form body)
        // SKIP for GraphQL backends - forms submit via GraphQL mutations, not POST
        if !discovered_forms.is_empty() && !is_graphql_only {
            info!("  - Testing {} discovered forms with POST", discovered_forms.len());

            // Log all discovered API endpoints for debugging
            if !js_miner_results.api_endpoints.is_empty() {
                info!("    [JS-Miner] Discovered API endpoints:");
                for ep in &js_miner_results.api_endpoints {
                    info!("      - {}", ep);
                }
            }
            if !js_miner_results.form_actions.is_empty() {
                info!("    [JS-Miner] Discovered form actions:");
                for ep in &js_miner_results.form_actions {
                    info!("      - {}", ep);
                }
            }

            // For SPA forms, test discovered API endpoints (filtered for framework noise)
            // Filter out Sentry/Next.js/framework metadata that are NOT real API endpoints
            let framework_noise = [
                "traceparent", "csrftoken", "baggage", "sentry-trace", "sentry.sample_rand",
                "sentry.sample_rate", "sentry.dsc", "next-router-prefetch", "next-url",
                "next-router-state-tree", "rsc", "_rsc", "__next", "__nextjs",
                "x-middleware-prefetch", "x-invoke-path", "x-invoke-query",
            ];
            let form_api_endpoints: Vec<String> = js_miner_results.api_endpoints.iter()
                .chain(js_miner_results.form_actions.iter())
                .filter(|ep| {
                    let ep_lower = ep.to_lowercase();
                    // Remove leading slash for comparison
                    let ep_clean = ep_lower.trim_start_matches('/');
                    // Filter out framework noise
                    !framework_noise.iter().any(|noise| ep_clean == *noise || ep_clean.starts_with(&format!("{}.", noise)))
                })
                .cloned()
                .collect();

            for (action_url, form_inputs) in &discovered_forms {
                // Build base form body using smart values (SELECT options, preset values, or dummy)
                let base_body: String = form_inputs.iter()
                    .map(|input| format!("{}={}", input.name, get_form_input_value(input)))
                    .collect::<Vec<_>>()
                    .join("&");

                // Determine URLs to test - if action is just page URL, also try discovered API endpoints
                let mut test_urls: Vec<String> = vec![action_url.clone()];

                // If form action is the page URL (React/SPA default), add discovered API endpoints
                let parsed_target = url::Url::parse(target).ok();
                let action_normalized = action_url.trim_end_matches('/');
                let target_normalized = target.trim_end_matches('/');
                let is_page_url = action_normalized == target_normalized ||
                    parsed_target.as_ref()
                        .map(|t| {
                            let origin = t.origin().ascii_serialization();
                            action_normalized == origin || action_normalized == &format!("{}/", origin)
                        })
                        .unwrap_or(false);

                info!("    [DEBUG] action_url={}, target={}, is_page_url={}", action_url, target, is_page_url);

                if is_page_url && !form_api_endpoints.is_empty() {
                    info!("    [SPA] Form action is page URL, also testing {} potential API endpoints", form_api_endpoints.len());
                    for api_ep in &form_api_endpoints {
                        // Resolve relative URLs
                        let full_url = if api_ep.starts_with("http") {
                            api_ep.clone()
                        } else if let Some(ref parsed) = parsed_target {
                            let path = if api_ep.starts_with('/') {
                                api_ep.as_str()
                            } else {
                                &format!("/{}", api_ep)
                            };
                            format!("{}{}", parsed.origin().ascii_serialization(), path)
                        } else {
                            continue;
                        };
                        if !test_urls.contains(&full_url) {
                            test_urls.push(full_url);
                        }
                    }
                }

                // Build JSON body for API endpoints
                let json_body: String = format!("{{{}}}",
                    form_inputs.iter()
                        .map(|input| format!("\"{}\":\"{}\"", input.name, get_form_input_value(input)))
                        .collect::<Vec<_>>()
                        .join(",")
                );

                // Test each field in the form against all potential endpoints
                for input in form_inputs {
                    // Skip auto-generated selects and language selectors
                    if should_skip_form_input(&input) {
                        debug!("    Skipping auto-generated/language field '{}' ({})", input.name, input.input_type);
                        continue;
                    }

                    for test_url in &test_urls {
                        let is_api_endpoint = test_url.contains("/api/");
                        info!("    Testing form field '{}' ({}) at {}{}",
                              input.name, input.input_type, test_url,
                              if is_api_endpoint { " [API/JSON]" } else { "" });

                        // Choose content type based on endpoint
                        let (body_to_test, content_type) = if is_api_endpoint {
                            (json_body.clone(), Some("application/json"))
                        } else {
                            (base_body.clone(), Some("application/x-www-form-urlencoded"))
                        };

                        // XSS on form field
                        let (vulns, tests) = engine.xss_scanner.scan_post_body(
                            test_url, &input.name, &body_to_test, content_type, scan_config
                        ).await?;
                        all_vulnerabilities.extend(vulns);
                        total_tests += tests as u64;

                        // SQLi on form field (if not static)
                        if !is_static_site {
                            let (vulns, tests) = engine.sqli_scanner.scan_post_body(
                                test_url, &input.name, &body_to_test, scan_config
                            ).await?;
                            all_vulnerabilities.extend(vulns);
                            total_tests += tests as u64;
                        }
                    }
                }
            }
        } else if is_graphql_only && !discovered_forms.is_empty() {
            info!("  - Skipping {} form POST tests (GraphQL backend uses mutations)", discovered_forms.len());
        }

        // Build ScanContext for parameter testing
        // This provides context-aware information to scanners for intelligent testing
        let build_scan_context = |param_name: &str| -> lonkero_scanner::types::ScanContext {
            use lonkero_scanner::types::{ScanContext, ParameterSource, EndpointType};

            // Determine parameter source
            let parameter_source = if discovered_params.contains(&param_name.to_string()) {
                ParameterSource::HtmlForm
            } else if parsed_url.query_pairs().any(|(k, _)| k == param_name) {
                ParameterSource::UrlQueryString
            } else if js_miner_results.parameters.values().any(|params| params.contains(param_name)) {
                ParameterSource::JavaScriptMined
            } else {
                ParameterSource::Unknown
            };

            // Determine endpoint type
            let endpoint_type = if is_graphql_only || !js_miner_results.graphql_endpoints.is_empty() {
                EndpointType::GraphQlApi
            } else if !js_miner_results.api_endpoints.is_empty() {
                EndpointType::RestApi
            } else if !discovered_forms.is_empty() {
                EndpointType::FormSubmission
            } else {
                EndpointType::Unknown
            };

            // Determine if JSON API based on content-type or discovered endpoints
            let is_json_api = content_type.as_ref()
                .map(|ct| ct.contains("application/json"))
                .unwrap_or(false)
                || !js_miner_results.api_endpoints.is_empty();

            ScanContext {
                parameter_source,
                endpoint_type,
                detected_tech: detected_technologies.iter().cloned().collect(),
                framework: primary_framework.clone(),
                server: detected_server.clone(),
                other_parameters: test_params.iter()
                    .map(|(name, _)| name.clone())
                    .filter(|name| name != param_name)
                    .collect(),
                is_json_api,
                is_graphql: !js_miner_results.graphql_endpoints.is_empty(),
                form_fields: discovered_params.clone(),
                content_type: content_type.clone(),
            }
        };

        // THEN: Test URL parameters with GET (original behavior)
        // SKIP XSS for Vue/React SPAs with GraphQL - they auto-escape templates
        // GraphQL APIs return JSON, not HTML, so XSS payloads won't be reflected
        // XSS requires Professional+ license
        if scan_token.is_module_authorized(module_ids::advanced_scanning::XSS_SCANNER) {
            if !is_graphql_only {
                info!("  - Testing XSS ({} parameters)", test_params.len());
                for (param_name, _) in &test_params {
                    let context = build_scan_context(param_name);
                    let (vulns, tests) = engine.xss_scanner.scan_parameter(target, param_name, scan_config, Some(&context)).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            } else {
                info!("  - Skipping XSS ({} parameters) - GraphQL backend returns JSON, not HTML",
                      test_params.len());
            }
        } else {
            info!("  [SKIP] XSS scanner requires Professional or higher license");
        }

        // Run SQLi scanner (skip for static sites and GraphQL-only backends)
        // GraphQL uses typed queries - no SQL string interpolation
        // SQLi requires Professional+ license
        if scan_token.is_module_authorized(module_ids::advanced_scanning::SQLI_SCANNER) {
            if !is_static_site && !is_graphql_only {
                info!("  - Testing SQL Injection ({} parameters)", test_params.len());
                for (param_name, _) in &test_params {
                    let context = build_scan_context(param_name);
                    let (vulns, tests) = engine.sqli_scanner.scan_parameter(target, param_name, scan_config, Some(&context)).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            } else if is_graphql_only {
                info!("  - Skipping SQLi (GraphQL uses parameterized queries)");
            }
        } else {
            info!("  [SKIP] SQLi scanner requires Professional or higher license");
        }

        // Run Command Injection scanner
        // SKIP for Node.js stacks (Next.js, React, Vue, Angular) - they use JavaScript APIs, not shell commands
        // Command injection is only relevant for PHP, Python CGI, or legacy systems that shell out
        // Command Injection requires Professional+ license
        if scan_token.is_module_authorized(module_ids::advanced_scanning::COMMAND_INJECTION) {
            if !is_static_site && !is_nodejs_stack && (is_php_stack || is_python_stack || is_java_stack) {
                info!("  - Testing Command Injection");
                for (param_name, _) in &test_params {
                    let (vulns, tests) = engine.cmdi_scanner.scan_parameter(target, param_name, scan_config).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            } else if !is_static_site && is_nodejs_stack {
                info!("  - Skipping Command Injection (Node.js stacks don't execute shell commands)");
            }
        } else {
            info!("  [SKIP] Command Injection scanner requires Professional or higher license");
        }

        // Run Path Traversal scanner (skip for static sites and GraphQL backends)
        // Path Traversal requires Professional+ license
        if scan_token.is_module_authorized(module_ids::advanced_scanning::PATH_TRAVERSAL) {
            if !is_static_site && !is_graphql_only {
                info!("  - Testing Path Traversal");
                for (param_name, _) in &test_params {
                    let (vulns, tests) = engine.path_scanner.scan_parameter(target, param_name, scan_config).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            } else if is_graphql_only {
                info!("  - Skipping Path Traversal (GraphQL serves JSON data, not files)");
            }
        } else {
            info!("  [SKIP] Path Traversal scanner requires Professional or higher license");
        }

        // Run SSRF scanner (skip for static sites - they can't make server requests)
        // Only test parameters that could realistically accept URLs
        // SSRF requires Professional+ license
        if scan_token.is_module_authorized(module_ids::advanced_scanning::SSRF_SCANNER) {
            if !is_static_site {
                let ssrf_keywords = ["url", "link", "redirect", "callback", "webhook", "image", "img",
                                     "src", "href", "file", "path", "endpoint", "uri", "dest", "target",
                                     "fetch", "load", "proxy", "forward", "next", "return", "goto", "site"];

                let ssrf_params: Vec<_> = test_params.iter()
                    .filter(|(name, _)| {
                        let name_lower = name.to_lowercase();
                        // Include if param name contains URL-related keywords
                        ssrf_keywords.iter().any(|kw| name_lower.contains(kw))
                        // Or if the value looks like a URL
                        || name_lower.starts_with("http")
                    })
                    .collect();

                if !ssrf_params.is_empty() {
                    info!("  - Testing SSRF ({} URL-like params of {} total)", ssrf_params.len(), test_params.len());
                    for (param_name, _) in &ssrf_params {
                        // Standard SSRF
                        let (vulns, tests) = engine.ssrf_scanner.scan_parameter(target, param_name, scan_config).await?;
                        all_vulnerabilities.extend(vulns);
                        total_tests += tests as u64;

                        // Blind SSRF with OOB callback (also requires authorization)
                        if scan_token.is_module_authorized(module_ids::advanced_scanning::SSRF_BLIND) {
                            info!("    Testing Blind SSRF on '{}'", param_name);
                            let (blind_vulns, blind_tests) = engine.ssrf_blind_scanner.scan_parameter(target, param_name, scan_config).await?;
                            all_vulnerabilities.extend(blind_vulns);
                            total_tests += blind_tests as u64;
                        }
                    }
                } else {
                    info!("  - Skipping SSRF (no URL-like parameters found)");
                }
            }
        } else {
            info!("  [SKIP] SSRF scanner requires Professional or higher license");
        }
    }

    // Phase 2: Configuration & Header testing
    info!("Phase 2: Security configuration testing");

    // Security Headers (FREE tier)
    info!("  - Testing Security Headers");
    let (vulns, tests) = engine.security_headers_scanner.scan(target, scan_config).await?;
    all_vulnerabilities.extend(vulns);
    total_tests += tests as u64;

    // CORS (FREE tier)
    info!("  - Testing CORS Configuration");
    let (vulns, tests) = engine.cors_scanner.scan(target, scan_config).await?;
    all_vulnerabilities.extend(vulns);
    total_tests += tests as u64;

    // CORS Misconfiguration (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::CORS_MISCONFIG) {
        info!("  - Testing CORS Misconfiguration");
        let (vulns, tests) = engine.cors_misconfiguration_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // CSRF (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::CSRF_SCANNER) {
        info!("  - Testing CSRF Protection");
        let (vulns, tests) = engine.csrf_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Clickjacking (FREE tier)
    info!("  - Testing Clickjacking Protection");
    let (vulns, tests) = engine.clickjacking_scanner.scan(target, scan_config).await?;
    all_vulnerabilities.extend(vulns);
    total_tests += tests as u64;

    // Phase 3: Authentication & Authorization
    info!("Phase 3: Authentication testing");

    // Skip tests already done in early auth phase
    if !auth_tests_done {
        // JWT vulnerabilities (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::JWT_SCANNER) {
            info!("  - Testing JWT Security");
            if let Some(ref token) = scan_config.auth_token {
                let (vulns, tests) = engine.jwt_scanner.scan_jwt(target, token, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }

            // JWT Vulnerabilities Scanner (general JWT analysis)
            info!("  - Testing JWT Vulnerabilities");
            let (vulns, tests) = engine.jwt_vulnerabilities_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // Auth Bypass (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::AUTH_BYPASS) {
            info!("  - Testing Authentication Bypass");
            let (vulns, tests) = engine.auth_bypass_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // IDOR (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::IDOR_SCANNER) {
            info!("  - Testing IDOR");
            let (vulns, tests) = engine.idor_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // BOLA (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::BOLA_SCANNER) {
            info!("  - Testing BOLA");
            let (vulns, tests) = engine.bola_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    } else {
        info!("  - JWT/Auth Bypass/IDOR/BOLA already tested in early auth phase");
    }

    // OAuth (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::OAUTH_SCANNER) {
        info!("  - Testing OAuth Security");
        let (vulns, tests) = engine.oauth_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Session Management (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::SESSION_MANAGEMENT) {
        info!("  - Testing Session Management");
        let (vulns, tests) = engine.session_management_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Advanced Auth (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::ADVANCED_AUTH) {
        info!("  - Testing Advanced Authentication");
        let (vulns, tests) = engine.advanced_auth_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Auth Manager (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::AUTH_MANAGER) {
        info!("  - Testing Authentication Management");
        let (vulns, tests) = engine.auth_manager_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // MFA (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::MFA_SCANNER) {
        info!("  - Testing MFA Security");
        let (vulns, tests) = engine.mfa_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // SAML (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::SAML_SCANNER) {
        info!("  - Testing SAML Security");
        let (vulns, tests) = engine.saml_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // WebAuthn/FIDO2 (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::WEBAUTHN_SCANNER) {
        info!("  - Testing WebAuthn/FIDO2 Security");
        let (vulns, tests) = engine.webauthn_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Phase 4: API Security
    info!("Phase 4: API security testing");

    // Skip GraphQL/API tests if already done in early auth phase
    if !auth_tests_done {
        // GraphQL (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::GRAPHQL_SCANNER) {
            info!("  - Testing GraphQL Security");
            let (vulns, tests) = engine.graphql_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;

            // GraphQL Security (advanced GraphQL testing)
            info!("  - Testing Advanced GraphQL Security");
            let (vulns, tests) = engine.graphql_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // API Security (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::API_SECURITY) {
            info!("  - Testing API Security");
            let (vulns, tests) = engine.api_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    } else {
        info!("  - GraphQL/API Security already tested in early auth phase");
    }

    // gRPC (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::GRPC_SCANNER) {
        info!("  - Testing gRPC Security");
        let (vulns, tests) = engine.grpc_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Advanced API Fuzzing on discovered endpoints (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::API_FUZZER) {
        if !js_miner_results.api_endpoints.is_empty() || !js_miner_results.graphql_endpoints.is_empty() {
            info!("  - Running Advanced API Fuzzing on {} discovered endpoints",
                  js_miner_results.api_endpoints.len() + js_miner_results.graphql_endpoints.len());

            // Fuzz discovered API endpoints
            for api_url in &js_miner_results.api_endpoints {
                let (vulns, tests) = engine.api_fuzzer_scanner.scan(api_url, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }

            // Fuzz discovered GraphQL endpoints with injection testing
            for gql_url in &js_miner_results.graphql_endpoints {
                info!("  - Testing GraphQL injection on: {}", gql_url);
                let (vulns, tests) = engine.api_fuzzer_scanner.scan(gql_url, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        }
    }

    // Phase 5: Advanced injection testing (TECHNOLOGY-AWARE)
    info!("Phase 5: Advanced injection testing");

    // XXE - Only test if real params exist and not a static/JS-only site (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::XXE_SCANNER) {
        if has_real_params && !is_static_site && !is_nodejs_stack {
            info!("  - Testing XXE");
            for (param_name, _) in &test_params {
                let (vulns, tests) = engine.xxe_scanner.scan_parameter(target, param_name, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        } else {
            info!("  - Skipping XXE (not applicable for detected stack)");
        }
    }

    // SSTI - Only for Python (Jinja2, Django) or PHP (Twig) or Java (Freemarker) (Professional+)
    // Skip for Next.js/React - they don't use server-side templates
    if scan_token.is_module_authorized(module_ids::advanced_scanning::SSTI_SCANNER) {
        if is_python_stack || is_php_stack || is_java_stack {
            info!("  - Testing Template Injection (SSTI)");
            let (vulns, tests) = engine.template_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;

            // Advanced SSTI Scanner (deeper template analysis)
            if scan_token.is_module_authorized(module_ids::advanced_scanning::SSTI_ADVANCED) {
                info!("  - Testing Advanced SSTI");
                let (vulns, tests) = engine.ssti_advanced_scanner.scan(target, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        } else {
            info!("  - Skipping SSTI (not applicable for Next.js/React stack)");
        }
    }

    // NoSQL Injection - Only test if real params exist and not static site (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::NOSQL_SCANNER) {
        if has_real_params && !is_static_site {
            info!("  - Testing NoSQL Injection");
            for (param_name, _) in &test_params {
                let (vulns, tests) = engine.nosql_scanner.scan_parameter(target, param_name, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }

            // Advanced NoSQL Injection Scanner
            info!("  - Testing Advanced NoSQL Injection");
            let (vulns, tests) = engine.nosql_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        } else {
            info!("  - Skipping NoSQL Injection (no parameters or static site)");
        }
    }

    // LDAP Injection - Only for enterprise/Java/.NET stacks, not modern JS apps (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::LDAP_INJECTION) {
        if is_java_stack || (is_php_stack && !is_nodejs_stack) {
            info!("  - Testing LDAP Injection");
            let (vulns, tests) = engine.ldap_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        } else {
            info!("  - Skipping LDAP Injection (not applicable for detected stack)");
        }
    }

    // Code Injection - Only for PHP, Python, Ruby (eval-type injections) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::CODE_INJECTION) {
        if is_php_stack || is_python_stack {
            info!("  - Testing Code Injection");
            let (vulns, tests) = engine.code_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;

            // SSI Injection (Server Side Includes)
            if scan_token.is_module_authorized(module_ids::advanced_scanning::SSI_INJECTION) {
                info!("  - Testing SSI Injection");
                let (vulns, tests) = engine.ssi_injection_scanner.scan(target, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        } else {
            info!("  - Skipping Code Injection (not applicable for detected stack)");
        }
    }

    // XML Injection - Test for XML-based attacks (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::XML_INJECTION) {
        if has_real_params && !is_static_site && !is_nodejs_stack {
            info!("  - Testing XML Injection");
            let (vulns, tests) = engine.xml_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;

            // XPath Injection
            if scan_token.is_module_authorized(module_ids::advanced_scanning::XPATH_INJECTION) {
                info!("  - Testing XPath Injection");
                let (vulns, tests) = engine.xpath_injection_scanner.scan(target, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        }
    }

    // Deserialization - ONLY for PHP/Java/.NET, NOT for Node.js/Next.js (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::DESERIALIZATION) {
        if is_php_stack || is_java_stack {
            info!("  - Testing Insecure Deserialization");
            let (vulns, tests) = engine.deserialization_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        } else {
            info!("  - Skipping Deserialization (not applicable for Node.js/Next.js stack)");
        }
    }

    // ReDoS - Test parameters for regex denial of service (applies to all stacks) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::REDOS_SCANNER) {
        if has_real_params && !is_static_site {
            info!("  - Testing ReDoS (Regular Expression Denial of Service)");
            for (param_name, _) in &test_params {
                let (vulns, tests) = engine.redos_scanner.scan_parameter(target, param_name, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            }
        }
    }

    // Email Header Injection - Test for email-related parameters (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::EMAIL_HEADER_INJECTION) {
        if has_real_params && !is_static_site {
            info!("  - Testing Email Header Injection");
            let (vulns, tests) = engine.email_header_injection_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Phase 6: Protocol & Transport testing
    info!("Phase 6: Protocol testing");

    // HTTP Smuggling (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::HTTP_SMUGGLING) {
        info!("  - Testing HTTP Smuggling");
        let (vulns, tests) = engine.http_smuggling_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // WebSocket (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::WEBSOCKET_SCANNER) {
        info!("  - Testing WebSocket Security");
        let (vulns, tests) = engine.websocket_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // CRLF Injection (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::CRLF_INJECTION) {
        info!("  - Testing CRLF Injection");
        let (vulns, tests) = engine.crlf_injection_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Host Header Injection (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::HOST_HEADER_INJECTION) {
        info!("  - Testing Host Header Injection");
        let (vulns, tests) = engine.host_header_injection_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Phase 7: Business Logic & Misc
    info!("Phase 7: Business logic testing");

    // Race Conditions (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::RACE_CONDITION) {
        info!("  - Testing Race Conditions");
        let (vulns, tests) = engine.race_condition_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Mass Assignment (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::MASS_ASSIGNMENT) {
        info!("  - Testing Mass Assignment");
        let (vulns, tests) = engine.mass_assignment_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // File Upload (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::FILE_UPLOAD) {
        info!("  - Testing File Upload Security");
        let (vulns, tests) = engine.file_upload_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;

        // File Upload Vulnerabilities (advanced file upload testing)
        info!("  - Testing File Upload Vulnerabilities");
        let (vulns, tests) = engine.file_upload_vulnerabilities_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Open Redirect (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::OPEN_REDIRECT) {
        info!("  - Testing Open Redirect");
        let (vulns, tests) = engine.open_redirect_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Information Disclosure (Free tier - info_disclosure_basic)
    // Note: This is free tier, no authorization check needed
    info!("  - Testing Information Disclosure");
    let (vulns, tests) = engine.information_disclosure_scanner.scan(target, scan_config).await?;
    all_vulnerabilities.extend(vulns);
    total_tests += tests as u64;

    // Sensitive Data (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::SENSITIVE_DATA) {
        info!("  - Testing Sensitive Data Exposure");
        let (vulns, tests) = engine.sensitive_data_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Cache Poisoning (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::CACHE_POISONING) {
        info!("  - Testing Cache Poisoning");
        let (vulns, tests) = engine.cache_poisoning_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Prototype Pollution - ESPECIALLY important for JavaScript/React apps (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::PROTOTYPE_POLLUTION) {
        if is_nodejs_stack {
            info!("  - Testing Prototype Pollution (JS-heavy site detected)");
        } else {
            info!("  - Testing Prototype Pollution");
        }
        let (vulns, tests) = engine.prototype_pollution_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // JavaScript Mining already done in Phase 0.5 with endpoint extraction
    // Results are in js_miner_results variable

    // Business Logic (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::BUSINESS_LOGIC) {
        info!("  - Testing Business Logic Flaws");
        let (vulns, tests) = engine.business_logic_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Framework Vulnerabilities (framework-specific security issues) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::FRAMEWORK_VULNS) {
        info!("  - Testing Framework Vulnerabilities");
        let (vulns, tests) = engine.framework_vulnerabilities_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // ============================================================
    // Framework-Specific Security Scanners (Personal+ tier)
    // ============================================================

    // WordPress Security (only if WordPress detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::WORDPRESS_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("wordpress")) {
            info!("  - Testing WordPress Security");
            let (vulns, tests) = engine.wordpress_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Drupal Security (only if Drupal detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::DRUPAL_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("drupal")) {
            info!("  - Testing Drupal Security");
            let (vulns, tests) = engine.drupal_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Laravel Security (only if Laravel detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::LARAVEL_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("laravel")) {
            info!("  - Testing Laravel Security");
            let (vulns, tests) = engine.laravel_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Django Security (only if Django detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::DJANGO_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("django")) {
            info!("  - Testing Django Security");
            let (vulns, tests) = engine.django_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Express Security (only if Express detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::EXPRESS_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("express")) {
            info!("  - Testing Express.js Security");
            let (vulns, tests) = engine.express_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Next.js Security (only if Next.js detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::NEXTJS_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("next")) {
            info!("  - Testing Next.js Security");
            let (vulns, tests) = engine.nextjs_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // SvelteKit Security (only if SvelteKit detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::SVELTEKIT_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("svelte")) {
            info!("  - Testing SvelteKit Security");
            let (vulns, tests) = engine.sveltekit_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // React Security (only if React detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::REACT_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("react")) {
            info!("  - Testing React Security");
            let (vulns, tests) = engine.react_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Liferay Security (only if Liferay detected) (Personal+)
    if scan_token.is_module_authorized(module_ids::cms_security::LIFERAY_SCANNER) {
        if detected_technologies.iter().any(|t| t.to_lowercase().contains("liferay")) {
            info!("  - Testing Liferay Security");
            let (vulns, tests) = engine.liferay_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // ============================================================
    // Server Misconfiguration Scanners (Professional+ tier)
    // ============================================================

    // Tomcat Misconfiguration (only if Tomcat/Java detected) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::TOMCAT_MISCONFIG) {
        if is_java_stack || detected_technologies.iter().any(|t| t.to_lowercase().contains("tomcat")) {
            info!("  - Testing Tomcat Misconfigurations");
            let (vulns, tests) = engine.tomcat_misconfig_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Varnish Misconfiguration (check for caching issues) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::VARNISH_MISCONFIG) {
        info!("  - Testing Varnish/Cache Misconfigurations");
        let (vulns, tests) = engine.varnish_misconfig_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // ============================================================
    // General Security Scanners (Professional+ tier)
    // ============================================================

    // HTTP Parameter Pollution (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::HPP_SCANNER) {
        if has_real_params && !is_static_site {
            info!("  - Testing HTTP Parameter Pollution");
            let (vulns, tests) = engine.hpp_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // WAF Bypass Testing (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::WAF_BYPASS) {
        info!("  - Testing WAF Bypass Techniques");
        let (vulns, tests) = engine.waf_bypass_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Merlin Scanner - JavaScript Library Vulnerability Detection (Professional+)
    // Always run for SPAs and sites with JavaScript - detects Vue, React, axios, jQuery, etc.
    if scan_token.is_module_authorized(module_ids::advanced_scanning::MERLIN_SCANNER) {
        // For SPAs, we already detected JS files via headless browser or crawler
        // Also check baseline response for any JS indicators
        let has_js = baseline_response.as_ref().map_or(false, |r| {
            r.body.contains("<script") ||
            r.body.contains(".js\"") ||
            r.body.contains(".js'") ||
            r.body.contains("application/javascript") ||
            r.body.contains("text/javascript")
        });

        // Run Merlin if: detected JS, is SPA/Node.js stack, or discovered any scripts during crawl
        if has_js || is_spa_detected || is_nodejs_stack {
            info!("  - Running Merlin JS Library Vulnerability Scanner");
            let (vulns, tests) = engine.merlin_scanner.scan(target, scan_config).await?;
            let vuln_count = vulns.len();
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
            if vuln_count > 0 {
                info!("[SUCCESS] [Merlin] Found {} vulnerable JavaScript libraries", vuln_count);
            }
        } else {
            info!("  - Skipping Merlin (no JavaScript detected)");
        }
    }

    // JS Sensitive Info Scanner (for JavaScript sites) (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::JS_SENSITIVE_INFO) {
        if is_nodejs_stack {
            info!("  - Scanning JavaScript for Sensitive Information");
            let (vulns, tests) = engine.js_sensitive_info_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    // Source Map Detection Scanner (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::SOURCE_MAP_DETECTION) {
        info!("  - Scanning for Exposed Source Maps");
        let (vulns, tests) = engine.source_map_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Favicon Hash Detection Scanner (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::FAVICON_HASH_DETECTION) {
        info!("  - Scanning Favicon for Technology Fingerprinting");
        let (vulns, tests) = engine.favicon_hash_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Rate Limiting Scanner (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::RATE_LIMITING) {
        info!("  - Testing Rate Limiting");
        let (vulns, tests) = engine.rate_limiting_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // HTTP/3 Scanner (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::HTTP3_SCANNER) {
        info!("  - Testing HTTP/3 (QUIC) Security");
        let (vulns, tests) = engine.http3_scanner.scan(target, scan_config).await?;
        all_vulnerabilities.extend(vulns);
        total_tests += tests as u64;
    }

    // Firebase Scanner - only if Firebase detected (Professional+)
    if scan_token.is_module_authorized(module_ids::advanced_scanning::FIREBASE_SCANNER) {
        if let Some(ref response) = baseline_response {
            if detect_technology("firebase", &response.body, &response.headers) {
                info!("  - Testing Firebase Security");
                let (vulns, tests) = engine.firebase_scanner.scan(target, scan_config).await?;
                all_vulnerabilities.extend(vulns);
                total_tests += tests as u64;
            } else {
                info!("  - Skipping Firebase (not detected)");
            }
        }
    }

    // Phase 8: Cloud & Container (Thorough/Insane modes) (Team+ tier)
    if scan_config.enable_cloud_scanning() {
        info!("Phase 8: Cloud & Container security");

        // Cloud Storage (Team+)
        if scan_token.is_module_authorized(module_ids::cloud_scanning::CLOUD_STORAGE) {
            info!("  - Testing Cloud Storage Misconfigurations");
            let (vulns, tests) = engine.cloud_storage_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;

            // Scan discovered S3 buckets from JS Mining - DEDUPLICATE by bucket name
            if !js_miner_results.s3_buckets.is_empty() {
                // Extract unique bucket names from S3 URLs to avoid scanning same bucket multiple times
                let unique_s3_buckets: std::collections::HashSet<String> = js_miner_results.s3_buckets.iter()
                    .filter_map(|url| extract_s3_bucket_url(url))
                    .collect();
                info!("  - Scanning {} unique S3 buckets (from {} URLs)", unique_s3_buckets.len(), js_miner_results.s3_buckets.len());
                for s3_bucket_url in unique_s3_buckets {
                    info!("    Scanning S3 bucket: {}", s3_bucket_url);
                    let (vulns, tests) = engine.cloud_storage_scanner.scan(&s3_bucket_url, scan_config).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            }

            // Scan discovered Azure Blob URLs from JS Mining - DEDUPLICATE by container
            if !js_miner_results.azure_blobs.is_empty() {
                let unique_azure_containers: std::collections::HashSet<String> = js_miner_results.azure_blobs.iter()
                    .filter_map(|url| extract_azure_container_url(url))
                    .collect();
                info!("  - Scanning {} unique Azure containers (from {} URLs)", unique_azure_containers.len(), js_miner_results.azure_blobs.len());
                for azure_url in unique_azure_containers {
                    info!("    Scanning Azure container: {}", azure_url);
                    let (vulns, tests) = engine.cloud_storage_scanner.scan(&azure_url, scan_config).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            }

            // Scan discovered GCS bucket URLs from JS Mining - DEDUPLICATE by bucket name
            if !js_miner_results.gcs_buckets.is_empty() {
                let unique_gcs_buckets: std::collections::HashSet<String> = js_miner_results.gcs_buckets.iter()
                    .filter_map(|url| extract_gcs_bucket_url(url))
                    .collect();
                info!("  - Scanning {} unique GCS buckets (from {} URLs)", unique_gcs_buckets.len(), js_miner_results.gcs_buckets.len());
                for gcs_url in unique_gcs_buckets {
                    info!("    Scanning GCS bucket: {}", gcs_url);
                    let (vulns, tests) = engine.cloud_storage_scanner.scan(&gcs_url, scan_config).await?;
                    all_vulnerabilities.extend(vulns);
                    total_tests += tests as u64;
                }
            }
        }

        // Container Security (Team+)
        if scan_token.is_module_authorized(module_ids::cloud_scanning::CONTAINER_SCANNER) {
            info!("  - Testing Container Security");
            let (vulns, tests) = engine.container_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // API Gateway (Professional+)
        if scan_token.is_module_authorized(module_ids::advanced_scanning::API_GATEWAY) {
            info!("  - Testing API Gateway Security");
            let (vulns, tests) = engine.api_gateway_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }

        // Cloud Security (general cloud security testing) (Team+)
        if scan_token.is_module_authorized(module_ids::cloud_scanning::CLOUD_SECURITY) {
            info!("  - Testing Cloud Security");
            let (vulns, tests) = engine.cloud_security_scanner.scan(target, scan_config).await?;
            all_vulnerabilities.extend(vulns);
            total_tests += tests as u64;
        }
    }

    let elapsed = start_time.elapsed();

    info!("");
    info!("Scan completed: {} vulnerabilities, {} tests, {:.2}s",
        all_vulnerabilities.len(), total_tests, elapsed.as_secs_f64());

    // Create preliminary results for hashing
    let mut results = ScanResults {
        scan_id: job.scan_id.clone(),
        target: target.clone(),
        tests_run: total_tests,
        vulnerabilities: all_vulnerabilities,
        started_at,
        completed_at: chrono::Utc::now().to_rfc3339(),
        duration_seconds: elapsed.as_secs_f64(),
        early_terminated: false,
        termination_reason: None,
        scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        license_signature: Some(license::get_license_signature()),
        quantum_signature: None,
        authorization_token_id: Some(scan_token.token.clone()),
    };

    // ============================================================
    // QUANTUM-SAFE SIGNING - MANDATORY FOR ALL RESULTS
    // ============================================================
    // Sign the results with the scan token to prove authenticity.
    // This creates a cryptographic audit trail that cannot be forged.
    let results_hash = signing::hash_results(&results)
        .map_err(|e| anyhow::anyhow!("Failed to hash results: {}", e))?;

    // Collect privacy-safe findings summary (only counts, no URLs or details)
    let findings_summary = signing::FindingsSummary::from_vulnerabilities(&results.vulnerabilities);

    match signing::sign_results(
        &results_hash,
        &scan_token,
        vec![],
        Some(signing::ScanMetadata {
            targets_count: Some(1),
            scanner_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            scan_duration_ms: Some(elapsed.as_millis() as u64),
        }),
        Some(findings_summary),
        Some(vec![target.to_string()]),
    ).await {
        Ok(signature) => {
            info!("[SIGNED] Results signed with algorithm: {}", signature.algorithm);
            results.quantum_signature = Some(signature);
        }
        Err(SigningError::ServerUnreachable(msg)) => {
            // STRICT MODE: Signing requires server connection
            error!("Failed to sign results - server unreachable: {}", msg);
            error!("Results cannot be verified without server signature.");
            return Err(anyhow::anyhow!("Signing server unreachable: {}", msg));
        }
        Err(e) => {
            error!("Failed to sign results: {}", e);
            return Err(anyhow::anyhow!("Failed to sign results: {}", e));
        }
    }

    Ok(results)
}

fn print_banner() {
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
    println!("    Wraps around your attack surface");
    print!("\x1b[0m\x1b[92m");
    println!("      v2.0 - Happy Holidays - (c) 2025");
    print!("\x1b[0m");
    println!();
}

fn print_vulnerability_summary(results: &ScanResults) {
    use lonkero_scanner::types::Severity;

    let critical = results.vulnerabilities.iter().filter(|v| v.severity == Severity::Critical).count();
    let high = results.vulnerabilities.iter().filter(|v| v.severity == Severity::High).count();
    let medium = results.vulnerabilities.iter().filter(|v| v.severity == Severity::Medium).count();
    let low = results.vulnerabilities.iter().filter(|v| v.severity == Severity::Low).count();
    let info = results.vulnerabilities.iter().filter(|v| v.severity == Severity::Info).count();

    println!();
    println!("{}", "-".repeat(60));
    println!("VULNERABILITIES FOUND: {}", results.vulnerabilities.len());
    println!("{}", "-".repeat(60));

    if critical > 0 {
        println!("  [CRITICAL] {}", critical);
    }
    if high > 0 {
        println!("  [HIGH]     {}", high);
    }
    if medium > 0 {
        println!("  [MEDIUM]   {}", medium);
    }
    if low > 0 {
        println!("  [LOW]      {}", low);
    }
    if info > 0 {
        println!("  [INFO]     {}", info);
    }

    // Print each vulnerability
    for vuln in &results.vulnerabilities {
        let severity_str = match vuln.severity {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]    ",
            Severity::Medium => "[MEDIUM]  ",
            Severity::Low => "[LOW]     ",
            Severity::Info => "[INFO]    ",
        };

        println!();
        println!("{} {}", severity_str, vuln.vuln_type);
        println!("  URL:       {}", vuln.url);
        if let Some(param) = &vuln.parameter {
            println!("  Parameter: {}", param);
        }
        println!("  CWE:       {}", vuln.cwe);
        println!("  CVSS:      {:.1}", vuln.cvss);
    }

    println!("{}", "-".repeat(60));
}

fn write_results(results: &[ScanResults], path: &PathBuf, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Pdf => {
            // PDF requires binary output
            let pdf_data = generate_pdf_report(results)?;
            std::fs::write(path, pdf_data)?;
        }
        OutputFormat::Xlsx => {
            // XLSX requires binary output
            let xlsx_data = generate_xlsx_report(results)?;
            std::fs::write(path, xlsx_data)?;
        }
        _ => {
            let content = match format {
                OutputFormat::Json => serde_json::to_string_pretty(results)?,
                OutputFormat::Html => generate_html_report(results)?,
                OutputFormat::Markdown => generate_markdown_report(results)?,
                OutputFormat::Sarif => generate_sarif_report(results)?,
                OutputFormat::Csv => generate_csv_report(results)?,
                OutputFormat::Junit => generate_junit_report(results)?,
                _ => serde_json::to_string_pretty(results)?, // Fallback to JSON
            };
            std::fs::write(path, content)?;
        }
    }
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn generate_html_report(results: &[ScanResults]) -> Result<String> {
    let mut html = String::from(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lonkero Security Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon-green: #39ff14;
            --neon-green-dim: rgba(57, 255, 20, 0.3);
            --neon-glow: 0 0 20px rgba(57, 255, 20, 0.4), 0 0 40px rgba(57, 255, 20, 0.2);
            --bg-dark: #0a0a0a;
            --bg-darker: #050505;
            --bg-card: #0f0f0f;
            --bg-card-alt: #141414;
            --border-color: #1a1a1a;
            --border-glow: #39ff14;
            --text-primary: #e0e0e0;
            --text-secondary: #666666;
            --critical: #ff3366;
            --critical-bg: rgba(255, 51, 102, 0.15);
            --high: #ff6b35;
            --high-bg: rgba(255, 107, 53, 0.15);
            --medium: #ffcc00;
            --medium-bg: rgba(255, 204, 0, 0.15);
            --low: #00b4d8;
            --low-bg: rgba(0, 180, 216, 0.15);
            --info: #6c757d;
            --info-bg: rgba(108, 117, 125, 0.15);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-dark);
            background-image:
                radial-gradient(ellipse at top, rgba(57, 255, 20, 0.03) 0%, transparent 50%),
                radial-gradient(ellipse at bottom, rgba(57, 255, 20, 0.02) 0%, transparent 50%);
            color: var(--text-primary);
            line-height: 1.7;
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-darker) 100%);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px 50px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--neon-green), transparent);
            opacity: 0.8;
        }
        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .logo {
            height: 45px;
            filter: drop-shadow(0 0 8px rgba(57, 255, 20, 0.3));
        }
        .title-group h1 {
            font-size: 2em;
            font-weight: 700;
            color: var(--neon-green);
            text-shadow: var(--neon-glow);
            letter-spacing: -0.5px;
        }
        .title-group .subtitle {
            color: var(--text-secondary);
            font-size: 0.85em;
            margin-top: 4px;
        }
        .scan-meta {
            display: flex;
            gap: 30px;
            font-size: 0.8em;
            color: var(--text-secondary);
        }
        .scan-meta-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .scan-meta-label { color: var(--text-secondary); font-size: 0.9em; }
        .scan-meta-value { color: var(--neon-green); font-weight: 500; }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin: 30px 0;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            border-radius: 12px 12px 0 0;
        }
        .stat-card.critical::before { background: var(--critical); box-shadow: 0 0 15px var(--critical); }
        .stat-card.high::before { background: var(--high); box-shadow: 0 0 15px var(--high); }
        .stat-card.medium::before { background: var(--medium); box-shadow: 0 0 15px var(--medium); }
        .stat-card.low::before { background: var(--low); box-shadow: 0 0 15px var(--low); }
        .stat-card.info::before { background: var(--info); }
        .stat-number {
            font-size: 2.5em;
            font-weight: 700;
            display: block;
            margin-bottom: 8px;
        }
        .stat-card.critical .stat-number { color: var(--critical); text-shadow: 0 0 20px var(--critical); }
        .stat-card.high .stat-number { color: var(--high); text-shadow: 0 0 20px var(--high); }
        .stat-card.medium .stat-number { color: var(--medium); text-shadow: 0 0 20px var(--medium); }
        .stat-card.low .stat-number { color: var(--low); text-shadow: 0 0 20px var(--low); }
        .stat-card.info .stat-number { color: var(--info); }
        .stat-label {
            font-size: 0.85em;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Section */
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 24px;
        }
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        .section-title {
            font-size: 1.2em;
            font-weight: 600;
            color: var(--neon-green);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .target-badge {
            background: var(--bg-darker);
            border: 1px solid var(--neon-green);
            color: var(--neon-green);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .meta-info {
            display: flex;
            gap: 24px;
            font-size: 0.8em;
            color: var(--text-secondary);
            margin-bottom: 20px;
        }
        .meta-info span { color: var(--neon-green); }

        /* Vulnerability Cards */
        .vuln-list { display: flex; flex-direction: column; gap: 12px; }
        .vuln-card {
            background: var(--bg-darker);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            transition: all 0.2s ease;
        }
        .vuln-card:hover {
            border-color: var(--neon-green-dim);
            box-shadow: 0 0 20px rgba(57, 255, 20, 0.08);
        }
        .vuln-header {
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            cursor: pointer;
            border-left: 4px solid transparent;
        }
        .vuln-critical .vuln-header { border-left-color: var(--critical); background: var(--critical-bg); }
        .vuln-high .vuln-header { border-left-color: var(--high); background: var(--high-bg); }
        .vuln-medium .vuln-header { border-left-color: var(--medium); background: var(--medium-bg); }
        .vuln-low .vuln-header { border-left-color: var(--low); background: var(--low-bg); }
        .vuln-info .vuln-header { border-left-color: var(--info); background: var(--info-bg); }
        .vuln-title-row {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
        }
        .severity-badge {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .vuln-critical .severity-badge { background: var(--critical); color: #fff; }
        .vuln-high .severity-badge { background: var(--high); color: #fff; }
        .vuln-medium .severity-badge { background: var(--medium); color: #000; }
        .vuln-low .severity-badge { background: var(--low); color: #fff; }
        .vuln-info .severity-badge { background: var(--info); color: #fff; }
        .vuln-type {
            font-weight: 600;
            font-size: 0.95em;
            color: var(--text-primary);
        }
        .vuln-body {
            padding: 20px 24px;
            background: var(--bg-card);
            border-top: 1px solid var(--border-color);
        }
        .vuln-details {
            display: grid;
            gap: 16px;
        }
        .detail-row {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 16px;
            font-size: 0.85em;
        }
        .detail-label {
            color: var(--text-secondary);
            font-weight: 500;
        }
        .detail-value {
            color: var(--text-primary);
            word-break: break-word;
        }
        .detail-value code {
            background: var(--bg-darker);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            color: var(--neon-green);
            border: 1px solid var(--border-color);
        }
        .cvss-score {
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .cvss-value {
            background: var(--bg-darker);
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 600;
        }

        /* PoC Code Blocks */
        .poc-code, .evidence-code {
            background: var(--bg-darker);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--neon-green);
            border-radius: 6px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
            color: var(--neon-green);
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
            max-height: 300px;
            overflow-y: auto;
        }
        .evidence-code {
            border-left-color: var(--medium);
            color: var(--text-primary);
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
            font-size: 0.85em;
        }
        footer a {
            color: var(--neon-green);
            text-decoration: none;
            font-weight: 500;
            transition: text-shadow 0.2s ease;
        }
        footer a:hover {
            text-shadow: 0 0 10px var(--neon-green);
        }
        footer .footer-brand {
            font-size: 1.1em;
            margin-bottom: 8px;
        }

        /* Animations */
        @keyframes glow-pulse {
            0%, 100% { opacity: 0.8; }
            50% { opacity: 1; }
        }

        /* Responsive */
        @media (max-width: 768px) {
            body { padding: 20px 10px; }
            .header { padding: 24px; }
            .header-content { flex-direction: column; align-items: flex-start; }
            .title-group h1 { font-size: 1.5em; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .detail-row { grid-template-columns: 1fr; gap: 4px; }
            .scan-meta { flex-wrap: wrap; gap: 16px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="brand">
                    <img src="https://bountyyfi.s3.eu-north-1.amazonaws.com/bountyy.fi-2.png" alt="Bountyy" class="logo">
                    <div class="title-group">
                        <h1>Lonkero</h1>
                        <div class="subtitle">Security Scan Report</div>
                    </div>
                </div>
            </div>
        </div>
"#);

    for result in results {
        let critical = result.vulnerabilities.iter().filter(|v| v.severity == lonkero_scanner::types::Severity::Critical).count();
        let high = result.vulnerabilities.iter().filter(|v| v.severity == lonkero_scanner::types::Severity::High).count();
        let medium = result.vulnerabilities.iter().filter(|v| v.severity == lonkero_scanner::types::Severity::Medium).count();
        let low = result.vulnerabilities.iter().filter(|v| v.severity == lonkero_scanner::types::Severity::Low).count();
        let info = result.vulnerabilities.iter().filter(|v| v.severity == lonkero_scanner::types::Severity::Info).count();

        html.push_str(&format!(r#"
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Target</h2>
                <span class="target-badge">{}</span>
            </div>

            <div class="stats-grid">
                <div class="stat-card critical">
                    <span class="stat-number">{}</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="stat-card high">
                    <span class="stat-number">{}</span>
                    <span class="stat-label">High</span>
                </div>
                <div class="stat-card medium">
                    <span class="stat-number">{}</span>
                    <span class="stat-label">Medium</span>
                </div>
                <div class="stat-card low">
                    <span class="stat-number">{}</span>
                    <span class="stat-label">Low</span>
                </div>
                <div class="stat-card info">
                    <span class="stat-number">{}</span>
                    <span class="stat-label">Info</span>
                </div>
            </div>

            <div class="meta-info">
                Tests: <span>{}</span> &nbsp;|&nbsp; Duration: <span>{:.2}s</span> &nbsp;|&nbsp; Completed: <span>{}</span>
            </div>

            <div class="vuln-list">
"#, html_escape(&result.target), critical, high, medium, low, info, result.tests_run, result.duration_seconds, html_escape(&result.completed_at)));

        for vuln in &result.vulnerabilities {
            let severity_class = match vuln.severity {
                lonkero_scanner::types::Severity::Critical => "vuln-critical",
                lonkero_scanner::types::Severity::High => "vuln-high",
                lonkero_scanner::types::Severity::Medium => "vuln-medium",
                lonkero_scanner::types::Severity::Low => "vuln-low",
                lonkero_scanner::types::Severity::Info => "vuln-info",
            };
            let severity_label = match vuln.severity {
                lonkero_scanner::types::Severity::Critical => "Critical",
                lonkero_scanner::types::Severity::High => "High",
                lonkero_scanner::types::Severity::Medium => "Medium",
                lonkero_scanner::types::Severity::Low => "Low",
                lonkero_scanner::types::Severity::Info => "Info",
            };

            // Build PoC/Payload section if payload exists
            let poc_section = if !vuln.payload.is_empty() {
                format!(r#"
                            <div class="detail-row">
                                <span class="detail-label">PoC Payload</span>
                                <span class="detail-value"><pre class="poc-code">{}</pre></span>
                            </div>"#, html_escape(&vuln.payload))
            } else {
                String::new()
            };

            // Build Evidence section if evidence exists
            let evidence_section = if let Some(ref evidence) = vuln.evidence {
                if !evidence.is_empty() {
                    format!(r#"
                            <div class="detail-row">
                                <span class="detail-label">Evidence</span>
                                <span class="detail-value"><pre class="evidence-code">{}</pre></span>
                            </div>"#, html_escape(evidence))
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            html.push_str(&format!(r#"
                <div class="vuln-card {}">
                    <div class="vuln-header">
                        <div class="vuln-title-row">
                            <span class="severity-badge">{}</span>
                            <span class="vuln-type">{}</span>
                        </div>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-details">
                            <div class="detail-row">
                                <span class="detail-label">URL</span>
                                <span class="detail-value"><code>{}</code></span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">Parameter</span>
                                <span class="detail-value">{}</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">CWE</span>
                                <span class="detail-value">{}</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">CVSS</span>
                                <span class="detail-value cvss-score"><span class="cvss-value">{:.1}</span></span>
                            </div>{}{}
                            <div class="detail-row">
                                <span class="detail-label">Description</span>
                                <span class="detail-value">{}</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">Remediation</span>
                                <span class="detail-value">{}</span>
                            </div>
                        </div>
                    </div>
                </div>
"#, severity_class, severity_label, html_escape(&vuln.vuln_type), html_escape(&vuln.url), html_escape(vuln.parameter.as_deref().unwrap_or("-")), html_escape(&vuln.cwe), vuln.cvss, poc_section, evidence_section, html_escape(&vuln.description), html_escape(&vuln.remediation)));
        }

        html.push_str(r#"
            </div>
        </div>
"#);
    }

    let current_year = chrono::Utc::now().format("%Y");
    html.push_str(&format!(r#"
        <footer>
            <div class="footer-brand">
                Generated by <a href="https://lonkero.bountyy.fi/en" target="_blank"><strong>Lonkero</strong></a> - Wraps around your attack surface
            </div>
            <div>&copy; {} <a href="https://bountyy.fi" target="_blank">Bountyy Oy</a> | All rights reserved</div>
        </footer>
    </div>
</body>
</html>"#, current_year));

    Ok(html)
}

fn generate_markdown_report(results: &[ScanResults]) -> Result<String> {
    let mut md = String::from("# Lonkero Security Scan Report\n\n");

    for result in results {
        md.push_str(&format!("## Target: {}\n\n", result.target));
        md.push_str(&format!("- **Tests Run:** {}\n", result.tests_run));
        md.push_str(&format!("- **Duration:** {:.2}s\n", result.duration_seconds));
        md.push_str(&format!("- **Vulnerabilities Found:** {}\n\n", result.vulnerabilities.len()));

        if !result.vulnerabilities.is_empty() {
            md.push_str("### Vulnerabilities\n\n");
            md.push_str("| Severity | Type | URL | CWE | CVSS |\n");
            md.push_str("|----------|------|-----|-----|------|\n");

            for vuln in &result.vulnerabilities {
                md.push_str(&format!("| {:?} | {} | {} | {} | {:.1} |\n",
                    vuln.severity, vuln.vuln_type, vuln.url, vuln.cwe, vuln.cvss));
            }

            md.push_str("\n---\n\n");

            for vuln in &result.vulnerabilities {
                md.push_str(&format!("#### {} - {:?}\n\n", vuln.vuln_type, vuln.severity));
                md.push_str(&format!("- **URL:** `{}`\n", vuln.url));
                if let Some(param) = &vuln.parameter {
                    md.push_str(&format!("- **Parameter:** `{}`\n", param));
                }
                md.push_str(&format!("- **CWE:** {}\n", vuln.cwe));
                md.push_str(&format!("- **CVSS:** {:.1}\n\n", vuln.cvss));
                md.push_str(&format!("**Description:** {}\n\n", vuln.description));
                md.push_str(&format!("**Remediation:** {}\n\n", vuln.remediation));
                md.push_str("---\n\n");
            }
        }
    }

    let current_year = chrono::Utc::now().format("%Y");
    md.push_str(&format!("\n---\n*Generated by Lonkero v2.0.0 | (c) {} Bountyy Oy*\n", current_year));

    Ok(md)
}

fn generate_sarif_report(results: &[ScanResults]) -> Result<String> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": results.iter().map(|r| {
            serde_json::json!({
                "tool": {
                    "driver": {
                        "name": "Lonkero",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/bountyyfi/lonkero"
                    }
                },
                "results": r.vulnerabilities.iter().map(|v| {
                    serde_json::json!({
                        "ruleId": v.cwe.clone(),
                        "level": match v.severity {
                            lonkero_scanner::types::Severity::Critical | lonkero_scanner::types::Severity::High => "error",
                            lonkero_scanner::types::Severity::Medium => "warning",
                            _ => "note"
                        },
                        "message": {
                            "text": v.description.clone()
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": v.url.clone()
                                }
                            }
                        }]
                    })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn generate_csv_report(results: &[ScanResults]) -> Result<String> {
    let mut csv = String::from("Target,Vulnerability Type,Severity,URL,Parameter,CWE,CVSS,Description\n");

    for result in results {
        for vuln in &result.vulnerabilities {
            csv.push_str(&format!("\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\",\"{}\",\"{:.1}\",\"{}\"\n",
                result.target,
                vuln.vuln_type,
                vuln.severity,
                vuln.url,
                vuln.parameter.as_deref().unwrap_or(""),
                vuln.cwe,
                vuln.cvss,
                vuln.description.replace("\"", "\"\"")
            ));
        }
    }

    Ok(csv)
}

fn generate_pdf_report(results: &[ScanResults]) -> Result<Vec<u8>> {
    use lonkero_scanner::reporting::types::{
        BrandingConfig, EnhancedReport, ExecutiveSummary, VulnerabilityBreakdown,
        ComplianceMapping, RiskAssessment,
    };
    use lonkero_scanner::reporting::formats::pdf::PdfReportGenerator;
    use std::collections::HashMap;

    // Aggregate all vulnerabilities
    let mut all_vulns = Vec::new();
    let mut target = String::new();
    let mut scan_id = String::new();

    for result in results {
        if target.is_empty() {
            target = result.target.clone();
            scan_id = result.scan_id.clone();
        }
        all_vulns.extend(result.vulnerabilities.clone());
    }

    // Count severities
    let critical_count = all_vulns.iter().filter(|v| matches!(v.severity, lonkero_scanner::types::Severity::Critical)).count();
    let high_count = all_vulns.iter().filter(|v| matches!(v.severity, lonkero_scanner::types::Severity::High)).count();
    let medium_count = all_vulns.iter().filter(|v| matches!(v.severity, lonkero_scanner::types::Severity::Medium)).count();
    let low_count = all_vulns.iter().filter(|v| matches!(v.severity, lonkero_scanner::types::Severity::Low)).count();
    let info_count = all_vulns.iter().filter(|v| matches!(v.severity, lonkero_scanner::types::Severity::Info)).count();

    let risk_score = (critical_count as f64 * 10.0 + high_count as f64 * 7.0 + medium_count as f64 * 4.0 + low_count as f64 * 1.0) / 10.0;
    let risk_level = if critical_count > 0 { "Critical" } else if high_count > 0 { "High" } else if medium_count > 0 { "Medium" } else if low_count > 0 { "Low" } else { "Info" };

    let scan_results = lonkero_scanner::types::ScanResults {
        scan_id: scan_id.clone(),
        target: target.clone(),
        tests_run: results.iter().map(|r| r.tests_run).sum(),
        vulnerabilities: all_vulns,
        started_at: results.first().map(|r| r.started_at.clone()).unwrap_or_default(),
        completed_at: results.last().map(|r| r.completed_at.clone()).unwrap_or_default(),
        duration_seconds: results.iter().map(|r| r.duration_seconds).sum(),
        early_terminated: false,
        termination_reason: None,
        scanner_version: Some("2.0.0".to_string()),
        license_signature: Some(String::new()),
        quantum_signature: None,
        authorization_token_id: None,
    };

    let enhanced_report = EnhancedReport {
        scan_results,
        executive_summary: ExecutiveSummary {
            target: target.clone(),
            scan_date: chrono::Utc::now().to_rfc3339(),
            total_vulnerabilities: critical_count + high_count + medium_count + low_count + info_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            risk_score,
            risk_level: risk_level.to_string(),
            key_findings: Vec::new(),
            recommendations: Vec::new(),
            duration_seconds: results.iter().map(|r| r.duration_seconds).sum(),
        },
        vulnerability_breakdown: VulnerabilityBreakdown {
            by_severity: HashMap::new(),
            by_category: HashMap::new(),
            by_confidence: HashMap::new(),
            verified_count: 0,
            unverified_count: 0,
        },
        owasp_mapping: HashMap::new(),
        cwe_mapping: HashMap::new(),
        compliance_mapping: ComplianceMapping {
            pci_dss: HashMap::new(),
            hipaa: HashMap::new(),
            soc2: HashMap::new(),
            iso27001: HashMap::new(),
            gdpr: HashMap::new(),
            nist_csf: HashMap::new(),
            dora: HashMap::new(),
            nis2: HashMap::new(),
        },
        risk_assessment: RiskAssessment {
            overall_risk_score: risk_score,
            risk_level: risk_level.to_string(),
            risk_matrix: Vec::new(),
            attack_surface_score: 0.0,
            exploitability_score: 0.0,
            business_impact_score: 0.0,
        },
        trends: None,
        generated_at: chrono::Utc::now().to_rfc3339(),
        report_version: "1.0".to_string(),
    };

    let branding = BrandingConfig::default();
    let pdf_generator = PdfReportGenerator::new();

    // Use block_in_place to run async code from sync context within existing runtime
    let pdf_data = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            pdf_generator.generate(&enhanced_report, &branding)
        )
    })?;

    Ok(pdf_data)
}

fn generate_xlsx_report(results: &[ScanResults]) -> Result<Vec<u8>> {
    use rust_xlsxwriter::*;

    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Vulnerabilities")?;

    let header_format = Format::new()
        .set_bold()
        .set_background_color(Color::RGB(0x2563eb));

    // Headers
    worksheet.write_with_format(0, 0, "Target", &header_format)?;
    worksheet.write_with_format(0, 1, "Type", &header_format)?;
    worksheet.write_with_format(0, 2, "Severity", &header_format)?;
    worksheet.write_with_format(0, 3, "URL", &header_format)?;
    worksheet.write_with_format(0, 4, "Parameter", &header_format)?;
    worksheet.write_with_format(0, 5, "Payload", &header_format)?;
    worksheet.write_with_format(0, 6, "CWE", &header_format)?;
    worksheet.write_with_format(0, 7, "CVSS", &header_format)?;
    worksheet.write_with_format(0, 8, "Description", &header_format)?;
    worksheet.write_with_format(0, 9, "Remediation", &header_format)?;

    let mut row = 1u32;
    for result in results {
        for vuln in &result.vulnerabilities {
            worksheet.write(row, 0, &result.target)?;
            worksheet.write(row, 1, &vuln.vuln_type)?;
            worksheet.write(row, 2, &format!("{:?}", vuln.severity))?;
            worksheet.write(row, 3, &vuln.url)?;
            worksheet.write(row, 4, vuln.parameter.as_deref().unwrap_or(""))?;
            worksheet.write(row, 5, &vuln.payload)?;
            worksheet.write(row, 6, &vuln.cwe)?;
            worksheet.write(row, 7, vuln.cvss)?;
            worksheet.write(row, 8, &vuln.description)?;
            worksheet.write(row, 9, &vuln.remediation)?;
            row += 1;
        }
    }

    // Set column widths
    worksheet.set_column_width(0, 30)?;
    worksheet.set_column_width(1, 35)?;
    worksheet.set_column_width(2, 12)?;
    worksheet.set_column_width(3, 50)?;
    worksheet.set_column_width(4, 20)?;
    worksheet.set_column_width(5, 40)?;
    worksheet.set_column_width(6, 12)?;
    worksheet.set_column_width(7, 8)?;
    worksheet.set_column_width(8, 60)?;
    worksheet.set_column_width(9, 60)?;

    let temp_path = format!("/tmp/lonkero_report_{}.xlsx", std::process::id());
    workbook.save(&temp_path)?;
    let data = std::fs::read(&temp_path)?;
    let _ = std::fs::remove_file(&temp_path);

    Ok(data)
}

fn generate_junit_report(results: &[ScanResults]) -> Result<String> {
    let mut total_tests = 0usize;
    let mut total_failures = 0usize;

    for result in results {
        total_tests += result.vulnerabilities.len().max(1);
        total_failures += result.vulnerabilities.len();
    }

    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Lonkero Security Scan" tests="{}" failures="{}" time="{}">
"#,
        total_tests,
        total_failures,
        results.iter().map(|r| r.duration_seconds).sum::<f64>()
    );

    for result in results {
        let failures = result.vulnerabilities.len();
        xml.push_str(&format!(
            r#"  <testsuite name="{}" tests="{}" failures="{}" time="{}">
"#,
            xml_escape(&result.target),
            result.vulnerabilities.len().max(1),
            failures,
            result.duration_seconds
        ));

        if result.vulnerabilities.is_empty() {
            xml.push_str(&format!(
                r#"    <testcase name="Security Scan" classname="{}" time="{}" />
"#,
                xml_escape(&result.target),
                result.duration_seconds
            ));
        } else {
            for vuln in &result.vulnerabilities {
                xml.push_str(&format!(
                    r#"    <testcase name="{}" classname="{}" time="0">
      <failure message="{}" type="{:?}"><![CDATA[
URL: {}
CWE: {}
CVSS: {:.1}
Description: {}
Remediation: {}
]]></failure>
    </testcase>
"#,
                    xml_escape(&vuln.vuln_type),
                    xml_escape(&result.target),
                    xml_escape(&vuln.description),
                    vuln.severity,
                    vuln.url,
                    vuln.cwe,
                    vuln.cvss,
                    vuln.description,
                    vuln.remediation
                ));
            }
        }

        xml.push_str("  </testsuite>\n");
    }

    xml.push_str("</testsuites>\n");
    Ok(xml)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Extract unique S3 bucket URL from a full S3 object URL
/// e.g., "https://bucket.s3.region.amazonaws.com/path/file.png" -> "https://bucket.s3.region.amazonaws.com/"
fn extract_s3_bucket_url(url: &str) -> Option<String> {
    // Handle both path-style and virtual-hosted-style S3 URLs
    // Virtual-hosted: https://bucket.s3.region.amazonaws.com/key
    // Path-style: https://s3.region.amazonaws.com/bucket/key
    if url.contains(".s3.") && url.contains("amazonaws.com") {
        // Virtual-hosted style
        if let Some(pos) = url.find("amazonaws.com") {
            let base = &url[..pos + "amazonaws.com".len()];
            return Some(format!("{}/", base.trim_end_matches('\\')));
        }
    } else if url.contains("s3.amazonaws.com") || url.contains("s3-") {
        // Path-style or regional
        if let Ok(parsed) = url::Url::parse(url.trim_end_matches('\\')) {
            let host = parsed.host_str()?;
            return Some(format!("https://{}/", host));
        }
    }
    None
}

/// Extract unique Azure Blob container URL from a full blob URL
/// e.g., "https://account.blob.core.windows.net/container/path/file" -> "https://account.blob.core.windows.net/container/"
fn extract_azure_container_url(url: &str) -> Option<String> {
    if url.contains(".blob.core.windows.net") {
        if let Ok(parsed) = url::Url::parse(url.trim_end_matches('\\')) {
            let host = parsed.host_str()?;
            let path_segments: Vec<&str> = parsed.path().split('/').filter(|s| !s.is_empty()).collect();
            if !path_segments.is_empty() {
                return Some(format!("https://{}/{}/", host, path_segments[0]));
            } else {
                return Some(format!("https://{}/", host));
            }
        }
    }
    None
}

/// Extract unique GCS bucket URL from a full GCS object URL
/// e.g., "https://storage.googleapis.com/bucket/path/file" -> "https://storage.googleapis.com/bucket/"
fn extract_gcs_bucket_url(url: &str) -> Option<String> {
    if url.contains("storage.googleapis.com") || url.contains("storage.cloud.google.com") {
        if let Ok(parsed) = url::Url::parse(url.trim_end_matches('\\')) {
            let host = parsed.host_str()?;
            let path_segments: Vec<&str> = parsed.path().split('/').filter(|s| !s.is_empty()).collect();
            if !path_segments.is_empty() {
                return Some(format!("https://{}/{}/", host, path_segments[0]));
            } else {
                return Some(format!("https://{}/", host));
            }
        }
    }
    None
}

fn list_scanners(verbose: bool, category: Option<String>) -> Result<()> {
    let scanners = vec![
        ("xss", "Injection", "Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based"),
        ("sqli", "Injection", "SQL Injection - Error-based, Blind, Time-based"),
        ("command_injection", "Injection", "OS Command Injection"),
        ("path_traversal", "Injection", "Path/Directory Traversal"),
        ("ssrf", "Injection", "Server-Side Request Forgery"),
        ("xxe", "Injection", "XML External Entity Injection"),
        ("ssti", "Injection", "Server-Side Template Injection"),
        ("nosql", "Injection", "NoSQL Injection (MongoDB, Redis)"),
        ("ldap", "Injection", "LDAP Injection"),
        ("code_injection", "Injection", "Code Injection (PHP, Python, Ruby)"),
        ("crlf", "Injection", "CRLF Injection / HTTP Response Splitting"),
        ("xpath", "Injection", "XPath Injection"),
        ("xml", "Injection", "XML Injection"),
        ("ssi", "Injection", "Server-Side Includes Injection"),
        ("security_headers", "Configuration", "Missing/Misconfigured Security Headers"),
        ("cors", "Configuration", "CORS Misconfiguration"),
        ("csrf", "Configuration", "Cross-Site Request Forgery"),
        ("clickjacking", "Configuration", "Clickjacking / UI Redressing"),
        ("jwt", "Authentication", "JWT Security Issues"),
        ("oauth", "Authentication", "OAuth 2.0 Vulnerabilities"),
        ("saml", "Authentication", "SAML Security Issues"),
        ("auth_bypass", "Authentication", "Authentication Bypass"),
        ("session", "Authentication", "Session Management Issues"),
        ("mfa", "Authentication", "MFA Bypass/Weaknesses"),
        ("idor", "Authorization", "Insecure Direct Object References"),
        ("mass_assignment", "Authorization", "Mass Assignment Vulnerabilities"),
        ("graphql", "API", "GraphQL Security Issues"),
        ("api_security", "API", "API Security (REST, SOAP)"),
        ("grpc", "API", "gRPC Security"),
        ("websocket", "Protocol", "WebSocket Security"),
        ("http_smuggling", "Protocol", "HTTP Request Smuggling"),
        ("host_header", "Protocol", "Host Header Injection"),
        ("http3", "Protocol", "HTTP/3 and QUIC Security"),
        ("race_condition", "Logic", "Race Condition Vulnerabilities"),
        ("business_logic", "Logic", "Business Logic Flaws"),
        ("open_redirect", "Logic", "Open Redirect"),
        ("file_upload", "Files", "File Upload Vulnerabilities"),
        ("deserialization", "Files", "Insecure Deserialization"),
        ("info_disclosure", "Information", "Information Disclosure"),
        ("sensitive_data", "Information", "Sensitive Data Exposure"),
        ("js_miner", "Information", "JavaScript Secret Mining"),
        ("cache_poisoning", "Cache", "Web Cache Poisoning"),
        ("prototype_pollution", "JavaScript", "Prototype Pollution"),
        ("cloud_storage", "Cloud", "Cloud Storage Misconfigurations (S3, GCS, Azure Blob)"),
        ("container", "Cloud", "Container Security"),
        ("api_gateway", "Cloud", "API Gateway Security"),
        ("aws_ec2", "Cloud", "AWS EC2 Security"),
        ("aws_s3", "Cloud", "AWS S3 Security"),
        ("aws_rds", "Cloud", "AWS RDS Security"),
        ("aws_lambda", "Cloud", "AWS Lambda Security"),
        ("azure_storage", "Cloud", "Azure Storage Security"),
        ("azure_vm", "Cloud", "Azure VM Security"),
        ("gcp_storage", "Cloud", "GCP Storage Security"),
        ("gcp_compute", "Cloud", "GCP Compute Security"),
        ("framework", "Framework", "Framework-Specific Vulnerabilities"),
        ("webauthn", "Authentication", "WebAuthn/FIDO2 Security"),
    ];

    println!("Available Scanner Modules ({} total)", scanners.len());
    println!("{}", "=".repeat(70));

    let filter_category = category.as_ref().map(|c| c.to_lowercase());

    for (name, cat, desc) in &scanners {
        if let Some(ref filter) = filter_category {
            if !cat.to_lowercase().contains(filter) {
                continue;
            }
        }

        if verbose {
            println!("\n[{}]", name);
            println!("  Category:    {}", cat);
            println!("  Description: {}", desc);
        } else {
            println!("{:20} {:15} {}", name, cat, desc);
        }
    }

    println!("\n{}", "=".repeat(70));
    println!("Use --only or --skip flags to control which scanners run");

    Ok(())
}

async fn validate_targets(targets: Vec<String>) -> Result<()> {
    println!("Validating {} target(s)...\n", targets.len());

    for target in &targets {
        print!("{}: ", target);

        // Validate URL format
        match url::Url::parse(target) {
            Ok(parsed) => {
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    println!("INVALID (scheme must be http or https)");
                    continue;
                }

                // Try to connect
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?;

                match client.get(target).send().await {
                    Ok(response) => {
                        println!("OK (status: {}, server: {})",
                            response.status(),
                            response.headers()
                                .get("server")
                                .map(|v| v.to_str().unwrap_or("unknown"))
                                .unwrap_or("unknown")
                        );
                    }
                    Err(e) => {
                        println!("UNREACHABLE ({})", e);
                    }
                }
            }
            Err(e) => {
                println!("INVALID URL ({})", e);
            }
        }
    }

    Ok(())
}

fn generate_config(output: PathBuf) -> Result<()> {
    let config = r#"# Lonkero Scanner Configuration
# See: https://github.com/bountyyfi/lonkero

[scanner]
# Scan mode: fast, normal, thorough, insane
mode = "normal"

# Maximum concurrent requests
concurrency = 50

# Request timeout in seconds
timeout = 30

# Rate limit (requests per second per target)
rate_limit = 100

# Enable subdomain enumeration
subdomains = false

# Enable web crawler
crawl = false
max_depth = 3

[output]
# Output format: json, html, pdf, sarif, markdown, csv
format = "json"

# Output file path (optional)
# path = "scan-results.json"

[http]
# Custom User-Agent
# user_agent = "Lonkero/1.0"

# Follow redirects
follow_redirects = true
max_redirects = 5

# TLS verification
verify_tls = true

[authentication]
# Authentication cookie
# cookie = "session=abc123"

# Bearer token
# token = "eyJhbGciOiJIUzI1NiIs..."

# HTTP Basic Auth (user:pass)
# basic_auth = "admin:password"

[headers]
# Custom headers
# X-Custom-Header = "value"
# Authorization = "Bearer token"

[scanners]
# Enable/disable specific scanners
# skip = ["grpc", "websocket"]
# only = ["xss", "sqli", "ssrf"]

[proxy]
# Proxy URL
# url = "http://127.0.0.1:8080"

[cloud]
# AWS credentials (for cloud scanning)
# aws_region = "us-east-1"
# aws_profile = "default"

# Azure credentials
# azure_subscription_id = ""

# GCP credentials
# gcp_project_id = ""
"#;

    std::fs::write(&output, config)?;
    println!("Configuration file generated: {}", output.display());
    println!("\nEdit this file and run: lonkero scan --config {}", output.display());

    Ok(())
}

fn show_version() -> Result<()> {
    let current_year = chrono::Utc::now().format("%Y");
    println!("Lonkero v2.0.0");
    println!("Wraps around your attack surface");
    println!("");
    println!("(c) {} Bountyy Oy", current_year);
    println!("https://lonkero.bountyy.fi");
    println!("");
    println!("Build info:");
    println!("  Rust version: {}", env!("CARGO_PKG_RUST_VERSION").chars().take(10).collect::<String>());
    println!("  Target:       {}", std::env::consts::ARCH);
    println!("  OS:           {}", std::env::consts::OS);
    println!("");
    println!("Scanner modules: 60+");
    println!("Supported outputs: JSON, HTML, PDF, SARIF, Markdown, CSV, XLSX, JUnit");

    Ok(())
}

