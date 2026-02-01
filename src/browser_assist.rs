//! Browser-Assist Mode - Legitimate browser-assisted security scanning
//!
//! This module enables cooperative scanning where Lonkero works WITH the user's
//! browser rather than trying to impersonate it. This is the honest, sustainable
//! approach that enterprises actually buy.
//!
//! # Philosophy
//!
//! ```text
//! OLD THINKING: "How do we bypass bot detection?"
//! NEW THINKING: "Which surfaces are legitimate for automated testing?"
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │  lonkero scan https://target.com --browser-assist                       │
//! │                                                                         │
//! │  ┌────────────────────┐                                                 │
//! │  │   Lonkero CLI      │                                                 │
//! │  │   (Orchestrator)   │                                                 │
//! │  └─────────┬──────────┘                                                 │
//! │            │                                                            │
//! │            │ launches/attaches                                          │
//! │            ▼                                                            │
//! │  ┌────────────────────────────────────────────────────────────────┐     │
//! │  │  USER'S BROWSER (Chrome/Firefox)                               │     │
//! │  │  ┌──────────────────────────────────────────────────────────┐  │     │
//! │  │  │  Lonkero Extension (VISIBLE, user-installed)             │  │     │
//! │  │  │                                                          │  │     │
//! │  │  │  [Status: Scanning] [Scope: *.target.com] [47 requests]  │  │     │
//! │  │  │  [Pause] [Stop] [View Findings] [Export Log]            │  │     │
//! │  │  └──────────────────────────────────────────────────────────┘  │     │
//! │  └────────────────────────────────────────────────────────────────┘     │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Properties
//!
//! - **Browser not fooled**: Extension is visible, user-installed
//! - **Site not tricked**: Uses legitimate authenticated session
//! - **User in control**: Pause/Stop buttons, scope display, real-time status
//! - **Scanner is honest**: Audit logs, scope enforcement, From header identification

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// Re-export core types from parasite module for backward compatibility
pub use crate::parasite::{
    BrowserInfo, ParasiteClient, ParasiteRequest, ParasiteResponse, ParasiteStats,
    DEFAULT_PARASITE_PORT,
};

/// Default WebSocket port for Browser-Assist Mode
pub const DEFAULT_BROWSER_ASSIST_PORT: u16 = DEFAULT_PARASITE_PORT;

/// Scope authorization for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeAuthorization {
    /// Authorized domains/patterns (e.g., "*.target.com", "api.target.com")
    pub allowed_patterns: Vec<String>,
    /// Who authorized this scan
    pub authorized_by: String,
    /// When authorization was granted
    pub authorized_at: DateTime<Utc>,
    /// When authorization expires
    pub expires_at: Option<DateTime<Utc>>,
    /// Type of authorization (bug bounty, pentest engagement, etc.)
    pub authorization_type: AuthorizationType,
    /// Optional notes
    pub notes: Option<String>,
}

/// Type of scan authorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthorizationType {
    /// Bug bounty program
    BugBounty,
    /// Penetration test engagement
    PentestEngagement,
    /// Internal security audit
    InternalAudit,
    /// Development/staging testing
    DevTesting,
    /// Owner/administrator testing own assets
    SelfAuthorized,
}

impl std::fmt::Display for AuthorizationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationType::BugBounty => write!(f, "Bug Bounty"),
            AuthorizationType::PentestEngagement => write!(f, "Pentest Engagement"),
            AuthorizationType::InternalAudit => write!(f, "Internal Audit"),
            AuthorizationType::DevTesting => write!(f, "Dev/Staging"),
            AuthorizationType::SelfAuthorized => write!(f, "Self-Authorized"),
        }
    }
}

impl ScopeAuthorization {
    /// Create a new scope authorization
    pub fn new(patterns: Vec<String>, authorized_by: &str, auth_type: AuthorizationType) -> Self {
        Self {
            allowed_patterns: patterns,
            authorized_by: authorized_by.to_string(),
            authorized_at: Utc::now(),
            expires_at: None,
            authorization_type: auth_type,
            notes: None,
        }
    }

    /// Check if a URL is within scope
    pub fn is_in_scope(&self, url: &str) -> bool {
        // Check expiration
        if let Some(expires) = self.expires_at {
            if Utc::now() > expires {
                return false;
            }
        }

        // Parse URL to get host
        let host = match url::Url::parse(url) {
            Ok(parsed) => parsed.host_str().unwrap_or("").to_string(),
            Err(_) => return false,
        };

        // Check against patterns
        for pattern in &self.allowed_patterns {
            if self.matches_pattern(&host, pattern) {
                return true;
            }
        }

        false
    }

    /// Check if host matches pattern (supports wildcards)
    fn matches_pattern(&self, host: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            // Wildcard pattern: *.example.com matches sub.example.com
            let suffix = &pattern[1..]; // .example.com
            host.ends_with(suffix) || host == &pattern[2..]
        } else {
            // Exact match
            host == pattern
        }
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    /// Add notes
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }
}

/// Audit trail entry for scan actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Type of action
    pub action: AuditAction,
    /// URL involved
    pub url: String,
    /// HTTP method
    pub method: String,
    /// Response status (if applicable)
    pub status: Option<u16>,
    /// Duration in ms
    pub duration_ms: Option<u64>,
    /// Whether request was in scope
    pub in_scope: bool,
    /// Additional details
    pub details: Option<String>,
}

/// Type of auditable action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    /// Scan started
    ScanStarted,
    /// Scan paused
    ScanPaused,
    /// Scan resumed
    ScanResumed,
    /// Scan stopped
    ScanStopped,
    /// Request sent
    RequestSent,
    /// Response received
    ResponseReceived,
    /// Request blocked (out of scope)
    OutOfScopeBlocked,
    /// Error occurred
    Error,
    /// Finding discovered
    FindingDiscovered,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::ScanStarted => write!(f, "SCAN_STARTED"),
            AuditAction::ScanPaused => write!(f, "SCAN_PAUSED"),
            AuditAction::ScanResumed => write!(f, "SCAN_RESUMED"),
            AuditAction::ScanStopped => write!(f, "SCAN_STOPPED"),
            AuditAction::RequestSent => write!(f, "REQUEST_SENT"),
            AuditAction::ResponseReceived => write!(f, "RESPONSE_RECEIVED"),
            AuditAction::OutOfScopeBlocked => write!(f, "OUT_OF_SCOPE_BLOCKED"),
            AuditAction::Error => write!(f, "ERROR"),
            AuditAction::FindingDiscovered => write!(f, "FINDING_DISCOVERED"),
        }
    }
}

/// Audit trail for the scan session
pub struct AuditTrail {
    entries: RwLock<Vec<AuditEntry>>,
    entry_counter: AtomicU64,
    output_path: Option<PathBuf>,
}

impl AuditTrail {
    /// Create new audit trail
    pub fn new(output_path: Option<PathBuf>) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            entry_counter: AtomicU64::new(1),
            output_path,
        }
    }

    /// Log an audit entry
    pub async fn log(&self, action: AuditAction, url: &str, method: &str) -> u64 {
        let id = self.entry_counter.fetch_add(1, Ordering::SeqCst);
        let entry = AuditEntry {
            id,
            timestamp: Utc::now(),
            action,
            url: url.to_string(),
            method: method.to_string(),
            status: None,
            duration_ms: None,
            in_scope: true,
            details: None,
        };

        self.entries.write().await.push(entry);
        id
    }

    /// Log with full details
    pub async fn log_full(
        &self,
        action: AuditAction,
        url: &str,
        method: &str,
        status: Option<u16>,
        duration_ms: Option<u64>,
        in_scope: bool,
        details: Option<String>,
    ) -> u64 {
        let id = self.entry_counter.fetch_add(1, Ordering::SeqCst);
        let entry = AuditEntry {
            id,
            timestamp: Utc::now(),
            action,
            url: url.to_string(),
            method: method.to_string(),
            status,
            duration_ms,
            in_scope,
            details,
        };

        self.entries.write().await.push(entry);
        id
    }

    /// Get all entries
    pub async fn get_entries(&self) -> Vec<AuditEntry> {
        self.entries.read().await.clone()
    }

    /// Export audit trail to JSON
    pub async fn export_json(&self) -> Result<String> {
        let entries = self.entries.read().await;
        Ok(serde_json::to_string_pretty(&*entries)?)
    }

    /// Write audit trail to file
    pub async fn write_to_file(&self) -> Result<()> {
        if let Some(path) = &self.output_path {
            let json = self.export_json().await?;
            tokio::fs::write(path, json).await?;
        }
        Ok(())
    }

    /// Get summary stats
    pub async fn summary(&self) -> AuditSummary {
        let entries = self.entries.read().await;
        let mut summary = AuditSummary::default();

        for entry in entries.iter() {
            match entry.action {
                AuditAction::RequestSent => summary.requests_sent += 1,
                AuditAction::ResponseReceived => summary.responses_received += 1,
                AuditAction::OutOfScopeBlocked => summary.out_of_scope_blocked += 1,
                AuditAction::Error => summary.errors += 1,
                AuditAction::FindingDiscovered => summary.findings += 1,
                _ => {}
            }
        }

        summary.total_entries = entries.len() as u64;
        summary
    }
}

/// Summary of audit trail
#[derive(Debug, Default)]
pub struct AuditSummary {
    pub total_entries: u64,
    pub requests_sent: u64,
    pub responses_received: u64,
    pub out_of_scope_blocked: u64,
    pub errors: u64,
    pub findings: u64,
}

/// Browser-Assist Mode client
///
/// This wraps the underlying ParasiteClient with:
/// - Scope authorization and enforcement
/// - Audit trail logging
/// - User control (pause/stop)
pub struct BrowserAssistClient {
    /// Underlying browser connection
    inner: Arc<ParasiteClient>,
    /// Scope authorization
    scope: Arc<ScopeAuthorization>,
    /// Audit trail
    audit: Arc<AuditTrail>,
    /// Whether scanning is paused
    is_paused: Arc<AtomicBool>,
    /// Whether scanning is stopped
    is_stopped: Arc<AtomicBool>,
}

impl BrowserAssistClient {
    /// Create new Browser-Assist client with scope authorization
    pub async fn new(
        port: u16,
        scope: ScopeAuthorization,
        audit_path: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        let inner = ParasiteClient::new(port).await?;
        let audit = Arc::new(AuditTrail::new(audit_path));

        // Log scan start
        audit
            .log(
                AuditAction::ScanStarted,
                &format!("scope: {:?}", scope.allowed_patterns),
                "INIT",
            )
            .await;

        info!(
            "Browser-Assist Mode initialized. Scope: {:?}, Authorization: {}",
            scope.allowed_patterns, scope.authorization_type
        );

        Ok(Arc::new(Self {
            inner,
            scope: Arc::new(scope),
            audit,
            is_paused: Arc::new(AtomicBool::new(false)),
            is_stopped: Arc::new(AtomicBool::new(false)),
        }))
    }

    /// Check if browser is connected
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Check if scanning is paused
    pub fn is_paused(&self) -> bool {
        self.is_paused.load(Ordering::SeqCst)
    }

    /// Check if scanning is stopped
    pub fn is_stopped(&self) -> bool {
        self.is_stopped.load(Ordering::SeqCst)
    }

    /// Pause scanning
    pub async fn pause(&self) {
        self.is_paused.store(true, Ordering::SeqCst);
        self.audit.log(AuditAction::ScanPaused, "", "CONTROL").await;
        info!("Browser-Assist Mode: Scanning paused");
    }

    /// Resume scanning
    pub async fn resume(&self) {
        self.is_paused.store(false, Ordering::SeqCst);
        self.audit.log(AuditAction::ScanResumed, "", "CONTROL").await;
        info!("Browser-Assist Mode: Scanning resumed");
    }

    /// Stop scanning
    pub async fn stop(&self) {
        self.is_stopped.store(true, Ordering::SeqCst);
        self.audit.log(AuditAction::ScanStopped, "", "CONTROL").await;

        // Write final audit trail
        if let Err(e) = self.audit.write_to_file().await {
            warn!("Failed to write audit trail: {}", e);
        }

        info!("Browser-Assist Mode: Scanning stopped");
    }

    /// Get scope authorization
    pub fn scope(&self) -> &ScopeAuthorization {
        &self.scope
    }

    /// Get audit trail
    pub fn audit(&self) -> &Arc<AuditTrail> {
        &self.audit
    }

    /// Get browser info
    pub async fn browser_info(&self) -> Option<BrowserInfo> {
        self.inner.browser_info().await
    }

    /// Get statistics
    pub fn stats(&self) -> &ParasiteStats {
        self.inner.stats()
    }

    /// Make HTTP request through browser (with scope enforcement)
    pub async fn request(
        &self,
        url: &str,
        method: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        timeout_ms: u64,
    ) -> Result<ParasiteResponse> {
        // Check if stopped
        if self.is_stopped() {
            return Err(anyhow!("Scanning has been stopped"));
        }

        // Wait while paused
        while self.is_paused() {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            if self.is_stopped() {
                return Err(anyhow!("Scanning has been stopped"));
            }
        }

        // CRITICAL: Scope enforcement
        if !self.scope.is_in_scope(url) {
            self.audit
                .log_full(
                    AuditAction::OutOfScopeBlocked,
                    url,
                    method,
                    None,
                    None,
                    false,
                    Some("Request blocked: URL not in authorized scope".to_string()),
                )
                .await;

            warn!(
                "Browser-Assist Mode: Blocked out-of-scope request to {}",
                url
            );
            return Err(anyhow!(
                "Request blocked: {} is not in authorized scope {:?}",
                url,
                self.scope.allowed_patterns
            ));
        }

        // Log request
        self.audit.log(AuditAction::RequestSent, url, method).await;

        // Make request through browser
        let result = self.inner.request(url, method, headers, body, timeout_ms).await;

        // Log response
        match &result {
            Ok(response) => {
                self.audit
                    .log_full(
                        AuditAction::ResponseReceived,
                        url,
                        method,
                        Some(response.status),
                        Some(response.duration),
                        true,
                        None,
                    )
                    .await;
            }
            Err(e) => {
                self.audit
                    .log_full(
                        AuditAction::Error,
                        url,
                        method,
                        None,
                        None,
                        true,
                        Some(e.to_string()),
                    )
                    .await;
            }
        }

        result
    }

    /// Convenience method for GET request
    pub async fn get(&self, url: &str) -> Result<ParasiteResponse> {
        self.request(url, "GET", None, None, 30000).await
    }

    /// Convenience method for POST request
    pub async fn post(
        &self,
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<ParasiteResponse> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), content_type.to_string());
        self.request(url, "POST", Some(headers), Some(body.to_string()), 30000)
            .await
    }

    /// Log a security finding
    pub async fn log_finding(&self, url: &str, finding_type: &str, details: &str) {
        self.audit
            .log_full(
                AuditAction::FindingDiscovered,
                url,
                "FINDING",
                None,
                None,
                true,
                Some(format!("{}: {}", finding_type, details)),
            )
            .await;
    }

    /// Generate summary report
    pub async fn generate_report(&self) -> String {
        let summary = self.audit.summary().await;
        let browser = self.browser_info().await;
        let stats = self.stats();

        let mut report = String::new();
        report.push_str("\n============================================================\n");
        report.push_str("  BROWSER-ASSIST MODE SCAN REPORT\n");
        report.push_str("============================================================\n\n");

        report.push_str("AUTHORIZATION\n");
        report.push_str(&format!("{:-<40}\n", ""));
        report.push_str(&format!("Type:          {}\n", self.scope.authorization_type));
        report.push_str(&format!("Authorized by: {}\n", self.scope.authorized_by));
        report.push_str(&format!("Authorized at: {}\n", self.scope.authorized_at));
        report.push_str(&format!("Scope:         {:?}\n\n", self.scope.allowed_patterns));

        if let Some(browser) = browser {
            report.push_str("BROWSER\n");
            report.push_str(&format!("{:-<40}\n", ""));
            report.push_str(&format!("User Agent: {}\n", browser.user_agent));
            report.push_str(&format!("Platform:   {}\n", browser.platform));
            report.push_str(&format!("Extension:  v{}\n\n", browser.extension_version));
        }

        report.push_str("STATISTICS\n");
        report.push_str(&format!("{:-<40}\n", ""));
        report.push_str(&format!(
            "Requests sent:       {}\n",
            stats.requests_sent.load(Ordering::SeqCst)
        ));
        report.push_str(&format!(
            "Requests completed:  {}\n",
            stats.requests_completed.load(Ordering::SeqCst)
        ));
        report.push_str(&format!(
            "Requests failed:     {}\n",
            stats.requests_failed.load(Ordering::SeqCst)
        ));
        report.push_str(&format!(
            "Out-of-scope blocked: {}\n",
            summary.out_of_scope_blocked
        ));
        report.push_str(&format!("Findings:            {}\n\n", summary.findings));

        report.push_str("AUDIT TRAIL\n");
        report.push_str(&format!("{:-<40}\n", ""));
        report.push_str(&format!("Total entries: {}\n", summary.total_entries));

        if let Some(notes) = &self.scope.notes {
            report.push_str(&format!("\nNOTES\n"));
            report.push_str(&format!("{:-<40}\n", ""));
            report.push_str(&format!("{}\n", notes));
        }

        report.push_str("\n============================================================\n");

        report
    }
}

// Note: From<ParasiteResponse> for HttpResponse is already implemented in parasite.rs
// We re-export ParasiteResponse from there, so the conversion is available.

/// Browser launcher for automatic extension loading
///
/// Launches Chrome/Chromium with the Browser-Assist extension pre-loaded,
/// eliminating the need for manual extension installation.
pub struct BrowserLauncher {
    /// Child process handle
    process: Option<Child>,
    /// Path to browser executable
    browser_path: PathBuf,
    /// Path to extension directory
    extension_path: PathBuf,
    /// User data directory for isolated profile
    user_data_dir: PathBuf,
}

impl BrowserLauncher {
    /// Find Chrome/Chromium executable on the current platform
    pub fn find_chrome() -> Option<PathBuf> {
        #[cfg(target_os = "windows")]
        {
            // Windows paths (in order of preference)
            let paths = [
                // Chrome
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                // User install
                &format!(
                    r"{}\AppData\Local\Google\Chrome\Application\chrome.exe",
                    std::env::var("USERPROFILE").unwrap_or_default()
                ),
                // Edge (Chromium-based)
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                // Brave
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
            ];

            for path in paths {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
            }

            // Try to find via which
            if let Ok(output) = Command::new("where").arg("chrome").output() {
                if output.status.success() {
                    let path_str = String::from_utf8_lossy(&output.stdout);
                    if let Some(line) = path_str.lines().next() {
                        let p = PathBuf::from(line.trim());
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let paths = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ];

            for path in paths {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let names = [
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
                "brave-browser",
                "microsoft-edge",
            ];

            for name in names {
                if let Ok(output) = Command::new("which").arg(name).output() {
                    if output.status.success() {
                        let path_str = String::from_utf8_lossy(&output.stdout);
                        let p = PathBuf::from(path_str.trim());
                        if p.exists() {
                            return Some(p);
                        }
                    }
                }
            }

            // Common Linux paths
            let paths = [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/snap/bin/chromium",
            ];

            for path in paths {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
            }
        }

        None
    }

    /// Find the Browser-Assist extension directory
    pub fn find_extension_dir() -> Option<PathBuf> {
        // Check relative to executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                // Check various locations relative to the executable
                let candidates = [
                    exe_dir.join("browser-assist-extension"),
                    exe_dir.join("../browser-assist-extension"),
                    exe_dir.join("../../browser-assist-extension"),
                    exe_dir.join("extensions/browser-assist"),
                ];

                for candidate in candidates {
                    if candidate.join("manifest.json").exists() {
                        return Some(candidate.canonicalize().unwrap_or(candidate));
                    }
                }
            }
        }

        // Check relative to current directory
        let cwd_candidates = [
            PathBuf::from("browser-assist-extension"),
            PathBuf::from("./browser-assist-extension"),
            PathBuf::from("../browser-assist-extension"),
        ];

        for candidate in cwd_candidates {
            if candidate.join("manifest.json").exists() {
                return Some(candidate.canonicalize().unwrap_or(candidate));
            }
        }

        // Check in home directory
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = PathBuf::from(home).join(".lonkero/browser-assist-extension");
                if home_path.join("manifest.json").exists() {
                    return Some(home_path);
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                let appdata_path = PathBuf::from(appdata).join("lonkero/browser-assist-extension");
                if appdata_path.join("manifest.json").exists() {
                    return Some(appdata_path);
                }
            }
        }

        None
    }

    /// Create a new browser launcher
    pub fn new(extension_path: Option<PathBuf>) -> Result<Self> {
        let browser_path = Self::find_chrome()
            .ok_or_else(|| anyhow!("Could not find Chrome/Chromium browser. Please install Chrome or set CHROME_PATH environment variable."))?;

        let extension_path = extension_path
            .or_else(Self::find_extension_dir)
            .ok_or_else(|| anyhow!("Could not find browser-assist-extension directory. Make sure it exists in the project root."))?;

        // Create temporary user data directory for isolated profile
        let temp_dir = std::env::temp_dir();
        let user_data_dir = temp_dir.join(format!("lonkero-browser-assist-{}", std::process::id()));

        info!("Browser launcher initialized:");
        info!("  Browser: {}", browser_path.display());
        info!("  Extension: {}", extension_path.display());

        Ok(Self {
            process: None,
            browser_path,
            extension_path,
            user_data_dir,
        })
    }

    /// Create with specific browser path
    pub fn with_browser(browser_path: impl AsRef<Path>, extension_path: impl AsRef<Path>) -> Result<Self> {
        let browser_path = browser_path.as_ref().to_path_buf();
        let extension_path = extension_path.as_ref().to_path_buf();

        if !browser_path.exists() {
            return Err(anyhow!("Browser not found at: {}", browser_path.display()));
        }

        if !extension_path.join("manifest.json").exists() {
            return Err(anyhow!("Extension manifest not found at: {}", extension_path.display()));
        }

        let temp_dir = std::env::temp_dir();
        let user_data_dir = temp_dir.join(format!("lonkero-browser-assist-{}", std::process::id()));

        Ok(Self {
            process: None,
            browser_path,
            extension_path,
            user_data_dir,
        })
    }

    /// Launch browser with the extension loaded
    pub fn launch(&mut self, start_url: Option<&str>) -> Result<()> {
        if self.process.is_some() {
            return Ok(()); // Already running
        }

        // Create user data directory
        std::fs::create_dir_all(&self.user_data_dir)?;

        let mut cmd = Command::new(&self.browser_path);

        // Normalize extension path (remove \\?\ prefix on Windows)
        let ext_path_str = self.extension_path.display().to_string();
        let ext_path_clean = ext_path_str.strip_prefix(r"\\?\").unwrap_or(&ext_path_str);

        // Normalize user data directory path
        let user_data_str = self.user_data_dir.display().to_string();
        let user_data_clean = user_data_str.strip_prefix(r"\\?\").unwrap_or(&user_data_str);

        // Core arguments for extension loading
        cmd.arg(format!("--load-extension={}", ext_path_clean))
            .arg(format!("--user-data-dir={}", user_data_clean))
            // Disable first-run experience
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            // Allow extensions to run
            .arg("--enable-extensions");

        // Add start URL if provided
        if let Some(url) = start_url {
            cmd.arg(url);
        } else {
            // Open a blank tab or about:blank
            cmd.arg("about:blank");
        }

        info!("Launching browser with extension...");
        debug!("Command: {:?}", cmd);

        let child = cmd.spawn().map_err(|e| {
            anyhow!(
                "Failed to launch browser: {}. Browser path: {}",
                e,
                self.browser_path.display()
            )
        })?;

        self.process = Some(child);

        info!("Browser launched successfully with Browser-Assist extension");
        info!("The extension will auto-connect to the WebSocket server");

        Ok(())
    }

    /// Check if browser is running
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut process) = self.process {
            match process.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Close the browser
    pub fn close(&mut self) -> Result<()> {
        if let Some(mut process) = self.process.take() {
            #[cfg(target_os = "windows")]
            {
                // On Windows, use taskkill to kill the process tree
                let _ = Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &process.id().to_string()])
                    .output();
            }

            #[cfg(not(target_os = "windows"))]
            {
                let _ = process.kill();
            }

            let _ = process.wait();
        }

        // Clean up user data directory
        if self.user_data_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.user_data_dir);
        }

        Ok(())
    }

    /// Get the extension path
    pub fn extension_path(&self) -> &Path {
        &self.extension_path
    }

    /// Get the browser path
    pub fn browser_path(&self) -> &Path {
        &self.browser_path
    }
}

impl Drop for BrowserLauncher {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Launch browser with extension and wait for connection
///
/// This is a convenience function that:
/// 1. Finds Chrome/Chromium
/// 2. Launches it with the Browser-Assist extension
/// 3. Waits for the extension to connect to the WebSocket server
///
/// # Example
/// ```ignore
/// use lonkero_scanner::browser_assist::launch_browser_and_wait;
///
/// let launcher = launch_browser_and_wait(9339, None, 30).await?;
/// // Browser is now running with extension connected
/// ```
pub async fn launch_browser_and_wait(
    port: u16,
    extension_path: Option<PathBuf>,
    timeout_secs: u64,
) -> Result<BrowserLauncher> {
    let mut launcher = BrowserLauncher::new(extension_path)?;

    // Launch the browser
    launcher.launch(None)?;

    info!("Browser launched. Extension should auto-connect within {}s...", timeout_secs);

    // Give the browser time to start and extension to initialize
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    Ok(launcher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_exact_match() {
        let scope = ScopeAuthorization::new(
            vec!["example.com".to_string()],
            "tester",
            AuthorizationType::BugBounty,
        );

        assert!(scope.is_in_scope("https://example.com/path"));
        assert!(!scope.is_in_scope("https://other.com/path"));
        assert!(!scope.is_in_scope("https://sub.example.com/path"));
    }

    #[test]
    fn test_scope_wildcard() {
        let scope = ScopeAuthorization::new(
            vec!["*.example.com".to_string()],
            "tester",
            AuthorizationType::PentestEngagement,
        );

        assert!(scope.is_in_scope("https://sub.example.com/path"));
        assert!(scope.is_in_scope("https://api.example.com/path"));
        assert!(scope.is_in_scope("https://example.com/path")); // root domain also matches
        assert!(!scope.is_in_scope("https://other.com/path"));
    }

    #[test]
    fn test_authorization_type_display() {
        assert_eq!(format!("{}", AuthorizationType::BugBounty), "Bug Bounty");
        assert_eq!(
            format!("{}", AuthorizationType::PentestEngagement),
            "Pentest Engagement"
        );
    }
}
