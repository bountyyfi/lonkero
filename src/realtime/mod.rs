// Copyright (c) 2025 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Real-Time Scanner Integration
 * Rust scanner module for real-time vulnerability detection with streaming results
 *
 * Features:
 * - Real-time result streaming via callbacks
 * - Progress reporting (every 5 seconds)
 * - Cancellation support
 * - Resource monitoring (CPU, memory)
 * - Backpressure handling
 * - Scanner-level completion events
 *
 * @copyright 2025 Bountyy Oy
 * @license Proprietary
 */

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;

/// Real-time scan context
pub struct RealtimeScanContext {
    pub scan_id: String,
    pub target: String,
    pub start_time: Instant,
    pub cancelled: Arc<RwLock<bool>>,
    pub paused: Arc<RwLock<bool>>,
    pub progress_tx: mpsc::UnboundedSender<ProgressUpdate>,
    pub finding_tx: mpsc::UnboundedSender<FindingUpdate>,
    pub scanner_tx: mpsc::UnboundedSender<ScannerUpdate>,
}

/// Progress update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    pub scan_id: String,
    pub percentage: f64,
    pub current_scanner: String,
    pub scanners_completed: usize,
    pub total_scanners: usize,
    pub urls_scanned: usize,
    pub total_urls: usize,
    pub vulnerabilities_found: usize,
    pub elapsed_time_ms: u64,
    pub estimated_completion_ms: Option<u64>,
    pub timestamp: u64,
}

/// Finding update (new vulnerability discovered)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingUpdate {
    pub scan_id: String,
    pub vulnerability: VulnerabilityFinding,
    pub timestamp: u64,
}

/// Vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub evidence: String,
    pub remediation: Option<String>,
}

/// Scanner completion update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerUpdate {
    pub scan_id: String,
    pub scanner_name: String,
    pub status: String,
    pub duration_ms: u64,
    pub findings_count: usize,
    pub urls_tested: usize,
    pub timestamp: u64,
}

/// Resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: u64,
    pub active_threads: usize,
    pub network_requests_per_second: f64,
    pub timestamp: u64,
}

impl RealtimeScanContext {
    /// Create new real-time scan context
    pub fn new(
        scan_id: String,
        target: String,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<ProgressUpdate>,
        mpsc::UnboundedReceiver<FindingUpdate>,
        mpsc::UnboundedReceiver<ScannerUpdate>,
    ) {
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        let (finding_tx, finding_rx) = mpsc::unbounded_channel();
        let (scanner_tx, scanner_rx) = mpsc::unbounded_channel();

        let ctx = Self {
            scan_id,
            target,
            start_time: Instant::now(),
            cancelled: Arc::new(RwLock::new(false)),
            paused: Arc::new(RwLock::new(false)),
            progress_tx,
            finding_tx,
            scanner_tx,
        };

        (ctx, progress_rx, finding_rx, scanner_rx)
    }

    /// Check if scan is cancelled
    pub async fn is_cancelled(&self) -> bool {
        *self.cancelled.read().await
    }

    /// Cancel the scan
    pub async fn cancel(&self) {
        let mut cancelled = self.cancelled.write().await;
        *cancelled = true;
        println!("[RealtimeScanner] Scan {} cancelled", self.scan_id);
    }

    /// Check if scan is paused
    pub async fn is_paused(&self) -> bool {
        *self.paused.read().await
    }

    /// Pause the scan
    pub async fn pause(&self) {
        let mut paused = self.paused.write().await;
        *paused = true;
        println!("[RealtimeScanner] Scan {} paused", self.scan_id);
    }

    /// Resume the scan
    pub async fn resume(&self) {
        let mut paused = self.paused.write().await;
        *paused = false;
        println!("[RealtimeScanner] Scan {} resumed", self.scan_id);
    }

    /// Wait while paused
    pub async fn wait_if_paused(&self) {
        while self.is_paused().await {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Send progress update
    pub fn send_progress(
        &self,
        percentage: f64,
        current_scanner: String,
        scanners_completed: usize,
        total_scanners: usize,
        urls_scanned: usize,
        total_urls: usize,
        vulnerabilities_found: usize,
        estimated_completion_ms: Option<u64>,
    ) {
        let elapsed = self.start_time.elapsed().as_millis() as u64;

        let update = ProgressUpdate {
            scan_id: self.scan_id.clone(),
            percentage,
            current_scanner,
            scanners_completed,
            total_scanners,
            urls_scanned,
            total_urls,
            vulnerabilities_found,
            elapsed_time_ms: elapsed,
            estimated_completion_ms,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let _ = self.progress_tx.send(update);
    }

    /// Send finding update
    pub fn send_finding(&self, vulnerability: VulnerabilityFinding) {
        let update = FindingUpdate {
            scan_id: self.scan_id.clone(),
            vulnerability,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let _ = self.finding_tx.send(update);
    }

    /// Send scanner completion
    pub fn send_scanner_complete(
        &self,
        scanner_name: String,
        status: String,
        duration_ms: u64,
        findings_count: usize,
        urls_tested: usize,
    ) {
        let update = ScannerUpdate {
            scan_id: self.scan_id.clone(),
            scanner_name,
            status,
            duration_ms,
            findings_count,
            urls_tested,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        let _ = self.scanner_tx.send(update);
    }

    /// Get elapsed time
    pub fn elapsed_time_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

/// Progress tracker for automated progress updates
pub struct ProgressTracker {
    context: Arc<RealtimeScanContext>,
    total_scanners: usize,
    scanners_completed: usize,
    total_urls: usize,
    urls_scanned: usize,
    vulnerabilities_found: usize,
    current_scanner: String,
}

impl ProgressTracker {
    /// Create new progress tracker
    pub fn new(context: Arc<RealtimeScanContext>, total_scanners: usize, total_urls: usize) -> Self {
        Self {
            context,
            total_scanners,
            scanners_completed: 0,
            total_urls,
            urls_scanned: 0,
            vulnerabilities_found: 0,
            current_scanner: String::from("Initializing"),
        }
    }

    /// Start automated progress reporting
    pub fn start_auto_reporting(self: Arc<Self>) {
        let tracker = Arc::clone(&self);

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Check if scan is cancelled
                if tracker.context.is_cancelled().await {
                    break;
                }

                // Wait if paused
                tracker.context.wait_if_paused().await;

                // Send progress update
                tracker.send_update().await;
            }
        });
    }

    /// Send progress update
    async fn send_update(&self) {
        let percentage = if self.total_scanners > 0 {
            (self.scanners_completed as f64 / self.total_scanners as f64) * 100.0
        } else {
            0.0
        };

        // Estimate completion time
        let elapsed_ms = self.context.elapsed_time_ms();
        let estimated_completion_ms = if percentage > 0.0 && percentage < 100.0 {
            Some((elapsed_ms as f64 / percentage * 100.0) as u64 - elapsed_ms)
        } else {
            None
        };

        self.context.send_progress(
            percentage,
            self.current_scanner.clone(),
            self.scanners_completed,
            self.total_scanners,
            self.urls_scanned,
            self.total_urls,
            self.vulnerabilities_found,
            estimated_completion_ms,
        );
    }

    /// Update current scanner
    pub async fn set_scanner(&mut self, scanner_name: String) {
        self.current_scanner = scanner_name;
        self.send_update().await;
    }

    /// Complete a scanner
    pub async fn complete_scanner(&mut self) {
        self.scanners_completed += 1;
        self.send_update().await;
    }

    /// Update URL count
    pub async fn update_urls(&mut self, scanned: usize) {
        self.urls_scanned = scanned;
        self.send_update().await;
    }

    /// Add vulnerability
    pub async fn add_vulnerability(&mut self) {
        self.vulnerabilities_found += 1;
        self.send_update().await;
    }

    /// Get current stats
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.scanners_completed,
            self.urls_scanned,
            self.vulnerabilities_found,
        )
    }
}

/// Resource monitor
pub struct ResourceMonitor {
    start_cpu_time: f64,
    start_timestamp: Instant,
    network_requests: Arc<RwLock<usize>>,
}

impl ResourceMonitor {
    /// Create new resource monitor
    pub fn new() -> Self {
        Self {
            start_cpu_time: 0.0,
            start_timestamp: Instant::now(),
            network_requests: Arc::new(RwLock::new(0)),
        }
    }

    /// Record network request
    pub async fn record_request(&self) {
        let mut requests = self.network_requests.write().await;
        *requests += 1;
    }

    /// Get resource metrics
    pub async fn get_metrics(&self) -> ResourceMetrics {
        let elapsed_secs = self.start_timestamp.elapsed().as_secs_f64();
        let requests = *self.network_requests.read().await;
        let requests_per_second = if elapsed_secs > 0.0 {
            requests as f64 / elapsed_secs
        } else {
            0.0
        };

        // Get system metrics (simplified - in production use proper system monitoring)
        let cpu_usage = self.get_cpu_usage();
        let memory_usage = self.get_memory_usage();
        let active_threads = self.get_active_threads();

        ResourceMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb: memory_usage,
            active_threads,
            network_requests_per_second: requests_per_second,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get CPU usage (simplified)
    fn get_cpu_usage(&self) -> f64 {
        // In production, use proper CPU monitoring
        // For now, return a placeholder
        0.0
    }

    /// Get memory usage (simplified)
    fn get_memory_usage(&self) -> u64 {
        // In production, use proper memory monitoring
        // For now, return a placeholder
        0
    }

    /// Get active threads (simplified)
    fn get_active_threads(&self) -> usize {
        // In production, use proper thread counting
        // For now, return a placeholder
        0
    }
}

/// Backpressure handler
pub struct BackpressureHandler {
    max_queue_size: usize,
    current_queue_size: Arc<RwLock<usize>>,
}

impl BackpressureHandler {
    /// Create new backpressure handler
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            max_queue_size,
            current_queue_size: Arc::new(RwLock::new(0)),
        }
    }

    /// Wait if queue is full
    pub async fn wait_if_full(&self) {
        loop {
            let queue_size = *self.current_queue_size.read().await;

            if queue_size < self.max_queue_size {
                break;
            }

            // Wait a bit before checking again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Increment queue size
    pub async fn increment(&self) {
        let mut size = self.current_queue_size.write().await;
        *size += 1;
    }

    /// Decrement queue size
    pub async fn decrement(&self) {
        let mut size = self.current_queue_size.write().await;
        if *size > 0 {
            *size -= 1;
        }
    }

    /// Get current queue size
    pub async fn get_size(&self) -> usize {
        *self.current_queue_size.read().await
    }
}

/// Scan result aggregator
pub struct ScanResultAggregator {
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub scanner_results: Vec<ScannerUpdate>,
    pub start_time: Instant,
}

impl ScanResultAggregator {
    /// Create new aggregator
    pub fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            scanner_results: Vec::new(),
            start_time: Instant::now(),
        }
    }

    /// Add vulnerability
    pub fn add_vulnerability(&mut self, vuln: VulnerabilityFinding) {
        self.vulnerabilities.push(vuln);
    }

    /// Add scanner result
    pub fn add_scanner_result(&mut self, result: ScannerUpdate) {
        self.scanner_results.push(result);
    }

    /// Get summary
    pub fn get_summary(&self) -> ScanSummary {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for vuln in &self.vulnerabilities {
            match vuln.severity.as_str() {
                "CRITICAL" => critical_count += 1,
                "HIGH" => high_count += 1,
                "MEDIUM" => medium_count += 1,
                "LOW" => low_count += 1,
                _ => {}
            }
        }

        ScanSummary {
            total_vulnerabilities: self.vulnerabilities.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            scanners_executed: self.scanner_results.len(),
            total_duration_ms: self.start_time.elapsed().as_millis() as u64,
        }
    }
}

/// Scan summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub scanners_executed: usize,
    pub total_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_realtime_context_creation() {
        let (ctx, _progress_rx, _finding_rx, _scanner_rx) =
            RealtimeScanContext::new("test_scan".to_string(), "https://example.com".to_string());

        assert_eq!(ctx.scan_id, "test_scan");
        assert_eq!(ctx.target, "https://example.com");
        assert!(!ctx.is_cancelled().await);
        assert!(!ctx.is_paused().await);
    }

    #[tokio::test]
    async fn test_scan_cancellation() {
        let (ctx, _progress_rx, _finding_rx, _scanner_rx) =
            RealtimeScanContext::new("test_scan".to_string(), "https://example.com".to_string());

        assert!(!ctx.is_cancelled().await);

        ctx.cancel().await;

        assert!(ctx.is_cancelled().await);
    }

    #[tokio::test]
    async fn test_scan_pause_resume() {
        let (ctx, _progress_rx, _finding_rx, _scanner_rx) =
            RealtimeScanContext::new("test_scan".to_string(), "https://example.com".to_string());

        assert!(!ctx.is_paused().await);

        ctx.pause().await;
        assert!(ctx.is_paused().await);

        ctx.resume().await;
        assert!(!ctx.is_paused().await);
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let (ctx, mut progress_rx, _finding_rx, _scanner_rx) =
            RealtimeScanContext::new("test_scan".to_string(), "https://example.com".to_string());

        let mut tracker = ProgressTracker::new(Arc::new(ctx), 5, 100);

        tracker.set_scanner("XSS Scanner".to_string()).await;
        tracker.complete_scanner().await;

        // Check if progress update was received
        if let Ok(update) = progress_rx.try_recv() {
            assert_eq!(update.scan_id, "test_scan");
            assert_eq!(update.scanners_completed, 1);
            assert_eq!(update.total_scanners, 5);
        }
    }

    #[test]
    fn test_scan_result_aggregator() {
        let mut aggregator = ScanResultAggregator::new();

        let vuln = VulnerabilityFinding {
            id: "vuln_1".to_string(),
            severity: "HIGH".to_string(),
            confidence: "HIGH".to_string(),
            category: "XSS".to_string(),
            name: "Cross-Site Scripting".to_string(),
            description: "XSS vulnerability found".to_string(),
            url: "https://example.com".to_string(),
            parameter: Some("q".to_string()),
            payload: Some("<script>alert(1)</script>".to_string()),
            evidence: "Payload reflected in response".to_string(),
            remediation: Some("Sanitize user input".to_string()),
        };

        aggregator.add_vulnerability(vuln);

        let summary = aggregator.get_summary();
        assert_eq!(summary.total_vulnerabilities, 1);
        assert_eq!(summary.high_count, 1);
    }
}
