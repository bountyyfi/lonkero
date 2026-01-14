// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

//! Kalamari-based XSS Scanner with Real JavaScript Execution Detection
//!
//! This is the ONLY XSS scanner - uses kalamari headless browser to detect XSS by:
//! 1. Intercepting JavaScript dialogs (alert, confirm, prompt)
//! 2. Submitting forms with XSS payloads and detecting stored XSS
//! 3. Testing DOM-based XSS with URL fragment/query payloads
//!
//! Uses kalamari's built-in XSS detection for performance.

use crate::http_client::HttpClient;
use crate::types::{Confidence, ScanConfig, ScanMode, Severity, Vulnerability};
use anyhow::{Context, Result};
use kalamari::{
    Browser, BrowserConfig, BrowserPool, Page, PageConfig,
    XssTrigger, XssTriggerType as KalamariXssTriggerType,
    StoredXssTester, StoredXssTest,
};
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Shared browser instance for all XSS tests
pub struct SharedBrowser {
    browser: Arc<RwLock<Browser>>,
}

impl Clone for SharedBrowser {
    fn clone(&self) -> Self {
        Self {
            browser: Arc::clone(&self.browser),
        }
    }
}

impl SharedBrowser {
    pub fn new() -> Result<Self> {
        info!("[SharedBrowser] Launching kalamari headless browser...");

        let config = BrowserConfig::default()
            .timeout(Duration::from_secs(30))
            .enable_xss_detection(true);

        let browser = tokio::runtime::Handle::current()
            .block_on(Browser::new(config))
            .context("Failed to launch kalamari browser")?;

        info!("[SharedBrowser] Kalamari browser launched successfully");
        Ok(Self {
            browser: Arc::new(RwLock::new(browser)),
        })
    }

    pub async fn new_page_with_xss_detection(&self, marker: &str) -> Result<Arc<Page>> {
        let browser = self
            .browser
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to lock browser: {}", e))?;

        // marker is used for XSS detection callbacks, but kalamari handles this internally
        let _ = marker;

        let config = PageConfig::for_xss_scanning()
            .timeout(Duration::from_secs(8));

        let page = browser.new_page_with_config(config).await?;
        Ok(page)
    }

    pub fn is_alive(&self) -> bool {
        self.browser.read().is_ok()
    }

    /// Clean up resources
    pub fn cleanup_stale_tabs(&self) -> Result<usize> {
        // Kalamari handles cleanup automatically
        Ok(0)
    }

    /// Create page that auto-closes when dropped (RAII pattern)
    pub async fn new_guarded_page(&self, marker: &str) -> Result<PageGuard> {
        let page = self.new_page_with_xss_detection(marker).await?;
        Ok(PageGuard { page })
    }
}

/// RAII guard for browser pages - automatically closes page when dropped
pub struct PageGuard {
    page: Arc<Page>,
}

impl PageGuard {
    pub fn page(&self) -> &Arc<Page> {
        &self.page
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        // Kalamari handles page cleanup automatically
    }
}

#[derive(Debug, Clone)]
pub struct XssDetectionResult {
    pub xss_triggered: bool,
    pub trigger_type: XssTriggerType,
    pub payload: String,
    pub dialog_message: Option<String>,
    pub url: String,
    pub severity: XssSeverity,
    pub stack_trace: Option<String>,
    pub source: Option<String>,
    pub timestamp: Option<u64>,
    pub parameter: Option<String>,
    pub injection_point: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XssTriggerType {
    AlertDialog,
    ConfirmDialog,
    PromptDialog,
    DomExecution,
    ShadowDom,
    Eval,
    InnerHtml,
    DocumentWrite,
    LocationChange,
    DataExfil,
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XssSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl From<KalamariXssTriggerType> for XssTriggerType {
    fn from(t: KalamariXssTriggerType) -> Self {
        match t {
            KalamariXssTriggerType::Alert => XssTriggerType::AlertDialog,
            KalamariXssTriggerType::Confirm => XssTriggerType::ConfirmDialog,
            KalamariXssTriggerType::Prompt => XssTriggerType::PromptDialog,
            KalamariXssTriggerType::Eval => XssTriggerType::Eval,
            KalamariXssTriggerType::InnerHtml => XssTriggerType::InnerHtml,
            KalamariXssTriggerType::OuterHtml => XssTriggerType::InnerHtml,
            KalamariXssTriggerType::DocumentWrite => XssTriggerType::DocumentWrite,
            KalamariXssTriggerType::LocationChange => XssTriggerType::LocationChange,
            KalamariXssTriggerType::DomMutation => XssTriggerType::DomExecution,
            KalamariXssTriggerType::ShadowDom => XssTriggerType::ShadowDom,
            KalamariXssTriggerType::FetchUrl | KalamariXssTriggerType::ImageSrc => XssTriggerType::DataExfil,
            _ => XssTriggerType::DomExecution,
        }
    }
}

impl From<&XssTrigger> for XssDetectionResult {
    fn from(trigger: &XssTrigger) -> Self {
        let severity = match trigger.severity.as_str() {
            "CRITICAL" => XssSeverity::Critical,
            "HIGH" => XssSeverity::High,
            "MEDIUM" => XssSeverity::Medium,
            "LOW" => XssSeverity::Low,
            _ => XssSeverity::Unknown,
        };

        XssDetectionResult {
            xss_triggered: true,
            trigger_type: trigger.trigger_type.clone().into(),
            payload: trigger.payload.clone(),
            dialog_message: trigger.message.clone(),
            url: trigger.url.clone(),
            severity,
            stack_trace: trigger.stack_trace.clone(),
            source: trigger.source.clone(),
            timestamp: trigger.timestamp,
            parameter: None,
            injection_point: trigger.injection_point.clone(),
        }
    }
}

pub struct ChromiumXssScanner {
    confirmed_vulns: Arc<Mutex<HashSet<String>>>,
}

impl ChromiumXssScanner {
    pub fn new(_http_client: Arc<HttpClient>) -> Self {
        Self {
            confirmed_vulns: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn clear_cache(&self) {
        if let Ok(mut confirmed) = self.confirmed_vulns.lock() {
            confirmed.clear();
        }
    }

    pub async fn scan(
        &self,
        url: &str,
        config: &ScanConfig,
        shared_browser: Option<&SharedBrowser>,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        // License check - Chromium XSS is a premium feature
        if !crate::license::verify_scan_authorized() {
            debug!("[Kalamari-XSS] Scan skipped: No valid license");
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("[Kalamari-XSS] Scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        info!("[Kalamari-XSS] Starting real browser XSS scan for: {}", url);

        let owns_browser;
        let browser: SharedBrowser = match shared_browser {
            Some(b) => {
                owns_browser = false;
                b.clone()
            }
            None => {
                owns_browser = true;
                warn!("[Kalamari-XSS] No shared browser, creating temporary instance");
                SharedBrowser::new()?
            }
        };

        let mut vulnerabilities = Vec::new();
        let mut tests_run = 0;

        let url_owned = url.to_string();
        let mode = config.scan_mode.clone();
        let browser_clone = browser.clone();

        let results = Self::run_all_xss_tests(&url_owned, &mode, &browser_clone).await?;

        for result in results {
            if result.xss_triggered {
                let vuln = self.create_vulnerability(&result)?;

                let vuln_key = format!("{}:{:?}", result.url, result.trigger_type);
                let mut confirmed = self.confirmed_vulns.lock().unwrap();
                if !confirmed.contains(&vuln_key) {
                    confirmed.insert(vuln_key);
                    vulnerabilities.push(vuln);
                }
            }
            tests_run += 1;
        }

        // Cleanup temporary browser
        if owns_browser {
            let _ = browser.cleanup_stale_tabs();
        }

        info!(
            "[Kalamari-XSS] Scan complete: {} confirmed XSS, {} tests",
            vulnerabilities.len(),
            tests_run
        );

        Ok((vulnerabilities, tests_run))
    }

    async fn run_all_xss_tests(
        url: &str,
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();

        // Phase 1: Test reflected XSS
        info!("[Kalamari-XSS] Phase 1: Testing reflected XSS");
        let reflected = Self::test_reflected_xss(url, mode, browser).await?;
        let found_reflected = reflected.iter().any(|r| r.xss_triggered);
        results.extend(reflected);

        // Early exit: if we found reflected XSS, skip DOM phase (same vector)
        if !found_reflected {
            info!("[Kalamari-XSS] Phase 2: Testing DOM XSS");
            let dom = Self::test_dom_xss(url, browser).await?;
            results.extend(dom);
        }

        // Phase 3: Always test stored XSS (different attack vector - forms)
        info!("[Kalamari-XSS] Phase 3: Testing stored XSS");
        let stored = Self::test_stored_xss(url, browser).await?;
        results.extend(stored);

        Ok(results)
    }

    async fn test_reflected_xss(
        url: &str,
        mode: &ScanMode,
        browser: &SharedBrowser,
    ) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();
        let payloads = Self::get_xss_payloads(mode);

        // Extract existing parameters from URL to test each one
        let url_params = Self::extract_url_parameters(url);

        // If URL has parameters, test those. Otherwise, try to discover from page.
        let test_params: Vec<String> = if !url_params.is_empty() {
            url_params.into_iter().map(|(name, _)| name).collect()
        } else {
            Self::discover_page_parameters(browser, url).await.unwrap_or_default()
        };

        if test_params.is_empty() {
            debug!("[Kalamari-XSS] No parameters to test for reflected XSS on {}", url);
            return Ok(results);
        }

        let payload_limit = match mode {
            ScanMode::Intelligent => payloads.len(),
            ScanMode::Fast => 3,
            ScanMode::Normal => 6,
            ScanMode::Thorough | ScanMode::Insane => payloads.len(),
        };

        'param_loop: for param_name in &test_params {
            for payload_template in payloads.iter().take(payload_limit) {
                let marker = format!(
                    "XSS{}",
                    uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
                );
                let payload = payload_template.replace("MARKER", &marker);

                let test_url = Self::build_test_url(url, param_name, &payload);

                match Self::test_single_url(browser, &test_url, &marker).await {
                    Ok(mut result) => {
                        if result.xss_triggered {
                            info!("[Kalamari-XSS] CONFIRMED reflected XSS in parameter '{}'!", param_name);
                            result.parameter = Some(param_name.clone());
                            results.push(result);
                            break 'param_loop;
                        }
                    }
                    Err(e) => debug!("[Kalamari-XSS] Reflected test error: {}", e),
                }
            }
        }

        Ok(results)
    }

    fn extract_url_parameters(url: &str) -> Vec<(String, String)> {
        if let Ok(parsed) = url::Url::parse(url) {
            parsed
                .query_pairs()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    }

    fn build_test_url(base_url: &str, param_name: &str, payload: &str) -> String {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            let existing_params: Vec<(String, String)> = parsed
                .query_pairs()
                .filter(|(name, _)| name != param_name)
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();

            parsed.set_query(None);

            {
                let mut query_pairs = parsed.query_pairs_mut();
                for (name, value) in &existing_params {
                    query_pairs.append_pair(name, value);
                }
                query_pairs.append_pair(param_name, payload);
            }

            parsed.to_string()
        } else {
            if base_url.contains('?') {
                format!("{}&{}={}", base_url, param_name, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param_name, urlencoding::encode(payload))
            }
        }
    }

    async fn discover_page_parameters(browser: &SharedBrowser, url: &str) -> Result<Vec<String>> {
        let marker = format!("DISCOVER{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());
        let page = browser.new_page_with_xss_detection(&marker).await?;

        page.navigate(url).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Get forms and extract input names
        let forms = page.forms();
        let mut params: HashSet<String> = HashSet::new();

        for form in forms {
            for field in &form.fields {
                if let Some(name) = &field.name {
                    if !name.is_empty() {
                        params.insert(name.clone());
                    }
                }
            }
        }

        debug!("[Kalamari-XSS] Discovered {} parameters from page: {:?}", params.len(), params);
        Ok(params.into_iter().collect())
    }

    async fn test_dom_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();

        let dom_payloads = vec![
            "#<img src=x onerror=alert('MARKER')>",
            "#<svg onload=alert('MARKER')>",
            "#\"><script>alert('MARKER')</script>",
        ];

        for payload_template in &dom_payloads {
            let marker = format!(
                "DOM{}",
                uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
            );
            let payload = payload_template.replace("MARKER", &marker);
            let test_url = format!("{}{}", url.trim_end_matches('#'), payload);

            match Self::test_single_url(browser, &test_url, &marker).await {
                Ok(result) => {
                    if result.xss_triggered {
                        info!("[Kalamari-XSS] CONFIRMED DOM XSS!");
                        results.push(result);
                        break;
                    }
                }
                Err(e) => debug!("[Kalamari-XSS] DOM test error: {}", e),
            }
        }

        Ok(results)
    }

    async fn test_stored_xss(url: &str, browser: &SharedBrowser) -> Result<Vec<XssDetectionResult>> {
        let mut results = Vec::new();
        let marker = format!(
            "STORED{}",
            uuid::Uuid::new_v4().to_string()[..8].to_uppercase()
        );

        let page = browser.new_page_with_xss_detection(&marker).await?;
        page.navigate(url).await?;
        tokio::time::sleep(Duration::from_millis(600)).await;

        let forms = page.forms();
        info!("[Kalamari-XSS] Found {} forms to test", forms.len());

        let stored_payload = format!("<img src=x onerror=alert('{}')>", marker);

        for (form_idx, form) in forms.iter().take(3).enumerate() {
            // Fill form fields using JavaScript
            for field in &form.fields {
                if let Some(name) = &field.name {
                    if field.field_type != "hidden" && field.field_type != "submit" {
                        let selector = format!("[name='{}']", name);
                        let _ = page.fill(&selector, &stored_payload);
                    }
                }
            }

            // Submit form using selector
            let form_selector = format!("form:nth-of-type({})", form_idx + 1);
            if let Err(e) = page.submit_form(&form_selector).await {
                debug!("[Kalamari-XSS] Form submit failed: {}", e);
                continue;
            }

            tokio::time::sleep(Duration::from_millis(800)).await;

            // Check for XSS triggers
            let triggers = page.get_xss_triggers();
            for trigger in triggers {
                if trigger.is_confirmed() {
                    info!("[Kalamari-XSS] CONFIRMED stored XSS via form!");
                    let mut result: XssDetectionResult = (&trigger).into();
                    result.parameter = Some(form.fields.iter().filter_map(|f| f.name.clone()).collect::<Vec<_>>().join(", "));
                    result.injection_point = Some(format!("Form #{}", form_idx));
                    results.push(result);
                    return Ok(results);
                }
            }

            // Navigate back for next form
            let _ = page.navigate(url).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        Ok(results)
    }

    async fn test_single_url(
        browser: &SharedBrowser,
        url: &str,
        marker: &str,
    ) -> Result<XssDetectionResult> {
        // Validate URL scheme
        let url_lower = url.to_lowercase();
        if url_lower.starts_with("javascript:")
            || url_lower.starts_with("data:")
            || url_lower.starts_with("vbscript:")
        {
            debug!("[Kalamari-XSS] Skipping unsafe URL scheme: {}", url);
            return Ok(XssDetectionResult {
                xss_triggered: false,
                trigger_type: XssTriggerType::None,
                payload: url.to_string(),
                dialog_message: Some("Skipped: unsafe URL scheme".to_string()),
                url: url.to_string(),
                severity: XssSeverity::Unknown,
                stack_trace: None,
                source: None,
                timestamp: None,
                parameter: None,
                injection_point: None,
            });
        }

        let page = browser.new_page_with_xss_detection(marker).await?;

        if let Err(e) = page.navigate(url).await {
            debug!("[Kalamari-XSS] Navigation failed for {}: {}", url, e);
            return Ok(XssDetectionResult {
                xss_triggered: false,
                trigger_type: XssTriggerType::None,
                payload: url.to_string(),
                dialog_message: None,
                url: url.to_string(),
                severity: XssSeverity::Unknown,
                stack_trace: None,
                source: None,
                timestamp: None,
                parameter: None,
                injection_point: None,
            });
        }

        // Wait for JS execution
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Check for XSS triggers using kalamari's built-in detection
        let triggers = page.get_xss_triggers();

        if let Some(trigger) = triggers.into_iter().find(|t| t.is_confirmed()) {
            return Ok((&trigger).into());
        }

        // Trigger events to catch more XSS via JavaScript
        let _ = page.evaluate(r#"
            document.querySelectorAll('[onmouseover], [onfocus], [onload]').forEach(el => {
                if (el.onmouseover) el.onmouseover();
                if (el.onfocus) el.focus();
            });
        "#);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let triggers = page.get_xss_triggers();
        if let Some(trigger) = triggers.into_iter().find(|t| t.is_confirmed()) {
            return Ok((&trigger).into());
        }

        Ok(XssDetectionResult {
            xss_triggered: false,
            trigger_type: XssTriggerType::None,
            payload: url.to_string(),
            dialog_message: None,
            url: url.to_string(),
            severity: XssSeverity::Unknown,
            stack_trace: None,
            source: None,
            timestamp: None,
            parameter: None,
            injection_point: None,
        })
    }

    fn create_vulnerability(&self, result: &XssDetectionResult) -> Result<Vulnerability> {
        let trigger_desc = match result.trigger_type {
            XssTriggerType::AlertDialog => "JavaScript alert() executed",
            XssTriggerType::ConfirmDialog => "JavaScript confirm() executed",
            XssTriggerType::PromptDialog => "JavaScript prompt() executed",
            XssTriggerType::DomExecution => "DOM mutation detected with payload",
            XssTriggerType::ShadowDom => "Shadow DOM injection detected",
            XssTriggerType::Eval => "Code execution via eval/Function",
            XssTriggerType::InnerHtml => "DOM sink innerHTML/outerHTML triggered",
            XssTriggerType::DocumentWrite => "document.write injection detected",
            XssTriggerType::LocationChange => "Location manipulation detected",
            XssTriggerType::DataExfil => "Data exfiltration attempt detected",
            XssTriggerType::None => "Unknown trigger",
        };

        let xss_type = if result.payload.contains("STORED") {
            "Stored XSS"
        } else if result.payload.contains("DOM") || result.payload.starts_with('#') {
            "DOM-based XSS"
        } else {
            "Reflected XSS"
        };

        let (severity, cvss) = match result.severity {
            XssSeverity::Critical => (Severity::Critical, 9.6),
            XssSeverity::High => (Severity::High, 8.2),
            XssSeverity::Medium => (Severity::Medium, 6.5),
            XssSeverity::Low => (Severity::Low, 4.3),
            XssSeverity::Unknown => (Severity::High, 7.5),
        };

        let mut evidence_parts = vec![
            format!("Trigger: {}", trigger_desc),
            format!("Severity: {:?}", result.severity),
            format!("Payload: {}", result.payload),
        ];

        if let Some(ref injection_point) = result.injection_point {
            evidence_parts.push(format!("Found in: {}", injection_point));
        }
        if let Some(ref param) = result.parameter {
            evidence_parts.push(format!("Injected via: {}", param));
        }
        if let Some(ref msg) = result.dialog_message {
            evidence_parts.push(format!("Message: {}", msg));
        }
        if let Some(ref source) = result.source {
            evidence_parts.push(format!("Source: {}", source));
        }
        if let Some(ts) = result.timestamp {
            evidence_parts.push(format!("Timestamp: {}ms", ts));
        }
        if let Some(ref stack) = result.stack_trace {
            evidence_parts.push(format!("Stack trace:\n{}", stack));
        }

        Ok(Vulnerability {
            id: format!("xss_{}", uuid::Uuid::new_v4()),
            vuln_type: format!("{} (CONFIRMED)", xss_type),
            severity,
            confidence: Confidence::High,
            category: "Injection".to_string(),
            url: result.url.clone(),
            parameter: result.parameter.clone(),
            payload: result.payload.clone(),
            description: format!(
                "CONFIRMED {} vulnerability ({:?} severity). {}. Payload executed in real browser context.",
                xss_type, result.severity, trigger_desc
            ),
            evidence: Some(evidence_parts.join("\n")),
            cwe: "CWE-79".to_string(),
            cvss,
            verified: true,
            false_positive: false,
            remediation: "1. Encode all user input before rendering\n\
                         2. Use Content Security Policy (CSP)\n\
                         3. Use HTTP-only cookies\n\
                         4. Sanitize HTML with DOMPurify\n\
                         5. Use frameworks with auto-escaping (React, Vue, Angular)".to_string(),
            discovered_at: chrono::Utc::now().to_rfc3339(),
            ml_data: None,
        })
    }

    /// Parallel XSS scanning using kalamari's BrowserPool
    pub async fn scan_urls_parallel(
        &self,
        urls: &[String],
        config: &ScanConfig,
        shared_browser: Option<&SharedBrowser>,
        concurrency: usize,
    ) -> Result<(Vec<Vulnerability>, usize)> {
        if !crate::license::verify_scan_authorized() {
            return Ok((Vec::new(), 0));
        }
        if !crate::signing::is_scan_authorized() {
            warn!("[Kalamari-XSS] Parallel scan blocked: No valid scan authorization");
            return Ok((Vec::new(), 0));
        }

        let concurrency = concurrency.min(8).max(1);
        info!(
            "[Kalamari-XSS] Starting parallel XSS scan: {} URLs with {} concurrent pages",
            urls.len(),
            concurrency
        );

        let browser: SharedBrowser = match shared_browser {
            Some(b) => b.clone(),
            None => {
                warn!("[Kalamari-XSS] No shared browser, creating temporary instance");
                SharedBrowser::new()?
            }
        };

        let mut all_vulnerabilities = Vec::new();
        let mut total_tests = 0;

        for (chunk_idx, chunk) in urls.chunks(concurrency).enumerate() {
            let chunk_start = chunk_idx * concurrency + 1;
            let chunk_end = (chunk_start + chunk.len() - 1).min(urls.len());
            info!(
                "    [XSS] Testing URLs {}-{}/{}",
                chunk_start,
                chunk_end,
                urls.len()
            );

            for url in chunk {
                match Self::run_all_xss_tests(url, &config.scan_mode, &browser).await {
                    Ok(results) => {
                        for r in results {
                            if r.xss_triggered {
                                if let Ok(vuln) = self.create_vulnerability(&r) {
                                    let vuln_key = format!("{}:{:?}", r.url, r.trigger_type);
                                    let mut confirmed = self.confirmed_vulns.lock().unwrap();
                                    if !confirmed.contains(&vuln_key) {
                                        confirmed.insert(vuln_key);
                                        info!("    [XSS] CONFIRMED XSS at: {}", url);
                                        all_vulnerabilities.push(vuln);
                                    }
                                }
                            }
                            total_tests += 1;
                        }
                    }
                    Err(e) => {
                        debug!("[Kalamari-XSS] Error scanning {}: {}", url, e);
                    }
                }
            }
        }

        info!(
            "[Kalamari-XSS] Parallel scan complete: {} confirmed XSS, {} tests across {} URLs",
            all_vulnerabilities.len(),
            total_tests,
            urls.len()
        );

        Ok((all_vulnerabilities, total_tests))
    }

    fn get_xss_payloads(mode: &ScanMode) -> Vec<String> {
        let base = vec![
            "<img src=x onerror=alert('MARKER')>".to_string(),
            "<svg onload=alert('MARKER')>".to_string(),
            "'\"><script>alert('MARKER')</script>".to_string(),
            "<body onload=alert('MARKER')>".to_string(),
        ];

        let advanced = vec![
            "<details open ontoggle=alert('MARKER')>".to_string(),
            "<input onfocus=alert('MARKER') autofocus>".to_string(),
            "<script>alert`MARKER`</script>".to_string(),
        ];

        let mxss = vec![
            "<img src=\"`><script>alert('MARKER')</script>\">".to_string(),
            "<noscript><p title=\"</noscript><script>alert('MARKER')</script>\">".to_string(),
            "<form><button formaction=\"javascript:alert('MARKER')\">".to_string(),
        ];

        let waf_bypass = vec![
            "<ScRiPt>alert('MARKER')</sCrIpT>".to_string(),
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('MARKER')>".to_string(),
            "<iframe srcdoc=\"<script>alert('MARKER')</script>\">".to_string(),
        ];

        match mode {
            ScanMode::Fast => base[..2].to_vec(),
            ScanMode::Normal => base,
            ScanMode::Thorough => {
                let mut all = base;
                all.extend(advanced);
                all.extend(mxss);
                all
            }
            ScanMode::Insane | ScanMode::Intelligent => {
                let mut all = base;
                all.extend(advanced);
                all.extend(mxss);
                all.extend(waf_bypass);
                all
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_payloads() {
        let payloads = ChromiumXssScanner::get_xss_payloads(&ScanMode::Normal);
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.contains("MARKER")));
    }

    #[test]
    fn test_trigger_types() {
        assert_eq!(XssTriggerType::AlertDialog, XssTriggerType::AlertDialog);
        assert_ne!(XssTriggerType::AlertDialog, XssTriggerType::ConfirmDialog);
    }
}
